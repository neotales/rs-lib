//! Content digests used by the OCI Distribution boundary.
//!
//! The first slice deliberately implements the digest algorithms that the
//! fixture and policy tests need without pulling in a registry client.  A
//! digest is always kept in its canonical lower-case representation so a
//! caller cannot accidentally compare a header and a computed value using
//! different spellings.

use std::fmt;

use sha2::{Digest as ShaDigest, Sha256, Sha512};

/// A digest algorithm supported by this crate.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum DigestAlgorithm {
    /// SHA-256, the digest used by the deterministic fixtures.
    Sha256,
    /// SHA-512, useful for registries that advertise it explicitly.
    Sha512,
}

impl DigestAlgorithm {
    /// Returns the OCI algorithm name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
        }
    }

    /// Parses an OCI algorithm name.
    ///
    /// Algorithm names are case-sensitive in the canonical digest grammar.
    ///
    /// # Errors
    ///
    /// Returns [`DigestError::UnsupportedAlgorithm`] for an unknown algorithm.
    pub fn parse(value: &str) -> Result<Self, DigestError> {
        match value {
            "sha256" => Ok(Self::Sha256),
            "sha512" => Ok(Self::Sha512),
            _ => Err(DigestError::UnsupportedAlgorithm(value.to_owned())),
        }
    }

    const fn encoded_length(self) -> usize {
        match self {
            Self::Sha256 => 64,
            Self::Sha512 => 128,
        }
    }

    fn hasher(self) -> Hasher {
        match self {
            Self::Sha256 => Hasher::Sha256(Sha256::new()),
            Self::Sha512 => Hasher::Sha512(Sha512::new()),
        }
    }
}

enum Hasher {
    Sha256(Sha256),
    Sha512(Sha512),
}

impl Hasher {
    fn update(self, content: &[u8]) -> Self {
        match self {
            Self::Sha256(mut hasher) => {
                hasher.update(content);
                Self::Sha256(hasher)
            }
            Self::Sha512(mut hasher) => {
                hasher.update(content);
                Self::Sha512(hasher)
            }
        }
    }

    fn finish(self) -> Vec<u8> {
        match self {
            Self::Sha256(hasher) => hasher.finalize().to_vec(),
            Self::Sha512(hasher) => hasher.finalize().to_vec(),
        }
    }
}

/// A canonical OCI content digest such as `sha256:<hex>`.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Digest {
    algorithm: DigestAlgorithm,
    encoded: String,
    value: String,
}

impl Digest {
    /// Computes the SHA-256 digest of `content`.
    #[must_use]
    pub fn sha256(content: &[u8]) -> Self {
        Self::compute(DigestAlgorithm::Sha256, content)
    }

    /// Computes a digest using the selected algorithm.
    #[must_use]
    pub fn compute(algorithm: DigestAlgorithm, content: &[u8]) -> Self {
        let bytes = algorithm.hasher().update(content).finish();
        let encoded = encode_hex(&bytes);
        let value = format!("{}:{encoded}", algorithm.as_str());
        Self {
            algorithm,
            encoded,
            value,
        }
    }

    /// Parses a canonical OCI digest.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported algorithm or non-canonical digest.
    pub fn parse(value: &str) -> Result<Self, DigestError> {
        if value.is_empty() || value.bytes().any(|byte| byte.is_ascii_control()) {
            return Err(DigestError::Malformed);
        }
        let (algorithm_text, encoded) = value.split_once(':').ok_or(DigestError::Malformed)?;
        if algorithm_text.is_empty()
            || encoded.is_empty()
            || encoded.contains(':')
            || encoded.len() != DigestAlgorithm::parse(algorithm_text)?.encoded_length()
            || !encoded
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(DigestError::Malformed);
        }
        let algorithm = DigestAlgorithm::parse(algorithm_text)?;
        Ok(Self {
            value: value.to_owned(),
            algorithm,
            encoded: encoded.to_owned(),
        })
    }

    /// Returns the algorithm used by this digest.
    #[must_use]
    pub const fn algorithm(&self) -> DigestAlgorithm {
        self.algorithm
    }

    /// Returns the hexadecimal portion without the algorithm prefix.
    #[must_use]
    pub fn encoded(&self) -> &str {
        &self.encoded
    }

    /// Returns the canonical digest string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.value
    }

    /// Verifies that `content` hashes to this digest.
    ///
    /// # Errors
    ///
    /// Returns [`DigestMismatch`] when the computed digest differs.
    pub fn verify(&self, content: &[u8]) -> Result<(), DigestMismatch> {
        let actual = Self::compute(self.algorithm, content);
        if actual == *self {
            Ok(())
        } else {
            Err(DigestMismatch {
                expected: self.clone(),
                actual,
            })
        }
    }

    /// Returns whether `content` hashes to this digest.
    #[must_use]
    pub fn matches(&self, content: &[u8]) -> bool {
        self.verify(content).is_ok()
    }

    /// Verifies a `Docker-Content-Digest` header and returns its digest.
    ///
    /// # Errors
    ///
    /// Returns [`HeaderDigestError::Missing`], [`HeaderDigestError::Malformed`],
    /// or [`HeaderDigestError::Mismatch`].
    pub fn verify_content(header: Option<&str>, content: &[u8]) -> Result<Self, HeaderDigestError> {
        let header = header.ok_or(HeaderDigestError::Missing)?;
        let advertised = Digest::parse(header).map_err(HeaderDigestError::Malformed)?;
        advertised
            .verify(content)
            .map_err(|_| HeaderDigestError::Mismatch)?;
        Ok(advertised)
    }

    /// Verifies an optional `Docker-Content-Digest` response header.
    ///
    /// A missing header is rejected by this method.  Callers that need to
    /// accept registries which omit the header can use [`Digest::compute`]
    /// and record that policy explicitly.
    ///
    /// # Errors
    ///
    /// Returns an error when the header is absent, malformed, or disagrees
    /// with either the expected digest or the body.
    pub fn verify_header(
        &self,
        header: Option<&str>,
        content: &[u8],
    ) -> Result<(), HeaderDigestError> {
        let header = header.ok_or(HeaderDigestError::Missing)?;
        let advertised = Digest::parse(header).map_err(HeaderDigestError::Malformed)?;
        if advertised != *self {
            return Err(HeaderDigestError::Mismatch);
        }
        self.verify(content)
            .map_err(|_| HeaderDigestError::Mismatch)
    }

    /// Returns the canonical string through `Display`.
    #[must_use]
    pub fn to_canonical(&self) -> String {
        self.value.clone()
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}", self.algorithm.as_str(), self.encoded)
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Digest")
            .field("algorithm", &self.algorithm)
            .field("encoded", &self.encoded)
            .field("value", &self.value)
            .finish()
    }
}

/// Errors returned while parsing a digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DigestError {
    /// The value did not have a canonical algorithm and hexadecimal shape.
    Malformed,
    /// The algorithm is not implemented by this crate.
    UnsupportedAlgorithm(String),
}

impl fmt::Display for DigestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => formatter.write_str("OCI digest is malformed"),
            Self::UnsupportedAlgorithm(algorithm) => {
                write!(formatter, "unsupported OCI digest algorithm: {algorithm}")
            }
        }
    }
}

impl std::error::Error for DigestError {}

/// The expected and computed digests differed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DigestMismatch {
    /// Digest expected by the caller or registry.
    pub expected: Digest,
    /// Digest computed from the received bytes.
    pub actual: Digest,
}

impl fmt::Display for DigestMismatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "content digest mismatch: expected {}, computed {}",
            self.expected, self.actual
        )
    }
}

impl std::error::Error for DigestMismatch {}

/// Errors while validating a `Docker-Content-Digest` header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HeaderDigestError {
    /// The registry omitted the required digest header.
    Missing,
    /// The header was not a canonical OCI digest.
    Malformed(DigestError),
    /// The header and body described different content.
    Mismatch,
}

impl fmt::Display for HeaderDigestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => formatter.write_str("Docker-Content-Digest header is missing"),
            Self::Malformed(error) => write!(
                formatter,
                "Docker-Content-Digest header is invalid: {error}"
            ),
            Self::Mismatch => {
                formatter.write_str("Docker-Content-Digest does not match the content")
            }
        }
    }
}

impl std::error::Error for HeaderDigestError {}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{Digest, DigestAlgorithm, DigestError, HeaderDigestError};

    #[test]
    fn computes_the_standard_sha256_digest() {
        assert_eq!(
            Digest::sha256(b"abc").to_string(),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn rejects_non_canonical_digests() {
        assert_eq!(Digest::parse("sha256:abc"), Err(DigestError::Malformed));
        assert_eq!(
            Digest::parse(
                "SHA256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            ),
            Err(DigestError::UnsupportedAlgorithm("SHA256".to_owned()))
        );
        assert_eq!(
            Digest::parse(
                "sha256:BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"
            ),
            Err(DigestError::Malformed)
        );
    }

    #[test]
    fn verifies_body_and_header_fail_closed() {
        let digest = Digest::sha256(b"abc");
        assert!(digest.verify(b"abc").is_ok());
        assert!(digest.verify(b"wrong").is_err());
        assert_eq!(
            digest.verify_header(Some(&digest.to_string()), b"abc"),
            Ok(())
        );
        assert_eq!(
            digest.verify_header(None, b"abc"),
            Err(HeaderDigestError::Missing)
        );
        assert_eq!(
            digest.verify_header(Some("sha256:bad"), b"abc"),
            Err(HeaderDigestError::Malformed(DigestError::Malformed))
        );
    }

    #[test]
    fn supports_sha512_without_changing_sha256_defaults() {
        assert_eq!(
            Digest::compute(DigestAlgorithm::Sha512, b"")
                .encoded()
                .len(),
            128
        );
    }
}
