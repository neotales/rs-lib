//! Resource limits used while reading age files.

use crate::error::{AgeError, Result};

/// Bounds applied while parsing an age header and payload.
///
/// The default header and stanza limits match the upstream age parser. There
/// is no default decoded-payload or per-stanza-body cap: [`usize::MAX`]
/// represents an unbounded limit, while callers that need a resource policy
/// can set either field explicitly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgeReadOptions {
    /// Maximum number of bytes in the complete textual header, including the
    /// footer and its newline.
    pub max_header_bytes: usize,
    /// Maximum number of recipient stanzas.
    pub max_stanzas: usize,
    /// Maximum decoded bytes in one recipient body. The default is
    /// [`usize::MAX`], so the complete header limit is the effective bound.
    pub max_stanza_body_bytes: usize,
    /// Maximum decrypted payload bytes. The default is [`usize::MAX`], which
    /// means unbounded; set this explicitly when a resource cap is required.
    pub max_payload_bytes: usize,
}

impl Default for AgeReadOptions {
    fn default() -> Self {
        Self {
            max_header_bytes: 2 * 1024 * 1024,
            max_stanzas: 1024,
            max_stanza_body_bytes: usize::MAX,
            max_payload_bytes: usize::MAX,
        }
    }
}

impl AgeReadOptions {
    /// Creates the default read limits.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Validates the configured limits.
    ///
    /// # Errors
    ///
    /// Returns [`AgeError::InvalidFormat`] when a limit is outside its safe
    /// minimum.
    pub fn validate(self) -> Result<Self> {
        if self.max_header_bytes < 32 || self.max_stanzas < 1 || self.max_stanza_body_bytes < 16 {
            return Err(AgeError::InvalidFormat("read limits are too small"));
        }
        Ok(self)
    }

    /// Returns a copy with a different header limit.
    #[must_use]
    pub fn with_max_header_bytes(mut self, value: usize) -> Self {
        self.max_header_bytes = value;
        self
    }

    /// Returns a copy with a different stanza-count limit.
    #[must_use]
    pub fn with_max_stanzas(mut self, value: usize) -> Self {
        self.max_stanzas = value;
        self
    }

    /// Returns a copy with a different stanza-body limit.
    #[must_use]
    pub fn with_max_stanza_body_bytes(mut self, value: usize) -> Self {
        self.max_stanza_body_bytes = value;
        self
    }

    /// Returns a copy with a different payload limit.
    #[must_use]
    pub fn with_max_payload_bytes(mut self, value: usize) -> Self {
        self.max_payload_bytes = value;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::AgeReadOptions;

    #[test]
    fn defaults_match_upstream_header_limits_and_are_unbounded() {
        let options = AgeReadOptions::default();
        assert_eq!(options.max_header_bytes, 2 * 1024 * 1024);
        assert_eq!(options.max_stanzas, 1024);
        assert_eq!(options.max_stanza_body_bytes, usize::MAX);
        assert_eq!(options.max_payload_bytes, usize::MAX);
        assert!(options.validate().is_ok());
    }
}
