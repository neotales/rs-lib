//! Extension interfaces corresponding to age's recipient and identity model.

use zeroize::Zeroizing;

use crate::{Result, Stanza};

/// A recipient implementation that can wrap an age file key.
///
/// Implementations may return zero, one, or multiple stanzas. The `labels`
/// hook mirrors age's `RecipientWithLabels`; all recipients in one operation
/// must return identical label sets.
pub trait Recipient {
    /// Wraps the 16-byte age file key.
    ///
    /// # Errors
    ///
    /// Returns an error when the file key is invalid or the recipient's
    /// cryptographic operation fails.
    fn wrap(&self, file_key: &[u8]) -> Result<Vec<Stanza>>;

    /// Returns compatibility labels for this recipient.
    fn labels(&self) -> &'static [&'static str] {
        &[]
    }

    /// Wraps a file key and returns compatibility labels.
    ///
    /// # Errors
    ///
    /// Returns an error when wrapping fails.
    fn wrap_with_labels(&self, file_key: &[u8]) -> Result<(Vec<Stanza>, Vec<String>)> {
        Ok((
            self.wrap(file_key)?,
            self.labels()
                .iter()
                .map(|label| (*label).to_owned())
                .collect(),
        ))
    }
}

/// An identity implementation that can unwrap an age file key.
///
/// `Ok(None)` means that the identity did not match any stanza. Structural or
/// cryptographic errors for a recognized matching stanza must be returned as
/// `Err`, as required by age's `ErrIncorrectIdentity` distinction.
pub trait Identity {
    /// Attempts to unwrap the file key from the supplied stanzas.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed matching stanzas or failed cryptographic
    /// operations. `Ok(None)` denotes an ordinary identity mismatch.
    fn unwrap(&self, stanzas: &[Stanza]) -> Result<Option<Zeroizing<Vec<u8>>>>;
}
