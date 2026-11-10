//! Identity and recipient file parsing.

use crate::{
    AgeIdentity, AgeRecipient,
    error::{AgeError, Result},
};

const FILE_SIZE_LIMIT: usize = 1 << 24;
const LINE_LENGTH_LIMIT: usize = 1 << 16;

/// Parses newline-delimited native age secret keys, including hybrid
/// post-quantum keys.
///
/// Empty lines and lines beginning with `#` are ignored. Line numbers in
/// errors are one-based and include ignored lines.
///
/// # Errors
///
/// Returns an error for an oversized input or line, a malformed secret key, or
/// an input containing no secret keys.
pub fn parse_identities(input: &str) -> Result<Vec<AgeIdentity>> {
    check_input_limits(input)?;
    let mut identities = Vec::new();
    for (index, raw_line) in input.split_terminator('\n').enumerate() {
        let line_number = index.saturating_add(1);
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        check_line_length(line)?;
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let identity =
            AgeIdentity::from_private_key(line).map_err(|error| AgeError::InvalidIdentityLine {
                line: line_number,
                reason: identity_error_reason(&error),
            })?;
        identities.push(identity);
    }
    if identities.is_empty() {
        return Err(AgeError::NoSecretKeys);
    }
    Ok(identities)
}

/// Parses newline-delimited native age recipients, including hybrid
/// post-quantum keys.
///
/// Empty lines and lines beginning with `#` are ignored. Recipient errors
/// deliberately do not include line contents.
///
/// # Errors
///
/// Returns an error for an oversized input or line, a malformed recipient, or
/// an input containing no recipients.
pub fn parse_recipients(input: &str) -> Result<Vec<AgeRecipient>> {
    check_input_limits(input)?;
    let mut recipients = Vec::new();
    for (index, raw_line) in input.split_terminator('\n').enumerate() {
        let line_number = index.saturating_add(1);
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        check_line_length(line)?;
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let recipient = AgeRecipient::from_public_key(line)
            .map_err(|_| AgeError::MalformedRecipientLine { line: line_number })?;
        recipients.push(recipient);
    }
    if recipients.is_empty() {
        return Err(AgeError::NoRecipients);
    }
    Ok(recipients)
}

fn check_input_limits(input: &str) -> Result<()> {
    if input.len() > FILE_SIZE_LIMIT {
        return Err(AgeError::LimitExceeded(
            "identity or recipient file is too large",
        ));
    }
    Ok(())
}

fn check_line_length(line: &str) -> Result<()> {
    if line.len() > LINE_LENGTH_LIMIT {
        return Err(AgeError::LimitExceeded(
            "identity or recipient line is too long",
        ));
    }
    Ok(())
}

fn identity_error_reason(error: &AgeError) -> String {
    match error {
        AgeError::InvalidKey(message)
        | AgeError::InvalidFormat(message)
        | AgeError::Unsupported(message) => (*message).to_owned(),
        AgeError::Truncated => "truncated secret key".to_owned(),
        _ => "invalid secret key".to_owned(),
    }
}
