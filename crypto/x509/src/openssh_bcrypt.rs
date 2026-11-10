//! OpenSSH `bcrypt_pbkdf` key derivation.
//!
//! This is the key derivation function used by OpenSSH, not the OpenBSD
//! `$2a$` password-hash format.

use blowfish::Blowfish;
use sha2::{Digest, Sha512};
use zeroize::{Zeroize, Zeroizing};

/// Bytes produced by one bcrypt hash operation.
const BLOCK_SIZE: usize = 32;

/// Blowfish encrypts two big-endian words at a time.
const BLOWFISH_BLOCK_SIZE: usize = 8;

/// One Blowfish word in the output byte order.
const WORD_SIZE: usize = 4;

/// bcrypt's expensive key schedule repeats this many times.
const EXPAND_ITERATIONS: usize = 64;

/// Each output block is encrypted this many times.
const ENCRYPT_ITERATIONS: usize = 64;

/// Bytes appended to the salt for each output block.
const BLOCK_COUNTER_SIZE: usize = 4;

/// Largest accepted round count.
const MAX_ROUNDS: u32 = 1 << 20;

/// Largest accepted password length.
const MAX_PASSWORD_BYTES: usize = 1 << 20;

/// Largest accepted salt length.
const MAX_SALT_BYTES: usize = 1 << 20;

/// Largest accepted derived-key length.
const MAX_OUTPUT_BYTES: usize = 1024;

/// Text encrypted by each bcrypt hash operation.
const MAGIC: [u8; BLOCK_SIZE] = *b"OxychromaticBlowfishSwatDynamite";

/// Invalid OpenSSH bcrypt key-derivation input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenSshBcryptError {
    /// The password was empty.
    EmptyPassword,
    /// The password exceeded 1,048,576 bytes.
    PasswordTooLong,
    /// The round count was outside 1..=1,048,576.
    InvalidRounds,
    /// The salt was empty or exceeded 1,048,576 bytes.
    InvalidSalt,
    /// The requested output was empty or exceeded 1,024 bytes.
    InvalidOutputLength,
}

impl std::fmt::Display for OpenSshBcryptError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::EmptyPassword => "OpenSSH bcrypt KDF password must not be empty",
            Self::PasswordTooLong => "OpenSSH bcrypt KDF passwords must not exceed 1,048,576 bytes",
            Self::InvalidRounds => "OpenSSH bcrypt KDF rounds must be between 1 and 1,048,576",
            Self::InvalidSalt => "OpenSSH bcrypt KDF salt length is invalid",
            Self::InvalidOutputLength => "OpenSSH bcrypt KDF output length is invalid",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for OpenSshBcryptError {}

/// Derives a key with OpenSSH's `bcrypt_pbkdf` construction.
///
/// The password and salt are hashed with `SHA-512`, and their hashes drive the
/// bcrypt key schedule. This is not compatible with the `$2a$` password-hash
/// format implemented by password-hashing libraries.
///
/// # Errors
///
/// Returns [`OpenSshBcryptError::InvalidRounds`] when `rounds` is outside
/// 1..=1,048,576, [`OpenSshBcryptError::EmptyPassword`] when `password` is
/// empty, [`OpenSshBcryptError::PasswordTooLong`] when it exceeds 1,048,576
/// bytes, [`OpenSshBcryptError::InvalidSalt`] when `salt` is empty or exceeds
/// 1,048,576 bytes, and [`OpenSshBcryptError::InvalidOutputLength`] when
/// `output_len` is outside 1..=1024.
pub fn derive_key(
    password: &[u8],
    salt: &[u8],
    rounds: u32,
    output_len: usize,
) -> Result<Vec<u8>, OpenSshBcryptError> {
    if !(1..=MAX_ROUNDS).contains(&rounds) {
        return Err(OpenSshBcryptError::InvalidRounds);
    }
    if password.is_empty() {
        return Err(OpenSshBcryptError::EmptyPassword);
    }
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(OpenSshBcryptError::PasswordTooLong);
    }
    if salt.is_empty() || salt.len() > MAX_SALT_BYTES {
        return Err(OpenSshBcryptError::InvalidSalt);
    }
    if output_len == 0 || output_len > MAX_OUTPUT_BYTES {
        return Err(OpenSshBcryptError::InvalidOutputLength);
    }

    let blocks = output_len.div_ceil(BLOCK_SIZE);
    let full_output_len = blocks
        .checked_mul(BLOCK_SIZE)
        .ok_or(OpenSshBcryptError::InvalidOutputLength)?;
    let mut key = Zeroizing::new(vec![0u8; full_output_len]);
    let password_hash = sha512(password);

    let count_salt_len = salt
        .len()
        .checked_add(BLOCK_COUNTER_SIZE)
        .ok_or(OpenSshBcryptError::InvalidSalt)?;
    let mut count_salt = Zeroizing::new(Vec::with_capacity(count_salt_len));
    count_salt.extend_from_slice(salt);

    for block in 0..blocks {
        let block_number = block
            .checked_add(1)
            .and_then(|number| u32::try_from(number).ok())
            .ok_or(OpenSshBcryptError::InvalidOutputLength)?;
        count_salt.extend_from_slice(&block_number.to_be_bytes());

        let initial_salt_hash = sha512(count_salt.as_slice());
        let mut current = Zeroizing::new([0u8; BLOCK_SIZE]);
        bcrypt_hash(
            password_hash.as_slice(),
            initial_salt_hash.as_slice(),
            &mut current,
        );

        let mut accumulated = Zeroizing::new([0u8; BLOCK_SIZE]);
        accumulated.copy_from_slice(current.as_slice());

        for _ in 2..=rounds {
            let round_salt_hash = sha512(current.as_slice());
            bcrypt_hash(
                password_hash.as_slice(),
                round_salt_hash.as_slice(),
                &mut current,
            );
            for (accumulated_byte, current_byte) in accumulated.iter_mut().zip(current.iter()) {
                *accumulated_byte ^= *current_byte;
            }
        }

        for (index, byte) in accumulated.iter().copied().enumerate() {
            let position = index
                .checked_mul(blocks)
                .and_then(|position| position.checked_add(block))
                .ok_or(OpenSshBcryptError::InvalidOutputLength)?;
            let destination = key
                .get_mut(position)
                .ok_or(OpenSshBcryptError::InvalidOutputLength)?;
            *destination = byte;
        }
        count_salt.truncate(salt.len());
    }

    let result = key
        .get(..output_len)
        .ok_or(OpenSshBcryptError::InvalidOutputLength)?
        .to_vec();
    key.zeroize();
    Ok(result)
}

/// Runs OpenSSH's 32-byte bcrypt hash over pre-hashed password and salt.
fn bcrypt_hash(password_hash: &[u8], salt_hash: &[u8], output: &mut [u8; BLOCK_SIZE]) {
    let mut state = Blowfish::bc_init_state();
    state.salted_expand_key(salt_hash, password_hash);
    for _ in 0..EXPAND_ITERATIONS {
        state.bc_expand_key(salt_hash);
        state.bc_expand_key(password_hash);
    }

    output.copy_from_slice(&MAGIC);
    // `as_chunks` rather than `chunks_exact`: the buffer is a fixed 32 bytes and
    // every chunk size here divides it exactly, so the remainder is always empty
    // and the defensive "could not get a second word" branches were unreachable.
    for block in output
        .as_mut_slice()
        .as_chunks_mut::<BLOWFISH_BLOCK_SIZE>()
        .0
    {
        for _ in 0..ENCRYPT_ITERATIONS {
            let [left, right] = {
                let (words, _) = block.as_chunks::<WORD_SIZE>();
                state.bc_encrypt([read_u32_be(&words[0]), read_u32_be(&words[1])])
            };
            for (destination, word) in block
                .as_chunks_mut::<WORD_SIZE>()
                .0
                .iter_mut()
                .zip([left, right])
            {
                write_u32_be(destination, word);
            }
        }
    }

    for word in output.as_mut_slice().as_chunks_mut::<WORD_SIZE>().0 {
        word.reverse();
    }
}

/// Hashes one input with `SHA-512` and wipes the digest buffer.
fn sha512(bytes: &[u8]) -> Zeroizing<[u8; 64]> {
    let mut digest = Sha512::digest(bytes);
    let mut hash = [0u8; 64];
    hash.copy_from_slice(digest.as_slice());
    digest.as_mut_slice().zeroize();
    Zeroizing::new(hash)
}

/// Reads one big-endian Blowfish word.
fn read_u32_be(bytes: &[u8]) -> u32 {
    bytes
        .iter()
        .fold(0u32, |word, byte| (word << 8) | u32::from(*byte))
}

/// Writes one big-endian Blowfish word.
fn write_u32_be(bytes: &mut [u8], word: u32) {
    for (destination, byte) in bytes.iter_mut().zip(word.to_be_bytes()) {
        *destination = byte;
    }
}

#[cfg(test)]
mod tests {
    use super::{OpenSshBcryptError, derive_key};

    #[test]
    fn matches_published_openssh_vector() {
        let derived = derive_key(b"password", b"salt", 4, 32)
            .expect("OpenSSH bcrypt vector should derive successfully");
        assert_eq!(
            derived,
            decode_hex("5BBF0CC293587F1C3635555C27796598D47E579071BF427E9D8FBE842ABA34D9"),
        );
    }

    #[test]
    fn rejects_zero_rounds_and_output_length() {
        assert_eq!(
            derive_key(b"password", b"salt", 0, 32),
            Err(OpenSshBcryptError::InvalidRounds),
        );
        assert_eq!(
            derive_key(b"password", b"salt", 1, 0),
            Err(OpenSshBcryptError::InvalidOutputLength),
        );
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let pair = std::str::from_utf8(pair).expect("test vector should be ASCII");
                u8::from_str_radix(pair, 16).expect("test vector should be hexadecimal")
            })
            .collect()
    }
}
