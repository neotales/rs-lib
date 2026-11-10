use aes::Aes256;
use aes::cipher::{
    BlockCipherEncrypt, BlockModeDecrypt, BlockModeEncrypt, InnerIvInit, KeyInit, KeyIvInit,
    StreamCipher, StreamCipherSeek, block_padding::Pkcs7,
};
use chacha20::ChaCha20;
use hmac::{Hmac, Mac};
use salsa20::{SalsaCore, cipher::StreamCipherCoreWrapper};
use sha2::{Digest, Sha256, Sha512};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{KdbxError, KdbxFailureKind, KdbxLimitDetail, KdbxLimitParameter};
use crate::limits::KdbxReadLimits;

pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}
pub(crate) fn sha512(data: &[u8]) -> [u8; 64] {
    Sha512::digest(data).into()
}

pub(crate) fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; 32], KdbxError> {
    hmac_sha256_parts(key, &[data])
}

pub(crate) fn hmac_sha256_parts(key: &[u8], parts: &[&[u8]]) -> Result<[u8; 32], KdbxError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| KdbxError::malformed("invalid HMAC key"))?;
    for part in parts {
        mac.update(part);
    }
    Ok(mac.finalize().into_bytes().into())
}

pub(crate) fn aes_kdf(
    composite: &[u8],
    seed: &[u8],
    rounds: u64,
    limits: &KdbxReadLimits,
) -> Result<[u8; 32], KdbxError> {
    if composite.len() != 32 || seed.len() != 32 {
        return Err(KdbxError::malformed(
            "AES-KDF key and seed must be 32 bytes",
        ));
    }
    if rounds == 0 || rounds > limits.max_aes_kdf_rounds {
        return Err(KdbxError::resource_limit(
            "AES-KDF rounds exceed the configured limit",
        ));
    }
    let cipher =
        Aes256::new_from_slice(seed).map_err(|_| KdbxError::malformed("invalid AES-KDF seed"))?;
    let mut block = *<&[u8; 32]>::try_from(composite).expect("length checked");
    for _ in 0..rounds {
        let mut first = [0; 16];
        let mut second = [0; 16];
        first.copy_from_slice(&block[..16]);
        second.copy_from_slice(&block[16..]);
        let mut first_block = aes::cipher::Block::<Aes256>::from(first);
        let mut second_block = aes::cipher::Block::<Aes256>::from(second);
        cipher.encrypt_block(&mut first_block);
        cipher.encrypt_block(&mut second_block);
        block[..16].copy_from_slice(&first_block);
        block[16..].copy_from_slice(&second_block);
    }
    let result = sha256(&block);
    block.zeroize();
    Ok(result)
}

// Overflow is refused even when the ceiling is u64::MAX.
fn argon2_work(memory_kib: u64, time: u64, maximum: u64) -> Result<u64, KdbxLimitDetail> {
    let work = memory_kib.checked_mul(time);
    match work {
        Some(actual) if actual <= maximum => Ok(actual),
        _ => Err(KdbxLimitDetail {
            parameter: KdbxLimitParameter::Argon2Work,
            actual: work.unwrap_or(u64::MAX),
            maximum,
        }),
    }
}

pub(crate) fn validate_argon2_limits(
    memory_kib: u32,
    time: u32,
    lanes: u32,
    limits: &KdbxReadLimits,
) -> Result<(), KdbxLimitDetail> {
    for (parameter, actual, maximum) in [
        (
            KdbxLimitParameter::Argon2Memory,
            memory_kib,
            limits.max_argon2_memory_kib,
        ),
        (KdbxLimitParameter::Argon2Time, time, limits.max_argon2_time),
        (
            KdbxLimitParameter::Argon2Lanes,
            lanes,
            limits.max_argon2_lanes,
        ),
    ] {
        if actual > maximum {
            return Err(KdbxLimitDetail {
                parameter,
                actual: u64::from(actual),
                maximum: u64::from(maximum),
            });
        }
    }
    argon2_work(
        u64::from(memory_kib),
        u64::from(time),
        limits.max_argon2_work_kib_passes,
    )?;
    Ok(())
}

pub(crate) fn argon2(
    composite: &[u8],
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
    argon2id: bool,
    limits: &KdbxReadLimits,
) -> Result<[u8; 32], KdbxError> {
    if salt.is_empty() || iterations == 0 || memory_kib == 0 || lanes == 0 {
        return Err(KdbxError::malformed("invalid Argon2 parameters"));
    }
    validate_argon2_limits(memory_kib, iterations, lanes, limits)
        .map_err(KdbxError::argon2_limit)?;
    let algorithm = if argon2id {
        argon2::Algorithm::Argon2id
    } else {
        argon2::Algorithm::Argon2d
    };
    let params = argon2::Params::new(memory_kib, iterations, lanes, Some(32))
        .map_err(|_| KdbxError::malformed("invalid Argon2 parameters"))?;
    let argon = argon2::Argon2::new(algorithm, argon2::Version::V0x13, params);
    let mut output = [0; 32];
    argon
        .hash_password_into(composite, salt, &mut output)
        .map_err(|_| KdbxError::malformed("Argon2 derivation failed"))?;
    Ok(output)
}

#[cfg(test)]
mod argon2_tests {
    use super::*;

    #[test]
    fn work_overflow_is_refused() {
        assert_eq!(argon2_work(u64::MAX, 1, u64::MAX), Ok(u64::MAX));
        assert_eq!(
            argon2_work(u64::MAX, 2, u64::MAX),
            Err(KdbxLimitDetail {
                parameter: KdbxLimitParameter::Argon2Work,
                actual: u64::MAX,
                maximum: u64::MAX,
            })
        );
    }

    #[test]
    fn work_is_checked_before_params_and_hashing() {
        let limits = KdbxReadLimits {
            max_argon2_memory_kib: u32::MAX,
            max_argon2_time: u32::MAX,
            max_argon2_lanes: u32::MAX,
            max_argon2_work_kib_passes: 1,
            ..KdbxReadLimits::default()
        };
        for id in [false, true] {
            // Invalid memory/lanes would fail Params::new; the work error comes first.
            let error = argon2(&[0; 32], b"salt", 1, 2, 64, id, &limits).unwrap_err();
            assert_eq!(
                error.limit_detail().unwrap().parameter,
                KdbxLimitParameter::Argon2Work
            );
            // This request must be refused without allocating memory or hashing.
            let error = argon2(&[0; 32], b"salt", u32::MAX, u32::MAX, 1, id, &limits).unwrap_err();
            assert_eq!(
                error.limit_detail().unwrap().actual,
                u64::from(u32::MAX).pow(2)
            );
        }
    }
}

pub(crate) fn aes_cbc_decrypt(
    key: &[u8; 32],
    iv: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, KdbxError> {
    if iv.len() != 16 || data.is_empty() || data.len() % 16 != 0 {
        return Err(KdbxError::malformed("invalid AES-CBC input"));
    }
    let cipher =
        Aes256::new_from_slice(key).map_err(|_| KdbxError::malformed("invalid AES key"))?;
    let decryptor = cbc::Decryptor::<Aes256>::inner_iv_slice_init(cipher, iv)
        .map_err(|_| KdbxError::malformed("invalid AES-CBC IV"))?;
    let mut output = vec![0; data.len()];
    let length = decryptor
        .decrypt_padded_b2b::<Pkcs7>(data, &mut output)
        .map_err(|_| {
            KdbxError::new(
                KdbxFailureKind::Authentication,
                "AES-CBC padding is invalid",
            )
        })?
        .len();
    output.truncate(length);
    Ok(output)
}

pub(crate) fn aes_cbc_encrypt(
    key: &[u8; 32],
    iv: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, KdbxError> {
    if iv.len() != 16 {
        return Err(KdbxError::malformed("invalid AES-CBC IV"));
    }
    let cipher =
        Aes256::new_from_slice(key).map_err(|_| KdbxError::malformed("invalid AES key"))?;
    let encryptor = cbc::Encryptor::<Aes256>::inner_iv_slice_init(cipher, iv)
        .map_err(|_| KdbxError::malformed("invalid AES-CBC IV"))?;
    let mut output = vec![0; data.len() + 16];
    let length = encryptor
        .encrypt_padded_b2b::<Pkcs7>(data, &mut output)
        .map_err(|_| KdbxError::malformed("AES-CBC encryption failed"))?
        .len();
    output.truncate(length);
    Ok(output)
}

pub(crate) fn chacha20_transform(
    key: &[u8],
    nonce: &[u8],
    data: &mut [u8],
) -> Result<(), KdbxError> {
    if key.len() != 32 || nonce.len() != 12 {
        return Err(KdbxError::malformed(
            "ChaCha20 requires a 32-byte key and 12-byte nonce",
        ));
    }
    let mut cipher = ChaCha20::new_from_slices(key, nonce)
        .map_err(|_| KdbxError::malformed("invalid ChaCha20 material"))?;
    cipher.apply_keystream(data);
    Ok(())
}

pub(crate) enum InnerCipher {
    Salsa20(Box<StreamCipherCoreWrapper<SalsaCore<salsa20::cipher::consts::U10>>>),
    ChaCha20(Box<ChaCha20>),
}

impl InnerCipher {
    pub(crate) fn new(id: u32, key: &[u8]) -> Result<Self, KdbxError> {
        match id {
            2 => {
                let key = Zeroizing::new(sha256(key));
                let nonce = [0xe8, 0x30, 0x09, 0x4b, 0x97, 0x20, 0x5d, 0x2a];
                let cipher = salsa20::SalsaCore::<salsa20::cipher::consts::U10>::new_from_slices(
                    &key[..],
                    &nonce,
                )
                .map_err(|_| KdbxError::malformed("invalid Salsa20 inner key"))?;
                Ok(Self::Salsa20(Box::new(StreamCipherCoreWrapper::from_core(
                    cipher,
                ))))
            }
            3 => {
                let material = Zeroizing::new(sha512(key));
                let cipher = ChaCha20::new_from_slices(&material[..32], &material[32..44])
                    .map_err(|_| KdbxError::malformed("invalid ChaCha20 inner key"))?;
                Ok(Self::ChaCha20(Box::new(cipher)))
            }
            _ => Err(KdbxError::unsupported(
                "unsupported KDBX inner random stream",
            )),
        }
    }

    pub(crate) fn transform(&mut self, data: &mut [u8]) {
        match self {
            Self::Salsa20(cipher) => cipher.apply_keystream(data),
            Self::ChaCha20(cipher) => cipher.apply_keystream(data),
        }
    }

    pub(crate) fn advance(&mut self, length: usize) {
        match self {
            Self::Salsa20(cipher) => cipher.seek(length as u64),
            Self::ChaCha20(cipher) => cipher.seek(length as u64),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::InnerCipher;

    #[test]
    fn advancing_after_a_protected_value_matches_stream_continuation() {
        let key = [7u8; 64];
        let first = b"protected attachment";
        let second = b"protected password";
        let mut expected = InnerCipher::new(2, &key).unwrap();
        let mut expected_first = first.to_vec();
        expected.transform(&mut expected_first);
        let mut expected_second = second.to_vec();
        expected.transform(&mut expected_second);

        let mut parsed = InnerCipher::new(2, &key).unwrap();
        let mut parsed_first = first.to_vec();
        parsed.transform(&mut parsed_first);
        parsed.advance(first.len());
        let mut parsed_second = second.to_vec();
        parsed.transform(&mut parsed_second);
        assert_eq!(parsed_first, expected_first);
        assert_eq!(parsed_second, expected_second);
    }
}
