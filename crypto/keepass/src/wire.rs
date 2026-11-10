use std::collections::BTreeMap;

use zeroize::{Zeroize, Zeroizing};

use crate::crypto;
use crate::error::{KdbxError, KdbxFailureKind};
use crate::limits::KdbxReadLimits;
use crate::model::{VariantDictionary, VariantValue};
const SIGNATURE_1: u32 = 0x9aa2_d903;
const SIGNATURE_2: u32 = 0xb54b_fb67;
const VERSION_41: u32 = 0x0004_0001;
const AES_CIPHER: [u8; 16] = [
    0x31, 0xc1, 0xf2, 0xe6, 0xbf, 0x71, 0x43, 0x50, 0xbe, 0x58, 0x05, 0x21, 0x6a, 0xfc, 0x5a, 0xff,
];
const CHACHA_CIPHER: [u8; 16] = [
    0xd6, 0x03, 0x8a, 0x2b, 0x8b, 0x6f, 0x4c, 0xb5, 0xa5, 0x24, 0x33, 0x9a, 0x31, 0xdb, 0xb5, 0x9a,
];
const AES_KDF: [u8; 16] = [
    0xc9, 0xd9, 0xf3, 0x9a, 0x62, 0x8a, 0x44, 0x60, 0xbf, 0x74, 0x0d, 0x08, 0xc1, 0x8a, 0x4f, 0xea,
];
const ARGON2D: [u8; 16] = [
    0xef, 0x63, 0x6d, 0xdf, 0x8c, 0x29, 0x44, 0x4b, 0x91, 0xf7, 0xa9, 0xa4, 0x03, 0xe3, 0x0a, 0x0c,
];
const ARGON2ID: [u8; 16] = [
    0x9e, 0x29, 0x8b, 0x19, 0x56, 0xdb, 0x47, 0x73, 0xb2, 0x3d, 0xfc, 0x3e, 0xc6, 0xf0, 0xa1, 0xe6,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OuterCipher {
    Aes,
    ChaCha20,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Compression {
    None,
    GZip,
}

#[derive(Clone, Debug)]
pub(crate) enum KdfSpec {
    Aes {
        seed: Vec<u8>,
        rounds: u64,
    },
    Argon2 {
        argon2id: bool,
        salt: Vec<u8>,
        memory: u32,
        iterations: u32,
        lanes: u32,
    },
}

#[derive(Clone, Debug)]
pub(crate) struct OuterHeader {
    pub version: u32,
    pub cipher: OuterCipher,
    pub compression: Compression,
    pub master_seed: Vec<u8>,
    pub iv: Vec<u8>,
    pub kdf: KdfSpec,
    pub inner_stream_key: Option<Vec<u8>>,
    pub stream_start: Option<Vec<u8>>,
    pub inner_stream_id: Option<u32>,
    pub public_custom_data: Option<VariantDictionary>,
    pub has_unknown_fields: bool,
    pub raw: Vec<u8>,
}

impl Drop for OuterHeader {
    fn drop(&mut self) {
        if let Some(stream_key) = &mut self.inner_stream_key {
            stream_key.zeroize();
        }
    }
}

pub(crate) fn parse_header(
    data: &[u8],
    limits: &KdbxReadLimits,
) -> Result<(OuterHeader, usize), KdbxError> {
    if data.len() < 12
        || u32::from_le_bytes(data[0..4].try_into().expect("checked")) != SIGNATURE_1
        || u32::from_le_bytes(data[4..8].try_into().expect("checked")) != SIGNATURE_2
    {
        return Err(KdbxError::malformed("invalid KDBX signatures"));
    }
    let version = u32::from_le_bytes(data[8..12].try_into().expect("checked"));
    let major = version >> 16;
    if !((major == 3 && (version == 0x0003_0000 || version == 0x0003_0001))
        || (major == 4 && (version == 0x0004_0000 || version == VERSION_41)))
    {
        return Err(KdbxError::unsupported("unsupported KDBX version"));
    }
    let length_width = if major == 3 { 2 } else { 4 };
    let mut offset = 12;
    let mut fields = BTreeMap::new();
    loop {
        if offset >= data.len() {
            return Err(KdbxError::truncated());
        }
        let id = data[offset];
        offset += 1;
        if offset + length_width > data.len() {
            return Err(KdbxError::truncated());
        }
        let length = if length_width == 2 {
            u16::from_le_bytes(data[offset..offset + 2].try_into().expect("checked")) as usize
        } else {
            i32::from_le_bytes(data[offset..offset + 4].try_into().expect("checked")) as usize
        };
        offset += length_width;
        if length > limits.max_header_bytes || offset + length > data.len() {
            return Err(KdbxError::resource_limit(
                "KDBX outer header field exceeds the configured limit",
            ));
        }
        let value = &data[offset..offset + length];
        offset += length;
        if id == 0 {
            if major == 4 && value != [13, 10, 13, 10] {
                return Err(KdbxError::malformed("invalid KDBX header terminator"));
            }
            if major == 3 && !value.is_empty() && value != [13, 10, 13, 10] {
                return Err(KdbxError::malformed("invalid KDBX header terminator"));
            }
            break;
        }
        if fields.insert(id, value.to_vec()).is_some() {
            return Err(KdbxError::malformed("duplicate KDBX header field"));
        }
        if offset > limits.max_header_bytes {
            return Err(KdbxError::resource_limit(
                "KDBX header exceeds the configured limit",
            ));
        }
    }
    let cipher = match fields.remove(&2).as_deref() {
        Some(value) if value == AES_CIPHER => OuterCipher::Aes,
        Some(value) if value == CHACHA_CIPHER && major == 4 => OuterCipher::ChaCha20,
        _ => return Err(KdbxError::unsupported("unsupported KDBX cipher")),
    };
    let compression = match fields.remove(&3).as_deref() {
        Some(value) if value.len() == 4 && value[0] == 0 => Compression::None,
        Some(value) if value.len() == 4 && value[0] == 1 && value[1..] == [0, 0, 0] => {
            Compression::GZip
        }
        _ => return Err(KdbxError::unsupported("unsupported KDBX compression")),
    };
    let master_seed = fields
        .remove(&4)
        .ok_or_else(|| KdbxError::malformed("missing KDBX master seed"))?;
    if master_seed.len() != 32 {
        return Err(KdbxError::malformed("KDBX master seed must be 32 bytes"));
    }
    let iv = fields
        .remove(&7)
        .ok_or_else(|| KdbxError::malformed("missing KDBX encryption IV"))?;
    if iv.len() != if cipher == OuterCipher::Aes { 16 } else { 12 } {
        return Err(KdbxError::malformed("invalid KDBX encryption IV length"));
    }
    let kdf = if major == 3 {
        let seed = fields
            .remove(&5)
            .ok_or_else(|| KdbxError::malformed("missing KDBX transform seed"))?;
        let rounds = fields
            .remove(&6)
            .ok_or_else(|| KdbxError::malformed("missing KDBX transform rounds"))?;
        if seed.len() != 32 || rounds.len() != 8 {
            return Err(KdbxError::malformed("invalid KDBX AES-KDF fields"));
        }
        KdfSpec::Aes {
            seed,
            rounds: u64::from_le_bytes(rounds.try_into().expect("checked")),
        }
    } else {
        let kdf_data = fields
            .remove(&11)
            .ok_or_else(|| KdbxError::malformed("missing KDBX KDF parameters"))?;
        parse_kdf(&kdf_data)?
    };
    let has_obsolete_inner_fields =
        major == 4 && [8, 9, 10].iter().any(|id| fields.contains_key(id));
    let inner_stream_key = fields.remove(&8);
    let stream_start = fields.remove(&9);
    let inner_stream_id = fields
        .remove(&10)
        .map(|value| {
            if value.len() == 4 {
                Some(u32::from_le_bytes(value.try_into().expect("checked")))
            } else {
                None
            }
        })
        .unwrap_or(None);
    if major == 3
        && (inner_stream_key.is_none() || stream_start.is_none() || inner_stream_id.is_none())
    {
        return Err(KdbxError::malformed(
            "KDBX 3 inner stream header is incomplete",
        ));
    }
    if major == 3
        && (inner_stream_key
            .as_ref()
            .is_none_or(|value| value.len() != 32)
            || stream_start.as_ref().is_none_or(|value| value.len() != 32))
    {
        return Err(KdbxError::malformed(
            "KDBX 3 inner stream fields must be 32 bytes",
        ));
    }
    let public_custom_data = if major == 4 {
        fields
            .remove(&12)
            .map(|data| parse_variant_dictionary(&data))
            .transpose()?
    } else {
        None
    };
    Ok((
        OuterHeader {
            version,
            cipher,
            compression,
            master_seed,
            iv,
            kdf,
            inner_stream_key,
            stream_start,
            inner_stream_id,
            public_custom_data,
            has_unknown_fields: has_obsolete_inner_fields || !fields.is_empty(),
            raw: data[..offset].to_vec(),
        },
        offset,
    ))
}

fn parse_kdf(data: &[u8]) -> Result<KdfSpec, KdbxError> {
    if data.len() < 3 || u16::from_le_bytes(data[0..2].try_into().expect("checked")) != 0x0100 {
        return Err(KdbxError::malformed("invalid KDBX KDF dictionary"));
    }
    let mut offset = 2;
    let mut values = BTreeMap::new();
    let mut terminated = false;
    while offset < data.len() {
        let kind = data[offset];
        offset += 1;
        if kind == 0 {
            if offset != data.len() {
                return Err(KdbxError::malformed("data follows KDBX KDF terminator"));
            }
            terminated = true;
            break;
        }
        let key = read_value(data, &mut offset)?;
        let value = read_value(data, &mut offset)?;
        if values
            .insert(
                String::from_utf8(key.to_vec())
                    .map_err(|_| KdbxError::malformed("KDF key is not UTF-8"))?,
                (kind, value.to_vec()),
            )
            .is_some()
        {
            return Err(KdbxError::malformed("duplicate KDF parameter"));
        }
    }
    if !terminated {
        return Err(KdbxError::malformed("unterminated KDBX KDF dictionary"));
    }
    let uuid = bytes_value(&values, "$UUID", 0x42)?;
    if uuid == AES_KDF {
        let seed = bytes_value(&values, "S", 0x42)?;
        let rounds = u64_value(&values, "R", 0x05)?;
        if seed.len() != 32 {
            return Err(KdbxError::malformed("invalid AES-KDF seed"));
        }
        return Ok(KdfSpec::Aes { seed, rounds });
    }
    if uuid == ARGON2D || uuid == ARGON2ID {
        let salt = bytes_value(&values, "S", 0x42)?;
        let memory = u64_value(&values, "M", 0x05)?;
        let iterations = u64_value(&values, "I", 0x05)?;
        let lanes = u32::from(u32_value(&values, "P", 0x04)?);
        let version = u32_value(&values, "V", 0x04)?;
        if version != 0x13
            || memory % 1024 != 0
            || memory / 1024 > u32::MAX as u64
            || iterations > u32::MAX as u64
        {
            return Err(KdbxError::malformed("invalid Argon2 KDF parameters"));
        }
        return Ok(KdfSpec::Argon2 {
            argon2id: uuid == ARGON2ID,
            salt,
            memory: (memory / 1024) as u32,
            iterations: iterations as u32,
            lanes,
        });
    }
    Err(KdbxError::unsupported("unsupported KDBX KDF"))
}

fn read_value<'a>(data: &'a [u8], offset: &mut usize) -> Result<&'a [u8], KdbxError> {
    if *offset + 4 > data.len() {
        return Err(KdbxError::truncated());
    }
    let length = i32::from_le_bytes(data[*offset..*offset + 4].try_into().expect("checked"));
    *offset += 4;
    if length < 0 || *offset + length as usize > data.len() {
        return Err(KdbxError::malformed("invalid KDBX KDF value length"));
    }
    let value = &data[*offset..*offset + length as usize];
    *offset += length as usize;
    Ok(value)
}
fn bytes_value(
    values: &BTreeMap<String, (u8, Vec<u8>)>,
    name: &str,
    kind: u8,
) -> Result<Vec<u8>, KdbxError> {
    values
        .get(name)
        .filter(|(actual, _)| *actual == kind)
        .map(|(_, value)| value.clone())
        .ok_or_else(|| KdbxError::malformed(format!("missing KDF parameter {name}")))
}
fn u64_value(
    values: &BTreeMap<String, (u8, Vec<u8>)>,
    name: &str,
    kind: u8,
) -> Result<u64, KdbxError> {
    let value = bytes_value(values, name, kind)?;
    value
        .try_into()
        .map(u64::from_le_bytes)
        .map_err(|_| KdbxError::malformed(format!("invalid KDF parameter {name}")))
}
fn u32_value(
    values: &BTreeMap<String, (u8, Vec<u8>)>,
    name: &str,
    kind: u8,
) -> Result<u32, KdbxError> {
    let value = bytes_value(values, name, kind)?;
    value
        .try_into()
        .map(u32::from_le_bytes)
        .map_err(|_| KdbxError::malformed(format!("invalid KDF parameter {name}")))
}

pub(crate) fn derive_key(
    header: &OuterHeader,
    composite: &[u8],
    limits: &KdbxReadLimits,
) -> Result<([u8; 32], [u8; 64]), KdbxError> {
    let transformed = Zeroizing::new(match &header.kdf {
        KdfSpec::Aes { seed, rounds } => crypto::aes_kdf(composite, seed, *rounds, limits)?,
        KdfSpec::Argon2 {
            argon2id,
            salt,
            memory,
            iterations,
            lanes,
        } => crypto::argon2(
            composite,
            salt,
            *memory,
            *iterations,
            *lanes,
            *argon2id,
            limits,
        )?,
    });
    let mut cipher_input = header.master_seed.clone();
    cipher_input.extend_from_slice(&transformed[..]);
    let cipher_key = crypto::sha256(&cipher_input);
    cipher_input.zeroize();
    let mut hmac_input = header.master_seed.clone();
    hmac_input.extend_from_slice(&transformed[..]);
    hmac_input.push(1);
    let base_hmac = crypto::sha512(&hmac_input);
    hmac_input.zeroize();
    Ok((cipher_key, base_hmac))
}

pub(crate) fn read_hmac_blocks(
    data: &[u8],
    base_key: &[u8; 64],
    limits: &KdbxReadLimits,
) -> Result<Vec<u8>, KdbxError> {
    let mut offset = 0;
    let mut index = 0;
    let mut output = Vec::new();
    loop {
        if offset + 36 > data.len() {
            return Err(KdbxError::truncated());
        }
        let tag = &data[offset..offset + 32];
        let length = u32::from_le_bytes(data[offset + 32..offset + 36].try_into().expect("checked"))
            as usize;
        offset += 36;
        if length > limits.max_block_bytes {
            return Err(KdbxError::resource_limit(
                "KDBX block exceeds the configured limit",
            ));
        }
        if index >= limits.max_blocks || offset + length > data.len() {
            return Err(KdbxError::malformed("truncated KDBX block"));
        }
        let block = &data[offset..offset + length];
        offset += length;
        let expected = block_tag(index, length, block, base_key)?;
        if !constant_time_equal(tag, &expected) {
            return Err(KdbxError::new(
                KdbxFailureKind::Authentication,
                "KDBX payload HMAC validation failed",
            ));
        }
        if length == 0 {
            if offset != data.len() {
                return Err(KdbxError::malformed("trailing KDBX block data"));
            }
            return Ok(output);
        }
        if output.len() as u64 + length as u64 > limits.max_decompressed_bytes {
            return Err(KdbxError::resource_limit(
                "KDBX payload exceeds the configured limit",
            ));
        }
        output.extend_from_slice(block);
        index += 1;
    }
}

pub(crate) fn read_hashed_blocks(
    data: &[u8],
    limits: &KdbxReadLimits,
) -> Result<Vec<u8>, KdbxError> {
    let mut offset = 0;
    let mut expected_index = 0u32;
    let mut output = Vec::new();
    loop {
        if offset + 40 > data.len() {
            return Err(KdbxError::truncated());
        }
        let index = u32::from_le_bytes(data[offset..offset + 4].try_into().expect("checked"));
        let hash = &data[offset + 4..offset + 36];
        let length =
            i32::from_le_bytes(data[offset + 36..offset + 40].try_into().expect("checked"));
        offset += 40;
        if index != expected_index || length < 0 || length as usize > limits.max_block_bytes {
            return Err(KdbxError::malformed("invalid KDBX hashed block header"));
        }
        let length = length as usize;
        if length == 0 {
            if hash.iter().any(|byte| *byte != 0) {
                return Err(KdbxError::malformed("invalid KDBX hashed terminal block"));
            }
            if offset != data.len() {
                return Err(KdbxError::malformed("trailing KDBX hashed block data"));
            }
            return Ok(output);
        }
        if u64::from(expected_index) >= limits.max_blocks {
            return Err(KdbxError::resource_limit(
                "KDBX block count exceeds the configured limit",
            ));
        }
        if offset + length > data.len() {
            return Err(KdbxError::truncated());
        }
        let block = &data[offset..offset + length];
        offset += length;
        if !constant_time_equal(hash, &crypto::sha256(block)) {
            return Err(KdbxError::new(
                KdbxFailureKind::Authentication,
                "KDBX hashed block checksum validation failed",
            ));
        }
        if output.len() as u64 + length as u64 > limits.max_decompressed_bytes {
            return Err(KdbxError::resource_limit(
                "KDBX payload exceeds the configured limit",
            ));
        }
        output.extend_from_slice(block);
        expected_index = expected_index
            .checked_add(1)
            .ok_or_else(|| KdbxError::malformed("KDBX block index overflow"))?;
    }
}

pub(crate) fn write_hashed_blocks(
    data: &[u8],
    block_size: usize,
    limits: &KdbxReadLimits,
) -> Result<Vec<u8>, KdbxError> {
    if block_size == 0 || block_size > limits.max_block_bytes {
        return Err(KdbxError::new(
            KdbxFailureKind::InvalidArgument,
            "invalid KDBX block size",
        ));
    }
    if data.len() as u64 > limits.max_decompressed_bytes {
        return Err(KdbxError::resource_limit(
            "KDBX payload exceeds the decompression limit",
        ));
    }
    let mut output = Vec::new();
    let mut index = 0u32;
    for block in data.chunks(block_size) {
        if u64::from(index) >= limits.max_blocks {
            return Err(KdbxError::resource_limit(
                "KDBX block count exceeds the configured limit",
            ));
        }
        write_hashed_block(&mut output, index, block)?;
        index = index
            .checked_add(1)
            .ok_or_else(|| KdbxError::malformed("KDBX block index overflow"))?;
    }
    write_hashed_block(&mut output, index, &[])?;
    Ok(output)
}

fn write_hashed_block(output: &mut Vec<u8>, index: u32, block: &[u8]) -> Result<(), KdbxError> {
    output.extend_from_slice(&index.to_le_bytes());
    if block.is_empty() {
        output.extend_from_slice(&[0; 32]);
    } else {
        output.extend_from_slice(&crypto::sha256(block));
    }
    let length = u32::try_from(block.len())
        .map_err(|_| KdbxError::resource_limit("KDBX block is too large"))?;
    output.extend_from_slice(&length.to_le_bytes());
    output.extend_from_slice(block);
    Ok(())
}

pub(crate) fn write_hmac_blocks(
    data: &[u8],
    base_key: &[u8; 64],
    block_size: usize,
    limits: &KdbxReadLimits,
) -> Result<Vec<u8>, KdbxError> {
    if block_size == 0 || block_size > limits.max_block_bytes {
        return Err(KdbxError::new(
            KdbxFailureKind::InvalidArgument,
            "invalid KDBX block size",
        ));
    }
    let mut output = Vec::new();
    let mut index = 0;
    for block in data.chunks(block_size) {
        if index >= limits.max_blocks {
            return Err(KdbxError::resource_limit(
                "KDBX block count exceeds the configured limit",
            ));
        }
        write_block(&mut output, index, block, base_key)?;
        index += 1;
    }
    write_block(&mut output, index, &[], base_key)?;
    Ok(output)
}

fn write_block(
    output: &mut Vec<u8>,
    index: u64,
    block: &[u8],
    base_key: &[u8; 64],
) -> Result<(), KdbxError> {
    let tag = block_tag(index, block.len(), block, base_key)?;
    output.extend_from_slice(&tag);
    output.extend_from_slice(&(block.len() as u32).to_le_bytes());
    output.extend_from_slice(block);
    Ok(())
}

pub(crate) fn header_hmac(header: &[u8], base_key: &[u8; 64]) -> Result<[u8; 32], KdbxError> {
    let mut key_input = Vec::with_capacity(8 + base_key.len());
    key_input.extend_from_slice(&u64::MAX.to_le_bytes());
    key_input.extend_from_slice(base_key);
    let key = Zeroizing::new(crypto::sha512(&key_input));
    key_input.zeroize();
    crypto::hmac_sha256(&key[..], header)
}

pub(crate) fn aes_kdf_dictionary(seed: &[u8; 32], rounds: u64) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(&0x0100u16.to_le_bytes());
    output.push(0x42);
    write_value(&mut output, b"$UUID");
    write_value(&mut output, &AES_KDF);
    output.push(0x42);
    write_value(&mut output, b"S");
    write_value(&mut output, seed);
    output.push(0x05);
    write_value(&mut output, b"R");
    write_value(&mut output, &rounds.to_le_bytes());
    output.push(0);
    output
}

/// Serializes the Argon2d/id KDF dictionary used by KDBX 4.
pub(crate) fn argon2_kdf_dictionary(
    argon2id: bool,
    salt: &[u8; 32],
    memory_kib: u32,
    iterations: u32,
    lanes: u32,
) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(&0x0100u16.to_le_bytes());
    output.push(0x42);
    write_value(&mut output, b"$UUID");
    write_value(&mut output, if argon2id { &ARGON2ID } else { &ARGON2D });
    output.push(0x42);
    write_value(&mut output, b"S");
    write_value(&mut output, salt);
    output.push(0x05);
    write_value(&mut output, b"M");
    write_value(&mut output, &(u64::from(memory_kib) * 1024).to_le_bytes());
    output.push(0x05);
    write_value(&mut output, b"I");
    write_value(&mut output, &u64::from(iterations).to_le_bytes());
    output.push(0x04);
    write_value(&mut output, b"P");
    write_value(&mut output, &lanes.to_le_bytes());
    output.push(0x04);
    write_value(&mut output, b"V");
    write_value(&mut output, &0x13u32.to_le_bytes());
    output.push(0);
    output
}

fn parse_variant_dictionary(data: &[u8]) -> Result<VariantDictionary, KdbxError> {
    if data.len() < 3 {
        return Err(KdbxError::malformed("invalid KDBX variant dictionary"));
    }
    let version = u16::from_le_bytes(data[0..2].try_into().expect("checked"));
    if version >> 8 != 1 {
        return Err(KdbxError::unsupported(
            "unsupported KDBX variant-dictionary version",
        ));
    }
    let mut offset = 2;
    let mut output = VariantDictionary::default();
    let mut terminated = false;
    while offset < data.len() {
        let kind = data[offset];
        offset += 1;
        if kind == 0 {
            if offset != data.len() {
                return Err(KdbxError::malformed(
                    "data follows KDBX variant-dictionary terminator",
                ));
            }
            terminated = true;
            break;
        }
        let key = read_value(data, &mut offset)?;
        let key = std::str::from_utf8(key)
            .map_err(|_| KdbxError::malformed("variant-dictionary key is not UTF-8"))?
            .to_owned();
        let value = read_value(data, &mut offset)?;
        let value = match kind {
            0x04 => VariantValue::UInt32(
                value
                    .try_into()
                    .map(u32::from_le_bytes)
                    .map_err(|_| KdbxError::malformed("invalid UInt32 variant"))?,
            ),
            0x05 => VariantValue::UInt64(
                value
                    .try_into()
                    .map(u64::from_le_bytes)
                    .map_err(|_| KdbxError::malformed("invalid UInt64 variant"))?,
            ),
            0x08 => match value {
                [0] => VariantValue::Bool(false),
                [1] => VariantValue::Bool(true),
                _ => return Err(KdbxError::malformed("invalid Bool variant")),
            },
            0x0C => VariantValue::Int32(
                value
                    .try_into()
                    .map(i32::from_le_bytes)
                    .map_err(|_| KdbxError::malformed("invalid Int32 variant"))?,
            ),
            0x0D => VariantValue::Int64(
                value
                    .try_into()
                    .map(i64::from_le_bytes)
                    .map_err(|_| KdbxError::malformed("invalid Int64 variant"))?,
            ),
            0x18 => VariantValue::String(
                std::str::from_utf8(value)
                    .map_err(|_| KdbxError::malformed("variant string is not UTF-8"))?
                    .to_owned(),
            ),
            0x42 => VariantValue::Bytes(value.to_vec()),
            _ => {
                return Err(KdbxError::unsupported(
                    "unsupported KDBX public custom-data value type",
                ));
            }
        };
        if output.get(&key).is_some() {
            return Err(KdbxError::malformed(
                "duplicate KDBX public custom-data key",
            ));
        }
        output.set(key, value);
    }
    if !terminated {
        return Err(KdbxError::malformed("unterminated KDBX variant dictionary"));
    }
    Ok(output)
}

pub(crate) fn serialize_variant_dictionary(data: &VariantDictionary) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(&0x0100u16.to_le_bytes());
    for item in data.items() {
        let (kind, value): (u8, &[u8]) = match &item.value {
            VariantValue::UInt32(value) => (0x04, &value.to_le_bytes()),
            VariantValue::UInt64(value) => (0x05, &value.to_le_bytes()),
            VariantValue::Bool(value) => (0x08, &[u8::from(*value)]),
            VariantValue::Int32(value) => (0x0C, &value.to_le_bytes()),
            VariantValue::Int64(value) => (0x0D, &value.to_le_bytes()),
            VariantValue::String(value) => (0x18, value.as_bytes()),
            VariantValue::Bytes(value) => (0x42, value),
        };
        output.push(kind);
        write_value(&mut output, item.key.as_bytes());
        write_value(&mut output, value);
    }
    output.push(0);
    output
}

fn write_value(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as i32).to_le_bytes());
    output.extend_from_slice(value);
}

pub(crate) fn block_tag(
    index: u64,
    length: usize,
    block: &[u8],
    key: &[u8; 64],
) -> Result<[u8; 32], KdbxError> {
    let mut key_input = Vec::with_capacity(8 + key.len());
    key_input.extend_from_slice(&index.to_le_bytes());
    key_input.extend_from_slice(key);
    let block_key = Zeroizing::new(crypto::sha512(&key_input));
    key_input.zeroize();
    let index_bytes = index.to_le_bytes();
    let length_bytes = (length as u32).to_le_bytes();
    crypto::hmac_sha256_parts(&block_key[..], &[&index_bytes, &length_bytes, block])
}
fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0, |diff, (a, b)| diff | (a ^ b))
            == 0
}

pub(crate) struct InnerHeader {
    pub stream_id: u32,
    pub stream_key: Vec<u8>,
    pub binaries: Vec<(Vec<u8>, bool)>,
    pub consumed: usize,
}

impl Drop for InnerHeader {
    fn drop(&mut self) {
        self.stream_key.zeroize();
        for (binary, _) in &mut self.binaries {
            binary.zeroize();
        }
    }
}

impl InnerHeader {
    pub(crate) fn parse(data: &[u8], limits: &KdbxReadLimits) -> Result<Self, KdbxError> {
        let mut offset = 0;
        let mut stream_id = None;
        let mut stream_key = None;
        let mut binaries = Vec::new();
        let mut total_binary_bytes = 0usize;
        loop {
            if offset + 5 > data.len() {
                return Err(KdbxError::truncated());
            }
            let id = data[offset];
            let length =
                i32::from_le_bytes(data[offset + 1..offset + 5].try_into().expect("checked"));
            offset += 5;
            if length < 0
                || length as usize > limits.max_header_bytes
                || offset + length as usize > data.len()
            {
                return Err(KdbxError::malformed("invalid inner-header field length"));
            }
            let value = &data[offset..offset + length as usize];
            offset += length as usize;
            if id == 0 {
                if !value.is_empty() {
                    return Err(KdbxError::malformed("inner-header terminator is not empty"));
                }
                break;
            }
            match id {
                1 => {
                    if value.len() != 4 {
                        return Err(KdbxError::malformed("invalid inner stream ID"));
                    }
                    stream_id = Some(u32::from_le_bytes(value.try_into().expect("checked")));
                }
                2 => stream_key = Some(value.to_vec()),
                3 => {
                    if value.is_empty() {
                        return Err(KdbxError::malformed("empty inner binary"));
                    }
                    if binaries.len() >= limits.max_binary_records {
                        return Err(KdbxError::resource_limit(
                            "inner binary count exceeds the configured limit",
                        ));
                    }
                    total_binary_bytes = total_binary_bytes.saturating_add(value.len() - 1);
                    if total_binary_bytes as u64 > limits.max_binary_bytes {
                        return Err(KdbxError::resource_limit(
                            "inner binary bytes exceed the configured limit",
                        ));
                    }
                    binaries.push((value[1..].to_vec(), value[0] & 1 != 0));
                }
                _ => return Err(KdbxError::unsupported("unsupported inner-header field")),
            }
        }
        Ok(Self {
            stream_id: stream_id.ok_or_else(|| KdbxError::malformed("missing inner stream ID"))?,
            stream_key: stream_key
                .ok_or_else(|| KdbxError::malformed("missing inner stream key"))?,
            binaries,
            consumed: offset,
        })
    }
}

pub(crate) fn parse_xml_payload(
    _payload: &[u8],
    header: &InnerHeader,
    _limits: &KdbxReadLimits,
) -> Result<(Vec<(Vec<u8>, bool)>, usize), KdbxError> {
    let mut stream = crypto::InnerCipher::new(header.stream_id, &header.stream_key)?;
    let mut binaries = Vec::with_capacity(header.binaries.len());
    let mut inner_stream_offset = 0usize;
    for (value, protected) in &header.binaries {
        let mut value = value.clone();
        if *protected {
            stream.transform(&mut value);
            inner_stream_offset = inner_stream_offset.saturating_add(value.len());
        }
        binaries.push((value, *protected));
    }
    Ok((binaries, inner_stream_offset))
}

#[cfg(test)]
mod tests {
    use super::{KdbxFailureKind, KdbxReadLimits, read_hashed_blocks};

    fn hashed_block(index: u32, data: &[u8]) -> Vec<u8> {
        let hash = if data.is_empty() {
            [0; 32]
        } else {
            crate::crypto::sha256(data)
        };
        let mut block = Vec::with_capacity(40 + data.len());
        block.extend_from_slice(&index.to_le_bytes());
        block.extend_from_slice(&hash);
        block.extend_from_slice(&(data.len() as i32).to_le_bytes());
        block.extend_from_slice(data);
        block
    }

    #[test]
    fn hashed_block_reader_enforces_the_nonterminal_block_limit() {
        let mut blocks = hashed_block(0, b"a");
        blocks.extend_from_slice(&hashed_block(1, b"b"));
        blocks.extend_from_slice(&hashed_block(2, b""));
        let limits = KdbxReadLimits {
            max_blocks: 1,
            ..KdbxReadLimits::default()
        };

        let error = read_hashed_blocks(&blocks, &limits).unwrap_err();
        assert_eq!(error.kind, KdbxFailureKind::ResourceLimit);
        assert_eq!(
            error.message,
            "KDBX block count exceeds the configured limit"
        );

        let mut within_limit = hashed_block(0, b"a");
        within_limit.extend_from_slice(&hashed_block(1, b""));
        assert_eq!(read_hashed_blocks(&within_limit, &limits).unwrap(), b"a");
    }
}
