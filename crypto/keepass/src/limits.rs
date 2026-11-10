/// Bounds applied while reading untrusted KDBX data.
///
/// These defaults are intentionally finite. Callers may lower them for
/// services processing attacker-controlled vaults, or raise them for trusted
/// local files while retaining the checks. Every limit is checked before the
/// corresponding attacker-controlled allocation or KDF work begins.
///
/// The default is suitable as a conservative library baseline, not a service
/// policy. A caller accepting hostile input should choose a budget for input,
/// header, KDF, block, decompression, XML, and binary-pool resources and pass
/// the same policy to load and save.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KdbxReadLimits {
    /// Maximum complete KDBX input size.
    pub max_input_bytes: u64,
    /// Maximum encoded outer-header size.
    pub max_header_bytes: usize,
    /// Maximum AES-KDF rounds.
    pub max_aes_kdf_rounds: u64,
    /// Maximum Argon2 memory in kibibytes.
    pub max_argon2_memory_kib: u32,
    /// Maximum Argon2 time cost.
    pub max_argon2_time: u32,
    /// Maximum Argon2 lanes/parallelism.
    pub max_argon2_lanes: u32,
    /// Maximum Argon2 work: total memory in KiB multiplied by passes, not lanes.
    pub max_argon2_work_kib_passes: u64,
    /// Maximum decoded payload size before XML parsing.
    pub max_decompressed_bytes: u64,
    /// Maximum KDBX3/4 block count.
    pub max_blocks: u64,
    /// Maximum individual authenticated block size.
    pub max_block_bytes: usize,
    /// Maximum XML character count.
    pub max_xml_chars: u64,
    /// Maximum XML nesting depth.
    pub max_xml_depth: usize,
    /// Maximum binary-pool bytes and attachment bytes.
    pub max_binary_bytes: u64,
    /// Maximum number of binary-pool records.
    pub max_binary_records: usize,
}

impl Default for KdbxReadLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 64 * 1024 * 1024,
            max_header_bytes: 1024 * 1024,
            max_aes_kdf_rounds: 100_000_000,
            max_argon2_memory_kib: 1_048_576,
            max_argon2_time: 4096,
            max_argon2_lanes: 64,
            max_argon2_work_kib_passes: 16_777_216,
            max_decompressed_bytes: 64 * 1024 * 1024,
            max_blocks: 1 << 20,
            max_block_bytes: 1024 * 1024,
            max_xml_chars: 64 * 1024 * 1024,
            max_xml_depth: 256,
            max_binary_bytes: 64 * 1024 * 1024,
            max_binary_records: 1 << 20,
        }
    }
}

impl KdbxReadLimits {
    /// Validates that all limits are non-zero and internally coherent.
    ///
    /// # Errors
    ///
    /// Returns an error when a limit is zero or a maximum is below the
    /// required KDBX primitive size.
    pub fn validate(&self) -> Result<(), crate::KdbxError> {
        if self.max_input_bytes == 0
            || self.max_header_bytes < 12
            || self.max_aes_kdf_rounds == 0
            || self.max_argon2_memory_kib == 0
            || self.max_argon2_time == 0
            || self.max_argon2_lanes == 0
            || self.max_argon2_work_kib_passes == 0
            || self.max_decompressed_bytes == 0
            || self.max_blocks == 0
            || self.max_block_bytes < 32
            || self.max_xml_chars == 0
            || self.max_xml_depth == 0
            || self.max_binary_bytes == 0
            || self.max_binary_records == 0
        {
            return Err(crate::KdbxError::new(
                crate::KdbxFailureKind::InvalidArgument,
                "KDBX resource limits must be non-zero and primitive-safe",
            ));
        }
        Ok(())
    }
}
