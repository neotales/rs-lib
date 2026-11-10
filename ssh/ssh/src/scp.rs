//! Bounded single-file transfers using the historical SCP/RCP byte protocol.
//!
//! This module only operates on a caller-supplied byte stream.  It does not
//! create a process, open a socket, or send an SSH `exec` request.  The
//! [`upload_command`] and [`download_command`] helpers return command text for
//! the caller to use with its own channel policy.
//!
//! The implementation handles one regular file and deliberately rejects the
//! legacy `D` and `E` directory records.  Header lines and materialized file
//! bodies are bounded before they are parsed or retained.

#![allow(clippy::module_name_repetitions)]

use std::fmt;
use std::io::{self, Read, Write};

/// The maximum number of bytes in one SCP header line, including its newline.
pub const MAX_SCP_HEADER_LINE_SIZE: usize = 8 * 1024;

/// The maximum size of an in-memory SCP file body.
pub const MAX_SCP_FILE_SIZE: usize = 64 * 1024 * 1024;

/// The maximum number of bytes in an SCP file basename.
pub const MAX_SCP_BASENAME_SIZE: usize = 255;

/// The default mode used when an upload does not specify one.
pub const DEFAULT_SCP_MODE: u32 = 0o644;

/// The byte used for a successful SCP acknowledgement.
pub const SCP_ACK: u8 = 0;

/// The byte used by the peer for a non-fatal SCP error.
pub const SCP_PEER_ERROR: u8 = 1;

/// The byte used by the peer for a fatal SCP error.
pub const SCP_FATAL_ERROR: u8 = 2;

/// A short alias for [`MAX_SCP_HEADER_LINE_SIZE`].
pub const MAX_HEADER_LINE_SIZE: usize = MAX_SCP_HEADER_LINE_SIZE;

/// A short alias for [`MAX_SCP_FILE_SIZE`].
pub const MAX_FILE_SIZE: usize = MAX_SCP_FILE_SIZE;

/// A descriptive alias for [`MAX_SCP_FILE_SIZE`].
pub const MAX_SCP_BODY_SIZE: usize = MAX_SCP_FILE_SIZE;

/// A descriptive alias for [`MAX_SCP_BASENAME_SIZE`].
pub const MAX_BASENAME_SIZE: usize = MAX_SCP_BASENAME_SIZE;

/// A descriptive alias for [`SCP_ACK`].
pub const SCP_ACKNOWLEDGEMENT: u8 = SCP_ACK;

/// A safe error produced by the single-file SCP protocol implementation.
///
/// Error values retain no file bytes, paths, peer warning text, or other
/// untrusted diagnostic content.  Both formatting implementations use fixed
/// text even for transport and peer errors.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum ScpError {
    /// The caller-supplied stream returned an I/O error.
    Io(io::ErrorKind),
    /// A command path was empty or contained a forbidden control byte.
    InvalidPath,
    /// A header line did not have the required SCP shape.
    InvalidHeader,
    /// A time header was malformed or had an out-of-range microsecond field.
    InvalidTime,
    /// A file mode was not representable by four octal digits.
    InvalidMode,
    /// A file size was not a valid decimal number.
    InvalidSize,
    /// A file basename was empty, too long, or contained a forbidden byte.
    InvalidBasename,
    /// A header line exceeded [`MAX_SCP_HEADER_LINE_SIZE`].
    HeaderTooLong,
    /// A file size exceeded [`MAX_SCP_FILE_SIZE`].
    FileTooLarge,
    /// A peer sent an acknowledgement byte other than zero, one, or two.
    UnexpectedAcknowledgement,
    /// The peer sent a non-fatal or fatal warning byte.
    PeerError,
    /// The peer sent a directory record, which this single-file API rejects.
    DirectoryRecord,
    /// A downloaded file was not followed by the required zero byte.
    InvalidTrailer,
    /// Memory for a bounded in-memory result could not be reserved.
    AllocationFailed,
}

impl ScpError {
    const fn message(self) -> &'static str {
        match self {
            Self::Io(_) => "SCP transport failed",
            Self::InvalidPath => "SCP command path is invalid",
            Self::InvalidHeader => "SCP header is invalid",
            Self::InvalidTime => "SCP time header is invalid",
            Self::InvalidMode => "SCP file mode is invalid",
            Self::InvalidSize => "SCP file size is invalid",
            Self::InvalidBasename => "SCP file basename is invalid",
            Self::HeaderTooLong => "SCP header exceeds the 8 KiB limit",
            Self::FileTooLarge => "SCP file exceeds the 64 MiB limit",
            Self::UnexpectedAcknowledgement => "SCP acknowledgement is invalid",
            Self::PeerError => "SCP peer reported an error",
            Self::DirectoryRecord => "SCP directory records are not supported",
            Self::InvalidTrailer => "SCP file trailer is invalid",
            Self::AllocationFailed => "SCP result allocation failed",
        }
    }

    /// Compatibility spelling for [`ScpError::DirectoryRecord`].
    #[allow(non_upper_case_globals)]
    pub const Directory: Self = Self::DirectoryRecord;

    /// Compatibility spelling for [`ScpError::PeerError`].
    #[allow(non_upper_case_globals)]
    pub const PeerFailure: Self = Self::PeerError;

    /// Returns whether this error represents a peer-reported failure.
    #[must_use]
    pub const fn is_peer_error(self) -> bool {
        matches!(self, Self::PeerError)
    }
}

impl fmt::Debug for ScpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl fmt::Display for ScpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message())
    }
}

impl std::error::Error for ScpError {}

impl From<io::Error> for ScpError {
    fn from(error: io::Error) -> Self {
        Self::Io(error.kind())
    }
}

/// A short alias for [`ScpError`].
pub type Error = ScpError;

/// A short alias for [`ScpError`].
pub type ScpProtocolError = ScpError;

/// The seconds and microseconds carried by an optional SCP `T` header.
///
/// Uploads created with [`ScpTime::from_mtime`] use the same seconds for the
/// access and modification times and set both microsecond fields to zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScpTime {
    /// Modification time in seconds since the Unix epoch.
    pub mtime_seconds: u64,
    /// Modification time microseconds.
    pub mtime_usec: u32,
    /// Access time in seconds since the Unix epoch.
    pub atime_seconds: u64,
    /// Access time microseconds.
    pub atime_usec: u32,
}

impl ScpTime {
    /// Creates a time value using the same seconds for both times and zero
    /// microseconds.
    #[must_use]
    pub const fn from_mtime(seconds: u64) -> Self {
        Self {
            mtime_seconds: seconds,
            mtime_usec: 0,
            atime_seconds: seconds,
            atime_usec: 0,
        }
    }

    /// Creates a fully specified SCP time value.
    ///
    /// # Errors
    ///
    /// Returns [`ScpError::InvalidTime`] when either microsecond field is
    /// greater than 999999.
    pub fn new(
        mtime_seconds: u64,
        mtime_usec: u32,
        atime_seconds: u64,
        atime_usec: u32,
    ) -> Result<Self, ScpError> {
        let value = Self {
            mtime_seconds,
            mtime_usec,
            atime_seconds,
            atime_usec,
        };
        value.validate()?;
        Ok(value)
    }

    /// Returns the modification time in seconds.
    #[must_use]
    pub const fn mtime_seconds(self) -> u64 {
        self.mtime_seconds
    }

    /// Returns the access time in seconds.
    #[must_use]
    pub const fn atime_seconds(self) -> u64 {
        self.atime_seconds
    }

    /// Returns the modification-time microseconds.
    #[must_use]
    pub const fn mtime_microseconds(self) -> u32 {
        self.mtime_usec
    }

    /// Returns the access-time microseconds.
    #[must_use]
    pub const fn atime_microseconds(self) -> u32 {
        self.atime_usec
    }

    fn validate(self) -> Result<(), ScpError> {
        if self.mtime_usec > 999_999 || self.atime_usec > 999_999 {
            return Err(ScpError::InvalidTime);
        }
        Ok(())
    }
}

/// One downloaded regular file and its bounded protocol metadata.
///
/// The basename is kept as bytes because SCP names are length- and
/// byte-bounded rather than required to be UTF-8.  The two time fields retain
/// only seconds, as required by this API.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScpFile {
    /// The validated basename from the `C` header.
    pub basename: Vec<u8>,
    /// The four-digit octal mode from the `C` header.
    pub mode: u32,
    /// The complete file body.
    pub data: Vec<u8>,
    /// Modification seconds when a preceding `T` header was present.
    pub mtime: Option<u64>,
    /// Access seconds when a preceding `T` header was present.
    pub atime: Option<u64>,
}

impl ScpFile {
    /// Returns the file body as a byte slice.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.data
    }

    /// Returns the file body as a byte slice using the payload terminology.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        self.bytes()
    }

    /// Consumes the result and returns its file body.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }

    /// Consumes the result and returns its file body using the payload
    /// terminology.
    #[must_use]
    pub fn into_payload(self) -> Vec<u8> {
        self.into_bytes()
    }

    /// Returns the validated basename bytes.
    #[must_use]
    pub fn filename(&self) -> &[u8] {
        &self.basename
    }

    /// Returns the modification seconds, if a `T` header was present.
    #[must_use]
    pub const fn mtime_seconds(&self) -> Option<u64> {
        self.mtime
    }

    /// Returns the access seconds, if a `T` header was present.
    #[must_use]
    pub const fn atime_seconds(&self) -> Option<u64> {
        self.atime
    }
}

impl AsRef<[u8]> for ScpFile {
    fn as_ref(&self) -> &[u8] {
        self.bytes()
    }
}

/// A descriptive alias for [`ScpFile`].
pub type ScpDownload = ScpFile;

/// A short alias for [`ScpFile`].
pub type DownloadedFile = ScpFile;

/// A short alias for [`ScpFile`].
pub type ScpResult = ScpFile;

struct FileHeader {
    mode: u32,
    size: usize,
    basename: Vec<u8>,
}

/// Builds the command text for an SCP upload without executing it.
///
/// The path is enclosed in single quotes.  A literal single quote in the path
/// is represented by the shell sequence `'\''`.
///
/// # Errors
///
/// Returns [`ScpError::InvalidPath`] for an empty path, a NUL/CR/LF byte, or
/// bytes that cannot be represented by a Rust command string.
pub fn upload_command<P>(path: P) -> Result<String, ScpError>
where
    P: AsRef<[u8]>,
{
    build_command("-t", path.as_ref())
}

/// Builds the command text for an SCP download without executing it.
///
/// The path is quoted in the same way as [`upload_command`].
///
/// # Errors
///
/// Returns [`ScpError::InvalidPath`] for an empty path, a NUL/CR/LF byte, or
/// bytes that cannot be represented by a Rust command string.
pub fn download_command<P>(path: P) -> Result<String, ScpError>
where
    P: AsRef<[u8]>,
{
    build_command("-f", path.as_ref())
}

/// Uploads one in-memory file to an SCP sink over `stream`.
///
/// `path` is used to derive the file basename after the final `/`.  The
/// stream must already be connected to a caller-selected SCP sink; this
/// function sends no command or channel request.  When `mtime` is present,
/// the optional `T` header is sent before the `C` header and uses the same
/// seconds for access time with zero microseconds.
///
/// # Errors
///
/// Returns [`ScpError`] for invalid path or protocol metadata, a file over
/// [`MAX_SCP_FILE_SIZE`], a peer error, or a stream I/O failure.
pub fn upload<S, P>(
    stream: &mut S,
    path: P,
    data: &[u8],
    mtime: Option<u64>,
) -> Result<(), ScpError>
where
    S: Read + Write,
    P: AsRef<[u8]>,
{
    let basename = upload_basename(path.as_ref())?;
    upload_inner(
        stream,
        basename,
        data,
        mtime.map(ScpTime::from_mtime),
        DEFAULT_SCP_MODE,
    )
}

/// Uploads one file with an explicit four-digit octal mode.
///
/// # Errors
///
/// Returns the same errors as [`upload`], plus [`ScpError::InvalidMode`] when
/// `mode` cannot be represented by four octal digits.
pub fn upload_with_mode<S, P>(
    stream: &mut S,
    path: P,
    data: &[u8],
    mode: u32,
    mtime: Option<u64>,
) -> Result<(), ScpError>
where
    S: Read + Write,
    P: AsRef<[u8]>,
{
    let basename = upload_basename(path.as_ref())?;
    upload_inner(stream, basename, data, mtime.map(ScpTime::from_mtime), mode)
}

/// Uploads one file with a fully specified optional time header.
///
/// # Errors
///
/// Returns the same errors as [`upload`], plus [`ScpError::InvalidTime`] when
/// either supplied microsecond field is out of range.
pub fn upload_with_time<S, P>(
    stream: &mut S,
    path: P,
    data: &[u8],
    time: Option<ScpTime>,
) -> Result<(), ScpError>
where
    S: Read + Write,
    P: AsRef<[u8]>,
{
    let basename = upload_basename(path.as_ref())?;
    upload_inner(stream, basename, data, time, DEFAULT_SCP_MODE)
}

/// Uploads one file with explicit time and mode metadata.
///
/// # Errors
///
/// Returns the same errors as [`upload_with_time`] and [`upload_with_mode`].
pub fn upload_with_time_and_mode<S, P>(
    stream: &mut S,
    path: P,
    data: &[u8],
    time: Option<ScpTime>,
    mode: u32,
) -> Result<(), ScpError>
where
    S: Read + Write,
    P: AsRef<[u8]>,
{
    let basename = upload_basename(path.as_ref())?;
    upload_inner(stream, basename, data, time, mode)
}

/// Downloads one in-memory file from an SCP source over `stream`.
///
/// The function writes the initial acknowledgement, accepts at most one
/// immediately preceding `T` header, validates the `C` header, and requires
/// the historical zero trailer after the body.  It does not create a command
/// or an SSH channel.
///
/// # Errors
///
/// Returns [`ScpError`] for malformed, directory, oversized, truncated, or
/// otherwise invalid SCP input, or for a stream I/O failure.
pub fn download<S>(stream: &mut S) -> Result<ScpFile, ScpError>
where
    S: Read + Write,
{
    write_ack(stream)?;

    let first_line = read_header_line(stream)?;
    let time = if first_line.first() == Some(&b'T') {
        let parsed = parse_time_line(&first_line)?;
        write_ack(stream)?;
        Some(parsed)
    } else {
        None
    };

    let file_line = if time.is_some() {
        read_header_line(stream)?
    } else {
        first_line
    };
    let header = parse_file_header(&file_line)?;
    write_ack(stream)?;

    let mut data = Vec::new();
    data.try_reserve_exact(header.size)
        .map_err(|_| ScpError::AllocationFailed)?;
    data.resize(header.size, 0);
    stream.read_exact(&mut data)?;

    let mut trailer = [0_u8; 1];
    stream.read_exact(&mut trailer)?;
    if trailer[0] != SCP_ACK {
        return Err(ScpError::InvalidTrailer);
    }
    write_ack(stream)?;

    Ok(ScpFile {
        basename: header.basename,
        mode: header.mode,
        data,
        mtime: time.map(|value| value.mtime_seconds),
        atime: time.map(|value| value.atime_seconds),
    })
}

/// A reusable SCP byte-stream endpoint.
///
/// The endpoint owns only the caller-provided stream.  Its methods implement
/// the same single-file [`upload`] and [`download`] operations without
/// opening a channel or starting a process.
///
/// [`Debug`](std::fmt::Debug) is hand-written and adds a `T: Debug` bound
/// nowhere. That is the whole ergonomic point of this impl: `ScpClient<T>` is
/// the type a caller constructs from *their* byte stream — an established
/// channel, a buffered reader over a session handle, or a test fixture — and
/// demanding `Debug` of that would make the endpoint unusable with any stream
/// the caller had not already made printable for unrelated reasons. The
/// endpoint is a handle: it holds nothing but the stream, so printing the type
/// name is the complete and honest description. (The module deliberately names
/// no concrete stream type anywhere, and `tests/scp.rs` enforces that; a doc
/// comment is not an exemption.)
pub struct ScpClient<T> {
    stream: T,
}

impl<T> fmt::Debug for ScpClient<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // No `T: Debug` bound, and `stream` is not printed. See the type
        // documentation.
        formatter.write_str("ScpClient")
    }
}

impl<T> ScpClient<T> {
    /// Wraps a caller-supplied SCP stream.
    #[must_use]
    pub const fn new(stream: T) -> Self {
        Self { stream }
    }

    /// Returns a shared reference to the wrapped stream.
    #[must_use]
    pub const fn get_ref(&self) -> &T {
        &self.stream
    }

    /// Returns a mutable reference to the wrapped stream.
    pub const fn get_mut(&mut self) -> &mut T {
        &mut self.stream
    }

    /// Consumes the endpoint and returns the wrapped stream.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.stream
    }
}

impl<T> ScpClient<T>
where
    T: Read + Write,
{
    /// Uploads one file using [`upload`] on the wrapped stream.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`upload`].
    pub fn upload<P>(&mut self, path: P, data: &[u8], mtime: Option<u64>) -> Result<(), ScpError>
    where
        P: AsRef<[u8]>,
    {
        upload(&mut self.stream, path, data, mtime)
    }

    /// Uploads one file with an explicit mode using [`upload_with_mode`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`upload_with_mode`].
    pub fn upload_with_mode<P>(
        &mut self,
        path: P,
        data: &[u8],
        mode: u32,
        mtime: Option<u64>,
    ) -> Result<(), ScpError>
    where
        P: AsRef<[u8]>,
    {
        upload_with_mode(&mut self.stream, path, data, mode, mtime)
    }

    /// Uploads one file with a fully specified optional time header.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`upload_with_time`].
    pub fn upload_with_time<P>(
        &mut self,
        path: P,
        data: &[u8],
        time: Option<ScpTime>,
    ) -> Result<(), ScpError>
    where
        P: AsRef<[u8]>,
    {
        upload_with_time(&mut self.stream, path, data, time)
    }

    /// Downloads one file using [`download`] on the wrapped stream.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`download`].
    pub fn download(&mut self) -> Result<ScpFile, ScpError> {
        download(&mut self.stream)
    }
}

/// A short alias for [`ScpClient`].
pub type Scp<T> = ScpClient<T>;

fn build_command(flag: &str, path: &[u8]) -> Result<String, ScpError> {
    validate_path(path)?;
    let path = std::str::from_utf8(path).map_err(|_| ScpError::InvalidPath)?;
    let mut command = String::with_capacity(path.len().saturating_add(16));
    command.push_str("scp ");
    command.push_str(flag);
    command.push_str(" -- '");
    for character in path.chars() {
        if character == '\'' {
            command.push_str("'\\''");
        } else {
            command.push(character);
        }
    }
    command.push('\'');
    Ok(command)
}

fn validate_path(path: &[u8]) -> Result<(), ScpError> {
    if path.is_empty() || path.iter().any(|byte| matches!(*byte, 0 | b'\r' | b'\n')) {
        return Err(ScpError::InvalidPath);
    }
    Ok(())
}

fn upload_basename(path: &[u8]) -> Result<&[u8], ScpError> {
    validate_path(path)?;
    let start = path
        .iter()
        .rposition(|byte| *byte == b'/')
        .map_or(0, |index| index.saturating_add(1));
    let basename = path.get(start..).ok_or(ScpError::InvalidBasename)?;
    validate_basename(basename)?;
    Ok(basename)
}

fn validate_basename(basename: &[u8]) -> Result<(), ScpError> {
    if basename.is_empty()
        || basename.len() > MAX_SCP_BASENAME_SIZE
        || basename
            .iter()
            .any(|byte| matches!(*byte, 0 | b'/' | b'\\' | b'\r' | b'\n'))
    {
        return Err(ScpError::InvalidBasename);
    }
    Ok(())
}

fn upload_inner<S>(
    stream: &mut S,
    basename: &[u8],
    data: &[u8],
    time: Option<ScpTime>,
    mode: u32,
) -> Result<(), ScpError>
where
    S: Read + Write,
{
    validate_basename(basename)?;
    validate_mode(mode)?;
    if data.len() > MAX_SCP_FILE_SIZE {
        return Err(ScpError::FileTooLarge);
    }
    let time_line = time.map(encode_time_line).transpose()?;
    let file_line = encode_file_line(basename, data.len(), mode)?;

    read_ack(stream)?;
    if let Some(line) = time_line {
        stream.write_all(&line)?;
        read_ack(stream)?;
    }
    stream.write_all(&file_line)?;
    read_ack(stream)?;
    stream.write_all(data)?;
    stream.write_all(&[SCP_ACK])?;
    read_ack(stream)?;
    Ok(())
}

fn validate_mode(mode: u32) -> Result<(), ScpError> {
    if mode > 0o7777 {
        return Err(ScpError::InvalidMode);
    }
    Ok(())
}

fn encode_time_line(time: ScpTime) -> Result<Vec<u8>, ScpError> {
    time.validate()?;
    let mut line = Vec::with_capacity(64);
    line.push(b'T');
    append_decimal(&mut line, time.mtime_seconds);
    line.push(b' ');
    append_decimal(&mut line, u64::from(time.mtime_usec));
    line.push(b' ');
    append_decimal(&mut line, time.atime_seconds);
    line.push(b' ');
    append_decimal(&mut line, u64::from(time.atime_usec));
    line.push(b'\n');
    Ok(line)
}

fn encode_file_line(basename: &[u8], size: usize, mode: u32) -> Result<Vec<u8>, ScpError> {
    validate_basename(basename)?;
    validate_mode(mode)?;
    if size > MAX_SCP_FILE_SIZE {
        return Err(ScpError::FileTooLarge);
    }
    let size = u64::try_from(size).map_err(|_| ScpError::FileTooLarge)?;
    let mut line = Vec::with_capacity(basename.len().saturating_add(32));
    line.push(b'C');
    append_mode(&mut line, mode);
    line.push(b' ');
    append_decimal(&mut line, size);
    line.push(b' ');
    line.extend_from_slice(basename);
    line.push(b'\n');
    Ok(line)
}

fn append_decimal(output: &mut Vec<u8>, mut value: u64) {
    let mut digits = [0_u8; 20];
    let mut index = digits.len();
    loop {
        index -= 1;
        digits[index] = b'0' + decimal_digit(value);
        value /= 10;
        if value == 0 {
            break;
        }
    }
    output.extend_from_slice(&digits[index..]);
}

fn append_mode(output: &mut Vec<u8>, mode: u32) {
    for shift in (0..4).rev() {
        let digit = decimal_digit(u64::from((mode >> (shift * 3)) & 0o7));
        output.push(b'0' + digit);
    }
}

fn read_ack<S>(stream: &mut S) -> Result<(), ScpError>
where
    S: Read,
{
    let mut byte = [0_u8; 1];
    stream.read_exact(&mut byte)?;
    match byte[0] {
        SCP_ACK => Ok(()),
        SCP_PEER_ERROR | SCP_FATAL_ERROR => {
            discard_peer_line(stream);
            Err(ScpError::PeerError)
        }
        _ => Err(ScpError::UnexpectedAcknowledgement),
    }
}

fn write_ack<S>(stream: &mut S) -> Result<(), ScpError>
where
    S: Write,
{
    stream.write_all(&[SCP_ACK])?;
    Ok(())
}

fn discard_peer_line<S>(stream: &mut S)
where
    S: Read,
{
    let mut byte = [0_u8; 1];
    let mut remaining = MAX_SCP_HEADER_LINE_SIZE;
    while remaining > 0 {
        if stream.read_exact(&mut byte).is_err() {
            return;
        }
        if byte[0] == b'\n' {
            return;
        }
        remaining -= 1;
    }
}

fn read_header_line<S>(stream: &mut S) -> Result<Vec<u8>, ScpError>
where
    S: Read,
{
    let mut first = [0_u8; 1];
    stream.read_exact(&mut first)?;
    if first[0] == SCP_PEER_ERROR || first[0] == SCP_FATAL_ERROR {
        discard_peer_line(stream);
        return Err(ScpError::PeerError);
    }
    read_line(stream, first[0])
}

fn read_line<S>(stream: &mut S, first: u8) -> Result<Vec<u8>, ScpError>
where
    S: Read,
{
    let mut line = Vec::with_capacity(128);
    line.push(first);
    loop {
        if line.len() >= MAX_SCP_HEADER_LINE_SIZE {
            return Err(ScpError::HeaderTooLong);
        }
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte)?;
        line.push(byte[0]);
        if byte[0] == b'\n' {
            return Ok(line);
        }
    }
}

fn parse_time_line(line: &[u8]) -> Result<ScpTime, ScpError> {
    let content = line.strip_suffix(b"\n").ok_or(ScpError::InvalidTime)?;
    if content.first() != Some(&b'T') {
        return Err(ScpError::InvalidTime);
    }
    let fields = content
        .get(1..)
        .ok_or(ScpError::InvalidTime)?
        .split(|byte| *byte == b' ');
    let mut fields = fields;
    let mtime_seconds =
        parse_decimal(fields.next().ok_or(ScpError::InvalidTime)?).ok_or(ScpError::InvalidTime)?;
    let mtime_usec = parse_microseconds(fields.next().ok_or(ScpError::InvalidTime)?)?;
    let atime_seconds =
        parse_decimal(fields.next().ok_or(ScpError::InvalidTime)?).ok_or(ScpError::InvalidTime)?;
    let atime_usec = parse_microseconds(fields.next().ok_or(ScpError::InvalidTime)?)?;
    if fields.next().is_some() {
        return Err(ScpError::InvalidTime);
    }
    ScpTime::new(mtime_seconds, mtime_usec, atime_seconds, atime_usec)
}

fn parse_microseconds(value: &[u8]) -> Result<u32, ScpError> {
    let value = parse_decimal(value).ok_or(ScpError::InvalidTime)?;
    let value = u32::try_from(value).map_err(|_| ScpError::InvalidTime)?;
    if value > 999_999 {
        return Err(ScpError::InvalidTime);
    }
    Ok(value)
}

fn parse_decimal(value: &[u8]) -> Option<u64> {
    if value.is_empty() {
        return None;
    }
    let mut result = 0_u64;
    for digit in value {
        if !digit.is_ascii_digit() {
            return None;
        }
        result = result
            .checked_mul(10)?
            .checked_add(u64::from(*digit - b'0'))?;
    }
    Some(result)
}

fn parse_file_header(line: &[u8]) -> Result<FileHeader, ScpError> {
    if line.len() > MAX_SCP_HEADER_LINE_SIZE {
        return Err(ScpError::HeaderTooLong);
    }
    match line.first().copied() {
        Some(b'D' | b'E') => return Err(ScpError::DirectoryRecord),
        Some(b'C') => {}
        Some(_) | None => return Err(ScpError::InvalidHeader),
    }
    let content = line.strip_suffix(b"\n").ok_or(ScpError::InvalidHeader)?;
    let mode_bytes = content.get(1..5).ok_or(ScpError::InvalidHeader)?;
    if mode_bytes.len() != 4 || !mode_bytes.iter().all(|digit| is_octal_digit(*digit)) {
        return Err(ScpError::InvalidHeader);
    }
    if content.get(5).copied() != Some(b' ') {
        return Err(ScpError::InvalidHeader);
    }
    let size_and_name = content.get(6..).ok_or(ScpError::InvalidHeader)?;
    let size_length = size_and_name
        .iter()
        .position(|byte| *byte == b' ')
        .ok_or(ScpError::InvalidHeader)?;
    if size_length == 0 {
        return Err(ScpError::InvalidSize);
    }
    let size_bytes = size_and_name
        .get(..size_length)
        .ok_or(ScpError::InvalidSize)?;
    let size = parse_size(size_bytes)?;
    let name_start = size_length.checked_add(7).ok_or(ScpError::InvalidHeader)?;
    let basename = content.get(name_start..).ok_or(ScpError::InvalidHeader)?;
    validate_basename(basename)?;
    let mut mode = 0_u32;
    for digit in mode_bytes {
        mode = (mode << 3) | u32::from(*digit - b'0');
    }
    Ok(FileHeader {
        mode,
        size,
        basename: basename.to_vec(),
    })
}

fn parse_size(value: &[u8]) -> Result<usize, ScpError> {
    if value.is_empty() {
        return Err(ScpError::InvalidSize);
    }
    let mut size = 0_u64;
    for digit in value {
        if !digit.is_ascii_digit() {
            return Err(ScpError::InvalidSize);
        }
        size = size
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(*digit - b'0')))
            .ok_or(ScpError::FileTooLarge)?;
        if size > MAX_SCP_FILE_SIZE as u64 {
            return Err(ScpError::FileTooLarge);
        }
    }
    usize::try_from(size).map_err(|_| ScpError::FileTooLarge)
}

fn decimal_digit(value: u64) -> u8 {
    match value % 10 {
        1 => 1,
        2 => 2,
        3 => 3,
        4 => 4,
        5 => 5,
        6 => 6,
        7 => 7,
        8 => 8,
        9 => 9,
        _ => 0,
    }
}

fn is_octal_digit(value: u8) -> bool {
    (b'0'..=b'7').contains(&value)
}
