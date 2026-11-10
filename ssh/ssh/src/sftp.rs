//! A bounded SFTP version 3 client over an already-open byte stream.
//!
//! This module implements the client side of `draft-ietf-secsh-filexfer-02`.
//! It deliberately does not open or configure a channel, start an external
//! program, or create a network endpoint.  The caller supplies a stream that
//! is already carrying the SFTP byte stream (for example, the two directions of
//! an SSH channel joined by the application).
//!
//! Requests are strictly sequential: one request is written and its one
//! response is read before another request can be started.  SFTP frames are
//! bounded at 16 MiB, paths at 4096 bytes, and handles at 256 bytes.

#![allow(clippy::module_name_repetitions)]

use std::fmt;
use std::io::{self, Read, Write};

use neotales_ssh::{Error as WireError, Reader};

/// The maximum SFTP packet body, excluding its four-byte length prefix.
pub const MAX_SFTP_PACKET_SIZE: usize = 16_777_216;

/// A short alias for [`MAX_SFTP_PACKET_SIZE`].
pub const MAX_PACKET_SIZE: usize = MAX_SFTP_PACKET_SIZE;

/// A descriptive alias for [`MAX_SFTP_PACKET_SIZE`].
pub const MAX_SFTP_PACKET_LENGTH: usize = MAX_SFTP_PACKET_SIZE;

/// A descriptive alias for [`MAX_SFTP_PACKET_SIZE`].
pub const MAX_PACKET_LENGTH: usize = MAX_SFTP_PACKET_SIZE;

/// A descriptive alias for [`MAX_SFTP_PACKET_SIZE`].
pub const MAX_SFTP_PACKET_BODY: usize = MAX_SFTP_PACKET_SIZE;

/// A descriptive alias for [`MAX_SFTP_PACKET_SIZE`].
pub const MAX_PACKET_BODY_SIZE: usize = MAX_SFTP_PACKET_SIZE;

/// A short alias for [`MAX_SFTP_PACKET_SIZE`].
pub const MAX_PACKET_BODY: usize = MAX_SFTP_PACKET_SIZE;

/// A descriptive alias for [`MAX_SFTP_PACKET_SIZE`].
pub const MAX_SFTP_PACKET_BODY_SIZE: usize = MAX_SFTP_PACKET_SIZE;

/// The maximum byte length of an SFTP path.
pub const MAX_SFTP_PATH_SIZE: usize = 4096;

/// A short alias for [`MAX_SFTP_PATH_SIZE`].
pub const MAX_PATH_SIZE: usize = MAX_SFTP_PATH_SIZE;

/// A descriptive alias for [`MAX_SFTP_PATH_SIZE`].
pub const MAX_SFTP_PATH_LENGTH: usize = MAX_SFTP_PATH_SIZE;

/// A descriptive alias for [`MAX_SFTP_PATH_SIZE`].
pub const MAX_PATH_LENGTH: usize = MAX_SFTP_PATH_SIZE;

/// A short alias for [`MAX_SFTP_PATH_SIZE`].
pub const MAX_PATH_BYTES: usize = MAX_SFTP_PATH_SIZE;

/// The maximum byte length of an SFTP handle.
pub const MAX_SFTP_HANDLE_SIZE: usize = 256;

/// A short alias for [`MAX_SFTP_HANDLE_SIZE`].
pub const MAX_HANDLE_SIZE: usize = MAX_SFTP_HANDLE_SIZE;

/// A descriptive alias for [`MAX_SFTP_HANDLE_SIZE`].
pub const MAX_SFTP_HANDLE_LENGTH: usize = MAX_SFTP_HANDLE_SIZE;

/// A descriptive alias for [`MAX_SFTP_HANDLE_SIZE`].
pub const MAX_HANDLE_LENGTH: usize = MAX_SFTP_HANDLE_SIZE;

/// A short alias for [`MAX_SFTP_HANDLE_SIZE`].
pub const MAX_HANDLE_BYTES: usize = MAX_SFTP_HANDLE_SIZE;

/// The only SFTP protocol version implemented by this client.
pub const SFTP_VERSION: u32 = 3;

/// A descriptive alias for [`SFTP_VERSION`].
pub const SSH_FILEXFER_VERSION: u32 = SFTP_VERSION;

/// SFTP `INIT` packet type.
pub const SSH_FXP_INIT: u8 = 1;
/// SFTP `VERSION` packet type.
pub const SSH_FXP_VERSION: u8 = 2;
/// SFTP `OPEN` packet type.
pub const SSH_FXP_OPEN: u8 = 3;
/// SFTP `CLOSE` packet type.
pub const SSH_FXP_CLOSE: u8 = 4;
/// SFTP `READ` packet type.
pub const SSH_FXP_READ: u8 = 5;
/// SFTP `WRITE` packet type.
pub const SSH_FXP_WRITE: u8 = 6;
/// SFTP `LSTAT` packet type.
pub const SSH_FXP_LSTAT: u8 = 7;
/// SFTP `FSTAT` packet type.
pub const SSH_FXP_FSTAT: u8 = 8;
/// SFTP `SETSTAT` packet type.
pub const SSH_FXP_SETSTAT: u8 = 9;
/// SFTP `OPENDIR` packet type.
pub const SSH_FXP_OPENDIR: u8 = 11;
/// SFTP `READDIR` packet type.
pub const SSH_FXP_READDIR: u8 = 12;
/// SFTP `REMOVE` packet type.
pub const SSH_FXP_REMOVE: u8 = 13;
/// SFTP `MKDIR` packet type.
pub const SSH_FXP_MKDIR: u8 = 14;
/// SFTP `RMDIR` packet type.
pub const SSH_FXP_RMDIR: u8 = 15;
/// SFTP `REALPATH` packet type.
pub const SSH_FXP_REALPATH: u8 = 16;
/// SFTP `STAT` packet type.
pub const SSH_FXP_STAT: u8 = 17;
/// SFTP `RENAME` packet type.
pub const SSH_FXP_RENAME: u8 = 18;
/// SFTP `READLINK` packet type.
pub const SSH_FXP_READLINK: u8 = 19;
/// SFTP `SYMLINK` packet type.
pub const SSH_FXP_SYMLINK: u8 = 20;
/// SFTP `STATUS` response type.
pub const SSH_FXP_STATUS: u8 = 101;
/// SFTP `HANDLE` response type.
pub const SSH_FXP_HANDLE: u8 = 102;
/// SFTP `DATA` response type.
pub const SSH_FXP_DATA: u8 = 103;
/// SFTP `NAME` response type.
pub const SSH_FXP_NAME: u8 = 104;
/// SFTP `ATTRS` response type.
pub const SSH_FXP_ATTRS: u8 = 105;

/// Short alias for [`SSH_FXP_INIT`].
pub const SFTP_INIT: u8 = SSH_FXP_INIT;
/// Short alias for [`SSH_FXP_VERSION`].
pub const SFTP_VERSION_PACKET: u8 = SSH_FXP_VERSION;
/// Short alias for [`SSH_FXP_OPEN`].
pub const SFTP_OPEN: u8 = SSH_FXP_OPEN;
/// Short alias for [`SSH_FXP_CLOSE`].
pub const SFTP_CLOSE: u8 = SSH_FXP_CLOSE;
/// Short alias for [`SSH_FXP_READ`].
pub const SFTP_READ: u8 = SSH_FXP_READ;
/// Short alias for [`SSH_FXP_WRITE`].
pub const SFTP_WRITE: u8 = SSH_FXP_WRITE;
/// Short alias for [`SSH_FXP_LSTAT`].
pub const SFTP_LSTAT: u8 = SSH_FXP_LSTAT;
/// Short alias for [`SSH_FXP_FSTAT`].
pub const SFTP_FSTAT: u8 = SSH_FXP_FSTAT;
/// Short alias for [`SSH_FXP_SETSTAT`].
pub const SFTP_SETSTAT: u8 = SSH_FXP_SETSTAT;
/// Short alias for [`SSH_FXP_OPENDIR`].
pub const SFTP_OPENDIR: u8 = SSH_FXP_OPENDIR;
/// Short alias for [`SSH_FXP_READDIR`].
pub const SFTP_READDIR: u8 = SSH_FXP_READDIR;
/// Short alias for [`SSH_FXP_REMOVE`].
pub const SFTP_REMOVE: u8 = SSH_FXP_REMOVE;
/// Short alias for [`SSH_FXP_MKDIR`].
pub const SFTP_MKDIR: u8 = SSH_FXP_MKDIR;
/// Short alias for [`SSH_FXP_RMDIR`].
pub const SFTP_RMDIR: u8 = SSH_FXP_RMDIR;
/// Short alias for [`SSH_FXP_REALPATH`].
pub const SFTP_REALPATH: u8 = SSH_FXP_REALPATH;
/// Short alias for [`SSH_FXP_STAT`].
pub const SFTP_STAT: u8 = SSH_FXP_STAT;
/// Short alias for [`SSH_FXP_RENAME`].
pub const SFTP_RENAME: u8 = SSH_FXP_RENAME;
/// Short alias for [`SSH_FXP_READLINK`].
pub const SFTP_READLINK: u8 = SSH_FXP_READLINK;
/// Short alias for [`SSH_FXP_SYMLINK`].
pub const SFTP_SYMLINK: u8 = SSH_FXP_SYMLINK;
/// Short alias for [`SSH_FXP_STATUS`].
pub const SFTP_STATUS: u8 = SSH_FXP_STATUS;
/// Short alias for [`SSH_FXP_HANDLE`].
pub const SFTP_HANDLE: u8 = SSH_FXP_HANDLE;
/// Short alias for [`SSH_FXP_DATA`].
pub const SFTP_DATA: u8 = SSH_FXP_DATA;
/// Short alias for [`SSH_FXP_NAME`].
pub const SFTP_NAME: u8 = SSH_FXP_NAME;
/// Short alias for [`SSH_FXP_ATTRS`].
pub const SFTP_ATTRS: u8 = SSH_FXP_ATTRS;

/// The SFTP `SSH_FX_OK` status code.
pub const SSH_FX_OK: u32 = 0;
/// The SFTP `SSH_FX_EOF` status code.
pub const SSH_FX_EOF: u32 = 1;
/// The SFTP `SSH_FX_NO_SUCH_FILE` status code.
pub const SSH_FX_NO_SUCH_FILE: u32 = 2;
/// The SFTP `SSH_FX_PERMISSION_DENIED` status code.
pub const SSH_FX_PERMISSION_DENIED: u32 = 3;
/// The SFTP `SSH_FX_FAILURE` status code.
pub const SSH_FX_FAILURE: u32 = 4;
/// The SFTP `SSH_FX_BAD_MESSAGE` status code.
pub const SSH_FX_BAD_MESSAGE: u32 = 5;
/// The SFTP `SSH_FX_NO_CONNECTION` status code.
pub const SSH_FX_NO_CONNECTION: u32 = 6;
/// The SFTP `SSH_FX_CONNECTION_LOST` status code.
pub const SSH_FX_CONNECTION_LOST: u32 = 7;
/// The SFTP `SSH_FX_OP_UNSUPPORTED` status code.
pub const SSH_FX_OP_UNSUPPORTED: u32 = 8;
/// The SFTP `SSH_FX_INVALID_HANDLE` status code.
pub const SSH_FX_INVALID_HANDLE: u32 = 9;
/// The SFTP `SSH_FX_NO_SUCH_PATH` status code.
pub const SSH_FX_NO_SUCH_PATH: u32 = 10;
/// The SFTP `SSH_FX_FILE_ALREADY_EXISTS` status code.
pub const SSH_FX_FILE_ALREADY_EXISTS: u32 = 11;
/// The SFTP `SSH_FX_WRITE_PROTECT` status code.
pub const SSH_FX_WRITE_PROTECT: u32 = 12;
/// The SFTP `SSH_FX_NO_MEDIA` status code.
pub const SSH_FX_NO_MEDIA: u32 = 13;

/// Short alias for [`SSH_FX_OK`].
pub const SFTP_STATUS_OK: u32 = SSH_FX_OK;
/// Short alias for [`SSH_FX_EOF`].
pub const SFTP_STATUS_EOF: u32 = SSH_FX_EOF;
/// Short alias for [`SSH_FX_NO_SUCH_FILE`].
pub const SFTP_STATUS_NO_SUCH_FILE: u32 = SSH_FX_NO_SUCH_FILE;
/// Short alias for [`SSH_FX_PERMISSION_DENIED`].
pub const SFTP_STATUS_PERMISSION_DENIED: u32 = SSH_FX_PERMISSION_DENIED;
/// Short alias for [`SSH_FX_FAILURE`].
pub const SFTP_STATUS_FAILURE: u32 = SSH_FX_FAILURE;
/// Short alias for [`SSH_FX_BAD_MESSAGE`].
pub const SFTP_STATUS_BAD_MESSAGE: u32 = SSH_FX_BAD_MESSAGE;
/// Short alias for [`SSH_FX_NO_CONNECTION`].
pub const SFTP_STATUS_NO_CONNECTION: u32 = SSH_FX_NO_CONNECTION;
/// Short alias for [`SSH_FX_CONNECTION_LOST`].
pub const SFTP_STATUS_CONNECTION_LOST: u32 = SSH_FX_CONNECTION_LOST;
/// Short alias for [`SSH_FX_OP_UNSUPPORTED`].
pub const SFTP_STATUS_OP_UNSUPPORTED: u32 = SSH_FX_OP_UNSUPPORTED;
/// Short alias for [`SSH_FX_INVALID_HANDLE`].
pub const SFTP_STATUS_INVALID_HANDLE: u32 = SSH_FX_INVALID_HANDLE;
/// Short alias for [`SSH_FX_NO_SUCH_PATH`].
pub const SFTP_STATUS_NO_SUCH_PATH: u32 = SSH_FX_NO_SUCH_PATH;
/// Short alias for [`SSH_FX_FILE_ALREADY_EXISTS`].
pub const SFTP_STATUS_FILE_ALREADY_EXISTS: u32 = SSH_FX_FILE_ALREADY_EXISTS;
/// Short alias for [`SSH_FX_WRITE_PROTECT`].
pub const SFTP_STATUS_WRITE_PROTECT: u32 = SSH_FX_WRITE_PROTECT;
/// Short alias for [`SSH_FX_NO_MEDIA`].
pub const SFTP_STATUS_NO_MEDIA: u32 = SSH_FX_NO_MEDIA;

/// The SFTP v3 `READ` open flag.
pub const SSH_FXF_READ: u32 = 0x0000_0001;
/// The SFTP v3 `WRITE` open flag.
pub const SSH_FXF_WRITE: u32 = 0x0000_0002;
/// The SFTP v3 `APPEND` open flag.
pub const SSH_FXF_APPEND: u32 = 0x0000_0004;
/// The SFTP v3 `CREAT` open flag.
pub const SSH_FXF_CREAT: u32 = 0x0000_0008;
/// The SFTP v3 `TRUNC` open flag.
pub const SSH_FXF_TRUNC: u32 = 0x0000_0010;
/// The SFTP v3 `EXCL` open flag.
pub const SSH_FXF_EXCL: u32 = 0x0000_0020;

/// Short alias for [`SSH_FXF_READ`].
pub const SFTP_OPEN_READ: u32 = SSH_FXF_READ;
/// Short alias for [`SSH_FXF_WRITE`].
pub const SFTP_OPEN_WRITE: u32 = SSH_FXF_WRITE;
/// Short alias for [`SSH_FXF_APPEND`].
pub const SFTP_OPEN_APPEND: u32 = SSH_FXF_APPEND;
/// Short alias for [`SSH_FXF_CREAT`].
pub const SFTP_OPEN_CREAT: u32 = SSH_FXF_CREAT;
/// Short alias for [`SSH_FXF_TRUNC`].
pub const SFTP_OPEN_TRUNC: u32 = SSH_FXF_TRUNC;
/// Short alias for [`SSH_FXF_EXCL`].
pub const SFTP_OPEN_EXCL: u32 = SSH_FXF_EXCL;

/// The SFTP v3 size-attribute flag.
pub const SSH_FILEXFER_ATTR_SIZE: u32 = 0x0000_0001;
/// The SFTP v3 user/group-id attribute flag.
pub const SSH_FILEXFER_ATTR_UIDGID: u32 = 0x0000_0002;
/// The SFTP v3 permissions attribute flag.
pub const SSH_FILEXFER_ATTR_PERMISSIONS: u32 = 0x0000_0004;
/// The SFTP v3 access/modified-time attribute flag.
pub const SSH_FILEXFER_ATTR_ACMODTIME: u32 = 0x0000_0008;
/// The SFTP v3 extended-attribute flag.
pub const SSH_FILEXFER_ATTR_EXTENDED: u32 = 0x8000_0000;

/// Short alias for [`SSH_FILEXFER_ATTR_SIZE`].
pub const SFTP_ATTR_SIZE: u32 = SSH_FILEXFER_ATTR_SIZE;
/// Short alias for [`SSH_FILEXFER_ATTR_UIDGID`].
pub const SFTP_ATTR_UIDGID: u32 = SSH_FILEXFER_ATTR_UIDGID;
/// Short alias for [`SSH_FILEXFER_ATTR_PERMISSIONS`].
pub const SFTP_ATTR_PERMISSIONS: u32 = SSH_FILEXFER_ATTR_PERMISSIONS;
/// Short alias for [`SSH_FILEXFER_ATTR_ACMODTIME`].
pub const SFTP_ATTR_ACMODTIME: u32 = SSH_FILEXFER_ATTR_ACMODTIME;
/// Short alias for [`SSH_FILEXFER_ATTR_EXTENDED`].
pub const SFTP_ATTR_EXTENDED: u32 = SSH_FILEXFER_ATTR_EXTENDED;

/// A value that can be supplied as an SFTP path, handle, or opaque string.
///
/// Implementations retain the caller's bytes without interpreting their text
/// encoding.  This keeps the protocol client usable for non-UTF-8 names while
/// still allowing `&str`, `String`, byte slices, and owned byte vectors.
pub trait SftpBytes {
    /// Returns the exact bytes represented by this value.
    fn as_sftp_bytes(&self) -> &[u8];
}

impl SftpBytes for [u8] {
    fn as_sftp_bytes(&self) -> &[u8] {
        self
    }
}

impl SftpBytes for Vec<u8> {
    fn as_sftp_bytes(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<const N: usize> SftpBytes for [u8; N] {
    fn as_sftp_bytes(&self) -> &[u8] {
        self.as_slice()
    }
}

impl SftpBytes for str {
    fn as_sftp_bytes(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl SftpBytes for String {
    fn as_sftp_bytes(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<T> SftpBytes for &T
where
    T: SftpBytes + ?Sized,
{
    fn as_sftp_bytes(&self) -> &[u8] {
        (*self).as_sftp_bytes()
    }
}

/// A bounded SFTP protocol, validation, or transport error.
///
/// Error values intentionally do not retain paths, handles, response packets,
/// or server-provided message text.  The numeric server status is retained so a
/// caller can make a policy decision without exposing untrusted text.
pub enum SftpError {
    /// The caller-supplied byte stream returned an I/O error.
    Io(io::Error),
    /// An SSH primitive was malformed while decoding a packet.
    Wire(WireError),
    /// A packet was empty, truncated, or had trailing bytes.
    InvalidFrame,
    /// A packet length was zero.
    ZeroLength,
    /// A packet length exceeded [`MAX_SFTP_PACKET_SIZE`].
    FrameTooLarge,
    /// A path was empty.
    InvalidPath,
    /// A path exceeded [`MAX_SFTP_PATH_SIZE`].
    PathTooLong,
    /// A handle was empty.
    InvalidHandle,
    /// A handle exceeded [`MAX_SFTP_HANDLE_SIZE`].
    HandleTooLong,
    /// An attribute block was malformed or used an unknown flag bit.
    InvalidAttributes,
    /// An open-flag word contained a bit outside the v3 flag set.
    InvalidOpenFlags,
    /// The server's VERSION response was not exactly version 3.
    InvalidVersion(u32),
    /// A response had a packet type not valid for the operation.
    UnexpectedResponse(u8),
    /// A response did not carry the outstanding request id.
    ResponseIdMismatch {
        /// The id sent in the request.
        expected: u32,
        /// The id received in the response.
        actual: u32,
    },
    /// A packet did not contain a response id where one was required.
    MissingResponseId,
    /// The client has not completed VERSION negotiation.
    NotInitialized,
    /// VERSION negotiation was attempted more than once.
    AlreadyInitialized,
    /// A request was attempted while another request was outstanding.
    RequestInFlight,
    /// The request-id space was exhausted.
    RequestIdExhausted,
    /// A read length cannot be represented by the v3 wire field.
    InvalidReadLength,
    /// The server returned a non-success status.
    Status(u32),
}

impl fmt::Debug for SftpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(_) => formatter.write_str("Io"),
            Self::Wire(_) => formatter.write_str("Wire"),
            Self::InvalidFrame => formatter.write_str("InvalidFrame"),
            Self::ZeroLength => formatter.write_str("ZeroLength"),
            Self::FrameTooLarge => formatter.write_str("FrameTooLarge"),
            Self::InvalidPath => formatter.write_str("InvalidPath"),
            Self::PathTooLong => formatter.write_str("PathTooLong"),
            Self::InvalidHandle => formatter.write_str("InvalidHandle"),
            Self::HandleTooLong => formatter.write_str("HandleTooLong"),
            Self::InvalidAttributes => formatter.write_str("InvalidAttributes"),
            Self::InvalidOpenFlags => formatter.write_str("InvalidOpenFlags"),
            Self::InvalidVersion(_) => formatter.write_str("InvalidVersion"),
            Self::UnexpectedResponse(_) => formatter.write_str("UnexpectedResponse"),
            Self::ResponseIdMismatch { .. } => formatter.write_str("ResponseIdMismatch"),
            Self::MissingResponseId => formatter.write_str("MissingResponseId"),
            Self::NotInitialized => formatter.write_str("NotInitialized"),
            Self::AlreadyInitialized => formatter.write_str("AlreadyInitialized"),
            Self::RequestInFlight => formatter.write_str("RequestInFlight"),
            Self::RequestIdExhausted => formatter.write_str("RequestIdExhausted"),
            Self::InvalidReadLength => formatter.write_str("InvalidReadLength"),
            Self::Status(code) => formatter.debug_tuple("Status").field(code).finish(),
        }
    }
}

impl fmt::Display for SftpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(_) => formatter.write_str("SFTP transport failed"),
            Self::Wire(_) => formatter.write_str("SFTP wire data is malformed"),
            Self::InvalidFrame => formatter.write_str("SFTP packet is malformed"),
            Self::ZeroLength => formatter.write_str("SFTP packet has zero length"),
            Self::FrameTooLarge => formatter.write_str("SFTP packet exceeds the 16 MiB limit"),
            Self::InvalidPath => formatter.write_str("SFTP path is empty or invalid"),
            Self::PathTooLong => formatter.write_str("SFTP path exceeds the 4096-byte limit"),
            Self::InvalidHandle => formatter.write_str("SFTP handle is empty or invalid"),
            Self::HandleTooLong => formatter.write_str("SFTP handle exceeds the 256-byte limit"),
            Self::InvalidAttributes => formatter.write_str("SFTP attributes are malformed"),
            Self::InvalidOpenFlags => formatter.write_str("SFTP open flags are invalid"),
            Self::InvalidVersion(_) => formatter.write_str("SFTP server version is unsupported"),
            Self::UnexpectedResponse(_) => {
                formatter.write_str("SFTP response packet type is unexpected")
            }
            Self::ResponseIdMismatch { .. } => {
                formatter.write_str("SFTP response request id does not match")
            }
            Self::MissingResponseId => formatter.write_str("SFTP response has no request id"),
            Self::NotInitialized => formatter.write_str("SFTP client is not initialized"),
            Self::AlreadyInitialized => formatter.write_str("SFTP client is already initialized"),
            Self::RequestInFlight => formatter.write_str("an SFTP request is already outstanding"),
            Self::RequestIdExhausted => formatter.write_str("SFTP request id space is exhausted"),
            Self::InvalidReadLength => formatter.write_str("SFTP read length is invalid"),
            Self::Status(code) => write!(formatter, "SFTP server returned status {code}"),
        }
    }
}

impl std::error::Error for SftpError {}

impl From<io::Error> for SftpError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<WireError> for SftpError {
    fn from(error: WireError) -> Self {
        Self::Wire(error)
    }
}

impl SftpError {
    /// Returns the server status code when this is a status error.
    #[must_use]
    pub const fn status_code(&self) -> Option<u32> {
        match self {
            Self::Status(code) => Some(*code),
            _ => None,
        }
    }

    /// Returns whether this error is the SFTP EOF status.
    #[must_use]
    pub const fn is_eof(&self) -> bool {
        matches!(self, Self::Status(SSH_FX_EOF))
    }
}

/// A short alias for [`SftpError`].
pub type Error = SftpError;

/// A short alias for [`SftpError`].
pub type SftpProtocolError = SftpError;

/// A numeric SFTP status code from the v3 draft.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u32)]
pub enum SftpStatusCode {
    /// The operation completed successfully.
    Ok = 0,
    /// No more data is available for a read operation.
    Eof = 1,
    /// The requested file does not exist.
    NoSuchFile = 2,
    /// The server denied permission for the operation.
    PermissionDenied = 3,
    /// The operation failed for a server-specific reason.
    Failure = 4,
    /// The server received a malformed message.
    BadMessage = 5,
    /// The server has no connection to perform the operation.
    NoConnection = 6,
    /// The connection was lost.
    ConnectionLost = 7,
    /// The operation is not supported.
    OpUnsupported = 8,
    /// The supplied handle is invalid.
    InvalidHandle = 9,
    /// The requested path does not exist.
    NoSuchPath = 10,
    /// The destination already exists.
    FileAlreadyExists = 11,
    /// The destination is write-protected.
    WriteProtect = 12,
    /// The requested media is unavailable.
    NoMedia = 13,
}

impl SftpStatusCode {
    /// Converts a wire status number into a known status code.
    #[must_use]
    pub const fn from_u32(value: u32) -> Option<Self> {
        match value {
            SSH_FX_OK => Some(Self::Ok),
            SSH_FX_EOF => Some(Self::Eof),
            SSH_FX_NO_SUCH_FILE => Some(Self::NoSuchFile),
            SSH_FX_PERMISSION_DENIED => Some(Self::PermissionDenied),
            SSH_FX_FAILURE => Some(Self::Failure),
            SSH_FX_BAD_MESSAGE => Some(Self::BadMessage),
            SSH_FX_NO_CONNECTION => Some(Self::NoConnection),
            SSH_FX_CONNECTION_LOST => Some(Self::ConnectionLost),
            SSH_FX_OP_UNSUPPORTED => Some(Self::OpUnsupported),
            SSH_FX_INVALID_HANDLE => Some(Self::InvalidHandle),
            SSH_FX_NO_SUCH_PATH => Some(Self::NoSuchPath),
            SSH_FX_FILE_ALREADY_EXISTS => Some(Self::FileAlreadyExists),
            SSH_FX_WRITE_PROTECT => Some(Self::WriteProtect),
            SSH_FX_NO_MEDIA => Some(Self::NoMedia),
            _ => None,
        }
    }

    /// Returns the numeric wire value for this status.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }
}

/// A short alias for [`SftpStatusCode`].
pub type SftpStatus = SftpStatusCode;

/// A validated opaque SFTP handle.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct SftpHandle {
    value: Vec<u8>,
}

impl SftpHandle {
    /// Creates a validated handle from its exact wire bytes.
    ///
    /// # Errors
    ///
    /// Returns [`SftpError::InvalidHandle`] for an empty value and
    /// [`SftpError::HandleTooLong`] for a value over 256 bytes.
    pub fn from_bytes(value: &[u8]) -> Result<Self, SftpError> {
        validate_handle_bytes(value)?;
        Ok(Self {
            value: value.to_vec(),
        })
    }

    /// Creates a validated owned handle.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::from_bytes`].
    pub fn new(value: impl AsRef<[u8]>) -> Result<Self, SftpError> {
        Self::from_bytes(value.as_ref())
    }

    /// Returns the exact opaque handle bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.value
    }

    /// Returns the exact opaque handle bytes using the short name.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        self.as_bytes()
    }

    /// Consumes the handle and returns its exact bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.value
    }

    /// Returns the number of opaque handle bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.value.len()
    }

    /// Returns whether the handle has no bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }
}

impl fmt::Debug for SftpHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SftpHandle")
            .field("length", &self.value.len())
            .finish()
    }
}

impl SftpBytes for SftpHandle {
    fn as_sftp_bytes(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl AsRef<[u8]> for SftpHandle {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl TryFrom<&[u8]> for SftpHandle {
    type Error = SftpError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(value)
    }
}

impl TryFrom<Vec<u8>> for SftpHandle {
    type Error = SftpError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::from_bytes(&value)
    }
}

/// An extended SFTP attribute type/data pair.
///
/// The pair is retained so callers can inspect it, but it never changes the
/// typed fields in [`SftpAttributes`].
#[derive(Clone, Eq, PartialEq)]
pub struct SftpExtendedAttribute {
    /// Exact extension type name bytes.
    pub name: Vec<u8>,
    /// Exact extension data bytes.
    pub data: Vec<u8>,
}

impl SftpExtendedAttribute {
    /// Creates one extended attribute pair.
    #[must_use]
    pub fn new<N, D>(name: N, data: D) -> Self
    where
        N: AsRef<[u8]>,
        D: AsRef<[u8]>,
    {
        Self {
            name: name.as_ref().to_vec(),
            data: data.as_ref().to_vec(),
        }
    }

    /// Returns the exact extension type name bytes.
    #[must_use]
    pub fn name(&self) -> &[u8] {
        &self.name
    }

    /// Returns the exact extension type name bytes.
    #[must_use]
    pub fn type_name(&self) -> &[u8] {
        self.name()
    }

    /// Returns the exact extension data bytes.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Returns the exact extension data bytes.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        self.data()
    }
}

/// A short alias for [`SftpExtendedAttribute`].
pub type SftpExtendedAttr = SftpExtendedAttribute;

impl fmt::Debug for SftpExtendedAttribute {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SftpExtendedAttribute")
            .field("name_length", &self.name.len())
            .field("data_length", &self.data.len())
            .finish()
    }
}

/// An SFTP v3 attribute block.
///
/// `uid` and `gid` are represented separately, but the protocol emits both
/// whenever either is present.  Likewise, `access_time` and `modify_time` are
/// emitted together when either is present.  Extended pairs are retained but
/// do not alter any of these typed fields.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct SftpAttributes {
    /// File size, when the SIZE flag was present.
    pub size: Option<u64>,
    /// User id, when the UIDGID flag was present.
    pub uid: Option<u32>,
    /// Group id, when the UIDGID flag was present.
    pub gid: Option<u32>,
    /// File permissions, when the PERMISSIONS flag was present.
    pub permissions: Option<u32>,
    /// Access time, when the ACMODTIME flag was present.
    pub access_time: Option<u32>,
    /// Modification time, when the ACMODTIME flag was present.
    pub modify_time: Option<u32>,
    /// Extended type/data pairs.
    pub extended: Vec<SftpExtendedAttribute>,
}

impl SftpAttributes {
    /// Creates an empty attribute block.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            size: None,
            uid: None,
            gid: None,
            permissions: None,
            access_time: None,
            modify_time: None,
            extended: Vec::new(),
        }
    }

    /// Creates an attribute block from all typed v3 fields.
    #[must_use]
    pub const fn from_fields(
        size: Option<u64>,
        uid: Option<u32>,
        gid: Option<u32>,
        permissions: Option<u32>,
        access_time: Option<u32>,
        modify_time: Option<u32>,
    ) -> Self {
        Self {
            size,
            uid,
            gid,
            permissions,
            access_time,
            modify_time,
            extended: Vec::new(),
        }
    }

    /// Creates an attribute block from non-optional typed values.
    #[must_use]
    pub const fn from_values(
        size: u64,
        uid: u32,
        gid: u32,
        permissions: u32,
        access_time: u32,
        modify_time: u32,
    ) -> Self {
        Self::from_fields(
            Some(size),
            Some(uid),
            Some(gid),
            Some(permissions),
            Some(access_time),
            Some(modify_time),
        )
    }

    /// Adds or replaces the file size.
    #[must_use]
    pub fn with_size(mut self, size: Option<u64>) -> Self {
        self.size = size;
        self
    }

    /// Creates an empty attribute block.
    #[must_use]
    pub const fn empty() -> Self {
        Self::new()
    }

    /// Adds or replaces the user id.
    #[must_use]
    pub fn with_uid(mut self, uid: Option<u32>) -> Self {
        self.uid = uid;
        self
    }

    /// Adds or replaces the group id.
    #[must_use]
    pub fn with_gid(mut self, gid: Option<u32>) -> Self {
        self.gid = gid;
        self
    }

    /// Adds or replaces the user id using its descriptive name.
    #[must_use]
    pub fn with_user_id(self, uid: Option<u32>) -> Self {
        self.with_uid(uid)
    }

    /// Adds or replaces the group id using its descriptive name.
    #[must_use]
    pub fn with_group_id(self, gid: Option<u32>) -> Self {
        self.with_gid(gid)
    }

    /// Adds or replaces the user and group ids.
    #[must_use]
    pub fn with_ids(mut self, uid: Option<u32>, gid: Option<u32>) -> Self {
        self.uid = uid;
        self.gid = gid;
        self
    }

    /// Adds or replaces the permissions.
    #[must_use]
    pub fn with_permissions(mut self, permissions: Option<u32>) -> Self {
        self.permissions = permissions;
        self
    }

    /// Adds or replaces the access and modification times.
    #[must_use]
    pub fn with_times(mut self, access_time: Option<u32>, modify_time: Option<u32>) -> Self {
        self.access_time = access_time;
        self.modify_time = modify_time;
        self
    }

    /// Adds or replaces the access time.
    #[must_use]
    pub fn with_access_time(mut self, access_time: Option<u32>) -> Self {
        self.access_time = access_time;
        self
    }

    /// Adds or replaces the modification time.
    #[must_use]
    pub fn with_modify_time(mut self, modify_time: Option<u32>) -> Self {
        self.modify_time = modify_time;
        self
    }

    /// Adds or replaces the extended pairs.
    #[must_use]
    pub fn with_extended(mut self, extended: Vec<SftpExtendedAttribute>) -> Self {
        self.extended = extended;
        self
    }

    /// Returns the optional file size.
    #[must_use]
    pub const fn size(&self) -> Option<u64> {
        self.size
    }

    /// Returns the optional user id.
    #[must_use]
    pub const fn uid(&self) -> Option<u32> {
        self.uid
    }

    /// Returns the optional group id.
    #[must_use]
    pub const fn gid(&self) -> Option<u32> {
        self.gid
    }

    /// Returns the optional user id using the descriptive name.
    #[must_use]
    pub const fn user_id(&self) -> Option<u32> {
        self.uid
    }

    /// Returns the optional group id using the descriptive name.
    #[must_use]
    pub const fn group_id(&self) -> Option<u32> {
        self.gid
    }

    /// Returns the optional permissions.
    #[must_use]
    pub const fn permissions(&self) -> Option<u32> {
        self.permissions
    }

    /// Returns the optional access time.
    #[must_use]
    pub const fn access_time(&self) -> Option<u32> {
        self.access_time
    }

    /// Returns the optional modification time.
    #[must_use]
    pub const fn modify_time(&self) -> Option<u32> {
        self.modify_time
    }

    /// Returns the optional access time using the short name.
    #[must_use]
    pub const fn atime(&self) -> Option<u32> {
        self.access_time()
    }

    /// Returns the optional modification time using the short name.
    #[must_use]
    pub const fn mtime(&self) -> Option<u32> {
        self.modify_time()
    }

    /// Returns the retained extended pairs.
    #[must_use]
    pub fn extended(&self) -> &[SftpExtendedAttribute] {
        &self.extended
    }

    /// Returns the retained extended pairs using the descriptive name.
    #[must_use]
    pub fn extended_attributes(&self) -> &[SftpExtendedAttribute] {
        self.extended()
    }

    /// Encodes this attribute block without an SFTP response id.
    ///
    /// # Errors
    ///
    /// Returns [`SftpError::FrameTooLarge`] if the complete block exceeds the
    /// packet cap.
    pub fn encode(&self) -> Result<Vec<u8>, SftpError> {
        encode_attributes(self)
    }

    /// Encodes this attribute block without an SFTP response id.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::encode`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, SftpError> {
        self.encode()
    }

    /// Decodes one complete attribute block.
    ///
    /// # Errors
    ///
    /// Returns [`SftpError::InvalidAttributes`] for unknown flag bits or
    /// malformed fields, and a framing error for truncation or trailing data.
    pub fn decode(input: &[u8]) -> Result<Self, SftpError> {
        if input.len() > MAX_SFTP_PACKET_SIZE {
            return Err(SftpError::FrameTooLarge);
        }
        let mut reader = Reader::new(input);
        let attributes = decode_attributes(&mut reader)?;
        if !reader.is_empty() {
            return Err(SftpError::InvalidFrame);
        }
        Ok(attributes)
    }

    /// Decodes one complete attribute block.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::decode`].
    pub fn from_bytes(input: &[u8]) -> Result<Self, SftpError> {
        Self::decode(input)
    }
}

impl fmt::Debug for SftpAttributes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SftpAttributes")
            .field("size", &self.size)
            .field("uid", &self.uid)
            .field("gid", &self.gid)
            .field("permissions", &self.permissions)
            .field("access_time", &self.access_time)
            .field("modify_time", &self.modify_time)
            .field("extended_count", &self.extended.len())
            .finish()
    }
}

/// A short alias for [`SftpAttributes`].
pub type SftpAttrs = SftpAttributes;

/// A descriptive alias for [`SftpAttributes`].
pub type SftpFileAttributes = SftpAttributes;

/// A short alias for [`SftpAttributes`].
pub type FileAttributes = SftpAttributes;

/// A short alias for [`SftpAttributes`].
pub type SftpAttribute = SftpAttributes;

/// A short alias for [`SftpAttributes`].
pub type SftpFileAttrs = SftpAttributes;

/// One entry in an SFTP `NAME` response used by directory listings or links.
#[derive(Clone, Eq, PartialEq)]
pub struct SftpDirectoryEntry {
    /// The exact filename/path bytes.
    pub name: Vec<u8>,
    /// The exact long-name bytes supplied by the server.
    pub long_name: Vec<u8>,
    /// The entry's typed and extended attributes.
    pub attributes: SftpAttributes,
}

impl SftpDirectoryEntry {
    /// Creates a directory entry after validating its filename bytes.
    ///
    /// # Errors
    ///
    /// Returns an empty or overlong path error for `name`.
    pub fn new<N, L>(name: N, long_name: L, attributes: SftpAttributes) -> Result<Self, SftpError>
    where
        N: AsRef<[u8]>,
        L: AsRef<[u8]>,
    {
        validate_path(name.as_ref())?;
        Ok(Self {
            name: name.as_ref().to_vec(),
            long_name: long_name.as_ref().to_vec(),
            attributes,
        })
    }

    /// Returns the exact filename/path bytes.
    #[must_use]
    pub fn name(&self) -> &[u8] {
        &self.name
    }

    /// Returns the exact filename/path bytes using the long-name spelling.
    #[must_use]
    pub fn file_name(&self) -> &[u8] {
        self.name()
    }

    /// Returns the exact long-name bytes.
    #[must_use]
    pub fn long_name(&self) -> &[u8] {
        &self.long_name
    }

    /// Returns the entry attributes.
    #[must_use]
    pub const fn attributes(&self) -> &SftpAttributes {
        &self.attributes
    }

    /// Returns the entry attributes using the short name.
    #[must_use]
    pub const fn attrs(&self) -> &SftpAttributes {
        self.attributes()
    }
}

impl fmt::Debug for SftpDirectoryEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SftpDirectoryEntry")
            .field("name_length", &self.name.len())
            .field("long_name_length", &self.long_name.len())
            .field("attributes", &self.attributes)
            .finish()
    }
}

/// A short alias for [`SftpDirectoryEntry`].
pub type DirectoryEntry = SftpDirectoryEntry;

/// The result of one SFTP `READDIR` request.
///
/// `Eof` is a successful end-of-directory result, not a transport error.
#[derive(Clone, Eq, PartialEq)]
pub enum SftpReadDirResult {
    /// One batch of directory entries.
    Entries(Vec<SftpDirectoryEntry>),
    /// The server reported `SSH_FX_EOF`.
    Eof,
}

impl fmt::Debug for SftpReadDirResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Entries(entries) => formatter
                .debug_struct("Entries")
                .field("count", &entries.len())
                .finish(),
            Self::Eof => formatter.write_str("Eof"),
        }
    }
}

impl SftpReadDirResult {
    /// Returns whether this is an end-of-directory result.
    #[must_use]
    pub const fn is_eof(&self) -> bool {
        matches!(self, Self::Eof)
    }

    /// Returns the entry vector, or `None` for EOF.
    #[must_use]
    pub fn into_option(self) -> Option<Vec<SftpDirectoryEntry>> {
        match self {
            Self::Entries(entries) => Some(entries),
            Self::Eof => None,
        }
    }
}

/// A short alias for [`SftpReadDirResult`].
pub type ReadDirResult = SftpReadDirResult;

/// A descriptive alias for [`SftpReadDirResult`].
pub type SftpReadDirOutcome = SftpReadDirResult;

/// The result of one SFTP `READ` request.
///
/// `Eof` is a successful end-of-file result, not a transport error.  A short
/// data response is represented by `Data` and may contain fewer bytes than the
/// requested length.
#[derive(Clone, Eq, PartialEq)]
pub enum SftpReadResult {
    /// Bytes returned by the server.
    Data(Vec<u8>),
    /// The server reported `SSH_FX_EOF`.
    Eof,
}

impl fmt::Debug for SftpReadResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Data(data) => formatter
                .debug_struct("Data")
                .field("length", &data.len())
                .finish(),
            Self::Eof => formatter.write_str("Eof"),
        }
    }
}

impl SftpReadResult {
    /// Returns whether this is an end-of-file result.
    #[must_use]
    pub const fn is_eof(&self) -> bool {
        matches!(self, Self::Eof)
    }

    /// Returns the data slice, or `None` for EOF.
    #[must_use]
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Data(data) => Some(data),
            Self::Eof => None,
        }
    }

    /// Returns the data slice, treating EOF as an empty slice.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Data(data) => data,
            Self::Eof => &[],
        }
    }

    /// Returns the number of data bytes, or zero for EOF.
    #[must_use]
    pub fn len(&self) -> usize {
        self.as_slice().len()
    }

    /// Returns whether the result has no data bytes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.as_slice().is_empty()
    }

    /// Converts this result into the optional byte representation.
    #[must_use]
    pub fn into_option(self) -> Option<Vec<u8>> {
        match self {
            Self::Data(data) => Some(data),
            Self::Eof => None,
        }
    }
}

impl AsRef<[u8]> for SftpReadResult {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl PartialEq<Vec<u8>> for SftpReadResult {
    fn eq(&self, other: &Vec<u8>) -> bool {
        matches!(self, Self::Data(data) if data.as_slice() == other.as_slice())
    }
}

impl PartialEq<SftpReadResult> for Vec<u8> {
    fn eq(&self, other: &SftpReadResult) -> bool {
        other == self
    }
}

impl PartialEq<&[u8]> for SftpReadResult {
    fn eq(&self, other: &&[u8]) -> bool {
        matches!(self, Self::Data(data) if data.as_slice() == *other)
    }
}

impl PartialEq<SftpReadResult> for &[u8] {
    fn eq(&self, other: &SftpReadResult) -> bool {
        other == self
    }
}

impl From<SftpReadResult> for Option<Vec<u8>> {
    fn from(result: SftpReadResult) -> Self {
        result.into_option()
    }
}

/// A short alias for [`SftpReadResult`].
pub type ReadResult = SftpReadResult;

/// A descriptive alias for [`SftpReadResult`].
pub type SftpReadOutcome = SftpReadResult;

/// An extension pair received in a VERSION response.
///
/// This client parses and retains these pairs for inspection, but does not
/// implement any extension operation.
#[derive(Clone, Eq, PartialEq)]
pub struct SftpExtension {
    /// Exact extension name bytes.
    pub name: Vec<u8>,
    /// Exact extension value bytes.
    pub value: Vec<u8>,
}

impl SftpExtension {
    /// Creates one extension pair.
    #[must_use]
    pub fn new<N, V>(name: N, value: V) -> Self
    where
        N: AsRef<[u8]>,
        V: AsRef<[u8]>,
    {
        Self {
            name: name.as_ref().to_vec(),
            value: value.as_ref().to_vec(),
        }
    }

    /// Returns the exact extension name bytes.
    #[must_use]
    pub fn name(&self) -> &[u8] {
        &self.name
    }

    /// Returns the exact extension value bytes.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

impl fmt::Debug for SftpExtension {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SftpExtension")
            .field("name_length", &self.name.len())
            .field("value_length", &self.value.len())
            .finish()
    }
}

/// The v3 SFTP `OPEN` pflags represented as a safe bit set.
#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SftpOpenFlags(u32);

impl SftpOpenFlags {
    /// Open for reading.
    pub const READ: Self = Self(SSH_FXF_READ);
    /// Open for writing.
    pub const WRITE: Self = Self(SSH_FXF_WRITE);
    /// Append writes.
    pub const APPEND: Self = Self(SSH_FXF_APPEND);
    /// Create the file when it does not exist.
    pub const CREAT: Self = Self(SSH_FXF_CREAT);
    /// Truncate an existing file.
    pub const TRUNC: Self = Self(SSH_FXF_TRUNC);
    /// Fail with `FILE_ALREADY_EXISTS` when combined with CREAT.
    pub const EXCL: Self = Self(SSH_FXF_EXCL);

    /// Rust-style aliases for the protocol flag names.
    #[allow(non_upper_case_globals)]
    pub const Read: Self = Self::READ;
    /// Rust-style alias for [`Self::WRITE`].
    #[allow(non_upper_case_globals)]
    pub const Write: Self = Self::WRITE;
    /// Rust-style alias for [`Self::APPEND`].
    #[allow(non_upper_case_globals)]
    pub const Append: Self = Self::APPEND;
    /// Rust-style alias for [`Self::CREAT`].
    #[allow(non_upper_case_globals)]
    pub const Create: Self = Self::CREAT;
    /// An uppercase alias for [`Self::CREAT`].
    pub const CREATE: Self = Self::CREAT;
    /// Rust-style alias for [`Self::TRUNC`].
    #[allow(non_upper_case_globals)]
    pub const Truncate: Self = Self::TRUNC;
    /// Rust-style alias for [`Self::EXCL`].
    #[allow(non_upper_case_globals)]
    pub const Exclusive: Self = Self::EXCL;

    /// Creates a flag set from a raw wire value.
    ///
    /// # Errors
    ///
    /// Returns [`SftpError::InvalidOpenFlags`] when a bit outside the six v3
    /// pflags is set.
    pub const fn from_bits(bits: u32) -> Result<Self, SftpError> {
        if bits & !Self::all_bits() == 0 {
            Ok(Self(bits))
        } else {
            Err(SftpError::InvalidOpenFlags)
        }
    }

    /// Creates a flag set from a raw wire value, retaining only known bits.
    #[must_use]
    pub const fn from_bits_truncate(bits: u32) -> Self {
        Self(bits & Self::all_bits())
    }

    /// Creates a flag set from a raw wire value, retaining only known bits.
    #[must_use]
    pub const fn from_bits_retain(bits: u32) -> Self {
        Self::from_bits_truncate(bits)
    }

    /// Returns an empty flag set.
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Returns a flag set containing every v3 pflag.
    #[must_use]
    pub const fn all() -> Self {
        Self(Self::all_bits())
    }

    /// Returns whether the raw value contains only known v3 pflags.
    #[must_use]
    pub const fn is_valid(bits: u32) -> bool {
        bits & !Self::all_bits() == 0
    }

    /// Returns the raw wire bits.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Returns whether no flag is set.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Returns whether all bits in `other` are set.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Returns whether any bit in `other` is set.
    #[must_use]
    pub const fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    const fn all_bits() -> u32 {
        SSH_FXF_READ | SSH_FXF_WRITE | SSH_FXF_APPEND | SSH_FXF_CREAT | SSH_FXF_TRUNC | SSH_FXF_EXCL
    }
}

impl std::ops::BitOr for SftpOpenFlags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitOrAssign for SftpOpenFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl std::ops::BitAnd for SftpOpenFlags {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl std::ops::Not for SftpOpenFlags {
    type Output = Self;

    fn not(self) -> Self::Output {
        Self(!self.0 & Self::all_bits())
    }
}

impl PartialEq<u32> for SftpOpenFlags {
    fn eq(&self, other: &u32) -> bool {
        self.bits() == *other
    }
}

impl PartialEq<SftpOpenFlags> for u32 {
    fn eq(&self, other: &SftpOpenFlags) -> bool {
        *self == other.bits()
    }
}

impl From<SftpOpenFlags> for u32 {
    fn from(flags: SftpOpenFlags) -> Self {
        flags.bits()
    }
}

impl TryFrom<u32> for SftpOpenFlags {
    type Error = SftpError;

    fn try_from(bits: u32) -> Result<Self, Self::Error> {
        Self::from_bits(bits)
    }
}

impl fmt::Debug for SftpOpenFlags {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SftpOpenFlags")
            .field(&self.0)
            .finish()
    }
}

/// A short alias for [`SftpOpenFlags`].
pub type OpenFlags = SftpOpenFlags;

/// A value accepted as an SFTP OPEN pflags word.
///
/// Raw `u32` values are validated rather than silently truncated, so callers
/// can pass the protocol constants directly to [`SftpClient::open`].
pub trait SftpOpenFlagsInput {
    /// Converts the value to a validated v3 pflags set.
    ///
    /// # Errors
    ///
    /// Returns [`SftpError::InvalidOpenFlags`] for unknown raw bits.
    fn into_open_flags(self) -> Result<SftpOpenFlags, SftpError>;
}

impl SftpOpenFlagsInput for SftpOpenFlags {
    fn into_open_flags(self) -> Result<SftpOpenFlags, SftpError> {
        Ok(self)
    }
}

impl SftpOpenFlagsInput for &SftpOpenFlags {
    fn into_open_flags(self) -> Result<SftpOpenFlags, SftpError> {
        Ok(*self)
    }
}

impl SftpOpenFlagsInput for u32 {
    fn into_open_flags(self) -> Result<SftpOpenFlags, SftpError> {
        SftpOpenFlags::from_bits(self)
    }
}

macro_rules! impl_sftp_open_flags_input_integer {
    ($($integer:ty),+ $(,)?) => {
        $(
            impl SftpOpenFlagsInput for $integer {
                fn into_open_flags(self) -> Result<SftpOpenFlags, SftpError> {
                    let bits = u32::try_from(self).map_err(|_error| SftpError::InvalidOpenFlags)?;
                    SftpOpenFlags::from_bits(bits)
                }
            }
        )+
    };
}

impl_sftp_open_flags_input_integer!(u8, u16, u64, usize, i8, i16, i32, i64, isize);

/// Values accepted by [`SftpClient::make_directory`].
pub trait SftpAttributesInput {
    /// Returns the optional attribute block represented by this value.
    fn as_attributes(&self) -> Option<&SftpAttributes>;
}

impl SftpAttributesInput for SftpAttributes {
    fn as_attributes(&self) -> Option<&SftpAttributes> {
        Some(self)
    }
}

impl SftpAttributesInput for &SftpAttributes {
    fn as_attributes(&self) -> Option<&SftpAttributes> {
        Some(self)
    }
}

impl SftpAttributesInput for Option<&SftpAttributes> {
    fn as_attributes(&self) -> Option<&SftpAttributes> {
        *self
    }
}

/// A sequential SFTP version 3 client over a caller-supplied byte stream.
///
/// Use [`Self::initialize`] once, then issue one operation at a time.  The
/// client never negotiates a channel and never owns a network endpoint.
pub struct SftpClient<T> {
    transport: T,
    initialized: bool,
    version: u32,
    extensions: Vec<SftpExtension>,
    next_request_id: u32,
    request_in_flight: bool,
}

#[allow(clippy::missing_fields_in_debug)]
impl<T> fmt::Debug for SftpClient<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SftpClient")
            .field("initialized", &self.initialized)
            .field("version", &self.version)
            .field("extension_count", &self.extensions.len())
            .field("next_request_id", &self.next_request_id)
            .field("request_in_flight", &self.request_in_flight)
            .finish()
    }
}

impl<T> SftpClient<T> {
    /// Wraps an already-open byte stream without performing I/O.
    #[must_use]
    pub const fn new(transport: T) -> Self {
        Self {
            transport,
            initialized: false,
            version: 0,
            extensions: Vec::new(),
            next_request_id: 0,
            request_in_flight: false,
        }
    }

    /// Returns whether VERSION negotiation has completed.
    #[must_use]
    pub const fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Returns whether VERSION negotiation has completed.
    #[must_use]
    pub const fn initialized(&self) -> bool {
        self.initialized
    }

    /// Returns the negotiated version, or zero before initialization.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Returns the negotiated version as an optional value.
    #[must_use]
    pub const fn negotiated_version(&self) -> Option<u32> {
        if self.initialized {
            Some(self.version)
        } else {
            None
        }
    }

    /// Returns extension pairs received in the VERSION packet.
    #[must_use]
    pub fn extensions(&self) -> &[SftpExtension] {
        &self.extensions
    }

    /// Returns the next request id that will be used.
    #[must_use]
    pub const fn next_request_id(&self) -> u32 {
        self.next_request_id
    }

    /// Returns whether a request is currently being exchanged.
    #[must_use]
    pub const fn request_in_flight(&self) -> bool {
        self.request_in_flight
    }

    /// Returns a reference to the wrapped stream.
    #[must_use]
    pub const fn transport(&self) -> &T {
        &self.transport
    }

    /// Returns a mutable reference to the wrapped stream.
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Consumes the client and returns its wrapped stream.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.transport
    }
}

impl<T> SftpClient<T>
where
    T: Read + Write,
{
    /// Creates a client and performs SFTP VERSION negotiation.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::initialize`].
    pub fn connect(transport: T) -> Result<Self, SftpError> {
        let mut client = Self::new(transport);
        client.initialize()?;
        Ok(client)
    }

    /// Creates a client and performs SFTP VERSION negotiation.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::initialize`].
    pub fn from_stream(transport: T) -> Result<Self, SftpError> {
        Self::connect(transport)
    }

    /// Creates a client and performs SFTP VERSION negotiation.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::initialize`].
    pub fn start(transport: T) -> Result<Self, SftpError> {
        Self::connect(transport)
    }

    /// Sends INIT and requires a VERSION response with version exactly 3.
    ///
    /// Extension pairs following the version are parsed and retained for
    /// inspection, but no extension operation is enabled.
    ///
    /// # Errors
    ///
    /// Returns a transport, framing, version, or malformed-response error.
    pub fn initialize(&mut self) -> Result<(), SftpError> {
        if self.initialized {
            return Err(SftpError::AlreadyInitialized);
        }
        if self.request_in_flight {
            return Err(SftpError::RequestInFlight);
        }

        let init = [SSH_FXP_INIT, 0, 0, 0, 3];
        write_packet(&mut self.transport, &init)?;
        let response = read_packet(&mut self.transport)?;
        let packet_type = response.first().copied().ok_or(SftpError::InvalidFrame)?;
        if packet_type != SSH_FXP_VERSION {
            return Err(SftpError::UnexpectedResponse(packet_type));
        }
        let (version, extensions) = parse_version(&response)?;
        if version != SFTP_VERSION {
            return Err(SftpError::InvalidVersion(version));
        }
        self.version = version;
        self.extensions = extensions;
        self.initialized = true;
        self.next_request_id = 0;
        Ok(())
    }

    /// Sends INIT and requires a VERSION response with version exactly 3.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::initialize`].
    pub fn init(&mut self) -> Result<(), SftpError> {
        self.initialize()
    }

    /// Negotiates SFTP version 3 and returns the negotiated version.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::initialize`].
    pub fn initialize_version(&mut self) -> Result<u32, SftpError> {
        self.initialize()?;
        Ok(self.version)
    }

    /// Negotiates SFTP version 3 and returns the negotiated version.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::initialize`].
    pub fn init_version(&mut self) -> Result<u32, SftpError> {
        self.initialize_version()
    }

    /// Negotiates SFTP version 3.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::initialize`].
    pub fn negotiate(&mut self) -> Result<(), SftpError> {
        self.initialize()
    }

    /// Opens a remote path and returns its opaque handle.
    ///
    /// # Errors
    ///
    /// Returns path, packet, request-id, transport, or server-status errors.
    pub fn open<P, F>(&mut self, path: P, flags: F) -> Result<SftpHandle, SftpError>
    where
        P: SftpBytes,
        F: SftpOpenFlagsInput,
    {
        let flags = flags.into_open_flags()?;
        self.open_with_attributes(path, flags, SftpAttributes::new())
    }

    /// Opens a remote path with explicit v3 attributes.
    ///
    /// # Errors
    ///
    /// Returns path, attribute, packet, request-id, transport, or server-status
    /// errors.
    #[allow(clippy::needless_pass_by_value)]
    pub fn open_with_attributes<P, F, A>(
        &mut self,
        path: P,
        flags: F,
        attributes: A,
    ) -> Result<SftpHandle, SftpError>
    where
        P: SftpBytes,
        F: SftpOpenFlagsInput,
        A: SftpAttributesInput,
    {
        let flags = flags.into_open_flags()?;
        let attributes = attributes
            .as_attributes()
            .map_or_else(SftpAttributes::new, Clone::clone);
        let path = path.as_sftp_bytes();
        validate_path_bytes(path)?;
        let flags_bits = flags.bits();
        if !SftpOpenFlags::is_valid(flags_bits) {
            return Err(SftpError::InvalidOpenFlags);
        }
        let response = self.exchange(SSH_FXP_OPEN, |id| {
            let mut packet = PacketBuilder::with_capacity(64);
            packet.push_byte(SSH_FXP_OPEN);
            packet.push_uint32(id);
            packet.push_string(path, MAX_SFTP_PATH_SIZE, SftpError::PathTooLong)?;
            packet.push_uint32(flags_bits);
            packet.push_bytes(&attributes.encode()?)?;
            packet.finish()
        })?;
        parse_handle_response(&response, self.last_request_id())
    }

    /// Opens a remote path with explicit raw pflags after validating them.
    ///
    /// # Errors
    ///
    /// Returns invalid-flag, path, packet, transport, or server-status errors.
    pub fn open_with_pflags<P>(&mut self, path: P, flags: u32) -> Result<SftpHandle, SftpError>
    where
        P: SftpBytes,
    {
        let flags = SftpOpenFlags::from_bits(flags)?;
        self.open(path, flags)
    }

    /// Closes an opaque remote handle.
    ///
    /// # Errors
    ///
    /// Returns handle, packet, transport, request-id, or server-status errors.
    pub fn close<H>(&mut self, handle: H) -> Result<(), SftpError>
    where
        H: SftpBytes,
    {
        let handle = handle.as_sftp_bytes();
        validate_handle_bytes(handle)?;
        let response = self.exchange(SSH_FXP_CLOSE, |id| {
            let mut packet = PacketBuilder::with_capacity(32);
            packet.push_byte(SSH_FXP_CLOSE);
            packet.push_uint32(id);
            packet.push_string(handle, MAX_SFTP_HANDLE_SIZE, SftpError::HandleTooLong)?;
            packet.finish()
        })?;
        status_result(&response, false).map(|_| ())
    }

    /// Reads up to `length` bytes at a remote offset.
    ///
    /// `SftpReadResult::Eof` is returned for `SSH_FX_EOF`; it is not a
    /// transport failure.  A shorter `Data` result is a valid short read.
    ///
    /// # Errors
    ///
    /// Returns handle, length, packet, transport, request-id, or non-EOF server
    /// status errors.
    pub fn read<H, L>(
        &mut self,
        handle: H,
        offset: u64,
        length: L,
    ) -> Result<SftpReadResult, SftpError>
    where
        H: SftpBytes,
        L: TryInto<u32>,
    {
        let handle = handle.as_sftp_bytes();
        validate_handle_bytes(handle)?;
        let length_wire = length
            .try_into()
            .map_err(|_error| SftpError::InvalidReadLength)?;
        let length = usize::try_from(length_wire).map_err(|_error| SftpError::InvalidReadLength)?;
        let response = self.exchange(SSH_FXP_READ, |id| {
            let mut packet = PacketBuilder::with_capacity(64);
            packet.push_byte(SSH_FXP_READ);
            packet.push_uint32(id);
            packet.push_string(handle, MAX_SFTP_HANDLE_SIZE, SftpError::HandleTooLong)?;
            packet.push_uint64(offset);
            packet.push_uint32(length_wire);
            packet.finish()
        })?;
        if response.first() == Some(&SSH_FXP_DATA) {
            let data = parse_data_response(&response, length)?;
            return Ok(SftpReadResult::Data(data));
        }
        if response.first() == Some(&SSH_FXP_STATUS) {
            return match parse_status_response(&response, true)? {
                StatusDisposition::Ok => Ok(SftpReadResult::Data(Vec::new())),
                StatusDisposition::Eof => Ok(SftpReadResult::Eof),
            };
        }
        Err(unexpected_response_type(&response))
    }

    /// Reads up to `length` bytes and returns the explicit data/EOF result.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::read`].
    pub fn read_result<H, L>(
        &mut self,
        handle: H,
        offset: u64,
        length: L,
    ) -> Result<SftpReadResult, SftpError>
    where
        H: SftpBytes,
        L: TryInto<u32>,
    {
        self.read(handle, offset, length)
    }

    /// Reads up to `length` bytes and converts EOF to `None`.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::read`].
    pub fn read_optional<H, L>(
        &mut self,
        handle: H,
        offset: u64,
        length: L,
    ) -> Result<Option<Vec<u8>>, SftpError>
    where
        H: SftpBytes,
        L: TryInto<u32>,
    {
        Ok(self.read(handle, offset, length)?.into_option())
    }

    /// Reads bytes and reports EOF as [`SftpError::Status`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::read`], including a status error for
    /// `SSH_FX_EOF`.
    pub fn read_bytes<H, L>(
        &mut self,
        handle: H,
        offset: u64,
        length: L,
    ) -> Result<Vec<u8>, SftpError>
    where
        H: SftpBytes,
        L: TryInto<u32>,
    {
        match self.read(handle, offset, length)? {
            SftpReadResult::Data(data) => Ok(data),
            SftpReadResult::Eof => Err(SftpError::Status(SSH_FX_EOF)),
        }
    }

    /// Writes bytes at a remote offset.
    ///
    /// # Errors
    ///
    /// Returns handle, packet, transport, request-id, or server-status errors.
    pub fn write<H, D>(&mut self, handle: H, offset: u64, data: D) -> Result<(), SftpError>
    where
        H: SftpBytes,
        D: AsRef<[u8]>,
    {
        let handle = handle.as_sftp_bytes();
        let data = data.as_ref();
        validate_handle_bytes(handle)?;
        let response = self.exchange(SSH_FXP_WRITE, |id| {
            let mut packet = PacketBuilder::with_capacity(64);
            packet.push_byte(SSH_FXP_WRITE);
            packet.push_uint32(id);
            packet.push_string(handle, MAX_SFTP_HANDLE_SIZE, SftpError::HandleTooLong)?;
            packet.push_uint64(offset);
            packet.push_string(data, MAX_SFTP_PACKET_SIZE, SftpError::FrameTooLarge)?;
            packet.finish()
        })?;
        status_result(&response, false).map(|_| ())
    }

    /// Gets attributes without following a symbolic link.
    ///
    /// # Errors
    ///
    /// Returns path, packet, transport, request-id, or server-status errors.
    pub fn lstat<P>(&mut self, path: P) -> Result<SftpAttributes, SftpError>
    where
        P: SftpBytes,
    {
        self.path_attributes(SSH_FXP_LSTAT, path)
    }

    /// Gets attributes for an open handle.
    ///
    /// # Errors
    ///
    /// Returns handle, packet, transport, request-id, or server-status errors.
    pub fn fstat<H>(&mut self, handle: H) -> Result<SftpAttributes, SftpError>
    where
        H: SftpBytes,
    {
        let handle = handle.as_sftp_bytes();
        validate_handle_bytes(handle)?;
        let response = self.exchange(SSH_FXP_FSTAT, |id| {
            let mut packet = PacketBuilder::with_capacity(32);
            packet.push_byte(SSH_FXP_FSTAT);
            packet.push_uint32(id);
            packet.push_string(handle, MAX_SFTP_HANDLE_SIZE, SftpError::HandleTooLong)?;
            packet.finish()
        })?;
        if response.first() == Some(&SSH_FXP_ATTRS) {
            parse_attributes_response(&response)
        } else if response.first() == Some(&SSH_FXP_STATUS) {
            status_result(&response, false)?;
            Err(SftpError::UnexpectedResponse(SSH_FXP_STATUS))
        } else {
            Err(unexpected_response_type(&response))
        }
    }

    /// Gets attributes following symbolic links.
    ///
    /// # Errors
    ///
    /// Returns path, packet, transport, request-id, or server-status errors.
    pub fn stat<P>(&mut self, path: P) -> Result<SftpAttributes, SftpError>
    where
        P: SftpBytes,
    {
        self.path_attributes(SSH_FXP_STAT, path)
    }

    /// Changes attributes for a path.
    ///
    /// # Errors
    ///
    /// Returns path, attribute, packet, transport, request-id, or server-status
    /// errors.
    #[allow(clippy::needless_pass_by_value)]
    pub fn setstat<P, A>(&mut self, path: P, attributes: A) -> Result<(), SftpError>
    where
        P: SftpBytes,
        A: SftpAttributesInput,
    {
        let attributes = attributes
            .as_attributes()
            .map_or_else(SftpAttributes::new, Clone::clone);
        let path = path.as_sftp_bytes();
        validate_path_bytes(path)?;
        let response = self.exchange(SSH_FXP_SETSTAT, |id| {
            let mut packet = PacketBuilder::with_capacity(64);
            packet.push_byte(SSH_FXP_SETSTAT);
            packet.push_uint32(id);
            packet.push_string(path, MAX_SFTP_PATH_SIZE, SftpError::PathTooLong)?;
            packet.push_bytes(&attributes.encode()?)?;
            packet.finish()
        })?;
        status_result(&response, false).map(|_| ())
    }

    /// Opens a directory and returns its opaque handle.
    ///
    /// # Errors
    ///
    /// Returns path, packet, transport, request-id, or server-status errors.
    pub fn opendir<P>(&mut self, path: P) -> Result<SftpHandle, SftpError>
    where
        P: SftpBytes,
    {
        let path = path.as_sftp_bytes();
        validate_path_bytes(path)?;
        let response = self.exchange(SSH_FXP_OPENDIR, |id| {
            let mut packet = PacketBuilder::with_capacity(32);
            packet.push_byte(SSH_FXP_OPENDIR);
            packet.push_uint32(id);
            packet.push_string(path, MAX_SFTP_PATH_SIZE, SftpError::PathTooLong)?;
            packet.finish()
        })?;
        parse_handle_response(&response, self.last_request_id())
    }

    /// Opens a directory using the descriptive method name.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::opendir`].
    pub fn open_directory<P>(&mut self, path: P) -> Result<SftpHandle, SftpError>
    where
        P: SftpBytes,
    {
        self.opendir(path)
    }

    /// Reads one directory batch.
    ///
    /// An EOF status is represented by an empty vector.  This is an end result,
    /// not a transport error.
    ///
    /// # Errors
    ///
    /// Returns handle, packet, transport, request-id, or non-EOF server-status
    /// errors.
    pub fn readdir<H>(&mut self, handle: H) -> Result<Vec<SftpDirectoryEntry>, SftpError>
    where
        H: SftpBytes,
    {
        match self.readdir_result(handle)? {
            SftpReadDirResult::Entries(entries) => Ok(entries),
            SftpReadDirResult::Eof => Ok(Vec::new()),
        }
    }

    /// Reads one directory batch and preserves EOF as an explicit result.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::readdir`].
    pub fn readdir_result<H>(&mut self, handle: H) -> Result<SftpReadDirResult, SftpError>
    where
        H: SftpBytes,
    {
        let handle = handle.as_sftp_bytes();
        validate_handle_bytes(handle)?;
        let response = self.exchange(SSH_FXP_READDIR, |id| {
            let mut packet = PacketBuilder::with_capacity(32);
            packet.push_byte(SSH_FXP_READDIR);
            packet.push_uint32(id);
            packet.push_string(handle, MAX_SFTP_HANDLE_SIZE, SftpError::HandleTooLong)?;
            packet.finish()
        })?;
        if response.first() == Some(&SSH_FXP_NAME) {
            parse_name_response(&response).map(SftpReadDirResult::Entries)
        } else if response.first() == Some(&SSH_FXP_STATUS) {
            match status_result(&response, true)? {
                StatusDisposition::Ok => Ok(SftpReadDirResult::Entries(Vec::new())),
                StatusDisposition::Eof => Ok(SftpReadDirResult::Eof),
            }
        } else {
            Err(unexpected_response_type(&response))
        }
    }

    /// Reads one directory batch and converts EOF to `None`.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::readdir`].
    pub fn readdir_optional<H>(
        &mut self,
        handle: H,
    ) -> Result<Option<Vec<SftpDirectoryEntry>>, SftpError>
    where
        H: SftpBytes,
    {
        Ok(self.readdir_result(handle)?.into_option())
    }

    /// Reads one directory batch using the descriptive method name.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::readdir`].
    pub fn read_directory<H>(&mut self, handle: H) -> Result<Vec<SftpDirectoryEntry>, SftpError>
    where
        H: SftpBytes,
    {
        self.readdir(handle)
    }

    /// Removes a remote file.
    ///
    /// # Errors
    ///
    /// Returns path, packet, transport, request-id, or server-status errors.
    pub fn remove<P>(&mut self, path: P) -> Result<(), SftpError>
    where
        P: SftpBytes,
    {
        self.path_status(SSH_FXP_REMOVE, path)
    }

    /// Creates a directory, optionally with v3 attributes.
    ///
    /// Pass `None` for the protocol's empty attribute block. An attribute
    /// value or reference is also accepted for callers that already have one.
    ///
    /// # Errors
    ///
    /// Returns path, attribute, packet, transport, request-id, or server-status
    /// errors.
    #[allow(clippy::needless_pass_by_value)]
    pub fn mkdir<P, A>(&mut self, path: P, attributes: A) -> Result<(), SftpError>
    where
        P: SftpBytes,
        A: SftpAttributesInput,
    {
        self.mkdir_with_optional_attributes(path, attributes.as_attributes())
    }

    /// Creates a directory with no optional attributes.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::mkdir`].
    pub fn mkdir_default<P>(&mut self, path: P) -> Result<(), SftpError>
    where
        P: SftpBytes,
    {
        self.mkdir(path, None)
    }

    /// Creates a directory with explicit v3 attributes.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::mkdir`].
    pub fn mkdir_with_attributes<P>(
        &mut self,
        path: P,
        attributes: &SftpAttributes,
    ) -> Result<(), SftpError>
    where
        P: SftpBytes,
    {
        self.mkdir(path, Some(attributes))
    }

    /// Creates a directory using a caller-selected optional attribute input.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::mkdir`].
    #[allow(clippy::needless_pass_by_value)]
    pub fn make_directory<P, A>(&mut self, path: P, attributes: A) -> Result<(), SftpError>
    where
        P: SftpBytes,
        A: SftpAttributesInput,
    {
        self.mkdir(path, attributes.as_attributes())
    }

    /// Removes an empty remote directory.
    ///
    /// # Errors
    ///
    /// Returns path, packet, transport, request-id, or server-status errors.
    pub fn rmdir<P>(&mut self, path: P) -> Result<(), SftpError>
    where
        P: SftpBytes,
    {
        self.path_status(SSH_FXP_RMDIR, path)
    }

    /// Resolves a path using the v3 REALPATH operation.
    ///
    /// The returned bytes are the exact filename field from the single NAME
    /// response entry.
    ///
    /// # Errors
    ///
    /// Returns path, packet, transport, request-id, malformed-NAME, or
    /// server-status errors.
    pub fn realpath<P>(&mut self, path: P) -> Result<Vec<u8>, SftpError>
    where
        P: SftpBytes,
    {
        let path = path.as_sftp_bytes();
        validate_path_bytes(path)?;
        let response = self.exchange(SSH_FXP_REALPATH, |id| {
            let mut packet = PacketBuilder::with_capacity(32);
            packet.push_byte(SSH_FXP_REALPATH);
            packet.push_uint32(id);
            packet.push_string(path, MAX_SFTP_PATH_SIZE, SftpError::PathTooLong)?;
            packet.finish()
        })?;
        single_name_field(&response)
    }

    /// Renames `old_path` to `new_path` in the required v3 order.
    ///
    /// # Errors
    ///
    /// Returns path, packet, transport, request-id, or server-status errors.
    pub fn rename<O, N>(&mut self, old_path: O, new_path: N) -> Result<(), SftpError>
    where
        O: SftpBytes,
        N: SftpBytes,
    {
        let old_path = old_path.as_sftp_bytes();
        let new_path = new_path.as_sftp_bytes();
        validate_path_bytes(old_path)?;
        validate_path_bytes(new_path)?;
        let response = self.exchange(SSH_FXP_RENAME, |id| {
            let mut packet = PacketBuilder::with_capacity(64);
            packet.push_byte(SSH_FXP_RENAME);
            packet.push_uint32(id);
            packet.push_string(old_path, MAX_SFTP_PATH_SIZE, SftpError::PathTooLong)?;
            packet.push_string(new_path, MAX_SFTP_PATH_SIZE, SftpError::PathTooLong)?;
            packet.finish()
        })?;
        status_result(&response, false).map(|_| ())
    }

    /// Reads the target of a symbolic link.
    ///
    /// # Errors
    ///
    /// Returns path, packet, transport, request-id, malformed-NAME, or
    /// server-status errors.
    pub fn readlink<P>(&mut self, path: P) -> Result<Vec<u8>, SftpError>
    where
        P: SftpBytes,
    {
        let path = path.as_sftp_bytes();
        validate_path_bytes(path)?;
        let response = self.exchange(SSH_FXP_READLINK, |id| {
            let mut packet = PacketBuilder::with_capacity(32);
            packet.push_byte(SSH_FXP_READLINK);
            packet.push_uint32(id);
            packet.push_string(path, MAX_SFTP_PATH_SIZE, SftpError::PathTooLong)?;
            packet.finish()
        })?;
        single_name_field(&response)
    }

    /// Creates a symbolic link using draft-02 wire order.
    ///
    /// The first path is the link path and the second path is the target path.
    /// OpenSSH's historical reversed order is intentionally not selected
    /// implicitly.
    ///
    /// # Errors
    ///
    /// Returns path, packet, transport, request-id, or server-status errors.
    pub fn symlink<L, Target>(&mut self, link_path: L, target_path: Target) -> Result<(), SftpError>
    where
        L: SftpBytes,
        Target: SftpBytes,
    {
        let link_path = link_path.as_sftp_bytes();
        let target_path = target_path.as_sftp_bytes();
        validate_path_bytes(link_path)?;
        validate_path_bytes(target_path)?;
        let response = self.exchange(SSH_FXP_SYMLINK, |id| {
            let mut packet = PacketBuilder::with_capacity(64);
            packet.push_byte(SSH_FXP_SYMLINK);
            packet.push_uint32(id);
            packet.push_string(link_path, MAX_SFTP_PATH_SIZE, SftpError::PathTooLong)?;
            packet.push_string(target_path, MAX_SFTP_PATH_SIZE, SftpError::PathTooLong)?;
            packet.finish()
        })?;
        status_result(&response, false).map(|_| ())
    }

    /// Creates a symbolic link with a target-first public argument order.
    ///
    /// The wire order remains the draft-02 link path followed by target path.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::symlink`].
    pub fn create_symbolic_link<Target, Link>(
        &mut self,
        target_path: Target,
        link_path: Link,
    ) -> Result<(), SftpError>
    where
        Target: SftpBytes,
        Link: SftpBytes,
    {
        self.symlink(link_path, target_path)
    }

    /// Creates a symbolic link using the link-first argument order.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::symlink`].
    pub fn create_symlink<Link, Target>(
        &mut self,
        link_path: Link,
        target_path: Target,
    ) -> Result<(), SftpError>
    where
        Link: SftpBytes,
        Target: SftpBytes,
    {
        self.symlink(link_path, target_path)
    }

    fn mkdir_with_optional_attributes<P>(
        &mut self,
        path: P,
        attributes: Option<&SftpAttributes>,
    ) -> Result<(), SftpError>
    where
        P: SftpBytes,
    {
        let path = path.as_sftp_bytes();
        validate_path_bytes(path)?;
        let attributes = attributes.map_or_else(SftpAttributes::new, Clone::clone);
        let response = self.exchange(SSH_FXP_MKDIR, |id| {
            let mut packet = PacketBuilder::with_capacity(64);
            packet.push_byte(SSH_FXP_MKDIR);
            packet.push_uint32(id);
            packet.push_string(path, MAX_SFTP_PATH_SIZE, SftpError::PathTooLong)?;
            packet.push_bytes(&attributes.encode()?)?;
            packet.finish()
        })?;
        status_result(&response, false).map(|_| ())
    }

    fn path_attributes<P>(&mut self, packet_type: u8, path: P) -> Result<SftpAttributes, SftpError>
    where
        P: SftpBytes,
    {
        let path = path.as_sftp_bytes();
        validate_path_bytes(path)?;
        let response = self.exchange(packet_type, |id| {
            let mut packet = PacketBuilder::with_capacity(32);
            packet.push_byte(packet_type);
            packet.push_uint32(id);
            packet.push_string(path, MAX_SFTP_PATH_SIZE, SftpError::PathTooLong)?;
            packet.finish()
        })?;
        if response.first() == Some(&SSH_FXP_ATTRS) {
            parse_attributes_response(&response)
        } else if response.first() == Some(&SSH_FXP_STATUS) {
            status_result(&response, false)?;
            Err(SftpError::UnexpectedResponse(SSH_FXP_STATUS))
        } else {
            Err(unexpected_response_type(&response))
        }
    }

    fn path_status<P>(&mut self, packet_type: u8, path: P) -> Result<(), SftpError>
    where
        P: SftpBytes,
    {
        let path = path.as_sftp_bytes();
        validate_path_bytes(path)?;
        let response = self.exchange(packet_type, |id| {
            let mut packet = PacketBuilder::with_capacity(32);
            packet.push_byte(packet_type);
            packet.push_uint32(id);
            packet.push_string(path, MAX_SFTP_PATH_SIZE, SftpError::PathTooLong)?;
            packet.finish()
        })?;
        status_result(&response, false).map(|_| ())
    }

    fn exchange<F>(&mut self, packet_type: u8, build: F) -> Result<Vec<u8>, SftpError>
    where
        F: FnOnce(u32) -> Result<Vec<u8>, SftpError>,
    {
        if !self.initialized {
            return Err(SftpError::NotInitialized);
        }
        if self.request_in_flight {
            return Err(SftpError::RequestInFlight);
        }
        let id = self.next_request_id;
        let body = build(id)?;
        if body.first() != Some(&packet_type) {
            return Err(SftpError::InvalidFrame);
        }
        let next_id = id.checked_add(1).ok_or(SftpError::RequestIdExhausted)?;
        self.next_request_id = next_id;
        self.request_in_flight = true;
        let result = write_packet(&mut self.transport, &body)
            .and_then(|()| read_packet(&mut self.transport));
        self.request_in_flight = false;
        let response = result?;
        validate_response_id(&response, id)?;
        Ok(response)
    }

    fn last_request_id(&self) -> u32 {
        self.next_request_id.saturating_sub(1)
    }
}

/// Validates a path without interpreting its bytes.
///
/// # Errors
///
/// Returns [`SftpError::InvalidPath`] for an empty path and
/// [`SftpError::PathTooLong`] for a path over 4096 bytes.
pub fn validate_path<P>(path: P) -> Result<(), SftpError>
where
    P: SftpBytes,
{
    validate_path_bytes(path.as_sftp_bytes())
}

/// Validates an opaque handle without interpreting its bytes.
///
/// # Errors
///
/// Returns [`SftpError::InvalidHandle`] for an empty handle and
/// [`SftpError::HandleTooLong`] for a handle over 256 bytes.
pub fn validate_handle<H>(handle: H) -> Result<(), SftpError>
where
    H: SftpBytes,
{
    validate_handle_bytes(handle.as_sftp_bytes())
}

/// Frames one complete SFTP packet for a caller-supplied stream.
///
/// The returned vector contains the four-byte length prefix followed by the
/// packet body.  Empty and oversized bodies are rejected.
///
/// # Errors
///
/// Returns [`SftpError::ZeroLength`] for an empty body and
/// [`SftpError::FrameTooLarge`] for a body over the packet cap.
pub fn encode_packet(packet: &[u8]) -> Result<Vec<u8>, SftpError> {
    if packet.is_empty() {
        return Err(SftpError::ZeroLength);
    }
    if packet.len() > MAX_SFTP_PACKET_SIZE {
        return Err(SftpError::FrameTooLarge);
    }
    let length = u32::try_from(packet.len()).map_err(|_error| SftpError::FrameTooLarge)?;
    let mut framed = Vec::with_capacity(4 + packet.len());
    framed.extend_from_slice(&length.to_be_bytes());
    framed.extend_from_slice(packet);
    Ok(framed)
}

/// Decodes exactly one complete framed SFTP packet from `input`.
///
/// The length is checked before a body is copied.  Extra bytes after the frame
/// are rejected.
///
/// # Errors
///
/// Returns a framing or packet-size error for invalid input.
pub fn decode_packet(input: &[u8]) -> Result<Vec<u8>, SftpError> {
    if input.len() < 4 {
        return Err(SftpError::InvalidFrame);
    }
    let length = read_length(input.get(0..4).ok_or(SftpError::InvalidFrame)?)?;
    validate_length(length)?;
    let end = 4_usize
        .checked_add(usize::try_from(length).map_err(|_error| SftpError::FrameTooLarge)?)
        .ok_or(SftpError::FrameTooLarge)?;
    if input.len() != end {
        return Err(SftpError::InvalidFrame);
    }
    Ok(input.get(4..end).ok_or(SftpError::InvalidFrame)?.to_vec())
}

/// Decodes one framed packet and returns the number of consumed input bytes.
///
/// # Errors
///
/// Returns the same errors as [`decode_packet`], except that bytes after the
/// first frame are returned as the consumed prefix length.
pub fn decode_packet_prefix(input: &[u8]) -> Result<(Vec<u8>, usize), SftpError> {
    if input.len() < 4 {
        return Err(SftpError::InvalidFrame);
    }
    let length = read_length(input.get(0..4).ok_or(SftpError::InvalidFrame)?)?;
    validate_length(length)?;
    let length = usize::try_from(length).map_err(|_error| SftpError::FrameTooLarge)?;
    let end = 4_usize
        .checked_add(length)
        .ok_or(SftpError::FrameTooLarge)?;
    let body = input.get(4..end).ok_or(SftpError::InvalidFrame)?;
    Ok((body.to_vec(), end))
}

/// Reads one complete SFTP frame from a caller-supplied stream.
///
/// The four-byte length is read and validated before the body vector is
/// allocated.  This is useful to callers that need framing without creating a
/// client state machine.
///
/// # Errors
///
/// Returns [`SftpError::ZeroLength`], [`SftpError::FrameTooLarge`], a transport
/// error, or a truncated-body error.
pub fn read_packet<T>(stream: &mut T) -> Result<Vec<u8>, SftpError>
where
    T: Read,
{
    let mut encoded_length = [0_u8; 4];
    stream.read_exact(&mut encoded_length)?;
    let length = u32::from_be_bytes(encoded_length);
    validate_length(length)?;
    let length = usize::try_from(length).map_err(|_error| SftpError::FrameTooLarge)?;
    let mut body = vec![0_u8; length];
    stream.read_exact(&mut body)?;
    Ok(body)
}

/// Writes one complete SFTP frame to a caller-supplied stream.
///
/// # Errors
///
/// Returns a size or transport error.
pub fn write_packet<T>(stream: &mut T, packet: &[u8]) -> Result<(), SftpError>
where
    T: Write,
{
    if packet.is_empty() {
        return Err(SftpError::ZeroLength);
    }
    if packet.len() > MAX_SFTP_PACKET_SIZE {
        return Err(SftpError::FrameTooLarge);
    }
    let length = u32::try_from(packet.len()).map_err(|_error| SftpError::FrameTooLarge)?;
    stream.write_all(&length.to_be_bytes())?;
    stream.write_all(packet)?;
    Ok(())
}

fn validate_path_bytes(path: &[u8]) -> Result<(), SftpError> {
    if path.is_empty() {
        Err(SftpError::InvalidPath)
    } else if path.len() > MAX_SFTP_PATH_SIZE {
        Err(SftpError::PathTooLong)
    } else {
        Ok(())
    }
}

fn validate_handle_bytes(handle: &[u8]) -> Result<(), SftpError> {
    if handle.is_empty() {
        Err(SftpError::InvalidHandle)
    } else if handle.len() > MAX_SFTP_HANDLE_SIZE {
        Err(SftpError::HandleTooLong)
    } else {
        Ok(())
    }
}

fn validate_length(length: u32) -> Result<(), SftpError> {
    if length == 0 {
        return Err(SftpError::ZeroLength);
    }
    match usize::try_from(length) {
        Ok(value) if value > MAX_SFTP_PACKET_SIZE => Err(SftpError::FrameTooLarge),
        Ok(_) => Ok(()),
        Err(_error) => Err(SftpError::FrameTooLarge),
    }
}

fn read_length(bytes: &[u8]) -> Result<u32, SftpError> {
    let encoded: [u8; 4] = bytes.try_into().map_err(|_error| SftpError::InvalidFrame)?;
    Ok(u32::from_be_bytes(encoded))
}

fn map_wire_error(error: WireError) -> SftpError {
    match error {
        WireError::LimitExceeded => SftpError::FrameTooLarge,
        WireError::Truncated | WireError::InvalidPacket => SftpError::InvalidFrame,
        other => SftpError::Wire(other),
    }
}

fn read_u32(reader: &mut Reader<'_>) -> Result<u32, SftpError> {
    reader.read_uint32().map_err(map_wire_error)
}

fn read_u64(reader: &mut Reader<'_>) -> Result<u64, SftpError> {
    reader.read_uint64().map_err(map_wire_error)
}

fn read_string(reader: &mut Reader<'_>, limit: usize) -> Result<Vec<u8>, SftpError> {
    reader
        .read_string_with_limit(limit)
        .map(<[u8]>::to_vec)
        .map_err(map_wire_error)
}

fn parse_version(packet: &[u8]) -> Result<(u32, Vec<SftpExtension>), SftpError> {
    let mut reader = Reader::new(packet.get(1..).ok_or(SftpError::InvalidFrame)?);
    let version = read_u32(&mut reader)?;
    let mut extensions = Vec::new();
    while !reader.is_empty() {
        let name = read_string(&mut reader, MAX_SFTP_PACKET_SIZE)?;
        let value = read_string(&mut reader, MAX_SFTP_PACKET_SIZE)?;
        extensions.push(SftpExtension { name, value });
    }
    Ok((version, extensions))
}

fn validate_response_id(packet: &[u8], expected: u32) -> Result<(), SftpError> {
    let bytes = packet.get(1..5).ok_or(SftpError::MissingResponseId)?;
    let encoded: [u8; 4] = bytes
        .try_into()
        .map_err(|_error| SftpError::MissingResponseId)?;
    let actual = u32::from_be_bytes(encoded);
    if actual == expected {
        Ok(())
    } else {
        Err(SftpError::ResponseIdMismatch { expected, actual })
    }
}

fn unexpected_response_type(packet: &[u8]) -> SftpError {
    packet
        .first()
        .copied()
        .map_or(SftpError::InvalidFrame, SftpError::UnexpectedResponse)
}

fn response_body(packet: &[u8], expected_type: u8, expected_id: u32) -> Result<&[u8], SftpError> {
    let packet_type = packet.first().copied().ok_or(SftpError::InvalidFrame)?;
    if packet_type != expected_type {
        return Err(SftpError::UnexpectedResponse(packet_type));
    }
    validate_response_id(packet, expected_id)?;
    packet.get(5..).ok_or(SftpError::InvalidFrame)
}

enum StatusDisposition {
    Ok,
    Eof,
}

fn parse_status_response(packet: &[u8], allow_eof: bool) -> Result<StatusDisposition, SftpError> {
    let body = packet.get(5..).ok_or(SftpError::InvalidFrame)?;
    let mut reader = Reader::new(body);
    let code = read_u32(&mut reader)?;
    let _message = read_string(&mut reader, MAX_SFTP_PACKET_SIZE)?;
    let _language = read_string(&mut reader, MAX_SFTP_PACKET_SIZE)?;
    if !reader.is_empty() {
        return Err(SftpError::InvalidFrame);
    }
    match code {
        SSH_FX_OK => Ok(StatusDisposition::Ok),
        SSH_FX_EOF if allow_eof => Ok(StatusDisposition::Eof),
        _ => Err(SftpError::Status(code)),
    }
}

fn status_result(packet: &[u8], allow_eof: bool) -> Result<StatusDisposition, SftpError> {
    let packet_type = packet.first().copied().ok_or(SftpError::InvalidFrame)?;
    if packet_type != SSH_FXP_STATUS {
        return Err(SftpError::UnexpectedResponse(packet_type));
    }
    let _response_id = response_id(packet)?;
    parse_status_response(packet, allow_eof)
}

fn parse_handle_response(packet: &[u8], expected_id: u32) -> Result<SftpHandle, SftpError> {
    let body = response_body(packet, SSH_FXP_HANDLE, expected_id)?;
    let mut reader = Reader::new(body);
    let handle = read_handle(&mut reader)?;
    if !reader.is_empty() {
        return Err(SftpError::InvalidFrame);
    }
    Ok(handle)
}

fn parse_data_response(packet: &[u8], expected_length: usize) -> Result<Vec<u8>, SftpError> {
    let expected_id = response_id(packet)?;
    let body = response_body(packet, SSH_FXP_DATA, expected_id)?;
    let mut reader = Reader::new(body);
    let data = read_string(&mut reader, MAX_SFTP_PACKET_SIZE)?;
    if !reader.is_empty() {
        return Err(SftpError::InvalidFrame);
    }
    if data.len() > expected_length {
        return Err(SftpError::InvalidFrame);
    }
    Ok(data)
}

fn parse_attributes_response(packet: &[u8]) -> Result<SftpAttributes, SftpError> {
    let expected_id = response_id(packet)?;
    let body = response_body(packet, SSH_FXP_ATTRS, expected_id)?;
    let mut reader = Reader::new(body);
    let attributes = decode_attributes(&mut reader)?;
    if !reader.is_empty() {
        return Err(SftpError::InvalidFrame);
    }
    Ok(attributes)
}

fn parse_name_response(packet: &[u8]) -> Result<Vec<SftpDirectoryEntry>, SftpError> {
    let expected_id = response_id(packet)?;
    let body = response_body(packet, SSH_FXP_NAME, expected_id)?;
    let mut reader = Reader::new(body);
    let count = read_u32(&mut reader)?;
    let count = usize::try_from(count).map_err(|_error| SftpError::InvalidFrame)?;
    if count > reader.len() / 12 {
        return Err(SftpError::InvalidFrame);
    }
    let mut entries = Vec::new();
    for _ in 0..count {
        let name = read_path(&mut reader)?;
        let long_name = read_string(&mut reader, MAX_SFTP_PACKET_SIZE)?;
        let attributes = decode_attributes(&mut reader)?;
        entries.push(SftpDirectoryEntry {
            name,
            long_name,
            attributes,
        });
    }
    if !reader.is_empty() {
        return Err(SftpError::InvalidFrame);
    }
    Ok(entries)
}

fn single_name_field(packet: &[u8]) -> Result<Vec<u8>, SftpError> {
    if packet.first() == Some(&SSH_FXP_STATUS) {
        status_result(packet, false)?;
        return Err(SftpError::UnexpectedResponse(SSH_FXP_STATUS));
    }
    let entries = parse_name_response(packet)?;
    if entries.len() != 1 {
        return Err(SftpError::InvalidFrame);
    }
    entries
        .into_iter()
        .next()
        .map(|entry| entry.name)
        .ok_or(SftpError::InvalidFrame)
}

fn response_id(packet: &[u8]) -> Result<u32, SftpError> {
    let bytes = packet.get(1..5).ok_or(SftpError::MissingResponseId)?;
    let encoded: [u8; 4] = bytes
        .try_into()
        .map_err(|_error| SftpError::MissingResponseId)?;
    Ok(u32::from_be_bytes(encoded))
}

fn read_path(reader: &mut Reader<'_>) -> Result<Vec<u8>, SftpError> {
    let path = read_string(reader, MAX_SFTP_PATH_SIZE).map_err(|error| match error {
        SftpError::FrameTooLarge => SftpError::PathTooLong,
        other => other,
    })?;
    validate_path_bytes(&path)?;
    Ok(path)
}

fn read_handle(reader: &mut Reader<'_>) -> Result<SftpHandle, SftpError> {
    let handle = read_string(reader, MAX_SFTP_HANDLE_SIZE).map_err(|error| match error {
        SftpError::FrameTooLarge => SftpError::HandleTooLong,
        other => other,
    })?;
    validate_handle_bytes(&handle)?;
    SftpHandle::from_bytes(&handle)
}

const KNOWN_ATTRIBUTE_FLAGS: u32 = SSH_FILEXFER_ATTR_SIZE
    | SSH_FILEXFER_ATTR_UIDGID
    | SSH_FILEXFER_ATTR_PERMISSIONS
    | SSH_FILEXFER_ATTR_ACMODTIME
    | SSH_FILEXFER_ATTR_EXTENDED;

fn decode_attributes(reader: &mut Reader<'_>) -> Result<SftpAttributes, SftpError> {
    let flags = read_u32(reader)?;
    if flags & !KNOWN_ATTRIBUTE_FLAGS != 0 {
        return Err(SftpError::InvalidAttributes);
    }

    let size = if flags & SSH_FILEXFER_ATTR_SIZE != 0 {
        Some(read_u64(reader)?)
    } else {
        None
    };
    let (uid, gid) = if flags & SSH_FILEXFER_ATTR_UIDGID != 0 {
        (Some(read_u32(reader)?), Some(read_u32(reader)?))
    } else {
        (None, None)
    };
    let permissions = if flags & SSH_FILEXFER_ATTR_PERMISSIONS != 0 {
        Some(read_u32(reader)?)
    } else {
        None
    };
    let (access_time, modify_time) = if flags & SSH_FILEXFER_ATTR_ACMODTIME != 0 {
        (Some(read_u32(reader)?), Some(read_u32(reader)?))
    } else {
        (None, None)
    };
    let extended = if flags & SSH_FILEXFER_ATTR_EXTENDED != 0 {
        let count = read_u32(reader)?;
        let count = usize::try_from(count).map_err(|_error| SftpError::InvalidAttributes)?;
        if count > reader.len() / 8 {
            return Err(SftpError::InvalidAttributes);
        }
        let mut pairs = Vec::new();
        for _ in 0..count {
            let name = read_string(reader, MAX_SFTP_PACKET_SIZE)?;
            let data = read_string(reader, MAX_SFTP_PACKET_SIZE)?;
            pairs.push(SftpExtendedAttribute { name, data });
        }
        pairs
    } else {
        Vec::new()
    };

    Ok(SftpAttributes {
        size,
        uid,
        gid,
        permissions,
        access_time,
        modify_time,
        extended,
    })
}

#[allow(clippy::map_identity)]
fn encode_attributes(attributes: &SftpAttributes) -> Result<Vec<u8>, SftpError> {
    let mut flags = 0_u32;
    if attributes.size.is_some() {
        flags |= SSH_FILEXFER_ATTR_SIZE;
    }
    if attributes.uid.is_some() || attributes.gid.is_some() {
        flags |= SSH_FILEXFER_ATTR_UIDGID;
    }
    if attributes.permissions.is_some() {
        flags |= SSH_FILEXFER_ATTR_PERMISSIONS;
    }
    if attributes.access_time.is_some() || attributes.modify_time.is_some() {
        flags |= SSH_FILEXFER_ATTR_ACMODTIME;
    }
    if !attributes.extended.is_empty() {
        flags |= SSH_FILEXFER_ATTR_EXTENDED;
    }

    let mut packet = PacketBuilder::with_capacity(64);
    packet.push_uint32(flags);
    if let Some(size) = attributes.size {
        packet.push_uint64(size);
    }
    if flags & SSH_FILEXFER_ATTR_UIDGID != 0 {
        let uid = attributes.uid.unwrap_or(0);
        let gid = attributes.gid.unwrap_or(0);
        packet.push_uint32(uid);
        packet.push_uint32(gid);
    }
    if let Some(permissions) = attributes.permissions {
        packet.push_uint32(permissions);
    }
    if flags & SSH_FILEXFER_ATTR_ACMODTIME != 0 {
        let access_time = attributes.access_time.unwrap_or(0);
        let modify_time = attributes.modify_time.unwrap_or(0);
        packet.push_uint32(access_time);
        packet.push_uint32(modify_time);
    }
    if flags & SSH_FILEXFER_ATTR_EXTENDED != 0 {
        let count =
            u32::try_from(attributes.extended.len()).map_err(|_error| SftpError::FrameTooLarge)?;
        packet.push_uint32(count);
        for pair in &attributes.extended {
            packet.push_string(pair.name(), MAX_SFTP_PACKET_SIZE, SftpError::FrameTooLarge)?;
            packet.push_string(pair.data(), MAX_SFTP_PACKET_SIZE, SftpError::FrameTooLarge)?;
        }
    }
    packet.finish()
}

struct PacketBuilder {
    bytes: Vec<u8>,
}

impl PacketBuilder {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity.min(MAX_SFTP_PACKET_SIZE)),
        }
    }

    fn push_byte(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn push_uint32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn push_uint64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn push_bytes(&mut self, value: &[u8]) -> Result<(), SftpError> {
        let end = self
            .bytes
            .len()
            .checked_add(value.len())
            .ok_or(SftpError::FrameTooLarge)?;
        if end > MAX_SFTP_PACKET_SIZE {
            return Err(SftpError::FrameTooLarge);
        }
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn push_string(
        &mut self,
        value: &[u8],
        limit: usize,
        limit_error: SftpError,
    ) -> Result<(), SftpError> {
        if value.len() > limit {
            return Err(limit_error);
        }
        let length = u32::try_from(value.len()).map_err(|_error| limit_error)?;
        let end = self
            .bytes
            .len()
            .checked_add(4)
            .and_then(|size| size.checked_add(value.len()))
            .ok_or(SftpError::FrameTooLarge)?;
        if end > MAX_SFTP_PACKET_SIZE {
            return Err(SftpError::FrameTooLarge);
        }
        self.bytes.extend_from_slice(&length.to_be_bytes());
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn finish(self) -> Result<Vec<u8>, SftpError> {
        if self.bytes.is_empty() {
            return Err(SftpError::InvalidFrame);
        }
        if self.bytes.len() > MAX_SFTP_PACKET_SIZE {
            return Err(SftpError::FrameTooLarge);
        }
        Ok(self.bytes)
    }
}
