#![allow(
    clippy::all,
    clippy::pedantic,
    reason = "format codecs have explicit protocol-shaped APIs and bounds"
)]

//! Headless, bounded KeePass KDBX support for Neotales.
//!
//! The crate keeps document editing, wire codecs, and secret handling separate
//! so callers can use the model without depending on a UI, filesystem policy,
//! or platform credential store. [`KdbxFile::load`] and [`KdbxFile::save`]
//! operate on caller-owned streams; [`KdbxReadLimits`] must be selected for
//! the trust boundary of the input. For ordinary local files,
//! [`KdbxFile::open`], [`KdbxFile::open_with_credentials`],
//! [`KdbxFile::save_default`], and
//! [`KdbxFile::save_default_with_credentials`] provide concise standard-limit
//! convenience forms.
//!
//! KDBX 4 header and payload authentication is checked before decryption, and
//! unsupported or unauthenticated data fails closed. [`ProtectedValue`] keeps
//! byte-origin values behind an explicit reveal API, but the core crate does
//! not claim that text is pinned or that zeroization is guaranteed against
//! operating-system swap. See the crate `README.md` and `RELEASE-GATE.md` for
//! the supported format matrix, dependency policy, and remaining limitations.
#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod async_api;
mod cancellation;
mod credentials;
mod crypto;
mod error;
mod file;
mod limits;
mod model;
mod otp;
mod path;
mod primitives;
mod wire;
/// Hardened KeePass XML helpers.
pub mod xml;

pub use async_api::{KdbxAsyncRead, KdbxAsyncWrite, KdbxLoadFuture, KdbxSaveFuture};
pub use cancellation::{KdbxCancellation, KdbxCancellationToken};
pub use credentials::{CredentialProvider, KdbxCredentials, KdbxKeyFile, read_key_file};
pub use error::{KdbxError, KdbxFailureKind, KdbxLimitDetail, KdbxLimitParameter};
pub use file::{
    Kdbx3WriteOptions, Kdbx4AuthenticatedBlockReader, KdbxCompression, KdbxFile, KdbxKdf,
    KdbxOuterCipher, KdbxWriteOptions,
};
pub use limits::KdbxReadLimits;
pub use model::{
    Attachment, AutoType, AutoTypeAssociation, BinaryPool, BinaryRecord, ChaCha20MemoryProtection,
    CustomData, CustomDataItem, CustomIcon, DeletedObject, Entry, Field, Group, KeePassAttachment,
    KeePassDatabase, KeePassEntry, KeePassField, KeePassGroup, KeePassMeta, KeePassTimes,
    MemoryPinningPolicy, MemoryPinningStatus, MemoryProtectionError, MemoryProtectionProvider,
    MergeStrategy, ProtectedValue, SecretBytes, SecretString, VariantDictionary,
    VariantDictionaryItem, VariantValue,
};
pub use otp::{
    Hotp, HotpParameters, KeePassXcOtp, OtpAlgorithm, OtpDigits, OtpKind, OtpSecret, OtpUri, Totp,
    TotpParameters,
};
pub use path::{Comparison, PathError, PathOptions};
pub use primitives::{KdbxColor, KdbxTimestamp, KdbxUuid};
pub use xml::KdbxXml;
