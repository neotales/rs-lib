#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Optional, target-specific memory protection adapters for `neotales-keepass`.
//!
//! The portable `KeePass` crate deliberately contains no operating-system FFI.
//! Enable the `windows-dpapi` feature to build the optional Windows adapter;
//! the adapter implements the existing [`neotales_keepass::MemoryProtectionProvider`]
//! hook and does not change the core crate's public API. Enable `memory-pin`
//! for a separate page-aligned Unix `mlock` buffer. That feature
//! stays inside this crate's `forbid(unsafe_code)` boundary and does not report
//! a core `SecretBytes` allocation as pinned.
#![doc = include_str!("../README.md")]

#[cfg(feature = "memory-pin")]
mod memory_pin;
#[cfg(feature = "windows-dpapi")]
mod windows_dpapi;

#[cfg(feature = "memory-pin")]
pub use memory_pin::{MAX_PINNED_BYTES, PinnedBytes};
#[cfg(feature = "windows-dpapi")]
pub use windows_dpapi::{DpapiScope, WindowsDpapiProvider};

pub use neotales_keepass::{MemoryPinningPolicy, MemoryPinningStatus};
