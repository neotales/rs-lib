//! SSH protocol message codecs.
//!
//! The message implementations in this module use the wire primitives from the
//! parent crate.  The module is kept separate from the crate root until the
//! crate-surface integration ticket wires it into the public library API.

#[allow(dead_code)]
#[path = "kexinit.rs"]
pub(crate) mod kexinit;

// The path-based integration harness makes these re-exports private to the
// test crate.  Keep the allow local to that harness rather than requiring
// every test to import a dummy symbol.
#[allow(unused_imports)]
pub(crate) use kexinit::*;
