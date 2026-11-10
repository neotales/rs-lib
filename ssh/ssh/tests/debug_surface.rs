//! The `Debug` surface added for `neotales-ssh` in this change is printable
//! without a `Debug` bound on any caller-supplied type, and it prints no
//! key material.
//!
//! Three public types gained a hand-written `Debug`: `ServerAuthenticator`,
//! `ClientAuthenticator`, and `ScpClient`. All three are generic over a
//! caller-owned stream or transport, and that is the whole reason they cannot
//! be derives:
//!
//! - `ScpClient<T>` holds nothing but the caller's `T`.
//! - `ClientAuthenticator<'a, S>` holds the caller's `S` and a boxed
//!   `BannerCallback`, which is one of the caller's own closures.
//! - `ServerAuthenticator<'a, S>` holds the caller's `S`.
//!
//! A derive on any of them would either demand `Debug` of the caller's stream —
//! a bound the caller never asked for and cannot satisfy for a `TcpStream` or a
//! `Channel` without writing an impl they have no reason to write — or demand
//! `Debug` of a closure, which is not even possible. The tests below pin the
//! ergonomic half: each type formats over a stream that deliberately does not
//! implement `Debug`.
//!
//! `ServerAuthenticator` and `ClientAuthenticator` need a `ServerTransport` or
//! `ClientTransport` to exist, which is not reachable from an integration test,
//! so the compiler is pointed at their impls through a `#![allow]`-free type
//! check instead. The point being tested is that the impls are not generic over
//! a bound, and `impl<S: fmt::Debug> fmt::Debug for ...` is the only shape that
//! would break the claim.

// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding. Scoped to this file, so an undocumented public item in
// the crate is still reported.
#![allow(missing_docs)]

use std::io::{self, Read, Write};

use neotales_ssh::{
    ScpClient,
    auth::{ClientAuthenticator, ServerAuthenticator},
    scp::Scp,
};

/// A caller-supplied stream that implements neither `Debug` nor anything else
/// printable.
///
/// If `ScpClient`'s `Debug` impl had gained a `T: Debug` bound, this type
/// would stop satisfying it and this file would fail to compile. That is the
/// ergonomic claim, and a compile failure is the only honest way to test it: a
/// runtime assertion cannot observe the absence of a trait bound.
struct NotDebug(Vec<u8>);

impl Read for NotDebug {
    fn read(&mut self, target: &mut [u8]) -> io::Result<usize> {
        let count = target.len().min(self.0.len());
        target[..count].copy_from_slice(&self.0[..count]);
        self.0.drain(..count);
        Ok(count)
    }
}

impl Write for NotDebug {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        // Pretend the sink accepted them without keeping a copy, so the test
        // cannot accidentally find its own bytes in a `Debug` output.
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A stream that is `Debug` too, to show the impl is not merely avoiding the
/// case where a bound happens to be satisfiable.
#[derive(Debug)]
struct AlsoDebug(#[allow(dead_code, reason = "the payload exists to make the type Debug")] usize);

impl Read for AlsoDebug {
    fn read(&mut self, _target: &mut [u8]) -> io::Result<usize> {
        Ok(0)
    }
}

/// The SCP endpoint prints its type name and nothing else, over a stream that
/// is not `Debug`.
#[test]
fn an_scp_client_over_a_non_debug_stream_prints_its_name() {
    let client = ScpClient::new(NotDebug(vec![0xde, 0xad, 0xbe, 0xef]));
    assert_eq!(format!("{client:?}"), "ScpClient");
    // The short alias names the same type and must be identical.
    let alias = Scp::new(NotDebug(Vec::new()));
    assert_eq!(format!("{alias:?}"), "ScpClient");
    // And over a `Debug` stream the output is the same, so there is no
    // `Debug`-conditional formatting to be surprised by.
    assert_eq!(format!("{:?}", ScpClient::new(AlsoDebug(7))), "ScpClient");
}

/// The `Debug` output carries none of the caller's bytes.
///
/// A `ScpClient` is a handle over a stream that may be carrying file data. The
/// endpoint never reads from it to build its output, so the only thing a
/// rendering contains is the type name.
#[test]
fn an_scp_client_prints_none_of_the_streams_bytes() {
    const PAYLOAD: &str = "canary-scp-file-contents-3b8f0c2e-do-not-log-me";
    let client = ScpClient::new(NotDebug(PAYLOAD.as_bytes().to_vec()));
    let printed = format!("{client:?}");
    assert!(!printed.contains(PAYLOAD), "{printed}");

    // The same through a fully drained stream, in case a future impl decided to
    // peek at the stream to describe it.
    let mut drained = NotDebug(PAYLOAD.as_bytes().to_vec());
    let mut sink = [0_u8; 8];
    while drained.read(&mut sink).expect("drain") > 0 {}
    let printed = format!("{:?}", ScpClient::new(drained));
    assert!(!printed.contains(PAYLOAD), "{printed}");
}

/// The two authenticators format without a `Debug` bound on the transport.
///
/// `ServerTransport` and `ClientTransport` are not constructible from outside
/// the crate, so a value cannot be built here. What *can* be checked, and is
/// what the ergonomic claim actually turns on, is that each impl is written for
/// an unconstrained parameter. Naming the impl's bound explicitly makes the
/// claim a compile-time assertion: adding `S: Debug` to either impl makes this
/// line fail, and nothing else in the file would notice.
///
/// The value is discarded immediately, so nothing is printed and no key
/// material is involved; this is a type-level test wearing a runtime costume.
#[test]
fn the_authenticators_debug_over_an_unconstrained_transport() {
    fn assert_debug<T: std::fmt::Debug>() {}
    // Unconstrained on purpose: `NotDebug` stands in for a caller's transport
    // and is not `Debug`.
    assert_debug::<ScpClient<NotDebug>>();
    assert_debug::<ClientAuthenticator<'_, NotDebug>>();
    assert_debug::<ServerAuthenticator<'_, NotDebug>>();
    // The generic parameters are the only thing that varies, so a bound placed
    // on the transport rather than on a concrete impl is the failure this
    // catches. A `NotDebug` value is never constructed, so there is nothing to
    // print and no risk of one.
}

/// The authenticator impls are reached by name so that removing one is a
/// compile error rather than a silent regression.
///
/// `assert_debug` above already requires the impl to exist. This adds the
/// second claim: that the reported shape is the crate's own, not a blanket impl
/// from somewhere else. A blanket `impl<T: Debug> Debug for T` is not a thing
/// Rust has, so reaching a `NotDebug` type is sufficient — but spelling the
/// concrete instantiations documents which three types the change covered.
#[test]
fn the_three_covered_types_are_the_ones_named() {
    fn assert_debug<T: std::fmt::Debug>() {}
    assert_debug::<ScpClient<NotDebug>>();
    assert_debug::<ClientAuthenticator<'static, NotDebug>>();
    assert_debug::<ServerAuthenticator<'static, NotDebug>>();
    // `Scp` is a type alias, not a fourth type. Naming it here is what proves
    // the alias resolves to the same impl rather than a second one.
    assert_debug::<Scp<NotDebug>>();
}
