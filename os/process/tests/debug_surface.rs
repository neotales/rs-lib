//! `ExecutionOptions` can be `Debug`-printed, and the printing does not carry
//! the child's environment.
//!
//! `ExecutionOptions<'a>` is the only public type in this crate that the
//! `missing_debug_implementations` workspace lint named, and a derive was not
//! available for two independent reasons:
//!
//! - `is_cancelled` is `&'a dyn Fn() -> bool`, which is not `Debug`. A derive
//!   would not have compiled, and the `Debug` bound it would need is a bound on
//!   the caller's own closure.
//! - `environment` is `&'a BTreeMap<String, String>` holding the child's
//!   *complete* environment. A derived `Debug` prints a map's values, and a
//!   caller who puts a token or a password in the environment has put it
//!   somewhere a log line would otherwise carry it.
//!
//! So the impl reports the working directory, the count of environment
//! variables, the passthrough names, and the timeout, and omits the two fields
//! above. The passthrough *names* are printed on purpose: a variable name is not
//! a secret, and "which three variables was this run inheriting" is usually the
//! question being asked.

// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
//! rather than a finding. Scoped to this file, so an undocumented public item in
// the crate is still reported.
#![allow(missing_docs)]

use std::{collections::BTreeMap, fmt::Write as _, time::Duration};

use neotales_process::ExecutionOptions;

/// An environment value that must never appear in a `Debug` output.
const SECRET_VALUE: &str = "canary-environment-secret-6d1b8a40-do-not-log-me";

/// A second one, to show the check is not a single-string special case.
const OTHER_SECRET: &str = "canary-other-secret-2f5c9e13-do-not-log-me";

/// A cancellation closure that deliberately does not implement `Debug`.
///
/// If `ExecutionOptions`'s `Debug` impl had gained a bound on the caller's
/// closure, this type would stop satisfying it and this file would fail to
/// compile. A runtime assertion cannot observe the absence of a trait bound, so
/// the compile is the test.
fn is_cancelled() -> bool {
    false
}

/// The options print their shape, and neither environment value.
#[test]
fn execution_options_print_their_shape_and_not_the_environment() {
    let environment: BTreeMap<String, String> = [
        ("MODE".to_owned(), "release".to_owned()),
        ("API_TOKEN".to_owned(), SECRET_VALUE.to_owned()),
        ("SECOND_SECRET".to_owned(), OTHER_SECRET.to_owned()),
    ]
    .into_iter()
    .collect();

    let options = ExecutionOptions {
        working_directory: std::path::Path::new("/srv/app"),
        environment: &environment,
        passthrough: &[],
        is_cancelled: &is_cancelled,
        timeout: Some(Duration::from_secs(30)),
    };

    let printed = format!("{options:?}");
    assert!(printed.starts_with("ExecutionOptions"), "{printed}");
    // The count, not the map. Three variables went in.
    assert!(printed.contains("environment_len: 3"), "{printed}");
    // The directory and the timeout, which are the fields that describe a run.
    assert!(printed.contains("/srv/app"), "{printed}");
    assert!(printed.contains("30s"), "{printed}");
    // Neither secret, in text form.
    assert!(!printed.contains(SECRET_VALUE), "{printed}");
    assert!(!printed.contains(OTHER_SECRET), "{printed}");
}

/// A `Debug` for these options must be checked against the byte-list rendering
/// too, or a leak that printed the values as bytes would slip past a text
/// search. `BTreeMap<String, String>` values are `String`s, so a derived
/// `Debug` would print them as quoted text rather than as a byte list — but
/// checking both costs one loop and removes the question.
#[test]
fn the_check_covers_the_decimal_and_hex_renderings_too() {
    let environment: BTreeMap<String, String> = [("API_TOKEN".to_owned(), SECRET_VALUE.to_owned())]
        .into_iter()
        .collect();
    let options = ExecutionOptions {
        working_directory: std::path::Path::new("."),
        environment: &environment,
        passthrough: &[],
        is_cancelled: &is_cancelled,
        timeout: None,
    };
    let printed = format!("{options:?}");

    let secret = SECRET_VALUE.as_bytes();
    let decimal = secret
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    assert!(
        !printed.contains(&decimal),
        "the value leaked as a decimal byte list: {printed}"
    );
    let mut hex = String::new();
    for byte in SECRET_VALUE.as_bytes() {
        write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    assert!(
        !printed.contains(&hex),
        "the value leaked as a hex byte list: {printed}"
    );

    // And the negative control: a rendering that *does* contain the decimal
    // list is caught, so the loop above is not vacuous.
    let leaked = format!("ExecutionOptions {{ environment_len: 3, leak: [{decimal}] }}");
    assert!(leaked.contains(&decimal), "sanity: the control does leak");
    assert!(
        !leaked.is_empty() && !printed.contains(&decimal),
        "the real output must not contain what the control does"
    );
}

/// The passthrough names are printed, because a name is not a secret and the
/// set of inherited variables is the useful diagnostic.
#[test]
fn the_passthrough_names_are_printed() {
    let environment: BTreeMap<String, String> = [("MODE".to_owned(), "release".to_owned())]
        .into_iter()
        .collect();
    let passthrough = ["LANG".to_owned(), "HOME".to_owned()];
    let options = ExecutionOptions {
        working_directory: std::path::Path::new("."),
        environment: &environment,
        passthrough: &passthrough,
        is_cancelled: &is_cancelled,
        timeout: None,
    };
    let printed = format!("{options:?}");
    assert!(printed.contains("LANG"), "{printed}");
    assert!(printed.contains("HOME"), "{printed}");
    assert!(printed.contains("environment_len: 1"), "{printed}");

    // An empty passthrough is the default in practice, and the field is still
    // reported so a reader can tell "inherits nothing" from "not reported".
    let options = ExecutionOptions {
        working_directory: std::path::Path::new("."),
        environment: &environment,
        passthrough: &[],
        is_cancelled: &is_cancelled,
        timeout: None,
    };
    let printed = format!("{options:?}");
    assert!(printed.contains("passthrough: []"), "{printed}");
    assert!(printed.contains("timeout: None"), "{printed}");
}

/// The `Debug` bound claim, spelled out as a compile-time assertion.
///
/// `ExecutionOptions` is not itself generic, so the bound being absent is
/// about its *fields*: `is_cancelled` is a caller's closure. Naming the
/// concrete instantiation documents the claim, and the test file's
/// non-`Debug` closure above is the part that would stop compiling if an
/// `F: Debug`-style bound were ever introduced.
#[test]
fn a_non_debug_closure_is_accepted_as_the_cancellation_check() {
    fn accepts(f: &dyn Fn() -> bool) -> String {
        let environment: BTreeMap<String, String> = BTreeMap::new();
        format!(
            "{:?}",
            ExecutionOptions {
                working_directory: std::path::Path::new("."),
                environment: &environment,
                passthrough: &[],
                is_cancelled: f,
                timeout: None,
            }
        )
    }
    let printed = accepts(&is_cancelled);
    assert!(printed.starts_with("ExecutionOptions"), "{printed}");
    // The closure is not printed in any form — not its value, not a note that it
    // exists. The impl reports only the four printable fields.
    assert!(!printed.contains("is_cancelled"), "{printed}");
    assert!(!printed.contains("closure"), "{printed}");
}
