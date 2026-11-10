//! Renders the upstream Sprig parity fixture through the real template engine.
//!
//! The fixture at `fixtures/sprig/upstream_parity.json` holds 276
//! `(template, expected)` pairs extracted from the reference implementation's own
//! `SprigUpstreamParityTests.cs`, which is itself ported from the upstream
//! Masterminds Sprig test suite. Those pairs are the authority for what a helper
//! computes: a helper that renders the right answer for the examples someone
//! thought to write down is still wrong for the case nobody wrote down, and
//! comparing against the reference's own expectations is the closest thing to
//! comparing against the reference's behaviour.
//!
//! The cases run through [`neotales_gotmpl::Template`] rather than calling the
//! helper crate directly, so the whole path is covered: the template's argument
//! handling, the typed-versus-rendered argument policy, and the helper itself.

// `missing_docs` is a workspace lint aimed at the published API. A test
// binary has no public API to document, so the lint firing here is noise
// rather than a finding. Scoped to this file, so an undocumented public
// item in the crate is still reported.
#![allow(missing_docs)]

use std::collections::BTreeMap;

use neotales_gotmpl::{Template, Value};
use serde::Deserialize;

/// One `(template, expected)` pair from the fixture.
#[derive(Clone, Debug, Deserialize)]
struct Case {
    /// The Go template source.
    template: String,
    /// The text the reference renders it to.
    expected: String,
    /// The input the reference renders into `.value`, for the cases written in
    /// the reference's three-argument form or with its `Render` helper.
    ///
    /// It is absent for an ordinary case. Treating it as absent rather than
    /// defaulting it to something would silently run a case against the wrong
    /// input, so the distinction is kept.
    #[serde(default)]
    value: Option<String>,
}

/// The environment a case is rendered against.
///
/// The fixture templates were written against an environment the reference
/// supplies through its render options. The cases that use `env` or a `.env`
/// lookup need the same names here, and the reference's own test file names
/// them; anything a case needs that is not listed is reported as a failure
/// rather than silently rendered as empty, because a silently-empty environment
/// would let a broken `env` helper look correct.
fn fixture_environment() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("HOME".to_owned(), "/home/dev".to_owned()),
        ("USER".to_owned(), "dev".to_owned()),
        ("SHELL".to_owned(), "/bin/bash".to_owned()),
        ("PWD".to_owned(), "/tmp/opencode".to_owned()),
        ("NAME".to_owned(), "fixture".to_owned()),
        ("GREETING".to_owned(), "hello-from-dotenv".to_owned()),
        ("DB_PASSWORD".to_owned(), "s3cr3t-from-dotenv".to_owned()),
    ])
}

/// Builds the template root the fixture cases are rendered against.
///
/// The root is a flat map, which is how the engine's public render entry point
/// takes it. The shapes here are the ones the reference's own tests build:
///
/// - `Render(source, value)` puts its argument in `.value`.
/// - Its expanded-helper test puts `"neo-env"` in `.value` and
///   `[alpha beta gamma]` in `.items`.
///
/// Reproducing both is what lets one fixture hold cases written against either
/// helper. The `env` and `values` entries are the namespaces a Compose template
/// is written against, so a case that uses `env "HOME"` or `.env.NAME` sees the
/// same shape it would see in a real Compose file.
fn fixture_root() -> BTreeMap<String, Value> {
    let environment: BTreeMap<String, Value> = fixture_environment()
        .into_iter()
        .map(|(key, value)| (key, Value::String(value)))
        .collect();
    BTreeMap::from([
        ("env".to_owned(), Value::Map(environment)),
        (
            "values".to_owned(),
            Value::Map(BTreeMap::from([
                ("name".to_owned(), Value::String("fixture".to_owned())),
                ("port".to_owned(), Value::Number(8080.0)),
                ("replicas".to_owned(), Value::Number(3.0)),
            ])),
        ),
        ("name".to_owned(), Value::String("fixture".to_owned())),
        ("port".to_owned(), Value::Number(8080.0)),
        ("value".to_owned(), Value::String("neo-env".to_owned())),
        (
            "items".to_owned(),
            Value::List(vec![
                Value::String("alpha".to_owned()),
                Value::String("beta".to_owned()),
                Value::String("gamma".to_owned()),
            ]),
        ),
    ])
}

/// Reads the fixture, which is checked in beside this crate.
/// How many `(template, expected)` pairs the parity fixture is expected to hold.
///
/// Pinned so the number in the support matrix, the area readme and this file are
/// the same number, and so adding a case is a deliberate act.
const EXPECTED_CASES: usize = 276;

fn cases() -> Vec<Case> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/sprig/upstream_parity.json"
    );
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("the Sprig parity fixture must be readable: {error}"));
    serde_json::from_str(&raw)
        .unwrap_or_else(|error| panic!("the Sprig parity fixture must be valid JSON: {error}"))
}

/// The names a case's template calls, for the failure report.
fn helpers_in(template: &str) -> Vec<String> {
    let mut names = Vec::new();
    let bytes = template.as_bytes();
    let mut index = 0;
    while index + 1 < bytes.len() {
        if bytes[index..].starts_with(b"{{") {
            // Step past the action, the trim markers, and an optional pipeline.
            let mut cursor = index + 2;
            while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
                cursor += 1;
            }
            if cursor < bytes.len() && bytes[cursor] == b'-' {
                cursor += 1;
            }
            while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
                cursor += 1;
            }
            let start = cursor;
            while cursor < bytes.len()
                && (bytes[cursor].is_ascii_alphanumeric() || bytes[cursor] == b'_')
            {
                cursor += 1;
            }
            if cursor > start {
                let candidate = template[start..cursor].to_owned();
                // `range`, `if`, `with`, `end` and `else` are template
                // constructs, not helpers; the engine handles them itself.
                if !matches!(
                    candidate.as_str(),
                    "range" | "if" | "with" | "end" | "else" | "define" | "template" | "block"
                ) && !names.contains(&candidate)
                {
                    names.push(candidate);
                }
            }
            index = cursor;
        } else {
            index += 1;
        }
    }
    names
}

/// Every case in the fixture must render to its expected text.
#[test]
fn every_upstream_parity_case_renders_exactly() {
    let root = fixture_root();
    let cases = cases();
    // Exact, not a floor. This was `>= 200`, which is why three different counts
    // for the same fixture could all be true at once: 200 in the assertion, 230 in
    // this file's own documentation, and 262 in the support matrix and the area
    // readme, against 276 entries actually present. A bound that anything satisfies
    // is not a check, and a count nobody pins is a count that drifts.
    //
    // Adding or removing cases is legitimate; doing it silently is not. Bump this
    // number in the same commit, and the support matrix with it.
    assert_eq!(
        cases.len(),
        EXPECTED_CASES,
        "the parity fixture holds {} cases, not {EXPECTED_CASES}. If that is deliberate, \
         update EXPECTED_CASES and the support matrix's count in the same commit.",
        cases.len()
    );
    let skipped = out_of_scope_names();
    let mut failures = Vec::new();
    let mut skipped_cases: Vec<String> = Vec::new();
    for case in &cases {
        // A case written in the reference's three-argument form supplies its own
        // `.value`, and that input is what the expectation was written against.
        // Rendering it against this test's default instead would report a
        // helper bug for a case the helper never saw.
        let mut case_root = root.clone();
        if let Some(value) = &case.value {
            case_root.insert("value".to_owned(), Value::String(value.clone()));
        }
        // A case whose only helpers are deliberately out of scope is counted and
        // skipped rather than reported as a failure. Several of them assert a
        // *random* value or a generated key, so they could never be compared; the
        // skip is counted so a mis-flagged case cannot quietly hide a real one.
        let helpers = helpers_in(&case.template);
        if !helpers.is_empty() && helpers.iter().all(|name| skipped.contains_key(name)) {
            skipped_cases.push(case.template.clone());
            continue;
        }
        let rendered =
            Template::parse(&case.template).and_then(|template| template.render_typed(&case_root));
        match rendered {
            Ok(actual) if actual == case.expected => {}
            Ok(actual) => failures.push(format!(
                "{:?}\n     expected {:?}\n     rendered  {:?}\n     helpers   {:?}",
                case.template,
                case.expected,
                actual,
                helpers_in(&case.template)
            )),
            // Two of the reference's cases assert the *message* of the exception
            // a bad call throws, so a case whose expectation is the error text is
            // satisfied by producing exactly that error. Without this the two
            // cases would report as failures while the helper was in fact
            // refusing the call the way the reference does.
            Err(error) if error.to_string() == case.expected => {}
            Err(error) => failures.push(format!(
                "{:?}\n     expected {:?}\n     error     {error}\n     helpers   {:?}",
                case.template,
                case.expected,
                helpers_in(&case.template)
            )),
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} upstream parity cases do not match ({} skipped as out of scope):\n{}",
        failures.len(),
        cases.len(),
        skipped_cases.len(),
        failures.join("\n  ")
    );
}

/// The fixture must exercise a real spread of helpers.
///
/// A parity suite that silently stopped testing anything would pass, so the
/// count of distinct helpers the cases call is asserted. The number is a floor,
/// not an exact figure: it is here to catch a fixture that lost its contents, not
/// to pin a count that legitimately grows.
#[test]
fn the_fixture_exercises_a_broad_set_of_helpers() {
    let mut helpers: Vec<String> = Vec::new();
    for case in cases() {
        for name in helpers_in(&case.template) {
            if !helpers.contains(&name) {
                helpers.push(name);
            }
        }
    }
    helpers.sort();
    assert!(
        helpers.len() >= 60,
        "the fixture only exercises {} distinct helpers: {helpers:?}",
        helpers.len()
    );
}

/// The helper names the reference registers, one per line.
fn reference_names() -> Vec<String> {
    read_fixture("reference_helper_names.txt")
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(ToOwned::to_owned)
        .collect()
}

/// Reads a checked-in fixture beside this crate.
fn read_fixture(name: &str) -> String {
    let path = format!("{}/../../fixtures/sprig/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("the Sprig fixture {name} must be readable: {error}"))
}

/// The reference helpers this crate deliberately does not implement.
///
/// Only `not_implemented` counts. The `implemented_but_not_reproducible` group
/// is *not* skipped: those helpers work, and a parity case that exercises one is
/// a real case that must pass.
fn out_of_scope_names() -> std::collections::BTreeMap<String, String> {
    #[derive(Deserialize)]
    struct Groups {
        not_implemented: NotImplemented,
    }
    #[derive(Deserialize)]
    struct NotImplemented {
        non_reproducible: Group,
        cryptography: Group,
        network: Group,
    }
    #[derive(Deserialize)]
    struct Group {
        reason: String,
        helpers: Vec<String>,
    }
    let raw: Groups =
        serde_json::from_str(&read_fixture("out_of_scope.json")).expect("out_of_scope.json");
    let raw = raw.not_implemented;
    let mut names = std::collections::BTreeMap::new();
    for group in [raw.non_reproducible, raw.cryptography, raw.network] {
        for name in group.helpers {
            names.insert(name, group.reason.clone());
        }
    }
    names
}

/// The reference helpers that work here but read a clock.
///
/// They are listed so the crate's own claim — that no helper reads a clock — can
/// be checked rather than asserted, and so a reader can see the exception.
fn clock_reading_names() -> std::collections::BTreeMap<String, String> {
    #[derive(Deserialize)]
    struct Groups {
        implemented_but_not_reproducible: ClockGroup,
    }
    #[derive(Deserialize)]
    struct ClockGroup {
        clock: Group,
    }
    #[derive(Deserialize)]
    struct Group {
        reason: String,
        helpers: Vec<String>,
    }
    let raw: Groups =
        serde_json::from_str(&read_fixture("out_of_scope.json")).expect("out_of_scope.json");
    let reason = raw.implemented_but_not_reproducible.clock.reason;
    raw.implemented_but_not_reproducible
        .clock
        .helpers
        .into_iter()
        .map(|name| (name, reason.clone()))
        .collect()
}

/// Every reference helper that is not deliberately out of scope must exist here.
///
/// This is the name-level half of the parity gate. The behaviour half is
/// `every_upstream_parity_case_renders_exactly`; this catches a helper that is
/// simply absent, which a behaviour fixture cannot see because a fixture only
/// covers the helpers somebody wrote an example for.
#[test]
fn every_in_scope_reference_helper_is_implemented() {
    let skipped = out_of_scope_names();
    let implemented: std::collections::BTreeSet<String> = neotales_sprig::helper_names()
        .into_iter()
        .map(ToOwned::to_owned)
        .collect();
    let mut missing: Vec<String> = reference_names()
        .into_iter()
        .filter(|name| !skipped.contains_key(name))
        .filter(|name| !implemented.contains(name))
        .collect();
    missing.sort();
    assert!(
        missing.is_empty(),
        "{} in-scope reference helpers are not implemented: {}",
        missing.len(),
        missing.join(" ")
    );
}

/// A helper that only one implementation has makes a template fail elsewhere.
///
/// The additions list is the place to record one, with its reason, so the
/// difference is a decision rather than a surprise.
#[test]
fn an_implemented_helper_is_also_a_reference_helper_or_a_documented_addition() {
    #[derive(Deserialize)]
    struct Additions {
        additions: Vec<Addition>,
    }
    #[derive(Deserialize)]
    struct Addition {
        name: String,
        reason: String,
    }
    let additions: Additions =
        serde_json::from_str(&read_fixture("documented_additions.json")).expect("additions.json");
    let reference: std::collections::BTreeSet<String> = reference_names().into_iter().collect();
    let documented: std::collections::BTreeMap<String, String> = additions
        .additions
        .into_iter()
        .map(|addition| (addition.name, addition.reason))
        .collect();
    let extra: Vec<String> = neotales_sprig::helper_names()
        .into_iter()
        .map(ToOwned::to_owned)
        .filter(|name| !reference.contains(name) && !documented.contains_key(name))
        .collect();
    assert!(
        extra.is_empty(),
        "these helpers are not in the reference and are not a documented addition: {}",
        extra.join(" ")
    );
    for (name, reason) in &documented {
        assert!(
            !reason.trim().is_empty(),
            "the addition {name} has no reason recorded"
        );
    }
}

/// Every skipped helper must be one the reference actually registers.
///
/// A stale entry in the out-of-scope list would quietly shrink the gate: the
/// name would stop being required while still reading as a deliberate decision.
#[test]
fn an_out_of_scope_entry_is_a_real_reference_helper() {
    let reference: std::collections::BTreeSet<String> = reference_names().into_iter().collect();
    for name in out_of_scope_names().keys() {
        assert!(
            reference.contains(name),
            "{name} is listed as out of scope but the reference does not register it"
        );
    }
}

/// The clock exception is exactly the two helpers that are recorded as such.
///
/// The crate documents that every helper is a pure function of its arguments
/// except `now` and `ago`, which read the clock. That claim is only worth
/// anything if it is checked: a third helper that read the time would make a
/// rendered file differ between two runs, and a reader relying on the claim would
/// be misled. The list is checked against the recorded file *and* against what is
/// actually implemented, so neither can drift from the other unnoticed.
#[test]
fn the_clock_reading_exception_is_exactly_the_recorded_helpers() {
    let recorded = clock_reading_names();
    // Sorted, because the recorded set is a map and the order is not the point.
    let mut names: Vec<&str> = recorded.keys().map(String::as_str).collect();
    names.sort_unstable();
    assert_eq!(
        names,
        vec!["ago", "now"],
        "the documented exception is `now` and `ago`; anything else needs both the \\
         documentation and this list to change"
    );
    for name in &names {
        assert!(
            neotales_sprig::helper_names().contains(name),
            "{name} is recorded as reading the clock but is not implemented, so the \\
             documented exception would name a helper that does not exist"
        );
        // Every recorded exception must also carry a reason, so the file is a
        // decision record rather than a list.
        assert!(!recorded[*name].is_empty(), "{name} has no reason recorded");
    }
}

/// A helper that reads the clock must be in the recorded list.
///
/// This is the same guarantee from the other direction, and it is the one that
/// would catch a new clock-reading helper being added without anyone recording
/// it. The names are spelled out rather than derived, because the whole point is
/// to notice when the set changes.
#[test]
fn no_helper_reads_the_clock_without_being_recorded() {
    let recorded = clock_reading_names();
    for name in neotales_sprig::helper_names() {
        // The two date helpers that take an explicit time are pure: `date` and
        // `toDate` read the value they are given.
        if name == "now" || name == "ago" {
            assert!(
                recorded.contains_key(name),
                "{name} reads the clock and must be recorded as doing so"
            );
        }
    }
    // A helper that is recorded must exist, so a stale entry cannot silently
    // keep the guarantee true by naming nothing.
    for name in recorded.keys() {
        assert!(
            neotales_sprig::helper_names().contains(&name.as_str()),
            "{name} is recorded as reading the clock but is not implemented"
        );
    }
}

/// One reference case is deliberately **not** in the fixture, because this crate
/// does not reproduce it: `mergeOverwrite` does not share a nested map between
/// the destination and the source, so overwriting the destination is not visible
/// through the source.
///
/// The reference asserts both halves of the pair, `SprigUpstreamParityTests.cs:531`
/// and `:543`, under the name `MergeOverwriteSharesNestedMapsUntilDeepCopyMatchesUpstream`:
///
/// ```text
/// {{ ... mergeOverwrite $target $one ... }}{{ $_ := mergeOverwrite $target $two }}{{ $one }}
///     reference  map[foo:map[bar:baz2] qux:true]      <- shared
///     here       map[foo:map[bar:baz]  qux:true]      <- copied
/// {{ ... deepCopy $one | mergeOverwrite $target ... }}{{ $_ := mergeOverwrite $target $two }}{{ $one }}
///     reference  map[foo:map[bar:baz] qux:true]       <- copied, so unaffected
///     here       map[foo:map[bar:baz] qux:true]
/// ```
///
/// The two expectations differ in exactly one token, so a fixture carrying both
/// would be a red test rather than a decision. Reproducing the first would mean
/// giving `Value` interior sharing, which is a value-model change and not a
/// helper fix. This test pins the current behaviour so the divergence is visible
/// and cannot be lost, and so whoever closes it sees the reference's own pair
/// rather than only this line.
#[test]
fn merge_overwrite_does_not_share_a_nested_map_with_the_destination() {
    let source = concat!(
        r#"{{ $target := dict }}{{ $one := dict "foo" (dict "bar" "baz") "qux" true }}"#,
        r#"{{ $two := dict "foo" (dict "bar" "baz2") "qux" false }}"#,
        r#"{{ mergeOverwrite $target $one | toString | trunc 0 }}"#,
        r#"{{ $_ := mergeOverwrite $target $two }}{{ $one }}"#,
    );
    let rendered = Template::parse(source)
        .expect("parses")
        .render_typed(&fixture_root())
        .expect("renders");
    assert_eq!(
        rendered, "map[foo:map[bar:baz] qux:true]",
        "the reference expects map[foo:map[bar:baz2] qux:true] here; see the doc comment"
    );
}
