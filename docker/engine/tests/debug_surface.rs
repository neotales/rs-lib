//! Every public type this crate added a `Debug` impl for is printable, and none
//! of the printings can carry a payload.
//!
//! `missing_debug_implementations` is a workspace lint, so the seven types this
//! file covers were named by the build: `ContainerArchive` and
//! `AttachedSession` in `containers.rs`, `EventStream` in `system.rs`,
//! `DockerStream` in `streams.rs`, and `RawResponse`, `LogFrames` and
//! `SwarmLogFrames` in `raw`. Adding an impl is not a cleanup here. A `Debug`
//! output is a panic message, a test failure, and a log line, and a Docker
//! client holds things worth keeping out of all three: a container's stdout, the
//! bytes of a filesystem archive, the two halves of a live terminal session,
//! and a registry credential.
//!
//! Five of the seven are hand-written, and each has a field that must not
//! appear:
//!
//! - `LogFrames` and `SwarmLogFrames` hold a decoder's partly-arrived bytes and
//!   a queue of finished frame payloads. Both fields already have `Debug` impls
//!   that render in full, so `#[derive(Debug)]` here *compiles* and leaks.
//! - `DockerStream<T>` is generic over the item type the caller asked for, so a
//!   derived impl on it, or on any wrapper that embeds it, would add a `T: Debug`
//!   requirement to a type the caller does not control.
//! - `AttachedSession` owns both halves of an upgraded connection — what a
//!   caller typed into a container, and what it typed back. No test constructs
//!   one and none needs to: its two fields are `DockerStream<ContainerLogFrame>`
//!   and a `Box<dyn AsyncWrite>`, neither of which holds a caller byte that a
//!   `Debug` could reach, and both fields are private so nothing outside the
//!   crate could build the value to try. The guarantee belongs to the two types
//!   underneath, which are tested here, and the mirror below carries the claim
//!   for the derived shape.
//! - `ContainerArchive` is the container's filesystem. A `#[derive(Debug)]`
//!   would compile, because `DockerStream` renders no item, and that is exactly
//!   why it is hand-written: the guarantee would belong to another module.
//! - `EventStream` cannot be derived at all, because its field is a
//!   `Pin<Box<dyn Stream>>`.
//!
//! `RawResponse` is the sixth and the only derive, and it is argued for in
//! place: the body is a hyper `Incoming` **that has not been read**, hyper's own
//! `Debug` for it prints the body's *kind* and never its bytes, `Extensions`
//! prints type names, and the headers are the daemon's own negotiation. The
//! assertion is made here rather than trusted: [`a_raw_response_cannot_render_its
//! own_body`].
//!
//! The assertions check the **absence** of the payload rather than the presence
//! of a format, so a reformatting that stays safe still passes. The helpers are
//! only worth what they can catch, so
//! [`the_negative_control_catches_an_injected_leak`] renders a canary in all
//! three forms a byte string takes in a `Debug` output — text, decimal list,
//! hex list — and requires each to be rejected, and
//! [`a_derive_would_have_rendered_these_payloads`] is a local mirror of each
//! hand-written shape that *does* derive, so the output that was avoided is
//! shown rather than described.
//!
//! # Two more, found by reading what the type holds rather than by a lint
//!
//! The seven types above were named by `missing_debug_implementations`, which
//! only fires on a type that **lacks** `Debug`. It is therefore blind to a
//! `#[derive(Debug)]` on a type that holds a secret, which is the defect that
//! matters here — and the ones it missed are the ones this file now also covers.
//!
//! ## Container output
//!
//! - `raw::LogDecoder` is `pub`, re-exported from `raw`, and its private
//!   `partial` and `ready` fields are container stdout — one frame mid-arrival,
//!   one whole frames not yet handed over. They are the buffer with no other
//!   door: `LogFrames` can be drained through
//!   `next_frame`, a `LogDecoder` cannot, so its bytes are reachable through
//!   `Debug` and nothing else. A derived impl prints them as a decimal byte
//!   list — the one form a search for the payload as text would miss.
//! - `raw::LogFrame` and `ContainerLogFrame` are the two spellings of a decoded
//!   frame, on the owned and Bollard paths. Both derive `Debug` over the
//!   payload. Both are redacted here, and both are kept in step deliberately:
//!   leaving one derived would mean the same bytes printed on one transport and
//!   withheld on the other, decided only by which one a caller configured.
//!
//! ## Credentials
//!
//! - `SwarmInfo` is `pub` and its `join_tokens` is a `serde_json::Value`
//!   carrying the worker and manager join tokens, which are credentials. The
//!   crate already redacts the two credentials beside it in the same file
//!   (`SwarmCertificates::key`, `SwarmUnlockKey::key`); the inconsistency was
//!   the defect.
//! - Redacting the named field was **not sufficient**, and that is the part worth
//!   reading twice. `SwarmInfo` also has `additional`, a `#[serde(flatten)]`
//!   catch-all holding arbitrary daemon JSON, and swarmkit reports the join
//!   tokens a second time nested under `ClusterInfo`. So the first cut at this
//!   was a redaction with a documented bypass, and
//!   [`a_swarm_info_redaction_is_not_bypassed_by_the_flattened_catch_all`] is
//!   the test that would have caught it. The catch-all is now reported as a
//!   count — key names withheld too, since a key name is daemon-chosen.
//!   `SwarmSpec` has the same catch-all, and [`SwarmUpdateOptions`] holds a
//!   `SwarmSpec`, so its redaction is inherited silently and is asserted.
//! - `SwarmJoinOptions::token` and `SwarmUnlockOptions::key` are the *input*
//!   side of two credentials this crate already refuses to render on the output
//!   side. A derived impl protected the credential on the way out and published
//!   it on the way in.
//!
//! All of these are redactions of a *private* field, or of a field whose value is
//! a credential, in a type whose other fields are safe — a shape the mirrors
//! further down now cover too. See
//! [`a_derive_would_have_rendered_the_private_fields_too`], whose
//! `DerivedSwarmInfoWithCatchAll` mirror reproduces the bypass specifically:
//! a guard that searched only the named field would pass while the credential
//! rendered.
//!
//! # Two of the same kind, and the two documents this crate retains whole
//!
//! Both are `serde_json::Value` held **on purpose** — a struct would drop
//! members the daemon sent, and `ContainerInspect` measured itself losing
//! `ExecIDs` that way — so for both the derived impl was the defect rather than
//! a convenience. Both now report identity, state, and counts, and reach no
//! further.
//!
//! - `raw::ContainerInspect` keeps `GET /containers/{id}/json`, twenty-four
//!   top-level members. `Config.Env` is where a container's credentials are:
//!   the database URL, API token, or signing key a caller passed in with `-e` so
//!   the process inside would have it. A caller holding a `ContainerInspect` is
//!   holding it *after something went wrong*, which is the moment `{:?}` gets
//!   reached for.
//! - `raw::ExecInspect` keeps `GET /exec/{id}/json`, eleven members. Its
//!   `ProcessConfig.env` is the same credential on the *one-off command* path: a
//!   caller running `docker exec` with an API key in its environment reads the
//!   answer back to work out why the command printed nothing, which is the
//!   ordinary sequence. `ProcessConfig.arguments` and `entrypoint` are the
//!   command line, where `--token` lives, so they are withheld by association
//!   rather than by inspection.
//!
//! Redacting one named member would not have been enough for either, for the
//! reason `SwarmInfo` ran into: the document is daemon-chosen at every depth.
//! The canaries in the tests below are spread across six members of the
//! container document and three of the exec one, precisely so that a redaction
//! written against the member the issue named fails.
//!
//! # A length problem as well as a content one
//!
//! A `Debug` that emits whatever length the peer chose hands the peer the width
//! of the log line, so the identity members are cut at a fixed budget that says
//! how much was withheld — and **only** those, because a truncation is a length
//! bound and not a redaction, so it must never be the thing standing between a
//! credential and a log. The two copies of that bound are asserted to cut at a
//! character boundary, and the fixture each uses is chosen so the bound really
//! does land mid-codepoint; an earlier version of one of them did not, and passed
//! without ever reaching the code it claimed to cover.
//!
//! # What is still exposed, and is not fixed
//!
//! Recorded here because the sweep these two changes came from found it, and a
//! sweep that reports only what it fixed is not a sweep. Every type below is
//! still `#[derive(Debug)]` over daemon JSON this crate does not model. None of
//! them is claimed clean, and none is covered by a test here.
//!
//! - `raw::NetworkEntry` (`raw/networks.rs`) and `raw::DiskUsageReport`
//!   (`raw/system.rs`) — the same whole-document design as the two above, with
//!   no known credential in either document. Same shape, so the same fix when
//!   they are worth one.
//! - `ContainerStatsResponse` (`streams.rs`) — six `serde_json::Value` fields
//!   of counters (`cpu_stats`, `memory_stats`, `pids_stats`, `blkio_stats`,
//!   `storage_stats`, `precpu_stats`) plus a `networks` map keyed by
//!   daemon-chosen interface name. Numeric in practice; arbitrary JSON at depth
//!   in principle.
//! - `SwarmConfigSpec` (`swarm.rs`) — `data` is the base64 config payload, which
//!   operators routinely carry TLS material in. `SwarmConfig` inherits it. This
//!   one needs a redaction rather than a count, which is why it is called out
//!   separately from the rest of the Swarm types.
//! - `ServiceSpec` (`swarm.rs`) — `task_template` reaches
//!   `ContainerSpec.Env`, the `docker service create --env` credential
//!   location. `SwarmService` inherits it silently.
//! - Nine more Swarm types with a `#[serde(flatten)] additional` catch-all
//!   rendered in full by a derive: `SwarmNode`, `NodeSpec`, `NodeManagerStatus`,
//!   `SwarmSecret`, `SwarmSecretSpec`, `SwarmTask`, `SwarmTaskStatus`,
//!   `SwarmConfig`, and `ServiceSpec` again. This is the exact bypass that was
//!   found and closed for `SwarmInfo` and `SwarmSpec` and left open everywhere
//!   else, so the fix for all nine is mechanical once one exists.

// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding. Scoped to this file, so an undocumented public item in
// the crate is still reported.
#![allow(missing_docs)]

use std::fmt::Write as _;

/// Container output that must never appear in any `Debug` output.
///
/// The literal bytes, so a leak is caught whether it is rendered as text, as a
/// decimal byte list, or as a hex list. `assert_no_secret` checks all three.
const CANARY: &str = "canary-container-output-3f9a2b71-do-not-log-me";

/// A registry credential that must never appear in any `Debug` output.
const SECRET: &str = "canary-registry-secret-8c4e1d05-do-not-log-me";

/// The worker join token a `SwarmInfo` must never render.
///
/// Module-level rather than local to each test, because two tests need it and a
/// canary defined twice is a canary that can drift apart: the leak test and the
/// mirror that proves the leak test can fail both have to search for *the same*
/// string, or the mirror would pass for the wrong reason.
const SWARM_TOKEN: &str = "canary-swarm-worker-token-6b1e0d94-do-not-log-me";

/// The manager join token, which the same rendering must withhold.
const SWARM_MANAGER_TOKEN: &str = "canary-swarm-manager-token-2f7c3a61-do-not-log-me";

/// A type that deliberately does not implement `Debug`.
///
/// Used to compile the claim that a `DockerStream` is printable without one.
/// If any of the seven impls grows a `T: Debug` bound, or any wrapper of
/// `DockerStream` starts deriving, this stops compiling — which is the point:
/// the bound is a tax on every caller and a test that only ran at runtime would
/// not notice it until a consumer's build broke.
struct NotDebug;

/// Requires `T: Debug` without needing a value of it.
///
/// This is the guard that fails the **build** when a hand-written impl is
/// deleted, which an in-crate unit test could not do: `missing_debug_implementations`
/// is a `warn`, so removing the impl would leave the library compiling and only
/// this file would notice. It lives in an integration test for that reason.
fn requires_debug<T: std::fmt::Debug>() {}

/// The seven types the workspace lint named, asserted printable.
///
/// The `DockerStream<NotDebug>` instantiation is the claim that matters most and
/// the one a derive would break: the handle is printable over an item type the
/// caller supplies and this crate has never heard of.
///
/// The second group is the types the lint **cannot** name, because they already
/// had a `Debug` — a derived one, which is the defect. They are listed here for
/// the same reason: removing a hand-written impl has to break the *build*, not
/// just a test, since `missing_debug_implementations` is a `warn` and deleting
/// the impl leaves the library compiling. Two are credential-bearing Swarm
/// types, two are frame types whose payload is container stdout,
/// `SwarmUpdateOptions` is here because it *inherits* a redaction from the
/// `SwarmSpec` it holds — it keeps compiling and keeps its derive either way, so
/// the assertion that matters for it is about the rendering, below — and
/// `ContainerInspect` and `ExecInspect` because they already had a derive over
/// a whole inspect document, which is the largest thing this crate retains.
#[test]
fn every_type_the_lint_named_is_debug_and_some_need_no_item_bound() {
    requires_debug::<neotales_docker::ContainerArchive>();
    requires_debug::<neotales_docker::AttachedSession>();
    requires_debug::<neotales_docker::EventStream>();
    requires_debug::<neotales_docker::DockerStream<NotDebug>>();
    requires_debug::<neotales_docker::raw::RawResponse>();
    requires_debug::<neotales_docker::raw::LogFrames>();
    requires_debug::<neotales_docker::raw::SwarmLogFrames>();

    requires_debug::<neotales_docker::raw::LogDecoder>();
    requires_debug::<neotales_docker::raw::LogFrame>();
    requires_debug::<neotales_docker::ContainerLogFrame>();
    requires_debug::<neotales_docker::SwarmInfo>();
    requires_debug::<neotales_docker::SwarmSpec>();
    requires_debug::<neotales_docker::SwarmUpdateOptions>();
    requires_debug::<neotales_docker::SwarmJoinOptions>();
    requires_debug::<neotales_docker::SwarmUnlockOptions>();
    requires_debug::<neotales_docker::raw::ContainerInspect>();
    requires_debug::<neotales_docker::raw::ExecInspect>();
}

/// Every field name the two summary `Debug`s are allowed to render, gathered in
/// one place for reference.
///
/// **The lists that are actually enforced are the ones inline in each test** —
/// [`a_container_inspect_prints_its_identity_and_not_its_document`]'s and
/// [`an_exec_inspect_prints_its_identity_and_not_its_process_config`]'s — because
/// a summary's fields are a property of that summary, and a reader fixing a
/// field name wants to see the list beside the impl that renders it. This
/// constant is not the gate; it is the inventory, and
/// [`the_field_allowlist_rejects_an_added_or_a_renamed_field`] asserts the two
/// cannot drift apart.
///
/// The reason the gate exists at all: the canary tests prove a *known* payload
/// is absent, and cannot prove the set of fields has not grown. A new member
/// added to a summary — by a deliberate edit, or by a future `#[derive]`
/// replacing the impl — would render something the canaries never thought of,
/// and every canary test would stay green. That is the `SwarmInfo` catch-all
/// failure one level up: a guard that searched only what it knew about.
const SUMMARY_FIELDS: [&str; 24] = [
    // `ContainerInspect`.
    "id",
    "name",
    "image",
    "state",
    "health",
    "running",
    "paused",
    "tty",
    "exit_code",
    "pid",
    "env_vars",
    "ports",
    "members",
    // `ExecInspect`. `id` is deliberately repeated: it is the name the exec
    // answer uses, and the renderer derives it from the same struct shape. A
    // duplicate here is harmless — the check is a set comparison — and dropping
    // it would misrepresent what the allowlist is.
    "id",
    "container",
    "running",
    "exit_code",
    "pid",
    "open_stdin",
    "open_stdout",
    "open_stderr",
    "env",
    "arguments",
    "members",
];

/// What a `debug_struct` rendering actually printed: its field names, and
/// whether it ended non-exhaustively.
///
/// Parsed rather than searched for, because a substring check cannot tell a
/// field name from a value that happens to contain one — and a value in these
/// summaries is a digest, a number, or a document member name, so `state:
/// Some("running")` would make a naive `contains("state")` pass while the field
/// had been renamed to something else.
///
/// Only the top level is walked: the values nest inside `Some(…)`, so a
/// parenthesis depth counter is what keeps a nested `..` or a quoted name from
/// being counted as a field. The `finish_non_exhaustive` marker is dropped, since
/// it is not a field and its presence is asserted separately.
struct PrintedSummary {
    fields: Vec<String>,
    non_exhaustive: bool,
}

fn printed_fields(rendered: &str) -> PrintedSummary {
    // The type name is whatever precedes the first brace and carries nothing the
    // allowlist cares about, so it is dropped by finding the brace rather than
    // by stripping a known number of leading characters — a predicate-based
    // `strip_prefix` removes a single char, which is the type name's first
    // letter, and leaves the rest to be walked as if it were field syntax.
    let body = rendered
        .trim()
        .split_once('{')
        .map(|(_, body)| body)
        .unwrap_or_default();
    let body = body.rsplit_once('}').map_or(body, |(body, _)| body);

    let mut fields = Vec::new();
    let mut non_exhaustive = false;
    let mut depth = 0_usize;
    let mut part = String::new();
    for character in body.chars() {
        match character {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            // Only a comma at the top level ends a part, so a value's own commas
            // stay inside the value they belong to.
            ',' if depth == 0 => {
                fields.extend(field_names(part.trim(), &mut non_exhaustive));
                part.clear();
                continue;
            }
            _ => {}
        }
        part.push(character);
    }
    fields.extend(field_names(part.trim(), &mut non_exhaustive));

    PrintedSummary {
        fields,
        non_exhaustive,
    }
}

/// The field name `part` contributes, if it is one at all.
///
/// A part with no `:` is not a field. In a `debug_struct` rendering that can only
/// be the `..` from `finish_non_exhaustive`, and recognising it here is what
/// makes the marker a **structural** observation: a value containing two dots
/// lives inside a part that does have a `:`, so it is a value, and cannot be
/// mistaken for the marker the way a substring search over the whole rendering
/// could.
///
/// A part that *does* have a `:` is a field only if what precedes the first colon
/// is an identifier. The caller has already split on commas at nesting depth
/// zero, so a value cannot be this fragment to begin with; the identifier test is
/// what rejects a malformed rendering, not an ordinary name.
fn field_names(part: &str, non_exhaustive: &mut bool) -> Option<String> {
    let Some((name, _value)) = part.split_once(':') else {
        *non_exhaustive |= part == "..";
        return None;
    };
    // A field name is an identifier, so anything else is not one.
    let name = name.trim();
    (name.chars().all(|c| c.is_alphanumeric() || c == '_') && !name.is_empty())
        .then(|| name.to_owned())
}

/// Requires that `rendered` names exactly the fields in `expected`.
///
/// The comparison is on the **set**, not the order, so reordering a summary to
/// read better is not a test failure, and a name may appear in `expected` for one
/// type and in the other type's list too. An extra name is the case that matters,
/// so the diff names both sides: a reader who has just added a field needs to be
/// told which one.
fn assert_fields(rendered: &str, expected: &[&str]) {
    let PrintedSummary {
        fields: printed,
        non_exhaustive,
    } = printed_fields(rendered);
    let extra: Vec<_> = printed
        .iter()
        .filter(|name| !expected.contains(&name.as_str()))
        .collect();
    assert!(
        extra.is_empty(),
        "a summary Debug rendered fields that are not on the allowlist: {extra:?} in {rendered}"
    );
    let missing: Vec<_> = expected
        .iter()
        .filter(|name| !printed.iter().any(|printed| printed == *name))
        .collect();
    assert!(
        missing.is_empty(),
        "a summary Debug dropped allowed fields: {missing:?} in {rendered}"
    );
    // The door left open for a member added later, asserted rather than assumed:
    // dropping `finish_non_exhaustive` from either impl would let a new field
    // appear in full, and the allowlist would then be the only thing standing
    // between that and a log line.
    //
    // Structural, not a search for two dots. A value that happens to contain
    // `..` — a path, a name, a daemon's own message — would satisfy a substring
    // search and pass a check that is about a *position* in the rendering, so
    // the marker is recognised as the one top-level part that is not a field.
    assert!(
        non_exhaustive,
        "the rendering does not end with a non-exhaustive marker: {rendered}"
    );
}

/// The field-name allowlist is only worth what it can catch, so this is the
/// check that a field the canaries know nothing about is rejected, and that a
/// renamed field is caught even though a substring search would have passed.
///
/// Three cases, one of which is the one that makes the helper a parser rather
/// than a `contains`: a value that *contains* a field name must not satisfy the
/// check for that field. `state: Some("running")` would make a `contains`
/// pass after the field had been renamed to `status`, and the whole guard would
/// be decorative.
#[test]
fn the_field_allowlist_rejects_an_added_or_a_renamed_field() {
    // A field nobody thought of, rendered in the middle where a future addition
    // would actually land.
    let extra = "ContainerInspect { id: Some(\"abc\"), config: Some(\"[redacted]\"), .. }";
    let caught = std::panic::catch_unwind(|| {
        assert_fields(extra, &["id", "name", "members"]);
    });
    assert!(caught.is_err(), "an added field must be caught: {extra}");

    // A field the allowlist knows, missing from the rendering.
    let dropped = "ContainerInspect { id: Some(\"abc\"), .. }";
    let caught = std::panic::catch_unwind(|| {
        assert_fields(dropped, &["id", "name", "members"]);
    });
    assert!(caught.is_err(), "a dropped field must be caught: {dropped}");

    // The renaming case: `status` is what a redaction would plausibly be
    // renamed to, and `state: Some("running")` is a value mentioning the old
    // name. A `contains`-based check would pass this; a parser must not.
    let renamed = "ContainerInspect { id: None, state: Some(\"running\"), .. }";
    let caught = std::panic::catch_unwind(|| {
        assert_fields(renamed, &["id", "name", "members"]);
    });
    assert!(
        caught.is_err(),
        "a renamed field must be caught even when a value mentions the old name: {renamed}"
    );

    // And a real rendering must pass, with no false positive on nested text. A
    // `Some("…")` value contains commas and quotes, which the depth counter has
    // to survive, and a `..` must not be counted as a field name.
    assert_fields(
        "ContainerInspect { id: Some(\"a, b\"), state: Some(\"running\"), members: Some(2), .. }",
        &["id", "state", "members"],
    );

    // The marker is a position, not a substring. A value carrying two dots would
    // satisfy a `contains("..")` check, so this is the case that makes the
    // structural read load-bearing rather than a rename of the same assertion.
    let dotted_value = "ExecInspect { id: Some(\"3101..\"), env: Some(2), .. }";
    assert_fields(dotted_value, &["id", "env"]);
    // And a rendering that has *no* marker must be caught even though a value
    // in it contains two dots, which is the false positive this replaces.
    let no_marker = "ExecInspect { id: Some(\"3101..\"), env: Some(2) }";
    let caught = std::panic::catch_unwind(|| assert_fields(no_marker, &["id", "env"]));
    assert!(
        caught.is_err(),
        "a missing marker must be caught even when a value contains two dots: {no_marker}"
    );

    // The type name is not field syntax, whatever it is spelled. Both the short
    // and the qualified spellings reach the same field list, which a prefix
    // strip that removed a single character would not.
    for name in ["ExecInspect", "neotales_docker::raw::ExecInspect", "X"] {
        let qualified = format!("{name} {{ id: Some(\"x\"), env: None, .. }}");
        assert_fields(&qualified, &["id", "env"]);
    }

    // The global allowlist and the two per-test lists must agree, or one of them
    // is documenting a set that no longer exists.
    for name in [
        "name",
        "image",
        "health",
        "paused",
        "tty",
        "env_vars",
        "ports",
        "container",
        "open_stdin",
        "open_stdout",
        "open_stderr",
        "env",
        "arguments",
    ] {
        assert!(
            SUMMARY_FIELDS.contains(&name),
            "{name:?} is in a per-test allowlist but not the shared one"
        );
    }
}

/// Fails the test if `output` contains `secret` in any of the three forms a byte
/// string can take in a `Debug` rendering: as text, as a decimal list, or as a
/// hex list.
fn assert_no_secret(output: &str, secret: &str) {
    assert_no_bytes(output, Some(secret), secret.as_bytes());
}

/// The same check for a value that need not be valid UTF-8.
///
/// `text` is the encoding to search for as a string and is `None` when there is
/// none. A derived `Debug` prints a `Vec<u8>` as a decimal list, which is the
/// form a leaked byte string would *most likely* take here, and it is the form a
/// check that searched only for text would miss.
fn assert_no_bytes(output: &str, text: Option<&str>, secret: &[u8]) {
    if let Some(text) = text {
        assert!(
            !output.contains(text),
            "Debug output leaked the payload as text: {output}"
        );
    }
    let mut decimal = String::new();
    for (index, byte) in secret.iter().enumerate() {
        if index > 0 {
            decimal.push_str(", ");
        }
        decimal.push_str(&byte.to_string());
    }
    assert!(
        !output.contains(&decimal),
        "Debug output leaked the payload as a decimal byte list: {output}"
    );
    let mut hex = String::new();
    for byte in secret {
        write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    let spaced = hex
        .as_bytes()
        .chunks(2)
        .map(|pair| std::str::from_utf8(pair).unwrap_or_default())
        .collect::<Vec<_>>()
        .join(", ");
    assert!(
        !output.contains(&hex) && !output.contains(&spaced),
        "Debug output leaked the payload as a hex byte list: {output}"
    );
}

/// The helpers above are the load-bearing part of this file, so they are checked
/// against a leak deliberately rendered in each of the three forms they claim to
/// catch.
///
/// If this ever passes while the helpers cannot fail, the rest of the file is
/// decorative.
#[test]
fn the_negative_control_catches_an_injected_leak() {
    // Form 1: a `String` or `Vec<u8>`-of-UTF-8 field printed as text.
    let leaked_text = format!("LogFrames {{ payload: {CANARY:?} }}");
    let caught = std::panic::catch_unwind(|| assert_no_secret(&leaked_text, CANARY));
    assert!(caught.is_err(), "a text leak must be caught: {leaked_text}");

    // Form 2: a `Vec<u8>` field printed as a decimal list. This is what
    // `LogFrames { decoder: LogDecoder { partial: .. } }` would actually have
    // looked like, because the field is a `Vec<u8>`.
    let leaked_decimal = format!(
        "LogDecoder {{ pending: [{}] }}",
        CANARY
            .as_bytes()
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    );
    let caught = std::panic::catch_unwind(|| assert_no_secret(&leaked_decimal, CANARY));
    assert!(
        caught.is_err(),
        "a decimal-list leak must be caught: {leaked_decimal}"
    );

    // Form 3: the same bytes as a hex list, which is what a redacting
    // implementation may print and what a redaction check must not miss.
    let mut hex = String::new();
    for byte in CANARY.as_bytes() {
        write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    let leaked_hex = format!("AttachedSession {{ input: [{hex}] }}");
    let caught = std::panic::catch_unwind(|| assert_no_secret(&leaked_hex, CANARY));
    assert!(
        caught.is_err(),
        "a hex-list leak must be caught: {leaked_hex}"
    );

    // And the raw-byte variant, for a payload that is not valid UTF-8 and so has
    // no text form to search for.
    let non_utf8 = [0xff_u8, 0xfe, 0x00, 0x80];
    let leaked_raw = format!(
        "ContainerArchive {{ stream: [{}] }}",
        non_utf8
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    );
    let caught = std::panic::catch_unwind(|| assert_no_bytes(&leaked_raw, None, &non_utf8));
    assert!(
        caught.is_err(),
        "a raw-byte leak must be caught: {leaked_raw}"
    );

    // A real, safe `Debug` output from this crate must *not* be caught. Without
    // this, the four checks above would also pass if `assert_no_bytes` simply
    // rejected everything.
    assert_no_secret("LogFrames { tty: false, buffered: 12 }", CANARY);
    assert_no_secret("AttachedSession", SECRET);
}

/// A `RawRequest` carries a registry credential in a header, and its query is
/// a caller-supplied string, and neither may reach any `Debug` output.
///
/// Both were leaking, and the suites next door did not notice: this file's own
/// `assert_no_bytes` searches for a canary as text, a decimal byte list, or a
/// hex list — and a base64 credential is **none of those three**. So a header
/// leak slips straight past the helper written to stop exactly this, which is
/// why this test searches the base64 form as well.
///
/// The base64 is produced by an independent implementation of the same
/// specification rather than by the crate the code under test uses, so the test
/// cannot pass by agreeing with the encoder it is checking.
#[test]
fn a_raw_request_debug_redacts_the_credential_and_the_query() {
    use hyper::Method;
    use hyper::header::{HeaderMap, HeaderValue};
    use neotales_docker::raw::{RawBody, RawRequest};

    const PLAIN: &str = "canary-rawrequest-credential-5d1e8a34-do-not-log-me";
    const QUERY: &str = "canary-rawrequest-query-do-not-log-me";
    const CONFIG: &str = "canary-rawrequest-config-do-not-log-me";
    const BODY: &str = "canary-rawrequest-body-do-not-log-me";

    let mut headers = HeaderMap::new();
    for (name, secret) in [("x-registry-auth", PLAIN), ("x-registry-config", CONFIG)] {
        // URL_SAFE is the alphabet the crate encodes with, and it is the one that
        // differs from the standard form for the two canaries carrying `?` or `~`.
        let forms = base64_forms(secret.as_bytes());
        let encoded = forms[1].clone();
        headers.insert(
            name,
            HeaderValue::from_str(&encoded).expect("a base64 credential is a legal header value"),
        );
    }
    headers.insert("content-type", HeaderValue::from_static("application/json"));

    let request = RawRequest {
        method: Method::POST,
        path: "/images/load".to_owned(),
        query: Some(format!("tag={QUERY}")),
        headers,
        body: RawBody::Bytes(bytes::Bytes::from_static(BODY.as_bytes())),
    };

    let rendered = format!("{request:?}");

    // The plaintext forms, and the base64 forms a credential takes on the wire.
    // A base64 encoding of a secret is not a redaction, and a check searching
    // only for the plaintext would pass while the leak continued.
    for secret in [PLAIN, QUERY, CONFIG, BODY, ALPHABET_CANARY] {
        let mut forms = vec![secret.to_owned()];
        forms.extend(base64_forms(secret.as_bytes()));
        for form in forms {
            assert!(
                !rendered.contains(&form),
                "a RawRequest Debug leaked {form:?}: {rendered}"
            );
        }
    }

    // The safe parts have to survive, or this test would also pass against a
    // `Debug` that printed nothing at all.
    assert!(
        rendered.contains("/images/load"),
        "the path is the part a reader diagnosing a request needs: {rendered}"
    );
    assert!(
        rendered.contains("application/json"),
        "a non-credential header value is diagnostic: {rendered}"
    );
    assert!(
        rendered.contains("redacted"),
        "the redaction must be visible rather than an omission: {rendered}"
    );
}

/// Base64 with padding, per RFC 4648 §4, in **both** alphabets.
///
/// Written out from the specification rather than calling the `base64` crate, so
/// this suite and the code under test cannot be wrong in the same way.
///
/// Both alphabets, and that is the part that was wrong. This encoded `STANDARD`
/// (`+/`) while the crate encodes registry credentials with `URL_SAFE` (`-_`) —
/// the whole argument of `image_transfer.rs` is that the two differ and the
/// daemon decodes URL-safe. Every canary here happened to encode identically
/// under both, so the test fired and *looked* like it covered the base64 form.
/// It did not: a canary carrying `?`, `~` or `>` at a 3-byte-aligned offset
/// encodes differently, and that is the condition `image_transfer.rs` calls "a
/// real password".
fn base64_forms(input: &[u8]) -> [String; 2] {
    /// `STANDARD` differs from `URL_SAFE` only in the last two characters, per
    /// RFC 4648 §5.
    const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    let encode = |alphabet: &[u8; 64], input: &[u8]| -> String {
        let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
        for chunk in input.chunks(3) {
            let b0 = u32::from(chunk[0]);
            let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
            let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
            let triple = (b0 << 16) | (b1 << 8) | b2;
            out.push(alphabet[(triple >> 18 & 0x3f) as usize] as char);
            out.push(alphabet[(triple >> 12 & 0x3f) as usize] as char);
            out.push(if chunk.len() > 1 {
                alphabet[(triple >> 6 & 0x3f) as usize] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                alphabet[(triple & 0x3f) as usize] as char
            } else {
                '='
            });
        }
        out
    };
    [encode(STANDARD, input), encode(URL_SAFE, input)]
}

/// A canary whose base64 **differs** between the two alphabets.
///
/// `?` and `~` are the two characters the alphabets disagree on, so a secret
/// containing one at a 3-byte-aligned offset encodes to a string the standard
/// encoder never produces. Without this canary the base64 arm of the redaction
/// test cannot fail, which is the same defect as testing nothing.
const ALPHABET_CANARY: &str = "canary-rawrequest-a?b-alphabet-do-not-log-me";

/// Serves exactly one HTTP/1.1 request and returns the address to point a client
/// at, the thread answering it, and the handle that lets the caller finish it.
///
/// The connection is held open after the response is written until the caller
/// releases it, because the handles under test are *streams*: their whole point
/// is that they own a live response, and a fixture that closed immediately would
/// leave nothing buffered and the assertions would pass vacuously. The wait is a
/// rendezvous rather than a sleep, so a passing run costs no wall time and a
/// hung one still ends.
fn serve_once(
    response: Vec<u8>,
) -> (
    std::net::SocketAddr,
    std::thread::JoinHandle<()>,
    std::sync::mpsc::Sender<()>,
) {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
    let address = listener.local_addr().expect("a bound address");
    let (release, released) = std::sync::mpsc::channel::<()>();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("a connection");
        let mut request = [0_u8; 2048];
        let _ = stream.read(&mut request);
        stream
            .write_all(&response)
            .expect("the fixture writes its response");
        stream.flush().expect("the fixture flushes");
        let _ = released.recv_timeout(std::time::Duration::from_secs(30));
        let _ = stream.shutdown(std::net::Shutdown::Both);
    });
    (address, handle, release)
}

/// An owned transport pointed at a loopback fixture.
fn engine_at(address: std::net::SocketAddr) -> neotales_docker::raw::RawEngine {
    neotales_docker::raw::RawEngine::new(
        neotales_docker::raw::RawTarget::Tcp {
            host: address.ip().to_string(),
            port: address.port(),
        },
        neotales_docker::ApiVersion {
            major: 1,
            minor: 53,
        },
    )
}

/// One multiplexed frame exactly as the Engine writes it: an eight-byte header
/// naming the stream and the payload length, then the payload.
fn frame(stream: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![stream, 0, 0, 0];
    out.extend_from_slice(
        &u32::try_from(payload.len())
            .expect("a canary fits u32")
            .to_be_bytes(),
    );
    out.extend_from_slice(payload);
    out
}

/// A frame header that promises `declared` payload bytes.
fn header(stream: u8, declared: usize) -> Vec<u8> {
    let mut out = vec![stream, 0, 0, 0];
    out.extend_from_slice(
        &u32::try_from(declared)
            .expect("a canary fits u32")
            .to_be_bytes(),
    );
    out
}

/// Builds a `200` whose body is `body`, with an explicit length.
fn multiplexed_response(body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/vnd.docker.multiplexed-stream\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

/// Opens a log stream against a fixture carrying `body`, and reads one frame.
///
/// The two are separate because the interesting assertions are about what the
/// handle is *holding*, and which of its two buffers holds it depends on the
/// body. A caller that only ever drained a stream would find both empty, and an
/// assertion about a payload that is not there proves nothing.
async fn open_logs(
    body: Vec<u8>,
) -> (
    neotales_docker::raw::LogFrames,
    neotales_docker::raw::RawEngine,
    std::thread::JoinHandle<()>,
    std::sync::mpsc::Sender<()>,
) {
    let (address, server, release) = serve_once(multiplexed_response(&body));
    let engine = engine_at(address);
    let mut frames = neotales_docker::raw::logs(
        &engine,
        "web",
        &neotales_docker::raw::ContainerLogOptions::default(),
    )
    .await
    .expect("the fixture answers 200");
    let first = frames
        .next_frame()
        .await
        .expect("a frame stream reads")
        .expect("a frame");
    assert_eq!(
        first.payload,
        CANARY.as_bytes(),
        "the fixture really carried the canary"
    );
    (frames, engine, server, release)
}

/// `LogFrames` must not render a frame's payload, checked against a real frame
/// arriving over a real socket rather than against a mirror of one.
///
/// The bytes are held in one of two fields depending on the state, and **both**
/// states are checked, because checking only one is how a redaction assertion
/// ends up guarding an empty buffer:
///
/// - `ready` holds the frames one network read completed beyond the first. The
///   body is two complete frames and the test reads one, so the second is queued.
/// - `decoder.partial` holds bytes that have arrived but do not yet form a
///   frame. The body is one complete frame followed by a header promising more
///   payload than the body delivers, so the canary is left in the decoder.
///
/// Both fields have `Debug` impls that render in full, so `#[derive(Debug)]` on
/// `LogFrames` compiles and prints the container's output.
#[tokio::test]
async fn a_log_frame_stream_prints_no_queued_frame_payload() {
    // Two whole frames; reading the first leaves the second in `ready`.
    let body = [frame(1, CANARY.as_bytes()), frame(2, CANARY.as_bytes())].concat();
    let (frames, engine, server, release) = open_logs(body).await;

    let rendered = format!("{frames:?}");
    assert_no_secret(&rendered, CANARY);
    // The queue is not empty, so the assertion above is about a payload that was
    // really there rather than about one that never arrived.
    assert!(rendered.contains("ready_frames: 1"), "{rendered}");

    drop(frames);
    drop(engine);
    drop(release);
    server.join().expect("the fixture thread finished");
}

/// The same claim for the decoder's own buffer, which is the field that leaks a
/// *partially arrived* frame — the one a caller cannot see through any other
/// door.
#[tokio::test]
async fn a_log_frame_stream_prints_no_partly_arrived_frame() {
    // One whole frame, then a header promising 4096 bytes of which the body
    // delivers only a few. Those few bytes are the canary, and the decoder is
    // holding them because it cannot yet make a frame of them.
    let delivered = CANARY.len() / 2;
    let body = [
        frame(1, CANARY.as_bytes()),
        header(1, 4096),
        CANARY.as_bytes()[..delivered].to_vec(),
    ]
    .concat();
    let (frames, engine, server, release) = open_logs(body).await;

    let rendered = format!("{frames:?}");
    assert_no_secret(&rendered, CANARY);
    // The buffer holds the trailing header as well as the payload bytes, so the
    // count is the eight-byte header plus what was delivered.
    assert!(
        rendered.contains(&format!("buffered: {}", 8 + delivered)),
        "the decoder should be holding the partly arrived payload: {rendered}"
    );

    drop(frames);
    drop(engine);
    drop(release);
    server.join().expect("the fixture thread finished");
}

/// `SwarmLogFrames` is the same shape duplicated for `/tasks/{id}/logs`, and it
/// gets the same assertion rather than being assumed to follow. The body is the
/// queued-frame state, because that is the one a task's output lands in.
#[tokio::test]
async fn a_swarm_log_frame_stream_prints_no_frame_payload() {
    let body = [frame(1, CANARY.as_bytes()), frame(2, CANARY.as_bytes())].concat();
    let (address, server, release) = serve_once(multiplexed_response(&body));
    let engine = engine_at(address);
    let mut frames = neotales_docker::raw::task_logs(
        &engine,
        "web.1.abc",
        &neotales_docker::SwarmLogOptions::default(),
    )
    .await
    .expect("the fixture answers 200");

    let first = frames
        .next_frame()
        .await
        .expect("a frame stream reads")
        .expect("a frame");
    assert_eq!(
        first.payload,
        CANARY.as_bytes(),
        "the fixture carried the canary"
    );

    let rendered = format!("{frames:?}");
    assert_no_secret(&rendered, CANARY);
    assert!(rendered.contains("ready_frames: 1"), "{rendered}");

    drop(frames);
    drop(engine);
    drop(release);
    server.join().expect("the fixture thread finished");
}

/// A `DockerStream` is printable over an item type the caller supplies, and the
/// handle says whether it is open without rendering the item.
///
/// The client is never asked for anything, so the handle is exactly what a
/// caller holds after starting an operation: an owned response it has not read.
#[test]
fn a_docker_stream_prints_its_state_and_not_its_item() {
    let client = neotales_docker::DockerClient::connect_http("http://127.0.0.1:1")
        .expect("a client that has connected to nothing yet");
    let stream: neotales_docker::DockerStream<Vec<u8>> = client.export_image("busybox");
    let rendered = format!("{stream:?}");
    assert!(rendered.contains("open: true"), "{rendered}");
    assert!(rendered.contains("owned_task"), "{rendered}");

    let mut cancelled = stream;
    cancelled.cancel();
    let rendered = format!("{cancelled:?}");
    assert!(rendered.contains("open: false"), "{rendered}");

    // The "not its item" half, which the name above claims and which the two
    // assertions alone do not reach. A canary cannot be placed here the way
    // `assert_no_secret` places one elsewhere in this file: the items are
    // daemon bytes held in a channel, and this handle is connected to nothing,
    // so there is no item in it to canary and no public way to put one there.
    //
    // What *is* observable from outside the crate is whether the rendering
    // depends on the item type at all. So this compares two handles carrying
    // different item types in the same state. A `Debug` that rendered the item,
    // named its type, or showed anything derived from `T` would make these two
    // differ — including a derive on a wrapper, which is the specific way this
    // guarantee is usually lost. The hand-written impl prints `open` and
    // `owned_task` and calls `finish_non_exhaustive`, which is the same
    // rendering for every `T`.
    let over_bytes = client.export_image("busybox");
    let over_wait: neotales_docker::DockerStream<neotales_docker::ContainerWaitResult> =
        client.wait_container("web", None);
    assert_eq!(
        format!("{over_bytes:?}"),
        format!("{over_wait:?}"),
        "a handle's rendering must not depend on the item type it carries"
    );
}

/// `ContainerArchive` is hand-written rather than derived, and the reason is that
/// its archive is the container's filesystem. This asserts the part that *is*
/// observable: the path metadata is reported, so the type is still a useful thing
/// to log, and the stream contributes only its state.
///
/// What cannot be observed from here is the archive's bytes, because
/// `DockerStream` does not buffer any — which is why the mirror in
/// [`a_derive_would_have_rendered_these_payloads`] carries that claim instead.
#[test]
fn a_container_archive_reports_its_path_metadata_and_its_handle() {
    let client = neotales_docker::DockerClient::connect_http("http://127.0.0.1:1")
        .expect("a client that has connected to nothing yet");
    let archive = neotales_docker::ContainerArchive {
        stat: neotales_docker::ContainerPathStat {
            name: "id_rsa".to_owned(),
            size: 1679,
            mode: 0o100_600,
            link_target: None,
        },
        stream: client.export_container("web"),
    };
    let rendered = format!("{archive:?}");
    assert!(rendered.contains("id_rsa"), "{rendered}");
    assert!(rendered.contains("open: true"), "{rendered}");
}

/// `RawResponse` is the one derive in this change, and this is the assertion the
/// decision rests on: the body has not been read, so hyper renders its *kind* and
/// no byte of it can appear.
#[tokio::test]
async fn a_raw_response_cannot_render_its_own_body() {
    let response = format!(
        "HTTP/1.1 200 OK\r\nApi-Version: 1.53\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{CANARY}",
        CANARY.len()
    );
    let (address, server, release) = serve_once(response.into_bytes());
    let engine = engine_at(address);
    let raw = engine
        .send(neotales_docker::raw::RawRequest::new(
            hyper::Method::GET,
            "/containers/json",
        ))
        .await
        .expect("the fixture answers 200");

    let rendered = format!("{raw:?}");
    assert_no_secret(&rendered, CANARY);
    // The derive is only defensible if the caller still learns the two things
    // that matter about an answer. A redacting impl that dropped them would be a
    // worse tool in exchange for a guarantee this type does not need.
    assert!(rendered.contains("200"), "{rendered}");
    assert!(
        rendered.to_lowercase().contains("api-version"),
        "{rendered}"
    );

    drop(raw);
    drop(engine);
    drop(release);
    server.join().expect("the fixture thread finished");
}

/// Mirrors of the field shapes the hand-written impls exist for, with `Debug`
/// **derived**, so the output that was avoided is on the screen rather than in a
/// comment.
///
/// Each is a faithful copy of one real type's fields. If a derived `Debug` on
/// the real type would not have printed the canary, the hand-written impl is not
/// earning its place and the reasoning beside it is wrong — so
/// [`a_derive_would_have_rendered_these_payloads`] is a claim about the *real*
/// impls, checked against these.
///
/// Every field is read by nothing but the derived `Debug`, which is the entire
/// point of each type, and rustc's dead-code pass does not count a derived
/// `Debug` as a read. That is the one thing the `allow` is for.
//
/// Mirrors `raw::logs::LogDecoder`: `pending` stands for the buffers that hold a
/// frame whose header has not finished arriving — a partly arrived payload
/// (`partial`) and whole frames the caller has not been handed yet (`ready`).
/// They are one field here so the mirror stays a minimal derive, which is the
/// shape under test.
#[derive(Debug)]
#[allow(
    dead_code,
    reason = "the derived Debug is the only reader, and it is the subject"
)]
struct DerivedLogDecoder {
    pending: Vec<u8>,
}

/// Mirrors `raw::logs::LogFrame`: the payload is the container's own output.
#[derive(Debug)]
#[allow(
    dead_code,
    reason = "the derived Debug is the only reader, and it is the subject"
)]
struct DerivedLogFrame {
    payload: Vec<u8>,
}

/// Mirrors `raw::logs::LogFrames`.
#[derive(Debug)]
#[allow(
    dead_code,
    reason = "the derived Debug is the only reader, and it is the subject"
)]
struct DerivedLogFrames {
    decoder: DerivedLogDecoder,
    ready: Vec<DerivedLogFrame>,
}

/// Mirrors `containers::SessionInput`'s neighbour in the same session: the bytes
/// a caller types into an attached container.
#[derive(Debug)]
#[allow(
    dead_code,
    reason = "the derived Debug is the only reader, and it is the subject"
)]
struct DerivedAttachedSession {
    input: Vec<u8>,
}

/// Mirrors `containers::ContainerArchive` with an embedded stream.
#[derive(Debug)]
#[allow(
    dead_code,
    reason = "the derived Debug is the only reader, and it is the subject"
)]
struct DerivedContainerArchive {
    stream: Vec<u8>,
}

/// Mirrors a `RawResponse` that rendered its body, which is the one thing the
/// real type must never do.
///
/// `RawResponse` is the only derive in this change, and its guard cannot be made
/// to fail by editing this crate: what keeps the body out is hyper's own `Debug`
/// for `Incoming`, which prints the body's *kind*. This mirror is the control for
/// the assertion rather than for the impl — a response that *did* render its body
/// is caught by exactly the check
/// `a_raw_response_cannot_render_its_own_body` makes against a real one.
#[derive(Debug)]
#[allow(
    dead_code,
    reason = "the derived Debug is the only reader, and it is the subject"
)]
struct ResponseThatRenderedItsBody {
    status: u16,
    body: Vec<u8>,
}

/// Asserts that a rendering which *does* carry `secret` is rejected, naming
/// which shape it was, so a failure says which mirror stopped being a mirror.
///
/// The rendering happens outside the `catch_unwind` closure: formatting borrows
/// the value, and a borrow is not `UnwindSafe`.
///
/// The secret is a parameter rather than this file's `CANARY` because the
/// mirrors cover two different credentials — container output and a Swarm join
/// token — and each has to be searched for in the rendering that carries *it*.
fn assert_derived_shape_leaks<T: std::fmt::Debug>(name: &str, secret: &str, value: T) {
    let rendered = format!("{value:?}");
    let caught = std::panic::catch_unwind(|| assert_no_secret(&rendered, secret));
    assert!(
        caught.is_err(),
        "a derived {name} must be caught, so the hand-written impl is load-bearing: {rendered}"
    );
}

/// A `#[derive(Debug)]` on each of the real types would have rendered the
/// container's own output. See the mirrors above for why each exists.
#[test]
fn a_derive_would_have_rendered_these_payloads() {
    assert_derived_shape_leaks(
        "LogFrames",
        CANARY,
        DerivedLogFrames {
            decoder: DerivedLogDecoder {
                pending: CANARY.as_bytes().to_vec(),
            },
            ready: vec![DerivedLogFrame {
                payload: CANARY.as_bytes().to_vec(),
            }],
        },
    );
    assert_derived_shape_leaks(
        "AttachedSession",
        CANARY,
        DerivedAttachedSession {
            input: CANARY.as_bytes().to_vec(),
        },
    );
    assert_derived_shape_leaks(
        "ContainerArchive",
        CANARY,
        DerivedContainerArchive {
            stream: CANARY.as_bytes().to_vec(),
        },
    );
    assert_derived_shape_leaks(
        "response that rendered its body",
        CANARY,
        ResponseThatRenderedItsBody {
            status: 200,
            body: CANARY.as_bytes().to_vec(),
        },
    );
}

/// `zeroize` derives `Debug` for `Zeroizing` by printing the wrapped value, and
/// the wrapper is an erasure guarantee rather than a redaction one.
///
/// None of the seven types here holds a `Zeroizing`, so no impl in this change
/// rests on the claim — but it is the trap a future edit would fall into, and it
/// fails silently in the dangerous direction: if `zeroize` ever stopped deriving
/// `Debug`, a `#[derive(Debug)]` on a struct holding one would become safe and
/// the maintainer reading only the struct would have no way to know. Asserted
/// here so that a change of behaviour in the dependency fails loudly instead.
#[test]
fn zeroizing_is_not_a_redaction_wrapper() {
    let canary = *b"CANARY-IN-MEMORY-PROTECTION-KEY!";
    let rendered = format!("{:?}", zeroize::Zeroizing::new(canary));
    assert!(
        rendered.contains(
            &canary
                .iter()
                .map(u8::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        "zeroize is expected to derive Debug for Zeroizing by printing the wrapped \
         value; if this no longer holds, revisit any hand-written impl in this \
         crate that holds a Zeroizing: {rendered}"
    );
}

/// An SSH password and a key passphrase never render, in either spelling.
///
/// Gated on the `ssh` feature because the types are, and an ungated reference
/// would make a default-features build of this suite fail to compile. The
/// credential surface is the only part of this file that is not unconditional.
///
/// This crate has leaked a credential three times and the redaction test above
/// is why it has not a fourth. An SSH secret is a **new** place for one to
/// appear, and the two obvious ways out of this crate's own reach are both
/// checked here: a `Debug` that renders the value, and a `Display` that renders
/// it. The second is the one a `Debug`-only redaction misses, and it is one
/// `{}` away from a log line — `tracing::info!("connecting as {}", secret)` is
/// ordinary-looking code, and an `SshSecret` that implements `Display` by
/// delegating to its inner `String` would be a leak nobody would notice.
///
/// The canary is searched in all three forms this file's helpers know, plus the
/// base64 encoding above, because a base64 secret is still a secret.
#[cfg(all(feature = "ssh", unix))]
#[test]
fn an_ssh_secret_renders_as_a_redaction_and_nothing_else() {
    const CANARY: &str = "canary-ssh-password-9e4c07b2-do-not-log-me";
    let secret = neotales_docker::SshSecret::new(CANARY);

    for (label, rendered) in [
        ("Debug", format!("{secret:?}")),
        ("Display", format!("{secret}")),
    ] {
        assert_no_secret(&rendered, CANARY);
        let mut forms = vec![CANARY.to_owned()];
        forms.extend(base64_forms(CANARY.as_bytes()));
        for form in forms {
            assert!(
                !rendered.contains(&form),
                "an SshSecret {label} leaked a secret as {form:?}: {rendered}"
            );
        }
        // The redaction has to be *visible*. A `Debug` that printed nothing at
        // all would pass every check above, and a reader would have no way to
        // tell "redacted" from "this type has no Debug".
        assert!(
            rendered.contains("[REDACTED]"),
            "the SshSecret {label} redaction must be visible rather than an omission: \
             {rendered}"
        );
    }
}

/// The secret is the caller's to read back, and this is the only way out.
///
/// The point is the negative space: there is no `Deref<Target = str>`, no
/// `AsRef<str>`, and no `Display` that delegates, so the value cannot reach a
/// format argument through an ordinary-looking trait. `expose` is a method a
/// reader has to look up. The test cannot compile-fail on a *new* such impl —
/// nothing stops one being added later — so it asserts the two that exist work,
/// and the absence is argued in the type's own documentation. What it can do is
/// fail if `expose` stops being the value, which is what a careless refactor
/// toward a lazily-decoded secret would do.
#[cfg(all(feature = "ssh", unix))]
#[test]
fn an_ssh_secret_is_readable_only_by_expose() {
    const CANARY: &str = "canary-ssh-expose-31a8d5c6-do-not-log-me";
    let secret = neotales_docker::SshSecret::new(CANARY);
    assert_eq!(secret.expose(), CANARY);
}

/// An `SshIdentity` names its mechanism and never its value.
///
/// The passphrase is a *variant field* on a public enum, so a `#[derive(Debug)]`
/// on `SshIdentity` would compile and leak. That it is hand-written is asserted
/// by the canary, and so is that the redaction survives being printed through a
/// `Debug`-only path such as `{:?}` on a borrowed value.
#[cfg(all(feature = "ssh", unix))]
#[test]
fn an_ssh_identity_debug_names_the_mechanism_and_not_the_passphrase() {
    const CANARY: &str = "canary-ssh-identity-passphrase-5d7e2a94-do-not-log-me";
    let identity = neotales_docker::SshIdentity::EncryptedKeyFile {
        path: "/keys/id_ed25519".into(),
        passphrase: neotales_docker::SshSecret::new(CANARY),
    };

    let rendered = format!("{identity:?}");
    assert_no_secret(&rendered, CANARY);
    assert!(
        rendered.contains("EncryptedKeyFile"),
        "the mechanism is what a failed authentication has to say: {rendered}"
    );

    // A password credential carries no key path, so nothing about the enum's
    // `Debug` may print one.
    let password = neotales_docker::SshIdentity::Password(neotales_docker::SshSecret::new(
        "canary-ssh-identity-password-88ba01f7-do-not-log-me",
    ));
    let rendered = format!("{password:?}");
    assert_no_secret(
        &rendered,
        "canary-ssh-identity-password-88ba01f7-do-not-log-me",
    );
    assert!(
        rendered.contains("Password"),
        "the mechanism is what a failed authentication has to say: {rendered}"
    );
}

/// `LogDecoder` is `pub`, re-exported from `raw`, and its `partial` and `ready`
/// fields hold the container's own stdout: one mid-frame, one whole frames the
/// caller has not been handed yet.
///
/// Unlike `LogFrames`, this is the buffer with no other door. A caller holding a
/// `LogFrames` can drain the payload through `next_frame`; a caller holding a
/// `LogDecoder` is holding the decoder itself, and the bytes are reachable
/// through nothing but `Debug`. The type a caller is *more* likely to hold is
/// therefore the one whose redaction has to be its own.
///
/// Driven through the public constructor rather than through a socket, because
/// the guarantee is about what the type renders and a socket would only add a
/// way for the fixture to be wrong. The state chosen is the one a derive gets
/// wrong on its own: a whole header has arrived, so `stream` and `expected` are
/// set, and the payload has partly arrived, so `partial` holds real bytes that
/// no frame has been built from yet.
#[test]
fn a_log_decoder_prints_no_partly_arrived_frame() {
    let mut decoder = neotales_docker::raw::LogDecoder::new(false);
    // A complete header promising 4096 bytes, then a fraction of them. The
    // decoder cannot yet make a frame, so it is holding the payload.
    decoder
        .push(&header(1, 4096))
        .expect("the header is valid framing");
    decoder
        .push(CANARY.as_bytes())
        .expect("a partial payload cannot be rejected");

    let rendered = format!("{decoder:?}");
    assert_no_secret(&rendered, CANARY);

    // The useful fields must survive, or this test would also pass against a
    // `Debug` that printed nothing. `stream` and `expected` are what a reader
    // diagnosing a stalled log cannot get any other way: `expected` is the
    // payload length the header promised, which is what distinguishes
    // "mid-payload" from "mid-header", and `stream` is what says which of the
    // container's two outputs is not arriving.
    assert!(rendered.contains("stream: Stdout"), "{rendered}");
    assert!(rendered.contains("expected: Some(4096)"), "{rendered}");
    assert!(rendered.contains("tty: false"), "{rendered}");
    // The header's eight bytes plus the payload delivered so far.
    assert!(
        rendered.contains(&format!("buffered: {}", 8 + CANARY.len())),
        "{rendered}"
    );
}

/// The same guarantee for the decoder's other shape: a TTY body, whose `partial`
/// field holds unframed console output — whatever the container's program wrote,
/// including whatever a user typed into it.
///
/// The two shapes reach `partial` through different code, so a redaction applied
/// to only one of them would leave the other printing raw terminal output. The
/// TTY path in `decode` takes the buffer with `mem::take` rather than draining a
/// frame out of it, so it is worth asserting separately.
///
/// What this test proves, stated exactly: after `push`, the TTY buffer is
/// **empty**, because `decode` took all of it on its first call and the payload
/// left in a `LogFrame` the caller was handed.
///
/// An earlier draft of this test also claimed that a future `push` that stopped
/// looping would be caught here, and that claim was wrong. It cannot be: for a
/// TTY body `decode` drains the whole buffer in one call, so the loop in `push`
/// never iterates a second time and removing it would change nothing observable.
/// A single `push` therefore cannot distinguish the two implementations, and
/// asserting otherwise would have left a guard that looks load-bearing and is not.
///
/// What *is* load-bearing is the `decode` path this pins: if the TTY branch ever
/// stopped taking the whole buffer — grew a frame size, or buffered ahead — the
/// bytes would stay resident and this assertion fails. That is the change that
/// would turn a TTY `Debug` from `buffered: 0` into a rendering of console
/// output, so it is the one worth a test.
#[test]
fn a_tty_log_decoder_holds_no_console_output() {
    let mut decoder = neotales_docker::raw::LogDecoder::new(true);
    let frames = decoder
        .push(CANARY.as_bytes())
        .expect("an unframed body cannot be rejected");

    // The bytes really did arrive, and really are gone from the buffer: they
    // came back as a frame rather than being retained.
    assert_eq!(frames.len(), 1, "the console write is one frame");
    assert_eq!(frames[0].payload, CANARY.as_bytes());
    let rendered = format!("{decoder:?}");
    assert_no_secret(&rendered, CANARY);
    assert!(
        rendered.contains("buffered: 0"),
        "a TTY decoder takes its whole buffer on decode, so it retains nothing: \
         {rendered}"
    );
    // And the framing is still reported, because a reader diagnosing a stalled
    // TTY log has to be able to tell the two framings apart.
    assert!(rendered.contains("tty: true"), "{rendered}");
    assert!(rendered.contains("stream: Console"), "{rendered}");
}

/// The public `payload` field is untouched by the redaction: a caller that wants
/// the bytes still gets them, and the two frame types still compare by them.
///
/// The redaction is a property of `Debug`, not of the API, and this is what
/// holds that line. Without it, "make the payload not render" and "stop giving
/// callers the payload" are the same edit, and a future maintainer under pressure
/// to fix a log line would not notice the difference.
#[test]
fn a_redacted_frame_still_gives_its_caller_the_payload() {
    let frame = neotales_docker::raw::LogFrame::new(
        neotales_docker::raw::LogStream::Stdout,
        CANARY.as_bytes().to_vec(),
    );
    assert_eq!(frame.payload, CANARY.as_bytes(), "the field is unchanged");
    // Equality compares payloads, which is what makes two frames distinguishable
    // to a caller and is unaffected by the formatting.
    let same = neotales_docker::raw::LogFrame::new(
        neotales_docker::raw::LogStream::Stdout,
        CANARY.as_bytes().to_vec(),
    );
    let other = neotales_docker::raw::LogFrame::new(
        neotales_docker::raw::LogStream::Stderr,
        CANARY.as_bytes().to_vec(),
    );
    assert_eq!(frame, same);
    assert_ne!(frame, other);
    // Cloning a frame is a normal caller move and still carries the payload.
    assert_eq!(frame.clone().payload, CANARY.as_bytes());

    // And the same for the Bollard-backed spelling.
    let bollard = neotales_docker::ContainerLogFrame::new(
        neotales_docker::ContainerLogStream::Stdout,
        CANARY.as_bytes().to_vec(),
    );
    assert_eq!(bollard.payload, CANARY.as_bytes());
    assert_eq!(bollard.clone().payload, CANARY.as_bytes());
}

/// A `LogFrame` names its stream and counts its payload; it never renders either
/// the payload or a frame that arrives with the header still attached.
///
/// Checked in all three forms `assert_no_bytes` knows, because a derived impl
/// prints a `Vec<u8>` as a decimal list — the form a text-only search misses.
#[test]
fn a_log_frame_prints_its_stream_and_a_payload_count() {
    let frame = neotales_docker::raw::LogFrame::new(
        neotales_docker::raw::LogStream::Stdout,
        CANARY.as_bytes().to_vec(),
    );
    let rendered = format!("{frame:?}");
    assert_no_secret(&rendered, CANARY);
    assert!(rendered.contains("stream: Stdout"), "{rendered}");
    assert!(
        rendered.contains(&format!("payload_bytes: {}", CANARY.len())),
        "the length is the diagnostic a caller actually wants: {rendered}"
    );

    // The Bollard-backed spelling is the same shape and is checked rather than
    // assumed, because leaving one of the two derived would mean the same bytes
    // printed on one transport and not the other.
    let bollard = neotales_docker::ContainerLogFrame::new(
        neotales_docker::ContainerLogStream::Stderr,
        CANARY.as_bytes().to_vec(),
    );
    let rendered = format!("{bollard:?}");
    assert_no_secret(&rendered, CANARY);
    assert!(rendered.contains("stream: Stderr"), "{rendered}");
    assert!(
        rendered.contains(&format!("payload_bytes: {}", CANARY.len())),
        "{rendered}"
    );
}

/// A `LogDecoder` built for a TTY still has to render safely while it is
/// *empty*, because an empty buffer is what a caller prints when a log stream
/// has produced nothing and the stream itself is what has stalled.
///
/// A redaction that only fired once bytes arrived would be useless in the one
/// case where a caller is most likely to reach for `Debug` on a decoder: the
/// one where nothing has happened yet.
#[test]
fn an_empty_log_decoder_says_it_is_empty() {
    let rendered = format!("{:?}", neotales_docker::raw::LogDecoder::new(false));
    assert_no_secret(&rendered, CANARY);
    assert!(rendered.contains("buffered: 0"), "{rendered}");
    // `expected` is `None` while the next bytes are a header rather than a
    // payload, which is the distinction the field exists to make.
    assert!(rendered.contains("expected: None"), "{rendered}");
}

/// `SwarmInfo` holds the worker and manager join tokens, which are credentials,
/// and the crate already redacts the two credentials beside it in the same file
/// (`SwarmCertificates::key`, `SwarmUnlockKey::key`).
///
/// `join_tokens` is a `serde_json::Value`, so a derived `Debug` prints it in
/// full and both tokens land in every panic message and log line that mentions a
/// `SwarmInfo`. A manager node's token is passed to `docker swarm join --token`,
/// so a printed `SwarmInfo` is a printed invitation to join somebody else's
/// Swarm.
///
/// Checked in all three renderings `assert_no_bytes` knows, plus the base64
/// form, because a token is a long high-entropy string that survives
/// re-encoding unchanged.
#[test]
fn a_swarm_info_prints_no_join_token() {
    let document = format!(
        r#"{{"ID":"swarm-canary","Version":{{"Index":42}},"Spec":{{"Name":"canary"}},"JoinTokens":{{"Worker":"{SWARM_TOKEN}","Manager":"{SWARM_MANAGER_TOKEN}"}}}}"#
    );
    let info: neotales_docker::SwarmInfo =
        serde_json::from_str(&document).expect("the fixture is a Swarm document");

    let rendered = format!("{info:?}");
    for token in [SWARM_TOKEN, SWARM_MANAGER_TOKEN] {
        assert_no_secret(&rendered, token);
        for form in std::iter::once(token.to_owned()).chain(base64_forms(token.as_bytes())) {
            assert!(
                !rendered.contains(&form),
                "a SwarmInfo Debug leaked a join token as {form:?}: {rendered}"
            );
        }
    }

    // The redaction has to be visible rather than an omission: "the daemon sent
    // no tokens" and "the tokens were withheld" are different facts about a
    // node, and a reader cannot tell them apart from an absent field.
    assert!(rendered.contains("<redacted>"), "{rendered}");
    // And the fields a caller reads a `SwarmInfo` for have to survive.
    assert!(rendered.contains("swarm-canary"), "{rendered}");
    assert!(rendered.contains("index: Some(42)"), "{rendered}");
}

/// A `SwarmInfo` with no join tokens — what a worker node reports — must say so
/// rather than render nothing, or the redaction above cannot be told apart from
/// an implementation that dropped the field.
#[test]
fn a_swarm_info_without_tokens_says_none_were_reported() {
    let info: neotales_docker::SwarmInfo =
        serde_json::from_str(r#"{"ID":"swarm-canary","Version":{"Index":7}}"#)
            .expect("the fixture is a Swarm document");
    let rendered = format!("{info:?}");
    assert!(rendered.contains("join_tokens: None"), "{rendered}");
    assert!(rendered.contains("index: Some(7)"), "{rendered}");
}

/// The named-field redaction is **not** sufficient, and this is the bypass.
///
/// `SwarmInfo.join_tokens` is the Engine's own top-level spelling. swarmkit
/// reports the same cluster state as a nested `ClusterInfo` object, which this
/// crate does not name as a field — so it lands in the `#[serde(flatten)]`
/// catch-all `additional`, carrying a *second* pair of join tokens. A `Debug`
/// that redacts `join_tokens` and renders `additional` in full therefore leaks
/// the credential through the field that exists precisely to hold the members
/// nobody modelled.
///
/// This is not a contrived shape: `SwarmInfo::trust_root` in this crate already
/// looks for `ClusterInfo` in `additional` for exactly the dual-spelling reason,
/// so the crate knows the nesting exists and reads it. Reading it and printing it
/// were both the same decision.
///
/// The second canary is the general form of the same hole: `additional` accepts
/// arbitrary daemon JSON at any depth, so there is no field list that could make
/// rendering it safe. Both are searched for in all three renderings plus base64.
#[test]
fn a_swarm_info_redaction_is_not_bypassed_by_the_flattened_catch_all() {
    const NESTED: &str = "canary-swarm-clusterinfo-token-71fa3c08-do-not-log-me";
    const ARBITRARY: &str = "canary-swarm-unmodelled-member-e2b84516-do-not-log-me";
    let document = format!(
        r#"{{"ID":"swarm-canary","Version":{{"Index":42}},"ClusterInfo":{{"ID":"cluster-1","JoinTokens":{{"Worker":"{NESTED}","Manager":"{NESTED}-mgr"}}}},"SomeUnmodelledMember":{{"Nested":{{"Credential":"{ARBITRARY}"}}}}}}"#
    );
    let info: neotales_docker::SwarmInfo =
        serde_json::from_str(&document).expect("the fixture is a Swarm document");

    // The tokens really are present in the value, on both paths, so the
    // assertions below are about a payload that arrived rather than one that
    // never existed.
    assert!(
        info.additional.contains_key("ClusterInfo"),
        "the fixture's nested spelling must survive as an unmodelled member"
    );
    let nested = serde_json::to_string(info.additional.get("ClusterInfo").expect("ClusterInfo"))
        .expect("a JSON value serialises");
    assert!(nested.contains(NESTED), "the fixture carried the token");

    let rendered = format!("{info:?}");
    for canary in [NESTED, ARBITRARY] {
        assert_no_secret(&rendered, canary);
        for form in std::iter::once(canary.to_owned()).chain(base64_forms(canary.as_bytes())) {
            assert!(
                !rendered.contains(&form),
                "a SwarmInfo Debug leaked {canary:?} through the flattened catch-all \
                 as {form:?}: {rendered}"
            );
        }
    }

    // The catch-all is reported as a count, so a reader still learns that
    // unmodelled state arrived — which is the question worth answering, and the
    // reason the field exists.
    assert!(
        rendered.contains("additional: 2 unmodeled member(s)"),
        "the count is the whole diagnostic: {rendered}"
    );
    // Key *names* are withheld too, and that is a deliberate choice rather than
    // an oversight: a key name is daemon-chosen, so printing one is printing
    // daemon-controlled text into a log line.
    for name in [
        "ClusterInfo",
        "SomeUnmodelledMember",
        "Nested",
        "Credential",
    ] {
        assert!(
            !rendered.contains(name),
            "a daemon-chosen key name must not be rendered either: {name} in {rendered}"
        );
    }
}

/// The same catch-all, one level down, on the type an update carries.
///
/// `SwarmUpdateOptions` keeps its derive and needs no redaction of its own: it
/// renders its `spec` through `SwarmSpec`'s hand-written impl, so a
/// `#[serde(flatten)]` map of unmodelled daemon JSON cannot reach a panic
/// message about an update. The test exists because that inheritance is silent —
/// nothing in `SwarmUpdateOptions` says its payload is redacted, so the only way
/// to know is to check.
#[test]
fn a_swarm_update_cannot_inherit_unmodelled_values_through_its_spec() {
    const ARBITRARY: &str = "canary-swarm-update-spec-5d31b6f4-do-not-log-me";
    let spec: neotales_docker::SwarmSpec = serde_json::from_str(&format!(
        r#"{{"Name":"canary-swarm","Unmodelled":"{ARBITRARY}"}}"#
    ))
    .expect("the fixture is a Swarm specification");

    let rendered = format!("{spec:?}");
    assert_no_secret(&rendered, ARBITRARY);
    assert!(
        rendered.contains("canary-swarm"),
        "the name survives: {rendered}"
    );
    assert!(
        rendered.contains("additional: 1 unmodeled member(s)"),
        "{rendered}"
    );

    // And through the type that holds it. `SwarmUpdateOptions` is derived, so
    // this passes through `SwarmSpec::fmt` — which is the whole point.
    let options = neotales_docker::SwarmUpdateOptions {
        version: 42,
        spec,
        rotate_worker_token: false,
        rotate_manager_token: false,
        rotate_manager_unlock_key: false,
    };
    let rendered = format!("{options:?}");
    assert_no_secret(&rendered, ARBITRARY);
    // The fields a caller reads an update for survive.
    assert!(rendered.contains("version: 42"), "{rendered}");
    assert!(rendered.contains("canary-swarm"), "{rendered}");
    assert!(
        rendered.contains("additional: 1 unmodeled member(s)"),
        "{rendered}"
    );
}

/// The join token a caller supplies to join a Swarm is the same credential
/// [`SwarmInfo`] refuses to render on the way out, and this crate documents it
/// as one: "the token is a credential".
///
/// A derived `Debug` printed it in full. The addresses survive, because they are
/// what a reader diagnosing a failed join needs and they are not secret.
#[test]
fn a_swarm_join_options_prints_its_addresses_and_not_its_token() {
    let options = neotales_docker::SwarmJoinOptions {
        token: SWARM_TOKEN.to_owned(),
        remote_addresses: vec!["10.0.0.1:2377".to_owned()],
        listen_address: Some("0.0.0.0:2377".to_owned()),
        advertise_address: Some("10.0.0.2:2377".to_owned()),
        data_path_address: Some("10.0.0.2:4789".to_owned()),
    };

    let rendered = format!("{options:?}");
    assert_no_secret(&rendered, SWARM_TOKEN);
    for form in std::iter::once(SWARM_TOKEN.to_owned()).chain(base64_forms(SWARM_TOKEN.as_bytes()))
    {
        assert!(
            !rendered.contains(&form),
            "a SwarmJoinOptions Debug leaked a join token as {form:?}: {rendered}"
        );
    }

    // Every non-secret field survives, because a redaction that took the
    // addresses with it would have removed the reason to log this at all.
    assert!(rendered.contains("10.0.0.1:2377"), "{rendered}");
    assert!(rendered.contains("0.0.0.0:2377"), "{rendered}");
    assert!(rendered.contains("10.0.0.2:2377"), "{rendered}");
    assert!(rendered.contains("10.0.0.2:4789"), "{rendered}");
    // The redaction is visible, so "no token" is distinguishable from "withheld".
    assert!(rendered.contains("<redacted>"), "{rendered}");
}

/// The manager unlock key on the way *in*, which the crate redacts on the way out.
///
/// [`SwarmUnlockKey`] refuses to render the key it reads back from the daemon. A
/// derived `Debug` on this input type printed it, which protected the credential
/// on one side of the operation and published it on the other.
#[test]
fn a_swarm_unlock_options_prints_no_unlock_key() {
    const KEY: &str = "canary-swarm-unlock-key-9ac60d35-do-not-log-me";
    let rendered = format!(
        "{:?}",
        neotales_docker::SwarmUnlockOptions {
            key: KEY.to_owned(),
        }
    );
    assert_no_secret(&rendered, KEY);
    for form in std::iter::once(KEY.to_owned()).chain(base64_forms(KEY.as_bytes())) {
        assert!(
            !rendered.contains(&form),
            "a SwarmUnlockOptions Debug leaked an unlock key as {form:?}: {rendered}"
        );
    }
    assert!(rendered.contains("<redacted>"), "{rendered}");
}

/// An empty credential renders as absent rather than as `<redacted>`.
///
/// The distinction is worth a test because getting it backwards is a real
/// misreading: a rendering that showed `<redacted>` for a field holding nothing
/// teaches a reader that the marker is decoration, and then stops looking at it
/// on the fields where it matters. A `SwarmJoinOptions` built by `Default` has
/// no token, and that is an ordinary state worth reading correctly.
#[test]
fn an_empty_swarm_credential_renders_as_absent_not_as_redacted() {
    let rendered = format!("{:?}", neotales_docker::SwarmJoinOptions::default());
    assert!(rendered.contains("token: None"), "{rendered}");
    assert!(
        !rendered.contains("<redacted>"),
        "there is no credential to redact, so claiming one misleads: {rendered}"
    );

    let rendered = format!(
        "{:?}",
        neotales_docker::SwarmUnlockOptions { key: String::new() }
    );
    assert!(rendered.contains("key: None"), "{rendered}");
    assert!(!rendered.contains("<redacted>"), "{rendered}");
}

/// `LogDecoder` and `SwarmInfo` were the two shapes the earlier mirrors could
/// not reach, because both are redactions of a **private field** inside a type
/// whose *other* fields are safe to print.
///
/// A derive renders the private field exactly as it renders the safe ones, so
/// each mirror carries both: the canary in the field that must be withheld, and
/// a realistic value in a field that must survive. That second half is what
/// makes these mirrors worth having over the ones above — it is the shape a
/// maintainer would write when adding a new private field, and the earlier
/// mirrors, whose every field was a payload, would not prepare them for it.
#[derive(Debug)]
#[allow(
    dead_code,
    reason = "the derived Debug is the only reader, and it is the subject"
)]
struct DerivedLogDecoderWithSafeFields {
    stream: neotales_docker::raw::LogStream,
    expected: Option<u32>,
    tty: bool,
    pending: Vec<u8>,
}

/// Mirrors `raw::swarm::SwarmInfo`, whose `join_tokens` is a `serde_json::Value`
/// that renders in full.
#[derive(Debug)]
#[allow(
    dead_code,
    reason = "the derived Debug is the only reader, and it is the subject"
)]
struct DerivedSwarmInfo {
    id: Option<String>,
    join_tokens: Option<serde_json::Value>,
}

/// Mirrors the *bypass* shape: a `SwarmInfo` whose named `join_tokens` is empty
/// and whose flattened `additional` holds the same credential under swarmkit's
/// `ClusterInfo` spelling.
///
/// This is the mirror that matters most in the file. A guard that only searched
/// the named field would pass while the credential rendered, and the negative
/// control has to reproduce that exact false green to prove it is not one.
#[derive(Debug)]
#[allow(
    dead_code,
    reason = "the derived Debug is the only reader, and it is the subject"
)]
struct DerivedSwarmInfoWithCatchAll {
    id: Option<String>,
    join_tokens: Option<serde_json::Value>,
    additional: std::collections::BTreeMap<String, serde_json::Value>,
}

/// Mirrors `raw::swarm::SwarmJoinOptions`, whose `token` is a credential.
#[derive(Debug)]
#[allow(
    dead_code,
    reason = "the derived Debug is the only reader, and it is the subject"
)]
struct DerivedSwarmJoinOptions {
    token: String,
    remote_addresses: Vec<String>,
}

/// Mirrors `raw::logs::LogFrame`, whose `payload` is container stdout.
#[derive(Debug)]
#[allow(
    dead_code,
    reason = "the derived Debug is the only reader, and it is the subject"
)]
struct DerivedFrameWithPayload {
    stream: neotales_docker::raw::LogStream,
    payload: Vec<u8>,
}

/// Asserts the mirrors above leak, so the hand-written impls on the real types
/// are load-bearing rather than decorative.
#[test]
fn a_derive_would_have_rendered_the_private_fields_too() {
    assert_derived_shape_leaks(
        "LogDecoder",
        CANARY,
        DerivedLogDecoderWithSafeFields {
            stream: neotales_docker::raw::LogStream::Stdout,
            expected: Some(4096),
            tty: false,
            pending: CANARY.as_bytes().to_vec(),
        },
    );
    assert_derived_shape_leaks(
        "SwarmInfo",
        SWARM_TOKEN,
        DerivedSwarmInfo {
            id: Some("swarm-canary".to_owned()),
            join_tokens: Some(serde_json::json!({
                "Worker": SWARM_TOKEN,
            })),
        },
    );
    // The same type with the named field empty and the credential one level
    // down, which is what a guard that only searched `join_tokens` would miss.
    assert_derived_shape_leaks(
        "SwarmInfo with a flattened catch-all",
        SWARM_TOKEN,
        DerivedSwarmInfoWithCatchAll {
            id: Some("swarm-canary".to_owned()),
            join_tokens: None,
            additional: std::collections::BTreeMap::from([(
                "ClusterInfo".to_owned(),
                serde_json::json!({ "JoinTokens": { "Worker": SWARM_TOKEN } }),
            )]),
        },
    );
    assert_derived_shape_leaks(
        "SwarmJoinOptions",
        SWARM_TOKEN,
        DerivedSwarmJoinOptions {
            token: SWARM_TOKEN.to_owned(),
            remote_addresses: vec!["10.0.0.1:2377".to_owned()],
        },
    );
    // The frame mirrors, one per frame type, because they are two independent
    // impls and a guard that only reached one would say nothing about the other.
    assert_derived_shape_leaks(
        "LogFrame",
        CANARY,
        DerivedFrameWithPayload {
            stream: neotales_docker::raw::LogStream::Stdout,
            payload: CANARY.as_bytes().to_vec(),
        },
    );
}

/// # The container inspect document
///
/// The tests above redactions of *named* fields. This one is a different shape
/// and a harder one, because `raw::ContainerInspect` does not hold a document
/// **member** — it holds the whole document, on purpose, because decoding into a
/// struct would drop the members the daemon sent (the module's own measurement:
/// a generated model loses `ExecIDs`, which arrives as `null`).
///
/// So the exposure is total rather than per-field, and it is the largest thing
/// this crate retains: twenty-four top-level members against Docker Engine
/// 29.8.0. `Config.Env` is the one that matters in practice, because a container
/// is handed its credentials with `-e` — a database URL, an API token, a signing
/// key — and the whole reason a caller holds a `ContainerInspect` at all is
/// that something went wrong, which is the moment `{:?}` is reached for.
const INSPECT_ENV: &str = "canary-inspect-env-4e8a1c37-do-not-log-me";

/// A label value, which lands in `Config.Labels` rather than `Config.Env`.
///
/// Named separately so the test can tell "the environment is withheld" from
/// "every caller-supplied string in the document is withheld". They are the same
/// guarantee, but a guard that only searched `Env` would be one rename away from
/// failing on the next member the daemon adds.
const INSPECT_LABEL: &str = "canary-inspect-label-6b2d8e50-do-not-log-me";

/// A bind mount source, in `HostConfig.Binds`.
///
/// The document's third credential shape. It is at a different depth from `Env`
/// and reaches the rendering by a different path, so a redaction written against
/// the one nesting would not touch it.
const INSPECT_BIND: &str = "canary-inspect-bind-9c7f1a24-do-not-log-me";

/// An argument, in the top-level `Args` array and again in `Config.Cmd`.
const INSPECT_ARG: &str = "canary-inspect-args-1f5b6d93-do-not-log-me";

/// The health check's own recorded output, in `State.Health.Log[].Output`.
///
/// Worth its own canary because it is a **daemon-recorded** string rather than a
/// caller-supplied one: it is whatever the check wrote, which for a check that
/// curls an endpoint or prints a connection string is a secret the operator
/// never put in a `-e` flag and never thought to protect.
const INSPECT_HEALTH: &str = "canary-inspect-health-output-7d0e3c68-do-not-log-me";

/// A `GraphDriver.Data` entry, which is an arbitrary daemon-chosen map.
///
/// The general form of the same hole, and the reason the fix is structural: a
/// catch-all at any depth accepts whatever the peer sent, so there is no field
/// list that could make rendering it safe.
const INSPECT_GRAPH: &str = "canary-inspect-graphdriver-2a9e4f81-do-not-log-me";

/// Every canary the inspect document carries, in one place.
///
/// The tests search for all of them rather than for `INSPECT_ENV` alone, so a
/// redaction that handled the environment and nothing else fails.
const INSPECT_CANARIES: [&str; 6] = [
    INSPECT_ENV,
    INSPECT_LABEL,
    INSPECT_BIND,
    INSPECT_ARG,
    INSPECT_HEALTH,
    INSPECT_GRAPH,
];

/// A `GET /containers/{id}/json` answer with a canary in every member that
/// carries caller-supplied or daemon-chosen text.
///
/// Shaped after a real Engine answer: the members the summary names are present
/// and realistic, and the rest is where a value a reader must not see would
/// actually arrive. The safe members matter as much as the canaries — a
/// redaction that rendered nothing would pass every search in the test below.
///
/// Built from the canary constants rather than written out with them inlined, so
/// the mirror at the end of this file is fed the *same* document the fixture
/// serves. A fixture that merely *looked* like the daemon's would let the two
/// drift apart, and a negative control checked against a drifted sample proves
/// nothing.
fn inspect_body() -> String {
    format!(
        r#"{{
    "Id":"38df04270233eb5551a444c5a1064b683a071e41eb77e43db8c34e84b6f51344",
    "Created":"2026-09-26T05:30:16.418592304Z",
    "Path":"sh",
    "Args":["-c","--token","{INSPECT_ARG}"],
    "State":{{
        "Status":"running","Running":true,"Paused":false,"Restarting":false,
        "OOMKilled":false,"Dead":false,"Pid":935123,"ExitCode":0,
        "StartedAt":"2026-09-26T05:30:16.418592304Z",
        "FinishedAt":"0001-01-01T00:00:00Z",
        "Health":{{"Status":"healthy","FailingStreak":0,"Log":[
            {{"Start":"2026-09-26T05:31:00.000000000Z","ExitCode":0,
             "Output":"{INSPECT_HEALTH}"}}]}}}},
    "Image":"sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc",
    "Name":"/rawprobe-tty",
    "Driver":"overlayfs","Platform":"linux",
    "GraphDriver":{{"Name":"overlayfs","Data":{{
        "MergedDir":"/var/lib/docker/overlay2/{INSPECT_GRAPH}/merged"}}}},
    "HostConfig":{{"NetworkMode":"default","LogConfig":{{"Type":"json-file"}},
        "Binds":["/srv/{INSPECT_BIND}:/data:ro"]}},
    "Config":{{"Hostname":"38df04270233","Tty":true,"OpenStdin":true,
        "Env":["PATH=/usr/bin","DATABASE_URL=postgres://user:{INSPECT_ENV}@db/web",
               "SIGNING_KEY={INSPECT_ENV}"],
        "Cmd":["sh","-c","--token","{INSPECT_ARG}"],
        "Image":"alpine:3.20","Labels":{{
            "com.example.note":"{INSPECT_LABEL}"}}}},
    "NetworkSettings":{{"Ports":{{"80/tcp":[{{"HostIp":"0.0.0.0","HostPort":"18080"}}]}},
        "Networks":{{"bridge":{{"IPAddress":"172.17.0.2"}}}}}}
}}"#
    )
}

/// Builds a `200` carrying `body` as a JSON document.
///
/// Separate from the multiplexed fixture the log tests use: an inspect answer is
/// an ordinary buffered JSON body, and reusing the streaming fixture here would
/// be a way for the two suites' helpers to drift apart.
fn json_response(status: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status} OK\r\nApi-Version: 1.53\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// Reads a container's inspect document from a fixture serving `body`.
///
/// The public constructor of a `ContainerInspect` is the request, so this goes
/// through `raw::inspect` over a loopback socket rather than constructing a
/// value: `document` is private, and a test that could build one in-crate would
/// not be testing the surface a caller has. The fixture is released only when
/// the caller drops the handle, so the connection is still live while the
/// assertions run.
async fn inspect_from(
    body: &str,
) -> (
    neotales_docker::raw::ContainerInspect,
    neotales_docker::raw::RawEngine,
    std::thread::JoinHandle<()>,
    std::sync::mpsc::Sender<()>,
) {
    let (address, server, release) = serve_once(json_response("200", body));
    let engine = engine_at(address);
    let inspect = neotales_docker::raw::inspect(&engine, "rawprobe-tty")
        .await
        .expect("the fixture answers 200 with a document");
    (inspect, engine, server, release)
}

/// `ContainerInspect` must not render a single member of the document it
/// retains, and the answer must still be worth logging.
///
/// Driven through `raw::inspect` over a real socket, because the guarantee is
/// about a value a caller can actually obtain — and because a fixture is the
/// only way to build one from outside the crate, so this also proves the
/// redaction is reachable rather than theoretical.
///
/// The canary is in all six places a document carries text a reader must not
/// see, and they are searched for in every form `assert_no_bytes` knows plus
/// base64, because a base64 encoding of a secret is not a redaction.
///
/// The other half of the test is the part that makes the first half worth
/// having: a `Debug` that printed nothing would pass every search above. So the
/// four identity members and the three counts are required to be present, and
/// `..` is required to be there for a member added later.
#[tokio::test]
async fn a_container_inspect_prints_its_identity_and_not_its_document() {
    let (inspect, engine, server, release) = inspect_from(&inspect_body()).await;

    // The canaries really are in the value, so the assertions below are about a
    // payload that arrived rather than one that never existed.
    let document = inspect.document();
    for canary in INSPECT_CANARIES {
        let found = serde_json::to_string(document)
            .expect("a document serialises")
            .contains(canary);
        assert!(found, "the fixture did not carry {canary:?}");
    }

    let rendered = format!("{inspect:?}");
    // The allowlist first, because it is the check that keeps the canary checks
    // meaningful: a field the canaries never thought of is exactly the addition
    // a canary search cannot see.
    assert_fields(
        &rendered,
        &[
            "id",
            "name",
            "image",
            "state",
            "health",
            "running",
            "paused",
            "tty",
            "exit_code",
            "pid",
            "env_vars",
            "ports",
            "members",
        ],
    );
    for canary in INSPECT_CANARIES {
        assert_no_secret(&rendered, canary);
        for form in std::iter::once(canary.to_owned()).chain(base64_forms(canary.as_bytes())) {
            assert!(
                !rendered.contains(&form),
                "a ContainerInspect Debug leaked {canary:?} as {form:?}: {rendered}"
            );
        }
    }
    // The specific shape the issue is about, named so a failure says which
    // member leaked rather than only that one of six did.
    assert!(!rendered.contains("DATABASE_URL"), "{rendered}");
    assert!(!rendered.contains("SIGNING_KEY"), "{rendered}");
    // `Config.Image` is withheld even though the image *id* survives: they are
    // two members of the document and the summary names only one.
    assert!(!rendered.contains("alpine:3.20"), "{rendered}");

    // What a caller reads an inspect answer for.
    assert!(
        rendered.contains("id: Some(\"38df04270233eb5551a444c5a1064b683"),
        "{rendered}"
    );
    assert!(
        rendered.contains("name: Some(\"/rawprobe-tty\")"),
        "{rendered}"
    );
    assert!(rendered.contains("state: Some(\"running\")"), "{rendered}");
    assert!(rendered.contains("health: Some(\"healthy\")"), "{rendered}");
    assert!(rendered.contains("running: Some(true)"), "{rendered}");
    assert!(rendered.contains("paused: Some(false)"), "{rendered}");
    assert!(rendered.contains("tty: Some(true)"), "{rendered}");
    assert!(rendered.contains("exit_code: Some(0)"), "{rendered}");
    assert!(rendered.contains("pid: Some(935123)"), "{rendered}");

    // The counts stand in for what was withheld, so a reader can tell three
    // environment variables from a container that was given none — which is the
    // question a "the image cannot see its config" report is actually asking.
    assert!(rendered.contains("env_vars: Some(3)"), "{rendered}");
    assert!(rendered.contains("ports: Some(1)"), "{rendered}");
    assert!(rendered.contains("members: Some(13)"), "{rendered}");
    // And the door left open for a member added later.
    assert!(rendered.contains(".."), "{rendered}");

    drop(inspect);
    drop(engine);
    drop(release);
    server.join().expect("the fixture thread finished");
}

/// A container the daemon gave no environment to must say so, or
/// `env_vars: Some(3)` reads as decoration and a reader stops trusting it.
///
/// The distinction is the same one the Swarm credential tests make, and getting
/// it backwards is a real misreading rather than a stylistic one: a rendering
/// that showed a count for a member that was never sent tells a reader the
/// implementation looked somewhere it did not.
#[tokio::test]
async fn a_container_without_an_environment_says_none_were_reported() {
    let (inspect, engine, server, release) =
        inspect_from(r#"{"Id":"38df04270233","Name":"/rawprobe","State":{"Status":"exited","Running":false,"ExitCode":7}}"#)
            .await;

    let rendered = format!("{inspect:?}");
    assert_no_secret(&rendered, INSPECT_ENV);
    assert!(rendered.contains("env_vars: None"), "{rendered}");
    assert!(rendered.contains("ports: None"), "{rendered}");
    assert!(rendered.contains("members: Some(3)"), "{rendered}");
    // The state fields still read, so the summary is not merely a shape.
    assert!(rendered.contains("state: Some(\"exited\")"), "{rendered}");
    assert!(rendered.contains("exit_code: Some(7)"), "{rendered}");
    assert!(rendered.contains("health: None"), "{rendered}");

    drop(inspect);
    drop(engine);
    drop(release);
    server.join().expect("the fixture thread finished");
}

/// The redaction is a property of `Debug` and not of the API, so `Clone`,
/// `PartialEq` and the explicit document accessors are all exactly as they were.
///
/// Without this, "make the payload not render" and "stop giving callers the
/// document" are the same edit, and a maintainer under pressure to fix a log
/// line would not notice the difference. This is the test that would notice.
#[tokio::test]
async fn a_redacted_inspect_still_gives_its_caller_the_whole_document() {
    let (inspect, engine, server, release) = inspect_from(&inspect_body()).await;

    // The borrowed accessor hands back the document untouched, canary and all.
    let borrowed: &serde_json::Value = inspect.document();
    assert!(
        borrowed.pointer("/Config/Env/1").is_some_and(|value| {
            value
                .as_str()
                .is_some_and(|entry| entry.contains(INSPECT_ENV))
        }),
        "Config.Env must still be readable in full"
    );
    // And so must the consuming one.
    let owned = inspect.clone().into_document();
    assert_eq!(owned, *borrowed, "into_document and document agree");
    assert!(
        serde_json::to_string(&owned)
            .expect("a document serialises")
            .contains(INSPECT_GRAPH)
    );

    // Clone and PartialEq are a caller's ordinary moves, and equality still
    // compares the document — a redaction that changed what "the same answer"
    // means would be a much worse defect than a leak.
    assert_eq!(inspect, inspect.clone());
    // A second fixture, because `serve_once` accepts one connection and the
    // point is to compare two *different* answers rather than ask the same one
    // twice. A document differing only in a member the summary does not name is
    // the interesting case: a redaction that leaked into equality would make
    // two answers the same when the daemon did not.
    let (other, other_engine, other_server, other_release) = inspect_from(
        r#"{"Id":"38df04270233eb5551a444c5a1064b683a071e41eb77e43db8c34e84b6f51344","Name":"/other","State":{"Status":"exited","Running":false,"ExitCode":1}}"#,
    )
    .await;
    assert_ne!(inspect, other);
    // And a redaction did not make equality a function of the summary: the two
    // render differently *because* they are different answers.
    assert_ne!(format!("{inspect:?}"), format!("{other:?}"));

    // And the typed accessors are untouched by any of it.
    assert_eq!(inspect.name(), Some("/rawprobe-tty"));
    assert_eq!(inspect.running(), Some(true));
    assert_eq!(inspect.health().as_deref(), Some("healthy"));
    assert_eq!(inspect.ports().len(), 1);

    drop(other);
    drop(other_engine);
    drop(other_release);
    other_server.join().expect("the second fixture finished");
    drop(engine);
    drop(release);
    server.join().expect("the fixture thread finished");
}

/// Mirrors `raw::ContainerInspect` with a **derived** `Debug` over the same
/// document the fixture above serves.
///
/// Fed the identical body, deliberately: a mirror built from a hand-written
/// sample can drift from what the daemon really sends, and a guard checked
/// against the drifted sample proves nothing about the real document. The only
/// difference between this and the real type is the `#[derive(Debug)]`, so a
/// failure here means the hand-written impl is load-bearing.
#[derive(Debug)]
#[allow(
    dead_code,
    reason = "the derived Debug is the only reader, and it is the subject"
)]
struct DerivedContainerInspect {
    document: serde_json::Value,
}

/// The negative control for the tests above, and the reason they are not
/// vacuous.
///
/// `assert_derived_shape_leaks` runs the *same* `assert_no_secret` the real
/// tests run, over a rendering of the *same* document, and requires it to fail.
/// Without this, a `Debug` that had been replaced by one printing the type name
/// alone would pass every test above, and so would a `Debug` that printed
/// nothing.
#[test]
fn a_derived_container_inspect_would_have_rendered_the_whole_document() {
    for canary in INSPECT_CANARIES {
        let document: serde_json::Value =
            serde_json::from_str(&inspect_body()).expect("the fixture is a document");
        assert_derived_shape_leaks(
            "ContainerInspect",
            canary,
            DerivedContainerInspect { document },
        );
    }

    // And the *general* form, which is the one a per-field redaction gets
    // wrong: the document is daemon-chosen at every depth, so the next member
    // the Engine adds is one more thing a field list cannot cover. This is the
    // shape `ContainerInspect` is — a `Value`, and nothing this crate chose.
    assert_derived_shape_leaks(
        "ContainerInspect holding a document this crate does not model",
        INSPECT_GRAPH,
        DerivedContainerInspect {
            document: serde_json::json!({
                "Id": "38df04270233",
                "SomeMemberFromANewerEngine": {
                    "Nested": { "Credential": INSPECT_GRAPH },
                },
            }),
        },
    );
}

/// The environment value an `ExecInspect` must never render, in the credential
/// shape a caller actually uses.
///
/// `AWS_SECRET_ACCESS_KEY` rather than a bare marker, because the shape is the
/// point: what leaks here is a value the caller put in a one-off
/// `docker exec --env` and then read back while working out why the command
/// printed nothing.
const EXEC_ENV: &str = "canary-exec-env-5b3e8a17-do-not-log-me";

/// An argument, in `ProcessConfig.arguments`.
///
/// The second credential shape in the same document. A command line carries
/// `--token` and `--password` as readily as an environment carries a key, so a
/// guard that searched only `env` would be one argument away from failing.
const EXEC_ARG: &str = "canary-exec-arguments-2f7c4d90-do-not-log-me";

/// The entrypoint, in `ProcessConfig.entrypoint`.
const EXEC_ENTRYPOINT: &str = "canary-exec-entrypoint-8a1d6b53-do-not-log-me";

/// A member this crate does not model, holding an arbitrary nested value.
///
/// The general form, and the reason the fix is structural rather than a field
/// list. `ProcessConfig` is a `serde_json::Value` on the way in and the daemon
/// is free to add to it, so the next member is one more thing a named-field
/// redaction cannot cover.
const EXEC_NESTED: &str = "canary-exec-unmodelled-c1d4e872-do-not-log-me";

/// Every canary the exec document carries.
const EXEC_CANARIES: [&str; 4] = [EXEC_ENV, EXEC_ARG, EXEC_ENTRYPOINT, EXEC_NESTED];

/// A `GET /exec/{id}/json` answer with a canary in every caller-supplied member.
///
/// The `ProcessConfig` members are spelled lower-camel, as the daemon sends
/// them, and that is deliberate rather than incidental: this crate's own create
/// request writes `Env` and `Cmd`, so a fixture using those spellings would let
/// an accessor written for the wrong one pass a test it should fail.
///
/// The members the summary names are present and realistic, and they matter as
/// much as the canaries — a redaction that rendered nothing would pass every
/// search in the tests below.
fn exec_inspect_body() -> String {
    format!(
        r#"{{
    "CanRemove":false,
    "ContainerID":"38df04270233eb5551a444c5a1064b683a071e41eb77e43db8c34e84b6f51344",
    "DetachKeys":"ctrl-p,ctrl-q","ExitCode":0,
    "ID":"3101d054e78255d1cdaf74c73684b35c86f253516b6497682c6c5b56cc7d0477",
    "OpenStderr":true,"OpenStdin":false,"OpenStdout":true,"Pid":935200,
    "ProcessConfig":{{
        "tty":false,
        "entrypoint":"{EXEC_ENTRYPOINT}",
        "arguments":["--token","{EXEC_ARG}"],
        "env":["PATH=/usr/bin","AWS_SECRET_ACCESS_KEY={EXEC_ENV}"],
        "user":"root","working_dir":"/srv"}},
    "Running":false,
    "SomeMemberFromANewerEngine":{{"Nested":{{"Credential":"{EXEC_NESTED}"}}}}
}}"#
    )
}

/// Reads an exec's inspect document from a fixture serving `body`.
///
/// The public constructor of an `ExecInspect` is the request, so this goes
/// through `raw::exec_inspect` over a loopback socket: `document` is private,
/// and a test that could build one in-crate would not be testing the surface a
/// caller has.
async fn exec_inspect_from(
    body: &str,
) -> (
    neotales_docker::raw::ExecInspect,
    neotales_docker::raw::RawEngine,
    std::thread::JoinHandle<()>,
    std::sync::mpsc::Sender<()>,
) {
    let (address, server, release) = serve_once(json_response("200", body));
    let engine = engine_at(address);
    let inspect = neotales_docker::raw::exec_inspect(&engine, "3101d054e782")
        .await
        .expect("the fixture answers 200 with a document");
    (inspect, engine, server, release)
}

/// `ExecInspect` must not render a single member of the document it retains,
/// and the answer must still be worth logging.
///
/// Driven through `raw::exec_inspect` over a real socket, for the same reason
/// the container fixture is: the guarantee is about a value a caller can obtain,
/// and the fixture is the only way to build one from outside the crate.
///
/// The canaries are in all three caller-supplied `ProcessConfig` members plus an
/// unmodelled top-level member, and they are searched for in every form
/// `assert_no_bytes` knows plus base64 — a base64 encoding of a secret is not a
/// redaction.
///
/// The second half is the part that makes the first half worth having: a `Debug`
/// that printed nothing would pass every search above, so the identifiers, the
/// state, the counts, and `..` are all required to be present.
#[tokio::test]
async fn an_exec_inspect_prints_its_identity_and_not_its_process_config() {
    let (inspect, engine, server, release) = exec_inspect_from(&exec_inspect_body()).await;

    // The canaries really are in the value, so the assertions below are about a
    // payload that arrived rather than one that never existed.
    let document = inspect.document();
    for canary in EXEC_CANARIES {
        let found = serde_json::to_string(document)
            .expect("a document serialises")
            .contains(canary);
        assert!(found, "the fixture did not carry {canary:?}");
    }
    // And the environment is where the issue says it is, under the spelling the
    // daemon uses rather than the one this crate's create request uses.
    assert!(
        document.pointer("/ProcessConfig/env").is_some(),
        "the fixture must carry ProcessConfig.env in the daemon's spelling"
    );

    let rendered = format!("{inspect:?}");
    // The allowlist first, for the reason the container test gives: a field the
    // canaries never thought of is the addition a canary search cannot see, and
    // `ProcessConfig` is the block a future member would land in.
    assert_fields(
        &rendered,
        &[
            "id",
            "container",
            "running",
            "exit_code",
            "pid",
            "open_stdin",
            "open_stdout",
            "open_stderr",
            "env",
            "arguments",
            "members",
        ],
    );
    for canary in EXEC_CANARIES {
        assert_no_secret(&rendered, canary);
        for form in std::iter::once(canary.to_owned()).chain(base64_forms(canary.as_bytes())) {
            assert!(
                !rendered.contains(&form),
                "an ExecInspect Debug leaked {canary:?} as {form:?}: {rendered}"
            );
        }
    }
    // The specific shape the issue is about, named so a failure says which
    // member leaked rather than only that one of four did.
    assert!(!rendered.contains("AWS_SECRET_ACCESS_KEY"), "{rendered}");
    assert!(!rendered.contains("--token"), "{rendered}");

    // What a caller reads an exec inspect answer for.
    assert!(
        rendered.contains("id: Some(\"3101d054e78255d1cdaf74c73684b35c8"),
        "{rendered}"
    );
    assert!(
        rendered.contains("container: Some(\"38df04270233eb5551a444c5a1064"),
        "{rendered}"
    );
    assert!(rendered.contains("running: Some(false)"), "{rendered}");
    assert!(rendered.contains("exit_code: Some(0)"), "{rendered}");
    assert!(rendered.contains("pid: Some(935200)"), "{rendered}");
    assert!(rendered.contains("open_stdin: Some(false)"), "{rendered}");
    assert!(rendered.contains("open_stdout: Some(true)"), "{rendered}");
    assert!(rendered.contains("open_stderr: Some(true)"), "{rendered}");
    // The counts stand in for what was withheld, so a reader can tell an exec
    // given two environment entries from one given none — which is the question
    // a "the one-off command produced no output" report is asking.
    assert!(rendered.contains("env: Some(2)"), "{rendered}");
    assert!(rendered.contains("arguments: Some(2)"), "{rendered}");
    assert!(rendered.contains("members: Some(12)"), "{rendered}");
    // And the door left open for a member added later.
    assert!(rendered.contains(".."), "{rendered}");

    drop(inspect);
    drop(engine);
    drop(release);
    server.join().expect("the fixture thread finished");
}

/// An exec the daemon reported no process configuration for must say so, or
/// `env: Some(2)` reads as decoration and a reader stops trusting it.
///
/// Getting it backwards is a real misreading rather than a stylistic one: a
/// rendering that showed a count for a member that was never sent tells a
/// reader the implementation looked somewhere it did not.
#[tokio::test]
async fn an_exec_with_no_process_config_says_none_was_reported() {
    let (inspect, engine, server, release) =
        exec_inspect_from(r#"{"ID":"3101d054e782","Running":true,"ExitCode":null}"#).await;

    let rendered = format!("{inspect:?}");
    assert_no_secret(&rendered, EXEC_ENV);
    assert!(rendered.contains("env: None"), "{rendered}");
    assert!(rendered.contains("arguments: None"), "{rendered}");
    assert!(rendered.contains("members: Some(3)"), "{rendered}");
    // The state fields still read, so the summary is not merely a shape.
    assert!(rendered.contains("running: Some(true)"), "{rendered}");
    assert!(rendered.contains("exit_code: None"), "{rendered}");
    assert!(rendered.contains("container: None"), "{rendered}");

    drop(inspect);
    drop(engine);
    drop(release);
    server.join().expect("the fixture thread finished");
}

/// The redaction is a property of `Debug` and not of the API, so `Clone`,
/// `PartialEq`, `state()` and the document accessors are all exactly as they
/// were.
///
/// Without this, "make the payload not render" and "stop giving callers the
/// environment" are the same edit, and a maintainer under pressure to fix a log
/// line would not notice the difference. This is the test that would notice.
#[tokio::test]
async fn a_redacted_exec_inspect_still_gives_its_caller_the_whole_document() {
    let (inspect, engine, server, release) = exec_inspect_from(&exec_inspect_body()).await;

    // The borrowed accessor hands back the document untouched, canary and all.
    let borrowed: &serde_json::Value = inspect.document();
    assert!(
        borrowed
            .pointer("/ProcessConfig/env/1")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|entry| entry.contains(EXEC_ENV)),
        "ProcessConfig.env must still be readable in full"
    );
    // And so must the consuming one.
    let owned = inspect.clone().into_document();
    assert_eq!(owned, *borrowed, "into_document and document agree");
    assert!(
        serde_json::to_string(&owned)
            .expect("a document serialises")
            .contains(EXEC_NESTED)
    );

    // Clone and PartialEq are ordinary caller moves, and equality still compares
    // the document — a redaction that changed what "the same answer" means would
    // be a much worse defect than a leak.
    assert_eq!(inspect, inspect.clone());
    let (other, other_engine, other_server, other_release) = exec_inspect_from(
        r#"{"ID":"3101d054e782","Running":false,"ExitCode":0,"ProcessConfig":{"env":[]}}"#,
    )
    .await;
    assert_ne!(inspect, other);

    // And the typed accessors and the repository projection are untouched.
    assert_eq!(
        inspect.id(),
        Some("3101d054e78255d1cdaf74c73684b35c86f253516b6497682c6c5b56cc7d0477")
    );
    assert_eq!(inspect.running(), Some(false));
    assert_eq!(inspect.pid(), Some(935_200));
    let state = inspect.state();
    assert!(!state.running);
    assert_eq!(state.exit_code, Some(0));
    assert_eq!(state.id, inspect.id().map(ToOwned::to_owned));

    drop(other);
    drop(other_engine);
    drop(other_release);
    other_server.join().expect("the second fixture finished");
    drop(engine);
    drop(release);
    server.join().expect("the fixture thread finished");
}

/// Mirrors `raw::ExecInspect` with a **derived** `Debug` over the same document
/// the fixture above serves.
///
/// Fed the identical body, deliberately: a mirror built from a hand-written
/// sample can drift from what the daemon really sends, and a guard checked
/// against the drifted sample proves nothing about the real document. The only
/// difference between this and the real type is the `#[derive(Debug)]`, so a
/// failure here means the hand-written impl is load-bearing.
#[derive(Debug)]
#[allow(
    dead_code,
    reason = "the derived Debug is the only reader, and it is the subject"
)]
struct DerivedExecInspect {
    document: serde_json::Value,
}

/// The negative control for the exec tests above, and the reason they are not
/// vacuous.
///
/// `assert_derived_shape_leaks` runs the *same* `assert_no_secret` the real tests
/// run, over a rendering of the *same* document, and requires it to fail. Without
/// this, a `Debug` that had been replaced by one printing the type name alone
/// would pass every test above, and so would one that printed nothing.
#[test]
fn a_derived_exec_inspect_would_have_rendered_the_whole_document() {
    for canary in EXEC_CANARIES {
        let document: serde_json::Value =
            serde_json::from_str(&exec_inspect_body()).expect("the fixture is a document");
        assert_derived_shape_leaks("ExecInspect", canary, DerivedExecInspect { document });
    }

    // And the *general* form, which is the one a per-field redaction gets wrong:
    // the document is daemon-chosen at every depth, so the next member the
    // Engine adds to `ProcessConfig` is one more thing a field list cannot
    // cover. This is the shape `ExecInspect` is — a `Value`, and nothing this
    // crate chose.
    assert_derived_shape_leaks(
        "ExecInspect holding a ProcessConfig this crate does not model",
        EXEC_NESTED,
        DerivedExecInspect {
            document: serde_json::json!({
                "ID": "3101d054e782",
                "ProcessConfig": {
                    "env": [format!("AWS_SECRET_ACCESS_KEY={EXEC_ENV}")],
                    "SomeMemberFromANewerEngine": { "Nested": { "Credential": EXEC_NESTED } },
                },
            }),
        },
    );
}
