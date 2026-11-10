//! Merge semantics for layered Compose sources.
//!
//! These tests exist because the merge used to replace whole services. That
//! passes a single-file test and fails the first time someone writes the
//! ordinary Compose pattern of a base file plus a small override file: the
//! override names the service, and naming it was enough to delete the base
//! image, command, and ports.
//!
//! The rule under test is one sentence — *a field the incoming declaration did
//! not set leaves the base value alone* — applied with per-field treatment that
//! follows the shape of the value.

use neotales_docker_compose::{
    ComposeProject, ComposeProjectOptions, InterpolationPolicy, InterpolationValues, MergePolicy,
};

fn options(merge: MergePolicy) -> ComposeProjectOptions {
    ComposeProjectOptions {
        interpolation: InterpolationPolicy::explicit_values(),
        merge,
        ..ComposeProjectOptions::default()
    }
}

fn load(sources: &[(&str, &str)], merge: MergePolicy) -> ComposeProject {
    let owned = sources
        .iter()
        .map(|(source, path)| (*source, *path))
        .collect::<Vec<_>>();
    ComposeProject::parse_sources(&owned, &InterpolationValues::new(), options(merge))
        .expect("layered sources load")
}

const BASE: &str = r#"
services:
  api:
    image: "registry.example/api:1"
    command: ["serve", "--port=8080"]
    deploy:
      replicas: 3
    tty: true
    environment:
      MODE: production
      KEEP: base-only
    labels:
      tier: base
      owner: platform
    ports:
      - "8080:8080"
"#;

const OVERRIDE: &str = "services:\n  api:\n    environment:\n      MODE: debug\n      ADDED: override\n    labels:\n      tier: merged\n";

#[test]
fn an_override_that_omits_a_field_leaves_the_base_value_intact() {
    let project = load(
        &[(BASE, "base.yaml"), (OVERRIDE, "over.yaml")],
        MergePolicy::MergeServices,
    );
    let api = &project.services["api"];

    // The whole bug in one assertion: the override names the service but does
    // not set an image, so the base image must survive.
    assert_eq!(api.image, "registry.example/api:1");
    assert_eq!(api.command, vec!["serve", "--port=8080"]);
    assert_eq!(api.replicas, 3);
    assert!(
        api.tty,
        "an override that never mentions tty must not clear it"
    );
    assert_eq!(api.ports.len(), 1, "base ports must survive");
}

#[test]
fn maps_merge_key_by_key_with_the_override_winning_per_key() {
    let project = load(
        &[(BASE, "base.yaml"), (OVERRIDE, "over.yaml")],
        MergePolicy::MergeServices,
    );
    let api = &project.services["api"];

    assert_eq!(
        api.environment.get("MODE").map(String::as_str),
        Some("debug")
    );
    assert_eq!(
        api.environment.get("KEEP").map(String::as_str),
        Some("base-only"),
        "a base environment entry the override did not name must survive"
    );
    assert_eq!(
        api.environment.get("ADDED").map(String::as_str),
        Some("override")
    );
    assert_eq!(api.labels.get("tier").map(String::as_str), Some("merged"));
    assert_eq!(
        api.labels.get("owner").map(String::as_str),
        Some("platform")
    );
}

#[test]
fn an_explicit_default_in_an_override_replaces_the_base_value() {
    // The declared-field tracking exists precisely so this is distinguishable
    // from the previous test: `replicas: 1` and an absent `replicas` produce the
    // same normalized value, so only the declared set can tell them apart.
    let project = load(
        &[
            (BASE, "base.yaml"),
            (
                "services:\n  api:\n    image: \"registry.example/api:2\"\n    deploy:\n      replicas: 1\n    tty: false\n",
                "over.yaml",
            ),
        ],
        MergePolicy::MergeServices,
    );
    let api = &project.services["api"];

    assert_eq!(api.replicas, 1, "an explicit replicas: 1 must win");
    assert!(!api.tty, "an explicit tty: false must clear a base true");
    assert_eq!(
        api.image, "registry.example/api:2",
        "an explicit image must win"
    );
    assert_eq!(
        api.command,
        vec!["serve", "--port=8080"],
        "fields the second source never set still come from the base"
    );
}

#[test]
fn merge_order_is_significant_and_reversible() {
    let forward = load(
        &[(BASE, "base.yaml"), (OVERRIDE, "over.yaml")],
        MergePolicy::MergeServices,
    );
    let backward = load(
        &[(OVERRIDE, "over.yaml"), (BASE, "base.yaml")],
        MergePolicy::MergeServices,
    );

    // The override's `tier: merged` must win going forward and lose going
    // backward, or the merge is not actually order-sensitive.
    assert_eq!(
        forward.services["api"]
            .labels
            .get("tier")
            .map(String::as_str),
        Some("merged")
    );
    assert_eq!(
        backward.services["api"]
            .labels
            .get("tier")
            .map(String::as_str),
        Some("base")
    );
    // And the environment merge follows the same order.
    assert_eq!(
        forward.services["api"]
            .environment
            .get("MODE")
            .map(String::as_str),
        Some("debug")
    );
    assert_eq!(
        backward.services["api"]
            .environment
            .get("MODE")
            .map(String::as_str),
        Some("production")
    );
}

#[test]
fn last_wins_replaces_a_whole_service_and_so_loses_the_base_image() {
    // `LastWins` is the documented escape hatch for whole-service replacement.
    // It behaves differently from the field-level merge, and the difference is
    // not subtle: an override that omits the image produces a merged service
    // with no image at all, which is rejected. That is the reason `--merge`
    // selects `MergeServices` instead.
    let error = ComposeProject::parse_sources(
        &[(BASE, "base.yaml"), (OVERRIDE, "over.yaml")],
        &InterpolationValues::new(),
        options(MergePolicy::LastWins),
    )
    .expect_err("whole-service replacement drops the base image");

    assert_eq!(error.code(), "compose_service_requires_image");
    // The merged document has no single file, and the diagnostic says so rather
    // than pointing the reader at one of the inputs.
    assert_eq!(error.source(), Some("<merged>"));
}

#[test]
fn last_wins_keeps_a_fully_specified_override() {
    // `LastWins` is still usable when the override is self-contained, which is
    // what it is for.
    let project = load(
        &[
            (BASE, "base.yaml"),
            (
                "services:\n  api:\n    image: \"registry.example/api:9\"\n    command: [\"migrate\"]\n    environment:\n      MODE: only\n",
                "over.yaml",
            ),
        ],
        MergePolicy::LastWins,
    );
    let api = &project.services["api"];
    assert_eq!(api.image, "registry.example/api:9");
    assert_eq!(api.command, vec!["migrate"]);
    assert_eq!(
        api.environment.get("MODE").map(String::as_str),
        Some("only")
    );
    assert!(
        !api.environment.contains_key("KEEP"),
        "LastWins does not merge environment maps"
    );
    assert!(api.ports.is_empty(), "LastWins does not inherit base ports");
}

#[test]
fn a_service_appearing_only_in_an_override_is_added_whole() {
    let project = load(
        &[
            (BASE, "base.yaml"),
            (
                "services:\n  worker:\n    image: \"registry.example/worker:1\"\n",
                "over.yaml",
            ),
        ],
        MergePolicy::MergeServices,
    );
    assert_eq!(
        project.services["worker"].image,
        "registry.example/worker:1"
    );
    assert_eq!(project.services["api"].image, "registry.example/api:1");
}

#[test]
fn a_merged_service_without_any_image_is_still_rejected() {
    // Moving the requirement after the merge must not turn it off. A service
    // with no image anywhere is still an error, reported against the merged
    // document rather than against whichever layer happened to be parsed last.
    let error = ComposeProject::parse_sources(
        &[
            ("services:\n  api:\n    command: [\"serve\"]\n", "base.yaml"),
            (
                "services:\n  api:\n    deploy:\n      replicas: 2\n",
                "over.yaml",
            ),
        ],
        &InterpolationValues::new(),
        options(MergePolicy::MergeServices),
    )
    .expect_err("no image in any layer");
    assert_eq!(error.code(), "compose_service_requires_image");
    assert_eq!(error.path(), "$.services.api");
}

#[test]
fn a_single_source_with_no_image_is_still_rejected() {
    let error = ComposeProject::parse_sources(
        &[(
            "services:\n  api:\n    command: [\"serve\"]\n",
            "compose.yaml",
        )],
        &InterpolationValues::new(),
        options(MergePolicy::Reject),
    )
    .expect_err("a lone service with no image");
    assert_eq!(error.code(), "compose_service_requires_image");
}

#[test]
fn string_maps_accept_the_sequence_spelling() {
    // Docker Compose accepts `key=value` sequences wherever a map is expected.
    // The reference implementation's `StringMap` handles both, and rejecting the
    // sequence form made ordinary Compose files fail to parse.
    let project = load(
        &[(
            r#"
services:
  api:
    image: "api:1"
    labels:
      - "tier=base"
      - "owner=platform"
      - "flag"
    build:
      context: "."
      args:
        - "MODE=release"
        - "DEBUG=false"
      labels:
        - "org.opencontainers.image.source=repo"
"#,
            "compose.yaml",
        )],
        MergePolicy::Reject,
    );
    let api = &project.services["api"];
    assert_eq!(api.labels.get("tier").map(String::as_str), Some("base"));
    assert_eq!(
        api.labels.get("owner").map(String::as_str),
        Some("platform")
    );
    // An entry with no `=` is a bare key with an empty value, which is how a
    // valueless label is written.
    assert_eq!(api.labels.get("flag").map(String::as_str), Some(""));

    let build = api.build.as_ref().expect("build is declared");
    assert_eq!(
        build.arguments.get("MODE").map(String::as_str),
        Some("release")
    );
    assert_eq!(
        build
            .labels
            .get("org.opencontainers.image.source")
            .map(String::as_str),
        Some("repo")
    );
}

#[test]
fn both_string_map_spellings_produce_the_same_result() {
    let mapping = load(
        &[(
            "services:\n  api:\n    image: \"api:1\"\n    labels:\n      tier: base\n      owner: platform\n",
            "compose.yaml",
        )],
        MergePolicy::Reject,
    );
    let sequence = load(
        &[(
            "services:\n  api:\n    image: \"api:1\"\n    labels:\n      - \"tier=base\"\n      - \"owner=platform\"\n",
            "compose.yaml",
        )],
        MergePolicy::Reject,
    );
    assert_eq!(
        mapping.services["api"].labels,
        sequence.services["api"].labels
    );
}

#[test]
fn a_value_containing_an_equals_sign_survives_the_sequence_spelling() {
    // The split is at the first `=` only, so a value may contain more.
    let project = load(
        &[(
            "services:\n  api:\n    image: \"api:1\"\n    labels:\n      - \"query=a=b=c\"\n",
            "compose.yaml",
        )],
        MergePolicy::Reject,
    );
    assert_eq!(
        project.services["api"]
            .labels
            .get("query")
            .map(String::as_str),
        Some("a=b=c")
    );
}

#[test]
fn a_duplicate_key_across_both_spellings_is_rejected() {
    // A sequence that repeats a key would otherwise make the last one win
    // silently, which hides a mistake in the source.
    let error = ComposeProject::parse_sources(
        &[(
            "services:\n  api:\n    image: \"api:1\"\n    labels:\n      - \"tier=one\"\n      - \"tier=two\"\n",
            "compose.yaml",
        )],
        &InterpolationValues::new(),
        options(MergePolicy::Reject),
    )
    .expect_err("a repeated key is a mistake");
    assert_eq!(error.code(), "compose_duplicate_key");
}
