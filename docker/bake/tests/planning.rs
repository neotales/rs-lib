//! Integration tests for bake defaults, inheritance, selection, and cycle validation.

use neotales_docker_bake::{
    BakeError, DEFAULT_CONTEXT, DEFAULT_DOCKERFILE, parse_json, parse_normalized_json,
};

const DEFAULTS: &str = include_str!("fixtures/defaults.json");
const INHERITANCE: &str = include_str!("fixtures/inheritance.json");
const SELECTION: &str = include_str!("fixtures/selection.json");
const INHERITANCE_CYCLE: &str = include_str!("fixtures/inheritance-cycle.json");
const TARGET_CYCLE: &str = include_str!("fixtures/target-cycle.json");
const GROUP_CYCLE: &str = include_str!("fixtures/group-cycle.json");

#[test]
fn defaults_are_normalized_from_the_fixture() {
    let document = parse_normalized_json(DEFAULTS).expect("defaults fixture");
    let app = document.target("app").expect("default target");

    assert_eq!(app.context, DEFAULT_CONTEXT);
    assert_eq!(app.dockerfile, DEFAULT_DOCKERFILE);
    assert_eq!(app.tags, ["registry.example/demo:latest"]);
    assert_eq!(app.platforms, ["linux/amd64", "linux/arm64"]);
    assert_eq!(app.target.as_deref(), Some("runtime"));
    assert!(app.no_cache);
    assert!(app.pull);
    assert_eq!(app.args["VERSION"], Some("1.0.0".to_owned()));
    assert_eq!(app.args["DOCKER_DEFAULT"], None);
}

#[test]
fn inheritance_merges_maps_and_replaces_scalar_lists() {
    let document = parse_normalized_json(INHERITANCE).expect("inheritance fixture");
    let base = document.target("base").expect("base target");
    let app = document.target("app").expect("app target");

    assert_eq!(base.context, "./base");
    assert_eq!(base.dockerfile, "base.Dockerfile");
    assert_eq!(base.tags, ["example/base:base"]);
    assert_eq!(base.target.as_deref(), Some("builder"));
    assert!(base.no_cache);
    assert!(!base.pull);

    assert_eq!(app.inherits, ["base"]);
    assert_eq!(app.context, "./base");
    assert_eq!(app.dockerfile, "base.Dockerfile");
    assert_eq!(app.args["MODE"], Some("app".to_owned()));
    assert_eq!(app.args["KEEP"], Some("yes".to_owned()));
    assert_eq!(app.tags, ["example/app:base"]);
    assert_eq!(app.platforms, ["linux/arm64"]);
    assert_eq!(app.target.as_deref(), Some("runtime"));
    assert!(app.no_cache);
    assert!(app.pull);
}

#[test]
fn selection_expands_groups_and_named_target_dependencies() {
    let document = parse_normalized_json(SELECTION).expect("selection fixture");

    let default_graph = document.plan(&[]).expect("default group");
    assert_eq!(default_graph.requested, ["default"]);
    assert_eq!(
        default_graph.target_names().collect::<Vec<_>>(),
        ["app", "base", "lint"]
    );
    assert_eq!(default_graph.edges["app"], ["base"]);
    assert_eq!(default_graph.execution_order(), ["base", "app", "lint"]);

    let release_graph = document.plan(&["release"]).expect("release group");
    assert_eq!(
        release_graph.target_names().collect::<Vec<_>>(),
        ["app", "base", "test"]
    );
    assert_eq!(release_graph.inheritance["test"], ["app"]);
    assert_eq!(release_graph.execution_order(), ["base", "app", "test"]);

    let selected = document.plan(&["lint"]).expect("direct target selection");
    assert_eq!(selected.target_names().collect::<Vec<_>>(), ["lint"]);
    assert!(selected.edges["lint"].is_empty());
}

#[test]
fn planning_is_deterministic_for_the_same_fixture() {
    let first = parse_normalized_json(SELECTION)
        .expect("first parse")
        .plan(&["release"])
        .expect("first plan");
    let second = parse_normalized_json(SELECTION)
        .expect("second parse")
        .plan(&["release"])
        .expect("second plan");
    assert_eq!(first, second);
}

#[test]
fn inheritance_cycles_are_rejected_with_a_trace() {
    let error = parse_normalized_json(INHERITANCE_CYCLE).expect_err("inheritance cycle");
    assert_eq!(
        error,
        BakeError::InheritanceCycle {
            trace: vec![
                "first".to_owned(),
                "second".to_owned(),
                "third".to_owned(),
                "first".to_owned()
            ]
        }
    );
}

#[test]
fn named_context_cycles_are_rejected_with_a_trace() {
    let error = parse_normalized_json(TARGET_CYCLE).expect_err("target cycle");
    assert_eq!(
        error,
        BakeError::DependencyCycle {
            trace: vec!["first".to_owned(), "second".to_owned(), "first".to_owned()]
        }
    );
}

#[test]
fn group_cycles_are_rejected_before_selection() {
    let error = parse_normalized_json(GROUP_CYCLE).expect_err("group cycle");
    assert_eq!(
        error,
        BakeError::GroupCycle {
            trace: vec!["first".to_owned(), "second".to_owned(), "first".to_owned()]
        }
    );
}

#[test]
fn unknown_fields_and_selections_are_rejected() {
    let unknown = parse_json(r#"{"target":{"app":{"unknown": true}}}"#).expect_err("unknown field");
    assert!(matches!(unknown, BakeError::UnsupportedField { .. }));

    let unknown_variable = parse_json(r#"{"variable":{"TAG":{"unknown": true}}}"#)
        .expect_err("unknown variable field");
    assert!(matches!(
        unknown_variable,
        BakeError::UnsupportedField { .. }
    ));

    let document = parse_normalized_json(SELECTION).expect("selection fixture");
    assert_eq!(
        document.plan(&["missing"]),
        Err(BakeError::UnknownSelection("missing".to_owned()))
    );
}
