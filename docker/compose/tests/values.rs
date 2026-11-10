//! Structured values files and the merge that layers them.
//!
//! These are the inputs a Compose Go template is parameterized with. Before this
//! existed the template root was a flat string map, so a values file could not
//! carry a nested service map at all and
//! `{{ range $name, $cfg := .values.services }}` had nothing to range over.

use std::collections::BTreeMap;

use neotales_docker_compose::{
    TemplateOptions, TemplateValueMap, merge_values, parse_values, render_template, template_root,
};
use neotales_sprig::Value;

fn values(text: &str, path: &str) -> TemplateValueMap {
    parse_values(text, path).expect("values parse")
}

#[test]
fn a_json_values_file_keeps_numbers_booleans_and_nulls_distinct() {
    let parsed = values(
        r#"{"replicas":3,"ratio":1.5,"enabled":true,"disabled":false,"unset":null,"name":"api"}"#,
        "values.json",
    );
    assert_eq!(parsed.get("replicas"), Some(&Value::Number(3.0)));
    assert_eq!(parsed.get("ratio"), Some(&Value::Number(1.5)));
    assert_eq!(parsed.get("enabled"), Some(&Value::Bool(true)));
    assert_eq!(parsed.get("disabled"), Some(&Value::Bool(false)));
    assert_eq!(parsed.get("unset"), Some(&Value::Null));
    assert_eq!(parsed.get("name"), Some(&Value::String("api".to_owned())));
}

#[test]
fn a_yaml_values_file_reads_the_same_shapes() {
    let parsed = values(
        "replicas: 3\nratio: 1.5\nenabled: true\nunset: null\nname: api\nnested:\n  a: 1\n  b: two\n",
        "values.yaml",
    );
    assert_eq!(parsed.get("replicas"), Some(&Value::Number(3.0)));
    assert_eq!(parsed.get("enabled"), Some(&Value::Bool(true)));
    assert_eq!(parsed.get("unset"), Some(&Value::Null));
    let nested = parsed.get("nested").expect("nested map");
    let Value::Map(nested) = nested else {
        panic!("nested should be a map: {nested:?}");
    };
    assert_eq!(nested.get("b"), Some(&Value::String("two".to_owned())));
}

#[test]
fn the_format_comes_from_the_extension_and_is_sniffed_otherwise() {
    // `.json` selects the JSON parser.
    let json = values(r#"{"a":1}"#, "values.json");
    assert_eq!(json.get("a"), Some(&Value::Number(1.0)));

    // `.yml` selects the YAML parser. For a flow mapping the two agree, because
    // YAML is a superset of JSON — the extension still decides which parser
    // runs, and the visible difference shows up in a value that only one of them
    // can read.
    let yaml = values("{\"a\":1}\n", "values.yml");
    assert_eq!(yaml.get("a"), Some(&Value::Number(1.0)));
    // A flow mapping with an unquoted key is legal YAML and illegal JSON, so the
    // same bytes read differently depending on the extension. That is the
    // clearest evidence the extension is honored rather than decorative.
    let unquoted_key = "{a: 1}";
    assert_eq!(
        values(unquoted_key, "values.yaml").get("a"),
        Some(&Value::Number(1.0))
    );
    assert!(
        parse_values(unquoted_key, "values.json").is_err(),
        "an unquoted key is not legal JSON, so the extension selected the parser"
    );

    // No usable extension, so the first non-whitespace character decides.
    let sniffed_json = values("\n  {\"a\": 1}", "values");
    assert_eq!(sniffed_json.get("a"), Some(&Value::Number(1.0)));
    let sniffed_yaml = values("a: 1\n", "values");
    assert_eq!(sniffed_yaml.get("a"), Some(&Value::Number(1.0)));
}

#[test]
fn an_empty_values_file_is_an_empty_map_rather_than_an_error() {
    assert!(values("", "values.yaml").is_empty());
    assert!(values("   \n", "values.yaml").is_empty());
}

#[test]
fn a_top_level_list_or_scalar_is_refused() {
    // The values are merged under a single `.values` key, and a list has no key
    // to merge under. Inventing a root key would be a contract the author never
    // wrote.
    for (text, path) in [("- 1\n- 2\n", "values.yaml"), ("42\n", "values.yaml")] {
        let error = parse_values(text, path).expect_err("not a mapping");
        assert_eq!(error.code(), "compose_values_not_a_mapping", "{path}");
    }
}

#[test]
fn an_undecodable_values_file_names_the_file() {
    let error = parse_values("a: [1, 2\n", "broken.yaml").expect_err("invalid YAML");
    assert_eq!(error.code(), "compose_values_invalid");
    assert!(
        error.message().contains("broken.yaml"),
        "the diagnostic must name the file: {error:?}"
    );
}

#[test]
fn a_merge_changes_the_leaves_it_names_and_keeps_the_rest() {
    let mut merged = values(
        r#"{"services":{"api":{"image":"api:1","replicas":3},"web":{"image":"web:1"}}}"#,
        "base.json",
    );
    let override_values = values(r#"{"services":{"api":{"image":"api:2"}}}"#, "override.json");
    merge_values(&mut merged, override_values);

    let services = merged.get("services").expect("services");
    let Value::Map(services) = services else {
        panic!("services should be a map");
    };
    let api = services.get("api").expect("api");
    let Value::Map(api) = api else {
        panic!("api should be a map");
    };
    assert_eq!(api.get("image"), Some(&Value::String("api:2".to_owned())));
    // The override did not name `replicas`, so the base value survives. This is
    // the whole point of merging recursively rather than replacing the map.
    assert_eq!(api.get("replicas"), Some(&Value::Number(3.0)));
    // And a sibling service is untouched.
    assert!(services.contains_key("web"));
}

#[test]
fn a_merge_replaces_a_scalar_rather_than_merging_it() {
    let mut merged = values(r#"{"a":{"b":1}}"#, "base.json");
    merge_values(&mut merged, values(r#"{"a":"scalar"}"#, "over.json"));
    assert_eq!(merged.get("a"), Some(&Value::String("scalar".to_owned())));
}

#[test]
fn a_merge_adds_services_the_base_never_had() {
    let mut merged = values(r#"{"services":{"api":{"image":"api:1"}}}"#, "base.json");
    merge_values(
        &mut merged,
        values(r#"{"services":{"cache":{"image":"redis:7"}}}"#, "over.json"),
    );
    let Value::Map(services) = merged.get("services").expect("services") else {
        panic!("services should be a map");
    };
    assert_eq!(services.len(), 2);
    assert!(services.contains_key("api"));
    assert!(services.contains_key("cache"));
}

#[test]
fn the_root_exposes_values_and_env_and_always_both() {
    let structured = values(r#"{"tag":"1.2"}"#, "values.json");
    let environment = BTreeMap::from([("MODE".to_owned(), "dev".to_owned())]);
    let root = template_root(structured, &environment);

    let rendered = |source: &str| {
        render_template(source, &root, &TemplateOptions::default()).expect("template renders")
    };
    assert_eq!(rendered("{{ .values.tag }}"), "1.2");
    assert_eq!(rendered("{{ .env.MODE }}"), "dev");

    // Both namespaces exist even with nothing to put in them, so a template
    // does not have to guard against an absent member.
    let empty = template_root(TemplateValueMap::new(), &BTreeMap::new());
    assert_eq!(
        render_template(
            "{{ if .values }}{{ end }}{{ if .env }}{{ end }}ok",
            &empty,
            &TemplateOptions::default()
        )
        .expect("renders"),
        "ok"
    );
}

#[test]
fn a_template_can_range_the_values_namespace() {
    // The case that was impossible with a flat root.
    let structured = values(
        r#"{"services":{"api":{"image":"api:1","replicas":3},"web":{"image":"web:1","replicas":1}}}"#,
        "values.json",
    );
    let root = template_root(structured, &BTreeMap::new());
    let rendered = render_template(
        "{{ range $name, $cfg := .values.services }}{{ $name }}:{{ $cfg.image }}:{{ $cfg.replicas }};{{ end }}",
        &root,
        &TemplateOptions::default(),
    )
    .expect("renders");
    assert_eq!(rendered, "api:api:1:3;web:web:1:1;");
}
