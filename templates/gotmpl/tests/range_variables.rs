//! `range` variable binding, checked against Go's own `text/template`.
//!
//! `{{ range $k, $v := .mapping }}` is the ordinary way to iterate a map in a Go
//! template, and it is what someone parameterizing a Compose file writes. Before
//! this was supported the action was rejected outright with
//! `unsupported template action: $name, $cfg := .values.services`, and ranging a
//! map without variables silently lost every key because only the value was
//! reachable through `.`.
//!
//! Every expectation below was produced by Go 1.24.13 `text/template` on the same
//! template and the same data, rather than by this implementation's reading of the
//! language. Where Go and this implementation differ, the test says so and
//! explains which is correct rather than quietly matching this implementation.

use std::collections::BTreeMap;

use neotales_gotmpl::{Error, Template, Value};

fn map(pairs: &[(&str, Value)]) -> Value {
    Value::Map(
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), value.clone()))
            .collect::<BTreeMap<String, Value>>(),
    )
}

/// Renders `source` with `root` as the template's root value.
///
/// The typed API takes a map, so a root that is itself a map is used directly.
fn render(source: &str, root: &Value) -> Result<String, Error> {
    let values = match root {
        Value::Map(entries) => entries.clone(),
        other => {
            let mut entries = BTreeMap::new();
            entries.insert("root".to_owned(), other.clone());
            entries
        }
    };
    Template::parse(source)?.render_typed(&values)
}

/// A root whose `services` member is the two-service map, so a template can say
/// `.services` exactly as a Compose template does.
fn with_services() -> Value {
    map(&[("services", services())])
}

fn services() -> Value {
    map(&[
        (
            "api",
            map(&[
                ("image", Value::String("api:1".to_owned())),
                ("replicas", Value::String("2".to_owned())),
            ]),
        ),
        (
            "web",
            map(&[
                ("image", Value::String("web:1".to_owned())),
                ("replicas", Value::String("1".to_owned())),
            ]),
        ),
    ])
}

/// Go 1.24.13: `api=api:1;web=web:1;`
#[test]
fn a_two_variable_range_binds_the_key_and_the_value() {
    let output = render(
        "{{ range $name, $cfg := .services }}{{ $name }}={{ $cfg.image }};{{ end }}",
        &with_services(),
    )
    .expect("renders");
    assert_eq!(output, "api=api:1;web=web:1;");
}

/// Go 1.24.13: `api:1;web:1;`
#[test]
fn a_one_variable_range_over_a_map_binds_the_value() {
    let output = render(
        "{{ range $cfg := .services }}{{ $cfg.image }};{{ end }}",
        &with_services(),
    )
    .expect("renders");
    assert_eq!(output, "api:1;web:1;");
}

/// Go 1.24.13: `0:a;1:b;`
#[test]
fn a_list_range_binds_the_index_and_the_element() {
    let root = map(&[(
        "list",
        Value::List(vec![
            Value::String("a".to_owned()),
            Value::String("b".to_owned()),
        ]),
    )]);
    let output = render(
        "{{ range $i, $v := .list }}{{ $i }}:{{ $v }};{{ end }}",
        &root,
    )
    .expect("renders");
    assert_eq!(output, "0:a;1:b;");
}

/// Go 1.24.13: `a,b,`
#[test]
fn a_one_variable_range_over_a_list_binds_the_element() {
    let root = map(&[(
        "list",
        Value::List(vec![
            Value::String("a".to_owned()),
            Value::String("b".to_owned()),
        ]),
    )]);
    let output = render("{{ range $v := .list }}{{ $v }},{{ end }}", &root).expect("renders");
    assert_eq!(output, "a,b,");
}

/// Go 1.24.13: `api=api:1;web=web:1;`
#[test]
fn the_dot_is_rebound_to_the_element_even_with_variables() {
    let output = render(
        "{{ range $name, $cfg := .services }}{{ $name }}={{ .image }};{{ end }}",
        &with_services(),
    )
    .expect("renders");
    assert_eq!(output, "api=api:1;web=web:1;");
}

/// Go 1.24.13: `adeep`
#[test]
fn a_variable_path_is_resolved_against_the_bound_value() {
    let root = map(&[(
        "deep",
        map(&[(
            "a",
            map(&[("b", map(&[("c", Value::String("deep".to_owned()))]))]),
        )]),
    )]);
    let output = render(
        "{{ range $k, $v := .deep }}{{ $k }}{{ $v.b.c }}{{ end }}",
        &root,
    )
    .expect("renders");
    assert_eq!(output, "adeep");
}

/// Go 1.24.13: `[empty]`
#[test]
fn an_empty_map_uses_the_else_branch() {
    let root = map(&[("services", Value::Map(BTreeMap::new()))]);
    let output = render(
        "[{{ range $k, $v := .services }}body{{ else }}empty{{ end }}]",
        &root,
    )
    .expect("renders");
    assert_eq!(output, "[empty]");
}

/// Go 1.24.13: `[apiweb]`
#[test]
fn a_populated_map_uses_the_body_not_the_else_branch() {
    let root = map(&[("services", services())]);
    let output = render(
        "[{{ range $k, $v := .services }}{{ $k }}{{ else }}empty{{ end }}]",
        &root,
    )
    .expect("renders");
    assert_eq!(output, "[apiweb]");
}

/// Go 1.24.13: `xapixweb`
#[test]
fn an_outer_variable_is_still_reachable_inside_the_loop() {
    let root = map(&[
        ("p", Value::String("x".to_owned())),
        ("services", services()),
    ]);
    let output = render(
        "{{ $p := .p }}{{ range $n, $c := .services }}{{ $p }}{{ $n }}{{ end }}",
        &root,
    )
    .expect("renders");
    assert_eq!(output, "xapixweb");
}

/// Go 1.24.13: `api:1;web:1;`
#[test]
fn a_single_variable_without_declaration_still_rebinds_the_dot() {
    let output = render(
        "{{ range .services }}{{ .image }};{{ end }}",
        &with_services(),
    )
    .expect("renders");
    assert_eq!(output, "api:1;web:1;");
}

/// Go 1.24.13: `api:2web:1`
#[test]
fn a_non_string_member_renders_by_its_value() {
    let output = render(
        "{{ range $n, $c := .services }}{{ $n }}:{{ $c.replicas }}{{ end }}",
        &with_services(),
    )
    .expect("renders");
    assert_eq!(output, "api:2web:1");
}

/// Go 1.24.13 renders exactly this, newline for newline.
#[test]
fn the_compose_use_case_renders_a_service_block_per_entry() {
    // The shape a parameterized Compose file uses.
    let template = "services:\n{{- range $name, $cfg := .values.services }}\n  {{ $name }}:\n    image: {{ $cfg.image }}\n{{- end }}\n";
    let root = map(&[("values", map(&[("services", services())]))]);
    let output = render(template, &root).expect("renders");
    assert_eq!(
        output,
        "services:\n  api:\n    image: api:1\n  web:\n    image: web:1\n"
    );
}

/// Go 1.24.13 rejects this at parse time with
/// `too many declarations in range`.
#[test]
fn a_three_variable_declaration_is_rejected() {
    let error = Template::parse("{{ range $a, $b, $c := .services }}{{ end }}")
        .expect_err("Go binds at most two variables");
    assert!(matches!(error, Error::UnsupportedAction(_)), "{error:?}");
}

/// Go 1.24.13 rejects this at parse time with `undefined variable "$k"`.
///
/// Go scopes a `:=` declaration to the block and knows the name at parse time,
/// so a reference outside the loop is a parse error. This implementation binds
/// per iteration and resolves variables at render time, so the same template
/// parses and then fails to render with [`Error::MissingVariable`] — a different
/// diagnostic at a different time, for the same input.
///
/// The divergence is recorded rather than papered over: Go's parse-time scope
/// check would need a static binding pass over the whole template, and this
/// subset resolves names during rendering. The observable outcome is the same
/// (the render fails and no output is produced), which is why it is a
/// documentation difference and not a behavior bug.
#[test]
fn a_variable_declared_only_inside_the_loop_is_not_reachable_after_it() {
    let error = render(
        "{{ range $k, $v := .services }}{{ $k }}{{ end }}|{{ $k }}",
        &with_services(),
    )
    .expect_err("the name is out of scope after the loop");
    let Error::MissingVariable(name) = &error else {
        panic!("expected a missing-variable error naming 'k', got {error:?}");
    };
    assert_eq!(name, "k");
}

/// `{{ range $k, $v }}` has no expression, so the names would have to be
/// resolved from the enclosing scope before the loop. Refusing it is honest;
/// treating it as the `:=` form would bind something the author did not name.
#[test]
fn the_assign_to_existing_scope_form_is_refused_rather_than_guessed() {
    for source in ["{{ range $k, $v }}{{ end }}", "{{ range $v }}{{ end }}"] {
        let error = Template::parse(source).expect_err("no expression to range over");
        assert!(
            matches!(error, Error::UnsupportedAction(_)),
            "{source}: {error:?}"
        );
    }
}

/// The `range` over a non-collection still takes the `else` branch, as before.
#[test]
fn a_scalar_ranging_source_takes_the_else_branch() {
    let root = map(&[("services", Value::String("not a collection".to_owned()))]);
    let output = render(
        "[{{ range $k, $v := .services }}body{{ else }}empty{{ end }}]",
        &root,
    )
    .expect("renders");
    assert_eq!(output, "[empty]");
}

/// Go 1.24.13 renders `<no value>` for `{{ .env.MODE }}` inside a `range`, and
/// `dev` for `{{ $.env.MODE }}`.
///
/// `.` is rebound to the element per iteration, so a name from the surrounding
/// document is reached through `$`, the root. Getting this wrong is the usual
/// reason a parameterized Compose file renders empty values inside a loop.
#[test]
fn the_root_is_reachable_inside_a_range_through_the_dollar_sign() {
    let root = map(&[
        ("env", map(&[("MODE", Value::String("dev".to_owned()))])),
        (
            "services",
            map(&[("api", map(&[("image", Value::String("api:1".to_owned()))]))]),
        ),
    ]);

    // `$` reaches the surrounding document from inside the loop.
    let output = render(
        "{{ range $n, $c := .services }}{{ $.env.MODE }}{{ end }}",
        &root,
    )
    .expect("renders");
    assert_eq!(output, "dev");

    // And the values namespace likewise.
    let valued = map(&[
        (
            "values",
            map(&[(
                "services",
                map(&[("api", map(&[("image", Value::String("x".to_owned()))]))]),
            )]),
        ),
        (
            "services",
            map(&[("api", map(&[("image", Value::String("y".to_owned()))]))]),
        ),
    ]);
    let output = render(
        "{{ range $n, $c := .services }}{{ $.values.services.api.image }}{{ end }}",
        &valued,
    )
    .expect("renders");
    assert_eq!(output, "x");
}

/// Go renders `<no value>` where this implementation reports a missing value.
///
/// The divergence is deliberate and predates the two-variable range: a name that
/// is not present is an error here, so a typo in a Compose template fails loudly
/// instead of writing `<no value>` into a YAML document that a daemon would then
/// reject with a far less useful message. The test records the Go spelling so
/// the difference is a decision rather than a surprise.
#[test]
fn a_dot_name_that_is_only_in_the_root_is_reported_inside_a_range() {
    let root = map(&[
        ("env", map(&[("MODE", Value::String("dev".to_owned()))])),
        (
            "services",
            map(&[("api", map(&[("image", Value::String("api:1".to_owned()))]))]),
        ),
    ]);
    let error = render(
        "{{ range $n, $c := .services }}{{ .env.MODE }}{{ end }}",
        &root,
    )
    .expect_err("`.` is the element inside a range, so `.env` is not there");
    let Error::MissingValue(name) = &error else {
        panic!("expected a missing-value error, got {error:?}");
    };
    assert_eq!(name, "env.MODE");
}
