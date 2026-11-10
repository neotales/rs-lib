//! The four scalar styles, reached the way a consumer reaches them.
//!
//! `plan_yaml.rs` measures each string and picks one of four styles for it
//! (`Style::Plain`, `Single`, `Double`, `Literal`). `Style` itself is crate
//! internal: the crate root publishes `OrderedMap`, `OrderedValue` and
//! `render_yaml_value`, and the choice of style is made inside the emitter,
//! never by the caller. Nothing in a published signature mentions it, so it is
//! `pub(crate)` and this file is the check that the narrowing cost the published
//! surface nothing.
//!
//! Every expectation here is one already recorded in `plan_yaml.rs`'s own tests
//! or in its module documentation, each of which was captured from
//! `docker compose config` on Docker 29.8. This file does not measure anything
//! new; it asserts the same bytes through the crate-root path, from a test
//! binary outside the crate, so that deleting a variant of the style table
//! cannot pass.

#![allow(missing_docs)]

use neotales_docker_compose::{OrderedMap, OrderedValue, render_yaml_value};

fn document(entries: Vec<(&str, OrderedValue)>) -> OrderedValue {
    OrderedValue::Mapping(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect::<OrderedMap>(),
    )
}

/// All four styles in one document, because the point is that none of them is
/// the caller's to make and all of them are the emitter's to apply.
#[test]
fn every_scalar_style_is_reachable_through_the_published_emitter() {
    let rendered = render_yaml_value(&document(vec![
        // Plain: Docker writes `alpine:3.20` and `unless-stopped` bare.
        ("restart", OrderedValue::string("unless-stopped")),
        // Double: a bare `9000` would read back as a number.
        ("port", OrderedValue::string("9000")),
        // Single: `yes` is a boolean under YAML 1.1 rules and not under 1.2.
        ("answer", OrderedValue::string("yes")),
        // Literal: a multi-line string that can be written as a block.
        ("script", OrderedValue::string("a\nb\n")),
    ]));

    assert_eq!(
        rendered,
        concat!(
            "restart: unless-stopped\n",
            "port: \"9000\"\n",
            "answer: 'yes'\n",
            "script: |\n  a\n  b\n",
        ),
        "{rendered}"
    );
}

/// The literal header is the part of `Literal` a consumer can see, and it
/// carries the trailing-newline convention: kept, stripped, or kept-and-more.
#[test]
fn the_literal_header_variants_are_the_emitters_too() {
    let rendered = render_yaml_value(&document(vec![
        ("keep", OrderedValue::string("a\nb\n")),
        ("strip", OrderedValue::string("a\nb")),
        ("keep_more", OrderedValue::string("a\n\n\n")),
        ("indented", OrderedValue::string(" a\nb")),
    ]));

    assert_eq!(
        rendered,
        concat!(
            "keep: |\n  a\n  b\n",
            "strip: |-\n  a\n  b\n",
            "keep_more: |+\n  a\n  \n  \n",
            "indented: |2-\n   a\n  b\n",
        ),
        "{rendered}"
    );
}

/// A multi-line string that cannot be written as a block falls back to `Double`
/// rather than to `Literal`, which is the one decision here that is a judgement
/// about the value rather than about its spelling.
#[test]
fn a_multi_line_string_that_cannot_be_a_block_is_double_quoted() {
    let rendered = render_yaml_value(&document(vec![("value", OrderedValue::string("a \nb"))]));

    assert_eq!(rendered, "value: \"a \\nb\"\n", "{rendered}");
}
