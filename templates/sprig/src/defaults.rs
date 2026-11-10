//! Defaults and flow control: the helpers that choose a value or stop a render.
//!
//! The behavior is the reference implementation's `Default`, `Empty`,
//! `Coalesce`, `All`, `Any`, `Ternary`, and `Fail`, and the `EmptyValue` they
//! all ask. The one that matters most is `default`: it returns the *value* it
//! was handed rather than its rendering, so a list stays a list and a number
//! stays a number, which is the entire point of the helper.
//!
//! The reference does not register `required`. Upstream Masterminds Sprig does,
//! as a synonym for `fail`, and that is how it is spelled here: a missing
//! required value stops the render with the message the template wrote.

use crate::support::any_text;
use crate::{Context, Error, Value, arity, invalid};

/// Dispatches a defaults helper.
pub(super) const DISPATCH: crate::Dispatch =
    |name, arguments, context| dispatch(name, arguments, context);

#[allow(clippy::trivially_copy_pass_by_ref)]
fn dispatch(
    name: &str,
    arguments: &[Value],
    context: &Context<'_>,
) -> Option<Result<Value, Error>> {
    // No default reads the call site; the parameter is part of the signature
    // every module shares.
    let _ = context;
    call(name, arguments)
}

fn call(name: &str, arguments: &[Value]) -> Option<Result<Value, Error>> {
    let result = match name {
        "default" => default(name, arguments),
        "empty" => empty(name, arguments),
        "coalesce" => Ok(coalesce(arguments)),
        "all" => Ok(Value::Bool(arguments.iter().all(|value| !value.is_empty()))),
        "any" => Ok(Value::Bool(arguments.iter().any(|value| !value.is_empty()))),
        "fail" | "required" => fail(name, arguments),
        "ternary" => ternary(name, arguments),
        _ => return None,
    };
    Some(result)
}

/// Reports whether this module's helper wants rendered string arguments.
///
/// None of them do, and `default` in particular must not: it would see the
/// string `"[a b]"` where the caller wrote a list, decide the list was not
/// empty, and hand back a string where the template expected a list.
pub(super) fn takes_rendered_strings(name: &str) -> bool {
    let _ = name;
    false
}

/// Implements `Default`: the first argument unless the second one is empty.
///
/// The reference takes one argument at least rather than exactly two, so a
/// single argument is the fallback and a third is ignored, which is what
/// `{{ default "fallback" "value" "ignored" }}` relies on.
fn default(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    arity(name, arguments.len(), 1, None)?;
    if arguments.len() == 1 {
        return Ok(arguments[0].clone());
    }
    let fallback = &arguments[0];
    let value = &arguments[1];
    // `crate::default` is the crate's own spelling of the same rule, and it
    // clones the chosen value rather than rendering it.
    Ok(crate::default(fallback, value))
}

/// Implements `Empty`.
fn empty(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    arity(name, arguments.len(), 1, Some(1))?;
    Ok(Value::Bool(arguments[0].is_empty()))
}

/// Implements `Coalesce`: the first argument that is not empty.
///
/// With no arguments at all the answer is null, and with every argument empty
/// it is the last one, so `coalesce` has an answer in every case rather than
/// failing.
fn coalesce(arguments: &[Value]) -> Value {
    arguments
        .iter()
        .find(|value| !value.is_empty())
        .cloned()
        .unwrap_or_else(|| arguments.last().cloned().unwrap_or(Value::Null))
}

/// Implements `Fail`, which `required` is a synonym for.
///
/// The message is the rendered argument, so a template can spell the failure in
/// a variable. The failure is an error and never a panic: a render that stops
/// is the documented outcome of `fail`, and a crate that panicked on a
/// template's own text would turn a typo into a crash.
fn fail(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    arity(name, arguments.len(), 1, Some(1))?;
    Err(invalid(name, any_text(&arguments[0])))
}

/// Implements `Ternary`: the first argument when the third one is not empty.
fn ternary(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    arity(name, arguments.len(), 3, Some(3))?;
    Ok(if arguments[2].is_empty() {
        arguments[1].clone()
    } else {
        arguments[0].clone()
    })
}

#[cfg(test)]
mod tests {
    use super::DISPATCH;
    use crate::{Context, Error, Value};
    use std::collections::BTreeMap;

    fn s(value: &str) -> Value {
        Value::String(value.to_owned())
    }

    fn n(value: f64) -> Value {
        Value::Number(value)
    }

    /// Calls a helper and renders the result the way a template would write it.
    fn render(name: &str, arguments: &[Value]) -> String {
        ok(name, arguments).render()
    }

    fn ok(name: &str, arguments: &[Value]) -> Value {
        match super::call(name, arguments) {
            Some(Ok(value)) => value,
            Some(Err(error)) => panic!("{name} returned an error: {error}"),
            None => panic!("{name} is not a defaults helper"),
        }
    }

    fn error(name: &str, arguments: &[Value]) -> Error {
        match super::call(name, arguments) {
            Some(Err(error)) => error,
            Some(Ok(value)) => panic!("{name} unexpectedly returned {}", value.render()),
            None => panic!("{name} is not a defaults helper"),
        }
    }

    // Fixtures: `{{ default "fallback" "" }}` is `fallback`,
    // `{{ default "fallback" 234 }}` is `234`,
    // `{{ default "fallback" }}` is `fallback`,
    // `{{ default "fallback" "value" "ignored" }}` is `value`, and
    // `{{ default "fallback" (trim " ") }}` is `fallback`.
    #[test]
    fn default_answers_the_second_argument_unless_it_is_empty() {
        assert_eq!(render("default", &[s("fallback"), s("")]), "fallback");
        assert_eq!(render("default", &[s("fallback"), n(234.0)]), "234");
        assert_eq!(render("default", &[s("fallback")]), "fallback");
        assert_eq!(
            render("default", &[s("fallback"), s("value"), s("ignored")]),
            "value"
        );
        // The fixture's `{{ default "fallback" (trim " ") }}` reads a helper
        // that has already answered the empty string, so the same argument.
        assert_eq!(render("default", &[s("fallback"), s("")]), "fallback");
    }

    // The point of `default` is the type it hands back, not just the text: a
    // list stays a list and a number stays a number.
    #[test]
    fn default_preserves_the_type_of_its_answer() {
        let list = Value::List(vec![n(1.0), n(2.0)]);
        assert_eq!(ok("default", &[s("fallback"), list.clone()]), list);
        let map = Value::Map([("a".to_owned(), s("b"))].into());
        assert_eq!(ok("default", &[s("fallback"), map.clone()]), map);
        assert_eq!(ok("default", &[s("fallback"), n(0.0)]), s("fallback"));
        assert_eq!(ok("default", &[n(7.0), n(0.0)]), n(7.0));
        // An empty list and an empty map are both empty, so the fallback wins.
        assert_eq!(
            render("default", &[s("fallback"), Value::List(Vec::new())]),
            "fallback"
        );
        assert_eq!(
            render("default", &[s("fallback"), Value::Map(BTreeMap::new())]),
            "fallback"
        );
    }

    // Fixtures: `{{ empty "" }}` is `true`, `{{ empty false }}` is `true`,
    // `{{ empty 0 }}` is `true`, `{{ empty 1 }}` is `false`, and
    // `{{ empty 0x0 }}` is `true` — the fixture writes the same zero in Go's
    // hexadecimal spelling, and either way the crate is handed the zero.
    #[test]
    fn empty_reports_emptiness() {
        assert_eq!(render("empty", &[s("")]), "true");
        assert_eq!(render("empty", &[Value::Bool(false)]), "true");
        assert_eq!(render("empty", &[n(0.0)]), "true");
        assert_eq!(render("empty", &[n(1.0)]), "false");
        assert_eq!(render("empty", &[Value::Null]), "true");
        assert_eq!(render("empty", &[Value::List(Vec::new())]), "true");
        assert_eq!(render("empty", &[Value::Bool(true)]), "false");
        assert_eq!(render("empty", &[s("x")]), "false");
    }

    // Fixtures: `{{ coalesce "" "" "value" }}` is `value` and `{{ coalesce }}`
    // is `<no value>`.
    #[test]
    fn coalesce_answers_the_first_non_empty_argument() {
        assert_eq!(render("coalesce", &[s(""), s(""), s("value")]), "value");
        assert_eq!(render("coalesce", &[]), "<no value>");
        // Every argument empty answers the last one, as `?? Arguments[^1]` does.
        assert_eq!(render("coalesce", &[s(""), s("")]), "");
        assert_eq!(render("coalesce", &[n(0.0), n(5.0)]), "5");
        // The answer keeps its type rather than becoming a string.
        assert_eq!(
            ok(
                "coalesce",
                &[Value::List(Vec::new()), Value::List(vec![s("a")])]
            ),
            Value::List(vec![s("a")])
        );
    }

    // Fixtures: `{{ all "a" "b" }}` is `true` and `{{ all }}` is `true`, while
    // `{{ any "" "b" }}` is `true` and `{{ any }}` is `false`. Neither helper
    // checks its argument count, so both accept none.
    #[test]
    fn all_and_any_take_any_number_of_arguments() {
        assert_eq!(render("all", &[s("a"), s("b")]), "true");
        assert_eq!(render("all", &[]), "true");
        assert_eq!(render("all", &[s("a"), s("")]), "false");
        assert_eq!(render("any", &[s(""), s("b")]), "true");
        assert_eq!(render("any", &[]), "false");
        assert_eq!(render("any", &[s(""), n(0.0), Value::Null]), "false");
        assert_eq!(render("any", &[s(""), Value::Null, n(1.0)]), "true");
    }

    // Fixture: `{{ ternary "yes" "no" true }}` is `yes`. The condition is the
    // third argument and is read with the same emptiness rule as everywhere
    // else, so a non-empty string that is not `true` still selects the first
    // branch.
    #[test]
    fn ternary_reads_its_condition_from_the_third_argument() {
        assert_eq!(
            render("ternary", &[s("yes"), s("no"), Value::Bool(true)]),
            "yes"
        );
        assert_eq!(
            render("ternary", &[s("yes"), s("no"), Value::Bool(false)]),
            "no"
        );
        assert_eq!(render("ternary", &[s("yes"), s("no"), s("")]), "no");
        assert_eq!(render("ternary", &[n(1.0), n(2.0), s("x")]), "1");
    }

    // No fixture covers a failing render, so these are the reference's
    // `Fail`: exactly one argument, whose rendering becomes the message, and
    // the render stops.
    #[test]
    fn fail_and_required_stop_the_render() {
        for name in ["fail", "required"] {
            let message = error(name, &[s("a required value is missing")]);
            assert!(
                message.to_string().contains("a required value is missing"),
                "{name}: {message}"
            );
            // A number is rendered into the message, since `S(i, 0)` renders.
            let numbered = error(name, &[n(42.0)]);
            assert!(numbered.to_string().contains("42"), "{name}: {numbered}");
            assert!(error(name, &[]).to_string().contains("expects 1"), "{name}");
            assert!(
                error(name, &[s("a"), s("b")])
                    .to_string()
                    .contains("expects 1"),
                "{name}"
            );
        }
    }

    #[test]
    fn wrong_argument_counts_are_reported() {
        assert!(error("default", &[]).to_string().contains("at least 1"));
        assert!(error("empty", &[]).to_string().contains("expects 1"));
        assert!(
            error("ternary", &[s("a"), s("b")])
                .to_string()
                .contains("expects 3")
        );
    }

    #[test]
    fn this_module_never_takes_rendered_strings() {
        for name in [
            "default", "empty", "coalesce", "all", "any", "fail", "ternary", "required",
        ] {
            assert!(!super::takes_rendered_strings(name), "{name}");
        }
    }

    #[test]
    fn a_name_from_another_module_is_not_claimed() {
        assert!(DISPATCH("trim", &[], &Context::default()).is_none());
    }
}
