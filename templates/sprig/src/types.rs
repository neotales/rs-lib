//! Type reflection and length.
//!
//! The reference registers six names onto two methods: `kindOf`, `kindIs`,
//! `typeOf`, `typeIs`, and `typeIsLike` all read the same `Kind` string, and
//! `typeIs` and `typeIsLike` compare it for equality rather than by prefix.
//! `typeIsLike` in upstream Masterminds Sprig is a prefix match; here it is
//! `KindIs`, as the reference spells it, so `typeIsLike "sl" $list` is false.
//!
//! `len` is not a Sprig helper at all — it is Go's `text/template` builtin,
//! which the reference inherits from its own engine. This crate has to supply
//! it itself, and it reports the length Go's `length` function reports: the
//! byte length of a string, the number of elements of a list or a map, and
//! zero for anything else.

use crate::support::any_text;
use crate::{Context, Error, Value, arity};

/// Dispatches a types helper.
pub(super) const DISPATCH: crate::Dispatch =
    |name, arguments, context| dispatch(name, arguments, context);

#[allow(clippy::trivially_copy_pass_by_ref)]
fn dispatch(
    name: &str,
    arguments: &[Value],
    context: &Context<'_>,
) -> Option<Result<Value, Error>> {
    call(name, arguments, *context)
}

/// Runs this module's helper by name.
///
/// `None` means the name is not one of this module's, so the next module is
/// tried; `Some(Err)` means it is one of them and the call was refused.
fn call(name: &str, arguments: &[Value], _context: Context<'_>) -> Option<Result<Value, Error>> {
    let result = match name {
        "kindOf" | "typeOf" => kind_of(name, arguments),
        "kindIs" | "typeIs" | "typeIsLike" => kind_is(name, arguments),
        "len" => length(name, arguments),
        _ => return None,
    };
    Some(result)
}

/// Reports whether this module's helper wants rendered string arguments.
///
/// Nothing here does: a helper that reports a *type* has to be able to tell a
/// boolean from the four characters `true`, so it must receive the value rather
/// than a rendering of it.
pub(super) fn takes_rendered_strings(_name: &str) -> bool {
    false
}

/// Implements `KindOf`, which `typeOf` is registered to in the reference.
fn kind_of(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    arity(name, arguments.len(), 1, Some(1))?;
    Ok(Value::String(kind(&arguments[0]).to_owned()))
}

/// Implements `KindIs`, which `typeIs` and `typeIsLike` are registered to.
fn kind_is(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    arity(name, arguments.len(), 2, Some(2))?;
    let expected = any_text(&arguments[0]);
    Ok(Value::Bool(expected == kind(&arguments[1])))
}

/// Implements `len`, Go's `text/template` builtin.
///
/// A string reports its length in bytes, which is what Go's `reflect.Value.Len`
/// returns and what Rust's own `str::len` returns, so a multi-byte character
/// counts as its bytes. A number, a boolean, and a null have no length in Go and
/// report zero here rather than failing, because a template measuring something
/// that has no length wants a zero and not a diagnostic.
fn length(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    arity(name, arguments.len(), 1, Some(1))?;
    let length = match &arguments[0] {
        Value::String(value) => value.len(),
        Value::List(values) => values.len(),
        Value::Map(values)
        | Value::Object {
            members: values, ..
        } => values.len(),
        // A method is something to call rather than something with a length, and
        // neither is a number, a boolean, or a null.
        Value::Method { .. }
        | Value::Number(_)
        | Value::Float(_)
        | Value::Bool(_)
        | Value::Null => 0,
    };
    // A length is a count of elements or of bytes, so it is never anywhere near
    // the point where an `f64` would stop representing it exactly.
    #[allow(clippy::cast_precision_loss)]
    Ok(Value::Number(length as f64))
}

/// Returns the name the reference's `Kind` gives a value.
///
/// The spellings are the reference's and not Go's: a list is `slice` rather than
/// `[]interface {}`, a map is `map` rather than `map[string]interface {}`, and
/// an integer is `int` rather than `int64`.
fn kind(value: &Value) -> &'static str {
    match value {
        Value::String(_) => "string",
        Value::Bool(_) => "bool",
        // This is the one place the int/float distinction is observable, and it
        // is why `Value` has two numeric variants: the reference decides from the
        // number's own spelling, so a value that came from `1.0` reports
        // `float64` and one that came from `1` reports `int`.
        Value::Number(_) => "int",
        Value::Float(_) => "float64",
        Value::List(_) => "slice",
        Value::Map(_) => "map",
        // The reference's `Kind` switch has no arm for an object or for a value
        // that is a method, so both fall through the same way a null does.
        // The reference's switch has no arm for an object, for a method, or for
        // a null, so all three fall through to "invalid" — Go would write
        // `<nil>` for the last of them.
        Value::Object { .. } | Value::Method { .. } | Value::Null => "invalid",
    }
}

#[cfg(test)]
mod tests {
    use super::DISPATCH;
    use crate::{Context, Error, Value};
    use std::slice;

    fn s(value: &str) -> Value {
        Value::String(value.to_owned())
    }

    fn n(value: f64) -> Value {
        Value::Number(value)
    }

    /// A value that was written as a float, so `kindOf` reports `float64`.
    fn f(value: f64) -> Value {
        Value::Float(value)
    }

    /// Calls a helper and renders the result the way a template would write it.
    fn render(name: &str, arguments: &[Value]) -> String {
        ok(name, arguments).render()
    }

    fn ok(name: &str, arguments: &[Value]) -> Value {
        match super::call(name, arguments, Context::default()) {
            Some(Ok(value)) => value,
            Some(Err(error)) => panic!("{name} returned an error: {error}"),
            None => panic!("{name} is not a types helper"),
        }
    }

    fn error(name: &str, arguments: &[Value]) -> Error {
        match super::call(name, arguments, Context::default()) {
            Some(Err(error)) => error,
            Some(Ok(value)) => panic!("{name} unexpectedly returned {}", value.render()),
            None => panic!("{name} is not a types helper"),
        }
    }

    // Fixtures: `{{ typeOf (list "value") }}|{{ kindOf (list "value") }}` is
    // `slice|slice` and `{{ typeOf "text" }}` is `string`, so the two names are
    // the same method. `{{ kindOf "text" }}` is `string`,
    // `{{ kindOf true }}` is `bool`, `{{ $value := list "one" }}{{ kindOf $value }}`
    // is `slice`, and `{{ $value := dict "one" "1" }}{{ kindOf $value }}` is
    // `map`.
    #[test]
    fn type_of_and_kind_of_read_the_same_names() {
        let list = Value::List(vec![s("value")]);
        assert_eq!(render("typeOf", slice::from_ref(&list)), "slice");
        assert_eq!(render("kindOf", &[list]), "slice");
        assert_eq!(render("typeOf", &[s("text")]), "string");
        assert_eq!(render("kindOf", &[s("text")]), "string");
        assert_eq!(render("kindOf", &[Value::Bool(true)]), "bool");
        assert_eq!(render("kindOf", &[Value::List(vec![s("one")])]), "slice");
        assert_eq!(
            render("kindOf", &[Value::Map([("one".to_owned(), s("1"))].into())]),
            "map"
        );
        // The reference's `Kind` switch has no arm for a null.
        assert_eq!(render("kindOf", &[Value::Null]), "invalid");
    }

    // Fixtures: `{{ kindOf 42 }}` is `int`, `{{ kindOf 4.2 }}` is `float64`, and
    // `{{ $value := addf 1.0 2.0 }}{{ kindOf $value }}` is `float64`.
    //
    // The distinction comes from *how the value was written*, not from how it
    // renders. Deciding it from the rendering was wrong in both directions: the
    // sum of two floats is `3.0` and would have read as an int, while an integer
    // that happens to render in scientific notation would have read as a float.
    #[test]
    fn a_number_is_a_float_only_when_it_was_written_as_one() {
        assert_eq!(render("kindOf", &[n(42.0)]), "int");
        assert_eq!(render("kindOf", &[n(3.0)]), "int");
        assert_eq!(render("kindOf", &[n(-7.0)]), "int");
        assert_eq!(render("kindOf", &[f(4.2)]), "float64");
        assert_eq!(render("kindOf", &[f(0.5)]), "float64");
        // A large *integer* stays an integer even though Go writes it as `1e+06`.
        assert_eq!(render("kindOf", &[n(1_000_000.0)]), "int");
        // A whole float is still a float: `addf 1.0 2.0` is `3.0`.
        assert_eq!(render("kindOf", &[f(3.0)]), "float64");
        // A number written as a string is a string, not a number.
        assert_eq!(render("kindOf", &[s("42")]), "string");
    }

    // Fixture: `{{ kindIs "string" "text" }}` is `true`,
    // `{{ $value := dict "one" "1" }}{{ kindIs "map" $value }}` is `true`,
    // `{{ typeIs "bool" true }}` is `true`, and
    // `{{ $value := list "one" }}{{ typeIsLike "slice" $value }}` is `true`.
    #[test]
    fn type_is_and_kind_is_compare_the_name_for_equality() {
        assert_eq!(render("kindIs", &[s("string"), s("text")]), "true");
        assert_eq!(
            render(
                "kindIs",
                &[s("map"), Value::Map([("one".to_owned(), s("1"))].into())]
            ),
            "true"
        );
        assert_eq!(render("typeIs", &[s("bool"), Value::Bool(true)]), "true");
        assert_eq!(
            render("typeIsLike", &[s("slice"), Value::List(vec![s("one")])]),
            "true"
        );
        assert_eq!(render("kindIs", &[s("int"), s("text")]), "false");
        // `typeIsLike` is registered to `KindIs`, so it is an exact comparison
        // here and a prefix match is false.
        assert_eq!(
            render("typeIsLike", &[s("sl"), Value::List(vec![s("one")])]),
            "false"
        );
    }

    // Fixture: `{{ $items := tuple 1 2 3 }}{{ append $items 4 | len }}` is 4,
    // and `{{ len "two" | plural "1 char" "chars" }}` is `chars` because the
    // string is three bytes long.
    #[test]
    fn len_counts_strings_lists_and_maps() {
        assert_eq!(render("len", &[s("two")]), "3");
        assert_eq!(render("len", &[s("")]), "0");
        assert_eq!(
            render("len", &[Value::List(vec![n(1.0), n(2.0), n(3.0), n(4.0)])]),
            "4"
        );
        assert_eq!(render("len", &[Value::List(Vec::new())]), "0");
        assert_eq!(
            render("len", &[Value::Map([("a".to_owned(), s("1"))].into())]),
            "1"
        );
        // A multi-byte character counts as its bytes, as `reflect.Value.Len` does.
        assert_eq!(render("len", &[s("☃")]), "3");
        // Anything else has no length, which Go's `length` refuses and this
        // helper reports as zero.
        assert_eq!(render("len", &[n(42.0)]), "0");
        assert_eq!(render("len", &[Value::Bool(true)]), "0");
        assert_eq!(render("len", &[Value::Null]), "0");
    }

    #[test]
    fn wrong_argument_counts_are_reported() {
        assert!(error("typeOf", &[]).to_string().contains("expects 1"));
        assert!(
            error("kindIs", &[s("string")])
                .to_string()
                .contains("expects 2")
        );
        assert!(error("len", &[]).to_string().contains("expects 1"));
    }

    #[test]
    fn this_module_never_takes_rendered_strings() {
        for name in ["typeOf", "typeIs", "typeIsLike", "kindOf", "kindIs", "len"] {
            assert!(!super::takes_rendered_strings(name), "{name}");
        }
    }

    #[test]
    fn a_name_from_another_module_is_not_claimed() {
        assert!(DISPATCH("toJson", &[], &Context::default()).is_none());
    }
}
