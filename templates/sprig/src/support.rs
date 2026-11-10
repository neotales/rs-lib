//! Argument coercion shared by the helper modules.
//!
//! Go's Sprig helpers are loose about types: `toInt64` accepts a numeric string,
//! `upper` calls `fmt.Sprint` on whatever it is given, and a list helper accepts
//! a scalar as a one-element list. Reproducing that looseness in one place is
//! what keeps each helper's own code about its actual behavior.

use crate::{Error, Value};

/// Renders an argument the way Go's `fmt.Sprint` would for a string helper.
///
/// A list and a map are refused rather than rendered, because `upper (list 1 2)`
/// has no Go equivalent that does something sensible, and printing the
/// structural form would look like a result.
pub(crate) fn text(helper: &str, value: &Value) -> Result<String, Error> {
    match value {
        Value::List(_) | Value::Map(_) => Err(crate::invalid(
            helper,
            "expects a string, number, or boolean argument",
        )),
        other => Ok(other.render()),
    }
}

/// Renders an argument as a string without refusing collections.
pub(crate) fn any_text(value: &Value) -> String {
    value.render()
}

/// Coerces an argument to a signed integer, following Go's rules.
pub(crate) fn integer(helper: &str, value: &Value) -> Result<i64, Error> {
    match value {
        // Go's `toInt64` truncates toward zero rather than refusing a value that
        // is not a whole number, so `{{ int 102.9 }}` is `102`. Refusing here
        // would reject a call the reference accepts.
        #[allow(clippy::cast_possible_truncation)]
        Value::Number(number) | Value::Float(number) => Ok(*number as i64),
        Value::Bool(flag) => Ok(i64::from(*flag)),
        Value::String(text) => {
            let trimmed = text.trim();
            trimmed.parse::<i64>().map_err(|_| {
                crate::invalid(helper, format!("cannot read {trimmed:?} as an integer"))
            })
        }
        other => Err(crate::invalid(
            helper,
            format!("cannot read {} as an integer", other.render()),
        )),
    }
}

/// Coerces an argument to a float, following Go's rules.
pub(crate) fn float(helper: &str, value: &Value) -> Result<f64, Error> {
    match value {
        Value::Number(number) | Value::Float(number) => Ok(*number),
        Value::Bool(flag) => Ok(if *flag { 1.0 } else { 0.0 }),
        Value::String(text) => text.trim().parse::<f64>().map_err(|_| {
            crate::invalid(helper, format!("cannot read {:?} as a number", text.trim()))
        }),
        other => Err(crate::invalid(
            helper,
            format!("cannot read {} as a number", other.render()),
        )),
    }
}

/// Coerces an argument to a list, accepting a scalar as one element.
pub(crate) fn list(value: &Value) -> Vec<Value> {
    value.as_list()
}

/// Coerces an argument to a map, refusing anything else.
pub(crate) fn map<'a>(
    helper: &str,
    value: &'a Value,
) -> Result<&'a std::collections::BTreeMap<String, Value>, Error> {
    match value {
        Value::Map(entries) => Ok(entries),
        other => Err(crate::invalid(
            helper,
            format!("expects a map, received {}", other.render()),
        )),
    }
}

/// Renders a `[]string` the way Go's `strings.Join` and `toStrings` do.
pub(crate) fn join_strings(values: &[Value], separator: &str) -> String {
    values
        .iter()
        .map(Value::render)
        .collect::<Vec<_>>()
        .join(separator)
}

#[cfg(test)]
mod tests {
    use super::{float, integer, join_strings, list, text};
    use crate::Value;

    #[test]
    fn an_integer_is_read_from_a_number_a_bool_or_a_numeric_string() {
        assert_eq!(integer("x", &Value::Number(42.0)), Ok(42));
        assert_eq!(integer("x", &Value::Float(42.9)), Ok(42));
        assert_eq!(integer("x", &Value::Bool(true)), Ok(1));
        assert_eq!(integer("x", &Value::String(" 42 ".to_owned())), Ok(42));
        assert!(integer("x", &Value::String("neo".to_owned())).is_err());
    }

    #[test]
    fn a_float_is_read_the_same_way_and_keeps_its_fraction() {
        assert_eq!(float("x", &Value::Float(1.5)), Ok(1.5));
        assert_eq!(float("x", &Value::Bool(false)), Ok(0.0));
        assert_eq!(float("x", &Value::String(" 1.5 ".to_owned())), Ok(1.5));
        assert!(float("x", &Value::Null).is_err());
    }

    /// A collection is refused by `text` rather than rendered, because a
    /// rendered list would look like a plausible string result.
    #[test]
    fn a_collection_is_refused_where_a_string_is_wanted() {
        let list_value = Value::List(vec![Value::String("a".to_owned())]);
        assert!(text("x", &list_value).is_err());
        assert_eq!(
            text("x", &Value::String("a".to_owned())),
            Ok("a".to_owned())
        );
        assert_eq!(text("x", &Value::Number(1.0)), Ok("1".to_owned()));
    }

    #[test]
    fn a_scalar_is_a_one_element_list() {
        assert_eq!(list(&Value::String("a".to_owned())).len(), 1);
        assert_eq!(list(&Value::List(vec![Value::Null])).len(), 1);
    }

    #[test]
    fn strings_join_with_the_given_separator() {
        let values = vec![Value::String("a".to_owned()), Value::String("b".to_owned())];
        assert_eq!(join_strings(&values, "/"), "a/b");
        assert_eq!(join_strings(&values, " "), "a b");
    }
}
