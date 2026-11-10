//! List helpers: building a list, taking it apart, and counting into one.
//!
//! The behavior is the reference implementation's, read out of
//! `SprigFunctions.cs` — `List`, `First`, `Last`, `Rest`, `Initial`,
//! `Reverse`, `Concat`, `Has`, `Without`, `Compact`, `Uniq`, `Append`,
//! `Prepend`, `Join`, `SortAlpha`, `SliceRange`, `Chunk`, `Seq`, `Until`, and
//! `UntilStep`, plus the `L`, `End`, `Slice`, `ListWithOthers`, and `Numbers`
//! helpers they are written in terms of. Where the reference's spelling differs
//! from what the helper's name suggests, the reference wins: `join` and
//! `append` each take exactly two arguments, `push` is `append` under a second
//! name, and `seq` answers a space-separated *string* rather than a list.
//!
//! One coercion is looser than the reference's `L`, which refuses an argument
//! that is not a list. Here a scalar is a one-element list, which is
//! `Value::as_list`'s documented contract and what makes `append "a" "b"` and
//! `append (list "a") "b"` spell the same two-element list.

use crate::support::{any_text, integer, join_strings, list as list_of};
use crate::{Context, Error, Value, arity, invalid};

/// Dispatches a lists helper.
pub(super) const DISPATCH: crate::Dispatch =
    |name, arguments, context| dispatch(name, arguments, context);

/// The most values a counting helper will produce.
///
/// `Numbers` in the reference is unbounded, so `{{ until 1000000000 }}` there
/// allocates a billion numbers before the template engine's render budget ever
/// sees it. A template is input rather than a trusted program, so the count is
/// bounded here and a longer run is reported as a bad argument instead of
/// exhausting memory. No template that means anything sequences past a million
/// values.
const MAX_SEQUENCE: usize = 1_000_000;

#[allow(clippy::trivially_copy_pass_by_ref)]
fn dispatch(
    name: &str,
    arguments: &[Value],
    context: &Context<'_>,
) -> Option<Result<Value, Error>> {
    // No list helper reads the call site; the parameter is part of the
    // signature every module shares.
    let _ = context;
    call(name, arguments)
}

fn call(name: &str, arguments: &[Value]) -> Option<Result<Value, Error>> {
    let result = match name {
        // `List` collects its arguments into a list and checks nothing about
        // them, so zero arguments is an empty list rather than an error.
        "list" | "tuple" => Ok(Value::List(arguments.to_vec())),
        // `End` answers null for an empty list, which is what makes
        // `{{ first (list) }}` render `<no value>` instead of failing.
        "first" => one(name, arguments, |values| values.first().cloned()),
        "last" => one(name, arguments, |values| values.last().cloned()),
        "rest" => transform(name, arguments, |values| {
            values.into_iter().skip(1).collect()
        }),
        // `Take(Math.Max(0, x.Count - 1))` keeps every element of a one-element
        // list, because dropping the last of one leaves nothing.
        "initial" => transform(name, arguments, |values| {
            let kept = values.len().saturating_sub(1);
            values.into_iter().take(kept).collect()
        }),
        "reverse" => transform(name, arguments, |mut values| {
            values.reverse();
            values
        }),
        "compact" => transform(name, arguments, |values| {
            values
                .into_iter()
                .filter(|value| !value.is_empty())
                .collect()
        }),
        // `Uniq` keeps the first of each equal run, so order is first-seen.
        "uniq" => transform(name, arguments, |values| {
            let mut seen: Vec<Value> = Vec::new();
            for value in values {
                if !seen.contains(&value) {
                    seen.push(value);
                }
            }
            seen
        }),
        "append" | "push" => append(name, arguments),
        "prepend" => prepend(name, arguments),
        "concat" => concat(name, arguments),
        "has" => has(name, arguments),
        "without" => without(name, arguments),
        "join" => join(name, arguments),
        "sortAlpha" => sort_alpha(name, arguments),
        "slice" => slice(name, arguments),
        "chunk" => chunk(name, arguments),
        "seq" => seq(name, arguments),
        "until" => until(name, arguments),
        "untilStep" => until_step(name, arguments),
        _ => return None,
    };
    Some(result)
}

/// Reports whether this module's helper wants rendered string arguments.
///
/// Every helper here inspects or returns a collection, so all of them want the
/// typed value: a list helper handed `"[a b]"` would see one string where it
/// needs two elements, and `default`-style emptiness would be unanswerable.
pub(super) fn takes_rendered_strings(name: &str) -> bool {
    let _ = name;
    false
}

/// Implements `first` and `last`: one argument, one element or null.
fn one(
    name: &str,
    arguments: &[Value],
    pick: impl Fn(&[Value]) -> Option<Value>,
) -> Result<Value, Error> {
    arity(name, arguments.len(), 1, Some(1))?;
    Ok(pick(&list_of(&arguments[0])).unwrap_or(Value::Null))
}

/// Implements the helpers `Slice` writes: one argument, a list out.
fn transform(
    name: &str,
    arguments: &[Value],
    apply: impl FnOnce(Vec<Value>) -> Vec<Value>,
) -> Result<Value, Error> {
    arity(name, arguments.len(), 1, Some(1))?;
    Ok(Value::List(apply(list_of(&arguments[0]))))
}

/// Implements `Append`, which `push` is registered to in the reference.
///
/// `Count("append", i, 2)` and `L` on the first argument, so both spellings
/// take exactly two arguments with the list first and the item second. `push`
/// is not a second helper here, it is this one under a second name, which is
/// what the fixture `{{ push (list 1) 2 }}` renders as `[1 2]`.
fn append(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    arity(name, arguments.len(), 2, Some(2))?;
    let mut values = list_of(&arguments[0]);
    values.push(arguments[1].clone());
    Ok(Value::List(values))
}

/// Implements `Prepend`: the new element first, then the list.
fn prepend(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    arity(name, arguments.len(), 2, Some(2))?;
    let mut values = vec![arguments[1].clone()];
    values.extend(list_of(&arguments[0]));
    Ok(Value::List(values))
}

/// Implements `Concat`, which flattens one level of every argument.
fn concat(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    arity(name, arguments.len(), 1, None)?;
    Ok(Value::List(arguments.iter().flat_map(list_of).collect()))
}

/// Implements `Has`: membership, comparing values the way `Equal` does.
fn has(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    arity(name, arguments.len(), 2, Some(2))?;
    if arguments[1] == Value::Null {
        return Ok(Value::Bool(false));
    }
    Ok(Value::Bool(list_of(&arguments[1]).contains(&arguments[0])))
}

/// Implements `Without`, which is written in terms of `ListWithOthers`.
///
/// The reference takes the *first* argument that is a list as the list and
/// treats every other argument — including a second list — as an item to
/// remove. With no list at all it is an error, which is the one place this
/// module keeps `L`'s strictness, because a `without` with no list has no
/// answer to give.
fn without(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    arity(name, arguments.len(), 1, None)?;
    let index = arguments
        .iter()
        .position(|argument| matches!(argument, Value::List(_)))
        .ok_or_else(|| invalid(name, "expects a list argument"))?;
    let excluded: Vec<&Value> = arguments
        .iter()
        .enumerate()
        .filter(|(position, _)| *position != index)
        .map(|(_, argument)| argument)
        .collect();
    let Value::List(values) = &arguments[index] else {
        return Err(invalid(name, "expects a list argument"));
    };
    Ok(Value::List(
        values
            .iter()
            .filter(|value| !excluded.contains(value))
            .cloned()
            .collect(),
    ))
}

/// Implements `Join`.
///
/// A list argument joins its rendered elements, skipping nulls the way
/// `values.Where(static x => !x.IsNull)` does. A null argument is the empty
/// string and any other scalar is its own text, which is what makes
/// `join ", " (split "," .name)` work on a field that is not a list.
fn join(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    arity(name, arguments.len(), 2, Some(2))?;
    let separator = any_text(&arguments[0]);
    let values = match &arguments[1] {
        Value::List(values) => values,
        Value::Null => return Ok(Value::String(String::new())),
        other => return Ok(Value::String(any_text(other))),
    };
    let present: Vec<Value> = values
        .iter()
        .filter(|value| !matches!(value, Value::Null))
        .cloned()
        .collect();
    Ok(Value::String(join_strings(&present, &separator)))
}

/// Implements `SortAlpha`, ordering by rendered text with `StringComparer.Ordinal`.
///
/// Rust's `String` ordering is a byte-wise comparison, which is what ordinal
/// means, so `sortAlpha` sorts exactly as the reference does.
fn sort_alpha(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    arity(name, arguments.len(), 1, Some(1))?;
    let Value::List(values) = &arguments[0] else {
        // A scalar answers with a one-element list of its text, not with itself.
        return Ok(Value::List(vec![Value::String(any_text(&arguments[0]))]));
    };
    let mut sorted = values.clone();
    sorted.sort_by_cached_key(Value::render);
    Ok(Value::List(sorted))
}

/// Implements `SliceRange`, Go's half-open `s[low:high]`.
///
/// Both bounds are clamped into the list — a negative index becomes zero, and
/// a bound past the end becomes the length — so `slice $items 1 99` is the
/// tail rather than an error.
fn slice(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    arity(name, arguments.len(), 1, Some(3))?;
    let values = list_of(&arguments[0]);
    let length = i64::try_from(values.len()).unwrap_or(i64::MAX);
    let start = if arguments.len() == 1 {
        0
    } else {
        integer(name, &arguments[1])?.clamp(0, length)
    };
    let end = if arguments.len() == 3 {
        integer(name, &arguments[2])?.clamp(start, length)
    } else {
        length
    };
    let start = usize::try_from(start).unwrap_or(0);
    let end = usize::try_from(end).unwrap_or(values.len());
    Ok(Value::List(values[start..end].to_vec()))
}

/// Implements `Chunk`, which refuses a size below one instead of looping.
fn chunk(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    arity(name, arguments.len(), 2, Some(2))?;
    let size = integer(name, &arguments[0])?;
    if size < 1 {
        return Err(invalid(name, "expects a positive chunk size"));
    }
    let size = usize::try_from(size).unwrap_or(usize::MAX);
    let values = list_of(&arguments[1]);
    Ok(Value::List(
        values
            .chunks(size)
            .map(<[Value]>::to_vec)
            .map(Value::List)
            .collect(),
    ))
}

/// Implements `Seq`, which answers a space-separated string.
///
/// The reference returns a string, so `{{ seq 2 6 }}` is `2 3 4 5 6` and
/// `{{ seq 2 6 | len }}` counts those nine characters. Anything but one to
/// three arguments is the empty string rather than an error, which is what
/// makes `{{ seq }}` and `{{ seq 0 1 2 3 }}` render nothing at all.
fn seq(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    // Not an arity error: `Seq` answers the empty string for anything but one
    // to three arguments, and two fixtures write exactly that.
    if !(1..=3).contains(&arguments.len()) {
        return Ok(Value::String(String::new()));
    }
    let single = arguments.len() == 1;
    let start = if single {
        1
    } else {
        integer(name, &arguments[0])?
    };
    let end = integer(name, &arguments[arguments.len() - 1])?;
    let step = if arguments.len() == 3 {
        integer(name, &arguments[1])?
    } else if start <= end {
        1
    } else {
        -1
    };
    if step == 0 || (end > start && step < 0) || (end < start && step > 0) {
        return Ok(Value::String(String::new()));
    }
    // The walk is the shape of `NumbersInclusive`, so the end value is included
    // when the step lands on it and the walk stops one step past it otherwise.
    let mut values: Vec<String> = Vec::new();
    let mut value = start;
    while if step > 0 { value <= end } else { value >= end } {
        if values.len() == MAX_SEQUENCE {
            return Err(sequence_too_long(name));
        }
        values.push(value.to_string());
        value = value.saturating_add(step);
    }
    Ok(Value::String(values.join(" ")))
}

/// Implements `Until`, which counts from zero up to but excluding its argument.
fn until(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    arity(name, arguments.len(), 1, Some(1))?;
    let stop = integer(name, &arguments[0])?;
    numbers(name, 0, stop, if stop < 0 { -1 } else { 1 })
}

/// Implements `UntilStep`, which counts from `start` up to but excluding `stop`.
///
/// A zero step is the empty list rather than a walk that never moves.
fn until_step(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    arity(name, arguments.len(), 3, Some(3))?;
    let start = integer(name, &arguments[0])?;
    let stop = integer(name, &arguments[1])?;
    let stride = integer(name, &arguments[2])?;
    if stride == 0 {
        return Ok(Value::List(Vec::new()));
    }
    numbers(name, start, stop, stride)
}

/// Implements `Numbers`: `start` up to but excluding `stop`, stepping by `step`.
///
/// The caller has already rejected a zero step, which is what `UntilStep` does
/// before it gets here, so the walk always moves. The step is saturated rather
/// than added so that a run that would pass the largest `i64` stops instead of
/// overflowing.
#[allow(clippy::cast_precision_loss)] // A count of at most a million is exact in an `f64`.
fn numbers(name: &str, start: i64, stop: i64, stride: i64) -> Result<Value, Error> {
    let mut values: Vec<Value> = Vec::new();
    let mut value = start;
    while if stride > 0 {
        value < stop
    } else {
        value > stop
    } {
        if values.len() == MAX_SEQUENCE {
            return Err(sequence_too_long(name));
        }
        values.push(Value::Number(value as f64));
        value = value.saturating_add(stride);
    }
    Ok(Value::List(values))
}

/// Reports a counting helper that was asked for more values than [`MAX_SEQUENCE`].
fn sequence_too_long(name: &str) -> Error {
    invalid(
        name,
        format!("refuses to count more than {MAX_SEQUENCE} values"),
    )
}

#[cfg(test)]
mod tests {
    use super::{DISPATCH, MAX_SEQUENCE};
    use crate::{Context, Error, Value};
    use std::slice;

    fn s(value: &str) -> Value {
        Value::String(value.to_owned())
    }

    fn n(value: f64) -> Value {
        Value::Number(value)
    }

    fn l(values: &[Value]) -> Value {
        Value::List(values.to_vec())
    }

    /// Calls a helper and renders the result the way a template would write it.
    fn render(name: &str, arguments: &[Value]) -> String {
        ok(name, arguments).render()
    }

    fn ok(name: &str, arguments: &[Value]) -> Value {
        match super::call(name, arguments) {
            Some(Ok(value)) => value,
            Some(Err(error)) => panic!("{name} returned an error: {error}"),
            None => panic!("{name} is not a lists helper"),
        }
    }

    fn error(name: &str, arguments: &[Value]) -> Error {
        match super::call(name, arguments) {
            Some(Err(error)) => error,
            Some(Ok(value)) => panic!("{name} unexpectedly returned {}", value.render()),
            None => panic!("{name} is not a lists helper"),
        }
    }

    // Fixture: `{{ $items := tuple 1 "a" "foo" }}` and then three `index`
    // calls, which this crate has no builtin for. The list the template builds
    // is what is checked here.
    #[test]
    fn tuple_and_list_collect_their_arguments() {
        assert_eq!(render("tuple", &[n(1.0), s("a"), s("foo")]), "[1 a foo]");
        // Fixture: `{{ list 1 0 "" "hello" | compact }}` starts from this list.
        assert_eq!(
            render("list", &[n(1.0), n(0.0), s(""), s("hello")]),
            "[1 0  hello]"
        );
        // `List` checks nothing about its arguments, so none is an empty list.
        assert_eq!(render("list", &[]), "[]");
    }

    // Fixtures: `{{ $items := tuple 1 2 3 }}{{ append $items 4 | len }}` is 4,
    // `{{ $items := list "a" "b" "c" }}{{ append $items "d" | join "-" }}` is
    // `a-b-c-d`, and `{{ push (list 1) 2 }}` is `[1 2]`.
    #[test]
    fn append_and_push_take_the_list_first() {
        assert_eq!(
            render("append", &[l(&[n(1.0), n(2.0), n(3.0)]), n(4.0)]),
            "[1 2 3 4]"
        );
        assert_eq!(
            render("append", &[l(&[s("a"), s("b"), s("c")]), s("d")]),
            "[a b c d]"
        );
        // `push` is registered to `Append` in the reference, so it is `append`.
        assert_eq!(render("push", &[l(&[n(1.0)]), n(2.0)]), "[1 2]");
        // The first argument is a scalar, which `as_list` reads as one element.
        assert_eq!(render("append", &[s("a"), s("b")]), "[a b]");
    }

    // Fixtures: `{{ $items := tuple 1 2 3 4 }}{{ prepend $items 0 | join "-" }}`
    // is `0-1-2-3-4` and `{{ $items := list "a" "b" "c" }}{{ prepend $items "z"
    // | join "-" }}` is `z-a-b-c`. `Prepend` puts the new element before the
    // whole list, and the second half of each fixture is `join` over the result.
    #[test]
    fn prepend_puts_the_element_before_the_list() {
        assert_eq!(
            render("prepend", &[l(&[n(1.0), n(2.0), n(3.0), n(4.0)]), n(0.0)]),
            "[0 1 2 3 4]"
        );
        assert_eq!(
            render("prepend", &[l(&[s("a"), s("b"), s("c")]), s("z")]),
            "[z a b c]"
        );
    }

    // Fixtures: `{{ $items := list "a" "b" "c" }}{{ slice $items }}` is
    // `[a b c]` and `{{ slice $items 1 3 }}` is `[b c]`.
    #[test]
    fn slice_takes_a_half_open_range() {
        let items = l(&[s("a"), s("b"), s("c")]);
        assert_eq!(render("slice", slice::from_ref(&items)), "[a b c]");
        assert_eq!(render("slice", &[items.clone(), n(1.0), n(3.0)]), "[b c]");
        // `Math.Clamp` pulls both bounds into the list: a low below zero is
        // zero and a high past the end is the length.
        assert_eq!(render("slice", &[items.clone(), n(-1.0), n(2.0)]), "[a b]");
        assert_eq!(render("slice", &[items.clone(), n(1.0), n(99.0)]), "[b c]");
        assert_eq!(render("slice", &[items, n(0.0), n(0.0)]), "[]");
    }

    // Fixtures: `{{ $items := list "a" "b" "c" "d" "e" }}{{ chunk 2 $items }}`
    // is `[[a b] [c d] [e]]` and
    // `{{ tuple 1 2 3 4 5 6 7 | chunk 3 | len }}` is 3.
    #[test]
    fn chunk_splits_into_lists_of_the_given_size() {
        assert_eq!(
            render(
                "chunk",
                &[n(2.0), l(&[s("a"), s("b"), s("c"), s("d"), s("e")])]
            ),
            "[[a b] [c d] [e]]"
        );
        assert_eq!(
            render(
                "chunk",
                &[
                    n(3.0),
                    l(&[n(1.0), n(2.0), n(3.0), n(4.0), n(5.0), n(6.0), n(7.0)])
                ]
            ),
            "[[1 2 3] [4 5 6] [7]]"
        );
        // `Chunk` refuses a size below one instead of walking forever.
        let error = error("chunk", &[n(0.0), l(&[s("a")])]);
        assert!(error.to_string().contains("positive chunk size"), "{error}");
    }

    // Fixtures: `{{ tuple 1 2 3 | initial | last }}` is `2` and
    // `{{ tuple 1 2 3 | rest | first }}` is `2`, so the tails of those two
    // pipelines are spelled out after the slice each one reads.
    #[test]
    fn rest_drops_the_first_and_initial_drops_the_last() {
        let items = l(&[n(1.0), n(2.0), n(3.0)]);
        assert_eq!(render("rest", slice::from_ref(&items)), "[2 3]");
        assert_eq!(render("first", &[l(&[n(2.0), n(3.0)])]), "2");
        assert_eq!(render("initial", slice::from_ref(&items)), "[1 2]");
        assert_eq!(render("last", &[l(&[n(1.0), n(2.0)])]), "2");
        // `Take(Math.Max(0, x.Count - 1))` keeps nothing from a one-element list
        // and `Skip(1)` keeps nothing from a one-element list either.
        let single = l(&[s("a")]);
        assert_eq!(render("initial", slice::from_ref(&single)), "[]");
        assert_eq!(render("rest", &[single]), "[]");
    }

    // Fixture: `{{ tuple 1 2 3 | reverse | first }}` is `3`, so the first of the
    // reversed list is the last of the original.
    #[test]
    fn first_and_last_read_the_two_ends_of_the_list() {
        let items = l(&[n(1.0), n(2.0), n(3.0)]);
        assert_eq!(render("first", slice::from_ref(&items)), "1");
        assert_eq!(render("last", slice::from_ref(&items)), "3");
        assert_eq!(render("reverse", slice::from_ref(&items)), "[3 2 1]");
        // The head of the reversed list, which is what the fixture asks for.
        assert_eq!(render("first", &[l(&[n(3.0), n(2.0), n(1.0)])]), "3");
    }

    #[test]
    fn first_and_last_are_null_for_an_empty_list() {
        // `End` answers null for an empty list rather than failing on it.
        assert_eq!(render("first", &[l(&[])]), "<no value>");
        assert_eq!(render("last", &[l(&[])]), "<no value>");
    }

    // Fixture: `{{ list 1 0 "" "hello" | compact }}` is `[1 hello]`, so the
    // zero number and the empty string both count as empty.
    #[test]
    fn compact_drops_the_empty_values() {
        assert_eq!(
            render("compact", &[l(&[n(1.0), n(0.0), s(""), s("hello")])]),
            "[1 hello]"
        );
        assert_eq!(
            render("compact", &[l(&[Value::Null, Value::Bool(false), s("x")])]),
            "[x]"
        );
    }

    // Fixture: `{{ list 1 1 1 2 2 | uniq }}` is `[1 2]`.
    #[test]
    fn uniq_keeps_the_first_of_each_equal_run() {
        assert_eq!(
            render("uniq", &[l(&[n(1.0), n(1.0), n(1.0), n(2.0), n(2.0)])]),
            "[1 2]"
        );
        assert_eq!(render("uniq", &[l(&[s("b"), s("a"), s("b")])]), "[b a]");
        // A number and its spelling are not equal, which is `Equal`'s kind check.
        assert_eq!(render("uniq", &[l(&[n(1.0), s("1")])]), "[1 1]");
    }

    // Fixtures: `{{ without (list 1 1 2) 1 }}` is `[2]` and
    // `{{ $items := list "a" "b" "a" }}{{ without $items "a" }}` is `[b]`.
    #[test]
    fn without_removes_every_listed_item() {
        assert_eq!(
            render("without", &[l(&[n(1.0), n(1.0), n(2.0)]), n(1.0)]),
            "[2]"
        );
        assert_eq!(
            render("without", &[l(&[s("a"), s("b"), s("a")]), s("a")]),
            "[b]"
        );
        assert_eq!(
            render("without", &[l(&[n(1.0), n(2.0)]), n(1.0), n(2.0)]),
            "[]"
        );
        // `ListWithOthers` searches the arguments for the first list, so a list
        // after the items is still the list.
        assert_eq!(render("without", &[n(1.0), l(&[n(1.0), n(2.0)])]), "[2]");
        // With no list anywhere it is an error, as in the reference.
        let error = error("without", &[n(1.0), n(2.0)]);
        assert!(
            error.to_string().contains("expects a list argument"),
            "{error}"
        );
    }

    // Fixture: `{{ $items := list "a" "b" "a" }}{{ has "b" $items }}` is `true`.
    #[test]
    fn has_tests_membership() {
        let items = l(&[s("a"), s("b"), s("a")]);
        assert_eq!(render("has", &[s("b"), items.clone()]), "true");
        assert_eq!(render("has", &[s("c"), items]), "false");
        // `Has` answers false for a null list rather than failing on it.
        assert_eq!(render("has", &[s("b"), Value::Null]), "false");
    }

    // Fixtures: `{{ concat (list 1 2) (list 3 4) }}` is `[1 2 3 4]` and
    // `{{ concat (list 1 2 3) (list 4 5) (list (list "foo")) }}` is
    // `[1 2 3 4 5 [foo]]`, so a nested list is an element and not a splice.
    #[test]
    fn concat_flattens_one_level() {
        assert_eq!(
            render("concat", &[l(&[n(1.0), n(2.0)]), l(&[n(3.0), n(4.0)])]),
            "[1 2 3 4]"
        );
        assert_eq!(
            render(
                "concat",
                &[
                    l(&[n(1.0), n(2.0), n(3.0)]),
                    l(&[n(4.0), n(5.0)]),
                    l(&[l(&[s("foo")])]),
                ]
            ),
            "[1 2 3 4 5 [foo]]"
        );
        assert_eq!(render("concat", &[l(&[s("a")])]), "[a]");
    }

    // Fixture: `{{ $d := dict "a" 1 "b" 2 }}{{ values $d | sortAlpha | join "," }}`
    // is `1,2`. The list the fixture sorts is the two numbers.
    #[test]
    fn join_and_sort_alpha_write_the_list_out() {
        assert_eq!(render("join", &[s(","), l(&[n(1.0), n(2.0)])]), "1,2");
        assert_eq!(
            render("join", &[s("-"), l(&[s("a"), s("b"), s("c"), s("d")])]),
            "a-b-c-d"
        );
        // `Join` skips a null element and answers a non-list with its own text.
        assert_eq!(
            render("join", &[s(","), l(&[s("a"), Value::Null, s("b")])]),
            "a,b"
        );
        assert_eq!(render("join", &[s(","), s("a")]), "a");
        assert_eq!(render("join", &[s(","), Value::Null]), "");
        // `SortAlpha` orders by rendered text, ordinally.
        assert_eq!(render("sortAlpha", &[l(&[s("b"), s("a")])]), "[a b]");
        assert_eq!(render("sortAlpha", &[l(&[n(2.0), n(1.0)])]), "[1 2]");
        // A scalar answers with a one-element list of its text.
        assert_eq!(render("sortAlpha", &[s("b")]), "[b]");
    }

    // Fixtures: `{{ seq 2 2 6 }}` is `2 4 6`, `{{ seq 0 1 3 }}` is `0 1 2 3`,
    // `{{ seq 0 3 10 }}` is `0 3 6 9`, `{{ seq 3 3 2 }}` is empty,
    // `{{ seq 3 -3 2 }}` is `3`, `{{ seq }}` is empty, `{{ seq -5 }}` is
    // `1 0 -1 -2 -3 -4 -5`, `{{ seq 0 }}` is `1 0`, `{{ seq 0 1 2 3 }}` is
    // empty, and `{{ seq 0 -4 }}` is `0 -1 -2 -3 -4`.
    #[test]
    fn seq_counts_the_way_the_reference_does() {
        assert_eq!(render("seq", &[n(2.0), n(2.0), n(6.0)]), "2 4 6");
        assert_eq!(render("seq", &[n(0.0), n(1.0), n(3.0)]), "0 1 2 3");
        assert_eq!(render("seq", &[n(0.0), n(3.0), n(10.0)]), "0 3 6 9");
        assert_eq!(render("seq", &[n(3.0), n(3.0), n(2.0)]), "");
        assert_eq!(render("seq", &[n(3.0), n(-3.0), n(2.0)]), "3");
        assert_eq!(render("seq", &[]), "");
        assert_eq!(render("seq", &[n(-5.0)]), "1 0 -1 -2 -3 -4 -5");
        assert_eq!(render("seq", &[n(0.0)]), "1 0");
        assert_eq!(render("seq", &[n(0.0), n(1.0), n(2.0), n(3.0)]), "");
        assert_eq!(render("seq", &[n(0.0), n(-4.0)]), "0 -1 -2 -3 -4");
        // Two arguments step by one, descending when the end is below the start.
        assert_eq!(render("seq", &[n(1.0), n(3.0)]), "1 2 3");
        assert_eq!(render("seq", &[n(3.0), n(1.0)]), "3 2 1");
    }

    // Fixtures: `{{ until 5 }}` is `[0 1 2 3 4]` and `{{ untilStep 3 6 2 }}`
    // is `[3 5]`, both excluding the stop, and
    // `{{ untilStep 0 -10 -2 }}` walks `0 -2 -4 -6 -8`.
    #[test]
    fn until_and_until_step_exclude_the_stop() {
        assert_eq!(render("until", &[n(5.0)]), "[0 1 2 3 4]");
        assert_eq!(render("until", &[n(0.0)]), "[]");
        assert_eq!(render("until", &[n(-3.0)]), "[0 -1 -2]");
        assert_eq!(render("untilStep", &[n(3.0), n(6.0), n(2.0)]), "[3 5]");
        assert_eq!(
            render("untilStep", &[n(0.0), n(-10.0), n(-2.0)]),
            "[0 -2 -4 -6 -8]"
        );
        // A zero step is the empty list, not a walk that never moves.
        assert_eq!(render("untilStep", &[n(0.0), n(5.0), n(0.0)]), "[]");
    }

    #[test]
    fn counts_are_bounded() {
        // `{{ until 9007199254740992 }}` has no fixture, and the reference would
        // try to build a list of nine quadrillion numbers before anything could
        // stop it. The bound is reported instead.
        let walk = error("until", &[n(9_007_199_254_740_992.0)]);
        assert!(
            walk.to_string().contains(&MAX_SEQUENCE.to_string()),
            "{walk}"
        );
        // `seq` counts the same way, so it is bounded too. A step that would run
        // past the largest `i64` saturates there, which ends the walk instead of
        // wrapping around to the bottom of the range.
        let long = error("seq", &[n(0.0), n(9_007_199_254_740_992.0)]);
        assert!(
            long.to_string().contains(&MAX_SEQUENCE.to_string()),
            "{long}"
        );
        assert_eq!(
            ok(
                "seq",
                &[
                    n(0.0),
                    n(9_007_199_254_740_992.0),
                    n(9_007_199_254_740_992.0)
                ]
            ),
            Value::String("0 9007199254740992".to_owned())
        );
    }

    #[test]
    fn wrong_argument_counts_are_reported() {
        // `Count("append", i, 2)` and `Count("join", i, 2)` in the reference.
        assert!(
            error("append", &[l(&[])]).to_string().contains("expects 2"),
            "append"
        );
        assert!(
            error("join", &[s(",")]).to_string().contains("expects 2"),
            "join"
        );
        assert!(
            error("first", &[]).to_string().contains("expects 1"),
            "first"
        );
        assert!(
            error("untilStep", &[n(1.0)])
                .to_string()
                .contains("expects 3"),
            "untilStep"
        );
        assert!(
            error("slice", &[l(&[]), n(0.0), n(0.0), n(0.0)])
                .to_string()
                .contains("expects 1 to 3"),
            "slice"
        );
    }

    #[test]
    fn this_module_never_takes_rendered_strings() {
        for name in [
            "list",
            "tuple",
            "first",
            "last",
            "rest",
            "initial",
            "append",
            "push",
            "prepend",
            "concat",
            "reverse",
            "uniq",
            "without",
            "compact",
            "has",
            "slice",
            "chunk",
            "join",
            "sortAlpha",
            "seq",
            "until",
            "untilStep",
        ] {
            assert!(!super::takes_rendered_strings(name), "{name}");
        }
    }

    #[test]
    fn a_name_from_another_module_is_not_claimed() {
        assert!(DISPATCH("hasKey", &[], &Context::default()).is_none());
    }
}
