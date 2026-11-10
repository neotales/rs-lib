// The digests in this file are the conversion-heavy part of a string helper: they
// narrow message words into a fixed word size and widen them back for the
// arithmetic. Every conversion is part of the algorithm rather than an accident,
// and the published vectors in the tests are what pins them.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss
)]

//! The string helpers, ported from the reference's `SprigFunctions.cs`.
//!
//! Three properties of this group are worth knowing before reading a helper.
//!
//! * A helper that measures a string counts **bytes**, because `trunc`,
//!   `abbrev`, `abbrevboth`, and `substr` are ports of Go's byte-indexed
//!   `strings` functions and of the reference's own `value[..n]`, and `wrap`
//!   counts the same way. Go is allowed to cut a rune in half and a Rust
//!   `String` is not, so [`slice_bytes`] widens a byte range outwards to the
//!   nearest character boundary. That is the one place this implementation
//!   cannot copy the reference byte for byte.
//! * `split`, `splitList`, and `splitn` are Go's `strings.Split` and
//!   `strings.SplitN`, including Go's rule for an empty separator: it splits
//!   after every UTF-8 rune. It is not a no-op, and an empty value splits into
//!   nothing at all.
//! * [`takes_rendered_strings`] is `true` for the helpers that consume every
//!   argument as text and return text, so the engine hands them rendered
//!   strings. It is `false` for the helpers that have to see a typed value:
//!   `contains`, `hasPrefix`, and `hasSuffix` return booleans, `splitList`
//!   refuses a collection, `plural` needs its count to be a number, and `cat`
//!   and `toString` have to know whether an argument was null.

use std::collections::BTreeMap;

use crate::support;
use crate::{Context, Error, Value};

/// Dispatches a strings helper.
///
/// The shape of this is the crate's rather than this module's: every helper
/// module exposes the same signature and the engine reaches the modules through
/// this function pointer, so the two lints the shape trips are allowed here
/// rather than worked around.
#[allow(clippy::trivially_copy_pass_by_ref, clippy::type_complexity)]
pub(super) const DISPATCH: crate::Dispatch =
    |name, arguments, context| dispatch(name, arguments, context);

#[allow(clippy::trivially_copy_pass_by_ref)]
fn dispatch(
    name: &str,
    arguments: &[Value],
    context: &Context<'_>,
) -> Option<Result<Value, Error>> {
    // No string helper reads the call site; the parameter is part of the
    // signature every module shares.
    let _ = context;
    call(name, arguments)
}

fn call(name: &str, arguments: &[Value]) -> Option<Result<Value, Error>> {
    let result = match name {
        // One string in, one string out: the reference's `One`.
        "trim" => one_string(name, arguments, |value| {
            value.trim_matches(is_go_space).to_owned()
        }),
        "upper" => one_string(name, arguments, str::to_uppercase),
        // The reference's `untitle` is `ToLowerInvariant`, the same as `lower`,
        // and not a real "un-title": it inverts `title` only because
        // title-casing also lower-cases the rest of each word.
        "lower" | "untitle" => one_string(name, arguments, str::to_lowercase),
        "title" => one_string(name, arguments, title_case),
        "swapcase" => one_string(name, arguments, swap_case),
        "initials" => one_string(name, arguments, initial_letters),
        // `NoSpace` drops every whitespace rune anywhere in the value, not just
        // at its ends.
        "nospace" => one_string(name, arguments, |value| {
            value.chars().filter(|c| !is_go_space(*c)).collect()
        }),
        "camelcase" => one_string(name, arguments, pascal_words),
        "kebabcase" => one_string(name, arguments, |value| {
            words(value).join("-").to_lowercase()
        }),
        "snakecase" => one_string(name, arguments, |value| {
            words(value).join("_").to_lowercase()
        }),
        // The rest take more than one argument or are not plain transforms.
        "trimAll" | "trimall" => trim_all(name, arguments),
        "trimPrefix" => trim_prefix(name, arguments),
        "trimSuffix" => trim_suffix(name, arguments),
        "repeat" => repeat(name, arguments),
        "substr" => substr(name, arguments),
        "trunc" => trunc(name, arguments),
        "contains" => contains(name, arguments),
        "hasPrefix" => has_prefix(name, arguments),
        "hasSuffix" => has_suffix(name, arguments),
        "replace" => replace(name, arguments),
        "split" => split(name, arguments),
        "splitList" => split_list(name, arguments),
        "splitn" => split_n(name, arguments),
        "cat" => Ok(Value::String(cat(arguments))),
        "indent" => indent(name, arguments),
        "nindent" => nindent(name, arguments),
        "abbrev" => abbrev(name, arguments),
        "abbrevboth" => abbrev_both(name, arguments),
        "wrap" => wrap(name, arguments),
        "wrapWith" => wrap_with(name, arguments),
        "toString" => to_string(name, arguments),
        "plural" => plural(name, arguments),
        "sha1sum" => checksum(name, arguments, sha1_hex),
        "sha256sum" => checksum(name, arguments, sha256_hex),
        "sha512sum" => checksum(name, arguments, sha512_hex),
        "adler32sum" => checksum(name, arguments, adler32),
        _ => return None,
    };
    Some(result)
}

/// Reports whether this module's helper wants rendered string arguments.
pub(super) fn takes_rendered_strings(name: &str) -> bool {
    matches!(
        name,
        "trim"
            | "trimAll"
            | "trimall"
            | "trimPrefix"
            | "trimSuffix"
            | "upper"
            | "lower"
            | "title"
            | "untitle"
            | "repeat"
            | "substr"
            | "trunc"
            | "replace"
            | "split"
            | "splitn"
            | "cat"
            | "indent"
            | "nindent"
            | "swapcase"
            | "initials"
            | "camelcase"
            | "kebabcase"
            | "snakecase"
            | "nospace"
            | "abbrev"
            | "abbrevboth"
            | "wrap"
            | "wrapWith"
            | "toString"
            | "sha1sum"
            | "sha256sum"
            | "adler32sum"
    )
}

/// Applies a one-argument string transform, the shape the reference calls
/// `One`.
fn one_string(
    name: &str,
    arguments: &[Value],
    transform: impl FnOnce(&str) -> String,
) -> Result<Value, Error> {
    crate::arity(name, arguments.len(), 1, Some(1))?;
    Ok(Value::String(transform(&arguments[0].render())))
}

/// Reports whether a rune is whitespace to Go and to the reference.
///
/// Both `unicode.IsSpace` and .NET's `char.IsWhiteSpace` are Unicode
/// `White_Space` plus `U+0085` NEL, which is a Latin-1 control character rather
/// than a `White_Space` member, so `char::is_whitespace` on its own would miss
/// it. The reference's `Trim`, `NoSpace`, and `InitialLetters` all use that
/// set, so all three read it from here.
fn is_go_space(character: char) -> bool {
    character.is_whitespace() || character == '\u{85}'
}

/// Removes any rune of the cutset from both ends, the reference's `TrimAll`
/// with `string.Trim(char[])`. An empty cutset removes nothing, which is also
/// what Go's `strings.Trim` does.
fn trim_all(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    crate::arity(name, arguments.len(), 2, Some(2))?;
    let cutset: Vec<char> = arguments[0].render().chars().collect();
    let value = arguments[1].render();
    Ok(Value::String(
        value.trim_matches(|c| cutset.contains(&c)).to_owned(),
    ))
}

/// Removes a literal prefix, and only if it is there: the reference's
/// `TrimPrefix`, which checks `StartsWith` before it slices.
fn trim_prefix(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    crate::arity(name, arguments.len(), 2, Some(2))?;
    let prefix = arguments[0].render();
    let value = arguments[1].render();
    // The prefix matched the value, so its length is a boundary of the value.
    Ok(Value::String(if value.starts_with(&prefix) {
        value[prefix.len()..].to_owned()
    } else {
        value
    }))
}

/// The suffix counterpart of [`trim_prefix`], the reference's `TrimSuffix`.
fn trim_suffix(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    crate::arity(name, arguments.len(), 2, Some(2))?;
    let suffix = arguments[0].render();
    let value = arguments[1].render();
    // The suffix matched the value, so its length is a boundary of the value.
    Ok(Value::String(if value.ends_with(&suffix) {
        value[..value.len() - suffix.len()].to_owned()
    } else {
        value
    }))
}

/// Concatenates a string with itself, the reference's `Repeat`.
fn repeat(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    /// A result no engine would render, refused rather than allocated.
    const MAX_BYTES: usize = 1 << 26;
    crate::arity(name, arguments.len(), 2, Some(2))?;
    let count = length(name, support::integer(name, &arguments[0])?)?;
    let value = arguments[1].render();
    // Go's `strings.Repeat` panics on a negative count and the reference
    // throws, so both refuse rather than answer. This reports the argument.
    let total = value
        .len()
        .checked_mul(count)
        .filter(|total| *total <= MAX_BYTES)
        .ok_or_else(|| crate::invalid(name, "cannot repeat that string that many times"))?;
    let mut out = String::with_capacity(total);
    for _ in 0..count {
        out.push_str(&value);
    }
    Ok(Value::String(out))
}

/// The reference's `Substr`: three arguments, clamped rather than panicking.
///
/// A negative `start` measures the result's end, and a negative or out-of-range
/// `end` means "to the end of the value". Every bound is clamped into the value
/// rather than throwing the way a bare `s[low:high]` would.
fn substr(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    crate::arity(name, arguments.len(), 3, Some(3))?;
    let start = support::integer(name, &arguments[0])?;
    let end = support::integer(name, &arguments[1])?;
    let value = arguments[2].render();
    let bytes = value.len();

    if start < 0 {
        // `value[..clamp(end, 0, len)]`
        return Ok(Value::String(slice_bytes(
            &value,
            0,
            usize::try_from(end).unwrap_or(bytes).min(bytes),
        )));
    }
    let low = usize::try_from(start).unwrap_or(usize::MAX).min(bytes);
    if end < 0 || usize::try_from(end).unwrap_or(usize::MAX) > bytes {
        // `value[clamp(start, 0, len)..]`
        return Ok(Value::String(slice_bytes(&value, low, bytes)));
    }
    // `value[clamp(start, 0, len)..clamp(end, start, len)]`, so an end before
    // the start yields nothing.
    let high = usize::try_from(end).unwrap_or(bytes);
    Ok(Value::String(slice_bytes(&value, low, high.max(low))))
}

/// Keeps the first or the last `length` bytes, the reference's `Trunc`.
///
/// A negative length keeps that many bytes from the end, and a positive one
/// longer than the value is the value.
fn trunc(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    crate::arity(name, arguments.len(), 2, Some(2))?;
    let length = support::integer(name, &arguments[0])?;
    let value = arguments[1].render();
    let bytes = value.len();
    let result = if length >= 0 {
        slice_bytes(
            &value,
            0,
            usize::try_from(length).unwrap_or(usize::MAX).min(bytes),
        )
    } else {
        // `value[max(len + length, 0)..]`, measured in bytes.
        let from = i64::try_from(bytes)
            .unwrap_or(i64::MAX)
            .saturating_add(length)
            .max(0);
        slice_bytes(&value, usize::try_from(from).unwrap_or(bytes), bytes)
    };
    Ok(Value::String(result))
}

/// Reports whether the first argument appears in the second, the reference's
/// `Contains`. Note the argument order: needle before haystack.
fn contains(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    crate::arity(name, arguments.len(), 2, Some(2))?;
    let needle = support::text(name, &arguments[0])?;
    let haystack = support::text(name, &arguments[1])?;
    Ok(Value::Bool(haystack.contains(&needle)))
}

/// The prefix counterpart, the reference's `HasPrefix`.
fn has_prefix(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    crate::arity(name, arguments.len(), 2, Some(2))?;
    let prefix = support::text(name, &arguments[0])?;
    let value = support::text(name, &arguments[1])?;
    Ok(Value::Bool(value.starts_with(&prefix)))
}

/// The suffix counterpart, the reference's `HasSuffix`.
fn has_suffix(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    crate::arity(name, arguments.len(), 2, Some(2))?;
    let suffix = support::text(name, &arguments[0])?;
    let value = support::text(name, &arguments[1])?;
    Ok(Value::Bool(value.ends_with(&suffix)))
}

/// Replaces every occurrence of the first argument with the second inside the
/// third, the reference's `Replace` with an ordinal comparison.
fn replace(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    crate::arity(name, arguments.len(), 3, Some(3))?;
    let from = arguments[0].render();
    let to = arguments[1].render();
    let value = arguments[2].render();
    Ok(Value::String(value.replace(&from, &to)))
}

/// Shortens to `size` bytes, keeping the front and an ellipsis, the
/// reference's `Abbrev`.
///
/// A size below four would leave no room for the ellipsis, and a size at or
/// above the length of the value is the value.
fn abbrev(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    crate::arity(name, arguments.len(), 2, Some(2))?;
    let size = support::integer(name, &arguments[0])?;
    let value = arguments[1].render();
    let bytes = value.len();
    if size < 4 || usize::try_from(size).unwrap_or(usize::MAX) >= bytes {
        return Ok(Value::String(value));
    }
    // `value[..size - 3] + "..."`
    let head = usize::try_from(size - 3).unwrap_or(0);
    Ok(Value::String(format!(
        "{}...",
        slice_bytes(&value, 0, head)
    )))
}

/// Shortens to `size` bytes, keeping the middle and an ellipsis at each end,
/// the reference's `AbbrevBoth`.
///
/// `left` is how many bytes to drop from the front. The reference keeps the
/// value whole when it already fits, when a size below four leaves no room for
/// the two ellipses, or when a non-zero `left` leaves a size below seven too
/// cramped to be worth it.
fn abbrev_both(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    crate::arity(name, arguments.len(), 3, Some(3))?;
    let left = support::integer(name, &arguments[0])?;
    let size = support::integer(name, &arguments[1])?;
    let value = arguments[2].render();
    let bytes = value.len();
    if left < 0 {
        // The reference reaches .NET's `Skip`, which throws on a negative
        // count.
        return Err(crate::invalid(
            name,
            "cannot keep a negative number of bytes",
        ));
    }
    let left = usize::try_from(left).unwrap_or(usize::MAX);
    let size = usize::try_from(size).unwrap_or(usize::MAX);
    if size < 4 || size >= bytes || (left > 0 && size < 7) {
        return Ok(Value::String(value));
    }
    // `"..." + value.Skip(left).Take(max(size - 6, 0)) + "..."`
    let from = left.min(bytes);
    let to = from.saturating_add(size.saturating_sub(6));
    let middle = slice_bytes(&value, from, to);
    Ok(Value::String(format!("...{middle}...")))
}

/// Splits into the reference's `_0`, `_1`, ... map, the reference's `Split`
/// with no limit on the number of pieces.
fn split(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    crate::arity(name, arguments.len(), 2, Some(2))?;
    let separator = arguments[0].render();
    let value = arguments[1].render();
    Ok(indexed_map(go_split(&value, &separator, None)))
}

/// Splits into at most `count` pieces, the reference's `SplitN`.
fn split_n(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    crate::arity(name, arguments.len(), 3, Some(3))?;
    let separator = arguments[0].render();
    let count = support::integer(name, &arguments[1])?;
    if count < 0 {
        // Go reads a negative limit as no limit at all, but the reference
        // hands it to .NET's `Split`, which throws.
        return Err(crate::invalid(name, "cannot split that many times"));
    }
    let value = arguments[2].render();
    let pieces = go_split(&value, &separator, usize::try_from(count).ok());
    Ok(indexed_map(pieces))
}

/// Splits into a list, the reference's `SplitList`.
fn split_list(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    crate::arity(name, arguments.len(), 2, Some(2))?;
    let separator = support::text(name, &arguments[0])?;
    let value = support::text(name, &arguments[1])?;
    Ok(Value::List(
        go_split(&value, &separator, None)
            .into_iter()
            .map(Value::String)
            .collect(),
    ))
}

/// Labels the pieces of a split the way the reference does, `_0` upwards.
fn indexed_map(pieces: Vec<String>) -> Value {
    Value::Map(
        pieces
            .into_iter()
            .enumerate()
            .map(|(index, piece)| (format!("_{index}"), Value::String(piece)))
            .collect::<BTreeMap<String, Value>>(),
    )
}

/// Splits the way Go's `strings.Split` and `strings.SplitN` do.
///
/// `count` of `None` is an unlimited split. Go's rule for an empty separator is
/// reproduced by [`explode`], because that is what makes `{{ split "" "abc" }}`
/// three pieces and not one.
fn go_split(value: &str, separator: &str, count: Option<usize>) -> Vec<String> {
    if separator.is_empty() {
        return explode(value, count.unwrap_or(usize::MAX));
    }
    match count {
        // Go returns nothing at all for a limit of zero.
        Some(0) => Vec::new(),
        Some(limit) => value.splitn(limit, separator).map(str::to_owned).collect(),
        None => value.split(separator).map(str::to_owned).collect(),
    }
}

/// Splits after every rune, which is Go's `explode`, reached only for an empty
/// separator.
///
/// The first `count - 1` pieces are one rune each and the last piece is the
/// whole remainder. A count at or above the number of runes means "all of
/// them", so an empty value splits into nothing.
fn explode(value: &str, count: usize) -> Vec<String> {
    let pieces = count.min(value.chars().count());
    let mut out = Vec::with_capacity(pieces);
    let mut rest = value;
    for index in 0..pieces {
        let width = if index + 1 == pieces {
            rest.len()
        } else {
            rest.chars().next().map_or(0, char::len_utf8)
        };
        out.push(rest[..width].to_owned());
        rest = &rest[width..];
    }
    out
}

/// Joins the arguments with a space, dropping the nulls, as the reference's
/// `Cat` does.
///
/// A variadic helper needs no arity check: the reference takes any number of
/// arguments and zero of them is the empty string. A null is the one thing it
/// looks at instead of rendering, which is why `cat` is not a rendered-strings
/// helper.
fn cat(arguments: &[Value]) -> String {
    let mut out = String::new();
    for argument in arguments
        .iter()
        .filter(|value| !matches!(value, Value::Null))
    {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(&support::any_text(argument));
    }
    out
}

/// Prefixes every line with a number of spaces, the reference's `Indent`.
///
/// The split is on a line feed alone, so a carriage return stays at the end of
/// its line, and an empty value is padded as one empty line.
fn indent(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    crate::arity(name, arguments.len(), 2, Some(2))?;
    let spaces = length(name, support::integer(name, &arguments[0])?)?;
    let value = arguments[1].render();
    let pad = " ".repeat(spaces);
    Ok(Value::String(
        value
            .split('\n')
            .map(|line| format!("{pad}{line}"))
            .collect::<Vec<_>>()
            .join("\n"),
    ))
}

/// A newline and then [`indent`], the reference's `NIndent`.
fn nindent(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    let Value::String(indented) = indent(name, arguments)? else {
        unreachable!("indent returns a string or an error");
    };
    Ok(Value::String(format!("\n{indented}")))
}

/// Greedily wraps at a column, the reference's `Wrap`.
///
/// Words are separated by runs of whitespace with the empty pieces dropped, and
/// a width below one returns the value untouched. The fit test counts the space
/// that would join the word to the line, so a line is never as wide as the
/// column once a further word would be added to it.
fn wrap(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    crate::arity(name, arguments.len(), 2, Some(2))?;
    let width = support::integer(name, &arguments[0])?;
    let value = arguments[1].render();
    Ok(Value::String(wrap_text(&value, width, "\n")))
}

/// Wraps with a caller-chosen separator, the reference's `WrapWith`.
fn wrap_with(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    crate::arity(name, arguments.len(), 3, Some(3))?;
    let width = support::integer(name, &arguments[0])?;
    let separator = arguments[1].render();
    let value = arguments[2].render();
    Ok(Value::String(wrap_text(&value, width, &separator)))
}

/// The line-breaking part of `wrap` and `wrapWith`, the reference's `WrapText`.
///
/// The reference measures a line in UTF-16 code units, which is this byte count
/// for every ASCII line and differs only once a line holds a rune above
/// `U+07FF`.
fn wrap_text(value: &str, width: i64, separator: &str) -> String {
    if width < 1 {
        return value.to_owned();
    }
    let width = usize::try_from(width).unwrap_or(usize::MAX);
    let mut lines: Vec<String> = Vec::new();
    let mut line = String::new();
    for word in value.split_whitespace() {
        if !line.is_empty() && line.len() + word.len() + 1 > width {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines.join(separator)
}

/// Renders any value as a string, the reference's `ToString`.
///
/// It does not refuse a list or a map: the reference renders its argument
/// rather than inspecting it, so a list becomes `[a b]` exactly as it would
/// anywhere else in a rendered template.
fn to_string(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    crate::arity(name, arguments.len(), 1, Some(1))?;
    Ok(Value::String(support::any_text(&arguments[0])))
}

/// Picks the singular or the plural spelling, the reference's `Plural`.
///
/// The reference tests the third argument for exactly one, so a count of one
/// picks the first argument and everything else, zero included, picks the
/// second.
fn plural(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    crate::arity(name, arguments.len(), 3, Some(3))?;
    let singular = support::text(name, &arguments[0])?;
    let many = support::text(name, &arguments[1])?;
    let count = support::integer(name, &arguments[2])?;
    Ok(Value::String(if count == 1 { singular } else { many }))
}

/// Hashes the rendered argument, the reference's `Hash` and `Adler32`.
///
/// Both take exactly one argument, and a list is rendered rather than joined,
/// which is what the reference's own rendering does, so these are
/// rendered-strings helpers.
fn checksum(name: &str, arguments: &[Value], digest: fn(&[u8]) -> String) -> Result<Value, Error> {
    crate::arity(name, arguments.len(), 1, Some(1))?;
    Ok(Value::String(digest(arguments[0].render().as_bytes())))
}

/// Slices a byte range the way Go's `s[low:high]` would.
///
/// Go is free to leave half a rune behind and a Rust `String` is not, so both
/// bounds are widened outwards to the nearest character boundary. The
/// measurement stays in bytes: a `trunc` of five on a value of four runes keeps
/// five bytes' worth of runes, not five runes.
fn slice_bytes(value: &str, start: usize, end: usize) -> String {
    let mut low = start.min(value.len());
    while low > 0 && !value.is_char_boundary(low) {
        low -= 1;
    }
    let mut high = end.clamp(low, value.len());
    while high < value.len() && !value.is_char_boundary(high) {
        high += 1;
    }
    value[low..high].to_owned()
}

/// Reads a non-negative count or width as a `usize`.
fn length(name: &str, value: i64) -> Result<usize, Error> {
    usize::try_from(value)
        .map_err(|_| crate::invalid(name, format!("cannot use {value} as a length")))
}

/// Upper-cases the first letter of every word and lower-cases the rest, which
/// is what the reference's `ToTitleCase` does.
///
/// Go's `strings.Title`, which upstream Sprig used, leaves the rest of a word
/// alone and so leaves `HELLO` alone; this makes it `Hello`, which is the
/// reference's answer. A run of non-letters ends a word, so a digit starts
/// one.
fn title_case(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut at_word_start = true;
    for character in value.chars() {
        if character.is_alphabetic() {
            if at_word_start {
                out.extend(character.to_uppercase());
            } else {
                out.extend(character.to_lowercase());
            }
            at_word_start = false;
        } else {
            out.push(character);
            at_word_start = true;
        }
    }
    out
}

/// Swaps the case of every character, the reference's `SwapCase`.
///
/// This is the one helper that maps character by character, because that is
/// what the reference does: a single character is swapped with the simple
/// mapping rather than the full one, so `ß` is left alone where `upper` would
/// make it `SS` as Go's `strings.ToUpper` does.
fn swap_case(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        if character.is_uppercase() {
            out.extend(character.to_lowercase());
        } else {
            out.extend(character.to_uppercase());
        }
    }
    out
}

/// Takes the first character of every whitespace-separated run, the
/// reference's `InitialLetters`.
fn initial_letters(value: &str) -> String {
    let mut out = String::new();
    let mut first = true;
    for character in value.chars() {
        if is_go_space(character) {
            first = true;
        } else if first {
            out.push(character);
            first = false;
        }
    }
    out
}

/// Splits a value into words the way the reference's `Words` does.
///
/// Anything that is neither a letter nor a digit ends a word, and an upper-case
/// letter that follows a lower-case one, or that is followed by a lower-case
/// one, starts a new word. That is what separates `HTTPServer` into `HTTP` and
/// `Server` while leaving `HTTPS` in one piece.
fn words(value: &str) -> Vec<String> {
    let characters: Vec<char> = value.chars().collect();
    let mut out: Vec<String> = Vec::new();
    let mut word = String::new();
    for (index, character) in characters.iter().enumerate() {
        if !character.is_alphanumeric() {
            add_word(&mut out, &mut word);
            continue;
        }
        if !word.is_empty() && character.is_uppercase() && starts_word(&characters, index) {
            add_word(&mut out, &mut word);
        }
        word.push(*character);
    }
    add_word(&mut out, &mut word);
    out
}

/// Reports whether the character at `index` begins a new word.
///
/// The reference looks for a lower-case character before it or after it. The
/// index is clamped because the first character of a value is only reached with
/// an empty word, which the caller has already ruled out.
fn starts_word(characters: &[char], index: usize) -> bool {
    characters[index.saturating_sub(1)].is_lowercase()
        || characters
            .get(index + 1)
            .is_some_and(|next| next.is_lowercase())
}

/// Appends a word and empties it, the reference's `Add`. An empty word is
/// dropped, which is what collapses consecutive separators.
fn add_word(out: &mut Vec<String>, word: &mut String) {
    if word.is_empty() {
        return;
    }
    out.push(std::mem::take(word));
}

/// Joins the words in camel case, the reference's `PascalWords`.
///
/// An underscore ends a word but is not a separator between words: a run of
/// them is reproduced in the output, one shorter when a word came before it,
/// and a run after the last word is kept whole. Anything else that is neither a
/// letter nor a digit ends a word and is dropped.
fn pascal_words(value: &str) -> String {
    let characters: Vec<char> = value.chars().collect();
    let mut out = String::new();
    let mut word = String::new();
    let mut underscores = 0_usize;
    let mut has_word = false;
    for (index, character) in characters.iter().enumerate() {
        if *character == '_' {
            append_pascal_word(&mut out, &mut word, &mut has_word);
            underscores += 1;
            continue;
        }
        if !character.is_alphanumeric() {
            append_pascal_word(&mut out, &mut word, &mut has_word);
            underscores = 0;
            continue;
        }
        if underscores > 0 {
            // The underscore directly before a word belongs to that word's
            // capital, so it is the one that is not repeated.
            let kept = if has_word {
                underscores - 1
            } else {
                underscores
            };
            for _ in 0..kept {
                out.push('_');
            }
            underscores = 0;
        }
        if !word.is_empty() && character.is_uppercase() && starts_word(&characters, index) {
            append_pascal_word(&mut out, &mut word, &mut has_word);
        }
        word.push(*character);
    }
    append_pascal_word(&mut out, &mut word, &mut has_word);
    for _ in 0..underscores {
        out.push('_');
    }
    out
}

/// Appends a word as a capital followed by the rest lower-cased, the
/// reference's `AppendPascalWord`. An empty word contributes nothing but does
/// not set `has_word`.
fn append_pascal_word(out: &mut String, word: &mut String, has_word: &mut bool) {
    let Some(first) = word.chars().next() else {
        return;
    };
    out.extend(first.to_uppercase());
    out.push_str(&word[first.len_utf8()..].to_lowercase());
    word.clear();
    *has_word = true;
}

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// The sixty-four round constants of SHA-256: the first thirty-two bits of the
/// fractional parts of the cube roots of the first sixty-three primes, with
/// the last constant rounded up.
const SHA256_ROUND: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// Renders bytes as the lower-case hex Go's `fmt.Sprintf("%x", ...)` writes,
/// which is what the reference's `Convert.ToHexString(...).ToLowerInvariant()`
/// produces.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

/// Yields the padded 64-byte blocks that both of the digests below consume.
///
/// A message is a `0x80` byte, then zeroes up to the last eight bytes of a
/// block, then its length in bits as a big-endian 64-bit integer. The three
/// padding cases are a value that already ends in a block boundary, one that
/// is one byte short of it, and one that needs a whole extra block.
fn padded_blocks(data: &[u8]) -> Vec<[u8; 64]> {
    let bit_length = u64::try_from(data.len())
        .unwrap_or(u64::MAX)
        .wrapping_mul(8);
    let mut message = data.to_vec();
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0);
    }
    message.extend_from_slice(&bit_length.to_be_bytes());
    // The padded length is a whole number of blocks, so `chunks` yields exactly
    // the blocks and no remainder.
    message
        .chunks(64)
        .map(|chunk| {
            let mut block = [0_u8; 64];
            block.copy_from_slice(chunk);
            block
        })
        .collect()
}

/// Reads the sixteen big-endian words a 64-byte block is made of. Both digests
/// expand those into their longer schedules.
fn block_words(block: &[u8; 64]) -> [u32; 16] {
    let mut words = [0_u32; 16];
    for (index, word) in words.iter_mut().enumerate() {
        let start = index * 4;
        *word = u32::from_be_bytes([
            block[start],
            block[start + 1],
            block[start + 2],
            block[start + 3],
        ]);
    }
    words
}

/// Computes SHA-1 and renders it as lower-case hex, the reference's
/// `HashSha1`.
///
/// SHA-1 is not a hash anyone should choose, but `sha1sum` is in the helper set
/// for parity with the reference and with Go's Sprig, where it is used to key a
/// cache of rendered content. This crate depends on no hashing library, so the
/// algorithm is here.
// The working variables are the algorithm's own names; spelling them out would
// make the round loop harder to check against the specification.
#[allow(clippy::many_single_char_names)]
fn sha1_hex(data: &[u8]) -> String {
    let mut state: [u32; 5] = [
        0x6745_2301,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];
    for block in padded_blocks(data) {
        let mut words = [0_u32; 80];
        words[..16].copy_from_slice(&block_words(&block));
        for index in 16..80 {
            words[index] =
                (words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16])
                    .rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = state;
        for (index, word) in words.iter().enumerate() {
            let (mixed, constant) = match index {
                0..=19 => ((b & c) | (!b & d), 0x5a82_7999),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(mixed)
                .wrapping_add(e)
                .wrapping_add(constant)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        for (slot, value) in state.iter_mut().zip([a, b, c, d, e]) {
            *slot = slot.wrapping_add(value);
        }
    }
    hex(&state
        .iter()
        .flat_map(|word| word.to_be_bytes())
        .collect::<Vec<u8>>())
}

/// Computes SHA-256 and renders it as lower-case hex, the reference's
/// `HashSha256`.
fn sha256_hex(data: &[u8]) -> String {
    let mut state: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];
    for block in padded_blocks(data) {
        let mut words = [0_u32; 64];
        words[..16].copy_from_slice(&block_words(&block));
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }
        let mut working = state;
        for (index, word) in words.iter().enumerate() {
            let s1 = working[4].rotate_right(6)
                ^ working[4].rotate_right(11)
                ^ working[4].rotate_right(25);
            let choose = (working[4] & working[5]) ^ (!working[4] & working[6]);
            let first = working[7]
                .wrapping_add(s1)
                .wrapping_add(choose)
                .wrapping_add(SHA256_ROUND[index])
                .wrapping_add(*word);
            let s0 = working[0].rotate_right(2)
                ^ working[0].rotate_right(13)
                ^ working[0].rotate_right(22);
            let majority =
                (working[0] & working[1]) ^ (working[0] & working[2]) ^ (working[1] & working[2]);
            let second = s0.wrapping_add(majority);
            working.rotate_right(1);
            working[4] = working[4].wrapping_add(first);
            working[0] = first.wrapping_add(second);
        }
        for (slot, value) in state.iter_mut().zip(working) {
            *slot = slot.wrapping_add(value);
        }
    }
    hex(&state
        .iter()
        .flat_map(|word| word.to_be_bytes())
        .collect::<Vec<u8>>())
}

/// Computes the Adler-32 checksum and renders it in decimal, the reference's
/// `Adler32`.
///
/// It is a checksum and not a cryptographic digest: it is additive, so two
/// bytes of input change it a little and it is not a commitment to anything.
fn adler32(data: &[u8]) -> String {
    const MODULUS: u32 = 65_521;
    let mut low: u32 = 1;
    let mut high: u32 = 0;
    for byte in data {
        low = (low + u32::from(*byte)) % MODULUS;
        high = (high + low) % MODULUS;
    }
    // The reference writes `(b << 16) | a`, which is unsigned and can exceed
    // the signed 32-bit range.
    format!("{}", (high << 16) | low)
}

#[cfg(test)]
mod tests {
    use super::{call, takes_rendered_strings};
    use crate::{Error, Value};

    /// A rendered string argument, which is what the engine passes a helper
    /// that wants text.
    fn text(value: &str) -> Value {
        Value::String(value.to_owned())
    }

    /// A number argument, which is what the engine passes a helper that wants
    /// a typed value.
    fn count(value: f64) -> Value {
        Value::Number(value)
    }

    /// Evaluates a helper this module claims.
    fn ok(name: &str, arguments: &[Value]) -> Value {
        call(name, arguments)
            .unwrap_or_else(|| panic!("{name} is a strings helper"))
            .unwrap_or_else(|error| panic!("{name} should accept {arguments:?}: {error}"))
    }

    /// Evaluates a helper and renders its result.
    fn rendered(name: &str, arguments: &[Value]) -> String {
        ok(name, arguments).render()
    }

    /// Evaluates a helper that is expected to refuse its arguments.
    fn refused(name: &str, arguments: &[Value]) -> Error {
        call(name, arguments)
            .unwrap_or_else(|| panic!("{name} is a strings helper"))
            .expect_err("the call should have been refused")
    }

    #[test]
    fn trim_matches_the_upstream_parity_cases() {
        // {{ default "fallback" (trim " ") }} renders "fallback", so trim of a
        // single space is the empty string.
        assert_eq!(rendered("trim", &[text(" ")]), "");
        // {{ upper (trim " go " | repeat 2) }} renders "GOGO", so trim strips the
        // spaces and nothing else.
        assert_eq!(rendered("trim", &[text(" go ")]), "go");
        // `Trim` in the reference is a whitespace trim, not a rune trim.
        assert_eq!(rendered("trim", &[text("\t\nx\r\n")]), "x");
        assert_eq!(rendered("trim", &[text("\u{85}x\u{a0}")]), "x");
    }

    #[test]
    fn trim_all_matches_the_upstream_parity_case() {
        // {{ trimall "$" "$value$" }} renders "value", and the helper is
        // registered under both spellings.
        for name in ["trimAll", "trimall"] {
            assert_eq!(rendered(name, &[text("$"), text("$value$")]), "value");
        }
        // `Trim(char[])` removes any of the runes, not a whole prefix.
        assert_eq!(
            rendered("trimAll", &[text("-$"), text("-$value-$")]),
            "value"
        );
        // An empty cutset is not a wildcard, it removes nothing.
        assert_eq!(rendered("trimAll", &[text(""), text(" value ")]), " value ");
    }

    #[test]
    fn trim_prefix_and_suffix_remove_only_a_literal_edge() {
        // `TrimPrefix` checks StartsWith before it slices, so a partial match
        // leaves the value alone.
        assert_eq!(
            rendered("trimPrefix", &[text("/tmp/"), text("/tmp/x")]),
            "x"
        );
        assert_eq!(
            rendered("trimPrefix", &[text("tmp"), text("/tmp/x")]),
            "/tmp/x"
        );
        assert_eq!(
            rendered("trimSuffix", &[text(".env"), text("compose.env")]),
            "compose"
        );
        assert_eq!(
            rendered("trimSuffix", &[text("xt"), text("compose.env")]),
            "compose.env"
        );
        // Removing the whole value is allowed.
        assert_eq!(rendered("trimPrefix", &[text("abc"), text("abc")]), "");
    }

    #[test]
    fn upper_and_lower_change_case() {
        // {{ upper (trim " go " | repeat 2) }} renders "GOGO".
        assert_eq!(rendered("upper", &[text("gogo")]), "GOGO");
        assert_eq!(rendered("lower", &[text("GOGO")]), "gogo");
        // The case helpers render a non-string argument, so a number prints.
        assert_eq!(rendered("upper", &[count(1.0)]), "1");
    }

    #[test]
    fn untitle_lowercases_like_the_reference() {
        // {{ untitle "First Try" }} renders "first try". `Untitle` in the
        // reference is `ToLowerInvariant`, not the inverse of `ToTitleCase`.
        assert_eq!(rendered("untitle", &[text("First Try")]), "first try");
        assert_eq!(rendered("untitle", &[text("HTTPServer")]), "httpserver");
    }

    #[test]
    fn title_uppercases_each_word_and_lowercases_the_rest() {
        // `ToTitleCase` in the reference, which is not Go's `strings.Title`:
        // that one would leave the rest of a word alone.
        assert_eq!(rendered("title", &[text("hello world")]), "Hello World");
        assert_eq!(rendered("title", &[text("HELLO WORLD")]), "Hello World");
        // A run of non-letters ends a word, so a digit starts one.
        assert_eq!(rendered("title", &[text("1st place")]), "1St Place");
        // Untitling a title case value is what `untitle` inverts.
        assert_eq!(
            rendered("untitle", &[ok("title", &[text("HELLO WORLD")])]),
            "hello world"
        );
    }

    #[test]
    fn repeat_matches_the_upstream_parity_case() {
        // {{ upper (trim " go " | repeat 2) }} renders "GOGO".
        assert_eq!(rendered("repeat", &[count(2.0), text("go")]), "gogo");
        assert_eq!(rendered("repeat", &[count(0.0), text("go")]), "");
        // Go's `strings.Repeat` panics on a negative count and the reference
        // throws, so this reports the argument instead.
        assert!(matches!(
            refused("repeat", &[count(-1.0), text("go")]),
            Error::InvalidArgument { .. }
        ));
    }

    #[test]
    fn substr_matches_the_upstream_parity_cases() {
        // {{ substr -1 3 "fooo" }} renders "foo": a negative start measures the
        // end of the result rather than throwing.
        assert_eq!(
            rendered("substr", &[count(-1.0), count(3.0), text("fooo")]),
            "foo"
        );
        // {{ substr 1 -1 "fooo" }} renders "ooo": a negative end is the end of
        // the value.
        assert_eq!(
            rendered("substr", &[count(1.0), count(-1.0), text("fooo")]),
            "ooo"
        );
        // {{ substr 1 10 "fooo" }} renders "ooo", and an end past the value is
        // the value rather than an error.
        assert_eq!(
            rendered("substr", &[count(1.0), count(10.0), text("fooo")]),
            "ooo"
        );
        // Every bound is clamped into the value rather than throwing.
        assert_eq!(
            rendered("substr", &[count(2.0), count(1.0), text("fooo")]),
            ""
        );
        assert_eq!(
            rendered("substr", &[count(-1.0), count(99.0), text("fooo")]),
            "fooo"
        );
        assert_eq!(
            rendered("substr", &[count(99.0), count(99.0), text("fooo")]),
            ""
        );
    }

    #[test]
    fn trunc_keeps_a_counted_number_of_bytes_from_one_end() {
        // `Trunc` in the reference, and the count is bytes, not characters.
        assert_eq!(rendered("trunc", &[count(3.0), text("hello world")]), "hel");
        assert_eq!(
            rendered("trunc", &[count(-6.0), text("hello world")]),
            " world"
        );
        assert_eq!(
            rendered("trunc", &[count(-5.0), text("hello world")]),
            "world"
        );
        assert_eq!(
            rendered("trunc", &[count(99.0), text("hello world")]),
            "hello world"
        );
        assert_eq!(
            rendered("trunc", &[count(-99.0), text("hello world")]),
            "hello world"
        );
        assert_eq!(rendered("trunc", &[count(0.0), text("hello")]), "");
    }

    #[test]
    fn a_count_in_bytes_will_not_split_a_rune() {
        // The measurements are in bytes, so a cut can land in the middle of a
        // multi-byte rune. Go would leave half of it behind, and a Rust `String`
        // cannot hold that, so the range is widened outwards to the nearest
        // character boundary: two bytes are the whole of `é`, and three are
        // `é` plus the `c` that follows it.
        assert_eq!(rendered("trunc", &[count(2.0), text("éclair")]), "é");
        assert_eq!(rendered("trunc", &[count(3.0), text("éclair")]), "éc");
        // The same widening at the front of an abbreviation: five bytes are
        // `é` and the three of the ellipsis.
        assert_eq!(rendered("abbrev", &[count(5.0), text("éclair")]), "é...");
        // Nothing is lost from the other end either, and a count that would cut
        // into the first rune widens back to the start rather than into it.
        assert_eq!(rendered("trunc", &[count(-2.0), text("éclair")]), "ir");
        assert_eq!(rendered("trunc", &[count(-3.0), text("éclair")]), "air");
        assert_eq!(rendered("trunc", &[count(-6.0), text("éclair")]), "éclair");
    }

    #[test]
    fn contains_and_the_affix_searches_take_the_needle_first() {
        // `Search` in the reference passes argument 0 as the pattern and
        // argument 1 as the value.
        assert_eq!(
            ok("contains", &[text("cat"), text("concatenate")]),
            Value::Bool(true)
        );
        assert_eq!(
            ok("contains", &[text("dog"), text("concatenate")]),
            Value::Bool(false)
        );
        assert_eq!(
            ok("contains", &[text(""), text("concatenate")]),
            Value::Bool(true)
        );
        // {{ hasPrefix "cat" "catch" }} renders "true".
        assert_eq!(
            ok("hasPrefix", &[text("cat"), text("catch")]),
            Value::Bool(true)
        );
        assert_eq!(
            ok("hasPrefix", &[text("at"), text("catch")]),
            Value::Bool(false)
        );
        // {{ hasSuffix "cat" "bobcat" }} renders "true".
        assert_eq!(
            ok("hasSuffix", &[text("cat"), text("bobcat")]),
            Value::Bool(true)
        );
        assert_eq!(
            ok("hasSuffix", &[text("bob"), text("bobcat")]),
            Value::Bool(false)
        );
    }

    #[test]
    fn replace_matches_the_upstream_parity_case() {
        // {{ replace "x" "y" "xoxo" }} renders "yoyo".
        assert_eq!(
            rendered("replace", &[text("x"), text("y"), text("xoxo")]),
            "yoyo"
        );
        // Every occurrence, and a pattern that is not there changes nothing.
        assert_eq!(
            rendered("replace", &[text("a"), text("-"), text("aba")]),
            "-b-"
        );
        assert_eq!(
            rendered("replace", &[text("z"), text("y"), text("abc")]),
            "abc"
        );
    }

    #[test]
    fn split_matches_the_upstream_parity_case() {
        // {{ $values := "foo$bar$baz" | split "$" }}{{ $values._0 }} renders
        // "foo", and the map is keyed `_0` upwards.
        let split = ok("split", &[text("$"), text("foo$bar$baz")]);
        let Value::Map(pieces) = split else {
            panic!("split returns a map");
        };
        assert_eq!(pieces.get("_0"), Some(&text("foo")));
        assert_eq!(pieces.get("_1"), Some(&text("bar")));
        assert_eq!(pieces.get("_2"), Some(&text("baz")));
        assert_eq!(pieces.get("_3"), None);
    }

    #[test]
    fn splitn_matches_the_upstream_parity_case() {
        // {{ $values := "foo$bar$baz" | splitn "$" 2 }}{{ $values._1 }} renders
        // "bar$baz": the limit is the number of pieces, not of separators.
        let split = ok("splitn", &[text("$"), count(2.0), text("foo$bar$baz")]);
        let Value::Map(pieces) = split else {
            panic!("splitn returns a map");
        };
        assert_eq!(pieces.get("_0"), Some(&text("foo")));
        assert_eq!(pieces.get("_1"), Some(&text("bar$baz")));
        // A limit of zero yields nothing, and a limit past the value is the
        // value; Go returns nothing for zero, and so does the reference.
        let Value::Map(none) = ok("splitn", &[text("$"), count(0.0), text("foo")]) else {
            panic!("splitn returns a map");
        };
        assert!(none.is_empty());
        let Value::Map(all) = ok("splitn", &[text("$"), count(9.0), text("foo")]) else {
            panic!("splitn returns a map");
        };
        assert_eq!(all.get("_0"), Some(&text("foo")));
    }

    #[test]
    fn an_empty_separator_splits_after_every_rune() {
        // Go's rule for an empty separator, which is what `Split` and `SplitN`
        // do: the value is not left whole. An empty value yields no pieces.
        let Value::List(runes) = ok("splitList", &[text(""), text("ab")]) else {
            panic!("splitList returns a list");
        };
        assert_eq!(runes, vec![text("a"), text("b")]);
        let Value::List(nothing) = ok("splitList", &[text(""), text("")]) else {
            panic!("splitList returns a list");
        };
        assert!(nothing.is_empty());
        // A rune is a rune, not a byte.
        let Value::List(wide) = ok("splitList", &[text(""), text("é☃")]) else {
            panic!("splitList returns a list");
        };
        assert_eq!(wide, vec![text("é"), text("☃")]);
        // The limit applies to the rune count: two pieces, the second holding
        // the rest.
        let Value::Map(limited) = ok("splitn", &[text(""), count(2.0), text("abc")]) else {
            panic!("splitn returns a map");
        };
        assert_eq!(limited.get("_0"), Some(&text("a")));
        assert_eq!(limited.get("_1"), Some(&text("bc")));
    }

    #[test]
    fn split_list_returns_a_list_of_strings() {
        let Value::List(pieces) = ok("splitList", &[text("-"), text("neo-sprig")]) else {
            panic!("splitList returns a list");
        };
        assert_eq!(pieces, vec![text("neo"), text("sprig")]);
        // A separator that is not there leaves one piece, as Go's does.
        let Value::List(single) = ok("splitList", &[text("+"), text("neo")]) else {
            panic!("splitList returns a list");
        };
        assert_eq!(single, vec![text("neo")]);
        // A collection is not text, so it is refused rather than rendered.
        assert!(matches!(
            refused("splitList", &[text("-"), Value::List(vec![text("a")])]),
            Error::InvalidArgument { .. }
        ));
    }

    #[test]
    fn cat_joins_with_a_space_and_drops_nulls() {
        // `Cat` in the reference joins the rendered arguments that are not
        // null, which is the one thing it inspects rather than renders.
        assert_eq!(rendered("cat", &[text("a"), text("b")]), "a b");
        assert_eq!(rendered("cat", &[text("a"), Value::Null, text("b")]), "a b");
        assert_eq!(rendered("cat", &[count(1.0), Value::Bool(true)]), "1 true");
        // No arguments at all is the empty string, not an error.
        assert_eq!(rendered("cat", &[]), "");
    }

    #[test]
    fn indent_and_nindent_match_the_upstream_parity_cases() {
        // {{ indent 2 "a\nb" }} renders "  a\n  b".
        assert_eq!(rendered("indent", &[count(2.0), text("a\nb")]), "  a\n  b");
        // {{ nindent 2 "a\nb" }} renders "\n  a\n  b".
        assert_eq!(
            rendered("nindent", &[count(2.0), text("a\nb")]),
            "\n  a\n  b"
        );
        // The split is on a line feed alone, so a trailing newline is padded as
        // its own empty line, and an empty value is one padded empty line.
        assert_eq!(rendered("indent", &[count(1.0), text("a\n")]), " a\n ");
        assert_eq!(rendered("indent", &[count(2.0), text("")]), "  ");
        // A carriage return stays at the end of its line.
        assert_eq!(
            rendered("indent", &[count(1.0), text("a\r\nb")]),
            " a\r\n b"
        );
    }

    #[test]
    fn swapcase_matches_the_upstream_parity_case() {
        // {{ swapcase "Hello" }} renders "hELLO".
        assert_eq!(rendered("swapcase", &[text("Hello")]), "hELLO");
        // `SwapCase` maps character by character, so a character with no case
        // is untouched.
        assert_eq!(rendered("swapcase", &[text("Go 1.21!")]), "gO 1.21!");
    }

    #[test]
    fn initials_matches_the_upstream_parity_case() {
        // {{ initials "First Try" }} renders "FT".
        assert_eq!(rendered("initials", &[text("First Try")]), "FT");
        // `InitialLetters` takes the first character of every whitespace run,
        // including the last.
        assert_eq!(rendered("initials", &[text("  neo   env  ")]), "ne");
        assert_eq!(rendered("initials", &[text("  ")]), "");
    }

    #[test]
    fn nospace_matches_the_upstream_parity_case() {
        // {{ nospace "h e l l o " }} renders "hello".
        assert_eq!(rendered("nospace", &[text("h e l l o ")]), "hello");
        // `NoSpace` drops whitespace anywhere, not only spaces at the ends.
        assert_eq!(rendered("nospace", &[text("a\tb\nc\rd")]), "abcd");
    }

    #[test]
    fn camelcase_matches_the_upstream_parity_cases() {
        // {{ camelcase "_camel_case" }} renders "_CamelCase", and
        // {{ camelcase "_complex__case_" }} renders "_Complex_Case_".
        assert_eq!(rendered("camelcase", &[text("_camel_case")]), "_CamelCase");
        assert_eq!(
            rendered("camelcase", &[text("_complex__case_")]),
            "_Complex_Case_"
        );
        // `PascalWords` capitalises each word and drops everything that is
        // neither a letter, a digit, nor an underscore.
        assert_eq!(rendered("camelcase", &[text("HTTPServer")]), "HttpServer");
        assert_eq!(rendered("camelcase", &[text("foo-bar baz")]), "FooBarBaz");
    }

    #[test]
    fn kebabcase_and_snakecase_match_the_upstream_parity_cases() {
        // {{ snakecase "HTTPServer" }} renders "http_server" and
        // {{ snakecase "NoHTTPS" }} renders "no_https": an upper-case letter
        // that is followed by a lower-case one starts a new word, one that is
        // only preceded by one does not.
        assert_eq!(rendered("snakecase", &[text("HTTPServer")]), "http_server");
        assert_eq!(rendered("snakecase", &[text("NoHTTPS")]), "no_https");
        // {{ kebabcase "GO_PATH" }} renders "go-path": an underscore is not a
        // letter, so it ends a word and is dropped.
        assert_eq!(rendered("kebabcase", &[text("GO_PATH")]), "go-path");
        assert_eq!(rendered("kebabcase", &[text("HTTPServer")]), "http-server");
        assert_eq!(rendered("snakecase", &[text("a..b")]), "a_b");
    }

    #[test]
    fn abbrev_matches_the_upstream_parity_cases() {
        // {{ abbrev 3 "hello world" }} renders "hello world": a size below four
        // leaves no room for the ellipsis.
        assert_eq!(
            rendered("abbrev", &[count(3.0), text("hello world")]),
            "hello world"
        );
        // A size at or above the length of the value is the value.
        assert_eq!(
            rendered("abbrev", &[count(11.0), text("hello world")]),
            "hello world"
        );
        assert_eq!(
            rendered("abbrev", &[count(99.0), text("hello world")]),
            "hello world"
        );
        // Otherwise the front is kept and the total is the size, ellipsis
        // included.
        assert_eq!(
            rendered("abbrev", &[count(8.0), text("hello world")]),
            "hello..."
        );
        assert_eq!(
            rendered("abbrev", &[count(4.0), text("hello world")]),
            "h..."
        );
    }

    #[test]
    fn abbrevboth_matches_the_upstream_parity_cases() {
        // {{ abbrevboth 5 10 "1234 5678 9123" }} renders "...5678...".
        assert_eq!(
            rendered(
                "abbrevboth",
                &[count(5.0), count(10.0), text("1234 5678 9123")]
            ),
            "...5678..."
        );
        // {{ abbrevboth 0 3 "hello world" }} renders "hello world", a size below
        // four leaving no room for two ellipses.
        assert_eq!(
            rendered("abbrevboth", &[count(0.0), count(3.0), text("hello world")]),
            "hello world"
        );
        // {{ abbrevboth 1 6 "hello world" }} renders "hello world": a non-zero
        // left count needs a size of at least seven to be worth it.
        assert_eq!(
            rendered("abbrevboth", &[count(1.0), count(6.0), text("hello world")]),
            "hello world"
        );
        // A size at or above the length of the value is the value, and the two
        // ellipses take six of the size, so a size of seven keeps one byte.
        assert_eq!(
            rendered(
                "abbrevboth",
                &[count(0.0), count(11.0), text("hello world")]
            ),
            "hello world"
        );
        assert_eq!(
            rendered("abbrevboth", &[count(0.0), count(7.0), text("abcdefgh")]),
            "...a..."
        );
        // The reference hands a negative count to .NET's `Skip`, which throws.
        assert!(matches!(
            refused(
                "abbrevboth",
                &[count(-1.0), count(10.0), text("hello world")]
            ),
            Error::InvalidArgument { .. }
        ));
    }

    #[test]
    fn wrap_and_wrapwith_match_the_upstream_parity_cases() {
        // {{ wrap 5 "Hello World" }} renders "Hello\nWorld": the fit test counts
        // the space that would join the word, so two five-wide words do not
        // fit on one five-wide line.
        assert_eq!(
            rendered("wrap", &[count(5.0), text("Hello World")]),
            "Hello\nWorld"
        );
        // {{ wrapWith 5 "\t" "Hello World" }} renders "Hello\tWorld".
        assert_eq!(
            rendered("wrapWith", &[count(5.0), text("\t"), text("Hello World")]),
            "Hello\tWorld"
        );
        // Words are separated by runs of whitespace with the empty pieces
        // dropped, and a width of zero returns the value untouched. A width of
        // one does not, because the reference only refuses a width below one.
        assert_eq!(
            rendered("wrap", &[count(0.0), text("Hello World")]),
            "Hello World"
        );
        assert_eq!(
            rendered("wrap", &[count(1.0), text("Hello World")]),
            "Hello\nWorld"
        );
        // A word that fits exactly still joins the line, because the fit test
        // only breaks when the line plus the word and a space is too wide.
        assert_eq!(
            rendered("wrap", &[count(11.0), text("Hello  World")]),
            "Hello World"
        );
        assert_eq!(
            rendered("wrap", &[count(8.0), text("a bb ccc dddd")]),
            "a bb ccc\ndddd"
        );
        assert_eq!(
            rendered("wrap", &[count(7.0), text("a bb ccc dddd")]),
            "a bb\nccc\ndddd"
        );
        // A word wider than the column still gets a line of its own.
        assert_eq!(rendered("wrap", &[count(2.0), text("ab cd")]), "ab\ncd");
    }

    #[test]
    fn tostring_renders_whatever_it_is_given() {
        // `ToString` in the reference renders its argument rather than
        // inspecting it, so a number and a list both print.
        assert_eq!(rendered("toString", &[count(8080.0)]), "8080");
        assert_eq!(
            rendered("toString", &[Value::List(vec![text("a"), text("b")])]),
            "[a b]"
        );
        assert_eq!(rendered("toString", &[Value::Bool(true)]), "true");
    }

    #[test]
    fn plural_matches_the_upstream_parity_cases() {
        // {{ plural "item" "items" 1 }} renders "item" and
        // {{ plural "item" "items" 2 }} renders "items".
        assert_eq!(
            rendered("plural", &[text("item"), text("items"), count(1.0)]),
            "item"
        );
        assert_eq!(
            rendered("plural", &[text("item"), text("items"), count(2.0)]),
            "items"
        );
        // {{ len "two" | plural "1 char" "chars" }} renders "chars", so the
        // count arrives as a number and anything but one is plural.
        assert_eq!(
            rendered("plural", &[text("1 char"), text("chars"), count(3.0)]),
            "chars"
        );
        // `Plural` tests the count for exactly one, so zero is plural.
        assert_eq!(
            rendered("plural", &[text("item"), text("items"), count(0.0)]),
            "items"
        );
    }

    #[test]
    fn sha1sum_matches_the_upstream_parity_case() {
        // {{ sha1sum "abc" }} renders "a9993e364706816aba3e25717850c26c9cd0d89d".
        assert_eq!(
            rendered("sha1sum", &[text("abc")]),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        // The empty value, and a value that spans more than one block, which is
        // where a hand-written padding is most likely to be wrong.
        assert_eq!(
            rendered("sha1sum", &[text("")]),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        assert_eq!(
            rendered("sha1sum", &[text(&"a".repeat(1000))]),
            "291e9a6c66994949b57ba5e650361e98fc36b1ba"
        );
        assert_eq!(
            rendered("sha1sum", &[text("héllo wörld")]),
            "24e9f5c07847ff8a2a9fa77456655792f5bc7f9f"
        );
    }

    #[test]
    fn sha256sum_matches_the_upstream_parity_case() {
        // {{ sha256sum "abc" }} renders
        // "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".
        assert_eq!(
            rendered("sha256sum", &[text("abc")]),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            rendered("sha256sum", &[text("")]),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // A length that lands in each of the three padding cases, 55, 56, and
        // 64 bytes, plus a multi-block value.
        assert_eq!(
            rendered("sha256sum", &[text(&"a".repeat(55))]),
            "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"
        );
        assert_eq!(
            rendered("sha256sum", &[text(&"a".repeat(56))]),
            "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"
        );
        assert_eq!(
            rendered("sha256sum", &[text(&"a".repeat(64))]),
            "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"
        );
        assert_eq!(
            rendered("sha256sum", &[text(&"a".repeat(1000))]),
            "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"
        );
        // A multi-byte rune hashes as its UTF-8 bytes.
        assert_eq!(
            rendered("sha256sum", &[text("héllo wörld")]),
            "a1003f7d04a4115711d0b48a2eaf1359ce565d2d2a6fd65098dfcffadeeef59f"
        );
    }

    #[test]
    fn adler32sum_matches_the_upstream_parity_case() {
        // {{ adler32sum "abc" }} renders "38600999", the decimal checksum the
        // reference writes rather than a hex digest.
        assert_eq!(rendered("adler32sum", &[text("abc")]), "38600999");
        // The empty value is the Adler-32 initial state, one.
        assert_eq!(rendered("adler32sum", &[text("")]), "1");
        // The result is unsigned: a long run of the largest byte exceeds the
        // signed 32-bit range, so a signed reading would render a negative
        // number.
        assert_eq!(
            rendered("adler32sum", &[text(&"a".repeat(1000))]),
            "4191714040"
        );
        assert_eq!(rendered("adler32sum", &[text("héllo wörld")]), "773523054");
    }

    #[test]
    fn only_the_text_helpers_take_rendered_strings() {
        for name in [
            "trim",
            "trimAll",
            "trimPrefix",
            "trimSuffix",
            "upper",
            "lower",
            "title",
            "untitle",
            "repeat",
            "substr",
            "trunc",
            "replace",
            "split",
            "splitn",
            "cat",
            "indent",
            "nindent",
            "swapcase",
            "initials",
            "camelcase",
            "kebabcase",
            "snakecase",
            "nospace",
            "abbrev",
            "abbrevboth",
            "wrap",
            "wrapWith",
            "toString",
            "sha1sum",
            "sha256sum",
            "adler32sum",
        ] {
            assert!(
                takes_rendered_strings(name),
                "{name} takes rendered strings"
            );
        }
        // These answer a boolean, return a list, or need a typed number, so the
        // engine must hand them the value rather than its rendering.
        for name in ["contains", "hasPrefix", "hasSuffix", "splitList", "plural"] {
            assert!(!takes_rendered_strings(name), "{name} takes typed values");
        }
        // A name this module does not claim says nothing about it.
        assert!(!takes_rendered_strings("regexMatch"));
    }

    #[test]
    fn the_wrong_number_of_arguments_is_an_arity_error() {
        assert!(matches!(
            refused("upper", &[]),
            Error::WrongArgumentCount { actual: 0, .. }
        ));
        assert!(matches!(
            refused("substr", &[count(0.0), count(1.0)]),
            Error::WrongArgumentCount { actual: 2, .. }
        ));
        assert!(matches!(
            refused("wrapWith", &[count(5.0), text(" "), text("a"), text("b")]),
            Error::WrongArgumentCount { actual: 4, .. }
        ));
        // `cat` is variadic, so any count is fine.
        assert_eq!(rendered("cat", &[text("a"), text("b"), text("c")]), "a b c");
    }

    #[test]
    fn a_name_this_module_does_not_claim_is_left_to_the_next_one() {
        assert!(call("regexMatch", &[text("a")]).is_none());
        assert!(call("", &[]).is_none());
    }
}

/// Formats the SHA-512 digest of `data` as lowercase hex.
///
/// SHA-512 is the same construction as SHA-256 over 64-bit words with a longer
/// schedule and a different round count, so it is written out here rather than
/// pulled in as a dependency: a Compose template that wants a digest should not
/// drag a crypto stack into the binary, and the two lines that are actually
/// different from SHA-256 are the word size and the constants.
///
/// The additions are carried in a `u128` because two 64-bit words sum to 65 bits,
/// and truncating the carry would make every other round wrong.
#[allow(clippy::many_single_char_names, clippy::too_many_lines)]
fn sha512_hex(data: &[u8]) -> String {
    use std::fmt::Write as _;

    /// The first sixty-four bits of the fractional parts of the cube roots of the
    /// first eighty primes, as specified for SHA-512.
    const INITIAL: [u64; 8] = [
        0x6a09_e667_f3bc_c908,
        0xbb67_ae85_84ca_a73b,
        0x3c6e_f372_fe94_f82b,
        0xa54f_f53a_5f1d_36f1,
        0x510e_527f_ade6_82d1,
        0x9b05_688c_2b3e_6c1f,
        0x1f83_d9ab_fb41_bd6b,
        0x5be0_cd19_137e_2179,
    ];
    /// The first sixty-four bits of the fractional parts of the cube roots of the
    /// first eighty primes, again as specified.
    const K: [u64; 80] = [
        0x428a_2f98_d728_ae22,
        0x7137_4491_23ef_65cd,
        0xb5c0_fbcf_ec4d_3b2f,
        0xe9b5_dba5_8189_dbbc,
        0x3956_c25b_f348_b538,
        0x59f1_11f1_b605_d019,
        0x923f_82a4_af19_4f9b,
        0xab1c_5ed5_da6d_8118,
        0xd807_aa98_a303_0242,
        0x1283_5b01_4570_6fbe,
        0x2431_85be_4ee4_b28c,
        0x550c_7dc3_d5ff_b4e2,
        0x72be_5d74_f27b_896f,
        0x80de_b1fe_3b16_96b1,
        0x9bdc_06a7_25c7_1235,
        0xc19b_f174_cf69_2694,
        0xe49b_69c1_9ef1_4ad2,
        0xefbe_4786_384f_25e3,
        0x0fc1_9dc6_8b8c_d5b5,
        0x240c_a1cc_77ac_9c65,
        0x2de9_2c6f_592b_0275,
        0x4a74_84aa_6ea6_e483,
        0x5cb0_a9dc_bd41_fbd4,
        0x76f9_88da_8311_53b5,
        0x983e_5152_ee66_dfab,
        0xa831_c66d_2db4_3210,
        0xb003_27c8_98fb_213f,
        0xbf59_7fc7_beef_0ee4,
        0xc6e0_0bf3_3da8_8fc2,
        0xd5a7_9147_930a_a725,
        0x06ca_6351_e003_826f,
        0x1429_2967_0a0e_6e70,
        0x27b7_0a85_46d2_2ffc,
        0x2e1b_2138_5c26_c926,
        0x4d2c_6dfc_5ac4_2aed,
        0x5338_0d13_9d95_b3df,
        0x650a_7354_8baf_63de,
        0x766a_0abb_3c77_b2a8,
        0x81c2_c92e_47ed_aee6,
        0x9272_2c85_1482_353b,
        0xa2bf_e8a1_4cf1_0364,
        0xa81a_664b_bc42_3001,
        0xc24b_8b70_d0f8_9791,
        0xc76c_51a3_0654_be30,
        0xd192_e819_d6ef_5218,
        0xd699_0624_5565_a910,
        0xf40e_3585_5771_202a,
        0x106a_a070_32bb_d1b8,
        0x19a4_c116_b8d2_d0c8,
        0x1e37_6c08_5141_ab53,
        0x2748_774c_df8e_eb99,
        0x34b0_bcb5_e19b_48a8,
        0x391c_0cb3_c5c9_5a63,
        0x4ed8_aa4a_e341_8acb,
        0x5b9c_ca4f_7763_e373,
        0x682e_6ff3_d6b2_b8a3,
        0x748f_82ee_5def_b2fc,
        0x78a5_636f_4317_2f60,
        0x84c8_7814_a1f0_ab72,
        0x8cc7_0208_1a64_39ec,
        0x90be_fffa_2363_1e28,
        0xa450_6ceb_de82_bde9,
        0xbef9_a3f7_b2c6_7915,
        0xc671_78f2_e372_532b,
        0xca27_3ece_ea26_619c,
        0xd186_b8c7_21c0_c207,
        0xeada_7dd6_cde0_eb1e,
        0xf57d_4f7f_ee6e_d178,
        0x06f0_67aa_7217_6fba,
        0x0a63_7dc5_a2c8_98a6,
        0x113f_9804_bef9_0dae,
        0x1b71_0b35_131c_471b,
        0x28db_77f5_2304_7d84,
        0x32ca_ab7b_40c7_2493,
        0x3c9e_be0a_15c9_bebc,
        0x431d_67c4_9c10_0d4c,
        0x4cc5_d4be_cb3e_42b6,
        0x597f_299c_fc65_7e2a,
        0x5fcb_6fab_3ad6_faec,
        0x6c44_198c_4a47_5817,
    ];

    let mut state = INITIAL;
    let mut message = data.to_vec();
    // A 128-bit length field, and a 128-byte block, so the padding is the byte
    // 0x80 then zeros then the length. The high word of the length is written
    // even though it is always zero for an input this crate can hold, because
    // the digest is defined over all 2^64 bits.
    let bit_length = (data.len() as u128) * 8;
    message.push(0x80);
    while message.len() % 128 != 112 {
        message.push(0);
    }
    message.extend_from_slice(&bit_length.to_be_bytes());

    for block in message.chunks(128) {
        let mut w = [0u64; 80];
        for (index, word) in block.chunks(8).enumerate() {
            w[index] = u64::from_be_bytes(word.try_into().expect("eight bytes"));
        }
        for index in 16..80 {
            let s0 = w[index - 15].rotate_right(1)
                ^ w[index - 15].rotate_right(8)
                ^ (w[index - 15] >> 7);
            let s1 =
                w[index - 2].rotate_right(19) ^ w[index - 2].rotate_right(61) ^ (w[index - 2] >> 6);
            w[index] = w[index - 16]
                .wrapping_add(s0)
                .wrapping_add(w[index - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ ((!e) & g);
            // A `u64` always fits a `u128`, so these are widening conversions
            // rather than casts that could lose anything.
            let temp1 = u128::from(h)
                + u128::from(s1)
                + u128::from(ch)
                + u128::from(K[index])
                + u128::from(w[index]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = u128::from(s0) + u128::from(maj);
            h = g;
            g = f;
            f = e;
            e = (u128::from(d) + temp1) as u64;
            d = c;
            c = b;
            b = a;
            a = (temp1 + temp2) as u64;
        }
        for (slot, value) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(value);
        }
    }

    // Written through `write!` rather than `format!` per word, because a digest
    // is built once and the intermediate strings are pure overhead.
    let mut out = String::with_capacity(state.len() * 16);
    for word in &state {
        let _ = write!(out, "{word:016x}");
    }
    out
}

#[cfg(test)]
mod sha512_tests {
    use super::sha512_hex;

    /// The published SHA-512 vectors.
    ///
    /// The constants are *computed* from their definition rather than typed in,
    /// so these digests are what actually pins the implementation: a wrong
    /// constant, a wrong word width, or a wrong carry would change the output and
    /// fail here. The empty-string vector also covers the padding path, and the
    /// one-block vector covers the length encoding.
    #[test]
    fn sha512_matches_the_published_vectors() {
        assert_eq!(
            sha512_hex(b"abc"),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
        assert_eq!(
            sha512_hex(b""),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
             47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
    }

    /// A message that spans several blocks exercises the schedule recurrence
    /// across block boundaries, which a one-block vector cannot reach.
    #[test]
    fn sha512_handles_a_multi_block_message() {
        // 200 bytes of the repeating pattern, which is one full block plus a
        // partial one and so forces a second round of the message schedule.
        let data: Vec<u8> = (0..200u32).map(|index| (index % 251) as u8).collect();
        let digest = sha512_hex(&data);
        assert_eq!(digest.len(), 128, "SHA-512 is 512 bits, so 128 hex digits");
        assert!(
            digest
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }
}
