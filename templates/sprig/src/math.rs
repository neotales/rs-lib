//! The arithmetic helpers.
//!
//! Every method here is a port of one method in the reference's
//! `SprigFunctions.cs`, and the comment on each says which one. Two of the
//! reference's spellings differ from what the helper's name suggests and were
//! confirmed against `fixtures/sprig/upstream_parity.json` rather than assumed:
//!
//! - `div` and `mod` are integer operations (`Divide`, `Modulo`) and `divf` is
//!   the floating-point one, which is the opposite of what "div" suggests.
//! - `toDecimal` (`ToDecimal`) does not group digits with commas. It reads its
//!   argument as a decimal integer and then reinterprets those digits in base
//!   eight, so `toDecimal "0755"` is 493.
//!
//! The one behavior that cannot be ported is a floating-point result's trailing
//! zeros. The reference computes with C# `decimal`, which carries a scale, and
//! renders `mulf 1.5 2` as `3.0` and reports `addf 1.0 2.0` as a `float64`.
//! `Value::Number` is an `f64` and renders through Go's `text/template` rules,
//! where a whole number has no fractional part, so the same results render as
//! `3` here. `the_reference_decimal_scale_is_not_representable` in the tests
//! below records exactly which fixture cases that costs and why returning a
//! string instead would be worse.

use crate::support::{any_text, float};
use crate::{Context, Error, Value, arity, invalid};

/// Dispatches a math helper.
pub(super) const DISPATCH: crate::Dispatch =
    |name, arguments, context| dispatch(name, arguments, context);

#[allow(clippy::trivially_copy_pass_by_ref)]
fn dispatch(
    name: &str,
    arguments: &[Value],
    context: &Context<'_>,
) -> Option<Result<Value, Error>> {
    let _ = context;
    let result = match name {
        "add" => sum(name, arguments),
        "add1" => add_one(name, arguments),
        "sub" => subtract(name, arguments),
        "mul" => product(name, arguments),
        "div" => quotient(name, arguments),
        "mod" => remainder(name, arguments),
        // The reference registers `biggest` against the same method as `max`.
        "max" | "biggest" => largest(name, arguments),
        "min" => smallest(name, arguments),
        "floor" => floor(name, arguments),
        "ceil" => ceiling(name, arguments),
        "round" => round(name, arguments),
        "maxf" => largest_float(name, arguments),
        "minf" => smallest_float(name, arguments),
        "addf" => sum_float(name, arguments),
        "add1f" => add_one_float(name, arguments),
        "subf" => subtract_float(name, arguments),
        "mulf" => product_float(name, arguments),
        "divf" => quotient_float(name, arguments),
        "int" | "int64" | "atoi" => whole_number(name, arguments),
        "float64" => to_float(name, arguments),
        "toDecimal" => to_decimal(name, arguments),
        _ => return None,
    };
    Some(result)
}

/// Reports whether this module's helper wants rendered string arguments.
///
/// Never. An integer helper that received `"3"` as text would have to parse it
/// back, and the fixture's `{{ add 1 2 }}` is only a sum if the arguments arrive
/// as the numbers they were written as.
pub(super) fn takes_rendered_strings(_name: &str) -> bool {
    false
}

/// The numeric value of an integer result.
///
/// An `i64` is not exactly representable as an `f64` above 2^53, but every other
/// integer is, and Go's `int64` is rendered the same way once it is a `float64`.
#[allow(clippy::cast_precision_loss)]
fn number(value: i64) -> Value {
    Value::Number(value as f64)
}

/// Coerces an argument to a whole number, the reference's `NLong`.
///
/// A boolean is one or zero, a number is truncated toward zero, and a string is
/// read as a decimal number and truncated, so `int "42.9"` is 42 as the
/// reference's `decimal.TryParse` and `decimal.Truncate` make it. Go's
/// `toInt64` renders an argument it cannot read as zero; this crate refuses it
/// instead, which is the policy `Error::InvalidArgument` documents.
fn whole(helper: &str, value: &Value) -> Result<i64, Error> {
    match value {
        Value::Bool(flag) => Ok(i64::from(*flag)),
        // A float beyond `i64`'s range saturates rather than wrapping, because
        // Rust's cast saturates and Go's would have overflowed silently anyway.
        #[allow(clippy::cast_possible_truncation)]
        Value::Number(number) | Value::Float(number) => Ok(*number as i64),
        Value::String(text) => {
            let trimmed = text.trim();
            if let Ok(value) = trimmed.parse::<i64>() {
                return Ok(value);
            }
            match trimmed.parse::<f64>() {
                #[allow(clippy::cast_possible_truncation)]
                Ok(value) if value.is_finite() => Ok(value as i64),
                _ => Err(invalid(
                    helper,
                    format!("cannot read {trimmed:?} as an integer"),
                )),
            }
        }
        other => Err(invalid(
            helper,
            format!("cannot read {} as an integer", other.render()),
        )),
    }
}

/// Reports a floating-point result whose scale follows its operands.
///
/// The reference computes with `decimal`, which carries a scale, and a reader
/// can see it: `{{ mulf 1.5 2 }}` is `3.0` because the multiplication kept one
/// decimal place, while `{{ addf 1 2 }}` is `3` because the terms had none. An
/// `f64` cannot carry a scale, so the operands decide: a result is a float when
/// any operand was written as one. That reproduces both spellings without
/// inventing a decimal type.
fn scaled(helper: &str, value: f64, arguments: &[Value]) -> Result<Value, Error> {
    if !value.is_finite() {
        return Err(invalid(helper, "produces a number too large to represent"));
    }
    if arguments
        .iter()
        .any(|argument| matches!(argument, Value::Float(_)))
    {
        return Ok(Value::Float(value));
    }
    #[allow(clippy::cast_possible_truncation)]
    if value.fract() == 0.0 && value.abs() < 9.007_199_254_740_992e15 {
        return Ok(number(value as i64));
    }
    Ok(Value::Float(value))
}

/// `Add`: the sum of any number of arguments, including none.
fn sum(helper: &str, arguments: &[Value]) -> Result<Value, Error> {
    arity(helper, arguments.len(), 0, None)?;
    let mut total = 0i64;
    for argument in arguments {
        total = total.wrapping_add(whole(helper, argument)?);
    }
    Ok(number(total))
}

/// `Add1`: the first argument plus one.
fn add_one(helper: &str, arguments: &[Value]) -> Result<Value, Error> {
    arity(helper, arguments.len(), 1, Some(1))?;
    Ok(number(whole(helper, &arguments[0])?.wrapping_add(1)))
}

/// `Subtract`: the first argument less the second.
fn subtract(helper: &str, arguments: &[Value]) -> Result<Value, Error> {
    arity(helper, arguments.len(), 2, Some(2))?;
    let left = whole(helper, &arguments[0])?;
    let right = whole(helper, &arguments[1])?;
    Ok(number(left.wrapping_sub(right)))
}

/// `Multiply`: the product of one or more arguments.
fn product(helper: &str, arguments: &[Value]) -> Result<Value, Error> {
    arity(helper, arguments.len(), 1, None)?;
    let mut total = 1i64;
    for argument in arguments {
        total = total.wrapping_mul(whole(helper, argument)?);
    }
    Ok(number(total))
}

/// `Divide`: integer division, truncated toward zero.
fn quotient(helper: &str, arguments: &[Value]) -> Result<Value, Error> {
    arity(helper, arguments.len(), 2, Some(2))?;
    let left = whole(helper, &arguments[0])?;
    let right = whole(helper, &arguments[1])?;
    // Go's integer division by zero panics and the reference's throws; neither
    // is an answer, so the caller's mistake is reported instead.
    left.checked_div(right)
        .map(number)
        .ok_or_else(|| invalid(helper, "cannot divide by zero"))
}

/// `Modulo`: the remainder after integer division, with Go's truncated sign.
fn remainder(helper: &str, arguments: &[Value]) -> Result<Value, Error> {
    arity(helper, arguments.len(), 2, Some(2))?;
    let left = whole(helper, &arguments[0])?;
    let right = whole(helper, &arguments[1])?;
    left.checked_rem(right)
        .map(number)
        .ok_or_else(|| invalid(helper, "cannot divide by zero"))
}

/// `Max`: the largest of one or more arguments.
fn largest(helper: &str, arguments: &[Value]) -> Result<Value, Error> {
    arity(helper, arguments.len(), 1, None)?;
    let mut best = whole(helper, &arguments[0])?;
    for argument in &arguments[1..] {
        best = best.max(whole(helper, argument)?);
    }
    Ok(number(best))
}

/// `Min`: the smallest of one or more arguments.
fn smallest(helper: &str, arguments: &[Value]) -> Result<Value, Error> {
    arity(helper, arguments.len(), 1, None)?;
    let mut best = whole(helper, &arguments[0])?;
    for argument in &arguments[1..] {
        best = best.min(whole(helper, argument)?);
    }
    Ok(number(best))
}

/// `Floor`: the largest whole number not greater than the argument.
fn floor(helper: &str, arguments: &[Value]) -> Result<Value, Error> {
    arity(helper, arguments.len(), 1, Some(1))?;
    let value = float(helper, &arguments[0])?;
    if !value.is_finite() {
        return Err(invalid(helper, "expects a finite number"));
    }
    // A whole number outside `i64` saturates. The reference's cast to `long`
    // is undefined there, so the bound is this crate's own.
    #[allow(clippy::cast_possible_truncation)]
    return Ok(number(value.floor() as i64));
}

/// `Ceiling`: the smallest whole number not less than the argument.
fn ceiling(helper: &str, arguments: &[Value]) -> Result<Value, Error> {
    arity(helper, arguments.len(), 1, Some(1))?;
    let value = float(helper, &arguments[0])?;
    if !value.is_finite() {
        return Err(invalid(helper, "expects a finite number"));
    }
    #[allow(clippy::cast_possible_truncation)]
    Ok(number(value.ceil() as i64))
}

/// `Round`: the value rounded to a number of decimal places.
///
/// The reference scales by a power of ten, then rounds the *fraction* of the
/// scaled value up or down. That is not `math.Round`: a negative half rounds
/// toward zero, so `round -1.5 0` is -1. The threshold is the third argument
/// when it is given and 0.5 otherwise, which is what makes `round 123.233 2 0.3`
/// 123.24 while `round 123.233 2` would be 123.23.
fn round(helper: &str, arguments: &[Value]) -> Result<Value, Error> {
    arity(helper, arguments.len(), 2, Some(3))?;
    let value = float(helper, &arguments[0])?;
    let places = whole(helper, &arguments[1])?;
    // `Pow10` bounds the precision to what the reference's `decimal` can hold.
    let Ok(places) = i32::try_from(places) else {
        return Err(invalid(helper, "expects a precision between -28 and 28"));
    };
    if !(-28..=28).contains(&places) {
        return Err(invalid(helper, "expects a precision between -28 and 28"));
    }
    let threshold = if arguments.len() == 3 {
        float(helper, &arguments[2])?
    } else {
        0.5
    };
    let power = 10f64.powi(places);
    let scaled = value * power;
    let fraction = scaled - scaled.floor();
    let rounded = if fraction >= threshold {
        scaled.ceil()
    } else {
        scaled.floor()
    };
    // `round` divides by a power of ten, and the reference's `decimal` division
    // drops the scale it no longer needs: `round 1.5 0` is `2`, not `2.0`, while
    // `round 123.233 2` keeps its two places. A whole result is therefore an
    // integer and a fractional one is a float, which is the same distinction a
    // reader sees in the reference's own output.
    let result = rounded / power;
    if !result.is_finite() {
        return Err(invalid(helper, "produces a number too large to represent"));
    }
    #[allow(clippy::cast_possible_truncation)]
    if result.fract() == 0.0 && result.abs() < 9.007_199_254_740_992e15 {
        return Ok(number(result as i64));
    }
    Ok(Value::Float(result))
}

/// `AddFloat`: the sum of any number of arguments as floating-point numbers.
fn sum_float(helper: &str, arguments: &[Value]) -> Result<Value, Error> {
    arity(helper, arguments.len(), 0, None)?;
    let mut total = 0.0f64;
    for argument in arguments {
        total += float(helper, argument)?;
    }
    scaled(helper, total, arguments)
}

/// `Add1Float`: the first argument plus one, as floating point.
fn add_one_float(helper: &str, arguments: &[Value]) -> Result<Value, Error> {
    arity(helper, arguments.len(), 1, Some(1))?;
    scaled(helper, float(helper, &arguments[0])? + 1.0, arguments)
}

/// `SubtractFloat`: the first argument less every later one.
fn subtract_float(helper: &str, arguments: &[Value]) -> Result<Value, Error> {
    arity(helper, arguments.len(), 2, None)?;
    let mut total = float(helper, &arguments[0])?;
    for argument in &arguments[1..] {
        total -= float(helper, argument)?;
    }
    scaled(helper, total, arguments)
}

/// `MultiplyFloat`: the product of one or more arguments, as floating point.
fn product_float(helper: &str, arguments: &[Value]) -> Result<Value, Error> {
    arity(helper, arguments.len(), 1, None)?;
    let mut total = 1.0f64;
    for argument in arguments {
        total *= float(helper, argument)?;
    }
    scaled(helper, total, arguments)
}

/// `DivideFloat`: the first argument divided by every later one.
///
/// A zero divisor is an error rather than an infinity: the reference's `decimal`
/// division throws for it, and an `+Inf` in a rendered value would be worse
/// than a failure.
fn quotient_float(helper: &str, arguments: &[Value]) -> Result<Value, Error> {
    arity(helper, arguments.len(), 2, None)?;
    let mut total = float(helper, &arguments[0])?;
    for argument in &arguments[1..] {
        let divisor = float(helper, argument)?;
        if divisor == 0.0 {
            return Err(invalid(helper, "cannot divide by zero"));
        }
        total /= divisor;
    }
    scaled(helper, total, arguments)
}

/// `MaxFloat`: the largest of one or more arguments, as floating point.
fn largest_float(helper: &str, arguments: &[Value]) -> Result<Value, Error> {
    arity(helper, arguments.len(), 1, None)?;
    pick_float(helper, arguments, |left, right| left > right)
}

/// `MinFloat`: the smallest of one or more arguments, as floating point.
fn smallest_float(helper: &str, arguments: &[Value]) -> Result<Value, Error> {
    arity(helper, arguments.len(), 1, None)?;
    pick_float(helper, arguments, |left, right| left < right)
}

/// Returns the winning *argument*, not a number computed from it.
///
/// The reference's `MaxFloat` and `MinFloat` select one of their arguments and
/// return it unchanged, so `{{ maxf 1.4 2 3 }}` is `3` and not `3.0`: the `3` was
/// written as an integer and keeps that spelling, while `{{ minf 1.4 2 3 }}` is
/// `1.4` for the same reason. Recomputing a value and re-typing it would lose
/// exactly that.
fn pick_float(
    helper: &str,
    arguments: &[Value],
    better: fn(f64, f64) -> bool,
) -> Result<Value, Error> {
    let mut best = &arguments[0];
    let mut best_value = float(helper, best)?;
    for argument in &arguments[1..] {
        let value = float(helper, argument)?;
        if better(value, best_value) {
            best = argument;
            best_value = value;
        }
    }
    Ok(best.clone())
}

/// `Integer`: the argument truncated to a whole number.
///
/// One method serves `int`, `int64`, and `atoi`, exactly as the reference
/// registers `Integer` three times.
fn whole_number(helper: &str, arguments: &[Value]) -> Result<Value, Error> {
    arity(helper, arguments.len(), 1, Some(1))?;
    Ok(number(whole(helper, &arguments[0])?))
}

/// `Float`: the argument as a floating-point number.
fn to_float(helper: &str, arguments: &[Value]) -> Result<Value, Error> {
    arity(helper, arguments.len(), 1, Some(1))?;
    // `{{ float64 true }}` is `1`, not `1.0`: the reference's conversion reads a
    // boolean as the integer one and keeps that spelling, so the result follows
    // the argument rather than the helper's own name.
    scaled(helper, float(helper, &arguments[0])?, arguments)
}

/// `ToDecimal`: the argument's decimal digits read in base eight.
///
/// The reference parses the argument with `NumberStyles.AllowLeadingSign`, so a
/// value that is not a signed decimal integer is zero, and then converts that
/// number's own digits with `Convert.ToInt64(…, 8)`, which is what makes
/// `toDecimal "0755"` 493 rather than 755 or `0755`. A digit that is not an
/// octal digit, or a value that does not fit, throws there and is an error here.
fn to_decimal(helper: &str, arguments: &[Value]) -> Result<Value, Error> {
    arity(helper, arguments.len(), 1, Some(1))?;
    let text = any_text(&arguments[0]);
    let Some(decimal) = parse_signed_int(&text) else {
        return Ok(number(0));
    };
    let mut octal: i128 = 0;
    for digit in decimal.unsigned_abs().to_string().bytes() {
        if !digit.is_ascii_digit() || digit > b'7' {
            return Err(invalid(helper, format!("{decimal} is not an octal number")));
        }
        octal = octal * 8 + i128::from(digit - b'0');
    }
    if decimal < 0 {
        octal = -octal;
    }
    let value = i64::try_from(octal).map_err(|_| {
        invalid(
            helper,
            format!("{decimal} does not fit in a 64-bit octal number"),
        )
    })?;
    Ok(number(value))
}

/// Parses an optionally signed decimal integer, as `long.TryParse` with
/// `NumberStyles.AllowLeadingSign` does.
///
/// Only a sign and digits are accepted: no surrounding space, no decimal point,
/// and no exponent, which is what makes `toDecimal " 7"` zero.
fn parse_signed_int(text: &str) -> Option<i64> {
    let (negative, digits) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text.strip_prefix('+').unwrap_or(text)),
    };
    if digits.is_empty() || !digits.bytes().all(|digit| digit.is_ascii_digit()) {
        return None;
    }
    let magnitude: u64 = digits.parse().ok()?;
    if !negative {
        return i64::try_from(magnitude).ok();
    }
    // `i64::MIN` has a magnitude one larger than `i64::MAX`, so it is the one
    // value whose sign cannot be recovered by negating a positive parse.
    if magnitude == (1_u64 << 63) {
        return Some(i64::MIN);
    }
    Some(-i64::try_from(magnitude).ok()?)
}

#[cfg(test)]
mod tests {
    use super::{DISPATCH, takes_rendered_strings};
    use crate::{Error, Value};

    /// Calls a helper the way the engine does and renders the result.
    fn rendered(helper: &str, arguments: &[Value]) -> String {
        crate::call(helper, arguments)
            .unwrap_or_else(|error| panic!("{helper} failed: {error}"))
            .render()
    }

    #[test]
    fn the_module_claims_its_own_helpers() {
        for name in [
            "add",
            "add1",
            "sub",
            "mul",
            "div",
            "mod",
            "max",
            "min",
            "floor",
            "ceil",
            "round",
            "maxf",
            "minf",
            "addf",
            "add1f",
            "subf",
            "mulf",
            "divf",
            "int",
            "int64",
            "float64",
            "atoi",
            "toDecimal",
        ] {
            assert!(
                DISPATCH(name, &[], &crate::Context::default()).is_some(),
                "{name} is not claimed by the math module"
            );
            assert!(!takes_rendered_strings(name));
        }
        assert!(DISPATCH("upper", &[], &crate::Context::default()).is_none());
    }

    #[test]
    fn the_integer_helpers_fold_and_truncate() {
        // `{{ add 1 2 3 }}` and `{{ add 2 3 }}` from the fixture.
        assert_eq!(
            rendered(
                "add",
                &[Value::Number(1.0), Value::Number(2.0), Value::Number(3.0)]
            ),
            "6"
        );
        assert_eq!(
            rendered("add", &[Value::Number(2.0), Value::Number(3.0)]),
            "5"
        );
        // `{{ mul 2 3 4 }}`, `{{ sub 10 3 }}` from the fixture.
        assert_eq!(
            rendered(
                "mul",
                &[Value::Number(2.0), Value::Number(3.0), Value::Number(4.0)]
            ),
            "24"
        );
        assert_eq!(
            rendered("sub", &[Value::Number(10.0), Value::Number(3.0)]),
            "7"
        );
        // `Add1` and the fixture's `{{ add1 3 }}`.
        assert_eq!(rendered("add1", &[Value::Number(3.0)]), "4");
    }

    #[test]
    fn add_returns_a_number_for_kind_of_to_report_as_int() {
        // The fixture's `{{ $value := add 1 2 }}{{ kindOf $value }}` expects
        // `int`, which is what the types module reports for a number with no
        // fractional part. That requires a number, not a rendered string.
        let value = crate::call("add", &[Value::Number(1.0), Value::Number(2.0)]).unwrap();
        assert_eq!(value, Value::Number(3.0));
        assert_eq!(value.render(), "3");
    }

    #[test]
    fn division_and_modulo_are_integer_operations() {
        // `Divide` and `Modulo` use `NLong`, so `{{ div 9 2 }}` is 4 and
        // `{{ mod 9 2 }}` is 1. The float division is `divf`.
        assert_eq!(
            rendered("div", &[Value::Number(9.0), Value::Number(2.0)]),
            "4"
        );
        assert_eq!(
            rendered("mod", &[Value::Number(9.0), Value::Number(2.0)]),
            "1"
        );
        // Truncation is toward zero on both sides, as `decimal.Truncate` is.
        assert_eq!(
            rendered("div", &[Value::Number(-9.0), Value::Number(2.0)]),
            "-4"
        );
        assert_eq!(
            rendered("mod", &[Value::Number(-9.0), Value::Number(2.0)]),
            "-1"
        );
        assert_eq!(
            rendered("div", &[Value::Number(7.0), Value::Number(2.0)]),
            "3"
        );
    }

    #[test]
    fn max_and_min_fold_over_their_arguments() {
        // The fixture's `{{ max 1 3 2 }}`, `{{ max 2 8 3 }}`, and their minima.
        assert_eq!(
            rendered(
                "max",
                &[Value::Number(1.0), Value::Number(3.0), Value::Number(2.0)]
            ),
            "3"
        );
        assert_eq!(
            rendered(
                "max",
                &[Value::Number(2.0), Value::Number(8.0), Value::Number(3.0)]
            ),
            "8"
        );
        assert_eq!(
            rendered(
                "min",
                &[Value::Number(1.0), Value::Number(3.0), Value::Number(2.0)]
            ),
            "1"
        );
        assert_eq!(
            rendered(
                "min",
                &[Value::Number(2.0), Value::Number(8.0), Value::Number(3.0)]
            ),
            "2"
        );
    }

    #[test]
    fn floor_and_ceil_return_whole_numbers() {
        // The fixture's `{{ floor 1.8 }}` and `{{ ceil 1.2 }}`, and the negative
        // cases `Math.Floor` and `Math.Ceiling` define.
        assert_eq!(rendered("floor", &[Value::Number(1.8)]), "1");
        assert_eq!(rendered("ceil", &[Value::Number(1.2)]), "2");
        assert_eq!(rendered("floor", &[Value::Number(-1.2)]), "-2");
        assert_eq!(rendered("ceil", &[Value::Number(-1.2)]), "-1");
        assert_eq!(rendered("floor", &[Value::Number(3.0)]), "3");
    }

    #[test]
    fn round_uses_the_places_and_threshold_arguments() {
        // The fixture's `{{ round 1.5 0 }}`, `{{ round 123.2329999 2 0.3 }}`, and
        // `{{ round 123.233 2 0.3 }}`.
        assert_eq!(
            rendered("round", &[Value::Number(1.5), Value::Number(0.0)]),
            "2"
        );
        assert_eq!(
            rendered(
                "round",
                &[
                    Value::Number(123.232_999_9),
                    Value::Number(2.0),
                    Value::Number(0.3)
                ]
            ),
            "123.23"
        );
        assert_eq!(
            rendered(
                "round",
                &[
                    Value::Number(123.233),
                    Value::Number(2.0),
                    Value::Number(0.3)
                ]
            ),
            "123.24"
        );
        // Without a threshold the fraction rounds at a half.
        assert_eq!(
            rendered("round", &[Value::Number(1.4), Value::Number(0.0)]),
            "1"
        );
        assert_eq!(
            rendered("round", &[Value::Number(1.5), Value::Number(0.0)]),
            "2"
        );
        assert_eq!(
            rendered("round", &[Value::Number(1.2345), Value::Number(2.0)]),
            "1.23"
        );
    }

    #[test]
    fn round_uses_the_reference_fraction_rule_rather_than_math_round() {
        // `Round` compares the fraction of the scaled value with the threshold,
        // so a negative half rounds toward zero: this is not Go's `math.Round`,
        // which rounds a half away from zero, and not banker's rounding either.
        assert_eq!(
            rendered("round", &[Value::Number(-1.5), Value::Number(0.0)]),
            "-1"
        );
        assert_eq!(
            rendered("round", &[Value::Number(-1.6), Value::Number(0.0)]),
            "-2"
        );
    }

    #[test]
    fn round_refuses_a_precision_the_reference_cannot_hold() {
        // `Pow10` throws outside -28 to 28, because a `decimal` cannot hold it.
        for places in [-29.0, 29.0] {
            let error =
                crate::call("round", &[Value::Number(1.5), Value::Number(places)]).unwrap_err();
            assert!(matches!(error, Error::InvalidArgument { .. }), "{error}");
        }
    }

    #[test]
    fn the_float_helpers_use_floating_point_arithmetic() {
        // The fixture's `{{ addf 1.2 2.3 }}`, `{{ add1f 3.4 }}`, `{{ subf 5 1.5 }}`,
        // and `{{ divf 7 2 }}`.
        assert_eq!(
            rendered("addf", &[Value::Number(1.2), Value::Number(2.3)]),
            "3.5"
        );
        assert_eq!(rendered("add1f", &[Value::Number(3.4)]), "4.4");
        assert_eq!(
            rendered("subf", &[Value::Number(5.0), Value::Number(1.5)]),
            "3.5"
        );
        assert_eq!(
            rendered("divf", &[Value::Number(7.0), Value::Number(2.0)]),
            "3.5"
        );
    }

    #[test]
    fn the_float_helpers_fold_like_their_integer_forms() {
        // `AddFloat`, `SubtractFloat`, `MultiplyFloat`, and `DivideFloat` all
        // take more than the two arguments their names suggest.
        assert_eq!(
            rendered(
                "addf",
                &[Value::Number(1.1), Value::Number(2.2), Value::Number(3.3)]
            ),
            "6.6"
        );
        assert_eq!(
            rendered(
                "subf",
                &[Value::Number(5.5), Value::Number(2.2), Value::Number(1.0)]
            ),
            "2.3"
        );
        assert_eq!(
            rendered(
                "mulf",
                &[Value::Number(1.5), Value::Number(2.0), Value::Number(2.0)]
            ),
            "6"
        );
        assert_eq!(
            rendered(
                "divf",
                &[Value::Number(10.0), Value::Number(4.0), Value::Number(2.0)]
            ),
            "1.25"
        );
    }

    #[test]
    fn float_results_carry_the_binary_error_a_float_has() {
        // The reference computes with `decimal`, so `mulf 2.1 5.2 1.3` is
        // 14.196 there. A `float64` has no decimal scale to work in, so the
        // product is 14.196000000000003 — which is the same answer Go's Sprig
        // gives, and the value Go would render.
        assert_eq!(
            rendered(
                "mulf",
                &[Value::Number(2.1), Value::Number(5.2), Value::Number(1.3)]
            ),
            "14.196000000000003"
        );
    }

    #[test]
    fn the_float_extremes_keep_a_fraction() {
        // The fixture's `{{ maxf 1.4 2 3 }}` and `{{ minf 1.4 2 3 }}`. The
        // minimum is a float even though the maximum is a whole number, so
        // these compare as numbers rather than as their rendered text.
        assert_eq!(
            rendered(
                "maxf",
                &[Value::Number(1.4), Value::Number(2.0), Value::Number(3.0)]
            ),
            "3"
        );
        assert_eq!(
            rendered(
                "minf",
                &[Value::Number(1.4), Value::Number(2.0), Value::Number(3.0)]
            ),
            "1.4"
        );
    }

    #[test]
    fn the_reference_decimal_scale_is_not_representable() {
        // The reference computes with C# `decimal`, which carries a scale, so
        // these two fixture cases come out as `3.0` and `float64`:
        //
        //     {{ mulf 1.5 2 }}                              -> 3.0
        //     {{ $value := addf 1.0 2.0 }}{{ kindOf $value }} -> float64
        //
        // `Value::Number` is an `f64` rendered by Go's `text/template` rules,
        // where 1.5 * 2 is the whole number 3, so the same values render as `3`
        // and report `int`. Returning a string would make the second case
        // report `string` and would make `{{ if (addf 0 0) }}` true where the
        // reference's zero number is empty, so the number is kept and the two
        // renderings are recorded here instead.
        assert_eq!(
            rendered("mulf", &[Value::Number(1.5), Value::Number(2.0)]),
            "3"
        );
        assert_eq!(
            rendered("addf", &[Value::Number(1.0), Value::Number(2.0)]),
            "3"
        );
        // A float result is still a number, and a zero one is still empty.
        let zero = crate::call("addf", &[Value::Number(0.0), Value::Number(0.0)]).unwrap();
        assert_eq!(zero, Value::Number(0.0));
        assert!(zero.is_empty());
    }

    #[test]
    fn division_by_zero_is_an_error_rather_than_a_panic_or_an_infinity() {
        // Go panics on integer division by zero and its float division yields an
        // infinity; the reference throws for both. None of those is an answer a
        // rendered value can carry, so all four are errors.
        for (helper, arguments) in [
            ("div", vec![Value::Number(1.0), Value::Number(0.0)]),
            ("mod", vec![Value::Number(1.0), Value::Number(0.0)]),
            ("divf", vec![Value::Number(1.0), Value::Number(0.0)]),
            (
                "divf",
                vec![Value::Number(1.0), Value::Number(2.0), Value::Number(0.0)],
            ),
        ] {
            let error = crate::call(helper, &arguments).unwrap_err();
            assert!(
                matches!(error, Error::InvalidArgument { .. }),
                "{helper} by zero returned {error}"
            );
            assert!(error.to_string().contains("zero"), "{error}");
        }
    }

    #[test]
    fn the_conversions_follow_the_reference() {
        // The fixture's `{{ atoi "42" }}`, `{{ int64 42 }}`, `{{ int true }}`,
        // `{{ int 102.9 }}`, and `{{ float64 true }}`.
        assert_eq!(rendered("atoi", &[Value::String("42".to_owned())]), "42");
        assert_eq!(rendered("int64", &[Value::Number(42.0)]), "42");
        assert_eq!(rendered("int", &[Value::Bool(true)]), "1");
        assert_eq!(rendered("int", &[Value::Number(102.9)]), "102");
        assert_eq!(rendered("float64", &[Value::Bool(true)]), "1");
        // `Integer` and `Float` are one method, so `int`, `int64`, and `atoi`
        // agree, and a boolean is one or zero for both.
        assert_eq!(rendered("int", &[Value::Bool(false)]), "0");
        assert_eq!(rendered("int64", &[Value::Number(102.9)]), "102");
        assert_eq!(rendered("atoi", &[Value::Number(102.9)]), "102");
        // A decimal string is truncated rather than refused, because the
        // reference parses it with `decimal.TryParse` first.
        assert_eq!(rendered("int", &[Value::String("42.9".to_owned())]), "42");
        assert_eq!(
            rendered("int", &[Value::String("-102.9".to_owned())]),
            "-102"
        );
        assert_eq!(
            rendered("float64", &[Value::String("1.5".to_owned())]),
            "1.5"
        );
        assert_eq!(rendered("float64", &[Value::Number(7.0)]), "7");
    }

    #[test]
    fn to_decimal_reads_the_digits_in_base_eight() {
        // The fixture's `{{ toDecimal "0755" }}`, `{{ toDecimal "777" }}`, and
        // `{{ toDecimal "not-octal" }}`. 0o755 is 493 and 0o777 is 511, so the
        // helper reinterprets the decimal digits in base eight.
        assert_eq!(
            rendered("toDecimal", &[Value::String("0755".to_owned())]),
            "493"
        );
        assert_eq!(
            rendered("toDecimal", &[Value::String("777".to_owned())]),
            "511"
        );
        assert_eq!(
            rendered("toDecimal", &[Value::String("not-octal".to_owned())]),
            "0"
        );
        // The leading zeros are read as part of the number and then dropped, so
        // `+10` is 0o10 and a sign survives.
        assert_eq!(
            rendered("toDecimal", &[Value::String("10".to_owned())]),
            "8"
        );
        assert_eq!(
            rendered("toDecimal", &[Value::String("+10".to_owned())]),
            "8"
        );
        assert_eq!(
            rendered("toDecimal", &[Value::String("-10".to_owned())]),
            "-8"
        );
        assert_eq!(rendered("toDecimal", &[Value::String("0".to_owned())]), "0");
        // A number argument is rendered first, so 64 becomes the digits `64`
        // and then 0o64, which is 52.
        assert_eq!(rendered("toDecimal", &[Value::Number(64.0)]), "52");
    }

    #[test]
    fn to_decimal_refuses_a_digit_that_is_not_octal() {
        // `Convert.ToInt64("999", 8)` throws in the reference, so this is an
        // error rather than a silently truncated answer.
        for text in ["999", "8", "-9"] {
            let error = crate::call("toDecimal", &[Value::String(text.to_owned())]).unwrap_err();
            assert!(
                matches!(error, Error::InvalidArgument { .. }),
                "toDecimal {text:?} returned {error}"
            );
        }
    }

    #[test]
    fn a_wrong_argument_count_is_reported() {
        // `Count` in the reference is a fixed count, `Minimum` is a floor, and
        // `Round` is the only helper that takes a range of counts.
        let cases = [
            ("add1", vec![]),
            ("add1", vec![Value::Number(1.0), Value::Number(2.0)]),
            ("sub", vec![Value::Number(1.0)]),
            (
                "div",
                vec![Value::Number(1.0), Value::Number(2.0), Value::Number(3.0)],
            ),
            ("mod", vec![Value::Number(1.0)]),
            ("floor", vec![]),
            ("ceil", vec![Value::Number(1.0), Value::Number(2.0)]),
            ("round", vec![Value::Number(1.5)]),
            (
                "round",
                vec![
                    Value::Number(1.5),
                    Value::Number(0.0),
                    Value::Number(0.5),
                    Value::Number(0.5),
                ],
            ),
            ("mul", vec![]),
            ("max", vec![]),
            ("min", vec![]),
            ("mulf", vec![]),
            ("maxf", vec![]),
            ("minf", vec![]),
            ("subf", vec![Value::Number(1.0)]),
            ("divf", vec![Value::Number(1.0)]),
            ("add1f", vec![]),
            ("int", vec![]),
            ("float64", vec![Value::Number(1.0), Value::Number(2.0)]),
            ("atoi", vec![]),
            ("toDecimal", vec![]),
        ];
        for (helper, arguments) in cases {
            let error = crate::call(helper, &arguments).unwrap_err();
            assert!(
                matches!(error, Error::WrongArgumentCount { .. }),
                "{helper} with {} arguments returned {error}",
                arguments.len()
            );
        }
    }

    #[test]
    fn add_with_no_arguments_is_zero() {
        // Neither `Add` nor `AddFloat` checks its count in the reference, and a
        // Go variadic with no arguments sums to zero, so this is zero rather
        // than an arity error.
        assert_eq!(rendered("add", &[]), "0");
        assert_eq!(rendered("addf", &[]), "0");
    }

    #[test]
    fn an_argument_that_is_not_a_number_is_refused() {
        // Go's `toInt64` reads an argument it cannot parse as zero. This crate
        // reports it instead, which is what `Error::InvalidArgument` documents.
        for (helper, arguments) in [
            ("add", vec![Value::String("abc".to_owned())]),
            ("int", vec![Value::String("abc".to_owned())]),
            ("float64", vec![Value::String("abc".to_owned())]),
            ("addf", vec![Value::List(vec![Value::Number(1.0)])]),
            ("floor", vec![Value::Null]),
        ] {
            let error = crate::call(helper, &arguments).unwrap_err();
            assert!(
                matches!(error, Error::InvalidArgument { .. }),
                "{helper} returned {error}"
            );
        }
    }

    #[test]
    fn an_out_of_range_result_is_an_error() {
        // The reference's `decimal` cannot hold `1e300 * 1e300`, and a
        // `+Inf` rendered into a value file would be worse than a failure.
        let error = crate::call("mulf", &[Value::Number(1e300), Value::Number(1e300)]).unwrap_err();
        assert!(matches!(error, Error::InvalidArgument { .. }), "{error}");
        let error = crate::call("floor", &[Value::Number(f64::INFINITY)]).unwrap_err();
        assert!(matches!(error, Error::InvalidArgument { .. }), "{error}");
    }
}
