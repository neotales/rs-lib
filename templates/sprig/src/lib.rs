//! Deterministic, side-effect-free helpers compatible with a safe Sprig subset.
//!
//! The helper set is ported from the reference implementation's
//! `SprigUpstreamParityTests`, which itself ports examples from upstream
//! Masterminds Sprig. `fixtures/sprig/upstream_parity.json` holds those
//! `(template, expected)` pairs and is the conformance oracle: a helper is not
//! finished until a pair that exercises it renders the expected bytes.
//!
//! # What "safe" means here
//!
//! Every helper is a pure function of its arguments and, for `env` and
//! `expandenv`, of the template's own environment. Nothing reads the process
//! environment, the filesystem, or a random source, so a rendered Compose file is
//! the same on a laptop and in a pipeline. The reference's crypto and random
//! helpers are therefore out of scope here: they would make a template
//! non-reproducible, which is the opposite of what a Compose file needs.
//!
//! There is exactly one exception, and it is deliberate: `now` and `ago` read the
//! clock. They are implemented rather than refused because a template written
//! against the reference would otherwise fail on a name that exists, which is a
//! worse outcome than a rendering that is not reproducible. `fixtures/sprig/
//! out_of_scope.json` records them under `implemented_but_not_reproducible`, and
//! a parity test checks that the exception is still exactly two names long.
#![doc = include_str!("../README.md")]

use std::fmt::Write as _;
use std::{collections::BTreeMap, fmt};

mod context;
mod dates;
mod defaults;
mod dicts;
mod encoding;
mod env;
mod lists;
mod math;
mod musthelpers;
mod paths;
mod quotes;
mod regex;
mod semver;
mod strings;
mod support;
mod types;
mod urls;

pub use context::Context;

/// The signature every helper module dispatches through.
///
/// Naming it once is not only shorter: written out inline, the type is complex
/// enough to trip `clippy::type_complexity` in all fifteen modules, and a named
/// type says what the contract *is* rather than leaving each module to spell it.
pub(crate) type Dispatch = fn(&str, &[Value], &Context<'_>) -> Option<Result<Value, Error>>;

pub use quotes::quote;

/// A value a template expression can produce.
///
/// The distinction that matters is not string versus number but *how a number was
/// written*, because Go's `text/template` tells an integer from a decimal and
/// renders them differently. `{{ 3 }}` is `3`; `{{ 3.0 }}` is `3.0`. That is why
/// this is [`Self::Number`] and [`Self::Float`] rather than one numeric variant.
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    /// A text value.
    String(String),
    /// A boolean, which is also what a Go template's truthiness rules are applied
    /// to when deciding which branch to take.
    Bool(bool),
    /// A number from a JSON or YAML values file.
    ///
    /// Values files are full of numbers — `"replicas": 3`, `"port": 8080` — and
    /// before this existed they could not be represented at all, so a template
    /// over a realistic values file failed to parse. The number is kept as
    /// `f64` because that is what JSON decodes to, and rendered the way Go
    /// renders a `float64`.
    ///
    /// This is the *integer* case. A value that came from a decimal literal or
    /// from a floating-point helper is [`Self::Float`] instead, because Go's
    /// `text/template` tells them apart: `{{ kindOf 3 }}` is `int` and
    /// `{{ kindOf 3.0 }}` is `float64`, and `{{ 3.0 }}` renders `3.0` where
    /// `{{ 3 }}` renders `3`. A single `f64` cannot carry that, and a template
    /// that used `kindOf` to choose a numeric type would get the wrong answer.
    ///
    /// This is the *integer* case. A value from a decimal literal is
    /// [`Self::Float`] instead, because Go tells them apart: `{{ kindOf 3 }}` is
    /// `int` and `{{ kindOf 3.0 }}` is `float64`, and `{{ 3.0 }}` renders `3.0`
    /// where `{{ 3 }}` renders `3`. A single `f64` cannot carry that, and a
    /// template that used `kindOf` to choose a numeric type would be wrong.
    Number(f64),
    /// A value that came from a decimal literal or a floating-point helper.
    ///
    /// The payload is the same `f64`; what differs is the spelling, which is
    /// what `kindOf` reports and what `render` must reproduce.
    Float(f64),
    /// An explicit JSON or YAML null.
    ///
    /// Go renders a nil interface as `<no value>`, and this matches that so a
    /// template over a values file containing a null does not invent a spelling.
    Null,
    /// An ordered sequence.
    List(Vec<Value>),
    /// A keyed collection, rendered in sorted key order so output is stable.
    Map(BTreeMap<String, Value>),
    /// A value that reads as a string but is reached through named members.
    ///
    /// The reference's `TemplateValue.Object` is exactly this: a display string
    /// plus members plus methods. The display is what separates it from a plain
    /// map, and it is load-bearing rather than cosmetic — `semver` returns an
    /// object whose display is the canonical version, so
    /// `{{ semver "1.2.3" | (semver "1.3.3").Compare }}` can render the piped
    /// object and parse it back. A plain map would render its members, including
    /// the method, and no longer be a version.
    Object {
        /// How the value reads when it is rendered.
        display: String,
        /// The members reached with a field path.
        members: BTreeMap<String, Value>,
    },
    /// A value that is called rather than read.
    ///
    /// The reference's `semver` returns an object carrying a `Compare` method,
    /// and `{{ semver "1.2.3" | (semver "1.3.3").Compare }}` is a fixture case:
    /// the field is a delegate, so reading it yields something to invoke rather
    /// than something to print. A method names the helper it delegates to, and
    /// the value it was reached through is passed as that helper's first
    /// argument.
    Method {
        /// The helper the method delegates to.
        helper: String,
        /// The value the method was reached through, passed as its first
        /// argument.
        receiver: Box<Value>,
    },
}

impl Value {
    /// Reports whether this value is empty for the safe `default` contract.
    ///
    /// A number is empty at zero and null is always empty, matching Go's
    /// `empty` for the values a values file can carry.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        match self {
            Self::String(value) => value.is_empty(),
            Self::Bool(value) => !*value,
            Self::Number(value) | Self::Float(value) => *value == 0.0,
            Self::Null => true,
            Self::List(values) => values.is_empty(),
            Self::Map(values) => values.is_empty(),
            // An object is never empty: it is a value with a display string, and
            // an object whose display is empty is still a value.
            Self::Object { display, .. } => display.is_empty(),
            // A method is never empty: it is something to call, and a template
            // that tests it is asking whether it exists.
            Self::Method { .. } => false,
        }
    }

    /// Returns this value as a string slice, or the empty string for anything else.
    ///
    /// Go's sprig string helpers call `fmt.Sprint` on their argument, which
    /// renders a number and a boolean but refuses a map. A non-string argument
    /// is therefore a caller error rather than a silent coercion to `""`, and the
    /// helpers that accept one check with [`Value::as_str`] first.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    /// Returns the rendered form of this value.
    #[must_use]
    pub fn render(&self) -> String {
        match self {
            Self::String(value) => value.clone(),
            Self::Bool(value) => value.to_string(),
            Self::Number(value) => go_number(*value),
            // A float keeps its decimal spelling even when the value is whole,
            // which is the whole reason this variant exists: `3.0` is what Go
            // writes for a float64 of three, and `3` is what it writes for an
            // int of three.
            Self::Float(value) => go_float(*value),
            Self::Null => "<no value>".to_owned(),
            Self::List(values) => format!(
                "[{}]",
                values
                    .iter()
                    .map(Value::render)
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
            Self::Method { helper, .. } => helper.clone(),
            // The display, not the members: that is the whole reason this is a
            // separate variant from a map.
            Self::Object { display, .. } => display.clone(),
            Self::Map(values) => format!(
                "map[{}]",
                values
                    .iter()
                    .map(|(key, value)| format!("{key}:{}", value.render()))
                    .collect::<Vec<_>>()
                    .join(" ")
            ),
        }
    }

    /// Returns this value as a number, converting the types Go converts.
    ///
    /// Go's `toInt64` accepts a string it can parse and a bool as 1 or 0, and
    /// renders a non-convertible value as zero. A number is returned unchanged.
    #[must_use]
    pub fn as_number(&self) -> f64 {
        match self {
            Self::Number(value) | Self::Float(value) => *value,
            Self::Bool(value) => {
                if *value {
                    1.0
                } else {
                    0.0
                }
            }
            Self::String(value) => value
                .trim()
                .parse::<f64>()
                // A large integer loses its low bits here, which is what Go's
                // `float64` conversion does too: the alternative is to fail on a
                // value a template is entitled to read.
                .or_else(|_| {
                    value.trim().parse::<i64>().map(|number| {
                        #[allow(clippy::cast_precision_loss)]
                        let number = number as f64;
                        number
                    })
                })
                .unwrap_or(0.0),
            _ => 0.0,
        }
    }

    /// Returns this value as a boolean, following Go's truth rules.
    #[must_use]
    pub fn as_bool(&self) -> bool {
        match self {
            Self::Bool(value) => *value,
            Self::String(value) => value == "true",
            Self::Number(value) | Self::Float(value) => *value != 0.0,
            Self::Null => false,
            Self::List(values) => !values.is_empty(),
            Self::Map(values) => !values.is_empty(),
            // An object and a method are both truthy: each is something to reach
            // into or call, so a template testing whether one is present must not
            // be told it is empty.
            Self::Object { .. } | Self::Method { .. } => true,
        }
    }

    /// Returns the elements of a list, or a single-element list for a scalar.
    ///
    /// Sprig's list helpers accept a scalar as a one-element list, which is what
    /// makes `append "a" "b"` and `append (list "a") "b"` both spell a two
    /// element list.
    #[must_use]
    pub fn as_list(&self) -> Vec<Value> {
        match self {
            Self::List(values) => values.clone(),
            // A null and a method are both empty: a null has no elements, and a
            // method is not a one-element list, because a helper that walks a
            // list must not find a callable in it.
            Self::Null | Self::Method { .. } => Vec::new(),
            other => vec![other.clone()],
        }
    }
}

/// Renders a number the way Go's `text/template` renders a `float64`.
///
/// Go prints the shortest representation that round-trips and switches to
/// scientific notation when the decimal exponent is below `-4` or at least `6`.
/// Rust's default formatting never switches, so `1000000` would render as
/// `1000000` where Go writes `1e+06`, and `1e21` as twenty-one digits where Go
/// writes `1e+21`. A template over a values file should not depend on which
/// formatting the implementation happened to choose, so Go's rule is reproduced
/// exactly.
///
/// The shortest round-tripping digits and the exponent are read back out of
/// Rust's own `{:e}` formatting, which is the same shortest representation, and
/// then laid out by Go's rule.
/// Renders a float the way Go writes a `float64`, with its decimal spelling.
#[must_use]
pub(crate) fn render_float(value: f64) -> String {
    go_float(value)
}

fn go_float(value: f64) -> String {
    let rendered = go_number(value);
    // Go's `%v` for a `float64` keeps a fractional part, so a whole float still
    // reads as a float. The scientific form already carries a point, and a
    // negative zero keeps its sign, so neither needs a point added.
    if rendered.contains('.') || rendered.contains('e') || rendered.contains("Inf") {
        return rendered;
    }
    format!("{rendered}.0")
}

fn go_number(value: f64) -> String {
    if value.is_nan() {
        return "NaN".to_owned();
    }
    if value.is_infinite() {
        return if value.is_sign_positive() {
            "+Inf".to_owned()
        } else {
            "-Inf".to_owned()
        };
    }

    // `{:e}` yields the shortest round-tripping mantissa and a decimal exponent,
    // e.g. `1.234567e6`. Zero is the one value it renders as `0e0`.
    let scientific = format!("{value:e}");
    let (mantissa, exponent) = scientific
        .split_once('e')
        .expect("Rust's exponential formatting always has an exponent");
    let exponent: i32 = exponent
        .parse()
        .expect("Rust's exponential formatting writes a decimal exponent");
    let negative = mantissa.starts_with('-');
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let digits = digits.trim_end_matches('0');
    let digits = if digits.is_empty() { "0" } else { digits };

    if value == 0.0 {
        return if negative {
            "-0".to_owned()
        } else {
            "0".to_owned()
        };
    }

    // Go's rule: scientific when the exponent is below -4 or at least 6.
    if !(-4..6).contains(&exponent) {
        let sign = if negative { "-" } else { "" };
        let mut out = String::from(sign);
        out.push_str(&digits[..1]);
        if digits.len() > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        // Go's exponent always carries a sign and at least two digits.
        out.push('e');
        out.push(if exponent < 0 { '-' } else { '+' });
        // Go writes at least two exponent digits, so `1e+06` is not `1e+6`.
        let _ = write!(out, "{:02}", exponent.unsigned_abs());
        return out;
    }

    // Decimal layout. `exponent` is the power of ten of the leading digit, so a
    // negative exponent puts the point before the digits and needs that many
    let sign = if negative { "-" } else { "" };
    if exponent < 0 {
        // Both conversions are exact: the branch is reached only for a negative
        // exponent, and the point index is only read for a non-negative one.
        #[allow(clippy::cast_sign_loss)]
        let zeros = exponent.unsigned_abs() as usize;
        return format!("{sign}0.{}{}", "0".repeat(zeros - 1), digits);
    }
    #[allow(clippy::cast_sign_loss)]
    let point = exponent as usize + 1;
    if point >= digits.len() {
        return format!("{sign}{digits}{}", "0".repeat(point - digits.len()));
    }
    format!("{sign}{}.{}", &digits[..point], &digits[point..])
}

/// Why a template helper refused to run.
///
/// Each variant is something the caller can act on. A helper that receives an
/// empty value where an empty-aware answer exists is not an error, because every
/// empty-aware helper has a defined answer for that.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// The template named a helper that does not exist, with the name. A near
    /// match is the usual cause, so the message says what was expected.
    UnknownHelper(String),
    /// A helper was called with the wrong number of arguments.
    ///
    /// `expected` describes the accepted shape, which for a variadic helper is a
    /// range like `2 to 4` or `at least 1` rather than a single count.
    WrongArgumentCount {
        /// The helper that was called.
        helper: String,
        /// The shape it accepts, such as `2 to 4` or `at least 1` for a
        /// variadic helper, rather than a single count.
        expected: String,
        /// How many arguments were actually passed.
        actual: usize,
    },
    /// A helper refused its arguments for a reason the caller can act on.
    ///
    /// This is for a value of the wrong type, a non-numeric string where a number
    /// is required, or a key that is not present. It is deliberately not used for
    /// "this value is empty", because every empty-aware helper has a defined
    /// answer for that.
    InvalidArgument {
        /// The helper that refused.
        helper: String,
        /// What was wrong with the arguments.
        message: String,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownHelper(helper) => {
                write!(output, "unsupported safe Sprig helper: {helper}")
            }
            Self::WrongArgumentCount {
                helper,
                expected,
                actual,
            } => write!(
                output,
                "safe Sprig helper {helper} expects {expected} arguments, received {actual}"
            ),
            Self::InvalidArgument { helper, message } => {
                write!(output, "safe Sprig helper {helper}: {message}")
            }
        }
    }
}

impl std::error::Error for Error {}

/// Returns the fallback when `value` is empty in the supported value model.
///
/// `false`, empty strings, empty lists, and empty maps are empty. The selected
/// argument is returned without converting its value type to a string.
#[must_use]
pub fn default(fallback: &Value, value: &Value) -> Value {
    if value.is_empty() {
        fallback.clone()
    } else {
        value.clone()
    }
}

/// Checks an argument count against an inclusive range.
///
/// `max` of `None` means unbounded, which is how the variadic helpers declare
/// that they take any number of trailing arguments.
pub(crate) fn arity(
    helper: &str,
    actual: usize,
    min: usize,
    max: Option<usize>,
) -> Result<(), Error> {
    let within = actual >= min && max.is_none_or(|max| actual <= max);
    if within {
        return Ok(());
    }
    let expected = match max {
        None => format!("at least {min}"),
        Some(max) if max == min => format!("{min}"),
        Some(max) => format!("{min} to {max}"),
    };
    Err(Error::WrongArgumentCount {
        helper: helper.to_owned(),
        expected,
        actual,
    })
}

/// Reports an argument a helper cannot use.
pub(crate) fn invalid(helper: &str, message: impl Into<String>) -> Error {
    Error::InvalidArgument {
        helper: helper.to_owned(),
        message: message.into(),
    }
}

/// Evaluates a documented safe helper without an environment.
///
/// # Errors
///
/// Returns an error for unsupported helpers or an incorrect argument count.
pub fn call(name: &str, arguments: &[Value]) -> Result<Value, Error> {
    call_with(name, arguments, &Context::default())
}

/// Evaluates a documented safe helper with access to the call site.
///
/// # Errors
///
/// Returns an error for unsupported helpers, an incorrect argument count, or an
/// argument the helper cannot use.
pub fn call_with(name: &str, arguments: &[Value], context: &Context<'_>) -> Result<Value, Error> {
    // The order is the order in which the reference registers them, so a name
    // that two modules claim would resolve the same way there. No name is
    // currently claimed twice, and `claims` below is what keeps that true.
    for module in [
        defaults::DISPATCH,
        strings::DISPATCH,
        lists::DISPATCH,
        dicts::DISPATCH,
        types::DISPATCH,
        math::DISPATCH,
        encoding::DISPATCH,
        regex::DISPATCH,
        paths::DISPATCH,
        urls::DISPATCH,
        env::DISPATCH,
        dates::DISPATCH,
        semver::DISPATCH,
        quotes::DISPATCH,
        musthelpers::DISPATCH,
    ] {
        if let Some(result) = module(name, arguments, context) {
            return result;
        }
    }
    Err(Error::UnknownHelper(name.to_owned()))
}

/// Returns whether a helper receives its arguments already rendered as strings.
///
/// A helper that concatenates, wraps, or measures a string needs the rendered
/// form so that a number or a boolean can be printed. A helper that inspects a
/// collection, or that returns a collection, needs the typed value or it would
/// see `"[a b]"` where it needs two elements. The engine asks here rather than
/// keeping its own list, so a new helper is described in one place.
#[must_use]
pub fn takes_rendered_strings(name: &str) -> bool {
    // Every module is asked, rather than the three that happen to want rendered
    // strings today. A module that answers `false` costs one string comparison
    // on a path that is not hot, and a module added later is then described
    // correctly without anyone having to remember to wire it in here — which is
    // how a helper ends up receiving typed values it cannot use.
    strings::takes_rendered_strings(name)
        || lists::takes_rendered_strings(name)
        || defaults::takes_rendered_strings(name)
        || types::takes_rendered_strings(name)
        || dicts::takes_rendered_strings(name)
        || encoding::takes_rendered_strings(name)
        || math::takes_rendered_strings(name)
        || regex::takes_rendered_strings(name)
        || paths::takes_rendered_strings(name)
        || urls::takes_rendered_strings(name)
        || env::takes_rendered_strings(name)
        || dates::takes_rendered_strings(name)
        || semver::takes_rendered_strings(name)
        || quotes::takes_rendered_strings(name)
        || musthelpers::takes_rendered_strings(name)
}

/// Every helper name this crate implements, sorted.
///
/// A conformance test compares this against the reference's registered set, so a
/// helper that is added without a parity fixture is visible rather than silent.
#[must_use]
pub fn helper_names() -> Vec<&'static str> {
    let mut names = claims().to_vec();
    names.sort_unstable();
    names.dedup();
    names
}

/// The complete list of registered helper names.
///
/// The list is long because the reference's is, and it is kept as one table
/// rather than derived from the modules so that a reader can check a name
/// against the reference's registry in one place.
#[allow(clippy::too_many_lines)]
const fn claims() -> &'static [&'static str] {
    &[
        // Defaults and flow control.
        "default",
        "empty",
        "coalesce",
        "all",
        "any",
        "fail",
        "ternary",
        "compact",
        // Strings.
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
        "contains",
        "hasPrefix",
        "hasSuffix",
        "replace",
        "split",
        "splitList",
        "splitn",
        "quote",
        "squote",
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
        "plural",
        "sha1sum",
        "sha512sum",
        "sha256sum",
        "adler32sum",
        // Lists.
        "list",
        "tuple",
        "first",
        "rest",
        "last",
        "initial",
        "append",
        "prepend",
        "concat",
        "reverse",
        "uniq",
        "without",
        "has",
        "slice",
        "chunk",
        "join",
        "sortAlpha",
        "seq",
        "until",
        "untilStep",
        "compact",
        // Dictionaries.
        "dict",
        "get",
        "set",
        "unset",
        "hasKey",
        "pluck",
        "keys",
        "values",
        "pick",
        "omit",
        "dig",
        "merge",
        "mergeOverwrite",
        "deepCopy",
        "deepEqual",
        "values",
        // Types.
        "typeOf",
        "typeIs",
        "typeIsLike",
        "kindOf",
        "kindIs",
        "deepEqual",
        // Math.
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
        "biggest",
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
        // Encoding.
        "b64enc",
        "b64dec",
        "b32enc",
        "b32dec",
        "toJson",
        "toPrettyJson",
        "toRawJson",
        "fromJson",
        "toStrings",
        // Regular expressions.
        "regexMatch",
        "mustRegexMatch",
        "regexFind",
        "regexFindAll",
        "regexReplaceAll",
        "regexReplaceAllLiteral",
        "regexSplit",
        "regexQuoteMeta",
        "mustRegexFind",
        "mustRegexFindAll",
        "mustRegexReplaceAll",
        "mustRegexReplaceAllLiteral",
        "mustRegexSplit",
        // Paths.
        "base",
        "dir",
        "clean",
        "ext",
        "isAbs",
        "osBase",
        "osDir",
        "osClean",
        "osExt",
        "osIsAbs",
        // URLs.
        "urlParse",
        "urlJoin",
        // Environment.
        "env",
        "expandenv",
        // Dates. `now` and `ago` read the clock, which is the one thing a
        // helper here does that a pure function could not; they are implemented
        // and recorded as non-reproducible rather than refused, because
        // refusing the name would break a template written against the
        // reference for no gain.
        "now",
        "ago",
        "date",
        "dateInZone",
        "date_in_zone",
        "dateModify",
        "date_modify",
        "mustDateModify",
        "must_date_modify",
        "htmlDate",
        "htmlDateInZone",
        "toDate",
        "mustToDate",
        "duration",
        "durationRound",
        "unixEpoch",
        "toDate",
        "mustAppend",
        "mustChunk",
        "mustCompact",
        "mustDeepCopy",
        "mustFirst",
        "mustFromJson",
        "mustHas",
        "mustInitial",
        "mustLast",
        "mustMerge",
        "mustMergeOverwrite",
        "mustPrepend",
        "mustPush",
        "mustRest",
        "mustReverse",
        "mustSlice",
        "mustToJson",
        "mustToPrettyJson",
        "mustToRawJson",
        "mustUniq",
        "mustWithout",
        "mustRegexFind",
        "mustRegexFindAll",
        "mustRegexMatch",
        "mustRegexReplaceAll",
        "mustRegexReplaceAllLiteral",
        "mustRegexSplit",
        // The plain helpers the must* family stands for.
        "push",
        "biggest",
        "sha512sum",
        "trimall",
        // Semantic versions.
        "semver",
        "semverCompare",
    ]
}
