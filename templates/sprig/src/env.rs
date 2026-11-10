//! The environment helpers.
//!
//! `env` and `expandenv` read the template's own environment, which the caller
//! hands over through [`crate::Context`], never the process environment. A
//! template that read the real environment would render differently on a
//! developer machine and in a pipeline for the same inputs, which makes a
//! Compose file unreproducible, so an absent environment is an absent value
//! rather than a fallback to `std::env`.

use crate::support;
use crate::{Context, Error, Value};

/// Dispatches an environment helper.
pub(super) const DISPATCH: crate::Dispatch =
    |name, arguments, context| dispatch(name, arguments, context);

#[allow(clippy::trivially_copy_pass_by_ref)]
fn dispatch(
    name: &str,
    arguments: &[Value],
    context: &Context<'_>,
) -> Option<Result<Value, Error>> {
    let result = match name {
        "env" => environment_value(arguments, *context),
        "expandenv" => expand_environment(arguments, *context),
        _ => return None,
    };
    Some(result)
}

/// Reports whether this module's helper wants rendered string arguments.
///
/// False for both. `env` is given a *name*, not a rendered template, and
/// `expandenv` a string that is about to be scanned for `$` references, so
/// neither wants its argument rendered into a different form first.
///
/// The answer is kept per module because that is where the contract for it
/// lives: a module that later grows a helper which does want its arguments
/// rendered has one place to say so. `lib.rs` currently folds the answer for
/// this module to a constant `false`, so nothing outside the module's own tests
/// calls this; the lint is allowed rather than the function dropped so that the
/// two cannot drift apart.
#[allow(dead_code)]
pub(super) fn takes_rendered_strings(_name: &str) -> bool {
    false
}

/// Returns the value of one name, or the empty string when it is unset.
///
/// This is the reference's `EnvironmentValue`, which is
/// `Environment.GetEnvironmentVariable(value) ?? string.Empty`: a name that is
/// not in the environment is the empty string and never an error, because a
/// Compose file routinely interpolates a name that an operator may or may not
/// have exported.
fn environment_value(arguments: &[Value], context: Context<'_>) -> Result<Value, Error> {
    crate::arity("env", arguments.len(), 1, Some(1))?;
    let name = support::text("env", &arguments[0])?;
    Ok(Value::String(
        context.lookup(&name).unwrap_or("").to_owned(),
    ))
}

/// Substitutes `$NAME` and `${NAME}` references from the template's environment.
///
/// This is the reference's `ExpandEnvironment`, whose `ExpandGoEnvironment`
/// reproduces Go's `os.Expand`, including the two spellings and the two cases
/// where a reference is dropped rather than substituted.
fn expand_environment(arguments: &[Value], context: Context<'_>) -> Result<Value, Error> {
    crate::arity("expandenv", arguments.len(), 1, Some(1))?;
    let value = support::text("expandenv", &arguments[0])?;
    Ok(Value::String(expand(&value, |name| context.lookup(name))))
}

/// Expands environment references the way the reference's `ExpandGoEnvironment` does.
///
/// The reference scans for `$` and then, in order:
///
/// - `${NAME}` substitutes `NAME`; an unterminated `${` and an empty `${}` are
///   both dropped, so `prefix${` renders `prefix` rather than keeping a brace.
/// - A `$` followed by one of `* # $ @ ! ? -` or a digit names that single
///   character, which is how a shell spells `$$` and `$1`.
/// - Otherwise the name runs over `[0-9A-Za-z_]`; a `$` with no name after it is
///   a literal `$`, so `price$` renders `price$`.
///
/// An unset name substitutes the empty string in every case, including inside
/// braces: `${MISSING-suffix}` is the name `MISSING-suffix`, which is unset, and
/// therefore renders as nothing. Go's `${NAME:-default}` form is not implemented
/// here either, because the reference does not implement it.
fn expand<'a>(value: &str, lookup: impl Fn(&str) -> Option<&'a str>) -> String {
    // The scan is over characters rather than bytes so that an index is a
    // character position, which is what every step below compares against.
    let characters: Vec<char> = value.chars().collect();
    let mut output = String::with_capacity(value.len());
    let mut index = 0;
    while index < characters.len() {
        if characters[index] != '$' || index + 1 == characters.len() {
            output.push(characters[index]);
            index += 1;
            continue;
        }

        let next = index + 1;
        if characters[next] == '{' {
            let Some(position) = characters[next + 1..].iter().position(|c| *c == '}') else {
                // No closing brace: the reference drops the `${` and carries on
                // after the brace.
                index = next + 1;
                continue;
            };
            let end = next + 1 + position;
            if end != next + 1 {
                let name: String = characters[next + 1..end].iter().collect();
                if let Some(found) = lookup(&name) {
                    output.push_str(found);
                }
            }
            index = end + 1;
            continue;
        }

        if is_special(characters[next]) {
            let name = characters[next].to_string();
            if let Some(found) = lookup(&name) {
                output.push_str(found);
            }
            index = next + 1;
            continue;
        }

        let mut end = next;
        while end < characters.len() && is_name_character(characters[end]) {
            end += 1;
        }
        if end == next {
            output.push('$');
            index += 1;
            continue;
        }
        let name: String = characters[next..end].iter().collect();
        if let Some(found) = lookup(&name) {
            output.push_str(found);
        }
        index = end;
    }
    output
}

/// Reports whether a `$` is followed by a single-character name.
///
/// The reference's `IsGoEnvironmentSpecial`.
fn is_special(value: char) -> bool {
    matches!(value, '*' | '#' | '$' | '@' | '!' | '?' | '-' | '0'..='9')
}

/// Reports whether a character may appear in an unbraced name.
///
/// The reference's `IsGoEnvironmentNameCharacter`.
fn is_name_character(value: char) -> bool {
    value == '_' || value.is_ascii_alphanumeric()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{DISPATCH, environment_value, expand, expand_environment, takes_rendered_strings};
    use crate::{Context, Error, Value};

    /// A context over the names the reference's own environment test uses.
    ///
    /// The reference's `EnvironmentFunctionsMatchUpstreamContracts` sets
    /// `NEOTALES_SPRIG_TEST_VALUE=bar` and then reads it back, so that is the
    /// name reproduced here.
    fn context() -> Context<'static> {
        let environment: &'static BTreeMap<String, String> = Box::leak(Box::new(BTreeMap::from([
            ("NEOTALES_SPRIG_TEST_VALUE".to_owned(), "bar".to_owned()),
            ("USER".to_owned(), "dev".to_owned()),
        ])));
        Context::with_environment(environment)
    }

    /// Calls the dispatch table the way `lib.rs` does, unwrapping `Some`.
    fn call(name: &str, arguments: &[Value], context: Context<'_>) -> Result<Value, Error> {
        DISPATCH(name, arguments, &context).expect("the module claims the name")
    }

    /// The value `env` produces for a name, as a string.
    fn env(name: &str) -> String {
        let context = context();
        call("env", &[Value::String(name.to_owned())], context)
            .expect("env succeeds")
            .render()
    }

    /// The value `expandenv` produces for a string.
    fn expandenv(value: &str) -> String {
        let context = context();
        call("expandenv", &[Value::String(value.to_owned())], context)
            .expect("expandenv succeeds")
            .render()
    }

    #[test]
    fn the_module_claims_only_its_own_helpers() {
        let context = context();
        assert!(DISPATCH("trim", &[], &context).is_none());
        assert!(DISPATCH("date", &[], &context).is_none());
        assert!(DISPATCH("semver", &[], &context).is_none());
        assert!(DISPATCH("urlParse", &[], &context).is_none());
        assert!(DISPATCH("env", &[Value::String("USER".to_owned())], &context).is_some());
        assert!(DISPATCH("expandenv", &[Value::String(String::new())], &context).is_some());
    }

    #[test]
    fn no_helper_wants_rendered_arguments() {
        // `env`'s argument is a name, and `expandenv`'s is scanned for `$`.
        assert!(!takes_rendered_strings("env"));
        assert!(!takes_rendered_strings("expandenv"));
        assert!(!takes_rendered_strings("date"));
    }

    #[test]
    fn env_reads_the_template_environment() {
        // The reference's EnvironmentFunctionsMatchUpstreamContracts:
        // `{{ env "NEOTALES_SPRIG_TEST_VALUE" }}` renders `bar`.
        assert_eq!(env("NEOTALES_SPRIG_TEST_VALUE"), "bar");
        assert_eq!(env("USER"), "dev");
    }

    #[test]
    fn env_of_an_unset_name_is_the_empty_string() {
        // The reference's `?? string.Empty`, never an error: a Compose file
        // interpolates names an operator may not have exported.
        assert_eq!(env("NEOTALES_MISSING"), "");
        assert_eq!(expandenv("$NEOTALES_MISSING"), "");
    }

    #[test]
    fn env_without_an_environment_is_the_empty_string() {
        // No environment at all must read as an empty string rather than
        // falling back to the process environment, which on the machine running
        // these tests has a `USER` that would make this assertion pass by
        // accident.
        let context = Context::default();
        let result = call("env", &[Value::String("USER".to_owned())], context);
        assert_eq!(result.expect("env succeeds"), Value::String(String::new()));
        let expanded = call(
            "expandenv",
            &[Value::String("hi $USER".to_owned())],
            context,
        );
        assert_eq!(
            expanded.expect("expandenv succeeds"),
            Value::String("hi ".to_owned())
        );
    }

    #[test]
    fn expandenv_substitutes_both_spellings() {
        // The reference's EnvironmentFunctionsMatchUpstreamContracts:
        // `Hello ${NAME}` renders `Hello bar` and `${NAME}` renders `bar`.
        assert_eq!(expandenv("Hello $NEOTALES_SPRIG_TEST_VALUE"), "Hello bar");
        assert_eq!(expandenv("$NEOTALES_SPRIG_TEST_VALUE"), "bar");
        assert_eq!(expandenv("${NEOTALES_SPRIG_TEST_VALUE}"), "bar");
        assert_eq!(expandenv("a${NEOTALES_SPRIG_TEST_VALUE}b"), "abarb");
    }

    #[test]
    fn expandenv_reproduces_the_references_drops_and_literals() {
        // `prefix${NEOTALES_MISSING-suffix}` is the unset name
        // `NEOTALES_MISSING-suffix`, so the whole reference is empty.
        assert_eq!(expandenv("prefix${NEOTALES_MISSING-suffix}"), "prefix");
        // An unterminated `${` is dropped, and a trailing `$` is a literal.
        assert_eq!(expandenv("prefix${"), "prefix");
        assert_eq!(expandenv("price$"), "price$");
        // A `$` with no name after it is literal too.
        assert_eq!(expandenv("$ x"), "$ x");
        // `${}` names nothing and is dropped.
        assert_eq!(expandenv("a${}b"), "ab");
    }

    #[test]
    fn expandenv_reads_a_single_character_name_after_a_dollar() {
        // The reference's `IsGoEnvironmentSpecial` lets `$$` and `$1` name one
        // character, which is how a shell spells them.
        let environment: &'static BTreeMap<String, String> = Box::leak(Box::new(BTreeMap::from([
            ("$".to_owned(), "pid".to_owned()),
            ("1".to_owned(), "first".to_owned()),
        ])));
        let context = Context::with_environment(environment);
        assert_eq!(
            call("expandenv", &[Value::String("$$".to_owned())], context).expect("ok"),
            Value::String("pid".to_owned())
        );
        assert_eq!(
            call("expandenv", &[Value::String("$1".to_owned())], context).expect("ok"),
            Value::String("first".to_owned())
        );
        // An unset single-character name is still the empty string.
        assert_eq!(expandenv("$*"), "");
    }

    #[test]
    fn a_name_ends_at_the_first_character_that_cannot_be_part_of_one() {
        // An unbraced name runs over `[0-9A-Za-z_]` only, so the hyphen here is
        // not part of the name: it is a literal that follows the substituted
        // value. Inside braces the whole run is the name instead, which is why
        // `${MISSING-suffix}` renders as nothing at all.
        assert_eq!(expandenv("$NEOTALES_SPRIG_TEST_VALUE-x"), "bar-x");
    }

    #[test]
    fn the_argument_count_is_checked() {
        let context = context();
        for name in ["env", "expandenv"] {
            assert!(matches!(
                call(name, &[], context),
                Err(Error::WrongArgumentCount { .. })
            ));
            assert!(matches!(
                call(
                    name,
                    &[Value::String("a".to_owned()), Value::String("b".to_owned())],
                    context
                ),
                Err(Error::WrongArgumentCount { .. })
            ));
        }
    }

    #[test]
    fn a_number_is_a_valid_name_and_a_collection_is_not() {
        // The reference renders a scalar argument with `S`, so `env 42` reads
        // the name "42" and finds nothing.
        let context = context();
        assert_eq!(
            call("env", &[Value::Number(42.0)], context).expect("ok"),
            Value::String(String::new())
        );
        assert!(matches!(
            call(
                "env",
                &[Value::List(vec![Value::String("USER".to_owned())])],
                context
            ),
            Err(Error::InvalidArgument { .. })
        ));
    }

    #[test]
    fn the_expansion_scanner_is_reachable_without_a_template() {
        // The scanner takes a lookup rather than a context so its behaviour can
        // be checked directly, including for a name whose value is itself
        // empty.
        let expanded = expand("$A/$B", |name| match name {
            "A" => Some("one"),
            "B" => Some(""),
            _ => None,
        });
        assert_eq!(expanded, "one/");
    }

    #[test]
    fn the_two_entry_points_agree_with_the_dispatch_table() {
        let context = context();
        let arguments = [Value::String("USER".to_owned())];
        assert_eq!(
            environment_value(&arguments, context).expect("ok"),
            call("env", &arguments, context).expect("ok")
        );
        let text = [Value::String("$USER".to_owned())];
        assert_eq!(
            expand_environment(&text, context).expect("ok"),
            call("expandenv", &text, context).expect("ok")
        );
    }
}
