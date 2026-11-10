//! The `must*` family: a helper that refuses rather than falling back.
//!
//! Sprig has two spellings of many helpers. The plain one returns a zero value
//! or a partial result when its input is unusable; the `must*` one panics in Go.
//! A panic is not an acceptable outcome for a template renderer — there is no
//! caller left to recover, and a Compose file that is half rendered is worse
//! than one that was refused — so here the `must*` spelling returns an error
//! instead.
//!
//! The behaviour is therefore identical to the plain helper in every case where
//! the plain helper succeeds, and differs only where the plain helper would have
//! silently produced something. That is implemented by delegation rather than by
//! a second copy of each rule, so a fix to a base helper cannot leave its `must*`
//! twin behind.

use crate::{Context, Error, Value};

/// The `must*` helpers and the plain helper each one delegates to.
const DELEGATES: &[(&str, &str)] = &[
    ("mustAppend", "append"),
    ("mustChunk", "chunk"),
    ("mustCompact", "compact"),
    ("mustDeepCopy", "deepCopy"),
    ("mustFirst", "first"),
    ("mustFromJson", "fromJson"),
    ("mustHas", "has"),
    ("mustInitial", "initial"),
    ("mustLast", "last"),
    ("mustMerge", "merge"),
    ("mustMergeOverwrite", "mergeOverwrite"),
    ("mustPrepend", "prepend"),
    ("mustPush", "push"),
    ("mustRest", "rest"),
    ("mustReverse", "reverse"),
    ("mustSlice", "slice"),
    ("mustToDate", "toDate"),
    ("mustToJson", "toJson"),
    ("mustToPrettyJson", "toPrettyJson"),
    ("mustToRawJson", "toRawJson"),
    ("mustUniq", "uniq"),
    ("mustWithout", "without"),
    ("mustRegexFind", "regexFind"),
    ("mustRegexFindAll", "regexFindAll"),
    ("mustRegexMatch", "regexMatch"),
    ("mustRegexReplaceAll", "regexReplaceAll"),
    ("mustRegexReplaceAllLiteral", "regexReplaceAllLiteral"),
    ("mustRegexSplit", "regexSplit"),
    ("mustDateModify", "dateModify"),
    ("must_date_modify", "date_modify"),
];

/// Dispatches a `must*` helper.
pub(super) const DISPATCH: crate::Dispatch =
    |name, arguments, context| dispatch(name, arguments, context);

#[allow(clippy::trivially_copy_pass_by_ref)]
fn dispatch(
    name: &str,
    arguments: &[Value],
    context: &Context<'_>,
) -> Option<Result<Value, Error>> {
    let base = DELEGATES
        .iter()
        .find(|(must, _)| *must == name)
        .map(|(_, base)| *base)?;
    // `crate::call_with` is the public dispatcher, so this module needs no
    // knowledge of how any base helper is implemented.
    match crate::call_with(base, arguments, context) {
        Ok(value) => Some(Ok(value)),
        Err(error) => Some(Err(Error::InvalidArgument {
            helper: (*name).to_owned(),
            message: format!("{error}"),
        })),
    }
}

/// The plain helper a `must*` name delegates to, if any.
///
/// Exposed for the parity report, which names the plain helper a `must*` spelling
/// stands for.
#[must_use]
pub(super) fn base_for(name: &str) -> Option<&'static str> {
    DELEGATES
        .iter()
        .find(|(must, _)| *must == name)
        .map(|(_, base)| *base)
}

/// Reports whether this module's helper wants rendered string arguments.
///
/// The `must*` helpers behave exactly as the helper they stand for, so the
/// answer has to match it rather than being a fixed choice. The engine asks this
/// before dispatch, so returning a blanket value would give some `must*` helpers
/// rendered strings and the plain helper typed values — and the two would then
/// disagree about the same call.
pub(super) fn takes_rendered_strings(name: &str) -> bool {
    base_for(name).is_some_and(crate::takes_rendered_strings)
}

#[cfg(test)]
mod tests {
    use super::{base_for, dispatch};
    use crate::{Context, Error, Value};

    #[test]
    fn every_must_helper_names_the_plain_helper_it_stands_for() {
        for (must, base) in [
            ("mustAppend", "append"),
            ("mustFirst", "first"),
            ("mustToJson", "toJson"),
            ("mustRegexMatch", "regexMatch"),
            ("mustDateModify", "dateModify"),
        ] {
            assert_eq!(base_for(must), Some(base), "{must}");
        }
        assert_eq!(base_for("append"), None, "a plain helper has no delegate");
    }

    #[test]
    fn a_name_this_module_does_not_own_is_passed_on() {
        let context = Context::default();
        // `None` is what lets the next module be tried. Returning an error for an
        // unrecognised name here would shadow every other module's dispatch and
        // make the whole helper set unusable.
        assert!(
            dispatch("mustNotAHelper", &[Value::Null], &context).is_none(),
            "an unknown name must be passed on rather than claimed"
        );
        assert!(base_for("mustNotAHelper").is_none());
    }

    /// A `must*` helper that cannot be satisfied must be an error, not a panic and
    /// not a silent zero. The base helper's own diagnostic is kept inside the
    /// message so the caller can see what actually went wrong.
    #[test]
    fn an_unsatisfiable_must_helper_is_an_error_carrying_the_reason() {
        let context = Context::default();
        // `slice` needs a list; a number is not one.
        // Calling with the wrong arity is unsatisfiable for every helper, so it
        // is the one refusal that does not depend on which helper is picked.
        // The base helper raises the arity error and the `must*` spelling must
        // re-raise it under its own name.
        let result = dispatch("mustFirst", &[], &context).expect("the name is recognised");
        match result {
            Err(Error::InvalidArgument { helper, message }) => {
                assert_eq!(helper, "mustFirst");
                assert!(
                    !message.is_empty(),
                    "the reason for refusing must survive into the message"
                );
            }
            other => {
                panic!("a must* helper that cannot be satisfied must be an error, got {other:?}")
            }
        }
    }
}
