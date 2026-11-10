//! The regular-expression helpers.
//!
//! Every method here is a port of one method in the reference's
//! `SprigFunctions.cs`:
//!
//! - `RegexMatch` catches a pattern it cannot compile and answers `false`,
//!   while `MustRegexMatch` lets the failure out.
//! - `RegexFindAll` takes a count where a negative one means every match, and
//!   `RegexSplit` takes a count where zero means no pieces at all and a
//!   negative one means every piece.
//! - `RegexReplace` expands `$1` and `${1}` against the match, and
//!   `RegexReplaceLiteral` does not.
//! - `RegexQuoteMeta` escapes the characters Go's `regexp.QuoteMeta` escapes.
//!
//! # The engine
//!
//! Go's `regexp` is RE2 and the `regex` crate is not a dependency of this crate,
//! so `engine` below is a small compiler and matcher written for this module. It
//! compiles a pattern to a flat instruction list and runs that list over the
//! subject's characters with an explicit stack of pending alternatives, so
//! nothing recurses and a long subject cannot overflow the stack. It is a
//! backtracking matcher, which makes it predictable for the patterns a Compose
//! file uses but not linear for a pathological one; a step budget and a pending
//! budget turn "not linear" into a reported error rather than a hang, a panic, or
//! an unbounded allocation. The syntax it accepts is the part of RE2 a template
//! can express: literals, `.`, character classes, anchors, `\b`, the Perl
//! character classes, capturing and non-capturing groups with optional names,
//! alternation, the greedy and lazy counted and uncounted quantifiers, and the
//! `i`, `s`, `m`, and `U` flags. Backreferences, lookaround, and possessive
//! quantifiers are not RE2, and a pattern that uses one is an error naming the
//! construct rather than a different answer.
//!
//! # `must*` and a pattern that does not match
//!
//! Go's `must*` helpers panic when there is no match. The reference answers with
//! the empty result instead, which is a silent wrong answer for a helper whose
//! name promises a match, so a `must*` helper here reports the absence of a match
//! as an error. `mustRegexMatch` is the one exception: `false` is the answer to
//! the question it asks rather than a failure to answer it, and the reference's
//! `MustRegexMatch` returns it, so only a pattern that will not compile is an
//! error there.

use crate::support::text;
use crate::{Context, Error, Value, arity, invalid};

/// The characters Go's `regexp.QuoteMeta` escapes, which is also the set
/// `QuoteGoRegexMeta` escapes.
const META: &[char] = &[
    '\\', '.', '+', '*', '?', '(', ')', '|', '[', ']', '{', '}', '^', '$',
];

/// Dispatches a regular-expression helper.
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
        "regexMatch" => matches_pattern(name, arguments, false),
        "mustRegexMatch" => matches_pattern(name, arguments, true),
        "regexFind" => find(name, arguments, false),
        "mustRegexFind" => find(name, arguments, true),
        "regexFindAll" => find_all(name, arguments, false),
        "mustRegexFindAll" => find_all(name, arguments, true),
        "regexReplaceAll" => replace(name, arguments, false, false),
        "mustRegexReplaceAll" => replace(name, arguments, false, true),
        "regexReplaceAllLiteral" => replace(name, arguments, true, false),
        "mustRegexReplaceAllLiteral" => replace(name, arguments, true, true),
        "regexSplit" => split(name, arguments, false),
        "mustRegexSplit" => split(name, arguments, true),
        "regexQuoteMeta" => quote_meta(name, arguments),
        _ => return None,
    };
    Some(result)
}

/// Reports whether this module's helper wants rendered string arguments.
///
/// Never. A pattern is text either way, and rendering a number argument first
/// would hand the matcher a spelling the author never wrote.
pub(super) fn takes_rendered_strings(_name: &str) -> bool {
    false
}

/// A compiled pattern, a subject, and the budget one search runs against.
struct Call<'a> {
    helper: &'a str,
    source: String,
    program: engine::Program,
    subject: String,
}

impl<'a> Call<'a> {
    /// Compiles the pattern argument and reads the subject argument.
    fn new(
        helper: &'a str,
        arguments: &[Value],
        pattern: usize,
        subject: usize,
    ) -> Result<Self, Error> {
        let source = text(helper, &arguments[pattern])?;
        let program = engine::compile(&source).map_err(|message| {
            invalid(
                helper,
                format!("cannot compile the pattern {source:?}: {message}"),
            )
        })?;
        let subject = text(helper, &arguments[subject])?;
        Ok(Self {
            helper,
            source,
            program,
            subject,
        })
    }

    /// Builds a matcher over this call's subject.
    fn matcher(&self) -> engine::Matcher<'_> {
        engine::Matcher::new(&self.program, &self.subject)
    }

    /// Reports a failure from inside the matcher.
    fn failed(&self, message: &str) -> Error {
        invalid(
            self.helper,
            format!("cannot evaluate the pattern {:?}: {message}", self.source),
        )
    }

    /// Reports the absence of a match for a `must*` helper.
    fn no_match(&self) -> Error {
        invalid(
            self.helper,
            format!(
                "the pattern {:?} does not match, and this helper requires a match",
                self.source
            ),
        )
    }
}

/// `RegexMatch` and `MustRegexMatch`: whether the pattern matches the subject.
///
/// `RegexMatch` answers `false` for a pattern that will not compile, which is
/// the one place the reference catches the failure instead of raising it.
fn matches_pattern(helper: &str, arguments: &[Value], required: bool) -> Result<Value, Error> {
    arity(helper, arguments.len(), 2, Some(2))?;
    if !required {
        // `RegexMatch` wraps its body in a `catch (ArgumentException)`, and an
        // uncompilable pattern is the only failure that catch is for. An argument
        // that is not text at all is a caller error and is still reported, and so
        // is a pattern that compiles but exceeds the step budget.
        let source = text(helper, &arguments[0])?;
        let Ok(program) = engine::compile(&source) else {
            return Ok(Value::Bool(false));
        };
        let subject = text(helper, &arguments[1])?;
        let call = Call {
            helper,
            source,
            program,
            subject,
        };
        let mut matcher = call.matcher();
        let found = matcher
            .find_at(0)
            .map_err(|message| call.failed(&message))?;
        return Ok(Value::Bool(found.is_some()));
    }
    let call = Call::new(helper, arguments, 0, 1)?;
    let mut matcher = call.matcher();
    let found = matcher
        .find_at(0)
        .map_err(|message| call.failed(&message))?;
    Ok(Value::Bool(found.is_some()))
}

/// `RegexFind` and `MustRegexFind`: the leftmost match, or the empty string.
fn find(helper: &str, arguments: &[Value], required: bool) -> Result<Value, Error> {
    arity(helper, arguments.len(), 2, Some(2))?;
    let call = Call::new(helper, arguments, 0, 1)?;
    let mut matcher = call.matcher();
    let found = matcher
        .find_at(0)
        .map_err(|message| call.failed(&message))?;
    match found {
        Some(_) => Ok(Value::String(matcher.text_of(found.as_ref()))),
        None if required => Err(call.no_match()),
        // A pattern that does not match is the empty string, which is what
        // `Match().Value` is in the reference.
        None => Ok(Value::String(String::new())),
    }
}

/// `RegexFindAll` and `MustRegexFindAll`: every match, or the first `count`.
fn find_all(helper: &str, arguments: &[Value], required: bool) -> Result<Value, Error> {
    arity(helper, arguments.len(), 3, Some(3))?;
    let call = Call::new(helper, arguments, 0, 1)?;
    let count = match_count(helper, &arguments[2])?;
    let mut matcher = call.matcher();
    let found = matcher
        .matches(count)
        .map_err(|message| call.failed(&message))?;
    if found.is_empty() && required {
        return Err(call.no_match());
    }
    Ok(Value::List(
        found
            .iter()
            .map(|found| Value::String(matcher.text_of(Some(found))))
            .collect(),
    ))
}

/// `RegexReplaceAll` and `RegexReplaceAllLiteral`, and their `must*` forms.
///
/// The subject is the third argument, which is what the reference registers:
/// the pattern, then the replacement, then the subject.
fn replace(
    helper: &str,
    arguments: &[Value],
    literal: bool,
    required: bool,
) -> Result<Value, Error> {
    arity(helper, arguments.len(), 3, Some(3))?;
    let call = Call::new(helper, arguments, 0, 2)?;
    let replacement = text(helper, &arguments[1])?;
    let mut matcher = call.matcher();
    if required
        && matcher
            .find_at(0)
            .map_err(|message| call.failed(&message))?
            .is_none()
    {
        return Err(call.no_match());
    }
    let replaced = matcher
        .replace_all(&replacement, literal)
        .map_err(|message| call.failed(&message))?;
    Ok(Value::String(replaced))
}

/// `RegexSplit` and `MustRegexSplit`: the subject split on the pattern.
///
/// A count of zero is no pieces at all, which is the reference's own special
/// case, a negative count is every piece, and a positive count leaves the rest
/// of the subject in the last piece.
fn split(helper: &str, arguments: &[Value], required: bool) -> Result<Value, Error> {
    arity(helper, arguments.len(), 3, Some(3))?;
    let call = Call::new(helper, arguments, 0, 1)?;
    let count = match_count(helper, &arguments[2])?;
    if count == 0 {
        return Ok(Value::List(Vec::new()));
    }
    let mut matcher = call.matcher();
    if required
        && matcher
            .find_at(0)
            .map_err(|message| call.failed(&message))?
            .is_none()
    {
        return Err(call.no_match());
    }
    let pieces = matcher
        .split(count)
        .map_err(|message| call.failed(&message))?;
    Ok(Value::List(pieces.into_iter().map(Value::String).collect()))
}

/// `RegexQuoteMeta`: the value with every metacharacter escaped.
fn quote_meta(helper: &str, arguments: &[Value]) -> Result<Value, Error> {
    arity(helper, arguments.len(), 1, Some(1))?;
    let value = text(helper, &arguments[0])?;
    let mut quoted = String::with_capacity(value.len());
    for character in value.chars() {
        if META.contains(&character) {
            quoted.push('\\');
        }
        quoted.push(character);
    }
    Ok(Value::String(quoted))
}

/// Reads a match count the way the reference's `N` does.
///
/// A boolean is one or zero and a number is truncated toward zero, which is what
/// makes a count of `-1` mean "all of them". A string is read as a number, and a
/// value that is not a number at all is refused rather than read as zero, because
/// a silent zero would answer a different question than the author asked.
fn match_count(helper: &str, value: &Value) -> Result<i64, Error> {
    match value {
        Value::Bool(flag) => Ok(i64::from(*flag)),
        #[allow(clippy::cast_possible_truncation)]
        Value::Number(number) if number.is_finite() => Ok(number.trunc() as i64),
        Value::String(text) => {
            let trimmed = text.trim();
            if let Ok(count) = trimmed.parse::<i64>() {
                return Ok(count);
            }
            match trimmed.parse::<f64>() {
                #[allow(clippy::cast_possible_truncation)]
                Ok(count) if count.is_finite() => Ok(count.trunc() as i64),
                _ => Err(invalid(
                    helper,
                    format!("cannot read {trimmed:?} as a match count"),
                )),
            }
        }
        other => Err(invalid(
            helper,
            format!("cannot read {} as a match count", other.render()),
        )),
    }
}

/// A small RE2-compatible pattern compiler and backtracking matcher.
///
/// The compiler turns a pattern into a flat instruction list, and the matcher
/// runs that list over the subject's characters, trying each start position and
/// backtracking through an explicit stack of pending alternatives.
mod engine {
    /// How many instructions one search may execute.
    ///
    /// A pattern that matches a long subject in one pass needs about one step
    /// per character, so this covers a subject a few hundred kilobytes long. It
    /// is a ceiling rather than a promise: a pattern whose alternatives multiply
    /// reaches it and is reported, which is the honest answer for a shape RE2
    /// rejects for the same reason.
    pub(super) const MAX_STEPS: u32 = 300_000;

    /// How many pending alternatives one search may hold.
    ///
    /// A greedy `a*` over a subject holds one alternative per character, so this
    /// is also the longest subject a repetitive pattern can be run over.
    pub(super) const MAX_PENDING: u32 = 100_000;

    /// The largest count a `{n,m}` may repeat, as Go's own limit.
    const MAX_REPEAT: u32 = 1_000;

    /// The most capture groups one pattern may have.
    const MAX_GROUPS: usize = 64;

    /// The largest character, which a negated class is written up to.
    const LAST: char = '\u{10ffff}';

    /// A compiled pattern.
    pub(super) struct Program {
        instructions: Vec<Instruction>,
        classes: Vec<Class>,
        /// The name of each capture group, in group order.
        names: Vec<Option<String>>,
        group_count: usize,
        /// Whether the pattern is the empty pattern, which `split` treats
        /// differently from a pattern that simply does not match.
        empty_pattern: bool,
        /// How many choice points the pattern has, which sizes the matcher's
        /// per-loop bookkeeping.
        choices: usize,
    }

    /// One match, as offsets into the subject.
    #[derive(Clone, Debug)]
    pub(super) struct Found {
        /// The offset the match starts at.
        pub(super) start: usize,
        /// The offset just past the match.
        pub(super) end: usize,
        /// The start and end offset of each capture group, in group order.
        captures: Vec<Option<usize>>,
    }

    /// Compiles a pattern.
    pub(super) fn compile(pattern: &str) -> Result<Program, String> {
        let mut parser = Parser {
            characters: pattern.chars().collect(),
            index: 0,
            flags: Flags::default(),
            classes: Vec::new(),
            names: Vec::new(),
            group_count: 0,
            choices: 0,
            steps: 0,
        };
        let mut instructions = Vec::new();
        parser.parse_alternate(&mut instructions)?;
        if let Some(character) = parser.peek() {
            return Err(format!("unexpected {character:?}"));
        }
        instructions.push(Instruction::Match);
        Ok(Program {
            instructions,
            classes: parser.classes,
            names: parser.names,
            group_count: parser.group_count,
            empty_pattern: parser.characters.is_empty(),
            choices: parser.choices,
        })
    }

    /// Runs a compiled pattern over a subject.
    pub(super) struct Matcher<'a> {
        program: &'a Program,
        input: Vec<char>,
    }

    impl<'a> Matcher<'a> {
        /// Builds a matcher for a subject.
        pub(super) fn new(program: &'a Program, subject: &str) -> Self {
            Self {
                program,
                input: subject.chars().collect(),
            }
        }

        /// Returns the characters of a match, or the empty string for none.
        pub(super) fn text_of(&self, found: Option<&Found>) -> String {
            let Some(found) = found else {
                return String::new();
            };
            self.slice(found.start, found.end)
        }

        /// Returns the characters between two offsets.
        fn slice(&self, start: usize, end: usize) -> String {
            let start = start.min(self.input.len());
            let end = end.min(self.input.len()).max(start);
            self.input[start..end].iter().collect()
        }

        /// Finds the leftmost match at or after `from`.
        ///
        /// The offsets are absolute, so an anchor is only satisfied where the
        /// subject really starts or ends even when the search starts later, which
        /// is how Go's `FindString` and `FindAll` behave.
        pub(super) fn find_at(&mut self, from: usize) -> Result<Option<Found>, String> {
            // The budget covers the whole search rather than one start position,
            // so a long subject cannot multiply the work by its own length.
            let mut steps = 0u32;
            for start in from..=self.input.len() {
                if let Some(found) = self.run(start, &mut steps)? {
                    return Ok(Some(found));
                }
            }
            Ok(None)
        }

        /// Runs the program anchored at one start position.
        ///
        /// This is the matcher itself. Every step is one instruction against the
        /// program, and each case is a few lines; splitting the loop would put
        /// the value an instruction computes a call away from the state it
        /// updates, which is the one thing a backtracking matcher must not do.
        #[allow(clippy::too_many_lines)]
        fn run(&self, start: usize, steps: &mut u32) -> Result<Option<Found>, String> {
            let mut captures: Vec<Option<usize>> = vec![None; self.program.group_count * 2];
            let mut pending: Vec<Pending> = Vec::new();
            // Where on the stack each loop put its current choice point, which is
            // how its back edge finds that point again.
            let mut entered: Vec<usize> = vec![NONE; self.program.choices];
            // The position each loop entered its current iteration at, kept even
            // after that iteration's choice point is spent, so the back edge can
            // still tell an iteration that consumed nothing from one that did.
            let mut entering: Vec<usize> = vec![NONE; self.program.choices];
            let mut counter = 0usize;
            let mut position = start;
            loop {
                *steps += 1;
                if *steps > MAX_STEPS {
                    return Err("the pattern needs more steps than this crate allows".to_owned());
                }
                // **Indexed with `get`, not `[]`.** `counter` is maintained by this
                // loop and by `backtrack`, so nothing in the type system proves it is
                // in bounds — and an out-of-range read here is a panic in a function
                // whose whole job is to turn hostile input into an `Err`. The parser
                // always appends `Instruction::Match`, so this arm is unreachable in
                // practice; it is here so that "unreachable" is a property rather
                // than an assumption, and so the bound is checked on every step
                // instead of trusted.
                //
                // `Instruction` is `Copy`, so `.copied()` keeps the `match` arms
                // below unchanged -- a borrow would force every arm to re-derive
                // its fields through a reference.
                //
                // **Four** other indices in this function are still checked rather than
                // guarded -- `self.program.classes[class]`, `entered[loop_number]`,
                // `entering[loop_number]` and `captures[slot]` -- and each is in range
                // *by construction*: `push_class` returns `self.classes.len() - 1`,
                // `next_choice` returns `self.choices - 1` against `program.choices`
                // slots, and `slot` is `(group - 1) * 2 + offset` with `group` bounded
                // by `MAX_GROUPS`, so it stays under `captures.len()`.
                //
                // An earlier version of this comment said "three" and named three, so
                // a reader auditing *every* index here would have missed `captures[slot]`
                // entirely. The count is the load-bearing part: a comment that
                // undercounts is worse than none, because it tells the reader the
                // sweep is finished when it is not.
                //
                // This one is different from all four: `counter` is reassigned from a
                // `Pending` payload inside `backtrack`, which no type constrains, so a
                // bounds check is the only thing standing between a malformed program
                // and a panic.
                let Some(instruction) = self.program.instructions.get(counter).copied() else {
                    return Err(format!(
                        "the compiled program has no instruction at index {counter}, so the \
                         pattern is malformed"
                    ));
                };
                match instruction {
                    Instruction::Character { character, fold } => {
                        if self
                            .consumes(position, |found| character_matches(found, character, fold))
                        {
                            position += 1;
                            counter += 1;
                        } else if !backtrack(
                            &mut pending,
                            &mut captures,
                            &mut counter,
                            &mut position,
                            &mut entered,
                        ) {
                            return Ok(None);
                        }
                    }
                    Instruction::AnyCharacter { newline } => {
                        if self.consumes(position, |found| newline || found != '\n') {
                            position += 1;
                            counter += 1;
                        } else if !backtrack(
                            &mut pending,
                            &mut captures,
                            &mut counter,
                            &mut position,
                            &mut entered,
                        ) {
                            return Ok(None);
                        }
                    }
                    Instruction::Class(class) => {
                        if self
                            .consumes(position, |found| self.program.classes[class].matches(found))
                        {
                            position += 1;
                            counter += 1;
                        } else if !backtrack(
                            &mut pending,
                            &mut captures,
                            &mut counter,
                            &mut position,
                            &mut entered,
                        ) {
                            return Ok(None);
                        }
                    }
                    Instruction::Save(slot) => {
                        captures[slot] = Some(position);
                        counter += 1;
                    }
                    Instruction::Split {
                        prefer,
                        fallback,
                        choice,
                    } => {
                        if pending.len() >= MAX_PENDING as usize {
                            return Err(
                                "the pattern holds more alternatives than this crate allows"
                                    .to_owned(),
                            );
                        }
                        // A loop records where its choice point went and where the
                        // iteration it opens starts, which is what its back edge
                        // needs to tell a spent iteration from a live one.
                        if let Choice::Loop(loop_number) = choice {
                            entered[loop_number] = pending.len();
                            entering[loop_number] = position;
                        }
                        pending.push(Pending {
                            counter: fallback,
                            position,
                            captures: captures.clone(),
                            choice,
                        });
                        counter = prefer;
                    }
                    Instruction::Jump(target) => counter = target,
                    Instruction::Repeat {
                        loop_start,
                        exit,
                        loop_number,
                    } => {
                        // The back edge of a repeat. A body that matched nothing
                        // must not be entered again, or a loop over a body that can
                        // match empty never terminates: `(a*)*b` is the standard
                        // example, and an engine that cannot rule that out spends
                        // forever on it.
                        //
                        // The body may have left choice points of its own on the
                        // stack — a nested alternation's, or the loop's own on the
                        // way in — so this loop's choice point is found through the
                        // index recorded when it was pushed rather than by a
                        // search.
                        //
                        // Whether this loop's choice point is still on the stack.
                        // One that is not has already been used, so the loop opens
                        // a fresh one and the body is tried again. A quantifier
                        // over a body that can match the empty string is the shape
                        // RE2 exists to avoid, because it has no linear reading
                        // here; the step budget is what reports it.
                        let live = entered
                            .get(loop_number)
                            .copied()
                            .filter(|index| *index < pending.len())
                            .is_some_and(|index| {
                                pending[index].choice == Choice::Loop(loop_number)
                            });
                        if live && entering.get(loop_number).copied() == Some(position) {
                            // The iteration started where the matcher now is, so
                            // it consumed nothing and the loop is over. Only the
                            // loop's own choice point is dropped: the
                            // alternatives the body left behind are still worth
                            // trying, and dropping them would make `(|a)*b` never
                            // try its `a` branch at all. The captures go back to
                            // what the choice point recorded, because an iteration
                            // that consumed nothing should not leave its group
                            // boundaries behind, and in `(a*)*b` the match Go
                            // reports for group one is the first iteration's.
                            let index = entered[loop_number];
                            captures = std::mem::take(&mut pending[index].captures);
                            pending.remove(index);
                            entered[loop_number] = NONE;
                            entering[loop_number] = NONE;
                            counter = exit;
                        } else {
                            counter = loop_start;
                        }
                    }
                    Instruction::Fail { alternation } => {
                        // Every branch of this alternation failed. Its own choice
                        // points are still on the stack, so they are discarded
                        // before the one that came before the alternation is
                        // resumed. Resuming one of them instead would retry the
                        // next branch forever, and falling through to the
                        // continuation would make the alternation match the empty
                        // string where it matched nothing at all.
                        while pending
                            .last()
                            .is_some_and(|frame| frame.choice == Choice::Branch(alternation))
                        {
                            pending.pop();
                        }
                        if !backtrack(
                            &mut pending,
                            &mut captures,
                            &mut counter,
                            &mut position,
                            &mut entered,
                        ) {
                            return Ok(None);
                        }
                    }
                    Instruction::Assert(anchor) => {
                        if self.anchor_holds(anchor, position) {
                            counter += 1;
                        } else if !backtrack(
                            &mut pending,
                            &mut captures,
                            &mut counter,
                            &mut position,
                            &mut entered,
                        ) {
                            return Ok(None);
                        }
                    }
                    Instruction::Match => {
                        return Ok(Some(Found {
                            start,
                            end: position,
                            captures,
                        }));
                    }
                }
            }
        }

        /// Reports whether the instruction accepts the character at `position`.
        fn consumes(&self, position: usize, accept: impl Fn(char) -> bool) -> bool {
            self.input.get(position).copied().is_some_and(accept)
        }

        /// Reports whether an anchor is satisfied at `position`.
        fn anchor_holds(&self, anchor: Anchor, position: usize) -> bool {
            match anchor {
                Anchor::TextStart => position == 0,
                Anchor::TextEnd => position == self.input.len(),
                Anchor::LineStart => position == 0 || self.input.get(position - 1) == Some(&'\n'),
                Anchor::LineEnd => {
                    position == self.input.len() || self.input.get(position) == Some(&'\n')
                }
                Anchor::WordBoundary | Anchor::NotWordBoundary => {
                    // Go's word characters are the ASCII alphanumerics and the
                    // underscore, and a boundary is a change between one of them
                    // and anything else.
                    let before = position
                        .checked_sub(1)
                        .and_then(|index| self.input.get(index))
                        .is_some_and(|character| is_word(*character));
                    let after = self
                        .input
                        .get(position)
                        .is_some_and(|character| is_word(*character));
                    (before != after) == matches!(anchor, Anchor::WordBoundary)
                }
            }
        }

        /// Finds successive non-overlapping matches.
        ///
        /// This follows Go's `allMatches` step for step, because two of its rules
        /// are observable: an empty match is not reported when it begins exactly
        /// where the previous match ended, and the scan advances by the width of
        /// the character at the current position rather than past the match. A
        /// negative count is every match, as `-1` is in Go.
        pub(super) fn matches(&mut self, count: i64) -> Result<Vec<Found>, String> {
            let limit = if count < 0 {
                None
            } else {
                usize::try_from(count).ok()
            };
            let mut found: Vec<Found> = Vec::new();
            let mut position = 0usize;
            // `-1` is the "no previous match" sentinel, since no offset is below
            // zero.
            let mut previous_end: Option<usize> = None;
            while position <= self.input.len() {
                if limit.is_some_and(|limit| found.len() >= limit) {
                    break;
                }
                let Some(found_match) = self.find_at(position)? else {
                    break;
                };
                let mut accepted = true;
                if found_match.start == found_match.end {
                    accepted = previous_end != Some(found_match.start);
                    // At the end of the subject there is no character to step
                    // over, so the scan steps past the end instead.
                    position = if position < self.input.len() {
                        position + 1
                    } else {
                        self.input.len() + 1
                    };
                } else {
                    position = found_match.end;
                }
                previous_end = Some(found_match.end);
                if accepted {
                    found.push(found_match);
                }
            }
            Ok(found)
        }

        /// Splits the subject on the pattern.
        ///
        /// A negative count is every piece and a positive one leaves the rest of
        /// the subject in the last piece, which is Go's `Split`. An empty subject
        /// with a non-empty pattern is one empty piece, which is also Go's rule
        /// and the reason an empty pattern and an unmatched pattern differ.
        pub(super) fn split(&mut self, count: i64) -> Result<Vec<String>, String> {
            if self.input.is_empty() && !self.program.empty_pattern {
                return Ok(vec![String::new()]);
            }
            let limit = if count < 0 {
                None
            } else {
                usize::try_from(count).ok()
            };
            let matches = self.matches(count)?;
            let mut pieces: Vec<String> = Vec::new();
            let mut begin = 0usize;
            let mut end = 0usize;
            for found in matches {
                if limit.is_some_and(|limit| pieces.len() + 1 >= limit) {
                    break;
                }
                end = found.start;
                // An empty match at the very start contributes no piece, which is
                // Go's `Split`.
                if found.end != 0 {
                    pieces.push(self.slice(begin, end));
                }
                begin = found.end;
            }
            if end != self.input.len() {
                pieces.push(self.slice(begin, self.input.len()));
            }
            Ok(pieces)
        }

        /// Replaces every match, expanding `$1` unless the replacement is literal.
        ///
        /// This follows Go's `replaceAll`, including its two rules that are
        /// observable on a pattern matching both empty and non-empty text: an
        /// empty match that begins exactly where the previous match ended is
        /// copied through rather than replaced, so `x*` on `ab` does not double
        /// the replacement, and the scan steps over the character at the current
        /// position, which is what keeps an empty match from repeating.
        pub(super) fn replace_all(
            &mut self,
            replacement: &str,
            literal: bool,
        ) -> Result<String, String> {
            let mut output = String::new();
            let mut position = 0usize;
            let mut last_end = 0usize;
            while position <= self.input.len() {
                let Some(found) = self.find_at(position)? else {
                    break;
                };
                output.push_str(&self.slice(last_end, found.start));
                if found.end > last_end || found.start == 0 {
                    if literal {
                        output.push_str(replacement);
                    } else {
                        self.expand(&mut output, &found, replacement);
                    }
                }
                last_end = found.end;
                // Advance at least one character. At the end of the subject there
                // is no character to step over, so the scan steps past the end.
                position = if position < found.end {
                    found.end
                } else if position < self.input.len() {
                    position + 1
                } else {
                    self.input.len() + 1
                };
            }
            output.push_str(&self.slice(last_end, self.input.len()));
            Ok(output)
        }

        /// Expands a replacement against a match, as `ExpandGoRegexReplacement`
        /// does.
        ///
        /// `$1` and `${1}` name a group, `$$` is one dollar, a lone `$` is one
        /// dollar, and a name that is neither a group number nor a named group
        /// expands to nothing.
        fn expand(&self, output: &mut String, found: &Found, replacement: &str) {
            let template: Vec<char> = replacement.chars().collect();
            let mut index = 0usize;
            while index < template.len() {
                if template[index] != '$' {
                    output.push(template[index]);
                    index += 1;
                    continue;
                }
                if index + 1 == template.len() {
                    output.push('$');
                    index += 1;
                    continue;
                }
                if template[index + 1] == '$' {
                    output.push('$');
                    index += 2;
                    continue;
                }
                let Some((name, next)) = extract_name(&template, index + 1) else {
                    // A `$` that names nothing is a dollar, and the character
                    // after it is read again.
                    output.push('$');
                    index += 1;
                    continue;
                };
                index = next;
                if let Some(text) = self.group_text(found, &name) {
                    output.push_str(&text);
                }
            }
        }

        /// Returns the text a replacement's group name refers to.
        ///
        /// `$0` is the whole match, as it is in Go. A group that took no part in
        /// the match refers to nothing, which is what an unmatched group expands
        /// to there as well.
        fn group_text(&self, found: &Found, name: &str) -> Option<String> {
            let group = match group_number(name) {
                Some(group) => group,
                None => {
                    self.program
                        .names
                        .iter()
                        .position(|candidate| candidate.as_deref() == Some(name))?
                        + 1
                }
            };
            if group == 0 {
                return Some(self.slice(found.start, found.end));
            }
            if group > self.program.group_count {
                return None;
            }
            let start = (*found.captures.get((group - 1) * 2)?)?;
            let end = (*found.captures.get((group - 1) * 2 + 1)?)?;
            Some(self.slice(start, end))
        }
    }

    /// Restores the most recent pending alternative, reporting whether there was
    /// one to restore.
    ///
    /// A loop's record of where its choice point went is cleared when that point
    /// is consumed, so the loop's back edge can tell a choice point it still owns
    /// from one that has already been used up.
    fn backtrack(
        pending: &mut Vec<Pending>,
        captures: &mut Vec<Option<usize>>,
        counter: &mut usize,
        position: &mut usize,
        entered: &mut [usize],
    ) -> bool {
        let Some(alternative) = pending.pop() else {
            return false;
        };
        if let Choice::Loop(loop_number) = alternative.choice {
            entered[loop_number] = NONE;
        }
        *counter = alternative.counter;
        *position = alternative.position;
        *captures = alternative.captures;
        true
    }

    /// A saved alternative to try when the current one fails.
    struct Pending {
        counter: usize,
        position: usize,
        captures: Vec<Option<usize>>,
        /// Which construct this choice point belongs to, so a `Fail` or a
        /// `Repeat` finds its own and not a nested one's.
        choice: Choice,
    }

    /// The "no choice point" value in the per-loop index.
    const NONE: usize = usize::MAX;

    /// What a choice point belongs to.
    ///
    /// An alternation's branches and a repeat's loop each get their own number,
    /// so neither discards the other's choice points when it gives up.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Choice {
        /// A branch of the alternation with this number.
        Branch(usize),
        /// The loop of the repeat with this number.
        Loop(usize),
    }

    /// Reads a replacement's group name, which is `${name}` or a bare name.
    ///
    /// A name is the letters, digits, and underscores after the `$`; a `{` form
    /// that is never closed is not a name at all.
    fn extract_name(template: &[char], start: usize) -> Option<(String, usize)> {
        if template.get(start) == Some(&'{') {
            let name_start = start + 1;
            let name_end = name_start + template[name_start..].iter().position(|c| *c == '}')?;
            return Some((
                template[name_start..name_end].iter().collect(),
                name_end + 1,
            ));
        }
        let mut end = start;
        while let Some(character) = template.get(end) {
            if !character.is_alphanumeric() && *character != '_' {
                break;
            }
            end += 1;
        }
        if end == start {
            return None;
        }
        Some((template[start..end].iter().collect(), end))
    }

    /// Returns the group a numeric replacement name refers to.
    ///
    /// A name with a leading zero is not a number, which is Go's rule: `$01` is a
    /// name, and a pattern with no group of that name expands it to nothing.
    fn group_number(name: &str) -> Option<usize> {
        if name.is_empty() || !name.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        if name.len() > 1 && name.starts_with('0') {
            return None;
        }
        name.parse().ok()
    }

    /// Reports whether a character is one of Go's word characters.
    fn is_word(character: char) -> bool {
        character.is_ascii_alphanumeric() || character == '_'
    }

    /// Reports whether a subject character matches a literal.
    ///
    /// Folding is the simple kind Go applies: the ASCII letter cases and a
    /// character's own single-character lowercase and uppercase.
    fn character_matches(found: char, literal: char, fold: bool) -> bool {
        found == literal
            || (fold && (lower(found) == lower(literal) || upper(found) == upper(literal)))
    }

    /// The lowercase form of a character, as Go's simple folding spells it.
    fn lower(character: char) -> char {
        character.to_lowercase().next().unwrap_or(character)
    }

    /// The uppercase form of a character, as Go's simple folding spells it.
    fn upper(character: char) -> char {
        character.to_uppercase().next().unwrap_or(character)
    }

    /// A compiled instruction.
    #[derive(Clone, Copy)]
    enum Instruction {
        Character {
            character: char,
            fold: bool,
        },
        AnyCharacter {
            newline: bool,
        },
        Class(usize),
        Save(usize),
        Split {
            prefer: usize,
            fallback: usize,
            /// Which construct this choice point belongs to.
            choice: Choice,
        },
        Jump(usize),
        /// The back edge of an unbounded repeat, which leaves the loop through
        /// `exit` rather than retrying a body that matched nothing.
        Repeat {
            loop_start: usize,
            exit: usize,
            /// This loop's own number, so its back edge finds its choice point.
            loop_number: usize,
        },
        /// Gives up the current alternative, which is how the last branch of an
        /// alternation reports that the whole of it failed.
        Fail {
            alternation: usize,
        },
        Assert(Anchor),
        Match,
    }

    /// An anchor an instruction asserts.
    #[derive(Clone, Copy)]
    enum Anchor {
        TextStart,
        TextEnd,
        LineStart,
        LineEnd,
        WordBoundary,
        NotWordBoundary,
    }

    /// A set of characters, which is what a character class compiles to.
    struct Class {
        negated: bool,
        ranges: Vec<(char, char)>,
        fold: bool,
    }

    impl Class {
        /// Reports whether the class accepts a character.
        fn matches(&self, found: char) -> bool {
            let mut hit = self.contains(found);
            if !hit && self.fold {
                // A folded class accepts either case, which is what makes
                // `(?i)[a-z]` accept `A` and `(?i)[A-Z]` accept `a`.
                hit = self.contains(lower(found)) || self.contains(upper(found));
            }
            hit != self.negated
        }

        /// Reports whether the class's own ranges hold a character.
        fn contains(&self, character: char) -> bool {
            self.ranges
                .iter()
                .any(|(first, last)| character >= *first && character <= *last)
        }
    }

    /// The flags a pattern has set, which change how the rest of it matches.
    ///
    /// Each flag is an independent switch, and a pattern sets any combination of
    /// them, so they are booleans rather than a nested mode. Go's `regexp` spells
    /// them the same way.
    #[allow(clippy::struct_excessive_bools)]
    #[derive(Clone, Copy, Default)]
    struct Flags {
        fold: bool,
        dot_newline: bool,
        line_anchors: bool,
        ungreedy: bool,
    }

    /// The pattern compiler.
    struct Parser {
        characters: Vec<char>,
        index: usize,
        flags: Flags,
        classes: Vec<Class>,
        names: Vec<Option<String>>,
        group_count: usize,
        /// How many choice points have been compiled, which names the next one.
        choices: usize,
        steps: u32,
    }

    /// One item of a character class.
    enum ClassItem {
        /// A single character, which may be the start of a range.
        Character(char),
        /// A shorthand's own ranges, which cannot.
        Ranges(Vec<(char, char)>),
    }

    impl Parser {
        /// Returns the character at the cursor.
        fn peek(&self) -> Option<char> {
            self.characters.get(self.index).copied()
        }

        /// Consumes a character if it is the one expected.
        fn eat(&mut self, expected: char) -> bool {
            if self.peek() == Some(expected) {
                self.index += 1;
                return true;
            }
            false
        }

        /// Names the next choice point, so an alternation's branches and a
        /// repeat's loop are told apart when either gives up.
        fn next_choice(&mut self) -> usize {
            self.choices += 1;
            self.choices - 1
        }

        /// Counts one step of parsing, which bounds a pathologically long pattern.
        fn parse_step(&mut self) -> Result<(), String> {
            self.steps += 1;
            if self.steps > MAX_STEPS {
                return Err("the pattern is longer than this crate allows".to_owned());
            }
            Ok(())
        }

        /// Parses `branch ("|" branch)*` into `output`.
        fn parse_alternate(&mut self, output: &mut Vec<Instruction>) -> Result<(), String> {
            let mut branches: Vec<Vec<Instruction>> = Vec::new();
            loop {
                let mut branch = Vec::new();
                self.parse_sequence(&mut branch)?;
                branches.push(branch);
                if !self.eat('|') {
                    break;
                }
            }
            // A branch is parsed into its own list, so its jump targets are
            // relative to where that list starts. `append` moves them, which is
            // what makes a group body's own loop land in the right place.
            if branches.len() == 1 {
                append(output, &branches[0]);
                return Ok(());
            }
            // Each branch is laid out as `Split body, next; body; Jump end`, and a
            // `Fail` follows the last one. The last branch's fallback is that
            // `Fail` rather than `end`, because falling through to `end` would
            // make an alternation that matched nothing succeed as an empty match
            // at the same offset: `cat|dog` would match the empty string at the
            // start of `hotdog` instead of finding `dog` three characters in.
            let size: usize = branches.iter().map(|branch| branch.len() + 2).sum();
            let fail = output.len() + size;
            let end = fail + 1;
            let alternation = self.next_choice();
            let mut start = output.len();
            for (index, branch) in branches.iter().enumerate() {
                let body = start + 1;
                let after = body + branch.len();
                let fallback = if index + 1 == branches.len() {
                    fail
                } else {
                    after + 1
                };
                output.push(Instruction::Split {
                    prefer: body,
                    fallback,
                    choice: Choice::Branch(alternation),
                });
                append(output, branch);
                output.push(Instruction::Jump(end));
                start = after + 1;
            }
            output.push(Instruction::Fail { alternation });
            Ok(())
        }

        /// Parses a run of atoms into `output`.
        fn parse_sequence(&mut self, output: &mut Vec<Instruction>) -> Result<(), String> {
            while let Some(character) = self.peek() {
                if character == '|' || character == ')' {
                    break;
                }
                self.parse_step()?;
                self.parse_repeated(output)?;
            }
            Ok(())
        }

        /// Parses an atom and the quantifier that may follow it.
        fn parse_repeated(&mut self, output: &mut Vec<Instruction>) -> Result<(), String> {
            let mut atom = Vec::new();
            self.parse_atom(&mut atom)?;
            let bounds = match self.peek() {
                Some('*') => {
                    self.index += 1;
                    Some((0, None))
                }
                Some('+') => {
                    self.index += 1;
                    Some((1, None))
                }
                Some('?') => {
                    self.index += 1;
                    Some((0, Some(1)))
                }
                Some('{') => self.parse_bounds()?,
                _ => None,
            };
            let Some((min, max)) = bounds else {
                append(output, &atom);
                return Ok(());
            };
            // A `?` after a quantifier makes it lazy, and the `U` flag makes
            // laziness the default.
            let mut greedy = !self.flags.ungreedy;
            match self.peek() {
                Some('?') => {
                    self.index += 1;
                    greedy = !greedy;
                }
                Some('+') => return Err("a possessive quantifier is not supported".to_owned()),
                _ => {}
            }
            if matches!(self.peek(), Some('*' | '+' | '?' | '{')) {
                return Err("a quantifier cannot follow a quantifier".to_owned());
            }
            self.emit_repeat(&atom, min, max, greedy, output);
            Ok(())
        }

        /// Parses a `{n}`, `{n,}`, or `{n,m}` bound.
        ///
        /// A brace that does not open a valid bound is a literal brace, which is
        /// what Go's parser does with `a{b`.
        fn parse_bounds(&mut self) -> Result<Option<(u32, Option<u32>)>, String> {
            let start = self.index;
            self.index += 1;
            // A `{` that does not open a valid bound is a literal brace, so
            // failing to parse one rewinds rather than raising: the position is
            // restored and the caller treats the brace as text.
            let Some(min) = self.parse_count() else {
                self.index = start;
                return Ok(None);
            };
            let max = if !self.eat(',') {
                Some(min)
            } else if self.peek() == Some('}') {
                None
            } else if let Some(count) = self.parse_count() {
                Some(count)
            } else {
                self.index = start;
                return Ok(None);
            };
            if !self.eat('}') {
                self.index = start;
                return Ok(None);
            }
            if max.is_some_and(|max| max < min) {
                return Err(format!(
                    "{{{},{}}} repeats fewer times than it requires",
                    min,
                    max.unwrap_or(0)
                ));
            }
            if min > MAX_REPEAT || max.is_some_and(|max| max > MAX_REPEAT) {
                return Err(format!(
                    "a repeat count above {MAX_REPEAT} is not supported"
                ));
            }
            Ok(Some((min, max)))
        }

        /// Parses the digits of a bound, or `None` when there are none.
        fn parse_count(&mut self) -> Option<u32> {
            let start = self.index;
            while self
                .peek()
                .is_some_and(|character| character.is_ascii_digit())
            {
                self.index += 1;
            }
            if start == self.index {
                return None;
            }
            let digits: String = self.characters[start..self.index].iter().collect();
            match digits.parse() {
                Ok(count) => Some(count),
                // A count too large for `u32` is over the limit either way.
                Err(_) => Some(u32::MAX),
            }
        }

        /// Parses a single atom into `output`.
        fn parse_atom(&mut self, output: &mut Vec<Instruction>) -> Result<(), String> {
            let Some(character) = self.peek() else {
                return Ok(());
            };
            match character {
                '(' => self.parse_group(output),
                '[' => {
                    let class = self.parse_class()?;
                    output.push(Instruction::Class(self.push_class(class)));
                    Ok(())
                }
                '.' => {
                    self.index += 1;
                    output.push(Instruction::AnyCharacter {
                        newline: self.flags.dot_newline,
                    });
                    Ok(())
                }
                '^' => {
                    self.index += 1;
                    output.push(Instruction::Assert(if self.flags.line_anchors {
                        Anchor::LineStart
                    } else {
                        Anchor::TextStart
                    }));
                    Ok(())
                }
                '$' => {
                    self.index += 1;
                    output.push(Instruction::Assert(if self.flags.line_anchors {
                        Anchor::LineEnd
                    } else {
                        Anchor::TextEnd
                    }));
                    Ok(())
                }
                '\\' => self.parse_escape(output),
                '*' | '+' | '?' => Err(format!("nothing to repeat before {character:?}")),
                ')' => Err("unmatched )".to_owned()),
                other => {
                    self.index += 1;
                    output.push(Instruction::Character {
                        character: other,
                        fold: self.flags.fold,
                    });
                    Ok(())
                }
            }
        }

        /// Parses a group, which may capture, name its capture, or set flags.
        fn parse_group(&mut self, output: &mut Vec<Instruction>) -> Result<(), String> {
            self.index += 1;
            let mut name = None;
            let mut capture = true;
            if self.peek() == Some('?') {
                match self.characters.get(self.index + 1).copied() {
                    Some(':') => {
                        self.index += 2;
                        capture = false;
                    }
                    // Both spellings of a named group are accepted: Go writes
                    // `(?P<name>` and the reference's own engine `(?<name>`.
                    Some('P' | '<') => {
                        self.index += if self.characters.get(self.index + 1) == Some(&'P') {
                            3
                        } else {
                            2
                        };
                        name = Some(self.parse_group_name()?);
                    }
                    _ => {
                        self.index += 1;
                        let flags = self.parse_flags()?;
                        if self.eat(':') {
                            // A flag group restores the previous flags when it
                            // closes, so its body is parsed with its own.
                            return self.parse_flagged_group(output, capture, name, flags);
                        }
                        if !self.eat(')') {
                            return Err("a flag setting ends with ) or starts a group".to_owned());
                        }
                        self.flags = flags;
                        return Ok(());
                    }
                }
            }
            if capture {
                if self.group_count >= MAX_GROUPS {
                    return Err("the pattern has too many capture groups".to_owned());
                }
                self.group_count += 1;
                let group = self.group_count;
                self.names.push(name);
                output.push(Instruction::Save((group - 1) * 2));
                self.parse_alternate(output)?;
                self.expect(')')?;
                output.push(Instruction::Save((group - 1) * 2 + 1));
            } else {
                self.parse_alternate(output)?;
                self.expect(')')?;
            }
            Ok(())
        }

        /// Parses a group that sets flags for its own body only.
        fn parse_flagged_group(
            &mut self,
            output: &mut Vec<Instruction>,
            capture: bool,
            name: Option<String>,
            flags: Flags,
        ) -> Result<(), String> {
            let restore = self.flags;
            self.flags = flags;
            let result = self.parse_group_body(output, capture, name);
            self.flags = restore;
            result
        }

        /// Parses the body of a group and the instruction that closes it.
        fn parse_group_body(
            &mut self,
            output: &mut Vec<Instruction>,
            capture: bool,
            name: Option<String>,
        ) -> Result<(), String> {
            if !capture {
                self.parse_alternate(output)?;
                return self.expect(')');
            }
            if self.group_count >= MAX_GROUPS {
                return Err("the pattern has too many capture groups".to_owned());
            }
            self.group_count += 1;
            let group = self.group_count;
            self.names.push(name);
            output.push(Instruction::Save((group - 1) * 2));
            self.parse_alternate(output)?;
            self.expect(')')?;
            output.push(Instruction::Save((group - 1) * 2 + 1));
            Ok(())
        }

        /// Parses the name of a named capture group, which ends at `>`.
        fn parse_group_name(&mut self) -> Result<String, String> {
            let start = self.index;
            while let Some(character) = self.peek() {
                if character == '>' {
                    let name: String = self.characters[start..self.index].iter().collect();
                    self.index += 1;
                    return Ok(name);
                }
                if character == ')' || character == '<' {
                    return Err(format!("the group name is not closed before {character:?}"));
                }
                self.index += 1;
            }
            Err("the group name is not closed".to_owned())
        }

        /// Parses the `i`, `s`, `m`, and `U` flags, which a `-` turns off.
        ///
        /// The name ends at `)` or `:`, which is what tells a flag setting from a
        /// flag group.
        fn parse_flags(&mut self) -> Result<Flags, String> {
            let mut flags = self.flags;
            let mut turning_off = false;
            while let Some(character) = self.peek() {
                if character == ')' || character == ':' {
                    break;
                }
                self.index += 1;
                match character {
                    'i' => flags.fold = !turning_off,
                    's' => flags.dot_newline = !turning_off,
                    'm' => flags.line_anchors = !turning_off,
                    'U' => flags.ungreedy = !turning_off,
                    '-' => turning_off = true,
                    other => return Err(format!("{other:?} is not a supported flag")),
                }
            }
            Ok(flags)
        }

        /// Consumes an expected character or reports it missing.
        fn expect(&mut self, expected: char) -> Result<(), String> {
            if self.eat(expected) {
                return Ok(());
            }
            match self.peek() {
                Some(character) => Err(format!("expected {expected:?} and found {character:?}")),
                None => Err(format!(
                    "expected {expected:?} and found the end of the pattern"
                )),
            }
        }
        /// Emits a quantified atom.
        ///
        /// A counted bound is expanded into copies of the atom, which is exact and
        /// keeps the matcher simple at the cost of a program that grows with the
        /// count; `MAX_REPEAT` bounds that growth.
        ///
        /// An unbounded bound is a loop whose split comes *before* its body, so the
        /// loop is also how a repeat of zero matches the empty string. Putting the
        /// body first, as `x+` does, would make `x*` require one character.
        fn emit_repeat(
            &mut self,
            atom: &[Instruction],
            min: u32,
            max: Option<u32>,
            greedy: bool,
            output: &mut Vec<Instruction>,
        ) {
            match max {
                None => {
                    // An unbounded repeat is the atom `min - 1` times, then one
                    // mandatory copy, then a loop. The mandatory copy is outside the
                    // loop's choice point so that `x+` cannot match the empty string
                    // by going straight round it.
                    for _ in 0..min.saturating_sub(1) {
                        append(output, atom);
                    }
                    if min > 0 {
                        append(output, atom);
                    }
                    let loop_number = self.next_choice();
                    let split = output.len();
                    output.push(placeholder(Choice::Loop(loop_number)));
                    let body = output.len();
                    append(output, atom);
                    output.push(Instruction::Repeat {
                        loop_start: split,
                        exit: 0,
                        loop_number,
                    });
                    let end = output.len();
                    output[split] = loop_split(body, end, greedy, loop_number);
                    output[end - 1] = Instruction::Repeat {
                        loop_start: split,
                        exit: end,
                        loop_number,
                    };
                }
                Some(max) => {
                    for _ in 0..min {
                        append(output, atom);
                    }
                    let mut splits = Vec::new();
                    for _ in min..max {
                        let loop_number = self.next_choice();
                        splits.push((output.len(), loop_number));
                        output.push(placeholder(Choice::Loop(loop_number)));
                        append(output, atom);
                    }
                    let end = output.len();
                    for (split, loop_number) in splits {
                        output[split] = loop_split(split + 1, end, greedy, loop_number);
                    }
                }
            }
        }

        /// Adds a class to the pattern and returns the index that names it.
        fn push_class(&mut self, class: Class) -> usize {
            self.classes.push(class);
            self.classes.len() - 1
        }

        /// Parses a character class, which the cursor is on the `[` of.
        fn parse_class(&mut self) -> Result<Class, String> {
            self.index += 1;
            let negated = self.eat('^');
            let mut ranges: Vec<(char, char)> = Vec::new();
            let mut first = true;
            loop {
                let Some(character) = self.peek() else {
                    return Err("the character class is not closed".to_owned());
                };
                if character == ']' && !first {
                    self.index += 1;
                    break;
                }
                first = false;
                let item = self.parse_class_item()?;
                let start = match item {
                    ClassItem::Ranges(found) => {
                        ranges.extend(found);
                        continue;
                    }
                    ClassItem::Character(character) => character,
                };
                // A `-` between two characters is a range, unless it is the last
                // character before the closing bracket.
                let after = self.characters.get(self.index + 1).copied();
                if self.peek() == Some('-') && after.is_some() && after != Some(']') {
                    self.index += 1;
                    let end = match self.parse_class_item()? {
                        ClassItem::Character(end) => end,
                        ClassItem::Ranges(_) => {
                            return Err("a range cannot end in a shorthand class".to_owned());
                        }
                    };
                    if end < start {
                        return Err(format!("the range {start:?}-{end:?} is reversed"));
                    }
                    ranges.push((start, end));
                } else {
                    ranges.push((start, start));
                }
            }
            Ok(Class {
                negated,
                ranges,
                fold: self.flags.fold,
            })
        }

        /// Parses one character or shorthand inside a character class.
        fn parse_class_item(&mut self) -> Result<ClassItem, String> {
            let Some(character) = self.peek() else {
                return Err("the character class is not closed".to_owned());
            };
            if character != '\\' {
                self.index += 1;
                return Ok(ClassItem::Character(character));
            }
            self.index += 1;
            let Some(character) = self.peek() else {
                return Err("the pattern ends inside an escape".to_owned());
            };
            self.index += 1;
            if let Some(ranges) = shorthand_ranges(character) {
                return Ok(ClassItem::Ranges(ranges));
            }
            Ok(ClassItem::Character(self.escaped_character(character)?))
        }

        /// Returns the character an escape names.
        fn escaped_character(&mut self, character: char) -> Result<char, String> {
            Ok(match character {
                'a' => '\u{7}',
                'f' => '\u{c}',
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                'v' => '\u{b}',
                // Inside a class `\b` is a backspace, as in Go.
                'b' => '\u{8}',
                '0' => '\0',
                'x' => self.parse_hex_escape()?,
                other if other.is_alphanumeric() => {
                    return Err(format!("\\{other} is not an escape this crate supports"));
                }
                other => other,
            })
        }

        /// Parses `\xHH` and `\x{HHHH}`.
        fn parse_hex_escape(&mut self) -> Result<char, String> {
            if self.eat('{') {
                let start = self.index;
                while let Some(character) = self.peek() {
                    if character == '}' {
                        let digits: String = self.characters[start..self.index].iter().collect();
                        self.index += 1;
                        return u32::from_str_radix(&digits, 16)
                            .ok()
                            .and_then(char::from_u32)
                            .ok_or_else(|| format!("{digits:?} is not a character"));
                    }
                    self.index += 1;
                }
                return Err("a \\x{…} escape is not closed".to_owned());
            }
            let digits: String = self
                .characters
                .get(self.index..self.index + 2)
                .map(<[char]>::to_vec)
                .unwrap_or_default()
                .into_iter()
                .collect();
            if digits.len() != 2 {
                return Err("a \\x escape needs two hexadecimal digits".to_owned());
            }
            self.index += 2;
            u32::from_str_radix(&digits, 16)
                .ok()
                .and_then(char::from_u32)
                .ok_or_else(|| format!("{digits:?} is not a character"))
        }

        /// Parses an escape outside a character class.
        fn parse_escape(&mut self, output: &mut Vec<Instruction>) -> Result<(), String> {
            self.index += 1;
            let Some(character) = self.peek() else {
                return Err("the pattern ends inside an escape".to_owned());
            };
            self.index += 1;
            let anchor = match character {
                'A' => Some(Anchor::TextStart),
                'z' => Some(Anchor::TextEnd),
                'b' => Some(Anchor::WordBoundary),
                'B' => Some(Anchor::NotWordBoundary),
                _ => None,
            };
            if let Some(anchor) = anchor {
                output.push(Instruction::Assert(anchor));
                return Ok(());
            }
            if let Some(ranges) = shorthand_ranges(character) {
                let class = Class {
                    // `shorthand_ranges` already writes an uppercase shorthand as
                    // the ranges it does *not* exclude, so the class is not
                    // negated again here.
                    negated: false,
                    ranges,
                    fold: false,
                };
                output.push(Instruction::Class(self.push_class(class)));
                return Ok(());
            }
            let literal = self.escaped_character(character)?;
            output.push(Instruction::Character {
                character: literal,
                fold: self.flags.fold,
            });
            Ok(())
        }
    }

    /// The ranges a Perl-style shorthand names, or `None` when the escape is not
    /// one.
    ///
    /// An uppercase shorthand names what it excludes, written as the ranges
    /// between the characters it does include, so it composes inside a class.
    fn shorthand_ranges(character: char) -> Option<Vec<(char, char)>> {
        Some(match character {
            'd' => vec![('0', '9')],
            'D' => vec![('\0', '/'), (':', LAST)],
            'w' => vec![('0', '9'), ('A', 'Z'), ('a', 'z'), ('_', '_')],
            'W' => vec![('\0', '/'), (':', '@'), ('[', '^'), ('`', '`'), ('{', LAST)],
            's' => vec![('\t', '\r'), (' ', ' ')],
            'S' => vec![('\0', '\u{8}'), ('\u{e}', '\u{1f}'), ('!', LAST)],
            _ => return None,
        })
    }

    /// Appends an atom, moving the jump targets it holds.
    fn append(output: &mut Vec<Instruction>, fragment: &[Instruction]) {
        let shift = output.len();
        output.extend(fragment.iter().map(|item| shifted(item, shift)));
    }

    /// Moves an instruction's jump targets by `by` places.
    fn shifted(instruction: &Instruction, by: usize) -> Instruction {
        match *instruction {
            Instruction::Split {
                prefer,
                fallback,
                choice,
            } => Instruction::Split {
                prefer: prefer + by,
                fallback: fallback + by,
                choice,
            },
            Instruction::Jump(target) => Instruction::Jump(target + by),
            Instruction::Repeat {
                loop_start,
                exit,
                loop_number,
            } => Instruction::Repeat {
                loop_start: loop_start + by,
                exit: exit + by,
                loop_number,
            },
            other => other,
        }
    }

    /// A split whose targets are not known until the body is emitted.
    fn placeholder(choice: Choice) -> Instruction {
        Instruction::Split {
            prefer: 0,
            fallback: 0,
            choice,
        }
    }

    /// Builds a repeat's choice point.
    fn loop_split(body: usize, end: usize, greedy: bool, loop_number: usize) -> Instruction {
        let (prefer, fallback) = if greedy { (body, end) } else { (end, body) };
        Instruction::Split {
            prefer,
            fallback,
            choice: Choice::Loop(loop_number),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{META, engine, match_count};
    use crate::{Error, Value};

    /// Calls a helper with text arguments and renders the result.
    fn rendered(helper: &str, arguments: &[&str]) -> String {
        let arguments: Vec<Value> = arguments
            .iter()
            .map(|argument| Value::String((*argument).to_owned()))
            .collect();
        crate::call(helper, &arguments)
            .unwrap_or_else(|error| panic!("{helper} failed: {error}"))
            .render()
    }

    /// Calls a helper with typed arguments.
    fn call(helper: &str, arguments: &[Value]) -> Result<Value, Error> {
        crate::call(helper, arguments)
    }

    fn number(value: f64) -> Value {
        Value::Number(value)
    }

    fn text(value: &str) -> Value {
        Value::String(value.to_owned())
    }

    #[test]
    fn the_module_claims_its_own_helpers() {
        for name in [
            "regexMatch",
            "mustRegexMatch",
            "regexFind",
            "mustRegexFind",
            "regexFindAll",
            "mustRegexFindAll",
            "regexReplaceAll",
            "mustRegexReplaceAll",
            "regexReplaceAllLiteral",
            "mustRegexReplaceAllLiteral",
            "regexSplit",
            "mustRegexSplit",
            "regexQuoteMeta",
        ] {
            assert!(
                super::DISPATCH(name, &[], &crate::Context::default()).is_some(),
                "{name} is not claimed by the regex module"
            );
            assert!(!super::takes_rendered_strings(name));
        }
        assert!(super::DISPATCH("add", &[], &crate::Context::default()).is_none());
    }

    #[test]
    fn regex_match_reports_whether_the_pattern_matches() {
        // The fixture's `{{ regexMatch "^neo" "neo-sprig" }}` and the miss that
        // pairs with it.
        assert_eq!(rendered("regexMatch", &["^neo", "neo-sprig"]), "true");
        assert_eq!(rendered("regexMatch", &["^neo", "sprig-neo"]), "false");
        assert_eq!(rendered("mustRegexMatch", &["^neo", "neo-sprig"]), "true");
        // `RegexMatch` catches a pattern it cannot compile and answers false.
        assert_eq!(rendered("regexMatch", &["[", "neo"]), "false");
        // `MustRegexMatch` lets the failure out, where Go panics.
        assert!(matches!(
            call("mustRegexMatch", &[text("["), text("neo")]),
            Err(Error::InvalidArgument { .. })
        ));
    }

    #[test]
    fn regex_find_returns_the_leftmost_match() {
        // The fixture's `{{ regexFind "[0-9]+" "neo42" }}` and its `must` twin.
        assert_eq!(rendered("regexFind", &["[0-9]+", "neo42"]), "42");
        assert_eq!(rendered("mustRegexFind", &["[0-9]+", "neo42"]), "42");
        // A pattern that does not match is the empty string, as `Match().Value`
        // is in the reference.
        assert_eq!(rendered("regexFind", &["[0-9]+", "neo"]), "");
        // `^` is only satisfied at the start of the subject, so a search that
        // starts later finds nothing.
        assert_eq!(rendered("regexFind", &["^a", "ba"]), "");
    }

    #[test]
    fn regex_find_all_returns_every_match_or_the_first_count_of_them() {
        // The fixture's `{{ regexFindAll "[0-9]" "n1e2o3" -1 }}` and its `must`
        // twin. A negative count is all of them, as `-1` is in Go.
        assert_eq!(
            rendered("regexFindAll", &["[0-9]", "n1e2o3", "-1"]),
            "[1 2 3]"
        );
        assert_eq!(
            rendered("mustRegexFindAll", &["a", "banana", "-1"]),
            "[a a a]"
        );
        assert_eq!(rendered("regexFindAll", &["[0-9]", "n1e2o3", "2"]), "[1 2]");
        assert_eq!(rendered("regexFindAll", &["[0-9]", "n1e2o3", "0"]), "[]");
    }

    #[test]
    fn regex_replace_all_expands_group_references() {
        // The fixture's four `regexReplaceAll` cases. `$1` is the group, `${1}W`
        // is the group and then a literal `W`, and `$1W` names a group that does
        // not exist, so it expands to nothing.
        assert_eq!(
            rendered("regexReplaceAll", &["a(x*)b", "T", "-ab-axxb-"]),
            "-T-T-"
        );
        assert_eq!(
            rendered("regexReplaceAll", &["a(x*)b", "$1", "-ab-axxb-"]),
            "--xx-"
        );
        assert_eq!(
            rendered("regexReplaceAll", &["a(x*)b", "${1}W", "-ab-axxb-"]),
            "-W-xxW-"
        );
        assert_eq!(
            rendered("regexReplaceAll", &["a(x*)b", "$1W", "-ab-axxb-"]),
            "---"
        );
        // `$$` is one dollar, and a dollar with nothing after it is also one
        // dollar, so the two spell the same replacement. `$$$` is a dollar pair
        // and then a lone dollar.
        assert_eq!(
            rendered("regexReplaceAll", &["a", "$$", "banana"]),
            "b$n$n$"
        );
        assert_eq!(rendered("regexReplaceAll", &["a", "$", "banana"]), "b$n$n$");
        assert_eq!(
            rendered("regexReplaceAll", &["a", "$$$", "banana"]),
            "b$$n$$n$$"
        );
        // A `$` before a character that cannot start a name is a dollar, and the
        // character is kept.
        assert_eq!(
            rendered("regexReplaceAll", &["a", "x$y", "banana"]),
            "bxnxnx"
        );
        // A group that took no part in the match expands to nothing.
        assert_eq!(rendered("regexReplaceAll", &["(a)|(b)", "[$1]", "b"]), "[]");
    }

    #[test]
    fn regex_replace_all_literal_does_not_expand() {
        // The fixture's `{{ regexReplaceAllLiteral "a(x*)b" "$1" "-ab-axxb-" }}`.
        assert_eq!(
            rendered("regexReplaceAllLiteral", &["a(x*)b", "$1", "-ab-axxb-"]),
            "-$1-$1-"
        );
    }

    #[test]
    fn regex_replace_all_handles_a_match_at_either_end() {
        // The fixture's `{{ regexReplaceAll "-" "#" .value }}` on `neo-env`.
        assert_eq!(
            rendered("regexReplaceAll", &["-", "#", "neo-env"]),
            "neo#env"
        );
        assert_eq!(rendered("regexReplaceAll", &["-", "#", "-a-"]), "#a#");
        // An empty match is replaced where it is, and the scan still advances.
        assert_eq!(rendered("regexReplaceAll", &["x*", "-", "ab"]), "-a-b-");
    }

    #[test]
    fn must_regex_replace_all_requires_a_match() {
        // The fixture's `{{ mustRegexReplaceAll "a" "x" "banana" }}`.
        assert_eq!(
            rendered("mustRegexReplaceAll", &["a", "x", "banana"]),
            "bxnxnx"
        );
        assert_eq!(
            rendered("mustRegexReplaceAllLiteral", &["a", "x", "banana"]),
            "bxnxnx"
        );
        // A pattern that does not match is an error rather than the unchanged
        // subject, which is what Go panics over.
        for helper in ["mustRegexReplaceAll", "mustRegexReplaceAllLiteral"] {
            assert!(
                matches!(
                    call(helper, &[text("z"), text("x"), text("banana")]),
                    Err(Error::InvalidArgument { .. })
                ),
                "{helper} accepted a pattern that does not match"
            );
        }
    }

    #[test]
    fn regex_split_reads_its_count() {
        // The fixture's `{{ regexSplit "a" "banana" 0 }}`, `{{ regexSplit "a"
        // "banana" 2 }}`, `{{ regexSplit "-" "neo-sprig" -1 }}`, and its `must`
        // twin.
        assert_eq!(rendered("regexSplit", &["a", "banana", "0"]), "[]");
        assert_eq!(rendered("regexSplit", &["a", "banana", "2"]), "[b nana]");
        assert_eq!(
            rendered("regexSplit", &["-", "neo-sprig", "-1"]),
            "[neo sprig]"
        );
        assert_eq!(
            rendered("mustRegexSplit", &["a", "banana", "-1"]),
            "[b n n ]"
        );
        // A count of one leaves the whole subject in one piece.
        assert_eq!(rendered("regexSplit", &["a", "banana", "1"]), "[banana]");
        // Splitting on a pattern that does not match is the subject itself.
        assert_eq!(rendered("regexSplit", &["z", "banana", "-1"]), "[banana]");
        // An empty subject with a pattern that cannot match it is one empty
        // piece, which is Go's `Split` and .NET's.
        assert_eq!(rendered("regexSplit", &["a", "", "-1"]), "[]");
    }

    #[test]
    fn regex_split_returns_a_list_the_list_helpers_can_use() {
        // The fixture's `{{ mustSlice (regexSplit "/" "foo/bar/baz" -1) 1 2 }}` is
        // `[bar]`, which is the second of three pieces.
        let split = call(
            "regexSplit",
            &[text("/"), text("foo/bar/baz"), number(-1.0)],
        )
        .unwrap();
        assert_eq!(split.render(), "[foo bar baz]");
    }

    #[test]
    fn must_regex_split_requires_a_match() {
        assert!(matches!(
            call("mustRegexSplit", &[text("z"), text("banana"), number(-1.0)]),
            Err(Error::InvalidArgument { .. })
        ));
    }

    #[test]
    fn a_split_of_an_empty_pattern_does_not_produce_empty_pieces() {
        // Go's `Split` drops an empty match at the start of the subject, so an
        // empty pattern splits between the characters and adds nothing around
        // them.
        assert_eq!(rendered("regexSplit", &["", "ab", "-1"]), "[a b]");
        // An empty subject and an empty pattern is no pieces at all, which is
        // Go's `Split`, and different from an empty subject with a pattern that
        // cannot match it.
        assert_eq!(rendered("regexSplit", &["", "", "-1"]), "[]");
        assert_eq!(rendered("regexSplit", &["a", "", "-1"]), "[]");
    }

    #[test]
    fn a_failed_must_helper_is_an_error_rather_than_a_panic() {
        // Go's `mustRegexFind` panics when there is no match. Every `must*`
        // helper that produces a value reports it instead, and none of them may
        // unwind, which `catch_unwind` checks directly.
        let calls: Vec<(&str, Vec<Value>)> = vec![
            ("mustRegexFind", vec![text("z+"), text("abc")]),
            (
                "mustRegexFindAll",
                vec![text("z+"), text("abc"), number(-1.0)],
            ),
            (
                "mustRegexReplaceAll",
                vec![text("z+"), text("x"), text("abc")],
            ),
            (
                "mustRegexSplit",
                vec![text("z+"), text("abc"), number(-1.0)],
            ),
        ];
        for (helper, arguments) in calls {
            let result = std::panic::catch_unwind(|| call(helper, &arguments));
            let error = result
                .expect("the helper must not panic")
                .expect_err("a must* helper with no match must fail");
            match &error {
                Error::InvalidArgument { message, .. } => {
                    assert!(message.contains("does not match"), "{error}");
                }
                other => panic!("{helper} returned {other}"),
            }
        }
        // A pattern that will not compile is an error for every `must*` helper,
        // which is what Go's `MustCompile` panics over.
        // The three-argument helpers take the replacement or the count between
        // the pattern and the subject, so an uncompilable pattern is checked with
        // each helper's own shape.
        let calls: Vec<(&str, Vec<Value>)> = vec![
            ("mustRegexMatch", vec![text("("), text("abc")]),
            ("mustRegexFind", vec![text("("), text("abc")]),
            (
                "mustRegexFindAll",
                vec![text("("), text("abc"), number(-1.0)],
            ),
            (
                "mustRegexReplaceAll",
                vec![text("("), text("x"), text("abc")],
            ),
            (
                "mustRegexReplaceAllLiteral",
                vec![text("("), text("x"), text("abc")],
            ),
            ("mustRegexSplit", vec![text("("), text("abc"), number(-1.0)]),
        ];
        for (helper, arguments) in calls {
            let error = call(helper, &arguments).expect_err("an uncompilable pattern must fail");
            assert!(
                matches!(error, Error::InvalidArgument { .. }),
                "{helper} returned {error}"
            );
        }
    }

    #[test]
    fn regex_quote_meta_escapes_go_s_metacharacters() {
        // The fixture's `{{ regexQuoteMeta "1.2.3" }}` and `{{ regexQuoteMeta
        // "[value]" }}`.
        assert_eq!(rendered("regexQuoteMeta", &["1.2.3"]), r"1\.2\.3");
        assert_eq!(rendered("regexQuoteMeta", &["[value]"]), r"\[value\]");
        // The escaped set is the one Go escapes, which is not every punctuation
        // character: a dash and an underscore are left alone.
        let every = META.iter().collect::<String>();
        assert_eq!(
            rendered("regexQuoteMeta", &[&every]),
            r"\\\.\+\*\?\(\)\|\[\]\{\}\^\$"
        );
        assert_eq!(rendered("regexQuoteMeta", &["a-b_c"]), "a-b_c");
        assert_eq!(rendered("regexQuoteMeta", &[""]), "");
    }

    #[test]
    fn a_quoted_pattern_matches_the_value_it_escaped() {
        // `regexQuoteMeta` exists so that a literal can be used as a pattern, and
        // the round trip is what has to hold.
        assert_eq!(rendered("regexMatch", &["1.2.3", "a1.2.3b"]), "true");
        let quoted = rendered("regexQuoteMeta", &["1.2.3"]);
        assert_eq!(rendered("regexMatch", &[&quoted, "a1.2.3b"]), "true");
        assert_eq!(rendered("regexMatch", &[&quoted, "a1x2x3b"]), "false");
    }

    #[test]
    fn a_wrong_argument_count_is_reported() {
        let cases = [
            ("regexMatch", vec![text("a")]),
            ("regexMatch", vec![text("a"), text("b"), text("c")]),
            ("regexFind", vec![]),
            ("regexFindAll", vec![text("a"), text("b")]),
            ("regexReplaceAll", vec![text("a"), text("b")]),
            ("regexSplit", vec![text("a"), text("b")]),
            ("regexQuoteMeta", vec![]),
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
    fn a_count_that_is_not_a_number_is_refused() {
        // The reference's `N` reads an argument it cannot parse as zero; this
        // crate reports it, because a silent zero answers a different question
        // than the author asked.
        for helper in ["regexFindAll", "regexSplit"] {
            let error =
                crate::call(helper, &[text("a"), text("banana"), text("many")]).unwrap_err();
            assert!(matches!(error, Error::InvalidArgument { .. }), "{error}");
        }
    }

    #[test]
    fn a_count_is_read_the_way_the_reference_reads_it() {
        // `N` truncates a number toward zero and reads a boolean as one or zero.
        assert_eq!(match_count("regexSplit", &number(-1.9)).unwrap(), -1);
        assert_eq!(match_count("regexSplit", &number(2.9)).unwrap(), 2);
        assert_eq!(match_count("regexSplit", &Value::Bool(true)).unwrap(), 1);
        assert_eq!(match_count("regexSplit", &text("-1")).unwrap(), -1);
    }

    #[test]
    fn an_argument_that_is_not_text_is_refused() {
        let cases = [
            ("regexMatch", vec![Value::List(vec![text("a")]), text("a")]),
            ("regexMatch", vec![text("a"), Value::Map(BTreeMap::new())]),
            ("regexQuoteMeta", vec![Value::List(Vec::new())]),
        ];
        for (helper, arguments) in cases {
            let error = crate::call(helper, &arguments).unwrap_err();
            assert!(matches!(error, Error::InvalidArgument { .. }), "{error}");
        }
    }

    #[test]
    fn the_engine_matches_the_re2_syntax_a_template_can_express() {
        // The engine is reached through the helpers, so these are the observable
        // behaviors of the syntax it supports.
        let cases = [
            // Counted quantifiers, greedy and lazy.
            ("a{3}", "aaaa", "aaa"),
            ("a{2,3}", "aaaa", "aaa"),
            ("a{2,}", "aaaa", "aaaa"),
            ("a{0}b", "ab", "b"),
            // A lazy repeat takes the fewest characters that still lets the rest
            // of the pattern match, so it needs a `b` it can reach.
            ("a+?b", "aaab", "aaab"),
            ("a+?b", "aaacb", ""),
            // Alternation, and a group that captures a branch.
            ("cat|dog", "hotdog", "dog"),
            ("(cat|dog)s", "hotdogs", "dogs"),
            // A negated class, a range, and a class that ends in a dash.
            ("[^a-z]+", "abc123", "123"),
            ("[a-c]+", "xbcay", "bca"),
            ("[a-]+", "x-y", "-"),
            // The Perl shorthands, inside and outside a class.
            ("\\d+", "ab12", "12"),
            ("\\w+", "  ab_1", "ab_1"),
            ("\\s+", "ab  cd", "  "),
            ("\\D+", "12ab34", "ab"),
            ("[\\d-]+", "a1-b", "1-"),
            // Anchors, and what the multiline flag does to them.
            ("^ab$", "ab", "ab"),
            ("^b", "ab", ""),
            ("(?m)^b", "a\nb", "b"),
            ("(?m)b$", "a\nb\nc", "b"),
            // The case-insensitive and dot-matches-newline flags. A match is the
            // subject's own text, not the pattern's, so a folded pattern still
            // returns the spelling that was there.
            ("(?i)NEO", "neosprig", "neo"),
            ("(?i)[a-z]+", "NEO", "NEO"),
            ("(?i:A)a", "Aa", "Aa"),
            ("(?i-s)A.B", "A.B", "A.B"),
            ("a.b", "a\nb", ""),
            ("(?s)a.b", "a\nb", "a\nb"),
            // A word boundary, and a named group.
            ("\\bword\\b", "a word here", "word"),
            ("\\Bord", "word", "ord"),
            ("(?P<key>[a-z]+)=(\\d+)", "a=1 b=2", "a=1"),
            // An escaped metacharacter, and an escaped brace. A bare `{` that does
            // not open a valid bound is a literal brace, so `a{2}` means `aa` and
            // the text `a{2}` needs the brace escaped.
            ("a\\.b", "xa.by", "a.b"),
            ("a\\{2\\}", "xa{2}y", "a{2}"),
            ("\\x41", "xAy", "A"),
            ("\\t", "a\tb", "\t"),
            // The ungreedy flag flips the default.
            ("(?U)a+", "aaab", "a"),
        ];
        for (pattern, subject, expected) in cases {
            assert_eq!(
                rendered("regexFind", &[pattern, subject]),
                expected,
                "pattern {pattern:?} on {subject:?}"
            );
        }
    }

    #[test]
    fn the_engine_refuses_syntax_re2_does_not_have() {
        // Backreferences, lookaround, and possessive quantifiers are not RE2, so
        // a pattern that uses one is an error rather than a different answer.
        for pattern in [
            "(a)\\1", "(?=a)", "(?!a)", "(?<=a)b", "a*+", "a**", "*a", "[a", "(a", "a)", "\\q",
            "(?z)a", "a{3,2}", "(?P<a>x",
        ] {
            let error = call("regexFind", &[text(pattern), text("aa")]).unwrap_err();
            assert!(
                matches!(error, Error::InvalidArgument { .. }),
                "pattern {pattern:?} returned {error}"
            );
        }
    }

    #[test]
    fn a_replacement_can_name_a_group_by_name() {
        // `$key` is the named group, `$2` is the second group, and a name that
        // does not exist expands to nothing.
        assert_eq!(
            rendered(
                "regexReplaceAll",
                &["(?P<key>[a-z]+)=(\\d+)", "$key:$2", "a=1 b=2"]
            ),
            "a:1 b:2"
        );
        assert_eq!(
            rendered("regexReplaceAll", &["(?P<key>a)", "$nope", "a"]),
            ""
        );
        // A leading zero is a name, not a group number, as in Go.
        assert_eq!(rendered("regexReplaceAll", &["(a)", "$01", "a"]), "");
    }

    #[test]
    fn the_matcher_bounds_what_it_will_do() {
        // A pattern whose alternatives multiply is reported rather than run to
        // completion, which is what keeps a hostile pattern from hanging a
        // render. `(a|aa)*b` is one: each branch of the body matches a different
        // length, so the ways to divide a run of `a`s multiply.
        let program = engine::compile("(a|aa)*(a|aa)*b").unwrap();
        let subject = "a".repeat(40);
        let mut matcher = engine::Matcher::new(&program, &subject);
        let error = matcher
            .find_at(0)
            .expect_err("a pattern whose alternatives multiply must be reported");
        assert!(
            error.contains("steps") || error.contains("alternatives"),
            "{error}"
        );

        // A subject a linear pattern can handle is not a problem: a greedy star
        // holds one alternative per character, so the budget is generous enough
        // for a real file.
        let program = engine::compile("a*").unwrap();
        let subject = "a".repeat(50_000);
        let mut matcher = engine::Matcher::new(&program, &subject);
        let found = matcher.find_at(0).unwrap().unwrap();
        assert_eq!(found.start, 0);
        assert_eq!(found.end, 50_000);
    }

    #[test]
    fn a_repeat_over_a_body_that_can_match_nothing_still_terminates() {
        // The shapes that need the loop bookkeeping to be right: a quantifier
        // over a body that can match the empty string, and a quantifier over an
        // alternation whose first branch is empty. Both are answered rather than
        // reported, because the alternatives the body leaves behind still have to
        // be explored.
        for (pattern, subject, expected) in [
            ("(a*)*b", "b", "b"),
            ("(a*)*b", "aab", "aab"),
            ("(a*)+b", "aab", "aab"),
            ("(a?)*b", "ab", "ab"),
            ("(a?)*b", "b", "b"),
            ("(a|)*b", "ab", "ab"),
            ("(|a)*b", "ab", "ab"),
            ("(a*)*", "aa", "aa"),
        ] {
            assert_eq!(
                rendered("regexFind", &[pattern, subject]),
                expected,
                "pattern {pattern:?} on {subject:?}"
            );
        }
    }

    #[test]
    fn an_empty_match_is_not_reported_twice() {
        // Go's `FindAll` does not report an empty match that begins exactly where
        // the previous match ended, which is what keeps `a*` from matching at
        // every offset of a run of characters. The empty match at the very end of
        // the subject is a different position, so it *is* reported.
        assert_eq!(rendered("regexFindAll", &["a*", "aab", "-1"]), "[aa ]");
        assert_eq!(rendered("regexFindAll", &["a*", "aaab", "-1"]), "[aaa ]");
    }

    #[test]
    fn an_empty_pattern_matches_at_every_position() {
        // An empty pattern matches the empty string everywhere, and Go reports one
        // match per boundary including both ends.
        assert_eq!(rendered("regexFindAll", &["", "ab", "-1"]), "[  ]");
        assert_eq!(rendered("regexFind", &["", "ab"]), "");
    }
}
