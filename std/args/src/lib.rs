//! Literal argv parsing without shell evaluation.
#![doc = include_str!("../README.md")]

use std::{ffi::OsString, fmt, iter::FromIterator};

/// A portable, literal argument vector.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Args(Vec<String>);

/// An error produced while parsing literal argv input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// A quote was opened and never closed.
    UnterminatedQuote,
    /// The input ended with a backslash that had nothing to escape.
    TrailingEscape,
}

impl fmt::Display for Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnterminatedQuote => output.write_str("literal argv has an unterminated quote"),
            Self::TrailingEscape => output.write_str("literal argv has a trailing escape"),
        }
    }
}

impl std::error::Error for Error {}

impl Args {
    /// Parses literal argv input with quotes, escapes, and line continuations.
    ///
    /// This parser never expands environment variables or evaluates command substitutions.
    ///
    /// # Errors
    ///
    /// Returns an error for an unterminated quote or trailing escape.
    pub fn parse(input: &str) -> Result<Self, Error> {
        let mut arguments = Vec::new();
        let mut current = String::new();
        let mut quote = None;
        let mut escaped = false;
        let mut started = false;
        let mut characters = input.chars().peekable();

        while let Some(character) = characters.next() {
            if escaped {
                if character == '\n' {
                    escaped = false;
                    continue;
                }
                if character == '\r' && characters.next_if_eq(&'\n').is_some() {
                    escaped = false;
                    continue;
                }
                current.push(character);
                started = true;
                escaped = false;
                continue;
            }
            if character == '\\' && quote != Some('\'') {
                escaped = true;
                started = true;
                continue;
            }
            if matches!(character, '\'' | '"') {
                if quote == Some(character) {
                    quote = None;
                } else if quote.is_none() {
                    quote = Some(character);
                } else {
                    current.push(character);
                }
                started = true;
                continue;
            }
            if quote.is_some() {
                current.push(character);
                started = true;
                continue;
            }
            if character.is_whitespace() {
                push_argument(&mut arguments, &mut current, &mut started);
                continue;
            }
            current.push(character);
            started = true;
        }
        if escaped {
            return Err(Error::TrailingEscape);
        }
        if quote.is_some() {
            return Err(Error::UnterminatedQuote);
        }
        push_argument(&mut arguments, &mut current, &mut started);
        Ok(Self(arguments))
    }

    /// Returns the arguments as strings.
    #[must_use]
    pub fn as_slice(&self) -> &[String] {
        &self.0
    }

    /// Returns an argument by index without panicking.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<&str> {
        self.0.get(index).map(String::as_str)
    }

    /// Returns whether no arguments are present.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of arguments.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns a copy with an argument appended.
    #[must_use]
    pub fn appended(mut self, argument: impl Into<String>) -> Self {
        self.0.push(argument.into());
        self
    }

    /// Returns a copy with an argument prepended.
    #[must_use]
    pub fn prepended(mut self, argument: impl Into<String>) -> Self {
        self.0.insert(0, argument.into());
        self
    }

    /// Returns a copy without the argument at `index`, or `None` when absent.
    #[must_use]
    pub fn without(mut self, index: usize) -> Option<Self> {
        (index < self.0.len()).then(|| {
            self.0.remove(index);
            self
        })
    }

    /// Appends an argument in place.
    pub fn push(&mut self, argument: impl Into<String>) {
        self.0.push(argument.into());
    }

    /// Inserts an argument in place, returning `false` when `index` is absent.
    pub fn insert(&mut self, index: usize, argument: impl Into<String>) -> bool {
        if index > self.0.len() {
            return false;
        }
        self.0.insert(index, argument.into());
        true
    }

    /// Removes and returns an argument by index without panicking.
    pub fn remove(&mut self, index: usize) -> Option<String> {
        (index < self.0.len()).then(|| self.0.remove(index))
    }

    /// Consumes this value as string arguments.
    #[must_use]
    pub fn into_vec(self) -> Vec<String> {
        self.0
    }

    /// Converts the portable arguments for direct OS process invocation.
    #[must_use]
    pub fn into_os_strings(self) -> Vec<OsString> {
        self.0.into_iter().map(OsString::from).collect()
    }
}

fn push_argument(arguments: &mut Vec<String>, current: &mut String, started: &mut bool) {
    if *started {
        arguments.push(std::mem::take(current));
        *started = false;
    }
}

impl AsRef<[String]> for Args {
    fn as_ref(&self) -> &[String] {
        self.as_slice()
    }
}

impl From<Vec<String>> for Args {
    fn from(arguments: Vec<String>) -> Self {
        Self(arguments)
    }
}

impl FromIterator<String> for Args {
    fn from_iter<T: IntoIterator<Item = String>>(iter: T) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl IntoIterator for Args {
    type IntoIter = std::vec::IntoIter<String>;
    type Item = String;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::{Args, Error};

    #[test]
    fn preserves_empty_arguments() {
        assert_eq!(Args::parse("'' \"\" ").unwrap().as_slice(), ["", ""]);
    }

    #[test]
    fn parses_quotes_and_escapes_without_expansion() {
        let args = Args::parse("run 'two words' \"three words\" four\\ five '$HOME'").unwrap();
        assert_eq!(
            args.as_slice(),
            ["run", "two words", "three words", "four five", "$HOME"]
        );
    }

    #[test]
    fn supports_line_continuations() {
        assert_eq!(
            Args::parse("run one\\\ntwo").unwrap().as_slice(),
            ["run", "onetwo"]
        );
        assert_eq!(
            Args::parse("run one\\\r\ntwo").unwrap().as_slice(),
            ["run", "onetwo"]
        );
    }

    #[test]
    fn conformance_keeps_shell_syntax_literal() {
        assert_eq!(
            Args::parse("tool '$HOME' \"$(whoami)\" 'a && b' \"\" ")
                .unwrap()
                .as_slice(),
            ["tool", "$HOME", "$(whoami)", "a && b", ""]
        );
    }

    #[test]
    fn rejects_malformed_input() {
        assert_eq!(Args::parse("'unterminated"), Err(Error::UnterminatedQuote));
        assert_eq!(Args::parse("trailing\\"), Err(Error::TrailingEscape));
    }

    #[test]
    fn provides_checked_argument_operations() {
        let args = Args::from(vec!["run".into()])
            .appended("--quiet")
            .prepended("env");
        assert_eq!(args.get(3), None);
        assert_eq!(args.without(1).unwrap().as_slice(), ["env", "--quiet"]);
    }
}
