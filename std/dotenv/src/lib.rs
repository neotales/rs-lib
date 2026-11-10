//! Source-preserving, policy-free parsing for dotenv documents.
#![doc = include_str!("../README.md")]

/// A one-based source location within a dotenv document.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Span {
    /// First source line covered by the node.
    pub line: u32,
    /// First source column covered by the node.
    pub column: u32,
    /// Last source line covered by the node.
    pub end_line: u32,
    /// Last source column covered by the node.
    pub end_column: u32,
}

/// The quoting syntax used by an assignment value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuoteStyle {
    /// An unquoted value.
    Unquoted,
    /// A single-quoted value.
    Single,
    /// A double-quoted value.
    Double,
    /// A backtick-delimited raw value.
    Raw,
}

/// One parsed dotenv document node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Node {
    /// A blank source line.
    Blank {
        /// Where the line is in the source document.
        span: Span,
    },
    /// A comment-only source line.
    Comment {
        /// The comment text, including its leading `#`.
        text: String,
        /// Where the line is in the source document.
        span: Span,
    },
    /// An environment assignment.
    Assignment(Assignment),
    /// Source that could not be interpreted as an assignment.
    Invalid {
        /// The source text that could not be parsed, which may span several lines.
        text: String,
        /// A description of what was expected instead.
        message: String,
        /// Where the offending source begins and ends.
        span: Span,
    },
}

/// A parsed environment assignment.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Assignment {
    /// Whether the source used the optional `export` prefix.
    pub exported: bool,
    /// The unvalidated assignment name.
    pub key: String,
    /// The decoded value with only its outer quotes removed.
    pub value: String,
    /// The source quote syntax.
    pub quote: QuoteStyle,
    /// Assignment source span.
    pub span: Span,
}

/// A parsed dotenv document that retains its original text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Document {
    source: String,
    nodes: Vec<Node>,
}

impl Document {
    /// Returns the exact document text, including its original line endings.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Returns nodes in source order.
    #[must_use]
    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    /// Returns assignments in source order, excluding invalid nodes.
    pub fn assignments(&self) -> impl Iterator<Item = &Assignment> {
        self.nodes.iter().filter_map(|node| match node {
            Node::Assignment(assignment) => Some(assignment),
            Node::Blank { .. } | Node::Comment { .. } | Node::Invalid { .. } => None,
        })
    }

    /// Returns the first recoverable parse error, if any.
    #[must_use]
    pub fn first_invalid(&self) -> Option<(&str, &Span)> {
        self.nodes.iter().find_map(|node| match node {
            Node::Invalid { message, span, .. } => Some((message.as_str(), span)),
            Node::Blank { .. } | Node::Comment { .. } | Node::Assignment(_) => None,
        })
    }
}

/// Parses a dotenv document without interpolation, key validation, or I/O.
#[must_use]
pub fn parse(input: &str) -> Document {
    let mut nodes = Vec::new();
    let lines: Vec<&str> = input.split_inclusive('\n').collect();
    let mut index = 0;

    while index < lines.len() {
        let line_number = u32::try_from(index + 1).unwrap_or(u32::MAX);
        let raw = lines[index].strip_suffix('\n').unwrap_or(lines[index]);
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        let trimmed = raw.trim();
        let span = line_span(line_number, raw);
        if trimmed.is_empty() {
            nodes.push(Node::Blank { span });
            index += 1;
            continue;
        }
        if trimmed.starts_with('#') {
            nodes.push(Node::Comment {
                text: raw.to_owned(),
                span,
            });
            index += 1;
            continue;
        }

        let (exported, assignment) = match trimmed.strip_prefix("export ") {
            Some(value) => (true, value.trim_start()),
            None => (false, trimmed),
        };
        let Some((key, value)) = assignment.split_once('=') else {
            nodes.push(Node::Invalid {
                text: raw.to_owned(),
                message: "expected KEY=VALUE assignment in dotenv file".to_owned(),
                span,
            });
            index += 1;
            continue;
        };

        let key = key.trim();
        let value = value.trim();
        let (quote, delimiter) = match value.chars().next() {
            Some('\'') => (QuoteStyle::Single, '\''),
            Some('"') => (QuoteStyle::Double, '"'),
            Some('`') => (QuoteStyle::Raw, '`'),
            _ => (QuoteStyle::Unquoted, '\0'),
        };
        if delimiter == '\0' {
            nodes.push(Node::Assignment(Assignment {
                exported,
                key: key.to_owned(),
                value: value.to_owned(),
                quote,
                span,
            }));
            index += 1;
            continue;
        }

        let mut decoded = value[delimiter.len_utf8()..].to_owned();
        let mut end_index = index;
        while !decoded.ends_with(delimiter) && end_index + 1 < lines.len() {
            end_index += 1;
            let next = lines[end_index]
                .strip_suffix('\n')
                .unwrap_or(lines[end_index]);
            decoded.push('\n');
            decoded.push_str(next.strip_suffix('\r').unwrap_or(next));
        }
        if !decoded.ends_with(delimiter) {
            nodes.push(Node::Invalid {
                text: input_line_range(&lines, index, end_index),
                message: "unterminated quoted dotenv value".to_owned(),
                span: multi_line_span(line_number, end_index, &lines),
            });
            index = end_index + 1;
            continue;
        }
        decoded.pop();
        nodes.push(Node::Assignment(Assignment {
            exported,
            key: key.to_owned(),
            value: decoded,
            quote,
            span: multi_line_span(line_number, end_index, &lines),
        }));
        index = end_index + 1;
    }

    Document {
        source: input.to_owned(),
        nodes,
    }
}

fn line_span(line: u32, source: &str) -> Span {
    let width = u32::try_from(source.chars().count() + 1).unwrap_or(u32::MAX);
    Span {
        line,
        column: 1,
        end_line: line,
        end_column: width,
    }
}

fn multi_line_span(start: u32, end_index: usize, lines: &[&str]) -> Span {
    let end_line = u32::try_from(end_index + 1).unwrap_or(u32::MAX);
    let raw = lines[end_index]
        .strip_suffix('\n')
        .unwrap_or(lines[end_index]);
    let raw = raw.strip_suffix('\r').unwrap_or(raw);
    Span {
        line: start,
        column: 1,
        end_line,
        end_column: u32::try_from(raw.chars().count() + 1).unwrap_or(u32::MAX),
    }
}

fn input_line_range(lines: &[&str], start: usize, end: usize) -> String {
    lines[start..=end].concat()
}

#[cfg(test)]
mod tests {
    use super::{Node, QuoteStyle, parse};

    #[test]
    fn preserves_document_structure_and_crlf_source() {
        let input = "# note\r\n\r\nexport NAME='Neo Env'\r\nCOUNT=2\r\n";
        let document = parse(input);
        assert_eq!(document.source(), input);
        assert!(matches!(document.nodes()[0], Node::Comment { .. }));
        assert!(matches!(document.nodes()[1], Node::Blank { .. }));
        let assignments: Vec<_> = document.assignments().collect();
        assert_eq!(assignments[0].value, "Neo Env");
        assert_eq!(assignments[0].quote, QuoteStyle::Single);
        assert_eq!(assignments[1].value, "2");
    }

    #[test]
    fn supports_multiline_and_raw_quoted_values() {
        let document = parse("DOUBLE=\"one\ntwo\"\nRAW=`three`\n");
        let assignments: Vec<_> = document.assignments().collect();
        assert_eq!(assignments[0].value, "one\ntwo");
        assert_eq!(assignments[0].span.end_line, 2);
        assert_eq!(assignments[1].quote, QuoteStyle::Raw);
    }

    #[test]
    fn conformance_preserves_all_value_syntax_without_interpolation() {
        let input = "# retained\r\nSINGLE='a $NAME'\r\nDOUBLE=\"b ${NAME}\"\r\nRAW=`c $NAME`\r\nPLAIN=$NAME # literal\r\nMULTI=\"first\r\nsecond\"\r\n";
        let document = parse(input);
        let assignments: Vec<_> = document.assignments().collect();
        assert_eq!(document.source(), input);
        assert_eq!(assignments.len(), 5);
        assert_eq!(assignments[0].value, "a $NAME");
        assert_eq!(assignments[1].value, "b ${NAME}");
        assert_eq!(assignments[2].value, "c $NAME");
        assert_eq!(assignments[3].value, "$NAME # literal");
        assert_eq!(assignments[4].value, "first\nsecond");
        assert_eq!(assignments[4].span.end_line, 7);
    }

    #[test]
    fn retains_invalid_lines_for_callers_to_report() {
        let document = parse("NAME=value\nbroken\n");
        assert_eq!(
            document.first_invalid().map(|(message, _)| message),
            Some("expected KEY=VALUE assignment in dotenv file")
        );
    }
}
