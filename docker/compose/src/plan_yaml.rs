//! An ordered YAML emitter that reproduces the Docker CLI's rendering style.
//!
//! `compose config` exists to be read and diffed, so the rendered document has to
//! look like the one a reader is comparing against. Three properties of Docker's
//! output are reproduced here, each measured against `docker compose config` and
//! `docker stack config` on Docker 29.8:
//!
//! * **Order is the caller's.** Compose prints a service's keys in the order of
//!   compose-go's `ServiceConfig` struct — alphabetical except that `hostname`
//!   precedes `healthcheck` — with `profiles` ahead of all of them. A YAML
//!   library that sorts map keys cannot express that, which is why this emitter
//!   takes an [`OrderedMap`] rather than a `serde_json::Map`: that type is a
//!   `BTreeMap` in this workspace, because enabling `serde_json`'s `preserve_order`
//!   feature was tried and reverted. It reorders the JSON of every crate in the
//!   workspace, including the diagnostic envelopes whose key order other crates
//!   assert. That is why the choice is a property of the shared dependency rather
//!   than something one crate opts into.
//! * **A sequence is indented under its key.** Docker prints `volumes:` and then
//!   `  - type: bind`; `serde_yaml` prints the dash in the key's own column.
//! * **A scalar is quoted only when a plain one would be read as something
//!   else.** Docker writes `alpine:3.20` and `unless-stopped` bare, `"1"`,
//!   `"true"`, `"9000"` and `"8080"` in double quotes, and `'yes'`, `'a: b'`,
//!   `'{x}'` in single quotes. `serde_yaml` uses `'` for all three cases.
//!
//! The quoting rules are reproduced as measured rather than as derived from a
//! specification, because Docker's choice is not a single rule. A string that
//! YAML 1.2 reads as a number, a `true`/`false`, a `null`, or a timestamp gets
//! double quotes, while a string that only YAML 1.1 reads as a boolean (`yes`,
//! `on`, `N`, `Off`) or as a sexagesimal integer (`1:2:3`) gets single quotes.
//! Every expectation in this module's tests was captured from the CLI.

/// One indentation level, in spaces.
///
/// Docker indents by two and indents a sequence under its key, so a sequence
/// item's own mapping starts four columns in from the key.
const INDENT: usize = 2;

/// The column past which a plain or single-quoted scalar is folded onto the next
/// line.
///
/// This is `go-yaml`'s `best_width`, and it is a property of this emitter rather
/// than a caller choice: a rendered document that wraps at a different column
/// still differs from the reference byte for byte.
const BEST_WIDTH: usize = 80;

/// A mapping whose keys keep the order the caller inserted them in.
///
/// This is the whole reason the crate owns an emitter. `serde_json::Map` is a
/// `BTreeMap` here, so any value that passes through it is alphabetized before
/// it is ever seen, and Compose's key order is not alphabetical.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct OrderedMap {
    entries: Vec<(String, OrderedValue)>,
}

impl OrderedMap {
    /// Creates an empty mapping.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Drops every entry whose key does not satisfy a predicate, in place.
    pub fn retain(&mut self, mut keep: impl FnMut(&str) -> bool) {
        self.entries.retain(|(key, _)| keep(key));
    }

    /// Inserts a key, replacing any earlier value for it in place.
    ///
    /// Replacing in place rather than appending matters: a key that is filled in
    /// by a default must not move to the end of the mapping, because the order
    /// is the output.
    pub fn insert(&mut self, key: impl Into<String>, value: OrderedValue) {
        let key = key.into();
        match self.entries.iter_mut().find(|(name, _)| *name == key) {
            Some(entry) => entry.1 = value,
            None => self.entries.push((key, value)),
        }
    }

    /// Returns the value stored under a key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&OrderedValue> {
        self.entries
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value)
    }

    /// Returns whether the mapping has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Iterates over the entries in insertion order.
    /// Removes a member, returning it.
    ///
    /// Needed by a transform that adapts one document shape into another: the v3
    /// form is the Compose-spec document with a handful of members taken away,
    /// and taking a member out is the operation.
    pub fn remove(&mut self, key: &str) -> Option<OrderedValue> {
        self.entries
            .iter()
            .position(|(name, _)| name == key)
            .map(|at| self.entries.remove(at).1)
    }

    /// Replaces a member's value, keeping its position.
    ///
    /// A remove-then-insert moves the member to the end, which is why a transform
    /// that only changes one member's *shape* has to use this: `depends_on` is
    /// reshaped from a mapping into a list and must stay where Compose put it.
    pub fn replace(&mut self, key: &str, value: OrderedValue) -> bool {
        match self.entries.iter().position(|(name, _)| name == key) {
            Some(at) => {
                self.entries[at].1 = value;
                true
            }
            None => false,
        }
    }

    /// Whether a member with this name is present.
    #[must_use]
    pub fn contains(&self, key: &str) -> bool {
        self.entries.iter().any(|(name, _)| name == key)
    }

    /// Iterates the members in document order.
    ///
    /// Order is the whole point of this type, so this yields the order Compose
    /// wrote rather than any sorted or hash order. Use [`Self::get`] to look a
    /// member up by name.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &OrderedValue)> {
        self.entries
            .iter()
            .map(|(key, value)| (key.as_str(), value))
    }
}

impl FromIterator<(String, OrderedValue)> for OrderedMap {
    fn from_iter<I: IntoIterator<Item = (String, OrderedValue)>>(iter: I) -> Self {
        let mut map = Self::new();
        for (key, value) in iter {
            map.insert(key, value);
        }
        map
    }
}

/// A JSON-shaped value that can carry an explicit mapping order.
#[derive(Clone, Debug, PartialEq)]
pub enum OrderedValue {
    /// An explicit null, rendered `null`.
    Null,
    /// A boolean, rendered bare.
    Bool(bool),
    /// A number, rendered bare.
    Number(serde_json::Number),
    /// A string, rendered with Docker's quoting rules.
    String(String),
    /// A sequence, rendered with its items indented under the owning key.
    Sequence(Vec<OrderedValue>),
    /// A mapping, rendered in insertion order.
    Mapping(OrderedMap),
}

impl OrderedValue {
    /// Creates a string value.
    #[must_use]
    pub fn string(value: impl Into<String>) -> Self {
        Self::String(value.into())
    }

    /// Creates a mapping value.
    #[must_use]
    pub fn mapping(map: OrderedMap) -> Self {
        Self::Mapping(map)
    }

    /// Creates a sequence value.
    #[must_use]
    pub fn sequence(values: Vec<OrderedValue>) -> Self {
        Self::Sequence(values)
    }

    /// Returns whether the value is an empty array or object, or null.
    ///
    /// This is "carries nothing", and a rendered document has to be able to tell
    /// it apart from a key that is present and empty. Measured against
    /// `docker compose config`: Docker omits `labels: {}` and `extra_hosts: []`
    /// from a service entirely, and prints `bind: {}` only where the mount kind
    /// calls for it.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Null => true,
            Self::Sequence(values) => values.is_empty(),
            Self::Mapping(map) => map.is_empty(),
            _ => false,
        }
    }

    /// Converts to a `serde_json::Value`.
    ///
    /// The conversion goes through `serde_json::Map`, which is a `BTreeMap` in
    /// this workspace, so the JSON form is alphabetized and the YAML form is
    /// not. The asymmetry is deliberate: the JSON form is machine-read and
    /// stable, and the YAML form is the one a person diffs against Docker.
    #[must_use]
    pub fn to_json_value(&self) -> serde_json::Value {
        match self {
            Self::Null => serde_json::Value::Null,
            Self::Bool(value) => serde_json::Value::Bool(*value),
            Self::Number(number) => serde_json::Value::Number(number.clone()),
            Self::String(value) => serde_json::Value::String(value.clone()),
            Self::Sequence(values) => {
                serde_json::Value::Array(values.iter().map(Self::to_json_value).collect())
            }
            Self::Mapping(map) => serde_json::Value::Object(
                map.iter()
                    .map(|(key, value)| (key.to_owned(), value.to_json_value()))
                    .collect(),
            ),
        }
    }
}

impl From<serde_json::Value> for OrderedValue {
    /// Adopts an unordered value, keeping the key order the source had.
    ///
    /// A `serde_json::Map` arrives alphabetized, which is what a Compose
    /// document wants for the blocks Compose itself models as a Go map —
    /// `environment`, `labels`, `deploy.resources.limits`, `sysctls` — because
    /// `go-yaml` sorts Go map keys when it marshals them. It is the wrong order
    /// for a block Compose models as a struct, and those are built with
    /// [`OrderedMap`] directly.
    fn from(value: serde_json::Value) -> Self {
        match value {
            serde_json::Value::Null => Self::Null,
            serde_json::Value::Bool(value) => Self::Bool(value),
            serde_json::Value::Number(number) => Self::Number(number),
            serde_json::Value::String(value) => Self::String(value),
            serde_json::Value::Array(values) => {
                Self::Sequence(values.into_iter().map(Self::from).collect())
            }
            serde_json::Value::Object(map) => Self::Mapping(
                map.into_iter()
                    .map(|(key, value)| (key, Self::from(value)))
                    .collect(),
            ),
        }
    }
}

/// How one scalar is written.
///
/// The emitter chooses this for every string it is handed and the caller never
/// names it, which is why it is `pub(crate)` while [`to_yaml`] is published.
/// `tests/plan_yaml_surface.rs` is the check that the four variants are all
/// still reachable through the published emitter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Style {
    /// Bare, as `alpine:3.20` or `unless-stopped`.
    Plain,
    /// Single-quoted, as `'yes'` or `'a: b'`.
    Single,
    /// Double-quoted, as `"1"` or `"true"`.
    Double,
    /// A literal block, as `|` or `|-`.
    Literal,
}

/// Renders a value as YAML in Docker's style.
///
/// The output ends with a newline. A document that is not a non-empty mapping or
/// sequence is written as a bare scalar, or as `{}` when it is an empty one.
#[must_use]
pub fn to_yaml(value: &OrderedValue) -> String {
    let mut out = String::new();
    let mut column = 0usize;
    match value {
        OrderedValue::Mapping(map) if !map.is_empty() => write_map(&mut out, &mut column, map, 0),
        OrderedValue::Sequence(values) if !values.is_empty() => {
            write_sequence(&mut out, &mut column, values, 0);
        }
        other => {
            push_indent(&mut out, &mut column, 0);
            write_value(&mut out, &mut column, other, 0);
        }
    }
    out
}

fn write_map(out: &mut String, column: &mut usize, map: &OrderedMap, indent: usize) {
    for (key, value) in map.iter() {
        push_indent(out, column, indent);
        write_key(out, column, key);
        out.push(':');
        *column += 1;
        write_value(out, column, value, indent);
    }
}

/// Writes a key, which is a simple-key context and is therefore never folded.
fn write_key(out: &mut String, column: &mut usize, key: &str) {
    let scalar = Scalar {
        style: classify(key),
        value: key.to_owned(),
    };
    match scalar.style {
        // A key is written before any wrapping decision can apply, so the
        // reference's fold never reaches one.
        Style::Plain | Style::Literal => out.push_str(key),
        Style::Single => write_single_quoted(out, column, key, usize::MAX),
        Style::Double => write_double_quoted(out, column, key),
    }
    *column += key.chars().count();
}

/// Writes the value that follows a `key:` or `- ` marker, ending its line.
fn write_value(out: &mut String, column: &mut usize, value: &OrderedValue, indent: usize) {
    match value {
        OrderedValue::Mapping(map) if map.is_empty() => {
            out.push_str(" {}");
            *column += 3;
            out.push('\n');
        }
        OrderedValue::Sequence(values) if values.is_empty() => {
            out.push_str(" []");
            *column += 3;
            out.push('\n');
        }
        OrderedValue::Mapping(map) => {
            out.push('\n');
            write_map(out, column, map, indent + INDENT);
        }
        OrderedValue::Sequence(values) => {
            // The dash is indented under its key. This is the difference from
            // `serde_yaml`, which puts the dash in the key's own column.
            out.push('\n');
            write_sequence(out, column, values, indent + INDENT);
        }
        other => {
            out.push(' ');
            *column += 1;
            // A folded scalar continues at the value's own indentation, which is
            // one level in from the key that owns it.
            write_scalar(out, column, &scalar_of(other), indent + INDENT);
            out.push('\n');
        }
    }
}

fn write_sequence(out: &mut String, column: &mut usize, values: &[OrderedValue], indent: usize) {
    for value in values {
        push_indent(out, column, indent);
        out.push_str("- ");
        *column += 2;
        match value {
            OrderedValue::Mapping(map) if map.is_empty() => {
                out.push_str("{}");
                *column += 2;
                out.push('\n');
            }
            OrderedValue::Mapping(map) => {
                // The item's first key shares the dash's line and the rest line
                // up under it, which is what puts `source:` in the same column as
                // `type:` in a rendered long-form mount.
                let mut first = true;
                for (key, item) in map.iter() {
                    if !first {
                        push_indent(out, column, indent + INDENT);
                    }
                    first = false;
                    write_key(out, column, key);
                    out.push(':');
                    *column += 1;
                    write_value(out, column, item, indent + INDENT);
                }
            }
            OrderedValue::Sequence(values) if values.is_empty() => {
                out.push_str("[]");
                *column += 2;
                out.push('\n');
            }
            OrderedValue::Sequence(values) => {
                out.push('\n');
                write_sequence(out, column, values, indent + INDENT);
            }
            other => {
                write_scalar(out, column, &scalar_of(other), indent);
                out.push('\n');
            }
        }
    }
}

fn push_indent(out: &mut String, column: &mut usize, indent: usize) {
    for _ in 0..indent {
        out.push(' ');
    }
    *column = indent;
}

/// A scalar and the style it was measured to need.
struct Scalar {
    style: Style,
    value: String,
}

fn scalar_of(value: &OrderedValue) -> Scalar {
    let (style, value) = match value {
        OrderedValue::Null => (Style::Plain, "null".to_owned()),
        OrderedValue::Bool(value) => (Style::Plain, value.to_string()),
        OrderedValue::Number(number) => (Style::Plain, number.to_string()),
        OrderedValue::String(value) => (classify(value), value.clone()),
        // Only reachable for a bare document; a nested empty collection is
        // written inline by the caller.
        OrderedValue::Mapping(_) => (Style::Plain, "{}".to_owned()),
        OrderedValue::Sequence(_) => (Style::Plain, "[]".to_owned()),
    };
    Scalar { style, value }
}

fn write_scalar(out: &mut String, column: &mut usize, scalar: &Scalar, indent: usize) {
    match scalar.style {
        Style::Plain => write_plain(out, column, &scalar.value, indent),
        Style::Single => write_single_quoted(out, column, &scalar.value, indent),
        Style::Double => write_double_quoted(out, column, &scalar.value),
        Style::Literal => write_literal(out, column, &scalar.value, indent),
    }
}

/// Writes a bare scalar, folding at a space once the line is past the reference
/// width.
///
/// Measured: `long_plain: aaaa bbbb …` wraps after `mmmm`, which is the first
/// space past column 80, and a long value with no space in it — `long_dashy`,
/// `long_url` — never wraps.
fn write_plain(out: &mut String, column: &mut usize, value: &str, indent: usize) {
    let mut chars = value.chars().peekable();
    let mut spaces = false;
    while let Some(ch) = chars.next() {
        if ch == ' ' {
            let folds =
                !spaces && *column > BEST_WIDTH && chars.peek().is_none_or(|next| *next != ' ');
            if folds {
                out.push('\n');
                push_indent(out, column, indent);
                spaces = true;
            } else {
                out.push(' ');
                *column += 1;
                spaces = true;
            }
        } else {
            out.push(ch);
            *column += 1;
            spaces = false;
        }
    }
}

/// Writes a single-quoted scalar, doubling any `'` and folding like a plain one.
fn write_single_quoted(out: &mut String, column: &mut usize, value: &str, indent: usize) {
    out.push('\'');
    *column += 1;
    let mut chars = value.chars().peekable();
    let mut spaces = false;
    while let Some(ch) = chars.next() {
        if ch == ' ' {
            let folds = !spaces
                && *column > BEST_WIDTH
                && indent != usize::MAX
                && chars.peek().is_none_or(|next| *next != ' ');
            if folds {
                out.push('\n');
                push_indent(out, column, indent);
                spaces = true;
            } else {
                out.push(' ');
                *column += 1;
                spaces = true;
            }
        } else {
            if ch == '\'' {
                out.push('\'');
                *column += 1;
            }
            out.push(ch);
            *column += 1;
            spaces = false;
        }
    }
    out.push('\'');
    *column += 1;
}

/// Writes a double-quoted scalar, escaping only what has to be escaped.
fn write_double_quoted(out: &mut String, column: &mut usize, value: &str) {
    out.push('"');
    *column += 1;
    for ch in value.chars() {
        if let Some(escape) = escape(ch) {
            out.push_str(&escape);
            *column += escape.chars().count();
        } else {
            out.push(ch);
            *column += 1;
        }
    }
    out.push('"');
    *column += 1;
}

/// Writes a literal block, including the chomping indicator.
///
/// Measured against `docker compose config`: `"a\nb\n"` becomes `|`, `"a\nb"`
/// becomes `|-`, `"a\n\n\n"` becomes `|+`, and `" a\nb"` becomes `|2-` because
/// the first line's leading space would otherwise be read as indentation.
fn write_literal(out: &mut String, column: &mut usize, value: &str, indent: usize) {
    let header = literal_header(value);
    out.push_str(&header);
    *column += header.chars().count();
    for line in literal_lines(value) {
        out.push('\n');
        push_indent(out, column, indent);
        out.push_str(line);
        *column += line.chars().count();
    }
}

/// The header of a literal block: `|`, an optional indentation indicator, and an
/// optional chomping indicator.
fn literal_header(value: &str) -> String {
    let mut header = String::from("|");
    if value.starts_with(' ') {
        header.push_str(&INDENT.to_string());
    }
    match value.chars().rev().take_while(|ch| *ch == '\n').count() {
        0 => header.push('-'),
        1 => {}
        _ => header.push('+'),
    }
    header
}

/// The content lines of a literal block, with the trailing breaks the chomping
/// indicator accounts for removed.
fn literal_lines(value: &str) -> Vec<&str> {
    let mut parts: Vec<&str> = value.split('\n').collect();
    // The split leaves one empty tail per trailing break; the indicator already
    // says what to do with them, so one is always dropped.
    if parts.last() == Some(&"") {
        parts.pop();
    }
    if value.chars().rev().take_while(|ch| *ch == '\n').count() == 0 {
        while parts.last() == Some(&"") {
            parts.pop();
        }
    }
    parts
}

/// Chooses a scalar's style, as measured from the Docker CLI.
fn classify(value: &str) -> Style {
    if value.is_empty() {
        return Style::Double;
    }
    if value.contains('\n') {
        return if literal_allowed(value) {
            Style::Literal
        } else {
            Style::Double
        };
    }
    if needs_double_quotes(value) {
        return Style::Double;
    }
    if plain_allowed(value) {
        Style::Plain
    } else {
        Style::Single
    }
}

/// A string that reads as something other than a string under YAML 1.2, or that
/// cannot be written without escapes.
///
/// Measured: `"1"`, `"-1"`, `"1.5"`, `"1e5"`, `"0"`, `"00"`, `"1_000"`,
/// `"0x1f"`, `"0o17"`, `"0b101"`, `"+1"`, `".inf"`, `".nan"`, `"-.inf"`,
/// `"true"`, `"TRUE"`, `"null"`, `"~"`, `""`, `"2021-01-01"`,
/// `"2021-01-01T00:00:00Z"`, `"a\tb"`, `"a\rb"`, `"a\u{7f}b"`, `"a\u{85}b"`,
/// and `"café \u{1f600}"` are all double-quoted by `docker compose config`.
///
/// `"1:2:3"` and `"yes"` are not in this set even though a reader would not take
/// them for strings: they are single-quoted instead. That split is a property of
/// Docker's writer rather than of YAML, and it is reproduced here.
fn needs_double_quotes(value: &str) -> bool {
    if matches!(
        value,
        "~" | "null" | "Null" | "NULL" | "true" | "True" | "TRUE" | "false" | "False" | "FALSE"
    ) {
        return true;
    }
    if is_core_number(value) || is_timestamp(value) {
        return true;
    }
    value.chars().any(needs_escape)
}

/// Whether a character has to be written as an escape inside double quotes.
///
/// Measured: `\r`, `\t`, `U+0085`, `U+007F`, `U+FEFF`, `U+FFFF` and anything
/// above the basic multilingual plane force double quotes, while `é`, `中文`
/// and a no-break space are written bare.
fn needs_escape(ch: char) -> bool {
    match ch {
        // C0 controls, DEL, the C1 block, the Unicode line and paragraph
        // separators, the byte-order mark, the two non-characters, and anything
        // above the basic multilingual plane.
        '\u{0}'..='\u{1f}'
        | '\u{7f}'
        | '\u{80}'..='\u{9f}'
        | '\u{2028}'
        | '\u{2029}'
        | '\u{feff}'
        | '\u{fffe}'
        | '\u{ffff}' => true,
        _ => ch > '\u{ffff}',
    }
}

/// The escape Docker writes for a character inside double quotes.
fn escape(ch: char) -> Option<String> {
    let escape = match ch {
        '"' => "\\\"",
        '\\' => "\\\\",
        '\u{0}' => "\\0",
        '\u{7}' => "\\a",
        '\u{8}' => "\\b",
        '\t' => "\\t",
        '\n' => "\\n",
        '\u{b}' => "\\v",
        '\u{c}' => "\\f",
        '\r' => "\\r",
        '\u{1b}' => "\\e",
        '\u{85}' => "\\N",
        // A no-break space is written as `_`, as `go-yaml` does.
        '\u{a0}' => "_",
        _ if needs_escape(ch) => {
            return Some(match ch as u32 {
                code @ 0x01..=0xff => format!("\\x{code:02X}"),
                code @ 0x100..=0xffff => format!("\\u{code:04X}"),
                code => format!("\\U{code:08X}"),
            });
        }
        _ => return None,
    };
    Some(escape.to_owned())
}

/// A YAML 1.2 core-schema number, which a reader would not take for a string.
fn is_core_number(value: &str) -> bool {
    let body = value.strip_prefix(['-', '+']).unwrap_or(value);
    // The base prefixes come first: `0x1f` is a number even though `x` is not a
    // digit, and it would otherwise fall through to the decimal rules.
    for (prefix, radix) in [("0x", 16u32), ("0o", 8), ("0b", 2)] {
        if let Some(head) = body.get(..2)
            && head.eq_ignore_ascii_case(prefix)
        {
            let rest = &body[2..];
            return !rest.is_empty() && rest.chars().all(|ch| ch == '_' || ch.is_digit(radix));
        }
    }
    if let Some(rest) = body.strip_prefix('.') {
        // `.inf` and `.nan`, and their signed spellings of `.inf`.
        if rest.eq_ignore_ascii_case("inf") || rest.eq_ignore_ascii_case("nan") {
            return true;
        }
    }
    let Some(index) = body.find(['.', 'e', 'E']) else {
        return !body.is_empty() && body.chars().all(|c| c.is_ascii_digit() || c == '_');
    };
    let (mantissa, rest) = body.split_at(index);
    if mantissa.is_empty() || !mantissa.chars().all(|c| c.is_ascii_digit() || c == '_') {
        return false;
    }
    let separator = rest.as_bytes()[0];
    let tail = &rest[1..];
    // A `.` may be followed by nothing at all (`1.`), but an `e` may not.
    if separator == b'e' || separator == b'E' {
        return is_exponent(tail);
    }
    is_exponent(tail) || tail.is_empty()
}

fn is_exponent(value: &str) -> bool {
    let digits = value.strip_prefix(['+', '-']).unwrap_or(value);
    !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit())
}

/// A YAML 1.1 sexagesimal integer such as `1:2:3`, which Docker single-quotes.
///
/// Measured: `"1:2:3"` comes back as `'1:2:3'` while `"1:60"` and `"1000:1000"`
/// come back bare. The second is bare because a sexagesimal field is one or two
/// digits, and `1000` is four; the first is bare because a sexagesimal field
/// runs to 59 and `60` does not.
fn is_sexagesimal(value: &str) -> bool {
    let body = value.strip_prefix(['-', '+']).unwrap_or(value);
    let mut fields = body.split(':');
    let Some(first) = fields.next() else {
        return false;
    };
    let mut leading = first.chars();
    if !matches!(leading.next(), Some('1'..='9'))
        || !leading.all(|c| c.is_ascii_digit() || c == '_')
    {
        return false;
    }
    let mut seen = 0;
    for field in fields {
        seen += 1;
        // One digit, or a tens digit below six followed by a units digit.
        let mut chars = field.chars();
        let Some(lead) = chars.next() else {
            return false;
        };
        if !('0'..='5').contains(&lead) {
            return false;
        }
        if let Some(second) = chars.next()
            && !second.is_ascii_digit()
        {
            return false;
        }
        if chars.next().is_some() {
            return false;
        }
    }
    seen > 0
}

/// The YAML 1.1 booleans that YAML 1.2 reads as strings, and which Docker
/// single-quotes anyway.
fn is_yaml_11_bool(value: &str) -> bool {
    matches!(
        value,
        "y" | "Y"
            | "yes"
            | "Yes"
            | "YES"
            | "n"
            | "N"
            | "no"
            | "No"
            | "NO"
            | "on"
            | "On"
            | "ON"
            | "off"
            | "Off"
            | "OFF"
    )
}

/// Whether a string can be written bare.
///
/// These are the YAML indicator rules `go-yaml` applies, plus the two YAML 1.1
/// readings Docker guards against anyway. Measured against
/// `docker compose config`: `alpine:3.20`, `unless-stopped`, `1000:1000`,
/// `node.role == worker`, `a:b:c`, `-x`, `?a`, `:a`, `a#b`, `a & b` and `v` are
/// all bare; `'a: b'`, `'a #b'`, `' x'`, `'x '`, `'@x'`, `'*x'`, `'&x'`, `'!x'`,
/// `'>x'`, `'|x'`, `'{x}'`, `'[x]'`, `'-'`, `'- '`, `':'`, `'?'`, `'? a'`,
/// `'#a'`, `'a:'`, `'a: '`, `'yes'`, `'y'`, `'on'`, `'N'`, `'Off'` and
/// `'1:2:3'` are all single-quoted.
fn plain_allowed(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    let second = value.chars().nth(1);
    let followed_by_space = second.is_none() || second == Some(' ');
    let starts_indicator = match first {
        '#' | ',' | '[' | ']' | '{' | '}' | '&' | '*' | '!' | '|' | '>' | '\'' | '"' | '%'
        | '@' | '`' => true,
        // `?` and `:` only introduce a mapping key when a space follows, and `-`
        // only introduces a block entry when a space follows. That is why `-x`,
        // `--flag`, `?a` and `:a` are bare while `? a`, `?`, `- ` and `-` are not.
        '?' | ':' | '-' => followed_by_space,
        _ => false,
    };
    if starts_indicator
        || value.starts_with(' ')
        || value.ends_with(' ')
        || value.contains(": ")
        || value.ends_with(':')
        // A `#` only comments when it starts the scalar or follows a space.
        || value.starts_with('#')
        || value.contains(" #")
        || is_yaml_11_bool(value)
        || is_sexagesimal(value)
    {
        return false;
    }
    // The merge key is a YAML indicator even though it is alphabetic.
    !value.starts_with("<<")
}

/// A date or date-time, which Docker double-quotes.
///
/// Measured: `"2021-01-01"` and `"2021-01-01T00:00:00Z"` are both quoted. The
/// four-digit-year requirement is `go-yaml`'s, and it is what keeps `1-2-3` bare.
fn is_timestamp(value: &str) -> bool {
    // `go-yaml` only reads a timestamp when the value opens with four digits and
    // a dash, which is what keeps `1-2-3` bare.
    let Some(date) = value.get(..10) else {
        return false;
    };
    if !is_date(date) {
        return false;
    }
    let rest = &value[10..];
    if rest.is_empty() {
        return true;
    }
    if !matches!(rest.chars().next(), Some('T' | 't' | ' ')) {
        return false;
    }
    let time = rest[1..].trim_end_matches('Z');
    // Drop a numeric zone offset, then a fractional second, before reading the
    // clock fields themselves.
    let time = time.split(['+', '-']).next().unwrap_or_default();
    let time = time.split('.').next().unwrap_or_default();
    let parts: Vec<&str> = time.split(':').collect();
    (2..=3).contains(&parts.len()) && parts.iter().all(|part| part.parse::<u8>().is_ok())
}

fn is_date(value: &str) -> bool {
    let parts: Vec<&str> = value.split('-').collect();
    parts.len() == 3
        && parts[0].len() == 4
        && parts[0].parse::<u32>().is_ok()
        && parts[1]
            .parse::<u32>()
            .is_ok_and(|month| (1..=12).contains(&month))
        && parts[2]
            .parse::<u32>()
            .is_ok_and(|day| (1..=31).contains(&day))
}

/// Whether a string can be written as a literal block.
///
/// Measured: `"a\nb\n"` becomes `|`, `"a\nb"` becomes `|-`, `"a\n\n\n"` becomes
/// `|+`, `" a\nb"` becomes `|2-`, and `"a \nb"`, `"a\rb"`, `"a\0b"` and a string
/// that is nothing but newlines all fall back to double quotes. A tab inside a
/// literal block is left alone — measured on `"a\nb\tc"`.
fn literal_allowed(value: &str) -> bool {
    if value.chars().all(|ch| ch == '\n') {
        return false;
    }
    if value
        .chars()
        .any(|ch| ch != '\n' && ch != '\t' && needs_escape(ch))
    {
        return false;
    }
    // A space only matters where a reader cannot tell it from indentation, which
    // is at the end of a line; a leading space on a later line is content and is
    // what the indentation indicator is for.
    !value.split('\n').any(|line| line.ends_with(' '))
}

#[cfg(test)]
mod tests {
    use super::{
        BEST_WIDTH, INDENT, OrderedMap, OrderedValue, Style, classify, escape, is_core_number,
        is_sexagesimal, is_timestamp, literal_allowed, literal_header, literal_lines,
        plain_allowed, to_yaml,
    };

    fn map(entries: Vec<(&str, OrderedValue)>) -> OrderedValue {
        OrderedValue::Mapping(
            entries
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value))
                .collect::<OrderedMap>(),
        )
    }

    fn list(values: Vec<&str>) -> OrderedValue {
        OrderedValue::Sequence(values.into_iter().map(OrderedValue::string).collect())
    }

    /// Every expectation here was captured from `docker compose config` on
    /// Docker 29.8 rather than written from the YAML specification, because
    /// Docker's split between double and single quotes is not a rule the
    /// specification states.
    #[test]
    fn scalars_are_quoted_exactly_as_docker_quotes_them() {
        let cases = [
            ("1", Style::Double),
            ("-1", Style::Double),
            ("1.5", Style::Double),
            ("1e5", Style::Double),
            ("0", Style::Double),
            ("00", Style::Double),
            ("1_000", Style::Double),
            ("0x1f", Style::Double),
            ("0o17", Style::Double),
            ("0b101", Style::Double),
            ("+1", Style::Double),
            (".inf", Style::Double),
            (".nan", Style::Double),
            ("-.inf", Style::Double),
            ("true", Style::Double),
            ("TRUE", Style::Double),
            ("null", Style::Double),
            ("~", Style::Double),
            ("", Style::Double),
            ("2021-01-01", Style::Double),
            ("2021-01-01T00:00:00Z", Style::Double),
            ("a\tb", Style::Double),
            ("a\rb", Style::Double),
            ("yes", Style::Single),
            ("on", Style::Single),
            ("y", Style::Single),
            ("N", Style::Single),
            ("Off", Style::Single),
            ("1:2:3", Style::Single),
            ("a: b", Style::Single),
            ("a #b", Style::Single),
            (" x", Style::Single),
            ("x ", Style::Single),
            ("@x", Style::Single),
            ("*x", Style::Single),
            ("&x", Style::Single),
            ("!x", Style::Single),
            (">x", Style::Single),
            ("|x", Style::Single),
            ("{x}", Style::Single),
            ("[x]", Style::Single),
            ("-", Style::Single),
            ("- ", Style::Single),
            (":", Style::Single),
            ("?", Style::Single),
            ("? a", Style::Single),
            ("#a", Style::Single),
            ("a:", Style::Single),
            ("a: ", Style::Single),
            ("alpine:3.20", Style::Plain),
            ("unless-stopped", Style::Plain),
            ("1000:1000", Style::Plain),
            ("node.role == worker", Style::Plain),
            ("a:b:c", Style::Plain),
            ("-x", Style::Plain),
            ("--flag", Style::Plain),
            ("?a", Style::Plain),
            (":a", Style::Plain),
            ("a#b", Style::Plain),
            ("a & b", Style::Plain),
            ("v", Style::Plain),
            ("1:60", Style::Plain),
            ("1.2.3", Style::Plain),
            ("v1.2", Style::Plain),
            ("null_value", Style::Plain),
            ("trueish", Style::Plain),
            ("a,b", Style::Plain),
            ("a, b", Style::Plain),
            ("has \"quotes\"", Style::Plain),
            ("has 'single'", Style::Plain),
            ("a[b]", Style::Plain),
            ("a{b}", Style::Plain),
        ];
        for (value, expected) in cases {
            assert_eq!(classify(value), expected, "{value:?}");
        }
    }

    #[test]
    fn a_sequence_is_indented_under_its_key() {
        let document = map(vec![(
            "services",
            map(vec![(
                "app",
                map(vec![(
                    "volumes",
                    OrderedValue::Sequence(vec![map(vec![
                        ("type", OrderedValue::string("bind")),
                        ("source", OrderedValue::string("/src")),
                        ("read_only", OrderedValue::Bool(true)),
                    ])]),
                )]),
            )]),
        )]);
        assert_eq!(
            to_yaml(&document),
            concat!(
                "services:\n",
                "  app:\n",
                "    volumes:\n",
                "      - type: bind\n",
                "        source: /src\n",
                "        read_only: true\n",
            )
        );
    }

    #[test]
    fn an_empty_collection_is_written_inline() {
        let document = map(vec![
            ("empty_map", OrderedValue::Mapping(OrderedMap::new())),
            ("empty_list", OrderedValue::Sequence(Vec::new())),
            ("nothing", OrderedValue::Null),
        ]);
        assert_eq!(
            to_yaml(&document),
            "empty_map: {}\nempty_list: []\nnothing: null\n"
        );
    }

    #[test]
    fn keys_keep_the_order_the_caller_supplied() {
        let document = OrderedValue::Mapping(
            vec![
                ("hostname".to_owned(), OrderedValue::string("h")),
                ("healthcheck".to_owned(), OrderedValue::Bool(true)),
                ("image".to_owned(), OrderedValue::string("alpine")),
            ]
            .into_iter()
            .collect(),
        );
        assert_eq!(
            to_yaml(&document),
            "hostname: h\nhealthcheck: true\nimage: alpine\n"
        );
    }

    #[test]
    fn a_long_plain_scalar_folds_past_the_reference_width() {
        // Nesting matters: the fold column is counted from the start of the line,
        // so a value's wrap point depends on how deep its key sits. This fixture
        // is the shape `docker compose config` printed for a `long_plain` at
        // indentation six, captured verbatim.
        let value =
            "aaaa bbbb cccc dddd eeee ffff gggg hhhh iiii jjjj kkkk llll mmmm nnnn oooo pppp qqqq";
        let document = map(vec![(
            "a",
            map(vec![(
                "b",
                map(vec![(
                    "c",
                    map(vec![("long_plain", OrderedValue::string(value))]),
                )]),
            )]),
        )]);
        assert_eq!(
            to_yaml(&document),
            concat!(
                "a:\n",
                "  b:\n",
                "    c:\n",
                "      long_plain: aaaa bbbb cccc dddd eeee ffff gggg hhhh iiii jjjj kkkk llll mmmm\n",
                "        nnnn oooo pppp qqqq\n",
            )
        );
    }

    #[test]
    fn a_long_scalar_without_a_space_does_not_fold() {
        let value =
            "aaaa-bbbb-cccc-dddd-eeee-ffff-gggg-hhhh-iiii-jjjj-kkkk-llll-mmmm-nnnn-oooo-pppp-qqqq";
        let document = map(vec![("long_dashy", OrderedValue::string(value))]);
        assert_eq!(to_yaml(&document), format!("long_dashy: {value}\n"));
    }

    #[test]
    fn a_multi_line_string_becomes_a_literal_block() {
        let document = map(vec![
            ("keep", OrderedValue::string("a\nb\n")),
            ("strip", OrderedValue::string("a\nb")),
            ("keep_more", OrderedValue::string("a\n\n\n")),
            ("indented", OrderedValue::string(" a\nb")),
        ]);
        assert_eq!(
            to_yaml(&document),
            concat!(
                "keep: |\n  a\n  b\n",
                "strip: |-\n  a\n  b\n",
                "keep_more: |+\n  a\n  \n  \n",
                "indented: |2-\n   a\n  b\n",
            )
        );
    }

    #[test]
    fn a_multi_line_string_that_cannot_be_a_block_is_quoted() {
        for value in ["a \nb", "a\rb", "a\0b", "\n"] {
            assert!(!literal_allowed(value), "{value:?}");
        }
        assert_eq!(classify("a \nb"), Style::Double);
        assert_eq!(classify("a\nb\tc"), Style::Literal);
    }

    #[test]
    fn literal_headers_and_lines_match_the_reference() {
        assert_eq!(literal_header("a\nb\n"), "|");
        assert_eq!(literal_header("a\nb"), "|-");
        assert_eq!(literal_header("a\n\n\n"), "|+");
        assert_eq!(literal_header("\na"), "|-");
        assert_eq!(literal_header(" a\nb"), "|2-");
        assert_eq!(literal_lines("a\n\n\n"), vec!["a", "", ""]);
        assert_eq!(literal_lines("a\n\nb\n"), vec!["a", "", "b"]);
        assert_eq!(literal_lines("\na"), vec!["", "a"]);
        assert_eq!(literal_lines("a"), vec!["a"]);
    }

    #[test]
    fn a_single_quote_inside_a_single_quoted_scalar_is_doubled() {
        assert_eq!(
            to_yaml(&map(vec![("x", OrderedValue::string("has 'single'"))])),
            "x: has 'single'\n"
        );
        assert_eq!(
            to_yaml(&map(vec![("x", OrderedValue::string("'lead"))])),
            "x: '''lead'\n"
        );
    }

    #[test]
    fn escapes_match_the_reference() {
        assert_eq!(escape('\''), None);
        assert_eq!(escape('"').as_deref(), Some("\\\""));
        assert_eq!(escape('\\').as_deref(), Some("\\\\"));
        assert_eq!(escape('\t').as_deref(), Some("\\t"));
        assert_eq!(escape('\r').as_deref(), Some("\\r"));
        assert_eq!(escape('\u{7f}').as_deref(), Some("\\x7F"));
        assert_eq!(escape('\u{ffff}').as_deref(), Some("\\uFFFF"));
        assert_eq!(escape('\u{1f600}').as_deref(), Some("\\U0001F600"));
        assert_eq!(
            to_yaml(&map(vec![(
                "x",
                OrderedValue::string("caf\u{e9} \u{4e2d}\u{6587}")
            )])),
            "x: caf\u{e9} \u{4e2d}\u{6587}\n"
        );
    }

    #[test]
    fn the_resolvers_agree_with_the_cli() {
        for value in [
            "1", "1.5", "1e5", "0x1f", "0o17", "0b101", "1_000", "+1", "00", "1.",
        ] {
            assert!(is_core_number(value), "{value}");
        }
        for value in ["1.2.3", "v1.2", "alpine:3.20", "1:60", "a", ".x"] {
            assert!(!is_core_number(value), "{value}");
        }
        assert!(is_sexagesimal("1:2:3"));
        assert!(!is_sexagesimal("1:60"));
        assert!(!is_sexagesimal("a:b"));
        assert!(is_timestamp("2021-01-01"));
        assert!(is_timestamp("2021-01-01T00:00:00Z"));
        assert!(!is_timestamp("1-2-3"));
        assert!(!plain_allowed("a: b"));
        assert!(plain_allowed("a:b"));
        assert_eq!(
            to_yaml(&map(vec![("x", list(vec!["a", "1"]))])),
            "x:\n  - a\n  - \"1\"\n"
        );
        assert_eq!(BEST_WIDTH, 80);
        assert_eq!(INDENT, 2);
    }

    #[test]
    fn a_json_value_becomes_an_alphabetical_mapping() {
        let value = OrderedValue::from(serde_json::json!({"z": "1", "a": 2}));
        assert_eq!(to_yaml(&value), "a: 2\nz: \"1\"\n");
    }
}
