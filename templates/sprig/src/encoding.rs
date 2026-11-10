//! Encoding helpers: base64, base32, and JSON.
//!
//! Sprig's encoders are the ones a Compose file reaches for when a value has to
//! travel as text: a digest in a label, a secret in an environment variable, or
//! a whole values tree inlined as JSON. Each of them is defined here by the bytes
//! it produces rather than by the crate it borrows an alphabet from, so a
//! rendered template is the same on any machine.
//!
//! The three JSON helpers differ in one axis each, and the difference is
//! visible in the output. `toJson` and `toPrettyJson` escape a string so that it
//! is safe to embed in HTML, which is what upstream Sprig does; `toRawJson`
//! leaves those characters alone. `toPrettyJson` indents with two spaces and a
//! newline. `fromJson` answers an unparsable document with an empty string
//! rather than failing the template, so pointing it at an optional value is safe.

use crate::support;
use crate::{Context, Error, Value, arity, invalid};

/// Dispatches an encoding helper.
pub(super) const DISPATCH: crate::Dispatch =
    |name, arguments, context| dispatch(name, arguments, context);

// No encoding helper reads the call site; only `env` and `expandenv` do.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn dispatch(
    name: &str,
    arguments: &[Value],
    _context: &Context<'_>,
) -> Option<Result<Value, Error>> {
    let result = match name {
        "b64enc" => b64enc(arguments),
        "b64dec" => b64dec(arguments),
        "b32enc" => b32enc(arguments),
        "b32dec" => b32dec(arguments),
        "toJson" => to_json(arguments, Layout::Compact),
        "toPrettyJson" => to_json(arguments, Layout::Indented),
        "toRawJson" => to_json(arguments, Layout::Relaxed),
        "fromJson" => from_json(arguments),
        "toStrings" => to_strings(arguments),
        _ => return None,
    };
    Some(result)
}

/// Reports whether this module's helper wants rendered string arguments.
pub(super) fn takes_rendered_strings(_name: &str) -> bool {
    // `toJson` has to see a number as a number and a map as a map, and `fromJson`
    // reads the text its argument renders to, so the typed value is what every
    // helper here needs.
    false
}

/// The standard base64 alphabet, which is what Go's `base64.StdEncoding` uses.
const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The standard base32 alphabet, RFC 4648 without padding rules of its own.
const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// The code points `toRawJson` writes as itself, as sorted disjoint ranges.
///
/// This is the allow-list of .NET's `JavaScriptEncoder.UnsafeRelaxedJsonEscaping`,
/// which is the encoder the reference hands its writer for `toRawJson`. It is not
/// "everything that is not a control character": most non-ASCII characters are
/// written as themselves, but the C1 controls, the no-break space, the line and
/// paragraph separators, and everything outside the basic multilingual plane are
/// escaped anyway. A rule cannot express that list, and a template that inlines a
/// non-ASCII label as raw JSON is exactly where the difference shows, so the
/// table is carried here.
const RELAXED_ALLOWED: &[(u32, u32)] = &[
    (0x0020, 0x0021),
    (0x0023, 0x005b),
    (0x005d, 0x007e),
    (0x00a1, 0x0377),
    (0x037a, 0x037f),
    (0x0384, 0x038a),
    (0x038c, 0x038c),
    (0x038e, 0x03a1),
    (0x03a3, 0x052f),
    (0x0531, 0x0556),
    (0x0559, 0x058a),
    (0x058d, 0x058f),
    (0x0591, 0x05c7),
    (0x05d0, 0x05ea),
    (0x05ef, 0x05f4),
    (0x0600, 0x070d),
    (0x070f, 0x074a),
    (0x074d, 0x07b1),
    (0x07c0, 0x07fa),
    (0x07fd, 0x082d),
    (0x0830, 0x083e),
    (0x0840, 0x085b),
    (0x085e, 0x085e),
    (0x0860, 0x086a),
    (0x0870, 0x088e),
    (0x0890, 0x0891),
    (0x0897, 0x0983),
    (0x0985, 0x098c),
    (0x098f, 0x0990),
    (0x0993, 0x09a8),
    (0x09aa, 0x09b0),
    (0x09b2, 0x09b2),
    (0x09b6, 0x09b9),
    (0x09bc, 0x09c4),
    (0x09c7, 0x09c8),
    (0x09cb, 0x09ce),
    (0x09d7, 0x09d7),
    (0x09dc, 0x09dd),
    (0x09df, 0x09e3),
    (0x09e6, 0x09fe),
    (0x0a01, 0x0a03),
    (0x0a05, 0x0a0a),
    (0x0a0f, 0x0a10),
    (0x0a13, 0x0a28),
    (0x0a2a, 0x0a30),
    (0x0a32, 0x0a33),
    (0x0a35, 0x0a36),
    (0x0a38, 0x0a39),
    (0x0a3c, 0x0a3c),
    (0x0a3e, 0x0a42),
    (0x0a47, 0x0a48),
    (0x0a4b, 0x0a4d),
    (0x0a51, 0x0a51),
    (0x0a59, 0x0a5c),
    (0x0a5e, 0x0a5e),
    (0x0a66, 0x0a76),
    (0x0a81, 0x0a83),
    (0x0a85, 0x0a8d),
    (0x0a8f, 0x0a91),
    (0x0a93, 0x0aa8),
    (0x0aaa, 0x0ab0),
    (0x0ab2, 0x0ab3),
    (0x0ab5, 0x0ab9),
    (0x0abc, 0x0ac5),
    (0x0ac7, 0x0ac9),
    (0x0acb, 0x0acd),
    (0x0ad0, 0x0ad0),
    (0x0ae0, 0x0ae3),
    (0x0ae6, 0x0af1),
    (0x0af9, 0x0aff),
    (0x0b01, 0x0b03),
    (0x0b05, 0x0b0c),
    (0x0b0f, 0x0b10),
    (0x0b13, 0x0b28),
    (0x0b2a, 0x0b30),
    (0x0b32, 0x0b33),
    (0x0b35, 0x0b39),
    (0x0b3c, 0x0b44),
    (0x0b47, 0x0b48),
    (0x0b4b, 0x0b4d),
    (0x0b55, 0x0b57),
    (0x0b5c, 0x0b5d),
    (0x0b5f, 0x0b63),
    (0x0b66, 0x0b77),
    (0x0b82, 0x0b83),
    (0x0b85, 0x0b8a),
    (0x0b8e, 0x0b90),
    (0x0b92, 0x0b95),
    (0x0b99, 0x0b9a),
    (0x0b9c, 0x0b9c),
    (0x0b9e, 0x0b9f),
    (0x0ba3, 0x0ba4),
    (0x0ba8, 0x0baa),
    (0x0bae, 0x0bb9),
    (0x0bbe, 0x0bc2),
    (0x0bc6, 0x0bc8),
    (0x0bca, 0x0bcd),
    (0x0bd0, 0x0bd0),
    (0x0bd7, 0x0bd7),
    (0x0be6, 0x0bfa),
    (0x0c00, 0x0c0c),
    (0x0c0e, 0x0c10),
    (0x0c12, 0x0c28),
    (0x0c2a, 0x0c39),
    (0x0c3c, 0x0c44),
    (0x0c46, 0x0c48),
    (0x0c4a, 0x0c4d),
    (0x0c55, 0x0c56),
    (0x0c58, 0x0c5a),
    (0x0c5d, 0x0c5d),
    (0x0c60, 0x0c63),
    (0x0c66, 0x0c6f),
    (0x0c77, 0x0c8c),
    (0x0c8e, 0x0c90),
    (0x0c92, 0x0ca8),
    (0x0caa, 0x0cb3),
    (0x0cb5, 0x0cb9),
    (0x0cbc, 0x0cc4),
    (0x0cc6, 0x0cc8),
    (0x0cca, 0x0ccd),
    (0x0cd5, 0x0cd6),
    (0x0cdd, 0x0cde),
    (0x0ce0, 0x0ce3),
    (0x0ce6, 0x0cef),
    (0x0cf1, 0x0cf3),
    (0x0d00, 0x0d0c),
    (0x0d0e, 0x0d10),
    (0x0d12, 0x0d44),
    (0x0d46, 0x0d48),
    (0x0d4a, 0x0d4f),
    (0x0d54, 0x0d63),
    (0x0d66, 0x0d7f),
    (0x0d81, 0x0d83),
    (0x0d85, 0x0d96),
    (0x0d9a, 0x0db1),
    (0x0db3, 0x0dbb),
    (0x0dbd, 0x0dbd),
    (0x0dc0, 0x0dc6),
    (0x0dca, 0x0dca),
    (0x0dcf, 0x0dd4),
    (0x0dd6, 0x0dd6),
    (0x0dd8, 0x0ddf),
    (0x0de6, 0x0def),
    (0x0df2, 0x0df4),
    (0x0e01, 0x0e3a),
    (0x0e3f, 0x0e5b),
    (0x0e81, 0x0e82),
    (0x0e84, 0x0e84),
    (0x0e86, 0x0e8a),
    (0x0e8c, 0x0ea3),
    (0x0ea5, 0x0ea5),
    (0x0ea7, 0x0ebd),
    (0x0ec0, 0x0ec4),
    (0x0ec6, 0x0ec6),
    (0x0ec8, 0x0ece),
    (0x0ed0, 0x0ed9),
    (0x0edc, 0x0edf),
    (0x0f00, 0x0f47),
    (0x0f49, 0x0f6c),
    (0x0f71, 0x0f97),
    (0x0f99, 0x0fbc),
    (0x0fbe, 0x0fcc),
    (0x0fce, 0x0fda),
    (0x1000, 0x10c5),
    (0x10c7, 0x10c7),
    (0x10cd, 0x10cd),
    (0x10d0, 0x1248),
    (0x124a, 0x124d),
    (0x1250, 0x1256),
    (0x1258, 0x1258),
    (0x125a, 0x125d),
    (0x1260, 0x1288),
    (0x128a, 0x128d),
    (0x1290, 0x12b0),
    (0x12b2, 0x12b5),
    (0x12b8, 0x12be),
    (0x12c0, 0x12c0),
    (0x12c2, 0x12c5),
    (0x12c8, 0x12d6),
    (0x12d8, 0x1310),
    (0x1312, 0x1315),
    (0x1318, 0x135a),
    (0x135d, 0x137c),
    (0x1380, 0x1399),
    (0x13a0, 0x13f5),
    (0x13f8, 0x13fd),
    (0x1400, 0x167f),
    (0x1681, 0x169c),
    (0x16a0, 0x16f8),
    (0x1700, 0x1715),
    (0x171f, 0x1736),
    (0x1740, 0x1753),
    (0x1760, 0x176c),
    (0x176e, 0x1770),
    (0x1772, 0x1773),
    (0x1780, 0x17dd),
    (0x17e0, 0x17e9),
    (0x17f0, 0x17f9),
    (0x1800, 0x1819),
    (0x1820, 0x1878),
    (0x1880, 0x18aa),
    (0x18b0, 0x18f5),
    (0x1900, 0x191e),
    (0x1920, 0x192b),
    (0x1930, 0x193b),
    (0x1940, 0x1940),
    (0x1944, 0x196d),
    (0x1970, 0x1974),
    (0x1980, 0x19ab),
    (0x19b0, 0x19c9),
    (0x19d0, 0x19da),
    (0x19de, 0x1a1b),
    (0x1a1e, 0x1a5e),
    (0x1a60, 0x1a7c),
    (0x1a7f, 0x1a89),
    (0x1a90, 0x1a99),
    (0x1aa0, 0x1aad),
    (0x1ab0, 0x1ace),
    (0x1b00, 0x1b4c),
    (0x1b4e, 0x1bf3),
    (0x1bfc, 0x1c37),
    (0x1c3b, 0x1c49),
    (0x1c4d, 0x1c8a),
    (0x1c90, 0x1cba),
    (0x1cbd, 0x1cc7),
    (0x1cd0, 0x1cfa),
    (0x1d00, 0x1f15),
    (0x1f18, 0x1f1d),
    (0x1f20, 0x1f45),
    (0x1f48, 0x1f4d),
    (0x1f50, 0x1f57),
    (0x1f59, 0x1f59),
    (0x1f5b, 0x1f5b),
    (0x1f5d, 0x1f5d),
    (0x1f5f, 0x1f7d),
    (0x1f80, 0x1fb4),
    (0x1fb6, 0x1fc4),
    (0x1fc6, 0x1fd3),
    (0x1fd6, 0x1fdb),
    (0x1fdd, 0x1fef),
    (0x1ff2, 0x1ff4),
    (0x1ff6, 0x1ffe),
    (0x200b, 0x2027),
    (0x202a, 0x202e),
    (0x2030, 0x205e),
    (0x2060, 0x2064),
    (0x2066, 0x2071),
    (0x2074, 0x208e),
    (0x2090, 0x209c),
    (0x20a0, 0x20c0),
    (0x20d0, 0x20f0),
    (0x2100, 0x218b),
    (0x2190, 0x2429),
    (0x2440, 0x244a),
    (0x2460, 0x2b73),
    (0x2b76, 0x2b95),
    (0x2b97, 0x2cf3),
    (0x2cf9, 0x2d25),
    (0x2d27, 0x2d27),
    (0x2d2d, 0x2d2d),
    (0x2d30, 0x2d67),
    (0x2d6f, 0x2d70),
    (0x2d7f, 0x2d96),
    (0x2da0, 0x2da6),
    (0x2da8, 0x2dae),
    (0x2db0, 0x2db6),
    (0x2db8, 0x2dbe),
    (0x2dc0, 0x2dc6),
    (0x2dc8, 0x2dce),
    (0x2dd0, 0x2dd6),
    (0x2dd8, 0x2dde),
    (0x2de0, 0x2e5d),
    (0x2e80, 0x2e99),
    (0x2e9b, 0x2ef3),
    (0x2f00, 0x2fd5),
    (0x2ff0, 0x2fff),
    (0x3001, 0x303f),
    (0x3041, 0x3096),
    (0x3099, 0x30ff),
    (0x3105, 0x312f),
    (0x3131, 0x318e),
    (0x3190, 0x31e5),
    (0x31ef, 0x321e),
    (0x3220, 0xa48c),
    (0xa490, 0xa4c6),
    (0xa4d0, 0xa62b),
    (0xa640, 0xa6f7),
    (0xa700, 0xa7cd),
    (0xa7d0, 0xa7d1),
    (0xa7d3, 0xa7d3),
    (0xa7d5, 0xa7dc),
    (0xa7f2, 0xa82c),
    (0xa830, 0xa839),
    (0xa840, 0xa877),
    (0xa880, 0xa8c5),
    (0xa8ce, 0xa8d9),
    (0xa8e0, 0xa953),
    (0xa95f, 0xa97c),
    (0xa980, 0xa9cd),
    (0xa9cf, 0xa9d9),
    (0xa9de, 0xa9fe),
    (0xaa00, 0xaa36),
    (0xaa40, 0xaa4d),
    (0xaa50, 0xaa59),
    (0xaa5c, 0xaac2),
    (0xaadb, 0xaaf6),
    (0xab01, 0xab06),
    (0xab09, 0xab0e),
    (0xab11, 0xab16),
    (0xab20, 0xab26),
    (0xab28, 0xab2e),
    (0xab30, 0xab6b),
    (0xab70, 0xabed),
    (0xabf0, 0xabf9),
    (0xac00, 0xd7a3),
    (0xd7b0, 0xd7c6),
    (0xd7cb, 0xd7fb),
    (0xf900, 0xfa6d),
    (0xfa70, 0xfad9),
    (0xfb00, 0xfb06),
    (0xfb13, 0xfb17),
    (0xfb1d, 0xfb36),
    (0xfb38, 0xfb3c),
    (0xfb3e, 0xfb3e),
    (0xfb40, 0xfb41),
    (0xfb43, 0xfb44),
    (0xfb46, 0xfbc2),
    (0xfbd3, 0xfd8f),
    (0xfd92, 0xfdc7),
    (0xfdcf, 0xfdcf),
    (0xfdf0, 0xfe19),
    (0xfe20, 0xfe52),
    (0xfe54, 0xfe66),
    (0xfe68, 0xfe6b),
    (0xfe70, 0xfe74),
    (0xfe76, 0xfefc),
    (0xff01, 0xffbe),
    (0xffc2, 0xffc7),
    (0xffca, 0xffcf),
    (0xffd2, 0xffd7),
    (0xffda, 0xffdc),
    (0xffe0, 0xffe6),
    (0xffe8, 0xffee),
    (0xfff9, 0xfffd),
];

/// Which of the three JSON spellings to write.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Layout {
    /// `toJson`: compact, and escaped so the result is safe inside HTML.
    Compact,
    /// `toPrettyJson`: two-space indent, and the same escaping as `toJson`.
    Indented,
    /// `toRawJson`: compact, and escaped only where JSON requires it.
    Relaxed,
}

impl Layout {
    /// The helper name a layout belongs to, for an error that names the call.
    fn helper(self) -> &'static str {
        match self {
            Self::Compact => "toJson",
            Self::Indented => "toPrettyJson",
            Self::Relaxed => "toRawJson",
        }
    }

    /// Reports whether strings are written unescaped past the JSON specials.
    fn is_relaxed(self) -> bool {
        self == Self::Relaxed
    }

    /// Reports whether the output is indented.
    fn is_indented(self) -> bool {
        self == Self::Indented
    }
}

/// Encodes a string as padded standard base64.
///
/// `Base64Encode` writes the padded form of Go's standard alphabet, so the
/// output is a multiple of four characters and a one- or two-byte input keeps
/// its `=` padding.
fn b64enc(arguments: &[Value]) -> Result<Value, Error> {
    arity("b64enc", arguments.len(), 1, Some(1))?;
    Ok(Value::String(base64_encode(&argument_bytes(arguments))))
}

/// Decodes standard base64, reporting Go's error text instead of failing.
///
/// `Base64Decode` returns a rendered message for input it cannot read, which is
/// what `{{ b64dec "!" }}` showing `illegal base64 data at input byte 0` in
/// the reference comes from: the helper answers, it does not abort the template.
fn b64dec(arguments: &[Value]) -> Result<Value, Error> {
    arity("b64dec", arguments.len(), 1, Some(1))?;
    let text = support::any_text(&arguments[0]);
    if let Some(offset) = go_base64_invalid_offset(&text) {
        return Ok(go_error("base64", offset));
    }
    let Some(decoded) = base64_decode(&strip_line_breaks(&text)) else {
        return Ok(go_error("base64", go_base64_padding_offset(&text)));
    };
    Ok(Value::String(
        String::from_utf8_lossy(&decoded).into_owned(),
    ))
}

/// Encodes a string as padded standard base32.
fn b32enc(arguments: &[Value]) -> Result<Value, Error> {
    arity("b32enc", arguments.len(), 1, Some(1))?;
    let mut out = String::new();
    let mut buffer = 0_u32;
    let mut bits = 0_u32;
    for byte in argument_bytes(arguments) {
        // The bits left over from the previous byte sit at the bottom of the
        // buffer, so the next byte lands above them and the encoder always reads
        // from the top. The mask drops the rest.
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            out.push(BASE32[((buffer >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(BASE32[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    while !out.len().is_multiple_of(8) {
        out.push('=');
    }
    Ok(Value::String(out))
}

/// Decodes standard base32, reporting Go's error text instead of failing.
fn b32dec(arguments: &[Value]) -> Result<Value, Error> {
    arity("b32dec", arguments.len(), 1, Some(1))?;
    let text = support::any_text(&arguments[0]);
    if let Some(offset) = go_base32_invalid_offset(&text) {
        return Ok(go_error("base32", offset));
    }
    let source: Vec<char> = text.chars().filter(|c| !matches!(c, '\r' | '\n')).collect();
    let padding = source.iter().position(|character| *character == '=');
    let data_length = padding.unwrap_or(source.len());
    let padding_length = source.len() - data_length;
    // Go accepts only the six padding shapes a 5-bit group can need, and only
    // padding made of `=` at the very end of a whole number of 8-character
    // groups. Anything else is a corrupt input, reported like one.
    let shaped = matches!(
        (data_length % 8, padding_length),
        (0, 0) | (2, 6) | (4, 4) | (5, 3) | (7, 1)
    );
    if !source.len().is_multiple_of(8)
        || padding.is_some_and(|start| source[start..].iter().any(|c| *c != '=') || !shaped)
    {
        return Ok(go_error(
            "base32",
            go_base32_padding_offset(&text, source.len(), padding),
        ));
    }
    let mut bytes = Vec::new();
    let mut buffer = 0_u32;
    let mut bits = 0_u32;
    for character in &source[..data_length] {
        let Some(value) = base32_value(*character) else {
            return Err(invalid("b32dec", "valid base32 input"));
        };
        buffer = (buffer << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            // The shift leaves the byte at the bottom and whatever came before it
            // above, so the narrowing takes exactly the byte the group spells.
            bytes.push(
                u8::try_from((buffer >> (bits - 8)) & 0xff).expect("a masked value fits in a byte"),
            );
            bits -= 8;
        }
    }
    Ok(Value::String(String::from_utf8_lossy(&bytes).into_owned()))
}

/// Serializes a value as JSON in one of the three spellings.
fn to_json(arguments: &[Value], layout: Layout) -> Result<Value, Error> {
    arity(layout.helper(), arguments.len(), 1, Some(1))?;
    let mut out = String::new();
    write_value(&mut out, &arguments[0], layout, 0);
    Ok(Value::String(out))
}

/// Parses JSON, answering an empty string for anything unreadable.
///
/// `FromJson` renders its argument first and parses that text, so a list or map
/// argument is read as the text it renders to — `[1 2]` — which is not JSON and
/// therefore yields the empty string. A document that is valid JSON but not an
/// object, such as `1`, is a number.
fn from_json(arguments: &[Value]) -> Result<Value, Error> {
    arity("fromJson", arguments.len(), 1, Some(1))?;
    let text = support::any_text(&arguments[0]);
    Ok(parse_json(&text).unwrap_or_else(|| Value::String(String::new())))
}

/// Renders every element of a list as a string.
///
/// `ToStrings` drops the null elements, accepts a scalar as a one-element list,
/// and answers a null argument with an empty list. So `{{ list 1 nil 2 | toStrings }}`
/// renders `[1 2]` — the missing element leaves no gap to line up columns with.
fn to_strings(arguments: &[Value]) -> Result<Value, Error> {
    arity("toStrings", arguments.len(), 1, Some(1))?;
    let values = arguments[0]
        .as_list()
        .iter()
        .filter(|value| !matches!(value, Value::Null))
        .map(|value| Value::String(value.render()))
        .collect();
    Ok(Value::List(values))
}

/// The bytes a helper encodes.
///
/// The reference reads its argument with `S`, which renders any value, so a
/// number or boolean encodes as the text it prints as. A list renders in the
/// structural form `Value::render` gives it, which is what a template that
/// encodes the wrong thing would have written anyway.
fn argument_bytes(arguments: &[Value]) -> Vec<u8> {
    support::any_text(&arguments[0]).into_bytes()
}

/// Returns the six-bit value of a base32 character.
fn base32_value(character: char) -> Option<u8> {
    BASE32
        .iter()
        .position(|byte| *byte as char == character)
        .and_then(|index| u8::try_from(index).ok())
}

/// Returns the six-bit value of a base64 character.
fn base64_value(byte: u8) -> Option<u8> {
    BASE64
        .iter()
        .position(|candidate| *candidate == byte)
        .and_then(|index| u8::try_from(index).ok())
}

/// Encodes bytes as padded standard base64.
fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let second = u32::from(chunk.get(1).copied().unwrap_or_default());
        let third = u32::from(chunk.get(2).copied().unwrap_or_default());
        let group = (u32::from(chunk[0]) << 16) | (second << 8) | third;
        out.push(BASE64[(group >> 18) as usize & 63] as char);
        out.push(BASE64[(group >> 12) as usize & 63] as char);
        out.push(match chunk.len() {
            1 => '=',
            _ => BASE64[(group >> 6) as usize & 63] as char,
        });
        out.push(match chunk.len() {
            3 => BASE64[group as usize & 63] as char,
            _ => '=',
        });
    }
    out
}

/// Decodes padded standard base64, or `None` for input that is not base64.
///
/// The rules are the ones `Convert.FromBase64String` applies, because that is
/// what the reference decodes with: the length is a multiple of four, and the
/// only padding is one or two `=` at the very end.
fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let data_length = match bytes.iter().position(|byte| *byte == b'=') {
        Some(first)
            if matches!(bytes.len() - first, 1 | 2)
                && bytes[first..].iter().all(|byte| *byte == b'=') =>
        {
            first
        }
        Some(_) => return None,
        None => bytes.len(),
    };
    let sextets = bytes[..data_length]
        .iter()
        .map(|byte| base64_value(*byte))
        .collect::<Option<Vec<u8>>>()?;
    let mut out = Vec::with_capacity(sextets.len() * 3 / 4);
    for group in sextets.chunks(4) {
        let mut bits = 0_u32;
        for (position, sextet) in group.iter().enumerate() {
            bits |= u32::from(*sextet) << (18 - 6 * position);
        }
        for position in 0..group.len() * 6 / 8 {
            out.push(
                u8::try_from((bits >> (16 - 8 * position)) & 0xff)
                    .expect("a masked value fits in a byte"),
            );
        }
    }
    Some(out)
}

/// Drops the carriage returns and newlines a wrapped encoding carries.
///
/// Go's decoders skip both anywhere in their input, so a base64 value that was
/// folded across lines still decodes.
fn strip_line_breaks(text: &str) -> String {
    text.chars().filter(|c| !matches!(c, '\r' | '\n')).collect()
}

/// Renders Go's `base64.CorruptInputError` text.
fn go_error(encoding: &str, offset: usize) -> Value {
    Value::String(format!("illegal {encoding} data at input byte {offset}"))
}

/// Returns the byte offset of the first character that is not in the alphabet.
///
/// This is the offset Go reports for a character it cannot read at all, which is
/// why `{{ b64dec "!" }}` says byte `0` rather than complaining about length.
fn go_base64_invalid_offset(value: &str) -> Option<usize> {
    value.char_indices().find_map(|(index, character)| {
        let readable =
            matches!(character, '\r' | '\n' | '=' | '+' | '/') || character.is_ascii_alphanumeric();
        (!readable).then_some(index)
    })
}

/// Returns the offset Go reports for a base64 input of the wrong length.
///
/// Go points at the first padding character, or at the start of the last
/// incomplete quantum when there is no padding at all.
fn go_base64_padding_offset(value: &str) -> usize {
    let kept: Vec<(usize, char)> = value
        .char_indices()
        .filter(|(_, character)| !matches!(character, '\r' | '\n'))
        .collect();
    if let Some((offset, _)) = kept.iter().find(|(_, character)| *character == '=') {
        return *offset;
    }
    let quantum_start = kept.len() - (kept.len() % 4);
    if quantum_start == kept.len() {
        value.len()
    } else {
        kept[quantum_start].0
    }
}

/// Returns the byte offset of the first character outside the base32 alphabet.
fn go_base32_invalid_offset(value: &str) -> Option<usize> {
    value.char_indices().find_map(|(index, character)| {
        let readable = matches!(character, '\r' | '\n' | '=')
            || character.is_ascii_uppercase()
            || matches!(character, '2'..='7');
        (!readable).then_some(index)
    })
}

/// Returns the offset Go reports for a base32 input of the wrong shape.
///
/// `source_length` is the length of the input with its line breaks removed, and
/// `padding` the position of the first `=` in it, if any.
fn go_base32_padding_offset(value: &str, source_length: usize, padding: Option<usize>) -> usize {
    let target = padding.unwrap_or(source_length - (source_length % 8));
    let mut normalized = 0_usize;
    for (index, character) in value.char_indices() {
        if matches!(character, '\r' | '\n') {
            continue;
        }
        if normalized == target {
            return index;
        }
        normalized += 1;
    }
    value.len()
}

/// Writes one JSON value, indenting when the layout asks for it.
fn write_value(out: &mut String, value: &Value, layout: Layout, depth: usize) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(flag) => out.push_str(if *flag { "true" } else { "false" }),
        Value::Number(number) => out.push_str(&json_number(*number)),
        // A float that came from `1.0` is written `1.0`, which is what the
        // reference does: it keeps the literal's scale rather than normalising
        // it away.
        Value::Float(number) => out.push_str(&super::render_float(*number)),
        // An object serializes as its display string, because that is what the
        // value reads as everywhere else.
        Value::Object { display, .. } => {
            write_string(out, display, layout);
        }
        // A method has no JSON form, and a template that serializes one is
        // asking for something that cannot be represented; the reference's JSON
        // writer raises rather than inventing a spelling.
        Value::Method { helper, .. } => {
            out.push('"');
            out.push_str(helper);
            out.push('"');
        }
        Value::String(text) => write_string(out, text, layout),
        Value::List(values) => {
            // An empty list stays on one line; the writer has nothing to indent.
            if values.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (index, item) in values.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_break(out, layout, depth + 1);
                write_value(out, item, layout, depth + 1);
            }
            write_break(out, layout, depth);
            out.push(']');
        }
        Value::Map(entries) => {
            if entries.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push('{');
            for (index, (key, item)) in entries.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_break(out, layout, depth + 1);
                write_string(out, key, layout);
                out.push(':');
                if layout.is_indented() {
                    out.push(' ');
                }
                write_value(out, item, layout, depth + 1);
            }
            write_break(out, layout, depth);
            out.push('}');
        }
    }
}

/// Starts a new indented line, or writes nothing in a compact layout.
///
/// The writer uses `\n` for its line ending and two spaces per level, which is
/// what makes `toPrettyJson (dict "key" "value")` a three-line document.
fn write_break(out: &mut String, layout: Layout, depth: usize) {
    if layout.is_indented() {
        out.push('\n');
        out.extend(std::iter::repeat_n(' ', depth * 2));
    }
}

/// Writes a JSON string, escaping it the way the layout's encoder does.
///
/// `toJson` and `toPrettyJson` use .NET's default encoder, which escapes
/// everything outside printable ASCII as well as the characters that would be
/// unsafe inside HTML — including the quote, which becomes `\\u0022` rather
/// than `\\"` — and then the reference lowercases every escape it wrote.
/// `toRawJson` uses the relaxed encoder, which escapes only the two characters
/// JSON itself reserves and the control characters, and keeps the uppercase hex
/// digits the writer chose.
fn write_string(out: &mut String, text: &str, layout: Layout) {
    let relaxed = layout.is_relaxed();
    out.push('"');
    for character in text.chars() {
        match character {
            '"' if relaxed => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{0c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            _ if unescaped(character, relaxed) => out.push(character),
            // Everything else becomes one escape per UTF-16 code unit, so a
            // character outside the basic plane is written as the surrogate pair
            // .NET writes for it.
            _ => {
                let mut units = [0_u16; 2];
                for unit in character.encode_utf16(&mut units) {
                    write_unit_escape(out, *unit, relaxed);
                }
            }
        }
    }
    out.push('"');
}

/// Reports whether a character is written as itself under an encoder.
fn unescaped(character: char, relaxed: bool) -> bool {
    if relaxed {
        relaxed_allows(u32::from(character))
    } else {
        // The default encoder keeps printable ASCII, minus the characters that
        // would be unsafe to embed in an HTML document. The quote is one of them,
        // which is why it is written as a `u` escape rather than as `\"`.
        matches!(character, ' '..='~')
            && !matches!(character, '"' | '\\' | '&' | '\'' | '+' | '<' | '>' | '`')
    }
}

/// Reports whether the relaxed encoder's allow-list covers a code point.
///
/// The list is sorted and disjoint, so the entry that could cover a code point is
/// the first one whose end reaches it.
fn relaxed_allows(code: u32) -> bool {
    let index = RELAXED_ALLOWED.partition_point(|(_, last)| *last < code);
    RELAXED_ALLOWED
        .get(index)
        .is_some_and(|(first, _)| *first <= code)
}

/// Writes a `\\uXXXX` escape for one UTF-16 code unit.
fn write_unit_escape(out: &mut String, unit: u16, relaxed: bool) {
    const LOWER: &[u8; 16] = b"0123456789abcdef";
    const UPPER: &[u8; 16] = b"0123456789ABCDEF";
    let digits = if relaxed { UPPER } else { LOWER };
    out.push_str("\\u");
    for shift in [12, 8, 4, 0] {
        out.push(char::from(digits[usize::from(unit >> shift) & 0xf]));
    }
}

/// Formats a number the way Go's `encoding/json` writes a `float64`.
///
/// This is not the rule `Value::render` follows. A rendered template switches to
/// exponent form at `1e+06`, because that is what `text/template` prints, while a
/// JSON number stays in decimal form until it leaves the range Go considers
/// reasonable: below `1e-6` or at `1e21` and above it goes exponential, with a
/// signed exponent and no padding on a negative one.
///
/// A `Value` number is an `f64`, so it cannot remember how many digits a literal
/// had: `fromJson "1.0" | toJson` answers `1` here, where the reference's decimal
/// answers `1.0`, and `fromJson "-0"` answers `-0` where the decimal answers `0`.
/// Go answers as this does. Preserving the scale would mean changing the value
/// model, which is a larger decision than a JSON helper should make on its own.
fn json_number(value: f64) -> String {
    // The reference stores numbers as decimals, which cannot hold a NaN or an
    // infinity, so there is no JSON spelling of one to copy.
    if !value.is_finite() {
        return Value::Number(value).render();
    }
    let magnitude = value.abs();
    if magnitude != 0.0 && !(1e-6..1e21).contains(&magnitude) {
        return json_exponent(value);
    }
    format!("{value}")
}

/// Writes a number in Go's JSON exponent form.
fn json_exponent(value: f64) -> String {
    let rendered = format!("{value:e}");
    let (mantissa, exponent) = rendered
        .split_once('e')
        .expect("Rust's exponential formatting always has an exponent");
    let exponent: i32 = exponent
        .parse()
        .expect("Rust's exponential formatting writes a decimal exponent");
    let digits = exponent.unsigned_abs();
    // Go pads the exponent to two digits and then takes the padding back off a
    // negative one, so `1e-7` is written with one digit and `1e-10` with two.
    let written = if exponent < 0 && digits < 10 {
        digits.to_string()
    } else {
        format!("{digits:02}")
    };
    format!(
        "{mantissa}e{}{written}",
        if exponent < 0 { '-' } else { '+' }
    )
}

/// Parses a JSON document, or `None` for anything unreadable.
fn parse_json(text: &str) -> Option<Value> {
    let mut parser = Parser { rest: text };
    let value = parser.value()?;
    parser.skip_whitespace();
    parser.rest.is_empty().then_some(value)
}

/// A recursive-descent reader over one JSON document.
struct Parser<'a> {
    rest: &'a str,
}

impl Parser<'_> {
    /// Skips the whitespace JSON allows between tokens.
    fn skip_whitespace(&mut self) {
        self.rest = self.rest.trim_start_matches([' ', '\t', '\n', '\r']);
    }

    /// Returns the next character without consuming it.
    fn peek(&self) -> Option<char> {
        self.rest.chars().next()
    }

    /// Consumes one character if it is the expected one.
    fn eat(&mut self, expected: char) -> Option<()> {
        let mut characters = self.rest.chars();
        (characters.next()? == expected).then(|| {
            self.rest = characters.as_str();
        })
    }

    /// Consumes the next character whatever it is.
    fn take(&mut self) -> Option<char> {
        let mut characters = self.rest.chars();
        let character = characters.next()?;
        self.rest = characters.as_str();
        Some(character)
    }

    /// Reads any JSON value.
    fn value(&mut self) -> Option<Value> {
        self.skip_whitespace();
        match self.peek()? {
            '{' => self.object(),
            '[' => self.array(),
            '"' => self.string().map(Value::String),
            't' => self.literal("true", Value::Bool(true)),
            'f' => self.literal("false", Value::Bool(false)),
            'n' => self.literal("null", Value::Null),
            _ => self.number(),
        }
    }

    /// Reads a `null`, `true`, or `false` keyword.
    fn literal(&mut self, word: &str, value: Value) -> Option<Value> {
        if self.rest.starts_with(word) {
            self.rest = &self.rest[word.len()..];
            Some(value)
        } else {
            None
        }
    }

    /// Reads an object, with a repeated key keeping its last value.
    fn object(&mut self) -> Option<Value> {
        self.eat('{')?;
        let mut entries = std::collections::BTreeMap::new();
        self.skip_whitespace();
        if self.peek()? == '}' {
            self.eat('}')?;
            return Some(Value::Map(entries));
        }
        loop {
            self.skip_whitespace();
            let key = self.string()?;
            self.skip_whitespace();
            self.eat(':')?;
            let value = self.value()?;
            entries.insert(key, value);
            self.skip_whitespace();
            match self.peek()? {
                ',' => {
                    self.eat(',')?;
                }
                '}' => {
                    self.eat('}')?;
                    return Some(Value::Map(entries));
                }
                _ => return None,
            }
        }
    }

    /// Reads an array.
    fn array(&mut self) -> Option<Value> {
        self.eat('[')?;
        let mut values = Vec::new();
        self.skip_whitespace();
        if self.peek()? == ']' {
            self.eat(']')?;
            return Some(Value::List(values));
        }
        loop {
            values.push(self.value()?);
            self.skip_whitespace();
            match self.peek()? {
                ',' => {
                    self.eat(',')?;
                }
                ']' => {
                    self.eat(']')?;
                    return Some(Value::List(values));
                }
                _ => return None,
            }
        }
    }

    /// Reads a string, resolving its escapes.
    fn string(&mut self) -> Option<String> {
        self.eat('"')?;
        let mut out = String::new();
        loop {
            match self.take()? {
                '"' => return Some(out),
                // A raw control character is not legal inside a JSON string.
                character if (character as u32) < 0x20 => return None,
                '\\' => out.push(self.escape()?),
                character => out.push(character),
            }
        }
    }

    /// Reads the character after a backslash.
    fn escape(&mut self) -> Option<char> {
        match self.take()? {
            '"' => Some('"'),
            '\\' => Some('\\'),
            '/' => Some('/'),
            'b' => Some('\u{08}'),
            'f' => Some('\u{0c}'),
            'n' => Some('\n'),
            'r' => Some('\r'),
            't' => Some('\t'),
            'u' => self.unicode_escape(),
            _ => None,
        }
    }

    /// Reads a `\\uXXXX` escape, joining a surrogate pair when there is one.
    fn unicode_escape(&mut self) -> Option<char> {
        let first = self.hex4()?;
        if (0xd800..0xdc00).contains(&first) {
            let unpaired = self.rest;
            if let (Some(()), Some(()), Some(second)) = (self.eat('\\'), self.eat('u'), self.hex4())
                && (0xdc00..0xe000).contains(&second)
            {
                let combined =
                    0x1_0000 + ((u32::from(first) - 0xd800) << 10) + (u32::from(second) - 0xdc00);
                return char::from_u32(combined);
            }
            self.rest = unpaired;
        }
        // A surrogate that stands alone is not a character, so it reads as the
        // replacement character rather than failing the whole document.
        char::from_u32(u32::from(first)).or(Some(char::REPLACEMENT_CHARACTER))
    }

    /// Reads four hexadecimal digits.
    fn hex4(&mut self) -> Option<u16> {
        let digits = self.rest.get(..4)?;
        let value = u16::from_str_radix(digits, 16).ok()?;
        self.rest = &self.rest[4..];
        Some(value)
    }

    /// Reads a number, which must follow the JSON grammar and not just the one
    /// `f64` accepts: `01`, `+1`, and `.5` are numbers to Rust and not to JSON.
    fn number(&mut self) -> Option<Value> {
        let end = self
            .rest
            .find(|character: char| !matches!(character, '-' | '+' | '.' | 'e' | 'E' | '0'..='9'))
            .unwrap_or(self.rest.len());
        let token = self.rest.get(..end)?;
        self.rest = &self.rest[end..];
        Some(Value::Number(parse_number(token)?))
    }
}

/// Reads a JSON number literal, or `None` when the token is not one.
fn parse_number(token: &str) -> Option<f64> {
    let (mantissa, exponent) = match token.find(['e', 'E']) {
        Some(at) => (&token[..at], Some(&token[at + 1..])),
        None => (token, None),
    };
    // A minus sign belongs to the number, not to its integer part, and JSON
    // allows it only there and in the exponent.
    let mantissa = mantissa.strip_prefix('-').unwrap_or(mantissa);
    let (integer, fraction) = match mantissa.find('.') {
        Some(at) => (&mantissa[..at], Some(&mantissa[at + 1..])),
        None => (mantissa, None),
    };
    let all_digits =
        |part: &str| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit());
    if !all_digits(integer) || (integer.len() > 1 && integer.starts_with('0')) {
        return None;
    }
    if fraction.is_some_and(|part| !all_digits(part)) {
        return None;
    }
    if exponent.is_some_and(|part| !all_digits(part.strip_prefix('-').unwrap_or(part))) {
        return None;
    }
    token.parse::<f64>().ok()
}

#[cfg(test)]
mod tests {
    use super::{Context, Error, Value, base64_encode, dispatch};
    use std::collections::BTreeMap;

    /// Calls an encoding helper, so a test cannot pass by accident on a name this
    /// module does not claim.
    fn helper(name: &str, arguments: &[Value]) -> Result<Value, Error> {
        match dispatch(name, arguments, &Context::default()) {
            Some(result) => result,
            None => panic!("{name} is not an encoding helper"),
        }
    }

    fn text(value: &str) -> Value {
        Value::String((*value).to_owned())
    }

    fn number(value: f64) -> Value {
        Value::Number(value)
    }

    /// Builds a map, for readable JSON expectations.
    fn map(entries: &[(&str, Value)]) -> Value {
        Value::Map(
            entries
                .iter()
                .map(|(key, value)| ((*key).to_owned(), value.clone()))
                .collect::<BTreeMap<_, _>>(),
        )
    }

    /// The single string a helper that answers with text produced.
    fn answer(name: &str, argument: &str) -> String {
        match helper(name, &[text(argument)]).expect("helper") {
            Value::String(answer) => answer,
            other => panic!("{name} answered with {}", other.render()),
        }
    }

    /// The `u` escape sequence an encoder writes for a string, one escape per
    /// UTF-16 code unit and in the hex case that encoder uses.
    ///
    /// Expectations are built from this rather than written out, because a
    /// literal escape in a test reads as a Rust escape and because the whole
    /// point of the two encoders is which case they use. It is applied to the one
    /// character under test, never to a whole string, so the test also says that
    /// the characters around it were left alone.
    fn escapes(value: &str, upper: bool) -> String {
        value
            .encode_utf16()
            .map(|unit| {
                if upper {
                    format!("\\u{unit:04X}")
                } else {
                    format!("\\u{unit:04x}")
                }
            })
            .collect()
    }

    #[test]
    fn claims_only_its_own_helpers() {
        assert!(dispatch("b64enc", &[text("a")], &Context::default()).is_some());
        assert!(dispatch("toStrings", &[], &Context::default()).is_some());
        // `None` hands the name to the next module.
        assert!(dispatch("upper", &[text("a")], &Context::default()).is_none());
        assert!(!super::takes_rendered_strings("toJson"));
    }

    #[test]
    fn every_helper_takes_exactly_one_argument() {
        for name in [
            "b64enc",
            "b64dec",
            "b32enc",
            "b32dec",
            "toJson",
            "toPrettyJson",
            "toRawJson",
            "fromJson",
            "toStrings",
        ] {
            let error = helper(name, &[]).expect_err(name);
            assert!(
                matches!(&error, Error::WrongArgumentCount { expected, actual: 0, .. } if expected == "1"),
                "{name}: {error:?}"
            );
            let error = helper(name, &[text("a"), text("b")]).expect_err(name);
            assert!(
                matches!(error, Error::WrongArgumentCount { actual: 2, .. }),
                "{name}: {error:?}"
            );
        }
    }

    #[test]
    fn b64enc_pads_to_a_multiple_of_four() {
        // fixtures/sprig/upstream_parity.json[25]: {{ b64enc "neo" }} renders `bmVv`.
        assert_eq!(answer("b64enc", "neo"), "bmVv");
        // `Convert.ToBase64String` writes the padded standard form, so a partial
        // group keeps one or two `=`.
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(answer("b64enc", "f"), "Zg==");
        assert_eq!(answer("b64enc", "fo"), "Zm8=");
        assert_eq!(answer("b64enc", "foo"), "Zm9v");
        assert_eq!(answer("b64enc", "foob"), "Zm9vYg==");
        assert_eq!(answer("b64enc", "fooba"), "Zm9vYmE=");
        assert_eq!(answer("b64enc", "foobar"), "Zm9vYmFy");
        assert_eq!(answer("b64enc", ""), "");
        // The bytes are UTF-8, so a character outside ASCII costs its own bytes.
        assert_eq!(answer("b64enc", "é"), "w6k=");
        assert_eq!(answer("b64enc", "☃"), "4piD");
    }

    #[test]
    fn b64dec_reverses_b64enc() {
        for plain in ["", "f", "fo", "foo", "foob", "fooba", "foobar", "é", "☃"] {
            let encoded = answer("b64enc", plain);
            assert_eq!(answer("b64dec", &encoded), plain, "{plain}");
        }
    }

    #[test]
    fn b64dec_reports_go_corrupt_input_text() {
        // SprigUpstreamParityTests.Base64DecodeReturnsGoErrorsAsText:
        // {{ b64dec "!" }} renders `illegal base64 data at input byte 0`.
        assert_eq!(answer("b64dec", "!"), "illegal base64 data at input byte 0");
        // A character it cannot read at all is reported at its own byte offset.
        assert_eq!(
            answer("b64dec", "Zm9v!"),
            "illegal base64 data at input byte 4"
        );
        // A length that is not a whole number of quanta is reported at the
        // padding, or at the start of the incomplete quantum when there is none.
        assert_eq!(
            answer("b64dec", "Zg="),
            "illegal base64 data at input byte 2"
        );
        assert_eq!(
            answer("b64dec", "Zm9vYg="),
            "illegal base64 data at input byte 6"
        );
        assert_eq!(
            answer("b64dec", "Zm9vY"),
            "illegal base64 data at input byte 4"
        );
        // Padding that is not one or two `=` at the very end is the same message,
        // reported at the first `=`.
        assert_eq!(
            answer("b64dec", "Zg==Zg=="),
            "illegal base64 data at input byte 2"
        );
        assert_eq!(
            answer("b64dec", "Zm=v"),
            "illegal base64 data at input byte 2"
        );
    }

    #[test]
    fn b64dec_skips_line_breaks() {
        // Go's decoders ignore a wrapped encoding, so a base64 value folded
        // across lines still decodes.
        assert_eq!(answer("b64dec", "Zm9v\nYmFy"), "foobar");
        assert_eq!(answer("b64dec", "Zm9v\r\nYmFy"), "foobar");
    }

    #[test]
    fn b32enc_pads_to_a_multiple_of_eight() {
        // fixtures/sprig/upstream_parity.json[152]: {{ b32enc "foo" }} => MZXW6===
        assert_eq!(answer("b32enc", "foo"), "MZXW6===");
        assert_eq!(answer("b32enc", ""), "");
        assert_eq!(answer("b32enc", "f"), "MY======");
        assert_eq!(answer("b32enc", "fo"), "MZXQ====");
        assert_eq!(answer("b32enc", "foob"), "MZXW6YQ=");
        assert_eq!(answer("b32enc", "fooba"), "MZXW6YTB");
        assert_eq!(answer("b32enc", "foobar"), "MZXW6YTBOI======");
    }

    #[test]
    fn b32dec_reverses_b32enc() {
        for plain in ["", "f", "fo", "foo", "foob", "fooba", "foobar", "☃"] {
            let encoded = answer("b32enc", plain);
            assert_eq!(answer("b32dec", &encoded), plain, "{plain}");
        }
        // SprigUpstreamParityTests.Base32DecodeUsesGoInputRules:
        // {{ b32dec "MZXW6===" }} renders `foo`.
        assert_eq!(answer("b32dec", "MZXW6==="), "foo");
        assert_eq!(answer("b32dec", "MZXW6YTBOI======"), "foobar");
    }

    #[test]
    fn b32dec_reports_go_corrupt_input_text() {
        // SprigUpstreamParityTests.Base32DecodeUsesGoInputRules:
        // {{ b32dec "mzxq====" }} renders `illegal base32 data at input byte 0`,
        // because the base32 alphabet is upper-case.
        assert_eq!(
            answer("b32dec", "mzxq===="),
            "illegal base32 data at input byte 0"
        );
        assert_eq!(
            answer("b32dec", "MZXW6!!="),
            "illegal base32 data at input byte 5"
        );
        // A length that is not a whole number of eight-character groups is
        // reported at the padding, or at the start of the incomplete group when
        // there is none.
        assert_eq!(
            answer("b32dec", "MY"),
            "illegal base32 data at input byte 0"
        );
        assert_eq!(
            answer("b32dec", "MZXW6="),
            "illegal base32 data at input byte 5"
        );
        // Padding of a shape Go does not accept is reported too: eight data
        // characters need no padding, so two `=` cannot be right. Padding that
        // is not made only of `=` is reported at its own position.
        assert_eq!(
            answer("b32dec", "MZXW6YTB=="),
            "illegal base32 data at input byte 8"
        );
        assert_eq!(
            answer("b32dec", "MZXW6YT=A"),
            "illegal base32 data at input byte 7"
        );
        // Eight data characters need no padding, and seven of them padded out to
        // a whole group is the one truncated shape Go accepts: the five bits it
        // leaves over are dropped.
        assert_eq!(answer("b32dec", "MZXW6YQ="), "foob");
        assert_eq!(answer("b32dec", "MZXW6YTB"), "fooba");
    }

    #[test]
    fn to_json_writes_compact_json_with_ordinal_keys() {
        // fixtures/sprig/upstream_parity.json[173]: {{ mustToJson (dict "key" "value") }}
        // renders {"key":"value"}, and `toJson` writes the same bytes.
        assert_eq!(
            helper("toJson", &[map(&[("key", text("value"))])]).expect("toJson"),
            text("{\"key\":\"value\"}")
        );
        // fixtures/sprig/upstream_parity.json[175]: {{ mustToRawJson (dict "key" "value") }}
        // renders the same bytes, because there is nothing here to escape.
        assert_eq!(
            helper("toRawJson", &[map(&[("key", text("value"))])]).expect("toRawJson"),
            text("{\"key\":\"value\"}")
        );
        // A map is a `SortedDictionary` in the reference, so its keys are written
        // in ordinal order whatever order they were given in.
        let entries = map(&[("b", number(2.0)), ("a", number(1.0))]);
        assert_eq!(
            helper("toJson", &[entries]).expect("toJson"),
            text("{\"a\":1,\"b\":2}")
        );
        assert_eq!(
            helper("toJson", &[Value::List(vec![number(1.0), number(2.0)])]).expect("toJson"),
            text("[1,2]")
        );
        assert_eq!(
            helper("toJson", &[Value::Null]).expect("toJson"),
            text("null")
        );
        assert_eq!(
            helper("toJson", &[Value::Bool(true)]).expect("toJson"),
            text("true")
        );
        assert_eq!(
            helper("toJson", &[Value::Bool(false)]).expect("toJson"),
            text("false")
        );
        // UpstreamNilCollectionContractsWork: {{ dict "value" nil | toJson }}
        // renders {"value":null}.
        assert_eq!(
            helper("toJson", &[map(&[("value", Value::Null)])]).expect("toJson"),
            text("{\"value\":null}")
        );
        // A bare string is a JSON string, not a document.
        assert_eq!(
            helper("toJson", &[text("text")]).expect("toJson"),
            text("\"text\"")
        );
        // An empty container is written on one line, indented or not.
        assert_eq!(helper("toJson", &[map(&[])]).expect("toJson"), text("{}"));
        assert_eq!(
            helper("toJson", &[Value::List(vec![])]).expect("toJson"),
            text("[]")
        );
    }

    #[test]
    fn to_json_escapes_strings_for_html() {
        // SprigUpstreamParityTests.RawJsonPreservesHtmlCharactersLikeUpstream pins
        // the difference: {{ dict "html" "<HEAD>" | toJson }} writes escapes for
        // the angle brackets, and | toRawJson writes the characters.
        let html = map(&[("html", text("<HEAD>"))]);
        let escaped = format!(
            "{{\"html\":\"{}HEAD{}\"}}",
            escapes("<", false),
            escapes(">", false)
        );
        assert_eq!(escaped, "{\"html\":\"\\u003cHEAD\\u003e\"}");
        assert_eq!(
            helper("toJson", std::slice::from_ref(&html)).expect("toJson"),
            text(&escaped)
        );
        assert_eq!(
            helper("toRawJson", &[html]).expect("toRawJson"),
            text("{\"html\":\"<HEAD>\"}")
        );
        // The default encoder escapes the quote as `u0022` rather than `\"`, and
        // the relaxed one writes `\"`.
        assert_eq!(escapes("\"", false), "\\u0022");
        assert_eq!(
            helper("toJson", &[text("a\"b")]).expect("toJson"),
            text(&format!("\"a{}b\"", escapes("\"", false)))
        );
        assert_eq!(
            helper("toRawJson", &[text("a\"b")]).expect("toRawJson"),
            text("\"a\\\"b\"")
        );
        // A backslash is the one character both encoders write the same way.
        assert_eq!(
            helper("toJson", &[text("a\\b")]).expect("toJson"),
            text("\"a\\\\b\"")
        );
        assert_eq!(
            helper("toRawJson", &[text("a\\b")]).expect("toRawJson"),
            text("\"a\\\\b\"")
        );
        // The other characters the default encoder treats as unsafe in HTML, each
        // escaped where it stands, and the ones it leaves alone.
        let html_punctuation = "a&b'c+d";
        let escaped_punctuation = html_punctuation
            .chars()
            .map(|character| {
                if matches!(character, '&' | '\'' | '+') {
                    escapes(&character.to_string(), false)
                } else {
                    character.to_string()
                }
            })
            .collect::<String>();
        assert_eq!(escaped_punctuation, "a\\u0026b\\u0027c\\u002bd");
        assert_eq!(
            helper("toJson", &[text(html_punctuation)]).expect("toJson"),
            text(&format!("\"{escaped_punctuation}\""))
        );
        assert_eq!(
            helper("toRawJson", &[text(html_punctuation)]).expect("toRawJson"),
            text("\"a&b'c+d\"")
        );
        assert_eq!(
            helper("toJson", &[text("a/b~c")]).expect("toJson"),
            text("\"a/b~c\"")
        );
    }

    #[test]
    fn to_json_escapes_everything_outside_printable_ascii() {
        // The default encoder escapes every non-ASCII character, and a character
        // outside the basic plane becomes the surrogate pair .NET writes for it.
        let snowman = "☃";
        assert_eq!(escapes(snowman, false), "\\u2603");
        assert_eq!(
            helper("toJson", &[text(snowman)]).expect("toJson"),
            text(&format!("\"{}\"", escapes(snowman, false)))
        );
        let grinning = "\u{1f600}";
        let pair = escapes(grinning, false);
        assert_eq!(pair, "\\ud83d\\ude00");
        assert_eq!(
            helper("toJson", &[text(grinning)]).expect("toJson"),
            text(&format!("\"{pair}\""))
        );
        // A combining mark is a character of its own, so `e` stays a letter and
        // only the mark is escaped.
        let combining = "e\u{301}";
        assert_eq!(escapes("\u{301}", false), "\\u0301");
        assert_eq!(
            helper("toJson", &[text(combining)]).expect("toJson"),
            text(&format!("\"e{}\"", escapes("\u{301}", false)))
        );
    }

    #[test]
    fn to_raw_json_keeps_only_what_its_encoder_allows() {
        // The relaxed encoder is not "everything printable": its allow-list is
        // most of Unicode with a few holes in it, and a character outside the
        // basic multilingual plane is always outside it.
        assert_eq!(
            helper("toRawJson", &[text("caf\u{e9}")]).expect("toRawJson"),
            text("\"caf\u{e9}\"")
        );
        assert_eq!(
            helper("toRawJson", &[text("☃")]).expect("toRawJson"),
            text("\"☃\"")
        );
        assert_eq!(
            helper("toRawJson", &[text("e\u{301}")]).expect("toRawJson"),
            text("\"e\u{301}\"")
        );
        assert_eq!(
            helper("toRawJson", &[text("\u{4e2d}\u{6587}")]).expect("toRawJson"),
            text("\"\u{4e2d}\u{6587}\"")
        );
        // The no-break space and the line separator are in the holes, and a
        // character outside the basic multilingual plane is written as the
        // surrogate pair the writer produced.
        assert_eq!(
            helper("toRawJson", &[text("\u{a0}")]).expect("toRawJson"),
            text("\"\\u00A0\"")
        );
        assert_eq!(
            helper("toRawJson", &[text("\u{2028}")]).expect("toRawJson"),
            text("\"\\u2028\"")
        );
        let grinning = "\u{1f600}";
        let pair = escapes(grinning, true);
        assert_eq!(pair, "\\uD83D\\uDE00");
        assert_eq!(
            helper("toRawJson", &[text(grinning)]).expect("toRawJson"),
            text(&format!("\"{pair}\""))
        );
        // The default encoder escapes all of those, in lower case.
        assert_eq!(
            helper("toJson", &[text("\u{a0}")]).expect("toJson"),
            text("\"\\u00a0\"")
        );
        assert_eq!(
            helper("toJson", &[text(grinning)]).expect("toJson"),
            text("\"\\ud83d\\ude00\"")
        );
    }

    #[test]
    fn both_encoders_escape_control_characters() {
        // Both encoders give the five control characters that have a short form a
        // short escape, and write a `u` escape for every other one below 0x20.
        // The relaxed encoder keeps the upper-case hex the writer chose, which is
        // the one visible difference here.
        let controls = "a\nb\tc\u{8}d\u{c}e\rf\u{b}\u{1}";
        assert_eq!(
            helper("toJson", &[text(controls)]).expect("toJson"),
            text("\"a\\nb\\tc\\bd\\fe\\rf\\u000b\\u0001\"")
        );
        assert_eq!(
            helper("toRawJson", &[text(controls)]).expect("toRawJson"),
            text("\"a\\nb\\tc\\bd\\fe\\rf\\u000B\\u0001\"")
        );
        // The two encoders differ in the case of the hex digits: the reference
        // lower-cases every escape the default encoder wrote and leaves the
        // relaxed encoder's alone.
        assert_eq!(escapes("\u{7f}", false), "\\u007f");
        assert_eq!(escapes("\u{7f}", true), "\\u007F");
        assert_eq!(
            helper("toJson", &[text("\u{7f}")]).expect("toJson"),
            text("\"\\u007f\"")
        );
        assert_eq!(
            helper("toRawJson", &[text("\u{7f}")]).expect("toRawJson"),
            text("\"\\u007F\"")
        );
    }

    #[test]
    fn to_pretty_json_indents_by_two_spaces() {
        // fixtures/sprig/upstream_parity.json[180]: {{ toPrettyJson (dict "key" "value") }}
        // renders three lines, and the `must` spelling in [174] renders the same.
        let expected = "{\n  \"key\": \"value\"\n}";
        assert_eq!(
            helper("toPrettyJson", &[map(&[("key", text("value"))])]).expect("toPrettyJson"),
            text(expected)
        );
        assert_eq!(
            helper("toRawJson", &[map(&[("key", text("value"))])]).expect("toRawJson"),
            text("{\"key\":\"value\"}")
        );
    }

    #[test]
    fn to_pretty_json_nests_and_keeps_empty_containers_on_one_line() {
        // `Utf8JsonWriter` indents two spaces per level, indents a nested
        // container, and leaves an empty one on a single line.
        let entries = map(&[("a", Value::List(vec![map(&[("b", number(1.0))])]))]);
        let expected = "{\n  \"a\": [\n    {\n      \"b\": 1\n    }\n  ]\n}";
        assert_eq!(
            helper("toPrettyJson", &[entries]).expect("toPrettyJson"),
            text(expected)
        );
        assert_eq!(
            helper("toPrettyJson", &[map(&[])]).expect("toPrettyJson"),
            text("{}")
        );
        assert_eq!(
            helper("toPrettyJson", &[Value::List(vec![])]).expect("toPrettyJson"),
            text("[]")
        );
        // Two keys are separated by a comma and a newline, not a comma alone.
        let two = map(&[("a", number(1.0)), ("b", number(2.0))]);
        assert_eq!(
            helper("toPrettyJson", &[two]).expect("toPrettyJson"),
            text("{\n  \"a\": 1,\n  \"b\": 2\n}")
        );
    }

    #[test]
    fn json_numbers_follow_go_not_the_template_rule() {
        // Whole numbers stay whole, and a fraction keeps its digits.
        assert_eq!(helper("toJson", &[number(1.0)]).expect("toJson"), text("1"));
        assert_eq!(helper("toJson", &[number(0.0)]).expect("toJson"), text("0"));
        assert_eq!(
            helper("toJson", &[number(-0.0)]).expect("toJson"),
            text("-0")
        );
        assert_eq!(
            helper("toJson", &[number(1.5)]).expect("toJson"),
            text("1.5")
        );
        assert_eq!(
            helper("toJson", &[number(0.1)]).expect("toJson"),
            text("0.1")
        );
        assert_eq!(
            helper("toJson", &[number(-1.5)]).expect("toJson"),
            text("-1.5")
        );
        // `text/template`, which `Value::render` follows, writes `1e+06`; a JSON
        // number stays in decimal form until it is far out of range.
        assert_eq!(
            helper("toJson", &[number(1_000_000.0)]).expect("toJson"),
            text("1000000")
        );
        assert_eq!(
            helper("toJson", &[number(1e20)]).expect("toJson"),
            text("100000000000000000000")
        );
        // Out of that range Go switches to exponent form, with a signed exponent
        // and with the padding taken back off a negative one.
        assert_eq!(
            helper("toJson", &[number(1e21)]).expect("toJson"),
            text("1e+21")
        );
        assert_eq!(
            helper("toJson", &[number(1e-7)]).expect("toJson"),
            text("1e-7")
        );
        assert_eq!(
            helper("toJson", &[number(1.5e-7)]).expect("toJson"),
            text("1.5e-7")
        );
        assert_eq!(
            helper("toJson", &[number(1e-10)]).expect("toJson"),
            text("1e-10")
        );
    }

    #[test]
    fn from_json_parses_into_the_value_model() {
        // fixtures/sprig/upstream_parity.json[77]: {{ fromJson "[1,2]" | toJson }}
        // renders [1,2], so a parsed number survives as a number and the writer
        // gives it back unchanged.
        let parsed = helper("fromJson", &[text("[1,2]")]).expect("fromJson");
        assert_eq!(parsed, Value::List(vec![number(1.0), number(2.0)]));
        assert_eq!(helper("toJson", &[parsed]).expect("toJson"), text("[1,2]"));
        // An object becomes a map, and its members keep their own types.
        let parsed = helper(
            "fromJson",
            &[text(
                "{\"a\":1,\"b\":\"two\",\"c\":null,\"d\":true,\"e\":[1]}",
            )],
        )
        .expect("fromJson");
        assert_eq!(
            parsed,
            map(&[
                ("a", number(1.0)),
                ("b", text("two")),
                ("c", Value::Null),
                ("d", Value::Bool(true)),
                ("e", Value::List(vec![number(1.0)])),
            ])
        );
        // Whitespace around the document is allowed, and a bare scalar is a value.
        assert_eq!(
            helper("fromJson", &[text("  1.5\n")]).expect("fromJson"),
            number(1.5)
        );
        assert_eq!(
            helper("fromJson", &[text("-2")]).expect("fromJson"),
            number(-2.0)
        );
        assert_eq!(
            helper("fromJson", &[text("null")]).expect("fromJson"),
            Value::Null
        );
        assert_eq!(
            helper("fromJson", &[text("\"text\"")]).expect("fromJson"),
            text("text")
        );
        assert_eq!(
            helper("fromJson", &[text("{}")]).expect("fromJson"),
            map(&[])
        );
        assert_eq!(
            helper("fromJson", &[text("[]")]).expect("fromJson"),
            Value::List(vec![])
        );
        // A repeated key keeps its last value. The reference raises on a
        // duplicate here while its own `dict` accepts one, and Go's decoder keeps
        // the last, which is the behavior kept.
        assert_eq!(
            helper("fromJson", &[text("{\"a\":1,\"a\":2}")]).expect("fromJson"),
            map(&[("a", number(2.0))])
        );
    }

    #[test]
    fn from_json_answers_an_unreadable_document_with_an_empty_string() {
        // fixtures/sprig/upstream_parity.json[78]: {{ fromJson "not json" }} is empty.
        assert_eq!(answer("fromJson", "not json"), "");
        // Trailing content, a truncated document, a single-quoted key, and the
        // number spellings JSON does not allow are all unreadable.
        assert_eq!(answer("fromJson", "[1,2] extra"), "");
        assert_eq!(answer("fromJson", "[1,2"), "");
        assert_eq!(answer("fromJson", "{\"a\":1,}"), "");
        assert_eq!(answer("fromJson", "{'a':1}"), "");
        assert_eq!(answer("fromJson", "01"), "");
        assert_eq!(answer("fromJson", "+1"), "");
        assert_eq!(answer("fromJson", ".5"), "");
        assert_eq!(answer("fromJson", "5."), "");
        assert_eq!(answer("fromJson", "1e"), "");
        assert_eq!(answer("fromJson", "trueish"), "");
        assert_eq!(answer("fromJson", ""), "");
        // A raw control character is not legal inside a JSON string.
        assert_eq!(answer("fromJson", "\"a\u{1}b\""), "");
        // `FromJson` renders its argument first, so a list is read as `[1 2]`,
        // which is not JSON, and a map as `map[a:1]`, which is not either.
        assert_eq!(
            helper("fromJson", &[Value::List(vec![number(1.0), number(2.0)])]).expect("fromJson"),
            text("")
        );
        assert_eq!(
            helper("fromJson", &[map(&[("a", number(1.0))])]).expect("fromJson"),
            text("")
        );
    }

    #[test]
    fn from_json_resolves_string_escapes() {
        assert_eq!(
            helper("fromJson", &[text("\"a\\nb\"")]).expect("fromJson"),
            text("a\nb")
        );
        assert_eq!(
            helper("fromJson", &[text("\"a\\u0041b\"")]).expect("fromJson"),
            text("aAb")
        );
        assert_eq!(
            helper("fromJson", &[text("\"\\/\"")]).expect("fromJson"),
            text("/")
        );
        assert_eq!(
            helper("fromJson", &[text("\"a\\\\b\"")]).expect("fromJson"),
            text("a\\b")
        );
        // A surrogate pair is one character, and writing it back out uses the
        // pair of escapes the default encoder writes for it.
        let grinning = "\u{1f600}";
        let pair = escapes(grinning, false);
        let parsed = helper("fromJson", &[text(&format!("\"{pair}\""))]).expect("fromJson");
        assert_eq!(parsed, text(grinning));
        assert_eq!(
            helper("toJson", &[parsed]).expect("fromJson"),
            text(&format!("\"{pair}\""))
        );
        // An unpaired surrogate is not a character, so it reads as the
        // replacement character rather than failing the whole document. The
        // reference raises on one; Go's decoder substitutes, which is what is
        // kept here.
        assert_eq!(
            helper("fromJson", &[text("\"\\ud83d\"")]).expect("fromJson"),
            text("\u{fffd}")
        );
        // An escape that is not one of the eight JSON names is unreadable.
        assert_eq!(answer("fromJson", "\"\\x\""), "");
    }

    #[test]
    fn to_strings_renders_every_element() {
        // UpstreamNilCollectionContractsWork: {{ list 1 nil 2 | toStrings }} renders
        // [1 2], because a null element leaves no element at all.
        assert_eq!(
            helper(
                "toStrings",
                &[Value::List(vec![number(1.0), Value::Null, number(2.0)])]
            )
            .expect("toStrings"),
            Value::List(vec![text("1"), text("2")])
        );
        // ToStringsAcceptsAScalarValueLikeUpstream: a scalar is a one-element
        // list, and a null argument is an empty one.
        assert_eq!(
            helper("toStrings", &[text("abc")]).expect("toStrings"),
            Value::List(vec![text("abc")])
        );
        assert_eq!(
            helper("toStrings", &[number(1.0)]).expect("toStrings"),
            Value::List(vec![text("1")])
        );
        assert_eq!(
            helper("toStrings", &[Value::Bool(true)]).expect("toStrings"),
            Value::List(vec![text("true")])
        );
        assert_eq!(
            helper("toStrings", &[Value::Null]).expect("toStrings"),
            Value::List(vec![])
        );
        // A nested value renders in its structural form, the way `join` would.
        let nested = Value::List(vec![
            map(&[("a", number(1.0))]),
            Value::List(vec![text("b")]),
        ]);
        assert_eq!(
            helper("toStrings", &[nested]).expect("toStrings"),
            Value::List(vec![text("map[a:1]"), text("[b]")])
        );
        // The list the helper answers with renders as a list of strings.
        let rendered = helper(
            "toStrings",
            &[Value::List(vec![number(1.0), Value::Null, number(2.0)])],
        )
        .expect("toStrings");
        assert_eq!(rendered.render(), "[1 2]");
    }
}
