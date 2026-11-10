//! The URL helpers.
//!
//! `urlParse` splits a URL into the fields `urlJoin` reassembles, and both work
//! on the same key set. The reference builds the split with `System.Uri` and
//! reassembles it by hand, so the two are inverse for every URL the reference
//! can parse: what `urlParse` percent-decodes in the path, `urlJoin` puts back.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::support;
use crate::{Context, Error, Value};

/// Dispatches a URL helper.
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
        "urlParse" => parse(arguments),
        "urlJoin" => join(arguments),
        _ => return None,
    };
    Some(result)
}

/// Reports whether this module's helper wants rendered string arguments.
///
/// False for both. `urlParse` returns a map and `urlJoin` takes one, so both need the typed value.
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

/// Splits a URL into the fields `urlJoin` reads back.
///
/// This is the reference's `UrlParse`, which returns exactly eight keys:
/// `scheme`, `host`, `hostname`, `path`, `query`, `opaque`, `fragment`, and
/// `userinfo`. A relative reference has no scheme, host, query, or fragment,
/// and its whole text is the path, which is what the reference's own
/// `UrlParseFieldsMatchUpstream` asserts for `something`.
fn parse(arguments: &[Value]) -> Result<Value, Error> {
    crate::arity("urlParse", arguments.len(), 1, Some(1))?;
    let value = support::text("urlParse", &arguments[0])?;
    let parts = split(&value);
    Ok(Value::Map(BTreeMap::from([
        ("scheme".to_owned(), Value::String(parts.scheme)),
        ("host".to_owned(), Value::String(parts.host)),
        ("hostname".to_owned(), Value::String(parts.hostname)),
        ("path".to_owned(), Value::String(parts.path)),
        ("query".to_owned(), Value::String(parts.query)),
        ("opaque".to_owned(), Value::String(parts.opaque)),
        ("fragment".to_owned(), Value::String(parts.fragment)),
        ("userinfo".to_owned(), Value::String(parts.userinfo)),
    ])))
}

/// Rebuilds a URL from the map `urlParse` produced.
///
/// This is the reference's `UrlJoin`, which reads the same eight keys through
/// its `GetText`, so a missing key is an empty string rather than an error. An
/// opaque URL wins over the authority: with both an `opaque` and a `host` set,
/// the result is `scheme:opaque` and the host is dropped, which the reference's
/// `UrlOpaqueValuesMatchUpstream` asserts.
fn join(arguments: &[Value]) -> Result<Value, Error> {
    crate::arity("urlJoin", arguments.len(), 1, Some(1))?;
    let values = support::map("urlJoin", &arguments[0])?;
    let scheme = text_of(values, "scheme");
    let opaque = text_of(values, "opaque");
    let host = text_of(values, "host");
    let userinfo = text_of(values, "userinfo");
    let path = text_of(values, "path");
    let query = text_of(values, "query");
    let fragment = text_of(values, "fragment");
    let prefix = if scheme.is_empty() {
        String::new()
    } else if opaque.is_empty() {
        format!("{scheme}://")
    } else {
        format!("{scheme}:")
    };
    let authority = if !opaque.is_empty() || userinfo.is_empty() {
        String::new()
    } else {
        format!("{userinfo}@")
    };
    let resource = if opaque.is_empty() {
        format!("{host}{}", escape_path(&path))
    } else {
        String::new()
    };
    let query = if query.is_empty() {
        String::new()
    } else {
        format!("?{query}")
    };
    let fragment = if fragment.is_empty() {
        String::new()
    } else {
        format!("#{fragment}")
    };
    Ok(Value::String(format!(
        "{prefix}{opaque}{authority}{resource}{query}{fragment}"
    )))
}

/// Reads one key of a parsed URL, treating a missing key as empty.
///
/// The reference's `GetText`, which renders whatever it finds and returns the
/// empty string for a key that is not there. A URL a caller assembled by hand
/// has no `opaque` key at all, so a missing key is the normal case rather than
/// an error.
fn text_of(values: &BTreeMap<String, Value>, key: &str) -> String {
    values.get(key).map_or_else(String::new, Value::render)
}

/// The fields of a URL.
struct Parts {
    scheme: String,
    host: String,
    hostname: String,
    path: String,
    query: String,
    opaque: String,
    fragment: String,
    userinfo: String,
}

/// Splits a URL into its parts, the way the reference's `System.Uri` does.
///
/// The rules the reference relies on are:
///
/// - A leading `scheme:` makes the URL absolute, and the scheme is lowercased.
///   A reference without one is relative, and a relative reference has no
///   scheme, authority, query, or fragment at all: its path is the whole text.
/// - `scheme://` introduces an authority, which runs to the first `/`, `?`, or
///   `#` and carries an optional `userinfo@`. The `host` keeps the port, and the
///   `hostname` drops it, which is the reference's own `host:80` versus `host`
///   distinction.
/// - `scheme:` followed by anything other than `/` is an *opaque* URL, as in
///   `mailto:someone@example.com`: the text after the colon is the `opaque` and
///   the path is empty.
/// - The path is percent-decoded, the query and the fragment are not, and the
///   `userinfo` is not either.
fn split(value: &str) -> Parts {
    let empty = || Parts {
        scheme: String::new(),
        host: String::new(),
        hostname: String::new(),
        path: String::new(),
        query: String::new(),
        opaque: String::new(),
        fragment: String::new(),
        userinfo: String::new(),
    };
    let Some(scheme_length) = scheme_length(value) else {
        // A relative reference: the reference's `UriKind.RelativeOrAbsolute`
        // reports `OriginalString` as the path and nothing else.
        return Parts {
            path: value.to_owned(),
            ..empty()
        };
    };
    let scheme = value[..scheme_length].to_ascii_lowercase();
    let rest = &value[scheme_length + 1..];
    if !rest.starts_with('/') {
        return Parts {
            scheme,
            opaque: rest.to_owned(),
            ..empty()
        };
    }

    let after_slashes = rest.strip_prefix("//").unwrap_or(rest);
    let authority_end = after_slashes
        .find(['/', '?', '#'])
        .unwrap_or(after_slashes.len());
    let authority = &after_slashes[..authority_end];
    // The authority is followed by the rest of the URL, which still starts with
    // whatever delimiter ended the authority, so it is kept here and the path is
    // taken as the text up to the next `?` or `#`. A scheme with a single slash
    // has no authority at all, as in `proto:/path`, and the slash starts the
    // path.
    let remainder = &after_slashes[authority_end..];

    let (userinfo, host) = match authority.rfind('@') {
        Some(index) => (&authority[..index], &authority[index + 1..]),
        None => ("", authority),
    };
    let hostname = match host.strip_prefix('[') {
        // An IPv6 literal keeps its brackets in the host, and the port is
        // separated by the bracket rather than by a colon, so the last colon is
        // not the one that ends the host.
        Some(rest) => match rest.find(']') {
            // `end` counts from after the bracket, so the closing bracket is one
            // further along in the host itself.
            Some(end) => &host[..=end + 1],
            None => host,
        },
        None => match host.rfind(':') {
            Some(index) if host[index + 1..].chars().all(|c| c.is_ascii_digit()) => &host[..index],
            _ => host,
        },
    };

    // The remainder runs from the `/` that ended the authority, so the path is
    // whatever precedes the query and the fragment, in that order. A URL with no
    // path at all, as in `proto://host?query`, has an empty one. The reference
    // trims the `?` and the `#` off with `TrimStart`, so both are dropped here
    // too rather than left on the value.
    let (before_fragment, fragment) = split_past(remainder, '#');
    let (path, query) = split_past(before_fragment, '?');
    Parts {
        scheme,
        host: host.to_ascii_lowercase(),
        hostname: hostname.to_ascii_lowercase(),
        path: unescape(path),
        query: query.to_owned(),
        opaque: String::new(),
        fragment: fragment.to_owned(),
        userinfo: userinfo.to_owned(),
    }
}

/// Returns the length of the leading scheme, or `None` for a relative reference.
///
/// A scheme is a letter followed by letters, digits, `+`, `-`, or `.` and then a
/// colon, which is what `System.Uri` accepts. The reference's own check is a
/// bare `IndexOf(':')`, which is only used to decide whether a URL is opaque,
/// so a colon in a relative reference such as `a:b/c` is still an opaque URL.
fn scheme_length(value: &str) -> Option<usize> {
    let colon = value.find(':')?;
    let first = value.chars().next()?;
    if !first.is_ascii_alphabetic() {
        return None;
    }
    let scheme = &value[..colon];
    let valid = scheme
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
    valid.then_some(colon)
}

/// Splits at the first delimiter, returning the text before it and the text
/// after it with the delimiter dropped.
///
/// A missing delimiter yields the whole value and an empty second half, which is
/// how a URL with no query or no fragment keeps those fields empty.
fn split_past(value: &str, delimiter: char) -> (&str, &str) {
    match value.find(delimiter) {
        Some(index) => (&value[..index], value.get(index + 1..).unwrap_or("")),
        None => (value, ""),
    }
}

/// Percent-decodes a URL component the way `Uri.UnescapeDataString` does.
///
/// An escape that is not two hexadecimal digits, and an escape that is not
/// followed by valid UTF-8, are both left as written: the reference's own
/// `urlJoin` case round-trips a path through this function and back out through
/// `EscapeUrlPath`, so a value that cannot be decoded has to survive the round
/// trip.
fn unescape(value: &str) -> String {
    if !value.contains('%') {
        return value.to_owned();
    }
    let bytes = value.as_bytes();
    let mut output: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let high = (bytes[index + 1] as char).to_digit(16);
            let low = (bytes[index + 2] as char).to_digit(16);
            if let (Some(high), Some(low)) = (high, low) {
                output.push(u8::try_from(high * 16 + low).unwrap_or(b'%'));
                index += 3;
                continue;
            }
        }
        output.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&output).into_owned()
}

/// Escapes a path the way the reference's `EscapeUrlPath` does.
///
/// That is `Uri.EscapeDataString` with `%2F` turned back into `/`: every
/// character outside the unreserved set is percent-encoded, and a path
/// separator is not. This is what makes `urlJoin` the inverse of `urlParse` for
/// the path, which `urlParse` decoded.
fn escape_path(path: &str) -> String {
    let mut output = String::with_capacity(path.len());
    for byte in path.bytes() {
        let unreserved = byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~');
        if unreserved || byte == b'/' {
            output.push(char::from(byte));
        } else {
            output.push('%');
            let _ = write!(output, "{byte:02X}");
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{DISPATCH, join, parse, split, takes_rendered_strings};
    use crate::{Context, Error, Value};

    /// Calls the dispatch table the way `lib.rs` does, unwrapping `Some`.
    fn call(name: &str, arguments: &[Value]) -> Result<Value, Error> {
        let context = Context::default();
        DISPATCH(name, arguments, &context).expect("the module claims the name")
    }

    /// Renders `urlParse value` the way the reference's own test templates do.
    ///
    /// `UrlParseFieldsMatchUpstream` renders
    /// `{{ $url := urlParse "V" }}{{ $url.host }}|{{ $url.userinfo }}|{{ $url.path
    /// }}|{{ $url.query }}|{{ $url.scheme }}|{{ $url.fragment }}`
    /// and that exact shape is used here, so the expected strings below can be
    /// read against the reference's own table.
    fn fields(value: &str) -> String {
        let url = call("urlParse", &[Value::String(value.to_owned())]).expect("urlParse");
        let entries = match &url {
            Value::Map(entries) => entries,
            other => panic!("urlParse returned {other:?}"),
        };
        ["host", "userinfo", "path", "query", "scheme", "fragment"]
            .map(|key| {
                entries
                    .get(key)
                    .map_or_else(String::new, Value::render)
                    .as_str()
                    .to_owned()
            })
            .join("|")
    }

    /// Renders `urlJoin (dict ...)`, which is how the reference's opaque cases
    /// build the map the helper takes.
    fn join_dict(entries: &[(&str, &str)]) -> String {
        let map = Value::Map(
            entries
                .iter()
                .map(|(key, value)| ((*key).to_owned(), Value::String((*value).to_owned())))
                .collect::<BTreeMap<_, _>>(),
        );
        call("urlJoin", &[map]).expect("urlJoin").render()
    }

    #[test]
    fn the_module_claims_only_its_own_helpers() {
        let context = Context::default();
        assert!(DISPATCH("trim", &[], &context).is_none());
        assert!(DISPATCH("env", &[], &context).is_none());
        assert!(DISPATCH("urlParse", &[Value::String(String::new())], &context).is_some());
        assert!(DISPATCH("urlJoin", &[Value::Map(BTreeMap::new())], &context).is_some());
    }

    #[test]
    fn no_helper_wants_rendered_arguments() {
        assert!(!takes_rendered_strings("urlParse"));
        assert!(!takes_rendered_strings("urlJoin"));
    }

    #[test]
    fn the_key_set_is_exactly_the_references_eight() {
        let url = call(
            "urlParse",
            &[Value::String("proto://host:80/path".to_owned())],
        )
        .expect("urlParse");
        let Value::Map(entries) = url else {
            panic!("urlParse returns a map");
        };
        let mut keys: Vec<&str> = entries.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "fragment", "host", "hostname", "opaque", "path", "query", "scheme", "userinfo"
            ]
        );
    }

    #[test]
    fn the_reference_url_parse_fields_match() {
        // The reference's UrlParseFieldsMatchUpstream table, verbatim.
        for (value, expected) in [
            ("proto://host:80/path", "host:80||/path||proto|"),
            ("something", "||something|||"),
            (
                "proto://user:passwor%20d@host:80/path",
                "host:80|user:passwor%20d|/path||proto|",
            ),
            (
                "proto://host:80/pa%20th?key=val%20ue",
                "host:80||/pa th|key=val%20ue|proto|",
            ),
        ] {
            assert_eq!(fields(value), expected, "{value}");
        }
    }

    #[test]
    fn host_and_hostname_differ_by_the_port() {
        // `{{ $url.host }}` is `host:80` and `{{ $url.hostname }}` is `host`
        // for `proto://auth@host:80/path?query#fragment`.
        let url = call(
            "urlParse",
            &[Value::String(
                "proto://auth@host:80/path?query#fragment".to_owned(),
            )],
        )
        .expect("urlParse");
        let Value::Map(entries) = url else {
            panic!("urlParse returns a map");
        };
        assert_eq!(entries["host"].render(), "host:80");
        assert_eq!(entries["hostname"].render(), "host");
        assert_eq!(entries["userinfo"].render(), "auth");
        assert_eq!(entries["path"].render(), "/path");
        assert_eq!(entries["query"].render(), "query");
        assert_eq!(entries["fragment"].render(), "fragment");
    }

    #[test]
    fn an_opaque_url_has_no_path_and_keeps_its_text() {
        // The reference's UrlOpaqueValuesMatchUpstream: `proto:opaque` is the
        // scheme and the opaque text, with an empty path, host, query, and
        // fragment.
        let url = call("urlParse", &[Value::String("proto:opaque".to_owned())]).expect("urlParse");
        let Value::Map(entries) = url else {
            panic!("urlParse returns a map");
        };
        let rendered = ["scheme", "opaque", "path", "host", "query", "fragment"]
            .map(|key| entries[key].render())
            .join("|");
        assert_eq!(rendered, "proto|opaque||||");
    }

    #[test]
    fn a_relative_reference_is_all_path() {
        // The relative case is also the one that decides a bare colon is a
        // scheme: `something` has none, so its whole text is its path.
        let parts = split("something");
        assert_eq!(parts.path, "something");
        assert_eq!(parts.scheme, "");
        assert_eq!(split("/just/a/path?query").path, "/just/a/path?query");
        assert_eq!(split("//host/path").scheme, "");
    }

    #[test]
    fn a_scheme_with_one_slash_has_a_path_and_no_authority() {
        // `proto:/path` is a scheme and a rooted path rather than a scheme and
        // an authority, and `proto://host` is an authority and no path. Both
        // have to come back the way `urlJoin` can put them together again.
        let rooted = split("proto:/path");
        assert_eq!(rooted.scheme, "proto");
        assert_eq!(rooted.path, "/path");
        assert_eq!(rooted.host, "");
        let authority = split("proto://host");
        assert_eq!(authority.scheme, "proto");
        assert_eq!(authority.host, "host");
        assert_eq!(authority.hostname, "host");
        assert_eq!(authority.path, "");
        for value in ["proto://host", "proto://host:80/"] {
            let parsed = parse(&[Value::String(value.to_owned())]).expect("urlParse");
            assert_eq!(join(&[parsed]).expect("urlJoin").render(), value, "{value}");
        }
        // `urlJoin` writes `scheme://` whenever there is no opaque part, so a
        // rooted path comes back with an empty authority in front of it. That
        // is the reference's own reassembly, not a defect here.
        let rooted = parse(&[Value::String("proto:/path".to_owned())]).expect("urlParse");
        assert_eq!(join(&[rooted]).expect("urlJoin").render(), "proto:///path");
    }

    #[test]
    fn a_port_is_split_from_the_host_and_an_ipv6_literal_is_not() {
        // The `host` keeps the port and the `hostname` does not, which is the
        // reference's own distinction. An IPv6 literal's brackets close before
        // the port, so the last colon is the one that matters.
        let with_port = split("proto://host:80/path");
        assert_eq!(with_port.host, "host:80");
        assert_eq!(with_port.hostname, "host");
        let literal = split("proto://[::1]:8080/path");
        assert_eq!(literal.host, "[::1]:8080");
        assert_eq!(literal.hostname, "[::1]");
        // A host with no port keeps the same text in both fields.
        let plain = split("proto://HOST/Path");
        assert_eq!(plain.host, "host");
        assert_eq!(plain.hostname, "host");
        assert_eq!(plain.path, "/Path");
    }

    #[test]
    fn url_join_reproduces_the_references_cases() {
        // The reference's UrlFunctionsMatchTheSupportedUpstreamContracts table.
        assert_eq!(
            call(
                "urlJoin",
                &[parse(&[Value::String(
                    "proto://host:80/pa%20th?key=val%20ue".to_owned()
                )])
                .expect("urlParse")]
            )
            .expect("urlJoin")
            .render(),
            "proto://host:80/pa%20th?key=val%20ue"
        );
        assert_eq!(
            join_dict(&[
                ("fragment", "fragment"),
                ("host", "host:80"),
                ("path", "/path"),
                ("query", "query"),
                ("scheme", "proto"),
            ]),
            "proto://host:80/path?query#fragment"
        );
        assert_eq!(
            join_dict(&[
                ("fragment", "fragment"),
                ("host", "host:80"),
                ("path", "/path"),
                ("scheme", "proto"),
                ("userinfo", "auth"),
            ]),
            "proto://auth@host:80/path#fragment"
        );
    }

    #[test]
    fn url_join_drops_the_authority_for_an_opaque_url() {
        // The reference's UrlOpaqueValuesMatchUpstream, verbatim.
        assert_eq!(
            join_dict(&[
                ("scheme", "proto"),
                ("opaque", "opaque"),
                ("query", "query"),
                ("fragment", "fragment"),
            ]),
            "proto:opaque?query#fragment"
        );
        assert_eq!(
            join_dict(&[
                ("scheme", "proto"),
                ("opaque", "opaque"),
                ("host", "host"),
                ("userinfo", "user"),
            ]),
            "proto:opaque"
        );
    }

    #[test]
    fn url_join_reattaches_every_field_of_a_parsed_url() {
        // The point of the pair: parse then join is the identity for a URL the
        // reference can round-trip, which is what makes `urlParse` safe to use
        // as a template's way of editing one field.
        for value in [
            "proto://auth@host:80/path?query#fragment",
            "proto://host:80/path",
            "proto://host/pa%20th?key=val%20ue",
            "proto:opaque",
        ] {
            let parsed = parse(&[Value::String(value.to_owned())]).expect("urlParse");
            assert_eq!(join(&[parsed]).expect("urlJoin").render(), value, "{value}");
        }
    }

    #[test]
    fn a_missing_key_is_an_empty_string_rather_than_an_error() {
        // The reference's `GetText` renders whatever it finds, so a map a
        // caller assembled by hand joins without complaint.
        assert_eq!(join_dict(&[("path", "/only")]), "/only");
        assert_eq!(join_dict(&[]), "");
        assert_eq!(
            join(&[Value::Map(BTreeMap::new())])
                .expect("urlJoin")
                .render(),
            ""
        );
    }

    #[test]
    fn the_argument_count_and_the_argument_type_are_checked() {
        assert!(matches!(
            call("urlParse", &[]),
            Err(Error::WrongArgumentCount { .. })
        ));
        assert!(matches!(
            call("urlJoin", &[]),
            Err(Error::WrongArgumentCount { .. })
        ));
        // `urlJoin` insists on a map, as the reference's `M` does.
        assert!(matches!(
            call("urlJoin", &[Value::String("proto://host/".to_owned())]),
            Err(Error::InvalidArgument { .. })
        ));
        assert!(matches!(
            call("urlParse", &[Value::Map(BTreeMap::new())]),
            Err(Error::InvalidArgument { .. })
        ));
    }

    #[test]
    fn an_escaped_path_survives_the_round_trip() {
        // `urlParse` decodes the path and `urlJoin` encodes it again, so a URL
        // written with escapes comes back byte for byte.
        let parts = split("proto://host/pa%20th");
        assert_eq!(parts.path, "/pa th");
        assert_eq!(escape_of("/pa th"), "/pa%20th");
        // An escape that is not valid UTF-8 is left alone rather than replaced.
        assert_eq!(split("proto://host/a%FFb").path, "/a\u{FFFD}b");
    }

    /// The escaping `urlJoin` applies to a path.
    fn escape_of(path: &str) -> String {
        join_dict(&[("path", path)])
    }
}
