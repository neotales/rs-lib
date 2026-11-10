//! The paths helpers: `base`, `dir`, `clean`, `ext`, `isAbs` and their `os*` twins.
//!
//! There are two families because Go has two path packages. `base`, `dir`,
//! `clean`, `ext` and `isAbs` are `path`, which always speaks forward slashes: a
//! leading slash is part of the path, there is no volume name, and a Windows
//! path such as `C:\etc\hosts` is one ordinary element. The `os*` spellings are
//! `path/filepath`, which is the host's own path syntax. They are not a rename
//! of the first family and are not allowed to become one: `osBase "a/b/"` is
//! empty where `base "a/b/"` is `b`, and `osExt "a."` is empty where `ext "a."`
//! is `.`.
//!
//! ```
//! use neotales_sprig::{Value, call};
//!
//! let name = call("base", &[Value::String("a/b.txt".to_owned())]).unwrap();
//! assert_eq!(name.render(), "b.txt");
//! ```
//!
//! # What the reference actually does
//!
//! The reference is the authority for these helpers, and it is not a thin
//! transliteration of Go. The `os*` half is `System.IO.Path`, so it answers the
//! way .NET answers for the platform it ran on, and the `path` half cleans
//! before it splits: `PathBaseGo` calls `CleanSlashPath` and then takes the text
//! after the last separator, which makes `base "a/b/.."` the string `a` where
//! Go's `path.Base` would say `..`. Both behaviours are reproduced as written.
//! The expectations in the tests are not a reading of the reference's code: the
//! table at the end of this file was produced by running the reference's own
//! method bodies, so it is the reference's answer to each input.
//!
//! # One platform, deliberately
//!
//! The reference's `os*` half is host-sensitive, and its own test spells the
//! `osClean` expectation as `\bar` on Windows and `/bar` everywhere else; the
//! parity fixture recorded `/bar`. A rendered Compose file has to be the same
//! bytes on a laptop and in a pipeline, so the Unix answer is the one this
//! crate computes unconditionally rather than asking the host. On that platform
//! `Path.DirectorySeparatorChar` is `/` and `Path.IsPathRooted` is
//! `StartsWith('/')`, which is why `clean` and `osClean`, and `isAbs` and
//! `osIsAbs`, are one function apiece here: they can only differ where the
//! reference's own test says they might.

use crate::{Context, Error, Value};

/// Dispatches a paths helper.
pub(super) const DISPATCH: crate::Dispatch =
    |name, arguments, context| dispatch(name, arguments, context);

/// What a paths helper does with its one rendered argument.
type Compute = fn(&str) -> Value;

/// Every helper this module claims, in the order the table at the end of this
/// file lists them.
///
/// The name is what decides ownership, so a name that is not in this list has to
/// fall through to the next module: `compact` is claimed by both the defaults
/// and the lists modules, and `len` by both the types and the math modules.
const HELPERS: [(&str, Compute); 10] = [
    ("base", |path| Value::String(base(path))),
    ("dir", |path| Value::String(dir(path))),
    ("clean", |path| Value::String(clean(path))),
    ("ext", |path| Value::String(ext(path))),
    ("isAbs", |path| Value::Bool(is_abs(path))),
    ("osBase", |path| Value::String(os_base(path))),
    ("osDir", |path| Value::String(os_dir(path))),
    ("osClean", |path| Value::String(os_clean(path))),
    ("osExt", |path| Value::String(os_ext(path))),
    ("osIsAbs", |path| Value::Bool(os_is_abs(path))),
];

#[allow(clippy::trivially_copy_pass_by_ref)]
fn dispatch(
    name: &str,
    arguments: &[Value],
    context: &Context<'_>,
) -> Option<Result<Value, Error>> {
    // No paths helper reads the call site, so the context is only here because
    // the engine hands one to every module.
    let _ = context;
    let helper = HELPERS
        .iter()
        .find(|(claimed, _)| *claimed == name)
        .map(|(_, compute)| *compute)?;
    Some((|| {
        // `One` in the reference: exactly one argument, and it is the rendered
        // form, so a number or a boolean arrives here as the text Go would print.
        crate::arity(name, arguments.len(), 1, Some(1))?;
        let path = crate::support::text(name, &arguments[0])?;
        Ok(helper(&path))
    })())
}

/// Reports whether this module's helper wants rendered string arguments.
pub(super) fn takes_rendered_strings(name: &str) -> bool {
    HELPERS.iter().any(|(claimed, _)| *claimed == name)
}

/// `base`: the last element of the path, after lexical cleaning.
///
/// `PathBaseGo` in the reference cleans first and then takes the text after the
/// last separator, with `/` itself as the one value that is returned whole. That
/// is why a trailing slash, a `.` segment and a `..` segment all disappear
/// first: `base "a/b/"` is `b`, `base "a/."` is `a`, and `base "a/b/.."` is `a`
/// rather than the `..` Go's `path.Base` would return. The empty path cleans to
/// `.`, which is the element it then reports.
fn base(path: &str) -> String {
    let cleaned = clean(path);
    if cleaned == "/" {
        return cleaned;
    }
    match cleaned.rfind('/') {
        Some(separator) => cleaned[separator + 1..].to_owned(),
        None => cleaned,
    }
}

/// `dir`: everything up to and including the final slash.
///
/// `PathDirGo` cleans first, hands back the whole string when cleaning left `.`
/// or `/`, and otherwise cuts at the last separator: a path with no separator at
/// all has the directory `.`, and one whose only separator is the leading slash
/// has the root. Together with [`base`] this accounts for the cleaned path.
fn dir(path: &str) -> String {
    let cleaned = clean(path);
    if cleaned == "." || cleaned == "/" {
        return cleaned;
    }
    match cleaned.rfind('/') {
        None => String::from("."),
        Some(0) => String::from("/"),
        Some(separator) => cleaned[..separator].to_owned(),
    }
}

/// `clean`: the lexical cleaning the `path` family shares.
///
/// `CleanSlashPath` in the reference: a leading slash is remembered and put back
/// at the front, empty and `.` segments are dropped, and `..` cancels the
/// segment before it. A `..` with nothing to cancel is dropped for an absolute
/// path — that is what stops `/..` from escaping the root — and kept for a
/// relative one, so `clean "../../x"` is `../../x`. An empty result is `.` for
/// a relative path, which is also what makes `base ""` the string `.`.
fn clean(path: &str) -> String {
    let absolute = path.starts_with('/');
    let mut segments: Vec<&str> = Vec::new();
    for segment in path.split('/').filter(|segment| !segment.is_empty()) {
        match segment {
            // A `.` segment is this directory, which the output already names.
            "." => {}
            // A `..` pops a real segment. It only survives when there is nothing
            // to pop and the path is relative; an absolute path cannot go above
            // its root, so the segment is dropped.
            ".." => match segments.last() {
                Some(last) if *last != ".." => {
                    segments.pop();
                }
                _ if !absolute => segments.push(segment),
                _ => {}
            },
            other => segments.push(other),
        }
    }

    let joined = segments.join("/");
    if absolute {
        format!("/{joined}")
    } else if joined.is_empty() {
        String::from(".")
    } else {
        joined
    }
}

/// `ext`: the final dot-suffix of the last element, including the dot.
///
/// The reference's `PathExt` lambda splits on `/` and takes the last piece, so a
/// path ending in a slash has no element and no extension. A name that is only a
/// dot run is not special: `.env` is entirely extension, and `.` and `..` are
/// reported as `.`, which is where this helper parts company with [`os_ext`].
fn ext(path: &str) -> String {
    let name = path.rsplit('/').next().unwrap_or(path);
    match name.rfind('.') {
        Some(dot) => name[dot..].to_owned(),
        None => String::new(),
    }
}

/// `isAbs`: whether the path starts at the root.
///
/// `PathIsAbsolute` in the reference is a literal `StartsWith('/')` with no
/// cleaning first, so `isAbs "a/.."` is false and `isAbs "//"` is true. It is a
/// boolean, not the string `true`.
fn is_abs(path: &str) -> bool {
    path.starts_with('/')
}

/// `osBase`: `Path.GetFileName`, the last element without cleaning.
///
/// The reference's `OsPathBase` is `System.IO.Path.GetFileName`, which is a
/// plain cut at the last separator: it resolves nothing. So a trailing slash
/// leaves nothing after the cut and the answer is empty, where [`base`] would
/// have cleaned the slash away and answered `b`, and a `..` segment is reported
/// as itself rather than resolved. On the platform this crate implements, `/` is
/// the only separator, so a backslash is an ordinary character.
fn os_base(path: &str) -> String {
    match path.rfind('/') {
        Some(separator) => path[separator + 1..].to_owned(),
        None => path.to_owned(),
    }
}

/// `osDir`: `Path.GetDirectoryName`, everything before the last separator.
///
/// The reference's `OsPathDir` is `System.IO.Path.GetDirectoryName` with its
/// null answer — the empty path and the root itself — turned into the empty
/// string. It does not clean, so `.` and `..` segments survive in the result
/// (`osDir "a/./b"` is `a/.`), and it collapses a run of separators to one
/// (`osDir "a//b//c"` is `a/b`), which is the other thing that separates it
/// from [`dir`]: `dir "a//b//c"` is `a/b` and `dir "a/./b"` is `a`.
fn os_dir(path: &str) -> String {
    // `GetDirectoryName` returns null for the empty path and for `/`, and the
    // reference maps that null to the empty string.
    if path.is_empty() || path == "/" {
        return String::new();
    }
    let Some(separator) = path.rfind('/') else {
        return String::new();
    };
    let directory = collapse_slashes(&path[..separator]);
    if directory.is_empty() {
        // The only way to cut a prefix to nothing is a path that starts at the
        // root, whose directory is the root.
        return String::from("/");
    }
    directory
}

/// Collapses a run of separators to one and drops a trailing separator.
///
/// `Path.GetDirectoryName` returns `a/b` for the directory of `a//b//c`, so the
/// collapse is part of what it returns, and `a` for the directory of `a//`,
/// where the separator that cut the prefix is taken off afterwards. A prefix that
/// is nothing but separators is the root, which keeps its one separator.
fn collapse_slashes(text: &str) -> String {
    let mut collapsed = String::with_capacity(text.len());
    for character in text.chars() {
        if character == '/' && collapsed.ends_with('/') {
            continue;
        }
        collapsed.push(character);
    }
    if collapsed.len() > 1 && collapsed.ends_with('/') {
        collapsed.pop();
    }
    collapsed
}

/// `osExt`: `Path.GetExtension`, the dot-suffix of an uncleaned last element.
///
/// The reference's `OsPathExt` is `System.IO.Path.GetExtension`, which scans back
/// from the end of the string and stops at the first separator, so a trailing
/// slash means no extension at all. Three cases separate it from [`ext`]: a name
/// that is only dots has no extension (`osExt "a/.."` is empty, `ext "a/.."` is
/// `.`), a trailing dot is not one (`osExt "a."` is empty, `ext "a."` is `.`),
/// and a leading dot belongs to the extension either way (`osExt ".env"` and
/// `ext ".env"` are both `.env`).
fn os_ext(path: &str) -> String {
    let name = path.rsplit('/').next().unwrap_or(path);
    // A name of nothing but dots is a relative directory reference, not a file
    // with an extension, so there is nothing to report.
    if name.is_empty() || name.bytes().all(|byte| byte == b'.') {
        return String::new();
    }
    match name.rfind('.') {
        // A dot in the last position is the end of a name, not a suffix.
        Some(dot) if dot + 1 == name.len() => String::new(),
        Some(dot) => name[dot..].to_owned(),
        None => String::new(),
    }
}

/// `osClean`: `CleanOsPath`, the `filepath` spelling of [`clean`].
///
/// The reference's `CleanOsPath` is the same algorithm as `CleanSlashPath` with
/// `Path.DirectorySeparatorChar` and `Path.IsPathRooted` substituted for `/` and
/// `StartsWith('/')`. On the platform this crate implements those two *are* `/`
/// and `StartsWith('/')`, so the two helpers agree by construction; the
/// reference's own test is what says they might not, spelling the Windows answer
/// to `osClean "/foo/../foo/../bar"` as `\bar`. See the module comment for why
/// one answer is implemented rather than the host's.
fn os_clean(path: &str) -> String {
    clean(path)
}

/// `osIsAbs`: `Path.IsPathFullyQualified`, whether the path is rooted.
///
/// The reference's `OsPathIsAbsolute` is `Path.IsPathFullyQualified`, which on
/// the platform this crate implements is true exactly when the path starts with
/// a separator, the same question [`is_abs`] asks. The two differ only where
/// .NET recognises something this implementation deliberately does not: a drive
/// letter or a UNC share is a rooted path on Windows, so there `osIsAbs
/// "C:\\foo"` would be true while `isAbs "C:\\foo"` stays false.
fn os_is_abs(path: &str) -> bool {
    path.starts_with('/')
}

#[cfg(test)]
mod tests {
    use super::{HELPERS, collapse_slashes, takes_rendered_strings};
    use crate::{Error, Value};

    /// Calls a helper and renders the answer as the template engine would.
    ///
    /// The fixture's `expected` is rendered text, and a boolean helper renders
    /// as `true` or `false`, so comparing rendered text is what lets one table
    /// hold the string helpers and the boolean ones together.
    fn render(helper: &str, path: &str) -> String {
        crate::call(helper, &[Value::String(path.to_owned())])
            .unwrap_or_else(|error| panic!("{helper} {path:?} failed: {error}"))
            .render()
    }

    /// Every `(template, expected)` pair in `fixtures/sprig/upstream_parity.json`
    /// that calls a paths helper.
    ///
    /// The sixteen pairs are the reference's own
    /// `PathFunctionsMatchUpstreamContracts` theory, which is itself ported from
    /// upstream Masterminds Sprig's path tests. The three `os*` expectations the
    /// reference computes at run time rather than hard-codes — `osDir`, `osIsAbs`
    /// and `osClean` — are recorded here as the Unix answers the fixture holds.
    #[test]
    fn matches_the_upstream_parity_fixture() {
        let cases = [
            ("base", "foo/bar", "bar"),
            // An empty path cleans to `.`, which is then the only element.
            ("base", "", "."),
            // `/` is returned whole rather than cut at its own separator.
            ("base", "/", "/"),
            ("dir", "foo/bar/baz", "foo/bar"),
            // A doubled separator is one separator as far as the cleaned path goes.
            ("dir", "foo//bar", "foo"),
            ("isAbs", "/foo", "true"),
            ("isAbs", "foo", "false"),
            ("clean", "/foo/../foo/../bar", "/bar"),
            ("ext", "/foo/bar/baz.txt", ".txt"),
            // A leading dot is part of the extension, not a name before it.
            ("ext", ".env", ".env"),
            ("osBase", "foo/bar", "bar"),
            ("osDir", "foo/bar/baz", "foo/bar"),
            ("osIsAbs", "/foo", "true"),
            ("osIsAbs", "foo", "false"),
            ("osClean", "/foo/../foo/../bar", "/bar"),
            ("osExt", "/foo/bar/baz.txt", ".txt"),
        ];
        for (helper, argument, expected) in cases {
            assert_eq!(render(helper, argument), expected, "{helper} {argument:?}");
        }
    }

    /// The reference's own answers, for every helper and sixty-eight paths.
    ///
    /// Each row was produced by running the reference's `CleanSlashPath`,
    /// `PathBaseGo`, `PathDirGo`, `PathExt` and `CleanOsPath` verbatim alongside
    /// `Path.GetFileName`, `Path.GetDirectoryName`, `Path.GetExtension` and
    /// `Path.IsPathFullyQualified`, so this is a comparison against the
    /// reference rather than against a reading of it. The columns are in
    /// [`HELPERS`] order, which the assertions depend on.
    ///
    /// The table is left as one line per input: a row that rustfmt wrapped
    /// across six lines would be a worse place to check an answer against.
    #[test]
    fn matches_the_reference_on_the_hard_cases() {
        #[rustfmt::skip]
        const REFERENCE: [(&str, [&str; 10]); 68] = [
            ("", [".", ".", ".", "", "false", "", "", ".", "", "false"]),
            (".", [".", ".", ".", ".", "false", ".", "", ".", "", "false"]),
            ("..", ["..", ".", "..", ".", "false", "..", "", "..", "", "false"]),
            ("...", ["...", ".", "...", ".", "false", "...", "", "...", "", "false"]),
            ("a", ["a", ".", "a", "", "false", "a", "", "a", "", "false"]),
            ("a.", ["a.", ".", "a.", ".", "false", "a.", "", "a.", "", "false"]),
            ("a..", ["a..", ".", "a..", ".", "false", "a..", "", "a..", "", "false"]),
            ("..a", ["..a", ".", "..a", ".a", "false", "..a", "", "..a", ".a", "false"]),
            (".a", [".a", ".", ".a", ".a", "false", ".a", "", ".a", ".a", "false"]),
            (".a.b", [".a.b", ".", ".a.b", ".b", "false", ".a.b", "", ".a.b", ".b", "false"]),
            ("a.b.c.d", ["a.b.c.d", ".", "a.b.c.d", ".d", "false", "a.b.c.d", "", "a.b.c.d", ".d", "false"]),
            ("a.b/c", ["c", "a.b", "a.b/c", "", "false", "c", "a.b", "a.b/c", "", "false"]),
            ("/", ["/", "/", "/", "", "true", "", "", "/", "", "true"]),
            ("//", ["/", "/", "/", "", "true", "", "/", "/", "", "true"]),
            ("///", ["/", "/", "/", "", "true", "", "/", "/", "", "true"]),
            ("////", ["/", "/", "/", "", "true", "", "/", "/", "", "true"]),
            ("/a", ["a", "/", "/a", "", "true", "a", "/", "/a", "", "true"]),
            ("//a", ["a", "/", "/a", "", "true", "a", "/", "/a", "", "true"]),
            ("///a", ["a", "/", "/a", "", "true", "a", "/", "/a", "", "true"]),
            ("/a/b", ["b", "/a", "/a/b", "", "true", "b", "/a", "/a/b", "", "true"]),
            ("/a/b/", ["b", "/a", "/a/b", "", "true", "", "/a/b", "/a/b", "", "true"]),
            ("/a//b//", ["b", "/a", "/a/b", "", "true", "", "/a/b", "/a/b", "", "true"]),
            ("a/", ["a", ".", "a", "", "false", "", "a", "a", "", "false"]),
            ("a//", ["a", ".", "a", "", "false", "", "a", "a", "", "false"]),
            ("a///", ["a", ".", "a", "", "false", "", "a", "a", "", "false"]),
            ("a/b", ["b", "a", "a/b", "", "false", "b", "a", "a/b", "", "false"]),
            ("a/b/", ["b", "a", "a/b", "", "false", "", "a/b", "a/b", "", "false"]),
            ("a//b", ["b", "a", "a/b", "", "false", "b", "a", "a/b", "", "false"]),
            ("a//b//", ["b", "a", "a/b", "", "false", "", "a/b", "a/b", "", "false"]),
            ("a//b//c", ["c", "a/b", "a/b/c", "", "false", "c", "a/b", "a/b/c", "", "false"]),
            ("a//b//c/", ["c", "a/b", "a/b/c", "", "false", "", "a/b/c", "a/b/c", "", "false"]),
            ("a/b/c", ["c", "a/b", "a/b/c", "", "false", "c", "a/b", "a/b/c", "", "false"]),
            ("a/b/c/", ["c", "a/b", "a/b/c", "", "false", "", "a/b/c", "a/b/c", "", "false"]),
            ("a/./b/../c", ["c", "a", "a/c", "", "false", "c", "a/./b/..", "a/c", "", "false"]),
            ("/foo/../foo/../bar", ["bar", "/", "/bar", "", "true", "bar", "/foo/../foo/..", "/bar", "", "true"]),
            ("a/..", [".", ".", ".", ".", "false", "..", "a", ".", "", "false"]),
            ("a/.", ["a", ".", "a", ".", "false", ".", "a", "a", "", "false"]),
            ("a/..b", ["..b", "a", "a/..b", ".b", "false", "..b", "a", "a/..b", ".b", "false"]),
            ("../a", ["a", "..", "../a", "", "false", "a", "..", "../a", "", "false"]),
            ("a/../..", ["..", ".", "..", ".", "false", "..", "a/..", "..", "", "false"]),
            ("/..", ["/", "/", "/", ".", "true", "..", "/", "/", "", "true"]),
            ("/../a", ["a", "/", "/a", "", "true", "a", "/..", "/a", "", "true"]),
            ("..", ["..", ".", "..", ".", "false", "..", "", "..", "", "false"]),
            (".../..", [".", ".", ".", ".", "false", "..", "...", ".", "", "false"]),
            ("a/b/..", ["a", ".", "a", ".", "false", "..", "a/b", "a", "", "false"]),
            ("a/b/.", ["b", "a", "a/b", ".", "false", ".", "a/b", "a/b", "", "false"]),
            ("x/.env", [".env", "x", "x/.env", ".env", "false", ".env", "x", "x/.env", ".env", "false"]),
            (".env", [".env", ".", ".env", ".env", "false", ".env", "", ".env", ".env", "false"]),
            (".env/", [".env", ".", ".env", "", "false", "", ".env", ".env", "", "false"]),
            ("x/.env/", [".env", "x", "x/.env", "", "false", "", "x/.env", "x/.env", "", "false"]),
            ("a/b.txt", ["b.txt", "a", "a/b.txt", ".txt", "false", "b.txt", "a", "a/b.txt", ".txt", "false"]),
            ("a/b.txt/", ["b.txt", "a", "a/b.txt", "", "false", "", "a/b.txt", "a/b.txt", "", "false"]),
            ("a/b.tar.gz", ["b.tar.gz", "a", "a/b.tar.gz", ".gz", "false", "b.tar.gz", "a", "a/b.tar.gz", ".gz", "false"]),
            ("foo\\bar", ["foo\\bar", ".", "foo\\bar", "", "false", "foo\\bar", "", "foo\\bar", "", "false"]),
            ("a\\b", ["a\\b", ".", "a\\b", "", "false", "a\\b", "", "a\\b", "", "false"]),
            ("C:\\foo", ["C:\\foo", ".", "C:\\foo", "", "false", "C:\\foo", "", "C:\\foo", "", "false"]),
            ("~/x", ["x", "~", "~/x", "", "false", "x", "~", "~/x", "", "false"]),
            (" /", [" ", ".", " ", "", "false", "", " ", " ", "", "false"]),
            (" ", [" ", ".", " ", "", "false", " ", "", " ", "", "false"]),
            ("a b/c//", ["c", "a b", "a b/c", "", "false", "", "a b/c", "a b/c", "", "false"]),
            ("a/../b", ["b", ".", "b", "", "false", "b", "a/..", "b", "", "false"]),
            ("a/../../b", ["b", "..", "../b", "", "false", "b", "a/../..", "../b", "", "false"]),
            ("a/./b", ["b", "a", "a/b", "", "false", "b", "a/.", "a/b", "", "false"]),
            ("./a/./b", ["b", "a", "a/b", "", "false", "b", "./a/.", "a/b", "", "false"]),
            ("a/b/../c/", ["c", "a", "a/c", "", "false", "", "a/b/../c", "a/c", "", "false"]),
            ("//a/b", ["b", "/a", "/a/b", "", "true", "b", "/a", "/a/b", "", "true"]),
            ("/a/b//c//d", ["d", "/a/b/c", "/a/b/c/d", "", "true", "d", "/a/b/c", "/a/b/c/d", "", "true"]),
            ("a//b//c//d", ["d", "a/b/c", "a/b/c/d", "", "false", "d", "a/b/c", "a/b/c/d", "", "false"]),
        ];
        assert_eq!(HELPERS.len(), 10, "the table's columns are HELPERS' order");
        for (path, expected) in REFERENCE {
            for ((helper, _), expected) in HELPERS.iter().zip(expected) {
                assert_eq!(
                    render(helper, path),
                    expected,
                    "{helper} {path:?} should be {expected:?}"
                );
            }
        }
    }

    /// `base` cleans first, which is where it stops being a plain cut.
    ///
    /// `PathBaseGo` calls `CleanSlashPath`, so the trailing slash, the `.`
    /// segment and the `..` segment are all resolved before the last element is
    /// taken. The `..` case is the one worth stating: Go's `path.Base("a/b/..")`
    /// is `..`, and the reference's is `a`, because the cleaning happened first.
    #[test]
    fn base_cleans_before_taking_the_last_element() {
        assert_eq!(render("base", "a/b/"), "b");
        assert_eq!(render("base", "a/b//"), "b");
        assert_eq!(render("base", "a/."), "a");
        assert_eq!(render("base", "a/.."), ".");
        assert_eq!(render("base", "a/b/.."), "a");
        assert_eq!(render("base", "a/b/../.."), ".");
        // An empty path cleans to `.`; `/` is handed back whole.
        assert_eq!(render("base", ""), ".");
        assert_eq!(render("base", "/"), "/");
    }

    /// `dir` returns everything through the final slash of the cleaned path.
    ///
    /// `PathDirGo` answers the cleaned string for `.` and `/`, `.` for a path
    /// with no separator left, and the root for a single leading separator.
    #[test]
    fn dir_returns_the_text_through_the_final_separator() {
        assert_eq!(render("dir", "a/b/c"), "a/b");
        // A trailing slash is cleaned away first, so it is not a separator.
        assert_eq!(render("dir", "a/b/"), "a");
        assert_eq!(render("dir", "/a/b"), "/a");
        assert_eq!(render("dir", "/a"), "/");
        // Nothing left before the only element, so the directory is `.`.
        assert_eq!(render("dir", "a"), ".");
        assert_eq!(render("dir", "a/b/.."), ".");
        assert_eq!(render("dir", ""), ".");
        assert_eq!(render("dir", "/"), "/");
    }

    /// `dir` and `base` account for the whole cleaned path.
    ///
    /// They are two cuts of one string, so for any path that cleans to
    /// something with a separator in it the directory, a separator, and the
    /// element reassemble the cleaned path exactly. The root is the one case
    /// that needs care: `dir "/a"` is `/`, and joining it with a separator would
    /// give `//a`. A path that cleans to a single element or to `.` is left out,
    /// because there the directory is `.` and the element is the whole string,
    /// which is not a decomposition of anything.
    #[test]
    fn dir_and_base_account_for_the_whole_cleaned_path() {
        let paths = [
            "a/b",
            "a/b/",
            "a//b//c",
            "a/b/c/",
            "a/./b/../c",
            "/foo/../foo/../bar",
            "/a/b",
            "/a/b/",
            "/a//b//",
            "../a",
            "a/../b",
            "a/../../b",
            "a/b/../c/",
            "//a/b",
            "/a/b//c//d",
            "a//b//c//d",
            "x/.env",
            "a/b.tar.gz",
        ];
        for path in paths {
            let cleaned = render("clean", path);
            if !cleaned.contains('/') || cleaned == "/" {
                // `a/../b` cleans to `b`, which is a single element: there is
                // nothing left to decompose into a directory and an element.
                continue;
            }
            let directory = render("dir", path);
            let element = render("base", path);
            let reassembled = if directory == "/" {
                format!("/{element}")
            } else {
                format!("{directory}/{element}")
            };
            assert_eq!(reassembled, cleaned, "{path:?} does not add up");
        }
    }

    /// `clean` is lexical, and an absolute path cannot climb above its root.
    ///
    /// `CleanSlashPath` drops empty and `.` segments, cancels `..` against the
    /// segment before it, and re-attaches the leading slash it remembered. A `..`
    /// that has nothing to cancel is kept for a relative path and dropped for an
    /// absolute one, which is the whole difference between `clean "a/../.."`
    /// (`..`) and `clean "/.."` (`/`).
    #[test]
    fn clean_is_lexical_and_stops_at_the_root() {
        assert_eq!(render("clean", "a/./b/../c"), "a/c");
        assert_eq!(render("clean", "a//b"), "a/b");
        assert_eq!(render("clean", "a/b/"), "a/b");
        assert_eq!(render("clean", "/foo/../foo/../bar"), "/bar");
        assert_eq!(render("clean", ".."), "..");
        assert_eq!(render("clean", "../a"), "../a");
        assert_eq!(render("clean", "a/../.."), "..");
        assert_eq!(render("clean", "a/../../b"), "../b");
        // `/..` has nothing left to cancel and cannot go above the root.
        assert_eq!(render("clean", "/.."), "/");
        assert_eq!(render("clean", "/../a"), "/a");
        // An empty result is `.` unless the path was absolute.
        assert_eq!(render("clean", ""), ".");
        assert_eq!(render("clean", "a/.."), ".");
        assert_eq!(render("clean", "///"), "/");
        // A backslash is an ordinary character: one element, no separator.
        assert_eq!(render("clean", "foo\\bar"), "foo\\bar");
    }

    /// `ext` includes the dot, and a dot-file is all extension.
    ///
    /// The reference's `PathExt` lambda takes the last `/`-separated piece and
    /// its last dot, with no special case for a name that begins with a dot or
    /// is nothing but dots. A path ending in a slash has no last piece, so it has
    /// no extension.
    #[test]
    fn ext_includes_the_dot_and_the_whole_dotfile() {
        assert_eq!(render("ext", "a/b.txt"), ".txt");
        // Only the final dot counts.
        assert_eq!(render("ext", "a/b.tar.gz"), ".gz");
        // A leading dot is the extension, not a name before one.
        assert_eq!(render("ext", ".env"), ".env");
        assert_eq!(render("ext", "x/.env"), ".env");
        // A name that is only dots has `.` for an extension here.
        assert_eq!(render("ext", "."), ".");
        assert_eq!(render("ext", "a/.."), ".");
        // No dot, or no last element at all.
        assert_eq!(render("ext", "a"), "");
        assert_eq!(render("ext", "a/b/"), "");
        assert_eq!(render("ext", ""), "");
    }

    /// `isAbs` and `osIsAbs` answer with a boolean, not a string.
    ///
    /// `OneBoolean` in the reference builds a `TemplateValue.Boolean`, and
    /// `PathIsAbsolute` asks only whether the text starts with a separator, so
    /// nothing is cleaned first: `a/..` is not absolute and `//` is.
    #[test]
    fn is_abs_is_a_boolean() {
        assert_eq!(
            crate::call("isAbs", &[Value::String("/foo".to_owned())]),
            Ok(Value::Bool(true))
        );
        assert_eq!(
            crate::call("isAbs", &[Value::String("foo".to_owned())]),
            Ok(Value::Bool(false))
        );
        assert_eq!(
            crate::call("isAbs", &[Value::String("a/..".to_owned())]),
            Ok(Value::Bool(false))
        );
        assert_eq!(
            crate::call("isAbs", &[Value::String("//".to_owned())]),
            Ok(Value::Bool(true))
        );
        // A volume name is not a root for the `path` family: one element.
        assert_eq!(
            crate::call("isAbs", &[Value::String("C:\\foo".to_owned())]),
            Ok(Value::Bool(false))
        );
        assert_eq!(
            crate::call("osIsAbs", &[Value::String("/foo".to_owned())]),
            Ok(Value::Bool(true))
        );
        assert_eq!(
            crate::call("osIsAbs", &[Value::String("foo".to_owned())]),
            Ok(Value::Bool(false))
        );
    }

    /// The two families disagree exactly where the reference says they do.
    ///
    /// Each row is an input where the `path` helper and its `os*` twin answer
    /// differently, with the reference method that explains the split named in
    /// the comment. This is the test that would fail first if a port quietly
    /// made `os*` a synonym for its partner, which is the mistake this module
    /// exists to prevent.
    #[test]
    fn the_os_family_keeps_what_the_path_family_cleans_away() {
        let cases = [
            // `Path.GetFileName` is a plain cut, so a trailing slash leaves
            // nothing; `PathBaseGo` cleans the slash away first.
            ("a/b/", "base", "b", "osBase", ""),
            // `GetFileName` does not resolve a `..` segment; `PathBaseGo` does.
            ("a/b/..", "base", "a", "osBase", ".."),
            ("a/.", "base", "a", "osBase", "."),
            // `GetDirectoryName` cuts at the last separator, so a trailing
            // slash makes the last element part of the directory, where
            // `PathDirGo` cleaned the slash away first.
            ("a/b/", "dir", "a", "osDir", "a/b"),
            ("/a/b/", "dir", "/a", "osDir", "/a/b"),
            // A path that cleans to one element has the directory `.`, where
            // `GetDirectoryName` still reports the text it did not resolve.
            ("a/..", "dir", ".", "osDir", "a"),
            ("a/../b", "dir", ".", "osDir", "a/.."),
            // `GetDirectoryName` keeps the dot segments it did not resolve.
            ("a/./b", "dir", "a", "osDir", "a/."),
            ("/../a", "dir", "/", "osDir", "/.."),
            // `GetExtension` has no answer for a name that is only dots, and a
            // trailing dot is not a suffix; `PathExt` reports the dot either way.
            ("a/..", "ext", ".", "osExt", ""),
            ("a.", "ext", ".", "osExt", ""),
            ("x/.", "ext", ".", "osExt", ""),
        ];
        for (path, helper, expected, os_helper, os_expected) in cases {
            assert_eq!(
                render(helper, path),
                expected,
                "{helper} {path:?} should be {expected:?}"
            );
            assert_eq!(
                render(os_helper, path),
                os_expected,
                "{os_helper} {path:?} should be {os_expected:?}"
            );
        }
    }

    /// `osBase` cuts, `osDir` collapses, and neither resolves a dot segment.
    ///
    /// `Path.GetFileName` is a cut at the last separator and nothing else.
    /// `Path.GetDirectoryName` is a cut too, but the prefix it returns has its
    /// runs of separators collapsed to one, which is a rewriting `GetFileName`
    /// never does and `PathDirGo` never does either.
    #[test]
    fn os_base_and_os_dir_cut_where_the_path_family_cleans() {
        assert_eq!(render("osBase", "a/b/"), "");
        assert_eq!(render("osBase", "a/b"), "b");
        assert_eq!(render("osBase", "/a/b/"), "");
        assert_eq!(render("osBase", "a//b//c"), "c");
        // A doubled separator is collapsed in the directory, not preserved.
        assert_eq!(render("osDir", "a//b//c"), "a/b");
        assert_eq!(render("osDir", "a//b//c/"), "a/b/c");
        assert_eq!(render("osDir", "a//"), "a");
        // A dot segment survives, and a leading slash collapses to the root.
        assert_eq!(render("osDir", "a/./b"), "a/.");
        assert_eq!(render("osDir", "a/../.."), "a/..");
        assert_eq!(render("osDir", "/a"), "/");
        assert_eq!(render("osDir", "//"), "/");
        // The empty path and the root itself are the null answer, which the
        // reference's `?? string.Empty` turns into the empty string.
        assert_eq!(render("osDir", ""), "");
        assert_eq!(render("osDir", "/"), "");
        // Only `/` is a separator here, so a backslash is part of the name.
        assert_eq!(render("osBase", "foo\\bar"), "foo\\bar");
        assert_eq!(render("osDir", "foo\\bar"), "");
    }

    /// Collapsing keeps one separator and drops the one that cut the prefix.
    #[test]
    fn collapse_slashes_keeps_one_separator() {
        assert_eq!(collapse_slashes("a//b"), "a/b");
        assert_eq!(collapse_slashes("a/"), "a");
        assert_eq!(collapse_slashes("///"), "/");
        assert_eq!(collapse_slashes("a.b/c"), "a.b/c");
        assert_eq!(collapse_slashes(""), "");
    }

    /// `clean` and `osClean` agree on the platform the fixture was recorded on.
    ///
    /// The reference's `CleanOsPath` is `CleanSlashPath` with
    /// `Path.DirectorySeparatorChar` and `Path.IsPathRooted` substituted in, and
    /// both of those are `/` and `StartsWith('/')` where the parity fixture was
    /// recorded — its own test spells the Windows answer to
    /// `osClean "/foo/../foo/../bar"` as `\bar`. Rendering a Compose file has to
    /// give the same bytes everywhere, so the two helpers are one function and
    /// this is the assertion that says so deliberately.
    #[test]
    fn clean_and_os_clean_agree_on_this_platform() {
        for path in [
            "",
            ".",
            "..",
            "/",
            "///",
            "a//b",
            "/foo/../foo/../bar",
            "a/../..",
        ] {
            assert_eq!(render("clean", path), render("osClean", path), "{path:?}");
        }
        // The Unix answer is the one the fixture recorded.
        assert_eq!(render("osClean", "/foo/../foo/../bar"), "/bar");
    }

    /// Every helper here takes exactly one rendered string argument.
    ///
    /// `One` and `OneBoolean` in the reference count to one, so zero arguments
    /// and two arguments are both caller errors rather than a default.
    #[test]
    fn every_helper_takes_exactly_one_argument() {
        for (helper, _) in HELPERS {
            assert!(
                takes_rendered_strings(helper),
                "{helper} is handed its argument already rendered"
            );
            let wrong_count = |actual| Error::WrongArgumentCount {
                helper: helper.to_owned(),
                expected: "1".to_owned(),
                actual,
            };
            assert_eq!(crate::call(helper, &[]), Err(wrong_count(0)));
            assert_eq!(
                crate::call(
                    helper,
                    &[Value::String("a".to_owned()), Value::String("b".to_owned())],
                ),
                Err(wrong_count(2))
            );
        }
    }

    /// An argument that is not a string is rendered, or refused.
    ///
    /// The engine renders the argument before this module sees it, so a number
    /// arrives as the text Go would print; a list or a map is refused rather than
    /// turned into `[a b]`, which is not a path.
    #[test]
    fn a_scalar_argument_is_rendered_and_a_collection_is_refused() {
        assert_eq!(render("base", "12"), "12");
        assert_eq!(
            crate::call("base", &[Value::Number(12.0)]),
            Ok(Value::String("12".to_owned()))
        );
        assert_eq!(
            crate::call("base", &[Value::Bool(true)]),
            Ok(Value::String("true".to_owned()))
        );
        let error =
            crate::call("base", &[Value::List(vec![Value::String("a".to_owned())])]).unwrap_err();
        assert!(
            matches!(&error, Error::InvalidArgument { helper, .. } if helper == "base"),
            "a list argument reported {error}"
        );
    }

    /// A name this module does not claim is left to the next module.
    #[test]
    fn an_unclaimed_name_is_not_mine() {
        assert!(!takes_rendered_strings("abs"));
        assert!(!takes_rendered_strings("osBaseDir"));
        assert!(!takes_rendered_strings("baseName"));
    }
}
