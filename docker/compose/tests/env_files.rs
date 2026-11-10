//! Service-level `env_file` and `label_file`.
//!
//! These are how a Compose document takes a secret from a file without putting
//! it in the document, which is the whole reason they exist. They are also the
//! one Compose feature that makes a document name a filesystem path, so the read
//! is gated: the document chooses the path and the caller chooses the bytes.
//!
//! The precedence expectations were confirmed against `docker compose config`
//! on the same files, not derived from the specification.

use std::collections::BTreeMap;

use neotales_docker_compose::{
    ComposeProject, ComposeProjectOptions, EnvFilePolicy, InterpolationPolicy, InterpolationValues,
};

fn options(policy: EnvFilePolicy, files: &[(&str, &str)]) -> ComposeProjectOptions {
    ComposeProjectOptions {
        merge: neotales_docker_compose::MergePolicy::Reject,
        interpolation: InterpolationPolicy::explicit_values(),
        env_file: policy,
        env_files: files
            .iter()
            .map(|(path, contents)| ((*path).to_owned(), (*contents).to_owned()))
            .collect::<BTreeMap<String, String>>(),
        ..ComposeProjectOptions::default()
    }
}

fn load(sources: &[(&str, &str)], options: &ComposeProjectOptions) -> ComposeProject {
    ComposeProject::parse_sources(sources, &InterpolationValues::new(), options.clone())
        .expect("project loads")
}

/// A document with a secret in a file, an explicit override, and a label file.
const DOCUMENT: &str = "services:\n  app:\n    image: alpine\n    env_file: [app.env]\n    label_file: app.labels\n    environment:\n      EXPLICIT: from-document\n    labels:\n      tier: document-wins\n";

const ENV_FILE: &str = "DB_PASSWORD=secret-from-file\nEXPLICIT=from-file\nTIER=from-file\n";
const LABEL_FILE: &str = "owner=platform\ntier=from-file\n";

#[test]
fn a_file_supplies_what_the_document_does_not_and_the_document_wins_on_a_collision() {
    // Verified against `docker compose config` on these exact files.
    let project = load(
        &[(DOCUMENT, "/p/compose.yaml")],
        &options(
            EnvFilePolicy::CallerSupplied,
            &[("/p/app.env", ENV_FILE), ("/p/app.labels", LABEL_FILE)],
        ),
    );
    let app = &project.services["app"];

    // Only the file supplied it, so it is present.
    assert_eq!(
        app.environment.get("DB_PASSWORD").map(String::as_str),
        Some("secret-from-file")
    );
    // The document and the file both set these, and the document wins.
    assert_eq!(
        app.environment.get("EXPLICIT").map(String::as_str),
        Some("from-document")
    );
    // Labels follow the same rule.
    assert_eq!(
        app.labels.get("owner").map(String::as_str),
        Some("platform")
    );
    assert_eq!(
        app.labels.get("tier").map(String::as_str),
        Some("document-wins")
    );
}

#[test]
fn a_file_alone_supplies_everything_it_names() {
    let project = load(
        &[(
            "services:\n  app:\n    image: alpine\n    env_file: app.env\n",
            "/p/compose.yaml",
        )],
        &options(
            EnvFilePolicy::CallerSupplied,
            &[("/p/app.env", "A=1\nB=2\n")],
        ),
    );
    let app = &project.services["app"];
    assert_eq!(app.environment.get("A").map(String::as_str), Some("1"));
    assert_eq!(app.environment.get("B").map(String::as_str), Some("2"));
}

#[test]
fn several_files_are_read_in_order_with_the_later_one_winning() {
    let project = load(
        &[(
            "services:\n  app:\n    image: alpine\n    env_file: [a.env, b.env]\n",
            "/p/compose.yaml",
        )],
        &options(
            EnvFilePolicy::CallerSupplied,
            &[
                ("/p/a.env", "SHARED=from-a\nONLY_A=a\n"),
                ("/p/b.env", "SHARED=from-b\n"),
            ],
        ),
    );
    let app = &project.services["app"];
    assert_eq!(
        app.environment.get("SHARED").map(String::as_str),
        Some("from-b")
    );
    assert_eq!(app.environment.get("ONLY_A").map(String::as_str), Some("a"));
}

#[test]
fn a_declared_file_with_no_supplied_contents_is_an_error_naming_the_path() {
    // Silently treating it as empty would produce a service that looks
    // configured and is missing its secret, which is the failure mode this
    // feature exists to prevent.
    let error = ComposeProject::parse_sources(
        &[(
            "services:\n  app:\n    image: alpine\n    env_file: app.env\n",
            "/p/compose.yaml",
        )],
        &InterpolationValues::new(),
        options(EnvFilePolicy::CallerSupplied, &[]),
    )
    .expect_err("no contents were supplied");
    assert_eq!(error.code(), "compose_env_file_missing");
    assert!(
        error.message().contains("/p/app.env"),
        "the diagnostic must name the resolved path: {error:?}"
    );
}

#[test]
fn the_default_policy_refuses_a_document_that_declares_one() {
    // Reading a path a document chose is gated the same way the other
    // document-declared filesystem access is.
    for (field, source) in [
        (
            "env_file",
            "services:\n  app:\n    image: alpine\n    env_file: app.env\n",
        ),
        (
            "label_file",
            "services:\n  app:\n    image: alpine\n    label_file: app.labels\n",
        ),
    ] {
        let error = ComposeProject::parse_sources(
            &[(source, "/p/compose.yaml")],
            &InterpolationValues::new(),
            options(
                EnvFilePolicy::Reject,
                &[("/p/app.env", ""), ("/p/app.labels", "")],
            ),
        )
        .expect_err("the default policy refuses");
        assert_eq!(error.code(), "compose_env_file_rejected", "{field}");
        assert!(error.path().contains(field), "{error:?}");
    }
}

#[test]
fn a_relative_path_resolves_against_the_declaring_file_not_the_working_directory() {
    // Two projects in different directories may both declare `app.env`; each
    // must get its own.
    let project = load(
        &[
            (
                "services:\n  app:\n    image: alpine\n    env_file: app.env\n",
                "/one/compose.yaml",
            ),
            (
                "services:\n  app:\n    image: alpine\n    env_file: app.env\n",
                "/two/compose.yaml",
            ),
        ],
        &ComposeProjectOptions {
            // Two sources for the same project, so a merge policy is required;
            // the point of the case is that each source resolved `app.env`
            // against its own directory rather than the process's.
            merge: neotales_docker_compose::MergePolicy::MergeServices,
            interpolation: InterpolationPolicy::explicit_values(),
            env_file: EnvFilePolicy::CallerSupplied,
            env_files: BTreeMap::from([
                ("/one/app.env".to_owned(), "WHICH=one\n".to_owned()),
                ("/two/app.env".to_owned(), "WHICH=two\n".to_owned()),
            ]),
            ..ComposeProjectOptions::default()
        },
    );
    // Later source wins the whole service, and the resolved path is the later
    // file's, so the value is `two`.
    assert_eq!(
        project.services["app"]
            .environment
            .get("WHICH")
            .map(String::as_str),
        Some("two")
    );
}

#[test]
fn an_absolute_declared_path_is_used_as_written() {
    let project = load(
        &[(
            "services:\n  app:\n    image: alpine\n    env_file: /secrets/app.env\n",
            "/p/compose.yaml",
        )],
        &options(
            EnvFilePolicy::CallerSupplied,
            &[("/secrets/app.env", "K=v\n")],
        ),
    );
    assert_eq!(
        project.services["app"]
            .environment
            .get("K")
            .map(String::as_str),
        Some("v")
    );
}

#[test]
fn a_bare_file_name_resolves_against_the_working_directory() {
    // A Compose file named with no directory component, as when a caller passes
    // a bare name on the command line. Both sides of the lookup must agree.
    let project = load(
        &[(
            "services:\n  app:\n    image: alpine\n    env_file: app.env\n",
            "compose.yaml",
        )],
        &options(EnvFilePolicy::CallerSupplied, &[("./app.env", "K=v\n")]),
    );
    assert_eq!(
        project.services["app"]
            .environment
            .get("K")
            .map(String::as_str),
        Some("v")
    );
}

#[test]
fn a_file_uses_the_same_dotenv_syntax_as_an_env_file_option() {
    // One parser, so the two spellings cannot drift: quoting, `export`, comments,
    // and blank lines all behave identically.
    let contents = "# a comment\nexport QUOTED=\"a b\"\n\nSINGLE='c'\nEMPTY=\n";
    let project = load(
        &[(
            "services:\n  app:\n    image: alpine\n    env_file: app.env\n",
            "/p/compose.yaml",
        )],
        &options(EnvFilePolicy::CallerSupplied, &[("/p/app.env", contents)]),
    );
    let app = &project.services["app"];
    assert_eq!(
        app.environment.get("QUOTED").map(String::as_str),
        Some("a b")
    );
    assert_eq!(app.environment.get("SINGLE").map(String::as_str), Some("c"));
    assert_eq!(app.environment.get("EMPTY").map(String::as_str), Some(""));
}

#[test]
fn file_values_survive_a_merge_without_the_override_erasing_them() {
    // An override that only sets `environment` must not drop the keys the base
    // got from its `env_file`.
    let project = load(
        &[
            (
                "services:\n  app:\n    image: alpine\n    env_file: app.env\n",
                "/p/compose.yaml",
            ),
            (
                "services:\n  app:\n    environment:\n      EXTRA: added\n",
                "/p/compose.override.yaml",
            ),
        ],
        &ComposeProjectOptions {
            merge: neotales_docker_compose::MergePolicy::MergeServices,
            interpolation: InterpolationPolicy::explicit_values(),
            env_file: EnvFilePolicy::CallerSupplied,
            env_files: BTreeMap::from([("/p/app.env".to_owned(), "SECRET=s\n".to_owned())]),
            ..ComposeProjectOptions::default()
        },
    );
    let app = &project.services["app"];
    assert_eq!(app.environment.get("SECRET").map(String::as_str), Some("s"));
    assert_eq!(
        app.environment.get("EXTRA").map(String::as_str),
        Some("added")
    );
    assert_eq!(app.image, "alpine", "the base image must survive the merge");
}

/// The caller's key may be spelled with this host's separator.
///
/// The document declares `app.env`, so the resolved path is whatever this host's
/// `join` produces: `/p/app.env` on Linux and `/p\app.env` on Windows. The key
/// is normalized to `/` on both sides of the lookup, so a caller who writes
/// either spelling of the path they know finds the same entry. Before the fix
/// the lookup key was the `Path`'s own display text, so the `/`-spelled key
/// every other fixture in this file uses missed on Windows and worked on Linux.
#[test]
fn a_supplied_key_may_use_the_hosts_separator() {
    let host_key = std::path::Path::new("/p")
        .join("app.env")
        .display()
        .to_string();
    let project = load(
        &[(
            "services:\n  app:\n    image: alpine\n    env_file: app.env\n",
            "/p/compose.yaml",
        )],
        &options(
            EnvFilePolicy::CallerSupplied,
            &[(host_key.as_str(), "K=v\n")],
        ),
    );
    assert_eq!(
        project.services["app"]
            .environment
            .get("K")
            .map(String::as_str),
        Some("v")
    );
}

/// The `compose_env_file_missing` diagnostic names the key, not a host spelling.
///
/// A caller who reads the error has to look the path up in `env_files`, so the
/// message has to name the text the lookup accepts. The assertion is one string
/// on every host, which is what pins that: the message used to be
/// `Path::display()`, which on Windows said `/p\app.env`.
#[test]
fn the_missing_file_diagnostic_names_the_key_the_caller_looks_up() {
    let error = ComposeProject::parse_sources(
        &[(
            "services:\n  app:\n    image: alpine\n    env_file: app.env\n",
            "/p/compose.yaml",
        )],
        &InterpolationValues::new(),
        options(EnvFilePolicy::CallerSupplied, &[]),
    )
    .expect_err("no contents were supplied");
    assert_eq!(error.code(), "compose_env_file_missing");
    assert!(
        error.message().contains("/p/app.env"),
        "the diagnostic must name the resolved path: {error:?}"
    );
}

/// A `.env` a Windows editor saved supplies its keys.
///
/// UTF-8 with a byte-order mark has been the Notepad default since Windows 10
/// 1903, so the caller-supplied bytes for a document written on Windows arrive
/// with one. Before the fix the mark became the first character of the first key
/// and the whole file was rejected with `compose_env_file_invalid` wrapping
/// `compose_invalid_environment_name` — a file that Docker loads, refused here.
#[test]
fn a_byte_order_marked_file_supplies_its_keys() {
    let project = load(
        &[(
            "services:\n  app:\n    image: alpine\n    env_file: app.env\n",
            "/p/compose.yaml",
        )],
        &options(
            EnvFilePolicy::CallerSupplied,
            &[("/p/app.env", "\u{feff}DB_PASSWORD=s\nOTHER=2\n")],
        ),
    );
    let app = &project.services["app"];
    assert_eq!(
        app.environment.get("DB_PASSWORD").map(String::as_str),
        Some("s")
    );
    assert_eq!(app.environment.get("OTHER").map(String::as_str), Some("2"));
}
