//! Conformance tests for command chain parsing and process execution.
//!
//! These drive the crate through its public API and spawn real child processes,
//! including the crate's own conformance fixture binary, so a passing run means
//! the behaviour works rather than merely parses.

// `missing_docs` is a workspace lint aimed at the published API. A test binary
// has no public API to document, so the lint firing here is noise rather than a
// finding. Scoped to this file, so an undocumented public item in the crate is
// still reported.
#![allow(missing_docs)]

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use neotales_process::{Error, ExecutionOptions, execute_argv, execute_chain, parse};
use tempfile::tempdir;

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_neotales-process-fixture"))
}

fn environment() -> BTreeMap<String, String> {
    let fixture = fixture();
    let mut environment = BTreeMap::from([(
        if cfg!(windows) { "Path" } else { "PATH" }.into(),
        fixture.parent().unwrap().to_string_lossy().into_owned(),
    )]);
    if cfg!(windows) {
        environment.insert("PATHEXT".into(), ".EXE".into());
    }
    environment
}

fn options<'a>(
    directory: &'a Path,
    environment: &'a BTreeMap<String, String>,
    cancelled: &'a dyn Fn() -> bool,
    timeout: Option<Duration>,
) -> ExecutionOptions<'a> {
    ExecutionOptions {
        working_directory: directory,
        environment,
        passthrough: &[],
        is_cancelled: cancelled,
        timeout,
    }
}

#[test]
fn literal_argv_is_delivered_without_shell_interpretation() {
    let directory = tempdir().unwrap();
    let output = directory.path().join("argv");
    let environment = environment();
    let cancelled = || false;
    let arguments = vec![
        "write-args".into(),
        output.to_string_lossy().into_owned(),
        "$HOME".into(),
        "$(not-run)".into(),
        "a && b | c; d".into(),
        String::new(),
        "two words".into(),
    ];

    assert!(
        execute_argv(
            fixture().to_str().unwrap(),
            &arguments,
            &options(directory.path(), &environment, &cancelled, None)
        )
        .unwrap()
        .success()
    );
    assert_eq!(
        fs::read_to_string(output).unwrap(),
        "24484f4d45\n24286e6f742d72756e29\n612026262062207c20633b2064\n\n74776f20776f726473"
    );
}

#[test]
fn supplied_path_performs_executable_lookup_with_windows_key_casing() {
    let directory = tempdir().unwrap();
    let environment = environment();
    let cancelled = || false;
    let status = execute_argv(
        "neotales-process-fixture",
        &["exit".into(), "0".into()],
        &options(directory.path(), &environment, &cancelled, None),
    )
    .unwrap();
    assert!(status.success());
}

#[test]
fn pipeline_returns_the_final_command_status() {
    let directory = tempdir().unwrap();
    let environment = environment();
    let cancelled = || false;
    let program = "neotales-process-fixture";
    let succeeds = parse(&format!("{program} exit 7 | {program} exit 0")).unwrap();
    let fails = parse(&format!("{program} exit 0 | {program} exit 9")).unwrap();
    let options = options(directory.path(), &environment, &cancelled, None);
    assert!(execute_chain(&succeeds, &options).unwrap().success());
    assert_eq!(execute_chain(&fails, &options).unwrap().code(), Some(9));
}

#[test]
fn cancellation_and_timeout_stop_hermetic_children() {
    let directory = tempdir().unwrap();
    let environment = environment();
    let cancelled = AtomicBool::new(false);
    let cancellation = || cancelled.load(Ordering::Relaxed);
    cancelled.store(true, Ordering::Relaxed);
    assert!(matches!(
        execute_argv(
            fixture().to_str().unwrap(),
            &["wait".into(), "1000".into()],
            &options(directory.path(), &environment, &cancellation, None),
        ),
        Err(Error::Cancelled)
    ));

    let never_cancelled = || false;
    assert!(matches!(
        execute_argv(
            fixture().to_str().unwrap(),
            &["wait".into(), "1000".into()],
            &options(
                directory.path(),
                &environment,
                &never_cancelled,
                Some(Duration::from_millis(20)),
            ),
        ),
        Err(Error::TimedOut)
    ));
}
