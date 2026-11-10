//! Conformance fixture binary, run by the other language ports.
//!
//! It takes one subcommand: `write-args` writes each argument to a file as
//! hex-encoded lines, `wait` sleeps for a given number of milliseconds, and
//! `exit` exits with a given code. Other ports assert against this behaviour, so
//! changing an output or an exit code is a change to a contract they depend on.

// Not a published API surface, so the workspace documentation lint has nothing to
// say about it. Scoped to this file rather than the crate.
#![allow(missing_docs)]

use std::{env, fmt::Write as _, fs, process::ExitCode, thread, time::Duration};

fn main() -> ExitCode {
    let arguments: Vec<_> = env::args().skip(1).collect();
    match arguments.first().map(String::as_str) {
        Some("write-args") => {
            let Some(path) = arguments.get(1) else {
                return ExitCode::from(2);
            };
            let output = arguments[2..]
                .iter()
                .map(|argument| {
                    let mut encoded = String::new();
                    for byte in argument.as_bytes() {
                        // `String` formatting has no fallible backend; this is
                        // a fixture invariant, not an effect-boundary result.
                        write!(&mut encoded, "{byte:02x}")
                            .expect("writing to an in-memory String cannot fail");
                    }
                    encoded
                })
                .collect::<Vec<_>>()
                .join("\n");
            match fs::write(path, output) {
                Ok(()) => ExitCode::SUCCESS,
                Err(_) => ExitCode::from(2),
            }
        }
        Some("wait") => {
            let milliseconds = arguments
                .get(1)
                .and_then(|value| value.parse().ok())
                .unwrap_or(1_000);
            thread::sleep(Duration::from_millis(milliseconds));
            ExitCode::SUCCESS
        }
        Some("exit") => arguments
            .get(1)
            .and_then(|value| value.parse::<u8>().ok())
            .map_or(ExitCode::from(2), ExitCode::from),
        _ => ExitCode::from(2),
    }
}
