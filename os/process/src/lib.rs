//! Portable command graph parsing and direct process execution without a shell.
#![doc = include_str!("../README.md")]

use std::{
    collections::BTreeMap,
    fmt,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use neotales_args::Args;

/// A parsed command line: one or more pipelines joined by operators.
///
/// This is the whole point of the crate. A command is parsed into a structure
/// that can be inspected and reviewed before anything runs, rather than being
/// handed to a shell as a string.
///
/// ```
/// use neotales_process::parse;
///
/// // A pipe binds tighter than `&&`, so this is two pipelines joined by `&&`.
/// let chain = parse("build | test && report").expect("parses");
/// assert_eq!(chain.programs.len(), 2);
/// assert_eq!(chain.operators, [neotales_process::ChainOperator::And]);
/// assert_eq!(chain.programs[0].commands.len(), 2);
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandChain {
    /// The pipelines, in left-to-right order.
    pub programs: Vec<Pipeline>,
    /// The operators joining them. One fewer than `programs`.
    pub operators: Vec<ChainOperator>,
}

/// One or more commands joined by a pipe, all writing into the next.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pipeline {
    /// The commands in this pipeline, in left-to-right order.
    pub commands: Vec<Argv>,
}

/// A program and its arguments, already separated.
///
/// The arguments are a vector rather than a string because that is the only
/// form in which they can be passed to a process without a second round of
/// parsing, and a second round of parsing is where quoting bugs live.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Argv {
    /// The program to run, which may be an unqualified name to be looked up on
    /// the configured search path.
    pub program: String,
    /// The arguments, already split and unquoted.
    pub arguments: Vec<String>,
}

/// How one pipeline is joined to the next.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChainOperator {
    /// Run the next pipeline only if this one succeeded. Written `&&`.
    And,
    /// Run the next pipeline only if this one failed. Written `||`.
    Or,
    /// Run the next pipeline regardless. Written `;`.
    Sequence,
}

enum Token {
    Argument(String),
    Operator(&'static str),
}

/// Caller-provided execution inputs. No process-global state is modified.
/// The inputs a caller supplies to run a command.
///
/// Nothing here is process-global. The environment is the complete child
/// environment rather than a set of edits to the parent's, so a run cannot
/// observe or disturb anything the caller did not hand it.
///
/// ```
/// use std::{collections::BTreeMap, time::Duration};
/// use neotales_process::ExecutionOptions;
///
/// let environment: BTreeMap<String, String> =
///     [("MODE".to_owned(), "release".to_owned())].into_iter().collect();
/// let options = ExecutionOptions {
///     working_directory: std::path::Path::new("."),
///     environment: &environment,
///     passthrough: &[],
///     is_cancelled: &|| false,
///     timeout: Some(Duration::from_secs(30)),
/// };
/// # let _ = options;
/// ```
///
/// [`Debug`](std::fmt::Debug) is hand-written. `is_cancelled` is the caller's
/// closure and is not `Debug` at all, so a derive would not even compile — a
/// `Debug` bound on that field would be a `Debug` bound on something the
/// caller wrote. The `environment` map is deliberately not printed either: it
/// is the child's *complete* environment, and a caller who puts a token or a
/// password in it has put it somewhere a log line would otherwise carry it. The
/// `passthrough` names are printed, because a variable name is not a secret and
/// "which three variables was this run inheriting" is usually the question. The
/// remaining fields are the ones that describe a run: where, how long, and how
/// much environment the child will get.
pub struct ExecutionOptions<'a> {
    /// The directory the child runs in.
    pub working_directory: &'a Path,
    /// The child's complete environment. Replaces the parent's rather than
    /// merging with it, including on Windows, where the standard library will
    /// otherwise consult the parent while resolving an executable.
    pub environment: &'a BTreeMap<String, String>,
    /// Variables named here are copied from the parent into `environment`. An
    /// empty slice, the default in practice, means the child inherits nothing.
    pub passthrough: &'a [String],
    /// Polled while the child runs. Returning `true` stops the child.
    pub is_cancelled: &'a dyn Fn() -> bool,
    /// How long to wait before stopping the child. `None` waits indefinitely.
    pub timeout: Option<Duration>,
}

impl fmt::Debug for ExecutionOptions<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `is_cancelled` is a caller's closure and is not printed.
        // `environment` is a count, not a map: its values may be secrets.
        // `passthrough` is a list of names, which are not secrets.
        formatter
            .debug_struct("ExecutionOptions")
            .field("working_directory", &self.working_directory)
            .field("environment_len", &self.environment.len())
            .field("passthrough", &self.passthrough)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

/// Everything that can go wrong between parsing a command and it finishing.
#[derive(Debug)]
pub enum Error {
    /// The command line contained nothing to run.
    EmptyCommand,
    /// A quote was opened and never closed.
    UnterminatedQuote,
    /// The command line ended with a backslash that had nothing to escape.
    TrailingEscape,
    /// An operator such as `|` or `&&` had nothing to join.
    MissingCommand(String),
    /// A pipeline contained no command at all.
    EmptyPipeline,
    /// The child process could not be started.
    Start(std::io::Error),
    /// Reading from, or waiting on, the child failed.
    Io(std::io::Error),
    /// An invariant this crate is responsible for was violated. A bug here.
    Internal(&'static str),
    /// The caller's cancellation check returned true.
    Cancelled,
    /// The caller's timeout elapsed before the child finished.
    TimedOut,
    /// A child exited or was stopped, and its descendants could not be cleaned up.
    StopProcessTree {
        /// A stable, machine-readable reason.
        reason: &'static str,
        /// A human-readable explanation, which may name a process.
        message: String,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyCommand => output.write_str("portable command is empty"),
            Self::UnterminatedQuote => {
                output.write_str("portable command has an unterminated quote")
            }
            Self::TrailingEscape => output.write_str("portable command has a trailing escape"),
            Self::MissingCommand(operator) => {
                write!(
                    output,
                    "portable command is missing an argv near {operator}"
                )
            }
            Self::EmptyPipeline => output.write_str("portable pipeline is empty"),
            Self::Start(error) => write!(output, "failed to start process: {error}"),
            Self::Io(error) => error.fmt(output),
            Self::Internal(message) => output.write_str(message),
            Self::Cancelled => output.write_str("execution cancelled"),
            Self::TimedOut => output.write_str("execution timed out"),
            Self::StopProcessTree { reason, message } => {
                write!(output, "failed to stop {reason} process tree: {message}")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Start(error) | Self::Io(error) => Some(error),
            Self::EmptyCommand
            | Self::UnterminatedQuote
            | Self::TrailingEscape
            | Self::MissingCommand(_)
            | Self::EmptyPipeline
            | Self::Internal(_)
            | Self::Cancelled
            | Self::TimedOut
            | Self::StopProcessTree { .. } => None,
        }
    }
}

/// Parses a literal command graph without environment expansion or execution.
///
/// # Errors
///
/// Returns an error for malformed quoting, escaping, or incomplete operators.
pub fn parse(input: &str) -> Result<CommandChain, Error> {
    let tokens = tokenize(input)?;
    if tokens.is_empty() {
        return Err(Error::EmptyCommand);
    }
    let mut programs = Vec::new();
    let mut operators = Vec::new();
    let mut pipeline = Vec::new();
    let mut argv = Vec::new();
    for token in tokens {
        match token {
            Token::Argument(argument) => argv.push(argument),
            Token::Operator("|") => push_argv(&mut pipeline, &mut argv, "|")?,
            Token::Operator(operator @ ("&&" | "||" | ";")) => {
                push_argv(&mut pipeline, &mut argv, operator)?;
                programs.push(Pipeline { commands: pipeline });
                pipeline = Vec::new();
                operators.push(match operator {
                    "&&" => ChainOperator::And,
                    "||" => ChainOperator::Or,
                    ";" => ChainOperator::Sequence,
                    _ => {
                        return Err(Error::Internal(
                            "command tokenizer produced an unknown operator",
                        ));
                    }
                });
            }
            Token::Operator(_operator) => {
                return Err(Error::Internal(
                    "command tokenizer produced an unexpected operator",
                ));
            }
        }
    }
    push_argv(&mut pipeline, &mut argv, "end")?;
    programs.push(Pipeline { commands: pipeline });
    Ok(CommandChain {
        programs,
        operators,
    })
}

/// Executes a parsed command graph by directly spawning its programs.
///
/// The final command of each pipeline receives `options.passthrough`.
///
/// # Errors
///
/// Returns process, cancellation, or timeout errors.
pub fn execute_chain(
    chain: &CommandChain,
    options: &ExecutionOptions<'_>,
) -> Result<ExitStatus, Error> {
    let mut status = None;
    for (index, pipeline) in chain.programs.iter().enumerate() {
        let should_run = if index == 0 {
            true
        } else {
            match chain
                .operators
                .get(index - 1)
                .ok_or_else(|| Error::MissingCommand("command graph".into()))?
            {
                ChainOperator::And => status.is_some_and(|status: ExitStatus| status.success()),
                ChainOperator::Or => status.is_some_and(|status: ExitStatus| !status.success()),
                ChainOperator::Sequence => true,
            }
        };
        if should_run {
            status = Some(execute_pipeline(pipeline, options)?);
        }
    }
    status.ok_or(Error::EmptyCommand)
}

/// Executes one program directly, appending `options.passthrough`.
///
/// # Errors
///
/// Returns process, cancellation, or timeout errors.
pub fn execute_argv(
    program: &str,
    arguments: &[String],
    options: &ExecutionOptions<'_>,
) -> Result<ExitStatus, Error> {
    let program = resolve_program(program, options.environment);
    let mut command = Command::new(program);
    command.args(arguments).args(options.passthrough);
    configure_command(&mut command, options);
    let child = command.spawn().map_err(Error::Start)?;
    wait_for_children(vec![child], options)
}

fn push_argv(
    pipeline: &mut Vec<Argv>,
    argv: &mut Vec<String>,
    operator: &str,
) -> Result<(), Error> {
    let Some(program) = (!argv.is_empty()).then(|| argv.remove(0)) else {
        return Err(Error::MissingCommand(operator.into()));
    };
    pipeline.push(Argv {
        program,
        arguments: std::mem::take(argv),
    });
    Ok(())
}

fn tokenize(input: &str) -> Result<Vec<Token>, Error> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    let mut escaped = false;
    let mut characters = input.chars().peekable();
    while let Some(character) = characters.next() {
        if escaped {
            current.push(character);
            escaped = false;
        } else if character == '\\' && quote != Some('\'') {
            current.push(character);
            escaped = true;
        } else if matches!(character, '\'' | '"') {
            if quote == Some(character) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(character);
            }
            current.push(character);
        } else if quote.is_some() {
            current.push(character);
        } else if character.is_whitespace() {
            push_token(&mut tokens, &mut current)?;
        } else if matches!(character, ';' | '|' | '&') {
            push_token(&mut tokens, &mut current)?;
            let operator = match (character, characters.peek()) {
                ('|', Some('|')) => {
                    characters.next();
                    "||"
                }
                ('&', Some('&')) => {
                    characters.next();
                    "&&"
                }
                ('|', _) => "|",
                (';', _) => ";",
                _ => return Err(Error::MissingCommand("&".into())),
            };
            tokens.push(Token::Operator(operator));
        } else {
            current.push(character);
        }
    }
    push_token(&mut tokens, &mut current)?;
    Ok(tokens)
}

fn push_token(tokens: &mut Vec<Token>, current: &mut String) -> Result<(), Error> {
    if !current.trim().is_empty() {
        tokens.extend(
            Args::parse(current)
                .map_err(|error| match error {
                    neotales_args::Error::UnterminatedQuote => Error::UnterminatedQuote,
                    neotales_args::Error::TrailingEscape => Error::TrailingEscape,
                })?
                .into_vec()
                .into_iter()
                .map(Token::Argument),
        );
    }
    current.clear();
    Ok(())
}

fn execute_pipeline(
    pipeline: &Pipeline,
    options: &ExecutionOptions<'_>,
) -> Result<ExitStatus, Error> {
    let mut children = Vec::with_capacity(pipeline.commands.len());
    let mut previous_stdout = None;
    for (index, argv) in pipeline.commands.iter().enumerate() {
        let program = resolve_program(&argv.program, options.environment);
        let mut command = Command::new(program);
        command.args(&argv.arguments);
        if index + 1 == pipeline.commands.len() {
            command.args(options.passthrough);
        }
        configure_command(&mut command, options);
        command.stdin(
            previous_stdout
                .take()
                .map_or_else(Stdio::inherit, Stdio::from),
        );
        if index + 1 < pipeline.commands.len() {
            command.stdout(Stdio::piped());
        }
        let mut child = command.spawn().map_err(Error::Start)?;
        previous_stdout = child.stdout.take();
        children.push(child);
    }
    wait_for_children(children, options)
}

/// Resolves an unqualified executable against the exact child `PATH`.
///
/// `std::process::Command` can consult the parent process environment during
/// executable lookup on Windows, even after `env_clear`. This crate deliberately
/// supplies an isolated child environment, so look up configured tool paths
/// ourselves before spawning. Windows additionally tries the child `PATHEXT`
/// list, which makes Git for Windows `.cmd` utilities available to portable
/// tasks.
fn resolve_program(program: &str, environment: &BTreeMap<String, String>) -> PathBuf {
    let path = Path::new(program);
    if path.is_absolute() || path.components().count() > 1 {
        return path.to_owned();
    }

    let configured_path = environment.iter().find_map(|(key, value)| {
        if cfg!(windows) {
            key.eq_ignore_ascii_case("PATH").then_some(value)
        } else {
            (key == "PATH").then_some(value)
        }
    });
    let extensions = executable_extensions(program, environment);
    if let Some(configured_path) = configured_path {
        for directory in std::env::split_paths(configured_path) {
            for extension in &extensions {
                let candidate = if extension.is_empty() {
                    directory.join(program)
                } else {
                    directory.join(format!("{program}{extension}"))
                };
                if candidate.is_file() {
                    return candidate;
                }
            }
        }
    }
    path.to_owned()
}

#[cfg(windows)]
fn executable_extensions(program: &str, environment: &BTreeMap<String, String>) -> Vec<String> {
    if Path::new(program).extension().is_some() {
        return vec![String::new()];
    }
    environment
        .iter()
        .find_map(|(key, value)| key.eq_ignore_ascii_case("PATHEXT").then_some(value))
        .map(|value| {
            value
                .split(';')
                .filter(|extension| !extension.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .filter(|extensions: &Vec<String>| !extensions.is_empty())
        .unwrap_or_else(|| vec![".COM".into(), ".EXE".into(), ".BAT".into(), ".CMD".into()])
}

#[cfg(not(windows))]
fn executable_extensions(_program: &str, _environment: &BTreeMap<String, String>) -> Vec<String> {
    vec![String::new()]
}

fn configure_command(command: &mut Command, options: &ExecutionOptions<'_>) {
    command
        .current_dir(options.working_directory)
        .env_clear()
        .envs(options.environment)
        .stderr(Stdio::inherit());
    contain_process_tree(command);
}

fn wait_for_children(
    mut children: Vec<Child>,
    options: &ExecutionOptions<'_>,
) -> Result<ExitStatus, Error> {
    let started = Instant::now();
    let last = children.len().checked_sub(1).ok_or(Error::EmptyPipeline)?;
    let mut statuses = vec![None; children.len()];
    loop {
        for (index, child) in children.iter_mut().enumerate() {
            if statuses[index].is_none() {
                statuses[index] = child.try_wait().map_err(Error::Io)?;
            }
        }
        if statuses.iter().all(Option::is_some) {
            return statuses[last].ok_or(Error::Internal(
                "completed process set is missing its final status",
            ));
        }
        let reason = if (options.is_cancelled)() {
            Some("cancelled")
        } else if options
            .timeout
            .is_some_and(|limit| started.elapsed() >= limit)
        {
            Some("timed out")
        } else {
            None
        };
        if let Some(reason) = reason {
            for (index, child) in children.iter_mut().enumerate() {
                if statuses[index].is_none() {
                    stop_process_tree(child, reason)?;
                }
            }
            return Err(if reason == "cancelled" {
                Error::Cancelled
            } else {
                Error::TimedOut
            });
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(unix)]
fn contain_process_tree(command: &mut Command) {
    use std::os::unix::process::CommandExt as _;
    command.process_group(0);
}

#[cfg(not(unix))]
fn contain_process_tree(_command: &mut Command) {}

#[cfg(unix)]
fn stop_process_tree(child: &mut Child, reason: &'static str) -> Result<ExitStatus, Error> {
    use nix::{
        errno::Errno,
        sys::signal::{Signal, kill},
        unistd::Pid,
    };
    let process_group = i32::try_from(child.id()).map_err(|_| Error::StopProcessTree {
        reason,
        message: "process ID is out of range".into(),
    })?;
    match kill(Pid::from_raw(-process_group), Signal::SIGKILL) {
        Ok(()) | Err(Errno::ESRCH) => {}
        Err(error) => {
            return Err(Error::StopProcessTree {
                reason,
                message: error.to_string(),
            });
        }
    }
    child.wait().map_err(Error::Io)
}

#[cfg(windows)]
fn stop_process_tree(child: &mut Child, reason: &'static str) -> Result<ExitStatus, Error> {
    let status = Command::new("taskkill")
        .args(["/PID", &child.id().to_string(), "/T", "/F"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| Error::StopProcessTree {
            reason,
            message: error.to_string(),
        })?;
    if !status.success() && child.try_wait().map_err(Error::Io)?.is_none() {
        return Err(Error::StopProcessTree {
            reason,
            message: "taskkill did not stop the process tree".into(),
        });
    }
    child.wait().map_err(Error::Io)
}

#[cfg(all(not(unix), not(windows)))]
fn stop_process_tree(child: &mut Child, reason: &'static str) -> Result<ExitStatus, Error> {
    child.kill().map_err(|error| Error::StopProcessTree {
        reason,
        message: error.to_string(),
    })?;
    child.wait().map_err(Error::Io)
}

#[cfg(test)]
mod tests {
    use super::{ChainOperator, Error, parse};

    #[cfg(unix)]
    use super::{ExecutionOptions, execute_chain};
    #[cfg(unix)]
    use std::{collections::BTreeMap, error::Error as _, io, path::Path, time::Duration};

    #[test]
    fn parses_literal_argv_pipelines_and_boolean_chains() {
        let command =
            parse("build --flag | check 'two words' && deploy || report; cleanup").unwrap();
        assert_eq!(command.programs.len(), 4);
        assert_eq!(command.programs[0].commands[0].arguments, ["--flag"]);
        assert_eq!(command.programs[0].commands[1].arguments, ["two words"]);
        assert_eq!(
            command.operators,
            [
                ChainOperator::And,
                ChainOperator::Or,
                ChainOperator::Sequence
            ]
        );
    }

    #[test]
    fn keeps_quoted_operators_literal_and_rejects_incomplete_syntax() {
        assert_eq!(
            parse("echo 'a && b | c'").unwrap().programs[0].commands[0].arguments,
            ["a && b | c"]
        );
        assert!(matches!(
            parse("echo ok &&"),
            Err(Error::MissingCommand(operator)) if operator == "end"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn executes_pipelines_and_chain_short_circuiting_without_a_shell() {
        let chain = parse("false && false || printf x | grep x; true").unwrap();
        let environment = BTreeMap::from([("PATH".into(), std::env::var("PATH").unwrap())]);
        let cancelled = || false;
        let options = ExecutionOptions {
            working_directory: Path::new("."),
            environment: &environment,
            passthrough: &[],
            is_cancelled: &cancelled,
            timeout: Some(Duration::from_secs(5)),
        };
        assert!(execute_chain(&chain, &options).unwrap().success());

        let chain = parse("printf hello | grep").unwrap();
        let passthrough = vec!["hello".into()];
        let options = ExecutionOptions {
            passthrough: &passthrough,
            ..options
        };
        assert!(execute_chain(&chain, &options).unwrap().success());
    }

    #[cfg(unix)]
    #[test]
    fn process_start_failure_retains_the_io_source() {
        let environment = BTreeMap::new();
        let cancelled = || false;
        let options = ExecutionOptions {
            working_directory: Path::new("."),
            environment: &environment,
            passthrough: &[],
            is_cancelled: &cancelled,
            timeout: None,
        };
        let error = super::execute_argv("program-that-does-not-exist", &[], &options).unwrap_err();
        assert!(
            error
                .source()
                .and_then(|source| source.downcast_ref::<io::Error>())
                .is_some()
        );
    }

    #[cfg(unix)]
    #[test]
    fn stops_a_direct_process_when_it_times_out() {
        let environment = BTreeMap::from([("PATH".into(), std::env::var("PATH").unwrap())]);
        let cancelled = || false;
        let options = ExecutionOptions {
            working_directory: Path::new("."),
            environment: &environment,
            passthrough: &[],
            is_cancelled: &cancelled,
            timeout: Some(Duration::from_millis(10)),
        };
        assert!(matches!(
            super::execute_argv("sleep", &["1".into()], &options),
            Err(Error::TimedOut)
        ));
    }
}
