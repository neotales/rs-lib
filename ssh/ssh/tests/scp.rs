// `missing_docs` is a workspace lint aimed at the published API. An integration
// test binary has no public API to document, so the lint firing here is noise
// rather than a finding, and leaving it in makes the real count on the library
// unreadable. Scoped to this file: an undocumented public item in the crate is
// still reported.
#![allow(missing_docs, unreachable_pub)]

#[allow(dead_code)]
#[path = "../src/scp.rs"]
mod scp;

use std::error::Error;
use std::io::{self, Cursor, Read, Write};

use scp::{
    MAX_SCP_FILE_SIZE, ScpError, ScpFile, download, download_command, upload, upload_command,
};

struct ScriptedStream {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
    read_lengths: Vec<usize>,
}

impl ScriptedStream {
    fn new(input: Vec<u8>) -> Self {
        Self {
            input: Cursor::new(input),
            output: Vec::new(),
            read_lengths: Vec::new(),
        }
    }
}

impl Read for ScriptedStream {
    fn read(&mut self, target: &mut [u8]) -> io::Result<usize> {
        self.read_lengths.push(target.len());
        self.input.read(target)
    }
}

impl Write for ScriptedStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.output.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn upload_sends_time_file_header_body_and_trailer_in_order() -> Result<(), Box<dyn Error>> {
    let mut stream = ScriptedStream::new(vec![0, 0, 0, 0]);

    upload(
        &mut stream,
        "remote/file.bin",
        b"payload",
        Some(1_700_000_000),
    )?;

    assert_eq!(
        stream.output,
        b"T1700000000 0 1700000000 0\nC0644 7 file.bin\npayload\0"
    );
    Ok(())
}

#[test]
fn download_accepts_optional_time_and_returns_body_and_seconds() -> Result<(), Box<dyn Error>> {
    let input = b"T1700000000 123 1700000001 456\nC0644 7 file.bin\npayload\0".to_vec();
    let mut stream = ScriptedStream::new(input);

    let file: ScpFile = download(&mut stream)?;

    assert_eq!(file.data, b"payload");
    assert_eq!(file.mtime, Some(1_700_000_000));
    assert_eq!(file.atime, Some(1_700_000_001));
    assert_eq!(file.basename, b"file.bin");
    assert_eq!(stream.output, vec![0, 0, 0, 0]);
    Ok(())
}

#[test]
fn a_directory_header_is_rejected_without_reading_a_body() {
    let mut stream = ScriptedStream::new(b"D0755 0 directory\n".to_vec());

    let error = download(&mut stream).expect_err("directory records are unsupported");

    assert!(matches!(error, ScpError::DirectoryRecord));
    assert_eq!(stream.output, vec![0]);
    assert!(stream.read_lengths.iter().all(|length| *length == 1));
}

#[test]
fn commands_quote_paths_and_reject_control_bytes() -> Result<(), Box<dyn Error>> {
    assert_eq!(upload_command("file.bin")?, "scp -t -- 'file.bin'");
    assert_eq!(download_command("-remote")?, "scp -f -- '-remote'");
    assert_eq!(upload_command("a'b.bin")?, "scp -t -- 'a'\\''b.bin'");
    assert!(matches!(upload_command(""), Err(ScpError::InvalidPath)));
    assert!(matches!(
        upload_command(&b"bad\0path"[..]),
        Err(ScpError::InvalidPath)
    ));
    assert!(matches!(
        download_command(&b"bad\rpath"[..]),
        Err(ScpError::InvalidPath)
    ));
    assert!(matches!(
        download_command(&b"bad\npath"[..]),
        Err(ScpError::InvalidPath)
    ));
    Ok(())
}

#[test]
fn an_oversized_file_header_is_rejected_before_body_allocation() {
    let header = format!("C0644 {} file.bin\n", MAX_SCP_FILE_SIZE + 1);
    let mut stream = ScriptedStream::new(header.into_bytes());

    let error = download(&mut stream).expect_err("oversized body must fail");

    assert!(matches!(error, ScpError::FileTooLarge));
    assert_eq!(stream.output, vec![0]);
}

#[test]
fn peer_warning_text_is_not_retained_in_error_formatting() {
    let warning = b"warning contains /secret/path and file bytes";
    let mut input = vec![1];
    input.extend_from_slice(warning);
    input.push(b'\n');
    let mut stream = ScriptedStream::new(input);

    let error = download(&mut stream).expect_err("peer warning must fail");

    assert!(matches!(error, ScpError::PeerError));
    assert!(!format!("{error}").contains("secret"));
    assert!(!format!("{error:?}").contains("secret"));
    assert!(!format!("{error}").contains("file bytes"));
    assert!(!format!("{error:?}").contains("file bytes"));
}

#[test]
fn malformed_time_and_basename_headers_are_rejected() {
    let mut invalid_time = ScriptedStream::new(b"T1 1000000 1 0\nC0644 0 file\n\0".to_vec());
    assert!(matches!(
        download(&mut invalid_time),
        Err(ScpError::InvalidTime)
    ));

    let mut invalid_name = ScriptedStream::new(b"C0644 0 ../escape\n\0".to_vec());
    assert!(matches!(
        download(&mut invalid_name),
        Err(ScpError::InvalidBasename)
    ));
}

#[test]
fn the_module_does_not_contain_process_or_socket_operations() {
    let source = include_str!("../src/scp.rs");
    assert!(!source.contains("std::process"));
    assert!(!source.contains("std::net"));
    assert!(!source.contains("TcpStream"));
    assert!(!source.contains("UnixStream"));
    assert!(!source.contains("Command"));
}
