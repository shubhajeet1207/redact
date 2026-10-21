//! Runs the built `spymonk-redact` binary as a subprocess (TRD §19.6): stdout and stderr are
//! captured separately, and every run is checked for leaked canaries.
#![allow(dead_code, clippy::disallowed_types, clippy::disallowed_methods)]

pub mod schema;

use std::ffi::OsStr;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};

/// Synthetic secret values used across the CLI tests. None may ever reach stderr or a report.
pub const CANARIES: &[&str] = &["CANARYcli1", "CANARYcli2", "CANARYcli3"];

pub fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_spymonk-redact"))
}

pub struct Run {
    pub code: i32,
    pub stdout: Vec<u8>,
    pub stderr: String,
}

impl Run {
    pub fn stdout_str(&self) -> String {
        String::from_utf8(self.stdout.clone()).expect("stdout is UTF-8")
    }
}

fn finish(out: Output) -> Run {
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: out.stdout,
        stderr: String::from_utf8(out.stderr).expect("stderr is UTF-8"),
    }
}

/// Runs the binary with `args`, feeding `stdin` through a pipe.
pub fn run<I, S>(args: I, stdin: &[u8]) -> Run
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut child = bin()
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("binary starts");
    let mut pipe = child.stdin.take().expect("stdin pipe");
    let data = stdin.to_vec();
    let writer = std::thread::spawn(move || {
        // The child may stop reading early (errors, broken pipes); that is not a test failure.
        let _ = pipe.write_all(&data);
    });
    let out = child.wait_with_output().expect("binary finishes");
    let _ = writer.join();
    let run = finish(out);
    assert_no_canary(&run.stderr, "stderr");
    run
}

/// Fails if any canary appears in `text`.
pub fn assert_no_canary(text: &str, what: &str) {
    for c in CANARIES {
        assert!(!text.contains(c), "canary {c} leaked into {what}: {text}");
    }
}

/// A fresh empty directory under Cargo's per-target temporary directory.
pub fn temp_dir(name: &str) -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "{name}-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

/// Names of entries left in `dir`, sorted.
pub fn entries(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .expect("readable dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

pub const NOTICE: &str = "Review output before sharing; detection is limited. Rotate any credential that was already exposed.";
