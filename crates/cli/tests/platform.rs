//! TRD §9.4, §9.5, §9.8, §19.6: terminal rendering, broken pipes, interruption, and hardening.
mod common;
use common::*;

#[test]
fn escape_always_marks_every_hidden_class_and_lone_cr() {
    let input = "\u{FEFF}a\tb\u{1b}[31mred\u{7}\u{7F}\u{85}\u{202E}\u{200B}\u{AD}\u{E0041}\u{FEFF}x\rnext\r\nend\n";
    let r = run(["--escape-controls", "always"], input.as_bytes());
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(
        r.stdout_str(),
        "\u{FEFF}a\tb<U+001B>[31mred<U+0007><U+007F><U+0085><U+202E><U+200B><U+00AD><U+E0041><U+FEFF>x<CR>\nnext\r\nend\n"
    );
}

#[test]
fn escape_never_and_redirected_auto_are_byte_exact() {
    let input = "a\u{1b}[2Jb\u{202E}c\rd\n";
    for args in [vec!["--escape-controls", "never"], vec![]] {
        let r = run(&args, input.as_bytes());
        assert_eq!(r.code, 0);
        assert_eq!(r.stdout, input.as_bytes(), "{args:?}");
    }
}

#[test]
fn escaping_renders_utf16_output_as_text() {
    let mut input = vec![0xFF, 0xFE];
    for unit in "token=CANARYcli1 \u{202E}x\n".encode_utf16() {
        input.extend(unit.to_le_bytes());
    }
    let r = run(["--escape-controls", "always"], &input);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(r.stdout_str(), "\u{FEFF}token=[REDACTED] <U+202E>x\n");
}

#[test]
fn escaping_never_applies_to_output_files() {
    let dir = temp_dir("escape-file");
    let out = dir.join("o.log");
    let r = run(
        [
            "--escape-controls",
            "always",
            "--report-format",
            "json",
            "-o",
            out.to_str().expect("utf8"),
        ],
        "a\u{202E}b\n".as_bytes(),
    );
    assert_eq!(r.code, 0);
    assert_eq!(
        std::fs::read(&out).expect("read"),
        "a\u{202E}b\n".as_bytes()
    );
    let doc: serde_json::Value = serde_json::from_str(r.stderr.trim()).expect("json");
    assert_eq!(doc["output"]["displayEscaped"], false);
}

#[test]
fn a_closed_stdout_stops_silently() {
    use std::io::{Read, Write};
    use std::process::Stdio;
    let mut child = bin()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let mut stdout = child.stdout.take().expect("stdout");
    let mut first = [0u8; 16];
    let mut stdin = child.stdin.take().expect("stdin");
    let writer = std::thread::spawn(move || {
        let line = b"token=CANARYcli1 and some padding to fill the pipe quickly\n".repeat(1000);
        for _ in 0..400 {
            if stdin.write_all(&line).is_err() {
                break;
            }
        }
    });
    stdout.read_exact(&mut first).expect("some output");
    drop(stdout);
    let out = child.wait_with_output().expect("wait");
    let _ = writer.join();
    let expected = if cfg!(unix) { 141 } else { 1 };
    assert_eq!(out.status.code(), Some(expected));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_no_canary(&stderr, "stderr");
    assert!(!stderr.contains("error"), "broken pipe is silent: {stderr}");
}

#[cfg(unix)]
#[test]
#[allow(unsafe_code)] // libc::kill on our own child.
fn signals_exit_130_and_143_and_remove_the_temporary_file() {
    use std::process::Stdio;
    for (signal, code) in [(libc::SIGINT, 130), (libc::SIGTERM, 143)] {
        let dir = temp_dir("signal");
        let out = dir.join("o.log");
        let mut child = bin()
            .args(["-o", out.to_str().expect("utf8")])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn");
        // Keep stdin open so the run blocks reading, then wait for its temporary file.
        let _stdin = child.stdin.take();
        for _ in 0..200 {
            if !entries(&dir).is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(
            entries(&dir).len(),
            1,
            "temporary file exists while running"
        );
        let pid = libc::pid_t::try_from(child.id()).expect("pid");
        // SAFETY: sending a signal to our own child process.
        assert_eq!(unsafe { libc::kill(pid, signal) }, 0);
        let status = child.wait().expect("wait");
        assert_eq!(status.code(), Some(code), "signal {signal}");
        assert!(
            entries(&dir).is_empty(),
            "temporary file removed: {:?}",
            entries(&dir)
        );
    }
}

#[cfg(all(target_os = "linux", feature = "sandbox-probe"))]
#[test]
fn linux_hardening_blocks_sockets_and_dumps() {
    let r = run(["--probe-sandbox"], b"");
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(r.stdout_str(), "dumpable=0 core=0 socket=EPERM\n");
}
