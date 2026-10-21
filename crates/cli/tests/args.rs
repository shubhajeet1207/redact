//! TRD §9.1, §9.6, §9.7: argument parsing and the information commands.
mod common;
use common::*;

#[test]
fn help_prints_usage_and_exits_zero() {
    let r = run(["--help"], b"");
    assert_eq!(r.code, 0);
    let out = r.stdout_str();
    assert!(
        out.starts_with("Usage: spymonk-redact [OPTIONS] [FILE | -]\n"),
        "{out}"
    );
    for option in [
        "--output",
        "--input-encoding",
        "--invalid-utf8",
        "--max-line-bytes",
        "--disable-email",
        "--enable-private-ip",
        "--list-rules",
        "--report-format",
        "--report-file",
        "--escape-controls",
        "--version",
    ] {
        assert!(out.contains(option), "help lacks {option}");
    }
    assert_eq!(r.stderr, "");
    assert_eq!(run(["-h"], b"").stdout, r.stdout);
}

#[test]
fn version_reports_tool_rules_commit_target_and_date() {
    let r = run(["--version"], b"");
    assert_eq!(r.code, 0);
    let out = r.stdout_str();
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(
        lines.first().copied(),
        Some(concat!("spymonk-redact ", env!("CARGO_PKG_VERSION")))
    );
    let rules = lines
        .iter()
        .find(|l| l.starts_with("rules "))
        .expect("rules line");
    let parts: Vec<&str> = rules.split(' ').collect();
    assert_eq!(parts.len(), 4, "{rules}");
    assert_eq!(parts[2], "sha256");
    assert!(parts[3].len() == 64 && parts[3].chars().all(|c| c.is_ascii_hexdigit()));
    for key in ["commit ", "target ", "built "] {
        assert!(
            lines.iter().any(|l| l.starts_with(key)),
            "missing {key}: {out}"
        );
    }
    assert_eq!(run(["-V"], b"").stdout, r.stdout);
}

#[test]
fn list_rules_text_names_every_rule_and_token_format() {
    let r = run(["--list-rules"], b"");
    assert_eq!(r.code, 0);
    let out = r.stdout_str();
    for id in 1..=9 {
        assert!(out.contains(&format!("SR-00{id}")), "missing SR-00{id}");
    }
    assert!(out.contains("aws-access-key-id"));
    assert!(out.contains("[PRIVATE KEY REDACTED]"));
}

#[test]
fn list_rules_json_is_one_document() {
    let r = run(["--list-rules", "--report-format", "json"], b"");
    assert_eq!(r.code, 0);
    let v: serde_json::Value = serde_json::from_slice(&r.stdout).expect("JSON");
    let catalog = v["catalog"].as_array().expect("catalog");
    assert_eq!(catalog.len(), 9);
    let by_id = |id: &str| catalog.iter().find(|r| r["id"] == id).expect("rule");
    assert_eq!(by_id("SR-005")["optional"], true);
    assert_eq!(by_id("SR-005")["defaultEnabled"], true);
    assert_eq!(by_id("SR-006")["defaultEnabled"], false);
    assert!(
        !by_id("SR-007")["formats"]
            .as_array()
            .expect("formats")
            .is_empty()
    );
    assert_eq!(v["rules"]["sha256"].as_str().map(str::len), Some(64));
}

#[test]
fn usage_errors_exit_2_without_echoing_values() {
    for args in [
        vec!["--bogus-flag=CANARYcli1"],
        vec!["--max-line-bytes", "CANARYcli1"],
        vec!["--max-line-bytes", "1023"],
        vec!["--max-line-bytes", "67108865"],
        vec!["--report-format", "CANARYcli1"],
        vec!["--input-encoding", "CANARYcli1"],
        vec!["--invalid-utf8", "CANARYcli1"],
        vec!["--escape-controls", "CANARYcli1"],
        vec!["--output"],
        vec!["CANARYcli1.log", "CANARYcli2.log"],
        vec!["--version=CANARYcli1"],
    ] {
        let r = run(&args, b"");
        assert_eq!(r.code, 2, "{args:?}: {}", r.stderr);
        assert!(r.stdout.is_empty(), "{args:?}");
        assert!(
            r.stderr.starts_with("spymonk-redact: "),
            "{args:?}: {}",
            r.stderr
        );
        assert!(r.stderr.contains("--help"), "{args:?}: {}", r.stderr);
    }
}

#[test]
fn double_dash_allows_a_file_name_that_starts_with_a_dash() {
    let dir = temp_dir("dash");
    std::fs::write(dir.join("-input.log"), "password=CANARYcli1\n").expect("write");
    let r = common::bin()
        .current_dir(&dir)
        .args(["--", "-input.log"])
        .output()
        .expect("run");
    assert_eq!(
        r.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&r.stderr)
    );
    assert_eq!(r.stdout, b"password=[REDACTED]\n");
}

#[cfg(unix)]
#[test]
fn non_utf8_arguments_are_rejected() {
    use std::os::unix::ffi::OsStrExt;
    let arg = std::ffi::OsStr::from_bytes(b"\xff\xfe.log");
    let r = run([arg], b"");
    assert_eq!(r.code, 2);
    assert!(r.stderr.contains("not valid UTF-8"), "{}", r.stderr);
}
