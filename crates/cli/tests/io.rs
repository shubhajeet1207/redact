//! TRD §9.2, §9.4, §5.4, §19.6: input selection, streaming, encodings, and limits.
mod common;
use common::*;

#[test]
fn stdin_file_and_dash_select_the_same_input() {
    let dir = temp_dir("select");
    let path = dir.join("in.log");
    std::fs::write(&path, "token=CANARYcli1 ok\n").expect("write");
    let from_stdin = run(Vec::<&str>::new(), b"token=CANARYcli1 ok\n");
    let from_dash = run(["-"], b"token=CANARYcli1 ok\n");
    let from_file = run([path.as_os_str()], b"");
    for r in [&from_stdin, &from_dash, &from_file] {
        assert_eq!(r.code, 0, "{}", r.stderr);
        assert_eq!(r.stdout, b"token=[REDACTED] ok\n");
        assert!(r.stderr.contains(NOTICE), "{}", r.stderr);
    }
}

#[test]
fn empty_input_is_valid() {
    let r = run(Vec::<&str>::new(), b"");
    assert_eq!(r.code, 0);
    assert!(r.stdout.is_empty());
}

#[test]
fn output_is_byte_exact_including_separators_and_bom() {
    let input = b"\xEF\xBB\xBFa=1\r\npassword=CANARYcli1\rlast";
    let r = run(Vec::<&str>::new(), input);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(r.stdout, b"\xEF\xBB\xBFa=1\r\npassword=[REDACTED]\rlast");
}

#[test]
fn directory_and_missing_inputs_fail_without_naming_the_path() {
    let dir = temp_dir("CANARYcli2-dir");
    let missing = dir.join("CANARYcli3-missing.log");
    for path in [dir.clone(), missing] {
        let r = run([path.as_os_str()], b"");
        assert_eq!(r.code, 1, "{}", r.stderr);
        assert!(r.stdout.is_empty());
        assert!(r.stderr.contains("INPUT_READ_FAILED"), "{}", r.stderr);
        assert!(!r.stderr.contains(&*dir.to_string_lossy()), "{}", r.stderr);
    }
}

#[test]
fn invalid_utf8_errors_or_replaces() {
    let r = run(Vec::<&str>::new(), b"ok\nbad \xff here\n");
    assert_eq!(r.code, 1);
    assert_eq!(
        r.stdout, b"ok\n",
        "complete lines before the failure are kept"
    );
    assert!(r.stderr.contains("INVALID_UTF8 (line 2)"), "{}", r.stderr);

    let r = run(["--invalid-utf8", "replace"], b"ok\nbad \xff here\n");
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(r.stdout, "ok\nbad \u{FFFD} here\n".as_bytes());
}

#[test]
fn nul_and_encoding_errors() {
    let cases: [(&[u8], &str); 4] = [
        (b"ok\nNUL\x00here\n", "NUL_BYTE"),
        (b"p\x00a\x00s\x00s\x00", "UTF16_WITHOUT_BOM"),
        (b"\xFF\xFE\x00\x00a\x00\x00\x00", "UNSUPPORTED_ENCODING"),
        (b"\x00\x00\xFE\xFF\x00\x00\x00a", "UNSUPPORTED_ENCODING"),
    ];
    for (input, code) in cases {
        let r = run(Vec::<&str>::new(), input);
        assert_eq!(r.code, 1, "{code}");
        assert!(r.stderr.contains(code), "{code}: {}", r.stderr);
    }
}

#[test]
fn utf16_with_bom_round_trips_in_its_own_encoding() {
    for (bom, le) in [(&b"\xFF\xFE"[..], true), (&b"\xFE\xFF"[..], false)] {
        let mut input = bom.to_vec();
        let mut expected = bom.to_vec();
        for (text, out) in [
            ("token=CANARYcli1\r\n", &mut input),
            ("token=[REDACTED]\r\n", &mut expected),
        ] {
            for unit in text.encode_utf16() {
                out.extend(if le {
                    unit.to_le_bytes()
                } else {
                    unit.to_be_bytes()
                });
            }
        }
        let r = run(Vec::<&str>::new(), &input);
        assert_eq!(r.code, 0, "{}", r.stderr);
        assert_eq!(r.stdout, expected);
    }
}

#[test]
fn explicit_utf16_without_bom() {
    let mut input = Vec::new();
    for unit in "password=CANARYcli1\n".encode_utf16() {
        input.extend(unit.to_le_bytes());
    }
    let r = run(["--input-encoding", "utf-16le"], &input);
    assert_eq!(r.code, 0, "{}", r.stderr);
    let text: Vec<u16> = r
        .stdout
        .chunks(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    assert_eq!(
        String::from_utf16(&text).expect("UTF-16"),
        "password=[REDACTED]\n"
    );
}

#[test]
fn line_limit_accepts_the_limit_and_rejects_one_more_byte() {
    let at_limit = format!("{}\n", "a".repeat(1024));
    let r = run(["--max-line-bytes", "1024"], at_limit.as_bytes());
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert_eq!(r.stdout, at_limit.as_bytes());

    let over = format!("first\n{}\n", "a".repeat(1025));
    let r = run(["--max-line-bytes", "1024"], over.as_bytes());
    assert_eq!(r.code, 1);
    assert_eq!(r.stdout, b"first\n", "output stops before the long line");
    assert!(r.stderr.contains("LINE_TOO_LONG (line 2)"), "{}", r.stderr);
}

#[test]
fn large_streams_keep_only_complete_lines_before_a_late_failure() {
    let mut input = "password=CANARYcli1 line\n".repeat(20_000).into_bytes();
    input.extend_from_slice(b"tail \xff\n");
    let r = run(Vec::<&str>::new(), &input);
    assert_eq!(r.code, 1);
    let out = r.stdout_str();
    assert_eq!(out.lines().count(), 20_000);
    assert!(out.ends_with("password=[REDACTED] line\n"));
    assert!(!out.contains("CANARY"));
}

#[test]
fn options_toggle_email_and_private_ip() {
    let input = b"a@example.com 10.1.2.3\n";
    assert_eq!(
        run(Vec::<&str>::new(), input).stdout,
        b"[EMAIL REDACTED] 10.1.2.3\n"
    );
    assert_eq!(
        run(["--disable-email"], input).stdout,
        b"a@example.com 10.1.2.3\n"
    );
    assert_eq!(
        run(["--enable-private-ip"], input).stdout,
        b"[EMAIL REDACTED] [PRIVATE IP REDACTED]\n"
    );
}

#[test]
fn hidden_characters_add_a_notice() {
    let r = run(Vec::<&str>::new(), "a\u{202E}b\n".as_bytes());
    assert_eq!(r.code, 0);
    assert!(
        r.stderr
            .contains("Output contains 1 hidden or control characters"),
        "{}",
        r.stderr
    );
    assert_eq!(
        r.stdout,
        "a\u{202E}b\n".as_bytes(),
        "redirected output stays byte-exact"
    );
}
