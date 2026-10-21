//! SR-008 private-key blocks.
mod common;
use common::*;
use spymonk_redact_core::{Options, Warning};

const BODY: &str = "MIIEvAIBADANBg\nkqhkiG9w0BAQEF\nAASCBKYwggSiAg\n";

#[test]
fn single_line_escaped_form_keeps_armor() {
    check_all(
        Options::default(),
        &[(
            "\"key_material\": \"-----BEGIN PRIVATE KEY-----\\nFAKE\\n-----END PRIVATE KEY-----\\n\"",
            "\"key_material\": \"-----BEGIN PRIVATE KEY-----[PRIVATE KEY REDACTED]-----END PRIVATE KEY-----\\n\"",
        )],
    );
}

#[test]
fn single_line_under_secret_key_resolves_the_overlap() {
    // FX-29: SR-001 covers the quoted value and SR-008 covers its body. Their differing ranges
    // merge to one [REDACTED] replacement attributed to higher-precedence SR-008.
    attributed(
        "\"private_key\": \"-----BEGIN PRIVATE KEY-----\\nFAKE\\n-----END PRIVATE KEY-----\\n\"",
        "\"private_key\": \"[REDACTED]\"",
        "SR-008",
        1,
    );
}

#[test]
fn malformed_quoted_private_key_is_stable() {
    let input =
        "\"api_key\": \"-----BEGIN PRIVATE KEY-----\"api_key\": \"-----END PRIVATE KEY-----'";
    let once = redact(input);
    assert_eq!(once, "\"api_key\": \"[REDACTED]");
    assert_eq!(redact(&once), once);
}

#[test]
fn multi_line_block_keeps_line_count() {
    let input = format!("-----BEGIN PRIVATE KEY-----\n{BODY}-----END PRIVATE KEY-----\nafter\n");
    let expected = "-----BEGIN PRIVATE KEY-----\n[PRIVATE KEY REDACTED]\n\n\n-----END PRIVATE KEY-----\nafter\n";
    let (got, s) = run(&input, Options::default());
    assert_eq!(got, expected);
    assert_eq!(count(&s, "SR-008"), 1);
    assert_eq!(s.replacements, 1);
    assert_eq!(s.lines, 6);
    assert!(s.warnings.is_empty());
}

#[test]
fn multi_line_block_is_idempotent() {
    let once = run(
        &format!("-----BEGIN RSA PRIVATE KEY-----\n{BODY}-----END RSA PRIVATE KEY-----\n"),
        Options::default(),
    )
    .0;
    let (twice, s) = run(&once, Options::default());
    assert_eq!(twice, once);
    assert_eq!(s.replacements, 0);
}

#[test]
fn labels_and_non_private_blocks() {
    for label in [
        "RSA PRIVATE KEY",
        "EC PRIVATE KEY",
        "OPENSSH PRIVATE KEY",
        "ENCRYPTED PRIVATE KEY",
        "PGP PRIVATE KEY BLOCK",
    ] {
        let input = format!("-----BEGIN {label}-----\nAAAA\n-----END {label}-----\n");
        let expected =
            format!("-----BEGIN {label}-----\n[PRIVATE KEY REDACTED]\n-----END {label}-----\n");
        assert_eq!(redact(&input), expected, "{label}");
    }
    unchanged_all(
        Options::default(),
        &[
            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
            "-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----\n",
        ],
    );
}

#[test]
fn crlf_and_log_prefixes_preserved() {
    let input = "2026-10-21 INFO -----BEGIN EC PRIVATE KEY-----\r\nAAAA\r\nBBBB\r\n2026-10-21 INFO -----END EC PRIVATE KEY-----\r\n";
    // TRD §6.9: content before the END armor is key body and is removed.
    let expected = "2026-10-21 INFO -----BEGIN EC PRIVATE KEY-----\r\n[PRIVATE KEY REDACTED]\r\n\r\n-----END EC PRIVATE KEY-----\r\n";
    assert_eq!(redact(input), expected);
}

#[test]
fn content_after_end_armor_is_still_scanned() {
    let input = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\", \"client_email\": \"svc@example.com\"\n";
    let expected = "-----BEGIN PRIVATE KEY-----\n[PRIVATE KEY REDACTED]\n-----END PRIVATE KEY-----\", \"client_email\": \"[EMAIL REDACTED]\"\n";
    assert_eq!(redact(input), expected);
}

#[test]
fn rest_of_begin_line_and_body_redacted_once() {
    let input = "k -----BEGIN PRIVATE KEY-----MIIabc\nMORE\n-----END PRIVATE KEY-----\n";
    let expected =
        "k -----BEGIN PRIVATE KEY-----[PRIVATE KEY REDACTED]\n\n-----END PRIVATE KEY-----\n";
    let (got, s) = run(input, Options::default());
    assert_eq!(got, expected);
    assert_eq!(s.replacements, 1);
}

#[test]
fn mismatched_end_label_does_not_close() {
    let input = "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\nBBBB\n-----END RSA PRIVATE KEY-----\nok\n";
    let expected = "-----BEGIN RSA PRIVATE KEY-----\n[PRIVATE KEY REDACTED]\n\n\n-----END RSA PRIVATE KEY-----\nok\n";
    assert_eq!(redact(input), expected);
}

#[test]
fn unterminated_block_fails_closed_with_warning() {
    let input = "first\n-----BEGIN PRIVATE KEY-----\nAAAA\npassword=x and more\n";
    let (got, s) = run(input, Options::default());
    assert_eq!(
        got,
        "first\n-----BEGIN PRIVATE KEY-----\n[PRIVATE KEY REDACTED]\n\n"
    );
    assert_eq!(
        s.warnings,
        [Warning::UnterminatedPrivateKeyBlock { line: 2 }]
    );
    assert_eq!(s.replacements, 1);
}

#[test]
fn removed_line_never_merges_lone_cr_with_lf() {
    // Regression from the line-structure property: an emptied line between a lone CR and an LF
    // would turn `\r` + `\n` into one CRLF separator.
    let input = "-----BEGIN PRIVATE KEY-----\rAAAA\rBBBB\n-----END PRIVATE KEY-----\n";
    let expected = "-----BEGIN PRIVATE KEY-----\r[PRIVATE KEY REDACTED]\r[PRIVATE KEY REDACTED]\n-----END PRIVATE KEY-----\n";
    let (got, s) = run(input, Options::default());
    assert_eq!(got, expected);
    assert_eq!(s.replacements, 2);
    assert_eq!(redact(&got), got);
}

#[test]
fn other_rules_never_break_an_armor() {
    // Regression from the idempotence property: an SR-001 value starting at `-----END` would
    // destroy the END armor and make a second run open an unterminated block.
    let input = "-----BEGIN PRIVATE KEY-----password=-----END PRIVATE KEY-----password=password=";
    let once = redact(input);
    assert_eq!(
        once,
        "-----BEGIN PRIVATE KEY-----[PRIVATE KEY REDACTED]-----END PRIVATE KEY-----password=[REDACTED]"
    );
    assert_eq!(redact(&once), once);
    // A secret value never crosses into a block: armors bound the other rules' scanning.
    let tricky = "-----BEGIN PRIVATE KEY-----\"api_key\": \"'-----END PRIVATE KEY-----password=Authorization: Bearer ";
    let once = redact(tricky);
    assert_eq!(
        once,
        "-----BEGIN PRIVATE KEY-----[PRIVATE KEY REDACTED]-----END PRIVATE KEY-----password=[REDACTED] Bearer "
    );
    assert_eq!(redact(&once), once);
}
