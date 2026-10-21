use sha2::{Digest, Sha256};
use spymonk_redact_core::rules::{self, DetectorKind};
use spymonk_redact_core::{ErrorCode, Limits, Options, RULE_COUNT, RuleId};

#[test]
fn default_options_match_manifest_defaults() {
    let o = Options::default();
    assert!(o.email);
    assert!(!o.private_ip);
    assert_eq!(rules::RULE_DEFAULT[rules::IDX_EMAIL], o.email);
    assert_eq!(rules::RULE_DEFAULT[rules::IDX_PRIVATE_IP], o.private_ip);
}

#[test]
fn limits_reject_out_of_range() {
    let bad = |n| {
        Limits {
            max_line_bytes: n,
            max_total_bytes: None,
        }
        .validate()
        .unwrap_err()
        .code
    };
    assert_eq!(bad(1023), ErrorCode::InvalidOptions);
    assert_eq!(bad(67_108_865), ErrorCode::InvalidOptions);
    assert!(
        Limits {
            max_line_bytes: 1024,
            max_total_bytes: None
        }
        .validate()
        .is_ok()
    );
    assert!(
        Limits {
            max_line_bytes: 67_108_864,
            max_total_bytes: Some(1)
        }
        .validate()
        .is_ok()
    );
    assert!(Limits::default().validate().is_ok());
    assert_eq!(Limits::default().max_line_bytes, 1_048_576);
    assert_eq!(Limits::default().max_total_bytes, None);
}

#[test]
fn error_codes_render_screaming_snake() {
    let all = [
        (ErrorCode::InvalidUtf8, "INVALID_UTF8"),
        (ErrorCode::InvalidUtf16, "INVALID_UTF16"),
        (ErrorCode::Utf16WithoutBom, "UTF16_WITHOUT_BOM"),
        (ErrorCode::UnsupportedEncoding, "UNSUPPORTED_ENCODING"),
        (ErrorCode::NulByte, "NUL_BYTE"),
        (ErrorCode::LineTooLong, "LINE_TOO_LONG"),
        (ErrorCode::InputTooLarge, "INPUT_TOO_LARGE"),
        (ErrorCode::InvalidOptions, "INVALID_OPTIONS"),
        (ErrorCode::InternalError, "INTERNAL_ERROR"),
    ];
    for (code, name) in all {
        assert_eq!(code.as_str(), name);
    }
}

#[test]
fn precedence_order_is_trd_order() {
    let mut ids: Vec<RuleId> = (0..RULE_COUNT as u8).map(RuleId).collect();
    ids.sort_by_key(|r| rules::rank(*r));
    let names: Vec<&str> = ids.iter().map(|r| rules::rule_id_str(*r)).collect();
    assert_eq!(
        names,
        [
            "SR-008", "SR-007", "SR-002", "SR-009", "SR-001", "SR-003", "SR-004", "SR-005",
            "SR-006"
        ]
    );
}

#[test]
fn placeholders_are_exact_set() {
    assert_eq!(
        rules::PLACEHOLDERS,
        [
            "[REDACTED]",
            "[USER]",
            "[EMAIL REDACTED]",
            "[PRIVATE IP REDACTED]",
            "[PRIVATE KEY REDACTED]"
        ]
    );
    assert!(rules::is_placeholder(b"[EMAIL REDACTED]"));
    assert!(!rules::is_placeholder(b"[REDACTED"));
    assert!(!rules::is_placeholder(b"[redacted]"));
    assert_eq!(
        rules::placeholder(RuleId(rules::IDX_HOME_PATH as u8)),
        "[USER]"
    );
}

#[test]
fn rule_table_matches_trd_catalog() {
    assert_eq!(RULE_COUNT, 9);
    assert_eq!(rules::rule_id_str(RuleId(0)), "SR-001");
    assert_eq!(
        rules::RULE_DETECTOR[rules::IDX_PEM_BLOCK],
        DetectorKind::PemBlock
    );
    assert_eq!(
        rules::rule_id_str(RuleId(rules::IDX_TOKEN_FORMAT as u8)),
        "SR-007"
    );
    assert!(rules::TOKEN_FORMATS.len() >= 16);
    assert_eq!(rules::RULES_VERSION, "1.0.0");
}

#[test]
fn rules_sha256_matches_manifest_file() {
    let bytes = include_bytes!("../../../rules/rules.v1.json");
    let hex: String = Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(rules::RULES_SHA256, hex);
}
