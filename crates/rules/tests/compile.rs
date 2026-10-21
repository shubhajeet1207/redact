use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use spymonk_redact_rules::{
    Detector, ManifestError, compile, generate_markdown, generate_rust, generate_web_json,
};

const MANIFEST: &[u8] = include_bytes!("../../../rules/rules.v1.json");

fn manifest_value() -> Value {
    serde_json::from_slice(MANIFEST).unwrap()
}

fn compile_value(v: &Value) -> Result<spymonk_redact_rules::Compiled, ManifestError> {
    compile(serde_json::to_string_pretty(v).unwrap().as_bytes())
}

fn rule_mut<'a>(v: &'a mut Value, id: &str) -> &'a mut Value {
    v["rules"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|r| r["id"] == id)
        .unwrap()
}

#[test]
fn valid_manifest_compiles() {
    let c = compile(MANIFEST).unwrap();
    assert_eq!(c.schema_version, 1);
    assert_eq!(c.rule_version, "1.0.0");
    assert_eq!(c.rules.len(), 9);
    let ids: Vec<&str> = c.rules.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "SR-001", "SR-002", "SR-003", "SR-004", "SR-005", "SR-006", "SR-007", "SR-008",
            "SR-009"
        ]
    );
    assert_eq!(
        c.precedence,
        [
            "SR-008", "SR-007", "SR-002", "SR-009", "SR-001", "SR-003", "SR-004", "SR-005",
            "SR-006"
        ]
    );
    assert_eq!(
        c.placeholders,
        [
            "[REDACTED]",
            "[USER]",
            "[EMAIL REDACTED]",
            "[PRIVATE IP REDACTED]",
            "[PRIVATE KEY REDACTED]"
        ]
    );
}

#[test]
fn detectors_map_one_to_one() {
    let c = compile(MANIFEST).unwrap();
    let expected = [
        ("SR-001", Detector::NamedValue),
        ("SR-002", Detector::Authorization),
        ("SR-003", Detector::UrlCredential),
        ("SR-004", Detector::HomePath),
        ("SR-005", Detector::Email),
        ("SR-006", Detector::PrivateIp),
        ("SR-007", Detector::TokenFormat),
        ("SR-008", Detector::PemBlock),
        ("SR-009", Detector::Cookie),
    ];
    for (id, det) in expected {
        let r = c.rules.iter().find(|r| r.id == id).unwrap();
        assert_eq!(r.detector, det, "{id}");
    }
}

#[test]
fn optional_rules_are_email_and_private_ip_with_trd_defaults() {
    let c = compile(MANIFEST).unwrap();
    for r in &c.rules {
        match r.detector {
            Detector::Email => assert!(r.optional && r.default_enabled),
            Detector::PrivateIp => assert!(r.optional && !r.default_enabled),
            _ => assert!(!r.optional && r.default_enabled, "{}", r.id),
        }
    }
}

#[test]
fn sha256_is_of_exact_bytes() {
    let c = compile(MANIFEST).unwrap();
    let expected: String = Sha256::digest(MANIFEST)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    assert_eq!(c.sha256_hex, expected);
}

#[test]
fn every_token_format_has_https_source() {
    let c = compile(MANIFEST).unwrap();
    let formats = &c
        .rules
        .iter()
        .find(|r| r.detector == Detector::TokenFormat)
        .unwrap()
        .data
        .formats;
    assert!(formats.len() >= 16);
    for f in formats {
        assert!(f.source.starts_with("https://"), "{}", f.id);
    }
}

#[test]
fn rejects_unsupported_schema_version() {
    let mut v = manifest_value();
    v["schemaVersion"] = json!(2);
    assert!(matches!(
        compile_value(&v),
        Err(ManifestError::UnsupportedSchemaVersion(2))
    ));
}

#[test]
fn rejects_duplicate_id() {
    let mut v = manifest_value();
    rule_mut(&mut v, "SR-002")["id"] = json!("SR-001");
    assert!(matches!(compile_value(&v), Err(ManifestError::DuplicateId(id)) if id == "SR-001"));
}

#[test]
fn rejects_unknown_detector() {
    let mut v = manifest_value();
    rule_mut(&mut v, "SR-003")["detector"] = json!("regex");
    assert!(matches!(compile_value(&v), Err(ManifestError::UnknownDetector(d)) if d == "regex"));
}

#[test]
fn rejects_second_rule_for_same_detector() {
    let mut v = manifest_value();
    rule_mut(&mut v, "SR-003")["detector"] = json!("email");
    assert!(matches!(compile_value(&v), Err(ManifestError::DuplicateDetector(d)) if d == "email"));
}

#[test]
fn rejects_missing_precedence_entry() {
    let mut v = manifest_value();
    v["precedence"].as_array_mut().unwrap().pop();
    assert!(matches!(
        compile_value(&v),
        Err(ManifestError::PrecedenceMismatch)
    ));
}

#[test]
fn rejects_format_without_source() {
    let mut v = manifest_value();
    let f = &mut rule_mut(&mut v, "SR-007")["data"]["formats"][0];
    f.as_object_mut().unwrap().remove("source");
    assert!(matches!(
        compile_value(&v),
        Err(ManifestError::FormatWithoutSource(_))
    ));
}

#[test]
fn rejects_alias_with_non_key_char() {
    let mut v = manifest_value();
    rule_mut(&mut v, "SR-001")["data"]["singleAliases"]
        .as_array_mut()
        .unwrap()
        .push(json!("pass word"));
    assert!(matches!(compile_value(&v), Err(ManifestError::InvalidAlias(a)) if a == "pass word"));
}

#[test]
fn rejects_bad_cidr() {
    let mut v = manifest_value();
    rule_mut(&mut v, "SR-006")["data"]["ipv4"][0] = json!("10.0.0.0/33");
    assert!(matches!(
        compile_value(&v),
        Err(ManifestError::InvalidCidr(_))
    ));
}

#[test]
fn rejects_placeholder_not_reserved() {
    let mut v = manifest_value();
    rule_mut(&mut v, "SR-001")["placeholder"] = json!("[HIDDEN]");
    assert!(matches!(
        compile_value(&v),
        Err(ManifestError::PlaceholderNotReserved(_))
    ));
}

#[test]
fn rejects_invalid_json() {
    assert!(matches!(compile(b"{not json"), Err(ManifestError::Json(_))));
}

#[test]
fn generated_rust_mentions_every_rule_and_hash() {
    let c = compile(MANIFEST).unwrap();
    let src = generate_rust(&c);
    for r in &c.rules {
        assert!(src.contains(&format!("\"{}\"", r.id)), "{}", r.id);
    }
    assert!(src.contains(&c.sha256_hex));
    assert!(src.contains("pub const RULES_VERSION: &str = \"1.0.0\";"));
}

#[test]
fn generated_markdown_documents_every_rule_and_format() {
    let c = compile(MANIFEST).unwrap();
    let md = generate_markdown(&c);
    for r in &c.rules {
        assert!(md.contains(&r.id), "{}", r.id);
    }
    for f in &c
        .rules
        .iter()
        .find(|r| r.detector == Detector::TokenFormat)
        .unwrap()
        .data
        .formats
    {
        assert!(md.contains(&f.id), "{}", f.id);
        assert!(md.contains(&f.source), "{}", f.id);
    }
    assert!(md.contains(&c.sha256_hex));
}

#[test]
fn authorization_schemes_are_parsed_and_generated() {
    let c = compile(MANIFEST).unwrap();
    let auth = &c.rule(Detector::Authorization).data;
    assert!(auth.schemes.iter().any(|s| s == "bearer"));
    assert!(auth.schemes.iter().any(|s| s == "aws4-hmac-sha256"));
    assert!(generate_rust(&c).contains("pub const AUTH_SCHEMES: &[&str]"));
}

#[test]
fn rejects_invalid_scheme() {
    let mut v = manifest_value();
    rule_mut(&mut v, "SR-002")["data"]["schemes"]
        .as_array_mut()
        .unwrap()
        .push(json!("Bad Scheme"));
    assert!(matches!(
        compile_value(&v),
        Err(ManifestError::InvalidField(_))
    ));
}

/// The browser's Rules section is generated from the same manifest (TRD §10.1).
#[test]
fn web_json_carries_every_rule_and_the_rule_set_identity() {
    let c = compile(MANIFEST).unwrap();
    let v: Value = serde_json::from_str(&generate_web_json(&c)).unwrap();
    assert_eq!(v["ruleVersion"], json!(c.rule_version));
    assert_eq!(v["sha256"], json!(c.sha256_hex));
    let rules = v["rules"].as_array().unwrap();
    assert_eq!(rules.len(), c.rules.len());
    for (r, j) in c.rules.iter().zip(rules) {
        assert_eq!(j["id"], json!(r.id));
        assert_eq!(j["name"], json!(r.name));
        assert_eq!(j["description"], json!(r.description));
        assert_eq!(j["placeholder"], json!(r.placeholder));
        assert_eq!(j["optional"], json!(r.optional));
        assert_eq!(j["defaultEnabled"], json!(r.default_enabled));
        assert_eq!(j["examples"].as_array().unwrap().len(), r.examples.len());
        assert_eq!(j["limitations"], json!(r.limitations));
    }
    assert_eq!(v["precedence"], json!(c.precedence));
}
