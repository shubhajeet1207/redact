//! Rule data for the browser's Rules section (TRD §10.1), generated from the same manifest as
//! the engine so the page cannot describe different rules than the ones it runs.

use serde_json::{Value, json};

use crate::Compiled;

pub fn generate_web_json(c: &Compiled) -> String {
    let rules: Vec<Value> = c
        .rules
        .iter()
        .map(|r| {
            json!({
                "id": r.id,
                "name": r.name,
                "description": r.description,
                "placeholder": r.placeholder,
                "optional": r.optional,
                "defaultEnabled": r.default_enabled,
                "examples": r.examples.iter().map(|(i, o)| json!({ "input": i, "output": o })).collect::<Vec<_>>(),
                "nonExamples": r.non_examples,
                "limitations": r.limitations,
            })
        })
        .collect();
    let doc = json!({
        "generatedBy": "cargo run -p spymonk-redact-rules --bin gen-docs (from rules/rules.v1.json; do not edit)",
        "schemaVersion": c.schema_version,
        "ruleVersion": c.rule_version,
        "sha256": c.sha256_hex,
        "placeholders": c.placeholders,
        "precedence": c.precedence,
        "rules": rules,
    });
    // Serializing a `Value` built from strings, numbers, and booleans cannot fail.
    let mut s = serde_json::to_string_pretty(&doc).unwrap_or_default();
    s.push('\n');
    s
}
