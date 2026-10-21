//! A validator for the JSON Schema 2020-12 keywords that `schemas/report.v1.schema.json` uses:
//! `type`, `const`, `enum`, `required`, `properties`, `additionalProperties`, `propertyNames`,
//! `items`, `minimum`, `maximum`, and `pattern` (the three patterns the schema contains). Any
//! other keyword fails the test, so the schema cannot silently outgrow its validator.
#![allow(dead_code)]

use serde_json::Value;

const ANNOTATIONS: &[&str] = &["$schema", "$id", "title", "description"];

pub fn report_schema() -> Value {
    let text = include_str!("../../../../schemas/report.v1.schema.json");
    serde_json::from_str(text).expect("schema is JSON")
}

/// Returns every violation as `path: message`.
pub fn validate(schema: &Value, value: &Value) -> Vec<String> {
    let mut errors = Vec::new();
    check(schema, value, "$", &mut errors);
    errors
}

fn type_matches(name: &str, v: &Value) -> bool {
    match name {
        "object" => v.is_object(),
        "array" => v.is_array(),
        "string" => v.is_string(),
        "boolean" => v.is_boolean(),
        "integer" => v.is_u64() || v.is_i64(),
        "number" => v.is_number(),
        "null" => v.is_null(),
        other => panic!("unsupported type {other}"),
    }
}

fn pattern_matches(pattern: &str, s: &str) -> bool {
    match pattern {
        "^[0-9a-f]{64}$" => {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }
        "^SR-[0-9]{3}$" => {
            s.len() == 6 && s.starts_with("SR-") && s[3..].bytes().all(|b| b.is_ascii_digit())
        }
        "^[0-9]+\\.[0-9]+\\.[0-9]+$" => {
            let parts: Vec<&str> = s.split('.').collect();
            parts.len() == 3
                && parts
                    .iter()
                    .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        }
        other => panic!("validator does not implement pattern {other}"),
    }
}

fn check(schema: &Value, v: &Value, path: &str, errors: &mut Vec<String>) {
    let Some(obj) = schema.as_object() else {
        panic!("schema at {path} is not an object");
    };
    for key in obj.keys() {
        let known = ANNOTATIONS.contains(&key.as_str())
            || matches!(
                key.as_str(),
                "type"
                    | "const"
                    | "enum"
                    | "required"
                    | "properties"
                    | "additionalProperties"
                    | "propertyNames"
                    | "items"
                    | "minimum"
                    | "maximum"
                    | "pattern"
            );
        assert!(
            known,
            "validator does not implement keyword {key} (at {path})"
        );
    }
    if let Some(t) = obj.get("type") {
        let ok = match t {
            Value::String(name) => type_matches(name, v),
            Value::Array(names) => names
                .iter()
                .any(|n| type_matches(n.as_str().unwrap_or(""), v)),
            _ => false,
        };
        if !ok {
            errors.push(format!("{path}: expected type {t}, got {v}"));
            return;
        }
    }
    if let Some(c) = obj.get("const")
        && c != v
    {
        errors.push(format!("{path}: expected {c}, got {v}"));
    }
    if let Some(Value::Array(options)) = obj.get("enum")
        && !options.contains(v)
    {
        errors.push(format!("{path}: {v} not in {options:?}"));
    }
    if let Some(n) = v.as_f64() {
        if let Some(min) = obj.get("minimum").and_then(Value::as_f64)
            && n < min
        {
            errors.push(format!("{path}: {n} < {min}"));
        }
        if let Some(max) = obj.get("maximum").and_then(Value::as_f64)
            && n > max
        {
            errors.push(format!("{path}: {n} > {max}"));
        }
    }
    if let (Some(p), Some(s)) = (obj.get("pattern").and_then(Value::as_str), v.as_str())
        && !pattern_matches(p, s)
    {
        errors.push(format!("{path}: {s:?} does not match {p}"));
    }
    if let Some(map) = v.as_object() {
        if let Some(Value::Array(req)) = obj.get("required") {
            for r in req {
                let key = r.as_str().unwrap_or_default();
                if !map.contains_key(key) {
                    errors.push(format!("{path}: missing {key}"));
                }
            }
        }
        let props = obj.get("properties").and_then(Value::as_object);
        for (k, child) in map {
            if let Some(names) = obj.get("propertyNames") {
                check(
                    names,
                    &Value::String(k.clone()),
                    &format!("{path}.<name {k}>"),
                    errors,
                );
            }
            match props.and_then(|p| p.get(k)) {
                Some(s) => check(s, child, &format!("{path}.{k}"), errors),
                None => match obj.get("additionalProperties") {
                    Some(Value::Bool(false)) => {
                        errors.push(format!("{path}: unexpected property {k}"))
                    }
                    Some(s @ Value::Object(_)) => check(s, child, &format!("{path}.{k}"), errors),
                    _ => {}
                },
            }
        }
    }
    if let (Some(items), Some(arr)) = (obj.get("items"), v.as_array()) {
        for (i, item) in arr.iter().enumerate() {
            check(items, item, &format!("{path}[{i}]"), errors);
        }
    }
}
