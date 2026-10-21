//! `--list-rules` (TRD §9.6): the rule catalog generated from the manifest at build time.

use std::fmt::Write as _;

use spymonk_redact_core::rules::{RULES_SHA256, RULES_VERSION};

use crate::json;

#[derive(Debug)]
pub struct CatalogRule {
    pub id: &'static str,
    pub name: &'static str,
    pub family: &'static str,
    pub optional: bool,
    pub default_enabled: bool,
    pub placeholder: &'static str,
    /// SR-007 only: `(format ID, provider)`.
    pub formats: &'static [(&'static str, &'static str)],
}

include!(concat!(env!("OUT_DIR"), "/catalog.rs"));

fn default_label(rule: &CatalogRule) -> &'static str {
    match (rule.optional, rule.default_enabled) {
        (false, _) => "always",
        (true, true) => "default-on",
        (true, false) => "default-off",
    }
}

pub fn text() -> String {
    let mut s = String::new();
    let _ = writeln!(s, "rules {RULES_VERSION} sha256 {RULES_SHA256}");
    for rule in CATALOG {
        let _ = writeln!(
            s,
            "{}  {:<15} {:<12} {:<24} {}",
            rule.id,
            rule.family,
            default_label(rule),
            rule.placeholder,
            rule.name
        );
        for (id, provider) in rule.formats {
            let _ = writeln!(s, "        format {id:<28} {provider}");
        }
    }
    s
}

pub fn json() -> String {
    let mut s = String::from("{\"schemaVersion\":1,\"rules\":{\"version\":");
    json::string(&mut s, RULES_VERSION);
    s.push_str(",\"sha256\":");
    json::string(&mut s, RULES_SHA256);
    s.push_str("},\"catalog\":[");
    for (i, rule) in CATALOG.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str("{\"id\":");
        json::string(&mut s, rule.id);
        s.push_str(",\"name\":");
        json::string(&mut s, rule.name);
        s.push_str(",\"family\":");
        json::string(&mut s, rule.family);
        let _ = write!(
            s,
            ",\"optional\":{},\"defaultEnabled\":{}",
            rule.optional, rule.default_enabled
        );
        s.push_str(",\"placeholder\":");
        json::string(&mut s, rule.placeholder);
        s.push_str(",\"formats\":[");
        for (j, (id, provider)) in rule.formats.iter().enumerate() {
            if j > 0 {
                s.push(',');
            }
            s.push_str("{\"id\":");
            json::string(&mut s, id);
            s.push_str(",\"provider\":");
            json::string(&mut s, provider);
            s.push('}');
        }
        s.push_str("]}");
    }
    s.push_str("]}\n");
    s
}
