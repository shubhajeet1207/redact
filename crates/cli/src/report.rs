//! Reports and notices (TRD §9.6). Reports never contain matched values, input content, file
//! names, paths, hashes of content, or environment data; byte and line counts are safe metadata.

use std::fmt::Write as _;

use spymonk_redact_core::rules::{RULES_SHA256, RULES_VERSION, rule_id_str};
use spymonk_redact_core::{
    DetectedEncoding, InputEncoding, InvalidUtf8, RULE_COUNT, RuleId, Summary, Warning,
};

use crate::args::RunConfig;
use crate::error::Failure;
use crate::json;

pub const NOTICE: &str = "Review output before sharing; detection is limited. Rotate any credential that was already exposed.";

pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const BUILD_COMMIT: &str = env!("SPYMONK_BUILD_COMMIT");
pub const BUILD_TARGET: &str = env!("SPYMONK_BUILD_TARGET");
pub const BUILD_DATE: &str = env!("SPYMONK_BUILD_DATE");

/// Everything a report may say about one run.
#[derive(Debug)]
pub struct Facts<'a> {
    pub cfg: &'a RunConfig,
    pub summary: Option<&'a Summary>,
    pub failure: Option<Failure>,
    /// Input encoding detected so far (known even after an early failure).
    pub encoding: Option<DetectedEncoding>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub display_escaped: bool,
    pub sandbox: &'static str,
}

pub fn hidden_total(summary: &Summary) -> u64 {
    let h = summary.hidden;
    h.bidi
        .saturating_add(h.invisible)
        .saturating_add(h.control)
        .saturating_add(h.lone_cr)
}

pub fn hidden_notice(n: u64) -> String {
    format!("Output contains {n} hidden or control characters; they may change how text appears.")
}

pub fn warning_text(w: &Warning) -> String {
    match w {
        Warning::UnterminatedPrivateKeyBlock { line } => format!(
            "spymonk-redact: warning: UNTERMINATED_PRIVATE_KEY_BLOCK (line {line}): a private-key block never ended; everything after it was removed"
        ),
        Warning::UnstableLineRedacted { first_line, lines } => format!(
            "spymonk-redact: warning: UNSTABLE_LINE_REDACTED (line {first_line}): {lines} line(s) kept producing new matches and were replaced entirely"
        ),
    }
}

fn on_off(b: bool) -> &'static str {
    if b { "on" } else { "off" }
}

fn encoding_name(e: InputEncoding) -> &'static str {
    match e {
        InputEncoding::Auto => "auto",
        InputEncoding::Utf8 => "utf-8",
        InputEncoding::Utf16Le => "utf-16le",
        InputEncoding::Utf16Be => "utf-16be",
    }
}

pub fn text(f: &Facts<'_>) -> String {
    let mut s = String::new();
    let status = if f.failure.is_some() {
        "failed"
    } else {
        "complete"
    };
    let _ = write!(s, "spymonk-redact: status={status}");
    if let Some(summary) = f.summary {
        let _ = write!(
            s,
            " replacements={} lines={}",
            summary.replacements, summary.lines
        );
    }
    let _ = writeln!(
        s,
        " email={} private_ip={} rules={RULES_VERSION}",
        on_off(f.cfg.email),
        on_off(f.cfg.private_ip)
    );
    if let Some(summary) = f.summary {
        let counts: Vec<String> = (0..RULE_COUNT)
            .filter_map(|i| {
                let n = *summary.by_rule.get(i)?;
                let id = rule_id_str(RuleId(u8::try_from(i).ok()?));
                (n > 0).then(|| format!("{id}={n}"))
            })
            .collect();
        let _ = writeln!(
            s,
            "spymonk-redact: {}",
            if counts.is_empty() {
                "none".to_string()
            } else {
                counts.join(" ")
            }
        );
        let h = summary.hidden;
        let _ = writeln!(
            s,
            "spymonk-redact: encoding={} bom={} hidden bidi={} invisible={} control={} lone_cr={}",
            summary.encoding.kind.as_str(),
            if summary.encoding.bom { "yes" } else { "no" },
            h.bidi,
            h.invisible,
            h.control,
            h.lone_cr
        );
        for w in &summary.warnings {
            let _ = writeln!(s, "{}", warning_text(w));
        }
    }
    if let Some(failure) = f.failure {
        let _ = write!(s, "spymonk-redact: error={}", failure.code_str());
        if let Some(line) = failure.line {
            let _ = write!(s, " line={line}");
        }
        s.push('\n');
    }
    s
}

/// One line of JSON that validates against `schemas/report.v1.schema.json`.
pub fn json(f: &Facts<'_>) -> String {
    let mut s =
        String::from("{\"schemaVersion\":1,\"tool\":{\"name\":\"spymonk-redact\",\"version\":");
    json::string(&mut s, TOOL_VERSION);
    s.push_str(",\"build\":");
    json::string(&mut s, BUILD_COMMIT);
    s.push_str(",\"target\":");
    json::string(&mut s, BUILD_TARGET);
    s.push_str("},\"rules\":{\"version\":");
    json::string(&mut s, RULES_VERSION);
    s.push_str(",\"sha256\":");
    json::string(&mut s, RULES_SHA256);
    let _ = write!(
        s,
        "}},\"options\":{{\"email\":{},\"privateIp\":{},\"maxLineBytes\":{},\"invalidUtf8\":\"{}\",\"inputEncoding\":\"{}\"}}",
        f.cfg.email,
        f.cfg.private_ip,
        f.cfg.max_line_bytes,
        match f.cfg.invalid_utf8 {
            InvalidUtf8::Error => "error",
            InvalidUtf8::Replace => "replace",
        },
        encoding_name(f.cfg.input_encoding)
    );
    let complete = f.failure.is_none();
    let _ = write!(
        s,
        ",\"status\":\"{}\",\"outputComplete\":{complete}",
        if complete { "complete" } else { "failed" }
    );
    s.push_str(",\"input\":{\"encoding\":");
    match f.encoding {
        Some(e) => {
            json::string(&mut s, e.kind.as_str());
            let _ = write!(s, ",\"bom\":{}", e.bom);
        }
        None => s.push_str("null,\"bom\":null"),
    }
    let _ = write!(s, ",\"bytes\":{},\"lines\":", f.bytes_in);
    json::opt_u64(&mut s, f.summary.map(|x| x.lines));
    let _ = write!(
        s,
        "}},\"output\":{{\"bytes\":{},\"displayEscaped\":{}}}",
        f.bytes_out, f.display_escaped
    );
    match f.summary {
        Some(summary) => {
            let _ = write!(
                s,
                ",\"replacements\":{{\"total\":{},\"byRule\":{{",
                summary.replacements
            );
            for i in 0..RULE_COUNT {
                let id = u8::try_from(i)
                    .map(|i| rule_id_str(RuleId(i)))
                    .unwrap_or("SR-???");
                if i > 0 {
                    s.push(',');
                }
                let _ = write!(
                    s,
                    "\"{id}\":{}",
                    summary.by_rule.get(i).copied().unwrap_or(0)
                );
            }
            let h = summary.hidden;
            let _ = write!(
                s,
                "}}}},\"hidden\":{{\"bidi\":{},\"invisible\":{},\"control\":{},\"loneCr\":{}}},\"invalidUtf8Replaced\":{}",
                h.bidi, h.invisible, h.control, h.lone_cr, summary.invalid_utf8_replaced
            );
            s.push_str(",\"warnings\":[");
            for (i, w) in summary.warnings.iter().enumerate() {
                if i > 0 {
                    s.push(',');
                }
                s.push_str("{\"code\":");
                json::string(&mut s, w.code());
                match w {
                    Warning::UnterminatedPrivateKeyBlock { line } => {
                        let _ = write!(s, ",\"line\":{line}}}");
                    }
                    Warning::UnstableLineRedacted { first_line, lines } => {
                        let _ = write!(s, ",\"line\":{first_line},\"lines\":{lines}}}");
                    }
                }
            }
            s.push(']');
        }
        None => s.push_str(
            ",\"replacements\":null,\"hidden\":null,\"invalidUtf8Replaced\":null,\"warnings\":[]",
        ),
    }
    s.push_str(",\"sandbox\":");
    json::string(&mut s, f.sandbox);
    s.push_str(",\"error\":");
    match f.failure {
        Some(failure) => {
            s.push_str("{\"code\":");
            json::string(&mut s, failure.code_str());
            s.push_str(",\"line\":");
            json::opt_u64(&mut s, failure.line);
            s.push('}');
        }
        None => s.push_str("null"),
    }
    s.push_str(",\"notice\":");
    json::string(&mut s, NOTICE);
    s.push_str("}\n");
    s
}

pub fn version() -> String {
    format!(
        "spymonk-redact {TOOL_VERSION}\nrules {RULES_VERSION} sha256 {RULES_SHA256}\ncommit {BUILD_COMMIT}\ntarget {BUILD_TARGET}\nbuilt {BUILD_DATE}\n"
    )
}
