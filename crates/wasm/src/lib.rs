//! WebAssembly exports for the browser worker (TRD §10.5, §11.2). The worker is the only caller:
//! it instantiates this module, never the page. Exports are limited to the sanitizer API.
//!
//! Buffers that held input or output are zeroed when a job is released (`free()` in
//! JavaScript). JavaScript strings are immutable and cannot be zeroed (TRD §11.4).
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

pub mod job;

use js_sys::{Array, JsString, Object, Reflect, Uint8Array, Uint32Array};
use spymonk_redact_core::census::{self, HiddenKind};
use spymonk_redact_core::rules::{self, RULES_SHA256, RULES_VERSION};
use spymonk_redact_core::{CoreError, RULE_COUNT, RuleId, Summary, Warning};
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

use crate::job::{FileCore, PasteOutcome};

#[wasm_bindgen(js_name = rulesVersion)]
pub fn rules_version() -> String {
    RULES_VERSION.into()
}

#[wasm_bindgen(js_name = rulesSha256)]
pub fn rules_sha256() -> String {
    RULES_SHA256.into()
}

#[wasm_bindgen(js_name = toolVersion)]
pub fn tool_version() -> String {
    env!("CARGO_PKG_VERSION").into()
}

/// Rule IDs in engine index order, for decoding the `rule` field of ranges.
#[wasm_bindgen(js_name = ruleIds)]
pub fn rule_ids() -> Array {
    (0..RULE_COUNT)
        .filter_map(|i| u8::try_from(i).ok())
        .map(|i| JsValue::from_str(rules::rule_id_str(RuleId(i))))
        .collect()
}

/// Classifies a code point for the hidden-character display: 0 none, 1 bidirectional control,
/// 2 invisible, 3 control. The page mirrors this table; a test checks every code point against
/// it so the browser and the CLI show the same set (TRD §9.5).
#[wasm_bindgen(js_name = hiddenKind)]
pub fn hidden_kind(code_point: u32) -> u8 {
    match char::from_u32(code_point).and_then(census::hidden_kind) {
        None => 0,
        Some(HiddenKind::Bidi) => 1,
        Some(HiddenKind::Invisible) => 2,
        Some(HiddenKind::Control) => 3,
    }
}

/// One paste job's result. Call `free()` after reading it to zero the output buffer.
#[wasm_bindgen]
#[derive(Debug)]
pub struct PasteResult {
    outcome: PasteOutcome,
}

#[wasm_bindgen]
impl PasteResult {
    /// The sanitized text, or an empty string after an error.
    #[wasm_bindgen(getter)]
    pub fn output(&self) -> JsString {
        match &self.outcome {
            PasteOutcome::Done { output, .. } => JsString::from(output.as_str()),
            PasteOutcome::Failed(_) => JsString::from(""),
        }
    }

    /// Flat `[start, end, ruleIndex]` UTF-16 offsets of inserted placeholders.
    #[wasm_bindgen(getter)]
    pub fn ranges(&self) -> Uint32Array {
        match &self.outcome {
            PasteOutcome::Done { ranges, .. } => Uint32Array::from(ranges.as_slice()),
            PasteOutcome::Failed(_) => Uint32Array::new_with_length(0),
        }
    }

    /// A plain summary object, or `undefined` after an error.
    #[wasm_bindgen(getter)]
    pub fn summary(&self) -> JsValue {
        match &self.outcome {
            PasteOutcome::Done { summary, .. } => summary_object(summary).into(),
            PasteOutcome::Failed(_) => JsValue::UNDEFINED,
        }
    }

    /// `{ code, line }` after an error, otherwise `undefined`.
    #[wasm_bindgen(getter)]
    pub fn error(&self) -> JsValue {
        match &self.outcome {
            PasteOutcome::Failed(e) => error_object(e),
            PasteOutcome::Done { .. } => JsValue::UNDEFINED,
        }
    }
}

impl Drop for PasteResult {
    fn drop(&mut self) {
        if let PasteOutcome::Done { output, .. } = &mut self.outcome {
            output.zeroize();
        }
    }
}

/// Sanitizes pasted text (at most 1 MiB of UTF-8). Taking the string by value lets the input
/// copy in WebAssembly memory be zeroed before this returns.
#[wasm_bindgen(js_name = sanitizePaste)]
pub fn sanitize_paste(text: String, email: bool, private_ip: bool) -> PasteResult {
    PasteResult {
        outcome: job::sanitize_paste(text, email, private_ip),
    }
}

/// A streaming file job (TRD §10.4). Errors are thrown as `{ code, line }` objects.
#[wasm_bindgen]
#[derive(Debug)]
pub struct FileJob {
    core: FileCore,
}

#[wasm_bindgen]
impl FileJob {
    #[wasm_bindgen(constructor)]
    pub fn new(email: bool, private_ip: bool, max_line_bytes: u32) -> Result<FileJob, JsValue> {
        FileCore::new(email, private_ip, max_line_bytes)
            .map(|core| FileJob { core })
            .map_err(|e| error_object(&e))
    }

    /// Sanitizes the next chunk; returns the complete output lines it produced.
    pub fn push(&mut self, mut chunk: Vec<u8>) -> Result<Uint8Array, JsValue> {
        let result = self.core.push(&chunk);
        chunk.zeroize();
        result.map(to_js_bytes).map_err(|e| error_object(&e))
    }

    /// Flushes the final line.
    pub fn finish(&mut self) -> Result<Uint8Array, JsValue> {
        self.core
            .finish()
            .map(to_js_bytes)
            .map_err(|e| error_object(&e))
    }

    /// The summary after a successful `finish()`, otherwise `undefined`.
    pub fn summary(&self) -> JsValue {
        self.core
            .summary()
            .map_or(JsValue::UNDEFINED, |s| summary_object(s).into())
    }

    /// The start of the sanitized text, at most 64 KiB.
    #[wasm_bindgen(js_name = previewText)]
    pub fn preview_text(&self) -> JsString {
        JsString::from(self.core.preview().0)
    }

    /// Flat `[start, end, ruleIndex]` UTF-16 ranges of placeholders inside the preview.
    #[wasm_bindgen(js_name = previewRanges)]
    pub fn preview_ranges(&self) -> Uint32Array {
        Uint32Array::from(self.core.preview().1.as_slice())
    }
}

/// Copies output into a JavaScript-owned array, then zeroes the WebAssembly copy.
fn to_js_bytes(mut bytes: Vec<u8>) -> Uint8Array {
    let array = Uint8Array::from(bytes.as_slice());
    bytes.zeroize();
    array
}

fn set(target: &Object, key: &str, value: JsValue) {
    // `Reflect.set` on a fresh plain object cannot fail.
    let _ = Reflect::set(target, &JsValue::from_str(key), &value);
}

fn num(n: u64) -> JsValue {
    // Counts stay far below 2^53, where f64 is exact.
    JsValue::from_f64(n as f64)
}

fn error_object(e: &CoreError) -> JsValue {
    let o = Object::new();
    set(&o, "code", JsValue::from_str(e.code.as_str()));
    set(&o, "line", e.line.map_or(JsValue::NULL, num));
    o.into()
}

fn summary_object(s: &Summary) -> Object {
    let o = Object::new();
    set(&o, "replacements", num(s.replacements));
    let by_rule = Object::new();
    for (i, n) in s.by_rule.iter().enumerate() {
        if let Ok(i) = u8::try_from(i) {
            set(&by_rule, rules::rule_id_str(RuleId(i)), num(*n));
        }
    }
    set(&o, "byRule", by_rule.into());
    set(&o, "lines", num(s.lines));
    set(&o, "bytesIn", num(s.bytes_in));
    set(&o, "bytesOut", num(s.bytes_out));
    set(&o, "encoding", JsValue::from_str(s.encoding.kind.as_str()));
    set(&o, "bom", JsValue::from_bool(s.encoding.bom));
    set(&o, "invalidUtf8Replaced", num(s.invalid_utf8_replaced));
    let hidden = Object::new();
    set(&hidden, "bidi", num(s.hidden.bidi));
    set(&hidden, "invisible", num(s.hidden.invisible));
    set(&hidden, "control", num(s.hidden.control));
    set(&hidden, "loneCr", num(s.hidden.lone_cr));
    set(&o, "hidden", hidden.into());
    let warnings: Array = s.warnings.iter().map(warning_object).collect();
    set(&o, "warnings", warnings.into());
    set(&o, "rulesVersion", JsValue::from_str(s.rules_version));
    set(&o, "rulesSha256", JsValue::from_str(s.rules_sha256));
    o
}

fn warning_object(w: &Warning) -> JsValue {
    let o = Object::new();
    set(&o, "code", JsValue::from_str(w.code()));
    match w {
        Warning::UnterminatedPrivateKeyBlock { line } => set(&o, "line", num(*line)),
        Warning::UnstableLineRedacted { first_line, lines } => {
            set(&o, "line", num(*first_line));
            set(&o, "lines", num(*lines));
        }
    }
    o.into()
}
