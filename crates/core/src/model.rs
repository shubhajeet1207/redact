//! Public data model of the engine (TRD §5.1, §5.5).

use alloc::vec::Vec;
use core::fmt;

use crate::rules;

/// Index of a rule in the compiled catalog (`RuleId(0)` is `SR-001`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RuleId(pub u8);

/// Number of rules in the compiled catalog.
pub const RULE_COUNT: usize = rules::RULE_COUNT;

/// User-controllable options. Only the optional rules can be toggled (PRD §7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    pub email: bool,
    pub private_ip: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            email: rules::RULE_DEFAULT[rules::IDX_EMAIL],
            private_ip: rules::RULE_DEFAULT[rules::IDX_PRIVATE_IP],
        }
    }
}

impl Options {
    /// Whether a rule runs under these options. Non-optional rules always run.
    pub fn rule_enabled(&self, rule: RuleId) -> bool {
        match usize::from(rule.0) {
            i if i == rules::IDX_EMAIL => self.email,
            i if i == rules::IDX_PRIVATE_IP => self.private_ip,
            _ => true,
        }
    }
}

pub const DEFAULT_MAX_LINE_BYTES: u32 = 1_048_576;
pub const MIN_MAX_LINE_BYTES: u32 = 1_024;
pub const MAX_MAX_LINE_BYTES: u32 = 67_108_864;

/// Resource limits (TRD §5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Longest permitted line in decoded UTF-8 bytes, excluding its separator.
    pub max_line_bytes: u32,
    /// Total input limit in bytes; `None` for the streaming CLI, `Some(1 MiB)` for paste mode.
    pub max_total_bytes: Option<u64>,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_line_bytes: DEFAULT_MAX_LINE_BYTES,
            max_total_bytes: None,
        }
    }
}

impl Limits {
    pub fn validate(&self) -> Result<(), CoreError> {
        if (MIN_MAX_LINE_BYTES..=MAX_MAX_LINE_BYTES).contains(&self.max_line_bytes) {
            Ok(())
        } else {
            Err(CoreError::new(ErrorCode::InvalidOptions))
        }
    }
}

/// Requested input encoding (TRD §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InputEncoding {
    #[default]
    Auto,
    Utf8,
    Utf16Le,
    Utf16Be,
}

/// Handling of invalid UTF-8 (TRD §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InvalidUtf8 {
    #[default]
    Error,
    Replace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodingKind {
    Utf8,
    Utf16Le,
    Utf16Be,
}

impl EncodingKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EncodingKind::Utf8 => "utf-8",
            EncodingKind::Utf16Le => "utf-16le",
            EncodingKind::Utf16Be => "utf-16be",
        }
    }
}

/// The encoding the input was read in; output is written in the same encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetectedEncoding {
    pub kind: EncodingKind,
    pub bom: bool,
}

/// Fixed error codes of the engine (TRD §5.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    InvalidUtf8,
    InvalidUtf16,
    Utf16WithoutBom,
    UnsupportedEncoding,
    NulByte,
    LineTooLong,
    InputTooLarge,
    InvalidOptions,
    InternalError,
}

impl ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::InvalidUtf8 => "INVALID_UTF8",
            ErrorCode::InvalidUtf16 => "INVALID_UTF16",
            ErrorCode::Utf16WithoutBom => "UTF16_WITHOUT_BOM",
            ErrorCode::UnsupportedEncoding => "UNSUPPORTED_ENCODING",
            ErrorCode::NulByte => "NUL_BYTE",
            ErrorCode::LineTooLong => "LINE_TOO_LONG",
            ErrorCode::InputTooLarge => "INPUT_TOO_LARGE",
            ErrorCode::InvalidOptions => "INVALID_OPTIONS",
            ErrorCode::InternalError => "INTERNAL_ERROR",
        }
    }

    /// A fixed, content-free explanation (TRD §5.5: never input, paths, or system text).
    pub fn message(self) -> &'static str {
        match self {
            ErrorCode::InvalidUtf8 => {
                "input is not valid UTF-8 (use --invalid-utf8 replace to substitute U+FFFD)"
            }
            ErrorCode::InvalidUtf16 => {
                "input is not valid UTF-16 (unpaired surrogate or odd length)"
            }
            ErrorCode::Utf16WithoutBom => {
                "input looks like UTF-16 without a byte-order mark (use --input-encoding utf-16le or utf-16be)"
            }
            ErrorCode::UnsupportedEncoding => {
                "input encoding is not supported (UTF-32 byte-order mark)"
            }
            ErrorCode::NulByte => "input contains a NUL byte; binary input is not supported",
            ErrorCode::LineTooLong => {
                "a line exceeds the maximum line length (raise --max-line-bytes)"
            }
            ErrorCode::InputTooLarge => "input exceeds the size limit for this mode",
            ErrorCode::InvalidOptions => "invalid options or limits",
            ErrorCode::InternalError => "internal error; no further output was produced",
        }
    }
}

/// An engine error. `line` is the 1-based line number where processing stopped, when known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoreError {
    pub code: ErrorCode,
    pub line: Option<u64>,
}

impl CoreError {
    pub const fn new(code: ErrorCode) -> Self {
        Self { code, line: None }
    }

    pub const fn at(code: ErrorCode, line: u64) -> Self {
        Self {
            code,
            line: Some(line),
        }
    }
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.line {
            Some(line) => write!(
                f,
                "{} (line {line}): {}",
                self.code.as_str(),
                self.code.message()
            ),
            None => write!(f, "{}: {}", self.code.as_str(), self.code.message()),
        }
    }
}

/// Counts of characters that can hide content from a human reviewer (TRD §9.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HiddenCensus {
    pub bidi: u64,
    pub invisible: u64,
    pub control: u64,
    pub lone_cr: u64,
}

impl HiddenCensus {
    pub fn total(&self) -> u64 {
        self.bidi
            .saturating_add(self.invisible)
            .saturating_add(self.control)
            .saturating_add(self.lone_cr)
    }
}

/// Non-fatal conditions reported in the summary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Warning {
    /// Input ended inside a private-key block; everything after `line` was redacted.
    UnterminatedPrivateKeyBlock { line: u64 },
    /// Redacting `lines` lines (the first is `first_line`) kept exposing new matches, so each was
    /// replaced entirely by one placeholder (fail closed).
    UnstableLineRedacted { first_line: u64, lines: u64 },
}

impl Warning {
    pub fn code(&self) -> &'static str {
        match self {
            Warning::UnterminatedPrivateKeyBlock { .. } => "UNTERMINATED_PRIVATE_KEY_BLOCK",
            Warning::UnstableLineRedacted { .. } => "UNSTABLE_LINE_REDACTED",
        }
    }
}

/// Result metadata. Never contains input content (TRD §5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    pub replacements: u64,
    pub by_rule: [u64; RULE_COUNT],
    pub lines: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub encoding: DetectedEncoding,
    pub invalid_utf8_replaced: u64,
    pub hidden: HiddenCensus,
    pub warnings: Vec<Warning>,
    pub rules_version: &'static str,
    pub rules_sha256: &'static str,
}

/// An inserted placeholder: half-open UTF-8 byte range into the output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Finding {
    pub start: u64,
    pub end: u64,
    pub rule: RuleId,
}
