//! The CLI's error model (TRD §5.5, §9.7): fixed codes and messages. Numeric details are limited
//! to line numbers; no message contains input, file names, paths, values, or system error text.

use spymonk_redact_core::{CoreError, ErrorCode};

#[cfg_attr(
    not(windows),
    expect(dead_code, reason = "named by the Windows console handler")
)]
pub const SIGINT: i32 = 2;
pub const SIGTERM: i32 = 15;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    Core(ErrorCode),
    InputReadFailed,
    OutputWriteFailed,
    OutputIsInput,
    OutputNotRegular,
    /// Interrupted by a signal: SIGINT/Ctrl+C (2) or SIGTERM (15).
    Interrupted(i32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Failure {
    pub code: Code,
    pub line: Option<u64>,
}

impl Failure {
    pub const fn new(code: Code) -> Self {
        Self { code, line: None }
    }

    pub fn code_str(&self) -> &'static str {
        match self.code {
            Code::Core(c) => c.as_str(),
            Code::InputReadFailed => "INPUT_READ_FAILED",
            Code::OutputWriteFailed => "OUTPUT_WRITE_FAILED",
            Code::OutputIsInput => "OUTPUT_IS_INPUT",
            Code::OutputNotRegular => "OUTPUT_NOT_REGULAR",
            Code::Interrupted(_) => "INTERRUPTED",
        }
    }

    pub fn message(&self) -> &'static str {
        match self.code {
            Code::Core(c) => c.message(),
            Code::InputReadFailed => {
                "the input could not be read (it must be a readable regular file, a pipe, or a terminal)"
            }
            Code::OutputWriteFailed => {
                "the output could not be written; no partial file was left at the target"
            }
            Code::OutputIsInput => "the output path refers to the input file",
            Code::OutputNotRegular => {
                "the output path exists and is not a regular file (or is a symbolic link)"
            }
            Code::Interrupted(_) => "interrupted; no output file was written",
        }
    }

    pub fn exit_code(&self) -> u8 {
        match self.code {
            Code::Interrupted(SIGTERM) => 143,
            Code::Interrupted(_) => 130,
            _ => 1,
        }
    }

    /// `spymonk-redact: error: CODE (line N): message`
    pub fn line_text(&self) -> String {
        match self.line {
            Some(line) => format!(
                "spymonk-redact: error: {} (line {line}): {}",
                self.code_str(),
                self.message()
            ),
            None => format!(
                "spymonk-redact: error: {}: {}",
                self.code_str(),
                self.message()
            ),
        }
    }
}

impl From<CoreError> for Failure {
    fn from(e: CoreError) -> Self {
        Self {
            code: Code::Core(e.code),
            line: e.line,
        }
    }
}
