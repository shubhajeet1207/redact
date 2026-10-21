//! Command-line parsing (TRD §9.1). Usage errors carry fixed messages that name the option but
//! never repeat a user-supplied value, and non-UTF-8 arguments are rejected.

use std::ffi::OsString;
use std::fmt;
use std::path::PathBuf;

use spymonk_redact_core::{
    DEFAULT_MAX_LINE_BYTES, InputEncoding, InvalidUtf8, MAX_MAX_LINE_BYTES, MIN_MAX_LINE_BYTES,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    Text,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Escape {
    Auto,
    Always,
    Never,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reporting {
    pub format: ReportFormat,
    pub file: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunConfig {
    /// `None` reads standard input.
    pub input: Option<PathBuf>,
    pub output: Option<PathBuf>,
    pub input_encoding: InputEncoding,
    pub invalid_utf8: InvalidUtf8,
    pub max_line_bytes: u32,
    pub email: bool,
    pub private_ip: bool,
    pub report: Option<Reporting>,
    pub escape: Escape,
    /// Hidden test hook (`--probe-sandbox`), compiled only with the `sandbox-probe` feature.
    pub probe_sandbox: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Help,
    Version,
    ListRules(ReportFormat),
    Run(RunConfig),
}

/// A usage error: a fixed message that may name an option, never a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UsageError(pub &'static str);

impl fmt::Display for UsageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "spymonk-redact: {}\nTry 'spymonk-redact --help' for usage.",
            self.0
        )
    }
}

pub const HELP: &str = "\
Usage: spymonk-redact [OPTIONS] [FILE | -]

Redacts secrets and personal identifiers from text. Reads FILE, or standard input when FILE is
absent or '-', and writes sanitized text to standard output. Nothing leaves this machine.

Input and output
  -o, --output PATH          Write sanitized output atomically to PATH (stdout stays empty)
      --input-encoding ENC   auto (default) | utf-8 | utf-16le | utf-16be
      --invalid-utf8 MODE    error (default) | replace
      --max-line-bytes N     Default 1048576; accepted range 1024 to 67108864
Rules
      --disable-email
      --enable-private-ip
      --list-rules           Print the rule catalog and exit (honors --report-format)
Reporting
      --report               Print a summary to stderr
      --report-format FMT    text (default) | json
      --report-file PATH     Write the report to PATH atomically, instead of stderr
Display
      --escape-controls MODE auto (default: when stdout is a terminal) | always | never
Information
  -h, --help
  -V, --version

Exit status: 0 success, 1 failure, 2 usage error, 130/143 interrupted, 141 broken pipe.
Review output before sharing; detection is limited. Rotate any credential that was already exposed.
";

fn utf8(value: OsString, message: &'static str) -> Result<String, UsageError> {
    value.into_string().map_err(|_| UsageError(message))
}

/// Parses the arguments after the program name.
pub fn parse<I>(args: I) -> Result<Command, UsageError>
where
    I: IntoIterator<Item = OsString>,
{
    use lexopt::Arg::{Long, Short, Value};

    let mut parser = lexopt::Parser::from_args(args);
    let mut cfg = RunConfig {
        input: None,
        output: None,
        input_encoding: InputEncoding::Auto,
        invalid_utf8: InvalidUtf8::Error,
        max_line_bytes: DEFAULT_MAX_LINE_BYTES,
        email: true,
        private_ip: false,
        report: None,
        escape: Escape::Auto,
        probe_sandbox: false,
    };
    let mut report_requested = false;
    let mut report_format: Option<ReportFormat> = None;
    let mut report_file: Option<PathBuf> = None;
    let mut list_rules = false;
    let mut info: Option<Command> = None;
    let mut operands = 0u8;

    loop {
        let arg = match parser.next() {
            Ok(Some(arg)) => arg,
            Ok(None) => break,
            Err(lexopt::Error::UnexpectedValue { .. }) => {
                return Err(UsageError("an option that takes no value was given one"));
            }
            Err(lexopt::Error::NonUnicodeValue(_)) => {
                return Err(UsageError(
                    "arguments must be valid UTF-8; an argument is not valid UTF-8",
                ));
            }
            Err(_) => return Err(UsageError("unknown or malformed option")),
        };
        match arg {
            Short('h') | Long("help") => info = Some(Command::Help),
            Short('V') | Long("version") => info = info.or(Some(Command::Version)),
            Long("list-rules") => list_rules = true,
            Short('o') | Long("output") => {
                let v = parser
                    .value()
                    .map_err(|_| UsageError("--output needs a PATH"))?;
                cfg.output = Some(PathBuf::from(utf8(v, "--output PATH is not valid UTF-8")?));
            }
            Long("input-encoding") => {
                let v = parser
                    .value()
                    .map_err(|_| UsageError("--input-encoding needs a value"))?;
                cfg.input_encoding = match utf8(v, "invalid value for --input-encoding")?.as_str() {
                    "auto" => InputEncoding::Auto,
                    "utf-8" | "utf8" => InputEncoding::Utf8,
                    "utf-16le" => InputEncoding::Utf16Le,
                    "utf-16be" => InputEncoding::Utf16Be,
                    _ => {
                        return Err(UsageError(
                            "invalid value for --input-encoding (auto, utf-8, utf-16le, utf-16be)",
                        ));
                    }
                };
            }
            Long("invalid-utf8") => {
                let v = parser
                    .value()
                    .map_err(|_| UsageError("--invalid-utf8 needs a value"))?;
                cfg.invalid_utf8 = match utf8(v, "invalid value for --invalid-utf8")?.as_str() {
                    "error" => InvalidUtf8::Error,
                    "replace" => InvalidUtf8::Replace,
                    _ => {
                        return Err(UsageError(
                            "invalid value for --invalid-utf8 (error, replace)",
                        ));
                    }
                };
            }
            Long("max-line-bytes") => {
                let v = parser
                    .value()
                    .map_err(|_| UsageError("--max-line-bytes needs a number"))?;
                let n: u32 = utf8(v, "invalid value for --max-line-bytes")?
                    .parse()
                    .map_err(|_| {
                        UsageError("invalid value for --max-line-bytes (1024 to 67108864)")
                    })?;
                if !(MIN_MAX_LINE_BYTES..=MAX_MAX_LINE_BYTES).contains(&n) {
                    return Err(UsageError(
                        "invalid value for --max-line-bytes (1024 to 67108864)",
                    ));
                }
                cfg.max_line_bytes = n;
            }
            Long("disable-email") => cfg.email = false,
            Long("enable-private-ip") => cfg.private_ip = true,
            Long("report") => report_requested = true,
            Long("report-format") => {
                let v = parser
                    .value()
                    .map_err(|_| UsageError("--report-format needs a value"))?;
                report_format = Some(
                    match utf8(v, "invalid value for --report-format")?.as_str() {
                        "text" => ReportFormat::Text,
                        "json" => ReportFormat::Json,
                        _ => {
                            return Err(UsageError(
                                "invalid value for --report-format (text, json)",
                            ));
                        }
                    },
                );
            }
            Long("report-file") => {
                let v = parser
                    .value()
                    .map_err(|_| UsageError("--report-file needs a PATH"))?;
                report_file = Some(PathBuf::from(utf8(
                    v,
                    "--report-file PATH is not valid UTF-8",
                )?));
            }
            Long("escape-controls") => {
                let v = parser
                    .value()
                    .map_err(|_| UsageError("--escape-controls needs a value"))?;
                cfg.escape = match utf8(v, "invalid value for --escape-controls")?.as_str() {
                    "auto" => Escape::Auto,
                    "always" => Escape::Always,
                    "never" => Escape::Never,
                    _ => {
                        return Err(UsageError(
                            "invalid value for --escape-controls (auto, always, never)",
                        ));
                    }
                };
            }
            #[cfg(feature = "sandbox-probe")]
            Long("probe-sandbox") => cfg.probe_sandbox = true,
            Value(v) => {
                operands = operands.saturating_add(1);
                if operands > 1 {
                    return Err(UsageError("more than one input FILE was given"));
                }
                let s = utf8(
                    v,
                    "arguments must be valid UTF-8; an argument is not valid UTF-8",
                )?;
                cfg.input = if s == "-" {
                    None
                } else {
                    Some(PathBuf::from(s))
                };
            }
            _ => return Err(UsageError("unknown or malformed option")),
        }
    }

    if let Some(cmd) = info {
        return Ok(cmd);
    }
    if list_rules {
        return Ok(Command::ListRules(
            report_format.unwrap_or(ReportFormat::Text),
        ));
    }
    if report_requested || report_format.is_some() || report_file.is_some() {
        if let (Some(r), Some(o)) = (&report_file, &cfg.output)
            && r == o
        {
            return Err(UsageError(
                "--output and --report-file must be different paths",
            ));
        }
        cfg.report = Some(Reporting {
            format: report_format.unwrap_or(ReportFormat::Text),
            file: report_file,
        });
    }
    Ok(Command::Run(cfg))
}
