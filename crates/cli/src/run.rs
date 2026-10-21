//! One sanitizing run (TRD §9.2–§9.7): open input and outputs by handle, harden, stream 64 KiB
//! chunks through the engine, write the output and reports, and choose the exit code.

use std::io::{self, BufWriter, IsTerminal, Read, Write};

use spymonk_redact_core::{DetectedEncoding, EncodingKind, Limits, Options, Sanitizer, Summary};

use crate::args::{Escape, ReportFormat, RunConfig};
use crate::atomic::{self, Pending};
use crate::error::{Code, Failure};
use crate::render::Escaper;
use crate::report::{self, Facts, NOTICE};
use crate::{harden, io as input_io, signals};

const CHUNK: usize = 64 * 1024;

enum Sink {
    Stdout(BufWriter<io::StdoutLock<'static>>),
    File(BufWriter<std::fs::File>),
}

/// Why streaming stopped early.
enum Stop {
    Failed(Failure),
    /// The consumer closed standard output: stop silently (exit 141 on Unix).
    BrokenPipe,
}

struct Progress {
    bytes_in: u64,
    bytes_out: u64,
    encoding: Option<DetectedEncoding>,
}

pub fn run(cfg: &RunConfig) -> u8 {
    if cfg.input.is_none() && io::stdin().is_terminal() {
        eprintln!(
            "spymonk-redact: no input: give a FILE, or pipe text to standard input\nTry 'spymonk-redact --help' for usage."
        );
        return 2;
    }

    let mut progress = Progress {
        bytes_in: 0,
        bytes_out: 0,
        encoding: None,
    };
    let mut report_pending: Option<Pending> = None;
    let mut sandbox = "none";

    let result = (|| -> Result<Summary, Stop> {
        let (mut input, input_id) =
            input_io::open_input(cfg.input.as_deref()).map_err(Stop::Failed)?;
        let mut output = match &cfg.output {
            Some(path) => Some(atomic::prepare(path, input_id).map_err(Stop::Failed)?),
            None => None,
        };
        if let Some(path) = cfg.report.as_ref().and_then(|r| r.file.as_ref()) {
            report_pending = Some(atomic::prepare(path, input_id).map_err(Stop::Failed)?);
        }
        signals::install();
        sandbox = harden::sandbox();

        let escape = output.is_none()
            && match cfg.escape {
                Escape::Always => true,
                Escape::Never => false,
                Escape::Auto => io::stdout().is_terminal(),
            };
        let mut sink = match output.as_mut().and_then(Pending::writer) {
            Some(file) => Sink::File(BufWriter::with_capacity(
                CHUNK,
                file.try_clone()
                    .map_err(|_| Stop::Failed(Failure::new(Code::OutputWriteFailed)))?,
            )),
            None => Sink::Stdout(BufWriter::with_capacity(CHUNK, io::stdout().lock())),
        };
        let summary = stream(cfg, &mut input, &mut sink, escape, &mut progress)?;
        flush(&mut sink)?;
        drop(sink);
        if let Some(pending) = output {
            pending.commit().map_err(Stop::Failed)?;
        }
        Ok(summary)
    })();

    let display_escaped = cfg.output.is_none()
        && match cfg.escape {
            Escape::Always => true,
            Escape::Never => false,
            Escape::Auto => io::stdout().is_terminal(),
        };

    let (summary, failure) = match result {
        Ok(summary) => (Some(summary), None),
        Err(Stop::Failed(f)) => (None, Some(f)),
        Err(Stop::BrokenPipe) => {
            drop(report_pending);
            return if cfg!(unix) { 141 } else { 1 };
        }
    };
    let facts = Facts {
        cfg,
        summary: summary.as_ref(),
        failure,
        encoding: summary.as_ref().map(|s| s.encoding).or(progress.encoding),
        bytes_in: progress.bytes_in,
        bytes_out: progress.bytes_out,
        display_escaped,
        sandbox,
    };
    let failure = finish_reports(cfg, &facts, report_pending).or(failure);
    match failure {
        Some(f) => f.exit_code(),
        None => 0,
    }
}

fn read_chunk(input: &mut impl Read, buf: &mut [u8]) -> Result<usize, Stop> {
    loop {
        if let Some(signal) = signals::pending() {
            return Err(Stop::Failed(Failure::new(Code::Interrupted(signal))));
        }
        match input.read(buf) {
            Ok(n) => return Ok(n),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(Stop::Failed(Failure::new(Code::InputReadFailed))),
        }
    }
}

fn stream(
    cfg: &RunConfig,
    input: &mut impl Read,
    sink: &mut Sink,
    escape: bool,
    progress: &mut Progress,
) -> Result<Summary, Stop> {
    let limits = Limits {
        max_line_bytes: cfg.max_line_bytes,
        max_total_bytes: None,
    };
    let options = Options {
        email: cfg.email,
        private_ip: cfg.private_ip,
    };
    let mut sanitizer =
        Sanitizer::new(options, limits, cfg.input_encoding, cfg.invalid_utf8, false)
            .map_err(|e| Stop::Failed(e.into()))?;
    let mut escaper = escape.then(Escaper::default);
    let mut buf = vec![0u8; CHUNK];
    let mut out = Vec::with_capacity(CHUNK);
    loop {
        let n = read_chunk(input, &mut buf)?;
        if n == 0 {
            break;
        }
        progress.bytes_in = progress.bytes_in.saturating_add(n as u64);
        out.clear();
        let pushed = sanitizer.push(buf.get(..n).unwrap_or_default(), &mut out);
        buf.fill(0);
        progress.encoding = Some(sanitizer.detected_encoding());
        // Lines completed before a failure are still written (TRD §9.4).
        emit(
            sink,
            &out,
            escaper.as_mut(),
            sanitizer.detected_encoding().kind,
            progress,
        )?;
        pushed.map_err(|e| Stop::Failed(e.into()))?;
        if let Some(signal) = signals::pending() {
            return Err(Stop::Failed(Failure::new(Code::Interrupted(signal))));
        }
    }
    out.clear();
    let finished = sanitizer.finish(&mut out);
    let kind = sanitizer.detected_encoding().kind;
    progress.encoding = Some(sanitizer.detected_encoding());
    emit(sink, &out, escaper.as_mut(), kind, progress)?;
    let summary = finished.map_err(|e| Stop::Failed(e.into()))?;
    if let Some(e) = escaper.as_mut() {
        let tail = e.finish();
        write(sink, tail.as_bytes(), progress)?;
    }
    Ok(summary)
}

fn emit(
    sink: &mut Sink,
    bytes: &[u8],
    escaper: Option<&mut Escaper>,
    kind: EncodingKind,
    progress: &mut Progress,
) -> Result<(), Stop> {
    match escaper {
        Some(e) => {
            let text = e.push(bytes, kind);
            write(sink, text.as_bytes(), progress)
        }
        None => write(sink, bytes, progress),
    }
}

fn write(sink: &mut Sink, bytes: &[u8], progress: &mut Progress) -> Result<(), Stop> {
    if bytes.is_empty() {
        return Ok(());
    }
    let result = match sink {
        Sink::Stdout(w) => w.write_all(bytes),
        Sink::File(w) => w.write_all(bytes),
    };
    result.map_err(|e| write_error(sink, &e))?;
    progress.bytes_out = progress.bytes_out.saturating_add(bytes.len() as u64);
    Ok(())
}

fn flush(sink: &mut Sink) -> Result<(), Stop> {
    let result = match sink {
        Sink::Stdout(w) => w.flush(),
        Sink::File(w) => w.flush(),
    };
    result.map_err(|e| write_error(sink, &e))
}

fn write_error(sink: &Sink, e: &io::Error) -> Stop {
    if matches!(sink, Sink::Stdout(_)) && e.kind() == io::ErrorKind::BrokenPipe {
        Stop::BrokenPipe
    } else {
        Stop::Failed(Failure::new(Code::OutputWriteFailed))
    }
}

/// Writes the report and notices. Returns a failure if the report file could not be written.
fn finish_reports(
    cfg: &RunConfig,
    facts: &Facts<'_>,
    report_file: Option<Pending>,
) -> Option<Failure> {
    let format = cfg.report.as_ref().map(|r| r.format);
    let rendered = format.map(|f| match f {
        ReportFormat::Text => report::text(facts),
        ReportFormat::Json => report::json(facts),
    });
    let mut stderr = io::stderr().lock();
    let mut failure = None;
    let json_on_stderr = format == Some(ReportFormat::Json) && report_file.is_none();

    if let (Some(mut pending), Some(text)) = (report_file, rendered.as_ref()) {
        let written = pending
            .writer()
            .map(|w| w.write_all(text.as_bytes()).is_ok())
            .unwrap_or(false);
        if !written || pending.commit().is_err() {
            failure = Some(Failure::new(Code::OutputWriteFailed));
        }
    } else if let Some(text) = rendered.as_ref() {
        let _ = stderr.write_all(text.as_bytes());
    }
    if json_on_stderr {
        // Standard error then carries exactly one JSON document.
        return failure;
    }

    match facts.failure {
        Some(f) => {
            let _ = writeln!(stderr, "{}", f.line_text());
        }
        None => {
            let _ = writeln!(stderr, "spymonk-redact: {NOTICE}");
            if let Some(summary) = facts.summary {
                let hidden = report::hidden_total(summary);
                if hidden > 0 {
                    let _ = writeln!(stderr, "spymonk-redact: {}", report::hidden_notice(hidden));
                }
                if format != Some(ReportFormat::Text)
                    || cfg.report.as_ref().is_some_and(|r| r.file.is_some())
                {
                    for w in &summary.warnings {
                        let _ = writeln!(stderr, "{}", report::warning_text(w));
                    }
                }
            }
        }
    }
    if let Some(f) = failure {
        let _ = writeln!(stderr, "{}", f.line_text());
    }
    failure
}
