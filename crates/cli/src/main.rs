//! `spymonk-redact`: redact secrets and personal identifiers from text before sharing it.
//!
//! The binary is a thin adapter over `spymonk-redact-core` (TRD §9). It performs no network
//! activity, process creation, environment configuration, recursion, or in-place editing.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod args;
mod atomic;
mod catalog;
mod error;
mod harden;
mod io;
mod json;
mod osrand;
mod render;
mod report;
mod run;
mod signals;

use std::io::Write;
use std::process::ExitCode;

use args::{Command, ReportFormat};

fn main() -> ExitCode {
    harden::early();
    let command = match args::parse(std::env::args_os().skip(1)) {
        Ok(command) => command,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let code = match command {
        Command::Help => print(args::HELP),
        Command::Version => print(&report::version()),
        Command::ListRules(ReportFormat::Text) => print(&catalog::text()),
        Command::ListRules(ReportFormat::Json) => print(&catalog::json()),
        Command::Run(cfg) => {
            #[cfg(feature = "sandbox-probe")]
            if cfg.probe_sandbox {
                harden::sandbox();
                return ExitCode::from(print(&harden::probe()));
            }
            run::run(&cfg)
        }
    };
    ExitCode::from(code)
}

fn print(text: &str) -> u8 {
    let mut out = std::io::stdout().lock();
    match out.write_all(text.as_bytes()).and_then(|()| out.flush()) {
        Ok(()) => 0,
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
            if cfg!(unix) {
                141
            } else {
                1
            }
        }
        Err(_) => 1,
    }
}
