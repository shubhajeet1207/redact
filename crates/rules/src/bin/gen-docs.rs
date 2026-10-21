//! Generates the checked-in rule reference (`docs/rules.md`) and the browser's rule data
//! (`web/src/generated/rules.json`) from the canonical rule manifest.
//!
//! `cargo run -p spymonk-redact-rules --bin gen-docs -- --check` fails when either checked-in
//! file does not match the manifest. Without `--check`, it writes both.

use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use spymonk_redact_rules::{compile, generate_markdown, generate_web_json};

fn main() -> Result<ExitCode, Box<dyn Error>> {
    let mut args = env::args_os();
    let _program = args.next();
    let check = match args.next() {
        None => false,
        Some(arg) if arg == "--check" && args.next().is_none() => true,
        Some(_) => {
            eprintln!("usage: gen-docs [--check]");
            return Ok(ExitCode::from(2));
        }
    };

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest = fs::read(root.join("rules/rules.v1.json"))?;
    let compiled = compile(&manifest)?;
    let outputs = [
        (root.join("docs/rules.md"), generate_markdown(&compiled)),
        (
            root.join("web/src/generated/rules.json"),
            generate_web_json(&compiled),
        ),
    ];

    let mut stale = false;
    for (destination, rendered) in &outputs {
        if check {
            if fs::read_to_string(destination).ok().as_deref() != Some(rendered.as_str()) {
                eprintln!("{} is stale", destination.display());
                stale = true;
            }
        } else {
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(destination, rendered)?;
        }
    }
    if stale {
        eprintln!("run `cargo run -p spymonk-redact-rules --bin gen-docs`");
        return Ok(ExitCode::from(1));
    }
    Ok(ExitCode::SUCCESS)
}
