//! SpyMonk Redact detection engine (TRD §5).
//!
//! `no_std` + `alloc` and `forbid(unsafe_code)`: the engine has no access to files, network,
//! processes, clocks, randomness, or the environment. It transforms buffers and nothing else.
#![no_std]
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

extern crate alloc;

pub mod census;
pub mod codec;
mod detectors;
mod engine;
pub mod framer;
mod model;
#[doc(hidden)]
pub mod resolve;
pub mod rules;
mod scan;

pub use engine::{Sanitizer, sanitize_bytes};

pub use model::{
    CoreError, DEFAULT_MAX_LINE_BYTES, DetectedEncoding, EncodingKind, ErrorCode, Finding,
    HiddenCensus, InputEncoding, InvalidUtf8, Limits, MAX_MAX_LINE_BYTES, MIN_MAX_LINE_BYTES,
    Options, RULE_COUNT, RuleId, Summary, Warning,
};
