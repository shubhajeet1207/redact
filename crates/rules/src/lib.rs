//! Build-time compiler for the SpyMonk Redact rule manifest (TRD §8).
//!
//! The manifest (`rules/rules.v1.json`) is data, not code: it cannot express arbitrary patterns.
//! [`compile`] validates it strictly and hashes its exact bytes, [`generate_rust`] emits the tables
//! that `spymonk-redact-core` embeds at build time, and [`generate_markdown`] emits the rule
//! reference, so documentation can never drift from behavior.

mod gen_md;
mod gen_rust;
mod gen_web;
mod validate;

use core::fmt;

pub use gen_md::generate_markdown;
pub use gen_rust::generate_rust;
pub use gen_web::generate_web_json;

/// Detector types, one per rule (closed enumeration, TRD §8.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Detector {
    NamedValue,
    Authorization,
    UrlCredential,
    HomePath,
    Email,
    PrivateIp,
    TokenFormat,
    PemBlock,
    Cookie,
}

impl Detector {
    pub const ALL: [Detector; 9] = [
        Detector::NamedValue,
        Detector::Authorization,
        Detector::UrlCredential,
        Detector::HomePath,
        Detector::Email,
        Detector::PrivateIp,
        Detector::TokenFormat,
        Detector::PemBlock,
        Detector::Cookie,
    ];

    /// Name used in the manifest's `detector` field.
    pub fn manifest_name(self) -> &'static str {
        match self {
            Detector::NamedValue => "named-value",
            Detector::Authorization => "authorization",
            Detector::UrlCredential => "url-credential",
            Detector::HomePath => "home-path",
            Detector::Email => "email",
            Detector::PrivateIp => "private-ip",
            Detector::TokenFormat => "token-format",
            Detector::PemBlock => "pem-block",
            Detector::Cookie => "cookie",
        }
    }

    /// Variant name of `DetectorKind` in the core crate.
    pub fn rust_name(self) -> &'static str {
        match self {
            Detector::NamedValue => "NamedValue",
            Detector::Authorization => "Authorization",
            Detector::UrlCredential => "UrlCredential",
            Detector::HomePath => "HomePath",
            Detector::Email => "Email",
            Detector::PrivateIp => "PrivateIp",
            Detector::TokenFormat => "TokenFormat",
            Detector::PemBlock => "PemBlock",
            Detector::Cookie => "Cookie",
        }
    }

    pub fn from_manifest_name(name: &str) -> Option<Detector> {
        Detector::ALL
            .into_iter()
            .find(|d| d.manifest_name() == name)
    }
}

/// Character classes for credential-format bodies (TRD §6.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Charset {
    /// `[A-Za-z0-9]`
    Alnum,
    /// `[A-Z0-9]`
    AlnumUpper,
    /// `[A-Za-z0-9_]`
    AlnumUs,
    /// `[A-Za-z0-9-]`
    AlnumDash,
    /// `[A-Za-z0-9_-]`
    B64url,
    /// `[A-Za-z0-9_.-]`
    B64urlDot,
}

impl Charset {
    pub const ALL: [Charset; 6] = [
        Charset::Alnum,
        Charset::AlnumUpper,
        Charset::AlnumUs,
        Charset::AlnumDash,
        Charset::B64url,
        Charset::B64urlDot,
    ];

    pub fn manifest_name(self) -> &'static str {
        match self {
            Charset::Alnum => "alnum",
            Charset::AlnumUpper => "alnum-upper",
            Charset::AlnumUs => "alnum-us",
            Charset::AlnumDash => "alnum-dash",
            Charset::B64url => "b64url",
            Charset::B64urlDot => "b64url-dot",
        }
    }

    pub fn rust_name(self) -> &'static str {
        match self {
            Charset::Alnum => "Alnum",
            Charset::AlnumUpper => "AlnumUpper",
            Charset::AlnumUs => "AlnumUs",
            Charset::AlnumDash => "AlnumDash",
            Charset::B64url => "B64url",
            Charset::B64urlDot => "B64urlDot",
        }
    }

    pub fn describe(self) -> &'static str {
        match self {
            Charset::Alnum => "[A-Za-z0-9]",
            Charset::AlnumUpper => "[A-Z0-9]",
            Charset::AlnumUs => "[A-Za-z0-9_]",
            Charset::AlnumDash => "[A-Za-z0-9-]",
            Charset::B64url => "[A-Za-z0-9_-]",
            Charset::B64urlDot => "[A-Za-z0-9_.-]",
        }
    }

    pub fn from_manifest_name(name: &str) -> Option<Charset> {
        Charset::ALL.into_iter().find(|c| c.manifest_name() == name)
    }
}

/// One `.`-separated segment of a credential format body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    pub charset: Charset,
    pub min: u32,
    /// When true the segment must be exactly `min` characters long.
    pub exact: bool,
}

/// A documented, prefix-identifiable credential format (SR-007).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Format {
    pub id: String,
    pub provider: String,
    pub prefixes: Vec<String>,
    pub segments: Vec<Segment>,
    pub source: String,
}

/// Detector-specific data. Fields not used by a rule's detector stay empty.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuleData {
    pub single_aliases: Vec<String>,
    pub pair_aliases: Vec<(String, String)>,
    pub skip_values: Vec<String>,
    pub headers: Vec<String>,
    /// SR-002: recognized authentication scheme names (lower case).
    pub schemes: Vec<String>,
    pub posix_prefixes: Vec<String>,
    pub windows_directory: String,
    /// `(network, prefix length)`
    pub ipv4: Vec<(u32, u8)>,
    /// `(network, prefix length)`
    pub ipv6: Vec<(u128, u8)>,
    pub formats: Vec<Format>,
    pub label_suffixes: Vec<String>,
    pub max_label_prefix: u32,
    pub request_headers: Vec<String>,
    pub response_headers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub detector: Detector,
    pub default_enabled: bool,
    pub optional: bool,
    pub placeholder: String,
    pub description: String,
    pub examples: Vec<(String, String)>,
    pub non_examples: Vec<String>,
    pub limitations: Vec<String>,
    pub data: RuleData,
}

/// A validated manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Compiled {
    pub schema_version: u32,
    pub rule_version: String,
    /// Lower-case hex SHA-256 of the manifest's exact bytes.
    pub sha256_hex: String,
    pub placeholders: Vec<String>,
    pub precedence: Vec<String>,
    /// Rules in ascending ID order; a rule's position is its `RuleId` in the core crate.
    pub rules: Vec<Rule>,
}

impl Compiled {
    pub fn rule(&self, detector: Detector) -> &Rule {
        // Validation guarantees exactly one rule per detector.
        self.rules
            .iter()
            .find(|r| r.detector == detector)
            .unwrap_or_else(|| unreachable!("validated manifest lacks {detector:?}"))
    }
}

/// Why a manifest was rejected. A malformed manifest always fails the build (TRD §8.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    Json(String),
    UnsupportedSchemaVersion(u64),
    InvalidRuleVersion(String),
    MissingField(String),
    InvalidField(String),
    InvalidId(String),
    DuplicateId(String),
    IdsNotAscending,
    UnknownDetector(String),
    DuplicateDetector(String),
    MissingDetector(String),
    InvalidPlaceholder(String),
    PlaceholderNotReserved(String),
    OptionalMismatch(String),
    PrecedenceMismatch,
    InvalidAlias(String),
    InvalidHeader(String),
    InvalidCidr(String),
    FormatWithoutSource(String),
    InvalidFormat(String),
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ManifestError::Json(e) => write!(f, "manifest is not valid JSON: {e}"),
            ManifestError::UnsupportedSchemaVersion(v) => {
                write!(f, "unsupported schemaVersion {v}")
            }
            ManifestError::InvalidRuleVersion(v) => write!(f, "ruleVersion {v:?} is not x.y.z"),
            ManifestError::MissingField(p) => write!(f, "missing field {p}"),
            ManifestError::InvalidField(p) => write!(f, "invalid field {p}"),
            ManifestError::InvalidId(id) => write!(f, "rule id {id:?} is not SR-NNN"),
            ManifestError::DuplicateId(id) => write!(f, "duplicate rule id {id}"),
            ManifestError::IdsNotAscending => write!(f, "rules must be sorted by ascending id"),
            ManifestError::UnknownDetector(d) => write!(f, "unknown detector {d:?}"),
            ManifestError::DuplicateDetector(d) => write!(f, "detector {d:?} is used by two rules"),
            ManifestError::MissingDetector(d) => write!(f, "no rule uses detector {d:?}"),
            ManifestError::InvalidPlaceholder(p) => write!(f, "invalid placeholder {p:?}"),
            ManifestError::PlaceholderNotReserved(p) => {
                write!(f, "placeholder {p:?} is not in the reserved set")
            }
            ManifestError::OptionalMismatch(id) => write!(
                f,
                "rule {id}: only the email and private-ip detectors may be optional, and both must be"
            ),
            ManifestError::PrecedenceMismatch => {
                write!(f, "precedence must list every rule id exactly once")
            }
            ManifestError::InvalidAlias(a) => write!(f, "alias {a:?} must match [a-z0-9]+"),
            ManifestError::InvalidHeader(h) => write!(f, "header name {h:?} must match [a-z-]+"),
            ManifestError::InvalidCidr(c) => write!(f, "invalid or unaligned CIDR {c:?}"),
            ManifestError::FormatWithoutSource(id) => {
                write!(f, "credential format {id} has no vendor source")
            }
            ManifestError::InvalidFormat(m) => write!(f, "invalid credential format: {m}"),
        }
    }
}

impl std::error::Error for ManifestError {}

/// Validates the manifest and hashes its exact bytes.
pub fn compile(manifest: &[u8]) -> Result<Compiled, ManifestError> {
    validate::compile(manifest)
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for b in digest {
        let _ = write!(out, "{b:02x}");
    }
    out
}
