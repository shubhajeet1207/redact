//! The compiled rule set (TRD §8). Tables are generated at build time from
//! `rules/rules.v1.json`; nothing is loaded at run time.

use crate::model::RuleId;

/// Detector type of a rule (closed enumeration, TRD §8.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectorKind {
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

/// Character classes for credential-format bodies (TRD §6.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Charset {
    Alnum,
    AlnumUpper,
    AlnumUs,
    AlnumDash,
    B64url,
    B64urlDot,
}

impl Charset {
    #[inline]
    pub fn contains(self, b: u8) -> bool {
        match self {
            Charset::Alnum => b.is_ascii_alphanumeric(),
            Charset::AlnumUpper => b.is_ascii_uppercase() || b.is_ascii_digit(),
            Charset::AlnumUs => b.is_ascii_alphanumeric() || b == b'_',
            Charset::AlnumDash => b.is_ascii_alphanumeric() || b == b'-',
            Charset::B64url => b.is_ascii_alphanumeric() || b == b'_' || b == b'-',
            Charset::B64urlDot => b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.',
        }
    }
}

/// One `.`-separated segment of a credential-format body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    pub charset: Charset,
    pub min: u32,
    pub exact: bool,
}

/// A documented, prefix-identifiable credential format (SR-007).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenFormat {
    pub id: &'static str,
    pub provider: &'static str,
    pub prefixes: &'static [&'static str],
    pub segments: &'static [Segment],
}

#[allow(clippy::all, clippy::pedantic)]
mod generated {
    use super::{Charset, DetectorKind, Segment, TokenFormat};
    include!(concat!(env!("OUT_DIR"), "/rules_generated.rs"));
}
pub use generated::*;

/// The rule's catalog ID, such as `SR-001`.
pub fn rule_id_str(rule: RuleId) -> &'static str {
    RULE_IDS
        .get(usize::from(rule.0))
        .copied()
        .unwrap_or("SR-???")
}

/// The rule's human-readable name.
pub fn rule_name(rule: RuleId) -> &'static str {
    RULE_NAMES.get(usize::from(rule.0)).copied().unwrap_or("")
}

/// The reserved placeholder this rule inserts.
pub fn placeholder(rule: RuleId) -> &'static str {
    RULE_PLACEHOLDER
        .get(usize::from(rule.0))
        .copied()
        .unwrap_or("[REDACTED]")
}

/// Precedence rank: 0 is the highest (TRD §7.1).
pub fn rank(rule: RuleId) -> u8 {
    PRECEDENCE_RANK
        .get(usize::from(rule.0))
        .copied()
        .unwrap_or(u8::MAX)
}

/// True when `s` is exactly one of the reserved placeholders.
pub fn is_placeholder(s: &[u8]) -> bool {
    PLACEHOLDERS.iter().any(|p| p.as_bytes() == s)
}

/// True when `s` consists only of one or more reserved placeholders, optionally separated by
/// ASCII whitespace. Such text is already redacted: adjacent placeholders produced by one run
/// must not be redacted again by the next (invariant P-4).
pub fn is_placeholder_sequence(s: &[u8]) -> bool {
    let mut rest = s.trim_ascii_start();
    let mut seen = false;
    while !rest.is_empty() {
        let Some(p) = PLACEHOLDERS.iter().find(|p| rest.starts_with(p.as_bytes())) else {
            return false;
        };
        rest = rest.get(p.len()..).unwrap_or_default().trim_ascii_start();
        seen = true;
    }
    seen
}

/// Rule index for a detector type.
pub(crate) const fn rule_for(kind: DetectorKind) -> RuleId {
    let idx = match kind {
        DetectorKind::NamedValue => IDX_NAMED_VALUE,
        DetectorKind::Authorization => IDX_AUTHORIZATION,
        DetectorKind::UrlCredential => IDX_URL_CREDENTIAL,
        DetectorKind::HomePath => IDX_HOME_PATH,
        DetectorKind::Email => IDX_EMAIL,
        DetectorKind::PrivateIp => IDX_PRIVATE_IP,
        DetectorKind::TokenFormat => IDX_TOKEN_FORMAT,
        DetectorKind::PemBlock => IDX_PEM_BLOCK,
        DetectorKind::Cookie => IDX_COOKIE,
    };
    // The manifest has exactly nine rules, so every index fits in u8.
    #[allow(clippy::cast_possible_truncation)]
    RuleId(idx as u8)
}
