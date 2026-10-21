//! Detectors (TRD §6). Each detector scans one line with a monotonic cursor and pushes
//! candidate ranges against the original line; resolution happens afterwards (TRD §7).

use alloc::vec::Vec;

use memchr::memmem::Finder;

use crate::model::Options;
use crate::resolve::Candidate;
use crate::rules::{self, DetectorKind, rule_for};

mod assign;
mod email;
mod home;
mod ip;
pub(crate) mod pem;
mod token;
mod url;

pub(crate) use pem::PemState;

/// Substring searchers, built once per sanitizer instead of once per line.
#[derive(Debug)]
pub(crate) struct Finders {
    pub(crate) scheme: Finder<'static>,
    pub(crate) home: Vec<Finder<'static>>,
    pub(crate) pem_begin: Finder<'static>,
    pub(crate) pem_end: Finder<'static>,
}

impl Finders {
    fn new() -> Self {
        Self {
            scheme: Finder::new(b"://"),
            home: rules::HOME_POSIX_PREFIXES
                .iter()
                .map(|p| Finder::new(p.as_bytes()))
                .collect(),
            pem_begin: Finder::new(pem::BEGIN),
            pem_end: Finder::new(pem::END),
        }
    }
}

/// Per-sanitizer detector resources: the credential-prefix automaton and scratch buffers.
#[derive(Debug)]
pub(crate) struct Detectors {
    tokens: token::TokenMatcher,
    finders: Finders,
    spans: Vec<url::UrlSpan>,
    owned: Vec<(usize, usize)>,
    filtered: Vec<Candidate>,
}

impl Detectors {
    pub(crate) fn new() -> Option<Self> {
        Some(Self {
            tokens: token::TokenMatcher::new()?,
            finders: Finders::new(),
            spans: Vec::new(),
            owned: Vec::new(),
            filtered: Vec::new(),
        })
    }

    /// Collects every enabled detector's candidates for one line (TRD §7.1 steps 1–4).
    pub(crate) fn run_line(
        &mut self,
        line: &str,
        opts: &Options,
        pem: &mut PemState,
        line_no: u64,
        out: &mut Vec<Candidate>,
    ) {
        let b = line.as_bytes();
        // An open multi-line block owns every following line until its matching END armor. The
        // design deliberately skips all other detectors in that state (TRD §7.1, step 1).
        let was_in_private_key_block = pem.in_block;
        pem::step(&self.finders, b, pem, line_no, out, &mut self.owned);
        // First scan the regions that are definitely outside private-key armor. This lets a line
        // containing an END armor resume normal detection immediately after that armor.
        let mut pos = 0usize;
        for index in 0..self.owned.len() {
            let Some(&(start, end)) = self.owned.get(index) else {
                break;
            };
            self.run_region(b, pos, start, opts, out);
            pos = pos.max(end);
        }
        self.run_region(b, pos, b.len(), opts, out);

        if !was_in_private_key_block && !self.owned.is_empty() {
            // The one exception to region-only scanning is an SR-001 candidate which encloses a
            // complete, same-line PEM block. FX-29 requires it to overlap SR-008: their union
            // becomes one [REDACTED] result attributed to the higher-precedence PEM rule.
            let candidate_start = out.len();
            assign::detect(b, out);
            self.retain_candidates_crossing_owned(out, candidate_start);
        }
    }

    fn retain_candidates_crossing_owned(
        &mut self,
        out: &mut Vec<Candidate>,
        candidate_start: usize,
    ) {
        self.filtered.clear();
        for candidate in out.iter().skip(candidate_start).copied() {
            let crosses_complete_private_key = candidate.rule == rule_for(DetectorKind::NamedValue)
                && usize::try_from(candidate.start)
                    .ok()
                    .zip(usize::try_from(candidate.end).ok())
                    .is_some_and(|(start, end)| {
                        self.owned.iter().any(|&(owned_start, owned_end)| {
                            start <= owned_start && end > owned_end
                        })
                    });
            if crosses_complete_private_key {
                self.filtered.push(candidate);
            }
        }
        out.truncate(candidate_start);
        out.extend_from_slice(&self.filtered);
    }

    fn run_region(
        &mut self,
        b: &[u8],
        start: usize,
        end: usize,
        opts: &Options,
        out: &mut Vec<Candidate>,
    ) {
        let Some(region) = b.get(start..end).filter(|region| !region.is_empty()) else {
            return;
        };
        let mark = out.len();
        self.run_others(region, opts, out);
        if start > 0 {
            let shift = u32::try_from(start).unwrap_or(u32::MAX);
            for candidate in out.iter_mut().skip(mark) {
                candidate.start = candidate.start.saturating_add(shift);
                candidate.end = candidate.end.saturating_add(shift);
            }
        }
    }

    fn run_others(&mut self, b: &[u8], opts: &Options, out: &mut Vec<Candidate>) {
        url::spans(&self.finders, b, &mut self.spans);
        assign::detect(b, out);
        url::detect(&self.spans, rule_for(DetectorKind::UrlCredential), out);
        home::detect(
            &self.finders,
            b,
            &self.spans,
            rule_for(DetectorKind::HomePath),
            out,
        );
        if opts.email {
            email::detect(b, &self.spans, rule_for(DetectorKind::Email), out);
        }
        if opts.private_ip {
            ip::detect(b, rule_for(DetectorKind::PrivateIp), out);
        }
        token::detect(&self.tokens, b, rule_for(DetectorKind::TokenFormat), out);
    }
}
