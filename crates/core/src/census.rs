//! Hidden-character census (TRD §5.2, §9.5). Counts characters that can make text look different
//! from what is copied or shared. The census never changes bytes; renderers in the CLI and
//! browser use [`hidden_kind`] so every surface classifies the same set.

use crate::model::HiddenCensus;

/// Category of a character that can hide content from a human reviewer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HiddenKind {
    /// Bidirectional controls that reorder displayed text (Trojan Source, CVE-2021-42574).
    Bidi,
    /// Zero-width and invisible characters, including Unicode tag characters.
    Invisible,
    /// C0 controls other than TAB, DEL, and C1 controls (terminal escape sequences, CWE-150).
    Control,
}

/// Classifies `c`. Line separators (LF, CR) never reach this function: the framer removes them.
pub fn hidden_kind(c: char) -> Option<HiddenKind> {
    match c {
        '\t' => None,
        '\u{0}'..='\u{1F}' | '\u{7F}'..='\u{9F}' => Some(HiddenKind::Control),
        '\u{61C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' => {
            Some(HiddenKind::Bidi)
        }
        '\u{AD}'
        | '\u{34F}'
        | '\u{115F}'
        | '\u{1160}'
        | '\u{17B4}'
        | '\u{17B5}'
        | '\u{180E}'
        | '\u{200B}'..='\u{200D}'
        | '\u{2060}'..='\u{2064}'
        | '\u{3164}'
        | '\u{FEFF}'
        | '\u{FFA0}'
        | '\u{E0000}'..='\u{E007F}' => Some(HiddenKind::Invisible),
        _ => None,
    }
}

/// Adds the hidden characters in `s` to `census`.
pub fn census(s: &str, census: &mut HiddenCensus) {
    // Fast path: printable ASCII and TAB contain nothing hidden.
    if s.bytes().all(|b| (0x20..0x7F).contains(&b) || b == b'\t') {
        return;
    }
    for c in s.chars() {
        let slot = match hidden_kind(c) {
            Some(HiddenKind::Bidi) => &mut census.bidi,
            Some(HiddenKind::Invisible) => &mut census.invisible,
            Some(HiddenKind::Control) => &mut census.control,
            None => continue,
        };
        *slot = slot.saturating_add(1);
    }
}
