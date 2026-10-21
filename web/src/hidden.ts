// Hidden-character classification for the output panel (TRD §9.5, §10.2). It mirrors the
// engine's census table; tests/hidden-parity.test.ts checks every code point against the
// WebAssembly export so the page and the CLI mark the same characters.

export type HiddenKind = 'bidi' | 'invisible' | 'control';

const INVISIBLE_SINGLES = new Set([0xad, 0x34f, 0x115f, 0x1160, 0x17b4, 0x17b5, 0x180e, 0x3164, 0xfeff, 0xffa0]);

export function hiddenKind(cp: number): HiddenKind | null {
  if (cp === 0x09) return null;
  if (cp <= 0x1f || (cp >= 0x7f && cp <= 0x9f)) return 'control';
  if (
    cp === 0x61c ||
    cp === 0x200e ||
    cp === 0x200f ||
    (cp >= 0x202a && cp <= 0x202e) ||
    (cp >= 0x2066 && cp <= 0x2069)
  ) {
    return 'bidi';
  }
  if (
    INVISIBLE_SINGLES.has(cp) ||
    (cp >= 0x200b && cp <= 0x200d) ||
    (cp >= 0x2060 && cp <= 0x2064) ||
    (cp >= 0xe0000 && cp <= 0xe007f)
  ) {
    return 'invisible';
  }
  return null;
}

/** The visible badge for a hidden character, e.g. `⟨U+202E⟩`. */
export function badgeText(cp: number): string {
  if (cp === 0x0d) return '⟨CR⟩';
  return `⟨U+${cp.toString(16).toUpperCase().padStart(4, '0')}⟩`;
}
