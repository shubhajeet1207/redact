// Output rendering (TRD §10.2, §10.6). Input-derived text enters the DOM only as text nodes;
// placeholders become <mark> elements and hidden characters become badges. Copy never reads
// this rendering: it copies the sanitized string itself.
import { badgeText, hiddenKind } from './hidden';

/** Highlighted placeholders and badges, combined, before falling back to plain text. */
export const HIGHLIGHT_CAP = 10_000;

export interface RenderOptions {
  badges: boolean;
  ruleIds: readonly string[];
  ruleNames: Readonly<Record<string, string>>;
  cap?: number;
}

export interface RenderInfo {
  /** False when the cap was exceeded and plain text was shown. */
  highlighted: boolean;
  /** Hidden characters (including lone CRs) in the text. */
  hidden: number;
}

/** Splits `text` into text nodes and badges, appending to `parent`. Returns badges added. */
function appendText(parent: Node, text: string, badges: boolean, budget: { left: number }): number {
  if (!badges) {
    if (text) parent.appendChild(document.createTextNode(text));
    return 0;
  }
  let added = 0;
  let start = 0;
  let i = 0;
  while (i < text.length) {
    const cp = text.codePointAt(i) ?? 0;
    const width = cp > 0xffff ? 2 : 1;
    const loneCr = cp === 0x0d && text.charCodeAt(i + 1) !== 0x0a;
    if (loneCr || (cp !== 0x0a && cp !== 0x0d && hiddenKind(cp) !== null)) {
      if (i > start) parent.appendChild(document.createTextNode(text.slice(start, i)));
      const badge = document.createElement('span');
      badge.className = 'badge';
      badge.textContent = badgeText(cp);
      parent.appendChild(badge);
      added++;
      budget.left--;
      start = i + width;
    }
    i += width;
  }
  if (start < text.length) parent.appendChild(document.createTextNode(text.slice(start)));
  return added;
}

/** Counts hidden characters the badge renderer would mark. */
export function countHidden(text: string): number {
  let n = 0;
  for (let i = 0; i < text.length; i++) {
    const cp = text.codePointAt(i) ?? 0;
    if (cp > 0xffff) i++;
    const loneCr = cp === 0x0d && text.charCodeAt(i + 1) !== 0x0a;
    if (loneCr || (cp !== 0x0a && cp !== 0x0d && hiddenKind(cp) !== null)) n++;
  }
  return n;
}

/**
 * Replaces the contents of `target` with `text`, highlighting the `[start, end, ruleIndex]`
 * UTF-16 ranges. Above the cap, shows plain text instead.
 */
export function renderOutput(target: HTMLElement, text: string, ranges: Uint32Array, options: RenderOptions): RenderInfo {
  const cap = options.cap ?? HIGHLIGHT_CAP;
  const hidden = countHidden(text);
  const elements = ranges.length / 3 + (options.badges ? hidden : 0);
  const fragment = document.createDocumentFragment();
  if (elements > cap) {
    fragment.appendChild(document.createTextNode(text));
    target.replaceChildren(fragment);
    return { highlighted: false, hidden };
  }
  const budget = { left: cap };
  let pos = 0;
  for (let i = 0; i < ranges.length; i += 3) {
    const start = ranges[i] ?? 0;
    const end = ranges[i + 1] ?? 0;
    const ruleId = options.ruleIds[ranges[i + 2] ?? 0] ?? '';
    appendText(fragment, text.slice(pos, start), options.badges, budget);
    const mark = document.createElement('mark');
    mark.className = 'ph';
    mark.dataset['rule'] = ruleId;
    const name = options.ruleNames[ruleId];
    mark.title = name ? `${ruleId}: ${name}` : ruleId;
    mark.textContent = text.slice(start, end);
    fragment.appendChild(mark);
    pos = end;
  }
  appendText(fragment, text.slice(pos), options.badges, budget);
  target.replaceChildren(fragment);
  return { highlighted: true, hidden };
}
