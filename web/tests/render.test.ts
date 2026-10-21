// @vitest-environment jsdom
import { describe, expect, it } from 'vitest';

import { countHidden, renderOutput } from '../src/render';
import { RULE_IDS } from './fixtures';

const options = { badges: true, ruleIds: RULE_IDS, ruleNames: { 'SR-001': 'Named secret values' } };

function target(): HTMLElement {
  return document.createElement('div');
}

describe('renderOutput', () => {
  it('wraps exactly the placeholder ranges in marks', () => {
    const el = target();
    const text = 'a=[REDACTED] b=[REDACTED]';
    const info = renderOutput(el, text, new Uint32Array([2, 12, 0, 15, 25, 0]), options);
    expect(info.highlighted).toBe(true);
    const marks = [...el.querySelectorAll('mark.ph')];
    expect(marks.map((m) => m.textContent)).toEqual(['[REDACTED]', '[REDACTED]']);
    expect(marks[0]?.getAttribute('data-rule')).toBe('SR-001');
    expect(marks[0]?.getAttribute('title')).toBe('SR-001: Named secret values');
    expect(el.textContent).toBe(text);
  });

  it('never interprets markup in the text', () => {
    const el = target();
    const text = '<img src=x onerror=alert(1)><b>bold</b>';
    renderOutput(el, text, new Uint32Array(), options);
    expect(el.children).toHaveLength(0);
    expect(el.textContent).toBe(text);
  });

  it('shows bidi controls, invisibles, controls, and lone CRs as badges', () => {
    const el = target();
    renderOutput(el, 'a‮b​c\u0007d\re\r\nf', new Uint32Array(), options);
    expect([...el.querySelectorAll('.badge')].map((b) => b.textContent)).toEqual([
      '⟨U+202E⟩',
      '⟨U+200B⟩',
      '⟨U+0007⟩',
      '⟨CR⟩',
    ]);
    // The badge replaces the character, so a bidi control cannot reorder the displayed text.
    expect(el.textContent).not.toContain('‮');
    expect(el.textContent).toContain('\r\nf');
  });

  it('keeps the raw text when badges are off', () => {
    const el = target();
    renderOutput(el, 'a‮b', new Uint32Array(), { ...options, badges: false });
    expect(el.querySelectorAll('.badge')).toHaveLength(0);
    expect(el.textContent).toBe('a‮b');
  });

  it('handles astral characters and tag characters as one code point', () => {
    const el = target();
    renderOutput(el, '🙂\u{E0041}x', new Uint32Array(), options);
    expect([...el.querySelectorAll('.badge')].map((b) => b.textContent)).toEqual(['⟨U+E0041⟩']);
    expect(el.textContent).toBe('🙂⟨U+E0041⟩x');
  });

  it('falls back to plain text above the cap', () => {
    const el = target();
    const info = renderOutput(el, 'a=[REDACTED]‮', new Uint32Array([2, 12, 0]), { ...options, cap: 1 });
    expect(info.highlighted).toBe(false);
    expect(el.children).toHaveLength(0);
    expect(el.textContent).toBe('a=[REDACTED]‮');
  });

  it('counts hidden characters like the badge renderer', () => {
    expect(countHidden('a‮b\r\nc\rd\u{E0041}')).toBe(3);
  });
});
