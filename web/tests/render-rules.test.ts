import { describe, expect, it } from 'vitest';

import rulesDoc from '../src/generated/rules.json';
import { escapeHtml, renderRules, type RulesDoc } from '../scripts/render-rules';

describe('build-time rules section', () => {
  it('renders every rule from the generated manifest data', () => {
    const html = renderRules(rulesDoc);
    for (const rule of rulesDoc.rules) {
      expect(html).toContain(`id="rule-${rule.id}"`);
      expect(html).toContain(escapeHtml(rule.name));
    }
    expect(html).toContain(rulesDoc.sha256);
  });

  it('escapes manifest text', () => {
    const doc: RulesDoc = {
      ruleVersion: '1.0.0',
      sha256: 'a'.repeat(64),
      placeholders: [],
      precedence: ['SR-001'],
      rules: [
        {
          id: 'SR-001',
          name: '<script>x</script>',
          description: '"quoted" & \'single\'',
          placeholder: '[REDACTED]',
          optional: false,
          defaultEnabled: true,
          examples: [{ input: '<b>', output: '<i>' }],
          nonExamples: [],
          limitations: [],
        },
      ],
    };
    const html = renderRules(doc);
    expect(html).not.toContain('<script>');
    expect(html).not.toContain('<b>');
    expect(html).toContain('&lt;script&gt;x&lt;/script&gt;');
    expect(html).toContain('&quot;quoted&quot; &amp; &#39;single&#39;');
  });
});
