// Renders the Rules section into index.html at build time from src/generated/rules.json, which
// gen-docs produces from the same manifest the engine is compiled from (TRD §10.1). All manifest
// text is escaped; this runs in Node at build time, never in the page.

export interface RuleDoc {
  id: string;
  name: string;
  description: string;
  placeholder: string;
  optional: boolean;
  defaultEnabled: boolean;
  examples: { input: string; output: string }[];
  nonExamples: string[];
  limitations: string[];
}

export interface RulesDoc {
  ruleVersion: string;
  sha256: string;
  placeholders: string[];
  precedence: string[];
  rules: RuleDoc[];
}

const ESCAPES: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};

export function escapeHtml(text: string): string {
  return text.replace(/[&<>"']/g, (c) => ESCAPES[c] ?? c);
}

export function enablement(rule: RuleDoc): string {
  if (!rule.optional) return 'Always on';
  return rule.defaultEnabled ? 'On by default' : 'Off by default';
}

function card(rule: RuleDoc): string {
  const e = escapeHtml;
  const examples = rule.examples
    .map((x) => `<tr><td><code>${e(x.input)}</code></td><td><code>${e(x.output)}</code></td></tr>`)
    .join('');
  const limits = rule.limitations.map((l) => `<li>${e(l)}</li>`).join('');
  const nonExamples = rule.nonExamples.map((n) => `<li><code>${e(n)}</code></li>`).join('');
  return [
    `<article class="rule" id="rule-${e(rule.id)}" aria-labelledby="rule-${e(rule.id)}-name">`,
    `<header class="rule__head"><span class="chip chip--id">${e(rule.id)}</span>`,
    `<h3 id="rule-${e(rule.id)}-name">${e(rule.name)}</h3>`,
    `<span class="chip chip--state">${e(enablement(rule))}</span></header>`,
    `<p>${e(rule.description)}</p>`,
    `<p class="rule__placeholder">Replaced with <code class="ph">${e(rule.placeholder)}</code></p>`,
    examples
      ? `<details><summary>Examples</summary><div class="table-scroll"><table><thead><tr><th scope="col">Input</th><th scope="col">Output</th></tr></thead><tbody>${examples}</tbody></table></div></details>`
      : '',
    nonExamples ? `<details><summary>Left unchanged</summary><ul class="plain">${nonExamples}</ul></details>` : '',
    limits ? `<details><summary>Limitations</summary><ul>${limits}</ul></details>` : '',
    '</article>',
  ].join('');
}

export function renderRules(doc: RulesDoc): string {
  const e = escapeHtml;
  return [
    `<p>Rule set <code>${e(doc.ruleVersion)}</code>, SHA-256 <code class="hash">${e(doc.sha256)}</code>. `,
    `When rules overlap, the higher one in this order wins: ${doc.precedence.map((p) => `<code>${e(p)}</code>`).join(' › ')}.</p>`,
    `<div class="rules-grid">${doc.rules.map(card).join('')}</div>`,
  ].join('');
}
