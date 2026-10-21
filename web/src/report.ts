// The per-job report (TRD §10.2): per-rule counts, lines, active options, rule set, encoding,
// and hidden-character counts. Built with createElement and textContent only.
import type { Options, Summary } from './protocol';
import { S, formatBytes } from './strings';

export interface RuleLabel {
  id: string;
  name: string;
}

function el<K extends keyof HTMLElementTagNameMap>(tag: K, text?: string): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  return node;
}

export function renderReport(target: HTMLElement, summary: Summary, rules: readonly RuleLabel[], options: Options): void {
  const table = el('table');
  const head = el('thead');
  const headRow = el('tr');
  for (const label of ['Rule', 'Name', 'Replacements']) {
    const th = el('th', label);
    th.scope = 'col';
    headRow.appendChild(th);
  }
  head.appendChild(headRow);
  const body = el('tbody');
  for (const rule of rules) {
    const row = el('tr');
    row.appendChild(el('td', rule.id));
    row.appendChild(el('td', rule.name));
    const count = el('td', String(summary.byRule[rule.id] ?? 0));
    count.className = 'num';
    row.appendChild(count);
    body.appendChild(row);
  }
  table.append(head, body);

  const meta = el('dl');
  meta.className = 'meta';
  const add = (term: string, value: string): void => {
    meta.append(el('dt', term), el('dd', value));
  };
  add('Total', String(summary.replacements));
  add('Lines', summary.lines.toLocaleString('en'));
  add('Options', S.options(options.email, options.privateIp));
  add('Encoding', `${summary.encoding}${summary.bom ? ' with byte-order mark' : ''}`);
  add('Size', `${formatBytes(summary.bytesIn)} in, ${formatBytes(summary.bytesOut)} out`);
  const h = summary.hidden;
  add('Hidden characters', `bidi ${h.bidi}, invisible ${h.invisible}, control ${h.control}, lone CR ${h.loneCr}`);
  add('Rule set', `${summary.rulesVersion} (${summary.rulesSha256})`);
  target.replaceChildren(table, meta);
}

/** One message per warning, in engine order. */
export function warningTexts(summary: Summary): string[] {
  return summary.warnings.map((w) =>
    w.code === 'UNSTABLE_LINE_REDACTED'
      ? S.warnings.UNSTABLE_LINE_REDACTED(w.line, w.lines ?? 1)
      : S.warnings.UNTERMINATED_PRIVATE_KEY_BLOCK(w.line),
  );
}

export function hiddenTotal(summary: Summary): number {
  const h = summary.hidden;
  return h.bidi + h.invisible + h.control + h.loneCr;
}
