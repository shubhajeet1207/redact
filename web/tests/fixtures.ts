import rulesDoc from '../src/generated/rules.json';
import type { Summary } from '../src/protocol';

export const SHA = rulesDoc.sha256;
export const RULE_IDS = rulesDoc.rules.map((r) => r.id);

/** A valid summary with `n` replacements attributed to SR-001. */
export function summary(n = 0, overrides: Partial<Summary> = {}): Summary {
  const byRule = Object.fromEntries(RULE_IDS.map((id) => [id, 0]));
  byRule['SR-001'] = n;
  return {
    replacements: n,
    byRule,
    lines: 1,
    bytesIn: 10,
    bytesOut: 10,
    encoding: 'utf-8',
    bom: false,
    invalidUtf8Replaced: 0,
    hidden: { bidi: 0, invisible: 0, control: 0, loneCr: 0 },
    warnings: [],
    rulesVersion: rulesDoc.ruleVersion,
    rulesSha256: SHA,
    ...overrides,
  };
}
