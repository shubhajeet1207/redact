import { describe, expect, it } from 'vitest';

import { isRanges, parsePageMessage, parseWorkerMessage } from '../src/protocol';
import { RULE_IDS, SHA, summary } from './fixtures';

const N = RULE_IDS.length;

describe('page → worker messages', () => {
  it('accepts exact shapes', () => {
    expect(parsePageMessage({ type: 'init' })).toEqual({ type: 'init' });
    expect(
      parsePageMessage({ type: 'paste', revision: 3, text: 'x', options: { email: true, privateIp: false } }),
    ).toEqual({ type: 'paste', revision: 3, text: 'x', options: { email: true, privateIp: false } });
    expect(parsePageMessage({ type: 'cancel', job: 1 })).toEqual({ type: 'cancel', job: 1 });
  });

  it.each([
    null,
    'paste',
    [],
    { type: 'unknown' },
    { type: 'init', extra: 1 },
    { type: 'paste', revision: 0, text: 'x', options: { email: true, privateIp: false } },
    { type: 'paste', revision: 1.5, text: 'x', options: { email: true, privateIp: false } },
    { type: 'paste', revision: 1, text: 5, options: { email: true, privateIp: false } },
    { type: 'paste', revision: 1, text: 'x', options: { email: 'yes', privateIp: false } },
    { type: 'paste', revision: 1, text: 'x', options: { email: true, privateIp: false, extra: true } },
    { type: 'cancel', job: -1 },
    { type: 'fileStart', job: 1, file: 'not a file', options: { email: true, privateIp: false }, maxLineBytes: 1024, sink: 'blob' },
  ])('drops malformed %j', (message) => {
    expect(parsePageMessage(message)).toBeNull();
  });

  it('bounds the line limit and requires a handle only for the handle sink', () => {
    const file = new File(['x'], 'a.log');
    const base = { type: 'fileStart', job: 1, file, options: { email: true, privateIp: false }, sink: 'blob' };
    expect(parsePageMessage({ ...base, maxLineBytes: 1024 })).not.toBeNull();
    expect(parsePageMessage({ ...base, maxLineBytes: 1023 })).toBeNull();
    expect(parsePageMessage({ ...base, maxLineBytes: 67_108_865 })).toBeNull();
    expect(parsePageMessage({ ...base, maxLineBytes: 1024, sink: 'handle' })).toBeNull();
    expect(parsePageMessage({ ...base, maxLineBytes: 1024, handle: {} })).toBeNull();
  });
});

describe('worker → page messages', () => {
  const ready = { type: 'ready', rulesVersion: '1.0.0', rulesSha256: SHA, toolVersion: '0.1.0', ruleIds: RULE_IDS };

  it('accepts a valid ready and paste result', () => {
    expect(parseWorkerMessage(ready, N)).toEqual(ready);
    const result = {
      type: 'pasteResult',
      revision: 2,
      output: 'a=[REDACTED]',
      summary: summary(1),
      ranges: new Uint32Array([2, 12, 0]),
    };
    expect(parseWorkerMessage(result, N)).toEqual(result);
  });

  it('rejects a summary whose per-rule counts do not add up (P-6)', () => {
    const bad = summary(1);
    bad.byRule['SR-002'] = 1;
    const msg = { type: 'pasteResult', revision: 1, output: 'x'.repeat(20), summary: bad, ranges: new Uint32Array([0, 10, 0]) };
    expect(parseWorkerMessage(msg, N)).toBeNull();
  });

  it('rejects ranges that disagree with the count or the output', () => {
    const base = { type: 'pasteResult', revision: 1, output: 'a=[REDACTED]', summary: summary(1) };
    expect(parseWorkerMessage({ ...base, ranges: new Uint32Array([]) }, N)).toBeNull();
    expect(parseWorkerMessage({ ...base, ranges: new Uint32Array([2, 99, 0]) }, N)).toBeNull();
    expect(parseWorkerMessage({ ...base, ranges: [2, 12, 0] }, N)).toBeNull();
  });

  it.each([
    { ...{ type: 'ready', rulesVersion: '1.0.0', rulesSha256: 'nothex', toolVersion: '0.1.0', ruleIds: [] } },
    { type: 'error', code: 'SOMETHING_ELSE' },
    { type: 'error', code: 'NUL_BYTE', line: 0 },
    { type: 'fileProgress', job: 1, bytesDone: 5, bytesTotal: 4 },
    { type: 'pasteResult', revision: 1, output: '', summary: { ...summary(0), extra: 1 }, ranges: new Uint32Array() },
  ])('drops malformed %j', (message) => {
    expect(parseWorkerMessage(message, N)).toBeNull();
  });

  it('checks range order, disjointness, and rule index', () => {
    expect(isRanges(new Uint32Array([0, 2, 0, 2, 4, 1]), 4, N)).toBe(true);
    expect(isRanges(new Uint32Array([0, 3, 0, 2, 4, 1]), 4, N)).toBe(false);
    expect(isRanges(new Uint32Array([0, 0, 0]), 4, N)).toBe(false);
    expect(isRanges(new Uint32Array([0, 2, N]), 4, N)).toBe(false);
  });
});
