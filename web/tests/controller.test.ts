import { beforeEach, describe, expect, it } from 'vitest';

import {
  DEBOUNCE_MS,
  PASTE_TIMEOUT_MS,
  PasteController,
  type PasteState,
} from '../src/controller';
import { PASTE_LIMIT_BYTES } from '../src/protocol';
import { FakeClock, FakeWorker } from './fakes';
import { RULE_IDS, SHA, summary } from './fixtures';

const READY = { type: 'ready', rulesVersion: '1.0.0', rulesSha256: SHA, toolVersion: '0.1.0', ruleIds: RULE_IDS };

function result(revision: number, output = 'a=[REDACTED]', n = 1): unknown {
  const ranges = n === 1 ? new Uint32Array([2, 12, 0]) : new Uint32Array();
  return { type: 'pasteResult', revision, output, summary: summary(n), ranges };
}

let clock: FakeClock;
let workers: FakeWorker[];
let states: PasteState[];
let clipboard: string[];
let controller: PasteController;

const worker = (): FakeWorker => {
  const w = workers.at(-1);
  if (!w) throw new Error('no worker');
  return w;
};
const state = (): PasteState => {
  const s = states.at(-1);
  if (!s) throw new Error('no state');
  return s;
};

beforeEach(() => {
  clock = new FakeClock();
  workers = [];
  states = [];
  clipboard = [];
  controller = new PasteController({
    createWorker: () => {
      const w = new FakeWorker();
      workers.push(w);
      return w;
    },
    clock,
    expectedRulesSha256: SHA,
    ruleCount: RULE_IDS.length,
    writeClipboard: (text) => {
      clipboard.push(text);
      return Promise.resolve();
    },
    onChange: (s) => states.push(s),
  });
  controller.start();
});

function startReady(): void {
  worker().reply(READY);
}

describe('PasteController', () => {
  it('keeps input disabled until the worker is ready', () => {
    expect(worker().sent).toEqual([{ type: 'init' }]);
    expect(state()).toMatchObject({ status: 'initializing', inputEnabled: false });
    startReady();
    expect(state()).toMatchObject({ status: 'empty', inputEnabled: true });
  });

  it('refuses a worker whose rule-set hash differs from the page', () => {
    worker().reply({ ...READY, rulesSha256: 'f'.repeat(64) });
    expect(state()).toMatchObject({ status: 'unavailable', error: 'RULES_MISMATCH', inputEnabled: false });
    expect(worker().terminated).toBe(true);
  });

  it('debounces dispatch by 150 ms', () => {
    startReady();
    controller.setText('a=1');
    controller.setText('a=12');
    clock.advance(DEBOUNCE_MS - 1);
    expect(worker().pastes()).toHaveLength(0);
    clock.advance(1);
    expect(worker().pastes()).toEqual([
      { type: 'paste', revision: 2, text: 'a=12', options: { email: true, privateIp: false } },
    ]);
  });

  it('accepts only the result for the current revision and enables Copy', () => {
    startReady();
    controller.setText('a=1');
    clock.advance(DEBOUNCE_MS);
    worker().reply(result(1));
    expect(state()).toMatchObject({ status: 'ready', canCopy: true });
    expect(state().result?.output).toBe('a=[REDACTED]');
  });

  it('clears the accepted result synchronously on every edit', () => {
    startReady();
    controller.setText('a=1');
    clock.advance(DEBOUNCE_MS);
    worker().reply(result(1));
    controller.setText('a=12');
    expect(state()).toMatchObject({ status: 'pending', canCopy: false, result: null });
  });

  it('keeps one request in flight and replaces the pending one', () => {
    startReady();
    controller.setText('one');
    clock.advance(DEBOUNCE_MS);
    controller.setText('two');
    clock.advance(DEBOUNCE_MS);
    controller.setText('three');
    clock.advance(DEBOUNCE_MS);
    expect(worker().pastes().map((p) => p.text)).toEqual(['one']);
    // The stale result is dropped, then only the newest pending request is sent.
    worker().reply(result(1, 'one', 0));
    expect(state().result).toBeNull();
    expect(worker().pastes().map((p) => p.text)).toEqual(['one', 'three']);
    worker().reply(result(3, 'three', 0));
    expect(state()).toMatchObject({ status: 'ready' });
    expect(state().result?.output).toBe('three');
  });

  it('rejects a result computed with options that are no longer current', () => {
    startReady();
    controller.setText('a=1');
    clock.advance(DEBOUNCE_MS);
    controller.setOptions({ email: false, privateIp: false });
    worker().reply(result(1));
    expect(state().result).toBeNull();
  });

  it('ignores malformed worker messages', () => {
    startReady();
    controller.setText('a=1');
    clock.advance(DEBOUNCE_MS);
    worker().reply({ type: 'pasteResult', revision: 1, output: 'a=[REDACTED]', summary: { replacements: 1 }, ranges: new Uint32Array([2, 12, 0]) });
    expect(state()).toMatchObject({ status: 'pending', result: null });
  });

  it('reports engine errors for the current revision', () => {
    startReady();
    controller.setText('a\u0000');
    clock.advance(DEBOUNCE_MS);
    worker().reply({ type: 'error', revision: 1, code: 'NUL_BYTE', line: 1 });
    expect(state()).toMatchObject({ status: 'error', error: 'NUL_BYTE', errorLine: 1 });
  });

  it('rejects input over 1 MiB of UTF-8 without sending it', () => {
    startReady();
    controller.setText('é'.repeat(PASTE_LIMIT_BYTES / 2 + 1));
    clock.advance(DEBOUNCE_MS);
    expect(worker().pastes()).toHaveLength(0);
    expect(state()).toMatchObject({ status: 'error', error: 'INPUT_TOO_LARGE' });
  });

  it('accepts input of exactly 1 MiB', () => {
    startReady();
    controller.setText('a'.repeat(PASTE_LIMIT_BYTES));
    clock.advance(DEBOUNCE_MS);
    expect(worker().pastes()).toHaveLength(1);
  });

  it('restarts a stuck worker once without resending input, then gives up', () => {
    startReady();
    controller.setText('a=1');
    clock.advance(DEBOUNCE_MS);
    clock.advance(PASTE_TIMEOUT_MS);
    const first = workers[0];
    expect(first?.terminated).toBe(true);
    expect(workers).toHaveLength(2);
    expect(state()).toMatchObject({ status: 'error', error: 'TIMEOUT', result: null });
    worker().reply(READY);
    expect(worker().pastes()).toHaveLength(0);
    // A new edit dispatches to the fresh worker; a second consecutive timeout is final.
    controller.setText('a=2');
    clock.advance(DEBOUNCE_MS);
    expect(worker().pastes()).toHaveLength(1);
    clock.advance(PASTE_TIMEOUT_MS);
    expect(state()).toMatchObject({ status: 'unavailable', inputEnabled: false });
    expect(workers).toHaveLength(2);
  });

  it('a success resets the failure count', () => {
    startReady();
    controller.setText('a=1');
    clock.advance(DEBOUNCE_MS + PASTE_TIMEOUT_MS);
    worker().reply(READY);
    controller.setText('a=2');
    clock.advance(DEBOUNCE_MS);
    worker().reply(result(2));
    controller.setText('a=3');
    clock.advance(DEBOUNCE_MS + PASTE_TIMEOUT_MS);
    expect(state()).toMatchObject({ status: 'error', error: 'TIMEOUT' });
  });

  it('copies the validated snapshot and never reports a newer revision as copied', async () => {
    startReady();
    controller.setText('a=1');
    clock.advance(DEBOUNCE_MS);
    worker().reply(result(1));
    expect(await controller.copy()).toBe('copied');
    expect(clipboard).toEqual(['a=[REDACTED]']);

    const copying = controller.copy();
    controller.setText('a=12');
    expect(await copying).toBe('superseded');
    expect(await controller.copy()).toBe('nothing');
  });

  it('Clear restores the default options and an empty state', () => {
    startReady();
    controller.setOptions({ email: false, privateIp: true });
    controller.setText('a=1');
    controller.clear();
    expect(state()).toMatchObject({ status: 'empty', options: { email: true, privateIp: false }, result: null });
    clock.advance(DEBOUNCE_MS);
    expect(worker().pastes()).toHaveLength(0);
  });
});
