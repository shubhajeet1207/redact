// The worker logic with the real WebAssembly engine (built by `npm run wasm`).
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { beforeAll, describe, expect, it } from 'vitest';

import * as engine from '../wasm-pkg/engine.js';
import { parseWorkerMessage, type WorkerMessage } from '../src/protocol';
import { CHUNK_BYTES, WorkerCore } from '../src/worker-core';
import { RULE_IDS } from './fixtures';

/** Stand-ins for the File System Access types, which Node lacks. */
class FakeWritable {
  chunks: Uint8Array[] = [];
  closed = false;
  aborted = false;
  constructor(private readonly failOnWrite: boolean) {}
  write(chunk: Uint8Array): Promise<void> {
    if (this.failOnWrite) return Promise.reject(new Error('disk full'));
    this.chunks.push(chunk.slice());
    return Promise.resolve();
  }
  close(): Promise<void> {
    this.closed = true;
    return Promise.resolve();
  }
  abort(): Promise<void> {
    this.aborted = true;
    return Promise.resolve();
  }
}

class FakeHandle {
  writable: FakeWritable;
  constructor(failOnWrite = false) {
    this.writable = new FakeWritable(failOnWrite);
  }
  createWritable(): Promise<FakeWritable> {
    return Promise.resolve(this.writable);
  }
}

beforeAll(() => {
  engine.initSync({ module: readFileSync(fileURLToPath(new URL('../wasm-pkg/engine_bg.wasm', import.meta.url))) });
  (globalThis as Record<string, unknown>)['FileSystemFileHandle'] = FakeHandle;
});

function setup(): { core: WorkerCore; posted: WorkerMessage[] } {
  const posted: WorkerMessage[] = [];
  const core = new WorkerCore(engine, (m) => posted.push(m));
  return { core, posted };
}

/** Every message the worker sends passes the page's own validator. */
function validated(posted: WorkerMessage[]): WorkerMessage[] {
  for (const m of posted) expect(parseWorkerMessage(m, RULE_IDS.length), JSON.stringify(m.type)).not.toBeNull();
  return posted;
}

const OPTIONS = { email: true, privateIp: false };

describe('WorkerCore with the real engine', () => {
  it('reports the engine identity', async () => {
    const { core, posted } = setup();
    await core.handle({ type: 'init' });
    expect(validated(posted)[0]).toMatchObject({ type: 'ready', ruleIds: RULE_IDS });
  });

  it('sanitizes a paste and returns UTF-16 ranges', async () => {
    const { core, posted } = setup();
    await core.handle({ type: 'paste', revision: 7, text: '🙂 password=hunter2 a@example.com', options: OPTIONS });
    const [msg] = validated(posted);
    expect(msg).toMatchObject({ type: 'pasteResult', revision: 7, output: '🙂 password=[REDACTED] [EMAIL REDACTED]' });
    if (msg?.type !== 'pasteResult') throw new Error('unexpected');
    expect([...msg.ranges]).toEqual([12, 22, 0, 23, 39, 4]);
    expect(msg.output.slice(12, 22)).toBe('[REDACTED]');
  });

  it('reports engine errors with the line number', async () => {
    const { core, posted } = setup();
    await core.handle({ type: 'paste', revision: 1, text: 'ok\nbad\u0000', options: OPTIONS });
    expect(validated(posted)).toEqual([{ type: 'error', revision: 1, code: 'NUL_BYTE', line: 2 }]);
  });

  it('drops and counts malformed messages', async () => {
    const { core, posted } = setup();
    await core.handle({ type: 'paste', revision: 1, text: 'x' });
    await core.handle('init');
    expect(posted).toEqual([]);
    expect(core.dropped).toBe(2);
  });

  it('streams a file to a Blob in 1 MiB chunks with progress', async () => {
    const { core, posted } = setup();
    const line = 'token=fake-value-0001 ok\n';
    const text = line.repeat(Math.ceil((CHUNK_BYTES * 2.5) / line.length));
    const file = new File([text], 'big.log');
    await core.handle({ type: 'fileStart', job: 1, file, options: OPTIONS, maxLineBytes: 1_048_576, sink: 'blob' });
    const messages = validated(posted);
    expect(messages.filter((m) => m.type === 'fileProgress')).toHaveLength(3);
    const result = messages.at(-1);
    if (result?.type !== 'fileResult' || !result.blob) throw new Error('no result');
    const expected = text.replaceAll('fake-value-0001', '[REDACTED]');
    expect(await result.blob.text()).toBe(expected);
    expect(result.outputBytes).toBe(expected.length);
    expect(result.copyText).toBeUndefined();
    expect(result.preview).toBe(expected.slice(0, result.preview.length));
    expect(result.preview.length).toBeLessThanOrEqual(64 * 1024);
  });

  it('includes copy text only for outputs of at most 1 MiB', async () => {
    const { core, posted } = setup();
    const file = new File(['password=x\n'], 'a.log');
    await core.handle({ type: 'fileStart', job: 2, file, options: OPTIONS, maxLineBytes: 1_048_576, sink: 'blob' });
    expect(validated(posted).at(-1)).toMatchObject({ type: 'fileResult', copyText: 'password=[REDACTED]\n' });
  });

  it('writes through a file handle and closes it on success', async () => {
    const { core, posted } = setup();
    const handle = new FakeHandle();
    const file = new File(['password=x\n'], 'a.log');
    await core.handle({ type: 'fileStart', job: 3, file, options: OPTIONS, maxLineBytes: 1_048_576, sink: 'handle', handle });
    const result = validated(posted).at(-1);
    expect(result).toMatchObject({ type: 'fileResult', job: 3 });
    expect(result?.type === 'fileResult' ? result.blob : 'not a result').toBeUndefined();
    expect(handle.writable.closed).toBe(true);
    expect(new TextDecoder().decode(handle.writable.chunks[0])).toBe('password=[REDACTED]\n');
  });

  it('aborts the staged file when a write fails', async () => {
    const { core, posted } = setup();
    const handle = new FakeHandle(true);
    const file = new File(['password=x\n'], 'a.log');
    await core.handle({ type: 'fileStart', job: 4, file, options: OPTIONS, maxLineBytes: 1_048_576, sink: 'handle', handle });
    expect(handle.writable.aborted).toBe(true);
    expect(handle.writable.closed).toBe(false);
    expect(validated(posted).at(-1)).toMatchObject({ type: 'error', job: 4 });
  });

  it('cancels between chunks', async () => {
    const { core, posted } = setup();
    const file = new File(['a'.repeat(CHUNK_BYTES * 3)].map((s) => s.replace(/a{1024}/g, (m) => `${m.slice(1)}\n`)), 'c.log');
    const running = core.handle({ type: 'fileStart', job: 5, file, options: OPTIONS, maxLineBytes: 1_048_576, sink: 'blob' });
    await core.handle({ type: 'cancel', job: 5 });
    await running;
    expect(validated(posted).at(-1)).toEqual({ type: 'error', job: 5, code: 'CANCELLED' });
  });

  it('reports a line that is too long, with its number', async () => {
    const { core, posted } = setup();
    const file = new File([`ok\n${'z'.repeat(2048)}\n`], 'long.log');
    await core.handle({ type: 'fileStart', job: 6, file, options: OPTIONS, maxLineBytes: 1024, sink: 'blob' });
    expect(validated(posted).at(-1)).toEqual({ type: 'error', job: 6, code: 'LINE_TOO_LONG', line: 2 });
  });
});
