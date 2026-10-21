import { beforeEach, describe, expect, it } from 'vitest';

import { CHUNK_TIMEOUT_MS, FileController, REVOKE_DELAY_MS, suggestedName, type FileState } from '../src/file-mode';
import { FakeClock, FakeWorker } from './fakes';
import { RULE_IDS, summary } from './fixtures';

describe('suggestedName', () => {
  it.each([
    ['app.log', 'app.redacted.log'],
    ['archive.tar.gz', 'archive.tar.redacted.gz'],
    ['README', 'README.redacted'],
    ['.env', '.env.redacted'],
    ['trace.', 'trace.redacted.'],
  ])('%s → %s', (input, expected) => {
    expect(suggestedName(input)).toBe(expected);
  });
});

describe('FileController', () => {
  let clock: FakeClock;
  let workers: FakeWorker[];
  let states: FileState[];
  let urls: { created: string[]; revoked: string[] };
  let controller: FileController;
  const worker = (): FakeWorker => workers.at(-1) ?? new FakeWorker();
  const state = (): FileState => states.at(-1) ?? { status: 'idle', bytesDone: 0, bytesTotal: 0 };
  const file = new File(['password=x\n'], 'app.log');
  const options = { email: true, privateIp: false };

  beforeEach(() => {
    clock = new FakeClock();
    workers = [];
    states = [];
    urls = { created: [], revoked: [] };
    controller = new FileController({
      createWorker: () => {
        const w = new FakeWorker();
        workers.push(w);
        return w;
      },
      clock,
      ruleCount: RULE_IDS.length,
      createObjectUrl: () => {
        const url = `blob:test/${urls.created.length}`;
        urls.created.push(url);
        return url;
      },
      revokeObjectUrl: (url) => urls.revoked.push(url),
      onChange: (s) => states.push(s),
    });
    controller.start();
  });

  it('posts the File itself to the worker and tracks progress', () => {
    controller.run(file, options, 1_048_576, 'blob');
    expect(worker().sent.at(-1)).toEqual({ type: 'fileStart', job: 1, file, options, maxLineBytes: 1_048_576, sink: 'blob' });
    worker().reply({ type: 'fileProgress', job: 1, bytesDone: 5, bytesTotal: 11 });
    expect(state()).toMatchObject({ status: 'running', bytesDone: 5, bytesTotal: 11, suggestedName: 'app.redacted.log' });
  });

  it('offers the Blob only after success and revokes its URL after saving', () => {
    controller.run(file, options, 1_048_576, 'blob');
    const blob = new Blob(['password=[REDACTED]\n']);
    worker().reply({
      type: 'fileResult',
      job: 1,
      summary: summary(1),
      preview: 'password=[REDACTED]\n',
      previewRanges: new Uint32Array([9, 19, 0]),
      outputBytes: 20,
      copyText: 'password=[REDACTED]\n',
      blob,
    });
    expect(state()).toMatchObject({ status: 'done', downloadUrl: 'blob:test/0', savedToDisk: false });
    controller.saved();
    // The link keeps its URL until the click's default action has run.
    expect(urls.revoked).toEqual([]);
    clock.advance(REVOKE_DELAY_MS);
    expect(urls.revoked).toEqual(['blob:test/0']);
    expect(state().downloadUrl).toBeUndefined();
  });

  it('Clear revokes an unsaved URL', () => {
    controller.run(file, options, 1_048_576, 'blob');
    worker().reply({
      type: 'fileResult', job: 1, summary: summary(0), preview: '', previewRanges: new Uint32Array(), outputBytes: 0, blob: new Blob([]),
    });
    controller.reset();
    expect(urls.revoked).toEqual(['blob:test/0']);
    expect(state().status).toBe('idle');
  });

  it('ignores messages for other jobs', () => {
    controller.run(file, options, 1_048_576, 'blob');
    worker().reply({ type: 'fileProgress', job: 9, bytesDone: 5, bytesTotal: 11 });
    expect(state().bytesDone).toBe(0);
  });

  it('stops a job when no chunk completes within 5 s and starts a fresh worker', () => {
    controller.run(file, options, 1_048_576, 'blob');
    clock.advance(CHUNK_TIMEOUT_MS - 1);
    worker().reply({ type: 'fileProgress', job: 1, bytesDone: 1, bytesTotal: 11 });
    clock.advance(CHUNK_TIMEOUT_MS - 1);
    expect(workers).toHaveLength(1);
    clock.advance(1);
    expect(workers[0]?.terminated).toBe(true);
    expect(workers).toHaveLength(2);
    expect(state()).toMatchObject({ status: 'error', error: 'TIMEOUT' });
  });

  it('forwards cancel and reports the cancellation', () => {
    controller.run(file, options, 1_048_576, 'blob');
    controller.cancel();
    expect(worker().sent.at(-1)).toEqual({ type: 'cancel', job: 1 });
    worker().reply({ type: 'error', job: 1, code: 'CANCELLED' });
    expect(state()).toMatchObject({ status: 'error', error: 'CANCELLED' });
  });
});
