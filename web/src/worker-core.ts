// Worker logic (TRD §10.4, §10.5), separated from the WebAssembly bootstrap so it can be tested
// with the real engine in Node. The worker holds no state other than the current file job.
import {
  PASTE_LIMIT_BYTES,
  isSummary,
  parsePageMessage,
  type Options,
  type PageMessage,
  type Summary,
  type WorkerMessage,
} from './protocol';

/** File chunk size (TRD §10.4). */
export const CHUNK_BYTES = 1_048_576;
/** Blob sink limit (TRD §10.4). */
export const BLOB_LIMIT_BYTES = 1_073_741_824;

interface PasteResultLike {
  readonly output: string;
  readonly ranges: Uint32Array;
  readonly summary: unknown;
  readonly error: unknown;
  free(): void;
}

interface FileJobLike {
  push(chunk: Uint8Array): Uint8Array;
  finish(): Uint8Array;
  summary(): unknown;
  previewText(): string;
  previewRanges(): Uint32Array;
  free(): void;
}

/** The subset of the wasm-bindgen exports the worker uses. */
export interface Engine {
  rulesVersion(): string;
  rulesSha256(): string;
  toolVersion(): string;
  ruleIds(): unknown[];
  sanitizePaste(text: string, email: boolean, privateIp: boolean): PasteResultLike;
  FileJob: new (email: boolean, privateIp: boolean, maxLineBytes: number) => FileJobLike;
}

export type Post = (message: WorkerMessage, transfer?: Transferable[]) => void;

interface EngineError {
  code: string;
  line: number | null;
}

function engineError(e: unknown): EngineError {
  if (typeof e === 'object' && e !== null && 'code' in e && typeof e.code === 'string') {
    const line = 'line' in e && typeof e.line === 'number' ? e.line : null;
    return { code: e.code, line };
  }
  return { code: 'INTERNAL_ERROR', line: null };
}

function errorMessage(base: { revision?: number; job?: number }, e: EngineError): WorkerMessage {
  const msg: WorkerMessage = { type: 'error', code: e.code, ...base };
  if (e.line !== null && e.line > 0) msg.line = e.line;
  return msg;
}

class Cancelled extends Error {}

/** A failure with an engine-style code, raised inside the file job. */
class JobError extends Error {
  constructor(
    readonly code: string,
    readonly line: number | null = null,
  ) {
    super(code);
  }
}

export class WorkerCore {
  /** Messages that failed validation (TRD §10.5: dropped and counted). */
  dropped = 0;
  private current: { job: number; cancelled: boolean } | null = null;

  constructor(
    private readonly engine: Engine,
    private readonly post: Post,
  ) {}

  /** Handles one incoming message; resolves when any file job it started has finished. */
  handle(data: unknown): Promise<void> {
    const msg = parsePageMessage(data);
    if (!msg) {
      this.dropped++;
      return Promise.resolve();
    }
    switch (msg.type) {
      case 'init':
        this.ready();
        return Promise.resolve();
      case 'paste':
        this.paste(msg.revision, msg.text, msg.options);
        return Promise.resolve();
      case 'fileStart':
        return this.file(msg);
      case 'cancel':
        if (this.current?.job === msg.job) this.current.cancelled = true;
        return Promise.resolve();
    }
  }

  private ready(): void {
    const ruleIds = this.engine.ruleIds().filter((r): r is string => typeof r === 'string');
    this.post({
      type: 'ready',
      rulesVersion: this.engine.rulesVersion(),
      rulesSha256: this.engine.rulesSha256(),
      toolVersion: this.engine.toolVersion(),
      ruleIds,
    });
  }

  private paste(revision: number, text: string, options: Options): void {
    // Strings longer than the limit in UTF-16 units are over it in UTF-8 bytes too.
    if (text.length > PASTE_LIMIT_BYTES) {
      this.post(errorMessage({ revision }, { code: 'INPUT_TOO_LARGE', line: null }));
      return;
    }
    const result = this.engine.sanitizePaste(text, options.email, options.privateIp);
    try {
      if (result.error !== undefined) {
        this.post(errorMessage({ revision }, engineError(result.error)));
        return;
      }
      const summary = result.summary;
      if (!isSummary(summary)) {
        this.post(errorMessage({ revision }, { code: 'INTERNAL_ERROR', line: null }));
        return;
      }
      const ranges = result.ranges;
      this.post({ type: 'pasteResult', revision, output: result.output, summary, ranges }, [ranges.buffer]);
    } finally {
      // Zeroes the WebAssembly copies of input and output (TRD §10.5).
      result.free();
    }
  }

  private async file(msg: Extract<PageMessage, { type: 'fileStart' }>): Promise<void> {
    if (this.current) {
      this.post(errorMessage({ job: msg.job }, { code: 'INVALID_OPTIONS', line: null }));
      return;
    }
    const state = { job: msg.job, cancelled: false };
    this.current = state;
    let job: FileJobLike | undefined;
    let writable: FileSystemWritableFileStream | undefined;
    const parts: Uint8Array[] = [];
    const copyParts: Uint8Array[] = [];
    let outputBytes = 0;
    const emit = async (bytes: Uint8Array): Promise<void> => {
      if (bytes.length === 0) return;
      outputBytes += bytes.length;
      if (outputBytes <= PASTE_LIMIT_BYTES) copyParts.push(bytes.slice());
      if (writable) {
        // Arrays from the engine are backed by a plain ArrayBuffer, never a shared one.
        await writable.write(bytes as Uint8Array<ArrayBuffer>);
        bytes.fill(0);
      } else {
        if (outputBytes > BLOB_LIMIT_BYTES) throw new JobError('OUTPUT_TOO_LARGE');
        parts.push(bytes);
      }
    };
    try {
      job = new this.engine.FileJob(msg.options.email, msg.options.privateIp, msg.maxLineBytes);
      if (msg.sink === 'handle' && msg.handle) writable = await msg.handle.createWritable();
      const total = msg.file.size;
      for (let offset = 0; offset < total; offset += CHUNK_BYTES) {
        if (state.cancelled) throw new Cancelled();
        let chunk: Uint8Array;
        try {
          chunk = new Uint8Array(await msg.file.slice(offset, offset + CHUNK_BYTES).arrayBuffer());
        } catch {
          throw new JobError('READ_FAILED');
        }
        const out = job.push(chunk);
        chunk.fill(0);
        await emit(out);
        this.post({ type: 'fileProgress', job: msg.job, bytesDone: Math.min(offset + CHUNK_BYTES, total), bytesTotal: total });
      }
      if (state.cancelled) throw new Cancelled();
      await emit(job.finish());
      const summary = job.summary();
      if (!isSummary(summary)) throw new JobError('INTERNAL_ERROR');
      if (writable) {
        await writable.close();
        writable = undefined;
      }
      this.post(this.result(msg.job, job, summary, outputBytes, parts, copyParts, msg.sink));
    } catch (e) {
      if (writable) {
        // Browsers stage writes and commit only on close(); abort() discards the partial file.
        await writable.abort().catch(() => undefined);
      }
      for (const p of parts) p.fill(0);
      const error = e instanceof Cancelled ? { code: 'CANCELLED', line: null } : engineError(e);
      this.post(errorMessage({ job: msg.job }, error));
    } finally {
      for (const p of copyParts) p.fill(0);
      job?.free();
      this.current = null;
    }
  }

  private result(
    jobId: number,
    job: FileJobLike,
    summary: Summary,
    outputBytes: number,
    parts: Uint8Array[],
    copyParts: Uint8Array[],
    sink: 'blob' | 'handle',
  ): WorkerMessage {
    const msg: WorkerMessage = {
      type: 'fileResult',
      job: jobId,
      summary,
      preview: job.previewText(),
      previewRanges: job.previewRanges(),
      outputBytes,
    };
    if (outputBytes <= PASTE_LIMIT_BYTES) {
      // Copy text is decoded in the output's own encoding; the BOM is not part of the text.
      const decoder = new TextDecoder(summary.encoding);
      let text = '';
      for (const p of copyParts) text += decoder.decode(p, { stream: true });
      msg.copyText = text + decoder.decode();
    }
    if (sink === 'blob') msg.blob = new Blob(parts as BlobPart[], { type: 'application/octet-stream' });
    return msg;
  }
}
