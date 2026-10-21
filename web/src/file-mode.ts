// File-mode controller (TRD §10.4). The File object goes to the worker; the main thread never
// holds its content. Output streams to a user-chosen file where the browser supports it, or
// accumulates as a Blob (up to 1 GiB) that is offered for saving only after success.
import { parseWorkerMessage, type Options, type Sink, type Summary } from './protocol';
import type { Clock, WorkerLike } from './controller';

export const CHUNK_TIMEOUT_MS = 5_000;
/** Delay between a Save click and revoking the object URL (TRD §10.4). */
export const REVOKE_DELAY_MS = 1_000;

export type FileStatus = 'idle' | 'running' | 'done' | 'error' | 'unavailable';

export interface FileState {
  status: FileStatus;
  fileName?: string;
  bytesDone: number;
  bytesTotal: number;
  error?: string;
  errorLine?: number;
  summary?: Summary;
  preview?: string;
  previewRanges?: Uint32Array;
  outputBytes?: number;
  copyText?: string;
  /** Object URL of the sanitized Blob (blob sink only). */
  downloadUrl?: string;
  suggestedName?: string;
  savedToDisk?: boolean;
}

export interface FileControllerDeps {
  createWorker: () => WorkerLike;
  clock: Clock;
  ruleCount: number;
  createObjectUrl: (blob: Blob) => string;
  revokeObjectUrl: (url: string) => void;
  onChange: (state: FileState) => void;
}

/** `<name>.redacted<ext>`, computed locally (TRD §10.4). */
export function suggestedName(name: string): string {
  const dot = name.lastIndexOf('.');
  if (dot <= 0) return `${name}.redacted`;
  return `${name.slice(0, dot)}.redacted${name.slice(dot)}`;
}

export class FileController {
  private worker: WorkerLike | null = null;
  private job = 0;
  private running = false;
  private watchdog: number | null = null;
  private state: FileState = { status: 'idle', bytesDone: 0, bytesTotal: 0 };

  constructor(private readonly deps: FileControllerDeps) {}

  /** Creates the worker eagerly so a loaded page keeps working offline (TRD §10.8). */
  start(): void {
    this.spawn();
    this.emit();
  }

  run(file: File, options: Options, maxLineBytes: number, sink: Sink, handle?: FileSystemFileHandle): void {
    if (this.running || !this.worker) return;
    this.reset();
    this.job++;
    this.running = true;
    this.state = {
      status: 'running',
      fileName: file.name,
      bytesDone: 0,
      bytesTotal: file.size,
      suggestedName: suggestedName(file.name),
    };
    if (sink === 'handle' && handle) {
      this.worker.postMessage({ type: 'fileStart', job: this.job, file, options, maxLineBytes, sink, handle });
    } else {
      this.worker.postMessage({ type: 'fileStart', job: this.job, file, options, maxLineBytes, sink: 'blob' });
    }
    this.armWatchdog();
    this.emit();
  }

  cancel(): void {
    if (this.running) this.worker?.postMessage({ type: 'cancel', job: this.job });
  }

  /** Drops results and revokes the object URL (Clear). */
  reset(): void {
    if (this.state.downloadUrl) this.deps.revokeObjectUrl(this.state.downloadUrl);
    if (!this.running) {
      this.state = { status: this.worker ? 'idle' : 'unavailable', bytesDone: 0, bytesTotal: 0 };
      this.emit();
    }
  }

  /**
   * The user clicked Save. The link must keep its URL until the browser has run the click's
   * default action, so the URL is revoked shortly afterwards rather than inside the handler.
   */
  saved(): void {
    const url = this.state.downloadUrl;
    if (!url) return;
    this.deps.clock.setTimeout(() => {
      if (this.state.downloadUrl !== url) return;
      this.deps.revokeObjectUrl(url);
      const next: FileState = { ...this.state };
      delete next.downloadUrl;
      this.state = next;
      this.emit();
    }, REVOKE_DELAY_MS);
  }

  dispose(): void {
    this.clearWatchdog();
    if (this.state.downloadUrl) this.deps.revokeObjectUrl(this.state.downloadUrl);
    this.worker?.terminate();
    this.worker = null;
    this.running = false;
    this.state = { status: 'idle', bytesDone: 0, bytesTotal: 0 };
  }

  current(): FileState {
    return this.state;
  }

  private emit(): void {
    this.deps.onChange(this.state);
  }

  /** Returns false when no worker could be created. */
  private spawn(): boolean {
    let worker: WorkerLike;
    try {
      worker = this.deps.createWorker();
    } catch {
      this.worker = null;
      this.state = { status: 'unavailable', bytesDone: 0, bytesTotal: 0 };
      return false;
    }
    this.worker = worker;
    worker.onmessage = (event) => {
      if (this.worker === worker) this.receive(event.data);
    };
    worker.onerror = () => {
      if (this.worker === worker) this.fail('ENGINE_UNAVAILABLE');
    };
    worker.postMessage({ type: 'init' });
    return true;
  }

  private receive(data: unknown): void {
    const msg = parseWorkerMessage(data, this.deps.ruleCount);
    if (!msg || !this.running) return;
    switch (msg.type) {
      case 'fileProgress':
        if (msg.job !== this.job) return;
        this.armWatchdog();
        this.state = { ...this.state, bytesDone: msg.bytesDone, bytesTotal: msg.bytesTotal };
        this.emit();
        return;
      case 'fileResult': {
        if (msg.job !== this.job) return;
        this.finish();
        const next: FileState = {
          ...this.state,
          status: 'done',
          bytesDone: this.state.bytesTotal,
          summary: msg.summary,
          preview: msg.preview,
          previewRanges: msg.previewRanges,
          outputBytes: msg.outputBytes,
          savedToDisk: msg.blob === undefined,
        };
        if (msg.copyText !== undefined) next.copyText = msg.copyText;
        if (msg.blob) next.downloadUrl = this.deps.createObjectUrl(msg.blob);
        this.state = next;
        this.emit();
        return;
      }
      case 'error': {
        if (msg.job !== this.job) return;
        this.finish();
        const next: FileState = { ...this.state, status: 'error', error: msg.code };
        if (msg.line !== undefined) next.errorLine = msg.line;
        this.state = next;
        this.emit();
        return;
      }
      default:
        return;
    }
  }

  private finish(): void {
    this.clearWatchdog();
    this.running = false;
  }

  private armWatchdog(): void {
    this.clearWatchdog();
    this.watchdog = this.deps.clock.setTimeout(() => {
      this.watchdog = null;
      this.fail('TIMEOUT');
    }, CHUNK_TIMEOUT_MS);
  }

  private clearWatchdog(): void {
    if (this.watchdog !== null) this.deps.clock.clearTimeout(this.watchdog);
    this.watchdog = null;
  }

  /** No chunk completed in time, or the worker crashed: stop the job and start a fresh worker. */
  private fail(code: string): void {
    const wasRunning = this.running;
    this.finish();
    this.worker?.terminate();
    this.worker = null;
    this.state = { ...this.state, status: 'error', error: wasRunning ? code : 'ENGINE_UNAVAILABLE' };
    if (!this.spawn()) this.state = { ...this.state, status: 'unavailable' };
    this.emit();
  }
}
