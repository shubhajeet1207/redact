// Paste-mode controller (TRD §10.2, §10.3). Every edit, sample load, or option change bumps the
// revision and clears the accepted result. Dispatch is debounced; at most one request is in
// flight with one pending; a result is accepted only if its revision, options, and rule-set hash
// match the current state. A watchdog restarts a stuck worker once, then gives up.
import {
  PASTE_LIMIT_BYTES,
  parseWorkerMessage,
  sameOptions,
  type Options,
  type PageMessage,
  type Summary,
} from './protocol';

export const DEBOUNCE_MS = 150;
export const PASTE_TIMEOUT_MS = 2_000;
export const READY_TIMEOUT_MS = 10_000;

export interface WorkerLike {
  postMessage(message: PageMessage, transfer?: Transferable[]): void;
  terminate(): void;
  onmessage: ((event: MessageEvent<unknown>) => void) | null;
  onerror: ((event: Event) => void) | null;
}

export interface Clock {
  setTimeout(fn: () => void, ms: number): number;
  clearTimeout(id: number): void;
}

export type PasteStatus = 'initializing' | 'empty' | 'pending' | 'ready' | 'error' | 'unavailable';

export interface Accepted {
  revision: number;
  options: Options;
  output: string;
  summary: Summary;
  ranges: Uint32Array;
}

export interface PasteState {
  status: PasteStatus;
  /** Error code (engine codes, or TIMEOUT, RULES_MISMATCH). */
  error?: string;
  errorLine?: number;
  result: Accepted | null;
  canCopy: boolean;
  inputEnabled: boolean;
  revision: number;
  options: Options;
}

export interface EngineInfo {
  rulesVersion: string;
  rulesSha256: string;
  toolVersion: string;
  ruleIds: string[];
}

interface Request {
  revision: number;
  text: string;
  options: Options;
}

export interface PasteControllerDeps {
  createWorker: () => WorkerLike;
  clock: Clock;
  expectedRulesSha256: string;
  ruleCount: number;
  writeClipboard: (text: string) => Promise<void>;
  onChange: (state: PasteState) => void;
  onReady?: (info: EngineInfo) => void;
}

export const DEFAULT_OPTIONS: Options = { email: true, privateIp: false };

export type CopyOutcome = 'copied' | 'nothing' | 'failed' | 'superseded';

export class PasteController {
  private worker: WorkerLike | null = null;
  private ready = false;
  private revision = 0;
  private text = '';
  private options: Options = { ...DEFAULT_OPTIONS };
  private status: PasteStatus = 'initializing';
  private error: string | undefined;
  private errorLine: number | undefined;
  private accepted: Accepted | null = null;
  private inFlight: Request | null = null;
  private pending: Request | null = null;
  private debounce: number | null = null;
  private watchdog: number | null = null;
  private consecutiveFailures = 0;
  private workerSha: string | null = null;
  private readonly encoder = new TextEncoder();
  private readonly measure = new Uint8Array(PASTE_LIMIT_BYTES + 4);

  constructor(private readonly deps: PasteControllerDeps) {}

  start(): void {
    this.status = 'initializing';
    this.spawn();
    this.emit();
  }

  /** The editor's text changed (typing, paste, sample load). */
  setText(text: string): void {
    this.text = text;
    this.invalidate();
    if (text === '') {
      this.cancelDebounce();
      this.pending = null;
      if (this.ready) this.status = 'empty';
      this.emit();
      return;
    }
    if (this.status !== 'unavailable') this.status = this.ready ? 'pending' : 'initializing';
    this.scheduleDispatch();
    this.emit();
  }

  setOptions(options: Options): void {
    if (sameOptions(options, this.options)) return;
    this.options = { ...options };
    this.setText(this.text);
  }

  /** Discards all state and restores the default options (TRD §10.8). */
  clear(): void {
    this.options = { ...DEFAULT_OPTIONS };
    this.setText('');
  }

  /** Copies the accepted result for the current revision (TRD §10.3). */
  async copy(): Promise<CopyOutcome> {
    const result = this.accepted;
    if (!result || result.revision !== this.revision || result.output === '') return 'nothing';
    const revision = this.revision;
    const snapshot = result.output;
    try {
      await this.deps.writeClipboard(snapshot);
    } catch {
      return 'failed';
    }
    // The validated snapshot was copied, but a newer revision is never shown as copied.
    return this.revision === revision ? 'copied' : 'superseded';
  }

  /** Terminates the worker and forgets everything (pagehide). */
  dispose(): void {
    this.cancelDebounce();
    this.clearWatchdog();
    this.worker?.terminate();
    this.worker = null;
    this.ready = false;
    this.text = '';
    this.accepted = null;
    this.inFlight = null;
    this.pending = null;
  }

  state(): PasteState {
    const s: PasteState = {
      status: this.status,
      result: this.accepted,
      canCopy: this.accepted !== null && this.accepted.revision === this.revision && this.accepted.output !== '',
      inputEnabled: this.ready && this.status !== 'unavailable',
      revision: this.revision,
      options: { ...this.options },
    };
    if (this.error !== undefined) s.error = this.error;
    if (this.errorLine !== undefined) s.errorLine = this.errorLine;
    return s;
  }

  private emit(): void {
    this.deps.onChange(this.state());
  }

  private invalidate(): void {
    this.revision++;
    this.accepted = null;
    this.error = undefined;
    this.errorLine = undefined;
  }

  private spawn(): void {
    let worker: WorkerLike;
    try {
      worker = this.deps.createWorker();
    } catch {
      this.giveUp();
      return;
    }
    this.worker = worker;
    this.ready = false;
    worker.onmessage = (event) => {
      if (this.worker === worker) this.receive(event.data);
    };
    worker.onerror = () => {
      if (this.worker === worker) this.fail();
    };
    worker.postMessage({ type: 'init' });
    this.startWatchdog(READY_TIMEOUT_MS);
  }

  private receive(data: unknown): void {
    const msg = parseWorkerMessage(data, this.deps.ruleCount);
    if (!msg) return;
    switch (msg.type) {
      case 'ready': {
        this.clearWatchdog();
        this.ready = true;
        this.workerSha = msg.rulesSha256;
        if (msg.rulesSha256 !== this.deps.expectedRulesSha256) {
          this.error = 'RULES_MISMATCH';
          this.giveUp();
          return;
        }
        this.deps.onReady?.(msg);
        if (this.status === 'initializing') this.status = this.text === '' ? 'empty' : 'pending';
        // Only text typed while starting is sent; a restart after a failure sends nothing.
        if (this.status === 'pending' && this.debounce === null) this.dispatch();
        this.emit();
        return;
      }
      case 'pasteResult': {
        const request = this.inFlight;
        if (!request || msg.revision !== request.revision) return;
        this.settle();
        // Option changes also bump the revision; the options check is kept as defence in depth.
        const current =
          request.revision === this.revision &&
          sameOptions(request.options, this.options) &&
          this.workerSha === this.deps.expectedRulesSha256 &&
          msg.summary.rulesSha256 === this.deps.expectedRulesSha256;
        if (current) {
          this.accepted = {
            revision: request.revision,
            options: request.options,
            output: msg.output,
            summary: msg.summary,
            ranges: msg.ranges,
          };
          this.status = 'ready';
          this.emit();
        }
        this.sendPending();
        return;
      }
      case 'error': {
        const request = this.inFlight;
        if (!request || msg.revision !== request.revision) return;
        this.settle();
        if (request.revision === this.revision) {
          this.status = 'error';
          this.error = msg.code;
          this.errorLine = msg.line;
          this.emit();
        }
        this.sendPending();
        return;
      }
      default:
        return;
    }
  }

  private settle(): void {
    this.clearWatchdog();
    this.inFlight = null;
    this.consecutiveFailures = 0;
  }

  private scheduleDispatch(): void {
    this.cancelDebounce();
    this.debounce = this.deps.clock.setTimeout(() => {
      this.debounce = null;
      this.dispatch();
    }, DEBOUNCE_MS);
  }

  private cancelDebounce(): void {
    if (this.debounce !== null) this.deps.clock.clearTimeout(this.debounce);
    this.debounce = null;
  }

  private dispatch(): void {
    if (this.text === '' || this.status === 'unavailable') return;
    if (this.tooLarge(this.text)) {
      this.status = 'error';
      this.error = 'INPUT_TOO_LARGE';
      this.emit();
      return;
    }
    const request: Request = { revision: this.revision, text: this.text, options: { ...this.options } };
    if (!this.ready || this.inFlight) {
      // A newer request replaces the pending one.
      this.pending = request;
      return;
    }
    this.send(request);
  }

  private sendPending(): void {
    const next = this.pending;
    this.pending = null;
    if (next && next.revision === this.revision && this.ready) this.send(next);
  }

  private send(request: Request): void {
    this.inFlight = request;
    this.worker?.postMessage({
      type: 'paste',
      revision: request.revision,
      text: request.text,
      options: request.options,
    });
    this.startWatchdog(PASTE_TIMEOUT_MS);
  }

  /** UTF-8 size check without allocating: encodeInto stops when the buffer is full. */
  private tooLarge(text: string): boolean {
    if (text.length > PASTE_LIMIT_BYTES) return true;
    const { read, written } = this.encoder.encodeInto(text, this.measure);
    return read < text.length || written > PASTE_LIMIT_BYTES;
  }

  private startWatchdog(ms: number): void {
    this.clearWatchdog();
    this.watchdog = this.deps.clock.setTimeout(() => {
      this.watchdog = null;
      this.fail();
    }, ms);
  }

  private clearWatchdog(): void {
    if (this.watchdog !== null) this.deps.clock.clearTimeout(this.watchdog);
    this.watchdog = null;
  }

  /** Timeout or worker crash: terminate, clear results, and restart once (TRD §10.2). */
  private fail(): void {
    this.clearWatchdog();
    this.worker?.terminate();
    this.worker = null;
    this.ready = false;
    this.inFlight = null;
    this.pending = null;
    this.accepted = null;
    this.consecutiveFailures++;
    if (this.consecutiveFailures >= 2) {
      this.giveUp();
      return;
    }
    this.status = 'error';
    this.error = 'TIMEOUT';
    this.emit();
    // Re-creation sends no input: the next edit dispatches again.
    this.spawn();
  }

  private giveUp(): void {
    this.clearWatchdog();
    this.cancelDebounce();
    this.worker?.terminate();
    this.worker = null;
    this.ready = false;
    this.inFlight = null;
    this.pending = null;
    this.accepted = null;
    this.status = 'unavailable';
    this.emit();
  }
}
