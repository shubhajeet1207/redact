// Worker protocol (TRD §10.5). Both sides validate every field: exact `type` values, integer
// ranges, booleans, and object shapes. Unknown or malformed messages are dropped and counted,
// never interpreted.

export interface Options {
  email: boolean;
  privateIp: boolean;
}

export interface Hidden {
  bidi: number;
  invisible: number;
  control: number;
  loneCr: number;
}

export interface WarningInfo {
  code: string;
  line: number;
  lines?: number;
}

export interface Summary {
  replacements: number;
  byRule: Record<string, number>;
  lines: number;
  bytesIn: number;
  bytesOut: number;
  encoding: 'utf-8' | 'utf-16le' | 'utf-16be';
  bom: boolean;
  invalidUtf8Replaced: number;
  hidden: Hidden;
  warnings: WarningInfo[];
  rulesVersion: string;
  rulesSha256: string;
}

export type Sink = 'blob' | 'handle';

export type PageMessage =
  | { type: 'init' }
  | { type: 'paste'; revision: number; text: string; options: Options }
  | {
      type: 'fileStart';
      job: number;
      file: File;
      options: Options;
      maxLineBytes: number;
      sink: Sink;
      handle?: FileSystemFileHandle;
    }
  | { type: 'cancel'; job: number };

export type WorkerMessage =
  | { type: 'ready'; rulesVersion: string; rulesSha256: string; toolVersion: string; ruleIds: string[] }
  | { type: 'pasteResult'; revision: number; output: string; summary: Summary; ranges: Uint32Array }
  | { type: 'fileProgress'; job: number; bytesDone: number; bytesTotal: number }
  | {
      type: 'fileResult';
      job: number;
      summary: Summary;
      preview: string;
      previewRanges: Uint32Array;
      outputBytes: number;
      copyText?: string;
      blob?: Blob;
    }
  | { type: 'error'; revision?: number; job?: number; code: string; line?: number };

/** Paste-mode limit (TRD §10.2), in UTF-8 bytes. */
export const PASTE_LIMIT_BYTES = 1_048_576;
export const MIN_LINE_BYTES = 1_024;
export const MAX_LINE_BYTES = 67_108_864;
export const DEFAULT_LINE_BYTES = 1_048_576;

const ERROR_CODES = new Set([
  'INVALID_UTF8',
  'INVALID_UTF16',
  'UTF16_WITHOUT_BOM',
  'UNSUPPORTED_ENCODING',
  'NUL_BYTE',
  'LINE_TOO_LONG',
  'INPUT_TOO_LARGE',
  'INVALID_OPTIONS',
  'INTERNAL_ERROR',
  'OUTPUT_TOO_LARGE',
  'WRITE_FAILED',
  'READ_FAILED',
  'CANCELLED',
  'ENGINE_UNAVAILABLE',
]);
const WARNING_CODES = new Set(['UNTERMINATED_PRIVATE_KEY_BLOCK', 'UNSTABLE_LINE_REDACTED']);
const ENCODINGS = new Set(['utf-8', 'utf-16le', 'utf-16be']);
const RULE_ID = /^SR-\d{3}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const SEMVER = /^\d+\.\d+\.\d+$/;

type Obj = Record<string, unknown>;

function isObj(v: unknown): v is Obj {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/** True when `v` has exactly the keys `required` plus any of `optional`. */
function hasShape(v: Obj, required: readonly string[], optional: readonly string[] = []): boolean {
  const keys = Object.keys(v);
  return required.every((k) => k in v) && keys.every((k) => required.includes(k) || optional.includes(k));
}

function isCount(v: unknown): v is number {
  return typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
}

export function isOptions(v: unknown): v is Options {
  return isObj(v) && hasShape(v, ['email', 'privateIp']) && typeof v['email'] === 'boolean' && typeof v['privateIp'] === 'boolean';
}

export function isSummary(v: unknown): v is Summary {
  if (!isObj(v)) return false;
  const keys = [
    'replacements',
    'byRule',
    'lines',
    'bytesIn',
    'bytesOut',
    'encoding',
    'bom',
    'invalidUtf8Replaced',
    'hidden',
    'warnings',
    'rulesVersion',
    'rulesSha256',
  ] as const;
  if (!hasShape(v, keys)) return false;
  const { byRule, hidden, warnings } = v;
  if (!isObj(byRule) || !Object.entries(byRule).every(([k, n]) => RULE_ID.test(k) && isCount(n))) return false;
  const total = Object.values(byRule).reduce<number>((a, n) => a + (n as number), 0);
  if (!isCount(v['replacements']) || total !== v['replacements']) return false;
  if (!isObj(hidden) || !hasShape(hidden, ['bidi', 'invisible', 'control', 'loneCr'])) return false;
  if (!Object.values(hidden).every(isCount)) return false;
  if (!Array.isArray(warnings) || !warnings.every(isWarning)) return false;
  return (
    isCount(v['lines']) &&
    isCount(v['bytesIn']) &&
    isCount(v['bytesOut']) &&
    isCount(v['invalidUtf8Replaced']) &&
    typeof v['encoding'] === 'string' &&
    ENCODINGS.has(v['encoding']) &&
    typeof v['bom'] === 'boolean' &&
    typeof v['rulesVersion'] === 'string' &&
    SEMVER.test(v['rulesVersion']) &&
    typeof v['rulesSha256'] === 'string' &&
    HEX64.test(v['rulesSha256'])
  );
}

function isWarning(v: unknown): v is WarningInfo {
  return (
    isObj(v) &&
    hasShape(v, ['code', 'line'], ['lines']) &&
    typeof v['code'] === 'string' &&
    WARNING_CODES.has(v['code']) &&
    isCount(v['line']) &&
    (v['lines'] === undefined || isCount(v['lines']))
  );
}

/** Ranges are flat `[start, end, ruleIndex]` triples, sorted and disjoint, within `length`. */
export function isRanges(v: unknown, length: number, ruleCount: number): v is Uint32Array {
  if (!(v instanceof Uint32Array) || v.length % 3 !== 0) return false;
  let last = 0;
  for (let i = 0; i < v.length; i += 3) {
    const start = v[i] ?? 0;
    const end = v[i + 1] ?? 0;
    const rule = v[i + 2] ?? 0;
    if (start < last || end <= start || end > length || rule >= ruleCount) return false;
    last = end;
  }
  return true;
}

function isRevision(v: unknown): v is number {
  return isCount(v) && v > 0;
}

/** Validates a message received by the worker. */
export function parsePageMessage(data: unknown): PageMessage | null {
  if (!isObj(data) || typeof data['type'] !== 'string') return null;
  switch (data['type']) {
    case 'init':
      return hasShape(data, ['type']) ? { type: 'init' } : null;
    case 'paste': {
      if (!hasShape(data, ['type', 'revision', 'text', 'options'])) return null;
      const { revision, text, options } = data;
      if (!isRevision(revision) || typeof text !== 'string' || !isOptions(options)) return null;
      return { type: 'paste', revision, text, options };
    }
    case 'fileStart': {
      if (!hasShape(data, ['type', 'job', 'file', 'options', 'maxLineBytes', 'sink'], ['handle'])) return null;
      const { job, file, options, maxLineBytes, sink, handle } = data;
      if (!isRevision(job) || !(file instanceof File) || !isOptions(options)) return null;
      if (!isCount(maxLineBytes) || maxLineBytes < MIN_LINE_BYTES || maxLineBytes > MAX_LINE_BYTES) return null;
      if (sink === 'blob' && handle === undefined) {
        return { type: 'fileStart', job, file, options, maxLineBytes, sink };
      }
      if (sink === 'handle' && typeof FileSystemFileHandle !== 'undefined' && handle instanceof FileSystemFileHandle) {
        return { type: 'fileStart', job, file, options, maxLineBytes, sink, handle };
      }
      return null;
    }
    case 'cancel': {
      if (!hasShape(data, ['type', 'job']) || !isRevision(data['job'])) return null;
      return { type: 'cancel', job: data['job'] };
    }
    default:
      return null;
  }
}

/** Validates a message received by the page. `ruleCount` bounds the rule index in ranges. */
export function parseWorkerMessage(data: unknown, ruleCount: number): WorkerMessage | null {
  if (!isObj(data) || typeof data['type'] !== 'string') return null;
  switch (data['type']) {
    case 'ready': {
      if (!hasShape(data, ['type', 'rulesVersion', 'rulesSha256', 'toolVersion', 'ruleIds'])) return null;
      const { rulesVersion, rulesSha256, toolVersion, ruleIds } = data;
      if (typeof rulesVersion !== 'string' || !SEMVER.test(rulesVersion)) return null;
      if (typeof rulesSha256 !== 'string' || !HEX64.test(rulesSha256)) return null;
      if (typeof toolVersion !== 'string' || !SEMVER.test(toolVersion)) return null;
      if (!Array.isArray(ruleIds) || !ruleIds.every((r): r is string => typeof r === 'string' && RULE_ID.test(r))) return null;
      return { type: 'ready', rulesVersion, rulesSha256, toolVersion, ruleIds };
    }
    case 'pasteResult': {
      if (!hasShape(data, ['type', 'revision', 'output', 'summary', 'ranges'])) return null;
      const { revision, output, summary, ranges } = data;
      if (!isRevision(revision) || typeof output !== 'string' || !isSummary(summary)) return null;
      if (!isRanges(ranges, output.length, ruleCount) || ranges.length / 3 !== summary.replacements) return null;
      return { type: 'pasteResult', revision, output, summary, ranges };
    }
    case 'fileProgress': {
      if (!hasShape(data, ['type', 'job', 'bytesDone', 'bytesTotal'])) return null;
      const { job, bytesDone, bytesTotal } = data;
      if (!isRevision(job) || !isCount(bytesDone) || !isCount(bytesTotal) || bytesDone > bytesTotal) return null;
      return { type: 'fileProgress', job, bytesDone, bytesTotal };
    }
    case 'fileResult': {
      if (!hasShape(data, ['type', 'job', 'summary', 'preview', 'previewRanges', 'outputBytes'], ['copyText', 'blob'])) {
        return null;
      }
      const { job, summary, preview, previewRanges, outputBytes, copyText, blob } = data;
      if (!isRevision(job) || !isSummary(summary) || typeof preview !== 'string' || !isCount(outputBytes)) return null;
      if (!isRanges(previewRanges, preview.length, ruleCount)) return null;
      if (copyText !== undefined && typeof copyText !== 'string') return null;
      if (blob !== undefined && !(blob instanceof Blob)) return null;
      const msg: WorkerMessage = { type: 'fileResult', job, summary, preview, previewRanges, outputBytes };
      if (copyText !== undefined) msg.copyText = copyText;
      if (blob !== undefined) msg.blob = blob;
      return msg;
    }
    case 'error': {
      if (!hasShape(data, ['type', 'code'], ['revision', 'job', 'line'])) return null;
      const { code, revision, job, line } = data;
      if (typeof code !== 'string' || !ERROR_CODES.has(code)) return null;
      if (revision !== undefined && !isRevision(revision)) return null;
      if (job !== undefined && !isRevision(job)) return null;
      if (line !== undefined && !isRevision(line)) return null;
      const msg: WorkerMessage = { type: 'error', code };
      if (revision !== undefined) msg.revision = revision;
      if (job !== undefined) msg.job = job;
      if (line !== undefined) msg.line = line;
      return msg;
    }
    default:
      return null;
  }
}

export function sameOptions(a: Options, b: Options): boolean {
  return a.email === b.email && a.privateIp === b.privateIp;
}
