// Page entry point (TRD §10). Creates the engine workers eagerly, wires paste and file modes,
// and clears everything on pagehide. The only Trusted Types policy accepts exactly the worker URL.
import './styles.css';

import workerUrl from './worker.ts?worker&url';
import rulesDoc from './generated/rules.json';

import { PasteController, type Clock, type WorkerLike } from './controller';
import { FileController } from './file-mode';
import { FileView } from './file-view';
import { PasteView } from './paste';

interface TrustedTypePolicyLike {
  createScriptURL(input: string): string;
}

interface TrustedTypesLike {
  createPolicy(name: string, rules: { createScriptURL: (input: string) => string }): TrustedTypePolicyLike;
}

function byId<T extends HTMLElement>(id: string, type: new () => T): T {
  const node = document.getElementById(id);
  if (!(node instanceof type)) throw new Error(`missing #${id}`);
  return node;
}

const factory = (globalThis as { trustedTypes?: TrustedTypesLike }).trustedTypes;
const policy = factory?.createPolicy('spymonk-worker', {
  createScriptURL: (input) => {
    if (input !== workerUrl) throw new TypeError('Refusing an unexpected worker script URL.');
    return input;
  },
});

function createWorker(): WorkerLike {
  const url = policy ? policy.createScriptURL(workerUrl) : workerUrl;
  return new Worker(url, { type: 'module', name: 'spymonk-engine' }) as unknown as WorkerLike;
}

const clock: Clock = {
  setTimeout: (fn, ms) => window.setTimeout(fn, ms),
  clearTimeout: (id) => {
    window.clearTimeout(id);
  },
};

const writeClipboard = (text: string): Promise<void> => navigator.clipboard.writeText(text);

const rules = rulesDoc.rules.map((r) => ({ id: r.id, name: r.name }));
const ruleNames = Object.fromEntries(rules.map((r) => [r.id, r.name]));

const pasteView = new PasteView(
  {
    input: byId('paste-input', HTMLTextAreaElement),
    output: byId('paste-output', HTMLElement),
    notice: byId('paste-notice', HTMLElement),
    status: byId('paste-status', HTMLElement),
    live: byId('paste-live', HTMLElement),
    hidden: byId('paste-hidden', HTMLElement),
    copy: byId('copy', HTMLButtonElement),
    clear: byId('clear', HTMLButtonElement),
    email: byId('opt-email', HTMLInputElement),
    privateIp: byId('opt-ip', HTMLInputElement),
    badges: byId('opt-badges', HTMLInputElement),
    sample: byId('sample', HTMLSelectElement),
    loadSample: byId('load-sample', HTMLButtonElement),
    report: byId('paste-report', HTMLDetailsElement),
    confirm: byId('confirm-sample', HTMLDialogElement),
  },
  rules,
  ruleNames,
);

const fileView = new FileView(
  {
    input: byId('file-input', HTMLInputElement),
    dropzone: byId('dropzone', HTMLElement),
    email: byId('file-opt-email', HTMLInputElement),
    privateIp: byId('file-opt-ip', HTMLInputElement),
    lineLimit: byId('file-line-limit', HTMLSelectElement),
    sinkHandle: byId('sink-handle', HTMLInputElement),
    sinkBlob: byId('sink-blob', HTMLInputElement),
    progress: byId('file-progress', HTMLElement),
    cancel: byId('file-cancel', HTMLButtonElement),
    status: byId('file-status', HTMLElement),
    live: byId('file-live', HTMLElement),
    warn: byId('file-warn', HTMLElement),
    save: byId('file-save', HTMLAnchorElement),
    saveNote: byId('file-save-note', HTMLElement),
    copy: byId('file-copy', HTMLButtonElement),
    clear: byId('file-clear', HTMLButtonElement),
    preview: byId('file-preview', HTMLElement),
    previewNote: byId('file-preview-note', HTMLElement),
    report: byId('file-report', HTMLDetailsElement),
  },
  rules,
  ruleNames,
  writeClipboard,
);

let paste: PasteController | null = null;
let file: FileController | null = null;

function boot(): void {
  paste = new PasteController({
    createWorker,
    clock,
    expectedRulesSha256: rulesDoc.sha256,
    ruleCount: rules.length,
    writeClipboard,
    onChange: (state) => {
      pasteView.render(state);
    },
    onReady: (info) => {
      pasteView.setRuleIds(info.ruleIds);
      fileView.setRuleIds(info.ruleIds);
    },
  });
  file = new FileController({
    createWorker,
    clock,
    ruleCount: rules.length,
    createObjectUrl: (blob) => URL.createObjectURL(blob),
    revokeObjectUrl: (url) => {
      URL.revokeObjectURL(url);
    },
    onChange: (state) => {
      fileView.render(state);
    },
  });
  pasteView.attach(paste);
  fileView.attach(file);
  paste.start();
  file.start();
}

// Tabs (WAI-ARIA tabs pattern with automatic activation).
const tabs = [byId('tab-paste', HTMLButtonElement), byId('tab-file', HTMLButtonElement)];
function select(tab: HTMLButtonElement, focus: boolean): void {
  for (const t of tabs) {
    const selected = t === tab;
    t.setAttribute('aria-selected', String(selected));
    t.tabIndex = selected ? 0 : -1;
    const panel = document.getElementById(t.getAttribute('aria-controls') ?? '');
    if (panel) panel.hidden = !selected;
  }
  if (focus) tab.focus();
}
tabs.forEach((tab, i) => {
  tab.addEventListener('click', () => {
    select(tab, false);
  });
  tab.addEventListener('keydown', (event) => {
    const next =
      event.key === 'ArrowRight' ? tabs[(i + 1) % tabs.length] : event.key === 'ArrowLeft' ? tabs[(i - 1 + tabs.length) % tabs.length] : event.key === 'Home' ? tabs[0] : event.key === 'End' ? tabs[tabs.length - 1] : undefined;
    if (next) {
      event.preventDefault();
      select(next, true);
    }
  });
});

// Lifecycle (TRD §10.8): leaving the page clears input, output, results, URLs, and workers.
window.addEventListener('pagehide', () => {
  pasteView.clear();
  paste?.dispose();
  file?.dispose();
  paste = null;
  file = null;
});
window.addEventListener('pageshow', (event) => {
  if (event.persisted) boot();
});

boot();
