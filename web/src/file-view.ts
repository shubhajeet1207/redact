// File-mode view: picker, drop zone, destination choice, progress, cancel, save, copy, preview.
import type { FileController, FileState } from './file-mode';
import { suggestedName } from './file-mode';
import type { Sink } from './protocol';
import { renderOutput } from './render';
import { hiddenTotal, renderReport, warningTexts, type RuleLabel } from './report';
import { S, errorText, formatBytes } from './strings';

interface SaveFilePickerOptions {
  suggestedName?: string;
}

type SavePicker = (options?: SaveFilePickerOptions) => Promise<FileSystemFileHandle>;

export interface FileElements {
  input: HTMLInputElement;
  dropzone: HTMLElement;
  email: HTMLInputElement;
  privateIp: HTMLInputElement;
  lineLimit: HTMLSelectElement;
  sinkHandle: HTMLInputElement;
  sinkBlob: HTMLInputElement;
  progress: HTMLElement;
  cancel: HTMLButtonElement;
  status: HTMLElement;
  /** Polite live region: start, completion, and errors, not every progress step. */
  live: HTMLElement;
  warn: HTMLElement;
  save: HTMLAnchorElement;
  saveNote: HTMLElement;
  copy: HTMLButtonElement;
  clear: HTMLButtonElement;
  preview: HTMLElement;
  previewNote: HTMLElement;
  report: HTMLDetailsElement;
}

export class FileView {
  private controller: FileController | null = null;
  private ruleIds: readonly string[] = [];
  private lastOptions = { email: true, privateIp: false };
  private readonly picker: SavePicker | undefined;
  private bound = false;

  constructor(
    private readonly el: FileElements,
    private readonly rules: readonly RuleLabel[],
    private readonly ruleNames: Readonly<Record<string, string>>,
    writeClipboard: (text: string) => Promise<void>,
  ) {
    const candidate: unknown = Reflect.get(window, 'showSaveFilePicker');
    this.picker = typeof candidate === 'function' ? (candidate.bind(window) as SavePicker) : undefined;
    if (!this.picker) {
      el.sinkHandle.disabled = true;
      el.sinkHandle.closest('label')?.setAttribute('hidden', '');
    }
    el.preview.dataset['empty'] = 'A preview of the sanitized file appears here.';
    el.copy.addEventListener('click', () => {
      const text = this.controller?.current().copyText;
      if (text === undefined) return;
      writeClipboard(text).then(
        () => {
          el.status.textContent = S.copy.done;
          el.live.textContent = S.copy.done;
        },
        () => {
          el.status.textContent = S.copy.failed;
          el.live.textContent = S.copy.failed;
        },
      );
    });
  }

  /** Binds listeners once; a restored page (pageshow) only swaps the controller. */
  attach(controller: FileController): void {
    const first = this.controller === null && !this.bound;
    this.controller = controller;
    if (!first) return;
    this.bound = true;
    const el = this.el;
    el.input.addEventListener('change', () => {
      const file = el.input.files?.[0];
      el.input.value = '';
      if (file) void this.start(file);
    });
    el.dropzone.addEventListener('dragover', (event) => {
      event.preventDefault();
      el.dropzone.classList.add('is-over');
    });
    el.dropzone.addEventListener('dragleave', () => {
      el.dropzone.classList.remove('is-over');
    });
    el.dropzone.addEventListener('drop', (event) => {
      event.preventDefault();
      el.dropzone.classList.remove('is-over');
      const file = event.dataTransfer?.files[0];
      if (file) void this.start(file);
    });
    el.cancel.addEventListener('click', () => {
      this.controller?.cancel();
    });
    el.clear.addEventListener('click', () => {
      this.controller?.reset();
    });
    el.save.addEventListener('click', () => {
      this.controller?.saved();
    });
  }

  setRuleIds(ids: readonly string[]): void {
    this.ruleIds = ids;
  }

  private async start(file: File): Promise<void> {
    if (!this.controller) return;
    const el = this.el;
    const options = { email: el.email.checked, privateIp: el.privateIp.checked };
    this.lastOptions = options;
    const maxLineBytes = Number(el.lineLimit.value);
    let sink: Sink = 'blob';
    let handle: FileSystemFileHandle | undefined;
    if (el.sinkHandle.checked && this.picker) {
      // The destination is chosen before any processing, inside the user's gesture.
      try {
        handle = await this.picker({ suggestedName: suggestedName(file.name) });
        sink = 'handle';
      } catch {
        el.status.textContent = S.file.pickerCancelled;
        el.live.textContent = S.file.pickerCancelled;
        return;
      }
    }
    this.controller.run(file, options, maxLineBytes, sink, handle);
  }

  render(state: FileState): void {
    const el = this.el;
    const running = state.status === 'running';
    el.cancel.disabled = !running;
    el.input.disabled = running || state.status === 'unavailable';
    const percent = state.bytesTotal > 0 ? Math.floor((state.bytesDone / state.bytesTotal) * 100) : state.status === 'done' ? 100 : 0;
    el.progress.setAttribute('aria-valuenow', String(percent));
    el.progress.style.setProperty('--progress', `${percent}%`);

    el.save.hidden = state.downloadUrl === undefined;
    if (state.downloadUrl) {
      el.save.href = state.downloadUrl;
      el.save.download = state.suggestedName ?? 'sanitized.txt';
      el.save.textContent = S.file.saveLabel;
    } else {
      el.save.removeAttribute('href');
    }
    el.saveNote.hidden = state.status !== 'done';
    el.saveNote.textContent = state.savedToDisk ? S.file.savedToDisk : S.file.downloadNote;
    el.copy.disabled = state.copyText === undefined;
    el.copy.title = state.status === 'done' && state.copyText === undefined ? S.file.copyTooLarge : '';

    let text: string;
    switch (state.status) {
      case 'idle':
        text = S.file.idle;
        break;
      case 'running':
        text = S.file.progress(formatBytes(state.bytesDone), formatBytes(state.bytesTotal));
        break;
      case 'done':
        text = S.file.done(state.summary?.replacements ?? 0);
        break;
      case 'error':
        text = state.error === 'TIMEOUT' ? S.file.timeout : errorText(state.error ?? 'INTERNAL_ERROR', state.errorLine);
        break;
      case 'unavailable':
        text = S.status.unavailable;
        break;
    }
    el.status.textContent = text;
    if (state.status !== 'running' || state.bytesDone === 0) el.live.textContent = text;

    if (state.status === 'done' && state.summary && state.preview !== undefined && state.previewRanges) {
      const info = renderOutput(el.preview, state.preview, state.previewRanges, {
        badges: true,
        ruleIds: this.ruleIds,
        ruleNames: this.ruleNames,
      });
      el.previewNote.hidden = false;
      el.previewNote.textContent = info.highlighted
        ? S.file.previewNote(formatBytes(new TextEncoder().encode(state.preview).length))
        : S.highlightLimited(10_000);
      const warnings = warningTexts(state.summary);
      const hidden = hiddenTotal(state.summary);
      if (hidden > 0) warnings.unshift(S.hidden(hidden));
      el.warn.hidden = warnings.length === 0;
      el.warn.textContent = warnings.join(' ');
      el.report.hidden = false;
      const body = el.report.querySelector('.report__body');
      if (body instanceof HTMLElement) renderReport(body, state.summary, this.rules, this.lastOptions);
    } else {
      el.preview.replaceChildren();
      el.previewNote.hidden = true;
      el.warn.hidden = true;
      el.report.hidden = true;
    }
  }
}
