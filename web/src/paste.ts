// Paste-mode view: wires the editor, toggles, samples, Copy, and Clear to the controller and
// renders its state. The editor's value is never rewritten by results, so focus and caret stay put.
import type { PasteController, PasteState } from './controller';
import { renderOutput } from './render';
import { hiddenTotal, renderReport, warningTexts, type RuleLabel } from './report';
import { SAMPLES } from './samples';
import { S, errorText } from './strings';

export interface PasteElements {
  input: HTMLTextAreaElement;
  output: HTMLElement;
  notice: HTMLElement;
  status: HTMLElement;
  /** Polite live region: completed updates only, never keystrokes (TRD §10.7). */
  live: HTMLElement;
  hidden: HTMLElement;
  copy: HTMLButtonElement;
  clear: HTMLButtonElement;
  email: HTMLInputElement;
  privateIp: HTMLInputElement;
  badges: HTMLInputElement;
  sample: HTMLSelectElement;
  loadSample: HTMLButtonElement;
  report: HTMLDetailsElement;
  confirm: HTMLDialogElement;
}

export class PasteView {
  private controller: PasteController | null = null;
  private last: PasteState | null = null;
  private ruleIds: readonly string[] = [];
  /** The sample text last loaded, to tell an untouched sample from edited input. */
  private loaded: string | null = null;
  private announced = '';
  private bound = false;

  constructor(
    private readonly el: PasteElements,
    private readonly rules: readonly RuleLabel[],
    private readonly ruleNames: Readonly<Record<string, string>>,
  ) {
    el.output.dataset['empty'] = 'Sanitized text appears here.';
    for (const sample of SAMPLES) {
      const option = document.createElement('option');
      option.value = sample.id;
      option.textContent = sample.label;
      el.sample.appendChild(option);
    }
  }

  /** Binds listeners once; a restored page (pageshow) only swaps the controller. */
  attach(controller: PasteController): void {
    const first = this.controller === null && !this.bound;
    this.controller = controller;
    if (!first) return;
    this.bound = true;
    const el = this.el;
    el.input.addEventListener('input', () => {
      this.controller?.setText(el.input.value);
    });
    const options = (): void => {
      this.controller?.setOptions({ email: el.email.checked, privateIp: el.privateIp.checked });
    };
    el.email.addEventListener('change', options);
    el.privateIp.addEventListener('change', options);
    el.badges.addEventListener('change', () => {
      if (this.last) this.render(this.last);
    });
    el.loadSample.addEventListener('click', () => {
      void this.loadSample();
    });
    el.copy.addEventListener('click', () => {
      void this.copy();
    });
    el.clear.addEventListener('click', () => {
      this.clear();
    });
  }

  setRuleIds(ids: readonly string[]): void {
    this.ruleIds = ids;
  }

  /** Clears the editor and restores defaults (Clear, and pagehide). */
  clear(): void {
    const el = this.el;
    el.input.value = '';
    el.email.checked = true;
    el.privateIp.checked = false;
    el.badges.checked = true;
    this.loaded = null;
    this.controller?.clear();
  }

  render(state: PasteState): void {
    this.last = state;
    const el = this.el;
    el.input.disabled = !state.inputEnabled;
    el.loadSample.disabled = !state.inputEnabled;
    el.copy.disabled = !state.canCopy;
    el.email.checked = state.options.email;
    el.privateIp.checked = state.options.privateIp;

    const result = state.result;
    if (result) {
      const info = renderOutput(el.output, result.output, result.ranges, {
        badges: el.badges.checked,
        ruleIds: this.ruleIds,
        ruleNames: this.ruleNames,
      });
      this.note(info.highlighted ? null : S.highlightLimited(10_000));
      const hidden = hiddenTotal(result.summary);
      const warnings = [...warningTexts(result.summary)];
      if (hidden > 0) warnings.unshift(S.hidden(hidden));
      el.hidden.hidden = warnings.length === 0;
      el.hidden.textContent = warnings.join(' ');
      el.report.hidden = false;
      const body = el.report.querySelector('.report__body');
      if (body instanceof HTMLElement) renderReport(body, result.summary, this.rules, result.options);
    } else {
      el.output.replaceChildren();
      el.hidden.hidden = true;
      this.note(null);
      el.report.hidden = true;
    }
    this.status(state);
  }

  private note(text: string | null): void {
    this.el.notice.hidden = text === null;
    this.el.notice.textContent = text ?? '';
  }

  /** The live region announces completed updates only, never keystrokes (TRD §10.7). */
  private status(state: PasteState): void {
    let text: string;
    let announce = true;
    switch (state.status) {
      case 'initializing':
        text = S.status.initializing;
        break;
      case 'empty':
        text = S.status.empty;
        break;
      case 'pending':
        text = S.status.pending;
        announce = false;
        break;
      case 'ready': {
        const n = state.result?.summary.replacements ?? 0;
        text = n === 0 ? S.status.none : S.status.some(n);
        break;
      }
      case 'error':
        if (state.error === 'TIMEOUT') text = S.status.timeout;
        else text = errorText(state.error ?? 'INTERNAL_ERROR', state.errorLine);
        break;
      case 'unavailable':
        text = state.error === 'RULES_MISMATCH' ? S.status.rulesMismatch : S.status.unavailable;
        break;
    }
    this.el.status.textContent = text;
    if (announce && text !== this.announced) {
      this.el.live.textContent = text;
      this.announced = text;
    } else if (!announce) {
      // A later completed update must be announced even if its text repeats.
      this.announced = '';
    }
  }

  private async loadSample(): Promise<void> {
    const sample = SAMPLES.find((s) => s.id === this.el.sample.value);
    if (!sample || !this.controller) return;
    const current = this.el.input.value;
    const edited = current !== '' && current !== this.loaded;
    if (edited && !(await this.confirm())) return;
    this.el.input.value = sample.text;
    this.loaded = sample.text;
    this.controller.setText(sample.text);
    this.el.input.focus();
  }

  private confirm(): Promise<boolean> {
    const dialog = this.el.confirm;
    return new Promise((resolve) => {
      const onClick = (event: Event): void => {
        const target = event.target;
        if (!(target instanceof HTMLButtonElement)) return;
        const choice = target.dataset['choice'];
        if (choice === 'replace' || choice === 'cancel') dialog.close(choice);
      };
      const onClose = (): void => {
        dialog.removeEventListener('click', onClick);
        dialog.removeEventListener('close', onClose);
        resolve(dialog.returnValue === 'replace');
      };
      dialog.returnValue = '';
      dialog.addEventListener('click', onClick);
      dialog.addEventListener('close', onClose);
      dialog.showModal();
    });
  }

  private async copy(): Promise<void> {
    if (!this.controller) return;
    const outcome = await this.controller.copy();
    const text =
      outcome === 'copied'
        ? S.copy.done
        : outcome === 'failed'
          ? S.copy.failed
          : outcome === 'superseded'
            ? S.copy.stale
            : null;
    if (text) {
      this.el.status.textContent = text;
      this.el.live.textContent = text;
      this.announced = text;
    }
  }
}
