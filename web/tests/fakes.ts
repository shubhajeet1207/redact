import type { Clock, WorkerLike } from '../src/controller';
import type { PageMessage } from '../src/protocol';

export class FakeWorker implements WorkerLike {
  sent: PageMessage[] = [];
  terminated = false;
  onmessage: ((event: MessageEvent<unknown>) => void) | null = null;
  onerror: ((event: Event) => void) | null = null;

  postMessage(message: PageMessage): void {
    this.sent.push(message);
  }

  terminate(): void {
    this.terminated = true;
  }

  reply(data: unknown): void {
    this.onmessage?.({ data } as MessageEvent<unknown>);
  }

  pastes(): Extract<PageMessage, { type: 'paste' }>[] {
    return this.sent.filter((m): m is Extract<PageMessage, { type: 'paste' }> => m.type === 'paste');
  }
}

/** A manual clock: timers fire only when `advance` passes their due time. */
export class FakeClock implements Clock {
  private now = 0;
  private next = 1;
  private timers = new Map<number, { at: number; fn: () => void }>();

  setTimeout(fn: () => void, ms: number): number {
    const id = this.next++;
    this.timers.set(id, { at: this.now + ms, fn });
    return id;
  }

  clearTimeout(id: number): void {
    this.timers.delete(id);
  }

  advance(ms: number): void {
    const end = this.now + ms;
    for (;;) {
      const due = [...this.timers.entries()].filter(([, t]) => t.at <= end).sort((a, b) => a[1].at - b[1].at)[0];
      if (!due) break;
      this.timers.delete(due[0]);
      this.now = due[1].at;
      due[1].fn();
    }
    this.now = end;
  }
}
