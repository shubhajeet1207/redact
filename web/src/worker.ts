// Worker bootstrap (TRD §10.5, §10.8). The engine bytes are embedded in this hashed script, so
// instantiation needs no fetch; the worker's CSP allows only 'wasm-unsafe-eval' for compilation.
import wasmBase64 from 'virtual:spymonk-wasm';

import {
  FileJob,
  initSync,
  ruleIds,
  rulesSha256,
  rulesVersion,
  sanitizePaste,
  toolVersion,
} from '../wasm-pkg/engine.js';
import { WorkerCore, type Engine } from './worker-core';

declare const self: DedicatedWorkerGlobalScope;

function decodeBase64(text: string): Uint8Array {
  const binary = atob(text);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

initSync({ module: decodeBase64(wasmBase64) });

// Named imports only: the glue's unused fetch-based initializer is then dropped from the bundle.
const engine: Engine = { FileJob, ruleIds, rulesSha256, rulesVersion, sanitizePaste, toolVersion };

const core = new WorkerCore(engine, (message, transfer) => {
  self.postMessage(message, transfer ?? []);
});

self.onmessage = (event: MessageEvent<unknown>) => {
  void core.handle(event.data);
};
