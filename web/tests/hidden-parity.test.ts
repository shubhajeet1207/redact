// The page's hidden-character table must match the engine's census for every code point, so
// the browser marks exactly what the CLI marks (TRD §9.5).
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { expect, it } from 'vitest';

import { hiddenKind as engineKind, initSync } from '../wasm-pkg/engine.js';
import { hiddenKind } from '../src/hidden';

const CODES = { bidi: 1, invisible: 2, control: 3 } as const;

it('matches the engine on all 1,114,112 code points', () => {
  initSync({ module: readFileSync(fileURLToPath(new URL('../wasm-pkg/engine_bg.wasm', import.meta.url))) });
  const mismatches: string[] = [];
  for (let cp = 0; cp <= 0x10ffff; cp++) {
    const page = hiddenKind(cp);
    const expected = page === null ? 0 : CODES[page];
    // Line separators never reach the census: the framer removes them.
    if (cp === 0x0a || cp === 0x0d) continue;
    if (engineKind(cp) !== expected) mismatches.push(cp.toString(16));
    if (mismatches.length > 10) break;
  }
  expect(mismatches).toEqual([]);
});
