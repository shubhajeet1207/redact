// Builds the engine for the browser worker (TRD §4 build commands): cargo, then wasm-bindgen
// --target web, then wasm-opt -Oz. Output goes to web/wasm-pkg/ (generated, not committed).
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const WASM_BINDGEN_VERSION = '0.2.129';
const MAX_MEMORY_PAGES = 8192; // 512 MiB in 64 KiB pages (TRD §11.2)

const web = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const root = resolve(web, '..');
const out = join(web, 'wasm-pkg');
const built = join(root, 'target', 'wasm32-unknown-unknown', 'release', 'spymonk_redact_wasm.wasm');

function run(command, args, options = {}) {
  execFileSync(command, args, { stdio: 'inherit', cwd: root, ...options });
}

run('cargo', [
  'build',
  '--locked',
  '--release',
  '-p',
  'spymonk-redact-wasm',
  '--target',
  'wasm32-unknown-unknown',
]);

const version = execFileSync('wasm-bindgen', ['--version'], { encoding: 'utf8' }).trim();
if (version !== `wasm-bindgen ${WASM_BINDGEN_VERSION}`) {
  throw new Error(
    `found "${version}"; install the pinned CLI: cargo install wasm-bindgen-cli --version ${WASM_BINDGEN_VERSION} --locked`,
  );
}

rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });
run('wasm-bindgen', ['--target', 'web', '--out-dir', out, '--out-name', 'engine', built]);

// The worker instantiates from embedded bytes with initSync. Remove the glue's default
// `new URL('engine_bg.wasm', import.meta.url)`, so the bundler emits no separate .wasm file and
// no fetch path stays reachable (connect-src is 'none').
const glue = join(out, 'engine.js');
const defaultUrl = "module_or_path = new URL('engine_bg.wasm', import.meta.url);";
const source = readFileSync(glue, 'utf8');
if (source.split(defaultUrl).length !== 2) throw new Error('wasm-bindgen glue changed: default URL not found once');
writeFileSync(glue, source.replace(defaultUrl, "throw new Error('the engine is embedded; use initSync');"));

const wasm = join(out, 'engine_bg.wasm');
run(process.execPath, [
  join(web, 'node_modules', 'binaryen', 'bin', 'wasm-opt'),
  wasm,
  '-Oz',
  '--enable-bulk-memory',
  '--enable-mutable-globals',
  '--enable-nontrapping-float-to-int',
  '--enable-sign-ext',
  '--enable-reference-types',
  '--enable-multivalue',
  '-o',
  wasm,
]);

// Fail the build if the memory cap did not survive linking and optimization.
const max = maxMemoryPages(readFileSync(wasm));
if (max !== MAX_MEMORY_PAGES) {
  throw new Error(`engine_bg.wasm maximum memory is ${String(max)} pages; expected ${MAX_MEMORY_PAGES}`);
}
console.log(`wasm-pkg ready: ${String(readFileSync(wasm).length)} bytes, max memory ${MAX_MEMORY_PAGES} pages`);

/** Reads the maximum page count of the module's memory, defined or imported. */
function maxMemoryPages(bytes) {
  let pos = 8;
  const leb = () => {
    let result = 0;
    let shift = 0;
    for (;;) {
      const b = bytes[pos++];
      result += (b & 0x7f) * 2 ** shift;
      if ((b & 0x80) === 0) return result;
      shift += 7;
    }
  };
  const limits = () => {
    const flags = bytes[pos++];
    leb();
    return flags & 1 ? leb() : undefined;
  };
  while (pos < bytes.length) {
    const id = bytes[pos++];
    const size = leb();
    const end = pos + size;
    if (id === 5) {
      leb(); // count
      return limits();
    }
    if (id === 2) {
      const count = leb();
      for (let i = 0; i < count; i++) {
        pos += leb(); // module name
        pos += leb(); // field name
        const kind = bytes[pos++];
        if (kind === 2) return limits();
        if (kind === 0) leb();
        else if (kind === 1) {
          pos++;
          limits();
        } else if (kind === 3) pos += 2;
        else if (kind === 4) {
          pos++;
          leb();
        }
      }
    }
    pos = end;
  }
  return undefined;
}
