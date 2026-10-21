// Post-build checks (TRD §10.8): exactly one entry script, one stylesheet, and one worker; SRI
// hashes that match the files on disk; the meta CSP equal to the header policy minus
// frame-ancestors; no separate .wasm file; the product mark as favicon; no framework default icon.
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const web = resolve(fileURLToPath(new URL('..', import.meta.url)));
const dist = join(web, 'dist');
const html = readFileSync(join(dist, 'index.html'), 'utf8');
const failures = [];
const check = (ok, message) => {
  if (!ok) failures.push(message);
};

const assets = readdirSync(join(dist, 'assets'));
const count = (re) => assets.filter((f) => re.test(f)).length;
check(count(/^app-.*\.js$/) === 1, 'expected exactly one app-*.js');
check(count(/^worker-.*\.js$/) === 1, 'expected exactly one worker-*.js');
check(count(/\.css$/) === 1, 'expected exactly one stylesheet');
check(count(/\.wasm$/) === 0, 'the engine must be embedded in the worker, not a separate .wasm file');
check(assets.length === 3, `unexpected assets: ${assets.join(', ')}`);

const tags = [...html.matchAll(/<(script|link)\b[^>]*>/g)].map((m) => m[0]);
const referenced = tags.filter((t) => /assets\//.test(t));
check(referenced.length === 2, 'index.html must reference exactly the entry script and the stylesheet');
for (const tag of referenced) {
  const url = /(?:src|href)="\.\/([^"]+)"/.exec(tag)?.[1];
  const integrity = /integrity="sha384-([^"]+)"/.exec(tag)?.[1];
  if (!url || !integrity) {
    failures.push(`missing integrity: ${tag}`);
    continue;
  }
  const actual = createHash('sha384').update(readFileSync(join(dist, url))).digest('base64');
  check(actual === integrity, `integrity mismatch for ${url}`);
}

const { routes } = JSON.parse(readFileSync(join(web, 'hosting', 'headers.json'), 'utf8'));
const csp = routes.find((r) => r.match.includes('/')).headers['Content-Security-Policy'];
const expected = csp
  .split(';')
  .map((d) => d.trim())
  .filter((d) => d && !d.startsWith('frame-ancestors'))
  .join('; ');
const meta = /<meta http-equiv="Content-Security-Policy" content="([^"]+)">/.exec(html)?.[1];
check(meta === expected, 'meta CSP differs from hosting/headers.json');

check(/<link rel="icon" href="\.\/spymonk-mark\.svg" type="image\/svg\+xml">/.test(html), 'favicon must be the product mark');
check(!/vite\.svg|vercel|next\.svg/i.test(html), 'framework default icon referenced');
check(!/%[A-Z_]+%/.test(html), 'unreplaced build token in index.html');
check(!html.includes('<!-- @rules -->'), 'rules section was not generated');
const worker = readFileSync(join(dist, 'assets', assets.find((f) => f.startsWith('worker-'))), 'utf8');
check(!/\bfetch\(/.test(worker), 'the worker bundle must not call fetch');

if (failures.length > 0) {
  console.error(`dist verification failed:\n- ${failures.join('\n- ')}`);
  process.exit(1);
}
console.log('dist verified: single entry, single stylesheet, embedded engine, SRI, meta CSP, favicon');
