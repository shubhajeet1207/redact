// Serves dist/ on 127.0.0.1 with the response headers from hosting/headers.json, so local
// previews and browser tests run under the production policy (TRD §11.3).
// Usage: node scripts/serve.mjs [port]
import { createServer } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { extname, join, normalize, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const web = resolve(fileURLToPath(new URL('..', import.meta.url)));
const dist = join(web, 'dist');
const { routes } = JSON.parse(await readFile(join(web, 'hosting', 'headers.json'), 'utf8'));
const port = Number(process.argv[2] ?? 4173);

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.txt': 'text/plain; charset=utf-8',
  '.json': 'application/json',
};

function glob(pattern) {
  const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '[^/]*');
  return new RegExp(`^${escaped}$`);
}

const compiled = routes.map((r) => ({ tests: r.match.map(glob), headers: r.headers }));

export function headersFor(path) {
  return compiled.find((r) => r.tests.some((t) => t.test(path)))?.headers ?? {};
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', 'http://localhost');
  const path = url.pathname === '/' ? '/index.html' : decodeURIComponent(url.pathname);
  const file = normalize(join(dist, path));
  if (!file.startsWith(dist + sep) || (req.method !== 'GET' && req.method !== 'HEAD')) {
    res.writeHead(404).end();
    return;
  }
  try {
    if (!(await stat(file)).isFile()) throw new Error('not a file');
    const body = await readFile(file);
    res.writeHead(200, {
      'Content-Type': TYPES[extname(file)] ?? 'application/octet-stream',
      'Content-Length': body.length,
      ...headersFor(url.pathname),
    });
    res.end(req.method === 'HEAD' ? undefined : body);
  } catch {
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8', ...headersFor('/404') }).end('Not found');
  }
});

server.listen(port, '127.0.0.1', () => {
  console.log(`serving dist/ with production headers at http://127.0.0.1:${port}/`);
});
