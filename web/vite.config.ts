// Build configuration (TRD §10.8): one main-thread ES module and one stylesheet, both carrying
// Subresource Integrity; the WebAssembly bytes embedded in the hashed worker script; no
// module-preload polyfill (it uses fetch); the header CSP embedded as a meta tag for self-hosting.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { defineConfig, type Plugin } from 'vite';

import { renderRules, type RulesDoc } from './scripts/render-rules';

const here = (path: string): string => fileURLToPath(new URL(path, import.meta.url));

interface HeaderRoute {
  match: string[];
  headers: Record<string, string>;
}

function readJson(path: string): unknown {
  return JSON.parse(readFileSync(here(path), 'utf8'));
}

function toolVersion(): string {
  const manifest = readFileSync(here('../Cargo.toml'), 'utf8');
  const match = /\[workspace\.package\][^[]*?\nversion\s*=\s*"([^"]+)"/.exec(manifest);
  if (!match?.[1]) throw new Error('workspace version not found in Cargo.toml');
  return match[1];
}

function commit(): string {
  // CI passes the commit explicitly; locally fall back to git, or say that there is none.
  const fromEnv = process.env['SOURCE_COMMIT'];
  if (fromEnv) return fromEnv.slice(0, 12);
  try {
    return execFileSync('git', ['rev-parse', '--short=12', 'HEAD'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
  } catch {
    return 'uncommitted';
  }
}

/** `virtual:spymonk-wasm` resolves to the engine bytes as base64, so no fetch is needed. */
function embedWasm(): Plugin {
  const id = 'virtual:spymonk-wasm';
  return {
    name: 'spymonk-embed-wasm',
    resolveId: (source) => (source === id ? `\0${id}` : null),
    load(loaded) {
      if (loaded !== `\0${id}`) return null;
      const bytes = readFileSync(here('wasm-pkg/engine_bg.wasm'));
      return `export default ${JSON.stringify(bytes.toString('base64'))};`;
    },
  };
}

/** Fills the build-identity tokens and the generated Rules section into index.html. */
function pageContent(info: Record<string, string>, rules: RulesDoc): Plugin {
  return {
    name: 'spymonk-page-content',
    transformIndexHtml: {
      order: 'pre',
      handler: (html) =>
        html
          .replace('<!-- @rules -->', renderRules(rules))
          .replace(/%(TOOL_VERSION|RULES_VERSION|RULES_SHA256|RULES_SHA256_SHORT|COMMIT)%/g, (_, key: string) => {
            const value = info[key];
            if (value === undefined) throw new Error(`unknown token ${key}`);
            return value;
          }),
    },
  };
}

/** Embeds the page CSP from hosting/headers.json; meta tags cannot carry frame-ancestors. */
function metaCsp(): Plugin {
  const routes = (readJson('hosting/headers.json') as { routes: HeaderRoute[] }).routes;
  const csp = routes.find((r) => r.match.includes('/'))?.headers['Content-Security-Policy'];
  if (!csp) throw new Error('page CSP missing from hosting/headers.json');
  const meta = csp
    .split(';')
    .map((d) => d.trim())
    .filter((d) => d !== '' && !d.startsWith('frame-ancestors'))
    .join('; ');
  return {
    name: 'spymonk-meta-csp',
    apply: 'build',
    transformIndexHtml: {
      order: 'post',
      handler: (html) =>
        html.replace(
          '<meta charset="utf-8">',
          `<meta charset="utf-8">\n    <meta http-equiv="Content-Security-Policy" content="${meta}">`,
        ),
    },
  };
}

/** Adds sha384 integrity to the entry script and stylesheet (TRD §10.8, T-10). */
function subresourceIntegrity(): Plugin {
  return {
    name: 'spymonk-sri',
    apply: 'build',
    enforce: 'post',
    transformIndexHtml: {
      order: 'post',
      handler(html, ctx) {
        const bundle = ctx.bundle;
        if (!bundle) return html;
        return html.replace(/<(script|link)\b[^>]*>/g, (tag) => {
          const url = /\s(?:src|href)="([^"]+)"/.exec(tag)?.[1];
          if (!url || (tag.startsWith('<link') && !tag.includes('rel="stylesheet"'))) return tag;
          const output = bundle[url.replace(/^\.?\//, '')];
          if (!output) return tag;
          const source = output.type === 'chunk' ? output.code : output.source;
          const digest = createHash('sha384').update(source).digest('base64');
          return tag.replace(/\s*>$/, ` integrity="sha384-${digest}">`);
        });
      },
    },
  };
}

const rules = readJson('src/generated/rules.json') as RulesDoc;
const info = {
  TOOL_VERSION: toolVersion(),
  RULES_VERSION: rules.ruleVersion,
  RULES_SHA256: rules.sha256,
  RULES_SHA256_SHORT: rules.sha256.slice(0, 12),
  COMMIT: commit(),
};

export default defineConfig({
  base: './',
  define: {
    __BUILD_INFO__: JSON.stringify(info),
  },
  plugins: [pageContent(info, rules), metaCsp(), subresourceIntegrity()],
  worker: {
    format: 'es',
    plugins: () => [embedWasm()],
    rollupOptions: {
      output: { entryFileNames: 'assets/worker-[hash].js' },
    },
  },
  build: {
    target: 'es2022',
    outDir: 'dist',
    emptyOutDir: true,
    cssCodeSplit: false,
    // data: URIs are blocked by img-src 'self'; keep every asset a same-origin file.
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
    sourcemap: false,
    rollupOptions: {
      output: {
        entryFileNames: 'assets/app-[hash].js',
        chunkFileNames: 'assets/chunk-[hash].js',
        assetFileNames: 'assets/[name]-[hash][extname]',
      },
    },
  },
  server: {
    // The dev server never sets the production headers; `npm run serve` does.
    fs: { allow: ['..'] },
  },
});
