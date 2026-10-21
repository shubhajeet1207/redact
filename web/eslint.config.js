// TRD §10.6: input-derived content enters the DOM only through text nodes and form values. These
// bans make string-to-HTML sinks, dynamic code, storage, and network APIs a lint error; Trusted
// Types (CSP) turns any regression into a runtime failure as well.
import js from '@eslint/js';
import tseslint from 'typescript-eslint';

const htmlSinks = ['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'srcdoc'].map((property) => ({
  property,
  message: 'TRD §10.6: build DOM with createElement and textContent.',
}));

export default tseslint.config(
  { ignores: ['dist', 'wasm-pkg', 'node_modules', 'test-results', 'playwright-report'] },
  js.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        project: ['./tsconfig.json', './tsconfig.worker.json', './tsconfig.node.json'],
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      'no-restricted-properties': [
        'error',
        ...htmlSinks,
        { object: 'document', property: 'write', message: 'TRD §10.6: no document.write.' },
        { object: 'document', property: 'writeln', message: 'TRD §10.6: no document.writeln.' },
        { object: 'window', property: 'localStorage', message: 'TRD §10.8: no client storage.' },
        { object: 'window', property: 'sessionStorage', message: 'TRD §10.8: no client storage.' },
        { object: 'window', property: 'indexedDB', message: 'TRD §10.8: no client storage.' },
        { object: 'window', property: 'caches', message: 'TRD §10.8: no Cache API.' },
        { object: 'document', property: 'cookie', message: 'TRD §10.8: no cookies.' },
        { object: 'navigator', property: 'sendBeacon', message: 'TRD §11.1 T-08: no network.' },
      ],
      'no-restricted-globals': [
        'error',
        { name: 'eval', message: 'TRD §10.6: no dynamic code.' },
        { name: 'Function', message: 'TRD §10.6: no dynamic code.' },
        { name: 'fetch', message: 'TRD §11.1 T-08: connect-src is none.' },
        { name: 'XMLHttpRequest', message: 'TRD §11.1 T-08: connect-src is none.' },
        { name: 'WebSocket', message: 'TRD §11.1 T-08: connect-src is none.' },
        { name: 'EventSource', message: 'TRD §11.1 T-08: connect-src is none.' },
        { name: 'localStorage', message: 'TRD §10.8: no client storage.' },
        { name: 'sessionStorage', message: 'TRD §10.8: no client storage.' },
        { name: 'indexedDB', message: 'TRD §10.8: no client storage.' },
        { name: 'caches', message: 'TRD §10.8: no Cache API.' },
      ],
      'no-restricted-syntax': [
        'error',
        {
          selector: "CallExpression[callee.name=/^set(Timeout|Interval)$/][arguments.0.type='Literal']",
          message: 'TRD §10.6: no string timers.',
        },
        {
          selector: "NewExpression[callee.name='Function']",
          message: 'TRD §10.6: no dynamic code.',
        },
      ],
      'no-implied-eval': 'off',
      '@typescript-eslint/no-implied-eval': 'error',
      '@typescript-eslint/restrict-template-expressions': ['error', { allowNumber: true }],
    },
  },
  {
    // Plain JavaScript build scripts run in Node and carry no type information.
    files: ['**/*.js', '**/*.mjs'],
    ...tseslint.configs.disableTypeChecked,
    languageOptions: {
      ...tseslint.configs.disableTypeChecked.languageOptions,
      globals: { process: 'readonly', console: 'readonly', URL: 'readonly' },
    },
  },
  {
    files: ['eslint.config.js', 'scripts/*.mjs', 'scripts/*.ts', 'vite.config.ts', 'vitest.config.ts', 'playwright.config.ts', 'e2e/**', 'tests/**'],
    rules: {
      // Build tooling and tests run in Node or the test runner, not in the shipped page.
      'no-restricted-globals': 'off',
      'no-restricted-properties': 'off',
      '@typescript-eslint/no-non-null-assertion': 'off',
    },
  },
);
