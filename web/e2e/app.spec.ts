// TRD §19.7–§19.8 browser checks against the built site served with the production headers.
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';

import { expect, test, type Page } from '@playwright/test';

const ORIGIN = 'http://127.0.0.1:4173';

/** Records CSP violations and console errors from the first script onwards. */
async function watch(page: Page): Promise<{ violations: string[]; errors: string[]; requests: string[] }> {
  const record = { violations: [] as string[], errors: [] as string[], requests: [] as string[] };
  page.on('console', (msg) => {
    if (msg.type() === 'error') record.errors.push(msg.text());
  });
  page.on('pageerror', (err) => record.errors.push(err.message));
  page.on('request', (req) => record.requests.push(req.url()));
  await page.exposeFunction('__cspViolation', (text: string) => record.violations.push(text));
  await page.addInitScript(() => {
    document.addEventListener('securitypolicyviolation', (e) => {
      (window as unknown as { __cspViolation: (t: string) => void }).__cspViolation(
        `${e.violatedDirective} ${e.blockedURI}`,
      );
    });
  });
  return record;
}

async function ready(page: Page): Promise<void> {
  await page.goto('/');
  await expect(page.locator('#paste-input')).toBeEnabled({ timeout: 15_000 });
}

test('paste mode redacts under the production CSP with Trusted Types enforced', async ({ page }) => {
  const record = await watch(page);
  await ready(page);
  await page.locator('#paste-input').fill('password=hunter2 user=alex@example.com path=/home/alex/app');
  await expect(page.locator('#paste-status')).toHaveText('3 replacements — review before sharing');
  await expect(page.locator('#paste-output')).toHaveText(
    'password=[REDACTED] user=[EMAIL REDACTED] path=/home/[USER]/app',
  );
  await expect(page.locator('#paste-output mark.ph')).toHaveCount(3);
  await expect(page.locator('#copy')).toBeEnabled();
  expect(record.violations).toEqual([]);
  expect(record.errors).toEqual([]);
});

test('editing invalidates the result and Copy follows the current revision', async ({ page }) => {
  await ready(page);
  const input = page.locator('#paste-input');
  await input.fill('token=abc');
  await expect(page.locator('#paste-output')).toHaveText('token=[REDACTED]');
  await input.press('End');
  await input.pressSequentially(' x');
  // Synchronously after the edit, the old result is gone and Copy is disabled.
  await expect(page.locator('#copy')).toBeDisabled();
  await expect(page.locator('#paste-output')).toHaveText('token=[REDACTED] x');
  await expect(page.locator('#copy')).toBeEnabled();
});

test('hidden characters render as badges and the toggle restores raw text', async ({ page }) => {
  await ready(page);
  await page.locator('#paste-input').fill('abc‮def');
  await expect(page.locator('#paste-output .badge')).toHaveText('⟨U+202E⟩');
  await expect(page.locator('#paste-hidden')).toBeVisible();
  await page.locator('#opt-badges').uncheck();
  await expect(page.locator('#paste-output .badge')).toHaveCount(0);
});

test('input-derived markup is never interpreted', async ({ page }) => {
  const record = await watch(page);
  await ready(page);
  const payload = '<img src=x onerror="window.__pwned=1"><script>window.__pwned=2</script>';
  await page.locator('#paste-input').fill(payload);
  await expect(page.locator('#paste-output')).toHaveText(payload);
  await expect(page.locator('#paste-output img, #paste-output script')).toHaveCount(0);
  expect(await page.evaluate(() => (window as unknown as { __pwned?: number }).__pwned)).toBeUndefined();
  expect(record.errors).toEqual([]);
});

test('no network beyond the page’s own assets and no client storage', async ({ page }) => {
  const record = await watch(page);
  await ready(page);
  await page.locator('#paste-input').fill('Authorization: Bearer fake-token-1');
  await expect(page.locator('#paste-status')).toHaveText('1 replacement — review before sharing');
  for (const url of record.requests) {
    expect(url.startsWith(`${ORIGIN}/`), url).toBe(true);
    expect(url).toMatch(/\/(index\.html)?$|\/assets\/(app|worker|style)-[\w-]+\.(js|css)$|\/spymonk-mark\.svg$/);
  }
  const storage = await page.evaluate(async () => ({
    local: localStorage.length,
    session: sessionStorage.length,
    cookie: document.cookie,
    databases: (await indexedDB.databases()).length,
    caches: (await caches.keys()).length,
  }));
  expect(storage).toEqual({ local: 0, session: 0, cookie: '', databases: 0, caches: 0 });
});

test('loading a sample over edited input asks first', async ({ page }) => {
  await ready(page);
  await page.locator('#paste-input').fill('my own text');
  await page.locator('#load-sample').click();
  await expect(page.locator('#confirm-sample')).toBeVisible();
  await page.locator('#confirm-sample [data-choice="cancel"]').click();
  await expect(page.locator('#paste-input')).toHaveValue('my own text');
  await page.locator('#load-sample').click();
  await page.locator('#confirm-sample [data-choice="replace"]').click();
  await expect(page.locator('#paste-input')).toHaveValue(/Authorization: Bearer/);
  await expect(page.locator('#paste-status')).toHaveText(/replacements — review before sharing/);
});

test('file mode sanitizes a local file and offers the sanitized result', async ({ page }) => {
  const record = await watch(page);
  await ready(page);
  await page.locator('#tab-file').click();
  await page.locator('#file-input').setInputFiles({
    name: 'app.log',
    mimeType: 'text/plain',
    buffer: Buffer.from('ok\npassword=fake-one\nCookie: sid=fake-two\n'),
  });
  await expect(page.locator('#file-status')).toHaveText('Done: 2 replacements — review before sharing');
  await expect(page.locator('#file-preview')).toHaveText('ok\npassword=[REDACTED]\nCookie: sid=[REDACTED]\n');
  const save = page.locator('#file-save');
  await expect(save).toBeVisible();
  await expect(save).toHaveAttribute('download', 'app.redacted.log');
  const [download] = await Promise.all([page.waitForEvent('download'), save.click()]);
  const path = await download.path();
  expect(readFileSync(path, 'utf8')).toBe('ok\npassword=[REDACTED]\nCookie: sid=[REDACTED]\n');
  expect(record.violations).toEqual([]);
  expect(record.errors).toEqual([]);
});

test('no horizontal page overflow at 320 px', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 800 });
  await ready(page);
  await page.locator('#paste-input').fill(`token=${'x'.repeat(400)} ${'y'.repeat(400)}`);
  await expect(page.locator('#paste-status')).toHaveText(/review before sharing/);
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  expect(overflow).toBeLessThanOrEqual(0);
});

test.describe('accessibility', () => {
  // axe-core is injected through the debugging protocol, so only this context bypasses the CSP.
  test.use({ bypassCSP: true });

  for (const scheme of ['light', 'dark'] as const) {
    test(`axe-core finds no WCAG 2.2 AA violations (${scheme})`, async ({ page }) => {
      await page.emulateMedia({ colorScheme: scheme });
      await ready(page);
      await page.locator('#paste-input').fill('password=hunter2 ‮ alex@example.com');
      await expect(page.locator('#paste-status')).toHaveText(/review before sharing/);
      const require = createRequire(import.meta.url);
      // Evaluated through the automation protocol: a script tag would itself be blocked by
      // Trusted Types, which WebKit enforces even when CSP is bypassed.
      await page.evaluate(readFileSync(require.resolve('axe-core/axe.min.js'), 'utf8'));
      const results = await page.evaluate(async () => {
        const axe = (window as unknown as { axe: { run: (o: object) => Promise<{ violations: { id: string; nodes: { target: string[] }[] }[] }> } }).axe;
        const r = await axe.run({ runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa'] } });
        return r.violations.map((v) => `${v.id}: ${v.nodes.map((n) => n.target.join(' ')).join(', ')}`);
      });
      expect(results).toEqual([]);
    });
  }
});

test('Trusted Types turn any string-to-HTML sink into an error (T-06)', async ({ page }) => {
  await ready(page);
  const outcome = await page.evaluate(() => {
    try {
      document.body.innerHTML = '<b>x</b>';
      return 'assigned';
    } catch (e) {
      return e instanceof TypeError ? 'blocked' : 'other';
    }
  });
  expect(outcome).toBe('blocked');
});

test('the production headers are served', async ({ request }) => {
  const page = await request.get('/');
  const csp = page.headers()['content-security-policy'] ?? '';
  expect(csp).toContain("connect-src 'none'");
  expect(csp).toContain("frame-ancestors 'none'");
  expect(csp).toContain('trusted-types spymonk-worker');
  expect(page.headers()['cross-origin-embedder-policy']).toBe('require-corp');
  const html = await page.text();
  const app = /assets\/app-[\w-]+\.js/.exec(html)?.[0] ?? '';
  // The app module refers to the worker relative to its own assets/ directory.
  const worker = /worker-[\w-]+\.js/.exec(await (await request.get(app)).text())?.[0];
  expect(worker).toBeTruthy();
  const workerCsp = (await request.get(`assets/${worker ?? ''}`)).headers()['content-security-policy'] ?? '';
  expect(workerCsp).toContain("'wasm-unsafe-eval'");
  expect(workerCsp).toContain("connect-src 'none'");
});

test('pagehide clears the editor, output, and results', async ({ page }) => {
  await ready(page);
  await page.locator('#paste-input').fill('password=hunter2');
  await expect(page.locator('#paste-output')).toHaveText('password=[REDACTED]');
  await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: false })));
  await expect(page.locator('#paste-input')).toHaveValue('');
  await expect(page.locator('#paste-output')).toHaveText('');
  await expect(page.locator('#copy')).toBeDisabled();
});

test('keyboard-only operation: skip link, tabs, editor, and buttons', async ({ page }) => {
  await ready(page);
  await page.keyboard.press('Tab');
  // Some engines (WebKit on Windows and macOS, like Safari's default) leave links out of the Tab
  // order; there the first Tab reaches the first control, which is a button.
  if (await page.locator('.skip-link').evaluate((el) => el === document.activeElement)) {
    await page.keyboard.press('Enter');
    await expect(page.locator('#playground')).toBeFocused();
    await page.keyboard.press('Tab');
  }
  await expect(page.locator('#tab-paste')).toBeFocused();
  await page.keyboard.press('ArrowRight');
  await expect(page.locator('#tab-file')).toBeFocused();
  await expect(page.locator('#panel-file')).toBeVisible();
  await page.keyboard.press('ArrowLeft');
  await expect(page.locator('#panel-paste')).toBeVisible();
  // Tab through the toolbar to the editor, type, then reach Clear.
  for (let i = 0; i < 10 && !(await page.locator('#paste-input').evaluate((el) => el === document.activeElement)); i++) {
    await page.keyboard.press('Tab');
  }
  await expect(page.locator('#paste-input')).toBeFocused();
  await page.keyboard.type('password=hunter2');
  await expect(page.locator('#paste-output')).toHaveText('password=[REDACTED]');
  await expect(page.locator('#paste-input')).toBeFocused();
  for (let i = 0; i < 6 && !(await page.locator('#clear').evaluate((el) => el === document.activeElement)); i++) {
    await page.keyboard.press('Tab');
  }
  await page.keyboard.press('Enter');
  await expect(page.locator('#paste-input')).toHaveValue('');
});
