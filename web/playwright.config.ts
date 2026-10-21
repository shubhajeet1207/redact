import { defineConfig, devices } from '@playwright/test';

// Browser tests run the built site under the production headers (scripts/serve.mjs).
export default defineConfig({
  testDir: 'e2e',
  fullyParallel: true,
  // The paste watchdog is 2 s (TRD §10.2); starting many browser engines at once on one machine
  // can starve a worker for longer than that, so parallelism is capped.
  workers: 2,
  forbidOnly: Boolean(process.env['CI']),
  retries: 0,
  reporter: [['list']],
  use: {
    baseURL: 'http://127.0.0.1:4173/',
    trace: 'off',
  },
  webServer: {
    command: 'node scripts/serve.mjs 4173',
    url: 'http://127.0.0.1:4173/',
    reuseExistingServer: false,
  },
  // TRD §19.8: automated Chromium, Firefox, and WebKit runs.
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    { name: 'firefox', use: { ...devices['Desktop Firefox'] } },
    { name: 'webkit', use: { ...devices['Desktop Safari'] } },
  ],
});
