import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: '.', testMatch: '*.spec.ts', fullyParallel: false, workers: 1,
  timeout: 45_000, retries: 0,
  use: { baseURL: process.env.WEB_UI_URL, ignoreHTTPSErrors: true, actionTimeout:15_000, launchOptions:{timeout:30_000},
    trace: 'retain-on-failure', screenshot: 'only-on-failure' },
  reporter: [['list'], ['json', { outputFile: '../../../.cache/webui/browser-results.json' }]],
  projects: [
    { name: 'chromium', use: { browserName: 'chromium', ...(process.env.WEB_UI_CHROME_CHANNEL ? {channel:process.env.WEB_UI_CHROME_CHANNEL} : {}) } },
    { name: 'firefox', use: { browserName: 'firefox' } },
    { name: 'webkit', use: { browserName: 'webkit' } },
  ],
});
