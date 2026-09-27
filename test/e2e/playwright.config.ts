import { defineConfig } from '@playwright/test';

// The web server script creates a throwaway vault and serves it on 7799.
export default defineConfig({
  testDir: './tests',
  fullyParallel: false,
  workers: 1,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'list',
  use: {
    baseURL: 'http://127.0.0.1:7799',
    trace: 'retain-on-failure',
  },
  webServer: {
    command: 'sh ./start.sh',
    url: 'http://127.0.0.1:7799/login',
    reuseExistingServer: false,
    timeout: 60_000,
  },
  projects: [{ name: 'chromium', use: { browserName: 'chromium' } }],
});
