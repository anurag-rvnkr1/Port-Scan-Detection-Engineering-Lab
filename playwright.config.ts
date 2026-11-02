import { defineConfig, devices } from '@playwright/test'

const databaseUrl = 'sqlite:////tmp/sentinelsoc-e2e.db'
const sensorDirectory = '/tmp/sentinelsoc-e2e-sensors'
process.env.E2E_DATABASE_URL = databaseUrl
process.env.E2E_ADMIN_USERNAME = 'e2e-admin'
process.env.E2E_ADMIN_PASSWORD = 'e2e-test-password-2026'

export default defineConfig({
  testDir: './e2e',
  timeout: 60_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  reporter: 'list',
  use: {
    baseURL: 'http://127.0.0.1:13000',
    trace: 'retain-on-failure',
    ...devices['Desktop Chrome'],
  },
  webServer: [
    {
      command: '.venv/bin/python e2e/reset_database.py && .venv/bin/uvicorn backend.app.main:app --host 127.0.0.1 --port 18000',
      url: 'http://127.0.0.1:18000/health',
      reuseExistingServer: false,
      timeout: 30_000,
      env: {
        LAB_HOST: '127.0.0.1',
        LAB_PORT: '18000',
        LAB_DATABASE_URL: databaseUrl,
        LAB_CORS_ORIGINS: 'http://127.0.0.1:13000',
        LAB_NMAP_ALLOWED_CIDRS: '',
        LAB_SENSOR_LOG_DIRS: sensorDirectory,
      },
    },
    {
      command: 'npm run dev -- --hostname 127.0.0.1 --port 13000',
      url: 'http://127.0.0.1:13000',
      reuseExistingServer: false,
      timeout: 120_000,
      env: {
        NEXT_BUILD_DIR: '.next-e2e',
        NEXT_PUBLIC_API_BASE_URL: 'http://127.0.0.1:18000',
      },
    },
  ],
})
