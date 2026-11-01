import { execFileSync } from 'node:child_process'
import { expect, test } from '@playwright/test'

test('administrator creates analyst, investigates scan, assigns incident and downloads report', async ({ page }) => {
  const username = process.env.E2E_ADMIN_USERNAME
  const password = process.env.E2E_ADMIN_PASSWORD
  const databaseUrl = process.env.E2E_DATABASE_URL
  if (!username || !password || !databaseUrl) throw new Error('Playwright E2E database settings are missing.')
  execFileSync(
    '.venv/bin/python',
    [
      '-c',
      'import os; from sqlalchemy import select; from backend.app.database import Base, engine, SessionLocal, UserRow; from backend.app.auth import create_user; Base.metadata.create_all(engine); session = SessionLocal(); username = os.environ["E2E_ADMIN_USERNAME"]; user = session.scalar(select(UserRow).where(UserRow.username == username)); user or create_user(session, username, os.environ["E2E_ADMIN_PASSWORD"], "super_admin"); session.commit(); session.close()',
    ],
    {
      env: {
        ...process.env,
        LAB_DATABASE_URL: databaseUrl,
      },
      stdio: 'inherit',
    },
  )

  await page.goto('/')
  await page.getByLabel('Username').fill(username)
  await page.getByLabel('Password').fill(password)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('heading', { name: 'Threat activity' })).toBeVisible()

  await page.getByRole('button', { name: 'Generate demo events' }).click()
  await expect(page.getByText(/Generated 40 simulated events/)).toBeVisible()

  await page.getByRole('button', { name: 'Analyst management' }).click()
  await page.getByLabel('Username').last().fill('e2e-analyst')
  await page.getByLabel('Temporary password').fill('e2e-analyst-password-2026')
  await page.getByRole('button', { name: 'Create account' }).click()
  await expect(page.getByRole('cell', { name: 'e2e-analyst' })).toBeVisible()

  await page.getByRole('button', { name: 'Security alerts' }).click()
  await page.getByRole('button', { name: /Investigate TCP SYN scan/ }).first().click()
  await expect(page.getByText('ALERT INVESTIGATION')).toBeVisible()
  await page.getByLabel('Assign analyst').fill('e2e-analyst')
  await page.getByRole('button', { name: 'Save alert changes' }).click()
  await page.getByRole('button', { name: 'Create incident' }).click()

  await expect(page.getByRole('heading', { name: 'Incident queue' })).toBeVisible()
  const assignment = page.getByRole('combobox', { name: /^Assign / }).first()
  await assignment.selectOption('e2e-analyst')
  const status = page.getByRole('combobox', { name: /^Update status for / }).first()
  await status.selectOption('Investigating')
  await expect(status).toHaveValue('Investigating')

  const incidentId = await page.locator('tbody tr').first().locator('td').first().locator('small').innerText()
  const auditTrail = await page.evaluate(async (id) => {
    const response = await fetch(`http://127.0.0.1:18000/api/incidents/${id}`, { credentials: 'include' })
    if (!response.ok) throw new Error(`Incident audit request returned ${response.status}`)
    return response.json()
  }, incidentId)
  expect(auditTrail.audit_trail.length).toBeGreaterThanOrEqual(3)
  expect(auditTrail.audit_trail.every((entry: { actor: string }) => entry.actor === username)).toBe(true)

  const downloadWaiter = page.waitForEvent('download')
  await page.getByRole('link', { name: 'Weekly PDF' }).click()
  const download = await downloadWaiter
  expect(download.suggestedFilename()).toBe('sentinelsoc-weekly-report.pdf')
})
