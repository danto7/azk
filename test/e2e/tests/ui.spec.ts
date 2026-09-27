import { test, expect, Page } from '@playwright/test';

const PASS = 'e2e-pass';

async function login(page: Page) {
  await page.goto('/login');
  await page.getByLabel('Passphrase').fill(PASS);
  await page.getByRole('button', { name: 'Unlock' }).click();
  await expect(page).toHaveURL('/');
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
}

test.describe.configure({ mode: 'serial' });

test('wrong passphrase is rejected, right one unlocks', async ({ page }) => {
  await page.goto('/');
  await expect(page).toHaveURL(/\/login$/);
  await page.getByLabel('Passphrase').fill('wrong');
  await page.getByRole('button', { name: 'Unlock' }).click();
  await expect(page.getByRole('alert')).toContainText('wrong passphrase');
  await login(page);
});

test('generate a key, see it listed, rotate and download the public key', async ({ page }) => {
  await login(page);
  const name = `web-rsa-${Date.now()}`;
  await page.goto('/items/new');
  await page.getByLabel('Name').fill(name);
  await page.getByLabel('Type').selectOption('rsa');
  await page.getByLabel(/Bits/).fill('2048');
  await page.getByRole('button', { name: 'Generate' }).click();
  await expect(page).toHaveURL(new RegExp(`/items/${name}`));
  await expect(page.getByRole('status')).toContainText('key generated');
  await expect(page.locator('#versions tbody tr')).toHaveCount(1);
  await expect(page.locator('#versions')).toContainText('enabled');
  await expect(page.locator('#versions')).toContainText('2048');

  await page.getByRole('button', { name: 'Rotate' }).click();
  await expect(page.getByRole('status')).toContainText('new version created');
  await expect(page.locator('#versions tbody tr')).toHaveCount(2);

  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.locator('#versions').getByRole('link', { name: 'PEM' }).first().click(),
  ]);
  expect(download.suggestedFilename()).toBe(`${name}-v2.pub.pem`);

  await page.goto('/items');
  await expect(page.locator('#items')).toContainText(name);
  await page.getByPlaceholder('name prefix').fill('seeded');
  await page.getByRole('button', { name: 'Filter' }).click();
  await expect(page.locator('#items')).toContainText('seeded-ec');
  await expect(page.locator('#items')).not.toContainText(name);
});

test('store a secret, reveal it inline, hide it, and see the audit entry', async ({ page }) => {
  await login(page);
  const name = `web-secret-${Date.now()}`;
  await page.goto('/items/new?tab=secret');
  await page.getByLabel('Name').fill(name);
  await page.getByLabel('Value', { exact: true }).fill('s3cret-value');
  await page.getByRole('button', { name: 'Store secret' }).click();
  await expect(page).toHaveURL(new RegExp(`/items/${name}`));
  await expect(page.locator('body')).not.toContainText('s3cret-value');

  await page.getByRole('button', { name: 'Reveal' }).click();
  await expect(page.locator('#reveal-1 .value')).toHaveText('s3cret-value');
  await expect(page).toHaveURL(new RegExp(`/items/${name}(\\?|$)`)); // htmx swap, no navigation

  await page.getByLabel('New value').fill('second');
  await page.getByRole('button', { name: 'Store new version' }).click();
  await expect(page.locator('#versions tbody tr:not(.reveal-row)')).toHaveCount(2);

  await page.goto('/audit');
  await expect(page.locator('#audit')).toContainText('secret.get');
  await expect(page.locator('#audit')).toContainText(name);
});

test('delete, recover, purge', async ({ page }) => {
  await login(page);
  const name = `web-del-${Date.now()}`;
  await page.goto('/items/new');
  await page.getByLabel('Name').fill(name);
  await page.getByLabel('Type').selectOption('ed25519');
  await page.getByRole('button', { name: 'Generate' }).click();
  page.once('dialog', (d) => d.accept());
  await page.getByRole('button', { name: 'Delete' }).click();
  await expect(page.getByRole('status')).toContainText('deleted');
  await expect(page.getByRole('heading', { level: 1 })).toContainText('deleted');
  await page.getByRole('button', { name: 'Recover' }).click();
  await expect(page.getByRole('status')).toContainText('recovered');
  page.once('dialog', (d) => d.accept());
  await page.getByRole('button', { name: 'Delete' }).click();
  page.once('dialog', (d) => d.accept());
  await page.getByRole('button', { name: 'Purge' }).click();
  await expect(page).toHaveURL(/\/items\?flash=purged/);
  await expect(page.locator('body')).not.toContainText(name);
});

test('remotes page validates input', async ({ page }) => {
  await login(page);
  await page.goto('/remotes');
  await page.getByLabel('Name').fill('emu');
  await page.getByLabel('Vault URL').fill('http://localhost:4577/devstoreaccount1-keyvault');
  await page.getByRole('button', { name: 'Add' }).click();
  await expect(page.getByRole('alert')).toContainText('insecure-http');
  await page.getByLabel('Name').fill('emu');
  await page.getByLabel('Vault URL').fill('http://localhost:4577/devstoreaccount1-keyvault');
  await page.getByLabel('allow plain http').check();
  await page.getByRole('button', { name: 'Add' }).click();
  await expect(page.locator('#remotes')).toContainText('emu');
  await expect(page.locator('#remotes')).toContainText('insecure http');
});

test('lock ends the session', async ({ page }) => {
  await login(page);
  await page.getByRole('button', { name: 'Lock' }).click();
  await expect(page).toHaveURL(/\/login/);
  await expect(page.getByRole('status')).toContainText('vault locked');
  await page.goto('/items');
  await expect(page).toHaveURL(/\/login$/);
});
