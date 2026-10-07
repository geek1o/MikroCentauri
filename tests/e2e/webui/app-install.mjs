// Synthetic lab credentials enter through stdin and are never reported.
import { chromium, expect } from '@playwright/test';
let raw = '';
for await (const chunk of process.stdin) raw += chunk;
const { url, password } = JSON.parse(raw);
const browser = await chromium.launch();
try {
  // The disposable certificate is verified separately by the Python TLS client.
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', e => errors.push(e.message));
  await page.goto(url);
  const login = page.waitForResponse(r => r.url().endsWith('/auth/login'));
  await page.getByLabel('Пароль администратора').fill(password);
  await page.getByRole('button', { name: 'Войти', exact: true }).click();
  expect((await login).status()).toBe(200);
  await expect(page.getByRole('heading', { name: 'Обзор', exact: true })).toBeVisible();
  for (const name of ['Правила', 'Система', 'Обзор']) {
    await page.getByRole('navigation').getByRole('link', { name, exact: true }).click();
    await expect(page.getByRole('heading', { name, level: 1, exact: true })).toBeVisible();
  }
  expect(await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length })))
    .toEqual({ local: 0, session: 0 });
  expect(errors).toEqual([]);
  process.stdout.write(JSON.stringify({ engine: 'Chromium', natural_host_origin: true,
    login_status: 200, pages: ['Обзор', 'Правила', 'Система'], page_errors: 0,
    token_browser_storage_empty: true, certificate_exception: 'disposable lab certificate only' }));
} finally {
  await browser.close();
}
