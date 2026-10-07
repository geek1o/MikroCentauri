import { test, expect, type Page } from '@playwright/test';
import { readFile } from 'node:fs/promises';

test('administrative workflow over real HTTPS API and pinned validator', async ({ page, request }, info) => {
  test.setTimeout(120_000);
  const prefix = info.project.name;
  const errors:string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  page.on('console', message => { if (message.type()==='error' && /Content Security Policy|Refused to/.test(message.text())) errors.push(message.text()); });
  await page.goto('/');
  const login = page.waitForResponse(r => r.url().endsWith('/auth/login'));
  await page.getByLabel('Пароль администратора').fill('BrowserFixturePassword-2026');
  await page.getByRole('button',{name:'Войти',exact:true}).click();
  const token=(await (await login).json()).access_token;
  const headers={Authorization:'Bearer '+token};
  await expect(page.getByRole('heading',{name:'Обзор',exact:true})).toBeVisible();
  const navigate=async(name:string) => { await page.getByRole('navigation').getByRole('link',{name,exact:true}).click(); await expect(page.getByRole('heading',{name,exact:true,level:1})).toBeVisible(); };
  const mutate=async(button:string,path:string) => {
    const response=page.waitForResponse(r=>r.url().endsWith('/api/v1/'+path)&&r.request().method()==='POST',{timeout:15_000});
    await page.getByRole('button',{name:button,exact:true}).click();
    const result=await response; expect(result.ok(),await result.text()).toBeTruthy();
    await expect(page.getByRole('button',{name:'↻ Обновить',exact:true})).toBeEnabled();
    return result.json();
  };
  for(const name of ['Начальная настройка','Прокси','Подписки','Группы','Правила','Устройства','DNS','Диагностика','Система','Обзор']) {
    await navigate(name);
    expect(await page.evaluate(()=>({local:localStorage.length,session:sessionStorage.length}))).toEqual({local:0,session:0});
  }
  await navigate('DNS');
  const dnsIPv6 = page.getByRole('complementary', {name: 'Граница IPv6'});
  await expect(dnsIPv6).toContainText('включён в настройках RouterOS');
  await expect(dnsIPv6).toContainText('сторонний DNS может обойти');
  await navigate('Начальная настройка');
  await page.getByRole('button',{name:'Далее',exact:true}).click();
  const routerCheck=page.waitForResponse(r=>r.url().endsWith('/routeros/network'));
  await page.getByRole('button',{name:'Проверить RouterOS API',exact:true}).click();
  expect((await routerCheck).ok()).toBe(true);
  await expect(page.getByRole('button',{name:'↻ Обновить',exact:true})).toBeEnabled();
  await page.getByRole('button',{name:'Далее',exact:true}).click();
  await expect(page.getByRole('complementary', {name: 'Граница IPv6'})).toContainText('Default routes обнаружено: 1');
  await expect(page.getByText(/192\.168\.88\.1\/24/).first()).toBeVisible();
  await page.getByRole('button',{name:'Далее',exact:true}).click();
  await expect(page.getByText(/пересечения\s+с\s+пулом\s+FakeIP\s+не\s+найдены/)).toBeVisible();

  await navigate('Прокси');
  const hostileName=prefix+' <img src=x onerror=window.uiXSS=1>,node';
  const port=info.project.name==='chromium'?9101:info.project.name==='firefox'?9102:9103;
  await page.getByLabel('URI прокси, по одному на строку').fill('ss://YWVzLTEyOC1nY206YnJvd3Nlci1zZWNyZXQ@192.0.2.22:'+port+'#'+encodeURIComponent(hostileName)+'\nss://YWVzLTEyOC1nY206c3BhcmUtc2VjcmV0@192.0.2.23:'+port+'#'+encodeURIComponent(prefix+' spare'));
  await mutate('Импортировать прокси','proxies/import');
  await expect(page.getByLabel('URI прокси, по одному на строку')).toHaveValue('');
  await expect(page.getByText(hostileName,{exact:true})).toBeVisible();
  expect(await page.evaluate(()=>('uiXSS' in window))).toBe(false);
  const row=page.locator('.row').filter({has:page.getByText(hostileName,{exact:true})});
  await row.getByRole('button',{name:'Изменить',exact:true}).click();
  await page.getByLabel('Название',{exact:true}).fill(prefix+' proxy');
  await mutate('Сохранить прокси в черновик','proxies/update');
  const spare=page.locator('.row').filter({has:page.getByText(prefix+' spare',{exact:true})});
  await spare.getByRole('button',{name:'Изменить',exact:true}).click();
  await page.getByLabel('Включён',{exact:true}).uncheck();
  await mutate('Сохранить прокси в черновик','proxies/update');
  await expect(spare).toContainText('Отключён');
  const deleted=page.waitForResponse(r=>r.url().endsWith('/proxies/delete'));
  await spare.getByRole('button',{name:'Удалить',exact:true}).click();
  expect((await deleted).ok()).toBe(true);
  await expect(spare).toHaveCount(0);

  await navigate('Группы');
  await page.getByLabel('ID группы',{exact:true}).fill(prefix+'-group');
  await page.getByRole('group',{name:'Участники группы'}).getByLabel(prefix+' proxy',{exact:true}).check();
  await mutate('Сохранить группу','config/draft/policy');
  await navigate('Правила');
  await page.getByLabel('ID правила',{exact:true}).fill(prefix+'-rule');
  await page.getByLabel('Название',{exact:true}).fill(prefix+' selected domain');
  await page.getByLabel('Домены',{exact:true}).fill(prefix+'.example.test');
  await page.getByRole('combobox',{name:'Маршрут',exact:true}).selectOption(prefix+'-group');
  await mutate('Сохранить правило','config/draft/policy');
  const draft=await (await request.get('/api/v1/config/draft',{headers})).json();
  expect(draft.policy.dns.selected_domains).toContain(prefix+'.example.test');
  expect((await request.post('/api/v1/proxies/update',{headers,data:{draft_revision:0,id:draft.model.endpoints[0].ID,name:'stale'}})).status()).toBe(409);

  await navigate('Устройства');
  await expect(page.getByText('Lab laptop',{exact:true})).toBeVisible();
  await page.getByLabel('IP/CIDR устройств',{exact:true}).fill('192.168.88.'+(port-9051)+'/32');
  await page.getByRole('combobox',{name:'Политика',exact:true}).selectOption(prefix+'-group');
  await mutate('Сохранить политику устройства','config/draft/policy');
  await navigate('DNS');
  await expect(page.getByLabel('Домены для FakeIP')).toHaveValue(new RegExp(prefix+'\.example\.test'));
  await page.getByLabel('Домены для FakeIP').fill((await page.getByLabel('Домены для FakeIP').inputValue())+'\n'+prefix+'-extra.example.test');
  await mutate('Сохранить DNS в черновик','config/draft/policy');
  const plan=await mutate('Проверить и показать план','config/plan');
  expect(plan.apply_available).toBe(true);
  expect(plan.changed_sections).toEqual(expect.arrayContaining(['endpoints','groups','rules','source_proxy','dns']));
  await expect(page.getByRole('region',{name:'План изменений'})).toBeVisible();
  await page.getByText('Посмотреть конфигурацию кандидата',{exact:true}).click();
  await expect(page.getByRole('region',{name:'План изменений'})).toContainText(prefix+'-extra.example.test');
  await mutate('Применить подтверждённый план','config/apply');
  const current=await (await request.get('/api/v1/config',{headers})).json();
  expect(current.revision).toBe(plan.base_revision+1);
  expect(current.policy.rules.some((r:any)=>r.id===prefix+'-rule')).toBe(true);
  await navigate('Прокси');
  const active=page.locator('.row').filter({has:page.getByText(prefix+' proxy',{exact:true})});
  const unavailableProbe=page.waitForResponse(r=>r.url().endsWith('/proxies/probe'));
  await active.getByRole('button',{name:'Проверить узел',exact:true}).click();
  expect((await unavailableProbe).status()).toBe(501);
  await expect(active).toContainText('Источник данных не подключён.');

  await navigate('Подписки');
  await page.getByLabel('ID подписки',{exact:true}).fill(prefix+'-provider');
  await page.getByLabel('HTTPS URL',{exact:true}).fill('https://provider.example/browser-private-token');
  await mutate('Сохранить подписку','subscriptions');
  await expect(page.getByLabel('HTTPS URL',{exact:true})).toHaveValue('');
  const source=page.locator('.row').filter({has:page.getByText(prefix+'-provider',{exact:true})});
  const refreshed=page.waitForResponse(r=>r.url().endsWith('/subscriptions/refresh'));
  await source.getByRole('button',{name:'Обновить подписку'}).click();
  expect((await refreshed).ok()).toBe(true);
  await expect(page.getByRole('button',{name:'↻ Обновить',exact:true})).toBeEnabled();
  await source.getByRole('button',{name:'Выбрать узлы'}).click();
  await page.getByLabel('Subscription node · ss',{exact:true}).check();
  await mutate('Импортировать выбранные','subscriptions/import');
  await page.getByLabel('Включить автообновление').check();
  await page.getByLabel('Интервал, минуты').fill('5');
  expect((await mutate('Сохранить расписание','subscriptions/schedule')).interval_seconds).toBe(300);
  await page.getByLabel('Включить автообновление').uncheck();
  await mutate('Сохранить расписание','subscriptions/schedule');

  await navigate('Диагностика');
  expect((await mutate('Проверить sing-box','diagnostics/run')).success).toBe(true);
  const diagDownload=page.waitForEvent('download');
  await page.getByRole('button',{name:'Скачать диагностику'}).click();
  expect((await diagDownload).suggestedFilename()).toBe('mikrocentauri-diagnostics.tar.gz');
  await navigate('Система');
  await expect(page.getByText('0.5.0-dev',{exact:true})).toBeVisible();
  await page.getByRole('combobox',{name:'Тема',exact:true}).selectOption('dark');
  await page.getByLabel('Часовой пояс').fill('Europe/Moscow');
  await mutate('Сохранить настройки','preferences');
  await expect(page.locator('html')).toHaveAttribute('data-theme','dark');
  const download=page.waitForEvent('download');
  await page.getByRole('button',{name:'Скачать резервную копию'}).click();
  const backup=await download;
  const data=await readFile((await backup.path())!);
  expect(data.toString()).not.toMatch(/browser-secret|fixture-secret|browser-private-token|sub-fixture/);
  await page.getByLabel('Файл безопасной копии').setInputFiles({name:'safe.json',mimeType:'application/json',buffer:data});
  await mutate('Проверить восстановление','backup/restore-preview');
  await expect(page.getByText(/Копия совместима/)).toBeVisible();
  await mutate('Создать черновик восстановления','backup/restore-draft');
  await mutate('Проверить и показать план','config/plan');
  await mutate('Применить подтверждённый план','config/apply');
  await page.setViewportSize({width:390,height:844});
  for(const name of ['Обзор','Прокси','Подписки','Правила','Система']) {
    await navigate(name);
    expect(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth+1)).toBe(true);
  }
  expect(errors).toEqual([]);
  const screenshot=async(name:string) => {
    const start=errors.length;
    await page.screenshot({path:'../../../.cache/webui/'+prefix+'-'+name+'.png',fullPage:true,caret:'initial'});
    // Playwright 1.58's WebKit screenshotter injects a transient inline "body {}"
    // stylesheet to synchronize animations. Our CSP correctly rejects that
    // tooling operation; application navigation/forms must have zero violations.
    const captureErrors=errors.splice(start);
    if(prefix==='webkit') expect(captureErrors).toEqual(["Refused to apply a stylesheet because its hash, its nonce, or 'unsafe-inline' does not appear in the style-src directive of the Content Security Policy."]);
    else expect(captureErrors).toEqual([]);
  };
  await screenshot('mobile');
  await page.setViewportSize({width:1440,height:1000});
  await navigate('Обзор');
  await screenshot('dashboard');
  await page.getByRole('button',{name:'Выйти',exact:true}).click();
  await expect(page.getByLabel('Пароль администратора')).toBeVisible();
  expect((await request.get('/api/v1/config',{headers})).status()).toBe(401);
  await page.reload();
  await expect(page.getByLabel('Пароль администратора')).toBeVisible();
  expect(errors).toEqual([]);
});

test('IPv6 settings never claim packet isolation when disabled or unavailable', async ({page}) => {
  await page.goto('/');
  await page.getByLabel('Пароль администратора').fill('BrowserFixturePassword-2026');
  await page.getByRole('button', {name: 'Войти', exact: true}).click();
  await expect(page.getByRole('heading', {name: 'Обзор', exact: true})).toBeVisible();
  await page.getByRole('navigation').getByRole('link', {name: 'DNS', exact: true}).click();
  const notice = page.getByRole('complementary', {name: 'Граница IPv6'});
  for (const variant of ['disabled', 'unknown', 'unavailable']) {
    await page.route('**/api/v1/routeros/network', async route => {
      if (variant === 'unavailable') {
        await route.fulfill({status: 503, json: {error: 'fixture unavailable'}});
        return;
      }
      const response = await route.fetch();
      const network = await response.json();
      network.ipv6 = {state: variant === 'disabled' ? 'configured_disabled' : 'unknown', forwarding: variant === 'disabled' ? false : null, enabled_addresses: 2, default_routes: 1};
      network.available['ipv6/address'] = variant === 'disabled';
      network.available['ipv6/route'] = variant === 'disabled';
      await route.fulfill({response, json: network});
    });
    await page.getByRole('button', {name: '↻ Обновить', exact: true}).click();
    await expect(page.getByRole('button', {name: '↻ Обновить', exact: true})).toBeEnabled();
    await expect(notice).toContainText(variant === 'disabled' ? 'выключен в настройках RouterOS' : 'настройки не получены');
    await expect(notice).toContainText('не подтверждают отсутствие обхода');
    await expect(notice).toContainText('могут требовать перезагрузки');
    if (variant === 'disabled') {
      await expect(notice).toContainText('Forwarding: выключен');
      await expect(notice).toContainText('Default routes обнаружено: 1');
    } else {
      await expect(notice).not.toContainText('Forwarding:');
      await expect(notice).not.toContainText('Default routes обнаружено:');
    }
    await page.unroute('**/api/v1/routeros/network');
  }
});
