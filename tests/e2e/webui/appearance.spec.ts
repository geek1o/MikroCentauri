import { test, expect } from '@playwright/test';

test('stellar appearance persists through login without browser storage', async ({page, request}, info) => {
  const errors:string[]=[];
  page.on('pageerror',e=>errors.push(e.message));
  page.on('console',m=>{if(m.type()==='error' && /Content Security Policy|Refused to/.test(m.text())) errors.push(m.text());});
  const capture = async (path:string) => {
    expect(errors).toEqual([]);
    const start=errors.length;
    await page.screenshot({path,fullPage:true,caret:'initial'});
    // The WebKit screenshot tool injects body {}; application CSP rejects it.
    const tooling=errors.splice(start);
    if(info.project.name==='webkit') expect(tooling).toEqual(["Refused to apply a stylesheet because its hash, its nonce, or 'unsafe-inline' does not appear in the style-src directive of the Content Security Policy."]);
    else expect(tooling).toEqual([]);
  };
  await page.emulateMedia({colorScheme:'dark',reducedMotion:'reduce'});
  await page.goto('/');
  await expect(page.locator('.sky-constellation')).toHaveCount(1);
  await expect(page.getByText('MIKROCENTAURI',{exact:true})).toHaveCount(0);
  await expect(page.getByText(/Защищённое соединение|SELECTIVE ROUTING|ROUTEROS NATIVE/)).toHaveCount(0);
  await capture('../../../.cache/webui/stellar-login-'+info.project.name+'.png');
  const login=page.waitForResponse(r=>r.url().endsWith('/auth/login'));
  await page.getByLabel('Пароль администратора').fill('BrowserFixturePassword-2026');
  await page.getByRole('button',{name:'Войти',exact:true}).click();
  expect((await login).ok()).toBe(true);
  await page.getByRole('navigation').getByRole('link',{name:'Система',exact:true}).click();
  await page.getByRole('combobox',{name:'Тема',exact:true}).selectOption('dark');
  await page.getByRole('combobox',{name:'Звёздный фон',exact:true}).selectOption('stars');
  const setRange=async(label:string,value:string)=>{await page.getByLabel(label,{exact:true}).evaluate((el,value)=>{const input=el as HTMLInputElement;input.value=value;input.dispatchEvent(new Event('input',{bubbles:true}));},value);};
  await setRange('Плотность звёзд','30');await setRange('Яркость фона','45');await setRange('Масштаб звёзд','140');
  await page.getByLabel('Движение звёзд',{exact:true}).check();
  await page.getByLabel('Звёзды на экране входа',{exact:true}).uncheck();
  await expect(page.locator('.sky-constellation')).toHaveCount(0);
  await expect(page.locator('.sky-preview circle')).toHaveCount(60);
  expect(await page.locator('.sky-preview .sky-drift').evaluate(el=>getComputedStyle(el).animationName)).toBe('none');
  const saved=page.waitForResponse(r=>r.url().endsWith('/preferences')&&r.request().method()==='POST');
  await page.getByRole('button',{name:'Сохранить настройки',exact:true}).click();
  expect((await saved).ok()).toBe(true);
  expect((await (await request.get('/api/v1/appearance')).json()).sky).toEqual({mode:'stars',density:30,brightness:45,scale:140,motion:true,login:false});
  for(const width of [1280,390]) {
    await page.setViewportSize({width,height:900});
    await page.getByRole('img',{name:'Предпросмотр звёздного фона'}).scrollIntoViewIfNeeded();
    await capture('../../../.cache/webui/stellar-settings-'+info.project.name+'-'+width+'.png');
    expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBe(true);
  }
  await page.reload();
  await expect(page.getByRole('button',{name:'Войти',exact:true})).toBeVisible();
  await expect(page.locator('.sky-scene svg')).toHaveCount(0);
  await expect(page.locator('html')).toHaveAttribute('data-theme','dark');
  expect(await page.evaluate(()=>({local:localStorage.length,session:sessionStorage.length}))).toEqual({local:0,session:0});
  // Re-open saved appearance with a fresh session; disabling the sky is reversible.
  await page.getByLabel('Пароль администратора').fill('BrowserFixturePassword-2026');
  await page.getByRole('button',{name:'Войти',exact:true}).click();
  await expect(page.getByLabel('Плотность звёзд',{exact:true})).toHaveValue('30');
  await page.getByRole('button',{name:'Сбросить оформление неба',exact:true}).click();
  await expect(page.locator('.sky-constellation')).toHaveCount(2);
  const reset=page.waitForResponse(r=>r.url().endsWith('/preferences')&&r.request().method()==='POST');
  await page.getByRole('button',{name:'Сохранить настройки',exact:true}).click(); await reset;
  await page.getByRole('navigation').getByRole('link',{name:'Селекторы',exact:true}).click();
  await page.setViewportSize({width:1280,height:900});
  await capture('../../../.cache/webui/stellar-selectors-'+info.project.name+'.png');
  expect(errors).toEqual([]);
});
