import {test,expect} from '@playwright/test';

test('first-start wizard verifies, saves and restores read-only RouterOS access',async({page,request},info)=>{
 test.setTimeout(90_000);
 const pageErrors:string[]=[];page.on('pageerror',e=>pageErrors.push(e.message));
 await page.goto('/');const login=page.waitForResponse(r=>r.url().endsWith('/auth/login'));
 await page.getByLabel('Пароль администратора').fill('BrowserFixturePassword-2026');await page.getByRole('button',{name:'Войти',exact:true}).click();
 const headers={Authorization:'Bearer '+(await(await login).json()).access_token};
 await page.getByRole('navigation').getByRole('link',{name:'Начальная настройка',exact:true}).click();
 await page.getByRole('button',{name:'Далее',exact:true}).click();
 await expect(page.getByRole('heading',{name:'Подключение к RouterOS',exact:true})).toBeVisible();
 const next=page.getByRole('button',{name:'Далее',exact:true});await expect(next).toBeDisabled();
 const address=page.getByLabel('Адрес RouterOS REST API',{exact:true});const user=page.getByLabel('Пользователь RouterOS',{exact:true});const password=page.getByLabel('Пароль RouterOS',{exact:true});
 await expect(address).toHaveValue('https://192.168.88.1/rest');
 await address.fill('http://192.168.88.1/rest');await user.fill('fixture-reader');await password.fill('wrong-fixture-password');
 await page.getByRole('button',{name:'Проверить подключение',exact:true}).click();await expect(page.getByRole('alert')).toContainText('HTTPS-адрес');
 await address.fill('https://192.168.88.1/rest');await page.getByRole('button',{name:'Проверить подключение',exact:true}).click();await expect(page.getByRole('alert')).toContainText('отклонил имя пользователя или пароль');
 await password.fill('FixtureRouterPassword-2026');
 await page.getByRole('button',{name:'Проверить подключение',exact:true}).click();
 await expect(page.getByRole('button',{name:'Сохранить подключение',exact:true})).toBeEnabled();
 const before=await(await request.get('/api/v1/setup/router',{headers})).json();expect(before.configured).toBe(false);
 await page.getByRole('button',{name:'Сохранить подключение',exact:true}).click();
 await expect(page.getByText('Подключение сохранено.',{exact:false})).toBeVisible();await expect(password).toHaveValue('');await expect(next).toBeEnabled();
 await expect(page.getByRole('heading',{name:'Подготовка маршрутизации',exact:true})).toBeVisible();
 const saved=await(await request.get('/api/v1/setup/router',{headers})).json();expect(saved).toMatchObject({configured:true,has_password:true,username:'fixture-reader'});expect(JSON.stringify(saved)).not.toContain('FixtureRouterPassword-2026');
 const state=await(await request.get('/api/v1/system',{headers})).json();expect(state.runtime_connected).toBe(false);expect(state.status.ready).toBe(false);
 for(const width of [1280,390]){await page.setViewportSize({width,height:900});expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBe(true);await page.screenshot({path:'../../../.cache/webui/router-setup-'+info.project.name+'-'+width+'.png',fullPage:true,caret:'initial'});}
 await page.reload();await page.getByLabel('Пароль администратора').fill('BrowserFixturePassword-2026');await page.getByRole('button',{name:'Войти',exact:true}).click();await page.getByRole('navigation').getByRole('link',{name:'Начальная настройка',exact:true}).click();await page.getByRole('button',{name:'Далее',exact:true}).click();await expect(password).toHaveValue('');await expect(password).toHaveAttribute('placeholder',/Сохранён/);
 await page.getByRole('button',{name:'Проверить подключение',exact:true}).click();await expect(page.getByRole('button',{name:'Сохранить подключение',exact:true})).toBeEnabled();
 expect(pageErrors).toEqual([]);
});
