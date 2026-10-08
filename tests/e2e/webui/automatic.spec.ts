import {test,expect} from '@playwright/test';

test('compact tiles retain size and owned sections change automatic policy',async({page,request},info)=>{
 test.setTimeout(90_000);
 const errors:string[]=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto('/');const logo=await page.locator('.celestial-mark').getAttribute('src');
 const login=page.waitForResponse(r=>r.url().endsWith('/auth/login'));
 await page.getByLabel('Пароль администратора').fill('BrowserFixturePassword-2026');await page.getByRole('button',{name:'Войти',exact:true}).click();
 const headers={Authorization:'Bearer '+(await(await login).json()).access_token};
 await expect(page.locator('.brand-icon')).toHaveAttribute('src',/centauri-navigation|data:image\/svg/);
 expect(await page.locator('.brand-icon').getAttribute('src')).not.toBe(logo);
 const draftInitial=await request.get('/api/v1/config/draft',{headers});
 const draftRevision=draftInitial.ok()?(await draftInitial.json()).draft_revision:0;
 const imported=await request.post('/api/v1/proxies/import',{headers,data:{draft_revision:draftRevision,uris:['ss://aes-256-gcm:fixture@192.0.2.25:9100#Backup%20north','ss://aes-256-gcm:fixture@192.0.2.26:9101#Backup%20south']}});expect(imported.ok()).toBe(true);
 await page.getByRole('button',{name:'↻ Обновить',exact:true}).click();await expect(page.getByRole('button',{name:'↻ Обновить',exact:true})).toBeEnabled();

 await page.getByRole('navigation').getByRole('link',{name:'Секции',exact:true}).click();
 await page.getByRole('button',{name:'Добавить секцию',exact:true}).click();await page.getByLabel('Название',{exact:true}).fill('Автосекция');
 await page.getByLabel('Собственный селектор серверов для секции').check();
 await page.getByText('Свои домены и IP-подсети',{exact:true}).click();await page.getByLabel('Домены и поддомены',{exact:true}).fill('automatic.example.test');
 const save=async()=>{const response=page.waitForResponse(r=>r.url().endsWith('/sections/save'));await page.getByRole('button',{name:'Сохранить секцию',exact:true}).click();expect((await response).ok()).toBe(true);};
 const apply=async()=>{const planned=page.waitForResponse(r=>r.url().endsWith('/config/plan'));await page.getByRole('button',{name:'Проверить и показать план',exact:true}).click();expect((await planned).ok()).toBe(true);const response=page.waitForResponse(r=>r.url().endsWith('/config/apply'));await page.getByRole('button',{name:'Применить подтверждённый план',exact:true}).click();expect((await response).ok()).toBe(true);await expect(page.getByRole('button',{name:'↻ Обновить',exact:true})).toBeEnabled();};
 await save();await apply();
 const section=page.getByRole('region',{name:'Секция Автосекция',exact:true});const tile=section.locator('.server-card').first();
 const before=(await tile.boundingBox())!.height;
 const controls=section.locator('.selector-toolbar').locator('input,select,button');
 for(let n=0;n<await controls.count();n++) expect((await controls.nth(n).boundingBox())!.height).toBe(40);
 const boxes=await Promise.all([0,1,2].map(n=>controls.nth(n).boundingBox()));
 expect(Math.max(...boxes.map(b=>b!.y+b!.height))-Math.min(...boxes.map(b=>b!.y+b!.height))).toBeLessThan(2);
 if(process.env.WEB_UI_LIVE_ENGINE==='1'){
  const response=page.waitForResponse(r=>r.url().endsWith('/engine/delay'));await tile.locator('.probe-server').click();expect((await response).ok()).toBe(true);
  await expect(tile.locator('.latency')).toHaveAttribute('title',/^Измерено /);expect((await tile.boundingBox())!.height).toBe(before);await expect(tile.locator('.measurement-time')).toHaveCount(0);
 }
 await section.getByRole('button',{name:'Настроить выбор',exact:true}).click();
 await expect(page.getByRole('combobox',{name:'Режим выбора сервера',exact:true})).toHaveValue('selector');
 await page.getByRole('combobox',{name:'Режим выбора сервера',exact:true}).selectOption('urltest');
 await page.getByRole('combobox',{name:'Цель URLTest',exact:true}).selectOption('cloudflare');
 await expect(page.getByRole('combobox',{name:'Цель URLTest',exact:true}).locator('option')).toHaveCount(4);
 await page.getByRole('combobox',{name:'Период проверки',exact:true}).selectOption('30s');
 await page.getByRole('combobox',{name:'Переключать при выигрыше',exact:true}).selectOption('1');
 await save();await expect(section).toContainText('Изменение режима ещё не применено');
 const draft=await(await request.get('/api/v1/config/draft',{headers})).json();const groupID=draft.policy.sections.find((s:any)=>s.name==='Автосекция').outbound;
 const group=draft.model.groups.find((g:any)=>g.id===groupID);expect(group).toMatchObject({type:'urltest',test_target:'cloudflare',interval:'30s',tolerance:1});expect(group.selected).toBeFalsy();
 expect((await(await request.get('/api/v1/config',{headers})).json()).model.groups.find((g:any)=>g.id===groupID).type).toBe('selector');
 await apply();await expect(section).toContainText('Автоматический выбор');await expect(section).not.toContainText('Изменение режима ещё не применено');await expect(section.locator('.choose-server').first()).toBeDisabled();
 for(const width of [1280,390]){await page.setViewportSize({width,height:900});expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBe(true);await page.screenshot({path:'../../../.cache/webui/compact-sections-'+info.project.name+'-'+width+'.png',fullPage:true,caret:'initial'});}
 await page.getByRole('navigation').getByRole('link',{name:'Прокси',exact:true}).click();await expect(page.locator('.proxy-tile').first()).toBeVisible();await page.screenshot({path:'../../../.cache/webui/compact-proxies-'+info.project.name+'.png',fullPage:true,caret:'initial'});
 // Return to manual selection without adding another group or losing section data.
 await page.getByRole('navigation').getByRole('link',{name:'Секции',exact:true}).click();await section.getByRole('button',{name:'Настроить выбор',exact:true}).click();
 await expect(page.getByRole('combobox',{name:'Период проверки',exact:true})).toHaveValue('30s');
 await expect(page.getByRole('combobox',{name:'Цель URLTest',exact:true})).toHaveValue('cloudflare');
 await page.getByRole('combobox',{name:'Режим выбора сервера',exact:true}).selectOption('selector');await save();
 const manual=await(await request.get('/api/v1/config/draft',{headers})).json();expect(manual.model.groups.filter((g:any)=>g.id===groupID)).toHaveLength(1);expect(manual.model.groups.find((g:any)=>g.id===groupID).type).toBe('selector');expect(manual.policy.sections[0].domains).toContain('automatic.example.test');
 expect(errors).toEqual([]);
});
