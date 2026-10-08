import {test,expect} from '@playwright/test';
import {readFileSync} from 'node:fs';

test('overview, proxy checks, backup spacing and navigation logo remain usable',async({page,request},info)=>{
 test.setTimeout(90_000);
 await page.goto('/');const login=page.waitForResponse(r=>r.url().endsWith('/auth/login'));
 await page.getByLabel('Пароль администратора').fill('BrowserFixturePassword-2026');await page.getByRole('button',{name:'Войти',exact:true}).click();
 const headers={Authorization:'Bearer '+(await(await login).json()).access_token};
 await expect(page.locator('.selector-panel')).toHaveCount(0);
 await expect(page.getByRole('heading',{name:'Текущие маршруты'})).toBeVisible();
 for(const width of [1280,390]){
  await page.setViewportSize({width,height:900});
  const logo=(await page.locator('.brand-icon').boundingBox())!;
  expect(logo.width).toBe(logo.height);expect(logo.width).toBe(width===1280?56:48);
 }
 await page.setViewportSize({width:1280,height:900});
 await page.getByRole('navigation').getByRole('link',{name:'Прокси',exact:true}).click();
 const checked:string[]=[];
 await page.route('**/api/v1/proxies/probe',async route=>{
  checked.push(route.request().postDataJSON().id);
  await route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({success:true,latency_ms:210})});
 });
 if(process.env.WEB_UI_LIVE_ENGINE==='1'){
  await page.getByRole('button',{name:'Проверить все узлы',exact:true}).click();
  await expect(page.getByRole('button',{name:'Проверить все узлы',exact:true})).toBeEnabled();
  const config=await(await request.get('/api/v1/config',{headers})).json();
  expect(checked.sort()).toEqual(config.model.endpoints.filter((e:any)=>e.Enabled!==false).map((e:any)=>e.ID).sort());
  await expect(page.locator('.proxy-tile .latency').first()).toHaveAttribute('data-tone','moderate');
 }
 await page.getByRole('navigation').getByRole('link',{name:'Селекторы',exact:true}).click();
 await page.getByRole('combobox',{name:'Тип группы',exact:true}).selectOption('urltest');
 const target=page.getByRole('combobox',{name:'Цель URLTest',exact:true});
 await expect(target.locator('option')).toHaveCount(4);await expect(target).toHaveValue('google');
 for(const id of ['google','cloudflare','apple','mozilla']){await target.selectOption(id);await expect(target).toHaveValue(id);}
 await page.getByRole('navigation').getByRole('link',{name:'Система',exact:true}).click();
 for(const width of [1280,390]){
  await page.setViewportSize({width,height:900});
  const download=(await page.getByRole('button',{name:'Скачать резервную копию',exact:true}).boundingBox())!;
  const restore=(await page.locator('.backup-restore-form label').boundingBox())!;
  expect(restore.y).toBeGreaterThan(download.y+download.height+12);
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBe(true);
 }
 // Render the same optical mark at several sizes to compare navigation legibility.
 const svg=readFileSync('../../../frontend/src/assets/centauri-navigation.svg','utf8');
 await page.setViewportSize({width:680,height:200});
 await page.goto('about:blank');
 await page.setContent(`<html><body style="background:#101b2d;color:#e5edf8;font:16px system-ui"><div style="display:flex;align-items:center;gap:48px;padding:48px">${[32,40,48,56].map(n=>`<div>${svg.replace('<svg','<svg width="'+n+'" height="'+n+'"')}<p>${n} px</p></div>`).join('')}</div></body></html>`);
 await page.screenshot({path:'../../../.cache/webui/navigation-logo-sizes-'+info.project.name+'.png',caret:'initial'});
});
