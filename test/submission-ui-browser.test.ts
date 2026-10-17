import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdtemp, mkdir, readFile, rm } from 'node:fs/promises';
import { chromium, type Browser, type Page } from 'playwright';
import { startDashboard } from '../src/dashboard.js';
import { createFixture, synthetic } from '../src/fixture.js';
import { root } from '../src/detectors.js';
import { dedicatedBrowser } from '../src/runtime-paths.js';
import { RECON_FILES } from '../src/recon/index.js';
/**
 * w3-ui: the dashboard's "Copy submission Markdown" button (one per finding) and the per-run recon download links, driven in a real browser.
 * Hard rules under test: the copied or shown text is masked, no full synthetic value reaches the DOM, URL, storage or console, the same POST action
 * serves a live run and a retained run after a restart, and the recon links download as attachments only when the run's recon files exist.
 * Loopback fixture and synthetic, nonfunctional keys only.
 */
const pause=(ms:number)=>new Promise(r=>setTimeout(r,ms));
const SECRETS=[synthetic.openai,synthetic.anthropic,synthetic.stripe,synthetic.supabase];
const BUTTON='Copy submission Markdown';

/** Everything a page could leak through: markup, live form values, visible text, the address bar and both storages. */
async function pageLeaks(page:Page,values:string[]){
  const html=await page.content();
  const live=await page.evaluate(()=>({fields:[...document.querySelectorAll('textarea,input')].map(e=>(e as HTMLInputElement).value).join('\n'),text:document.body.innerText,url:location.href,storage:localStorage.length+sessionStorage.length}));
  return {found:values.filter(v=>html.includes(v)||live.fields.includes(v)||live.text.includes(v)||live.url.includes(v)),storage:live.storage};
}
async function login(page:Page,origin:string,token:string){
  await page.goto(origin);await page.locator('#token').fill(token);await page.locator('#login-form button').click();await page.locator('#workspace').waitFor({state:'visible'});
  // The workspace is visible before it has loaded; it then opens its first page (projects or a new scan). Wait for that page, so a view the test opens next is not replaced by it.
  await page.locator('[data-view][aria-current="page"]').first().waitFor();
}
/** Opens a run from the run list and switches to its findings. */
async function openFindings(page:Page){
  await page.locator('[data-view="running"]').click();
  // Opening a run loads it and then shows the running page; its Open button stays busy until then (also when the run list is redrawn meanwhile).
  // Wait for that, so the findings page opened next is not replaced by the running page of the run being opened.
  const open=await page.locator('#run-history').getByRole('button',{name:/^Open run #[a-f0-9]{8} /}).first().elementHandle();assert.ok(open,'the run list offers the run');
  await open.click();await page.waitForFunction(button=>!(button as HTMLElement).dataset.busy,open);await open.dispose();
  await page.locator('#open-findings').click();await page.locator('.finding').first().waitFor();
}
/** The system clipboard (Windows stores line breaks as CRLF), compared with the page's LF text. */
const readClipboard=async(page:Page)=>(await page.evaluate(()=>navigator.clipboard.readText())).replace(/\r\n/g,'\n');
const openaiFinding=(page:Page)=>page.locator('.finding').filter({has:page.locator('h3').filter({hasText:'OpenAI'})}).first();

test('submission Markdown button per finding (clipboard and read-only fallback, live and retained runs) and recon download links stay masked',{timeout:300000},async()=>{
  const fixture=await createFixture(0,{minimalDiscovery:true});
  const parent=process.env.EXPOSURE_DATA_DIR||path.join(root,'.cache');await mkdir(parent,{recursive:true});const dataDir=await mkdtemp(path.join(parent,'submission-ui-'));
  let app=await startDashboard({port:0,persistent:true,dataDir,syntheticData:true});
  let browser:Browser|undefined;let id='',masked='',copied='';
  const consoleText:string[]=[],requested:string[]=[],errors:string[]=[],dialogs:string[]=[];
  const watch=(page:Page)=>{page.on('console',m=>consoleText.push(m.text()));page.on('request',r=>requested.push(r.url()));page.on('pageerror',e=>errors.push(e.message));page.on('dialog',d=>{dialogs.push(d.message());void d.dismiss();});};
  try{
    browser=await chromium.launch({headless:true,executablePath:dedicatedBrowser()||chromium.executablePath()});
    const context=await browser.newContext({permissions:['clipboard-read','clipboard-write'],acceptDownloads:true});
    const page=await context.newPage();watch(page);
    await login(page,app.origin,app.token);

    // One synthetic loopback scan, started through the page's own session and CSRF token.
    const call=(route:string,body:unknown)=>page.evaluate(async({route,body})=>{const csrf=await fetch('/api/session').then(r=>r.json()).then(j=>j.csrf);const r=await fetch(route,{method:'POST',headers:{'Content-Type':'application/json','X-Dashboard-Request':'1','X-CSRF-Token':csrf},body:JSON.stringify(body)});return {status:r.status,body:await r.json()};},{route,body});
    const started=await call('/api/scans',{authorized:true,config:{name:'Synthetic submission UI',urls:[fixture.origin+'/'],developmentFixtureOrigin:fixture.origin,requestsPerSecond:20,adjacentMaps:false,browser:false}});
    assert.equal(started.status,202,JSON.stringify(started.body));id=started.body.id;
    for(let i=0;i<300;i++){const s=app.scans.get(id);if(s&&!['running','ready'].includes(s.state))break;await pause(100);}
    assert.ok(app.scans.has(id),'the run stays in memory, so the live submission action serves it');

    await openFindings(page);
    // --- One button per finding ---
    const findings=await page.locator('.finding').count();assert.ok(findings>=1,'the fixture key is found');
    assert.equal(await page.locator('.finding').getByRole('button',{name:BUTTON,exact:true}).count(),findings,'every finding has exactly one submission button');
    const finding=openaiFinding(page);
    const view=await page.evaluate(async id=>(await fetch('/api/scans/'+id)).json(),id);
    const f=view.findings.find((x:any)=>x.provider==='OpenAI');assert.ok(f,'the OpenAI synthetic key is a finding');masked=f.masked;
    assert.ok(masked&&!masked.includes(synthetic.openai),'the view carries only the masked form');

    // --- Live run: the clipboard receives masked Markdown ---
    await finding.getByRole('button',{name:BUTTON,exact:true}).click();
    await page.waitForFunction(()=>document.getElementById('message')?.textContent?.startsWith('Masked submission Markdown copied.'));
    copied=await readClipboard(page);
    assert.match(copied,/^# /,'a Markdown report');assert.ok(copied.includes('Masked: `'+masked+'`'),'the report carries the masked value');
    for(const v of SECRETS)assert.ok(!copied.includes(v),'copied text holds no full value');
    assert.match((await finding.locator('.submission').textContent())!,/Masked submission Markdown copied\./,'a status line next to the button');
    assert.equal(await finding.locator('.submission textarea').isVisible(),false,'no text box when the clipboard worked');

    // --- Clipboard refused: a read-only box with the same masked text, reached by keyboard ---
    await page.evaluate(()=>{(navigator.clipboard as any).writeText=()=>Promise.reject(new DOMException('Write permission denied.','NotAllowedError'));});
    await finding.getByRole('button',{name:BUTTON,exact:true}).focus();await page.keyboard.press('Enter');
    const box=finding.locator('.submission textarea');await box.waitFor({state:'visible'});
    assert.equal(await box.evaluate(e=>(e as HTMLTextAreaElement).readOnly),true,'the fallback box is read-only');
    assert.equal(await box.inputValue(),copied,'the box shows the same masked Markdown');
    assert.ok(await box.evaluate(e=>document.activeElement===e&&(e as HTMLTextAreaElement).selectionStart===0&&(e as HTMLTextAreaElement).selectionEnd===(e as HTMLTextAreaElement).value.length),'focus moves to the selected text');
    assert.match((await finding.locator('.submission p').textContent())!,/^Clipboard unavailable\./);
    assert.match((await page.locator('#message').textContent())!,/^Clipboard unavailable\./);

    // --- Recon downloads: recon.json plus every text list, as attachments ---
    await page.locator('#recon-downloads').waitFor({state:'visible',timeout:30000});
    const links=page.locator('#recon-files a');
    const names=await links.allTextContents();
    assert.deepEqual([...names].sort(),[...RECON_FILES].sort(),'one link per allow-listed recon file');assert.equal(names[0],'recon.json','recon.json first');
    // Chromium lets a page start at most 10 downloads within about one second and silently drops the next one: no request reaches the server and no download event fires.
    // A person never starts 11 downloads within a second, but this loop can (one download takes about 40 ms on a fast Linux runner), so each download starts at least
    // 1.25 s after the one ten before it. Every file is still downloaded from the same page, and its status, Content-Disposition, masking and content are checked unchanged.
    const startedAt:number[]=[];
    for(const name of names){
      const link=links.filter({hasText:name}).first();
      assert.equal(await link.getAttribute('href'),`/api/scans/${id}/recon/${name}`);
      const head=await page.evaluate(async href=>{const r=await fetch(href);return {status:r.status,disposition:r.headers.get('content-disposition'),body:await r.text()};},(await link.getAttribute('href'))!);
      assert.equal(head.status,200,name);assert.equal(head.disposition,`attachment; filename="${name}"`,name+' is an attachment');
      for(const v of SECRETS)assert.ok(!head.body.includes(v),name+' holds no full value');
      // recon.json by keyboard, the rest by click; each starts a real download of that file.
      if(startedAt.length>=10)await pause(Math.max(0,startedAt[startedAt.length-10]+1250-Date.now()));startedAt.push(Date.now());
      const downloading=page.waitForEvent('download');
      if(name==='recon.json'){await link.focus();await page.keyboard.press('Enter');}else await link.click();
      const download=await downloading;assert.equal(download.suggestedFilename(),name);
      const saved=await readFile((await download.path())!,'utf8');assert.equal(saved,head.body,name+' downloads the served file');
    }
    // The list is rebuilt only when it changes: a focused link keeps focus across refresh ticks.
    await links.first().focus();await pause(3500);
    assert.equal(await page.evaluate(()=>document.activeElement?.textContent),'recon.json','refreshes keep keyboard focus on the link');

    const leaks=await pageLeaks(page,SECRETS);assert.deepEqual(leaks.found,[],'no full value in the DOM, form values, text or URL');assert.equal(leaks.storage,0,'nothing in local or session storage');
    await context.close();await app.close();

    // --- Retained run after a restart: the history submission action and the recon links resolve from the reloaded store ---
    app=await startDashboard({port:0,persistent:true,dataDir,syntheticData:true});
    await retainedRun(app,browser);
  }finally{await browser?.close();await app.close().catch(()=>{});await fixture.close();await rm(dataDir,{recursive:true,force:true});}

  // Neither the console nor any requested URL ever carried the Markdown or a value.
  for(const t of [...consoleText,...requested])for(const v of [...SECRETS,masked,'Masked: `'])assert.ok(!t.includes(v),'console and URLs stay free of the text: '+t.slice(0,120));
  assert.deepEqual(dialogs,[]);assert.deepEqual(errors,[]);

  async function retainedRun(app:Awaited<ReturnType<typeof startDashboard>>,browser:Browser){
    const context=await browser.newContext({permissions:['clipboard-read','clipboard-write'],acceptDownloads:true});
    const page=await context.newPage();watch(page);
    await login(page,app.origin,app.token);
    assert.equal(app.scans.has(id),false,'the run is retained history, not an in-memory scan');
    await openFindings(page);
    assert.equal(await page.locator('.finding').getByRole('button',{name:BUTTON,exact:true}).count(),await page.locator('.finding').count(),'retained findings keep the button');
    await openaiFinding(page).getByRole('button',{name:BUTTON,exact:true}).click();
    await page.waitForFunction(()=>document.getElementById('message')?.textContent?.startsWith('Masked submission Markdown copied.'));
    const retained=await readClipboard(page);
    assert.ok(retained.includes('Masked: `'+masked+'`'),'retained report carries the masked value');for(const v of SECRETS)assert.ok(!retained.includes(v),'retained copy holds no full value');
    await page.locator('#recon-downloads').waitFor({state:'visible',timeout:15000});
    assert.equal(await page.locator('#recon-files a').count(),RECON_FILES.length,'recon links for the retained run');
    // Without recon files the links disappear (shown only when the run has them).
    await rm(path.join(app.desk.store!.dir,'recon',id),{recursive:true,force:true});
    await page.locator('#recon-downloads').waitFor({state:'hidden',timeout:15000});
    assert.equal(await page.locator('#recon-files a').count(),0);
    const leaks=await pageLeaks(page,SECRETS);assert.deepEqual(leaks.found,[]);assert.equal(leaks.storage,0);
    await context.close();
  }
});
