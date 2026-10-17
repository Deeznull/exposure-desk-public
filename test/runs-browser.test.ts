import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import path from 'node:path';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { chromium } from 'playwright';
import { startDashboard } from '../src/dashboard.js';
import { root } from '../src/detectors.js';
import { dedicatedBrowser } from '../src/runtime-paths.js';
const pause=(ms:number)=>new Promise(r=>setTimeout(r,ms));
async function temp(){const parent=process.env.EXPOSURE_DATA_DIR||path.join(root,'.cache');await mkdir(parent,{recursive:true});return mkdtemp(path.join(parent,'runs-ui-'));}
async function slowSite(delayMs:number){const arrivals:string[]=[];const server=http.createServer((req,res)=>{arrivals.push(req.url||'');if(req.url==='/slow')setTimeout(()=>{res.writeHead(200,{'content-type':'text/html'});res.end('<html><body>slow synthetic page</body></html>');},delayMs);else{res.writeHead(404);res.end();}});await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));const origin=`http://127.0.0.1:${(server.address() as any).port}`;return {origin,arrivals,close:()=>new Promise<void>(r=>{server.close(()=>r());server.closeAllConnections();})};}
test('dashboard shows one current run and labeled previous runs; a double click starts one run; a quick repeat needs an inline confirmation',{timeout:120000},async()=>{
  const dir=await temp(),site=await slowSite(2500);await mkdir(path.join(dir,'scans'),{recursive:true});
  const legacyId='ffffffff-0000-4000-8000-0000000000aa';await writeFile(path.join(dir,'scans',legacyId+'.json'),JSON.stringify({schema:'exposure-history/2',savedAt:new Date().toISOString(),view:{schema:'exposure-scan/1',id:legacyId,name:'Authorized website',state:'completed',startedAt:'2026-01-01T00:00:00.000Z',endedAt:'2026-01-01T00:01:00.000Z',elapsedMs:60000,config:{urls:['https://legacy.example.com/'],relatedOrigins:[]},counts:{resources:2,scanned:2,blocked:0,bytes:5,pending:0,findings:0},engines:{websiteRules:'website/2.3.0',gitleaks:'8.30.1',ruleDigest:'x',companyRules:'none'},findings:[],resources:[],limitations:[]}}));
  const app=await startDashboard({port:0,persistent:true,dataDir:dir,syntheticData:true,projects:[{name:'Slow site',urls:[site.origin+'/slow'],developmentFixtureOrigin:site.origin,requestsPerSecond:20,adjacentMaps:false,browser:false,deep:false,semanticAnalysis:false}]});
  const browser=await chromium.launch({headless:true,executablePath:dedicatedBrowser()||chromium.executablePath()});
  try{const page=await browser.newPage(),errors:string[]=[],dialogs:string[]=[];page.on('pageerror',e=>errors.push(e.message));page.on('dialog',d=>{dialogs.push(d.message());void d.dismiss();});
    let posts=0;page.on('request',r=>{if(r.method()==='POST'&&new URL(r.url()).pathname==='/api/scans')posts++;});
    // Hold the start request briefly so the pending state is observable.
    await page.route('**/api/scans',async route=>{if(route.request().method()==='POST')await pause(800);await route.continue();});
    await page.goto(app.origin);await page.locator('#token').fill(app.token);await page.locator('#login-form button').click();await page.locator('#workspace').waitFor({state:'visible'});
    const prepare=async()=>{await page.locator('[data-view="new"]').click();await page.locator('#scan-advanced').evaluate((e:HTMLElement)=>{(e as HTMLDetailsElement).open=true;});await page.locator('#project').selectOption('legacy-0');await page.locator('#authorized').check();};
    await prepare();await page.locator('#start').dblclick();assert.equal(await page.locator('#start').isDisabled(),true,'Start is disabled while the request is pending');
    await page.waitForFunction(()=>document.getElementById('current-run-body')?.textContent?.includes('Manual start'));const currentText=(await page.locator('#current-run-body').textContent())!;assert.ok(currentText.includes('Slow site')&&/#[a-f0-9]{8}/.test(currentText));assert.equal(await page.locator('#current-run-body .run-row').count(),1,'exactly one current run');
    assert.equal(posts,1,'a double click sends one start request');
    // The run list shows a run while it is still starting (detector start-up, about 0.3 s); wait for it to register, then exactly one scan exists.
    for(let i=0;i<50&&app.scans.size<1;i++)await pause(100);assert.equal(app.scans.size,1);
    assert.ok((await page.locator('#run-counts').textContent())!.startsWith('1 active'));await page.locator('[data-view="new"]').click();assert.equal(await page.locator('#start').isDisabled(),true,'Start stays disabled while a run is active');assert.ok((await page.locator('#start-note').textContent())!.includes('is in progress'));await page.locator('[data-view="running"]').click();
    const history=page.locator('#run-history');await page.waitForFunction(()=>document.getElementById('run-history')?.textContent?.includes('legacy.example.com'));const legacyRow=history.locator('.run-row').filter({hasText:'legacy.example.com'});const legacyText=(await legacyRow.textContent())!;assert.ok(legacyText.includes('Trigger not recorded')&&legacyText.includes('#ffffffff')&&legacyText.includes('unknown build'));assert.ok((await page.locator('#run-history-panel summary').textContent())!.startsWith('Previous runs'));assert.equal(await legacyRow.locator('time').getAttribute('datetime'),'2026-01-01T00:00:00.000Z');
    const first=[...app.scans.values()][0];for(let i=0;i<200&&first.state==='running';i++)await pause(100);await page.waitForFunction(()=>document.getElementById('current-run-body')?.textContent?.includes('No scan is running'));
    await page.waitForFunction(()=>/1 entered seed · 1 domain group \(127\.0\.0\.1\) · 1 authorized origin · 1 contacted/.test(document.getElementById('scope-counts')?.textContent||''));assert.ok((await page.locator('#current-run-body').textContent())!.includes('Latest run'));
    // A repeat within two minutes asks inline (no blocking dialog) and is linked to the earlier run.
    await prepare();await page.locator('#start').click();await page.waitForFunction(()=>document.getElementById('start-note')?.textContent?.includes('Start another run of Slow site?'));assert.equal(await page.locator('#start').textContent(),'Start another run');assert.equal(posts,1,'no request before the repeat is confirmed');
    await pause(700);await page.locator('#start').click();for(let i=0;i<100&&app.scans.size<2;i++)await pause(50);assert.equal(app.scans.size,2);const second=[...app.scans.values()].find(s=>s.id!==first.id)!;assert.equal(second.launch!.previousRunId,first.id);assert.equal(second.launch!.relation,'repeat');assert.equal(posts,2);
    for(let i=0;i<200&&second.state==='running';i++)await pause(100);
    assert.deepEqual(dialogs,[],'no confirm() dialogs');assert.deepEqual(errors,[]);
  }finally{await browser.close();await app.close();await site.close();await rm(dir,{recursive:true,force:true});}
});
test('a person who leaves the New scan page while the start request is pending stays where they went, and the message says where the run is',{timeout:120000},async()=>{
  const dir=await temp(),site=await slowSite(1500);
  const app=await startDashboard({port:0,persistent:true,dataDir:dir,syntheticData:true,projects:[{name:'Slow site',urls:[site.origin+'/slow'],developmentFixtureOrigin:site.origin,requestsPerSecond:20,adjacentMaps:false,browser:false,deep:false,semanticAnalysis:false}]});
  const browser=await chromium.launch({headless:true,executablePath:dedicatedBrowser()||chromium.executablePath()});
  try{const page=await browser.newPage(),errors:string[]=[];page.on('pageerror',e=>errors.push(e.message));
    // Hold the start request long enough to navigate to another page while it is pending.
    let held=false;await page.route('**/api/scans',async route=>{if(route.request().method()==='POST'){held=true;await pause(1500);}await route.continue();});
    await page.goto(app.origin);await page.locator('#token').fill(app.token);await page.locator('#login-form button').click();await page.locator('#workspace').waitFor({state:'visible'});
    await page.locator('[data-view="new"]').click();await page.locator('#scan-advanced').evaluate((e:HTMLElement)=>{(e as HTMLDetailsElement).open=true;});await page.locator('#project').selectOption('legacy-0');await page.locator('#authorized').check();
    await page.locator('#start').click();for(let i=0;i<50&&!held;i++)await pause(20);assert.ok(held,'the start request is pending');
    await page.locator('[data-view="history"]').click();
    await page.waitForFunction(()=>/^Run #[a-f0-9]{8} started/.test(document.getElementById('message')?.textContent||''),undefined,{timeout:15000});
    assert.ok((await page.locator('#message').textContent())!.endsWith(' Open it from Running scan.'),'the message says where to find the run');
    assert.equal(await page.locator('[data-view="history"]').getAttribute('aria-current'),'page','the person stays on the page they navigated to');
    assert.equal(await page.locator('[data-page="running"]').isVisible(),false,'the dashboard does not switch to Running scan');
    assert.equal(app.scans.size,1);const run=[...app.scans.values()][0];
    await page.locator('[data-view="running"]').click();await page.waitForFunction((id:string)=>document.getElementById('current-run-body')?.textContent?.includes('#'+id.slice(0,8)),run.id);
    for(let i=0;i<200&&run.state==='running';i++)await pause(100);
    assert.deepEqual(errors,[]);
  }finally{await browser.close();await app.close();await site.close();await rm(dir,{recursive:true,force:true});}
});
