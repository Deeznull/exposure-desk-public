import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFile, rm, writeFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { chromium } from 'playwright';
import { privateDirectory } from '../src/local-files.js';
import { browserCrashArgs } from '../src/runtime-paths.js';
import { Scanner } from '../src/scanner.js';
import { createFixture, synthetic } from '../src/fixture.js';
import { startDashboard } from '../src/dashboard.js';
import { browserPath } from '../src/diagnostics.js';
import http from 'node:http';
import {Detector} from '../src/detectors.js';
const pause=(ms:number)=>new Promise(r=>setTimeout(r,ms));
test('committed pages retain runtime inspection when a deferred script prevents bounded DOM readiness',{timeout:30000},async()=>{
 const opaque='Q7r2T9w5Y1u8I3o6P4a0S9d7F2g5H8j1K6l3Z4x9C0v2B7n8M';
 const server=http.createServer((req,res)=>{if(req.url==='/'){res.setHeader('content-type','text/html');res.end('<html><body><script>window.RuntimeConfig={cohere:{apiKey:'+JSON.stringify([...opaque])+'.join("")}};</script><script defer src="/deferred.js"></script><p>Available document</p></body></html>');}else if(req.url==='/deferred.js'){const timer=setTimeout(()=>res.end('const delayed=1;'),4000);res.once('close',()=>clearTimeout(timer));}else{res.statusCode=404;res.end('missing');}});await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));const origin=`http://127.0.0.1:${(server.address() as any).port}`;
 try{const s=new Scanner({urls:[origin],developmentFixtureOrigin:origin,browser:true,browserPages:1,browserSettleMs:10,browserScrollSteps:0,requestsPerSecond:20,timeoutMs:800,maxDurationMs:20000,adjacentMaps:false},{detector:new Detector()});const v=await s.run();assert.equal(v.browserStatus!.launch,true,'Actual browser execution required');assert.equal(v.browserStatus!.runtimePages,1,'Available committed page must retain its snapshot');assert.ok(v.limitations.some(g=>g.code==='browser-readiness-timeout'&&g.incomplete));assert.ok(v.findings.some(f=>f.provider==='Cohere'&&f.occurrences.some(o=>o.evidence.includes('runtime configuration'))));assert.equal(v.state,'incomplete');s.dispose();}finally{await new Promise<void>(r=>{server.close(()=>r());server.closeAllConnections();});}
});
test('isolated Playwright runtime detects page/storage/API/worker exposures and forbids all dangerous fixture arrivals',{timeout:300000},async()=>{
  const fixture=await createFixture(),dashboard=await startDashboard({port:0});fixture.setDashboardOrigin(dashboard.origin);
  try{
    const s=new Scanner({urls:[fixture.origin],developmentFixtureOrigin:fixture.origin,browser:true,deep:false,requestsPerSecond:20,maxResources:200,maxResourceBytes:65536,timeoutMs:10000,maxDurationMs:240000,browserPages:8,browserSettleMs:1500,browserScrollSteps:3,browserScrollDelayMs:100},{deniedPorts:[Number(new URL(dashboard.origin).port)]});await s.init();await s.run();
    assert.ok(!s.limitations.some(g=>g.code==='browser-unavailable'),'Browser runtime must execute; this is a hard failure, not a skipped/passing test');
    const v=s.view();await mkdir((process.env.EXPOSURE_TEST_OUTPUT||'.cache/test-output'),{recursive:true});await writeFile((process.env.EXPOSURE_TEST_OUTPUT||'.cache/test-output')+'/browser-security-results.json',JSON.stringify({state:v.state,browser:v.browserStatus,accounting:v.accounting,resources:v.resources,limitations:v.limitations,arrivals:fixture.arrivals},null,2));assert.ok(v.resources.some(r=>r.kind==='browser'&&r.url.endsWith('/api/public')&&r.status==='scanned'),'Normal loading must expose text API responses');
    assert.ok(v.resources.some(r=>r.kind==='browser'&&r.url.endsWith('/api/scroll')&&r.status==='scanned'),'Bounded scrolling must load synthetic lazy content through guarded transport');
    assert.ok(v.findings.some(f=>f.occurrences.some(o=>o.sourceLabel?.startsWith('storage'))),'Fresh storage must be inspected');assert.ok(v.findings.some(f=>f.occurrences.some(o=>o.sourceLabel?.startsWith('runtime'))),'Runtime configuration must be inspected');
    assert.ok(v.resources.some(r=>r.reason==='credential-in-request'&&r.kind==='browser'));assert.ok(v.resources.some(r=>r.reason==='method'));assert.ok(v.resources.some(r=>r.reason==='websocket-disabled'));
    assert.ok(v.resources.filter(r=>r.kind==='browser'&&r.code).every(r=>r.provenance?.channel==='guarded-route'),'Every delivered runtime response must traverse guarded transport');
    assert.ok(v.resources.some(r=>r.reason==='credential-in-request'&&r.provenance?.channel==='guarded-route'),'Blocked routed credentials retain their request provenance');
    assert.ok(!fixture.arrivals.some(a=>/collect|write|delete|external:|upgrade:/.test(a.path)),'Secret URLs, headers, bodies, redirects, worker writes and websockets must never arrive');
    assert.ok(!JSON.stringify(v).includes(synthetic.openai));assert.ok(!v.findings.some(f=>f.provider==='jwt'&&f.category==='private-credential'),'Anonymous session tokens must not be escalated');
  }finally{await dashboard.close();await fixture.close();}
});
test('dashboard UI deliberately reveals/copies, remasks, exports and runs one-click full-pipeline diagnostics',{timeout:150000},async()=>{
  const fixture=await createFixture(0,{minimalDiscovery:true}),app=await startDashboard({port:0,projects:[{name:'Browser UI fixture',urls:[fixture.origin+'/.env'],developmentFixtureOrigin:fixture.origin,requestsPerSecond:20,adjacentMaps:false}]});
  let browser:Awaited<ReturnType<typeof chromium.connectOverCDP>>|undefined,child:ReturnType<typeof spawn>|undefined;const dir=await privateDirectory('ui-test-',true);
  try{
    child=spawn(browserPath(),['--headless=new','--user-data-dir='+dir,'--remote-debugging-port=0','--remote-debugging-address=127.0.0.1','--no-first-run','--disable-background-networking','--disable-crash-reporter',...browserCrashArgs(),'about:blank'],{stdio:'ignore',windowsHide:true});let failed=false;child.on('error',()=>{failed=true;});let port=0;
    for(let i=0;i<60;i++){if(failed||child.exitCode!==null)break;try{port=Number((await readFile(path.join(dir,'DevToolsActivePort'),'utf8')).split('\n')[0]);if(port)break;}catch{}await pause(100);}
    assert.ok(port>0,'Fresh Chromium must launch; Windows sandbox IPC restrictions cannot be reported as a passing UI test');
    browser=await chromium.connectOverCDP(`http://127.0.0.1:${port}`);const context=await browser.newContext({permissions:['clipboard-read','clipboard-write'],acceptDownloads:true});const page=await context.newPage();
    const payloads:string[]=[];page.on('response',r=>{if(r.url().includes('/api/scans'))void r.text().then(t=>payloads.push(t)).catch(()=>{});});
    await page.goto(app.origin);await page.locator('#token').fill(app.token);await page.locator('#login-form button').click();await page.locator('#workspace').waitFor({state:'visible'});await page.locator('[data-view="new"]').click();await page.waitForFunction(()=>document.getElementById('profile-label')?.textContent==='Standard + Normal (Recommended)');assert.equal(await page.locator('#option-standard-normal').isChecked(),true,'a new scan uses the Recommended ready option, Standard + Normal');assert.ok(await page.locator('#scan-scope').isVisible(),'Scope fieldset is visible without opening Advanced');for(const id of ['scope-registrable-domain','scope-exact-origin']){const radio=(await page.locator('#'+id).boundingBox())!,text=(await page.locator('#'+id+' + .choice-text').boundingBox())!;assert.ok(radio.width<=24&&radio.x+radio.width<=text.x,id+' radio sits beside its text, not stretched above it');}assert.equal(await page.locator('#scope-registrable-domain').isChecked(),true,'Domain scope is the default radio');await page.locator('#scan-advanced summary').click();await page.locator('#project').selectOption('legacy-0');await page.locator('#project').selectOption('');assert.equal(await page.locator('#option-standard-normal').isChecked(),true,'a new form returns to the Recommended option');await page.locator('label.option-card:has(#option-deep-normal)').click();assert.equal(await page.locator('#profile-label').textContent(),'Deep audit + Normal');assert.equal(await page.locator('#scope-registrable-domain').isChecked(),true);assert.ok((await page.locator('#scope-summary').textContent())?.includes('at most 50 additional'));await page.locator('#scope-exact-origin').check();assert.ok((await page.locator('#scope-summary').textContent())?.includes('Exact-origin scope'));await page.waitForFunction(()=>document.getElementById('authorized-text')?.textContent?.startsWith('I own these exact origins'));await page.locator('#scope-registrable-domain').check();await page.waitForFunction(()=>document.getElementById('authorized-text')?.textContent?.includes('all of its subdomains'));await page.locator('#project').selectOption('legacy-0');assert.equal(await page.locator('#scope-registrable-domain').isChecked(),true,'A config-file project without a scope key uses the default');await page.locator('#authorized').check();await page.locator('#start').click();await page.waitForFunction(()=>document.getElementById('state')?.textContent==='completed',undefined,{timeout:30000});await page.locator('#open-findings').click();
    assert.ok(payloads.every(p=>!p.includes(synthetic.openai)),'Background dashboard payloads must be redacted');assert.ok(!(await page.content()).includes(synthetic.openai));assert.ok(await page.evaluate(()=>localStorage.length===0&&sessionStorage.length===0),'Dashboard storage must contain no full values');
    const finding=page.locator('.finding').filter({has:page.locator('h3').filter({hasText:'OpenAI'})}).first();await finding.getByRole('button',{name:'Reveal full value',exact:true}).click();await page.waitForFunction(()=>document.querySelector('#findings')?.textContent?.includes('sk-proj-'));assert.ok((await finding.locator('.value').textContent())?.includes(synthetic.openai));
    await finding.getByRole('button',{name:'Copy full value',exact:true}).click();await page.waitForFunction(()=>document.getElementById('message')?.textContent?.startsWith('Full value copied deliberately.'));assert.ok(await page.evaluate(value=>navigator.clipboard.readText().then(t=>t===value),synthetic.openai));await finding.getByRole('button',{name:'Re-mask',exact:true}).click();assert.ok(!(await page.content()).includes(synthetic.openai));
    await page.clock.install();await finding.getByRole('button',{name:'Reveal full value',exact:true}).click();await page.waitForFunction(value=>document.querySelector('#findings')?.textContent?.includes(value),synthetic.openai);await page.clock.fastForward(31000);assert.ok(!(await page.content()).includes(synthetic.openai),'Timeout must remove full values from DOM');
    const downloadPromise=page.waitForEvent('download');await page.locator('#export').click();const download=await downloadPromise;assert.ok(download.suggestedFilename().endsWith('.json'));assert.ok(!download.suggestedFilename().includes('sensitive'));
    await page.clock.resume();await page.locator('[data-view="settings"]').click();await page.locator('#pipeline-test').click();
    await page.waitForFunction(()=>document.getElementById('message')?.textContent?.includes('Full-pipeline self-test started'));
    let result:any;for(let i=0;i<700;i++){result=await page.evaluate(async()=>fetch('/api/diagnostic-result').then(r=>r.json()));if(result.pipeline)break;await pause(100);}
    assert.equal(result.pipeline?.status,'passed','One-click Diagnostics must exercise the actual pipeline, not merely start a job');assert.equal(result.pipeline.summary.found,17);assert.equal(result.pipeline.scan.browser.runtimePages,2);
    await page.locator('#diagnose').click();await page.waitForFunction(()=>document.getElementById('pipeline-result')?.textContent?.includes('"status": "passed"'));assert.ok(!(await page.content()).includes(synthetic.openai));
    await context.close();
  }finally{if(browser)await browser.close().catch(()=>{});child?.kill();await rm(dir,{recursive:true,force:true,maxRetries:10,retryDelay:100});await app.close();await fixture.close();}
});
test('dashboard sizes scan limits by approved website count and imports JSON specifications',{timeout:60000},async()=>{
  const app=await startDashboard({port:0});const dir=await privateDirectory('scan-options-ui-',true);
  let browser:Awaited<ReturnType<typeof chromium.connectOverCDP>>|undefined,child:ReturnType<typeof spawn>|undefined;
  try{
    child=spawn(browserPath(),['--headless=new','--user-data-dir='+dir,'--remote-debugging-port=0','--remote-debugging-address=127.0.0.1','--no-first-run','--disable-background-networking','about:blank'],{stdio:'ignore',windowsHide:true});
    let port=0;for(let i=0;i<60;i++){try{port=Number((await readFile(path.join(dir,'DevToolsActivePort'),'utf8')).split('\n')[0]);if(port)break;}catch{}await pause(100);}
    assert.ok(port>0,'Fresh Chromium must launch');browser=await chromium.connectOverCDP(`http://127.0.0.1:${port}`);
    const page=await browser.newPage();page.setDefaultTimeout(5000);await page.goto(app.origin);await page.locator('#token').fill(app.token);await page.locator('#login-form button').click();await page.locator('#workspace').waitFor({state:'visible'});await page.locator('[data-view="new"]').click();
    await page.locator('#scan-advanced summary').click();await page.locator('#urls').fill('https://one.example/');await page.locator('#seed-urls').fill('https://two.example/');
    // A ready option sizes by website count (read-only); a JSON file with its own numbers loads as stored custom settings, shown read-only as stored.
    await page.waitForFunction(()=>(document.getElementById('profile-estimate-line')?.textContent||'').endsWith(' · 2 websites at once, adjusted for 2 websites'));
    await page.locator('#config-upload').setInputFiles({name:'spec.json',mimeType:'application/json',buffer:Buffer.from(JSON.stringify({maxPages:12,originMaxPages:9,maxResources:40,originMaxResources:30}))});
    await page.waitForFunction(()=>document.getElementById('message')?.textContent?.includes('JSON specifications loaded and validated'));
    assert.equal(await page.locator('#profile-label').textContent(),'Custom (from an older version)');assert.equal(await page.locator('#scan-form input[type=number]').count(),0,'no editable numbers');
    const pagesRow=page.locator('#option-uses tr').filter({has:page.getByRole('rowheader',{name:'Pages',exact:true})}).locator('td');await page.waitForFunction(()=>document.getElementById('option-uses-title')?.textContent==='What the stored settings use');assert.match((await pagesRow.textContent())||'',/^9 per website/);
    assert.equal(await page.locator('#authorized').isChecked(),false);
    await page.locator('#config-upload').setInputFiles({name:'bad.json',mimeType:'application/json',buffer:Buffer.from('{"maxPages":9999}')});
    await pause(500);assert.match((await page.locator('#message').textContent())||'',/Invalid setting: maxPages/);
    assert.equal(await page.locator('#profile-label').textContent(),'Custom (from an older version)','invalid upload must not replace reviewed settings');assert.match((await pagesRow.textContent())||'',/^9 per website/);
  }finally{if(browser)await browser.close().catch(()=>{});child?.kill();await rm(dir,{recursive:true,force:true,maxRetries:10,retryDelay:100});await app.close();}
});
