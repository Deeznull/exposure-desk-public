import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {createHash} from 'node:crypto';
import {mkdtemp,rm} from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {Scanner} from '../src/scanner.js';
import {Detector} from '../src/detectors.js';
import {startDashboard} from '../src/dashboard.js';
import {chromium,type Browser} from 'playwright';
import {dedicatedBrowser} from '../src/runtime-paths.js';
import {subjectGaps} from './browser-exit.js';
const key=(name:string)=>'sk-proj-'+createHash('sha512').update('browser-completeness-548-'+name).digest('base64url').slice(0,64);
test('worker and separate frame debugger code is captured; every descendant request stays guarded',{timeout:60000},async()=>{
 const worker=key('worker'),frame=key('frame'),arrivals:string[]=[],dns:string[]=[];let pageOrigin='',frameOrigin='',privateOrigin='';
 const codes=(s:string)=>JSON.stringify([...s].map(c=>c.charCodeAt(0)));
 const threats=`fetch('/must-not-arrive?api_key=private').catch(()=>{});fetch('${'PRIVATE_ORIGIN'}/private').catch(()=>{});fetch('/redirect').catch(()=>{});fetch('/must-not-put',{method:'PUT',body:'ordinary'}).catch(()=>{});fetch('/safe').catch(()=>{});`;
 const server=http.createServer((req,res)=>{arrivals.push(req.headers.host+req.url!);res.setHeader('Content-Type','text/html');if(req.url==='/')res.end(`<script>new Worker('/worker.js')</script><iframe src="${frameOrigin}/frame"></iframe>`);else if(req.url==='/worker.js'){res.setHeader('Content-Type','text/javascript');res.end(`(0,eval)('void '+JSON.stringify(String.fromCharCode(...${codes(worker)})));${threats.replaceAll('PRIVATE_ORIGIN',privateOrigin)}`);}else if(req.url==='/frame')res.end(`<script>(0,eval)('void '+JSON.stringify(String.fromCharCode(...${codes(frame)})));${threats.replaceAll('PRIVATE_ORIGIN',privateOrigin)}</script>`);else if(req.url==='/approved')res.end('<script>(0,eval)("void "+JSON.stringify(String.fromCharCode(...'+codes(key('approved'))+')));</script>');else if(req.url==='/redirect'){res.writeHead(302,{Location:'http://outside.invalid/never'});res.end();}else res.end('ordinary');});
 await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));const port=(server.address() as any).port;pageOrigin='http://page.example.com:'+port;frameOrigin='http://frame.example.net:'+port;privateOrigin='http://private.example.org:'+port;
 const s=new Scanner({urls:[pageOrigin],relatedOrigins:[frameOrigin,privateOrigin],privateOrigins:[pageOrigin,frameOrigin],browser:true,browserPages:2,browserNavigationUrls:[pageOrigin+'/approved#/settings'],browserLazyAssetLimit:0,browserSettleMs:100,requestsPerSecond:20,originRequestsPerSecond:20,maxDurationMs:40000,timeoutMs:2000,adjacentMaps:false,semanticAnalysis:false,maxRetries:0},{detector:new Detector('disabled'),resolver:async host=>{dns.push(host);return [{address:'127.0.0.1',family:4}];}});
 try{const v=await s.run();assert.equal(v.browserStatus!.launch,true);assert.equal(v.browserStatus!.runtimePages,2);assert.ok(arrivals.some(a=>a.endsWith('/approved')));for(const value of [worker,frame,key('approved')]){const f=[...s.evidence.findings.values()].find(f=>s.evidence.reveal(f.id).value===value);assert.ok(f,'Generated value must be collected from attached descendant debugger');assert.ok(f.occurrences.some(o=>o.sourceLabel?.includes('debugger')&&o.exposure==='runtime-memory'));}
 assert.ok(v.resources.some(r=>r.kind==='runtime-capture'&&r.chain.includes('Debugger loaded script')));assert.ok(v.resources.some(r=>r.reason==='credential-in-request'));assert.ok(v.resources.some(r=>r.reason==='private-address'));assert.ok(v.resources.some(r=>r.reason==='scope'&&r.url.includes('outside.invalid')));assert.ok(v.resources.some(r=>/method/.test(r.reason||'')));assert.ok(dns.some(h=>h==='private.example.org'));assert.ok(!dns.includes('outside.invalid'));
 assert.ok(!arrivals.some(a=>/must-not|\/private|\/never/.test(a)));assert.ok(arrivals.every(a=>/^(?:page.example.com|frame.example.net):/.test(a)));assert.ok(v.resources.filter(r=>r.code).every(r=>r.timings&&r.attemptId));assert.ok(s.transport.requests<=s.config.maxResources);console.log(JSON.stringify({descendantCoverage:{runtimeCaptures:v.accounting!.runtimeCaptures,guardedRequests:s.transport.requests,blocked:v.resources.filter(r=>r.status==='blocked').length,elapsedMs:v.elapsedMs,channels:v.resources.filter(r=>r.kind==='runtime-capture').map(r=>r.url.includes('frame.example.net')?'iframe':'worker-or-page'),gaps:v.limitations.map(g=>g.code)}}));
 }finally{s.dispose();await new Promise<void>(r=>{server.close(()=>r());server.closeAllConnections();});}
});
test('scripts parsed after the page inspection has ended are not captured, so no capture is left pending when the scan ends',{timeout:60000},async()=>{
 // When the page is left (pagehide) it starts generating scripts: from one second later, a new one every 200 ms until the browser closes. The capture of the
 // page's inline script is held until the session's cleanup has begun plus 1.5 s, so the cleanup waits for it while those scripts are parsed (as Chromium's own
 // script about a second after loading can be on a slow machine). Captured, they would start after the cleanup listed the work it waits for; their analysis
 // (held here until the scan has returned) would not be awaited, the captures would stay pending and the run would end incomplete ("Run ended before inspection").
 const page=`<html><body><h1>Late scripts</h1><script>void 'early-capture';addEventListener('pagehide',()=>{let n=0;setTimeout(()=>setInterval(()=>(0,eval)('void '+JSON.stringify(['late','capture',++n].join('-'))),200),1000);});</script></body></html>`;
 const server=http.createServer((req,res)=>{res.setHeader('Content-Type','text/html');res.end(req.url==='/'?page:'ordinary');});
 await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));const origin='http://127.0.0.1:'+(server.address() as any).port;
 const s=new Scanner({urls:[origin+'/'],developmentFixtureOrigin:origin,browser:true,adjacentMaps:false,requestsPerSecond:20,maxDurationMs:60000,maxResources:50,timeoutMs:5000,browserSettleMs:200,browserScrollSteps:1});
 // The page's record is published when its inspection ends, immediately before the cleanup.
 const cleanupBegun=()=>!!s.browserStatus.pages?.length;let returned=false;const late:boolean[]=[],held:Promise<unknown>[]=[];
 const until=async(done:()=>boolean,ms:number)=>{const end=Date.now()+ms;while(!done()&&Date.now()<end)await new Promise(r=>setTimeout(r,20));};
 const inspect=s.evidence.inspect.bind(s.evidence) as (...args:any[])=>Promise<void>;
 s.evidence.inspect=(text:string,...rest:any[])=>{
  if(rest[1]?.[1]!=='Debugger loaded script')return inspect(text,...rest);
  if(text.includes('early-capture'))return (async()=>{await until(cleanupBegun,30000);await new Promise(r=>setTimeout(r,1500));return inspect(text,...rest);})();
  if(!/late-capture-\d/.test(text))return inspect(text,...rest);
  const afterCleanup=cleanupBegun();late.push(afterCleanup);const p=(async()=>{if(afterCleanup)await until(()=>returned,6000);return inspect(text,...rest);})();held.push(p);return p;
 };
 try{await s.init();const v=await s.run();returned=true;
  assert.equal(v.browserStatus!.launch,true,'Chromium must actually run');assert.equal(v.browserStatus!.runtimePages,1);
  assert.ok(v.resources.some(r=>r.kind==='runtime-capture'&&r.analysis==='analyzed'),'the page’s own script is captured and analysed');
  assert.deepEqual(v.resources.filter(r=>r.kind==='runtime-capture'&&r.analysis!=='analyzed').map(r=>[r.url,r.analysis]),[],'every capture started is analysed before the scan ends');
  const {open,exitNotConfirmed}=subjectGaps(v.limitations,'late scripts');assert.deepEqual(open.map(g=>[g.code,g.url||'']),[],'no incomplete gap remains');assert.equal(v.state,exitNotConfirmed?'incomplete':'completed');
  console.log(JSON.stringify({captureWindow:{lateCaptures:late.length,startedAfterCleanup:late.filter(Boolean).length,elapsedMs:v.elapsedMs}}));
 }finally{returned=true;await Promise.allSettled(held);s.dispose();await new Promise<void>(r=>{server.close(()=>r());server.closeAllConnections();});}
});
test('requests a page starts after its inspection has ended are aborted and never sent, so no analysis is left pending when the scan ends',{timeout:60000},async()=>{
 // When the page is left (pagehide) it starts fetches: from one second later, a new one every 200 ms until the browser closes. The capture of the page's
 // inline script is held until the session's cleanup has begun plus 1.5 s, so the cleanup waits while those fetches are made. Routed, they would be sent
 // to the website after the inspection had ended and their analysis would start after the cleanup's wait began.
 const page=`<html><body><h1>Late requests</h1><script>void 'early-request-page';addEventListener('pagehide',()=>{let n=0;setTimeout(()=>setInterval(()=>{fetch('/late-'+(++n)).catch(()=>{});},200),1000);});</script></body></html>`;
 let cleanupBegun=()=>false;const late:{path:string,afterCleanup:boolean}[]=[];
 const server=http.createServer((req,res)=>{if(req.url!.startsWith('/late-'))late.push({path:req.url!,afterCleanup:cleanupBegun()});res.setHeader('Content-Type','text/html');res.end(req.url==='/'?page:'ordinary');});
 await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));const origin='http://127.0.0.1:'+(server.address() as any).port;
 const scan=new Scanner({urls:[origin+'/'],developmentFixtureOrigin:origin,browser:true,adjacentMaps:false,requestsPerSecond:20,maxDurationMs:60000,maxResources:50,timeoutMs:5000,browserSettleMs:200,browserScrollSteps:1});
 // The page's record is published when its inspection ends, immediately before the cleanup.
 cleanupBegun=()=>!!scan.browserStatus.pages?.length;
 const until=async(done:()=>boolean,ms:number)=>{const end=Date.now()+ms;while(!done()&&Date.now()<end)await new Promise(r=>setTimeout(r,20));};
 const inspect=scan.evidence.inspect.bind(scan.evidence) as (...args:any[])=>Promise<void>;
 scan.evidence.inspect=(text:string,...rest:any[])=>{
  if(rest[1]?.[1]==='Debugger loaded script'&&text.includes('early-request-page'))return (async()=>{await until(cleanupBegun,30000);await new Promise(r=>setTimeout(r,1500));return inspect(text,...rest);})();
  return inspect(text,...rest);
 };
 try{await scan.init();const v=await scan.run();
  assert.equal(v.browserStatus!.launch,true,'Chromium must actually run');assert.equal(v.browserStatus!.runtimePages,1);
  assert.ok(v.resources.some(r=>r.kind==='runtime-capture'&&r.analysis==='analyzed'),'the page’s own script is captured and analysed');
  assert.deepEqual(late.filter(l=>l.afterCleanup).map(l=>l.path),[],'no request started after the inspection ended reaches the website');
  assert.deepEqual(v.resources.filter(r=>r.kind==='browser'&&r.status!=='blocked'&&r.analysis!=='analyzed').map(r=>[r.url,r.analysis]),[],'every routed response is analysed before the scan ends');
  const {open,exitNotConfirmed}=subjectGaps(v.limitations,'late requests');assert.deepEqual(open.map(g=>[g.code,g.url||'']),[],'no incomplete gap remains');assert.equal(v.state,exitNotConfirmed?'incomplete':'completed');
  console.log(JSON.stringify({routingWindow:{lateRequests:late.length,sentAfterCleanup:late.filter(l=>l.afterCleanup).length,elapsedMs:v.elapsedMs}}));
 }finally{scan.dispose();await new Promise<void>(r=>{server.close(()=>r());server.closeAllConnections();});}
});
test('actual dashboard validates adaptive JSON, shows masked audit and preserves scoped feedback',{timeout:45000},async t=>{
 const dir=await mkdtemp(path.join(os.tmpdir(),'exposure-complete-ui-')),app=await startDashboard({port:0,persistent:true,dataDir:dir,syntheticData:true});
 // 2.9.1: the harness's own teardown runs after the test, outside the time its dashboard steps are given: on a machine saturated by parallel suites Playwright's own Chromium
 // took 20 s to 150 s to exit (measured), which ran past the time limit after every step had passed.
 let browser:Browser|undefined;t.after(async()=>{await browser?.close();await app.close();await rm(dir,{recursive:true,force:true});});
 browser=await chromium.launch({headless:true,executablePath:dedicatedBrowser()||chromium.executablePath()});{const page=await browser.newPage(),errors:string[]=[];page.on('pageerror',e=>errors.push(e.message));await page.goto(app.origin);await page.locator('#token').fill(app.token);await page.locator('#login-form button').click();await page.locator('#workspace').waitFor({state:'visible'});await page.locator('[data-view="new"]').click();await page.locator('#scan-advanced').evaluate((e:HTMLElement)=>{(e as HTMLDetailsElement).open=true;});await page.locator('#config-upload').setInputFiles({name:'legacy.json',mimeType:'application/json',buffer:Buffer.from(JSON.stringify({urls:['https://unit.invalid'],sizingMode:'adaptive'}))});await page.waitForFunction(()=>document.getElementById('message')?.textContent?.startsWith('JSON specifications loaded'));assert.equal(await page.locator('#profile-label').textContent(),'Custom (from an older version)','a JSON file with its own sizing loads as stored custom settings (the scan page has no sizing controls)');await page.locator('#urls').fill('https://unit.invalid');await page.locator('#sensitive-fields').fill('private profile.ssn');await page.locator('#authorized').check();await page.locator('#save-project').click();await page.waitForFunction(()=>document.getElementById('message')?.textContent==='Authorized project saved locally.');
 const project=app.desk.store!.projects[0];assert.equal(project.config.sizingMode,'adaptive');assert.deepEqual(project.config.sensitiveFields,[{path:'profile.ssn',expectation:'private'}]);
 const scan=new Scanner({...project.config,browser:false},{detector:new Detector('disabled'),correlationKey:await app.desk.store!.key(project.id)});app.scans.set(scan.id,scan);app.desk.scanProjects.set(scan.id,project.id);const value=key('ui');await scan.evidence.inspect('const apiKey='+JSON.stringify(value)+';const publishableKey="pk_live_A4b9C8d7E6f5G4h3I2j1K0l9";','https://unit.invalid/app.js',[],'Public response');await scan.evidence.triage!.flush();scan.state='completed';await app.desk.store!.record(project.id,scan.view());await page.locator('[data-view="running"]').click();await page.waitForFunction(()=>document.getElementById('run-history')?.textContent?.includes('unit.invalid'));
 // 2.9.1 (flake root cause): opening a run loads it and then showed the Running page, so a click on "Open findings" made while the run was still loading (a loaded machine) was undone and the
 // Suppression reason input below was hidden. The run's loading is held back here, so that click always comes first; the page the person moved to must stay open after the run loads.
 const scanRoute=/\/api\/scans\/[^/?]+$/;let slow=true;const held:Promise<void>[]=[];
 await page.route(scanRoute,route=>{if(!slow||route.request().method()!=='GET')return route.continue();const p=new Promise<void>(r=>setTimeout(r,1500)).then(()=>route.continue());held.push(p);return p;});
 await page.locator('#run-history').getByRole('button',{name:/^Open run #[a-f0-9]{8} unit.invalid completed$/}).click();await page.locator('#open-findings').click();
 await page.locator('#findings .finding').first().waitFor({state:'attached'});slow=false;await Promise.all(held);await page.unroute(scanRoute);await page.waitForTimeout(300);
 assert.ok(await page.locator('[data-page="findings"]').isVisible(),'still on the findings page after the run loaded');assert.ok(!(await page.locator('[data-page="running"]').isVisible()));
 assert.equal(await page.locator('#dismissed-observations details').count(),1);assert.ok(!(await page.locator('#dismissed-observations').textContent())!.includes('pk_live_'));
 const article=page.locator('.finding').first();await article.locator('details').last().evaluate((e:HTMLElement)=>{(e as HTMLDetailsElement).open=true;});await article.locator('input[aria-label="Suppression reason"]').fill('Owner reviewed synthetic finding');await article.getByRole('button',{name:'Mark false positive (expires)'}).click();await page.locator('#audit').check();await page.waitForFunction(()=>document.getElementById('findings')?.textContent?.includes('Project feedback: false-positive'));assert.ok(!(await page.content()).includes(value));await page.locator('.finding').first().locator('details').last().evaluate((e:HTMLElement)=>{(e as HTMLDetailsElement).open=true;});await page.locator('.finding').first().getByRole('button',{name:'Undo feedback'}).click();await page.waitForFunction(()=>document.getElementById('findings')?.textContent?.includes('Project feedback: unreviewed'));assert.equal(errors.length,0);
 }
});
