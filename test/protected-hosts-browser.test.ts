import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import path from 'node:path';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { chromium } from 'playwright';
import { Scanner } from '../src/scanner.js';
import { Detector, root } from '../src/detectors.js';
import { startDashboard } from '../src/dashboard.js';
import { dedicatedBrowser } from '../src/runtime-paths.js';
import { isProtectedHost } from '../src/protected-hosts.js';
/** Gov-block: the isolated browser's navigations (frames, a frame redirect) and subrequests (scripts, styles, fetch, beacons, WebSockets) to protected hosts are aborted
 * in the interception layer and recorded as protected-host blocks. The protected names point at a loopback canary that must never see a connection. */
async function canary(){let connections=0;const server=http.createServer((_q,res)=>res.end('must never arrive'));server.on('connection',()=>connections++);await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));return {port:(server.address() as any).port as number,count:()=>connections,close:()=>new Promise<void>(r=>{server.close(()=>r());server.closeAllConnections();})};}
async function site(port:number){
  // Names built at run time are invisible to static discovery, so only the browser can request them.
  const runtime=(label:string)=>`'http://'+['${label}','example','gov'].join('.')+':${port}'`;
  const routes:Record<string,[string,string]>={
    '/':['text/html',`<!doctype html><html><head><title>Owner</title><link rel="preconnect" href="http://pre.example.gov:${port}"><link rel="dns-prefetch" href="http://pre.example.gov:${port}"><link rel="stylesheet" href="http://static.example.mil:${port}/site.css"><script src="http://cdn.example.gov:${port}/lib.js"></script></head><body><h1>Owner</h1>
      <iframe src="http://forms.example.gov:${port}/embed"></iframe><img src="http://img.example.gov:${port}/logo.png" alt="">
      <script>fetch(${runtime('api')}+'/v1').catch(()=>{});navigator.sendBeacon(${runtime('beacon')}+'/b','x');try{new WebSocket('ws://'+['chat','example','gov'].join('.')+':${port}/live');}catch(e){}
        const frame=document.createElement('iframe');frame.src=${runtime('frame')}+'/x';document.body.appendChild(frame);</script><iframe src="/moved"></iframe></body></html>`],
    '/robots.txt':['text/plain','User-agent: *\nAllow: /\n']};
  const arrivals:string[]=[];const server=http.createServer((req,res)=>{arrivals.push(req.url||'');if(req.url==='/moved'){res.writeHead(302,{location:`http://redirect.example.gov:${port}/login`});res.end();return;}const r=routes[req.url||''];if(!r){res.statusCode=404;res.end('not found');return;}res.writeHead(200,{'content-type':r[0]});res.end(r[1]);});
  await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));
  return {origin:`http://127.0.0.1:${(server.address() as any).port}`,html:routes['/']![1],arrivals,close:()=>new Promise<void>(r=>{server.close(()=>r());server.closeAllConnections();})};
}
test('browser: navigations and subrequests to protected hosts are aborted in the interception layer, recorded, and never reach the network',{timeout:240000},async()=>{
  const c=await canary(),f=await site(c.port);let s:Scanner|undefined;
  try{s=new Scanner({urls:[f.origin+'/'],developmentFixtureOrigin:f.origin,browser:true,browserPages:1,browserSettleMs:1500,requestsPerSecond:20,originRequestsPerSecond:20,adjacentMaps:false,semanticAnalysis:false,maxRetries:0,maxDurationMs:90000},{detector:new Detector('disabled')});
    await s.init();const v=await s.run();
    assert.equal(v.browserStatus?.launch,true,JSON.stringify(v.browserStatus));assert.ok((v.browserStatus?.pages?.[0]?.blocked.scope||0)>=4,'refused dependencies count like out-of-scope ones in page readiness');assert.ok(v.resources.some(r=>r.kind==='browser'&&r.url===f.origin+'/'),'the isolated browser loaded the owner page');
    assert.equal(c.count(),0,'no connection ever reached the canary behind the protected names');
    const examples=new Map((v.scope?.protected?.examples||[]).map(e=>[e.host,e]));
    // Static discovery refuses the literal references first; the browser refuses its own requests for them and for the run-time names.
    for(const host of ['cdn.example.gov','static.example.mil','forms.example.gov','img.example.gov','api.example.gov','beacon.example.gov','frame.example.gov','redirect.example.gov'])assert.ok(examples.get(host)?.kinds.includes('browser'),host+' was refused in the browser: '+JSON.stringify(examples.get(host)));
    // The run-time names never appear literally in the served page, so the interception layer met them first; what the browser then reports
    // (observed navigations and hints) goes back through the scanner and is refused again there, still without a request.
    for(const host of ['api.example.gov','beacon.example.gov','frame.example.gov'])assert.ok(!f.html.includes(host),host+' is only reachable at run time');
    assert.ok(!v.resources.some(r=>r.reason==='scope'&&isProtectedHost(r.url)),'recorded as protected, not merely out of scope');
    // Chromium may preconnect to a hinted host through the deny-only proxy (never forwarded); such an event is counted as protected, never as an incomplete unrouted gap.
    assert.ok(!v.resources.some(r=>r.reason==='unrouted-browser-traffic'&&isProtectedHost(r.url))&&!v.limitations.some(g=>g.code==='unrouted-browser-traffic'&&isProtectedHost(g.url||'')));
    assert.ok(examples.has('chat.example.gov'),'the WebSocket host is refused (the channel is closed before connecting)');
    assert.ok(v.resources.filter(r=>r.reason==='protected-host').every(r=>r.status==='blocked'&&r.bytes===0&&r.attemptId===undefined));
    assert.ok(!v.resources.some(r=>isProtectedHost(r.url)&&['downloaded','scanned','http-error','redirect'].includes(String(r.status))));
    const gap=v.limitations.find(g=>g.code==='protected-host');assert.equal(gap?.incomplete,false);assert.equal(v.accounting!.protectedHostBlocks,v.scope!.protected!.references);
    assert.ok(f.arrivals.every(p=>!/example\.(?:gov|mil)/.test(p)));
  }finally{s?.dispose();await f.close();await c.close();}
});
test('dashboard UI: a blocked project shows the reason and offers no run, queue, schedule or trigger control; a scan lists its refused protected hosts apart from third parties',{timeout:120000},async()=>{
  const parent=process.env.EXPOSURE_DATA_DIR||path.join(root,'.cache');await mkdir(parent,{recursive:true});
  const dir=await mkdtemp(path.join(parent,'protected-ui-')),blockedId='55555555-5555-4555-8555-555555555555',now=new Date().toISOString(),c=await canary(),f=await site(c.port);
  await writeFile(path.join(dir,'workspace.json'),JSON.stringify({schema:'exposure-workspace/3',projects:[{id:blockedId,createdAt:now,authorizedAt:now,config:{name:'Ministry intranet',urls:['https://intranet.example.mil/']},schedule:{enabled:true,intervalHours:24,nextRun:now,missed:0},deploymentTrigger:{enabled:true,minIntervalMinutes:10,maxPerDay:24,recent:[]}}],reviews:{},settings:{retentionDays:90,maxScans:100,vaultMinutes:5},rules:[],ruleVersions:[],alerts:[]}));
  const app=await startDashboard({port:0,persistent:true,dataDir:dir,syntheticData:true}),browser=await chromium.launch({headless:true,executablePath:dedicatedBrowser()||chromium.executablePath()});
  try{const page=await browser.newPage(),errors:string[]=[];page.on('pageerror',e=>errors.push(e.message));page.setDefaultTimeout(10000);
    await page.goto(app.origin);await page.locator('#token').fill(app.token);await page.locator('#login-form button').click();await page.locator('#workspace').waitFor({state:'visible'});await page.locator('[data-view="projects"]').click();
    const card=page.locator('#project-list article',{hasText:'Ministry intranet'});await card.waitFor({state:'visible'});const reason='Exposure Desk never scans government, military, intelligence or law-enforcement websites: intranet.example.mil';
    assert.ok((await card.textContent())!.includes('Never runs: '+reason+'. There is no override.'),'the reason is shown once, with the way out');
    assert.equal(await card.getByRole('button',{name:'Queue scan'}).count(),0);assert.equal(await card.locator('input[type=checkbox]').isDisabled(),true,'it cannot be selected for a batch queue');
    const schedules=page.locator('#schedule-list');assert.ok((await schedules.textContent())!.includes('Never runs: '+reason));assert.ok((await schedules.textContent())!.includes('Never triggered: '+reason));
    for(const name of ['Pause schedule','Enable schedule','Disable','Disable deployment trigger','Enable deployment trigger'])assert.equal(await schedules.getByRole('button',{name,exact:true}).count(),0,name+' is not offered');
    assert.ok(!(await schedules.textContent())!.includes('cli.js trigger --project '+blockedId),'no trigger command is offered');
    assert.deepEqual(await page.locator('#project option[value="'+blockedId+'"]').evaluate(o=>[(o as HTMLOptionElement).disabled,o.textContent]),[true,'Ministry intranet (never runs: protected host)'],'it cannot be chosen to start a scan');
    // A finished scan that referenced protected hosts lists them apart from third-party origins, with no way to add them to a scan.
    const csrf=await page.evaluate(async()=>fetch('/api/session').then(r=>r.json()).then(j=>j.csrf));
    const started=await page.evaluate(async({csrf,origin}:{csrf:string;origin:string})=>fetch('/api/scans',{method:'POST',headers:{'Content-Type':'application/json','X-Dashboard-Request':'1','X-CSRF-Token':csrf},body:JSON.stringify({authorized:true,config:{name:'Protected UI',urls:[origin+'/'],developmentFixtureOrigin:origin,requestsPerSecond:20,adjacentMaps:false,browser:false,semanticAnalysis:false,maxDurationMs:30000}})}).then(r=>r.json()),{csrf,origin:f.origin});
    for(let i=0;i<300;i++){const s=app.scans.get(started.id);if(s&&s.state!=='running'&&s.state!=='ready')break;await new Promise(r=>setTimeout(r,100));}
    await page.locator('[data-view="running"]').click();await page.locator('#run-history').getByRole('button',{name:/^Open run #[a-f0-9]{8} Protected UI /}).first().click();
    await page.waitForFunction(()=>document.getElementById('scope-exclusions')?.textContent?.includes('Government, military, intelligence or law-enforcement hosts referenced'));
    const text=(await page.locator('#scope-exclusions').textContent())!;assert.match(text,/\d+ hosts · \d+ references · refused without any request; Exposure Desk never scans such websites and there is no override/);
    assert.match((await page.locator('#scope-counts').textContent())!,/government\/military\/law-enforcement hosts? refused \(never scanned\)/);
    const prot=page.locator('#scope-exclusions div',{hasText:'Government, military, intelligence or law-enforcement hosts referenced'}).last();await prot.locator('summary').click();
    assert.ok((await prot.textContent())!.includes('cdn.example.gov'));assert.equal(await prot.getByRole('button').count(),0,'a protected host can never be added to a scan');
    assert.equal(c.count(),0,'nothing reached the protected names');assert.deepEqual(errors,[]);
  }finally{await browser.close();await app.close();await f.close();await c.close();await rm(dir,{recursive:true,force:true});}
});
