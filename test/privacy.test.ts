import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, rm, writeFile, readdir, utimes } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { outboundHeaders, acceptLanguage, PRODUCT_USER_AGENT, HEADER_PROFILE, PolicyError } from '../src/transport.js';
import { makeConfig } from '../src/config.js';
import { Scanner } from '../src/scanner.js';
import { Detector, root } from '../src/detectors.js';
import { Evidence } from '../src/evidence.js';
import { startDashboard } from '../src/dashboard.js';
import { sweepStaleProfiles, PROFILE_MARKER } from '../src/local-files.js';
import { migrateProjectConfig, compareScans } from '../src/storage.js';
const pause=(ms:number)=>new Promise(r=>setTimeout(r,ms));
async function temp(prefix:string){const parent=process.env.EXPOSURE_DATA_DIR||path.join(root,'.cache');await mkdir(parent,{recursive:true});return mkdtemp(path.join(parent,prefix));}
type Arrival={method:string;url:string;headers:http.IncomingHttpHeaders;body:string};
/** Loopback target recording every request's method, path, headers and body. */
async function captureSite(){const arrivals:Arrival[]=[];const server=http.createServer((req,res)=>{let body='';req.on('data',c=>body+=c);req.on('end',()=>{arrivals.push({method:req.method||'',url:req.url||'',headers:{...req.headers},body});const p=(req.url||'/').split('?')[0];if(p==='/'||p==='/account/settings'){res.writeHead(200,{'content-type':'text/html'});res.end('<html><body><a href="/about">About</a><script src="/app.js"></script></body></html>');}else if(p==='/app.js'){res.writeHead(200,{'content-type':'text/javascript'});res.end('fetch("/api/data");');}else if(p==='/about'||p.startsWith('/api/')){res.writeHead(200,{'content-type':p.startsWith('/api/')?'application/json':'text/html'});res.end(p.startsWith('/api/')?'{}':'<html><body>about</body></html>');}else{res.writeHead(404,{'content-type':'text/html'});res.end('<html><body>Not found</body></html>');}});});await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));const origin=`http://127.0.0.1:${(server.address() as any).port}`;return {origin,arrivals,close:()=>new Promise<void>(r=>{server.close(()=>r());server.closeAllConnections();})};}
/** A local stand-in for an operator proxy: it only counts connections and never forwards anything. */
async function recorder(){let connections=0;const server=net.createServer(s=>{connections++;s.destroy();});await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));return {url:`http://127.0.0.1:${(server.address() as any).port}`,count:()=>connections,close:()=>new Promise<void>(r=>server.close(()=>r()))};}

test('one outbound header policy: product token and fixed language on static requests; strict-origin Referer and authorized Origin only on browser requests; nothing fabricated',()=>{
  assert.match(PRODUCT_USER_AGENT,/^Mozilla\/5\.0 \(compatible; ExposureDesk\/\d+\.\d+\)$/,'no build hash, OS or user details');assert.equal(HEADER_PROFILE,'v2');assert.equal(acceptLanguage('en-US'),'en-US,en;q=0.9');assert.equal(acceptLanguage('fr'),'fr');
  const target=new URL('https://www.example.com/app.js'),authorized=(o:string)=>['https://www.example.com','https://cdn.example.com'].includes(o);
  const page={referer:'https://www.example.com/account/settings?ref=newsletter&uid=123',origin:'https://www.example.com',cookie:'visit=1','user-agent':'Mozilla/5.0 HeadlessChrome/153','accept-language':'de-DE,de;q=0.9','sec-fetch-site':'same-origin','sec-fetch-mode':'cors','sec-fetch-dest':'script','sec-ch-ua':'"Chromium";v="153"','sec-ch-ua-platform':'"Windows"',priority:'u=1','x-requested-with':'XMLHttpRequest','upgrade-insecure-requests':'1','if-none-match':'"etag"'};
  const s=outboundHeaders(target,'http',page,{browserLocale:'en-US'},authorized);assert.deepEqual(Object.keys(s).sort(),['accept','accept-encoding','accept-language','host','user-agent']);assert.equal(s['user-agent'],PRODUCT_USER_AGENT);assert.equal(s['accept-language'],'en-US,en;q=0.9');
  assert.equal(outboundHeaders(target,'http',{},{staticUserAgent:'none',browserLocale:'en-US'},authorized)['user-agent'],undefined,'opt-out restores the pre-2.5 static behavior');
  const b=outboundHeaders(target,'browser',page,{browserLocale:'en-US'},authorized);
  assert.equal(b.referer,'https://www.example.com/','Referer is cut to the origin');assert.equal(b.origin,'https://www.example.com');assert.equal(b.cookie,'visit=1');assert.equal(b['user-agent'],'Mozilla/5.0 HeadlessChrome/153','browser keeps its real User-Agent');assert.equal(b['accept-language'],'en-US,en;q=0.9','the operating system language never passes');
  for(const k of ['sec-ch-ua','sec-ch-ua-platform','priority','x-requested-with','upgrade-insecure-requests','if-none-match'])assert.equal(b[k],undefined,k+' dropped');
  assert.equal(outboundHeaders(target,'browser',{referer:'https://cdn.example.com/lib/x.js?token=1'},{browserLocale:'en-US'},authorized).referer,'https://cdn.example.com/','authorized subdomain initiator kept as origin only');
  for(const ref of ['https://tracker.example.net/page','null','file:///C:/Users/me/page.html','not a url'])assert.equal(outboundHeaders(target,'browser',{referer:ref,origin:ref},{browserLocale:'en-US'},authorized).referer,undefined,ref);
  assert.equal(outboundHeaders(target,'browser',{origin:'null'},{},authorized).origin,undefined);assert.equal(outboundHeaders(target,'browser',{origin:'https://tracker.example.net'},{},authorized).origin,undefined);
  assert.equal(outboundHeaders(new URL('http://www.example.com/x'),'browser',{referer:'https://www.example.com/a'},{},o=>o==='https://www.example.com'||o==='http://www.example.com').referer,undefined,'no Referer on an https → http downgrade');
});

test('request privacy settings validate, default for legacy projects and survive redaction',()=>{
  const c=makeConfig({urls:['example.com']});assert.deepEqual([c.browserLocale,c.browserTimezone,c.staticUserAgent],['en-US','UTC','product']);
  assert.equal(makeConfig({urls:['example.com'],browserLocale:'fr-fr'}).browserLocale,'fr-FR');assert.equal(makeConfig({urls:['example.com'],browserTimezone:'Asia/Tokyo'}).browserTimezone,'Asia/Tokyo');
  for(const bad of [{browserLocale:'en_US'},{browserLocale:'x'.repeat(40)},{browserTimezone:'Mars/Base'},{browserTimezone:'../etc'},{staticUserAgent:'spoof'}])assert.throws(()=>makeConfig({urls:['example.com'],...bad} as any),JSON.stringify(bad));
  const legacy=makeConfig(migrateProjectConfig({urls:['https://example.com/'],relatedOrigins:[],sameRegistrableDomainDiscovery:false},'exposure-workspace/2'));assert.equal(legacy.staticUserAgent,'product');assert.equal(legacy.browserLocale,'en-US');
  const e=new Evidence(new Detector('disabled'));const red=e.redact({requestProfile:{headerProfile:'v2',staticUserAgent:PRODUCT_USER_AGENT,acceptLanguage:'en-US,en;q=0.9',browserLocale:'en-US',browserTimezone:'UTC',referrer:'strict-origin, authorized initiators only',egress:'direct'},browserStatus:{isolation:'checked',cleanup:'confirmed',isolationChecks:{freshProfile:true},pages:[{url:'https://example.com/',verdict:'partial',causes:['local-rate-limit'],pendingAtDeadline:{localQueue:2,network:0},blocked:{scope:1,policy:0,unrouted:0,examples:[]}}]}} as any) as any;
  assert.equal(red.requestProfile.staticUserAgent,PRODUCT_USER_AGENT);assert.equal(red.browserStatus.cleanup,'confirmed');assert.deepEqual(red.browserStatus.pages[0].causes,['local-rate-limit']);assert.equal(red.browserStatus.pages[0].pendingAtDeadline.localQueue,2);
});

test('the real request path screens what the page supplied before minimizing it, and sends only the documented headers',{timeout:30000},async()=>{
  const site=await captureSite();try{
    const s=new Scanner({urls:[site.origin+'/account/settings?ref=newsletter&uid=123'],developmentFixtureOrigin:site.origin,browser:false,adjacentMaps:false,requestsPerSecond:20,browserLocale:'fr-FR'},{detector:new Detector('disabled')});
    // A browser-supplied authentication header is blocked as a credential even though minimization would have dropped it.
    await assert.rejects(s.transport.one(site.origin+'/api/data',{headers:{'x-api-key':'nonfunctional-synthetic-key-0001'},kind:'browser'}),(e:any)=>e instanceof PolicyError&&e.code==='credential-in-request');assert.equal(site.arrivals.length,0,'blocked before any connection');
    await s.transport.one(site.origin+'/api/data',{headers:{referer:site.origin+'/account/settings?ref=newsletter&uid=123',origin:site.origin,cookie:'visit=1','user-agent':'Mozilla/5.0 HeadlessChrome/153','accept-language':'de-DE','sec-fetch-site':'same-origin','sec-fetch-mode':'cors','sec-fetch-dest':'empty','sec-ch-ua':'"Chromium"'},kind:'browser'});
    const routed=site.arrivals.at(-1)!;assert.equal(routed.headers.referer,site.origin+'/');assert.equal(routed.headers['accept-language'],'fr-FR,fr;q=0.9');assert.equal(routed.headers['sec-ch-ua'],undefined);assert.equal(routed.headers.cookie,'visit=1');
    const v=await s.run();const statics=site.arrivals.filter(a=>a.headers['user-agent']===PRODUCT_USER_AGENT);assert.ok(statics.length>=3,'robots, seed and discovered assets');
    for(const a of statics){assert.deepEqual(Object.keys(a.headers).sort(),['accept','accept-encoding','accept-language','connection','host','user-agent'],a.url);assert.equal(a.headers['accept-language'],'fr-FR,fr;q=0.9');}
    for(const a of site.arrivals)for(const [k,value]of Object.entries(a.headers))assert.ok(!String(value).includes('/account/settings')&&!String(value).includes('uid=123'),'no header repeats the page path or query: '+k);
    assert.equal(v.requestProfile!.headerProfile,'v2');assert.equal(v.requestProfile!.staticUserAgent,PRODUCT_USER_AGENT);
    const page=v.resources.find(r=>r.url===site.origin+'/account/settings?ref=newsletter&uid=123'&&r.code===200)!;assert.deepEqual(page.requestHeaderNames,['accept','accept-encoding','accept-language','host','user-agent']);
    // A record from a build that sent no User-Agent compares as uncertain, with the header change named.
    const before={schema:'exposure-history/2',projectId:'p',savedAt:'x',view:{...v,requestProfile:undefined}} as any,after={schema:'exposure-history/2',projectId:'p',savedAt:'x',view:v} as any;assert.ok(compareScans(before,after).reasons.some(r=>r.startsWith('Outgoing request headers changed')));
    s.dispose();
  }finally{await site.close();}
});

test('targets never receive local usernames, paths, run or project ids, dashboard tokens or tool-named probe paths',{timeout:60000},async()=>{
  const site=await captureSite(),dir=await temp('privacy-leak-');const app=await startDashboard({port:0,persistent:true,dataDir:dir,syntheticData:true});try{
    const login=await fetch(app.origin+'/api/login',{method:'POST',headers:{'Content-Type':'application/json',Origin:app.origin,'X-Dashboard-Request':'1'},body:JSON.stringify({token:app.token})});const cookie=login.headers.get('set-cookie')!.split(';')[0];const {csrf}=await login.json() as any;const headers={'Content-Type':'application/json',Origin:app.origin,'X-Dashboard-Request':'1','X-CSRF-Token':csrf,Cookie:cookie};
    const post=async(route:string,data:unknown)=>{const r=await fetch(app.origin+route,{method:'POST',headers,body:JSON.stringify(data)});assert.ok(r.ok,route);return r.json() as any;};
    const config={urls:[site.origin+'/'],developmentFixtureOrigin:site.origin,browser:false,deep:true,adjacentMaps:false,requestsPerSecond:20,semanticAnalysis:false};const p=await post('/api/projects/save',{config,authorized:true});const started=await post('/api/scans',{config,projectId:p.id,authorized:true,requestId:'leak-check-request-01'});
    for(let i=0;i<300;i++){const s=app.scans.get(started.id);if(s&&!['running','ready'].includes(s.state))break;await pause(100);}
    const sent=site.arrivals.map(a=>[a.method,a.url,JSON.stringify(a.headers),a.body].join('\n')).join('\n');assert.ok(site.arrivals.length>5);
    const user=os.userInfo().username;const forbidden=[started.id,started.id.slice(0,8),p.id,app.token,csrf,cookie.split('=')[1],'leak-check-request-01','__exposure','exposure_baseline',dir,os.homedir(),process.cwd(),root,...(user.length>=3?[user]:[])];
    for(const f of forbidden)assert.ok(!sent.toLowerCase().includes(f.toLowerCase()),'leaked: '+(f===app.token||f===csrf?'[secret]':f));
    assert.ok(!/ExposureDesk\/[\d.]+-rc|\+[a-f0-9]{16}/.test(sent),'no build id or prerelease tag in the product token');
    assert.equal(site.arrivals.filter(a=>/^\/[a-f0-9]{24}$/.test(a.url)).length,2,'deep baseline probes use neutral random paths');
  }finally{await app.close();await site.close();await rm(dir,{recursive:true,force:true});}
});

test('proxy environment variables are never used: a static CLI scan reaches the target directly and the recorder sees nothing',{timeout:60000},async()=>{
  const site=await captureSite(),rec=await recorder(),dir=await temp('privacy-proxy-');try{
    const cfg=path.join(dir,'scan.json'),out=path.join(dir,'report.json');await writeFile(cfg,JSON.stringify({urls:[site.origin+'/'],developmentFixtureOrigin:site.origin,browser:false,adjacentMaps:false,requestsPerSecond:20}));
    const env={...process.env,HTTP_PROXY:rec.url,HTTPS_PROXY:rec.url,ALL_PROXY:rec.url,http_proxy:rec.url,https_proxy:rec.url,NODE_USE_ENV_PROXY:'1',NO_PROXY:'',EXPOSURE_DATA_DIR:dir};
    const code=await new Promise<number>(resolve=>{const child=spawn(process.execPath,[path.join(root,'dist/src/cli.js'),'scan','--config',cfg,'--output',out],{cwd:dir,env,stdio:'ignore',windowsHide:true});child.once('exit',c=>resolve(c??2));});
    assert.ok([0,1,2].includes(code));assert.ok(existsSync(out),'report written');assert.ok(site.arrivals.some(a=>a.url==='/'),'the target was reached directly');assert.equal(rec.count(),0,'no connection to the proxy from environment variables');
  }finally{await rec.close();await site.close();await rm(dir,{recursive:true,force:true});}
});

test('the startup sweep removes orphaned browser profiles only: owner gone or older than a day; live, young and unrelated folders stay',async()=>{
  const parent=await temp('privacy-sweep-');try{
    const dead=await new Promise<number>(resolve=>{const c=spawn(process.execPath,['-e','0'],{stdio:'ignore',windowsHide:true});c.once('exit',()=>resolve(c.pid!));});
    const make=async(name:string,marker?:object,ageMs=0)=>{const d=path.join(parent,name);await mkdir(d);await writeFile(path.join(d,'Local State'),'{}');if(marker)await writeFile(path.join(d,PROFILE_MARKER),JSON.stringify(marker));if(ageMs){const t=new Date(Date.now()-ageMs);await utimes(d,t,t);}return d;};
    await make('browser-dead01',{ownerPid:dead,createdAt:new Date().toISOString()});await make('browser-live01',{ownerPid:process.pid,createdAt:new Date().toISOString()});await make('browser-old001',{ownerPid:process.pid,createdAt:new Date(Date.now()-25*3600000).toISOString()});
    await make('browser-young1');await make('browser-stale1',undefined,48*3600000);await make('browser-x');await make('engine-abc123',undefined,48*3600000);
    const result=await sweepStaleProfiles([parent,parent]);assert.deepEqual((await readdir(parent)).sort(),['browser-live01','browser-x','browser-young1','engine-abc123']);assert.equal(result.removed,3);
  }finally{await rm(parent,{recursive:true,force:true});}
});

test('the cleanup command sweeps orphaned browser profiles in the data folder and keeps live ones',async()=>{
  const dir=await temp('privacy-cleanup-');try{
    const tmp=path.join(dir,'tmp');await mkdir(tmp,{recursive:true});
    const dead=await new Promise<number>(resolve=>{const c=spawn(process.execPath,['-e','0'],{stdio:'ignore',windowsHide:true});c.once('exit',()=>resolve(c.pid!));});
    for(const [name,pid] of [['browser-dead02',dead],['browser-live02',process.pid]] as const){await mkdir(path.join(tmp,name));await writeFile(path.join(tmp,name,PROFILE_MARKER),JSON.stringify({ownerPid:pid,createdAt:new Date().toISOString()}));}
    const r=spawnSync(process.execPath,[path.join(root,'dist/src/cli.js'),'cleanup'],{encoding:'utf8',windowsHide:true,env:{...process.env,EXPOSURE_DATA_DIR:dir}});
    assert.equal(r.status,0,r.stderr);assert.match(r.stdout,/1 orphaned browser profile/);assert.deepEqual(await readdir(tmp),['browser-live02']);
  }finally{await rm(dir,{recursive:true,force:true});}
});
