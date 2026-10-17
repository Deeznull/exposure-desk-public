import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import path from 'node:path';
import { readdir } from 'node:fs/promises';
import { Scanner } from '../src/scanner.js';
import { Detector } from '../src/detectors.js';
import { PRODUCT_USER_AGENT } from '../src/transport.js';
import { privateParent } from '../src/local-files.js';
type Arrival={method:string;url:string;headers:http.IncomingHttpHeaders};
const SEED='/account/settings?ref=newsletter&uid=123';
/** Loopback application: a page with a script, a stylesheet, a frame, a cookie, a language/zone report, a shared-worker attempt and unload beacons; plus a page with many scripts and a third-party dependency. */
async function site(){const arrivals:Arrival[]=[];const html=(body:string)=>'<!doctype html><html><head><meta charset="utf-8"></head><body>'+body+'</body></html>';
  const routes:Record<string,[string,string]>={
    '/account/settings':['text/html',html('<link rel="stylesheet" href="/style.css"><h1>Settings</h1><iframe src="/frame.html"></iframe><script src="/app.js"></script>')],
    '/app.js':['text/javascript',"document.cookie='visit=1; path=/';fetch('/api/cookie');fetch('/report?lang='+encodeURIComponent(navigator.language)+'&tz='+encodeURIComponent(Intl.DateTimeFormat().resolvedOptions().timeZone)+'&sw='+typeof SharedWorker);try{new SharedWorker('/shared.js');}catch(e){}addEventListener('pagehide',function(){navigator.sendBeacon('/beacon','x');fetch('/keepalive',{method:'POST',keepalive:true,body:'y'}).catch(function(){});});"],
    '/style.css':['text/css','body{color:#123}'],'/frame.html':['text/html',html('<script src="/frame.js"></script>')],'/frame.js':['text/javascript',"fetch('/api/frame');"],
    '/many':['text/html',html(Array.from({length:24},(_,i)=>`<script src="/s/${i}.js"></script>`).join('')+'<script src="https://third-party.example.net/lib.js"></script>')],
  };
  const server=http.createServer((req,res)=>{arrivals.push({method:req.method||'',url:req.url||'',headers:{...req.headers}});req.resume();const p=(req.url||'/').split('?')[0];const r=routes[p];if(r){res.writeHead(200,{'content-type':r[0]});res.end(r[1]);}else if(/^\/s\/\d+\.js$/.test(p)){res.writeHead(200,{'content-type':'text/javascript'});res.end('void 0;');}else if(p.startsWith('/api/')||p==='/report'){res.writeHead(200,{'content-type':'application/json'});res.end('{}');}else{res.writeHead(404,{'content-type':'text/plain'});res.end('missing');}});
  await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));const origin=`http://127.0.0.1:${(server.address() as any).port}`;return {origin,arrivals,close:()=>new Promise<void>(r=>{server.close(()=>r());server.closeAllConnections();})};}
async function recorder(){let connections=0;const server=net.createServer(s=>{connections++;s.destroy();});await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));return {url:`http://127.0.0.1:${(server.address() as any).port}`,count:()=>connections,close:()=>new Promise<void>(r=>server.close(()=>r()))};}
const profiles=async()=>{try{return (await readdir(privateParent(true))).filter(n=>n.startsWith('browser-'));}catch{return [];}};

test('isolated browser visit: configured language and zone, strict-origin Referer, origin-bound cookies, no SharedWorker, guarded unload beacons, checked isolation and confirmed cleanup',{timeout:120000},async()=>{
  const f=await site(),rec=await recorder();const saved={HTTP_PROXY:process.env.HTTP_PROXY,HTTPS_PROXY:process.env.HTTPS_PROXY,ALL_PROXY:process.env.ALL_PROXY};const before=await profiles();
  // Operator proxy variables point at a recorder during the run: neither Chromium nor the local CDP connection may use them.
  process.env.HTTP_PROXY=rec.url;process.env.HTTPS_PROXY=rec.url;process.env.ALL_PROXY=rec.url;
  let s:Scanner|undefined;try{s=new Scanner({name:'Privacy fixture',urls:[f.origin+SEED],developmentFixtureOrigin:f.origin,browser:true,browserPages:1,requestsPerSecond:20,adjacentMaps:false,semanticAnalysis:false,browserLocale:'fr-FR',browserTimezone:'Asia/Tokyo',browserSettleMs:400,maxDurationMs:60000},{detector:new Detector('disabled')});
    const v=await s.run();const b=v.browserStatus!;assert.equal(b.launch,true);assert.equal(b.runtimePages,1);
    assert.equal(b.isolation,'checked',JSON.stringify(b.isolationChecks));assert.ok(Object.values(b.isolationChecks!).every(Boolean));assert.equal(b.cleanup,'confirmed');assert.deepEqual((await profiles()).filter(n=>!before.includes(n)),[],'no browser profile folder created by this visit remains');
    // Intercepted Chromium requests carry no fetch-metadata headers (Chromium adds them after interception), so the browser channel is identified by its own User-Agent.
    const browser=f.arrivals.filter(a=>a.headers['user-agent']!==PRODUCT_USER_AGENT),statics=f.arrivals.filter(a=>a.headers['user-agent']===PRODUCT_USER_AGENT);assert.ok(browser.length>=5&&statics.length>=2);
    for(const a of browser){assert.equal(a.headers['accept-language'],'fr-FR,fr;q=0.9',a.url);assert.ok(a.headers.referer===undefined||a.headers.referer===f.origin+'/',a.url+' '+a.headers.referer);assert.ok(!/ExposureDesk/.test(String(a.headers['user-agent'])),'browser keeps Chromium’s own User-Agent');for(const k of Object.keys(a.headers))assert.ok(!/^sec-ch-|^priority$|^x-/.test(k),k);}
    assert.ok(browser.some(a=>a.url!==SEED&&a.headers.referer===f.origin+'/'),'subresources carry an origin-only Referer');
    const report=browser.find(a=>a.url.startsWith('/report?'))!;const q=new URL(report.url,f.origin).searchParams;assert.deepEqual([q.get('lang'),q.get('tz'),q.get('sw')],['fr-FR','Asia/Tokyo','undefined'],'configured language and zone; SharedWorker is disabled');
    assert.equal(browser.find(a=>a.url==='/api/cookie')?.headers.cookie,'visit=1','a cookie set during the visit travels to its own origin through the guarded transport');assert.ok(browser.some(a=>a.url==='/api/frame'),'frame subresources are routed');
    assert.ok(!browser.some(a=>a.url==='/shared.js'),'the browser never loads a shared worker');for(const p of ['/beacon','/keepalive'])assert.ok(!f.arrivals.some(a=>a.url===p),p+' never reached the target');
    assert.ok(!v.resources.some(r=>r.kind==='browser-proxy'&&/\/(?:beacon|keepalive|shared\.js)$/.test(r.url)),'unload beacons and shared workers never escape routing to the deny proxy');
    for(const p of ['/beacon','/keepalive'])assert.equal(v.resources.find(r=>r.url===f.origin+p&&r.kind==='browser')?.reason,'method',p+' is a guarded method block (its body was screened, never sent)');assert.ok(!b.pages![0].causes.includes('blocked-dependency'),'unload-phase method blocks are not page dependencies: '+JSON.stringify(b.pages));
    for(const r of v.resources.filter(r=>r.kind==='browser'&&r.code)){const names=Object.keys(browser.find(a=>new URL(a.url,f.origin).href===r.url)?.headers||{}).filter(n=>n!=='connection').sort();if(names.length)assert.deepEqual(r.requestHeaderNames,names,r.url);}
    for(const a of f.arrivals)for(const value of Object.values(a.headers))assert.ok(!String(value).includes('uid=123')&&!String(value).includes('/account/settings'),'no header repeats the page path or query');
    assert.equal(rec.count(),0,'proxy variables were not used by Chromium or the CDP connection');assert.equal(v.requestProfile!.browserTimezone,'Asia/Tokyo');
  }finally{s?.dispose();for(const [k,val]of Object.entries(saved)){if(val===undefined)delete process.env[k];else process.env[k]=val;}await rec.close();await f.close();}
});

test('bounded readiness separates local rate-limit queueing from blocked dependencies; analysis backlog never aborts page requests',{timeout:120000},async()=>{
  const f=await site();let s:Scanner|undefined;try{s=new Scanner({urls:[f.origin+'/many'],developmentFixtureOrigin:f.origin,browser:true,browserPages:1,requestsPerSecond:4,originRequestsPerSecond:4,concurrency:2,adjacentMaps:false,semanticAnalysis:false,debuggerScripts:false,browserSettleMs:300,timeoutMs:2500,maxDurationMs:90000},{detector:new Detector('disabled')});
    const v=await s.run();const page=v.browserStatus!.pages!.find(p=>p.url===f.origin+'/many')!;assert.ok(page,'a readiness record exists for the page');
    assert.equal(page.verdict,'partial');assert.ok(page.causes.includes('local-rate-limit'),JSON.stringify(page));assert.ok(page.pendingAtDeadline.localQueue>0);assert.ok((page.extendedMs||0)>0,'one bounded extension while requests waited locally');
    assert.ok(page.causes.includes('blocked-dependency')&&page.blocked.scope>=1,'the third-party script is listed as a scope-blocked dependency');assert.ok(page.blocked.examples.includes('https://third-party.example.net'));
    assert.ok(!v.limitations.some(g=>g.code==='browser-queue-limit'),'request gate is separate from analysis');assert.ok(!f.arrivals.some(a=>a.url.includes('third-party')));
    assert.ok(v.limitations.some(g=>g.code==='browser-settle-deadline'&&/waiting in the local rate-limit queue/.test(g.detail)),'the gap explains local queueing');
  }finally{s?.dispose();await f.close();}
});

// External review F-01: a sibling-host frame starts with no committed document, so its navigation once took the destination as its own principal and kept a domain cookie.
test('domain cookies set by a page (response and script) stay with that host: a sibling-host frame and its subresources receive none, the page’s own requests keep them',{timeout:120000},async()=>{
  const arrivals:Arrival[]=[];let assets='';
  const server=http.createServer((req,res)=>{arrivals.push({method:req.method||'',url:(req.headers.host||'')+(req.url||''),headers:{...req.headers}});req.resume();const host=String(req.headers.host||'').split(':')[0],p=req.url||'/';
    const send=(type:string,body:string,extra:Record<string,string>={})=>{res.writeHead(200,{'content-type':type,...extra});res.end(body);};
    if(host==='owner.example.com'&&p==='/')return send('text/html','<!doctype html><html><body><script src="/app.js"></script></body></html>',{'set-cookie':'response_shared=synthetic-nonfunctional; Domain=.example.com; Path=/'});
    if(host==='owner.example.com'&&p==='/app.js')return send('text/javascript',`document.cookie='script_shared=1; domain=.example.com; path=/';fetch('/api/own').then(function(){var f=document.createElement('iframe');f.src=${JSON.stringify(assets+'/frame.html')};document.body.appendChild(f);});`);
    if(host==='owner.example.com'&&p==='/api/own')return send('application/json','{}');
    if(host==='assets.example.com'&&p==='/frame.html')return send('text/html','<!doctype html><html><body><script src="/frame.js"></script></body></html>');
    if(host==='assets.example.com'&&p==='/frame.js')return send('text/javascript','void 0;');
    res.writeHead(404,{'content-type':'text/plain'});res.end('missing');});
  await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));const port=(server.address() as any).port,owner=`http://owner.example.com:${port}`;assets=`http://assets.example.com:${port}`;
  let s:Scanner|undefined;try{s=new Scanner({urls:[owner+'/'],relatedOrigins:[assets],privateOrigins:[owner,assets],browser:true,browserPages:1,browserSettleMs:500,requestsPerSecond:20,originRequestsPerSecond:20,adjacentMaps:false,semanticAnalysis:false,maxRetries:0,maxDurationMs:60000},{detector:new Detector('disabled'),resolver:async host=>/^(?:owner|assets)\.example\.com$/.test(host)?[{address:'127.0.0.1',family:4}]:[]});
    const v=await s.run();assert.equal(v.browserStatus?.launch,true,JSON.stringify(v.browserStatus));
    const browser=arrivals.filter(a=>a.headers['user-agent']!==PRODUCT_USER_AGENT),own=browser.find(a=>a.url.endsWith('/api/own'))?.headers.cookie||'';
    assert.ok(own.includes('response_shared=')&&own.includes('script_shared=1'),'both cookies still travel to the page’s own origin: '+own.replace(/=[^;]*/g,'=…'));
    const sibling=browser.filter(a=>a.url.startsWith('assets.example.com:'));assert.deepEqual(sibling.map(a=>a.url.replace(/^[^/]*/,'')).sort(),['/frame.html','/frame.js'],'the sibling frame and its script were loaded by the browser');
    for(const a of sibling)assert.equal(a.headers.cookie,undefined,a.url+' must not receive the page’s cookies');
    for(const path of ['/frame.html','/frame.js']){const routed=v.resources.find(r=>r.url===assets+path&&r.kind==='browser');assert.ok(routed,path+' went through the guarded route');assert.ok(!routed!.requestHeaderNames?.includes('cookie'),path);}
  }finally{s?.dispose();await new Promise<void>(r=>{server.close(()=>r());server.closeAllConnections();});}
});

// 2.8.0 (w5-fix): on Linux a page's page-leave handlers ran a second time when the browser context closed, after routing had stopped, and their beacons
// reached the deny proxy. Leaving a page for the next one does the same on every platform. The drain runs them once, routed, for the page and its frames.
test('page-leave handlers of a page and its frames run once, routed: leaving for the next page or closing sends nothing to the deny proxy',{timeout:120000},async()=>{
  const arrivals:string[]=[];const html=(body:string)=>'<!doctype html><html><head><meta charset="utf-8"></head><body>'+body+'</body></html>';
  const pages:Record<string,string>={
    '/leave/one':html('<h1>One</h1><iframe src="/leave/frame"></iframe><script>addEventListener("pagehide",function(){navigator.sendBeacon("/leave/beacon-one","x");fetch("/leave/keepalive-one",{method:"POST",keepalive:true,body:"y"}).catch(function(){});});</script>'),
    '/leave/frame':html('<script>addEventListener("pagehide",function(){navigator.sendBeacon("/leave/beacon-frame","f");});</script>'),
    '/leave/two':html('<h1>Two</h1><script>addEventListener("pagehide",function(){navigator.sendBeacon("/leave/beacon-two","z");});</script>'),
  };
  const server=http.createServer((req,res)=>{const p=(req.url||'/').split('?')[0];arrivals.push((req.headers['user-agent']===PRODUCT_USER_AGENT?'static ':'')+p);req.resume();if(pages[p]){res.writeHead(200,{'content-type':'text/html'});res.end(pages[p]);}else{res.writeHead(404,{'content-type':'text/plain'});res.end('missing');}});
  await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));const origin=`http://127.0.0.1:${(server.address() as any).port}`;
  let s:Scanner|undefined;try{s=new Scanner({urls:[origin+'/leave/one'],browserNavigationUrls:[origin+'/leave/two'],developmentFixtureOrigin:origin,browser:true,browserPages:2,requestsPerSecond:20,adjacentMaps:false,semanticAnalysis:false,browserSettleMs:300,maxDurationMs:60000},{detector:new Detector('disabled')});
    const v=await s.run();const b=v.browserStatus!;assert.equal(b.launch,true);assert.equal(b.runtimePages,2,JSON.stringify(b.pages));
    const leave=['/leave/beacon-one','/leave/keepalive-one','/leave/beacon-frame','/leave/beacon-two'];
    assert.deepEqual(v.resources.filter(r=>r.kind==='browser-proxy'&&/\/leave\/(?:beacon|keepalive)/.test(r.url)).map(r=>r.url.replace(origin,'')+' '+r.provenance?.phase),[],'no page-leave request reaches the deny proxy, when the page is left for the next one or closed');
    for(const p of leave)assert.equal(v.resources.find(r=>r.url===origin+p&&r.kind==='browser')?.reason,'method',p+' is routed and blocked by method policy (its body was screened, never sent)');
    assert.deepEqual(arrivals.filter(a=>leave.includes(a)),[],'the browser never sends a page-leave request to the target');
    for(const p of b.pages!)assert.ok(!p.causes.some(c=>c==='blocked-dependency'||c==='unrouted-dependency'),'page-leave requests are not dependencies of the next page: '+JSON.stringify(b.pages));
  }finally{s?.dispose();await new Promise<void>(r=>{server.close(()=>r());server.closeAllConnections();});}
});
