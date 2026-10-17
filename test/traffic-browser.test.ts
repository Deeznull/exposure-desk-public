import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createHash } from 'node:crypto';
import { Scanner } from '../src/scanner.js';
import { Detector } from '../src/detectors.js';
import { report } from '../src/reports.js';
import type { ScanView } from '../src/types.js';
import { syntheticBundle } from './large-bundle.js';
/** 2.6 Part 2: Deep audit + Low-impact against Deep audit + Normal on one loopback website with the isolated browser. Synthetic, nonfunctional, seed-derived keys only. */
const key=(name:string)=>'sk-proj-'+createHash('sha512').update('unit-traffic-browser-'+name).digest('base64url').slice(0,64);
/** The large-bundle case: a deterministic 1.25 MB module whose key is split across constants near its end. */
const BUNDLE=syntheticBundle({seed:'ExposureDesk/traffic-browser/2.6/1'});
const KEYS={inline:key('inline'),app:key('app'),map:key('map'),env:key('env'),runtime:key('runtime'),bundle:BUNDLE.value};
/** Out-of-scope loopback canary: it counts connections and must never see one. */
async function canary(){let connections=0;const server=http.createServer((_q,res)=>res.end('must never arrive'));server.on('connection',()=>connections++);await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));return {origin:`http://127.0.0.1:${(server.address() as any).port}`,count:()=>connections,close:()=>new Promise<void>(r=>{server.close(()=>r());server.closeAllConnections();})};}
async function site(canaryOrigin:string){
  const cacheable={'cache-control':'max-age=600'},half=KEYS.runtime.length>>1;
  const routes:Record<string,[string,string,Record<string,string>?]>={
    '/':['text/html',`<!doctype html><html><head><title>Traffic fixture</title><link rel="preconnect" href="${canaryOrigin}"></head><body><h1>Fixture</h1><img src="${canaryOrigin}/pixel.png" alt=""><script>window.PUBLIC_SETTINGS={openai:${JSON.stringify(KEYS.inline)}};</script><script src="/app.js"></script><script src="/vendor.js"></script><script type="module" src="/bundle.js"></script></body></html>`,cacheable],
    '/app.js':['text/javascript',`const client={apiKey:${JSON.stringify(KEYS.app)}};window.RUNTIME_CONFIG={token:[${JSON.stringify(KEYS.runtime.slice(0,half))},${JSON.stringify(KEYS.runtime.slice(half))}].join('')};fetch(${JSON.stringify(canaryOrigin+'/beacon')}).catch(()=>{});\n//# sourceMappingURL=app.js.map`,cacheable],
    '/app.js.map':['application/json',JSON.stringify({version:3,file:'app.js',sources:['src/client.ts'],sourcesContent:[`export const serverKey=${JSON.stringify(KEYS.map)};`],names:[],mappings:'AAAA'}),cacheable],
    '/vendor.js':['text/javascript','/* vendor bundle */\n'+'var vendorValue=0;'.repeat(6000),cacheable],
    '/bundle.js':['text/javascript',BUNDLE.text,cacheable],
    '/.env':['text/plain',`OPENAI_API_KEY=${KEYS.env}\n`],
    '/robots.txt':['text/plain','User-agent: *\nAllow: /\n']
  };
  const arrivals:{path:string;at:number;ua:string}[]=[],sockets=new Set<import('node:net').Socket>();
  const server=http.createServer((req,res)=>{arrivals.push({path:req.url||'',at:Date.now(),ua:String(req.headers['user-agent']||'')});const r=routes[req.url||''];if(!r){res.statusCode=404;res.end('not found');return;}res.writeHead(200,{'content-type':r[0],...(r[2]||{})});res.end(r[1]);});
  server.on('connection',s=>{sockets.add(s);s.on('close',()=>sockets.delete(s));});await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));
  return {origin:`http://127.0.0.1:${(server.address() as any).port}`,arrivals,routes,open:()=>sockets.size,count:(path:string)=>arrivals.filter(a=>a.path===path).length,close:()=>new Promise<void>(r=>{server.close(()=>r());server.closeAllConnections();})};
}
async function scan(traffic:'normal'|'low-impact',canaryOrigin:string){
  const f=await site(canaryOrigin),s=new Scanner({urls:[f.origin+'/'],developmentFixtureOrigin:f.origin,coverage:'deep',traffic},{detector:new Detector()});
  try{await s.init();const v:ScanView=await s.run();
    // The run itself closes every connection it opened (kept-alive ones included), before the scanner is disposed.
    for(const end=Date.now()+5000;f.open()>0;await new Promise(r=>setTimeout(r,20)))if(Date.now()>end)assert.fail(`${traffic}: ${f.open()} connection(s) still open after the run`);
    // Observation ids name the run's own loopback port; the comparison is per website.
    const values=new Set([...s.evidence.findings.values()].map(x=>s.evidence.reveal(x.id).value.split(f.origin).join('<website>')));return {v,values,f,json:JSON.parse(report(s,'json'))};}finally{s.dispose();await f.close();}
}
test('Deep audit + Low-impact keeps Deep audit + Normal recall with fewer requests and connections: static downloads serve the browser from the run cache, pacing holds end to end and the deny-only proxy is never bypassed',{timeout:420000},async()=>{
  const c=await canary();
  try{
    const normal=await scan('normal',c.origin),low=await scan('low-impact',c.origin);
    for(const {v} of [normal,low]){const b=v.browserStatus!;assert.equal(b.launch,true);assert.ok(b.runtimePages>=1,'the isolated browser inspected the page');assert.equal(b.isolation,'checked',JSON.stringify(b.isolationChecks));assert.equal(b.isolationChecks!.denyProxy,true);assert.ok(!v.limitations.some(g=>g.code==='browser-unavailable'));}
    // Recall: every synthetic key in both runs, and the same values overall.
    for(const value of Object.values(KEYS)){assert.ok(normal.values.has(value),'Deep + Normal finds '+value.slice(0,12));assert.ok(low.values.has(value),'Deep + Low-impact finds '+value.slice(0,12));}
    assert.deepEqual([...low.values].sort(),[...normal.values].sort(),'Low-impact keeps Deep + Normal recall');
    const a=normal.v.accounting!,l=low.v.accounting!;
    assert.ok(l.networkAttempts<a.networkAttempts,`requests: low ${l.networkAttempts} < normal ${a.networkAttempts}`);assert.ok(l.connectionsOpened!<a.connectionsOpened!,`connections: low ${l.connectionsOpened} < normal ${a.connectionsOpened}`);
    assert.equal(a.connectionsOpened,a.networkAttempts,'Normal opens one connection per request');assert.equal(a.connectionsReused,0);assert.equal(a.browserCacheHits,0);assert.equal(a.requestsAvoided,0);
    assert.equal(l.connectionsOpened!+l.connectionsReused!,l.networkAttempts,'each Low-impact request opened or reused one connection');assert.ok(l.connectionsReused!>0);
    // Whichever copy (static or browser) is requested first goes to the network; the other waits for it and is served from the run cache.
    assert.ok(l.browserCacheHits!>=1,`browser cache hits ${l.browserCacheHits}`);assert.equal(l.requestsAvoided,l.browserCacheHits!+low.v.resources.filter(r=>r.servedFrom==='run-cache'&&r.kind!=='browser').length);assert.ok(l.requestsAvoided!>=4,`requests avoided ${l.requestsAvoided}: one copy each of /, app.js, vendor.js and bundle.js`);const repeated=[...new Set(low.f.arrivals.map(x=>x.path).filter((p,i,all)=>all.indexOf(p)!==i))];assert.ok(repeated.every(p=>!(p in low.f.routes)),'only uncacheable answers (404 without freshness) are requested twice: '+repeated.join(', '));assert.equal(l.repeatedRequests,repeated.reduce((n,p)=>n+low.f.count(p)-1,0));
    for(const path of ['/','/app.js','/vendor.js','/bundle.js']){assert.equal(low.f.count(path),1,path+' is downloaded once by Low-impact');assert.equal(normal.f.count(path),2,path+' is downloaded statically and by the browser at Normal traffic');}
    const cached=low.v.resources.filter(r=>r.servedFrom==='run-cache'&&r.kind==='browser');assert.ok(cached.some(r=>r.provenance?.resourceType==='document'),'the browser document came from the run cache');
    assert.match(low.v.coverage!.requestComparison![0].conclusion,/served from this run’s response cache/,'the static/browser comparison says no browser request was sent');assert.match(normal.v.coverage!.requestComparison![0].conclusion,/Recorded statuses match/);
    assert.ok(cached.every(r=>r.provenance?.channel==='guarded-route'&&/response cache/.test(r.provenance.evidence)&&r.attemptId===undefined));
    // Pacing end to end, static and browser together: one request at a time, 0.5 requests/s on the one website. Pacing applies at dispatch; analysis of the 1.25 MB bundle on the same
    // event loop can delay one arrival, so each gap has a margin and the whole span is checked against 2 s per request.
    const at=low.f.arrivals.map(x=>x.at);for(let i=1;i<at.length;i++)assert.ok(at[i]-at[i-1]>=1500,`Low-impact arrivals ${at[i]-at[i-1]} ms apart (${low.f.arrivals[i].path})`);assert.ok(at.at(-1)!-at[0]>=(at.length-1)*2000-1000,`${at.length} arrivals over ${at.at(-1)!-at[0]} ms`);
    const origin=low.v.origins!.find(o=>o.origin===low.f.origin)!;assert.equal(origin.peakRequests,1);assert.equal(origin.connectionsOpened,l.connectionsOpened);assert.equal(origin.browserCacheHits,l.browserCacheHits);
    assert.equal(c.count(),0,'no connection reached the out-of-scope canary in either run: routed requests are blocked and unrouted ones die at the deny-only proxy');
    assert.ok(low.v.resources.some(r=>r.url.startsWith(c.origin)&&r.status==='blocked'),'the routed canary request was blocked by policy');
    assert.equal(low.json.accounting.browserCacheHits,l.browserCacheHits,'the JSON report keeps the traffic accounting');assert.equal(low.json.profile.traffic,'low-impact');
  }finally{await c.close();}
});
