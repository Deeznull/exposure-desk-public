import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {references,extract,resolve,classifyLiteral,isBareExtensionPath,rememberUnparseable,unparseableMemo} from '../src/discovery.js';
import {Scanner} from '../src/scanner.js';
import {Detector} from '../src/detectors.js';
import {focusedRetry} from '../src/retry.js';
import type {ScanView} from '../src/types.js';
const o='https://example.com';
const detector=()=>new Detector('disabled');
const summary=()=>({rejected:{bareExtension:0,nonUrlContext:0,dottedIdentifier:0,glob:0,examples:[] as string[]},syntax:{} as Record<string,number>,sinks:{} as Record<string,number>,referenceLimit:0});
const resolved=(refs:ReturnType<typeof references>)=>refs.filter(r=>!r.unresolved).map(r=>new URL(r.raw,r.base).href);
test('bare extension literals, non-URL contexts and dotted identifiers are rejected with counted reasons',()=>{
  const s=summary(),refs=references('a.endsWith(".json");const m={".woff":"font/woff"};const e=".json",f=".woff",g="es.array.map",h="app.min.js";if(x==="/.css"){}',o+'/app.js','script',o+'/',{},{summary:s});
  const urls=resolved(refs);assert.ok(!urls.some(u=>/\/\.(?:json|woff|css)$/.test(u)||u.endsWith('/es.array.map')),JSON.stringify(urls));assert.ok(urls.includes(o+'/app.min.js'),'a real build name stays a heuristic hint');
  assert.ok(s.rejected.bareExtension>=2);assert.ok(s.rejected.nonUrlContext>=2);assert.ok(s.rejected.dottedIdentifier>=1);assert.ok(s.rejected.examples.includes('.json'));
  assert.equal(classifyLiteral('.json'),'bareExtension');assert.equal(classifyLiteral('*.js'),'bareExtension');assert.equal(classifyLiteral('/chunks/*.js'),'glob');assert.equal(classifyLiteral('http://www.w3.org/2000/svg'),'skip');assert.equal(classifyLiteral('config.json'),'accept');assert.equal(classifyLiteral('/.json'),'bareExtension');
  assert.equal(isBareExtensionPath(o+'/.json'),true);assert.equal(isBareExtensionPath(o+'/assets/.woff'),true);assert.equal(isBareExtensionPath(o+'/assets/x.woff'),false);
});
test('contextual uses keep bare fragments and carry sink, base role and certainty; unresolved expressions stay graph-only',()=>{
  const s=summary(),refs=references('fetch(".json");import("./c.js");new Worker(new URL("./w.js",import.meta.url));new Worker("/wk.js");navigator.serviceWorker.register("/sw.js");importScripts("./lib.js");const x=new XMLHttpRequest();x.open("GET","/x.json");location.href="/account";el.src="/img/a.js";',o+'/assets/main.js','script',o+'/',{},{summary:s});
  const by=(raw:string)=>refs.find(r=>r.raw===raw)!;
  assert.equal(new URL(by('.json').raw,by('.json').base).href,o+'/.json');assert.equal(by('.json').sink,'fetch');assert.equal(by('.json').certainty,'confirmed');assert.equal(by('.json').acquire,true);
  assert.equal(new URL(by('./c.js').raw,by('./c.js').base).href,o+'/assets/c.js');assert.equal(new URL(by('./w.js').raw,by('./w.js').base).href,o+'/assets/w.js');assert.equal(new URL(by('/wk.js').raw,by('/wk.js').base).href,o+'/wk.js');assert.equal(new URL(by('/sw.js').raw,by('/sw.js').base).href,o+'/sw.js');assert.equal(new URL(by('./lib.js').raw,by('./lib.js').base).href,o+'/assets/lib.js');
  assert.equal(by('/x.json').sink,'xhr');assert.equal(by('/x.json').method,'GET');assert.equal(by('/account').kind,'page');assert.equal(by('/account').certainty,'contextual');assert.equal(by('/img/a.js').sink,'attribute');
  assert.ok(s.sinks.fetch>=1&&s.sinks.worker>=2&&s.sinks['service-worker']>=1&&s.sinks['import-scripts']>=1&&s.sinks.location>=1);
  const unresolved=references('import("./chunks/"+n+".js");fetch("/api/"+id+"/x.json");fetch(`/v/${version}/data.json`);const t=cond?"/a.json":"/b.json";fetch(t);',o+'/app.js','script',o+'/');
  const u=unresolved.filter(r=>r.unresolved);assert.ok(u.some(r=>r.raw==='./chunks/{EXPR}.js'&&r.certainty==='unresolved'&&r.acquire===false));assert.ok(u.some(r=>r.raw==='/api/{EXPR}/x.json'));assert.ok(u.some(r=>r.raw==='/v/{EXPR}/data.json'));
  const scan=new Scanner({urls:[o]},{detector:detector()});try{scan.discover('import("./chunks/"+n+".js");fetch("/api/"+id+"/x.json");',o+'/app.js',0,[o+'/'],'script',{'content-type':'text/javascript'});assert.ok(!scan.queue.some(w=>w.url.includes('{EXPR}')||w.url.includes('%7BEXPR')));assert.ok(scan.view().discoveryGraph!.edges.some(e=>e.status==='unresolved'&&e.reference==='./chunks/{EXPR}.js'));assert.equal(scan.view().discovery!.unresolved,2);}finally{scan.dispose();}
});
test('non-GET sinks are observed, never enqueued; GET sinks without a static extension are browser-only',()=>{
  const refs=references('axios.post("/s.json");$.ajax({url:"/d.json",type:"DELETE"});fetch("/p.json",{method:"PUT"});axios.get("/g.json");fetch("/runtime-json");navigator.sendBeacon("/beacon.json");new EventSource("/events.json");',o+'/app.js','script',o+'/');
  const by=(raw:string)=>refs.find(r=>r.raw===raw)!;assert.equal(by('/s.json').acquire,false);assert.equal(by('/s.json').method,'POST');assert.equal(by('/d.json').method,'DELETE');assert.equal(by('/p.json').method,'PUT');assert.equal(by('/g.json').acquire,true);assert.equal(by('/runtime-json').acquire,false,'extensionless relative fetch targets stay browser-only');assert.equal(by('/beacon.json').acquire,false);assert.equal(by('/events.json').acquire,false);
  const scan=new Scanner({urls:[o],adjacentMaps:false},{detector:detector()});try{scan.discover('axios.post("/s.json");$.ajax({url:"/d.json",type:"DELETE"});fetch("/p.json",{method:"PUT"});axios.get("/g.json");fetch("/runtime-json");',o+'/app.js',0,[o+'/'],'script',{'content-type':'text/javascript'});assert.deepEqual(scan.queue.map(w=>w.url).filter(u=>!/robots|sitemap/.test(u)),[o+'/g.json']);const edges=scan.view().discoveryGraph!.edges;assert.ok(edges.some(e=>e.reference==='/s.json'&&e.status==='observed'&&e.method==='POST'));assert.equal(scan.view().discovery!.observedOnly,4);}finally{scan.dispose();}
});
test('bundler tables stay confirmed: webpack chunk maps on bounded windows, Vite dependency tables and Next manifests',()=>{
  const webpack=references('r.p="/static/js/";r.u=e=>e+"."+{"179":"a1b2c3d4"}[e]+".js";',o+'/runtime.js','script',o+'/');assert.ok(resolved(webpack).includes(o+'/static/js/179.a1b2c3d4.js'));assert.equal(webpack.find(r=>r.raw.includes('179'))!.certainty,'confirmed');
  const next=references('self.__BUILD_MANIFEST={"/":["static/chunks/page.js"]};',o+'/_next/static/build42/_buildManifest.js','asset',o+'/');assert.ok(resolved(next).includes(o+'/_next/static/chunks/page.js'));assert.equal(next[0].certainty,'confirmed');
  const vite=references('function __vite__mapDeps(){return ["assets/lazy.js"]}',o+'/app/assets/main.js','asset',o+'/');assert.ok(resolved(vite).includes(o+'/app/assets/lazy.js'));assert.equal(vite[0].certainty,'confirmed');
  const started=Date.now();references('const long="'+'a'.repeat(40000)+'";'+'x+"."+{1:"b"}[x]+".js";',o+'/q.js','script');assert.ok(Date.now()-started<500,'the webpack pattern no longer scans long word runs quadratically');
});
test('a 1.3 MiB bundle keeps module syntax and finds tail references within the node and time budgets',()=>{
  const s=summary(),text='"use strict";'+Array.from({length:26000},(_,i)=>'function f'+i+'(a){if(a.endsWith(".json"))return 1;return 0}\n').join('')+'import("./late-abcdef12.js");new Worker(new URL("./tail.js",import.meta.url));',started=Date.now(),refs=references(text,o+'/bundle.js','script',o+'/',{},{summary:s});
  assert.ok(text.length>1.3*1024*1024);assert.equal(s.syntax.module,1);assert.ok(resolved(refs).includes(o+'/late-abcdef12.js'));assert.ok(resolved(refs).includes(o+'/tail.js'));assert.ok(!resolved(refs).some(u=>u.endsWith('/.json')));assert.ok(Date.now()-started<4000);assert.ok(s.rejected.nonUrlContext>=26000);
});
test('extractions are reusable across contexts: identical text resolves to distinct chunk URLs and uses the current import map',()=>{
  const x=extract('import("./chunk.js");import "core";',o+'/a/app.js','script');
  const a=resolve(x,{url:o+'/a/app.js',documentUrl:o+'/',imports:{core:o+'/lib/core.js'}}),b=resolve(x,{url:o+'/b/app.js',documentUrl:o+'/',imports:{}});
  assert.ok(resolved(a).includes(o+'/a/chunk.js'));assert.ok(resolved(b).includes(o+'/b/chunk.js'));assert.ok(a.some(r=>r.raw===o+'/lib/core.js'&&!r.unresolved));assert.ok(b.some(r=>r.raw==='core'&&r.unresolved));
  const html=extract('<base href="/app/"><script type="importmap">{"imports":{"core":"./core"}}</script><script type="module">import("core");</script>',o+'/page','page');const imports:Record<string,string>={};const refs=resolve(html,{url:o+'/page',documentUrl:o+'/page',imports});assert.equal(imports.core,o+'/app/core');assert.ok(refs.some(r=>r.raw===o+'/app/core'&&r.context==='Import map resolved module'));
});
test('SPA fallback, soft-404 and login HTML answering asset requests are classified before promotion and never navigated',async()=>{
  const shell='<!doctype html><html><head><title>App</title></head><body><div id="app"></div><a href="/login">login</a><a href="/missing-page">old</a><a href="/about">about</a><script src="/app.js"></script><script>window.__cfg={e:".json"}</script></body></html>';const arrivals:string[]=[];
  const server=http.createServer((req,res)=>{arrivals.push(req.url!);const p=req.url!;if(p==='/app.js'){res.setHeader('content-type','text/javascript');res.end('const e=".json",w=".woff";fetch("/data.json");import("./assets/missing.js");');}else if(p==='/data.json'){res.setHeader('content-type','application/json');res.end('{"ok":true}');}else if(p==='/login'){res.setHeader('content-type','text/html');res.end('<html><title>Sign in</title><form><input type="password" name="p"></form></html>');}else if(p==='/missing-page'){res.setHeader('content-type','text/html');res.end('<html><title>404 Not Found</title><p>nothing</p></html>');}else if(p==='/robots.txt'){res.end('User-agent: *');}else{res.setHeader('content-type','text/html');res.end(shell);}});
  await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));const origin=`http://127.0.0.1:${(server.address() as any).port}`;
  try{const s=new Scanner({urls:[origin],developmentFixtureOrigin:origin,requestsPerSecond:20,adjacentMaps:true,semanticAnalysis:false,browserNavigationUrls:[origin+'/settings']},{detector:detector()});const v=await s.run();
    assert.ok(!arrivals.some(u=>u==='/.json'||u==='/.woff'),'bare literals never become requests');assert.ok(arrivals.includes('/data.json'),'contextual fetch targets are acquired');assert.ok(arrivals.includes('/assets/missing.js'));
    const missing=v.resources.find(r=>r.url===origin+'/assets/missing.js')!;assert.equal(missing.fallback?.type,'spa-fallback');assert.equal(missing.fallback?.sameAs,origin+'/');assert.equal(missing.fallback?.expected,'script');assert.equal(v.coverage!.inventory.find(r=>r.url===origin+'/assets/missing.js')!.state,'unavailable');assert.ok(v.limitations.some(g=>g.code==='expected-asset-html-fallback'&&g.incomplete));
    const map=v.resources.find(r=>r.url===origin+'/app.js.map')!;assert.ok(map);assert.equal(map.fallback,undefined,'map-guess probes keep their own classification');assert.ok(v.limitations.some(g=>g.code==='map-unavailable'&&!g.incomplete));
    const candidates=s.browserNavigationCandidates();assert.ok(candidates.includes(origin+'/settings'),'explicit routes are never suppressed');assert.ok(!candidates.includes(origin+'/assets/missing.js'));assert.ok(!candidates.includes(origin+'/login'),'discovered login pages are not navigated');assert.ok(!candidates.includes(origin+'/missing-page'),'discovered soft-404 pages are not navigated');assert.ok(candidates.includes(origin+'/'));assert.ok(candidates.includes(origin+'/about'),'same-shell client routes from anchors stay candidates');assert.equal(v.resources.find(r=>r.url===origin+'/login')!.fallback?.type,'login');assert.equal(v.resources.find(r=>r.url===origin+'/missing-page')!.fallback?.type,'soft-404');assert.ok(v.resources.some(r=>r.url===origin+'/login'&&r.analysis==='analyzed'),'login pages are still inspected');
    assert.ok(![...(s as any).modules.keys()].some((k:string)=>k.startsWith(origin+'/assets/missing.js#inline')),'fallback shells are not admitted as inline modules again');assert.ok(v.discovery!.fallbacks['spa-fallback']>=1);assert.ok(v.discovery!.rejected.bareExtension>=2);assert.ok(v.discovery!.reusedDiscoveries>=0);assert.equal(v.limitations.filter(g=>g.code==='bare-extension-literals').length,1);
  }finally{await new Promise<void>(r=>{server.close(()=>r());server.closeAllConnections();});}
});
test('exclusions aggregate per origin; legacy bare hints are skipped on retry; explicit stale assets are still requested',async()=>{
  const s=new Scanner({urls:[o]},{detector:detector()});
  try{for(let p=0;p<5;p++)for(let i=0;i<30;i++)s.enqueue('https://ext'+(i%3)+'.example.net/r'+i+'.js',o+'/page'+p,0,[o+'/page'+p],'script');const v=s.view();assert.equal(v.resources.filter(r=>r.reason==='scope').length,3);assert.equal(v.scope!.excluded.examples.length,3);assert.ok(v.scope!.excluded.examples.every(e=>e.count===50));assert.equal(v.scope!.excluded.references,150);}finally{s.dispose();}
  const view={id:'x',config:{urls:[o+'/'],relatedOrigins:[],maxResources:50,browser:false,browserPages:5},state:'incomplete',resources:[],uninspected:[{url:o+'/.json',kind:'asset-hint',depth:0,chain:[]},{url:o+'/.woff',kind:'asset',depth:0,chain:[]},{url:o+'/real.js',kind:'script',depth:0,chain:[]}]} as unknown as ScanView;
  assert.deepEqual(focusedRetry(view).selected.map(w=>w.url),[o+'/real.js']);
  const stale=new Scanner({urls:[o],staleAssetUrls:[o+'/.json']},{detector:detector()});try{(stale as any).enqueue(o+'/.json',o,0,['previous authorized scan or owner deployment manifest'],'stale-asset');assert.ok(stale.queue.some(w=>w.url===o+'/.json'),'explicit stale assets are never guarded');}finally{stale.dispose();}
});

// O1 (2.9): a large text acorn rejects in both modes is remembered by digest, so a repeat skips both failed parses with an identical extraction.
const bigScript=(tail:string,salt:string)=>{const lines=[`/* ${salt} */`];for(let i=0;lines.join('\n').length<70*1024;i++)lines.push(`var u${i}="/assets/chunk-${i}.js";fetch("https://api.example.com/v${i}/items");`);return lines.join('\n')+'\n'+tail;};
test('a large text broken in both modes is remembered once and extracts identically on repeat',()=>{
  unparseableMemo.clear();const text=bigScript('fetch("/assets/late-chunk.js");}','both-broken');
  const s1=summary(),a=extract(text,o+'/main.js','script',{summary:s1});assert.equal(unparseableMemo.size,1);assert.deepEqual(s1.syntax,{tokens:1});
  const s2=summary(),b=extract(text,o+'/main.js','script',{summary:s2});assert.equal(unparseableMemo.size,1);assert.deepEqual(s2.syntax,{tokens:1});
  assert.deepEqual(b,a);assert.ok(a.refs.some(r=>r.raw==="/assets/late-chunk.js"));
  unparseableMemo.clear();assert.deepEqual(extract(text,o+'/main.js','script'),a,'cleared memo gives the same extraction');
});
test('a large text that fails only as a module parses as a script every time and is never remembered',()=>{
  unparseableMemo.clear();const text=bigScript('if(window.x) function legacy(){return "/legacy/path.json";}','module-only');
  const s1=summary(),a=extract(text,o+'/main.js','script',{summary:s1}),s2=summary(),b=extract(text,o+'/main.js','script',{summary:s2});
  assert.deepEqual(s1.syntax,{script:1});assert.deepEqual(s2.syntax,{script:1});assert.deepEqual(b,a);assert.equal(unparseableMemo.size,0);
});
test('a small broken text is never remembered and extracts the same each time',()=>{
  unparseableMemo.clear();const text='fetch("/small/a.json");}';const a=extract(text,o+'/s.js','script'),b=extract(text,o+'/s.js','script');
  assert.deepEqual(b,a);assert.equal(unparseableMemo.size,0);
});
test('only two SyntaxErrors are remembered, and the memo is capped at 512 with the oldest evicted',()=>{
  unparseableMemo.clear();
  assert.equal(rememberUnparseable('r',new RangeError('stack'),new SyntaxError('x')),false);
  assert.equal(rememberUnparseable('r',new SyntaxError('x'),new RangeError('stack')),false);
  assert.equal(rememberUnparseable('r',undefined,new SyntaxError('x')),false);assert.equal(unparseableMemo.size,0);
  for(let i=0;i<513;i++)assert.equal(rememberUnparseable('d'+i,new SyntaxError('a'),new SyntaxError('b')),true);
  assert.equal(unparseableMemo.size,512);assert.equal(unparseableMemo.has('d0'),false);assert.equal(unparseableMemo.has('d1'),true);assert.equal(unparseableMemo.has('d512'),true);
  assert.equal(rememberUnparseable('d1',new SyntaxError('a'),new SyntaxError('b')),false);unparseableMemo.clear();
});
