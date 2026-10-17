import {writeFile,mkdir} from 'node:fs/promises';
import {BUILD} from '../src/build-info.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {makeConfig} from '../src/config.js';
import {Scanner} from '../src/scanner.js';
import {Detector} from '../src/detectors.js';
import {Evidence} from '../src/evidence.js';
import {Transport} from '../src/transport.js';
import {OriginControl} from '../src/origin-control.js';
import {FairScheduler} from '../src/scheduler.js';
import {analyzeModules} from '../src/semantic.js';
import type {WorkItem,Resource} from '../src/types.js';

export async function originFixtures(n:number){
 const arrivals:{origin:number;path:string;at:number}[]=[],active=new Map<number,number>();let peak=0,peakOrigins=0;
 const servers:http.Server[]=[],origins:string[]=[],timers=new Set<ReturnType<typeof setTimeout>>();
 for(let i=0;i<n;i++){let retry=0;const server=http.createServer((req,res)=>{const pathname=new URL(req.url!,'http://local').pathname;arrivals.push({origin:i,path:pathname,at:performance.now()});active.set(i,(active.get(i)||0)+1);peak=Math.max(peak,[...active.values()].reduce((a,b)=>a+b,0));peakOrigins=Math.max(peakOrigins,[...active.values()].filter(Boolean).length);res.once('close',()=>active.set(i,(active.get(i)||1)-1));
   const send=(status:number,text:string,type='text/plain',delay=0)=>{const t=setTimeout(()=>{timers.delete(t);res.writeHead(status,{'content-type':type});res.end(text);},delay);timers.add(t);};
   if(pathname==='/stall')return;
   if(pathname==='/retry'&&retry++===0){res.writeHead(503,{'retry-after':'0.01','content-type':'text/plain'});res.end('try later');return;}
   if(pathname.startsWith('/transport'))return send(200,'ok','text/plain',180);
   if(pathname==='/robots.txt')return send(200,'User-agent: *');
   if(pathname==='/sitemap.xml')return send(404,'none');
   if(pathname==='/'||pathname==='/seed2')return send(200,'<html><script src="/app.js"></script><script type="application/json" src="/config.json"></script>'+Array.from({length:12},(_,j)=>'<a href="/optional/'+j+'">page</a>').join('')+'</html>','text/html');
   if(pathname==='/app.js')return send(200,'const v=1;\n//# sourceMappingURL=app.js.map','application/javascript');
   if(pathname==='/app.js.map')return send(200,JSON.stringify({version:3,sources:['source.js'],sourcesContent:['const v=1;'],mappings:''}),'application/json');
   if(pathname==='/config.json')return send(200,'{"environment":"test"}','application/json');
   return send(200,'ok');
 });await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));servers.push(server);origins.push('http://127.0.0.1:'+(server.address() as any).port);}
 return {origins,arrivals,metrics:()=>({peak,peakOrigins}),close:async()=>{for(const t of timers)clearTimeout(t);await Promise.all(servers.map(s=>new Promise<void>(r=>{s.close(()=>r());s.closeAllConnections();})));}};
}
const detector=()=>new Detector('deliberately-unavailable');

test('monotonic origin clock starts at admission, includes idle turns, and freezes only at completion',async()=>{
 let now=100;const c=makeConfig({urls:['https://one.invalid','https://two.invalid'],originMaxDurationMs:1000}),control=new OriginControl(c,new AbortController().signal,()=>now);
 control.get(c.urls[1]);assert.equal(control.snapshots()[0].admitted,false);now=10000;control.run(c.urls[0],()=>{});now+=899;assert.equal(control.soft(c.urls[0]),false);now++;assert.equal(control.soft(c.urls[0]),true);control.run(c.urls[0],()=>{});assert.equal(control.elapsed(c.urls[0]),900);now+=100;control.expire(c.urls[0]);now+=25;control.finish(c.urls[0]);assert.equal(control.elapsed(c.urls[0]),1000);assert.equal(control.snapshots().find(o=>o.origin==='https://one.invalid')!.cleanupMs,25);assert.equal(control.elapsed(c.urls[1]),0);control.cancel();
});

test('configured seeds receive fair turns before optional pages; discovered high-value work has strict priority',()=>{
 const entries=Array.from({length:6},(_,i)=>'https://o'+i+'.invalid/'),q:WorkItem[]=entries.flatMap(url=>[{url,kind:'page',depth:0,chain:[]},{url:url+'optional',kind:'page',depth:1,chain:[]}]);q.push(...['script','config','map'].map(kind=>({url:entries[0]+kind,kind,depth:0,chain:[]})));
 const scheduler=new FairScheduler(()=>q,entries),first=[];for(let i=0;i<entries.length;i++){const w=scheduler.take()!;first.push(w.url);scheduler.finish(w);}assert.deepEqual(first,entries);
 const rest=[];while(q.length){const w=scheduler.take()!;rest.push(w);scheduler.finish(w);}assert.ok(rest.findIndex(w=>w.kind==='script')<rest.findIndex(w=>w.url===entries[0]+'optional'));assert.ok(rest.findIndex(w=>w.kind==='map')<rest.findIndex(w=>w.url===entries[0]+'optional'));
});

test('six origins outnumber two HTTP slots; continuous floods release origin capacity fairly',{timeout:12000},async()=>{
 const f=await originFixtures(6);try{const cfg=makeConfig({urls:f.origins,privateOrigins:f.origins,requestsPerSecond:20,originRequestsPerSecond:20,concurrency:2,globalConcurrency:6,originConcurrency:2,maxActiveOrigins:2,maxResources:100,maxDurationMs:10000,maxRetries:0}),records:Resource[]=[],t=new Transport(cfg,new Evidence(detector()),r=>records.push(r),()=>{});
 const promises=f.origins.flatMap((o,i)=>Array.from({length:i===0?18:3},(_,j)=>t.get(o+'/transport/'+j)));await Promise.all(promises);
 const first=f.origins.map((_,i)=>f.arrivals.findIndex(a=>a.origin===i));assert.ok(first.every(i=>i>=0));assert.ok(Math.max(...first)<18,'all origins must arrive before the flooding origin drains');assert.ok(f.metrics().peakOrigins<=2);assert.ok(f.metrics().peak<=6);assert.ok(t.originControl.snapshots().every(o=>o.peakRequests<=2));assert.ok(t.coordinator().peakActiveRequests>1);assert.equal(t.coordinator().activeRequests,0);assert.equal(t.coordinator().queuedRequests,0);t.cancel();
 }finally{await f.close();}
});

test('stalled seed cannot block all roots and seeds or allow optional pages ahead of them',{timeout:15000},async()=>{
 const f=await originFixtures(6);try{const seeds=f.origins.flatMap((o,i)=>[o+(i===0?'/stall':'/'),o+'/seed2']),s=new Scanner({urls:seeds,privateOrigins:f.origins,requestsPerSecond:20,originRequestsPerSecond:20,globalConcurrency:6,originConcurrency:2,maxActiveOrigins:2,maxDurationMs:12000,timeoutMs:300,maxRetries:0,maxResources:160,maxPages:30,adjacentMaps:false,semanticAnalysis:false},{detector:detector()});const v=await s.run();
 assert.ok(seeds.every(u=>f.arrivals.some(a=>f.origins[a.origin]+a.path===u)));const lastSeed=Math.max(...seeds.map(u=>f.arrivals.findIndex(a=>f.origins[a.origin]+a.path===u))),firstOptional=f.arrivals.findIndex(a=>a.path.startsWith('/optional/'));assert.ok(firstOptional>lastSeed);assert.equal(new Set(v.resources.filter(r=>r.url.endsWith('/app.js')&&r.analysis==='analyzed').map(r=>new URL(r.url).origin)).size,6);assert.ok(f.metrics().peakOrigins<=2);assert.ok(v.origins!.every(o=>o.requests>0));assert.equal(s.transport.coordinator().activeRequests,0);await mkdir((process.env.EXPOSURE_TEST_OUTPUT||'.cache/test-output'),{recursive:true});await writeFile((process.env.EXPOSURE_TEST_OUTPUT||'.cache/test-output')+'/milestone1-fairness.json',JSON.stringify({build:BUILD,origins:6,httpOriginSlots:2,configuredSeeds:seeds.length,seedsAttempted:seeds.filter(u=>f.arrivals.some(a=>f.origins[a.origin]+a.path===u)).length,lastSeedArrivalIndex:lastSeed,firstOptionalArrivalIndex:firstOptional,firstArrivalMsByOrigin:f.origins.map((_,i)=>f.arrivals.find(a=>a.origin===i)!.at-f.arrivals[0].at),javascriptOrigins:6,elapsedMs:v.elapsedMs,accounting:v.accounting,limits:{...s.config,urls:undefined,privateOrigins:undefined},networkPeaks:f.metrics()},null,2));s.dispose();
 }finally{await f.close();}
});

test('per-origin rate limits include a successful retry and do not throttle other origins via Retry-After',async()=>{
 const f=await originFixtures(2);try{const records:Resource[]=[],t=new Transport(makeConfig({urls:f.origins,privateOrigins:f.origins,requestsPerSecond:20,originRequestsPerSecond:5,globalConcurrency:4,originConcurrency:2,maxActiveOrigins:2,maxDurationMs:4000,maxRetries:1}),new Evidence(detector()),r=>records.push(r),()=>{});
 await Promise.all([t.get(f.origins[0]+'/retry'),t.get(f.origins[1]+'/transport/ok')]);const hits=f.arrivals.filter(a=>a.origin===0);assert.equal(hits.length,2);assert.ok(hits[1].at-hits[0].at>=185);assert.equal(records.filter(r=>r.url===f.origins[0]+'/retry').at(-1)!.code,200);assert.equal(t.originControl.get(f.origins[0]).retries,1);assert.equal(t.originControl.get(f.origins[0]).retryExhausted,0);t.cancel();
 }finally{await f.close();}
});

test('hard deadline terminates only its origin; project cancellation terminates all active requests',async()=>{
 const f=await originFixtures(2);try{const records:Resource[]=[],t=new Transport(makeConfig({urls:f.origins,privateOrigins:f.origins,requestsPerSecond:20,originRequestsPerSecond:20,globalConcurrency:4,originConcurrency:2,originMaxDurationMs:600,projectMaxDurationMs:4000,maxDurationMs:4000,timeoutMs:1000,maxRetries:0}),new Evidence(detector()),r=>records.push(r),()=>{});
 const results=await Promise.allSettled([t.get(f.origins[0]+'/stall'),t.get(f.origins[1]+'/transport/ok')]);assert.equal(results[0].status,'rejected');assert.equal(results[1].status,'fulfilled');assert.equal(t.projectSignal.aborted,false);assert.equal(t.originControl.get(f.origins[1]).controller.signal.aborted,false);assert.equal(t.coordinator().activeRequests,0);t.cancel();
 const s=new Scanner({urls:f.origins.map(o=>o+'/stall'),privateOrigins:f.origins,requestsPerSecond:20,originRequestsPerSecond:20,globalConcurrency:4,maxDurationMs:4000,timeoutMs:3000,maxRetries:0},{detector:detector()});const running=s.run();await new Promise(r=>setTimeout(r,220));s.cancel();const v=await running;assert.equal(v.state,'cancelled');assert.equal(s.transport.coordinator().activeRequests,0);assert.equal(s.transport.coordinator().queuedRequests,0);assert.ok(v.origins!.every(o=>o.requests>0));s.dispose();
 }finally{await f.close();}
});

test('soft deadline defers optional pages while retaining a discovered script turn',async()=>{
 const f=await originFixtures(1);try{const s=new Scanner({urls:[f.origins[0]],privateOrigins:f.origins,requestsPerSecond:20,originRequestsPerSecond:20,globalConcurrency:1,maxDurationMs:5000,originMaxDurationMs:10000,semanticAnalysis:false,adjacentMaps:false},{detector:detector()});
 const o=s.transport.originControl.get(f.origins[0]);o.started=s.transport.originControl.now()-9100;
 s.enqueue('/optional/a',f.origins[0],1,[],'page');s.enqueue('/app.js',f.origins[0],0,[],'script');await s.run();assert.ok(s.view().uninspected!.some(w=>w.url.endsWith('/optional/a')&&w.deferredReason==='origin-soft-deadline'));assert.ok(!f.arrivals.some(a=>a.path==='/optional/a'));assert.ok(f.arrivals.some(a=>a.path==='/app.js'));s.dispose();
 }finally{await f.close();}
});

test('origin cancellation reaches a semantic worker without cancelling another origin worker',async()=>{
 const c=makeConfig({urls:['https://a.invalid','https://b.invalid'],originMaxDurationMs:2000}),control=new OriginControl(c,new AbortController().signal);
 const first=control.run(c.urls[0],()=>analyzeModules([{url:c.urls[0]+'large.js',text:'const a=['+'1,'.repeat(300000)+'1];'}],control.signal));control.expire(c.urls[0]);const second=control.run(c.urls[1],()=>analyzeModules([{url:c.urls[1]+'small.js',text:'const a="test";'}],control.signal));const [a,b]=await Promise.all([first,second]);assert.ok(a.gaps.some(g=>g.code==='semantic-cancelled'));assert.ok(!b.gaps.some(g=>g.code==='semantic-cancelled'));control.cancel();
});

test('large direct analysis is cancellable and does not block the event loop',async()=>{const d=detector(),stop=new AbortController();d.signal=stop.signal;const task=d.inspect('const values=['+'123,'.repeat(300000)+'1];');setTimeout(()=>stop.abort(),10);const start=performance.now();await assert.rejects(task,/cancelled/);assert.ok(performance.now()-start<1500);});
