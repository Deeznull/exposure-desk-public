import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type {Socket} from 'node:net';
import {Scanner} from '../src/scanner.js';
import {Detector} from '../src/detectors.js';
import {FairScheduler} from '../src/scheduler.js';
import type {ScanConfig,WorkItem} from '../src/types.js';
/** 2.6 P4: ready options' websites at once. A website that has not started waits while `maxActiveOrigins` started websites still have work, so its time allowance starts with its own first turn
 * and Low-impact requests stay close enough to reuse each website's connection; 2.5 configurations keep round-robin over every website. Loopback servers and synthetic data only. */
async function websites(n:number){
 const arrivals:{origin:number;path:string;at:number;socket:number}[]=[],servers:http.Server[]=[],origins:string[]=[],sockets:Socket[][]=[];
 for(let i=0;i<n;i++){sockets.push([]);const server=http.createServer((req,res)=>{const path=new URL(req.url!,'http://local').pathname;arrivals.push({origin:i,path,at:performance.now(),socket:sockets[i].indexOf(req.socket)});
   const send=(status:number,body:string,type='text/plain')=>{res.writeHead(status,{'content-type':type});res.end(body);};
   if(path==='/robots.txt')return send(200,'User-agent: *');
   if(path==='/')return send(200,'<html><script src="/app.js"></script>'+[1,2,3].map(j=>'<a href="/page'+j+'">page</a>').join('')+'</html>','text/html');
   if(path==='/app.js')return send(200,'const v=1;','application/javascript');
   if(/^\/page\d$/.test(path))return send(200,'<html>page</html>','text/html');
   send(404,'none');
  });server.on('connection',s=>sockets[i].push(s));await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));servers.push(server);origins.push('http://127.0.0.1:'+(server.address() as any).port);}
 /** Largest number of websites between their first and last request at the same moment. */
 const overlap=()=>{const spans=origins.map((_,i)=>{const a=arrivals.filter(x=>x.origin===i);return [a[0].at,a.at(-1)!.at];});return Math.max(...spans.map(([s])=>spans.filter(([a,b])=>a<=s&&s<=b).length));};
 return {origins,arrivals,overlap,connections:()=>sockets.reduce((a,s)=>a+s.length,0),close:async()=>{await Promise.all(servers.map(s=>new Promise<void>(r=>{s.close(()=>r());s.closeAllConnections();})));}};
}
const scan=async(config:Partial<ScanConfig>)=>{const s=new Scanner(config,{detector:new Detector('deliberately-unavailable')});try{return {view:await s.run(),transport:s.transport};}finally{s.dispose();}};

test('a waiting website is left out before the seed barrier and its seed is taken once it may start',()=>{
 const entries=['https://a.invalid/','https://b.invalid/','https://c.invalid/'],q:WorkItem[]=entries.map(url=>({url,kind:'page',depth:0,chain:[]}));q.push({url:entries[0]+'app.js',kind:'script',depth:0,chain:[]});
 let wait=true;const scheduler=new FairScheduler(()=>q,entries,()=>undefined,()=>undefined,()=>w=>wait&&w.url.startsWith(entries[2])),taken:string[]=[];
 assert.equal(scheduler.view().classes.entryPages.blockedReason,undefined,'the first pending entry page belongs to a website that may start');
 for(let i=0;i<3;i++){const w=scheduler.take()!;taken.push(w.url);scheduler.finish(w);}
 assert.deepEqual(taken,[entries[0],entries[1],entries[0]+'app.js'],'the waiting seed does not hold back JavaScript of a website in progress');
 assert.equal(scheduler.take(),undefined,'nothing of the waiting website is taken');assert.match(scheduler.view().classes.entryPages.blockedReason!,/free website slot/);
 wait=false;assert.equal(scheduler.take()!.url,entries[2]);
});

test('ready options start websites in rounds of websites at once, each scanned in full; 2.5 configurations start every website at once',{timeout:90000},async()=>{
 const ready=await websites(5);try{
  const {view}=await scan({urls:ready.origins.map(o=>o+'/'),privateOrigins:ready.origins,coverage:'standard',traffic:'normal',maxActiveOrigins:2,deep:false,browser:false,semanticAnalysis:false});
  assert.equal(view.stopReason,'discovered-frontier-drained');assert.ok(ready.overlap()<=2,`websites started together: ${ready.overlap()}`);
  for(let i=0;i<5;i++)assert.equal(['/','/app.js','/page1','/page2','/page3','/robots.txt'].filter(p=>ready.arrivals.some(a=>a.origin===i&&a.path===p)).length,6,'website '+i+' is scanned in full');
  const firsts=ready.origins.map((_,i)=>ready.arrivals.find(a=>a.origin===i)!.at),lasts=ready.origins.map((_,i)=>ready.arrivals.filter(a=>a.origin===i).at(-1)!.at);
  assert.ok(firsts[2]>=Math.min(lasts[0],lasts[1]),'the third website starts after a website in progress is done');
  assert.ok(view.origins!.every(o=>o.elapsedMs<view.elapsedMs*.8),'each website\x27s time allowance counts only its own round');
 }finally{await ready.close();}
 const legacy=await websites(5);try{
  const {view}=await scan({urls:legacy.origins.map(o=>o+'/'),privateOrigins:legacy.origins,requestsPerSecond:20,originRequestsPerSecond:20,globalConcurrency:6,originConcurrency:2,maxActiveOrigins:2,maxRetries:0,maxPages:30,maxDurationMs:30000,deep:false,adjacentMaps:false,browser:false,semanticAnalysis:false});
  assert.equal(view.stopReason,'discovered-frontier-drained');assert.equal(legacy.overlap(),5,'2.5 configurations keep round-robin over every website');
 }finally{await legacy.close();}
});

test('Low-impact with more websites than websites at once keeps one connection per website',{timeout:90000},async()=>{
 // Five websites, two at once at 0.5 requests/s each: round-robin over all five would space each website's requests about 5 s apart, past the 4 s idle close.
 const low=await websites(5);try{
  const {view,transport}=await scan({urls:low.origins.map(o=>o+'/'),privateOrigins:low.origins,coverage:'quick',traffic:'low-impact',deep:false,browser:false,semanticAnalysis:false});
  assert.equal(view.stopReason,'discovered-frontier-drained');assert.equal(view.config.maxActiveOrigins,2);assert.ok(low.overlap()<=2,`websites started together: ${low.overlap()}`);
  assert.ok(low.origins.every((_,i)=>low.arrivals.some(a=>a.origin===i&&a.path==='/app.js')),'every website is scanned');
  assert.equal(transport.connectionsOpened,low.connections());assert.ok(low.connections()<=low.origins.length+1,`connections ${low.connections()} for ${low.origins.length} websites`);
  assert.ok(transport.connectionsReused>=low.arrivals.length-low.connections(),`opened ${transport.connectionsOpened}, reused ${transport.connectionsReused}`);
 }finally{await low.close();}
});
