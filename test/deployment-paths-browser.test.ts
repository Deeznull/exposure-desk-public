import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {Scanner} from '../src/scanner.js';
import {Detector} from '../src/detectors.js';
import type {ScanConfig} from '../src/types.js';
/** 2.6 P4: a ready-option website that waits for a browser slot other websites hold queues its deployment paths meanwhile, so its time allowance is not spent idle.
 * Found by the P4 matrix: on a small computer (one browser website at once) Standard + Normal for 10 websites lost `/.env` and `/config.json` of four websites to their soft deadline.
 * A free browser keeps the order browser pages, then deployment paths; 2.5 configurations keep it always. Actual Chromium, loopback servers and synthetic data only. */
async function websites(n:number,delayMs=800){
 const arrivals:{origin:number;path:string;at:number;browser:boolean}[]=[],servers:http.Server[]=[],origins:string[]=[];
 for(let i=0;i<n;i++){const server=http.createServer((req,res)=>{const path=new URL(req.url!,'http://local').pathname,browser=/Chrome\//.test(String(req.headers['user-agent']||''));arrivals.push({origin:i,path,at:performance.now(),browser});
   const send=(status:number,body:string,type='text/plain')=>{res.writeHead(status,{'content-type':type});res.end(body);};
   if(path==='/robots.txt')return send(200,'User-agent: *');
   // One browser page per website (a guarded browser turn takes several seconds); its document answers slowly, so one turn holds the slot while the other website has nothing else to do.
   if(path==='/'){setTimeout(()=>send(200,'<html><script src="/app.js"></script>page</html>','text/html'),browser?delayMs:0);return;}
   if(path==='/app.js')return send(200,'const v=1;','application/javascript');
   send(404,'none');
  });await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));servers.push(server);origins.push('http://127.0.0.1:'+(server.address() as any).port);}
 const documents=(i:number)=>arrivals.filter(a=>a.origin===i&&a.browser&&a.path==='/');
 /** Browser documents of a website that arrived after its first `/.env` request. */
 const afterEnv=(i:number)=>{const env=arrivals.find(a=>a.origin===i&&!a.browser&&a.path==='/.env');assert.ok(env,'website '+i+' probes its deployment paths');return documents(i).filter(a=>a.at>env.at).length;};
 return {origins,documents,afterEnv,close:async()=>{await Promise.all(servers.map(s=>new Promise<void>(r=>{s.close(()=>r());s.closeAllConnections();})));}};
}
async function scan(config:Partial<ScanConfig>,computer?:{cores:number;freeMemoryMb:number}){
 const s=new Scanner(config,{detector:new Detector('deliberately-unavailable'),...(computer?{computer}:{})});
 try{const view=await s.run();assert.equal(view.browserStatus!.launch,true,'Chromium must actually run');return {view,browserWebsites:s.caps.browserWebsites};}finally{s.dispose();}
}

test('a ready-option website waiting for a browser slot other websites hold probes its deployment paths meanwhile',{timeout:120000},async()=>{
 const f=await websites(2);try{
  const {view,browserWebsites}=await scan({urls:f.origins.map(o=>o+'/'),privateOrigins:f.origins,coverage:'standard',traffic:'normal',browserSettleMs:50,semanticAnalysis:false},{cores:2,freeMemoryMb:1024});
  assert.equal(browserWebsites,1,'a small computer has one browser website at once');assert.equal(view.stopReason,'discovered-frontier-drained');
  for(const i of [0,1])assert.equal(f.documents(i).length,1,'website '+i+' receives its browser page');
  const after=[0,1].map(f.afterEnv);assert.ok(after.includes(1),`the waiting website probes /.env before its browser page (browser pages after /.env per website: ${after})`);
 }finally{await f.close();}
});

test('a free browser and 2.5 configurations keep the order browser pages, then deployment paths',{timeout:120000},async()=>{
 const ready=await websites(1);try{
  const {view}=await scan({urls:ready.origins.map(o=>o+'/'),privateOrigins:ready.origins,coverage:'standard',traffic:'normal',browserSettleMs:50,semanticAnalysis:false});
  assert.equal(view.stopReason,'discovered-frontier-drained');assert.equal(ready.documents(0).length,1);assert.equal(ready.afterEnv(0),0,'deployment paths follow the browser page');
 }finally{await ready.close();}
 const legacy=await websites(2);try{
  const {view,browserWebsites}=await scan({urls:legacy.origins.map(o=>o+'/'),privateOrigins:legacy.origins,browser:true,browserPages:2,originBrowserPages:1,maxBrowserOrigins:1,browserSettleMs:50,requestsPerSecond:20,originRequestsPerSecond:20,originConcurrency:2,globalConcurrency:4,maxActiveOrigins:2,timeoutMs:4000,maxDurationMs:90000,deep:true,adjacentMaps:false,maxRetries:0,semanticAnalysis:false});
  assert.equal(browserWebsites,1);assert.equal(view.stopReason,'discovered-frontier-drained');
  for(const i of [0,1]){assert.equal(legacy.documents(i).length,1,'website '+i+' receives its browser page');assert.equal(legacy.afterEnv(i),0,'2.5: website '+i+' probes deployment paths after its browser page');}
 }finally{await legacy.close();}
});
