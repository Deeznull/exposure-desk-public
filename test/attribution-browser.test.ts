import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {Scanner} from '../src/scanner.js';
import {Detector} from '../src/detectors.js';
import {CHROME_SERVICE_HOSTS} from '../src/browser-provenance.js';
test('routed requests are attributed to page, frame or worker; unrouted traffic is classified by timing or the fixed Chrome service host list, never by any other hostname, and nothing bypasses the deny proxy',{timeout:90000},async()=>{
  const shadow:string[]=[],shadowServer=http.createServer((req,res)=>{shadow.push(req.url!);res.end('must never arrive');});await new Promise<void>(r=>shadowServer.listen(0,'127.0.0.1',r));const shadowOrigin=`http://127.0.0.1:${(shadowServer.address() as any).port}`;
  const arrivals:string[]=[];const server=http.createServer((req,res)=>{arrivals.push(req.url!);const p=req.url!;if(p==='/'){res.setHeader('content-type','text/html');res.end(`<html><head><link rel="preconnect" href="${shadowOrigin}"><link rel="dns-prefetch" href="https://update.googleapis.com"></head><body><iframe src="/frame"></iframe><script>new Worker("/worker.js");fetch("/page-data.json").catch(()=>{});fetch("${shadowOrigin}/shadow").catch(()=>{});</script></body></html>`);}else if(p==='/frame'){res.setHeader('content-type','text/html');res.end('<html><script>fetch("/frame-data.json").catch(()=>{})</script></html>');}else if(p==='/worker.js'){res.setHeader('content-type','text/javascript');res.end('fetch("/worker-data.json").catch(()=>{});');}else if(p.endsWith('.json')){res.setHeader('content-type','application/json');res.end('{"ok":true}');}else if(p==='/robots.txt'){res.end('User-agent: *');}else{res.statusCode=404;res.end('missing');}});
  await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));const origin=`http://127.0.0.1:${(server.address() as any).port}`;
  try{const s=new Scanner({urls:[origin],developmentFixtureOrigin:origin,browser:true,browserPages:1,browserSettleMs:300,browserBaselineMs:400,requestsPerSecond:20,adjacentMaps:false,maxDurationMs:60000,timeoutMs:5000,maxRetries:0,semanticAnalysis:false},{detector:new Detector('disabled')});const v=await s.run();
    assert.equal(v.browserStatus!.launch,true,'Chromium must actually run');assert.equal(v.browserStatus!.runtimePages,1);
    const routed=(path:string)=>v.resources.filter(r=>r.kind==='browser'&&r.url===origin+path&&r.provenance?.channel==='guarded-route');
    assert.ok(routed('/page-data.json').some(r=>r.provenance!.attribution==='page'),'page requests are attributed to the page');
    assert.ok(routed('/frame-data.json').some(r=>r.provenance!.attribution==='frame'),'subresources of child frames are attributed to the frame');
    // The worker may resume before this session's network observation is enabled (Playwright resumes it first); then the worker-channel source evidence applies.
    const worker=routed('/worker-data.json').find(r=>r.provenance!.attribution==='worker');assert.ok(worker,'worker requests are attributed to the worker');assert.ok(['cdp-observation','worker-source'].includes(worker!.provenance!.evidenceSource!),String(worker!.provenance!.evidenceSource));
    assert.equal(routed('/frame').find(r=>r.provenance!.resourceType==='document')!.provenance!.attribution,'frame','iframe navigations are attributed to the frame');
    assert.ok(v.resources.some(r=>r.url.startsWith(shadowOrigin)&&r.status==='blocked'),'the unauthorized loopback fetch is routed and blocked by policy');assert.deepEqual(shadow,[],'no request reaches a host outside scope: routed requests are blocked by policy and unrouted connections die at the deny proxy');
    const proxied=v.resources.filter(r=>r.kind==='browser-proxy');for(const r of proxied){assert.ok(['background','unknown','page','frame','worker','speculative'].includes(r.provenance!.attribution),r.provenance!.attribution);if(r.provenance!.attribution==='background'){if(r.provenance!.evidenceSource==='chrome-service-host')assert.ok(CHROME_SERVICE_HOSTS.has(new URL(r.url).hostname),'only listed Chrome service hosts: '+r.url);else assert.equal(r.provenance!.phase,'pre-navigation','otherwise background is only proven by pre-navigation timing');}assert.ok(r.provenance!.evidenceSource);
      // A target-origin tunnel (Chromium preconnect) carries no request and stays an incomplete, target-attributed gap.
      if(r.provenance!.targetOrigin){assert.notEqual(r.provenance!.attribution,'background');assert.ok(v.limitations.some(g=>g.code==='unrouted-browser-traffic'&&g.url===r.url&&g.incomplete&&g.targetOrigin));}}
    const unknown=v.limitations.filter(g=>g.code==='unrouted-browser-traffic');for(const g of unknown){assert.equal(g.incomplete,true);assert.ok(g.attribution);}
    const background=v.limitations.filter(g=>g.code==='browser-background-denied');assert.ok(background.length<=1);if(background.length){assert.equal(background[0].incomplete,false);assert.equal(background[0].count,v.browserStatus!.background!.count);}
    assert.ok(v.browserStatus!.background,'the background summary is always recorded');assert.ok(arrivals.every(a=>!a.includes('shadow')));
    console.log(JSON.stringify({attributionBrowser:{proxied:proxied.length,background:v.browserStatus!.background,unknown:unknown.length,routed:v.resources.filter(r=>r.kind==='browser'&&r.code).length}}));s.dispose();
  }finally{await new Promise<void>(r=>{server.close(()=>r());server.closeAllConnections();});await new Promise<void>(r=>{shadowServer.close(()=>r());shadowServer.closeAllConnections();});}
});
