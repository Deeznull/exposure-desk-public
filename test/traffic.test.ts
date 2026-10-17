import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import http from 'node:http';
import https from 'node:https';
import type { Socket } from 'node:net';
import type { TLSSocket } from 'node:tls';
import { makeConfig, resolveScanConfig } from '../src/config.js';
import { Transport, PolicyError, PRODUCT_USER_AGENT, RUN_CACHE_BYTES, connectionKey, cacheLifetimeMs, varyMatches } from '../src/transport.js';
import { Evidence } from '../src/evidence.js';
import { Detector } from '../src/detectors.js';
import { Scanner } from '../src/scanner.js';
import { COVERAGES, HARD_CEILINGS, TRAFFIC_NOTES, estimateScan } from '../src/profiles.js';
import { egressTripwire, virtualNetwork } from './virtual-network.js';
import { loopbackCertificate, trusting } from './tls-fixture.js';
import type { ScanConfig, Resource } from '../src/types.js';
/** 2.6 Part 2: Low-impact traffic — pacing, keep-alive reuse only to the same validated pinned address and TLS name, the run response cache and deduplicated probes. Loopback servers and synthetic data only. */
const detector=new Detector('disabled');await detector.init();
const SITE='https://example.com/',publicDns=async()=>[{address:'93.184.216.34',family:4}];
const CHROMIUM={'user-agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',accept:'*/*'};
type Route={body?:string;status?:number;headers?:Record<string,string|string[]>;delay?:number};
/** Loopback website listening on one port at each given address. It records every request (time, connection, Host, local address) and every connection; `delay` holds responses open to observe concurrency.
 * A request to /arm marks its connection: the next request on that connection is dropped without an answer, as a server closing an idle kept-alive connection would. */
async function site(routes:Record<string,Route>,options:{hosts?:string[];delay?:number;shared?:{inFlight:number;peak:number}}={}){
  const arrivals:{path:string;at:number;socket:number;host:string;local:string;connection:string}[]=[],sockets:Socket[]=[],armed=new Set<Socket>();let inFlight=0,peak=0;
  const handler=(req:http.IncomingMessage,res:http.ServerResponse)=>{
    const path=req.url||'',socket=sockets.indexOf(req.socket);arrivals.push({path,at:Date.now(),socket,host:String(req.headers.host),local:req.socket.localAddress||'',connection:String(req.headers.connection||'')});
    if(path==='/always-drop'||armed.has(req.socket)){armed.delete(req.socket);req.socket.destroy();return;}if(path==='/arm')armed.add(req.socket);
    inFlight++;peak=Math.max(peak,inFlight);if(options.shared){options.shared.inFlight++;options.shared.peak=Math.max(options.shared.peak,options.shared.inFlight);}
    const r=routes[path]??routes['*'];setTimeout(()=>{inFlight--;if(options.shared)options.shared.inFlight--;res.writeHead(r?.status??(r?200:404),{'content-type':'text/plain',...(r?.headers||{})});res.end(r?.body??(r?'ok':'not found'));},r?.delay??options.delay??0);
  };
  const hosts=options.hosts||['127.0.0.1'],servers:http.Server[]=[];let port=0;
  for(const host of hosts){const server=http.createServer(handler);server.on('connection',s=>sockets.push(s));await new Promise<void>(r=>server.listen(port,host,r));port=(server.address() as any).port;servers.push(server);}
  return {port,origin:`http://127.0.0.1:${port}`,arrivals,sockets,open:()=>sockets.filter(s=>!s.destroyed).length,peak:()=>peak,count:(path:string)=>arrivals.filter(a=>a.path===path).length,
    close:()=>Promise.all(servers.map(s=>new Promise<void>(r=>{s.close(()=>r());s.closeAllConnections();})))};
}
async function until(check:()=>boolean,message:string,ms=5000){const end=Date.now()+ms;while(!check()){if(Date.now()>end)assert.fail(message);await new Promise(r=>setTimeout(r,20));}}
/** The transport switches keep-alive reuse and the run cache on `traffic`. Pacing is tested with real profile settings below; these correctness tests use a fast legacy pace with the Low-impact switch so they do not wait on 0.5 requests/s. */
const fastLowImpact=(input:Partial<ScanConfig>)=>({...makeConfig({requestsPerSecond:20,originRequestsPerSecond:20,maxRetries:0,...input}),traffic:'low-impact'}) as ScanConfig;
const transport=(config:ScanConfig,resolver?:(host:string)=>Promise<{address:string;family:number}[]>,rows:Resource[]=[])=>new Transport(config,new Evidence(detector),r=>rows.push(r),()=>{},resolver);

test('pure rules: a connection key binds origin, validated address and TLS name; run-cache freshness and Vary follow RFC 9111 for a private cache',()=>{
  const u=new URL('https://a.example.com/x'),k=connectionKey(u,'127.0.0.1');
  assert.equal(connectionKey(new URL('https://a.example.com/y?q=1'),'127.0.0.1'),k,'same origin, address and TLS name');
  assert.equal(connectionKey(new URL('https://A.example.com:443/'),'::ffff:127.0.0.1'),k,'canonical host, default port and IPv4-mapped address');
  for(const other of [connectionKey(u,'127.0.0.2'),connectionKey(new URL('https://b.example.com/'),'127.0.0.1'),connectionKey(new URL('http://a.example.com/'),'127.0.0.1'),connectionKey(new URL('https://a.example.com:8443/'),'127.0.0.1')])assert.notEqual(other,k);
  assert.ok(k.endsWith('|a.example.com'),'the TLS server name is part of the key');assert.ok(connectionKey(new URL('https://127.0.0.1/'),'127.0.0.1').endsWith('|'),'an IP literal sends no server name');
  const now=Date.parse('2026-10-08T12:00:00Z'),date=new Date(now).toUTCString(),life=(h:Record<string,string|string[]>,status=200)=>cacheLifetimeMs({date,...h},status,now);
  assert.equal(life({'cache-control':'max-age=600'}),600000);assert.equal(life({'cache-control':'public, max-age=600',age:'100'}),500000,'Age is subtracted');
  for(const status of [404,410])assert.equal(life({'cache-control':'max-age=600'},status),600000);
  for(const status of [204,206,301,302,304,429,500,503])assert.equal(life({'cache-control':'max-age=600'},status),0,'status '+status);
  for(const h of [{'cache-control':'no-store, max-age=600'},{'cache-control':'no-cache'},{'cache-control':'private, max-age=600'},{'cache-control':'max-age=0'},{pragma:'no-cache'},{'cache-control':'max-age=600',vary:'Accept, *'},{'cache-control':'max-age=600','set-cookie':['sid=1; Path=/']},{expires:new Date(now-1000).toUTCString()},{expires:'0'},{}] as Record<string,string|string[]>[])assert.equal(life(h),0,JSON.stringify(h));
  assert.equal(life({expires:new Date(now+60000).toUTCString()}),60000);assert.equal(life({'last-modified':new Date(now-864e5).toUTCString()}),8640000,'Last-Modified heuristic: 10% of its age');assert.equal(life({pragma:'no-cache','cache-control':'max-age=60'}),60000,'Pragma applies only without Cache-Control');
  const stored={accept:'text/html','user-agent':PRODUCT_USER_AGENT,'accept-encoding':'gzip, br, deflate'};
  assert.ok(varyMatches('',stored,{}));assert.ok(varyMatches('Accept-Encoding',stored,{...stored,'user-agent':'Chromium'}));assert.ok(varyMatches('Cookie',stored,{...stored}),'absent on both sides matches');
  assert.ok(!varyMatches('User-Agent',stored,{...stored,'user-agent':'Chromium'}));assert.ok(!varyMatches('accept, origin',stored,{...stored,origin:'http://a.test'}));
});

test('Low-impact never exceeds its pace: one request at a time and 0.5 requests/s per website, 2 at once and 1 request/s overall',{timeout:120000},async()=>{
  const shared={inFlight:0,peak:0},sites=await Promise.all([0,1,2].map(()=>site({'*':{body:'ok'}},{delay:2500,shared})));
  try{
    const origins=sites.map(s=>s.origin),c=resolveScanConfig({urls:origins.map(o=>o+'/'),privateOrigins:origins,coverage:'standard',traffic:'low-impact'});
    assert.deepEqual([c.originRequestsPerSecond,c.originConcurrency,c.maxActiveOrigins,c.requestsPerSecond,c.globalConcurrency,c.maxRetries],[.5,1,2,1,2,0],'three websites: global pacing grows only with the two that may be active');
    const t=transport(c);try{await Promise.all(origins.flatMap(o=>[1,2,3].map(i=>t.get(`${o}/r${i}`))));}finally{t.close();}
    const all=sites.flatMap(s=>s.arrivals).sort((a,b)=>a.at-b.at);assert.equal(all.length,9);assert.equal(t.requests,9);
    for(const s of sites){assert.equal(s.peak(),1,'one request at a time per website');for(let i=1;i<s.arrivals.length;i++)assert.ok(s.arrivals[i].at-s.arrivals[i-1].at>=1900,`per-website gap ${s.arrivals[i].at-s.arrivals[i-1].at} ms`);}
    // Pacing is applied when a request is dispatched; an event-loop stall between dispatch and arrival can shorten one measured gap, so each gap has a margin and the span is checked against 1 request/s.
    for(let i=1;i<all.length;i++)assert.ok(all[i].at-all[i-1].at>=700,`global gap ${all[i].at-all[i-1].at} ms`);assert.ok(all.at(-1)!.at-all[0].at>=7500,`nine requests over ${all.at(-1)!.at-all[0].at} ms`);
    assert.equal(shared.peak,2,'at most two requests (so at most two websites) at once overall, and the limit was reached');
    assert.equal(t.connectionsOpened+t.connectionsReused,9,'every request opened or reused exactly one connection');
  }finally{await Promise.all(sites.map(s=>s.close()));}
});

test('Low-impact keeps one connection per website alive between requests; Normal and legacy settings open one per request; closing the run ends every kept-alive connection',{timeout:60000},async()=>{
  const s=await site({'*':{body:'ok'}});
  try{
    const rows:Resource[]=[],low=transport(resolveScanConfig({urls:[s.origin+'/'],privateOrigins:[s.origin],coverage:'standard',traffic:'low-impact'}),undefined,rows);
    for(const i of [1,2,3])await low.get(`${s.origin}/k${i}`);
    assert.deepEqual(s.arrivals.map(a=>a.socket),[0,0,0],'all three requests used the first connection');assert.ok(s.arrivals.every(a=>/keep-alive/i.test(a.connection)));
    assert.deepEqual([low.connectionsOpened,low.connectionsReused,low.tlsHandshakes],[1,2,0]);assert.equal(s.open(),1,'the connection stays open between requests');
    assert.equal(typeof rows[0].timings!.connectMs,'number');assert.equal(rows[0].timings!.connectionReused,undefined);assert.ok(rows.slice(1).every(r=>r.timings!.connectionReused===true&&r.timings!.connectMs===undefined),'a reused connection has no connect phase');
    const snapshot=low.originControl.snapshots().find(o=>o.origin===s.origin)!;assert.deepEqual([snapshot.connectionsOpened,snapshot.connectionsReused,snapshot.requests],[1,2,3]);
    low.close();await until(()=>s.open()===0,'closing the run must close the kept-alive connection');
    await low.get(`${s.origin}/late`);assert.match(s.arrivals.at(-1)!.connection,/close/i,'a late request after the run closed uses a one-off connection');assert.equal(low.connectionsOpened,2);await until(()=>s.open()===0,'and leaves nothing open');
    for(const config of [resolveScanConfig({urls:[s.origin+'/'],privateOrigins:[s.origin],coverage:'standard',traffic:'normal'}),makeConfig({urls:[s.origin+'/'],privateOrigins:[s.origin],requestsPerSecond:20})]){
      const before=s.sockets.length,arrived=s.arrivals.length,t=transport(config);for(const i of [1,2,3])await t.get(`${s.origin}/n${i}`);
      assert.equal(s.sockets.length-before,3,'one connection per request');assert.deepEqual([t.connectionsOpened,t.connectionsReused],[3,0]);assert.ok(s.arrivals.slice(arrived).every(a=>/close/i.test(a.connection)));t.close();
    }
  }finally{await s.close();}
});

test('connection reuse never crosses an address or host change: a changed DNS answer retires the kept-alive connection and opens a new validated one',{timeout:60000},async()=>{
  const s=await site({'*':{body:'ok'}},{hosts:['127.0.0.1','127.0.0.2']});
  try{
    const owner=`http://owner.example.com:${s.port}`,assets=`http://assets.example.com:${s.port}`;let answers=['127.0.0.1','127.0.0.2'];
    const t=transport(fastLowImpact({urls:[owner+'/'],relatedOrigins:[assets],privateOrigins:[owner,assets]}),async host=>/^(?:owner|assets)\.example\.com$/.test(host)?answers.map(address=>({address,family:4})):[]);
    try{
      await t.get(owner+'/a');answers=['127.0.0.2','127.0.0.1'];await t.get(owner+'/b');answers=['127.0.0.2'];await t.get(owner+'/c');await t.get(owner+'/d');
      assert.deepEqual(s.arrivals.map(a=>[a.path,a.socket,a.local.replace('::ffff:','')]),[['/a',0,'127.0.0.1'],['/b',0,'127.0.0.1'],['/c',1,'127.0.0.2'],['/d',1,'127.0.0.2']],'a reordered answer that still contains the pin keeps the connection; an answer without it gets its own connection, then reuses it');
      await until(()=>s.sockets[0].destroyed,'the connection to the old address is closed');assert.deepEqual([t.connectionsOpened,t.connectionsReused],[2,2]);
      for(const path of ['/e','/f','/g'])await t.get((path==='/f'?owner:assets)+path);
      const hostsBySocket=new Map<number,Set<string>>();for(const a of s.arrivals){const h=hostsBySocket.get(a.socket)||new Set();h.add(a.host);hostsBySocket.set(a.socket,h);}
      assert.ok([...hostsBySocket.values()].every(h=>h.size===1),'no connection ever carried requests for two host names');assert.equal(hostsBySocket.size,3);
    }finally{t.close();}
  }finally{await s.close();}
});

test('a metadata or private DNS answer is refused before any reuse and retires the kept-alive connection; the next request validates a fresh one',{timeout:60000},async()=>{
  const s=await site({'*':{body:'ok',headers:{'cache-control':'max-age=600'}}});
  try{
    const owner=`http://owner.example.com:${s.port}`;let answers=[{address:'127.0.0.1',family:4}];
    const t=transport(fastLowImpact({urls:[owner+'/'],privateOrigins:[owner]}),async host=>host==='owner.example.com'?answers:[]);
    try{
      await t.get(owner+'/a');assert.equal(s.open(),1);
      answers=[{address:'169.254.169.254',family:4}];await assert.rejects(t.get(owner+'/b'),e=>e instanceof PolicyError&&e.code==='metadata');
      await assert.rejects(t.one(owner+'/a',{kind:'browser',headers:CHROMIUM}),e=>e instanceof PolicyError&&e.code==='metadata','a cached copy is refused by the same DNS check');assert.equal(t.requestsAvoided,0);
      await until(()=>s.open()===0,'the refused answer retired the kept-alive connection');
      answers=[{address:'127.0.0.1',family:4},{address:'fd00:ec2::254',family:6}];await assert.rejects(t.get(owner+'/c'),e=>e instanceof PolicyError&&e.code==='metadata','a mixed answer with a metadata address is refused');
      assert.deepEqual(s.arrivals.map(a=>a.path),['/a'],'nothing was sent after a refused answer');
      answers=[{address:'127.0.0.1',family:4}];await t.get(owner+'/d');assert.deepEqual([t.connectionsOpened,t.connectionsReused],[2,0],'a fresh validated connection after the refusal');
      await t.one(owner+'/a',{kind:'browser',headers:CHROMIUM});assert.equal(t.requestsAvoided,1,'with a valid answer again the cached copy serves');
    }finally{t.close();}
    // Without a private-origin exception a loopback answer stays refused with reuse and the run cache on: no connection is opened.
    const plain=`http://site.example.com:${s.port}`,p=transport(fastLowImpact({urls:[plain+'/']}),async()=>[{address:'127.0.0.1',family:4}]);
    try{await assert.rejects(p.get(plain+'/x'),e=>e instanceof PolicyError&&e.code==='private-address');assert.equal(p.connectionsOpened,0);assert.ok(!s.arrivals.some(a=>a.path==='/x'));}finally{p.close();}
  }finally{await s.close();}
});

test('a kept-alive connection dropped by the server is replaced once: the GET is sent again on a fresh connection under a new permit, never twice',{timeout:60000},async()=>{
  const s=await site({'*':{body:'ok'}});
  try{
    const gaps:string[]=[],rows:Resource[]=[],t=new Transport(fastLowImpact({urls:[s.origin+'/'],privateOrigins:[s.origin]}),new Evidence(detector),r=>rows.push(r),g=>gaps.push(g.code));
    try{
      await t.get(s.origin+'/arm');const r=await t.get(s.origin+'/x');assert.equal(r.status,200);
      assert.deepEqual(s.arrivals.map(a=>[a.path,a.socket]),[['/arm',0],['/x',0],['/x',1]],'the dropped request went once more on a new connection');
      const x=rows.find(r=>r.url===s.origin+'/x')!.timings!;assert.equal(x.connectionReused,undefined,'the row describes the fresh connection that answered');assert.equal(typeof x.connectMs,'number');
      assert.deepEqual([t.requests,t.connectionsOpened,t.connectionsReused,t.connectionReplays],[3,2,1,1],'the replay is paced and counted as a request and as a replay');assert.ok(!gaps.includes('network-failure'));
      await assert.rejects(t.get(s.origin+'/always-drop'),e=>e instanceof PolicyError&&e.code==='network-failure');
      assert.equal(s.count('/always-drop'),2,'a replay that fails too is not repeated');assert.equal(t.connectionReplays,2);assert.ok(gaps.includes('network-failure'));
      const f=transport(fastLowImpact({urls:[s.origin+'/'],privateOrigins:[s.origin]}));try{const before=s.count('/always-drop');await assert.rejects(f.get(s.origin+'/always-drop'));assert.equal(s.count('/always-drop')-before,1,'a failure on a fresh connection is never replayed');}finally{f.close();}
    }finally{t.close();}
  }finally{await s.close();}
});

test('the run cache serves identical uncredentialed GETs already downloaded, never a credentialed, cross-origin, Vary-mismatched, uncacheable or stale response, and preflight still screens cached requests',{timeout:60000},async()=>{
  const day=new Date(Date.now()-864e5).toUTCString(),fresh={'cache-control':'max-age=600'};
  const s=await site({'/app.js':{body:'APP',headers:fresh},'/vary-ua.js':{body:'UA',headers:{...fresh,vary:'User-Agent'}},'/vary-accept.js':{body:'ACCEPT',headers:{...fresh,vary:'Accept'}},'/no-store.js':{headers:{'cache-control':'no-store'}},'/session.js':{headers:{...fresh,'set-cookie':'sid=synthetic; Path=/'}},'/plain.js':{},'/modified.js':{headers:{'last-modified':day}},'/short.js':{headers:{'cache-control':'max-age=1'}},'/gone':{status:404,headers:fresh},'/dump.sql':{body:'-- synthetic dump',headers:fresh}});
  try{
    const rows:Resource[]=[],o=s.origin,other=`http://127.0.0.2:${s.port}`,t=transport(fastLowImpact({urls:[o+'/'],relatedOrigins:[other],privateOrigins:[o]}),undefined,rows),browser=(path:string,headers:Record<string,string>=CHROMIUM)=>t.one(o+path,{kind:'browser',headers,chain:[o+'/','observed browser request']});
    try{
      await t.get(o+'/app.js');const wire=t.wireBytes,bytes=t.bytes,r=await browser('/app.js');
      assert.equal(r.body.toString(),'APP');assert.equal(r.status,200);assert.equal(r.resource!.servedFrom,'run-cache');assert.equal(r.resource!.kind,'browser');assert.equal(r.resource!.attemptId,undefined);assert.equal(r.resource!.requestHeaderNames,undefined,'no request was sent');
      assert.deepEqual([s.count('/app.js'),t.browserCacheHits,t.requestsAvoided,t.requests],[1,1,1,1]);assert.equal(t.wireBytes,wire,'no wire bytes');assert.equal(t.bytes,bytes+3,'decoded bytes count against the same budgets');
      await browser('/app.js',{...CHROMIUM,cookie:'sid=synthetic'});assert.equal(s.count('/app.js'),2,'a cookie always goes through guarded transport');
      await browser('/app.js',{...CHROMIUM,origin:o});assert.equal(s.count('/app.js'),2,'a same-origin module request carries its own origin and is reused');await browser('/app.js',{...CHROMIUM,origin:other});assert.equal(s.count('/app.js'),3,'a cross-origin Origin always goes through guarded transport');
      await browser('/app.js');assert.equal(s.count('/app.js'),3,'credentialed answers were not stored; the uncredentialed copy still serves');
      await assert.rejects(browser('/app.js',{...CHROMIUM,'x-api-key':'synthetic-header-value'}),e=>e instanceof PolicyError&&e.code==='credential-in-request');assert.equal(s.count('/app.js'),3);
      await t.get(o+'/vary-ua.js');await browser('/vary-ua.js');await browser('/vary-ua.js');await t.get(o+'/vary-ua.js');assert.equal(s.count('/vary-ua.js'),3,'Vary: User-Agent separates the product and browser requests; an equal request reuses');
      await t.get(o+'/vary-accept.js');await browser('/vary-accept.js',{...CHROMIUM,accept:'text/html,application/json,text/plain,*/*;q=0.5'});assert.equal(s.count('/vary-accept.js'),1,'equal Accept values reuse');await browser('/vary-accept.js');assert.equal(s.count('/vary-accept.js'),2);
      for(const path of ['/no-store.js','/session.js','/plain.js']){await t.get(o+path);await t.get(o+path);await browser(path);assert.equal(s.count(path),3,path+' is never reused');}
      await t.get(o+'/modified.js');await browser('/modified.js');assert.equal(s.count('/modified.js'),1,'Last-Modified heuristic freshness');
      await t.get(o+'/short.js');await new Promise(r=>setTimeout(r,1100));await t.get(o+'/short.js');assert.equal(s.count('/short.js'),2,'a stale entry is fetched again');
      const gone=await t.get(o+'/gone');await t.get(o+'/gone');assert.equal(gone.status,404);assert.equal(s.count('/gone'),1,'a fresh 404 serves a repeated static request');await browser('/gone');assert.equal(s.count('/gone'),1,'the browser receives the same fresh 404');
      await t.get(o+'/dump.sql');await t.get(o+'/dump.sql',[],'deep');assert.equal(s.count('/dump.sql'),2,'a bounded deployment-probe sample never uses the run cache');
      const cachedRows=rows.filter(x=>x.servedFrom==='run-cache');assert.equal(cachedRows.length,t.requestsAvoided,'every cache hit has its own resource row');assert.ok(cachedRows.every(x=>x.code!==undefined&&x.partial===false&&x.attemptId===undefined));
    }finally{t.close();}
    const normal=transport(makeConfig({urls:[o+'/'],privateOrigins:[o],requestsPerSecond:20}));try{const before=s.count('/app.js');await normal.get(o+'/app.js');await normal.one(o+'/app.js',{kind:'browser',headers:CHROMIUM});assert.equal(s.count('/app.js')-before,2,'Normal and legacy settings keep 2.5 behaviour: no run cache');assert.equal(normal.requestsAvoided,0);}finally{normal.close();}
  }finally{await s.close();}
});

test('Low-impact estimates fewer connections and a time allowance scaled by its slower pace; Normal estimates one connection per request',()=>{
  for(const coverage of COVERAGES){
    const low=makeConfig({urls:[SITE],coverage,traffic:'low-impact'}),normal=makeConfig({urls:[SITE],coverage,traffic:'normal'});
    assert.equal(low.originMaxDurationMs,Math.min(HARD_CEILINGS.originDurationMs,normal.originMaxDurationMs!*normal.originRequestsPerSecond!/low.originRequestsPerSecond!),coverage+': the allowance follows the pace');
    const e=estimateScan(low,3),n=estimateScan(normal,3),pages=low.browser?low.originBrowserPages!:0;
    assert.deepEqual([n.perWebsite.connections,n.perWebsite.connectionsMax,n.total.connections,n.total.connectionsMax],[n.perWebsite.requests,n.perWebsite.requests,n.total.requests,n.total.requests]);
    assert.equal(e.perWebsite.connections,2+pages);assert.equal(e.perWebsite.connectionsMax,e.perWebsite.requests);assert.equal(e.total.connections,Math.min(e.total.requests,3*(2+pages)));assert.equal(e.total.connectionsMax,e.total.requests);assert.ok(e.total.connections<n.total.connections);
    assert.match(e.basis,/one connection per website/);assert.match(e.basis,/not downloaded again/);assert.match(n.basis,/one connection per request/);
  }
  assert.match(TRAFFIC_NOTES['low-impact'],/kept-alive connection per website/);assert.match(TRAFFIC_NOTES['low-impact'],/does not hide the scan/);assert.match(TRAFFIC_NOTES['low-impact'],/not undetectable/);
});

test('Low-impact keeps both soft-404 baseline probes (deployment-path precision is unchanged); one query variant per path is the stated "Limited by profile" boundary (owner decision 2026-10-09), not an incomplete scan',{timeout:120000},async()=>{
  const page='<a href="/list?page=1">1</a><a href="/list?page=2">2</a><script src="/app.js"></script>',hosts={'https://example.com':{'/':{body:page},'/list':{body:'list'},'/app.js':{type:'text/javascript',body:'void 0;'}}};
  const baselines=(arrivals:{url:string}[])=>arrivals.filter(a=>/^https:\/\/example\.com\/[0-9a-f]{24}$/.test(a.url)).length;
  const trip=egressTripwire();try{
    const run=async(traffic:'low-impact'|'normal')=>{const s=new Scanner({urls:[SITE],coverage:'standard',traffic,browser:false,semanticAnalysis:false},{detector:new Detector('disabled'),resolver:publicDns});try{const net=virtualNetwork(s,hosts);const v=await s.run();return {v,arrivals:net.arrivals};}finally{s.dispose();}};
    const low=await run('low-impact'),normal=await run('normal');
    assert.equal(baselines(low.arrivals),2);assert.equal(baselines(normal.arrivals),2);
    assert.equal(low.v.accounting!.requestsAvoided,0,'requests avoided counts only run-cache answers');assert.equal(low.v.origins!.find(o=>o.origin==='https://example.com')!.requestsAvoided,0);assert.equal(normal.v.accounting!.requestsAvoided,0);
    for(const k of ['connectionsOpened','connectionsReused','tlsHandshakes','browserCacheHits','requestsAvoided'] as const)assert.equal(typeof low.v.accounting![k],'number',k);
    assert.ok(low.arrivals.some(a=>a.url==='https://example.com/list?page=1')&&!low.arrivals.some(a=>a.url==='https://example.com/list?page=2'));assert.ok(normal.arrivals.some(a=>a.url==='https://example.com/list?page=2'));
    const gap=low.v.limitations.find(g=>g.code==='profile-query-variants')!;assert.equal(gap.incomplete,false);assert.match(gap.detail,/^Limited by profile: Low-impact examines one query-string variant per path.*Standard \+ Normal visits/);assert.equal(low.v.limitations.some(g=>g.code==='query-variants'),false);
    assert.equal(low.v.profile!.profileLimit!.count,1);assert.ok(!low.v.limitations.some(g=>g.incomplete&&/variant/i.test(g.detail)),'no incomplete note for the boundary (this fixture disables the detector; the completed verdict is checked in profile-limit.test)');assert.ok(low.v.uninspected!.some(w=>w.url==='https://example.com/list?page=2'&&w.deferredReason==='profile-limit'),'the variant stays in the run data for a higher-coverage scan');
    assert.deepEqual(trip.violations,[],'nothing reached the real network');
  }finally{trip.restore();}
});

test('identical eligible GETs in flight are deduplicated before sending: the second waits and is served from the run cache; credentialed or uncacheable ones still go out',{timeout:60000},async()=>{
  const s=await site({'/slow.js':{body:'SLOW',headers:{'cache-control':'max-age=600'}},'/fresh-each.js':{body:'X',headers:{'cache-control':'no-store'}}},{delay:400});
  try{
    const o=s.origin,t=transport(fastLowImpact({urls:[o+'/'],privateOrigins:[o]}));
    try{
      // The first download is on the wire before the others ask, so which request holds the download never depends on scheduling.
      const first=t.get(o+'/slow.js');await until(()=>s.count('/slow.js')===1,'the first download is in flight');
      const [a,b,c]=await Promise.all([first,t.one(o+'/slow.js',{kind:'browser',headers:CHROMIUM}),t.one(o+'/slow.js',{kind:'browser',headers:{...CHROMIUM,cookie:'sid=synthetic'}})]);
      assert.deepEqual([a.body.toString(),b.body.toString(),c.body.toString()],['SLOW','SLOW','SLOW']);assert.equal(s.count('/slow.js'),2,'one shared download plus the credentialed request');
      assert.equal(b.resource!.servedFrom,'run-cache');assert.equal(b.resource!.timings!.connectionReused,undefined);assert.deepEqual([t.browserCacheHits,t.requestsAvoided],[1,1]);
      await Promise.all([t.get(o+'/fresh-each.js'),t.one(o+'/fresh-each.js',{kind:'browser',headers:CHROMIUM})]);assert.equal(s.count('/fresh-each.js'),2,'a waiter whose answer is not reusable sends its own request');
    }finally{t.close();}
  }finally{await s.close();}
});

test('a request waiting for an identical in-flight download stops at once when the run is cancelled and sends nothing',{timeout:60000},async()=>{
  const s=await site({'/slow.js':{body:'SLOW',headers:{'cache-control':'max-age=600'},delay:3000}});
  try{
    const o=s.origin,t=transport(fastLowImpact({urls:[o+'/'],privateOrigins:[o]})),live=(t as unknown as {live:Map<number,{phase:string;kind:string}>}).live;
    try{
      const first=t.get(o+'/slow.js');await until(()=>s.count('/slow.js')===1,'the first download is in flight');
      const waiting=t.one(o+'/slow.js',{kind:'browser',headers:CHROMIUM});await until(()=>[...live.values()].some(a=>a.kind==='browser'&&a.phase==='cache-wait'),'the identical request waits for the download');
      const cancelled=Date.now();t.cancel();
      await assert.rejects(waiting,e=>e instanceof PolicyError&&e.code==='cancelled');assert.ok(Date.now()-cancelled<1000,'the waiter stopped without waiting for the download');
      await assert.rejects(first,e=>e instanceof PolicyError&&e.code==='cancelled');
      assert.equal(s.count('/slow.js'),1,'the waiter sent nothing');assert.deepEqual([t.requests,t.requestsAvoided,t.browserCacheHits],[1,0,0]);assert.equal(live.size,0);
    }finally{t.close();}
  }finally{await s.close();}
});

test('a reused kept-alive connection gets the full request timeout back: an answer slower than the 4 s idle limit still arrives over it',{timeout:60000},async()=>{
  const s=await site({'*':{body:'ok'},'/slow':{body:'late but complete',delay:4500}});
  try{
    const rows:Resource[]=[],t=transport(fastLowImpact({urls:[s.origin+'/'],privateOrigins:[s.origin]}),undefined,rows);
    try{
      await t.get(s.origin+'/a');const r=await t.get(s.origin+'/slow');assert.equal(r.body.toString(),'late but complete');assert.equal(r.partial,false);
      assert.deepEqual(s.arrivals.map(a=>a.socket),[0,0],'the slow answer came over the reused connection');assert.equal(rows[1].timings!.connectionReused,true);assert.deepEqual([t.connectionsOpened,t.connectionsReused],[1,1]);
    }finally{t.close();}
  }finally{await s.close();}
});

test('HTTPS: a kept-alive connection is reused only under its own TLS name; each handshake names its website (SNI), and a certificate that does not name the website is refused and never pooled',{timeout:60000},async()=>{
  const {cert,key}=loopbackCertificate(['a.example.com','b.example.com']),sockets:TLSSocket[]=[],arrivals:{host:string;socket:number;servername:string}[]=[];
  const server=https.createServer({cert,key},(req,res)=>{const socket=req.socket as TLSSocket;arrivals.push({host:String(req.headers.host).split(':')[0],socket:sockets.indexOf(socket),servername:String(socket.servername)});res.writeHead(200,{'content-type':'text/plain'});res.end('ok');});
  server.on('secureConnection',s=>sockets.push(s));await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));
  const port=(server.address() as any).port,[A,B,C]=['a','b','c'].map(h=>`https://${h}.example.com:${port}`),resolver=async(host:string)=>/^[abc]\.example\.com$/.test(host)?[{address:'127.0.0.1',family:4}]:[];
  try{
    await trusting(cert,async()=>{
      const rows:Resource[]=[],t=transport(fastLowImpact({urls:[A+'/'],relatedOrigins:[B,C],privateOrigins:[A,B,C]}),resolver,rows);
      try{
        for(const url of [A+'/1',A+'/2',B+'/1',B+'/2',A+'/3'])assert.equal((await t.get(url)).status,200);
        const a=['a.example.com',0,'a.example.com'],b=['b.example.com',1,'b.example.com'];
        assert.deepEqual(arrivals.map(x=>[x.host,x.socket,x.servername]),[a,a,b,b,a],'each website has its own connection and TLS name; reuse never crosses them');
        assert.deepEqual([t.connectionsOpened,t.connectionsReused,t.tlsHandshakes],[2,3,2],'one validated handshake per new connection, none on reuse');
        const opened=rows.filter(r=>!r.timings!.connectionReused),reused=rows.filter(r=>r.timings!.connectionReused);
        assert.ok(opened.length===2&&opened.every(r=>typeof r.timings!.connectMs==='number'&&typeof r.timings!.tlsMs==='number'),'a new connection records its connect and TLS phases');
        assert.ok(reused.length===3&&reused.every(r=>r.timings!.connectMs===undefined&&r.timings!.tlsMs===undefined),'a reused connection has neither');
        for(const path of ['/1','/2'])await assert.rejects(t.get(C+path),e=>e instanceof PolicyError&&e.code==='network-failure');
        assert.equal(arrivals.length,5,'nothing was sent to a website the certificate does not name');assert.deepEqual([t.connectionsOpened,t.tlsHandshakes,t.connectionsReused],[4,4,3],'each refused handshake is counted and nothing refused is kept for reuse');
      }finally{t.close();}
      await until(()=>sockets.every(s=>s.destroyed),'closing the run closes the TLS connections');
      // Normal and legacy settings: a full handshake for every request.
      const legacy=transport(makeConfig({urls:[A+'/'],privateOrigins:[A],requestsPerSecond:20}),resolver);
      try{for(const path of ['/4','/5'])await legacy.get(A+path);assert.deepEqual([legacy.connectionsOpened,legacy.connectionsReused,legacy.tlsHandshakes],[2,0,2]);assert.deepEqual(arrivals.slice(5).map(x=>x.socket),[2,3]);}finally{legacy.close();}
    });
  }finally{await new Promise<void>(r=>{server.close(()=>r());server.closeAllConnections();});}
});

test('the run cache stays bounded: least recently used answers are evicted at its limit (64 MiB), an answer over a quarter of it (16 MiB) is never kept, and a cached answer never exceeds the byte budget',{timeout:60000},async()=>{
  assert.equal(RUN_CACHE_BYTES,64*1024*1024);
  // The same rules at a small limit, so the test moves kilobytes instead of 150 MiB through a shared test process.
  const LIMIT=4000,fresh={'cache-control':'max-age=600'},routes:Record<string,Route>={'/huge.js':{body:'h'.repeat(LIMIT/4+100),headers:fresh},'/small.js':{body:'s'.repeat(1000),headers:fresh}};
  for(const i of [1,2,3,4,5])routes['/e'+i+'.js']={body:String(i).repeat(900),headers:fresh};
  const s=await site(routes);
  try{
    const o=s.origin,big=transport(fastLowImpact({urls:[o+'/'],privateOrigins:[o]}));(big as unknown as {cacheLimit:number}).cacheLimit=LIMIT;
    try{
      for(const i of [1,2,3,4,5])await big.get(o+'/e'+i+'.js');
      await big.get(o+'/e5.js');assert.equal(s.count('/e5.js'),1,'the most recent answer is kept');
      await big.get(o+'/e1.js');assert.equal(s.count('/e1.js'),2,'the least recently used answer was evicted at the limit');
      await big.get(o+'/e2.js');assert.equal(s.count('/e2.js'),2,'storing e1 again evicted the next least recently used');
      await big.get(o+'/e5.js');assert.equal(s.count('/e5.js'),1);
      await big.get(o+'/huge.js');await big.get(o+'/huge.js');assert.equal(s.count('/huge.js'),2,'an answer over a quarter of the limit is never kept');assert.equal(big.requestsAvoided,2);
    }finally{big.close();}
    const small=transport(fastLowImpact({urls:[o+'/'],privateOrigins:[o],maxTotalBytes:2500,maxDecodedTotalBytes:2500}));
    try{
      await small.get(o+'/small.js');await small.get(o+'/small.js');assert.deepEqual([s.count('/small.js'),small.requestsAvoided,small.bytes],[1,1,2000],'a cached answer counts against the byte budget');
      const third=await small.get(o+'/small.js');assert.equal(s.count('/small.js'),2,'a cached answer that would pass the budget is not served');assert.equal(third.partial,true,'the guarded download stops at the budget like any other');assert.equal(small.bytes,2500);assert.equal(small.requestsAvoided,1);
    }finally{small.close();}
  }finally{await s.close();}
});

test('multi-subdomain fixture: Deep audit + Low-impact keeps Deep audit + Normal recall across same-registrable-domain websites, with no more requests',{timeout:120000},async()=>{
  const key=(name:string)=>'sk-proj-'+createHash('sha512').update('unit-traffic-subdomains-'+name).digest('base64url').slice(0,64),K={inline:key('inline'),local:key('local'),app:key('app'),map:key('map'),api:key('api'),env:key('env')};
  const hosts={
    'https://example.com':{'/':{body:`<!doctype html><html><body><script>window.SETTINGS={openai:${JSON.stringify(K.inline)}};</script><script src="/local.js"></script><script src="https://app.example.com/main.js"></script></body></html>`},'/local.js':{type:'text/javascript',body:`const local={apiKey:${JSON.stringify(K.local)}};`},'/.env':{type:'text/plain',body:`OPENAI_API_KEY=${K.env}\n`}},
    'https://app.example.com':{'/main.js':{type:'text/javascript',body:`const client={apiKey:${JSON.stringify(K.app)}};fetch("https://api.example.com/v1/config");\n//# sourceMappingURL=main.js.map`},'/main.js.map':{type:'application/json',body:JSON.stringify({version:3,file:'main.js',sources:['src/server.ts'],sourcesContent:[`export const serverKey=${JSON.stringify(K.map)};`],names:[],mappings:'AAAA'})}},
    'https://api.example.com':{'/v1/config':{type:'application/json',body:JSON.stringify({openai:K.api})}}
  };
  const trip=egressTripwire();try{
    const run=async(traffic:'low-impact'|'normal')=>{const s=new Scanner({urls:[SITE],coverage:'deep',traffic,browser:false,semanticAnalysis:false,sameRegistrableDomainDiscovery:true},{detector:new Detector('disabled'),resolver:publicDns});
      try{virtualNetwork(s,hosts);const v=await s.run();return {v,values:new Set([...s.evidence.findings.values()].map(x=>s.evidence.reveal(x.id).value))};}finally{s.dispose();}};
    const normal=await run('normal'),low=await run('low-impact');
    for(const [name,value] of Object.entries(K)){assert.ok(normal.values.has(value),'Deep + Normal finds '+name);assert.ok(low.values.has(value),'Deep + Low-impact finds '+name);}
    assert.deepEqual([...low.values].sort(),[...normal.values].sort(),'Low-impact keeps Deep + Normal recall');
    const websites=(v:typeof low.v)=>v.origins!.map(o=>o.origin).sort();assert.deepEqual(websites(low.v),websites(normal.v));assert.ok(websites(low.v).includes('https://api.example.com'),'all three websites were admitted and scanned');
    assert.ok(low.v.accounting!.networkAttempts<=normal.v.accounting!.networkAttempts,`requests: low ${low.v.accounting!.networkAttempts} <= normal ${normal.v.accounting!.networkAttempts}`);
    assert.deepEqual(trip.violations,[],'nothing reached the real network');
  }finally{trip.restore();}
});
