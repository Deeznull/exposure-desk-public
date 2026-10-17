import test from 'node:test';
import assert from 'node:assert/strict';
import {classifyProxyEvent,chromeServiceHost,backgroundDetail,CHROME_SERVICE_HOSTS,type NetObservation,type ProxyEvent} from '../src/browser-provenance.js';
import {Transport,NON_INCOMPLETE_BLOCKS} from '../src/transport.js';
import {makeConfig} from '../src/config.js';
import {Evidence} from '../src/evidence.js';
import {Detector} from '../src/detectors.js';
import {Scanner} from '../src/scanner.js';
import type {Gap,Resource} from '../src/types.js';
// Chrome's own service connections (w3-chrome): a fixed list of Chrome-internal hosts, counted as denied, informational background traffic
// only when complete CDP observation shows that no page, frame or worker touched them. Everything else keeps the earlier accounting.
const inScope=(origin:string)=>['https://example.com','http://example.com'].includes(origin);
const event=(over:Partial<ProxyEvent>={}):ProxyEvent=>({seq:1,at:10000,method:'CONNECT',authority:'accounts.google.com:443',phase:'settle',...over});
const observed={cdpObserved:true};
test('the Chrome service host list is fixed and documented: the four hosts the bundled Chrome contacts by itself, exact names, CONNECT to 443 only',()=>{
  assert.deepEqual([...CHROME_SERVICE_HOSTS.keys()].sort(),['accounts.google.com','android.clients.google.com','update.googleapis.com','www.google.com']);
  for(const [host,service] of CHROME_SERVICE_HOSTS){assert.ok(service.length>10,'each host names its Chrome service');assert.equal(chromeServiceHost({method:'CONNECT',authority:host+':443'}),host);assert.equal(chromeServiceHost({method:'CONNECT',authority:host.toUpperCase()+':443'}),host,'host names compare case-insensitively');}
  for(const authority of ['accounts.google.com:8443','accounts.google.com:80','xaccounts.google.com:443','accounts.google.com.attacker.example:443','accounts.google.com.:443','clients2.google.com:443','google.com:443','sub.www.google.com:443','127.0.0.1:443','[::1]:443'])assert.equal(chromeServiceHost({method:'CONNECT',authority}),undefined,authority);
  assert.equal(chromeServiceHost({method:'GET',authority:'www.google.com:80',url:'http://www.google.com/x'}),undefined,'plain-HTTP proxy requests never use the list');
});
test('a no-initiator CONNECT to a listed host after navigation is browser background: denied, informational, with its own evidence source',()=>{
  for(const host of CHROME_SERVICE_HOSTS.keys())for(const phase of ['navigation','settle','scroll','snapshot','unload','cleanup']){
    const p=classifyProxyEvent(event({authority:host+':443',phase}),[],inScope,observed);
    assert.equal(p.attribution,'background',host+' '+phase);assert.equal(p.evidenceSource,'chrome-service-host');assert.equal(p.phase,phase);assert.equal(p.channel,'deny-proxy');assert.equal(p.targetOrigin,false);assert.equal(p.connectAuthority,host+':443');
    assert.match(p.evidence,new RegExp(host.replace(/\./g,'\\.')));assert.match(p.evidence,/Denied at the proxy and never forwarded/);}
  // Unrelated observations (other hosts, or this host outside the window) do not block the rule.
  const other:NetObservation={at:9990,kind:'page',event:'request',url:'https://example.com/app.js',hostPort:'example.com:443'};const old:NetObservation={at:2000,kind:'page',event:'failed',url:'https://accounts.google.com/x',hostPort:'accounts.google.com:443',failure:'net::ERR_TUNNEL_CONNECTION_FAILED'};
  assert.equal(classifyProxyEvent(event(),[other,old],inScope,observed).attribution,'background');
  // Pre-navigation timing still decides first and keeps its own evidence source, listed or not.
  assert.equal(classifyProxyEvent(event({phase:'pre-navigation'}),[],inScope,observed).evidenceSource,'pre-navigation');assert.equal(classifyProxyEvent(event({phase:'pre-navigation',authority:'unlisted.example.net:443'}),[],inScope).attribution,'background');
});
test('a request that a page, frame or worker made to a listed host keeps the earlier attribution and accounting',()=>{
  const failed:NetObservation={at:9980,kind:'page',event:'failed',url:'https://www.google.com/x',hostPort:'www.google.com:443',failure:'net::ERR_TUNNEL_CONNECTION_FAILED',initiator:'https://example.com/app.js'};
  const page=classifyProxyEvent(event({authority:'www.google.com:443'}),[failed],inScope,observed);assert.equal(page.attribution,'page');assert.equal(page.evidenceSource,'cdp-observation');assert.equal(page.initiator,'https://example.com/app.js');
  const ws:NetObservation={at:9900,kind:'worker',event:'websocket',url:'wss://update.googleapis.com/s',hostPort:'update.googleapis.com:443'};assert.equal(classifyProxyEvent(event({authority:'update.googleapis.com:443'}),[ws],inScope,observed).attribution,'worker');
  const frame:NetObservation={...failed,kind:'frame',frameId:'F9',at:10500};assert.equal(classifyProxyEvent(event({authority:'www.google.com:443'}),[frame],inScope,observed).attribution,'frame','an observation up to 1 s after the CONNECT still claims it');
  // Any observation of the host in the window, even a routed request without proxy proof, keeps the connection unknown and incomplete.
  for(const o of [{at:9000,kind:'page',event:'request'},{at:10900,kind:'frame',event:'response'},{at:7001,kind:'worker',event:'failed',failure:'net::ERR_NAME_NOT_RESOLVED'}] as const){
    const p=classifyProxyEvent(event({authority:'www.google.com:443'}),[{...o,url:'https://www.google.com/x',hostPort:'www.google.com:443'}],inScope,observed);assert.equal(p.attribution,'unknown',JSON.stringify(o));assert.equal(p.evidenceSource,'none');}
  // Accounting through the transport is unchanged: an escaped page request is an incomplete unrouted gap with its attribution.
  const gaps:Gap[]=[],resources:Resource[]=[],t=new Transport(makeConfig({urls:['https://example.com']}),new Evidence(new Detector('disabled')),r=>resources.push(r),g=>gaps.push(g));
  try{t.recordBlocked('https://www.google.com','unrouted-browser-traffic',['deny-only proxy',page.evidence],'browser-proxy',page);const g=gaps.find(x=>x.code==='unrouted-browser-traffic')!;assert.equal(g.incomplete,true);assert.equal(g.attribution,'page');assert.equal(resources[0].provenance?.evidenceSource,'cdp-observation');}finally{t.cancel();}
});
test('unlisted, target-origin, uncovered or plain-HTTP unattributed traffic still makes the scan incomplete',()=>{
  for(const authority of ['telemetry.example.net:443','clients2.google.com:443','accounts.google.com:8443','www.google.com.example.net:443']){const p=classifyProxyEvent(event({authority}),[],inScope,observed);assert.equal(p.attribution,'unknown',authority);assert.equal(p.evidenceSource,'none');}
  assert.equal(classifyProxyEvent(event({method:'GET',authority:'www.google.com:80',url:'http://www.google.com/x'}),[],inScope,observed).attribution,'unknown','plain HTTP never uses the list');
  const target=classifyProxyEvent(event({authority:'www.google.com:443'}),[],(o:string)=>o==='https://www.google.com',observed);assert.equal(target.attribution,'unknown','an authorized target origin is never background after navigation');assert.equal(target.targetOrigin,true);
  // Without complete CDP observation the list never applies: no coverage given, observation unavailable, or a truncated record that no longer reaches back past the window.
  assert.equal(classifyProxyEvent(event(),[],inScope).attribution,'unknown','coverage defaults to none');assert.equal(classifyProxyEvent(event(),[],inScope,{cdpObserved:false}).attribution,'unknown');
  const recent:NetObservation={at:8000,kind:'page',event:'request',url:'https://example.com/a',hostPort:'example.com:443'},older:NetObservation={...recent,at:6900};
  assert.equal(classifyProxyEvent(event(),[recent],inScope,{cdpObserved:true,truncated:true}).attribution,'unknown','dropped observations may have named this host');assert.equal(classifyProxyEvent(event(),[],inScope,{cdpObserved:true,truncated:true}).attribution,'unknown');
  assert.equal(classifyProxyEvent(event(),[older,recent],inScope,{cdpObserved:true,truncated:true}).attribution,'background','a truncated record that still covers the whole window is complete');
  const gaps:Gap[]=[],t=new Transport(makeConfig({urls:['https://example.com']}),new Evidence(new Detector('disabled')),()=>{},g=>gaps.push(g));
  try{const p=classifyProxyEvent(event({authority:'telemetry.example.net:443'}),[],inScope,observed);t.recordBlocked('https://telemetry.example.net','unrouted-browser-traffic',['deny-only proxy',p.evidence],'browser-proxy',p);const g=gaps.find(x=>x.code==='unrouted-browser-traffic')!;assert.equal(g.incomplete,true);assert.equal(g.attribution,'unknown');assert.ok(!NON_INCOMPLETE_BLOCKS.includes('unrouted-browser-traffic'));}finally{t.cancel();}
});
test('the background gap stays one informational aggregate with an honest breakdown, and redaction keeps the new evidence source',()=>{
  assert.ok(NON_INCOMPLETE_BLOCKS.includes('browser-background-denied'));
  const both=backgroundDetail({count:5,preNavigation:2,service:3});assert.match(both,/^5 browser background connections were denied at the proxy and never forwarded: 2 observed before any target document was requested; 3 from Chrome's own services/);assert.match(both,/do not make the scan incomplete/);assert.match(both,/any other unattributed connection keeps the scan incomplete/);
  assert.match(backgroundDetail({count:1,preNavigation:0,service:1}),/^1 browser background connection was denied at the proxy and never forwarded: 1 from Chrome's own services/);assert.doesNotMatch(backgroundDetail({count:1,preNavigation:1,service:0}),/Chrome's own services/);
  const s=new Scanner({urls:['https://example.com']},{detector:new Detector('disabled')});try{for(let i=1;i<=3;i++)s.gap({code:'browser-background-denied',detail:backgroundDetail({count:i,preNavigation:1,service:i-1}),incomplete:false,count:i,examples:['accounts.google.com']});const g=s.limitations.filter(x=>x.code==='browser-background-denied');assert.equal(g.length,1);assert.equal(g[0].incomplete,false);assert.equal(g[0].count,3);}finally{s.dispose();}
  const e=new Evidence(new Detector('disabled'));try{const v=e.redact({provenance:{channel:'deny-proxy',attribution:'background',evidenceSource:'chrome-service-host',phase:'settle',connectAuthority:'accounts.google.com:443',targetOrigin:false,evidence:'e'}});assert.equal(v.provenance.attribution,'background');assert.equal(v.provenance.evidenceSource,'chrome-service-host');assert.equal(v.provenance.phase,'settle');}finally{e.clear();}
});
