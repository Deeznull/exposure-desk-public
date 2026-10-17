import test from 'node:test';
import assert from 'node:assert/strict';
import {classifyProxyEvent,proxyProvenance,proxyOrigins,hostPortOf,type NetObservation,type ProxyEvent} from '../src/browser-provenance.js';
import {Transport,NON_INCOMPLETE_BLOCKS} from '../src/transport.js';
import {makeConfig} from '../src/config.js';
import {Evidence} from '../src/evidence.js';
import {Detector} from '../src/detectors.js';
import {Scanner} from '../src/scanner.js';
import type {Gap,Resource} from '../src/types.js';
const inScope=(origin:string)=>['https://example.com','https://api.example.com','http://example.com'].includes(origin);
const event=(over:Partial<ProxyEvent>={}):ProxyEvent=>({seq:1,at:5000,method:'CONNECT',authority:'update.googleapis.com:443',phase:'navigation',...over});
test('proxy events are attributed by CDP proof, header evidence or pre-navigation timing; hostnames never decide',()=>{
  assert.equal(classifyProxyEvent(event({phase:'pre-navigation'}),[],inScope).attribution,'background');
  const after=classifyProxyEvent(event(),[],inScope);assert.equal(after.attribution,'unknown');assert.equal(after.evidenceSource,'none');assert.equal(after.targetOrigin,false);
  const worker:NetObservation={at:4500,kind:'worker',event:'websocket',url:'wss://update.googleapis.com/socket',hostPort:'update.googleapis.com:443'};const w=classifyProxyEvent(event(),[worker],inScope);assert.equal(w.attribution,'worker');assert.equal(w.evidenceSource,'cdp-observation');
  const frame:NetObservation={at:4800,kind:'frame',event:'failed',url:'https://update.googleapis.com/x',hostPort:'update.googleapis.com:443',failure:'net::ERR_TUNNEL_CONNECTION_FAILED',frameId:'F2'};assert.equal(classifyProxyEvent(event(),[frame],inScope).attribution,'frame');assert.equal(classifyProxyEvent(event(),[frame],inScope).frameId,'F2');
  const mixed=classifyProxyEvent(event(),[worker,frame],inScope);assert.equal(mixed.attribution,'unknown');assert.deepEqual(mixed.candidates,['worker','frame']);
  assert.equal(classifyProxyEvent(event(),[{...frame,at:500}],inScope).attribution,'unknown','observations outside the window do not count');assert.equal(classifyProxyEvent(event(),[{...frame,failure:'net::ERR_NAME_NOT_RESOLVED'}],inScope).attribution,'unknown','only proxy failures or proxy responses prove routing escape');
  const target=classifyProxyEvent(event({authority:'example.com:443'}),[],inScope);assert.equal(target.attribution,'unknown');assert.equal(target.targetOrigin,true);assert.equal(classifyProxyEvent(event({authority:'example.com:80'}),[],inScope).targetOrigin,true,'a port-80 CONNECT matches an http origin in scope');assert.equal(classifyProxyEvent(event({authority:'api.example.com:443',phase:'pre-navigation'}),[],inScope).attribution,'background','timing decides even for target hosts');
  assert.equal(classifyProxyEvent(event({method:'GET',url:'http://example.com/frame',fetchDest:'iframe'}),[],inScope).attribution,'frame');assert.equal(classifyProxyEvent(event({method:'GET',url:'http://example.com/frame',fetchDest:'iframe'}),[],inScope).evidenceSource,'header-derived');
  assert.deepEqual(proxyOrigins('host.example:8443'),['https://host.example:8443','http://host.example:8443']);assert.deepEqual(proxyOrigins('example.com:443'),['https://example.com']);assert.equal(hostPortOf('https://example.com/x'),'example.com:443');assert.equal(proxyProvenance('example.com:443',{},new Set(['https://example.com'])).targetOrigin,true);
});
test('proven background traffic is one non-incomplete aggregate; unknown and target events stay incomplete with attribution and target origin',()=>{
  assert.ok(NON_INCOMPLETE_BLOCKS.includes('browser-background-denied'));const gaps:Gap[]=[],resources:Resource[]=[],t=new Transport(makeConfig({urls:['https://example.com']}),new Evidence(new Detector('disabled')),r=>resources.push(r),g=>gaps.push(g));
  const unknown=classifyProxyEvent(event({authority:'example.com:443'}),[],inScope);t.recordBlocked('https://example.com','unrouted-browser-traffic',['deny-only proxy',unknown.evidence],'browser-proxy',unknown);
  const gap=gaps.find(g=>g.code==='unrouted-browser-traffic')!;assert.equal(gap.incomplete,true);assert.equal(gap.attribution,'unknown');assert.equal(gap.targetOrigin,true);assert.equal(resources[0].provenance?.connectAuthority,'example.com:443');
  const s=new Scanner({urls:['https://example.com']},{detector:new Detector('disabled')});try{for(let i=0;i<3;i++)s.gap({code:'browser-background-denied',detail:'bg',incomplete:false,count:i+1,examples:['a.example','b.example']});assert.equal(s.limitations.filter(g=>g.code==='browser-background-denied').length,1);assert.equal(s.limitations.find(g=>g.code==='browser-background-denied')!.count,3);const v=s.view();assert.equal(v.limitations[0].examples!.length,2);}finally{s.dispose();}
  t.cancel();
});
test('redaction keeps provenance, scope, analysis and discovery keys and the new control codes',()=>{
  const e=new Evidence(new Detector('disabled'));try{const v=e.redact({provenance:{channel:'deny-proxy',attribution:'background',evidenceSource:'pre-navigation',phase:'pre-navigation',connectAuthority:'x.example:443',targetOrigin:false,evidence:'e'},gap:{code:'browser-background-denied',cause:{kind:'analysis-turn-limit',phase:'engine-queue',analyzer:'text'}},scope:{mode:'host-subtree',source:'legacy-saved-default',groups:[{registrableDomain:'example.com',notAdmitted:[{reason:'exact-origin-mode',count:1}]}]},analysis:{backlog:{resumed:1}},discovery:{rejected:{bareExtension:2}},resource:{fallback:{type:'spa-fallback',expected:'script'},certainty:'heuristic',analysis:'deferred'}});
    assert.equal(v.provenance.attribution,'background');assert.equal(v.provenance.evidenceSource,'pre-navigation');assert.equal(v.gap.code,'browser-background-denied');assert.equal(v.gap.cause.kind,'analysis-turn-limit');assert.equal(v.scope.mode,'host-subtree');assert.equal(v.scope.source,'legacy-saved-default');assert.equal(v.scope.groups[0].notAdmitted[0].reason,'exact-origin-mode');assert.equal(v.analysis.backlog.resumed,1);assert.equal(v.discovery.rejected.bareExtension,2);assert.equal(v.resource.fallback.type,'spa-fallback');assert.equal(v.resource.certainty,'heuristic');assert.equal(v.resource.analysis,'deferred');}finally{e.clear();}
});
