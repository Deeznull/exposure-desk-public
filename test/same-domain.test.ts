import test from 'node:test';
import assert from 'node:assert/strict';
import {makeConfig} from '../src/config.js';
import {registrableDomain,ScopePolicy,TENANT_SUFFIXES} from '../src/domain-scope.js';
import {Transport,PolicyError,type Resolver} from '../src/transport.js';
import {Detector} from '../src/detectors.js';
import {Evidence} from '../src/evidence.js';
import {Scanner} from '../src/scanner.js';
import {references} from '../src/discovery.js';
import type {Resource,Gap,ScanConfig} from '../src/types.js';
const publicDns:Resolver=async()=>[{address:'93.184.216.34',family:4}];
function harness(seed='https://example.com',extra:Partial<ScanConfig>={},resolver=publicDns){
  const resources:Resource[]=[],gaps:Gap[]=[],evidence=new Evidence(new Detector('disabled'));
  const t=new Transport(makeConfig({urls:[seed],sameRegistrableDomainDiscovery:true,...extra}),evidence,r=>resources.push(r),g=>gaps.push(g),resolver);
  return {t,resources,gaps,close:()=>{t.cancel();evidence.clear();}};
}
test('registrable-domain scope is the default; explicit false still means exact-origin; the cap stays validated',()=>{
  const c=makeConfig({urls:['example.com']});assert.equal(c.domainScope,'registrable-domain');assert.equal(c.sameRegistrableDomainDiscovery,true);assert.equal(c.maxAutoDiscoveredOrigins,50);
  const exact=makeConfig({urls:['example.com'],sameRegistrableDomainDiscovery:false});assert.equal(exact.domainScope,'exact-origin');assert.equal(exact.sameRegistrableDomainDiscovery,false);
  for(const value of [-1,51,1.5,NaN,Infinity,null])assert.throws(()=>makeConfig({urls:c.urls,maxAutoDiscoveredOrigins:value as number}));
  assert.throws(()=>makeConfig({urls:c.urls,sameRegistrableDomainDiscovery:'true' as any}));
  assert.throws(()=>makeConfig({urls:c.urls,domainScope:'registrable-domain',sameRegistrableDomainDiscovery:false}),/Conflicting/);
});
test('PSL registrable domains handle multi-label suffixes, IDN, private tenants and non-domain hosts',()=>{
  for(const suffix of ['com','co.uk','com.au','co.jp'])assert.equal(registrableDomain('https://api.example.'+suffix),'example.'+suffix);
  assert.equal(registrableDomain('https://API.BÜCHER.de'),'xn--bcher-kva.de');
  assert.equal(registrableDomain('https://one.github.io'),'one.github.io');
  for(const url of ['http://localhost','http://api.localhost','http://127.0.0.1','http://[::1]','http://169.254.169.254','http://metadata.google.internal','ws://example.com','https://co.uk'])assert.equal(registrableDomain(url),null);
});
// External review F-03: a deep seed on a shared-hosting provider missing from the bundled PSL once made the whole provider domain one scope group.
test('supplemental tenant boundaries split shared-hosting customers, never widen a scope and are recorded with the PSL version',()=>{
  for(const [url,domain] of [['https://foo.wpengine.com','foo.wpengine.com'],['https://www.foo.wpengine.com','foo.wpengine.com'],['https://wpengine.com',null],['https://acme.us.auth0.com','acme.us.auth0.com'],['https://acme.auth0.com','acme.auth0.com'],
    ['https://vm.eastus.cloudapp.azure.com','vm.eastus.cloudapp.azure.com'],['https://eastus.cloudapp.azure.com',null],['https://notwpengine.com','notwpengine.com'],['https://wpengine.com.evil.com','evil.com'],['https://one.github.io','one.github.io'],['https://api.example.com','example.com']] as const)assert.equal(registrableDomain(url),domain,url);
  // Every entry is a boundary the bundled PSL lacks, so each one only narrows: the host directly beneath it is its own registrable domain.
  assert.equal(new Set(TENANT_SUFFIXES).size,TENANT_SUFFIXES.length);for(const s of TENANT_SUFFIXES){const host='zz-tenant.'+s.replace(/^\*\./,'region.');assert.equal(registrableDomain('https://'+host),host,s);}
  const policy=new ScopePolicy(makeConfig({urls:['https://foo.wpengine.com']})),view=policy.describe();assert.equal(policy.classify('https://other.wpengine.com/').reason,'third-party');assert.equal(policy.classify('https://cdn.foo.wpengine.com/').class,'in-domain');
  assert.deepEqual(view.unsupportedSeeds,[]);assert.equal(view.warnings.length,0,'the seed is its own registrable domain, so no deep-seed warning');assert.equal(view.psl.tenantSuffixes,TENANT_SUFFIXES.length);
  assert.equal(new ScopePolicy(makeConfig({urls:['https://wordpress.com']})).describe().unsupportedSeeds[0]?.reason,'shared-hosting tenant suffix has no registrable domain of its own');
});
// Adopted from the external review's passing adversarial cases (rewritten): confusable suffixes, a doubled trailing dot, per-port origins and encoded credential names.
test('confusable suffixes stay third-party, a doubled trailing dot is noncanonical, ports stay separate origins and credential names fail before DNS',async()=>{
  const idn=new ScopePolicy(makeConfig({urls:['https://BÜCHER.de']}));assert.equal(idn.classify('https://xn--bcher-kva.de./app').class,'explicit-seed');
  for(const raw of ['https://xn--bcher-kva.de.evil.test/app','https://notxn--bcher-kva.de/app','https://bücher.de.attacker.com/app'])assert.notEqual(idn.classify(raw).class,'in-domain',raw);
  const uk=new ScopePolicy(makeConfig({urls:['https://example.co.uk']}));assert.equal(uk.classify('https://api.example.co.uk.').class,'in-domain');assert.equal(uk.classify('https://api.example.co.uk../').reason,'noncanonical-host');
  let dns=0;const h=harness('https://example.com',{},async()=>{dns++;return [{address:'93.184.216.34',family:4}];});
  try{await h.t.preflight('https://API.example.com.:8443/a');await h.t.preflight('https://api.example.com:9443/b');assert.ok(h.t.isAuthorized('https://api.example.com:8443')&&h.t.isAuthorized('https://api.example.com:9443'));assert.equal(h.t.isAuthorized('https://api.example.com'),false,'each port is its own origin');
    const before=dns;for(const url of ['https://user:synthetic123@other.example.com/x','https://api.example.com/?%61ccess_token=synthetic_not_a_credential'])await assert.rejects(h.t.preflight(url),(e:PolicyError)=>e.code==='credential-in-request',url);assert.equal(dns,before,'credential screening happens before DNS');
  }finally{h.close();}
});
test('only the registrable domains of explicit seeds authorize discovery',async()=>{
  for(const [seed,target,allowed] of [
    ['example.com','api.example.com',true],['example.com','foo.bar.example.com',true],
    ['example.com','example.com.evil.test',false],['example.com','notexample.com',false],
    ['example.co.uk','api.example.co.uk',true],['example.co.uk','other.co.uk',false],
    ['example.com.au','api.example.com.au',true],['example.co.jp','api.example.co.jp',true],
    ['example.com','stripe.com',false],['example.com','cdn.thirdparty.com',false],
    ['one.github.io','two.github.io',false],['bücher.de','api.xn--bcher-kva.de',true],
    // External review F-03: tenants of a provider the bundled PSL lacks stay apart (supplemental boundaries); the customer's own subtree is unaffected.
    ['foo.wpengine.com','other.wpengine.com',false],['foo.wpengine.com','cdn.foo.wpengine.com',true],['acme.us.auth0.com','other.us.auth0.com',false]
  ] as const){const h=harness('https://'+seed);try{const promise=h.t.preflight('https://'+target+'/config', 'GET',{},'',[], 'https://'+seed+'/app.js');if(allowed){await promise;assert.equal(h.t.authorizations.get('https://'+target)?.type,'same-registrable-domain');}else{await assert.rejects(promise,(e:PolicyError)=>e.code==='scope');assert.equal(h.t.isAuthorized('https://'+target),false);}}finally{h.close();}}
  const h=harness('https://example.com',{relatedOrigins:['https://approved.org']});try{await assert.rejects(h.t.preflight('https://api.approved.org'),/scope/);}finally{h.close();}
  const disabled=harness('https://example.com',{sameRegistrableDomainDiscovery:false});try{await assert.rejects(disabled.t.preflight('https://api.example.com'),/scope/);}finally{disabled.close();}
  const unrelated=harness();try{await assert.rejects(unrelated.t.preflight('https://stripe.com/delete','POST'),/scope/);}finally{unrelated.close();}
});
test('50-origin cap is atomic, duplicates do not consume it, and unscanned origins remain visible',async()=>{
  const h=harness();try{
    await Promise.all(Array.from({length:60},(_,i)=>h.t.preflight('https://n'+i+'.example.com/app.js').catch(e=>{assert.equal(e.code,'auto-origin-limit');})));
    assert.equal([...h.t.authorizations.values()].filter(a=>a.type==='same-registrable-domain').length,50);
    const first=h.t.authorizedOrigins.find(o=>o.includes('n'))!;await Promise.all(Array.from({length:20},()=>h.t.preflight(first+'/duplicate')));
    assert.equal(h.t.authorizedOrigins.length,51);
    const gap=h.gaps.filter(g=>g.code==='auto-origin-limit').at(-1)!;assert.equal(gap.count,10);assert.equal(gap.incomplete,true);assert.equal(gap.examples!.length,10);
    assert.ok(gap.examples!.every(o=>!h.t.isAuthorized(o)));
  }finally{h.close();}
});
test('HTTP, HTTPS and ports are distinct budgeted origins; normalized duplicates share authorization',async()=>{
  const h=harness();try{
    for(const url of ['https://api.example.com:443/a','https://API.example.com/b','http://api.example.com:80/a','https://api.example.com:8443/a'])await h.t.preflight(url);
    assert.equal(h.t.authorizedOrigins.length,4);
    for(const origin of h.t.authorizedOrigins){const state=h.t.originControl.get(origin);assert.equal(state.requests,0);assert.equal(state.started,undefined);assert.equal(h.t.originControl.remainingMs(origin),h.t.config.originMaxDurationMs);}
  }finally{h.close();}
});
test('credentials, dashboard ports, methods and destructive URLs fail before automatic admission',async()=>{
  let dns=0;const h=harness('https://example.com',{},async()=>{dns++;return publicDns('');});h.t.deniedPorts.add(4317);
  try{for(const [url,method,headers,code] of [
    ['https://api.example.com/?access_token=secret','GET',{},'credential-in-request'],
    ['https://user:password@api.example.com/','GET',{},'credential-in-request'],
    ['https://api.example.com','GET',{Authorization:'Bearer opaque'},'credential-in-request'],
    ['https://api.example.com:4317/','GET',{},'dashboard-isolation'],
    ['https://api.example.com/delete','GET',{},'destructive-get'],
    ['https://api.example.com','POST',{},'method'],['ws://api.example.com','GET',{},'invalid-url']
  ] as const)await assert.rejects(h.t.preflight(url,method,headers),(e:PolicyError)=>e.code===code);
    assert.equal(dns,0);assert.equal(h.t.authorizedOrigins.length,1);
  }finally{h.close();}
});
test('automatic admission never permits private, mixed DNS or metadata addresses, even with private exceptions',async()=>{
  for(const address of ['127.0.0.1','10.0.0.1','192.168.0.1','::1','fd00::1','169.254.169.254','100.100.100.200','fd00:ec2::254']){
    const h=harness('https://example.com',{privateOrigins:['https://api.example.com']},async()=>[{address,family:address.includes(':')?6:4}]);try{await assert.rejects(h.t.preflight('https://api.example.com'),(e:PolicyError)=>['private-address','metadata'].includes(e.code));assert.equal(h.t.authorizedOrigins.length,1);}finally{h.close();}
  }
  const h=harness('https://example.com',{},async()=>[{address:'93.184.216.34',family:4},{address:'10.0.0.1',family:4}]);try{await assert.rejects(h.t.preflight('https://api.example.com'),/private-address/);}finally{h.close();}
  for(const seed of ['http://localhost','http://127.0.0.1','http://metadata.google.internal']){const h=harness(seed);try{await assert.rejects(h.t.preflight('http://api.localhost'),/scope/);}finally{h.close();}}
});
test('DNS rebinding is rechecked after admission and cannot inherit a private-origin exception',async()=>{
  let address='93.184.216.34';const h=harness('https://example.com',{privateOrigins:['https://api.example.com']},async()=>[{address,family:4}]);try{await h.t.preflight('https://api.example.com');address='10.0.0.1';await assert.rejects(h.t.addresses('https://api.example.com'),/private-address/);}finally{h.close();}
});
test('redirect from an authorized seed does not authorize an unrelated destination',async()=>{
  const h=harness();const seen:string[]=[];
  h.t.one=async(url,options={})=>{await h.t.preflight(url,'GET',{},'',options.chain);seen.push(url);return {url,status:302,headers:{location:'https://unrelated.com/'},body:Buffer.alloc(0),partial:false,chain:[]};};
  try{await assert.rejects(h.t.get('https://example.com/'),/scope/);assert.deepEqual(seen,['https://example.com/']);assert.equal(h.t.isAuthorized('https://unrelated.com'),false);}finally{h.close();}
});
test('all structured discovery channels surface origins without file-extension requirements',()=>{
  for(const [kind,text] of [
    ['page','<script src="https://api.example.com/script"></script><link href="https://css.example.com/style" rel="stylesheet">'],
    ['source','import "https://static.example.com/module"; import("https://dynamic.example.com/module"); fetch("https://api.example.com/v1"); new WebSocket("wss://socket.example.com/events"); navigator.serviceWorker.register("https://worker.example.com/sw"); const config=`https://config.example.com`;'],
    ['css','@import "https://css.example.com/styles"; a{background:url(https://assets.example.com/image)}'],
    ['manifest','{"apiBase":"https://api.example.com","config":"https://config.example.com/config"}'],
    ['framework-data','0:{"endpoint":"https:\\/\\/rsc.example.com\\/api"}']
  ]){const refs=references(text,'https://example.com/app.js',kind);assert.ok(refs.length>0,kind);for(const ref of refs)assert.match(ref.raw,/^(?:https?|wss?):/);}
  const script=references('self.__next_f.push([1,'+JSON.stringify('0:{"api":"https://rsc.example.com/v1"}')+']);','https://example.com/app.js','source');assert.ok(script.some(r=>r.raw==='https://rsc.example.com/v1'));const runtime=references(JSON.stringify({RuntimeConfig:JSON.stringify({api:'https://runtime.example.com/v1'})}),'https://example.com/','framework-data');assert.ok(runtime.some(r=>r.raw==='https://runtime.example.com/v1'));
});
test('recursive scanner admission drains asynchronous discovery and exposes provenance and coverage',async()=>{
  const s=new Scanner({urls:['https://example.com'],sameRegistrableDomainDiscovery:true,semanticAnalysis:false,adjacentMaps:false,maxResources:80,maxDurationMs:5000},{detector:new Detector('disabled'),resolver:publicDns});
  const attempted:string[]=[];
  s.transport.one=async(raw,options={})=>{
    const url=await s.transport.preflight(raw,'GET',{},'',options.chain),u=new URL(url);attempted.push(url);
    assert.equal(s.transport.originControl.current?.origin,u.origin);
    const text=u.pathname==='/robots.txt'?'User-agent: *':u.hostname==='example.com'&&u.pathname==='/'?'<script src="https://api.example.com/app.js"></script>':u.hostname==='api.example.com'&&u.pathname==='/app.js'?'fetch("https://static.example.com/config");fetch("https://stripe.com/api");new WebSocket("wss://socket.example.com/events");new WebSocket("wss://unsafe.example.com/events?access_token=private");':'{}';
    const resource:Resource={url,bytes:Buffer.byteLength(text),status:'downloaded',analysis:'pending',code:200,kind:options.kind||'http',chain:options.chain||[]};s.transport.onResource(resource);s.transport.requests++;s.transport.originControl.current!.requests++;
    return {url,status:200,headers:{'content-type':u.pathname==='/'?'text/html':'application/javascript'},body:Buffer.from(text),partial:false,chain:options.chain||[],resource};
  };
  try{const view=await s.run();assert.ok(attempted.includes('https://static.example.com/config'));assert.ok(!attempted.some(u=>u.includes('stripe.com')));assert.equal(view.origins!.length,4);assert.equal(view.config.relatedOrigins.length,0);assert.ok(attempted.includes('https://socket.example.com/'));assert.ok(!attempted.some(u=>u.includes('/events')||u.includes('unsafe.example.com')||u.startsWith('ws')));assert.ok(view.resources.some(r=>r.reason==='websocket-disabled'));assert.ok(view.resources.some(r=>r.reason==='credential-in-request'&&r.url.includes('unsafe.example.com')));
    const auth=view.origins!.find(o=>o.origin==='https://static.example.com')!.authorization!;assert.equal(auth.type,'same-registrable-domain');if(auth.type==='same-registrable-domain'){assert.equal(auth.seed,'https://example.com/');assert.equal(auth.discoveredFrom,'https://api.example.com/app.js');}
    assert.ok(view.coverage!.origins['https://static.example.com']);assert.ok(view.origins!.every(o=>o.requests>0));
  }finally{s.dispose();}
});
test('scanner cap retains deferred examples and source-map discovery admits safe same-domain origins',async()=>{
  const s=new Scanner({urls:['https://example.com'],sameRegistrableDomainDiscovery:true,maxAutoDiscoveredOrigins:1,semanticAnalysis:false,adjacentMaps:false},{detector:new Detector('disabled'),resolver:publicDns});
  try{
    await s.map(JSON.stringify({version:3,sources:['https://api.example.com/source.js'],mappings:''}),'https://example.com/app.js.map',[]);
    s.enqueue('https://static.example.com/app.js','https://example.com/app.js',0,[],'script');
    // Admission is asynchronous while normal scan work continues.
    for(let i=0;i<100&&!s.view().limitations.some(g=>g.code==='auto-origin-limit');i++)await new Promise<void>(r=>setImmediate(r));
    const view=s.view();assert.ok(s.transport.isAuthorized('https://api.example.com'));assert.equal(s.transport.isAuthorized('https://static.example.com'),false);
    assert.ok(view.limitations.some(g=>g.code==='auto-origin-limit'&&g.incomplete&&g.examples?.includes('https://static.example.com')));assert.ok(view.uninspected!.some(w=>w.url==='https://static.example.com/app.js'&&w.deferredReason==='auto-origin-limit'));
  }finally{s.dispose();}
});
test('HTML base URLs and extracted source labels do not replace the resource that granted authorization',async()=>{
  const s=new Scanner({urls:['https://example.com'],sameRegistrableDomainDiscovery:true,semanticAnalysis:false,adjacentMaps:false},{detector:new Detector('disabled'),resolver:publicDns});
  try{
    await s.discover('<base href="https://api.example.com/assets/"><script src="app.js"></script>','https://example.com/index.html',0,[],'page');
    await s.map(JSON.stringify({version:3,sources:['https://unfetched.example.com/source.js'],sourcesContent:['fetch("https://static.example.com/config")'],mappings:''}),'https://example.com/app.js.map',[]);
    for(let i=0;i<100&&!s.transport.isAuthorized('https://static.example.com');i++)await new Promise<void>(r=>setImmediate(r));
    const api=s.transport.authorizations.get('https://api.example.com')!,staticAuth=s.transport.authorizations.get('https://static.example.com')!;
    assert.equal(api.type,'same-registrable-domain');assert.equal(staticAuth.type,'same-registrable-domain');
    if(api.type==='same-registrable-domain')assert.equal(api.discoveredFrom,'https://example.com/index.html');
    if(staticAuth.type==='same-registrable-domain')assert.equal(staticAuth.discoveredFrom,'https://example.com/app.js.map');
  }finally{s.dispose();}
});
