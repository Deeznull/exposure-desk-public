import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {mkdtemp,rm,readFile,writeFile,mkdir} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import {makeConfig} from '../src/config.js';
import {ScopePolicy,registrableDomain,scopeSource} from '../src/domain-scope.js';
import {Transport,type Resolver} from '../src/transport.js';
import {Detector,root} from '../src/detectors.js';
import {Evidence} from '../src/evidence.js';
import {Scanner} from '../src/scanner.js';
import {Store,compareScans,WORKSPACE_SCHEMA,type History} from '../src/storage.js';
import {focusedRetry} from '../src/retry.js';
import {workPriority} from '../src/scheduler.js';
import {presets,presetConfig} from '../src/presets.js';
import {report} from '../src/reports.js';
import {startDashboard} from '../src/dashboard.js';
import type {Resource} from '../src/types.js';
const publicDns:Resolver=async()=>[{address:'93.184.216.34',family:4}];
const detector=()=>new Detector('disabled');
async function temp(){const parent=process.env.EXPOSURE_DATA_DIR||path.join(root,'.cache');await mkdir(parent,{recursive:true});return mkdtemp(path.join(parent,'scope-'));}
/** Synthetic transport: real preflight (scope, credentials, DNS admission), no sockets. */
function stubbed(s:Scanner,pages:Record<string,string|{status:number;location:string}>,attempted:string[]){s.transport.one=async(raw,options={})=>{const url=await s.transport.preflight(raw,options.method||'GET',options.headers||{},options.body||'',options.chain),u=new URL(url);attempted.push(url);const entry=pages[u.host+u.pathname]??(u.pathname==='/robots.txt'?'User-agent: *':'{}');const redirect=typeof entry==='object',text=redirect?'':entry,resource:Resource={url,bytes:Buffer.byteLength(text),status:redirect?'redirect':'downloaded',analysis:'pending',code:redirect?entry.status:200,kind:options.kind||'http',chain:options.chain||[]};s.transport.onResource(resource);s.transport.requests++;s.transport.originControl.current!.requests++;const headers:Record<string,string>=redirect?{location:entry.location}:{'content-type':/\.(?:js|json|xml|txt)$/.test(u.pathname)?'application/javascript':'text/html'};return {url,status:redirect?entry.status:200,headers,body:Buffer.from(text),partial:false,chain:options.chain||[],resource};};}
test('domain scope is the default for presets and omitted JSON; explicit opt-outs, conflicts and canonical hosts are enforced',()=>{
  for(const name of Object.keys(presets)){const c=presetConfig(name,{urls:['example.com']});assert.equal(c.domainScope,'registrable-domain',name);assert.equal(c.sameRegistrableDomainDiscovery,true);}
  assert.equal(makeConfig({urls:['example.com'],sameRegistrableDomainDiscovery:false}).domainScope,'exact-origin');
  assert.equal(makeConfig({urls:['example.com'],domainScope:'exact-origin'}).sameRegistrableDomainDiscovery,false);
  assert.equal(makeConfig({urls:['app.example.com'],domainScope:'host-subtree'}).sameRegistrableDomainDiscovery,true);
  assert.throws(()=>makeConfig({urls:['example.com'],domainScope:'exact-origin',sameRegistrableDomainDiscovery:true}),/Conflicting/);
  assert.throws(()=>makeConfig({urls:['example.com'],domainScope:'everything' as any}),/domainScope/);
  assert.throws(()=>makeConfig({urls:['example.com'],sameRegistrableDomainDiscovery:null as any}));
  assert.equal(scopeSource({urls:['example.com']}),'default');assert.equal(scopeSource({urls:['example.com'],sameRegistrableDomainDiscovery:false}),'legacy-flag');assert.equal(scopeSource({urls:['example.com'],domainScope:'exact-origin'}),'explicit');assert.equal(scopeSource({urls:['example.com'],domainScope:'exact-origin',scopeReview:{reason:'legacy-default-exact-origin',from:'2.4'}}),'legacy-saved-default');
  // Approved routes and POST endpoints follow the same policy as discovery.
  assert.ok(makeConfig({urls:['https://example.com'],browserNavigationUrls:['https://app.example.com/#/settings']}).browserNavigationUrls![0].endsWith('#/settings'));
  assert.throws(()=>makeConfig({urls:['https://example.com'],domainScope:'exact-origin',browserNavigationUrls:['https://app.example.com/']}));
  assert.throws(()=>makeConfig({urls:['https://example.com'],browserNavigationUrls:['https://example.com.evil.example/']}));
  assert.throws(()=>makeConfig({urls:['https://example.com'],browserNavigationUrls:['https://notexample.com/']}));
  assert.equal(makeConfig({urls:['https://example.com'],readOnlyPostEndpoints:['https://api.example.com/search']}).readOnlyPostEndpoints.length,1);
  assert.throws(()=>makeConfig({urls:['https://example.com'],readOnlyPostEndpoints:['https://notexample.com/search']}));
  assert.equal(makeConfig({urls:['https://Example.COM./a']}).urls[0],'https://example.com/a');
  for(const bad of ['https://*.example.com/','https://a..example.com/','https://example.com../'])assert.throws(()=>makeConfig({urls:[bad]}),bad);
  assert.equal(makeConfig({urls:['example.com'],domainScope:'registrable-domain',scopeReview:{reason:'legacy-default-exact-origin',from:'2.4'}}).scopeReview,undefined,'adopting domain scope drops the review marker');
  assert.throws(()=>makeConfig({urls:['example.com'],domainScope:'exact-origin',scopeReview:{reason:'other'} as any}));
});
test('one scope policy classifies by punycode registrable domain, never by substring, and previews unsupported or deep seeds',()=>{
  const policy=new ScopePolicy(makeConfig({urls:['https://example.com','https://bücher.de'],relatedOrigins:['https://cdn.example.net']}));
  for(const url of ['https://aaa.example.com/x','https://x.y.aaa.example.com','http://aaa.example.com','https://evil.example.example.com','https://AAA.EXAMPLE.COM./x','https://api.xn--bcher-kva.de','https://API.BÜCHER.de/'])assert.equal(policy.classify(url).class,'in-domain',url);
  assert.equal(policy.classify('https://AAA.EXAMPLE.COM./x').origin,'https://aaa.example.com');
  for(const url of ['https://example.com.evil.example','https://example.co.uk.evil.com','https://notexample.com','https://xn--80ak6aa92e.com','https://cdn.example.net.evil.example'])assert.equal(policy.classify(url).class,'outside',url);
  assert.equal(policy.classify('https://notexample.com').reason,'third-party');assert.equal(policy.classify('https://example.com.evil.example').reason,'no-public-suffix');
  assert.equal(policy.classify('https://example.com').class,'explicit-seed');assert.equal(policy.classify('https://cdn.example.net').class,'explicit-related');assert.equal(policy.classify('https://api.example.net').reason,'third-party','related origins never contribute a domain');
  assert.equal(policy.classify('https://example.com@evil.example/').reason,'userinfo');assert.equal(policy.classify('https://u:p@aaa.example.com/').reason,'userinfo');
  assert.equal(policy.classify('https://93.184.216.34/').reason,'ip-literal');assert.equal(policy.classify('ws://aaa.example.com/').reason,'non-http');
  const tenants=new ScopePolicy(makeConfig({urls:['https://one.github.io']}));assert.equal(tenants.classify('https://one.github.io/x').class,'explicit-seed');assert.equal(tenants.classify('https://two.github.io/').reason,'third-party');assert.equal(tenants.classify('https://foo.s3.amazonaws.com/').reason,'third-party');assert.equal(tenants.classify('https://sub.one.github.io/').class,'in-domain');
  const exact=new ScopePolicy(makeConfig({urls:['https://example.com'],domainScope:'exact-origin'}));assert.equal(exact.classify('https://api.example.com').reason,'exact-origin-mode');assert.equal(exact.classify('https://notexample.com').reason,'third-party');assert.equal(exact.inDomain('https://api.example.com'),true);assert.equal(exact.inDomain('https://notexample.com'),false);
  const subtree=new ScopePolicy(makeConfig({urls:['https://www.app.example.com'],domainScope:'host-subtree'}));assert.equal(subtree.classify('https://api.app.example.com').class,'in-domain');assert.equal(subtree.classify('https://other.example.com').reason,'outside-host-subtree');
  const preview=new ScopePolicy(makeConfig({urls:['https://deep.app.example.com','https://93.184.216.34','http://localhost','https://internal.corp'],relatedOrigins:['https://www.example.com']})).describe('default');
  assert.equal(preview.groups.length,1);assert.deepEqual(preview.groups[0].redundantExplicit,['https://www.example.com']);assert.equal(preview.unsupportedSeeds.length,3);assert.ok(preview.warnings[0].includes('deep.app.example.com'));assert.equal(preview.psl.library,'tldts');assert.ok(preview.summary.includes('example.com'));
  const idn=new ScopePolicy(makeConfig({urls:['https://bücher.de']})).describe('default');assert.equal(idn.groups[0].registrableDomain,'xn--bcher-kva.de');assert.equal(idn.groups[0].unicode,'bücher.de');
  assert.equal(registrableDomain('https://a..example.com'),null);assert.equal(registrableDomain('https://*.example.com'),null);
});
test('export-shaped fixture: a legacy explicit false excludes an owned subdomain as exact-origin-mode; the default admits it with provenance',async()=>{
  const pages={'example.org/':'<a href="https://blog.example.org/">blog</a><script src="https://labs.example.org/app.js"></script><a href="https://www.youtube.example/@channel">yt</a>','labs.example.org/app.js':'const n=1;','blog.example.org/':'<p>blog</p>'};
  for(const legacy of [true,false]){const attempted:string[]=[],dns:string[]=[];const s=new Scanner({urls:['https://example.org/'],relatedOrigins:['https://labs.example.org'],...(legacy?{sameRegistrableDomainDiscovery:false}:{}),semanticAnalysis:false,adjacentMaps:false,maxDurationMs:8000,maxResources:40,requestsPerSecond:20,originRequestsPerSecond:20},{detector:detector(),resolver:async host=>{dns.push(host);return publicDns('');}});stubbed(s,pages,attempted);
    try{const v=await s.run();const group=v.scope!.groups[0];assert.equal(v.scope!.groups.length,1);assert.equal(group.registrableDomain,'example.org');assert.deepEqual(group.explicitOrigins,['https://labs.example.org']);
      if(legacy){assert.equal(v.scope!.mode,'exact-origin');assert.equal(v.scope!.source,'legacy-flag');assert.ok(!attempted.some(u=>u.includes('blog')));assert.ok(!dns.includes('blog.example.org'));assert.equal(group.notAdmitted[0].reason,'exact-origin-mode');assert.ok(group.notAdmitted[0].examples.includes('https://blog.example.org'));assert.equal(v.websites!.count,2);assert.equal(v.scope!.autoAdmitted,0);assert.ok(v.resources.some(r=>r.reason==='scope'&&r.url==='https://blog.example.org/'));assert.equal(v.coverage!.groups.domainExcluded.discovered,1);}
      else{assert.equal(v.scope!.mode,'registrable-domain');assert.equal(v.scope!.source,'default');assert.ok(attempted.includes('https://blog.example.org/'));const auth=v.origins!.find(o=>o.origin==='https://blog.example.org')!.authorization!;assert.equal(auth.type,'same-registrable-domain');if(auth.type==='same-registrable-domain'){assert.equal(auth.discoveredFrom,'https://example.org/');assert.equal(auth.scope,'registrable-domain');}assert.equal(v.origins!.find(o=>o.origin==='https://labs.example.org')!.authorization!.type,'explicit-related');assert.equal(v.scope!.autoAdmitted,1);assert.equal(v.websites!.count,3);assert.deepEqual(group.redundantExplicit,['https://labs.example.org']);assert.ok(group.contactedOrigins.includes('https://blog.example.org'));}
      assert.equal(v.scope!.excluded.thirdPartyOrigins,1);assert.ok(!dns.includes('www.youtube.example'));assert.equal(v.limitations.filter(g=>g.code==='scope').length,1);assert.equal(v.limitations.find(g=>g.code==='scope')!.incomplete,false);
      const html=report(s,'html');assert.ok(html.includes('<h2>Scope</h2>'));assert.ok(html.includes('example.org'));const sarif=JSON.parse(report(s,'sarif'));assert.equal(sarif.runs[0].invocations[0].properties.scope.mode,v.scope!.mode);assert.equal(JSON.parse(report(s,'json')).scope.groups[0].registrableDomain,'example.org','redaction keeps scope keys');
    }finally{s.dispose();}}
});
test('legacy saved projects keep exact-origin with a review marker; old history, checkpoints and retries reproduce the scope that ran',async()=>{
  const dir=await temp();try{
    const legacyConfig={name:'Legacy',urls:['https://example.org/'],relatedOrigins:['https://labs.example.org'],privateOrigins:[],browser:false,deep:false,readOnlyPostEndpoints:[],requestsPerSecond:2,concurrency:2,maxDepth:3,maxPages:30,maxResources:200,maxResourceBytes:1048576,maxTotalBytes:20971520,timeoutMs:10000,maxDurationMs:120000,queryVariants:3,browserPages:5,browserSettleMs:1000,maxMaps:25,maxMapSources:40,deepPaths:['/.env'],adjacentMaps:true,preset:'custom',maxWireResourceBytes:16777216,maxDecodedTotalBytes:167772160,maxMapDepth:4,maxMapSections:50,browserScrollSteps:0,browserScrollDelayMs:500,sameRegistrableDomainDiscovery:false,maxAutoDiscoveredOrigins:50};
    await writeFile(path.join(dir,'workspace.json'),JSON.stringify({schema:'exposure-workspace/2',projects:[{id:'11111111-1111-4111-8111-111111111111',createdAt:'2026-01-01T00:00:00.000Z',authorizedAt:'2026-01-01T00:00:00.000Z',config:legacyConfig},{id:'22222222-2222-4222-8222-222222222222',createdAt:'2026-01-01T00:00:00.000Z',authorizedAt:'2026-01-01T00:00:00.000Z',config:{name:'Opted in',urls:['https://example.org/'],sameRegistrableDomainDiscovery:true}}],reviews:{},settings:{retentionDays:90,maxScans:100,vaultMinutes:5},rules:[],ruleVersions:[]}));
    await mkdir(path.join(dir,'scans'),{recursive:true});await mkdir(path.join(dir,'keys'),{recursive:true});await writeFile(path.join(dir,'keys','11111111-1111-4111-8111-111111111111.key'),Buffer.alloc(32,7),{mode:0o600});
    // A pre-2.4 shaped record: no build, origins, coverage, accounting, scope, analysis or trigger.
    const recent=new Date(Date.now()-86400000).toISOString();
    const legacyView:any={schema:'exposure-scan/1',id:'33333333-3333-4333-8333-333333333333',name:'Old run',state:'completed',startedAt:recent,endedAt:recent,elapsedMs:60000,config:{...legacyConfig,name:'Old run',relatedOrigins:[]},counts:{resources:3,scanned:2,blocked:1,bytes:100,pending:0,findings:0},engines:{websiteRules:'website/2.1.0',gitleaks:'8.30.1',ruleDigest:'',companyRules:'none'},findings:[],resources:[{url:'https://example.org/',status:'scanned',analysis:'analyzed',code:200,bytes:50,chain:[],kind:'page',analyzers:{semantic:{status:'not-attempted'}}},{url:'https://blog.example.org/',status:'blocked',analysis:'skipped',reason:'scope',bytes:0,chain:[],kind:'page'}],limitations:[]};
    await writeFile(path.join(dir,'scans',legacyView.id+'.json'),JSON.stringify({schema:'exposure-history/2',projectId:'11111111-1111-4111-8111-111111111111',view:legacyView,savedAt:recent}));
    const store=await new Store(dir,true).init();
    const legacy=store.projects.find(p=>p.config.name==='Legacy')!,opted=store.projects.find(p=>p.config.name==='Opted in')!;
    assert.equal(legacy.config.domainScope,'exact-origin');assert.equal(legacy.config.sameRegistrableDomainDiscovery,false);assert.equal(legacy.config.scopeReview?.reason,'legacy-default-exact-origin');
    assert.equal(opted.config.domainScope,'registrable-domain');assert.equal(opted.config.scopeReview,undefined);
    await store.save();const saved=JSON.parse(await readFile(path.join(dir,'workspace.json'),'utf8'));assert.equal(saved.schema,WORKSPACE_SCHEMA);assert.equal(saved.projects[0].config.domainScope,'exact-origin');assert.equal(saved.projects[0].config.sameRegistrableDomainDiscovery,false);assert.equal(saved.projects[0].config.scopeReview.reason,'legacy-default-exact-origin');
    const raw=JSON.parse(await readFile(path.join(dir,'scans',legacyView.id+'.json'),'utf8'));assert.equal(raw.view.config.domainScope,undefined,'stored history is never rewritten');assert.equal(raw.view.scope,undefined);
    const h=store.history.find(h=>h.view.id===legacyView.id)!;assert.ok(h);assert.equal(h.view.build,undefined);
    const plan=focusedRetry(h.view);assert.ok(plan.selected.length>=0);const retryScan=new Scanner(h.view.config,{detector:detector(),resolver:publicDns});try{assert.equal(retryScan.transport.scope.mode,'exact-origin');assert.equal(retryScan.scopeSource,'legacy-flag');assert.equal(retryScan.transport.sameDomainSeed('https://blog.example.org/'),undefined);}finally{retryScan.dispose();}
    const resumed=new Scanner(JSON.parse(JSON.stringify({schema:'exposure-checkpoint/1',config:h.view.config,frontier:[{url:'https://example.org/app.js'}]})).config,{detector:detector(),resolver:publicDns});try{assert.equal(resumed.transport.scope.mode,'exact-origin');}finally{resumed.dispose();}
    const current=new Scanner({...h.view.config,domainScope:'exact-origin'},{detector:detector(),resolver:publicDns});current.state='completed';const now:History={schema:'exposure-history/2',projectId:h.projectId,view:current.view(),savedAt:new Date().toISOString()};current.dispose();
    const comparison=compareScans(h,now);assert.ok(!comparison.reasons.some(r=>r.includes('Scope, checks or budgets')),comparison.reasons.join('; '));assert.ok(comparison.reasons.some(r=>r.includes('no recorded build')));assert.ok(comparison.reasons.some(r=>r.includes('lifecycle semantics')));
    const app=await startDashboard({port:0,persistent:true,dataDir:dir,syntheticData:true});try{const login=await fetch(app.origin+'/api/login',{method:'POST',headers:{'Content-Type':'application/json',Origin:app.origin,'X-Dashboard-Request':'1'},body:JSON.stringify({token:app.token})}),cookie=login.headers.get('set-cookie')!.split(';')[0],{csrf}=await login.json() as any,headers={'Content-Type':'application/json',Origin:app.origin,'X-Dashboard-Request':'1','X-CSRF-Token':csrf,Cookie:cookie};
      const list=await(await fetch(app.origin+'/api/scans',{headers:{Cookie:cookie}})).json() as any[];assert.ok(list.some(s=>s.id===legacyView.id&&s.scope===undefined));
      const view=await(await fetch(app.origin+'/api/scans/'+legacyView.id,{headers:{Cookie:cookie}})).json() as any;assert.equal(view.scope,undefined);assert.ok(!JSON.stringify(view).includes('"domainScope"'));
      const ws=await(await fetch(app.origin+'/api/workspace',{headers:{Cookie:cookie}})).json() as any;assert.equal(ws.projects.find((p:any)=>p.config.name==='Legacy').config.scopeReview.reason,'legacy-default-exact-origin');
      const preview=await(await fetch(app.origin+'/api/scope/preview',{method:'POST',headers,body:JSON.stringify({config:{...legacy.config,domainScope:'registrable-domain',sameRegistrableDomainDiscovery:true,scopeReview:undefined}})})).json() as any;assert.equal(preview.groups[0].unicode,'example.org');assert.equal(preview.mode,'registrable-domain');
      const saveResponse=await fetch(app.origin+'/api/projects/save',{method:'POST',headers,body:JSON.stringify({id:legacy.id,config:{...legacy.config,domainScope:'registrable-domain',sameRegistrableDomainDiscovery:true,scopeReview:undefined},authorized:true})}),adopted=await saveResponse.json() as any;assert.equal(saveResponse.status,200,JSON.stringify(adopted));assert.equal(adopted.config.domainScope,'registrable-domain');assert.equal(adopted.config.scopeReview,undefined);
      assert.equal((await fetch(app.origin+'/api/scans',{method:'POST',headers,body:JSON.stringify({config:legacy.config,projectId:legacy.id})})).status,400,'server-side authorization is required to start');
      const exportView=await(await fetch(app.origin+'/api/scans/'+legacyView.id+'/export',{method:'POST',headers,body:JSON.stringify({format:'html'})})).text();assert.ok(exportView.includes('Scope summary not recorded by unknown build'));
    }finally{await app.close();}
    store.close();
  }finally{await rm(dir,{recursive:true,force:true});}
});
test('admitted roots get discovery priority, trailing-dot duplicates share one origin, and admission is detached from the discovering turn',async()=>{
  assert.equal(workPriority({url:'https://api.example.com/',kind:'page'},['https://example.com/'],new Set(['https://api.example.com/'])),1);assert.equal(workPriority({url:'https://api.example.com/other',kind:'page'},['https://example.com/'],new Set(['https://api.example.com/'])),2);assert.equal(workPriority({url:'https://api.example.com/app.js',kind:'script'},['https://example.com/'],new Set(['https://api.example.com/'])),0);
  const t=new Transport(makeConfig({urls:['https://example.com']}),new Evidence(detector()),()=>{},()=>{},publicDns);
  try{await t.preflight('https://n1.example.com/x');await t.preflight('https://N1.example.com./y');await t.preflight('https://n1.example.com:443/z');assert.equal(t.authorizedOrigins.length,2);}finally{t.cancel();}
  let resolved=0;const s=new Scanner({urls:['https://example.com'],semanticAnalysis:false,adjacentMaps:false},{detector:detector(),resolver:async()=>{await new Promise(r=>setTimeout(r,30));resolved++;return publicDns('');}});
  try{const stop=new AbortController();stop.abort('work-turn-limit');s.transport.originControl.run('https://example.com/',()=>{s.enqueue('https://api.example.com/app.js','https://example.com/',0,['https://example.com/'],'script');s.enqueue('https://static.example.com/app.js','https://example.com/',0,['https://example.com/'],'script');},stop.signal);
    for(let i=0;i<300&&!s.transport.isAuthorized('https://static.example.com');i++)await new Promise(r=>setTimeout(r,10));
    assert.ok(s.transport.isAuthorized('https://api.example.com'));assert.ok(s.transport.isAuthorized('https://static.example.com'));assert.equal(resolved,2);assert.ok(!s.resources.some(r=>['work-turn-limit','cancelled','duration-limit'].includes(r.reason||'')),'an expired discovering turn must not fail other subdomains');
    assert.ok(s.queue.some(w=>w.url==='https://api.example.com/'),'admitted roots are queued');
  }finally{s.dispose();}
});
test('third-party exclusions are aggregated and never consume inventory or audit slots; userinfo is a credential block without DNS',()=>{
  let dns=0;const s=new Scanner({urls:['https://example.com'],semanticAnalysis:false,adjacentMaps:false},{detector:detector(),resolver:async()=>{dns++;return publicDns('');}});
  try{for(let i=0;i<7000;i++)s.enqueue('https://third'+(i%600)+'.example.net/asset'+i+'.js','https://example.com/',0,['https://example.com/'],'script');
    s.enqueue('https://example.com/late.js','https://example.com/',0,['https://example.com/'],'script');s.enqueue('https://operator:syntheticPassword123@aaa.example.com/x.js','https://example.com/',0,['https://example.com/'],'script');
    const v=s.view();assert.ok(s.queue.some(w=>w.url==='https://example.com/late.js'),'an in-scope URL after the flood is still queued');
    assert.equal(v.scope!.excluded.references,7000);assert.equal(v.scope!.excluded.thirdPartyOrigins,500);assert.equal(v.scope!.excluded.overflow,1100);assert.equal(v.resources.filter(r=>r.reason==='scope').length,500);assert.equal(v.limitations.filter(g=>g.code==='scope').length,1);assert.equal(v.limitations.find(g=>g.code==='scope')!.count,7000);assert.ok(!v.limitations.some(g=>['inventory-limit','audit-record-limit'].includes(g.code)));
    assert.ok(v.resources.some(r=>r.reason==='credential-in-request'&&r.url.includes('aaa.example.com')));assert.equal(dns,0);
  }finally{s.dispose();}
});
test('CLI --scope selects the policy and prints one scope line',async()=>{
  const dir=await temp();try{
  const run=(args:string[])=>spawnSync(process.execPath,[path.join(root,'dist/src/cli.js'),'scan','--url','http://127.0.0.1:9/','--preset','quick','--output',path.join(dir,'scope-cli-report.json'),...args],{encoding:'utf8',cwd:root,windowsHide:true,timeout:60000});
  const exact=run(['--scope','exact-origin']);assert.ok(exact.stdout.includes('Scope: Exact-origin scope'),exact.stdout+exact.stderr);
  const domain=run(['--scope','domain']);assert.ok(domain.stdout.includes('Scope: Domain scope'),domain.stdout+domain.stderr);
  assert.equal(run(['--scope','everything']).status,2);
  }finally{await rm(dir,{recursive:true,force:true});}
});
