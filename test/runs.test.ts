import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import path from 'node:path';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { makeConfig } from '../src/config.js';
import { scopeCounts, runSummary, defaultProjectName, RequestLedger, SafeError, scopeCountLine, LEGACY_DEFAULT_NAME } from '../src/runs.js';
import { Store } from '../src/storage.js';
import { Desk } from '../src/desk.js';
import { startDashboard } from '../src/dashboard.js';
import { root } from '../src/detectors.js';
import { synthetic } from '../src/fixture.js';
import type { ScanView } from '../src/types.js';
const pause=(ms:number)=>new Promise(r=>setTimeout(r,ms));
async function temp(){const parent=process.env.EXPOSURE_DATA_DIR||path.join(root,'.cache');await mkdir(parent,{recursive:true});return mkdtemp(path.join(parent,'runs-'));}
/** Loopback target whose seed answers slowly, so a run stays active long enough to test overlapping starts. Arrivals are counted per path. */
async function slowSite(delayMs=1500){const arrivals:string[]=[];const server=http.createServer((req,res)=>{arrivals.push(req.url||'');if(req.url==='/slow')setTimeout(()=>{res.writeHead(200,{'content-type':'text/html'});res.end('<html><body>slow synthetic page</body></html>');},delayMs);else{res.writeHead(404);res.end();}});await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));const origin=`http://127.0.0.1:${(server.address() as any).port}`;return {origin,arrivals,close:()=>new Promise<void>(r=>{server.close(()=>r());server.closeAllConnections();})};}
const view=(over:Partial<ScanView>):ScanView=>({schema:'exposure-scan/1',id:randomUUID(),name:'x',state:'completed',elapsedMs:0,config:makeConfig({urls:['https://example.com/']}),counts:{resources:0,scanned:0,blocked:0,bytes:0,pending:0,findings:0},engines:{websiteRules:'',gitleaks:'',ruleDigest:'',companyRules:''},findings:[],resources:[],limitations:[],...over} as ScanView);
const snap=(origin:string,requests:number,type='explicit-seed',extra:any={})=>({origin,requests,authorization:{type,...extra}} as any);

test('scope counts separate entered seeds, domain groups, authorized and contacted origins; older records report contacted as not recorded',()=>{
  // The owner export analogue: one seed, one approved related origin in the same domain, one same-domain origin excluded in exact-origin mode.
  const exact=view({config:makeConfig({urls:['https://example.com/'],relatedOrigins:['https://assets.example.com'],sameRegistrableDomainDiscovery:false}),origins:[snap('https://example.com',40),snap('https://assets.example.com',15,'explicit-related')],resources:[{url:'https://blocked.example.com/',status:'blocked',reason:'scope',bytes:0,chain:[],kind:'page'}]});
  const c=scopeCounts(exact);assert.deepEqual({seeds:c.enteredSeeds,groups:c.domainGroups,authorized:c.authorizedOrigins,contacted:c.contactedOrigins,inside:c.insideNotScannedOrigins,third:c.thirdPartyOrigins,mode:c.mode},{seeds:1,groups:1,authorized:2,contacted:2,inside:1,third:0,mode:'exact-origin'});
  assert.equal(scopeCountLine(c),'1 entered seed · 1 domain group (example.com) · 2 authorized origins · 2 contacted · 1 same-domain origin not scanned · exact-origin');
  // PSL private suffixes keep tenants apart; an IP literal is its own group.
  const many=scopeCounts(view({config:makeConfig({urls:['https://a.example.com/','https://shop.example.co.uk/'],relatedOrigins:['https://t1.github.io','http://127.0.0.1:8080']})}));assert.equal(many.domainGroups,4);assert.equal(many.enteredSeeds,2);assert.equal(many.contactedOrigins,null,'no origins recorded');
  const schemes=scopeCounts(view({config:makeConfig({urls:['https://example.com/','http://example.com/']}),origins:[snap('https://example.com',1),snap('http://example.com',0)]}));assert.equal(schemes.domainGroups,1);assert.equal(schemes.authorizedOrigins,2,'scheme and port stay distinct budgeted origins');assert.equal(schemes.contactedOrigins,1);
  const auto=scopeCounts(view({config:makeConfig({urls:['https://example.com/']}),origins:[snap('https://example.com',3),snap('https://cdn.example.com',2,'same-registrable-domain',{seed:'https://example.com/',discoveredFrom:'https://example.com/',registrableDomain:'example.com'})],scope:{groups:[{notAdmitted:[{reason:'auto-origin-limit',count:4,examples:['https://x.example.com','https://y.example.com']}]}],excluded:{thirdPartyOrigins:3,references:9,overflow:2,examples:[]}} as any}));assert.deepEqual([auto.automaticOrigins,auto.insideNotScannedOrigins,auto.thirdPartyOrigins,auto.domainGroups],[1,2,5,1]);
});

test('run summaries label legacy records honestly: trigger not recorded, inferred retry/demo, start time fallback and host labels',()=>{
  const legacy=view({name:LEGACY_DEFAULT_NAME,config:{urls:['https://xn--bcher-kva.example/'],relatedOrigins:[]} as any,startedAt:undefined});
  const s=runSummary({view:legacy,savedAt:'2026-01-02T00:00:00.000Z'});assert.equal(s.trigger,null);assert.equal(s.triggerSource,'unavailable');assert.equal(s.triggerLabel,'Trigger not recorded');assert.equal(s.label,'bücher.example');assert.equal(s.startedAt,null);assert.equal(s.savedAt,'2026-01-02T00:00:00.000Z');assert.equal(s.build,null);assert.equal(s.scope.contactedOrigins,null);assert.equal(s.shortId,legacy.id.slice(0,8));
  const source=randomUUID(),retry=runSummary({view:view({retry:{sourceScan:source,selected:[],excluded:[],browserUrls:[],omitted:0,note:''}})});assert.deepEqual([retry.trigger,retry.triggerSource,retry.previousRunId,retry.relation,retry.triggerLabel],['retry','inferred',source,'retry','Focused retry (inferred)']);
  const demo=runSummary({view:view({name:'DEMO · synthetic local exposures',config:makeConfig({urls:['http://127.0.0.1:9/.env'],developmentFixtureOrigin:'http://127.0.0.1:9'})})});assert.equal(demo.trigger,'demo');assert.equal(demo.triggerSource,'inferred');
  const recorded=runSummary({view:view({launch:{trigger:'schedule',requestedAt:'2026-01-01T00:00:00.000Z',previousRunId:source,relation:'repeat'}}),projectName:'Owner site'});assert.deepEqual([recorded.trigger,recorded.triggerSource,recorded.previousRunId,recorded.relation,recorded.label],['schedule','recorded',source,'repeat','Owner site']);
  assert.equal(runSummary({view:view({launch:{trigger:'manual',requestedAt:'x',previousRunId:'../../etc'}})}).previousRunId,null,'only well-formed run ids are linked');
  assert.equal(runSummary({view:view({stopReason:'application-interrupted',state:'incomplete'})}).interrupted,true);
});

test('default project names come from the entered host; explicit names, including the legacy constant, are kept',()=>{
  assert.equal(makeConfig({urls:['example.com']}).name,'example.com');assert.equal(makeConfig({urls:['https://xn--bcher-kva.example/']}).name,'bücher.example');
  assert.equal(makeConfig({urls:['https://a.example.com/','https://b.example.com/x','https://a.example.com/y']}).name,'a.example.com + 1 more');
  assert.equal(makeConfig({urls:['example.com'],name:'   '}).name,'example.com');assert.equal(makeConfig({urls:['example.com'],name:LEGACY_DEFAULT_NAME}).name,LEGACY_DEFAULT_NAME);assert.equal(makeConfig({urls:['example.com'],name:' Owner site '}).name,'Owner site');
  assert.throws(()=>makeConfig({urls:['example.com'],name:5 as any}));assert.throws(()=>makeConfig({urls:['example.com'],name:'x'.repeat(101)}));
  const long=['a'.repeat(63),'b'.repeat(63),'c'.repeat(63),'d'.repeat(61)].join('.');assert.equal(long.length,253);const name=makeConfig({urls:['https://'+long+'/']}).name;assert.ok(name.length<=100&&name.endsWith('…'));
  assert.equal(defaultProjectName([]),LEGACY_DEFAULT_NAME);
});

test('request ledger replays one result for a repeated identifier, refuses reuse with another body, forgets failures, expires and evicts',async()=>{
  let now=0,calls=0;const ledger=new RequestLedger(1000,3,()=>now);let release!:()=>void;const gate=new Promise<void>(r=>release=r);
  const fn=async()=>{calls++;await gate;return {id:'run-'+calls};};
  const first=ledger.once('scans','request-aaaaaaaa',{a:1},fn),second=ledger.once('scans','request-aaaaaaaa',{a:1},fn);release();
  const [x,y]=await Promise.all([first,second]);assert.equal(calls,1,'an in-flight duplicate never starts a second run');assert.deepEqual(x,{value:{id:'run-1'},duplicate:false});assert.deepEqual(y,{value:{id:'run-1'},duplicate:true});
  await assert.rejects(ledger.once('scans','request-aaaaaaaa',{a:2},fn),(e:any)=>e instanceof SafeError&&e.code==='request-id-reused'&&e.status===409);
  await assert.rejects(ledger.once('scans','request-bbbbbbbb',{},async()=>{throw new Error('first attempt failed');}));assert.deepEqual(await ledger.once('scans','request-bbbbbbbb',{},async()=>'recovered'),{value:'recovered',duplicate:false},'a failed request can be retried with the same identifier');
  assert.equal((await ledger.once('queue','request-aaaaaaaa',{a:2},async()=>'other scope')).duplicate,false,'scopes are separate');
  now=5000;assert.equal((await ledger.once('scans','request-aaaaaaaa',{a:1},fn)).duplicate,false,'expired identifiers run again');assert.equal(calls,2);
  for(let i=0;i<5;i++)await ledger.once('scans','request-evict-'+i,{},async()=>i);assert.equal(ledger.size,3);assert.equal((await ledger.once('scans','request-evict-0',{},async()=>'again')).duplicate,false,'oldest entries are evicted first');
  assert.deepEqual(await ledger.once('scans',undefined,{},async()=>'no id'),{value:'no id',duplicate:false});await assert.rejects(ledger.once('scans','bad id!',{},fn),(e:any)=>e.code==='request-id-invalid');
});

test('desk records manual, queued, scheduled and retry launches with run links that survive a store restart',{timeout:60000},async()=>{
  const dir=await temp(),site=await slowSite(50);const desk=new Desk(new Map(),()=>[]);
  const done=async(id:string)=>{for(let i=0;i<400;i++){if(desk.store!.history.some(h=>h.view.id===id&&!['running','ready'].includes(h.view.state))&&!desk.activeScan())return;await pause(25);}throw new Error('run did not finish');};
  try{desk.store=await new Store(dir,true).init();const p=await desk.store.project({urls:[site.origin+'/slow'],developmentFixtureOrigin:site.origin,adjacentMaps:false,requestsPerSecond:20,browser:false},true);
    assert.equal(p.config.name,'127.0.0.1','the saved project is named after its host');
    const first=await desk.start(p.config,p.id);await done(first.id);assert.deepEqual(first.launch&&{t:first.launch.trigger,p:first.launch.previousRunId},{t:'manual',p:undefined});
    const second=await desk.start(p.config,p.id);await done(second.id);assert.equal(second.launch!.previousRunId,first.id);assert.equal(second.launch!.relation,'repeat');
    const [job]=await desk.enqueue([p.id]);for(let i=0;i<400&&!job.scanId;i++)await pause(25);await done(job.scanId!);const queued=desk.scans.get(job.scanId!)!;assert.equal(queued.launch!.trigger,'queue');assert.equal(queued.launch!.queueJobId,job.id);assert.equal(job.trigger,'queue');assert.ok(job.requestedAt);
    // The queue job reports its terminal state asynchronously; a schedule tick while it still reads "running" is (correctly) counted as missed.
    for(let i=0;i<400&&['queued','running'].includes(job.state);i++)await pause(25);
    p.schedule={enabled:true,intervalHours:1,nextRun:new Date(Date.now()-1000).toISOString(),missed:0};await desk.tick();const scheduled=desk.queue.at(-1)!;for(let i=0;i<400&&!scheduled.scanId;i++)await pause(25);await done(scheduled.scanId!);assert.equal(desk.scans.get(scheduled.scanId!)!.launch!.trigger,'schedule');assert.equal(p.schedule.lastRunId,scheduled.scanId);
    const retry=await desk.start(p.config,p.id,false,undefined,undefined,{trigger:'retry',previousRunId:second.id});await done(retry.id);assert.deepEqual([retry.launch!.trigger,retry.launch!.previousRunId,retry.launch!.relation],['retry',second.id,'retry']);
    await assert.rejects(Promise.all([desk.start(p.config,p.id),desk.start(p.config,p.id)]),(e:any)=>e instanceof SafeError&&e.code==='scan-active');for(let i=0;i<400&&desk.activeScan();i++)await pause(25);
    await desk.close();const again=await new Store(dir,true).init();const triggers=again.history.map(h=>h.view.launch?.trigger);for(const t of ['manual','queue','schedule','retry'])assert.ok(triggers.includes(t as any),t+' survives restart');assert.equal(again.history.find(h=>h.view.id===second.id)!.view.launch!.previousRunId,first.id);assert.ok(again.history.every(h=>!JSON.stringify(h).includes('request-')),'request identifiers are never persisted');again.close();
  }finally{await desk.close();await site.close();await rm(dir,{recursive:true,force:true});}
});

test('dashboard runs API: one current run, labeled newest-first history, idempotent starts, 409 for overlaps, repeats linked, legacy records untouched',{timeout:90000},async()=>{
  const dir=await temp(),site=await slowSite(1500);await mkdir(path.join(dir,'scans'),{recursive:true});
  // Three retained records whose UUID order differs from their start order: a pre-2.4 shape (no origins, build or launch) and two 2.4-shaped records.
  const savedAt=new Date().toISOString(),ids=['ffffffff-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000002','88888888-0000-4000-8000-000000000003'];
  const legacyView=(id:string,startedAt:string,extra:any={})=>({schema:'exposure-history/2',view:{schema:'exposure-scan/1',id,name:LEGACY_DEFAULT_NAME,state:'completed',startedAt,endedAt:startedAt,elapsedMs:1,config:{urls:['https://legacy.example.com/'],relatedOrigins:[],sameRegistrableDomainDiscovery:false},counts:{resources:3,scanned:2,blocked:1,bytes:10,pending:0,findings:0},engines:{websiteRules:'website/2.3.0',gitleaks:'8.30.1',ruleDigest:'x',companyRules:'none'},findings:[],resources:[{url:'https://blog.legacy.example.com/',status:'blocked',reason:'scope',bytes:0,chain:[],kind:'page'}],limitations:[],...extra},savedAt});
  const files={[ids[0]]:legacyView(ids[0],'2026-01-01T00:00:00.000Z'),[ids[1]]:legacyView(ids[1],'2026-03-01T00:00:00.000Z',{build:{version:'2.4.0-rc.1',id:'2.4.0-rc.1+5d5acf0f7f18d7e6',sourceDigest:'x'},origins:[snap('https://legacy.example.com',20),snap('https://labs.legacy.example.com',5,'explicit-related')],config:{urls:['https://legacy.example.com/'],relatedOrigins:['https://labs.legacy.example.com'],sameRegistrableDomainDiscovery:false}}),[ids[2]]:legacyView(ids[2],'2026-02-01T00:00:00.000Z')};
  for(const [id,h]of Object.entries(files))await writeFile(path.join(dir,'scans',id+'.json'),JSON.stringify(h));const before=await Promise.all(ids.map(id=>readFile(path.join(dir,'scans',id+'.json'),'utf8')));
  const app=await startDashboard({port:0,persistent:true,dataDir:dir,syntheticData:true});
  try{
    assert.equal((await fetch(app.origin+'/api/runs')).status,401);
    const login=await fetch(app.origin+'/api/login',{method:'POST',headers:{'Content-Type':'application/json',Origin:app.origin,'X-Dashboard-Request':'1'},body:JSON.stringify({token:app.token})});const cookie=login.headers.get('set-cookie')!.split(';')[0];const {csrf}=await login.json() as any;
    const headers={'Content-Type':'application/json',Origin:app.origin,'X-Dashboard-Request':'1','X-CSRF-Token':csrf,Cookie:cookie};
    const post=(route:string,data:unknown)=>fetch(app.origin+route,{method:'POST',headers,body:JSON.stringify(data)});const get=async(route:string)=>(await fetch(app.origin+route,{headers:{Cookie:cookie}})).json() as any;
    let runs=await get('/api/runs');assert.equal(runs.schema,'exposure-runs/1');assert.equal(runs.current,null);assert.deepEqual(runs.history.map((r:any)=>r.id),[ids[1],ids[2],ids[0]],'newest first by start time, not file order');assert.equal(runs.latest.id,ids[1]);assert.equal(runs.counts.retainedRuns,3);assert.equal(runs.storage,'persistent');
    const old=runs.history.find((r:any)=>r.id===ids[0]);assert.deepEqual([old.triggerSource,old.triggerLabel,old.label,old.build,old.scope.contactedOrigins,old.scope.insideNotScannedOrigins],['unavailable','Trigger not recorded','legacy.example.com',null,null,1]);
    const export24=runs.history.find((r:any)=>r.id===ids[1]);assert.deepEqual([export24.scope.enteredSeeds,export24.scope.domainGroups,export24.scope.authorizedOrigins,export24.scope.contactedOrigins],[1,1,2,2],'one domain group, two authorized origins');
    const workspace=await get('/api/workspace');assert.deepEqual(workspace.history.map((h:any)=>h.id),[ids[0],ids[2],ids[1]],'workspace history stays chronological (oldest first) for existing readers');assert.equal(workspace.history[0].triggerLabel,'Trigger not recorded');
    const config={urls:[site.origin+'/slow'],developmentFixtureOrigin:site.origin,requestsPerSecond:20,adjacentMaps:false,browser:false,semanticAnalysis:false};const body={authorized:true,config,requestId:'double-click-0001'};
    const [a,b]=await Promise.all([post('/api/scans',body),post('/api/scans',body)]);assert.equal(a.status,202);assert.equal(b.status,202);const ja=await a.json() as any,jb=await b.json() as any;assert.equal(ja.id,jb.id,'a double submission starts exactly one run');assert.deepEqual([ja.duplicate,jb.duplicate].sort(),[false,true]);assert.equal(ja.shortId,ja.id.slice(0,8));assert.equal(app.scans.size,1);
    const overlap=await post('/api/scans',{...body,requestId:'second-start-0002'});assert.equal(overlap.status,409);const conflict=await overlap.json() as any;assert.equal(conflict.code,'scan-active');assert.equal(conflict.activeRunId,ja.id);
    const reused=await post('/api/scans',{...body,config:{...config,name:'changed'}});assert.equal(reused.status,409);assert.equal((await reused.json() as any).code,'request-id-reused');
    runs=await get('/api/runs');assert.equal(runs.current.id,ja.id);assert.equal(runs.current.trigger,'manual');assert.equal(runs.current.live,true);assert.ok(!runs.history.some((r:any)=>r.id===ja.id),'the current run is not repeated in history');assert.equal(runs.counts.activeRuns,1);
    for(let i=0;i<200;i++){runs=await get('/api/runs');if(!runs.current)break;await pause(50);}assert.equal(runs.current,null);assert.equal(site.arrivals.filter(p=>p==='/slow').length,1,'the seed was fetched once');
    const third=await post('/api/scans',{...body,requestId:'deliberate-repeat-03'});assert.equal(third.status,202);const j3=await third.json() as any;assert.notEqual(j3.id,ja.id);assert.equal(j3.launch.previousRunId,ja.id);assert.equal(j3.launch.relation,'repeat');
    for(let i=0;i<200;i++){runs=await get('/api/runs');if(!runs.current)break;await pause(50);}
    const single=await get('/api/scans/'+j3.id);assert.equal(single.run.previousRunId,ja.id);assert.equal(single.run.relation,'repeat');assert.equal(single.launch.trigger,'manual');
    const list=await get('/api/scans');assert.ok(list.every((r:any)=>typeof r.shortId==='string'&&'trigger' in r&&'label' in r));assert.equal(list.find((r:any)=>r.id===ids[0]).label,'legacy.example.com');
    const preview=await(await post('/api/scope/preview',{config:{urls:['https://xn--bcher-kva.example/','https://other.invalid/']}})).json() as any;assert.equal(preview.suggestedName,'bücher.example + 1 more');assert.equal(preview.counts.enteredSeeds,2);
    const resume=await post('/api/resume',{checkpoint:{schema:'exposure-checkpoint/1',config,frontier:[],redactedReview:{id:'not-a-run-id',launch:{trigger:'schedule'}}}});assert.equal(resume.status,202);const jr=await resume.json() as any;for(let i=0;i<200;i++){runs=await get('/api/runs');if(!runs.current)break;await pause(50);}const resumed=await get('/api/scans/'+jr.id);assert.equal(resumed.launch.trigger,'resume','checkpoint-supplied triggers are ignored');assert.equal(resumed.launch.previousRunId,undefined,'unknown checkpoint ids are not linked');
    const linked=await post('/api/resume',{checkpoint:{schema:'exposure-checkpoint/1',config,frontier:[],redactedReview:{id:j3.id}}});const jl=await linked.json() as any;for(let i=0;i<200;i++){runs=await get('/api/runs');if(!runs.current)break;await pause(50);}assert.equal((await get('/api/scans/'+jl.id)).launch.previousRunId,j3.id);
    assert.ok(!JSON.stringify(runs).includes(synthetic.openai)&&!JSON.stringify(runs).includes('double-click-0001'),'listing carries no secrets or request identifiers');
    const after=await Promise.all(ids.map(id=>readFile(path.join(dir,'scans',id+'.json'),'utf8')));assert.deepEqual(after,before,'legacy history files are never rewritten by listing or labeling');
  }finally{await app.close();await site.close();await rm(dir,{recursive:true,force:true});}
});
