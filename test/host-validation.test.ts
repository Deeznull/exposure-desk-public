import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { websiteHost, validHostLabels } from '../src/domain-scope.js';
import { makeConfig, makeNewConfig, resolveScanConfig, invalidHost, invalidHostMessage, isInvalidHostError } from '../src/config.js';
import { parseTargets } from '../src/cli/targets.js';
import { ProtectedHostError } from '../src/protected-hosts.js';
import { Desk } from '../src/desk.js';
import { Scanner } from '../src/scanner.js';
import { Transport, PolicyError, type Resolver } from '../src/transport.js';
import { Evidence } from '../src/evidence.js';
import { Detector, root } from '../src/detectors.js';
import { startDashboard } from '../src/dashboard.js';
import { makeTrigger, writeTrigger } from '../src/triggers.js';
import { egressTripwire } from './virtual-network.js';
import type { ScanConfig, Resource, Gap, ScanView } from '../src/types.js';
import { gapSummary } from '../src/cli/output.js';
import { coverage } from '../src/coverage.js';
import { historyReport } from '../src/reports.js';
/** 2.7 host validation (w2-hosts): strict for new input, lenient on load. A host that is not a website host (LDH or underscore labels, IDN after punycode, or an IP literal)
 * is refused in new input before any request; a saved record with one keeps loading unchanged with a warning, and every scan start of it is refused.
 * Loopback fixtures and synthetic names only: no invalid or protected name is ever resolved (the egress tripwire fails the test on any lookup or non-loopback socket). */
const message=(host:string)=>`Refused: "${host}" is not a valid website host. A host uses letters, digits, hyphens and underscores (international names are converted automatically) or is an IP address. Nothing was requested.`;
const protectedMessage=(host:string)=>`Exposure Desk never scans government, military, intelligence or law-enforcement websites: ${host}`;
const refused=(host:string)=>(e:unknown)=>isInvalidHostError(e)&&e.message===message(host)&&e.status===400&&e.details.host===host;
const protectedRefusal=(host:string)=>(e:unknown)=>e instanceof ProtectedHostError&&e.host===host;
const sleep=(ms:number)=>new Promise(r=>setTimeout(r,ms));
async function temp(prefix:string){const parent=process.env.EXPOSURE_DATA_DIR||path.join(root,'.cache');await mkdir(parent,{recursive:true});return mkdtemp(path.join(parent,prefix));}
/** Loopback owner website: records the path and Host header of every arrival. */
async function owner(routes:Record<string,[type:string,body:string]>){
  const arrivals:{path:string;host:string}[]=[];
  const server=http.createServer((req,res)=>{arrivals.push({path:req.url||'',host:String(req.headers.host)});const r=routes[(req.url||'/').split('?')[0]!];if(!r){res.statusCode=404;res.end('not found');return;}res.writeHead(200,{'content-type':r[0]});res.end(r[1]);});
  await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));
  return {origin:`http://127.0.0.1:${(server.address() as any).port}`,arrivals,close:()=>new Promise<void>(r=>{server.close(()=>r());server.closeAllConnections();})};
}
const SITE={'/':['text/html','<!doctype html><title>owner</title><script src="/app.js"></script>'],'/app.js':['text/javascript','window.ok=1;'],'/robots.txt':['text/plain','User-agent: *\nAllow: /\n']} as Record<string,[string,string]>;
const workspace=(projects:unknown[])=>JSON.stringify({schema:'exposure-workspace/3',projects,reviews:{},settings:{retentionDays:90,maxScans:100,vaultMinutes:5},rules:[],ruleVersions:[],alerts:[]});

test('host rule: one helper for target lists and configurations; LDH and underscore labels, punycode, IP literals, localhost and one trailing dot pass; anything else fails',()=>{
  for(const h of ['example.com','EXAMPLE.com','a-b.example.com','a_b.example.com','_dmarc.example.com','xn--bcher-kva.example','localhost','127.0.0.1','[::1]','[2001:db8::1]','[::ffff:7f00:1]','example.com.','x'.repeat(63)+'.example.com'])assert.ok(websiteHost(h),h);
  for(const h of ['shop{old}.example.com','bad*host.example.com','a,b.example.net','a!b.example.com','a$b.example.com','bad..example.com','.example.com','example.com..','','x'.repeat(64)+'.example.com','*.example.com','a b.example.com','[not-an-ip]'])assert.ok(!websiteHost(h),h);
  // The WHATWG parser lets these through for http(s), which is why the rule exists; IDN arrives as punycode and IPv4 forms canonicalized.
  assert.equal(new URL('https://shop{old}.example.com/').hostname,'shop{old}.example.com');assert.equal(new URL('https://bücher.example/').hostname,'xn--bcher-kva.example');assert.equal(new URL('http://0x7f.1/').hostname,'127.0.0.1');
  // The discovery-side label check stays lenient on purpose: discovered URLs keep their handling.
  assert.ok(validHostLabels('shop{old}.example.com'));
  // Target lists use the same helper and keep the invalid-url reason.
  const r=parseTargets(['https://shop{old}.example.com/','bad*host.example.com','a_b.example.com','bücher.example','http://[::1]:8080/','http://127.0.0.1:8080/','localhost:3000','example.org.','https://a,b.example.net/x'].join('\n'));
  assert.deepEqual(r.rejected.map(x=>[x.line,x.reason]),[[1,'invalid-url'],[2,'invalid-url'],[9,'invalid-url']]);
  assert.deepEqual(r.accepted.map(x=>x.url),['https://a_b.example.com/','https://xn--bcher-kva.example/','http://[::1]:8080/','http://127.0.0.1:8080/','https://localhost:3000/','https://example.org/']);
});

test('configuration: new input naming an invalid host in any URL field is refused with the message; the lenient load path still accepts it; valid edge cases and the examples pass',async()=>{
  assert.equal(invalidHostMessage('shop{old}.example.com'),message('shop{old}.example.com'));
  const cases:[Partial<ScanConfig>,string][]=[[{urls:['https://shop{old}.example.com/']},'shop{old}.example.com'],[{urls:['bad*host.example.com']},'bad*host.example.com'],[{urls:['https://owner.example.com/','https://a,b.example.net/x']},'a,b.example.net'],
    [{urls:['https://owner.example.com/'],relatedOrigins:['https://cdn{x}.example.com']},'cdn{x}.example.com'],[{urls:['https://owner.example.com/'],privateOrigins:['https://api{x}.example.com']},'api{x}.example.com'],
    [{urls:['https://owner.example.com/'],staleAssetCheck:true,staleAssetUrls:['https://old{x}.example.com/a.js']},'old{x}.example.com']];
  for(const [raw,host] of cases){const label=JSON.stringify(raw);
    assert.equal(invalidHost(raw),host,label);assert.throws(()=>makeNewConfig(raw),refused(host),label);assert.throws(()=>resolveScanConfig(raw),refused(host),'every scan start resolves through the strict check: '+label);
    assert.doesNotThrow(()=>makeConfig(raw),'a saved configuration still loads: '+label);}
  assert.equal(invalidHost({urls:['https://owner.example.com/']}),undefined);assert.equal(invalidHost(null),undefined);assert.equal(invalidHost({urls:'not a list'}),undefined);
  const edges:[string,string][]=[['https://a_b.example.com/','https://a_b.example.com/'],['https://_dmarc.example.com/','https://_dmarc.example.com/'],['https://bücher.example/','https://xn--bcher-kva.example/'],['https://xn--bcher-kva.example/','https://xn--bcher-kva.example/'],
    ['http://127.0.0.1:8080/','http://127.0.0.1:8080/'],['http://0x7f.1/','http://127.0.0.1/'],['http://[::1]:8080/','http://[::1]:8080/'],['http://[2001:db8::1]/','http://[2001:db8::1]/'],['https://example.com./','https://example.com/'],['http://localhost:3000/','http://localhost:3000/']];
  for(const [input,url] of edges)assert.deepEqual(makeNewConfig({urls:[input]}).urls,[url],input);
  // Protected hosts keep their rule and its order: they are refused first, by the lenient path too, wherever the invalid host sits.
  for(const raw of [{urls:['https://shop{x}.example.com/','https://www.example.gov/']},{urls:['https://www.example.gov/','https://shop{x}.example.com/']},{urls:['https://owner.example.com/'],relatedOrigins:['https://cdn{x}.example.com','https://cdn.example.mil']}] as Partial<ScanConfig>[]){
    const host=raw.relatedOrigins?'cdn.example.mil':'www.example.gov';assert.throws(()=>makeNewConfig(raw),protectedRefusal(host));assert.throws(()=>makeConfig(raw),protectedRefusal(host));}
  // Shipped example configurations keep working.
  const examples=(await readdir(root)).filter(f=>f.endsWith('.config.example.json'));assert.ok(examples.length>=3);
  for(const f of examples){const j=JSON.parse(await readFile(path.join(root,f),'utf8')),list=Array.isArray(j.projects)?j.projects:Array.isArray(j)?j:[j];for(const p of list){assert.equal(invalidHost(p),undefined,f);assert.doesNotThrow(()=>makeNewConfig(p),f);}}
});

test('CLI: --url, --config entries, a --targets template, a checkpoint, dashboard --config and trigger input with an invalid host exit 2 with one line before any request',{timeout:120000},async()=>{
  const cli=path.join(root,'dist/src/cli.js'),dir=await temp('hosts-cli-'),env={...process.env,EXPOSURE_DATA_DIR:dir},site=await owner(SITE),never=path.join(dir,'never.json');
  const run=(args:string[])=>spawnSync(process.execPath,[cli,...args],{encoding:'utf8',env,windowsHide:true,timeout:60000});
  const oneLine=(r:ReturnType<typeof run>,line:string,what:string)=>{assert.equal(r.status,2,what+': '+r.stderr);assert.deepEqual(r.stderr.trim().split(/\r?\n/),[line],what);assert.equal(r.stdout,'',what+' prints nothing else');};
  try{oneLine(run(['scan','--url','https://shop{old}.example.com/','--output',never]),message('shop{old}.example.com'),'--url');
    oneLine(run(['scan','--url','bad*host.example.com','--jsonl']),message('bad*host.example.com'),'--url with --jsonl writes no JSON line');
    const cfg=path.join(dir,'projects.json');await writeFile(cfg,JSON.stringify({projects:[{urls:[site.origin+'/'],developmentFixtureOrigin:site.origin},{urls:['https://a,b.example.net/']}]}));
    oneLine(run(['scan','--config',cfg,'--output',never]),message('a,b.example.net'),'--config: every entry is checked before the first one runs');
    const both=path.join(dir,'both.json');await writeFile(both,JSON.stringify({projects:[{urls:['https://shop{x}.example.com/']},{urls:['https://www.gouv.fr/']}]}));
    oneLine(run(['scan','--config',both,'--output',never]),protectedMessage('www.gouv.fr'),'the protected-host rule runs first');
    const template=path.join(dir,'template.json'),targets=path.join(dir,'targets.txt');await writeFile(template,JSON.stringify({projects:[{developmentFixtureOrigin:site.origin,relatedOrigins:['https://cdn{x}.example.com']}]}));await writeFile(targets,site.origin+'/\n');
    oneLine(run(['scan','--targets',targets,'--config',template,'--output',never]),message('cdn{x}.example.com'),'--targets template');
    const checkpoint=path.join(dir,'checkpoint.json');await writeFile(checkpoint,JSON.stringify({schema:'exposure-checkpoint/1',config:{urls:['https://shop{old}.example.com/']},frontier:[]}));
    oneLine(run(['scan','--resume',checkpoint,'--output',never]),message('shop{old}.example.com'),'--resume');
    oneLine(run(['dashboard','--config',cfg,'--port','0']),message('a,b.example.net'),'dashboard --config');
    // Trigger files: a saved project whose host is invalid, and an asset list naming one, write nothing.
    const badId=randomUUID(),goodId=randomUUID(),now=new Date().toISOString(),trigger={enabled:true,minIntervalMinutes:1,maxPerDay:24,recent:[]};
    await writeFile(path.join(dir,'workspace.json'),workspace([{id:badId,config:{name:'Old shop',urls:['https://shop{old}.example.com/']},authorizedAt:now,createdAt:now,deploymentTrigger:trigger},{id:goodId,config:{name:'Fixture',urls:[site.origin+'/'],developmentFixtureOrigin:site.origin},authorizedAt:now,createdAt:now,deploymentTrigger:trigger}]));
    oneLine(run(['trigger','--data-dir',dir,'--project',badId]),'Trigger not written: '+message('shop{old}.example.com'),'trigger for a saved invalid host');
    const manifest=path.join(dir,'assets.json');await writeFile(manifest,JSON.stringify(['/app.js','https://cdn{x}.example.com/app.js']));
    oneLine(run(['trigger','--data-dir',dir,'--project',goodId,'--assets',manifest]),'Trigger not written: '+message('cdn{x}.example.com'),'trigger asset list');
    assert.deepEqual(await readdir(path.join(dir,'triggers')).catch(()=>[]),[],'no trigger file was written');assert.ok(!(await readdir(dir)).includes('never.json'));assert.equal(site.arrivals.length,0,'nothing was requested');
  }finally{await site.close();await rm(dir,{recursive:true,force:true});}
});

test('saved projects: a record with an invalid host loads unchanged with a note; queue, routine, deployment trigger and every scan start are refused before any request; a corrected save lifts it',{timeout:180000},async()=>{
  const trip=egressTripwire(),dir=await temp('hosts-desk-'),site=await owner(SITE),detector=new Detector('disabled');await detector.init();
  const badId=randomUUID(),now=new Date().toISOString(),past=new Date(Date.now()-7200000).toISOString(),host='shop{old}.example.com';
  // A project saved by an earlier build: its host was never valid, it has a due routine and an enabled deployment trigger.
  const legacy={id:badId,config:{name:'Old shop',urls:['https://shop{old}.example.com/'],preset:'standard'},authorizedAt:now,createdAt:now,schedule:{enabled:true,intervalHours:1,nextRun:past,missed:0},deploymentTrigger:{enabled:true,minIntervalMinutes:1,maxPerDay:24,recent:[]}};
  await writeFile(path.join(dir,'workspace.json'),workspace([legacy]));
  const stored=async()=>JSON.parse(await readFile(path.join(dir,'workspace.json'),'utf8')).projects.find((p:any)=>p.id===badId);
  const desk=new Desk(new Map(),()=>[]);
  try{await desk.init(dir,true);assert.equal(desk.storageError,'','the workspace stays available');const st=desk.store!,p=st.projects.find(p=>p.id===badId)!;
    assert.deepEqual(p.config.urls,legacy.config.urls,'loaded as saved');assert.equal(p.config.name,'Old shop');assert.ok(!st.isBlocked(badId));assert.deepEqual((await stored()).config.urls,legacy.config.urls,'the startup save keeps the address');
    assert.ok(desk.notifications.some(n=>n.text==='1 saved project has a website address whose host is not valid. It loads and shows a warning, but no scan starts until the address is corrected and saved.'));
    assert.ok(refused(host)(st.hostRefusal(badId)));
    await assert.rejects(desk.enqueue([badId]),refused(host));assert.equal(desk.queue.length,0);
    const schedule={...p.schedule!};await desk.tick(Date.parse(schedule.nextRun)+60000);assert.equal(desk.queue.length,0,'the routine never fires');assert.deepEqual(p.schedule,schedule,'and is left as it was');
    const triggers=path.join(dir,'triggers');(desk as any).pumping=true;
    await writeTrigger(triggers,makeTrigger({projectId:badId}));await desk.processTriggers();assert.equal(st.alerts.at(-1)!.text,'Deployment trigger rejected: '+message(host));
    // Every scan start resolves through the strict check: the saved configuration, a fixture seed beside an invalid one, and the scanner itself.
    await assert.rejects(desk.start(p.config,badId),refused(host));
    await assert.rejects(desk.start({urls:[site.origin+'/','https://a,b.example.net/'],developmentFixtureOrigin:site.origin}),refused('a,b.example.net'));
    assert.throws(()=>new Scanner({urls:[site.origin+'/'],developmentFixtureOrigin:site.origin,staleAssetCheck:true,staleAssetUrls:['https://old{x}.example.com/a.js']},{detector}),refused('old{x}.example.com'));
    // An allowed project: a deployment trigger whose asset list names an invalid host is rejected with the message.
    const good=await st.project({urls:[site.origin+'/'],developmentFixtureOrigin:site.origin,browser:false,semanticAnalysis:false,adjacentMaps:false,requestsPerSecond:20},true);good.deploymentTrigger={enabled:true,minIntervalMinutes:1,maxPerDay:24,recent:[]};await st.save();
    await writeTrigger(triggers,makeTrigger({projectId:good.id,assets:[site.origin+'/app.js','https://cdn{x}.example.com/old.js']}));await desk.processTriggers();assert.equal(st.alerts.at(-1)!.text,'Deployment trigger rejected: '+message('cdn{x}.example.com'));assert.equal(desk.queue.length,0);
    (desk as any).pumping=false;assert.equal(site.arrivals.length,0,'nothing was requested');
    // Saving is new input: the invalid address cannot be saved again, and the stored record keeps it until the owner corrects it.
    await assert.rejects(st.project(p.config,true,badId),refused(host));assert.deepEqual((await stored()).config.urls,legacy.config.urls);
    // A valid loopback IP literal still scans.
    const s=await desk.start({...good.config},good.id);while(s.state==='running')await sleep(50);assert.ok(s.view().resources.some(r=>r.url===site.origin+'/'));assert.ok(site.arrivals.some(a=>a.path==='/'));
    // Correcting the address lifts the warning; an overdue routine moves on instead of firing at once.
    p.schedule!.nextRun=past;await st.project({name:'Old shop',urls:[site.origin+'/'],developmentFixtureOrigin:site.origin},true,badId);assert.equal(st.hostRefusal(badId),undefined);
    assert.ok(Date.parse(p.schedule!.nextRun)>Date.now(),'an overdue routine does not fire the moment the address is corrected');
    assert.ok(site.arrivals.every(a=>a.host===new URL(site.origin).host));assert.deepEqual(trip.violations,[],'no lookup or socket left the machine');
  }finally{(desk as any).pumping=false;desk.cancelQueue();await desk.close();trip.restore();await site.close();await rm(dir,{recursive:true,force:true});}
});

test('dashboard API: saves, previews, scans, resume, queue, routines and triggers with an invalid host return the message; the saved record is listed with its warning and never rewritten',{timeout:120000},async()=>{
  const trip=egressTripwire(),dir=await temp('hosts-dashboard-'),badId=randomUUID(),goodId=randomUUID(),now=new Date().toISOString(),host='shop{old}.example.com';
  const legacy={id:badId,config:{name:'Old shop',urls:['https://shop{old}.example.com/']},authorizedAt:now,createdAt:now,schedule:{enabled:false,intervalHours:24,nextRun:now,missed:0}};
  await writeFile(path.join(dir,'workspace.json'),workspace([legacy,{id:goodId,config:{name:'Owner',urls:['https://owner.example.com/']},authorizedAt:now,createdAt:now}]));
  const stored=async()=>JSON.parse(await readFile(path.join(dir,'workspace.json'),'utf8')).projects.find((p:any)=>p.id===badId);
  const app=await startDashboard({port:0,persistent:true,dataDir:dir,syntheticData:true});
  try{const login=await fetch(app.origin+'/api/login',{method:'POST',headers:{'Content-Type':'application/json',Origin:app.origin,'X-Dashboard-Request':'1'},body:JSON.stringify({token:app.token})}),cookie=login.headers.get('set-cookie')!.split(';')[0],{csrf}=await login.json() as any;
    const headers={'Content-Type':'application/json',Origin:app.origin,'X-Dashboard-Request':'1','X-CSRF-Token':csrf,Cookie:cookie},post=(route:string,data:unknown)=>fetch(app.origin+route,{method:'POST',headers,body:JSON.stringify(data)});
    const expectRefusal=async(route:string,data:unknown,h:string)=>{const r=await post(route,data);assert.equal(r.status,400,route);assert.deepEqual(await r.json(),{error:message(h),code:'invalid-url',host:h},route);};
    const list=async()=>(await(await fetch(app.origin+'/api/workspace',{headers:{Cookie:cookie}})).json() as any).projects;
    const atLoad=await stored();assert.deepEqual(atLoad.config.urls,legacy.config.urls,'loading keeps the saved address');assert.equal(atLoad.config.name,'Old shop');
    let listed=(await list()).find((p:any)=>p.id===badId);
    assert.deepEqual(listed.hostWarning,{code:'invalid-url',host,reason:message(host)});assert.deepEqual(listed.config.urls,legacy.config.urls);assert.equal(listed.blocked,undefined);
    assert.equal((await list()).find((p:any)=>p.id===goodId).hostWarning,undefined,'a valid project carries no warning');
    await expectRefusal('/api/projects/save',{authorized:true,config:{urls:['https://bad*host.example.com/']}},'bad*host.example.com');
    await expectRefusal('/api/projects/save',{authorized:true,id:badId,config:listed.config},host);
    await expectRefusal('/api/config/preview',{config:{urls:['https://shop{x}.example.com/']}},'shop{x}.example.com');await expectRefusal('/api/scope/preview',{config:{urls:['a,b.example.net']}},'a,b.example.net');
    await expectRefusal('/api/scans',{authorized:true,config:{urls:['https://shop{x}.example.com/']}},'shop{x}.example.com');
    await expectRefusal('/api/scans',{authorized:true,preset:'quick',config:{urls:['https://owner.example.com/'],relatedOrigins:['https://cdn{x}.example.com']}},'cdn{x}.example.com');
    await expectRefusal('/api/scans',{authorized:true,projectId:badId,config:listed.config},host);
    await expectRefusal('/api/resume',{checkpoint:{schema:'exposure-checkpoint/1',config:{urls:['https://shop{x}.example.com/']},frontier:[]}},'shop{x}.example.com');
    await expectRefusal('/api/queue',{projectIds:[badId]},host);
    await expectRefusal('/api/schedule',{projectId:badId,authorized:true,enabled:true,intervalHours:24},host);await expectRefusal('/api/deployment-trigger',{projectId:badId,authorized:true,enabled:true},host);
    // The protected-host rule keeps its place: first, with its own message.
    const r=await post('/api/projects/save',{authorized:true,config:{urls:['https://shop{x}.example.com/','https://www.example.gov/']}});assert.equal(r.status,400);assert.deepEqual(await r.json(),{error:protectedMessage('www.example.gov'),code:'protected-host',host:'www.example.gov'});
    assert.equal(app.scans.size,0,'no scan object was created');assert.deepEqual(await stored(),atLoad,'refusals never rewrite the record');
    // Turning a routine or trigger off stays possible; a corrected save lifts the warning.
    assert.equal((await post('/api/schedule',{projectId:badId,authorized:true,enabled:false,intervalHours:24})).status,200);assert.equal((await post('/api/deployment-trigger',{projectId:badId,authorized:true,enabled:false})).status,200);
    assert.equal((await post('/api/projects/save',{authorized:true,id:badId,config:{...listed.config,urls:['https://shop.example.com/']}})).status,200);
    listed=(await list()).find((p:any)=>p.id===badId);assert.equal(listed.hostWarning,undefined);assert.deepEqual(listed.config.urls,['https://shop.example.com/']);
    assert.deepEqual(trip.violations,[],'no lookup or socket left the machine');
  }finally{await app.close();trip.restore();await rm(dir,{recursive:true,force:true});}
});
test('discovered URLs (2.9 w7-hosts): a link, script, map or redirect target whose host is not a website host is refused as invalid-url before scope, admission or any DNS lookup',async()=>{
  const lookups:string[]=[],resolver:Resolver=async(host:string)=>{lookups.push(host);return [{address:'93.184.216.34',family:4}];};
  // Transport: every request path (seed, redirect hop, browser subrequest, map) goes through preflight; an in-domain name with a non-website host is refused there.
  const resources:Resource[]=[],gaps:Gap[]=[],evidence=new Evidence(new Detector('disabled'));
  const t=new Transport(makeConfig({urls:['https://example.com'],sameRegistrableDomainDiscovery:true}),evidence,r=>resources.push(r),g=>gaps.push(g),resolver);
  try{
    for(const bad of ['https://bad*host.example.com/app.js','https://a,b.example.com/','https://x!y.example.com/map.js.map',"https://it's.example.com/"])await assert.rejects(t.preflight(bad,'GET',{},'',['https://example.com/']),(e:unknown)=>e instanceof PolicyError&&e.code==='invalid-url',bad);
    assert.equal(lookups.length,0,'no invalid host is ever resolved: '+lookups.join());
    // Valid in-domain hosts still pass the same path (underscore labels and punycode included).
    for(const good of ['https://api.example.com/','https://_dmarc-like.example.com/','https://xn--bcher-kva.example.com/'])assert.equal(await t.preflight(good,'GET',{},'',['https://example.com/']),good);
    assert.ok(lookups.length>0,'valid hosts are resolved as before');
  }finally{t.cancel();evidence.clear();}
  // Scanner: discovered references with such hosts are recorded as blocked invalid-url and never attempted.
  lookups.length=0;
  const s=new Scanner({urls:['https://example.com'],sameRegistrableDomainDiscovery:true,semanticAnalysis:false,adjacentMaps:false,maxResources:40,maxDurationMs:5000},{detector:new Detector('disabled'),resolver});
  const attempted:string[]=[];
  s.transport.one=async(raw,options={})=>{
    const url=await s.transport.preflight(raw,'GET',{},'',options.chain),u=new URL(url);attempted.push(url);
    const text=u.pathname==='/robots.txt'?'User-agent: *':u.pathname==='/'?'<script src="https://bad*host.example.com/app.js"></script><a href="https://a,b.example.com/page">x</a><script src="https://api.example.com/ok.js"></script>':'{}';
    const resource:Resource={url,bytes:Buffer.byteLength(text),status:'downloaded',analysis:'pending',code:200,kind:options.kind||'http',chain:options.chain||[]};s.transport.onResource(resource);s.transport.requests++;s.transport.originControl.current!.requests++;
    return {url,status:200,headers:{'content-type':u.pathname==='/'?'text/html':'application/javascript'},body:Buffer.from(text),partial:false,chain:options.chain||[],resource};
  };
  const view=await s.run();
  assert.ok(attempted.includes('https://api.example.com/ok.js'),'a valid in-domain script is still requested');
  assert.ok(!attempted.some(u=>u.includes('bad*host')||u.includes('a,b.')),'no invalid host is attempted');
  assert.ok(!lookups.some(h=>h.includes('*')||h.includes(',')),'no invalid host is resolved');
  for(const host of ['bad*host.example.com','a,b.example.com'])assert.ok(view.resources.some(r=>r.reason==='invalid-url'&&new URL(r.url).hostname===host),host+' is recorded as invalid-url');
  // 2.9.1: the refusal is informational. Same reason and gap code, still listed (JSONL target-end.gaps marks it), but it does not make the target incomplete.
  const refusals=view.limitations.filter(g=>g.code==='invalid-url');assert.deepEqual([...new Set(refusals.map(g=>g.url))].sort(),['https://a,b.example.com/page','https://bad*host.example.com/app.js'],'each page that references them records them (the stub serves the same page on both origins)');assert.ok(refusals.every(g=>g.incomplete===false&&g.detail==='Request blocked: invalid-url.'),JSON.stringify(refusals));
  assert.deepEqual(gapSummary(view).find(g=>g.code==='invalid-url'),{code:'invalid-url',count:refusals.length,informational:true});
  assert.deepEqual([...new Set(view.limitations.filter(g=>g.incomplete).map(g=>g.code))],['semantic-disabled'],'only the configured gap of this test (semanticAnalysis off) keeps the target incomplete');
});
test('invalid-url is informational in completeness: coverage is not limited by it, a real gap still is, and a saved 2.9.0 record keeps its incomplete gap (2.9.1)',()=>{
  const config=makeConfig({urls:['https://example.com']}),seed:Resource={url:'https://example.com/',bytes:10,status:'scanned',analysis:'analyzed',code:200,kind:'http',chain:[]};
  // An over-long script URL on the entered origin (the one way an authorized-origin URL is refused as invalid-url) and a discovered invalid host.
  const long:Resource={url:'https://example.com/app.js?'+'x'.repeat(5000),bytes:0,status:'blocked',analysis:'skipped',reason:'invalid-url',kind:'script',chain:['https://example.com/']};
  const host:Resource={url:'https://bad*host.example.com/app.js',bytes:0,status:'blocked',analysis:'skipped',reason:'invalid-url',kind:'script',chain:['https://example.com/']};
  const gaps:Gap[]=[{code:'invalid-url',url:long.url,detail:'Request blocked: invalid-url.',incomplete:false},{code:'invalid-url',url:host.url,detail:'Request blocked: invalid-url.',incomplete:false}];
  const c=coverage(config,[seed,long,host],[],'completed',0,{gaps});
  assert.equal(c.assessment,'configured-checks-completed','an invalid-url refusal does not limit coverage');
  const row=c.inventory.find(r=>r.url===long.url)!;assert.equal(row.state,'unsupported');assert.equal(row.reason,'invalid-url','still listed with its reason');
  // A real refusal on the same script still limits it.
  const timeout:Resource={...long,url:'https://example.com/other.js',status:'failed',analysis:'failed',reason:'request-timeout'};
  assert.equal(coverage(config,[seed,long,timeout],[],'completed',0,{gaps}).assessment,'limited');
  // Saved 2.9.0 record: the gap was written as incomplete and the target as incomplete. Loaded as is: the JSONL summary and the report keep it.
  const saved={id:'saved-2-9-0',state:'incomplete',limitations:[{code:'invalid-url',url:host.url,detail:'Request blocked: invalid-url.',incomplete:true}],findings:[],resources:[seed,host],counts:{scanned:1,findings:0},build:{version:'2.9.0'}} as unknown as ScanView;
  assert.deepEqual(gapSummary(saved),[{code:'invalid-url',count:1}]);
  const json=JSON.parse(historyReport(saved,'json'));assert.equal(json.limitations[0].incomplete,true);assert.equal(json.state,'incomplete');assert.ok(historyReport(saved,'html').includes('invalid-url'),'shown in the HTML report');
});
