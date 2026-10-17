import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { mkdtemp, mkdir, rm, readFile, writeFile, readdir, link, symlink } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { Store, compareFocused, type History } from '../src/storage.js';
import { Desk } from '../src/desk.js';
import { Scanner } from '../src/scanner.js';
import { Detector, root } from '../src/detectors.js';
import { makeTrigger, writeTrigger } from '../src/triggers.js';
import { historyReport, exitState } from '../src/reports.js';
import { makeConfig } from '../src/config.js';
import { BUILD } from '../src/build-info.js';
import type { Finding, ScanView } from '../src/types.js';
const pause=(ms:number)=>new Promise(r=>setTimeout(r,ms));
async function temp(prefix:string){const parent=process.env.EXPOSURE_DATA_DIR||path.join(root,'.cache');await mkdir(parent,{recursive:true});return mkdtemp(path.join(parent,prefix));}
const SEED='ExposureDesk/regression-2.5/incidents/1';
const token=(label:string,n=24)=>[...createHash('sha256').update(SEED+label).digest()].map(b=>'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'[b%62]).join('').slice(0,n);
const SITE='https://www.example.com',APP=SITE+'/assets/app.js';
const finding=(c:string,over:Partial<Finding>={}):Finding=>({id:c.slice(0,32),fingerprint:c.slice(0,32),correlation:c,category:'private-credential',provider:'Stripe',rule:'stripe-secret',severity:'high',confidence:'high',reasons:[],masked:'[redacted: 32 characters]',validity:'unverified',impact:'',remediation:'',occurrences:[{url:APP,chain:[SITE+'/'],transformations:[],excerpt:'[redacted]',evidence:'Public response',exposure:'public-response',environment:'production'}],...over} as Finding);
const view=(over:Partial<ScanView>):ScanView=>({schema:'exposure-scan/1',id:randomUUID(),name:'www.example.com',state:'completed',startedAt:new Date().toISOString(),endedAt:new Date().toISOString(),elapsedMs:1,config:makeConfig({urls:[SITE+'/']}),build:BUILD,counts:{resources:2,scanned:2,blocked:0,bytes:10,pending:0,findings:0},engines:{websiteRules:'website/2.5.0',gitleaks:'8.30.1',ruleDigest:'d',companyRules:'none'},findings:[],resources:[{url:SITE+'/',status:'scanned',code:200,bytes:5,chain:[],kind:'page',analysis:'analyzed',analyzers:{directText:{status:'inspected'}}},{url:APP,status:'scanned',code:200,bytes:5,chain:[SITE+'/'],kind:'script',analysis:'analyzed',analyzers:{directText:{status:'inspected'}}}],limitations:[],launch:{trigger:'manual',requestedAt:new Date().toISOString()},analysis:{origins:{},interruptions:{},backlog:{items:0,bytes:0,resumed:0,deferred:0,dropped:0},note:''},requestProfile:{headerProfile:'v2',staticUserAgent:null,acceptLanguage:'en-US,en;q=0.9',browserLocale:'en-US',browserTimezone:'UTC',referrer:'x',egress:'x'},...over} as ScanView);
let clock=Date.parse('2026-09-01T00:00:00Z');const stamp=(v:ScanView)=>{clock+=3600000;v.startedAt=v.endedAt=new Date(clock).toISOString();return v;};

test('reviews merge: feedback keeps the review status, status changes keep suppressions, and a legacy “removed” is only a removal report (D8, D9, D11)',async()=>{
  const dir=await temp('incidents-review-');try{const st=await new Store(dir,true).init(),p=await st.project({urls:[SITE+'/']},true),c='c'.repeat(64),f=finding(c),future=new Date(Date.now()+86400000).toISOString();
    await st.review(p.id,f,{status:'reviewing'});await st.review(p.id,f,{reason:'Owner reviewed this synthetic value',expires:future});await st.feedback(p.id,f,'false-positive','Synthetic fixture value',future);
    assert.equal(st.reviews[p.id][c].status,'reviewing','feedback keeps status (D8)');assert.equal(f.remediationStatus,'reviewing');assert.ok(f.suppression);
    await st.review(p.id,f,{status:'open',clear:['removalReported']});assert.ok(st.reviews[p.id][c].reason,'a status change keeps an active suppression (D9)');
    await st.feedback(p.id,f,'confirmed','Owner confirmed this is real');assert.equal(st.reviews[p.id][c].reason,undefined,'confirming clears a false-positive suppression');assert.equal(st.reviews[p.id][c].status,'open');
    const legacy=finding('d'.repeat(64));st.reviews[p.id]['d'.repeat(64)]={reviewedAt:'2026-01-01T00:00:00.000Z',status:'removed'};st.applyReviews(p.id,[legacy]);
    assert.match(legacy.lifecycle!.removalReported!.note,/Legacy 2\.4/);assert.equal(legacy.lifecycle!.revocation,undefined,'never a revocation');assert.equal(legacy.remediationStatus,'removed');
    await st.ownerRecord(p.id,legacy,{environment:'test',restrictions:'restricted',permissionsNote:'read-only key per owner'});assert.equal(legacy.ownerRecord!.source,'owner-statement');assert.equal(legacy.assessment,undefined);assert.equal(legacy.priority!.level,'review');assert.ok(legacy.priority!.basis.some(b=>/owner/.test(b)));
    await assert.rejects(st.ownerRecord(p.id,legacy,{permissionsNote:'x'.repeat(501)}));await assert.rejects(st.lifecycle(p.id,legacy,'delete-everything',''));
    st.close();
  }finally{await rm(dir,{recursive:true,force:true});}
});

test('focused rescans can establish “not observed” at the affected URL; “removed from website” still needs a comparable full scan; incomplete or partial evidence stays uncertain (D10)',async()=>{
  const dir=await temp('incidents-rescan-');try{const st=await new Store(dir,true).init(),p=await st.project({urls:[SITE+'/']},true),c='e'.repeat(64);
    const first=await st.record(p.id,stamp(view({findings:[finding(c)],counts:{resources:2,scanned:2,blocked:0,bytes:10,pending:0,findings:1}})));await st.updateLifecycle(p.id,first.view);assert.equal(st.reviews[p.id][c].website!.state,'observed');
    const focused=stamp(view({launch:{trigger:'rescan',requestedAt:'x',previousRunId:first.view.id,relation:'rescan'},config:makeConfig({urls:[APP]}),resources:[{url:APP,status:'http-error',code:404,bytes:0,chain:[],kind:'page',analysis:'skipped'}]}));
    const fr=await st.record(p.id,focused);assert.deepEqual(compareFocused(first,fr,c),{kind:'focused',comparable:true,outcome:'not-observed',reasons:[]},'404 at the affected URL');await st.updateLifecycle(p.id,fr.view);
    assert.equal(st.reviews[p.id][c].rescan!.outcome,'not-observed');assert.equal(st.reviews[p.id][c].website!.state,'uncertain','a focused rescan alone does not establish removal from the website');
    const partial=await st.record(p.id,stamp(view({resources:[{url:APP,status:'scanned',code:200,bytes:5,chain:[],kind:'script',analysis:'analyzed',partial:true,analyzers:{directText:{status:'incomplete'}}}]})));assert.equal(compareFocused(first,partial,c).outcome,'uncertain');
    const incomplete=await st.record(p.id,stamp(view({state:'incomplete'})));assert.equal(compareFocused(first,incomplete,c).outcome,'uncertain');
    const full=await st.record(p.id,stamp(view({})));await st.updateLifecycle(p.id,full.view);assert.equal(st.reviews[p.id][c].website!.state,'not-observed','a comparable full scan inspected the affected URL and did not observe the value');
    const f=finding(c);st.applyReviews(p.id,[f]);assert.equal(f.lifecycle!.website!.state,'not-observed');assert.equal(f.lifecycle!.rescan!.kind,'full');
    st.close();
  }finally{await rm(dir,{recursive:true,force:true});}
});

test('masked alerts for new urgent, reappeared and post-revocation findings persist across restart and never contain values; acknowledgement works (D12)',async()=>{
  const dir=await temp('incidents-alerts-');try{let st=await new Store(dir,true).init();const p=await st.project({urls:[SITE+'/']},true),c='a'.repeat(64),secret='sk_live_'+token('alert');
    const clean=await st.record(p.id,stamp(view({})));await st.updateLifecycle(p.id,clean.view);
    const f=finding(c,{priority:{level:'urgent',basis:[],version:'priority/1'},exposureGroup:'payments',impacts:[{kind:'payment-asset-access',text:'x'}]});const leak=await st.record(p.id,stamp(view({findings:[f]})));const alerts=await st.updateLifecycle(p.id,leak.view);assert.deepEqual(alerts.map(a=>a.kind),['new-urgent']);assert.equal(alerts[0].location,APP);assert.equal(alerts[0].correlation,c.slice(0,8));
    await st.lifecycle(p.id,f,'report-removed','Removed from the bundle');const gone=await st.record(p.id,stamp(view({})));await st.updateLifecycle(p.id,gone.view);
    const back=await st.record(p.id,stamp(view({findings:[finding(c,{priority:{level:'urgent',basis:[],version:'priority/1'}})]})));assert.deepEqual((await st.updateLifecycle(p.id,back.view)).map(a=>a.kind),['reappeared']);
    await st.lifecycle(p.id,f,'record-revocation','Rolled in the provider console','replaced');const again=await st.record(p.id,stamp(view({findings:[finding(c)]})));assert.deepEqual((await st.updateLifecycle(p.id,again.view)).map(a=>a.kind),['published-after-revocation']);
    st.close();st=await new Store(dir,true).init();assert.equal(st.alerts.length,3,'alerts survive a restart');const workspace=await readFile(path.join(dir,'workspace.json'),'utf8');assert.ok(!workspace.includes(secret),'no values in the workspace');assert.ok(!JSON.stringify(st.alerts).includes(c),'alerts carry only an 8-character correlation prefix');
    await st.acknowledge([st.alerts[0].id]);assert.ok(st.alerts[0].acknowledgedAt);assert.ok(!st.alerts[1].acknowledgedAt);await st.acknowledge('all');assert.ok(st.alerts.every(a=>a.acknowledgedAt));await assert.rejects(st.acknowledge('everything'));
    st.close();
  }finally{await rm(dir,{recursive:true,force:true});}
});

test('affected assets distinguish the current deployment from a previous deployment reached only by replay',{timeout:60000},async()=>{
  const current='sk_live_'+token('current'),old='sk_live_'+token('old');const server=http.createServer((req,res)=>{const p=req.url||'/';res.writeHead(p==='/'?200:p==='/app.js'||p==='/old.js'?200:404,{'content-type':p.endsWith('.js')?'text/javascript':'text/html'});res.end(p==='/'?'<script src="/app.js"></script>':p==='/app.js'?`Stripe("${current}")`:p==='/old.js'?`Stripe("${old}")`:'missing');});
  await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));const origin=`http://127.0.0.1:${(server.address() as any).port}`;
  try{const s=new Scanner({urls:[origin+'/'],developmentFixtureOrigin:origin,staleAssetCheck:true,staleAssetUrls:[origin+'/old.js'],adjacentMaps:false,requestsPerSecond:20,browser:false,semanticAnalysis:false},{detector:new Detector('disabled')});const v=await s.run();
    const byValue=(value:string)=>v.findings.find(f=>s.evidence.reveal(f.id).value===value)!;assert.equal(byValue(current).assets![0].deployment,'current');assert.equal(byValue(old).assets![0].deployment,'previous-only');assert.ok(byValue(old).qualifiers!.includes('previous-deployment-only'));assert.equal(byValue(old).priority!.level,'urgent','a previous deployment that is still served stays urgent');s.dispose();
  }finally{await new Promise<void>(r=>{server.close(()=>r());server.closeAllConnections();});}
});

test('deployment triggers: opt-in, file-drop only, rate limited and coalesced; links, oversized, expired and unknown requests are rejected and removed; the CLI never touches history',{timeout:60000},async()=>{
  const dir=await temp('incidents-trigger-');const desk=new Desk(new Map(),()=>[]);try{desk.store=await new Store(dir,true).init();const st=desk.store,p=await st.project({urls:[SITE+'/']},true),triggers=path.join(dir,'triggers');
    const drop=async(over:Partial<Parameters<typeof makeTrigger>[0]>={},now=Date.now())=>writeTrigger(triggers,makeTrigger({projectId:p.id,...over},now));
    await drop({assets:[SITE+'/assets/app.1.js']});await desk.processTriggers();assert.equal(desk.queue.length,0,'no opt-in, no job');assert.equal(st.alerts.at(-1)!.kind,'trigger-rejected');assert.deepEqual(await readdir(triggers),[],'processed files are deleted');
    p.deploymentTrigger={enabled:true,minIntervalMinutes:10,maxPerDay:2,recent:[]};
    // Hold the queue so jobs stay queued (a running scan would need the network).
    (desk as any).pumping=true;
    await drop({assets:[SITE+'/assets/app.1.js'],label:'release 41'});await desk.processTriggers();assert.equal(desk.queue.length,1);const job=desk.queue[0];assert.equal(job.source,'deployment');assert.equal(job.trigger,'deployment');assert.equal(job.saveEvidence,false);assert.deepEqual(job.overrides!.staleAssetUrls,[SITE+'/assets/app.1.js']);assert.equal(job.label,'release 41');
    await drop({assets:[SITE+'/assets/app.2.js','https://cdn.thirdparty.example.net/x.js']});await desk.processTriggers();assert.equal(desk.queue.length,1,'a request while one is queued coalesces');assert.deepEqual(desk.queue[0].overrides!.staleAssetUrls,[SITE+'/assets/app.1.js',SITE+'/assets/app.2.js','https://cdn.thirdparty.example.net/x.js'],'the manifest grants no scope: out-of-scope URLs are refused by the transport at request time');
    job.state='completed';await drop();await desk.processTriggers();assert.equal(desk.queue.length,1,'minimum interval');assert.match(st.alerts.at(-1)!.text,/less than 10 minutes/);
    p.deploymentTrigger.lastTriggerAt=new Date(Date.now()-3600000).toISOString();p.deploymentTrigger.recent=[new Date().toISOString(),new Date().toISOString()];await drop();await desk.processTriggers();assert.match(st.alerts.at(-1)!.text,/per day/);
    await drop({},Date.now()-25*3600000);await desk.processTriggers();assert.equal(st.alerts.at(-1)!.kind,'trigger-expired');
    await writeTrigger(triggers,makeTrigger({projectId:randomUUID()}));await desk.processTriggers();assert.match(st.alerts.at(-1)!.text,/unknown project/);
    const big=randomUUID();await writeFile(path.join(triggers,big+'.json'),JSON.stringify({schema:'exposure-trigger/1',id:big,pad:'x'.repeat(70000)}));await desk.processTriggers();assert.match(st.alerts.at(-1)!.text,/64 KiB/);
    const original=await drop();const extra=path.join(dir,'linked.json');await link(path.join(triggers,original.id+'.json'),extra);await desk.processTriggers();assert.match(st.alerts.at(-1)!.text,/singly linked/);await rm(extra,{force:true});
    try{const target=path.join(dir,'elsewhere.json');await writeFile(target,'{}');const l=randomUUID();await symlink(target,path.join(triggers,l+'.json'));await desk.processTriggers();assert.match(st.alerts.at(-1)!.text,/regular/);}catch(e:any){if(!['EPERM','EACCES'].includes(e?.code))throw e;}
    assert.deepEqual((await readdir(triggers)).filter(n=>n.endsWith('.json')),[],'every handled file is removed');
    // The CLI writes one request file and reads the workspace read-only.
    (desk as any).pumping=false;await st.save();const before=await readFile(path.join(dir,'workspace.json'),'utf8');const cli=(args:string[])=>spawnSync(process.execPath,[path.join(root,'dist/src/cli.js'),'trigger','--data-dir',dir,...args],{encoding:'utf8',windowsHide:true});
    const ok=cli(['--project',p.id,'--label','release 42','--delay','600']);assert.equal(ok.status,0,ok.stderr);assert.equal((await readdir(triggers)).length,1);assert.equal(await readFile(path.join(dir,'workspace.json'),'utf8'),before,'the CLI never rewrites the workspace');
    const bad=cli(['--project',p.id,'--label','sk_live_'+token('label')]);assert.equal(bad.status,2);assert.match(bad.stderr,/credential/);assert.equal(cli(['--project',randomUUID()]).status,2);
    await desk.processTriggers();assert.equal((await readdir(triggers)).length,1,'a delayed request waits for its time');
  }finally{(desk as any).pumping=false;desk.cancelQueue();await desk.close();await rm(dir,{recursive:true,force:true});}
});

test('reports carry priority, impacts, qualifiers, lifecycle and the correlation fingerprint without values; --fail-on selects the exit policy',()=>{
  const c='f'.repeat(64),f=finding(c,{priority:{level:'urgent',basis:['private credential, high detection confidence'],version:'priority/1'},impacts:[{kind:'payment-asset-access',text:'Possible payment operations.'}],qualifiers:['previous-deployment-only'],lifecycle:{website:{state:'uncertain',basis:'focused rescan'},rescan:{scanId:'s',at:'t',kind:'focused',comparable:true,outcome:'not-observed',reasons:[]}},assets:[{url:APP,deployment:'previous-only',status:200}]});
  const v=view({findings:[f]}),html=historyReport(v,'html'),sarif=JSON.parse(historyReport(v,'sarif'));
  assert.match(html,/Priority urgent/);assert.match(html,/payment-asset-access/);assert.match(html,/previous-only/);assert.match(html,/Lifecycle: website uncertain/);assert.match(html,/Owner statements are not verified/);
  const r=sarif.runs[0].results[0];assert.equal(r.partialFingerprints['exposureDesk/correlation/v2'],c);assert.equal(r.properties.priority.level,'urgent');assert.equal(r.properties.lifecycle.rescan.outcome,'not-observed');
  const scan=(state:string,list:Partial<Finding>[])=>({state,evidence:{findings:new Map(list.map((x,i)=>[String(i),x]))}}) as any;
  assert.equal(exitState(scan('completed',[{category:'private-credential',priority:{level:'high',basis:[],version:'priority/1'}}])),1);assert.equal(exitState(scan('completed',[{category:'private-credential',priority:{level:'high',basis:[],version:'priority/1'}}]),'urgent'),0);assert.equal(exitState(scan('completed',[{category:'private-credential',priority:{level:'urgent',basis:[],version:'priority/1'}}]),'urgent'),1);assert.equal(exitState(scan('completed',[{category:'private-credential'}]),'never'),0);assert.equal(exitState(scan('incomplete',[]),'never'),2);
});
