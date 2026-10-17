import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {mkdtemp,mkdir,readdir,readFile,rm,writeFile} from 'node:fs/promises';
import {Detector,AnalysisInterrupted,ENGINE_RUNTIME_ISSUE,root,type AnalysisScope,type AnalysisFailureContext} from '../src/detectors.js';
import {FifoBudget} from '../src/fifo-budget.js';
import {Scanner} from '../src/scanner.js';
import {scanArtifacts} from '../src/artifact-scan.js';
import {privateDirectory} from '../src/local-files.js';
import {startDashboard} from '../src/dashboard.js';
import {trigger} from '../src/cli/commands/trigger.js';
import {Args} from '../src/cli/args.js';
import {analysisProcesses,type AnalysisChildInfo} from '../src/analysis-process.js';
import {syntheticBundle} from './large-bundle.js';
/** 2.8.0 w1-budget: a shared `Detector` reports to the scan whose call it is running. Every inspection carries its scan's scope (memory, signal, limits, failures), so scans that share one detector
 * (a mass run) each get only their own limits, failures and cancellation however their calls interleave. Main-thread callers stay bounded. Local only: nothing is contacted; keys are synthetic. */
const KiB=1024,BIG={cores:16,freeMemoryMb:32768};
const fill=(size:number,unit:string,tail='')=>unit.repeat(Math.floor((size-tail.length)/unit.length))+tail;
const synthetic=(seed:string)=>'sk-proj-'+createHash('sha512').update('ExposureDesk/w1-budget/'+seed).digest('base64url').slice(0,64).replace(/[-_]/g,'A');
/** A text over 128 KiB (the large-text path) ending in one synthetic key. */
const large=(seed:string,marker='')=>{const value=synthetic(seed);return {value,text:fill(300*KiB,'a;',`\n${marker}var k="${value}";`)};};
// A synthetic bundle whose key is split in two literals joined at the client call: only the whole-document analysis reconstructs it.
const bundle=(seed:string)=>{const value=synthetic(seed),rest=value.slice('sk-proj-'.length);
  return {value,text:syntheticBundle({seed:'ExposureDesk/w1-budget/'+seed,targetBytes:1252570}).text.replace('\n//# sourceMapping',`\nconst head="sk-proj-";const rest=${JSON.stringify(rest)};const openai=new OpenAI({apiKey:head+rest});\n//# sourceMapping`)};};
const alive=(pid:number)=>{try{process.kill(pid,0);return true;}catch(e){return (e as NodeJS.ErrnoException).code==='EPERM';}};
const settle=async(until:()=>boolean,ms=20000)=>{for(const end=Date.now()+ms;!until()&&Date.now()<end;)await new Promise(r=>setTimeout(r,10));assert.ok(until(),'condition reached');};
function watchSpawns(){const seen:AnalysisChildInfo[]=[],on=(info:AnalysisChildInfo)=>{seen.push(info);};analysisProcesses.events.on('spawn',on);return {seen,stop(){analysisProcesses.events.off('spawn',on);}};}
const started=(seen:AnalysisChildInfo[],n:number)=>()=>seen.filter(i=>i.role==='detector'&&i.startupMs!==undefined).length>=n;
/** One scan's scope with recorders. */
function recorder(memory?:FifoBudget,signal?:AnalysisScope['signal']){
  const limits:string[]=[],failures:{code:string;context?:AnalysisFailureContext}[]=[];
  const scope:AnalysisScope={memory,signal,onLimit:detail=>limits.push(detail),onFailure:(code,context)=>failures.push({code,context})};return {scope,limits,failures};
}
/** A detector whose offline engine is a local stand-in, so results are cached and failures can be routed without the binary: text containing `fail:` fails, text containing `hold:` waits for its scope's signal. */
function engineStandIn(d:Detector){
  const calls:string[]=[],holding=new Set<string>();(d as any).version='w1-budget-stand-in';
  (d as any).run=async(_args:string[],text:string,s:{signal():AbortSignal|undefined})=>{
    calls.push(text);
    if(text.includes('fail:'))throw new Error('synthetic engine failure');
    if(text.includes('hold:')){const signal=s.signal()!;holding.add(text);await new Promise<void>((_resolve,reject)=>{const stop=()=>reject(new AnalysisInterrupted(undefined,'engine'));if(signal.aborted)stop();else signal.addEventListener('abort',stop,{once:true});});}
    return '[]';
  };
  return {calls,holding};
}
const PROJECT='11111111-1111-4111-8111-111111111111';
const codes=(r:{failures:{code:string}[]})=>r.failures.map(f=>f.code);
const scanConfig={urls:['http://127.0.0.1:9/'],developmentFixtureOrigin:'http://127.0.0.1:9',coverage:'quick' as const,traffic:'normal' as const};
const gapCodes=(s:Scanner)=>s.limitations.map(g=>g.code);

test('two scopes interleaved on one detector each receive only their own limits, budget and results; the detector defaults are never used',{timeout:120000},async()=>{
  const d=new Detector('disabled'),stray:string[]=[],gone=new AbortController();d.onLimit=x=>stray.push('limit '+x);d.onFailure=c=>stray.push('failure '+c);
  // An explicit scope never falls back to the detector's own signal: an aborted default must not cancel it.
  gone.abort();d.signal=gone.signal;d.heapEstimate=(_text,whole)=>whole?96:48;
  const a=recorder(new FifoBudget(64)),b=recorder(new FifoBudget(256)),c=recorder(new FifoBudget(256)),ta=large('scope-a'),tb=large('scope-b'),kc=synthetic('scope-c');
  const [ra,rb,rc]=await Promise.all([d.inspect(ta.text,a.scope),d.inspect(tb.text,b.scope),d.inspect(`var k="${kc}";`,c.scope)]);
  assert.ok(ra.some(x=>x.value===ta.value)&&!ra.some(x=>x.value===tb.value||x.value===kc),'scope A got its own results');
  assert.ok(rb.some(x=>x.value===tb.value)&&!rb.some(x=>x.value===ta.value||x.value===kc),'scope B got its own results');
  assert.ok(rc.some(x=>x.value===kc)&&rc.length===1,'scope C got its own result');
  const memoryLimit=/exceeds the analysis memory setting \(64 MiB\)/,windows=/65536-character windows/;
  assert.ok(a.limits.some(l=>memoryLimit.test(l))&&a.limits.some(l=>windows.test(l)),a.limits.join('\n'));
  assert.ok(b.limits.some(l=>windows.test(l))&&!b.limits.some(l=>/analysis memory setting/.test(l)),'B states its own window limit only: '+b.limits.join('\n'));
  assert.deepEqual(c.limits,[]);assert.deepEqual([...a.failures,...b.failures,...c.failures],[]);assert.deepEqual(stray,[],'the detector defaults received nothing');
  assert.ok([...d.inspectionLimits].some(l=>memoryLimit.test(l)),'the detector-wide diagnostics still list every limit');
  const [ma,mb,mc]=[a.scope.memory!,b.scope.memory!,c.scope.memory!];
  assert.ok(ma.peak>0&&ma.peak<=64&&mb.peak>64,`each large text held its heap from its own scope (A ${ma.peak}, B ${mb.peak})`);assert.equal(mc.peak,0);assert.equal(d.analysisMemory.peak,0);
  assert.equal(ma.used+mb.used,0);
});

test('the same text inspected at once by two scopes is analysed for each (each states its limits); calls of one scope are still shared',{timeout:120000},async()=>{
  const d=new Detector('disabled'),watch=watchSpawns(),t=large('same-text');d.heapEstimate=()=>48;
  const a=recorder(new FifoBudget(256)),b=recorder(new FifoBudget(256));
  try{
    const results=await Promise.all([d.inspect(t.text,a.scope),d.inspect(t.text,a.scope),d.inspect(t.text,b.scope)]);
    for(const r of results)assert.ok(r.some(x=>x.value===t.value));
  }finally{watch.stop();}
  assert.equal(watch.seen.filter(i=>i.role==='detector').length,2,'one analysis process per scope: the second call of scope A shared the first');
  assert.equal(a.limits.filter(l=>/65536-character windows/.test(l)).length,1);assert.equal(b.limits.filter(l=>/65536-character windows/.test(l)).length,1);
});

test('cancelling one scope interrupts only its own large-text analysis: the other scope on the same detector completes, and both budgets are returned',{timeout:120000},async()=>{
  const d=new Detector('disabled'),watch=watchSpawns(),ca=new AbortController(),cb=new AbortController();
  // A reads its signal through a function (a scan's current origin turn); B passes the signal itself.
  const a=recorder(new FifoBudget(256),()=>ca.signal),b=recorder(new FifoBudget(256),cb.signal),ba=bundle('cancel-a'),bb=bundle('cancel-b');
  try{
    const runA=d.inspect(ba.text,a.scope),runB=d.inspect(bb.text,b.scope);runA.catch(()=>{});
    await settle(started(watch.seen,2));ca.abort();
    await assert.rejects(runA,(e:unknown)=>e instanceof AnalysisInterrupted&&e.phase==='direct');
    const found=await runB;assert.ok(found.some(x=>x.value===bb.value),'the other scope kept its whole-document finding');
    assert.ok(!cb.signal.aborted);assert.equal(d.signal,undefined,'the detector default signal is untouched');
    const [pa]=watch.seen.filter(i=>i.role==='detector');await settle(()=>!alive(pa.pid!));
  }finally{watch.stop();}
  assert.equal(a.scope.memory!.used,0);assert.equal(b.scope.memory!.used,0);assert.deepEqual([...a.failures,...b.failures],[]);assert.equal((d as any).directLanes.used,0);
});

test('a cached result is returned to another scope with the limits of its inspection stated once to that scope',{timeout:120000},async()=>{
  const d=new Detector('disabled'),engine=engineStandIn(d),watch=watchSpawns(),t=large('cached');d.heapEstimate=()=>48;
  const a=recorder(new FifoBudget(256)),b=recorder(new FifoBudget(256));
  try{
    const first=await d.inspect(t.text,a.scope);assert.ok(first.some(x=>x.value===t.value));const stated=[...a.limits];assert.ok(stated.some(l=>/65536-character windows/.test(l)));
    const hits=d.cacheHits,calls=engine.calls.length,again=await d.inspect(t.text,b.scope);
    assert.equal(again,first);assert.equal(d.cacheHits,hits+1);assert.equal(engine.calls.length,calls,'served from the cache');assert.deepEqual(b.limits,stated,'the other scope is told the limits of the cached inspection');
    await d.inspect(t.text,a.scope);await d.inspect(t.text,b.scope);assert.deepEqual(a.limits,stated,'no repeat to the scope that inspected it');assert.deepEqual(b.limits,stated,'and only once to the other');
  }finally{watch.stop();}
  assert.equal(watch.seen.filter(i=>i.role==='detector').length,1);
});

test('engine failures and interruptions reach only the scope whose call failed, with its request context; a failure is not cached and is not a setup issue',{timeout:60000},async()=>{
  const d=new Detector('disabled'),engine=engineStandIn(d),stray:string[]=[],ca=new AbortController(),cc=new AbortController();d.onFailure=c=>stray.push(c);
  const a=recorder(undefined,ca.signal),b=recorder(),c=recorder(undefined,cc.signal),ka=synthetic('fail-a'),kb=synthetic('fail-b'),kc=synthetic('hold-c');
  const metrics={engineMs:0,cacheHits:0,engineCalls:0,failures:new Set<string>(),url:'http://127.0.0.1:9/a.js',attemptId:7};
  const runA=d.measure(metrics,()=>d.inspect(`// fail:\nvar k="${ka}";`,a.scope)),runB=d.inspect(`var k="${kb}";`,b.scope),runC=d.inspect(`// hold:\nvar k="${kc}";`,c.scope);runC.catch(()=>{});
  await settle(()=>engine.holding.size>0);cc.abort();
  const [ra,rb]=await Promise.all([runA,runB]);await assert.rejects(runC,(e:unknown)=>e instanceof AnalysisInterrupted);
  assert.ok(ra.some(x=>x.value===ka),'direct evidence is kept when the engine fails');assert.ok(rb.some(x=>x.value===kb));
  assert.deepEqual(a.failures.map(f=>f.code),['engine-inspection-failure']);
  assert.equal(a.failures[0].context?.url,'http://127.0.0.1:9/a.js');assert.equal(a.failures[0].context?.attemptId,7);assert.equal(a.failures[0].context?.cause?.phase,'engine');assert.ok(metrics.failures.has('engine-inspection-failure'));
  assert.deepEqual(c.failures.map(f=>f.code),['engine-cancelled']);assert.equal(c.failures[0].context?.cause?.kind,'user-cancelled');assert.equal(c.failures[0].context?.url,undefined,'C ran outside A\'s request context');
  assert.deepEqual(b.failures,[]);assert.deepEqual(stray,[]);assert.ok(!ca.signal.aborted);
  assert.ok(d.issues.includes(ENGINE_RUNTIME_ISSUE)&&d.inspectionFailures.has('engine-inspection-failure'),'detector-wide diagnostics keep the failure');assert.ok(!d.setupIssues.includes(ENGINE_RUNTIME_ISSUE),'a scan starting later does not inherit it');
  const calls=engine.calls.length;await d.inspect(`var k="${kb}";`,b.scope);assert.equal(engine.calls.length,calls,'the successful result was cached');
  await d.inspect(`// fail:\nvar k="${ka}";`,b.scope);assert.ok(engine.calls.length>calls,'the failed result was not cached');assert.deepEqual(codes(b),['engine-inspection-failure'],'a failure of B\'s own call reaches B');assert.equal(a.failures.length,1);
});

test('with the pinned offline engine, cancelling one scope mid-engine reports engine-cancelled to that scope only; the other scope completes with no failure',{timeout:60000},async t=>{
  const d=new Detector();await d.init();if(d.version==='unavailable'){t.skip('pinned offline engine not present');return;}
  const ca=new AbortController(),a=recorder(undefined,ca.signal),b=recorder(),ka=synthetic('engine-a'),kb=synthetic('engine-b'),run=(d as any).run.bind(d);let began=0;
  (d as any).run=(args:string[],text:string,s:unknown)=>{const job=run(args,text,s);if(text.includes('abort-me:')){began++;setImmediate(()=>ca.abort());}return job;};
  // Each text carries a kept engine rule's keyword (ghp_, with no token after it) so the engine's own keyword prefilter lets it reach the engine (engineKeywordGate, w5-fix).
  const runA=d.inspect(`// abort-me: ghp_\nvar k="${ka}";`,a.scope),runB=d.inspect(`// ghp_\nvar k="${kb}";`,b.scope);runA.catch(()=>{});
  await assert.rejects(runA,(e:unknown)=>e instanceof AnalysisInterrupted);const rb=await runB;
  assert.ok(began>0,'scope A reached the engine');assert.deepEqual(codes(a),['engine-cancelled']);assert.equal(a.failures[0].context?.cause?.phase,'engine');
  assert.ok(rb.some(x=>x.value===kb));assert.deepEqual(b.failures,[]);assert.equal(d.inspectionFailures.size,0,'a cancellation is not an engine failure');assert.ok(!d.issues.includes(ENGINE_RUNTIME_ISSUE));
});

test('two scans sharing one detector: limits, request-preflight failures and cancellation land only in the scan that made the call',{timeout:180000},async()=>{
  const d=new Detector('disabled'),s1=new Scanner(scanConfig,{detector:d,computer:BIG}),s2=new Scanner(scanConfig,{detector:d,computer:BIG}),watch=watchSpawns();
  try{
    assert.equal(d.onLimit,undefined);assert.equal(d.onFailure,undefined);assert.equal(d.signalProvider,undefined,'a supplied detector keeps its defaults: the last scan constructed does not take it over');
    // Interleaved inspections: only s1's text is large.
    const t1=large('scan-1'),k2=synthetic('scan-2');
    await Promise.all([s1.evidence.inspect(t1.text,'http://127.0.0.1:9/one.js',['test'],'Synthetic local text'),s2.evidence.inspect(`var k="${k2}";`,'http://127.0.0.1:9/two.js',['test'],'Synthetic local text')]);
    assert.ok(gapCodes(s1).includes('decoded-inspection-limit'),gapCodes(s1).join());assert.ok(!gapCodes(s2).includes('decoded-inspection-limit'),'the other scan states no limit of s1: '+gapCodes(s2).join());
    const value=(s:Scanner)=>[...s.evidence.findings.values()].map(f=>s.evidence.reveal(f.id).value);
    assert.ok(value(s1).includes(t1.value)&&!value(s1).includes(k2));assert.ok(value(s2).includes(k2)&&!value(s2).includes(t1.value));
    // The request preflight screens supplied data through the scan's own scope (transport hook).
    engineStandIn(d);await s2.transport.preflight('http://127.0.0.1:9/fail:/check').catch(()=>{});
    assert.ok(gapCodes(s2).includes('engine-inspection-failure'),gapCodes(s2).join());assert.ok(!gapCodes(s1).includes('engine-inspection-failure'));
    assert.deepEqual([...s2.engineFailures],['engine-inspection-failure']);assert.equal(s1.engineFailures.size,0);
    // Cancelling one scan stops only its own analysis.
    const b1=bundle('scan-cancel-1'),b2=bundle('scan-cancel-2'),spawned=watch.seen.length;
    const run1=s1.evidence.inspect(b1.text,'http://127.0.0.1:9/b1.js',['test'],'Synthetic local text'),run2=s2.evidence.inspect(b2.text,'http://127.0.0.1:9/b2.js',['test'],'Synthetic local text');run1.catch(()=>{});
    await settle(()=>watch.seen.slice(spawned).filter(i=>i.role==='detector'&&i.startupMs!==undefined).length>=2);s1.cancel();
    await assert.rejects(run1,(e:unknown)=>e instanceof AnalysisInterrupted);await run2;
    assert.ok(!s2.transport.signal.aborted);assert.ok(value(s2).includes(b2.value),'the other scan kept its whole-document finding');assert.ok(!value(s1).includes(b1.value));
    assert.equal(s1.analysisMemory.used+s2.analysisMemory.used,0);assert.equal(d.analysisMemory.peak,0);
  }finally{watch.stop();s1.dispose();s2.dispose();}
});

test('an artifact scan on a shared detector states only its own engine failures, not another scan\'s',{timeout:60000},async()=>{
  const d=new Detector('disabled');engineStandIn(d);d.issues.push(ENGINE_RUNTIME_ISSUE);// as left by another scan's failed call
  const unavailable=(s:Scanner)=>s.view().limitations.filter(g=>g.code==='detector-unavailable').map(g=>g.detail);
  const clean=await privateDirectory('w1-budget-artifacts-',true),failing=await privateDirectory('w1-budget-artifacts-',true);
  try{
    await writeFile(path.join(clean,'config.js'),`var k="${synthetic('artifact-clean')}";`);await writeFile(path.join(failing,'config.js'),`// fail:\nvar k="${synthetic('artifact-fail')}";`);
    const ok=await scanArtifacts(clean,{detector:d});try{assert.deepEqual(unavailable(ok),[]);assert.equal(ok.engineFailures.size,0);}finally{ok.dispose();}
    const bad=await scanArtifacts(failing,{detector:d});try{assert.deepEqual(unavailable(bad),[ENGINE_RUNTIME_ISSUE]);assert.ok(bad.engineFailures.has('engine-inspection-failure'));}finally{bad.dispose();}
  }finally{await rm(clean,{recursive:true,force:true});await rm(failing,{recursive:true,force:true});}
});

test('no main-thread caller outside the detector uses the unbounded synchronous inspection',async()=>{
  const src=path.join(root,'src'),offenders:string[]=[];
  for(const entry of await readdir(src,{recursive:true})){const file=String(entry);if(!file.endsWith('.ts')||['detectors.ts','detector-worker.ts'].includes(path.basename(file)))continue;if((await readFile(path.join(src,file),'utf8')).includes('inspectSync('))offenders.push(file);}
  assert.deepEqual(offenders,[]);
});

test('trigger labels: a credential-bearing label is refused, a label over the 80-character limit is refused by its length, a normal label is written',{timeout:60000},async()=>{
  const dir=await mkdtemp(path.join(os.tmpdir(),'w1-budget-trigger-')),errors:string[]=[],logs:string[]=[],error=console.error,log=console.log,exit=process.exitCode;
  await mkdir(dir,{recursive:true});
  await writeFile(path.join(dir,'workspace.json'),JSON.stringify({projects:[{id:PROJECT,config:{name:'Local fixture',urls:['http://127.0.0.1:9/'],developmentFixtureOrigin:'http://127.0.0.1:9'},deploymentTrigger:{enabled:true}}]}));
  const run=async(label:string)=>{errors.length=0;logs.length=0;process.exitCode=undefined;await trigger(new Args(['trigger','--data-dir',dir,'--project',PROJECT,'--label',label]));return {errors:[...errors],logs:[...logs],code:process.exitCode as number|string|undefined};};
  console.error=(...m:unknown[])=>{errors.push(m.join(' '));};console.log=(...m:unknown[])=>{logs.push(m.join(' '));};
  try{
    const key=synthetic('label');
    const credential=`deploy ${key}`;assert.ok(credential.length<=80);
    const refused=await run(credential);assert.equal(refused.code,2);assert.match(refused.errors.join('\n'),/looks like it contains a credential/);
    const long=`${'release notes '.repeat(2)}${key}`;assert.ok(long.length>80);
    const tooLong=await run(long);assert.equal(tooLong.code,2);assert.match(tooLong.errors.join('\n'),/Labels are limited to 80 printable characters/);
    const fine=await run('release 2.8 build');assert.equal(fine.code,undefined,fine.errors.join('\n'));assert.match(fine.logs.join('\n'),/Deployment trigger queued/);
    assert.equal((await readdir(path.join(dir,'triggers'))).length,1,'only the normal label was written');
  }finally{console.error=error;console.log=log;process.exitCode=exit;await rm(dir,{recursive:true,force:true});}
});

test('project save: a credential-bearing seed URL is refused on the main thread without an analysis process; a normal seed is saved',{timeout:60000},async()=>{
  const dir=await privateDirectory('w1-budget-dashboard-',true),watch=watchSpawns();
  try{
    const app=await startDashboard({port:0,persistent:true,dataDir:dir,syntheticData:true});
    try{
      const login=await fetch(app.origin+'/api/login',{method:'POST',headers:{'Content-Type':'application/json',Origin:app.origin,'X-Dashboard-Request':'1'},body:JSON.stringify({token:app.token})}),cookie=login.headers.get('set-cookie')!.split(';')[0],{csrf}=await login.json() as any;
      const headers={'Content-Type':'application/json',Origin:app.origin,'X-Dashboard-Request':'1','X-CSRF-Token':csrf,Cookie:cookie};
      const save=(urls:string[])=>fetch(app.origin+'/api/projects/save',{method:'POST',headers,body:JSON.stringify({config:{name:'Local fixture',urls,developmentFixtureOrigin:'http://127.0.0.1:9'},authorized:true})});
      // The two seeds differ only in the query value, so the refusal is the credential check (the dashboard withholds raw error text).
      const saved=await save(['http://127.0.0.1:9/?key=release-notes']);assert.equal(saved.status,200,await saved.clone().text());assert.ok(((await saved.json()) as any).id);
      const refused=await save(['http://127.0.0.1:9/?key='+synthetic('seed')]);assert.equal(refused.status,400,await refused.clone().text());assert.match(await refused.text(),/Request rejected/);
      const workspace=await(await fetch(app.origin+'/api/workspace',{headers:{Cookie:cookie}})).json() as any;assert.equal(workspace.projects.length,1,'only the normal seed was saved');
    }finally{await app.close();}
  }finally{watch.stop();await rm(dir,{recursive:true,force:true});}
  assert.equal(watch.seen.length,0,'no analysis process was started');
});
