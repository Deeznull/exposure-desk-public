import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import path from 'node:path';
import {spawn,spawnSync} from 'node:child_process';
import {mkdir,mkdtemp,readFile,rm,writeFile} from 'node:fs/promises';
import {Detector,DISCARDED_ENGINE_RULE,engineKeywordGate,root} from '../src/detectors.js';
import {Evidence} from '../src/evidence.js';
import {Scanner} from '../src/scanner.js';
import {SemanticPool} from '../src/semantic.js';
import {OriginControl,TurnClock,splitRounded,type WorkUnit} from '../src/origin-control.js';
import {makeConfig} from '../src/config.js';
import {AnalysisDeferred,Transport} from '../src/transport.js';
import {programFromJson,PROGRAM_SCHEMA} from '../src/program/settings.js';
import {MemoryGate,massMemoryCeilingMb} from '../src/mass/memory-gate.js';
import {MassScheduler} from '../src/mass/scheduler.js';
import {ParseCollector,fullCollection,PARSE_COLLECT_BYTES,PARSE_COUNT_MIN_BYTES} from '../src/mass/parse-collector.js';
import {synthetic} from '../src/fixture.js';
import type {Candidate} from '../src/types.js';
import {providerCases,negativeCases} from './provider-fixtures.js';
/** 2.8.0 w5-fix: mass scans scale and complete. A target's time limits are not charged while it only waits for the analysis capacity every target shares (reported as
 * sharedWaitMs instead); the offline engine is not started for an input its own keyword prefilter would run no rule on; one finding-triage worker and one parser pool serve
 * every target; a memory-aware admission gate keeps the scan process within 512 MiB (or an explicit program setting) by holding further targets back. Local only:
 * loopback fixtures on 127.0.0.1 and synthetic, non-functional keys. */
const cli=path.join(root,'dist/src/cli.js');
const sleep=(ms:number)=>new Promise<void>(r=>setTimeout(r,ms));
async function temp(prefix:string){const parent=process.env.EXPOSURE_DATA_DIR||path.join(root,'.cache');await mkdir(parent,{recursive:true});return mkdtemp(path.join(parent,prefix));}

// ---- The offline engine's keyword prefilter (engineKeywordGate) ----
const RULES=`title = "fixture rules"

[[rules]]
id = "alpha-token"
description = "Alpha"
regex = '''alpha_[a-z]{8}'''
keywords = ["alpha_"]

[[rules]]
id = "kilo-key"
regex = '''(kilo|ikey)[0-9]{4}'''
keywords = [
    "kilo",
    "IKEY",
]
[[rules.allowlists]]
regexes = ['''kilo0000''']
stopwords = ["alpha_"]

[[rules]]
id = "generic-api-key"
regex = '''key[0-9]{4}'''
keywords = ["key"]

[[rules]]
id = "pkcs12-file"
path = '''\\.p12$'''

[allowlist]
paths = ['''vendor/''']
`;
test('engine keyword gate: an input passes only with a kept rule\'s keyword, matched as the engine lowercases (Kelvin sign, dotted capital I); discarded rules\' keywords do not count',()=>{
  const gate=engineKeywordGate(RULES,id=>DISCARDED_ENGINE_RULE.test(id))!;assert.equal(typeof gate,'function');
  assert.equal(gate('x = "ALPHA_abcdefgh"'),true);assert.equal(gate('kilo1234'),true);assert.equal(gate('ikey'),true,'keywords are lowercased like the engine does');
  assert.equal(gate('Kilo1234'),true,'Go lowercases the Kelvin sign to k, so the engine would run the rule');
  assert.equal(gate('İKEY1234'),true,'Go lowercases U+0130 to i (JavaScript gives i plus a combining dot), so "İKEY" contains the keyword ikey');
  assert.equal(gate('a key4321 here'),false,'generic-api-key is discarded, so its keyword alone never needs the engine');
  assert.equal(engineKeywordGate(RULES)!('a key4321 here'),true,'without the discard its keyword counts');
  assert.equal(gate('nothing to see'),false);assert.equal(gate(''),false);
  assert.equal(gate('stopwords and paths are not keywords: vendor/x.p12'),false);
});
test('engine keyword gate: anything the reading cannot follow exactly means no gate (the engine always runs)',()=>{
  const rule=(body:string)=>`[[rules]]\nid = "x-token"\n${body}\n`;
  const unsafe:Record<string,string>={
    'pattern without keywords':rule(`regex = '''x[0-9]+'''`),
    'empty keyword list':rule(`regex = '''x[0-9]+'''\nkeywords = []`),
    'escaped keyword':rule(`regex = '''x[0-9]+'''\nkeywords = ["a\\\\b"]`),
    'non-ASCII keyword':rule(`regex = '''x[0-9]+'''\nkeywords = ["clé"]`),
    'unterminated keyword list':rule(`regex = '''x[0-9]+'''\nkeywords = ["a",`),
    'multi-line literal string':rule(`regex = '''x[0-9]+\n'''\nkeywords = ["x"]`),
    'multi-line basic string':rule(`description = """x"""\nregex = '''x'''\nkeywords = ["x"]`),
    'an extend table':`[extend]\nuseDefault = true\n\n`+rule(`regex = '''x'''\nkeywords = ["x"]`),
    'a rule without an id':`[[rules]]\nregex = '''x'''\nkeywords = ["x"]\n`,
    'a rule with two ids':`[[rules]]\nid = "a"\nid = "b"\nregex = '''x'''\nkeywords = ["x"]\n`,
    'only discarded rules':`[[rules]]\nid = "generic-api-key"\nregex = '''x'''\nkeywords = ["x"]\n`,
    'no rules':'title = "empty"\n',
  };
  for(const [name,toml] of Object.entries(unsafe))assert.equal(engineKeywordGate(toml,id=>DISCARDED_ENGINE_RULE.test(id)),undefined,name);
  assert.equal(typeof engineKeywordGate(rule(`regex = '''x'''\nkeywords = ["x"]`)),'function','the same rule with a keyword is followed');
});
test('engine keyword gate: the pinned rule file is followed, and an initialised detector uses it',async()=>{
  const gate=engineKeywordGate(await readFile(path.join(root,'rules/gitleaks-v8.30.1.toml'),'utf8'),id=>DISCARDED_ENGINE_RULE.test(id));
  assert.equal(typeof gate,'function','the pinned rules must stay readable by the gate, or every input starts the engine');
  assert.equal(gate!('const token="'+synthetic.github+'";'),true);assert.equal(gate!('const total=1+2;'),false);
  const d=new Detector();d.syntheticFixture=true;await d.init();
  if(d.version!=='unavailable')assert.equal(typeof (d as any).keywordGate,'function');
});
test('engine keyword gate changes no result: gated and ungated detectors with the pinned engine agree on the provider and negative corpus',{timeout:600000},async t=>{
  const gated=new Detector(),plain=new Detector();gated.syntheticFixture=true;plain.syntheticFixture=true;await gated.init();await plain.init();
  if(gated.version==='unavailable'){t.skip('the pinned engine is not available on this machine');return;}
  assert.equal(gated.version,'8.30.1');(plain as any).keywordGate=undefined;
  const texts=[...providerCases.map(c=>c.text),...negativeCases.map(c=>c.text),...Object.values(synthetic).map(v=>'const k='+JSON.stringify(v)+';'),'const total=1+2;','<p>plain page</p>'];
  const norm=(list:Candidate[])=>list.map(c=>JSON.stringify(c)).sort();
  const metrics=()=>({engineMs:0,cacheHits:0,engineCalls:0,engineScreened:0,failures:new Set<string>()}),gm=metrics(),pm=metrics();
  const [a,b]=await Promise.all([gated.measure(gm,()=>Promise.all(texts.map(x=>gated.inspect(x)))),plain.measure(pm,()=>Promise.all(texts.map(x=>plain.inspect(x))))]);
  for(let i=0;i<texts.length;i++)assert.deepEqual(norm(a[i]!),norm(b[i]!),'same candidates for corpus text '+i);
  assert.equal(gm.failures.size+pm.failures.size,0,'no engine failure on either side');
  assert.ok(gated.engineScreened>0,'some corpus inputs carry no keyword and were not given to the engine');assert.equal(plain.engineScreened,0);
  assert.ok(pm.engineCalls>gm.engineCalls,'the ungated detector started the engine for them');assert.ok(gm.engineCalls>0,'inputs with keywords still reach the engine');
});
test('engine keyword gate: a keyword-free input counts as screened, an input with a keyword still runs the engine and finds the key',async t=>{
  const d=new Detector();d.syntheticFixture=true;await d.init();if(d.version==='unavailable'){t.skip('the pinned engine is not available on this machine');return;}
  const metrics=()=>({engineMs:0,cacheHits:0,engineCalls:0,failures:new Set<string>()} as {engineMs:number;cacheHits:number;engineCalls:number;engineScreened?:number;failures:Set<string>});
  const quiet=metrics();await d.measure(quiet,()=>d.inspect('const total=1+2;'));assert.equal(quiet.engineCalls,0);assert.equal(quiet.engineScreened,1);
  const keyed=metrics(),found=await d.measure(keyed,()=>d.inspect('const token="'+synthetic.github+'";'));assert.equal(keyed.engineCalls,1);assert.ok(!keyed.engineScreened);
  assert.ok(found.some(c=>c.value===synthetic.github),'the GitHub key is found');
});

// ---- One triage worker and one parser pool per process ----
test('every scan in the process shares one finding-triage worker; each gets only its own results; the worker ends with its last client',{timeout:60000},async()=>{
  // In a process of its own (a script file: an --eval flag would pass to the worker thread): the suite runs every test file in one process (--test-isolation=none), where scans
  // that other files leave open are clients of the same worker.
  const evidence=JSON.stringify(new URL('../src/evidence.js',import.meta.url).href),detectors=JSON.stringify(new URL('../src/detectors.js',import.meta.url).href);
  const script=`import assert from 'node:assert/strict';const {Evidence}=await import(${evidence});const {Detector}=await import(${detectors});
  const a=new Evidence(new Detector('disabled')),b=new Evidence(new Detector('disabled'));a.startTriage(()=>assert.fail('the worker must run'));b.startTriage(()=>assert.fail('the worker must run'));
  const add=(e,value,url)=>e.add({value,original:value,index:0,rule:'test-credential',provider:'Test',category:'private-credential',confidence:'high',severity:'high',reasons:[],transformations:[]},value,url,[],'Unauthenticated HTTP response');
  try{
    const ia=add(a,'alpha-private-value','https://a.example.com'),ib=add(b,'bravo-private-value','https://b.example.com');
    await Promise.all([a.triage.flush(),b.triage.flush()]);
    assert.ok(a.triage.worker,'a worker thread ran');assert.equal(a.triage.worker,b.triage.worker,'one worker thread serves both scans');
    assert.equal(a.findings.get(ia).triage.category,'direct-leak');assert.equal(b.findings.get(ib).triage.category,'direct-leak');
    assert.equal(a.findings.size,1);assert.equal(b.findings.size,1);
    a.clear();assert.ok(b.triage.worker,'closing one scan keeps the worker for the other');
    const ib2=add(b,'charlie-private-value','https://b.example.com/config');await b.triage.flush();assert.equal(b.findings.get(ib2).triage.category,'direct-leak');
    b.clear();assert.equal(b.triage.worker,undefined,'the worker ends with its last client');
  }finally{a.clear();b.clear();}
  console.log('shared-triage-worker-ok');`;
  const dir=await temp('triage-worker-');
  try{
    await writeFile(path.join(dir,'shared-triage.mjs'),script);const child=spawnSync(process.execPath,[path.join(dir,'shared-triage.mjs')],{encoding:'utf8',timeout:50000,windowsHide:true});
    assert.equal(child.status,0,child.stderr);assert.match(child.stdout,/shared-triage-worker-ok/);
  }finally{await rm(dir,{recursive:true,force:true});}
});
test('a finding-triage worker that stops ends its use by every scan attached to it, with or without a batch in flight: each falls back to the scan process and reports it once (w5-fix)',{timeout:60000},async()=>{
  const a=new Evidence(new Detector('disabled')),b=new Evidence(new Detector('disabled'));let failedA=0,failedB=0;a.startTriage(()=>failedA++);b.startTriage(()=>failedB++);
  const add=(e:Evidence,value:string,url:string)=>e.add({value,original:value,index:0,rule:'test-credential',provider:'Test',category:'private-credential',confidence:'high',severity:'high',reasons:[],transformations:[]},value,url,[],'Unauthenticated HTTP response');
  try{
    const ia=add(a,'delta-private-value','https://a.example.com');await a.triage!.flush();assert.equal(a.findings.get(ia)!.triage!.category,'direct-leak');
    // a's batch is answered and b has sent none: neither has a batch in flight when the worker stops.
    const worker=a.triage!.worker;assert.ok(worker,'a worker thread ran');await worker.terminate();
    assert.equal(failedA,1,'a scan whose batch was answered falls back');assert.equal(failedB,1,'a scan with no batch yet falls back');
    const ib=add(b,'echo-private-value','https://b.example.com'),ia2=add(a,'foxtrot-private-value','https://a.example.com/config');await Promise.all([a.triage!.flush(),b.triage!.flush()]);
    assert.equal(b.findings.get(ib)!.triage!.category,'direct-leak');assert.equal(a.findings.get(ia2)!.triage!.category,'direct-leak');assert.equal(a.triage!.view().pending,0);assert.equal(b.triage!.view().pending,0);
    assert.equal(failedA,1);assert.equal(failedB,1);
  }finally{a.clear();b.clear();}
});
test('a scan given the mass run\'s shared parser pool leaves it running when disposed; a scan with its own pool ends it',async()=>{
  const pool=new SemanticPool(1,64);
  try{
    const shared=new Scanner({urls:['https://fixture.invalid']},{detector:new Detector('disabled'),semanticPool:pool});shared.dispose();assert.equal((pool as any).disposed,false);
    const own=new Scanner({urls:['https://fixture.invalid']},{detector:new Detector('disabled')}),ownPool=(own as any).pool as SemanticPool;assert.notEqual(ownPool,pool);own.dispose();assert.equal((ownPool as any).disposed,true);
  }finally{await pool.dispose();}
});

// ---- Clocks: shared-capacity waits are reported, not charged (mass mode) ----
test('mass mode: a website\'s clock does not run while its work only waits for shared analysis capacity; its own work keeps it running; the scan\'s clock pauses only when every open website does',async()=>{
  let now=1000;const c=makeConfig({urls:['https://one.invalid','https://two.invalid'],originMaxDurationMs:400}),control=new OriginControl(c,new AbortController().signal,()=>now);control.excludeSharedWaits=true;
  const one='https://one.invalid/',two='https://two.invalid/';
  try{
    await control.run(one,async()=>{
      const wait=control.sharedWait();assert.equal(control.projectPaused,true,'the only open website waits, so the scan\'s clock pauses too');
      now+=600;assert.equal(control.expired(one),false);assert.equal(control.remainingMs(one),400);wait();
      assert.equal(control.elapsed(one),0);assert.equal(control.projectPaused,false);
      const working=control.busy(),waiting=control.sharedWait();now+=100;waiting();working();
      assert.equal(control.elapsed(one),100,'a shared wait during the website\'s own work (a request) is charged');
      now+=50;assert.equal(control.elapsed(one),150,'time with no marked unit is charged');
    });
    control.run(two,()=>{});
    await control.run(one,async()=>{const wait=control.sharedWait();assert.equal(control.projectPaused,false,'another open website is not waiting, so the scan\'s clock runs');now+=100;wait();});
    assert.equal(control.projectExcludedMs(),600);
    const snaps=Object.fromEntries(control.snapshots().map(s=>[s.origin,s]));assert.equal(snaps['https://one.invalid']!.sharedWaitMs,700);assert.equal(snaps['https://two.invalid']!.sharedWaitMs,0);
    assert.equal(snaps['https://one.invalid']!.elapsedMs,150);
  }finally{control.cancel();}
  // Outside mass mode the marks do nothing: the same wait is charged and snapshots have no sharedWaitMs.
  now=1000;const plain=new OriginControl(c,new AbortController().signal,()=>now);
  try{await plain.run(one,async()=>{const wait=plain.sharedWait();now+=300;wait();});assert.equal(plain.elapsed(one),300);assert.equal(plain.projectExcludedMs(),0);assert.ok(!('sharedWaitMs' in plain.snapshots()[0]!));}finally{plain.cancel();}
});
test('mass mode: an analysis turn\'s clock charges only its own work, and a wait inside it pauses its website while no other unit works',async()=>{
  let now=0;const c=makeConfig({urls:['https://one.invalid'],originMaxDurationMs:400}),control=new OriginControl(c,new AbortController().signal,()=>now);control.excludeSharedWaits=true;const url='https://one.invalid/';
  try{
    const turn=new TurnClock(control);
    await control.run(url,async()=>{now=10;const wait=control.sharedWait();assert.equal(turn.paused,true);now=110;wait();assert.equal(turn.paused,false);
      const working=control.busy(),again=control.sharedWait();assert.equal(turn.paused,false,'own work in the turn keeps it charged');now=130;again();working();now=150;},undefined,{inherit:false,turn});
    assert.equal(turn.ended,true);assert.equal(turn.charged(),50);assert.equal(control.elapsed(url),50);assert.equal(control.snapshots()[0]!.sharedWaitMs,100);
  }finally{control.cancel();}
});
test('mass mode with real timers: a shared wait longer than the website\'s limit does not expire it; its own work still reaches the limit on time',{timeout:30000},async()=>{
  const c=makeConfig({urls:['https://one.invalid'],originMaxDurationMs:300}),control=new OriginControl(c,new AbortController().signal);control.excludeSharedWaits=true;const url='https://one.invalid/';
  const untilExpired=()=>new Promise<void>(r=>{const s=control.get(url).controller.signal;if(s.aborted){r();return;}s.addEventListener('abort',()=>r(),{once:true});setTimeout(r,10000).unref();});
  try{
    await control.run(url,async()=>{const wait=control.sharedWait();await sleep(700);assert.equal(control.expired(url),false,'a 700 ms shared wait is not charged to a 300 ms limit');wait();});
    const at=performance.now();await control.run(url,async()=>{const working=control.busy(),waiting=control.sharedWait();await untilExpired();waiting();working();});const took=performance.now()-at;
    assert.equal(control.expired(url),true);assert.ok(took>=250&&took<5000,'the website expired by its own time: '+Math.round(took)+' ms');
    assert.ok(control.snapshots()[0]!.sharedWaitMs!>=650,'the wait is reported: '+control.snapshots()[0]!.sharedWaitMs);
  }finally{control.cancel();}
});
const analysisInput=()=>({url:'https://fixture.invalid/app.js',status:200,headers:{'content-type':'text/javascript'},body:Buffer.from('const token="'+synthetic.github+'";'),partial:false,chain:[] as string[]});
async function holdEngineLanes(d:Detector,ms:number){const lanes=(d as any).engineLanes;await lanes.acquire(2);setTimeout(()=>lanes.release(2),ms);}
test('mass mode: an analysis turn that waits longer than its turn, website and scan limits for an engine lane other targets hold still completes and finds the key',{timeout:120000},async t=>{
  const d=new Detector();d.syntheticFixture=true;await d.init();if(d.version==='unavailable'){t.skip('the pinned engine is not available on this machine');return;}
  // 2.9.1 (flake root cause): this test is about the wait for a lane other targets hold, not about the engine's speed. The engine process is the target's own work and had only the
  // 2000 ms turn, which a saturated CPU exceeded (analysis-turn-limit at post-engine). A stand-in answers at once with the report the pinned engine gives for this text; the lane
  // it runs in, and so the wait, are the real ones.
  let engineRuns=0;(d as any).pipeRun=async(_args:string[],text:string)=>{engineRuns++;return JSON.stringify(text.includes(synthetic.github)?[{RuleID:'github-pat',Secret:synthetic.github}]:[]);};
  const config={urls:['https://fixture.invalid'],analysisTurnMs:2000,originMaxDurationMs:2500,maxDurationMs:2500,semanticAnalysis:false};
  const scan=new Scanner(config,{detector:d,excludeSharedWaits:true});
  try{
    // 2.9.1 (flake root cause): the lanes are released 3.5 s after the analysis is seen waiting for one, not 3.5 s after they were taken: on a saturated CPU the analysis's own
    // work before the lane took up to 0.8 s of a fixed 3.5 s hold, so the wait reported on the website fell under 3 s although the code was right.
    const lanes=(d as any).engineLanes;await lanes.acquire(2);const at=performance.now(),analysis=scan.transport.analyze(analysisInput() as any);
    while(!lanes.waiting&&performance.now()-at<30000)await sleep(5);assert.ok(lanes.waiting,'the analysis waits for a lane');setTimeout(()=>lanes.release(2),3500);const text=await analysis,took=performance.now()-at;
    assert.ok(text.includes('const token'));assert.ok(took>=3000,'the turn waited for the lane: '+Math.round(took)+' ms');
    assert.ok([...scan.evidence.findings.keys()].some(id=>scan.evidence.reveal(id).value===synthetic.github),'the key is found');assert.equal(engineRuns,1,'the engine ran once, in the lane it waited for');
    assert.ok(!scan.limitations.some(g=>g.code==='analysis-interrupted'),'no interruption: '+JSON.stringify(scan.limitations.map(g=>g.code)));
    const control=scan.transport.originControl,site=()=>control.snapshots().find(s=>s.origin==='https://fixture.invalid');assert.equal(control.expired('https://fixture.invalid/'),false,'the website limit was not charged for the wait');
    assert.ok(site()!.sharedWaitMs!>=3000,'the wait is reported on the website: '+site()!.sharedWaitMs);
    assert.ok(control.projectExcludedMs()>=3000,'and not charged to the scan: '+control.projectExcludedMs());assert.ok(scan.transport.projectRemainingMs()>0);
  }finally{scan.dispose();}
});
test('outside mass mode the same wait is charged: the analysis turn reaches its limit and the body is deferred',{timeout:120000},async t=>{
  const d=new Detector();d.syntheticFixture=true;await d.init();if(d.version==='unavailable'){t.skip('the pinned engine is not available on this machine');return;}
  const scan=new Scanner({urls:['https://fixture.invalid'],analysisTurnMs:2000,originMaxDurationMs:2500,maxDurationMs:2500,semanticAnalysis:false},{detector:d});
  try{
    await holdEngineLanes(d,3500);
    await assert.rejects(scan.transport.analyze(analysisInput() as any),(e:unknown)=>e instanceof AnalysisDeferred&&e.cause.kind==='analysis-turn-limit');
    assert.ok(!('sharedWaitMs' in scan.transport.originControl.snapshots().find(s=>s.origin==='https://fixture.invalid')!));
  }finally{scan.dispose();}
});

test('mass mode: a work unit switches between own work and a wait for shared capacity, and its marks apply to the website it was made on from any context (w5-fix)',async()=>{
  let now=0;const c=makeConfig({urls:['https://one.invalid','https://two.invalid'],originMaxDurationMs:1000}),control=new OriginControl(c,new AbortController().signal,()=>now);control.excludeSharedWaits=true;
  const one='https://one.invalid/',two='https://two.invalid/';
  try{
    let unit!:WorkUnit;control.run(two,()=>{});await control.run(one,async()=>{unit=control.unit();});
    assert.equal(control.get(one).pausedSince,undefined,'a unit with no kind marks nothing');
    unit.wait();assert.equal(control.get(one).pausedSince,0,'a waiting unit and no working one pause the website, also when switched outside its turn');
    now=300;control.run(two,()=>unit.work());assert.equal(control.get(one).pausedSince,undefined,'switched to work from another website\'s turn, it still marks its own website');assert.equal(control.elapsed(one),0);
    now=400;assert.equal(control.elapsed(one),100,'own work is charged');
    unit.wait();now=450;unit.end();now=500;
    assert.equal(control.elapsed(one),150,'the wait is not charged; time with no unit is');assert.equal(control.snapshots().find(s=>s.origin==='https://one.invalid')!.sharedWaitMs,350);
    assert.equal(control.elapsed(two),500,'the other website was never paused');
  }finally{control.cancel();}
  now=0;const plain=new OriginControl(c,new AbortController().signal,()=>now);
  try{let u!:WorkUnit;await plain.run(one,async()=>{u=plain.unit();});u.wait();assert.equal(plain.get(one).pausedSince,undefined);now=200;u.end();assert.equal(plain.elapsed(one),200,'outside mass mode a unit marks nothing');}finally{plain.cancel();}
});
test('mass mode with real timers: a charged-time timer has no timeout while its website only waits for shared capacity, fires once after the website\'s charged limit and never after its cancel (w5-fix)',{timeout:30000},async()=>{
  const c=makeConfig({urls:['https://one.invalid'],originMaxDurationMs:60000}),control=new OriginControl(c,new AbortController().signal);control.excludeSharedWaits=true;const url='https://one.invalid/';
  try{
    await control.run(url,async()=>{
      let fired=0,firedAt=0,chargedAt=0;const start=performance.now(),cancel=control.chargedTimer(url,400,()=>{fired++;firedAt=performance.now();chargedAt=control.elapsed(url);});
      await sleep(150);const wait=control.sharedWait();await sleep(700);assert.equal(fired,0,'no timeout during a 700 ms wait');wait();const resumed=performance.now();
      for(let i=0;i<250&&!fired;i++)await sleep(20);
      assert.equal(fired,1);assert.ok(firedAt>resumed,'it fired after the wait');assert.ok(chargedAt>=395&&chargedAt<2400,'at the charged limit: '+Math.round(chargedAt)+' ms');
      assert.ok(firedAt-start>=1095,'the 700 ms wait was not counted: '+Math.round(firedAt-start)+' ms');
      await sleep(100);assert.equal(fired,1,'once');cancel();
      let early=0;const stop=control.chargedTimer(url,100,()=>early++);stop();await sleep(250);assert.equal(early,0,'a cancelled timer never fires');
      assert.equal(control.get(url).resumers!.size,0,'no timer is left registered');
    });
  }finally{control.cancel();}
});

// ---- Program-wide request slots that other targets hold (mass mode) ----
async function slotServer(holdMs:number){
  const seen:string[]=[];const server=http.createServer((req,res)=>{seen.push(req.url!);setTimeout(()=>{res.setHeader('content-type','text/html');res.end(req.url==='/'?'<html><body>fixture</body></html>':'ok');},req.url!.startsWith('/hold')?holdMs:10);});
  await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));
  return {seen,origin:'http://127.0.0.1:'+(server.address() as any).port,close:()=>new Promise<void>(r=>{server.close(()=>r());server.closeAllConnections();})};
}
const slotProgram=(name:string,rate:number)=>programFromJson({schema:PROGRAM_SCHEMA,scope:{in:['127.0.0.1']},rate:{requestsPerSecond:rate},concurrency:{targets:2,requests:1}},name+'-'+process.pid).config;
async function until(check:()=>boolean,ms=10000){for(const end=performance.now()+ms;!check()&&performance.now()<end;)await sleep(10);assert.ok(check(),'condition reached');}
test('mass mode: a request waiting for the program-wide slot another target holds pauses its website (reported as sharedWaitMs); a wait after its own grant stays charged; outside mass mode the slot wait is charged (w5-fix)',{timeout:60000},async()=>{
  const f=await slotServer(1500);
  try{
    const program=slotProgram('mass-scale-slots',2);
    const make=(mass:boolean)=>{const t=new Transport(makeConfig({urls:[f.origin+'/'],developmentFixtureOrigin:f.origin,program,globalConcurrency:4,originConcurrency:4,originRequestsPerSecond:20}),new Evidence(new Detector('disabled')),()=>{},()=>{});t.originControl.excludeSharedWaits=mass;return t;};
    const holder=make(true),waiter=make(true),site=(t:Transport)=>t.originControl.snapshots().find(s=>s.origin===f.origin)!;
    const held=holder.get(f.origin+'/hold1');await until(()=>f.seen.includes('/hold1'));
    await waiter.get(f.origin+'/a');await held;
    const slotWait=site(waiter).sharedWaitMs!;assert.ok(slotWait>=1000,'the wait for the slot the other target held is reported: '+slotWait);
    assert.ok(site(waiter).elapsedMs<500,'and not charged: '+site(waiter).elapsedMs);assert.deepEqual(site(waiter).sharedWaitByCause,{analysisMs:0,parserMs:0,preflightMs:0,programSlotMs:slotWait},'the whole wait is for the program slot (2.9)');assert.equal(site(holder).sharedWaitMs,0,'the holder never waited');
    // Its own grant set the next slot (2 per second): that wait is its own pacing.
    const before=site(waiter).elapsedMs;await waiter.get(f.origin+'/b');
    assert.ok(site(waiter).elapsedMs-before>=300,'its own pacing is charged: '+(site(waiter).elapsedMs-before));assert.ok(site(waiter).sharedWaitMs!-slotWait<100,'and not reported as a shared wait');
    const plain=make(false),again=holder.get(f.origin+'/hold2');await until(()=>f.seen.includes('/hold2'));
    await plain.get(f.origin+'/c');await again;
    assert.ok(!('sharedWaitMs' in site(plain)));assert.ok(site(plain).elapsedMs>=1000,'outside mass mode the slot wait is charged: '+site(plain).elapsedMs);
  }finally{await f.close();}
});
test('mass mode: a work turn is not cut while its website waits for the program-wide slot another target holds; outside mass mode the same wait reaches the turn limit (w5-fix)',{timeout:120000},async()=>{
  const f=await slotServer(3000);
  try{
    const program=slotProgram('mass-scale-turns',50),holder=new Transport(makeConfig({urls:[f.origin+'/'],developmentFixtureOrigin:f.origin,program}),new Evidence(new Detector('disabled')),()=>{},()=>{});
    // The website's own pacing (20 per second) is charged and stays far below the 1 s turn; only the slot the holder keeps for 3 s could reach it.
    const scanWhileHeld=async(mass:boolean,path:string)=>{
      const held=holder.get(f.origin+path);await until(()=>f.seen.includes(path));
      const s=new Scanner({urls:[f.origin+'/'],developmentFixtureOrigin:f.origin,program,workTurnMs:1000,requestsPerSecond:20,originRequestsPerSecond:20,semanticAnalysis:false,maxRetries:0},{detector:new Detector('disabled'),excludeSharedWaits:mass});
      try{await s.run();return {codes:s.limitations.map(g=>g.code),gaps:s.limitations.map(g=>({code:g.code,url:g.url,cause:(g as any).cause})),fetched:s.resources.map(r=>new URL(r.url).pathname),shared:s.transport.originControl.snapshots().find(x=>x.origin===f.origin)?.sharedWaitMs};}
      finally{s.dispose();await held;}
    };
    const mass=await scanWhileHeld(true,'/hold1');
    assert.ok(!mass.codes.includes('work-turn-limit'),'no turn was cut: '+JSON.stringify(mass.gaps)+' shared '+mass.shared);assert.ok(mass.fetched.includes('/'),'the page was fetched: '+JSON.stringify(mass.fetched));
    assert.ok(mass.shared!>=1500,'the wait is reported: '+mass.shared);
    const plain=await scanWhileHeld(false,'/hold2');
    assert.ok(plain.codes.includes('work-turn-limit'),'outside mass mode the wait is charged to the turn: '+JSON.stringify(plain.codes));
  }finally{await f.close();}
});

// ---- Memory-aware admission ----
test('memory gate: admits while the projection fits under the ceiling less a margin, follows the measured per-target growth, falls back slowly, counts each stretch of refusals once',()=>{
  let rss=100,t=0;const g=new MemoryGate(512,()=>rss,8,()=>t);
  assert.equal(g.marginMb,64);assert.equal(g.baseMb,100);assert.equal(g.perTargetMb,8);
  assert.equal(g.admit(1),true);
  t=250;rss=300;assert.equal(g.admit(4),true,'max(300, 100+4×50) + 50 = 350 fits under 448');assert.equal(g.perTargetMb,50,'the estimate rises at once');
  t=500;rss=400;assert.equal(g.admit(5),false,'max(400, 100+5×60) + 60 = 460 does not fit');assert.equal(g.waits,1);
  t=750;assert.equal(g.admit(5),false);assert.equal(g.waits,1,'one stretch of refusals counts once');
  t=1000;rss=200;assert.equal(g.admit(5),false,'a collection pause does not let a burst in: the estimate falls back slowly');assert.ok(Math.abs(g.perTargetMb-(60*0.98+20*0.02))<1e-9,String(g.perTargetMb));
  t=1250;assert.equal(g.admit(3),true,'with fewer targets running the projection fits again');
  t=1500;rss=430;assert.equal(g.admit(3),false,'growth raises the estimate at once (330 MiB over the 5 targets of the last 30 s: 66)');assert.equal(g.perTargetMb,66);assert.equal(g.waits,2);
  assert.deepEqual(g.stats(),{ceilingMb:512,marginMb:64,startRssMb:100,peakRssMb:430,perTargetMb:66,admissionWaits:2});
});
test('memory gate: the estimate falls back by elapsed time however often it is read, so a start-up burst keeps the prior and stops at the projection',()=>{
  let t=0;const burst=new MemoryGate(512,()=>100,8,()=>t);
  for(let n=1;n<=42;n++)assert.equal(burst.admit(n),true,'100 + '+n+'×8 + 8 fits under 448');
  assert.equal(burst.perTargetMb,8,'readings at one instant do not lower the prior');assert.equal(burst.admit(43),false,'100 + 43×8 + 8 = 452 does not fit');assert.equal(burst.waits,1);
  let rss=100,t1=0,t2=0;const once=new MemoryGate(512,()=>rss,8,()=>t1),often=new MemoryGate(512,()=>rss,8,()=>t2);
  rss=104;t1=1000;once.sample(2);for(const at of [250,500,750,1000]){t2=at;often.sample(2);}
  assert.ok(Math.abs(once.perTargetMb-often.perTargetMb)<1e-9,once.perTargetMb+' vs '+often.perTargetMb);assert.ok(Math.abs(once.perTargetMb-(2+6*0.98**4))<1e-9);
});
test('memory gate: a dip in the running targets does not read as a costlier target; the highest count is remembered for 30 s',()=>{
  let rss=100,t=0;const g=new MemoryGate(512,()=>rss,8,()=>t);
  g.sample(16);t=250;rss=400;g.sample(16);assert.equal(g.perTargetMb,300/16);
  t=500;assert.equal(g.admit(1),true,'one target left with 400 MiB not yet collected: 300 MiB over the 16 recent targets, max(400, 118.75) + 18.75 fits');assert.equal(g.perTargetMb,300/16);
  t=30251;assert.equal(g.admit(1),false,'after 30 s at one target the reading is that one target: 400 + 300 does not fit');assert.equal(g.perTargetMb,300);
});
test('memory ceiling: 512 MiB with ready options; an explicit program analysisMemoryMb raises it, at most to 2048',()=>{
  assert.equal(massMemoryCeilingMb(),512);assert.equal(massMemoryCeilingMb(100),512);assert.equal(massMemoryCeilingMb(1024),1024);assert.equal(massMemoryCeilingMb(2048),2048);assert.equal(massMemoryCeilingMb(4096),2048);
  assert.equal(new MemoryGate(2048,()=>0).marginMb,256);assert.equal(new MemoryGate(200,()=>0).marginMb,32);
});
test('scheduler admission: a refusing check holds further targets back and is asked again; with no target running one always starts; every target still runs',async()=>{
  const ran:number[]=[];let active=0,peak=0;const asked:number[]=[];
  const s=new MassScheduler([0,1,2,3,4,5],4,async i=>{active++;peak=Math.max(peak,active);await sleep(20);ran.push(i);active--;},n=>{asked.push(n);return n<2;},10);
  await s.run();assert.equal(s.peakActive,2);assert.equal(peak,2);assert.deepEqual([...ran].sort(),[0,1,2,3,4,5]);assert.ok(asked.length>0&&asked.every(n=>n>0),'asked only while a target runs');
  const none:number[]=[],never=new MassScheduler([0,1,2],4,async i=>{none.push(i);await sleep(5);},()=>false,10);
  await never.run();assert.equal(never.peakActive,1,'a gate that never admits still lets one target run at a time');assert.deepEqual(none,[0,1,2]);
  const slow=new MassScheduler([0,1,2],3,async()=>{await sleep(30);},()=>false,5);setTimeout(()=>slow.stop(),10);await slow.run();assert.equal(slow.peakActive,1,'a stop while refusing ends the run');
});

// ---- The mass run summary (CLI, loopback) ----
type Run={status:number|null;stdout:string;stderr:string;events:any[]};
function run(args:string[],env:NodeJS.ProcessEnv){return new Promise<Run>((resolve,reject)=>{const child=spawn(process.execPath,[cli,'scan',...args],{env,windowsHide:true});let stdout='',stderr='';const timer=setTimeout(()=>child.kill(),240000);
  child.stdout.on('data',d=>stdout+=d);child.stderr.on('data',d=>stderr+=d);child.stdin.on('error',()=>{});child.stdin.end('');child.on('error',reject);
  child.on('close',status=>{clearTimeout(timer);resolve({status,stdout,stderr,events:stdout.split('\n').filter(Boolean).map(l=>JSON.parse(l))});});});}
async function keySite(){
  const server=http.createServer((req,res)=>{const p=(req.url||'/').split('?')[0]!;
    if(p==='/robots.txt'){res.setHeader('content-type','text/plain');res.end('User-agent: *\nAllow: /\n');return;}
    if(p==='/app.js'){res.setHeader('content-type','text/javascript');res.end('const client={token:'+JSON.stringify(synthetic.github)+'};');return;}
    if(/^\/t\d+$/.test(p)){res.setHeader('content-type','text/html');res.end('<!doctype html><p>ok</p><script src="/app.js"></script>');return;}
    res.statusCode=404;res.setHeader('content-type','text/plain');res.end('nf');});
  await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));
  return {origin:'http://127.0.0.1:'+(server.address() as any).port,close:()=>new Promise<void>(r=>{server.close(()=>r());server.closeAllConnections();})};
}
test('mass run summary: effective concurrency, the memory gate (512 MiB ceiling with ready options) and the shared-capacity wait; target-end events report their wait',{timeout:300000},async()=>{
  const site=await keySite(),dir=await temp('mass-scale-'),env={...process.env,EXPOSURE_DATA_DIR:dir};try{
    const tpl=path.join(dir,'template.json'),list=path.join(dir,'targets.txt');
    await writeFile(tpl,JSON.stringify({developmentFixtureOrigin:site.origin,browser:false}));await writeFile(list,Array.from({length:4},(_,i)=>`${site.origin}/t${i}`).join('\n')+'\n');
    const r=await run(['--targets',list,'--authorized','--config',tpl,'--coverage','quick','--concurrency','3','--jsonl','--fail-on','never','--output',path.join(dir,'r.json')],env);
    assert.equal(r.status,0,r.stderr);const summary=r.events.find(e=>e.event==='summary');
    assert.equal(summary.statuses.done,4,JSON.stringify(summary.statuses));assert.ok(summary.uniqueFindings>=1,'the planted key is found');
    assert.ok(summary.effectiveConcurrency>=1&&summary.effectiveConcurrency<=3,String(summary.effectiveConcurrency));
    if(summary.memory.admissionWaits===0)assert.equal(summary.effectiveConcurrency,3,'with no admission wait every lane fills at once');
    assert.equal(summary.memory.ceilingMb,512);assert.equal(summary.memory.marginMb,64);assert.ok(summary.memory.peakRssMb<=512,'within the ceiling: '+summary.memory.peakRssMb);
    assert.equal(typeof summary.sharedWaitMs,'number');
    const ends=r.events.filter(e=>e.event==='target-end');assert.equal(ends.length,4);assert.ok(ends.every(e=>typeof e.sharedWaitMs==='number'&&e.sharedWaitMs>=0));
    assert.equal(summary.sharedWaitMs,ends.reduce((a,e)=>a+e.sharedWaitMs,0),'the summary adds up the targets\' waits');
    // 2.9: the split by cause adds up to sharedWaitMs on every target-end and on the summary, and the summary adds up the targets' parts.
    const causes=['analysisMs','parserMs','preflightMs','programSlotMs'],sum=(x:any)=>causes.reduce((a,k)=>a+x[k],0);
    for(const e of [...ends,summary]){assert.deepEqual(Object.keys(e.sharedWaitByCause).sort(),[...causes].sort());assert.ok(causes.every(k=>Number.isInteger(e.sharedWaitByCause[k])&&e.sharedWaitByCause[k]>=0));assert.equal(sum(e.sharedWaitByCause),e.sharedWaitMs);}
    for(const k of causes)assert.equal(summary.sharedWaitByCause[k],ends.reduce((a,e)=>a+e.sharedWaitByCause[k],0),k);
  }finally{await site.close();await rm(dir,{recursive:true,force:true,maxRetries:5});}
});
test('mass run summary: an explicit program analysisMemoryMb sets the ceiling; one target at a time has no gate and the 2.7 summary; with --state it is a mass run with summary.memory (2.9.1)',{timeout:300000},async()=>{
  const site=await keySite(),dir=await temp('mass-scale-program-'),env={...process.env,EXPOSURE_DATA_DIR:dir};try{
    const tpl=path.join(dir,'template.json'),list=path.join(dir,'targets.txt'),program=path.join(dir,'program');await mkdir(program,{recursive:true});
    await writeFile(tpl,JSON.stringify({developmentFixtureOrigin:site.origin,browser:false}));await writeFile(list,`${site.origin}/t0\n${site.origin}/t1\n`);
    await writeFile(path.join(program,'program.json'),JSON.stringify({schema:'exposure-program/1',name:'Loopback',authorized:true,scope:{in:['127.0.0.1'],out:[]},rate:{requestsPerSecond:50},concurrency:{targets:2,requests:4},analysisMemoryMb:1024}));
    const r=await run(['--targets',list,'--program',program,'--config',tpl,'--coverage','quick','--jsonl','--fail-on','never','--output',path.join(dir,'r.json')],env);
    assert.equal(r.status,0,r.stderr);const summary=r.events.find(e=>e.event==='summary');
    assert.equal(summary.statuses.done,2);assert.equal(summary.memory.ceilingMb,1024);assert.equal(summary.memory.marginMb,128);
    const single=await run(['--targets',list,'--authorized','--config',tpl,'--coverage','quick','--concurrency','1','--jsonl','--fail-on','never','--output',path.join(dir,'r1.json')],env);
    assert.equal(single.status,0,single.stderr);const s1=single.events.find(e=>e.event==='summary');
    for(const k of ['effectiveConcurrency','sharedWaitMs','sharedWaitByCause','memory'])assert.ok(!(k in s1),k+' is a mass-run field');
    assert.ok(single.events.filter(e=>e.event==='target-end').every(e=>!('sharedWaitMs' in e)&&!('sharedWaitByCause' in e)));
    // 2.9.1: a mass run at concurrency 1 (--state) reports memory like c2 and above; nothing is admitted against it (one target at a time).
    const stated=await run(['--targets',list,'--authorized','--config',tpl,'--coverage','quick','--concurrency','1','--state',path.join(dir,'run.state'),'--jsonl','--fail-on','never','--output',path.join(dir,'rs.json')],env);
    assert.equal(stated.status,0,stated.stderr);const sm=stated.events.find(e=>e.event==='summary');
    assert.equal(sm.statuses.done,2);assert.equal(sm.concurrency,1);assert.equal(sm.effectiveConcurrency,1);
    assert.ok(sm.memory,'summary.memory at concurrency 1: '+JSON.stringify(sm));assert.equal(sm.memory.ceilingMb,512);assert.equal(sm.memory.marginMb,64);assert.equal(sm.memory.admissionWaits,0);
    assert.ok(sm.memory.peakRssMb>0&&sm.memory.peakRssMb>=sm.memory.startRssMb&&sm.memory.peakRssMb<=512,JSON.stringify(sm.memory));assert.equal(typeof sm.memory.parseCollections,'number');
    for(const k of ['sharedWaitMs','sharedWaitByCause'])assert.ok(k in sm,k);
  }finally{await site.close();await rm(dir,{recursive:true,force:true,maxRetries:5});}
});

// ---- 2.9 w8-fixes: in-process parse garbage (ParseCollector) ----
test('parse collector: counts only texts of at least 64 KiB, collects once the counted bytes reach the threshold, then counts again; without a collection function it does nothing',()=>{
  let runs=0,t=0;const c=new ParseCollector(PARSE_COLLECT_BYTES,()=>{runs++;t+=7;},()=>t);
  for(let i=0;i<64;i++)assert.equal(c.parsed(PARSE_COUNT_MIN_BYTES-1),false,'small texts are never counted, however many');assert.equal(runs,0);
  assert.equal(c.parsed(300*1024),false);assert.equal(c.parsed(300*1024),true,'600 KiB counted reaches 512 KiB');assert.equal(runs,1);
  assert.equal(c.parsed(300*1024),false,'the count starts again after a collection');assert.equal(c.parsed(1250*1024),true,'one large text collects at once');
  assert.deepEqual(c.stats(),{parseCollections:2,parseCollectMs:14});
  const off=new ParseCollector(PARSE_COLLECT_BYTES,null);assert.equal(off.parsed(4*1048576),false);assert.deepEqual(off.stats(),{parseCollections:0,parseCollectMs:0});
});
test('parse collector: the full collection is fetched without leaving a global gc behind',()=>{
  const had='gc' in globalThis,gc=fullCollection();assert.equal(typeof gc,'function');gc!();assert.equal('gc' in globalThis,had,'no global gc appears');
});
async function largeBundleSite(bytes:number){
  // A parseable script of `bytes` with the planted key at its start and many small functions (no URLs, so coverage stays complete), so structured discovery parses it in the scan process.
  let body='const client={token:'+JSON.stringify(synthetic.github)+'};\n',i=0;while(body.length<bytes){body+=`function f${i}(a,b){const c={k:"v${i}",n:a*${i}+b};return c.n>${i}?c.k:[a,b,${i}].join("-");}\n`;i++;}
  const server=http.createServer((req,res)=>{const p=new URL(req.url||'/','http://x').pathname;
    if(p==='/robots.txt'){res.setHeader('content-type','text/plain');res.end('User-agent: *\nAllow: /\n');return;}
    if(/^\/b\d+\.js$/.test(p)){res.setHeader('content-type','text/javascript');res.end('/* '+p+' */\n'+body);return;}
    if(/^\/t\d+$/.test(p)){res.setHeader('content-type','text/html');res.end(`<!doctype html><p>ok</p><script src="/b${p.slice(2)}.js"></script>`);return;}
    res.statusCode=404;res.setHeader('content-type','text/plain');res.end('nf');});
  await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));
  return {origin:'http://127.0.0.1:'+(server.address() as any).port,close:()=>new Promise<void>(r=>{server.close(()=>r());server.closeAllConnections();})};
}
test('mass run with large bundles: the parse collector runs, and the findings equal those of one target at a time (nothing in the analysis changes)',{timeout:300000},async()=>{
  const site=await largeBundleSite(640*1024),dir=await temp('mass-scale-large-'),env={...process.env,EXPOSURE_DATA_DIR:dir};try{
    const tpl=path.join(dir,'template.json'),list=path.join(dir,'targets.txt');
    await writeFile(tpl,JSON.stringify({developmentFixtureOrigin:site.origin,browser:false}));await writeFile(list,Array.from({length:3},(_,i)=>`${site.origin}/t${i}`).join('\n')+'\n');
    const common=['--targets',list,'--authorized','--config',tpl,'--coverage','quick','--jsonl','--fail-on','never'];
    const mass=await run([...common,'--concurrency','3','--output',path.join(dir,'r3.json')],env),single=await run([...common,'--concurrency','1','--output',path.join(dir,'r1.json')],env);
    // A 640 KiB bundle is past quick coverage's decoded-inspection limit (gap decoded-inspection-limit), so each target ends incomplete (exit 2) at either concurrency; what matters is that both agree.
    assert.equal(mass.status,single.status,mass.stderr);assert.ok([0,2].includes(mass.status!),mass.stderr);
    const s3=mass.events.find(e=>e.event==='summary'),s1=single.events.find(e=>e.event==='summary');
    assert.equal(s3.scanned,3);assert.deepEqual(s3.states,s1.states,'the same end states at either concurrency');assert.ok(s3.memory.parseCollections>=3,'each 640 KiB bundle reaches the threshold: '+JSON.stringify(s3.memory));
    assert.equal(typeof s3.memory.parseCollectMs,'number');assert.ok(s3.memory.peakRssMb<=512,'within the ceiling: '+s3.memory.peakRssMb);
    // Finding IDs are keyed per run, so the comparison is on what was found: target, rule, provider, masked value, severity and occurrence count.
    const keys=(r:Run)=>r.events.filter(e=>e.event==='finding').map(e=>`${e.target}|${e.rule}|${e.provider}|${e.masked}|${e.severity}|${e.occurrences}`).sort();
    assert.ok(keys(mass).length>=3,'every target finds the planted key');assert.deepEqual(keys(mass),keys(single));
    assert.equal(s3.findings,s1.findings);
  }finally{await site.close();await rm(dir,{recursive:true,force:true,maxRetries:5});}
});

/** 2.9 (O3): sharedWaitMs split by cause. Virtual clock; no network. */
test('shared wait by cause: analysis by default, preflight inside waitCause, parser by name, a program slot through a work unit; the parts add up to sharedWaitMs (2.9)',async()=>{
  let now=0;const c=makeConfig({urls:['https://one.invalid'],originMaxDurationMs:10000}),control=new OriginControl(c,new AbortController().signal,()=>now);control.excludeSharedWaits=true;const one='https://one.invalid/';
  try{
    let unit!:WorkUnit;
    await control.run(one,async()=>{
      let w=control.sharedWait();now+=300;w();
      w=control.waitCause('preflight',()=>control.sharedWait());now+=200;w();
      w=control.sharedWait('parser');now+=50;w();
      unit=control.unit();
    });
    unit.wait();now+=500;unit.end();
    const s=control.snapshots()[0]!;assert.equal(s.sharedWaitMs,1050);
    assert.deepEqual(s.sharedWaitByCause,{analysisMs:300,parserMs:50,preflightMs:200,programSlotMs:500});
    assert.deepEqual(control.projectWait(),{sharedWaitMs:1050,sharedWaitByCause:{analysisMs:300,parserMs:50,preflightMs:200,programSlotMs:500}},'the only website, so the scan was paused for the same time');
    assert.equal(control.elapsed(one),0,'no wait is charged');
  }finally{control.cancel();}
});
test('shared wait by cause: overlapping waits share the paused time by their number; a cause that changes while paused is split at the change; a paused turn counts as one unit (2.9)',async()=>{
  let now=0;const c=makeConfig({urls:['https://one.invalid'],originMaxDurationMs:10000}),control=new OriginControl(c,new AbortController().signal,()=>now);control.excludeSharedWaits=true;const one='https://one.invalid/';
  try{
    let unit!:WorkUnit;
    await control.run(one,async()=>{
      unit=control.unit();
      const a=control.sharedWait();unit.wait();now+=100;unit.end();now+=100;a();
      // One unit switches cause while the website stays paused.
      unit=control.unit();unit.wait('preflight');now+=40;unit.wait();now+=60;unit.end();
    });
    assert.deepEqual(control.snapshots()[0]!.sharedWaitByCause,{analysisMs:150,parserMs:0,preflightMs:40,programSlotMs:110});
    // A paused analysis turn (two analysis waits and one parser wait inside it) and one own program-slot wait: two units, the turn split two thirds to one third (adds 100, 50 and 150).
    const turn=new TurnClock(control);let slot!:WorkUnit;
    await control.run(one,async()=>{slot=control.unit();},undefined,{inherit:false});
    await control.run(one,async()=>{const x=control.sharedWait(),y=control.sharedWait(),z=control.sharedWait('parser');slot.wait();now+=300;slot.end();x();y();z();},undefined,{inherit:false,turn});
    const s=control.snapshots()[0]!;assert.equal(s.sharedWaitMs,600);
    assert.deepEqual(s.sharedWaitByCause,{analysisMs:250,parserMs:50,preflightMs:40,programSlotMs:260});
  }finally{control.cancel();}
});
test('shared wait by cause: the scan splits its paused time by the average share of its paused websites; a website that runs keeps the scan running (2.9)',async()=>{
  let now=0;const c=makeConfig({urls:['https://one.invalid','https://two.invalid'],originMaxDurationMs:10000}),control=new OriginControl(c,new AbortController().signal,()=>now);control.excludeSharedWaits=true;
  const one='https://one.invalid/',two='https://two.invalid/';
  try{
    let u1!:WorkUnit,u2!:WorkUnit;await control.run(one,async()=>{u1=control.unit();});await control.run(two,async()=>{u2=control.unit();});
    u1.wait('preflight');now+=100;assert.equal(control.projectPaused,false,'two has no unit and runs');
    u2.wait('programSlot');now+=200;u2.work();now+=50;u2.wait('programSlot');now+=100;u1.end();u2.end();
    const p=control.projectWait();assert.equal(p.sharedWaitMs,300);assert.deepEqual(p.sharedWaitByCause,{analysisMs:0,parserMs:0,preflightMs:150,programSlotMs:150});
    const snaps=Object.fromEntries(control.snapshots().map(s=>[s.origin,s]));
    assert.deepEqual(snaps['https://one.invalid']!.sharedWaitByCause,{analysisMs:0,parserMs:0,preflightMs:450,programSlotMs:0});
    assert.deepEqual(snaps['https://two.invalid']!.sharedWaitByCause,{analysisMs:0,parserMs:0,preflightMs:0,programSlotMs:300});
  }finally{control.cancel();}
});
test('shared wait by cause: largest-remainder rounding always adds up to the rounded total; ties go to analysis, parser, preflight, program slot in turn; no parts go to analysis (2.9)',()=>{
  const z={analysis:0,parser:0,preflight:0,programSlot:0};
  assert.deepEqual(splitRounded(100,{...z,analysis:1,preflight:1,programSlot:1}),{analysisMs:34,parserMs:0,preflightMs:33,programSlotMs:33});
  assert.deepEqual(splitRounded(10,{analysis:1,parser:1,preflight:1,programSlot:1}),{analysisMs:3,parserMs:3,preflightMs:2,programSlotMs:2});
  assert.deepEqual(splitRounded(7.4,z),{analysisMs:7,parserMs:0,preflightMs:0,programSlotMs:0});
  assert.deepEqual(splitRounded(0,{...z,parser:5}),{analysisMs:0,parserMs:0,preflightMs:0,programSlotMs:0});
  for(let i=0;i<200;i++){const parts={analysis:Math.random()*1000,parser:Math.random()*10,preflight:Math.random()*100,programSlot:Math.random()*1000},total=Object.values(parts).reduce((a,b)=>a+b,0)+Math.random()-0.5,s=splitRounded(total,parts);
    assert.equal(s.analysisMs+s.parserMs+s.preflightMs+s.programSlotMs,Math.max(0,Math.round(total)));assert.ok(Object.values(s).every(v=>Number.isInteger(v)&&v>=0));}
});
test('shared wait by cause: outside mass mode there is no split in the snapshots, and redaction keeps the new keys (2.9)',async()=>{
  let now=0;const c=makeConfig({urls:['https://one.invalid']}),plain=new OriginControl(c,new AbortController().signal,()=>now);
  try{await plain.run('https://one.invalid/',async()=>{const w=plain.waitCause('preflight',()=>plain.sharedWait());now+=100;w();});const s=plain.snapshots()[0]!;assert.ok(!('sharedWaitByCause' in s)&&!('sharedWaitMs' in s));assert.equal(plain.elapsed('https://one.invalid/'),100);}finally{plain.cancel();}
  const record={sharedWaitMs:7,sharedWaitByCause:{analysisMs:1,parserMs:2,preflightMs:3,programSlotMs:1}};
  assert.deepEqual(new Evidence(new Detector('disabled')).redact(record),record);
});

/** 2.9.1: request preflight screening takes the same fair turns (one place per target, first in, first out) for the shared detector's lanes. The engine is a stub that
 * records the order it is started in; no network. */
function stubEngine(d:Detector,started:string[]){
  (d as any).version='fair-turns-stub';(d as any).keywordGate=undefined;
  (d as any).pipeRun=async(_args:string[],text:string)=>{const label=/\/(\w+)\?/.exec(text)?.[1];if(label&&!started.includes(label))started.push(label);await sleep(40);return '[]';};
}
test('mass mode: preflight screenings of one target take turns with other targets for the shared engine lanes, and the wait is reported as preflightMs (2.9.1)',{timeout:60000},async()=>{
  const d=new Detector(),started:string[]=[];stubEngine(d,started);
  const make=(host:string)=>new Scanner({urls:[`https://${host}.invalid`],semanticAnalysis:false,originMaxDurationMs:60000,maxDurationMs:60000},{detector:d,excludeSharedWaits:true});
  const a=make('one'),b=make('two');
  try{
    const screen=(scan:Scanner,origin:string,label:string)=>scan.transport.originControl.run(origin+'/',()=>scan.transport.preflight(`${origin}/${label}?api_key=x`)).catch(()=>undefined);
    await holdEngineLanes(d,800);
    const waits=[screen(a,'https://one.invalid','A1'),screen(a,'https://one.invalid','A2'),screen(a,'https://one.invalid','A3'),screen(a,'https://one.invalid','A4'),screen(a,'https://one.invalid','A5')];
    await sleep(100);waits.push(screen(b,'https://two.invalid','B1'));
    await Promise.all(waits);
    assert.deepEqual(started,['A1','A2','A3','B1','A4','A5'],'B\'s screening got the next turn after the ones that held the turns, not after all of A\'s');
    for(const [scan,origin] of [[a,'https://one.invalid'],[b,'https://two.invalid']] as const){
      const site=scan.transport.originControl.snapshots().find(s=>s.origin===origin)!,causes=site.sharedWaitByCause!;
      assert.ok(causes.preflightMs>0,`${origin}: the wait is a preflight wait: ${JSON.stringify(causes)}`);assert.equal(causes.analysisMs+causes.programSlotMs+causes.parserMs,0);
      assert.equal(causes.analysisMs+causes.parserMs+causes.preflightMs+causes.programSlotMs,site.sharedWaitMs,'the causes add up to sharedWaitMs');
      const p=scan.transport.originControl.projectWait();assert.equal(p.sharedWaitByCause.analysisMs+p.sharedWaitByCause.parserMs+p.sharedWaitByCause.preflightMs+p.sharedWaitByCause.programSlotMs,p.sharedWaitMs);
    }
    assert.equal((d as any).engineTurns.stats().active,0,'every turn was released');
  }finally{a.dispose();b.dispose();}
});
test('outside mass mode preflight takes no turn: the lanes stay first come, first served (2.9.1)',{timeout:60000},async()=>{
  const d=new Detector(),started:string[]=[];stubEngine(d,started);
  const make=(host:string)=>new Scanner({urls:[`https://${host}.invalid`],semanticAnalysis:false,originMaxDurationMs:60000,maxDurationMs:60000},{detector:d});
  const a=make('one'),b=make('two');
  try{
    const screen=(scan:Scanner,origin:string,label:string)=>scan.transport.originControl.run(origin+'/',()=>scan.transport.preflight(`${origin}/${label}?api_key=x`)).catch(()=>undefined);
    await holdEngineLanes(d,500);
    const waits=['A1','A2','A3','A4'].map(l=>screen(a,'https://one.invalid',l));await sleep(100);waits.push(screen(b,'https://two.invalid','B1'));
    await Promise.all(waits);assert.deepEqual(started,['A1','A2','A3','A4','B1']);assert.equal((d as any).engineTurns.stats().granted,0,'no turn was taken');
  }finally{a.dispose();b.dispose();}
});
