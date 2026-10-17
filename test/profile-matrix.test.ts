import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import { appendFileSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
/** scripts/profile-matrix.mjs (the ready-option measurement runner) in a throwaway project: a stub case script stands in for the real scans, so this checks what the runner
 * decides to run, how many cases run at once and in what order, what it records, and what the report says, in seconds and without network or Chromium. */
const root=fileURLToPath(new URL('../../',import.meta.url)),tree=mkdtempSync(path.join(os.tmpdir(),'profile-matrix-')),work=path.join(tree,'work'),trace=path.join(tree,'trace.jsonl');
const runner=path.join(tree,'scripts','profile-matrix.mjs'),results=path.join(work,'results.jsonl');
for(const d of ['scripts','dist/src','dist/test'])mkdirSync(path.join(tree,d),{recursive:true});
copyFileSync(path.join(root,'scripts','profile-matrix.mjs'),runner);
for(const f of ['virtual-network.js','tls-fixture.js','large-bundle.js'])writeFileSync(path.join(tree,'dist','test',f),`// stub ${f}\n`);
const build=(id:string)=>writeFileSync(path.join(tree,'dist','src','build-info.js'),`export const BUILD = { "version": "2.6.0-rc.1", "id": "${id}" };\n`);
build('2.6.0-rc.1+one');
// The stub scan: Quick 60 ms, Standard 120 ms, Deep 240 ms; STUB_FAIL exits without a result, STUB_HANG never finishes (with a child process of its own), STUB_LOWER reports lowered memory,
// STUB_CHILDREN reports analysis processes (STUB_OVER: more heap limit at once than the setting), STUB_LESS finds one key fewer.
writeFileSync(path.join(tree,'scripts','profile-matrix-case.mjs'),`import {appendFileSync} from 'node:fs';import {spawn} from 'node:child_process';import path from 'node:path';import {pathToFileURL} from 'node:url';
const spec=JSON.parse(Buffer.from(process.argv[2],'base64').toString()),env=process.env,has=v=>v&&spec.id.includes(v);
const trace=e=>appendFileSync(env.STUB_TRACE,JSON.stringify({id:spec.id,e,t:Date.now(),dataDir:spec.dataDir,dataEnv:env.EXPOSURE_DATA_DIR})+'\\n');trace('start');
if(has(env.STUB_HANG)){const g=spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'ignore'});appendFileSync(env.STUB_TRACE,JSON.stringify({id:spec.id,e:'grandchild',pid:g.pid})+'\\n');setInterval(()=>{},1000);}
else{const ms={quick:60,standard:120,deep:240}[spec.coverage]??30;await new Promise(r=>setTimeout(r,ms));if(has(env.STUB_FAIL))process.exit(3);
  const {BUILD}=await import(pathToFileURL(path.join(spec.dist,'src','build-info.js')).href),used={websitesAtOnce:spec.websites,browserWebsitesAtOnce:0,analysisMemoryMb:has(env.STUB_LOWER)?128:256,analysisWorkers:1};trace('end');
  const row=spec.mode==='resources'?{id:spec.id,mode:'resources',rows:[1,3,10].flatMap(websites=>['quick','standard','deep'].flatMap(coverage=>['normal','low-impact'].map(traffic=>({websites,computer:'this computer',coverage,traffic,resourceUse:{used:{...used,websitesAtOnce:websites,analysisMemoryMb:256},adjustments:[]}}))))}
    :{id:spec.id,mode:'scan',build:BUILD.id,fixture:spec.fixture,websites:spec.websites,coverage:spec.coverage,traffic:spec.traffic,computer:spec.computer?'small (2 cores, 1 GiB free)':'this computer',state:'completed',durationMs:ms,peakRssMb:100,workerHeap:{},
      ...(has(env.STUB_CHILDREN)?{analysisChildren:{byRole:{parser:{children:1,limits:[256],startupMs:[70],peakRssMb:40,outOfMemory:0},detector:{children:2,limits:[64],startupMs:[120],peakRssMb:56,outOfMemory:0}},concurrentHeapMb:has(env.STUB_OVER)?320:256,concurrentPeakRssMb:96,combinedPeakRssMb:196}}:{}),
      server:{requests:10,tcpConnections:spec.traffic==='low-impact'?2:10,tlsHandshakes:2,wireBytes:1000,peakWebsitesInFlight:1},browser:{peakBrowserOrigins:0},resourceUse:{option:{websitesAtOnce:6,browserWebsitesAtOnce:0,analysisMemoryMb:256},used,computer:{cores:16,freeMemoryMb:8000}},
      coverageView:{},statedLimits:[],recall:{found:has(env.STUB_LESS)?7:8,planted:8,missing:has(env.STUB_LESS)?['s:depth5']:[]},precision:{matched:8,findings:8},egressViolations:[]};
  process.stdout.write('starting\\nRESULT '+JSON.stringify(row)+'\\n');}
`);
const run=(args:string[],env:Record<string,string>={})=>{const r=spawnSync(process.execPath,[runner,'--work',work,...args],{encoding:'utf8',windowsHide:true,timeout:120000,env:{...process.env,EXPOSURE_DATA_DIR:'',STUB_TRACE:trace,...env}});
  assert.equal(r.status,0,r.stderr);return r.stdout;};
const rows=()=>readFileSync(results,'utf8').split('\n').filter(Boolean).map(l=>JSON.parse(l));
const events=(from=0)=>readFileSync(trace,'utf8').split('\n').filter(Boolean).map(l=>JSON.parse(l)).slice(from);
const traced=()=>existsSync(trace)?events().length:0;
const MULTI3=['quick','standard','deep'].flatMap(c=>['normal','low-impact'].map(t=>`2.6/${c}+${t}/multix3`));
test.after(()=>rmSync(tree,{recursive:true,force:true,maxRetries:5,retryDelay:200}));

test('profile matrix: runs each selected case once, records what measured it, and repeats nothing current', ()=>{
  const out=run(['--only','multix3','v26']),r=rows();
  assert.deepEqual(r.map(x=>x.id).sort(),[...MULTI3].sort());
  for(const id of MULTI3)assert.match(out,new RegExp(`^${id.replace(/[.+]/g,'\\$&')} … completed \\d+s req=10`,'m'),'serial output keeps one "id … result" line per case');
  for(const x of r){assert.equal(x.key.build,'2.6.0-rc.1+one');assert.match(x.key.harness,/^[0-9a-f]{16}$/);assert.equal(x.key.node,process.version);assert.equal(x.run.jobs,1);}
  const started=events().filter(e=>e.e==='start');assert.ok(started.every(e=>e.dataEnv===e.dataDir&&e.dataDir.startsWith(path.join(work,'data'))));assert.equal(new Set(started.map(e=>e.dataDir)).size,6,'each case has its own data folder');
  assert.match(run(['--only','multix3','v26']),/nothing to run: all 6 selected cases are current/);
});

test('profile matrix: a new build repeats its cases several at once, longest first, and keeps the replaced rows', ()=>{
  build('2.6.0-rc.1+two');
  const status=run(['--only','multix3','status','v26']);
  assert.equal(status.match(/measured by build 2\.6\.0-rc\.1\+one, now 2\.6\.0-rc\.1\+two/g)?.length,6);assert.match(status,/6 selected; 0 current; 6 to run; about \d+ min one at a time/);
  const before=traced(),out=run(['--jobs','3','--only','multix3','v26']),ev=events(before);
  let now=0,most=0;for(const e of ev.filter(e=>e.e!=='grandchild').sort((a,b)=>a.t-b.t)){now+=e.e==='start'?1:-1;most=Math.max(most,now);}
  assert.ok(most>=2&&most<=3,`at most 3 cases at once, and more than one (saw ${most})`);
  assert.deepEqual(ev.filter(e=>e.e==='start').slice(0,3).map(e=>e.id.split('/')[1].split('+')[0]).sort(),['deep','deep','standard'],'the longest cases start first');
  assert.match(out,/\(6\/6\)/);assert.match(out,/ran 6 of 6 selected cases \(0 already current\) in \d+ min with --jobs 3; 0 failed/);
  assert.ok(rows().every(x=>x.key.build==='2.6.0-rc.1+two'&&x.run.jobs===3));
  const history=readFileSync(path.join(work,'results-history.jsonl'),'utf8').split('\n').filter(Boolean).map(l=>JSON.parse(l));
  assert.equal(history.length,6);assert.ok(history.every(h=>h.key.build==='2.6.0-rc.1+one'&&h.replacedAt));
});

test('profile matrix: a serial run repeats cases measured alongside others; --only and --rerun pick cases', ()=>{
  assert.equal(run(['--only','multix3','status','v26']).match(/measured alongside other cases \(--jobs 3\)/g)?.length,6);
  assert.match(run(['--jobs','3','--only','multix3','status','v26']),/6 selected; 6 current; 0 to run/);
  assert.match(run(['--only','2.6/deep+normal/*x3','v26']),/ran 1 of 1 selected cases/);
  assert.match(run(['--jobs','3','--rerun','--only','quick+normal/multix3','v26']),/ran 1 of 1 selected cases \(0 already current\)/);
  assert.match(run(['--only','nothing-like-this','v26']),/no case matches --only nothing-like-this/);
});

test('profile matrix: a failed case runs again in an empty data folder, and a changed harness repeats everything', ()=>{
  const dir=path.join(work,'data','2.6_quick+low-impact_multix3');writeFileSync(path.join(dir,'left-from-an-earlier-run'),'x');
  assert.match(run(['--rerun','--only','quick+low-impact/multix3','v26'],{STUB_FAIL:'quick+low-impact/multix3'}),/ERROR child exited 3 without a result/);
  assert.ok(!existsSync(path.join(dir,'left-from-an-earlier-run')),'the case data folder is cleared before a run');
  assert.match(run(['--jobs','3','--only','multix3','status','v26']),/2\.6\/quick\+low-impact\/multix3 — failed: child exited 3 without a result\n6 selected; 5 current; 1 to run/);
  assert.match(run(['--jobs','3','--only','multix3','v26']),/ran 1 of 6 selected cases \(5 already current\)/);
  appendFileSync(path.join(tree,'dist','test','tls-fixture.js'),'// changed\n');
  assert.equal(run(['--jobs','3','--only','multix3','status','v26']).match(/measurement harness changed/g)?.length,6);
  assert.match(run(['--jobs','3','--only','multix3','v26']),/ran 6 of 6/);
});

test('profile matrix: a case past its time limit is stopped together with the processes it started', ()=>{
  const before=traced(),out=run(['--timeout-min','0.02','--only','quick+normal/singlex1','v26'],{STUB_HANG:'quick+normal/singlex1'});
  assert.match(out,/ERROR stopped after 0\.02 min without a result/);
  const pid=events(before).find(e=>e.e==='grandchild')?.pid;assert.ok(pid);
  assert.throws(()=>process.kill(pid,0),'the stuck case\'s own child process is gone too');
  assert.match(readFileSync(path.join(work,'logs','2.6_quick+normal_singlex1.log'),'utf8'),/\[profile-matrix\] stopped after 0\.02 min/);
});

test('profile matrix: the report keeps one row per case, marks stale rows and checks each scan used the recorded settings', ()=>{
  run(['resources']);run(['--rerun','--only','deep+low-impact/multix3','v26'],{STUB_LOWER:'deep+low-impact/multix3'});
  appendFileSync(results,readFileSync(results,'utf8').split('\n').find(l=>l.includes('"2.6/quick+normal/multix3"'))+'\n');// a duplicate an older runner could leave
  build('2.6.0-rc.1+three');
  const out=run(['report']),md=readFileSync(path.join(work,'matrix.md'),'utf8');
  assert.match(out,/rows 8; checks \d+; failing \d+; stale 7; failed 1/);
  assert.equal(md.split('\n').filter(l=>l.startsWith('| 2.6 | quick+normal | multi×3 |')).length,1,'one table row per case');
  assert.match(md,/\| completed · stale \|/);
  assert.match(md,/## Freshness\n\n- 2\.6 source build: 2\.6\.0-rc\.1\+three, harness [0-9a-f]{16}, Node v[\d.]+\n- baseline rows not checked: run report with --baseline/);
  assert.match(md,/- 2\.6\/quick\+normal\/singlex1: failed: stopped after 0\.02 min without a result/);
  assert.match(md,/- FAIL Settings as recorded — 2\.6\/deep\+low-impact\/multix3: analysisMemoryMb 128 \(recorded 256\); 8000 MiB free when the scan started/);
  assert.match(md,/- PASS Settings as recorded — 2\.6\/deep\+normal\/multix3: same as the resources phase/);
  const json=JSON.parse(readFileSync(path.join(work,'matrix.json'),'utf8'));assert.equal(json.schema,'exposure-profile-matrix/1');assert.equal(json.freshness.current.source.build,'2.6.0-rc.1+three');assert.deepEqual(json.labels,{source:'2.6',baseline:null});
});

test('profile matrix: prev runs the same options on an earlier release under its version; analysis processes and recall are checked against it', ()=>{
  const baseline=path.join(tree,'release 2.5.9');mkdirSync(path.join(baseline,'dist','src'),{recursive:true});
  writeFileSync(path.join(baseline,'dist','src','build-info.js'),'export const BUILD = { "version": "2.5.9", "id": "2.5.9+base" };\n');
  assert.throws(()=>run(['--only','singlex1','prev']),/--baseline <extracted release folder> is required for the prev phase/);
  const out=run(['--baseline',baseline,'--only','quick+normal/singlex1,quick+low-impact/singlex1','prev','current'],{STUB_CHILDREN:'singlex1',STUB_OVER:'quick+low-impact/singlex1',STUB_LESS:'2.6/quick+low-impact/singlex1'});
  assert.match(out,/ran 4 of 4 selected cases/);assert.ok(rows().some(x=>x.id==='2.5.9/quick+normal/singlex1'&&x.key.build==='2.5.9+base'));
  run(['--baseline',baseline,'report']);const md=readFileSync(path.join(work,'matrix.md'),'utf8');
  assert.match(md,/## Freshness\n\n- 2\.6 source build: 2\.6\.0-rc\.1\+three, harness [0-9a-f]{16}, Node v[\d.]+\n- 2\.5\.9 baseline: 2\.5\.9\+base, harness/);
  const first=md.indexOf('| 2.5.9 | quick+normal | single×1 |');assert.ok(first>0&&first<md.indexOf('| 2.6 | quick+normal | multi×3 |'),'baseline rows come first');
  assert.match(md,/\| parser 1×256, detector 2×64; ≤256 at once \| 96 \|/);assert.match(md,/\| 2\.6 \| quick\+normal \| multi×3 \|.*\| — \| — \|/);
  assert.match(md,/- PASS Within limits — 2\.6\/quick\+normal\/singlex1: analysis processes parser 1×256, detector 2×64 MiB, at most 256 MiB of heap limits at once of 256 MiB/);
  assert.match(md,/- FAIL Within limits — 2\.6\/quick\+low-impact\/singlex1: analysis processes .*at most 320 MiB of heap limits at once of 256 MiB/);
  assert.match(md,/- PASS Keeps the 2\.5\.9 recall — 2\.6\/quick\+normal\/singlex1: 8\/8 vs 8\/8/);
  assert.match(md,/- FAIL Keeps the 2\.5\.9 recall — 2\.6\/quick\+low-impact\/singlex1: 7\/8 vs 8\/8/);
  assert.ok(!/(?:Within limits|Finds its keys|Settings as recorded) — 2\.5\.9\//.test(md),'acceptance checks cover the source build only');
  const json=JSON.parse(readFileSync(path.join(work,'matrix.json'),'utf8'));assert.deepEqual(json.labels,{source:'2.6',baseline:'2.5.9'});assert.equal(json.freshness.current.base.build,'2.5.9+base');
});
