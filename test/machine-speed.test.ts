import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { parse } from 'acorn';
import { Scanner } from '../src/scanner.js';
import { SemanticPool, GROUP_SLICE_MS, GROUP_TIMEOUT_MS, GROUP_MARGIN_MS, VIEW_INSPECTION_MS } from '../src/semantic.js';
import { Detector } from '../src/detectors.js';
import { WebsiteBudget } from '../src/adaptive-budget.js';
import { makeConfig } from '../src/config.js';
import { report } from '../src/reports.js';
import { TIME_FACTOR_ENV, CALIBRATION, MEASURED_FACTOR_MAX, OVERRIDE_FACTOR_MAX, factorFrom, timeFactorOverride, scaleMs, runRounds, calibrate, calibrationSource, countNodes, currentTimeFactor, analysisTimeFactor, adoptTimeFactor, resetTimeFactorForTests } from '../src/machine-speed.js';
import { syntheticBundle } from './large-bundle.js';
import { synthetic } from '../src/fixture.js';

/** 2.8 w3-speed: the analysis time factor. Wall-clock analysis budgets scale on a slower computer (measured once per process, or EXPOSURE_ANALYSIS_TIME_FACTOR); a fast computer keeps the reference budgets.
 * Memory budgets and the scan's duration limits never scale. Loopback fixtures and synthetic keys only. */
const BIG={cores:16,freeMemoryMb:32768};
async function withFactor<T>(value:string|undefined,run:()=>Promise<T>|T):Promise<T>{
  const before=process.env[TIME_FACTOR_ENV];if(value===undefined)delete process.env[TIME_FACTOR_ENV];else process.env[TIME_FACTOR_ENV]=value;
  try{return await run();}finally{if(before===undefined)delete process.env[TIME_FACTOR_ENV];else process.env[TIME_FACTOR_ENV]=before;}
}
async function serve(routes:Record<string,[string,string]>){const server=http.createServer((q,r)=>{const x=routes[q.url||''];if(!x){r.statusCode=404;r.end('not found');return;}r.writeHead(200,{'content-type':x[0]});r.end(x[1]);});await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));const origin=`http://127.0.0.1:${(server.address() as any).port}`;return {origin,close:()=>new Promise<void>(r=>{server.closeAllConnections();server.close(()=>r());})};}

test('EXPOSURE_ANALYSIS_TIME_FACTOR: a positive number clamped to 1–8 (two decimals); anything else is ignored and reported as invalid',()=>{
  assert.equal(timeFactorOverride({}),undefined);assert.equal(timeFactorOverride({[TIME_FACTOR_ENV]:'  '}),undefined);
  for(const bad of ['abc','0','-2','NaN','Infinity','2x'])assert.deepEqual(timeFactorOverride({[TIME_FACTOR_ENV]:bad}),{invalid:bad},bad);
  assert.deepEqual(timeFactorOverride({[TIME_FACTOR_ENV]:'0.5'}),{factor:1,raw:'0.5'},'never below the reference budgets');
  assert.deepEqual(timeFactorOverride({[TIME_FACTOR_ENV]:' 2.5 '}),{factor:2.5,raw:'2.5'});
  assert.deepEqual(timeFactorOverride({[TIME_FACTOR_ENV]:'1.234'}),{factor:1.23,raw:'1.234'});
  assert.deepEqual(timeFactorOverride({[TIME_FACTOR_ENV]:'20'}),{factor:8,raw:'20'},'clamped to 8');
  assert.equal(OVERRIDE_FACTOR_MAX,8);assert.equal(MEASURED_FACTOR_MAX,4);
});

test('the factor in effect: explicit beats measured beats the reference default; an invalid value is ignored with a note; an analysis child adopts its scan process factor',async()=>{
  resetTimeFactorForTests();
  await withFactor(undefined,()=>{const f=currentTimeFactor();assert.deepEqual([f.factor,f.source],[1,'default']);assert.equal(scaleMs(GROUP_SLICE_MS),GROUP_SLICE_MS);});
  await withFactor('3',async()=>{const f=currentTimeFactor();assert.deepEqual([f.factor,f.source],[3,'override']);assert.match(f.detail,/^Set by EXPOSURE_ANALYSIS_TIME_FACTOR=3 /);assert.equal(scaleMs(GROUP_SLICE_MS),4800);
    const at=performance.now(),scan=await analysisTimeFactor();assert.equal(scan.factor,3);assert.ok(performance.now()-at<100,'an explicit factor needs no calibration');});
  await withFactor('fast',()=>{const f=currentTimeFactor();assert.deepEqual([f.factor,f.source],[1,'default']);assert.match(f.detail,/EXPOSURE_ANALYSIS_TIME_FACTOR="fast" is not a positive number and was ignored\./);});
  adoptTimeFactor(2.5);
  await withFactor(undefined,()=>{const f=currentTimeFactor();assert.deepEqual([f.factor,f.source,f.detail],[2.5,'measured','Adopted from the scan process.']);assert.equal(scaleMs(GROUP_TIMEOUT_MS),6250);});
  await withFactor('1',()=>assert.equal(currentTimeFactor().factor,1,'an explicit factor wins over an adopted one'));
  for(const bad of [0.5,9,Number.NaN,'2',undefined]){resetTimeFactorForTests();adoptTimeFactor(bad);await withFactor(undefined,()=>assert.equal(currentTimeFactor().source,'default',String(bad)));}
  resetTimeFactorForTests();
});
test('a detector used before any scan in its process measures this computer first, so its isolated-inspection and engine budgets never default to the reference speed; an adopted or explicit factor is used as is',{timeout:60000},async()=>{
  // w4-linuxfix: on the 2-vCPU Linux runner a large-text inspection made before any scan ran on the reference 10 s budget (factor 1, never measured) and timed out.
  const text='a;'.repeat(70000)+'\nvar k="'+synthetic.openai+'";';assert.ok(text.length>131072,'large enough for the isolated analysis process');
  await withFactor(undefined,async()=>{
    for(const call of ['inspect','inspectBounded'] as const){
      resetTimeFactorForTests();assert.equal(currentTimeFactor().source,'default');
      const found=await new Detector('disabled')[call](text);
      assert.equal(currentTimeFactor().source,'measured',call+' waits for the one bounded measurement');assert.ok(found.some(c=>c.value===synthetic.openai),call+' still inspects the text');
    }
    resetTimeFactorForTests();adoptTimeFactor(2);await new Detector('disabled').inspect(text);
    assert.equal(currentTimeFactor().detail,'Adopted from the scan process.','an analysis child keeps its scan process factor and measures nothing');
  });
  resetTimeFactorForTests();
  await withFactor('2',async()=>{const at=performance.now();await new Detector('disabled').inspectBounded('const small=1;');assert.ok(performance.now()-at<1000,'an explicit factor needs no measurement');assert.equal(currentTimeFactor().source,'override');});
  resetTimeFactorForTests();
});

test('measured factor: reference speed within the 1.5× deadband, fewer than four usable CPUs share the analysis threads, whole quarters, 1 to 4; factor 1 keeps every reference budget',()=>{
  const cases:[number|undefined,number,number][]=[[undefined,16,1],[0.5,16,1],[1,16,1],[1.5,16,1],[1.6,16,1.75],[2.1,8,2.25],[3,4,3],[10,16,4],[1,4,1],[1,3,1.5],[1,2,2],[1.2,2,2],[2,2,4],[1,1,4],[1.3,1,4],[1,0,4],[1,2.9,2],[undefined,2,2]];
  for(const [ratio,cpus,factor] of cases)assert.equal(factorFrom(ratio,cpus),factor,`speed ratio ${ratio} on ${cpus} CPUs`);
  assert.deepEqual([GROUP_SLICE_MS,GROUP_TIMEOUT_MS,GROUP_MARGIN_MS,VIEW_INSPECTION_MS],[1600,2500,750,2000],'the 2.7 reference budgets');
  for(const ms of [GROUP_SLICE_MS,GROUP_TIMEOUT_MS,GROUP_SLICE_MS+GROUP_MARGIN_MS,VIEW_INSPECTION_MS,250,1000,10000,12000])assert.equal(scaleMs(ms,1),ms);
  assert.equal(scaleMs(1600,2.5),4000);assert.equal(scaleMs(2350,1.75),4113);assert.equal(scaleMs(12000,4),48000);
});

test('calibration rounds stop at the first round inside the deadband, or after the round limit (injected clock); the workload is deterministic',()=>{
  const rounds=(durations:number[],limit:number)=>{let t=0,i=0;const seen:number[]=[];const times=runRounds(()=>{t+=durations[i++];},{rounds:limit,stopBelowMs:30,now:()=>t,onRound:ms=>seen.push(ms)});assert.deepEqual(seen,times);return times;};
  assert.deepEqual(rounds([50,40,25,35],6),[50,40,25],'stops at the first fast round');
  assert.deepEqual(rounds([50,45,40,35,33,31,29],6),[50,45,40,35,33,31],'at most the round limit');
  assert.deepEqual(rounds([10],6),[10]);
  const source=calibrationSource();assert.equal(source,calibrationSource());assert.equal(source.split('\n').length,CALIBRATION.lines);
  const nodes=countNodes(parse(source,{ecmaVersion:'latest',sourceType:'module'}));assert.equal(nodes,countNodes(parse(calibrationSource(),{ecmaVersion:'latest',sourceType:'module'})));assert.ok(nodes>40000,`${nodes} nodes`);
});

test('the calibration is bounded in time: a real measurement, a round that cannot finish (counted as slow) and a worker that cannot start in time (speed unknown)',{timeout:30000},async()=>{
  const limit=CALIBRATION.startupLimitMs+CALIBRATION.measureLimitMs;
  let at=performance.now();const real=await calibrate();let elapsed=performance.now()-at;
  assert.ok(elapsed<limit+1000,`the default calibration ends within its limits (${Math.round(elapsed)} ms)`);assert.ok(real.calibrationMs!<=limit+500);
  assert.equal(real.source,'measured');assert.ok(real.factor>=1&&real.factor<=MEASURED_FACTOR_MAX);assert.ok(real.cpus!>=1);assert.ok(real.rounds!<=CALIBRATION.rounds);assert.match(real.detail,/^Measured: .* usable CPUs? for 4 analysis threads\.$/);
  at=performance.now();const slow=await calibrate({lines:40000,warmup:0,measureLimitMs:100,cpus:16});elapsed=performance.now()-at;
  assert.deepEqual([slow.capped,slow.rounds,slow.factor],[true,0,MEASURED_FACTOR_MAX],'a round that cannot finish within the limit counts as slow');assert.match(slow.detail,/no calibration round finished within 100 ms \(counted as slow\)/);
  assert.ok(elapsed<CALIBRATION.startupLimitMs+100+1000,`ended at the measure limit (${Math.round(elapsed)} ms)`);
  const unknown=await calibrate({startupLimitMs:1,cpus:2});
  assert.deepEqual([unknown.capped,unknown.speedRatio,unknown.factor],[true,undefined,2],'speed unknown counts as the reference; two CPUs share four analysis threads');assert.match(unknown.detail,/did not start within 1 ms/);
  assert.equal((await calibrate({cpus:1})).factor,MEASURED_FACTOR_MAX,'one usable CPU');
});

test('per-website analysis allocation: factor 1 keeps the 2.7 values; a factor scales only the analysis time (initial allocation, growth and maximum) and says so',()=>{
  const origin='http://127.0.0.1:9',config=makeConfig({urls:[origin+'/'],sizingMode:'adaptive'}),bundle={url:origin+'/bundle.js',kind:'module',resourceType:'javascript',bytes:1252570} as any;
  const reference=new WebsiteBudget(origin,config),scaled=new WebsiteBudget(origin,config,2.5),without=({analysisMs,...rest}:WebsiteBudget['effective'])=>rest;
  assert.equal(reference.maximum.analysisMs,12000);assert.equal(reference.effective.analysisMs,1600);assert.ok(!reference.snapshot().reasons.some(r=>/Analysis time ×/.test(r)));
  assert.equal(scaled.maximum.analysisMs,30000);assert.equal(scaled.effective.analysisMs,4000);
  assert.ok(scaled.snapshot().reasons.includes("Analysis time ×2.5 for this computer's analysis speed (allocation and maximum); other allocations unchanged."),'the budget states the factor');
  assert.deepEqual(without(scaled.maximum),without(reference.maximum));
  reference.response(bundle);scaled.response(bundle);
  assert.equal(reference.effective.analysisMs,4100,'1600 + 5 × 500 ms for a 1.25 MB bundle');assert.equal(scaled.effective.analysisMs,10250);
  assert.deepEqual(without(scaled.effective),without(reference.effective),'resources, pages, bytes and maps never scale');
  const late=new WebsiteBudget(origin,config);late.response(bundle);late.setTimeFactor(2.5);
  assert.deepEqual([late.maximum,late.effective],[scaled.maximum,scaled.effective],'a budget created before the scan had its factor is rescaled as if created with it');assert.equal(late.snapshot().reasons.filter(r=>r.startsWith('Analysis time ×2.5 ')).length,1);
  late.setTimeFactor(1);assert.deepEqual([late.maximum.analysisMs,late.effective.analysisMs],[12000,4100]);assert.ok(!late.snapshot().reasons.some(r=>r.startsWith('Analysis time ×')));
});

test('the parser group time limit scales: a job held back past the 2500 ms reference limit times out at factor 1 and completes at factor 2',{timeout:60000},async()=>{
  const sources=[{url:'http://127.0.0.1:9/a.js',text:'export const a="x"+"y";'}];
  for(const [value,timesOut] of [['1',true],['2',false]] as const)await withFactor(value,async()=>{
    const pool=new SemanticPool(1,128);pool.jobDelayMs=2600;
    try{const r=await pool.run(sources),limit=r.gaps.find(g=>g.code==='semantic-time-limit');
      if(timesOut){assert.equal(r.stats.outcome,'timeout');assert.match(limit?.detail||'',/exceeded 2500 ms/);}
      else{assert.equal(r.stats.outcome,'completed',JSON.stringify(r.gaps));assert.equal(limit,undefined);}
    }finally{await pool.dispose();}
  });
});

test('a 1.25 MB bundle on a slow computer (forced factor, parser job held back 2.5 s): missed with the reference budgets, found with scaled ones, and the scan reports the factor and its budgets',{timeout:240000},async()=>{
  const bundle=syntheticBundle({seed:'ExposureDesk/ready-options/1',targetBytes:1252570});
  const site=await serve({'/':['text/html','<!doctype html><script type="module" src="/bundle.js"></script>'],'/bundle.js':['text/javascript',bundle.text],'/robots.txt':['text/plain','User-agent: *\nAllow: /\n']});
  try{
    for(const value of ['1','4'])await withFactor(value,async()=>{
      const s=new Scanner({urls:[site.origin+'/'],developmentFixtureOrigin:site.origin,coverage:'quick',traffic:'normal'},{detector:new Detector(),computer:BIG});s.pool.jobDelayMs=2500;
      try{await s.init();const v=await s.run(),found=[...s.evidence.findings.values()].some(f=>s.evidence.reveal(f.id).value===bundle.value),a=v.analysis!,o=a.origins[site.origin],note=/Analysis time budgets ×4 for this computer \(Set by EXPOSURE_ANALYSIS_TIME_FACTOR=4 /;
        assert.equal(s.caps.analysisMemoryMb,256,'memory is never scaled');
        if(value==='1'){
          assert.equal(found,false,'the reference budgets run out before the slowed parser job');assert.ok(v.limitations.some(g=>g.code==='semantic-time-limit'&&/exceeded 2350 ms/.test(g.detail)),'the gap is stated');
          assert.deepEqual(a.timeFactor,{factor:1,source:'override',detail:a.timeFactor!.detail,sliceMs:1600,groupTimeoutMs:2350,viewInspectionMs:2000});assert.equal(o.maximumMs,12000);assert.doesNotMatch(a.note,/Analysis time budgets/);
        }else{
          assert.equal(found,true,'the scaled budgets leave time for the slowed parser job');assert.ok(!v.limitations.some(g=>g.code==='semantic-time-limit'),JSON.stringify(v.limitations.map(g=>g.code)));
          assert.deepEqual(a.timeFactor,{factor:4,source:'override',detail:a.timeFactor!.detail,sliceMs:6400,groupTimeoutMs:9400,viewInspectionMs:8000});assert.equal(o.maximumMs,48000);assert.ok(o.allocationMs>=16400,`allocation ${o.allocationMs} ms`);
          assert.match(a.note,note);assert.match(report(s,'html'),/&quot;timeFactor&quot;|"timeFactor"/);
        }
      }finally{s.dispose();}
    });
  }finally{await site.close();}
});
