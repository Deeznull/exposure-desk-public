import os from 'node:os';
import {Worker,isMainThread,parentPort,workerData} from 'node:worker_threads';
/** Analysis time factor (2.8).
 * The wall-clock analysis budgets (the per-website analysis allocation, the parser's group slice and time limit, the reconstructed-view inspection budget and the detector's
 * isolated-inspection, cleanup, decoding and engine limits) were set on a fast reference computer. On a slower computer the same analysis takes longer, so a large bundle's key
 * was missed only because the clock ran out first (the 2-vCPU Linux runner, small VPSes). The factor scales those budgets:
 * - measured once per process: a short, fixed, deterministic parse workload in a worker thread (off the scan's critical path), combined with the CPUs this process may use;
 * - or set with EXPOSURE_ANALYSIS_TIME_FACTOR (tests and operators; 1 to 8).
 * A fast computer measures 1, so its budgets are the reference ones. Memory budgets and the scan's overall duration limits never scale. */
export const TIME_FACTOR_ENV='EXPOSURE_ANALYSIS_TIME_FACTOR';
/** Clamp of a measured factor. */
export const MEASURED_FACTOR_MAX=4;
/** Clamp of an explicit factor (EXPOSURE_ANALYSIS_TIME_FACTOR). */
export const OVERRIDE_FACTOR_MAX=8;
/** Fastest round of the calibration workload on the reference computer (8-core x86-64 laptop CPU, Node 24; the 2.7 budgets were set there). */
export const REFERENCE_ROUND_MS=20;
/** Up to 1.5 times slower per thread than the reference keeps the reference budgets: they leave that much headroom, and it absorbs measurement noise on a busy computer. */
export const SPEED_DEADBAND=1.5;
/** CPU-heavy threads a scan keeps busy while it analyses (the scan process, its garbage collector, the parser process, the detector's isolated inspection); fewer usable CPUs share the time. */
export const ANALYSIS_THREADS=4;
/** Factors are whole quarters, so small measurement differences do not change the budgets. */
const STEP=0.25;
const MARK='exposureDeskCalibration';
export interface TimeFactor {
  factor:number;source:'measured'|'override'|'default';detail:string;
  /** Fastest calibration round relative to the reference (measured only; absent when the calibration could not run). */
  speedRatio?:number;cpus?:number;calibrationMs?:number;rounds?:number;capped?:boolean;
}
export interface CalibrationOptions {lines?:number;warmup?:number;rounds?:number;startupLimitMs?:number;measureLimitMs?:number;cpus?:number}
/** The default calibration: about 100 kB of synthetic module source, two unmeasured warm-up parses, at most six measured rounds (it stops at the first round inside the deadband),
 * at most 3 s for the worker to start and warm up and at most 600 ms of measured rounds. */
export const CALIBRATION:Required<Omit<CalibrationOptions,'cpus'>>={lines:800,warmup:2,rounds:6,startupLimitMs:3000,measureLimitMs:600};

/** Deterministic synthetic module source (no randomness, no secrets): declarations, functions, calls and object literals like a bundled module. */
export function calibrationSource(lines=CALIBRATION.lines):string{
  const out:string[]=[];for(let i=0;i<lines;i++)out.push(`const v${i}=["a${i}",${i}*3+1,{k:'x'+${i},n:[${i},${i+1}]}];function f${i}(a,b){if(a>${i})return a+v${i}[1]*b;return b?f${i}(a+1,b-1):v${i}[2].k;}`);
  return out.join('\n');
}
/** Nodes of an ESTree tree (the walk is part of the workload, like the parser's propagation pass). */
export function countNodes(node:any):number{let n=1;for(const key in node){const v=node[key];if(v&&typeof v==='object'){if(Array.isArray(v)){for(const x of v)if(x&&typeof x.type==='string')n+=countNodes(x);}else if(typeof v.type==='string')n+=countNodes(v);}}return n;}
/** Measured rounds: stops at the first round at or under `stopBelowMs` (fast enough; nothing more to learn) or after `rounds`. */
export function runRounds(once:()=>unknown,options:{rounds:number;stopBelowMs:number;now?:()=>number;onRound?:(ms:number)=>void}):number[]{
  const now=options.now??(()=>performance.now()),times:number[]=[];
  for(let i=0;i<options.rounds;i++){const at=now();once();const ms=now()-at;times.push(ms);options.onRound?.(ms);if(ms<=options.stopBelowMs)break;}
  return times;
}
/** Factor from the fastest round's ratio to the reference and the usable CPUs: whole quarters, 1 to MEASURED_FACTOR_MAX. Unknown speed counts as the reference speed. */
export function factorFrom(speedRatio:number|undefined,cpus:number):number{
  const speed=speedRatio===undefined||!(speedRatio>SPEED_DEADBAND)?1:speedRatio,raw=speed*Math.max(1,ANALYSIS_THREADS/Math.max(1,Math.floor(cpus)||1));
  return Math.min(MEASURED_FACTOR_MAX,Math.max(1,Math.ceil(raw/STEP-1e-9)*STEP));
}
/** The explicit factor: a positive number, clamped to 1–8 (two decimals). Anything else is ignored (the measured factor applies) and reported as invalid. */
export function timeFactorOverride(env:NodeJS.ProcessEnv=process.env):{factor:number;raw:string}|{invalid:string}|undefined{
  const raw=env[TIME_FACTOR_ENV];if(raw===undefined||raw.trim()==='')return;
  const n=Number(raw.trim());if(!Number.isFinite(n)||n<=0)return {invalid:raw.slice(0,40)};
  return {factor:Math.min(OVERRIDE_FACTOR_MAX,Math.max(1,Math.round(n*100)/100)),raw:raw.trim().slice(0,40)};
}
/** `ms` at this factor (whole milliseconds; unchanged at factor 1). */
export function scaleMs(ms:number,factor:number=currentTimeFactor().factor):number{return factor===1?ms:Math.round(ms*factor);}

let measured:TimeFactor|undefined,pending:Promise<TimeFactor>|undefined;
const round2=(n:number)=>Math.round(n*100)/100;
function withInvalid(f:TimeFactor):TimeFactor{const o=timeFactorOverride();return o&&'invalid' in o?{...f,detail:`${f.detail} ${TIME_FACTOR_ENV}=${JSON.stringify(o.invalid)} is not a positive number and was ignored.`}:f;}
function overrideFactor():TimeFactor|undefined{const o=timeFactorOverride();return o&&'factor' in o?{factor:o.factor,source:'override',detail:`Set by ${TIME_FACTOR_ENV}=${o.raw} (explicit factors are clamped to 1–${OVERRIDE_FACTOR_MAX}).`}:undefined;}
/** The factor in effect now (synchronous): the explicit factor, else this process's measurement once it has finished, else 1. */
export function currentTimeFactor():TimeFactor{
  return overrideFactor()??withInvalid(measured??{factor:1,source:'default',detail:'Not measured in this process yet; reference budgets.'});
}
/** The factor for a scan: the explicit factor at once, else this process's measurement (started on first use, then cached; it never rejects). */
export function analysisTimeFactor():Promise<TimeFactor>{
  const explicit=overrideFactor();if(explicit)return Promise.resolve(explicit);
  pending??=calibrate().then(r=>measured=r);
  return pending.then(withInvalid);
}

/** One bounded calibration in a worker thread: at most `startupLimitMs` to start and warm up, then at most `measureLimitMs` of measured rounds; the worker is ended either way.
 * A worker that cannot start in time (or fails) leaves the speed unknown (the CPU count still counts); measured rounds that run past the limit count as slow. */
export function calibrate(options:CalibrationOptions={}):Promise<TimeFactor>{
  const o={...CALIBRATION,...options},cpus=Math.max(1,Math.floor(options.cpus??os.availableParallelism())),started=performance.now();
  return new Promise<TimeFactor>(resolve=>{
    const times:number[]=[];let worker:Worker|undefined,timer:NodeJS.Timeout|undefined,done=false;
    const finish=(how:'done'|'startup-limit'|'measure-limit'|'failure')=>{
      if(done)return;done=true;clearTimeout(timer);void worker?.terminate().catch(()=>{});
      const calibrationMs=Math.round(performance.now()-started),best=times.length?Math.min(...times):undefined;
      const speedRatio=best!==undefined?best/REFERENCE_ROUND_MS:how==='measure-limit'?o.measureLimitMs/REFERENCE_ROUND_MS:undefined,factor=factorFrom(speedRatio,cpus);
      const speed=best!==undefined?`fastest calibration round ${round2(best)} ms (reference ${REFERENCE_ROUND_MS} ms, ${round2(speedRatio!)}× per thread${speedRatio!<=SPEED_DEADBAND?', within the 1.5× deadband':''})`
        :how==='measure-limit'?`no calibration round finished within ${o.measureLimitMs} ms (counted as slow)`:how==='startup-limit'?`the calibration did not start within ${o.startupLimitMs} ms (speed unknown, counted as the reference)`:'the calibration could not run (speed unknown, counted as the reference)';
      resolve({factor,source:'measured',detail:`Measured: ${speed}; ${cpus} usable CPU${cpus===1?'':'s'} for ${ANALYSIS_THREADS} analysis threads.`,...(speedRatio!==undefined?{speedRatio:round2(speedRatio)}:{}),cpus,calibrationMs,rounds:times.length,...(how==='measure-limit'||how==='startup-limit'?{capped:true}:{})});
    };
    try{worker=new Worker(new URL(import.meta.url),{workerData:{[MARK]:true,lines:o.lines,warmup:o.warmup,rounds:o.rounds,stopBelowMs:REFERENCE_ROUND_MS*SPEED_DEADBAND}});}catch{finish('failure');return;}
    timer=setTimeout(()=>finish('startup-limit'),o.startupLimitMs);
    worker.on('message',(m:any)=>{if(m?.type==='ready'){clearTimeout(timer);timer=setTimeout(()=>finish('measure-limit'),o.measureLimitMs);}else if(m?.type==='round')times.push(m.ms);else if(m?.type==='done')finish('done');});
    worker.on('error',()=>finish(times.length?'done':'failure'));worker.on('exit',()=>finish(times.length?'done':'failure'));
  });
}
/** An analysis child process adopts its scan process's factor (sent with each job); an explicit factor in the environment still wins. */
export function adoptTimeFactor(factor:unknown){if(typeof factor==='number'&&Number.isFinite(factor)&&factor>=1&&factor<=OVERRIDE_FACTOR_MAX)measured={factor,source:'measured',detail:'Adopted from the scan process.'};}
/** Test hook: forget this process's measurement. */
export function resetTimeFactorForTests(){measured=undefined;pending=undefined;}

// The calibration worker: imports the parser, warms up, reports each measured round and ends. Importing this module elsewhere has no side effects.
if(!isMainThread&&parentPort&&workerData?.[MARK]){
  const port=parentPort,data=workerData as {lines:number;warmup:number;rounds:number;stopBelowMs:number};
  void import('acorn').then(({parse})=>{
    const source=calibrationSource(data.lines),once=()=>countNodes(parse(source,{ecmaVersion:'latest',sourceType:'module'}));
    for(let i=0;i<data.warmup;i++)once();
    port.postMessage({type:'ready'});
    runRounds(once,{rounds:data.rounds,stopBelowMs:data.stopBelowMs,onRound:ms=>port.postMessage({type:'round',ms})});
    port.postMessage({type:'done'});
  },()=>process.exit(1));
}
