import test from 'node:test';
import assert from 'node:assert/strict';
import {Detector,AnalysisInterrupted} from '../src/detectors.js';
import {FifoBudget} from '../src/fifo-budget.js';
// The engine is replaced by gates the test opens one at a time, so lane order is decided by the queue alone, never by timers.
function gatedDetector(){
  const d=new Detector('disabled'),started:{label:string;finish:()=>void}[]=[];
  const engine=(_args:string[],text:string)=>new Promise<string>(resolve=>started.push({label:text,finish:()=>resolve('[]')}));
  Object.assign(d,{pipeRun:engine,fileRun:engine});
  return {d,started,run:(label:string)=>(d as any).run(['stdin'],label) as Promise<string>};
}
const settle=async()=>{for(let i=0;i<5;i++)await new Promise(r=>setImmediate(r));};
test('engine lanes are first come, first served: back-to-back analysis calls never overtake a waiting request preflight',{timeout:10000},async()=>{
  const {started,run}=gatedDetector();
  // Two static-analysis chains call the engine back to back (raw text, then decoded views), as inspectFresh does.
  const chain=async(name:string)=>{for(let i=0;i<4;i++)await run(name+i);},chains=[chain('a'),chain('b')];await settle();
  assert.deepEqual(started.map(s=>s.label),['a0','b0']);
  const preflight=run('preflight');await settle();assert.equal(started.length,2,'both lanes are busy, so the preflight waits');
  started[0].finish();await settle();
  assert.equal(started[2]?.label,'preflight','the released lane goes to the waiting preflight, not to the chain that asks again at once');
  for(let i=1;i<started.length;i++){started[i].finish();await settle();}
  assert.equal(await preflight,'[]');await Promise.all(chains);
  assert.deepEqual(started.map(s=>s.label),['a0','b0','preflight','a1','b1','a2','b2','a3','b3']);
});
test('an aborted engine waiter leaves the queue with a typed interruption and takes no lane',{timeout:10000},async()=>{
  const {d,started,run}=gatedDetector(),held=[run('h1'),run('h2')];await settle();
  const controller=new AbortController();d.signal=controller.signal;const aborted=run('aborted');d.signal=undefined;const later=run('later');await settle();
  controller.abort();await assert.rejects(aborted,(e:unknown)=>e instanceof AnalysisInterrupted&&e.phase==='engine-queue');
  started[0].finish();await settle();assert.deepEqual(started.map(s=>s.label),['h1','h2','later']);
  for(const s of started)s.finish();await Promise.all([...held,later]);
  const before=started.length;controller.abort();d.signal=controller.signal;await assert.rejects(run('late'),(e:unknown)=>e instanceof AnalysisInterrupted&&e.phase==='engine-queue');assert.equal(started.length,before,'an already aborted caller never reaches the engine');
});
test('FIFO budget: a large request at the head is not starved by smaller ones behind it, aborts leave the queue, and the peak stays within capacity',async()=>{
  const b=new FifoBudget(4);let short=0;b.whenShort(()=>{short++;});const order:string[]=[];
  await b.acquire(3);const big=b.acquire(4).then(()=>order.push('big')),small=b.acquire(1).then(()=>order.push('small'));await settle();
  assert.deepEqual(order,[],'the small request would fit but waits behind the large one');assert.ok(short>0,'the head waiter that does not fit is reported');assert.equal(b.waiting,2);
  b.release(3);await big;await settle();assert.deepEqual(order,['big']);assert.equal(b.used,4);
  const controller=new AbortController(),gone=b.acquire(2,controller.signal,()=>new Error('stopped'));controller.abort();await assert.rejects(gone,/stopped/);assert.equal(b.waiting,1);
  b.release(4);await small;assert.deepEqual(order,['big','small']);assert.equal(b.used,1);assert.equal(b.peak,4);
  await assert.rejects(b.acquire(5),RangeError);await assert.rejects(b.acquire(0),RangeError);b.release(1);assert.equal(b.used,0);
});
