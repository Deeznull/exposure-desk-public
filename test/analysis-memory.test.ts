import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {Detector,AnalysisInterrupted,largeTextHeapMb} from '../src/detectors.js';
import {FifoBudget} from '../src/fifo-budget.js';
import {SemanticPool} from '../src/semantic.js';
import {Scanner} from '../src/scanner.js';
import {syntheticBundle} from './large-bundle.js';
import {analysisProcesses,type AnalysisChildInfo} from '../src/analysis-process.js';
/** 3.0 D10: the detector's large-text workers and the parser workers share one analysis-memory budget (the setting), so their heap limits together never exceed it. Local only: nothing is contacted. */
const MiB=1048576,BIG={cores:16,freeMemoryMb:32768};
// Every analysis process started while tracking adds its heap limit to the live sum until it has ended.
function trackHeaps(){
  let live=0,max=0;const limits:number[]=[],mine=new Set<AnalysisChildInfo>();
  const spawned=(info:AnalysisChildInfo)=>{mine.add(info);limits.push(info.heapMb);live+=info.heapMb;if(live>max)max=live;},ended=(info:AnalysisChildInfo)=>{if(mine.delete(info))live-=info.heapMb;};
  analysisProcesses.events.on('spawn',spawned);analysisProcesses.events.on('end',ended);
  return {limits,get live(){return live;},get max(){return max;},restore(){analysisProcesses.events.off('spawn',spawned);analysisProcesses.events.off('end',ended);}};
}
const fill=(size:number,unit:string,head='',tail='')=>head+unit.repeat(Math.floor((size-head.length-tail.length)/unit.length))+tail;
const shape=(kind:string,mib:number)=>{const size=Math.floor(mib*MiB);return kind==='bundle'?syntheticBundle({targetBytes:size,seed:'ExposureDesk/w1-stable/heap/'+mib}).text:({zeros:()=>fill(size,'0,','var a=[','0];'),stmts:()=>fill(size,'a;'),calls:()=>fill(size,'f(a,b);'),keys:()=>fill(size,'k:1,','var o={','z:1};'),strings:()=>fill(size,'"ab",','var s=[','"z"];'),plus:()=>fill(size,'a+','var x=','a;'),members:()=>fill(size,'a.b;'),b64:()=>'var d="'+Buffer.alloc(Math.floor(size*3/4)-16,7).toString('base64')+'";'} as Record<string,()=>string>)[kind]();};
// A synthetic bundle whose OpenAI key is split in two literals joined at the client call: only the whole-document analysis reconstructs it.
const bundle=(seed:string,targetBytes=1252570)=>{const label='ExposureDesk/w1-stable/analysis-memory/'+seed,rest=createHash('sha512').update(label).digest('base64url').slice(0,64).replace(/[-_]/g,'A');
  return {value:'sk-proj-'+rest,text:syntheticBundle({seed:label,targetBytes}).text.replace('\n//# sourceMapping',`\nconst head="sk-proj-";const rest=${JSON.stringify(rest)};const openai=new OpenAI({apiKey:head+rest});\n//# sourceMapping`)};};
const settle=async(until:()=>boolean)=>{for(let i=0;i<2000&&!until();i++)await new Promise(r=>setTimeout(r,5));assert.ok(until(),'condition reached');};

test('the large-text heap estimate covers the smallest heap each measured shape needed, with at least 25% to spare; window-only analysis needs 64 MiB',()=>{
  // Smallest old-generation limit (MiB) at which the detector worker completed, measured in 16 MiB steps on this build's shapes (dense shapes below their need ran out of memory, some ending the whole process).
  const measured:[string,number,number][]=[['bundle',1,48],['bundle',2,80],['zeros',1,64],['zeros',2,96],['stmts',1,80],['stmts',2,144],['calls',1,96],['calls',2,176],['keys',2,160],['strings',2,80],['plus',1,48],['members',2,192],['b64',2,48]];
  for(const [kind,mib,need] of measured){const estimate=largeTextHeapMb(shape(kind,mib),true);assert.ok(estimate>=Math.ceil(need*1.25),`${kind} ${mib} MiB: estimate ${estimate} MiB, measured need ${need} MiB`);}
  const typical=largeTextHeapMb(bundle('typical').text,true);assert.ok(typical<=128,`a 1.25 MB bundle with its whole-document parse fits beside a 128 MiB parser share in 256 MiB (estimate ${typical} MiB)`);
  assert.equal(largeTextHeapMb(shape('members',2),false),64);assert.equal(largeTextHeapMb('x'.repeat(16*MiB),false),80);assert.equal(largeTextHeapMb('x'.repeat(200000),true),64);
});

test('a scan holds every analysis heap from one budget the size of its analysis memory setting: parser workers and the detector\'s large-text workers',()=>{
  for(const coverage of ['quick','standard','deep'] as const){
    const s=new Scanner({urls:['http://127.0.0.1:9/'],developmentFixtureOrigin:'http://127.0.0.1:9',coverage,traffic:'normal'},{detector:new Detector('disabled'),computer:BIG});
    try{assert.equal(s.analysisMemory.capacity,s.caps.analysisMemoryMb);assert.equal(s.evidence.analysisMemory,s.analysisMemory);assert.equal(s.pool.budget,s.analysisMemory);assert.ok(s.caps.analysisMemoryMb<=512);
      // A supplied detector may be shared by other scans: it keeps its own default and the scan passes its budget with every call (w2-guard item 3).
      assert.notEqual(s.detector.analysisMemory,s.analysisMemory);}finally{s.dispose();}
  }
  const own=new Scanner({urls:['http://127.0.0.1:9/'],developmentFixtureOrigin:'http://127.0.0.1:9',coverage:'standard',traffic:'normal'},{computer:BIG});
  try{assert.equal(own.detector.analysisMemory,own.analysisMemory,'a detector of its own defaults to the scan\'s budget');}finally{own.dispose();}
});

test('parser and large-text heaps running together never exceed the shared budget, and every job still completes',{timeout:120000},async()=>{
  const heaps=trackHeaps(),budget=new FifoBudget(256),pool=new SemanticPool(2,128,budget),d=new Detector('disabled');d.analysisMemory=budget;
  try{
    const texts=[0,1,2].map(i=>bundle('together-'+i)),modules=[0,1,2,3].map(i=>bundle('module-'+i,400000));
    const [found,parsed]=await Promise.all([Promise.all(texts.map(t=>d.inspect(t.text))),Promise.all(modules.map((m,i)=>pool.run([{url:`https://unit.invalid/m${i}.js`,text:m.text}],undefined,60000,{memoryMb:128,maxMemoryMb:256})))]);
    texts.forEach((t,i)=>assert.ok(found[i].some(c=>c.value===t.value),'the whole-document analysis of bundle '+i+' ran and found its split key'));
    for(const r of parsed)assert.equal(r.stats.outcome,'completed',JSON.stringify(r.gaps));
    assert.ok(heaps.limits.some(mb=>mb===128)&&heaps.limits.filter(mb=>mb!==128).length>=3,'parser and large-text workers both ran: '+heaps.limits.join(','));
    assert.ok(heaps.max<=256,`live heap limits peaked at ${heaps.max} MiB`);assert.ok(budget.peak<=256);
  }finally{await pool.dispose();heaps.restore();}
  assert.equal(budget.used,0,'every heap is returned once its worker has ended');assert.equal(budget.waiting,0);
});

test('an idle parser worker that holds memory ends when a large-text worker is waiting for it',{timeout:60000},async()=>{
  const heaps=trackHeaps(),budget=new FifoBudget(192),pool=new SemanticPool(1,128,budget),d=new Detector('disabled'),b=bundle('idle');d.analysisMemory=budget;
  try{
    const r=await pool.run([{url:'https://unit.invalid/small.js',text:'const a=1;'}],undefined,30000);assert.equal(r.stats.outcome,'completed');
    assert.equal((pool as any).idle.length,1);assert.equal(budget.used,128,'the idle worker still holds its heap');
    const found=await d.inspect(b.text);assert.ok(found.some(c=>c.value===b.value));
    assert.equal((pool as any).idle.length,0,'the idle worker was ended');assert.ok(heaps.max<=192,`live heap limits peaked at ${heaps.max} MiB`);
    const again=await pool.run([{url:'https://unit.invalid/small.js',text:'const b=2;'}],undefined,30000);assert.equal(again.stats.outcome,'completed','the pool starts a new worker afterwards');
  }finally{await pool.dispose();heaps.restore();}
  assert.equal(budget.used,0);
});

test('an exclusive (whole-setting) parser job waits for large-text heaps, and later large-text work does not overtake it',{timeout:120000},async()=>{
  const heaps=trackHeaps(),budget=new FifoBudget(256),pool=new SemanticPool(2,128,budget),d=new Detector('disabled'),first=bundle('exclusive-1'),later=bundle('exclusive-2'),big=bundle('exclusive-module');d.analysisMemory=budget;
  try{
    const order:string[]=[],a=d.inspect(first.text).then(c=>{order.push('first');return c;});await settle(()=>budget.used>0);
    const job=pool.run([{url:'https://unit.invalid/big.js',text:big.text}],undefined,60000,{memoryMb:128,maxMemoryMb:256}).then(r=>{order.push('exclusive');return r;});await settle(()=>budget.waiting===1);
    const b=d.inspect(later.text).then(c=>{order.push('later');return c;});
    const [x,r,y]=await Promise.all([a,job,b]);assert.ok(x.some(c=>c.value===first.value));assert.ok(y.some(c=>c.value===later.value));
    assert.notEqual(r.stats.outcome,'memory-ceiling');assert.ok(!r.gaps.some(g=>/cancelled|worker-failure/.test(g.code)),JSON.stringify(r.gaps));
    assert.ok(heaps.limits.includes(256),'the parser job ran with the whole setting: '+heaps.limits.join(','));assert.deepEqual(order,['first','exclusive','later'],'memory is handed out in arrival order');
    assert.ok(heaps.max<=256,`live heap limits peaked at ${heaps.max} MiB`);
  }finally{await pool.dispose();heaps.restore();}
  assert.equal(budget.used,0);
});

test('a whole-document parse that would not fit the setting is skipped with a stated limit; window results are kept and the process survives',{timeout:60000},async()=>{
  const heaps=trackHeaps(),d=new Detector('disabled'),key='sk-proj-'+createHash('sha512').update('ExposureDesk/w1-stable/analysis-memory/small-setting').digest('base64url').slice(0,64).replace(/[-_]/g,'A');d.analysisMemory=new FifoBudget(64);
  try{
    const text=fill(MiB,'a.b;','',`\nvar k="${key}";`),found=await d.inspect(text);
    assert.ok(found.some(c=>c.value===key),'the window analysis still finds the key');assert.deepEqual(heaps.limits,[64]);
    assert.ok([...d.inspectionLimits].some(l=>l.includes('was skipped')&&l.includes('(64 MiB)')),[...d.inspectionLimits].join('\n'));
  }finally{heaps.restore();}
  assert.equal(d.analysisMemory.used,0);
});

test('a large-text inspection cancelled while it waits for memory leaves the queue typed, holding no lane and no memory',{timeout:60000},async()=>{
  const d=new Detector('disabled'),budget=new FifoBudget(128),b=bundle('abort'),controller=new AbortController();d.analysisMemory=budget;
  await budget.acquire(128);d.signal=controller.signal;
  const waiting=d.inspect(b.text);await settle(()=>budget.waiting===1);controller.abort();
  await assert.rejects(waiting,(e:unknown)=>e instanceof AnalysisInterrupted&&e.phase==='direct-queue');
  assert.equal(budget.waiting,0);assert.equal((d as any).directLanes.used,0,'the large-text lane was released');budget.release(128);
  d.signal=undefined;const found=await d.inspect(b.text);assert.ok(found.some(c=>c.value===b.value));assert.equal(budget.used,0);
});
