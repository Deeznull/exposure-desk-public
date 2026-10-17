import test from 'node:test';
import assert from 'node:assert/strict';
import {spawn} from 'node:child_process';
import {createHash} from 'node:crypto';
import {once} from 'node:events';
import {fileURLToPath} from 'node:url';
import {Detector,AnalysisInterrupted} from '../src/detectors.js';
import {FifoBudget} from '../src/fifo-budget.js';
import {SemanticPool} from '../src/semantic.js';
import {Scanner} from '../src/scanner.js';
import {analysisProcesses,type AnalysisChildInfo} from '../src/analysis-process.js';
import {syntheticBundle} from './large-bundle.js';
/** 2.7.0 w2-guard: analysis heaps run in child processes. Running out of memory ends that process alone (stated, other results kept), cancellation kills it, no process outlives its parent,
 * every heap is held from the calling scan's budget, and main-thread inspection never runs an unbounded whole-document parse. Local only: nothing is contacted; keys are synthetic. */
const MiB=1048576,BIG={cores:16,freeMemoryMb:32768};
const fill=(size:number,unit:string,tail='')=>unit.repeat(Math.floor((size-tail.length)/unit.length))+tail;
const synthetic=(seed:string)=>'sk-proj-'+createHash('sha512').update('ExposureDesk/w2-guard/'+seed).digest('base64url').slice(0,64).replace(/[-_]/g,'A');
// A synthetic bundle whose key is split in two literals joined at the client call: only the whole-document analysis reconstructs it.
const bundle=(seed:string)=>{const value=synthetic(seed),rest=value.slice('sk-proj-'.length);
  return {value,text:syntheticBundle({seed:'ExposureDesk/w2-guard/'+seed,targetBytes:1252570}).text.replace('\n//# sourceMapping',`\nconst head="sk-proj-";const rest=${JSON.stringify(rest)};const openai=new OpenAI({apiKey:head+rest});\n//# sourceMapping`)};};
const alive=(pid:number)=>{try{process.kill(pid,0);return true;}catch(e){return (e as NodeJS.ErrnoException).code==='EPERM';}};
const settle=async(until:()=>boolean,ms=10000)=>{for(const end=Date.now()+ms;!until()&&Date.now()<end;)await new Promise(r=>setTimeout(r,10));assert.ok(until(),'condition reached');};
function watchSpawns(){const seen:AnalysisChildInfo[]=[],on=(info:AnalysisChildInfo)=>{seen.push(info);};analysisProcesses.events.on('spawn',on);return {seen,stop(){analysisProcesses.events.off('spawn',on);}};}

test('a parser process that runs out of memory ends alone: the group gets a stated memory ceiling, its heap is returned and the next job starts a new parser',{timeout:60000},async()=>{
  const budget=new FifoBudget(48),pool=new SemanticPool(1,48,budget),before=analysisProcesses.outOfMemory,watch=watchSpawns();pool.estimate=()=>48;
  try{
    const r=await pool.run([{url:'https://unit.invalid/dense.js',text:fill(2*MiB,'f(a,b);')}],undefined,60000,{memoryMb:48,maxMemoryMb:48});
    assert.equal(r.stats.outcome,'memory-ceiling',JSON.stringify(r.gaps));assert.deepEqual(r.gaps.map(g=>g.code),['semantic-memory-ceiling']);
    assert.match(r.gaps[0].detail,/reached its 48 MiB heap limit; its process ended without affecting the scan/);
    assert.deepEqual(r.resources,[{url:'https://unit.invalid/dense.js',status:'incomplete',reason:'Parser heap limit reached',deterministic:true}]);
    assert.equal(analysisProcesses.outOfMemory,before+1);assert.equal(budget.used,0,'the heap is returned once the process has ended');
    const next=await pool.run([{url:'https://unit.invalid/small.js',text:'const a=1;'}],undefined,30000);assert.equal(next.stats.outcome,'completed');assert.equal(pool.spawns,2);
  }finally{await pool.dispose();watch.stop();}
  assert.equal(budget.used,0);assert.equal(watch.seen.length,2);assert.ok(watch.seen[0].exit?.outOfMemory&&watch.seen.every(i=>i.exit),'both parser processes of this test have ended');
});

test('a large-text inspection whose whole-document parse runs out of memory keeps its window results with a stated limit; the scan process survives',{timeout:60000},async()=>{
  const d=new Detector('disabled'),key=synthetic('oom-window'),before=analysisProcesses.outOfMemory,watch=watchSpawns();d.analysisMemory=new FifoBudget(256);d.heapEstimate=()=>48;
  const text=fill(2*MiB,'a;',`\nvar k="${key}";`);assert.ok(text.length<=2*MiB);
  let found:Awaited<ReturnType<Detector['inspect']>>=[];try{found=await d.inspect(text);}finally{watch.stop();}
  assert.ok(found.some(c=>c.value===key),'the window results are kept');assert.equal(analysisProcesses.outOfMemory,before+1);
  assert.ok([...d.inspectionLimits].some(l=>l.includes('reached its 48 MiB heap limit')&&l.includes('Window results are kept')),[...d.inspectionLimits].join('\n'));
  assert.equal(d.analysisMemory.used,0);assert.equal(watch.seen.length,1);assert.equal(watch.seen[0].heapMb,48);assert.ok(watch.seen[0].exit?.outOfMemory);
});

test('cancelling a large-text inspection or a parser job kills its analysis process and returns its heap',{timeout:60000},async()=>{
  const watch=watchSpawns();
  try{
    const d=new Detector('disabled'),budget=new FifoBudget(256),controller=new AbortController(),b=bundle('cancel');d.analysisMemory=budget;d.signal=controller.signal;
    const running=d.inspect(b.text);await settle(()=>watch.seen.some(i=>i.role==='detector'&&i.startupMs!==undefined));controller.abort();
    await assert.rejects(running,(e:unknown)=>e instanceof AnalysisInterrupted&&e.phase==='direct');
    const detector=watch.seen.find(i=>i.role==='detector')!;await settle(()=>!alive(detector.pid!));assert.equal(budget.used,0);assert.equal((d as any).directLanes.used,0);
    const pool=new SemanticPool(1,128,budget),parse=new AbortController();
    try{
      const job=pool.run([{url:'https://unit.invalid/dense.js',text:fill(2*MiB,'f(a,b);')}],parse.signal,60000,{memoryMb:256,maxMemoryMb:256});
      await settle(()=>watch.seen.some(i=>i.role==='parser'&&i.startupMs!==undefined));parse.abort();
      const r=await job;assert.equal(r.stats.outcome,'cancelled');
      const parser=watch.seen.find(i=>i.role==='parser')!;await settle(()=>!alive(parser.pid!));assert.equal(budget.used,0);
    }finally{await pool.dispose();}
  }finally{watch.stop();}
  assert.ok(watch.seen.every(i=>i.exit),'every analysis process of this test has ended');
});

for(const mode of ['stay','exit'] as const)test(`no analysis process outlives its parent (${mode==='stay'?'parent killed outright':'parent exits'})`,{timeout:60000},async()=>{
  const parent=spawn(process.execPath,[fileURLToPath(new URL('./analysis-orphan-parent.js',import.meta.url)),mode],{stdio:['ignore','pipe','ignore'],windowsHide:true});
  let out='';parent.stdout!.on('data',(b:Buffer)=>{out+=b.toString();});
  try{
    await settle(()=>out.includes('\n'),20000);const {pid}=JSON.parse(out.split('\n')[0]) as {pid:number};assert.ok(alive(pid),'the analysis process is running');
    if(mode==='stay')parent.kill('SIGKILL');
    if(parent.exitCode===null&&parent.signalCode===null)await once(parent,'exit');
    await settle(()=>!alive(pid),10000);
  }finally{if(parent.exitCode===null&&parent.signalCode===null)parent.kill('SIGKILL');}
});

test('a detector shared by two scans holds each scan\'s large-text heap from that scan\'s own budget',{timeout:120000},async()=>{
  const d=new Detector('disabled'),config={urls:['http://127.0.0.1:9/'],developmentFixtureOrigin:'http://127.0.0.1:9',coverage:'quick' as const,traffic:'normal' as const};
  const s1=new Scanner(config,{detector:d,computer:BIG}),s2=new Scanner(config,{detector:d,computer:BIG}),watch=watchSpawns(),held:[number,number][]=[];
  const record=(i:AnalysisChildInfo)=>{if(i.role==='detector')held.push([s1.analysisMemory.used,s2.analysisMemory.used]);};analysisProcesses.events.on('spawn',record);
  try{
    assert.notEqual(s1.analysisMemory,s2.analysisMemory);assert.equal(s1.evidence.analysisMemory,s1.analysisMemory);assert.equal(s2.evidence.analysisMemory,s2.analysisMemory);
    const first=bundle('shared-1');await s1.evidence.inspect(first.text,'http://127.0.0.1:9/a.js',['test'],'Synthetic local text');
    assert.equal(held.length,1);assert.ok(held[0][0]>0&&held[0][1]===0,'the first scan\'s inspection held from the first scan\'s budget: '+JSON.stringify(held));
    const second=bundle('shared-2');await Promise.all([s1.evidence.inspect(second.text,'http://127.0.0.1:9/b.js',['test'],'Synthetic local text'),s2.evidence.inspect(bundle('shared-3').text,'http://127.0.0.1:9/c.js',['test'],'Synthetic local text')]);
    assert.ok(s1.analysisMemory.peak>0&&s2.analysisMemory.peak>0,'each scan held its own heap');assert.equal(d.analysisMemory.peak,0,'the detector default was never used');
    assert.equal(s1.analysisMemory.used+s2.analysisMemory.used,0);
    assert.ok([...s1.evidence.findings.values()].some(f=>/openai/i.test(`${f.provider} ${f.rule}`)),'the split key was found through the scan path');
  }finally{analysisProcesses.events.off('spawn',record);watch.stop();s1.dispose();s2.dispose();}
});

test('main-thread inspection of a text over 128 KiB never runs the whole-document parse: window results are kept and the skipped parse is stated unless the text is covered',{timeout:60000},async()=>{
  const b=bundle('windowed'),watch=watchSpawns();
  try{
    const d=new Detector('disabled'),began=analysisProcesses.spawned,found=d.inspectWindowed(b.text);
    assert.ok(!found.some(c=>c.value===b.value),'only the whole-document parse joins the split key');assert.equal(analysisProcesses.spawned,began);
    assert.ok([...d.inspectionLimits].some(l=>l.includes('inspected on the main thread')),[...d.inspectionLimits].join('\n'));
    const covered=new Detector('disabled');covered.inspectWindowed(b.text,true);assert.ok(![...covered.inspectionLimits].some(l=>l.includes('inspected on the main thread')));
    const small=new Detector('disabled'),key=synthetic('small');assert.ok(small.inspectWindowed(`var k="${key}";`).some(c=>c.value===key));assert.equal(small.inspectionLimits.size,0);
    const budget=new FifoBudget(256),bounded=new Detector('disabled'),spawnsBefore=watch.seen.length;let heldAtSpawn=-1;const at=(i:AnalysisChildInfo)=>{heldAtSpawn=budget.used-i.heapMb;};analysisProcesses.events.on('spawn',at);
    try{const viaBudget=await bounded.inspectBounded(b.text,budget);assert.ok(viaBudget.some(c=>c.value===b.value),'the budgeted path keeps the whole-document finding');}finally{analysisProcesses.events.off('spawn',at);}
    assert.equal(watch.seen.length,spawnsBefore+1);assert.equal(heldAtSpawn,0,'the analysis process held exactly its heap from the given budget');assert.equal(budget.used,0);assert.equal(bounded.analysisMemory.peak,0);
  }finally{watch.stop();}
});

test('after the pool is disposed no analysis process is left',{timeout:60000},async()=>{
  const pool=new SemanticPool(2,128),watch=watchSpawns();
  try{
    const r=await Promise.all([1,2].map(i=>pool.run([{url:`https://unit.invalid/m${i}.js`,text:`export const a${i}=${i};`}],undefined,30000)));for(const x of r)assert.equal(x.stats.outcome,'completed');
    assert.equal((pool as any).idle.length,2,'both parsers are idle');assert.ok(watch.seen.every(i=>alive(i.pid!)));
  }finally{await pool.dispose();watch.stop();}
  assert.ok(watch.seen.every(i=>i.exit),'every parser process has ended');for(const i of watch.seen)await settle(()=>!alive(i.pid!));
});
