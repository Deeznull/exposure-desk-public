import type {FifoBudget} from './fifo-budget.js';
import {AnalysisChild,type AnalysisExit} from './analysis-process.js';
import {scaleMs} from './machine-speed.js';
export interface SemanticSource {url:string;text:string;label?:string;imports?:Record<string,string>}
export interface Constituent {url:string;start:number;end:number;line:number;column:number;representation:string;label?:string}
export interface SemanticView {text:string;url:string;start:number;end:number;label?:string;original:string;steps:string[];constituents:Constituent[];sink?:string}
export interface SemanticStats {modules:number;nodes:number;views:number;elapsedMs:number;startupMs?:number;queueWaitMs?:number;parseMs?:number;mutationMs?:number;propagationMs?:number;emitMs?:number;workerMs?:number;cleanupMs?:number;chargedMs?:number;mutationOps?:number;aliasOps?:number;webpackOps?:number;webpackMs?:number;outcome?:'completed'|'deadline'|'exhausted'|'cancelled'|'timeout'|'failure'|'memory-ceiling'}
export interface SemanticResult {resources?:{url:string;status:'inspected'|'incomplete'|'failed';reason?:string;deterministic?:boolean}[];views:SemanticView[];gaps:{url?:string;code:string;detail:string}[];stats:SemanticStats}
/** `sharedWait` / `sharedHold` (mass mode): mark the wait for a parser worker or analysis memory that is not free at once, and the time the job holds a worker; each returns its end. */
export interface SemanticJobOptions {sliceMs?:number;memoryMb?:number;maxMemoryMb?:number;skip?:Record<string,string>;mutationOpsCeiling?:number;sharedWait?:()=>()=>void;sharedHold?:()=>()=>void}
type PoolWorker={worker:AnalysisChild;memoryMb:number;ready:Promise<void>;startupMs:number;exclusive:boolean;held:boolean};
const estimateMb=(sources:SemanticSource[])=>64+60*sources.reduce((n,s)=>n+s.text.length,0)/1048576;
const PARSER_ENTRY=new URL('./semantic-worker.js',import.meta.url);
/** Reference wall-clock limits (a fast computer): the default group slice and time limit, and the wait for a worker's termination. Each use scales them by the analysis time factor (machine-speed.ts). */
export const GROUP_SLICE_MS=1600,GROUP_TIMEOUT_MS=2500,CLEANUP_LIMIT_MS=1000;
/** Reference margins of a scan's dependency-group job: the time limit over the configured slice, and the reconstructed-view inspection budget (both scaled like the slice). */
export const GROUP_MARGIN_MS=750,VIEW_INSPECTION_MS=2000;
/** Lazily started, reusable parser workers with a ready handshake, each in its own analysis process (so a parser that runs out of memory ends alone; the scan states the limit and continues).
 * A worker that times out, is cancelled, fails or runs out of memory is ended and respawned lazily; nothing is ever evaluated.
 * With a shared analysis-memory budget every live worker (idle ones too) holds its heap limit from that budget until its process has ended; idle workers end when another heap is waiting for memory. */
export class SemanticPool {
 private idle:PoolWorker[]=[];private busy=new Set<PoolWorker>();private waiters:(()=>void)[]=[];spawns=0;respawns=0;private disposed=false;private exclusiveWaiting=0;private starting=0;private startingExclusive=0;private stopShort?:()=>void;
 /** Parser heap estimate (MiB) for a dependency group; replaceable for tests and measurements. */
 estimate=estimateMb;
 /** Test and measurement hook: wall-clock delay before a job reaches its worker, inside the job's time limit (emulates a slower computer). Always 0 in scans. */
 jobDelayMs=0;
 constructor(readonly size=1,readonly memoryMb=128,readonly budget?:FifoBudget){this.stopShort=budget?.whenShort(()=>this.endIdle());}
 private free(entry:PoolWorker){if(entry.held){entry.held=false;this.budget?.release(entry.memoryMb);}}
 private end(entry:PoolWorker){return entry.worker.stop().then(()=>this.free(entry));}
 private endIdle(){for(const w of this.idle.splice(0))void this.end(w);}
 private spawn(memoryMb:number,exclusive:boolean):PoolWorker{
  const at=Date.now(),worker=new AnalysisChild('parser',memoryMb,PARSER_ENTRY);this.spawns++;
  const entry:PoolWorker={worker,memoryMb,exclusive,held:!!this.budget,startupMs:0,ready:new Promise<void>((resolve,reject)=>{const onMessage=(m:any)=>{if(m?.type==='ready'){worker.off('message',onMessage);worker.off('end',onEnd);entry.startupMs=Date.now()-at;resolve();}},onEnd=()=>reject(new Error('worker-failure'));worker.on('message',onMessage);worker.once('end',onEnd);})};
  // A worker whose process ends by itself (out of memory, a crash) frees its heap at once and is never reused.
  void worker.ended.then(()=>{const i=this.idle.indexOf(entry);if(i>=0)this.idle.splice(i,1);this.free(entry);});
  entry.ready.catch(()=>{});return entry;
 }
 /** The configured analysis memory is a ceiling for all parser heaps together (with the scan's budget, together with the detector's large-text heaps): an exclusive worker (the whole ceiling) runs alone, with idle workers ended first, and no shared worker starts while one waits or runs. */
 private async acquire(memoryMb:number,exclusive:boolean,signal?:AbortSignal):Promise<PoolWorker>{
  if(exclusive)this.exclusiveWaiting++;
  try{while(exclusive?this.busy.size+this.starting>0:this.busy.size+this.starting>=this.size||this.exclusiveWaiting>0||this.startingExclusive>0||[...this.busy].some(w=>w.exclusive)){if(signal?.aborted)throw new Error('cancelled');await new Promise<void>(resolve=>this.waiters.push(resolve));}}finally{if(exclusive){this.exclusiveWaiting--;if(this.exclusiveWaiting===0)for(const w of this.waiters.splice(0))w();}}
  if(this.disposed)throw new Error('disposed');
  if(exclusive)this.endIdle();
  let entry=exclusive?undefined:this.idle.find(w=>w.memoryMb===memoryMb&&!w.worker.exit);if(entry)this.idle.splice(this.idle.indexOf(entry),1);else{
   if(this.budget){this.starting++;if(exclusive)this.startingExclusive++;try{await this.budget.acquire(memoryMb,signal);}finally{this.starting--;if(exclusive)this.startingExclusive--;this.wake();}if(this.disposed){this.budget.release(memoryMb);throw new Error('disposed');}}
   entry=this.spawn(memoryMb,exclusive);if(this.spawns>this.size)this.respawns++;}
  this.busy.add(entry);entry.worker.ref();return entry;
 }
 private wake(){for(const w of this.waiters.splice(0))w();}
 /** Whether `acquire` would hand out a worker without waiting: the same admission test as its loop, then an idle worker of this heap size or free analysis memory for a new one. */
 private immediate(memoryMb:number,exclusive:boolean){
  const blocked=exclusive?this.busy.size+this.starting>0:this.busy.size+this.starting>=this.size||this.exclusiveWaiting>0||this.startingExclusive>0||[...this.busy].some(w=>w.exclusive);
  if(blocked||this.disposed)return false;if(!exclusive&&this.idle.some(w=>w.memoryMb===memoryMb&&!w.worker.exit))return true;return !this.budget||this.budget.available(memoryMb);
 }
 private release(entry:PoolWorker,terminate:boolean):Promise<number>{
  this.busy.delete(entry);
  if(!terminate&&!entry.exclusive&&!this.disposed){entry.startupMs=0;this.idle.push(entry);entry.worker.unref();this.wake();if(this.budget?.waiting)this.endIdle();return Promise.resolve(0);}
  const at=Date.now();return new Promise<number>(resolve=>{const limit=setTimeout(()=>{this.wake();resolve(-1);},scaleMs(CLEANUP_LIMIT_MS));void this.end(entry).then(()=>{clearTimeout(limit);this.wake();resolve(Date.now()-at);});});
 }
 /** Runs one dependency group. Its allocation charge (`chargedMs`) runs from the moment the job holds a parser worker: worker startup, parsing, propagation and cleanup.
  * The wait for a free worker or for analysis memory that other heaps hold (`queueWaitMs`) is reported separately and is not part of the charge. */
 async run(sources:SemanticSource[],signal?:AbortSignal,timeoutMs=scaleMs(GROUP_TIMEOUT_MS),options:SemanticJobOptions={}):Promise<SemanticResult>{
  const empty=(code:string,detail:string,outcome:SemanticStats['outcome'],extra:Partial<SemanticStats>={}):SemanticResult=>({views:[],gaps:[{code,detail}],stats:{modules:sources.length,nodes:0,views:0,elapsedMs:0,workerMs:0,startupMs:0,cleanupMs:0,outcome,...extra}});
  if(signal?.aborted)return empty('semantic-cancelled','Static module analysis cancelled.','cancelled');
  const cap=this.budget?.capacity??Infinity,per=Math.min(options.memoryMb||this.memoryMb,cap),max=Math.min(options.maxMemoryMb||per,cap),estimate=this.estimate(sources);
  if(estimate>max)return {views:[],gaps:[{code:'semantic-memory-ceiling',detail:`Estimated parser heap (${Math.round(estimate)} MiB) exceeds the configured ceiling (${max} MiB); the dependency group was not parsed and stays unknown.`}],resources:sources.map(s=>({url:s.url,status:'incomplete' as const,reason:'Estimated parser memory exceeds the configured ceiling',deterministic:true})),stats:{modules:sources.length,nodes:0,views:0,elapsedMs:0,workerMs:0,startupMs:0,cleanupMs:0,outcome:'memory-ceiling'}};
  const exclusive=estimate>per,memory=exclusive?max:per,queuedAt=Date.now();
  const waiting=this.immediate(memory,exclusive)?undefined:options.sharedWait?.();
  let entry:PoolWorker;try{entry=await this.acquire(memory,exclusive,signal);}catch{waiting?.();return empty('semantic-cancelled','Static module analysis cancelled before a parser worker was available.','cancelled',{queueWaitMs:Date.now()-queuedAt});}
  const held=options.sharedHold?.();waiting?.();
  try{return await this.runHeld(entry,sources,signal,timeoutMs,options,memory,queuedAt,empty);}finally{held?.();}
 }
 private async runHeld(entry:PoolWorker,sources:SemanticSource[],signal:AbortSignal|undefined,timeoutMs:number,options:SemanticJobOptions,memory:number,queuedAt:number,empty:(code:string,detail:string,outcome:SemanticStats['outcome'],extra?:Partial<SemanticStats>)=>SemanticResult):Promise<SemanticResult>{
  // The parser's process reached its heap limit: deterministic for this group and heap, so it is stated like the estimated ceiling and not retried.
  const outOfMemory=(workerMs:number):SemanticResult=>({views:[],gaps:[{code:'semantic-memory-ceiling',detail:`The parser reached its ${memory} MiB heap limit; its process ended without affecting the scan. The dependency group was not parsed and stays unknown; direct and decoded analysis retained.`}],resources:sources.map(s=>({url:s.url,status:'incomplete' as const,reason:'Parser heap limit reached',deterministic:true})),stats:{modules:sources.length,nodes:0,views:0,elapsedMs:0,workerMs,startupMs:0,cleanupMs:0,outcome:'memory-ceiling'}});
  const chargedAt=Date.now(),queueWaitMs=chargedAt-queuedAt;
  try{await entry.ready;}catch{const cleanupMs=await this.release(entry,true);return empty('semantic-worker-failure','Parser worker failed to start; direct and decoded analysis retained.','failure',{cleanupMs,queueWaitMs,chargedMs:Date.now()-chargedAt});}
  const startupMs=entry.startupMs,sent=Date.now(),id=Math.random().toString(36).slice(2);let terminate=false;
  const result=await new Promise<SemanticResult>(resolve=>{
   let done=false;const finish=(value:SemanticResult,kill:boolean)=>{if(done)return;done=true;clearTimeout(timer);signal?.removeEventListener('abort',cancel);entry.worker.off('message',onMessage);entry.worker.off('end',onEnd);terminate=kill;resolve(value);};
   const measured=()=>Date.now()-sent;
   const cancel=()=>finish(empty('semantic-cancelled','Static module analysis cancelled; unfinished values remain unknown.','cancelled',{workerMs:measured()}),true);
   const timer=setTimeout(()=>finish(empty('semantic-time-limit','Isolated parsing/propagation exceeded '+timeoutMs+' ms; no unfinished reconstruction accepted.','timeout',{workerMs:measured()}),true),timeoutMs);
   const onMessage=(m:any)=>{if(m?.type==='result'&&m.id===id)finish(m.result,false);},onEnd=(exit:AnalysisExit)=>finish(exit.outOfMemory?outOfMemory(measured()):empty('semantic-worker-failure','Parser worker exited without complete results.','failure',{workerMs:measured()}),true);
   signal?.addEventListener('abort',cancel,{once:true});entry.worker.on('message',onMessage);entry.worker.once('end',onEnd);
   const send=()=>{if(done)return;if(entry.worker.exit)onEnd(entry.worker.exit);else if(!entry.worker.send({type:'job',id,sources,sliceMs:options.sliceMs||scaleMs(GROUP_SLICE_MS),skip:options.skip||{},mutationOpsCeiling:options.mutationOpsCeiling||4000000}))finish(empty('semantic-worker-failure','Parser worker failed or exceeded its memory limit; direct and decoded analysis retained.','failure',{workerMs:measured()}),true);};
   if(signal?.aborted)cancel();else if(this.jobDelayMs>0)setTimeout(send,this.jobDelayMs);else send();
  });
  const cleanupMs=await this.release(entry,terminate);
  if(cleanupMs<0)result.gaps.push({code:'semantic-cleanup-limit',detail:`Worker termination did not confirm within ${scaleMs(CLEANUP_LIMIT_MS)} ms.`});
  result.stats={...result.stats,startupMs,cleanupMs:Math.max(0,cleanupMs),queueWaitMs,chargedMs:Date.now()-chargedAt,workerMs:result.stats.workerMs??result.stats.elapsedMs};
  return result;
 }
 async dispose(){this.disposed=true;this.stopShort?.();const all=[...this.idle,...this.busy];this.idle=[];this.busy.clear();this.wake();await Promise.allSettled(all.map(e=>this.end(e)));}
}
/** One-shot wrapper with the original API: a transient single worker that is terminated after the job (its heap is held from `budget`, the scan's analysis memory, when given). */
export async function analyzeModules(sources:SemanticSource[],signal?:AbortSignal,timeoutMs=scaleMs(GROUP_TIMEOUT_MS),options:SemanticJobOptions={},budget?:FifoBudget):Promise<SemanticResult>{
 const pool=new SemanticPool(1,options.memoryMb||128,budget);
 try{return await pool.run(sources,signal,timeoutMs,options);}finally{await pool.dispose();}
}

/** Connected imported graphs are never split arbitrarily between workers. */
export function moduleGroups(sources:SemanticSource[]):SemanticSource[][]{
 const byUrl=new Map(sources.map(s=>[s.url,s])),links=new Map(sources.map(s=>[s.url,new Set<string>()]));
 for(const s of sources){for(const match of s.text.matchAll(/\b(?:import|export)\s+(?:[^;\n]{0,500}?\bfrom\s*)?["']([^"']+)["']/g)){let url='';try{url=s.imports?.[match[1]]||new URL(match[1],s.url).href;}catch{}if(byUrl.has(url)){links.get(s.url)!.add(url);links.get(url)!.add(s.url);}}}
 const seen=new Set<string>(),groups:SemanticSource[][]=[];
 for(const s of sources){if(seen.has(s.url))continue;const stack=[s.url],group:SemanticSource[]=[];while(stack.length){const url=stack.pop()!;if(seen.has(url))continue;seen.add(url);group.push(byUrl.get(url)!);stack.push(...links.get(url)!);}groups.push(group);}
 // Relevant first: credential-shaped markers, SDK constructors and decoding idioms rank a group ahead; then smaller groups first.
 const score=(g:SemanticSource[])=>g.reduce((n,s)=>n+Number(/api[_-]?key|credential|secret|token|password|authorization|bearer/i.test(s.text))*4+Number(/\b(?:OpenAI|Anthropic|Stripe|Mistral|Cohere|Groq|Resend|createClient|initializeApp)\b/.test(s.text))*2+Number(/\batob\s*\(|fromCharCode|\.join\s*\(\s*["']{2}\s*\)|Buffer\.from/.test(s.text))+Number(/config|fetch\s*\(/i.test(s.text)),0);
 return groups.sort((a,b)=>score(b)-score(a)||a.reduce((n,s)=>n+s.text.length,0)-b.reduce((n,s)=>n+s.text.length,0));
}
