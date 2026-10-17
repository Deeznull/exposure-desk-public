import {fork,type ChildProcess} from 'node:child_process';
import {EventEmitter} from 'node:events';
import {fileURLToPath} from 'node:url';
/** Analysis heaps (the detector's large-text inspection and the parser) run in child processes of the same Node runtime (`process.execPath`, so the portable package uses its bundled runtime).
 * A worker thread that reaches its heap limit can end the whole process (measured: 3 to 5 of 6 tries on dense synthetic text); a child process that runs out of memory ends alone and the scan states the limit.
 * Children never outlive the scan: cancellation and termination kill them, the parent's exit kills any that remain, and a child exits by itself once its parent's channel closes (after a crash). */
export type AnalysisRole='detector'|'parser';
export interface AnalysisExit{code:number|null;signal:string|null;outOfMemory:boolean;startFailed:boolean}
export interface AnalysisChildInfo{role:AnalysisRole;heapMb:number;pid?:number;spawnedAt:number;startupMs?:number;peakRssMb?:number;endedAt?:number;exit?:AnalysisExit}
/** Marker argument: an entry module serves jobs only when it was started as an analysis child, so importing it elsewhere has no side effects. */
export const CHILD_FLAG='--exposure-analysis-child';
// V8's fatal heap message (old generation or allocation failure); any other ending is a failure, never called out of memory.
const OUT_OF_MEMORY=/JavaScript heap out of memory|Reached heap limit|Allocation failed/i;
const live=new Set<AnalysisChild>();
/** Process-wide counters for tests and measurements. `events` emits `spawn` and `end` with the child's AnalysisChildInfo. */
export const analysisProcesses={spawned:0,outOfMemory:0,liveHeapMb:0,peakLiveHeapMb:0,events:new EventEmitter(),get live(){return live.size;},pids(){return [...live].map(c=>c.info.pid).filter((p):p is number=>typeof p==='number');}};
let hooked=false;
/** One analysis child: a fixed heap limit (`--max-old-space-size`), the parser's stack depth (`--stack-size=3900` matches a worker's 4 MiB stack), structured-clone IPC, no console window.
 * Messages are emitted as `message`; `end` (and the `ended` promise) carry how it ended, after every message it sent has arrived. */
export class AnalysisChild extends EventEmitter{
  readonly info:AnalysisChildInfo;readonly ended:Promise<AnalysisExit>;exit?:AnalysisExit;private child:ChildProcess;private stderr='';
  constructor(readonly role:AnalysisRole,readonly heapMb:number,entry:URL){
    super();if(!hooked){hooked=true;process.on('exit',()=>{for(const c of live)c.kill();});}
    const env={...process.env};delete env.NODE_OPTIONS;this.info={role,heapMb,spawnedAt:Date.now()};
    this.child=fork(fileURLToPath(entry),[CHILD_FLAG],{execPath:process.execPath,execArgv:[`--max-old-space-size=${heapMb}`,'--stack-size=3900'],serialization:'advanced',stdio:['ignore','ignore','pipe','ipc'],windowsHide:true,env});
    this.info.pid=this.child.pid;live.add(this);analysisProcesses.spawned++;analysisProcesses.liveHeapMb+=heapMb;analysisProcesses.peakLiveHeapMb=Math.max(analysisProcesses.peakLiveHeapMb,analysisProcesses.liveHeapMb);
    this.child.stderr?.on('data',(b:Buffer)=>{this.stderr=(this.stderr+b.toString()).slice(-4096);});
    this.child.on('message',(m:any)=>{if(typeof m?.usage?.maxRssMb==='number')this.info.peakRssMb=Math.max(this.info.peakRssMb||0,m.usage.maxRssMb);if(m?.type==='ready'&&this.info.startupMs===undefined)this.info.startupMs=Date.now()-this.info.spawnedAt;this.emit('message',m);});
    this.ended=new Promise<AnalysisExit>(resolve=>{
      const done=(code:number|null,signal:string|null,startFailed:boolean)=>{if(this.exit)return;const exit={code,signal,outOfMemory:!startFailed&&OUT_OF_MEMORY.test(this.stderr),startFailed};this.exit=exit;
        if(live.delete(this))analysisProcesses.liveHeapMb-=heapMb;if(exit.outOfMemory)analysisProcesses.outOfMemory++;this.info.exit=exit;this.info.endedAt=Date.now();analysisProcesses.events.emit('end',this.info);this.emit('end',exit);resolve(exit);};
      // `close` follows the exit and the end of the IPC channel and stderr, so every message (and the fatal heap message) has arrived first.
      this.child.once('close',(code,signal)=>done(code,signal,false));
      // A failed spawn (no process) ends here; later errors (a send to an ended child) surface through `close`.
      this.child.on('error',()=>{if(this.child.pid===undefined)done(null,null,true);});
    });
    analysisProcesses.events.emit('spawn',this.info);
  }
  /** False when the child has ended or its channel is closed. */
  send(message:unknown){if(this.exit||!this.child.connected)return false;try{this.child.send(message as any,undefined,{},()=>{});return true;}catch{return false;}}
  kill(){if(!this.exit)try{this.child.kill();}catch{}}
  /** Kills the child and resolves once it has ended (an idle, unreferenced child is referenced again so its ending is awaited). */
  stop(){if(!this.exit)this.ref();this.kill();return this.ended;}
  ref(){this.child.ref();(this.child.channel as any)?.ref?.();(this.child.stderr as any)?.ref?.();}
  /** An idle child does not keep the parent running. */
  unref(){this.child.unref();(this.child.channel as any)?.unref?.();(this.child.stderr as any)?.unref?.();}
}
/** Child side: answers `job` messages over the IPC channel (each reply carries the child's peak RSS) and exits when the channel closes. Returns false outside an analysis child. */
export function serveAnalysisJobs(handle:(job:any,reply:(message:Record<string,unknown>)=>void)=>void){
  if(!process.send||!process.argv.includes(CHILD_FLAG))return false;
  const reply=(message:Record<string,unknown>)=>{try{process.send!({...message,usage:{maxRssMb:Math.round(process.resourceUsage().maxRSS/1024)}},undefined,{},()=>{});}catch{}};
  process.on('disconnect',()=>process.exit(0));
  process.on('message',(m:any)=>{if(m?.type==='job')handle(m,reply);});
  reply({type:'ready'});return true;
}
