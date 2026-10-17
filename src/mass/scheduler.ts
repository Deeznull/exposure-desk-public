/** Concurrent target scheduler for mass scans (2.8). It pumps a fixed list of target indices through at most `concurrency` in-flight runs, in index order. It owns no
 * signal handlers and cancels nothing itself: the caller (mass-run) registers the one SIGINT/SIGTERM/closed-reader handler and, on stop, cancels the running scans
 * it tracks — so `process.listenerCount('SIGINT')` stays 1 during a run. `stop()` starts no further target (Ctrl+C / closed JSONL reader); `halt()` also starts none
 * but lets the running targets finish (the program-wide block halt). At concurrency 1 this is a strict sequential loop, byte-for-byte the 2.7 behaviour.
 * The optional `admit(active)` check (the memory gate) can hold back a further target while `active` run; it is asked again when a target ends and every
 * `retryMs` while it refuses. With no target running a target always starts, so a run always progresses. `peakActive` is the effective concurrency reached. */
export class MassScheduler {
  private cursor=0;private active=0;private stopped=false;private halted=false;
  /** The most targets that ran at once (the effective concurrency). */
  peakActive=0;
  constructor(private readonly indices:number[],private readonly concurrency:number,private readonly runOne:(index:number)=>Promise<void>,private readonly admit?:(active:number)=>boolean,private readonly retryMs=250){}
  get isStopped(){return this.stopped;}
  /** Targets running now. */
  get running(){return this.active;}
  get isHalted(){return this.halted;}
  /** Start no further target; the caller cancels the running ones. */
  stop(){this.stopped=true;}
  /** Start no further target but let the running ones finish. */
  halt(){this.halted=true;}
  /** Resolves once every started target has settled and no further target will start. Rejects with the first error a target throws (and then starts no more). */
  run():Promise<void>{
    return new Promise<void>((resolve,reject)=>{
      let settled=false,error:unknown,retry:ReturnType<typeof setTimeout>|undefined;
      const finish=()=>{if(settled)return;settled=true;clearTimeout(retry);error!==undefined?reject(error):resolve();};
      const pump=()=>{
        clearTimeout(retry);retry=undefined;
        while(!this.stopped&&!this.halted&&this.active<this.concurrency&&this.cursor<this.indices.length){
          if(this.active>0&&this.admit&&!this.admit(this.active)){retry=setTimeout(pump,this.retryMs);retry.unref?.();break;}
          const index=this.indices[this.cursor++]!;this.active++;if(this.active>this.peakActive)this.peakActive=this.active;
          Promise.resolve().then(()=>this.runOne(index)).then(
            ()=>{this.active--;pump();},
            e=>{this.active--;if(error===undefined)error=e;this.stopped=true;pump();}
          );
        }
        if(this.active===0&&(this.stopped||this.halted||this.cursor>=this.indices.length))finish();
      };
      pump();
    });
  }
}
