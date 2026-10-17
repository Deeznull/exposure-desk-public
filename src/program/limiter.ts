import {performance} from 'node:perf_hooks';
import type {ProgramConfig} from '../types.js';
/** Program-wide request gate (2.8). Every Transport of one program in this process shares one limiter, consulted in `pumpPermits` as an extra gate on top of
 * the global and per-origin limits (never instead of them): at most `concurrency` requests in flight and at most `requestsPerSecond` grants per second
 * across all targets of the program. A transport whose ready request is held back registers a wake-up and is pumped again when it may go.
 * Fair turns (2.9, O2): the owners (transports, one per target) that are held back wait in one first-in, first-out queue, one place per owner. Only the owner at the head
 * is woken, by the limiter's one timer at the next rate slot or by a release, and an owner that takes a slot joins the back again for its next request, so the slots go
 * round the waiting targets in turn. Before 2.9 every waiting transport armed its own timer and the target that had just won a slot re-armed first, so it kept winning. */
export interface ProgramLimiterStats {requestsPerSecond:number;concurrency:number;active:number;peakActive:number;granted:number;
  /** onWait: requests that were ready under every per-website limit but waited for the program limit, and the total time they waited. */
  waits:number;waitMs:number;maxWaitMs:number}
export class ProgramLimiter {
  private active=0;private peakActive=0;private granted=0;private waits=0;private waitMs=0;private maxWaitMs=0;private nextAt=0;
  private waiters=new Set<()=>void>();private waitingSince=new WeakMap<object,number>();
  /** Grants per owner (one Transport, that is one target) still in flight, and the owner of the latest grant, which set the next rate slot. */
  private owners=new Map<object,number>();private lastOwner?:object;
  /** Owners held back, in the order they first waited (one entry each), and the one timer that wakes the head at the next rate slot. */
  private queue:{owner:object;wake:()=>void}[]=[];private timer?:ReturnType<typeof setTimeout>;private kicking=false;private kickAgain=false;
  /** Optional listener for each completed wait (milliseconds), e.g. for a progress line. */
  onWait?:(ms:number)=>void;
  constructor(readonly id:string,readonly requestsPerSecond:number,readonly concurrency:number,private readonly now:()=>number=()=>performance.now()){
    if(!(requestsPerSecond>0)||!(concurrency>=1))throw new Error('Invalid program limits');
  }
  /** 0 when a request may start now; Infinity while the concurrency limit is reached (wake-up on release) or, for `owner`, while other owners wait ahead of it
   * (wake-up on its turn); otherwise milliseconds until the next rate slot. */
  delay(owner?:object):number{
    if(this.active>=this.concurrency)return Infinity;
    if(owner!==undefined&&this.queue.length&&this.queue[0]!.owner!==owner)return Infinity;
    return Math.max(0,this.nextAt-this.now());
  }
  /** Records that `token` (one queued request) is held back by this limiter; `wake` is called on the next release. Counted once per request.
   * With `owner` (a transport) the owner takes a place in the fair queue (an earlier place is kept) and `wake` is called on its turn instead. */
  hold(token:object,wake?:()=>void,owner?:object){
    if(!this.waitingSince.has(token)){this.waitingSince.set(token,this.now());this.waits++;}
    if(owner===undefined){if(wake)this.waiters.add(wake);return;}
    const entry=this.queue.find(e=>e.owner===owner);if(entry){if(wake)entry.wake=wake;}else this.queue.push({owner,wake:wake??(()=>{})});
    this.kick();
  }
  /** `owner` has no request held back by this limiter now (its requests went, or wait for its own limits): it gives up its place, and the next owner is woken if it may go. */
  leave(owner:object){const i=this.queue.findIndex(e=>e.owner===owner);if(i<0)return;this.queue.splice(i,1);this.kick();}
  /** Takes one program permit for `owner` (optional). Callers must check `delay()===0` first and pair every acquire with one release (with the same owner). */
  acquire(token?:object,owner?:object){
    const now=this.now();this.active++;if(owner){this.owners.set(owner,(this.owners.get(owner)??0)+1);}this.lastOwner=owner;this.peakActive=Math.max(this.peakActive,this.active);this.granted++;this.nextAt=Math.max(now,this.nextAt)+1000/this.requestsPerSecond;
    if(token){const since=this.waitingSince.get(token);if(since!==undefined){this.waitingSince.delete(token);const ms=Math.max(0,now-since);this.waitMs+=ms;this.maxWaitMs=Math.max(this.maxWaitMs,ms);this.onWait?.(ms);}}
    if(owner){const i=this.queue.findIndex(e=>e.owner===owner);if(i>=0)this.queue.splice(i,1);}
    this.kick();
  }
  /** Whether the program limit that holds `owner`'s next request back now is reached because of other owners: at the concurrency limit, while another owner has a request in
   * flight; otherwise when another owner waits ahead of it for its turn, or (at the rate limit) when the latest grant (which set the next slot) went to another owner.
   * A wait after the owner's own grant, with no other owner ahead of it, is its own pacing. */
  heldByOthers(owner:object):boolean{
    if(this.active>=this.concurrency){for(const [o,n] of this.owners)if(o!==owner&&n>0)return true;return false;}
    const i=this.queue.findIndex(e=>e.owner===owner);if(i>0||(i<0&&this.queue.length>0))return true;
    return this.lastOwner!==undefined&&this.lastOwner!==owner;
  }
  /** A held request left the queue without a program permit (aborted or over budget). */
  forget(token:object){this.waitingSince.delete(token);}
  release(owner?:object){
    if(this.active>0)this.active--;
    if(owner){const n=(this.owners.get(owner)??0)-1;if(n>0)this.owners.set(owner,n);else this.owners.delete(owner);}
    const wake=[...this.waiters];this.waiters.clear();for(const w of wake){try{w();}catch{}}
    this.kick();
  }
  /** Wakes the owner at the head of the queue when a slot is free now, or arms the one timer for the next rate slot. A woken owner that neither took the slot nor gave up its
   * place (it has nothing ready) loses the place, so a stale owner never blocks the queue. A call made while one runs (a woken owner acquiring) is folded into the running one. */
  private kick(){
    if(this.kicking){this.kickAgain=true;return;}
    this.kicking=true;
    try{
      do{
        this.kickAgain=false;clearTimeout(this.timer);this.timer=undefined;
        while(this.queue.length&&this.active<this.concurrency){
          const wait=this.nextAt-this.now();
          if(wait>0){this.timer=setTimeout(()=>{this.timer=undefined;this.kick();},Math.max(1,Math.ceil(wait)));break;}
          const head=this.queue[0]!;try{head.wake();}catch{}
          if(this.queue[0]===head)this.queue.shift();
        }
      }while(this.kickAgain);
    }finally{this.kicking=false;}
  }
  stats():ProgramLimiterStats{return {requestsPerSecond:this.requestsPerSecond,concurrency:this.concurrency,active:this.active,peakActive:this.peakActive,granted:this.granted,waits:this.waits,waitMs:Math.round(this.waitMs),maxWaitMs:Math.round(this.maxWaitMs)};}
}
const limiters=new Map<string,ProgramLimiter>();
/** The one limiter for this program (id and limits) in this process. Changing a program's limits gives a new limiter key, so a stale limit never applies. */
export function programLimiter(program:Pick<ProgramConfig,'id'|'requestsPerSecond'|'concurrency'>):ProgramLimiter{
  const key=`${program.id}|${program.requestsPerSecond}|${program.concurrency.requests}`;
  let l=limiters.get(key);if(!l){l=new ProgramLimiter(program.id,program.requestsPerSecond,program.concurrency.requests);limiters.set(key,l);}
  return l;
}
/** Fair turns for a shared capacity (2.9.1). The same first-in, first-out owner queue as the program limiter (a `ProgramLimiter` with no rate limit, `capacity` at once), for work that several targets
 * queue for in one process: a mass run's request preflight screening on the shared detector. Each owner (one target) has one place in the queue however many calls it has waiting, so a target with many
 * screenings waiting takes one turn and joins the back again, and a target that arrives later is not stuck behind all of them. A turn is taken before the shared lane and released with it. */
export class FairTurns {
  private readonly gate:ProgramLimiter;
  private pending=new Map<object,{token:object;grant:(release:()=>void)=>void;done?:()=>void}[]>();
  constructor(readonly capacity:number,now?:()=>number){this.gate=new ProgramLimiter('fair-turns',Infinity,capacity,now);}
  /** Whether a call of `owner` would get its turn at once (no earlier call of it waits, a turn is free and no other owner waits ahead of it). */
  free(owner:object):boolean{return !this.pending.get(owner)?.length&&this.gate.delay(owner)===0;}
  /** Waits for `owner`'s turn; resolves with its release (idempotent). `signal` cancels the wait: the call leaves the queue and rejects with `abortError()`. */
  take(owner:object,signal?:AbortSignal,abortError:()=>Error=()=>new Error('Turn wait cancelled')):Promise<()=>void>{
    if(signal?.aborted)return Promise.reject(abortError());
    return new Promise((resolve,reject)=>{
      const entry:{token:object;grant:(release:()=>void)=>void;done?:()=>void}={token:{},grant:resolve};
      let list=this.pending.get(owner);if(!list){list=[];this.pending.set(owner,list);}list.push(entry);
      if(signal){const cancel=()=>{const l=this.pending.get(owner),i=l?l.indexOf(entry):-1;if(i<0)return;l!.splice(i,1);if(!l!.length)this.pending.delete(owner);this.gate.forget(entry.token);reject(abortError());this.pump(owner);};
        signal.addEventListener('abort',cancel,{once:true});entry.done=()=>signal.removeEventListener('abort',cancel);}
      this.pump(owner);
    });
  }
  /** Grants `owner`'s waiting calls while it may go; otherwise keeps (or takes) its place in the queue, to be pumped again on its turn. With nothing waiting it gives up its place. */
  private pump(owner:object){
    const list=this.pending.get(owner);
    if(!list?.length){this.pending.delete(owner);this.gate.leave(owner);return;}
    while(list.length){
      if(this.gate.delay(owner)>0){this.gate.hold(list[0]!.token,()=>this.pump(owner),owner);return;}
      const entry=list.shift()!;entry.done?.();this.gate.acquire(entry.token,owner);
      let released=false;entry.grant(()=>{if(released)return;released=true;this.gate.release(owner);});
    }
    if(this.pending.get(owner)===list&&!list.length)this.pending.delete(owner);
  }
  stats(){const s=this.gate.stats();return {capacity:this.capacity,active:s.active,peakActive:s.peakActive,granted:s.granted,waits:s.waits,waitMs:s.waitMs,maxWaitMs:s.maxWaitMs};}
}
