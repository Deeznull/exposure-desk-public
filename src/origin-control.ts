import {AsyncLocalStorage} from 'node:async_hooks';
import {performance} from 'node:perf_hooks';
import type {ScanConfig,OriginAuthorization,AbortReason} from './types.js';
import {WebsiteBudget} from './adaptive-budget.js';

export interface OriginState {
  authorization?:OriginAuthorization;
  budget:WebsiteBudget;
  origin:string; started?:number; ended?:number; expiredAt?:number; cleanupMs:number;
  controller:AbortController; timer?:ReturnType<typeof setTimeout>;
  requests:number; bytes:number; wireBytes:number; pages:number; maps:number;
  retries:number; retryExhausted:number; browserPages:number; browserRequests:number; analysisMs:number;
  browserAttempts:number;browserElapsedMs:number;runtimeCaptures:number;activeRequests:number; peakRequests:number; nextAt:number; pauseUntil:number;
  connectionsOpened:number; connectionsReused:number; connectionReplays:number; tlsHandshakes:number; browserCacheHits:number; requestsAvoided:number;
  /** Shared-wait exclusion (mass mode, `OriginControl.excludeSharedWaits`): units of this website's work that only wait for shared analysis capacity, units doing its own work,
   * the moment its clock paused (every unit waiting, none working) and the paused time so far. */
  sharedWaits:number; holds:number; pausedSince?:number; sharedWaitMs:number;
  /** Per-cause split of the shared waits (2.9): this website's own waiting units by cause, its analysis turns that are paused now (each one unit, split by the causes of
   * its own waits), the paused time so far by cause, and the clock reading up to which it is split. */
  waitsBy?:CauseMs; pausedTurns?:Set<TurnClock>; byCause?:CauseMs; causeAt?:number;
  /** Mass mode: timers that count this website's charged time (OriginControl.chargedTimer); each is set again when the website's clock runs again after a pause. */
  resumers?:Set<()=>void>;
}
/** What a shared wait waits for (mass mode, 2.9): `analysis` an engine or large-text lane or analysis memory for the detectors, `parser` a parser worker or the analysis memory
 * its heap needs, `preflight` the detector screening of a request before it is sent (its lanes and memory), `programSlot` a program-wide request slot that other targets hold. */
export type SharedWaitCause='analysis'|'parser'|'preflight'|'programSlot';
export const SHARED_WAIT_CAUSES:readonly SharedWaitCause[]=['analysis','parser','preflight','programSlot'];
export type CauseMs=Record<SharedWaitCause,number>;
const noCauses=():CauseMs=>({analysis:0,parser:0,preflight:0,programSlot:0});
/** The JSON Lines split of `sharedWaitMs` (target-end, summary and the origin snapshots): whole milliseconds that always add up to the rounded `sharedWaitMs`. */
export interface SharedWaitByCause{analysisMs:number;parserMs:number;preflightMs:number;programSlotMs:number}
/** Splits `totalMs` (rounded to whole milliseconds) in proportion to `parts` by largest remainder, so the parts add up to it exactly. Ties go in the order of
 * SHARED_WAIT_CAUSES; with no parts the whole goes to `analysis`. */
export function splitRounded(totalMs:number,parts:CauseMs):SharedWaitByCause{
  const total=Math.max(0,Math.round(totalMs)),weights=SHARED_WAIT_CAUSES.map(c=>Math.max(0,parts[c]||0)),sum=weights.reduce((a,b)=>a+b,0);
  const exact=sum>0?weights.map(w=>total*w/sum):weights.map((_,i)=>i===0?total:0),out=exact.map(Math.floor);
  let left=total-out.reduce((a,b)=>a+b,0);
  const order=exact.map((x,i)=>({i,r:x-Math.floor(x)})).sort((a,b)=>b.r-a.r||a.i-b.i);
  for(const {i} of order){if(left<=0)break;out[i]!++;left--;}
  return {analysisMs:out[0]!,parserMs:out[1]!,preflightMs:out[2]!,programSlotMs:out[3]!};
}
/** One unit of a website's work whose kind changes while it lasts (a request: own work, or a wait for a program-wide request slot that other targets hold). No-ops unless `excludeSharedWaits`.
 * `wait` takes the cause of the wait (default `programSlot`). */
export interface WorkUnit{work():void;wait(cause?:SharedWaitCause):void;end():void}
/** One analysis turn's own clock in mass mode. The turn is one unit of its website's work: working, or paused while it only waits for shared analysis capacity (an engine or
 * large-text lane, analysis memory, a parser worker) that other targets hold. `charged` is the turn's time without those waits; `onResume` runs when the turn works again. */
export class TurnClock{
  waits=0;holds=0;waitMs=0;since?:number;ended=false;state?:OriginState;onResume?:()=>void;readonly started:number;
  /** The turn's waiting units by cause (2.9). */
  waitsBy=noCauses();
  constructor(readonly control:OriginControl){this.started=control.now();}
  get paused(){return this.since!==undefined;}
  charged(at=this.control.now()){return Math.max(0,at-this.started-this.waitMs-(this.since===undefined?0:Math.max(0,at-this.since)));}
}
/** Normalize any abort reason (structured, legacy string or absent) into a structured cause. */
export function abortReason(signal:AbortSignal|undefined,fallback:AbortReason['kind']='user-cancelled'):AbortReason|undefined{
  if(!signal?.aborted)return undefined;const r=signal.reason;
  if(r&&typeof r==='object'&&typeof r.kind==='string')return {kind:r.kind,origin:r.origin,turn:r.turn};
  if(r==='work-turn-limit')return {kind:'work-turn-limit',turn:'static'};
  if(r==='analysis-turn-limit')return {kind:'analysis-turn-limit',turn:'analysis'};
  if(r==='origin-duration-limit')return {kind:'origin-deadline'};
  return {kind:fallback};
}
/** One monotonic clock per admitted exact origin. Idle turns never pause it. In mass mode (`excludeSharedWaits`) the time a website only waits for shared analysis capacity is not
 * charged to it: its clock pauses while at least one unit of its work waits for that capacity and none works (a request in flight or waiting for its permit, a backoff, a browser turn,
 * a held lane, worker or memory, or an analysis turn that is not waiting). A request waiting for a program-wide request slot that other targets hold (Transport.pumpPermits) counts as a wait.
 * The scan's own clock pauses while every open website is paused. Politeness waits (the website's own pacing, backoff and pauses) and program-limit waits after its own grant stay charged. */
export class OriginControl {
  readonly states=new Map<string,OriginState>();
  private context=new AsyncLocalStorage<{state:OriginState;signal:AbortSignal;turn?:TurnClock}>();
  /** Mass mode: other targets share this process's analysis capacity, so a wait for it is excluded from this target's clocks (set by the Scanner before the scan starts). */
  excludeSharedWaits=false;
  private closed=false;private projectSince?:number;private projectWaitMs=0;
  /** The scan's paused time by cause (2.9) and the clock reading up to which it is split; the cause of the shared waits marked inside `waitCause`. */
  private projectByCause=noCauses();private projectCauseAt?:number;private causeContext=new AsyncLocalStorage<SharedWaitCause>();
  /** Runs when the scan's own clock runs again after a pause (the scanner re-arms its project timer). */
  onProjectResume?:()=>void;
  /** The scan's analysis time factor (machine-speed.ts); it scales each website's analysis time allocation. */
  timeFactor=1;
  /** Sets the factor for budgets created from now on and rescales the existing ones (the seed websites' budgets are created with the transport, before the scan starts). */
  setTimeFactor(factor:number){this.timeFactor=factor;for(const state of this.states.values())state.budget.setTimeFactor(factor);}
  constructor(readonly config:ScanConfig,readonly projectSignal:AbortSignal,readonly now=()=>performance.now()){projectSignal.addEventListener('abort',()=>this.settleAll(),{once:true});}
  get current(){return this.context.getStore()?.state;}
  get signal(){return this.context.getStore()?.signal||this.projectSignal;}
  get(url:string){
    const origin=new URL(url).origin;let state=this.states.get(origin);
    if(!state){state={origin,budget:new WebsiteBudget(origin,this.config,this.timeFactor),controller:new AbortController(),cleanupMs:0,requests:0,bytes:0,wireBytes:0,pages:0,maps:0,retries:0,retryExhausted:0,browserPages:0,browserRequests:0,analysisMs:0,browserAttempts:0,browserElapsedMs:0,runtimeCaptures:0,activeRequests:0,peakRequests:0,nextAt:0,pauseUntil:0,connectionsOpened:0,connectionsReused:0,connectionReplays:0,tlsHandshakes:0,browserCacheHits:0,requestsAvoided:0,sharedWaits:0,holds:0,sharedWaitMs:0,waitsBy:noCauses(),pausedTurns:new Set(),byCause:noCauses()};this.states.set(origin,state);}
    return state;
  }
  /** Read-only lookup that never creates origin state. */
  peek(url:string){try{return this.states.get(new URL(url).origin);}catch{return undefined;}}
  /** Time not charged to the website up to `at`: its finished pauses and the current one. */
  private excluded(state:OriginState,at:number){return state.sharedWaitMs+(state.pausedSince===undefined?0:Math.max(0,at-state.pausedSince));}
  elapsed(url?:string){const state=url?this.get(url):this.current;if(state?.started===undefined)return 0;const end=state.ended??Math.min(this.now(),state.expiredAt??Infinity);return Math.max(0,end-state.started-this.excluded(state,end));}
  /** `at`: the clock reading to use (default: now), so a check can compare this with the scan's time left at one instant. */
  remainingMs(url?:string,at?:number){const state=url?this.get(url):this.current;if(state?.started===undefined)return Math.max(0,this.config.originMaxDurationMs??this.config.maxDurationMs);const end=state.ended??at??this.now();return Math.max(0,(this.config.originMaxDurationMs??this.config.maxDurationMs)-(end-state.started-this.excluded(state,end)));}
  soft(url?:string){const state=url?this.get(url):this.current;return state?.started!==undefined&&this.remainingMs(url)<=(this.config.originMaxDurationMs??this.config.maxDurationMs)*0.1;}
  expired(url?:string){const state=url?this.get(url):this.current;return !!state&&(state.controller.signal.aborted||state.started!==undefined&&this.remainingMs(url)<=0);}
  expire(url?:string){const state=url?this.get(url):this.current;if(state&&!state.controller.signal.aborted){const now=this.now();state.expiredAt=state.started===undefined?now:state.started+(this.config.originMaxDurationMs??this.config.maxDurationMs)+this.excluded(state,now);state.controller.abort({kind:'origin-deadline',origin:state.origin} satisfies AbortReason);this.settle(state);}}
  /** The scan's own time limit, set by the transport. A website's timer that finds it reached by the clock too (first, or at the same moment) expires the scan's
   * limit instead, as Transport.limitTimer does, so a wait ends the same way whichever timer runs first. */
  projectLimit?:{remainingMs(at?:number):number;expire():void};
  private arm(state:OriginState){clearTimeout(state.timer);state.timer=undefined;if(state.pausedSince!==undefined)return;state.timer=setTimeout(()=>this.due(state),Math.max(1,this.remainingMs(state.origin)));state.timer.unref();}
  /** A website's timer ran. Its limit counts as reached only when the clock reads it (Node can run a timer up to 1 ms early): before that the timer is set again
   * for the time still left. Once the clock reads the scan's limit as reached at or before the website's, the scan's limit expires. Both are read at one instant. */
  private due(state:OriginState){
    if(state.ended!==undefined||state.controller.signal.aborted||state.pausedSince!==undefined)return;
    const at=this.now(),website=this.remainingMs(state.origin,at),project=this.projectLimit?this.projectLimit.remainingMs(at):Infinity;
    if(website>0&&project>0){this.arm(state);return;}
    if(project<=website)this.projectLimit!.expire();else this.expire(state.origin);
  }
  /** Network runs inherit the parent turn; analysis runs (`inherit:false`) see only the project, their own origin and their own phase signal.
   * `turn` (mass mode) makes the run one unit of its website's work until its task settles; a run on the same website inherits its parent's turn. */
  run<T>(url:string,task:()=>T,extraSignal?:AbortSignal,options:{inherit?:boolean;turn?:TurnClock}={}):T {
    const state=this.get(url),parent=options.inherit===false?undefined:this.context.getStore();
    if(state.ended!==undefined){state.ended=undefined;this.arm(state);this.settle(state);}
    if(state.started===undefined){state.started=this.now();this.arm(state);this.settle(state);}
    if(this.remainingMs(url)<=0)this.due(state);
    const signals=[this.projectSignal,state.controller.signal,...(parent?[parent.signal]:[]),...(extraSignal?[extraSignal]:[])];
    const own=options.turn&&options.turn.state===undefined&&!options.turn.ended?options.turn:undefined,turn=options.turn??(parent?.state===state?parent.turn:undefined);
    if(!own)return this.context.run({state,signal:AbortSignal.any(signals),turn},task);
    own.state=state;state.holds++;this.settle(state);let result:T;
    try{result=this.context.run({state,signal:AbortSignal.any(signals),turn},task);}catch(e){this.detach(own);throw e;}
    if(result&&typeof (result as any).then==='function')(result as any).then(()=>this.detach(own),()=>this.detach(own));else this.detach(own);
    return result;
  }
  /** Marks, for the current unit of work, a wait for shared analysis capacity (`sharedWait`), a held share of it (`sharedHold`) or own work such as a request (`busy`); each returns its end (idempotent). No-ops unless `excludeSharedWaits`. */
  /** `cause` (2.9): what the wait is for; by default the cause of the enclosing `waitCause`, else `analysis`. */
  sharedWait(cause?:SharedWaitCause){return this.mark(true,cause??this.causeContext.getStore()??'analysis');}
  sharedHold(){return this.mark(false);}
  busy(){return this.mark(false);}
  /** Runs `task` with `cause` as the cause of the shared waits it marks without naming one (e.g. the detector's lane and memory waits of a preflight screening). */
  waitCause<T>(cause:SharedWaitCause,task:()=>T):T{return this.causeContext.run(cause,task);}
  /** The cause of the enclosing `waitCause`, if any (2.9.1: a mass run's request preflight takes fair turns for the shared detector by it). */
  currentCause():SharedWaitCause|undefined{return this.causeContext.getStore();}
  /** A unit of the current website's work that starts with no kind and can switch between own work and a wait for shared capacity; marks are applied to the website (or turn)
   * current when the unit was made, from whatever context the switch is called. A switch marks the new kind before it ends the old one, so the unit never reads as gone. */
  unit():WorkUnit{
    const store=this.context.getStore();let kind:string|undefined,end=()=>{};
    const set=(next:'work'|'wait'|undefined,cause:SharedWaitCause='programSlot')=>{const key=next==='wait'?'wait:'+cause:next;if(key===kind)return;const old=end;kind=key;end=next?this.markIn(store,next==='wait',cause):()=>{};old();};
    return {work:()=>set('work'),wait:(cause?:SharedWaitCause)=>set('wait',cause),end:()=>set(undefined)};
  }
  /** A timer for `limitMs` of the website's charged time from now (mass mode: its paused time is not counted). It has no timeout while the website's clock is paused and is set
   * again for the time left when it runs again; `onLimit` runs once when the clock reads the limit as reached. Returns its cancel. */
  chargedTimer(url:string,limitMs:number,onLimit:()=>void):()=>void{
    const state=this.get(url),charged=()=>{const at=this.now();return at-this.excluded(state,at);},start=charged(),resumers=state.resumers??=new Set();
    let timer:ReturnType<typeof setTimeout>|undefined,done=false;
    const arm=(due=false)=>{clearTimeout(timer);timer=undefined;if(done||state.pausedSince!==undefined)return;const left=limitMs-(charged()-start);if(due&&left<=0){done=true;resumers.delete(resume);onLimit();return;}timer=setTimeout(()=>arm(true),Math.max(1,Math.ceil(left)));},resume=()=>arm();
    resumers.add(resume);arm();
    return ()=>{done=true;clearTimeout(timer);timer=undefined;resumers.delete(resume);};
  }
  private mark(wait:boolean,cause:SharedWaitCause='analysis'):()=>void{return this.markIn(this.context.getStore(),wait,cause);}
  private markIn(store:{state:OriginState;turn?:TurnClock}|undefined,wait:boolean,cause:SharedWaitCause='analysis'):()=>void{
    if(!this.excludeSharedWaits||!store)return ()=>{};
    const {state,turn}=store,change=(by:number)=>{this.accrue();if(turn){if(wait){turn.waits+=by;turn.waitsBy[cause]+=by;}else turn.holds+=by;this.settleTurn(turn);}else{if(wait){state.sharedWaits+=by;(state.waitsBy??=noCauses())[cause]+=by;}else state.holds+=by;this.settle(state);}};
    change(1);let done=false;return ()=>{if(done)return;done=true;change(-1);};
  }
  private settleTurn(turn:TurnClock){
    if(turn.ended)return;const pause=this.excludeSharedWaits&&turn.waits>0&&turn.holds===0,state=turn.state;if(pause===turn.paused)return;
    const at=this.now();this.accrue(at);
    if(pause){turn.since=at;if(state){state.holds--;state.sharedWaits++;(state.pausedTurns??=new Set()).add(turn);}}else{turn.waitMs+=at-turn.since!;turn.since=undefined;if(state){state.sharedWaits--;state.holds++;state.pausedTurns?.delete(turn);}}
    if(state)this.settle(state);if(!pause)turn.onResume?.();
  }
  private detach(turn:TurnClock){
    if(turn.ended)return;turn.ended=true;const state=turn.state;const at=this.now();this.accrue(at);
    if(turn.since!==undefined){turn.waitMs+=at-turn.since;turn.since=undefined;if(state){state.sharedWaits--;state.pausedTurns?.delete(turn);}}else if(state)state.holds--;
    if(state)this.settle(state);
  }
  /** A paused website's waiting units by cause, as shares that add up to 1: each own waiting unit counts one, each paused analysis turn counts one split by the causes of its waits. */
  private shares(state:OriginState):CauseMs{
    const w={...(state.waitsBy??noCauses())};
    for(const t of state.pausedTurns??[])if(t.waits>0)for(const c of SHARED_WAIT_CAUSES)w[c]+=t.waitsBy[c]/t.waits;
    const sum=SHARED_WAIT_CAUSES.reduce((a,c)=>a+w[c],0);if(!(sum>0))return {...noCauses(),analysis:1};
    for(const c of SHARED_WAIT_CAUSES)w[c]/=sum;return w;
  }
  /** Splits the paused time up to `at` by cause (2.9): each paused website's by the shares of its waiting units, the scan's by the average share over its paused open websites.
   * Called before any unit, turn or pause changes, so every stretch of paused time is split by the units that waited during it. */
  private accrue(at=this.now()){
    if(!this.excludeSharedWaits)return;const shares:CauseMs[]=[],all:CauseMs[]=[];
    for(const s of this.states.values()){
      if(s.pausedSince===undefined)continue;const w=this.shares(s),from=s.causeAt??s.pausedSince,d=at-from,by=s.byCause??=noCauses();
      if(d>0){for(const c of SHARED_WAIT_CAUSES)by[c]+=d*w[c];s.causeAt=at;}
      all.push(w);if(this.open(s))shares.push(w);
    }
    if(this.projectSince===undefined)return;const from=this.projectCauseAt??this.projectSince,d=at-from;if(!(d>0))return;
    const list=shares.length?shares:all;
    for(const c of SHARED_WAIT_CAUSES)this.projectByCause[c]+=list.length?d*list.reduce((a,w)=>a+w[c],0)/list.length:(c==='analysis'?d:0);
    this.projectCauseAt=at;
  }
  private open(state:OriginState){return !this.closed&&state.started!==undefined&&state.ended===undefined&&!state.controller.signal.aborted&&!this.projectSignal.aborted;}
  /** Pauses or resumes a website's clock (and then the scan's) after its units changed. A paused clock has no timer; a resumed one is armed for the time left. */
  private settle(state:OriginState){
    const at=this.now(),pause=this.excludeSharedWaits&&this.open(state)&&state.sharedWaits>0&&state.holds===0;this.accrue(at);
    if(pause&&state.pausedSince===undefined){state.pausedSince=at;state.causeAt=at;clearTimeout(state.timer);state.timer=undefined;}
    else if(!pause&&state.pausedSince!==undefined){state.sharedWaitMs+=at-state.pausedSince;state.pausedSince=undefined;state.causeAt=undefined;if(this.open(state))this.arm(state);this.settleProject(at);this.resume(state);return;}
    this.settleProject(at);
  }
  /** The website's clock runs again: its charged-time timers are set again for the time they have left. */
  private resume(state:OriginState){if(state.resumers)for(const r of [...state.resumers])r();}
  private settleAll(){for(const state of this.states.values())this.settle(state);this.settleProject(this.now());}
  /** The scan's clock is paused while at least one website is open and every open website is paused. */
  private settleProject(at:number){
    let open=0,paused=0;if(this.excludeSharedWaits&&!this.closed&&!this.projectSignal.aborted)for(const s of this.states.values())if(this.open(s)){open++;if(s.pausedSince!==undefined)paused++;}
    const pause=open>0&&paused===open;this.accrue(at);
    if(pause&&this.projectSince===undefined){this.projectSince=at;this.projectCauseAt=at;}
    else if(!pause&&this.projectSince!==undefined){this.projectCauseAt=undefined;this.projectWaitMs+=at-this.projectSince;this.projectSince=undefined;this.onProjectResume?.();}
  }
  get projectPaused(){return this.projectSince!==undefined;}
  /** Time not charged to the scan's own clock up to `at` (the transport subtracts it from the scan's elapsed time). */
  projectExcludedMs(at=this.now()){return this.projectWaitMs+(this.projectSince===undefined?0:Math.max(0,at-this.projectSince));}
  /** The scan's excluded time up to now, rounded, and its split by cause (2.9, mass mode): the parts add up to `sharedWaitMs` exactly. */
  projectWait():{sharedWaitMs:number;sharedWaitByCause:SharedWaitByCause}{const at=this.now();this.accrue(at);const sharedWaitMs=Math.round(this.projectExcludedMs(at));return {sharedWaitMs,sharedWaitByCause:splitRounded(sharedWaitMs,this.projectByCause)};}
  /** Run outside every origin turn: only the project signal applies, and no origin clock starts. */
  detached<T>(task:()=>T):T{return this.context.exit(task);}
  finish(url:string){const state=this.get(url);clearTimeout(state.timer);if(state.started!==undefined&&state.ended===undefined){const now=this.now();this.accrue(now);const resumed=state.pausedSince!==undefined;if(resumed){state.sharedWaitMs+=now-state.pausedSince!;state.pausedSince=undefined;state.causeAt=undefined;}state.ended=Math.min(now,state.expiredAt??Infinity);state.cleanupMs=state.expiredAt===undefined?0:Math.max(0,now-state.expiredAt);this.settleProject(now);if(resumed)this.resume(state);}}
  cancel(){this.closed=true;this.settleAll();for(const state of this.states.values())clearTimeout(state.timer);}
  snapshots(){this.accrue();return [...this.states.values()].map(state=>({origin:state.origin,admitted:state.started!==undefined,elapsedMs:this.elapsed(state.origin),remainingMs:this.remainingMs(state.origin),softDeadline:this.soft(state.origin),deadlineReached:this.expired(state.origin),cleanupMs:state.cleanupMs,requests:state.requests,bytes:state.bytes,wireBytes:state.wireBytes,pages:state.pages,maps:state.maps,retries:state.retries,retryExhausted:state.retryExhausted,browserPages:state.browserPages,browserRequests:state.browserRequests,browserAttempts:state.browserAttempts,browserElapsedMs:state.browserElapsedMs,runtimeCaptures:state.runtimeCaptures,analysisMs:state.analysisMs,activeRequests:state.activeRequests,peakRequests:state.peakRequests,connectionsOpened:state.connectionsOpened,connectionsReused:state.connectionsReused,connectionReplays:state.connectionReplays,tlsHandshakes:state.tlsHandshakes,browserCacheHits:state.browserCacheHits,requestsAvoided:state.requestsAvoided,...(this.excludeSharedWaits?this.waitView(state):{})}));}
  /** Mass mode: a website's excluded time, rounded, and its split by cause (2.9); the parts add up to `sharedWaitMs` exactly. */
  private waitView(state:OriginState):{sharedWaitMs:number;sharedWaitByCause:SharedWaitByCause}{const sharedWaitMs=Math.round(this.excluded(state,state.ended??this.now()));return {sharedWaitMs,sharedWaitByCause:splitRounded(sharedWaitMs,state.byCause??noCauses())};}
}

/** 2.6 traffic counters; records from 2.5 and earlier (and 2.6 Part 1 views) do not have them. */
type TrafficCounter='connectionsOpened'|'connectionsReused'|'connectionReplays'|'tlsHandshakes'|'browserCacheHits'|'requestsAvoided';
type LiveSnapshot=ReturnType<OriginControl["snapshots"]>[number];
export type OriginSnapshot=Omit<LiveSnapshot,TrafficCounter> & Partial<Pick<LiveSnapshot,TrafficCounter>> & {authorization?:OriginAuthorization;completion?:"configured-checks-completed"|"limited"|"insufficient"};
