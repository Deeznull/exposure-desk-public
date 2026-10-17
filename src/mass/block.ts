/** Block detection for mass scans (2.8). A pure, dependency-free monitor: it is fed one observation per response and per connection reset, and decides when a
 * target is being blocked. The response here only ever STOPS and backs off; it never evades. There is no User-Agent, header, proxy or IP change, and no retry
 * around a block (the transport's retry delay throws the aborted stop cause once a block aborts the signal). The transport honours Retry-After and backs off
 * exponentially (capped) on its own before a streak ever trips. */
export interface BlockObservation {
  /** HTTP status of a completed response (undefined for a reset). */
  status?:number;
  /** The response's httpDisposition, computed with the body text so 'suspected-bot-challenge' is visible (cf-mitigated / challenge-platform / captcha / "verify you are human" / "checking your browser" / bot detection). */
  disposition?:string;
  /** The response carried a Retry-After header (recorded in the reason only; it does not by itself trip anything). */
  retryAfter?:boolean;
  /** A connection reset / network failure for an in-scope request. */
  reset?:boolean;
}
export interface BlockDecision {
  kind:'status'|'challenge'|'reset';
  /** Short machine-ish reason, e.g. "repeated HTTP 403 responses". */
  reason:string;
  /** The status that tripped a status/challenge decision (absent for resets). */
  status?:number;
  /** Full gap/event detail; always ends with the no-evasion statement. */
  detail:string;
}
export interface BlockLimits {statusStreak:number;challengeStreak:number;resetStreak:number}
/** Consecutive-signal thresholds before a target is called blocked. A challenge interstitial trips fast (2); plain repeated 403/429/503 trips at 5; connection resets at 3. */
export const BLOCK_DEFAULTS:BlockLimits={statusStreak:5,challengeStreak:2,resetStreak:3};
const NO_EVASION='No evasion was attempted: no User-Agent, header, proxy or IP change, and no retry around the block. Retry-After was honoured and back-off was exponential (capped) before stopping.';
/** The statuses that count toward a block streak (refusal / rate-limit / unavailable); a challenge is recognised separately by disposition. */
const BLOCK_STATUS=new Set([403,429,503]);
/** Tracks one target. `observe` returns a decision the first time a threshold is crossed and that same decision for every later call; a normal response clears the streaks. */
export class BlockMonitor {
  private statusRun=0;private challengeRun=0;private resetRun=0;
  blocked?:BlockDecision;
  constructor(readonly limits:BlockLimits=BLOCK_DEFAULTS){}
  observe(o:BlockObservation):BlockDecision|undefined{
    if(this.blocked)return this.blocked;
    if(o.reset){this.statusRun=0;this.challengeRun=0;this.resetRun++;return this.resetRun>=this.limits.resetStreak?this.trip('reset',`repeated connection resets (${this.resetRun})`):undefined;}
    this.resetRun=0;
    if(o.disposition==='suspected-bot-challenge'){this.challengeRun++;this.statusRun++;return this.challengeRun>=this.limits.challengeStreak?this.trip('challenge',`repeated bot/challenge interstitials (${this.challengeRun})`,o.status):undefined;}
    if(o.status!==undefined&&BLOCK_STATUS.has(o.status)){this.challengeRun=0;this.statusRun++;return this.statusRun>=this.limits.statusStreak?this.trip('status',`repeated HTTP ${o.status}${o.retryAfter?' with Retry-After':''} responses (${this.statusRun})`,o.status):undefined;}
    // Any other response (2xx/3xx/404/401/5xx that is not 503) means the target is still answering: clear the streaks.
    this.statusRun=0;this.challengeRun=0;return undefined;
  }
  private trip(kind:BlockDecision['kind'],reason:string,status?:number):BlockDecision{
    this.blocked={kind,reason,...(status!==undefined?{status}:{}),detail:`Target stopped: ${reason}. ${NO_EVASION}`};
    return this.blocked;
  }
}
