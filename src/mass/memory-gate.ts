import {ANALYSIS_MEMORY_CEILING_MB} from '../profiles.js';
import {PROGRAM_LIMITS} from '../program/settings.js';

const MiB=1048576;
/** The sampling interval the decay rate is stated in (mass-run samples this often), and how long the highest recent target count is remembered. */
export const MEMORY_SAMPLE_MS=250,RECENT_HIGH_MS=30000;

/** The scan process's memory ceiling for a mass run: 512 MiB with ready options; an explicit program `analysisMemoryMb` above that raises it to that value (at most 2048). */
export function massMemoryCeilingMb(explicitMb?:number){
  return explicitMb===undefined?ANALYSIS_MEMORY_CEILING_MB:Math.min(PROGRAM_LIMITS.analysisMemoryMb.max,Math.max(ANALYSIS_MEMORY_CEILING_MB,explicitMb));
}

/** Memory-aware admission for mass scans (2.8). The scan process (resident set) must stay within `ceilingMb` at any concurrency, so a further target starts only
 * when the larger of the current resident set and the projection (start-up resident set + running targets × per-target estimate) plus one more target fits under
 * the ceiling less a margin (an eighth of the ceiling, at least 32 MiB) for the growth of targets already running.
 * The per-target estimate starts at `priorMb` and follows what this run measures: a reading is (resident set − start-up resident set) ÷ targets, where targets is
 * the larger of the running count and the highest count of the last RECENT_HIGH_MS. Memory a finished target leaves behind until the next collection, and shared
 * memory such as the parser's workers, is so spread over the targets that held it, and a dip in the running count (targets ending, the gate holding the next one
 * back) does not read as a costlier target and hold the run at one target. A higher reading raises the estimate at once; a lower one lowers it slowly (2 % per
 * MEMORY_SAMPLE_MS of elapsed time, however often it is read), so neither a start-up burst nor a short collection pause lets a burst of targets in.
 * The scheduler always starts a target when none runs, so a run progresses even when one target alone needs more. The effective concurrency is what the
 * scheduler reached under this gate (MassScheduler.peakActive). */
export class MemoryGate{
  readonly marginMb:number;readonly baseMb:number;
  perTargetMb:number;peakRssMb:number;
  /** Times a further target was held back (one per stretch of refusals). */
  waits=0;
  private refusing=false;private lastAt:number;private recentHigh=0;private recentHighAt=0;
  constructor(readonly ceilingMb:number,private readonly rssMb:()=>number=()=>process.memoryUsage.rss()/MiB,priorMb=8,private readonly clock:()=>number=()=>performance.now()){
    this.marginMb=Math.max(32,Math.round(ceilingMb/8));this.baseMb=rssMb();this.peakRssMb=this.baseMb;this.perTargetMb=priorMb;this.lastAt=clock();
  }
  /** One reading with `active` targets running: keeps the peak and updates the per-target estimate. Returns the reading. */
  sample(active:number){
    const now=this.rssMb(),at=this.clock();if(now>this.peakRssMb)this.peakRssMb=now;
    if(active>=this.recentHigh||at-this.recentHighAt>RECENT_HIGH_MS){this.recentHigh=active;this.recentHighAt=at;}
    if(active>0){
      const per=Math.max(0,now-this.baseMb)/Math.max(active,this.recentHigh);
      if(per>=this.perTargetMb)this.perTargetMb=per;
      else{const keep=Math.pow(0.98,Math.max(0,at-this.lastAt)/MEMORY_SAMPLE_MS);this.perTargetMb=this.perTargetMb*keep+per*(1-keep);}
    }
    this.lastAt=at;return now;
  }
  /** Whether one more target may start while `active` run. */
  admit(active:number){
    const now=this.sample(active),projected=Math.max(now,this.baseMb+active*this.perTargetMb)+this.perTargetMb,ok=projected<=this.ceilingMb-this.marginMb;
    if(!ok&&!this.refusing)this.waits++;this.refusing=!ok;return ok;
  }
  stats(){return {ceilingMb:this.ceilingMb,marginMb:this.marginMb,startRssMb:Math.round(this.baseMb),peakRssMb:Math.round(this.peakRssMb),perTargetMb:Math.round(this.perTargetMb*10)/10,admissionWaits:this.waits};}
}
