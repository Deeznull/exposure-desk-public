import v8 from 'node:v8';
import vm from 'node:vm';

/** Texts below this size are not counted: their syntax trees are small enough to die in V8's young generation and are reclaimed by its cheap scavenges. */
export const PARSE_COUNT_MIN_BYTES=64*1024;
/** Counted parse bytes after which one full collection runs (the syntax tree of a script is roughly 100 times its text). */
export const PARSE_COLLECT_BYTES=512*1024;

/** V8's full collection, or undefined where it cannot be had. Node exposes it only under --expose-gc; the flag is set for the moment the function is fetched
 * from a fresh context and set back at once, the way test runners fetch it, so no other code sees a global `gc`. A process started with --expose-gc uses its own. */
export function fullCollection():(()=>void)|undefined{
  const own=(globalThis as {gc?:unknown}).gc;if(typeof own==='function')return own as ()=>void;
  try{v8.setFlagsFromString('--expose-gc');const gc=vm.runInNewContext('gc');return typeof gc==='function'?gc as ()=>void:undefined;}
  catch{return undefined;}
  finally{try{v8.setFlagsFromString('--no-expose-gc');}catch{}}
}

/** Mass runs (2.9): structured discovery parses each script in the scan process (acorn), and the syntax tree of a 1.25 MB bundle holds 60-200 MiB of heap for under a
 * second, then is garbage. One target leaves one such tree; several targets parsing in turn left theirs for V8 to collect later, by which time the heap and the pages it
 * keeps had grown to several trees (16 targets with a 1.25 MB bundle each: 378 MiB peak at one target, 560-580 MiB at 4). The target-level MemoryGate cannot see this:
 * the cost is a spike of one operation, not a steady cost of a target. The collector counts the bytes of texts of at least PARSE_COUNT_MIN_BYTES parsed in process since
 * the last collection and, once they reach `thresholdBytes`, runs one full collection, so the garbage of finished parses never piles up past that much text. Nothing in
 * the analysis changes: every text is parsed as before, with the same budgets. Without a collection function (`collect` null) it does nothing. */
export class ParseCollector{
  collections=0;collectMs=0;private pending=0;
  constructor(readonly thresholdBytes=PARSE_COLLECT_BYTES,private readonly collect:(()=>void)|null=fullCollection()??null,private readonly clock:()=>number=()=>performance.now()){}
  /** One finished in-process parse of `bytes` of text; collects when the counted bytes reach the threshold. Returns whether it collected. */
  parsed(bytes:number){
    if(bytes<PARSE_COUNT_MIN_BYTES||!this.collect)return false;
    this.pending+=bytes;if(this.pending<this.thresholdBytes)return false;
    this.pending=0;const at=this.clock();this.collect();this.collections++;this.collectMs+=this.clock()-at;return true;
  }
  stats(){return {parseCollections:this.collections,parseCollectMs:Math.round(this.collectMs)};}
}
