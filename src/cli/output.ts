import { BUILD } from '../build-info.js';
import type { Finding, ScanView } from '../types.js';
import { INFORMATIONAL_GAPS } from '../transport.js';
export const JSONL_SCHEMA='exposure-jsonl/1';
/** Terminal and JSON Lines output. With --jsonl, standard output carries only events (one JSON object per line, written at once) and the readable lines move to
 * standard error; --silent drops progress and plan lines and keeps results. Every value comes from the redacted scan view: output here is always masked. */
export class Output{
  /** Set once standard output fails, for example when the reader of a pipe went away (`| head -1`): later events are dropped and `onClosed` stops the run like Ctrl+C. */
  closed=false;onClosed?:()=>void;
  constructor(readonly jsonl:boolean,readonly silent:boolean){if(jsonl)watchStdout(this);}
  info(line:string){if(this.silent)return;if(this.jsonl)console.error(line);else console.log(line);}
  result(line:string){if(this.jsonl){if(!this.silent)console.error(line);}else console.log(line);}
  event(event:'run-start'|'target-start'|'finding'|'target-end'|'summary',data:Record<string,unknown>){if(this.jsonl&&!this.closed&&!process.stdout.destroyed)process.stdout.write(JSON.stringify({schema:JSONL_SCHEMA,event,at:new Date().toISOString(),...(event==='run-start'?{version:BUILD.version}:{}),...data})+'\n');}
}
/** One process-wide listener (a write error is emitted after the write returns, possibly after the run ended): without it a closed pipe ends the process with a raw stack trace. */
let watched:Output|undefined,watching=false;
function watchStdout(out:Output){watched=out;if(watching)return;watching=true;process.stdout.on('error',()=>{const o=watched;if(!o||o.closed)return;o.closed=true;o.onClosed?.();});}
const active=(f:Finding)=>!!f.suppression&&Date.parse(f.suppression.expires)>Date.now();
const where=(o?:Finding['occurrences'][number])=>o?o.url+(o.line!==undefined&&o.column!==undefined?`:${o.line}:${o.column}`:''):'location unavailable';
export const findingLine=(f:Finding)=>`Finding ${f.findingId||f.correlation||f.id} · ${f.priority?.level?f.priority.level+' priority · ':''}${f.severity} · ${f.category} · ${f.provider} (${f.rule}) · ${f.masked} · ${where(f.occurrences[0])}${f.occurrences.length>1?` (+${f.occurrences.length-1} more)`:''}${active(f)?' · suppressed':''}`;
export const findingEvent=(target:number,f:Finding)=>({target,findingId:f.findingId||f.correlation||f.id,category:f.category,severity:f.severity,confidence:f.confidence,priority:f.priority?.level??null,provider:f.provider,rule:f.rule,...(f.exposureKind?{exposureKind:f.exposureKind}:{}),masked:f.masked,validity:f.validity,suppressed:active(f),occurrences:f.occurrences.length,locations:f.occurrences.slice(0,20).map(o=>({url:o.url,...(o.line!==undefined&&o.column!==undefined?{line:o.line,column:o.column}:{})}))});
/** Incomplete coverage records by code, most frequent first (at most 50 codes). */
/** `target-end.gaps`: incomplete coverage by code, plus (2.9.1) the informational refusals that 2.9.0 listed here as incomplete (`invalid-url`), kept with `informational: true`. */
export const gapSummary=(v:ScanView)=>{const m=new Map<string,{count:number;informational:boolean}>();
  for(const g of v.limitations){const informational=!g.incomplete;if(informational&&!INFORMATIONAL_GAPS.includes(g.code))continue;const e=m.get(g.code);if(e){e.count++;if(!informational)e.informational=false;}else m.set(g.code,{count:1,informational});}
  return [...m].sort((a,b)=>b[1].count-a[1].count||a[0].localeCompare(b[0])).slice(0,50).map(([code,e])=>e.informational?{code,count:e.count,informational:true}:{code,count:e.count});};
