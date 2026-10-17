import type {WorkItem} from './types.js';
import {workClass,type WorkClass} from './resource-types.js';
const classes:WorkClass[]=['entryPages','javascript','configuration','sourceMaps','discovery','other','optionalPages','baseline','deployment','lowValue'];
/** Admitted in-domain roots (`/` and `/robots.txt` of automatically admitted origins) rank with discovery work, below JavaScript and above optional pages, without joining the seed barrier. */
export function workPriority(item:Pick<WorkItem,'url'|'kind'>,entries:string[]=[],roots?:ReadonlySet<string>){if(roots?.has(item.url))return 1;const c=workClass(item,entries);return ['javascript','configuration','sourceMaps'].includes(c)?0:c==='entryPages'||c==='discovery'||c==='other'?1:c==='optionalPages'?2:3;}
const certaintyRank=(w:Pick<WorkItem,'certainty'|'kind'>)=>w.certainty==='confirmed'?0:w.certainty==='contextual'?1:w.certainty==='heuristic'||w.kind==='asset-hint'?2:1;
const origin=(url:string)=>{try{return new URL(url).origin;}catch{return url;}};
/** Deterministic origin turns, resource priority, and a configured-seed barrier.
 * HTTP capacity is separately released after every bounded request turn.
 * `waiting` snapshots, once per take, which work belongs to a website that has to wait for a website slot (ready options' websites at once);
 * that work is left out before the seed barrier, so a waiting website's seed never holds back the websites in progress. */
export class FairScheduler{
 private lastOrigin='';readonly active=new Map<WorkItem,number>();readonly dispatches:{class:WorkClass;url:string;at:number}[]=[];
 constructor(private queue:()=>WorkItem[],private entries:string[],private blocked:(w:WorkItem)=>string|undefined=()=>undefined,private roots:()=>ReadonlySet<string>|undefined=()=>undefined,private waiting:()=>(w:WorkItem)=>boolean=()=>()=>false){}
 private priority(w:WorkItem){return workPriority(w,this.entries,this.roots());}
 take(includeOptional=true,essentialOnly=false):WorkItem|undefined{
  const q=this.queue(),now=Date.now(),waits=this.waiting(),ready=q.filter(w=>!waits(w)),seedsPending=ready.some(w=>this.entries.includes(w.url)),seedsActive=[...this.active.keys()].some(w=>this.entries.includes(w.url));
  let candidates=ready.filter(w=>(!w.notBefore||w.notBefore<=now)&&!this.blocked(w));
  if(!includeOptional)candidates=candidates.filter(w=>!['baseline','deployment'].includes(workClass(w,this.entries)));
  if(essentialOnly)candidates=candidates.filter(w=>['entryPages','javascript','configuration','sourceMaps'].includes(workClass(w,this.entries)));
  if(seedsPending){const seeds=candidates.filter(w=>this.entries.includes(w.url)||w.kind==='robots');candidates=seeds.length?seeds:candidates.filter(w=>this.priority(w)<2);}
  else if(seedsActive)candidates=candidates.filter(w=>this.priority(w)<2);
  if(!candidates.length)return;
  if(!seedsPending){const rank=Math.min(...candidates.map(w=>this.priority(w)));candidates=candidates.filter(w=>this.priority(w)===rank);}
  const origins=[...new Set(q.map(w=>origin(w.url)))],last=origins.indexOf(this.lastOrigin),order=last<0?origins:[...origins.slice(last+1),...origins.slice(0,last+1)];
  // Within one priority class, confirmed and contextual references precede heuristic literal hints.
  for(const next of order){const item=candidates.filter(w=>origin(w.url)===next).sort((a,b)=>this.priority(a)-this.priority(b)||certaintyRank(a)-certaintyRank(b))[0];if(!item)continue;q.splice(q.indexOf(item),1);this.lastOrigin=next;this.active.set(item,now);if(this.dispatches.length<2000)this.dispatches.push({class:workClass(item,this.entries),url:item.url,at:now});return item;}
 }
 finish(item:WorkItem){this.active.delete(item);}
 view(){const now=Date.now(),waits=this.waiting(),result:Record<string,{pending:number;active:number;oldestQueuedMs:number;blockedReason?:string;deferred?:number}>={};for(const c of classes){const pending=this.queue().filter(w=>workClass(w,this.entries)===c);result[c]={pending:pending.length,active:[...this.active].filter(([w])=>workClass(w,this.entries)===c).length,oldestQueuedMs:pending.length?Math.max(...pending.map(w=>now-(w.enqueuedAt||now))):0,blockedReason:pending.length?this.blocked(pending[0])||(waits(pending[0])?'Website waits for a free website slot (websites at once)':undefined)||(pending[0].notBefore&&pending[0].notBefore>now?'Backoff prevents dispatch':undefined):undefined};}return {classes:result,dispatches:this.dispatches};}
}
