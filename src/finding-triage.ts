import {Worker} from 'node:worker_threads';
import type {Finding} from './types.js';
import {classifyFinding,type TriageInput} from './finding-triage-rules.js';
type TriageRow={id:string;version:number;finding:TriageInput};type TriageResult={id:string;version:number;triage:NonNullable<Finding['triage']>};
type TriageClient={apply(rows:TriageResult[]):void;failure():void;inFlight:boolean};
/** The finding-triage worker thread, one per process and shared by every scan's FindingTriage: each worker thread is a V8 isolate of its own (about 12 MiB), so a worker per scan
 * would grow the scan process with the number of scans running at once (mass mode). Each batch carries its client's id and its answer goes to that client alone; a client has at
 * most one batch in flight. A worker that fails or exits stops serving every client attached to it, with or without a batch in flight: each falls back to classifying in the
 * scan process and reports it, as a scan whose own worker stopped did before 2.8.0; a scan that starts later gets a new worker. The worker ends when the last client closes. */
class SharedTriageWorker {
  private worker?:Worker;private clients=new Map<number,TriageClient>();private sequence=0;
  get current(){return this.worker;}
  attach(client:TriageClient){const id=++this.sequence;this.clients.set(id,client);return id;}
  detach(id:number){this.clients.delete(id);if(!this.clients.size){const worker=this.worker;this.worker=undefined;void worker?.terminate();}}
  post(id:number,rows:TriageRow[]){
    const client=this.clients.get(id);if(!client)throw new Error('closed');
    if(!this.worker){const worker=new Worker(new URL('./finding-triage-worker.js',import.meta.url));this.worker=worker;
      worker.on('message',(m:{client:number;rows:TriageResult[]})=>{const c=this.clients.get(m.client);if(c){c.inFlight=false;c.apply(m.rows);}if(this.worker===worker&&![...this.clients.values()].some(x=>x.inFlight))worker.unref();});
      const lost=()=>{if(this.worker!==worker)return;this.worker=undefined;void worker.terminate();for(const c of [...this.clients.values()]){c.inFlight=false;c.failure();}};worker.on('error',lost);worker.on('exit',lost);}
    // Marked in flight only once the batch is posted: a batch that cannot be posted leaves the worker and the other clients as they were.
    this.worker.postMessage({client:id,rows});client.inFlight=true;this.worker.ref();
  }
}
const sharedWorker=new SharedTriageWorker();
export class FindingTriage {
  private client:number;private dirty=new Map<string,number>();private versions=new Map<string,number>();private busy=false;private scheduled=false;private waiters:(()=>void)[]=[];private failed=false;
  private removed=new Set<string>();private inFlight=new Set<string>();
  constructor(private findings:Map<string,Finding>,private remove:(id:string)=>void,private onFailure:()=>void){this.client=sharedWorker.attach({apply:rows=>this.apply(rows),failure:()=>this.failure(),inFlight:false});}
  /** The shared worker thread this triage posts to (undefined until a batch needs one); diagnostics and tests. */
  get worker(){return sharedWorker.current;}
  wasRemoved(id:string){return this.removed.has(id);}
  queue(id:string){const version=(this.versions.get(id)||0)+1;this.versions.set(id,version);this.dirty.set(id,version);if(!this.scheduled){this.scheduled=true;setImmediate(()=>{this.scheduled=false;this.pump();});}}
  private input(f:Finding):TriageInput{return {category:f.category,confidence:f.confidence,rule:f.rule,observation:f.observation,credentialSet:f.credentialSet,exposures:[...new Set(f.occurrences.map(o=>o.exposure||'public-response'))],qualifiers:f.qualifiers};}
  private apply(rows:TriageResult[]){for(const row of rows){const f=this.findings.get(row.id);if(!f||this.versions.get(row.id)!==row.version)continue;f.triage=row.triage;if(row.triage.category==='insignificant'&&(!['private-credential','suspicious'].includes(f.category)||f.qualifiers?.includes('known-public-example'))){this.removed.add(row.id);this.remove(row.id);}else this.removed.delete(row.id);}this.inFlight.clear();this.busy=false;this.pump();}
  private pump(){
    if(this.busy)return;
    const rows=[...this.dirty].slice(0,128).flatMap(([id,version])=>{this.dirty.delete(id);const f=this.findings.get(id);return f?[{id,version,finding:this.input(f)}]:[];});
    if(!rows.length){for(const done of this.waiters.splice(0))done();return;}
    this.busy=true;this.inFlight=new Set(rows.map(r=>r.id));
    if(this.failed){this.apply(rows.map(r=>({...r,triage:classifyFinding(r.finding)})));return;}
    try{sharedWorker.post(this.client,rows);}catch{this.failure();}
  }
  private failure(){if(this.failed)return;this.failed=true;sharedWorker.detach(this.client);this.busy=false;this.onFailure();for(const id of this.findings.keys())this.dirty.set(id,this.versions.get(id)||0);this.pump();}
  async flush(){if(!this.busy&&!this.dirty.size)return;await new Promise<void>(resolve=>{this.waiters.push(resolve);this.pump();});}
  view(){const categories:Record<string,number>={'direct-leak':0,'high-potential-leak':0,'low-potential-leak':0};for(const f of this.findings.values())if(f.triage)categories[f.triage.category]=(categories[f.triage.category]||0)+1;return {pending:new Set([...this.dirty.keys(),...this.inFlight]).size,removedInsignificant:this.removed.size,categories};}
  close(){this.dirty.clear();this.inFlight.clear();sharedWorker.detach(this.client);this.busy=false;for(const done of this.waiters.splice(0))done();}
}
