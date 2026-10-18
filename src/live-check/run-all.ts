import type { LiveCheckResult } from '../types.js';
import { checkOneKey, LiveCheckRefused, type CheckEnv } from './egress.js';
/** Paced, cancellable "check all" driver. Strictly one key at a time, one provider paced after another; the first rate-limit or refusal (HTTP 429/403) from a provider halts every remaining key for that provider. Gated by the program file at the call site — this module only runs the list it is given. */
export interface LiveCheckItem { correlation:string; rule:string; provider:string; key:string; companions?:{accessKeyId?:string;sessionToken?:string}; }
export interface LiveCheckAllProgress { total:number; done:number; running:boolean; cancelled:boolean; current?:string; haltedProviders:string[]; results:Record<string,LiveCheckResult>; skipped:string[]; }
export interface RunAllOptions { env?:CheckEnv; perProviderPauseMs?:number; signal?:AbortSignal; onProgress?:(p:LiveCheckAllProgress)=>void; }
const sleep=(ms:number,signal?:AbortSignal)=>new Promise<void>(r=>{if(ms<=0||signal?.aborted)return r();const t=setTimeout(()=>{signal?.removeEventListener('abort',stop);r();},ms);const stop=()=>{clearTimeout(t);r();};signal?.addEventListener('abort',stop,{once:true});});
export async function runLiveCheckAll(items:LiveCheckItem[],opts:RunAllOptions={}):Promise<LiveCheckAllProgress>{
  const pause=opts.perProviderPauseMs??1000,signal=opts.signal;
  const progress:LiveCheckAllProgress={total:items.length,done:0,running:true,cancelled:false,haltedProviders:[],results:{},skipped:[]};
  const halted=new Set<string>(),lastAt=new Map<string,number>();
  const emit=()=>opts.onProgress?.({...progress,haltedProviders:[...halted],results:{...progress.results},skipped:[...progress.skipped]});
  emit();
  for(const item of items){
    if(signal?.aborted){progress.cancelled=true;break;}
    const provider=item.provider;
    if(halted.has(provider)){progress.skipped.push(item.correlation);progress.done++;emit();continue;}
    const wait=lastAt.has(provider)?Math.max(0,pause-(Date.now()-lastAt.get(provider)!)):0;
    if(wait>0){await sleep(wait,signal);if(signal?.aborted){progress.cancelled=true;break;}}
    progress.current=item.correlation;emit();
    let result:LiveCheckResult;
    try{result=await checkOneKey({rule:item.rule,key:item.key,provider:item.provider,companions:item.companions},opts.env);}
    catch(e){ // a hard refusal (protected host etc.) halts this provider and is recorded as unknown
      if(e instanceof LiveCheckRefused){halted.add(provider);result={result:'unknown',checkedAt:new Date().toISOString(),provider,reason:'host-not-allowlisted'};}
      else throw e;
    }
    lastAt.set(provider,Date.now());
    progress.results[item.correlation]=result;progress.done++;progress.current=undefined;
    if(result.reason==='rate-limited'||((result.status===429||result.status===403)&&result.result!=='revoked'))halted.add(provider); // first rate-limit/refusal stops the provider; a 403 that is a revoked verdict (e.g. AWS STS) is a dead key, not us being blocked
    emit();
  }
  progress.running=false;progress.haltedProviders=[...halted];emit();
  return {...progress,haltedProviders:[...halted]};
}
