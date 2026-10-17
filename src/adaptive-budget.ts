import type {ScanConfig,WorkItem,Resource} from './types.js';
import {scaleMs} from './machine-speed.js';
export interface BudgetSnapshot {origin:string;mode:string;effective:{resources:number;pages:number;bytes:number;maps:number;analysisMs:number};maximum:BudgetSnapshot['effective'];signals:{scripts:number;bundleBytes:number;maps:number;importantPending:number;responseMs:number;pages?:number;probes?:number};reasons:string[];importantUninspected:{url:string;reason:string}[];importantUnresolved?:number}
/** Soft allocations always stay inside immutable operator caps. Analysis time (the allocation and its maximum) is configured for a fast reference computer and scaled by the scan's
 * analysis time factor (machine-speed.ts; 1 on a fast computer); every other dimension is used as configured. */
const factorReason=(factor:number)=>`Analysis time ×${factor} for this computer's analysis speed (allocation and maximum); other allocations unchanged.`;
export class WebsiteBudget {
  readonly maximum:BudgetSnapshot['effective'];effective:BudgetSnapshot['effective'];
  signals:BudgetSnapshot['signals']={scripts:0,bundleBytes:0,maps:0,importantPending:0,responseMs:0};
  reasons:string[]=[];private discovered=new Set<string>();private responses=new Set<Resource>();private bundles=new Set<string>();
  constructor(readonly origin:string,readonly config:ScanConfig,public timeFactor=1){
    this.origin=new URL(origin).origin;if(config.coverage!==undefined)Object.assign(this.signals,{pages:0,probes:0});
    this.maximum={resources:config.originMaxResources!,pages:config.originMaxPages!,bytes:config.originMaxTotalBytes!,maps:config.originMaxMaps!,analysisMs:scaleMs(config.originAnalysisMs!,timeFactor)};
    this.effective=config.sizingMode==='adaptive'?{resources:Math.min(this.maximum.resources,32),pages:Math.min(this.maximum.pages,8),bytes:Math.min(this.maximum.bytes,8*1024*1024),maps:Math.min(this.maximum.maps,4),analysisMs:Math.min(this.maximum.analysisMs,scaleMs(config.semanticSliceMs!,timeFactor))}:{...this.maximum};
    this.reasons=[config.sizingMode==='adaptive'?'Initial bounded allocation; discovered demand can grow it within configured maxima.':'Fixed per-website maximum allocation.'];
    if(timeFactor!==1)this.reasons.push(factorReason(timeFactor));
  }
  /** The seed websites' budgets exist before the scan has its factor (measured off the critical path): rescale the analysis time as if the budget had been created with it
   * (signals already seen apply at the new factor). It is set when the scan starts, before anything is charged. */
  setTimeFactor(factor:number){
    if(factor===this.timeFactor)return;this.timeFactor=factor;this.maximum.analysisMs=scaleMs(this.config.originAnalysisMs!,factor);
    this.effective.analysisMs=this.config.sizingMode==='adaptive'?Math.min(this.maximum.analysisMs,scaleMs(this.config.semanticSliceMs!,factor)):this.maximum.analysisMs;
    this.reasons=this.reasons.filter(r=>!r.startsWith('Analysis time ×'));if(factor!==1)this.reasons.push(factorReason(factor));this.adapt();
  }
  /** Profile scans (Deep audit) also count discovered pages and deployment probes, so an adaptive allocation never under-crawls a page-heavy site; legacy adaptive settings keep the 2.5 signals. */
  discover(item:WorkItem){if(this.discovered.has(item.url))return;this.discovered.add(item.url);if(/script|module|source|browser|asset/.test(item.kind))this.signals.scripts++;if(/map/.test(item.kind))this.signals.maps++;if(this.signals.pages!==undefined&&item.kind==='page')this.signals.pages++;if(this.signals.probes!==undefined&&['deep','baseline'].includes(item.kind))this.signals.probes!++;this.adapt();}
  /** Bundle bytes are counted once per URL and size, so static and browser copies of one bundle are not double counted. */
  response(resource:Resource){if(this.responses.has(resource))return;this.responses.add(resource);if(resource.resourceType==='javascript'||/script|module|source/.test(resource.kind)){const key=resource.url+'|'+resource.bytes;if(!this.bundles.has(key)){this.bundles.add(key);this.signals.bundleBytes+=resource.bytes;}}if(resource.timings?.headersMs!==undefined)this.signals.responseMs=this.signals.responseMs?Math.round((this.signals.responseMs*3+resource.timings.headersMs)/4):resource.timings.headersMs;this.adapt();}
  pending(important:number){this.signals.importantPending=important;this.adapt();}
  private adapt(){if(this.config.sizingMode!=='adaptive')return;const s=this.signals,desired={resources:32+s.scripts*3+s.maps*2+s.importantPending+(s.pages||0)+(s.probes||0),pages:8+Math.ceil(s.scripts/6)+(s.pages||0),bytes:8*1024*1024+s.bundleBytes*2+s.maps*1024*1024,maps:Math.max(4,s.maps),analysisMs:scaleMs(this.config.semanticSliceMs!+Math.ceil(s.bundleBytes/(256*1024))*500+s.scripts*120+s.maps*250,this.timeFactor)};
    const changes:string[]=[];for(const name of Object.keys(this.effective) as (keyof typeof desired)[]){const next=Math.min(this.maximum[name],Math.max(this.effective[name],desired[name]));if(next!==this.effective[name]){this.effective[name]=next;changes.push(name);}}
    if(changes.length){const why=`Raised ${changes.join(', ')} for ${s.scripts} script candidates, ${s.bundleBytes} bundle bytes, ${s.maps} map candidates and ${s.importantPending} important queued resources.`;if(this.reasons.length<20)this.reasons.push(why);else this.reasons[19]=why;}
    if(s.responseMs>1000&&!this.reasons.some(r=>r.startsWith('Slow responses'))){this.reasons.push('Slow responses reserve the remaining deadline for important assets; request rate, concurrency and duration stay fixed.');}
  }
  snapshot(uninspected:WorkItem[]=[],importantUnresolved?:number):BudgetSnapshot{return {origin:this.origin,mode:this.config.sizingMode!,effective:{...this.effective},maximum:{...this.maximum},signals:{...this.signals},reasons:[...this.reasons],importantUninspected:uninspected.filter(w=>new URL(w.url).origin===this.origin&&/script|module|map|config|source|browser/.test(w.kind)).slice(0,100).map(w=>({url:w.url,reason:w.deferredReason||'pending'})),...(importantUnresolved!==undefined?{importantUnresolved}:{})};}
}
