import type {Resource,ScanConfig,ScanView,WorkItem,Gap} from './types.js';
import {resourceType} from './resource-types.js';
export type CoverageState='inspected'|'reused'|'pending'|'unavailable'|'failed'|'unsupported'|'deferred'|'partial';
export interface CoverageGroup {discovered:number;downloaded:number;analyzed:number;successful:number;errorResponses:number;blocked:number;skipped:number;uninspected:number;currentStates:Record<CoverageState,number>;reasons:Record<string,number>}
export interface OriginCoverage {assessment:'configured-checks-completed'|'limited'|'insufficient';groups:Record<string,CoverageGroup>;entryPoints:{url:string;successful:boolean;analyzed:boolean}[];highValueLimited:boolean;optionalPagesLimited:boolean}
export interface CoverageRow {url:string;category:string;state:CoverageState;reason?:string;chain:string[]}
export interface ScanCoverage extends OriginCoverage {summary:string;discoveryNote:string;origins:Record<string,OriginCoverage>;inventory:CoverageRow[];deploymentChecks?:{planned:number;attempted:number;remaining:number};requestComparison?:{url:string;headerProfile?:string;staticStatus?:number;browserStatus?:number;staticHeaders:string[];browserHeaders:string[];conclusion:string}[]}
interface CoverageOptions {additionalEntryUrls?:string[];authorizedOrigins?:string[];inventory?:Iterable<WorkItem>;deferred?:Iterable<WorkItem>;gaps?:Gap[];runtimePagesByOrigin?:ReadonlyMap<string,number>;stopReason?:string;inDomain?:(url:string)=>boolean;live?:ReadonlySet<string>}
const states=():Record<CoverageState,number>=>({inspected:0,reused:0,pending:0,unavailable:0,failed:0,unsupported:0,deferred:0,partial:0});
const empty=():CoverageGroup=>({discovered:0,downloaded:0,analyzed:0,successful:0,errorResponses:0,blocked:0,skipped:0,uninspected:0,currentStates:states(),reasons:{}});
const origin=(url:string)=>{try{return new URL(url).origin;}catch{return '';}};
const high=new Set(['javascript','jsonConfig','sourceMaps','runtimeCaptures','browserRuntime']);
const UNRESOLVED:CoverageState[]=['pending','deferred','partial','failed'];
/** One helper for every "important unresolved" count: high-value categories and entry documents whose current state is pending, deferred, partial or failed. */
export function importantUnresolved(rows:CoverageRow[],only?:string){const byOrigin=new Map<string,number>();let total=0;for(const r of rows){if(!(high.has(r.category)||r.category==='entryDocuments')||!UNRESOLVED.includes(r.state))continue;const o=origin(r.url);if(only&&o!==only)continue;total++;byOrigin.set(o,(byOrigin.get(o)||0)+1);}return {total,byOrigin};}
export function coverage(config:ScanConfig,resources:Resource[],pending:WorkItem[],state:ScanView['state'],runtimePages:number,options:CoverageOptions={}):ScanCoverage{
 const authorized=new Set(options.authorizedOrigins||[...config.urls.map(origin),...config.relatedOrigins]),terminal=!['running','ready'].includes(state);
 // Variants skipped only by the traffic option's stated boundary ("Limited by profile") are outside the examined set, like Quick's not-examined categories.
 const known=new Map<string,Resource|WorkItem>();for(const r of [...(options.inventory||[]),...pending,...resources])if((r as WorkItem).deferredReason!=='profile-limit')known.set(r.url,r);
 const deferred=new Map([...(options.deferred||[]),...pending.filter(w=>w.deferredReason)].map(w=>[w.url,w.deferredReason||'deferred']));
 const entries=new Set([...config.urls,...(options.additionalEntryUrls||[])]),category=(r:Resource|WorkItem)=>!authorized.has(origin(r.url))?(options.inDomain?.(r.url)?'domainExcluded':'externalDependencies'):entries.has(r.url)?'entryDocuments':({page:'applicationPages',javascript:'javascript','source-map':'sourceMaps',sitemap:'sitemaps',configuration:'jsonConfig',baseline:'baselineRequests',deployment:'deploymentChecks',image:'images','runtime-capture':'runtimeCaptures',other:'other'}[resourceType(r)]);
 const records=new Map<string,Resource[]>();for(const r of resources){const list=records.get(r.url)||[];list.push(r);records.set(r.url,list);}
 const certaintyOf=(url:string)=>{const k=known.get(url) as (Resource|WorkItem)|undefined;return (k as WorkItem)?.certainty||(k as Resource)?.certainty||records.get(url)?.find(r=>r.certainty)?.certainty;};
 const resultFor=(url:string,kind:string):{state:CoverageState;reason?:string}=>{
   const attempts=records.get(url)||[],last=attempts.at(-1);
   const confirmedFallback=(r:Resource)=>!!r.fallback&&['script','map','manifest'].includes(r.fallback.expected)&&certaintyOf(url)!=='heuristic'&&r.kind!=='asset-hint';
   const complete=(r:Resource)=>r.analysis==='analyzed'&&!r.partial&&!confirmedFallback(r)&&(r.kind==='runtime-capture'||r.code!==undefined&&r.code>=200&&r.code<300)&&
     (kind!=='sourceMaps'||r.sourceMap?.valid===true&&r.analyzers?.sourceMap?.status==='inspected');
   // A successful guarded recovery supersedes failed attempts; attempt evidence stays in resources.
   const recovered=[...attempts].reverse().find(complete);
   if(recovered){const unfinished=Object.entries(recovered.analyzers||{}).find(([name,a])=>name!=='debugger'&&(name!=='semantic'||config.semanticAnalysis)&&a&&a.status!=='inspected');
     if(unfinished){const a=unfinished[1]!;return {state:a.status==='unsupported'?'unsupported':a.status==='failed'?'failed':a.status==='incomplete'?'partial':a.status==='deferred'?'deferred':terminal?'deferred':'pending',reason:unfinished[0]+': '+(a.reason||a.status)};}
     return {state:recovered.analyzers?.offlineEngine?.reused?'reused':'inspected',reason:recovered.analyzers?.offlineEngine?.reused?'Exact text and detector configuration matched successful in-memory inspection; other configured analyzers completed':undefined};
   }
   if(state==='running'&&(options.live?.has(url)||pending.some(w=>w.url===url&&!w.deferredReason))&&!deferred.has(url))return {state:'pending',reason:'Attempt or retry is in progress'};
   const fallback=[...attempts].reverse().find(r=>confirmedFallback(r));if(fallback)return {state:'unavailable',reason:`expected ${fallback.fallback!.expected}; HTML fallback received (${fallback.fallback!.type})`};
   if(last?.code&&last.code>=400)return {state:'unavailable',reason:'HTTP '+last.code};
   if(last?.analysis==='deferred')return {state:'deferred',reason:last.reason||'analysis-deferred'};
   if(last?.status==='failed'||last?.analysis==='failed')return {state:'failed',reason:last.reason||'analysis-failure'};
   if(deferred.has(url))return {state:'deferred',reason:deferred.get(url)==='protected-host'?'Redirects to a protected government, military, intelligence or law-enforcement host; never requested (built-in rule)':deferred.get(url)};
   if(last?.partial)return {state:'unavailable',reason:'Partial body; complete document unavailable'};
   if(last?.code===304)return {state:'unavailable',reason:'304 without trusted matching cached body'};
   if(last?.status==='blocked'||last?.analysis==='skipped'||last?.status==='skipped')return {state:'unsupported',reason:last.reason||'Body intentionally not inspected'};
   if(kind==='sourceMaps'&&last&&last.analysis==='analyzed')return {state:'unsupported',reason:last.sourceMap?.reason||'Map unavailable or not validated'};
   if(kind==='images')return {state:'unsupported',reason:'Image body intentionally skipped after local URL inspection'};
   if(last?.status==='redirect'&&resources.some(r=>r.chain.includes(url)&&complete(r)))return {state:'inspected',reason:'Redirect response and guarded destination inspected'};
   if(terminal)return {state:'deferred',reason:state==='cancelled'?'Project cancelled before inspection':`Run ended before inspection (${options.stopReason||state})`};
   return {state:'pending',reason:last?'Configured analysis unfinished':'Discovered; no complete inspection'};
 };
 const inventory:CoverageRow[]=[...known].map(([url,r])=>{const base=category(r);return {url,category:base,...resultFor(url,base),chain:r.chain};});
 const build=(o?:string):OriginCoverage=>{
   // An informational refusal (2.9.1: a URL refused only as invalid-url) is listed but is not unresolved coverage.
   const informational=new Map<CoverageGroup,number>();
   const groups:Record<string,CoverageGroup>={};for(const k of ['entryDocuments','applicationPages','javascript','jsonConfig','sourceMaps','sitemaps','baselineRequests','deploymentChecks','images','runtimeCaptures','other','domainExcluded','externalDependencies'])groups[k]=empty();
   for(const row of inventory.filter(r=>!o||origin(r.url)===o)){
     const g=groups[row.category]||=empty(),attempts=records.get(row.url)||[];g.discovered++;
     if(row.state==='unsupported'&&attempts.length&&attempts.every(r=>r.status==='blocked'&&r.reason==='invalid-url'))informational.set(g,(informational.get(g)||0)+1);g.currentStates[row.state]++;if(row.reason)g.reasons[row.reason]=(g.reasons[row.reason]||0)+1;
     // Compatibility evidence counters are historical and may overlap. CurrentStates never overlap.
     if(attempts.some(r=>r.code!==undefined))g.downloaded++;if(attempts.some(r=>r.analysis==='analyzed'))g.analyzed++;
     if(attempts.some(r=>r.analysis==='analyzed'&&!!r.code&&r.code>=200&&r.code<300&&!r.partial&&(row.category!=='sourceMaps'||r.sourceMap?.valid===true&&r.analyzers?.sourceMap?.status==='inspected')))g.successful++;
     if(attempts.some(r=>!!r.code&&r.code>=400))g.errorResponses++;if(attempts.some(r=>r.status==='blocked'))g.blocked++;if(attempts.some(r=>r.status==='skipped'||r.analysis==='skipped'))g.skipped++;
     // Legacy uninspected is missing body/schema coverage; new states additionally report analyzer gaps.
     if(!attempts.some(r=>r.analysis==='analyzed'&&!!r.code&&r.code>=200&&r.code<300&&!r.partial&&(row.category!=='sourceMaps'||r.sourceMap?.valid===true&&r.analyzers?.sourceMap?.status==='inspected'))&&!['inspected','reused'].includes(row.state))g.uninspected++;
   }
   const seeds=[...entries].filter(u=>!o||origin(u)===o),entryPoints=seeds.map(url=>{const found=resources.filter(r=>r.url===url||r.chain.includes(url)&&r.chain.includes('HTTP redirect'));return {url,successful:found.some(r=>r.analysis==='analyzed'&&!!r.code&&r.code>=200&&r.code<300&&!r.partial),analyzed:found.some(r=>r.analysis==='analyzed')};});
   const planned=config.browser?new Set([...seeds,...(config.browserNavigationUrls||[]).filter(u=>!o||origin(u)===o)]).size:0,done=o?options.runtimePagesByOrigin?.get(o)||0:runtimePages;
   const runtime=groups.browserRuntime=empty();runtime.discovered=Math.max(planned,done);runtime.downloaded=runtime.analyzed=runtime.successful=done;runtime.currentStates.inspected=done;runtime.currentStates[terminal?'deferred':'pending']=Math.max(0,planned-done);runtime.uninspected=Math.max(0,planned-done);
   if(runtime.uninspected)runtime.reasons['Configured browser navigation unfinished']=runtime.uninspected;
   const unresolved=(g:CoverageGroup)=>g.discovered-(informational.get(g)||0)>g.currentStates.inspected+g.currentStates.reused;
   const highValueLimited=Object.entries(groups).some(([k,g])=>high.has(k)&&unresolved(g));
   const optionalPagesLimited=unresolved(groups.applicationPages);
   const gaps=(options.gaps||[]).some(g=>g.incomplete&&(!o||g.origin===o||g.url&&origin(g.url)===o||!g.origin&&!g.url));
   const limited=highValueLimited||optionalPagesLimited||unresolved(groups.entryDocuments)||gaps;
   const insufficient=entryPoints.length>0&&entryPoints.every(e=>!e.successful)&&!done;
   return {assessment:insufficient?'insufficient':state==='running'||state==='ready'||state==='cancelled'||limited?'limited':'configured-checks-completed',groups,entryPoints,highValueLimited,optionalPagesLimited};
 };
 const overall=build(),origins=Object.fromEntries([...authorized].map(o=>[o,build(o)]));
 const planned=config.deep?new Set(config.urls.map(origin)).size*config.deepPaths.length:0,attempted=new Set(resources.filter(r=>r.kind==='deep'&&(r.code!==undefined||r.status==='failed')).map(r=>r.url)).size;
 return {...overall,origins,inventory,summary:(overall.assessment==='configured-checks-completed'?'Configured checks finished for the discovered inventory within scope and limits.':'Coverage is limited or in progress; inspect each origin and resource category.')+' No findings means no supported exposure was detected in inspected coverage.',discoveryNote:'Discovered is the known unique URL inventory. Each URL has exactly one current state and category; inspected plus reused counts configured inspection coverage. Pending means live work only; deferred and partial are terminal states of unfinished work. Legacy downloaded/analyzed/error counters are historical evidence and can overlap. Browser runtime is a separate navigation count. Undiscovered resources cannot be counted; inventory omissions are reported.',deploymentChecks:{planned,attempted,remaining:Math.max(0,planned-attempted)},requestComparison:config.urls.map(url=>{const a=resources.find(r=>r.url===url&&r.kind==='page'),b=resources.find(r=>r.url===url&&r.kind==='browser'&&r.provenance?.resourceType==='document');return {url,headerProfile:'v2',staticStatus:a?.code,browserStatus:b?.code,staticHeaders:a?.requestHeaderNames||[],browserHeaders:b?.requestHeaderNames||[],conclusion:!b?'No guarded browser document response recorded.':b.servedFrom==='run-cache'?'Browser copy served from this run’s response cache (the identical static download); no browser request was sent, so no browser headers or separate status exist.':a?.code===b.code?'Recorded statuses match; causes not inferred.':'Recorded statuses differ; causes not inferred.'};})};
}
