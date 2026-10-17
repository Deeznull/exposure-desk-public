import type {ScanView,WorkItem} from './types.js';
import {normalizeUrl} from './config.js';
import {workClass} from './resource-types.js';
import {ScopePolicy} from './domain-scope.js';
import {isBareExtensionPath} from './discovery.js';
import {isProtectedHost} from './protected-hosts.js';
/** Retry origins reproduce the scope that actually ran: the stored config (legacy boolean or `domainScope`) decides, never a new default. */
function retryOrigins(view:ScanView){const policy=new ScopePolicy(view.config);return new Set([...view.config.urls.map(u=>new URL(u).origin),...view.config.relatedOrigins,...(view.origins||[]).filter(o=>o.authorization?.type==='same-registrable-domain'&&policy.classify(o.origin).class==='in-domain').map(o=>o.origin)]);}
export interface RetryPlan {sourceScan:string;selected:WorkItem[];excluded:string[];browserUrls:string[];omitted:number;note:string}
const unfinished=(a?:{status:string})=>!!a&&['incomplete','failed','deferred'].includes(a.status);
export function focusedRetry(view:ScanView,includeOptional=false):RetryPlan{
 const origins=retryOrigins(view);
 const safe=(raw:string)=>{try{const u=new URL(raw);return !isProtectedHost(raw)&&!raw.includes('[redacted')&&!u.username&&!u.password&&origins.has(u.origin)&&normalizeUrl(raw)===raw&&!/secret|password|api[_-]?key|access[_-]?token|signature|(?:^|&)sig=/i.test(u.search);}catch{return false;}};
 // Deferred and partial analyzers are retry candidates; legacy bare-extension hints are never re-requested. Protected hosts and the "Limited by profile" boundary are not gaps to retry.
 const candidates:WorkItem[]=[...(view.uninspected||[]).filter(w=>w.deferredReason!=='protected-host'&&w.deferredReason!=='profile-limit'),...(view.resources||[]).filter(r=>r.status!=='blocked'&&(r.status==='failed'||r.analysis==='pending'||r.analysis==='deferred'||r.partial||!!r.code&&r.code>=400||Object.values(r.analyzers||{}).some(unfinished))).map(r=>({url:r.url,depth:0,chain:[view.id,'focused retry of incomplete resource'],kind:r.kind==='browser'?r.provenance?.resourceType==='document'?'page':r.provenance?.resourceType==='script'?'script':'asset':r.kind}))].filter(w=>!(['asset-hint','asset'].includes(w.kind)&&isBareExtensionPath(w.url)));
 const rank=(w:WorkItem)=>({entryPages:0,javascript:1,configuration:2,sourceMaps:3,discovery:5,optionalPages:6,other:7,baseline:8,deployment:9,lowValue:10}[workClass(w,view.config.urls)]);
 const eligible=[...new Map(candidates.filter(w=>safe(w.url)&&(includeOptional||rank(w)<=3)).sort((a,b)=>rank(a)-rank(b)).map(w=>[w.url,w])).values()];
 const selected=eligible.slice(0,Math.min(50,view.config.maxResources)),chosen=new Set(selected.map(w=>w.url));
 const excluded=[...new Set((view.resources||[]).filter(r=>r.code&&r.code>=200&&r.code<300&&r.analysis==='analyzed'&&!r.partial&&!chosen.has(r.url)&&!Object.values(r.analyzers||{}).some(unfinished)&&safe(r.url)).map(r=>r.url))].slice(0,2000);
 const browserUrls=view.config.browser&&!view.browserStatus?.runtimePages?view.config.urls.filter(safe).slice(0,view.config.browserPages):[];
 return {sourceScan:view.id,selected,excluded,browserUrls,omitted:eligible.length-selected.length,note:'Fresh budgets and current policy apply to selected exact URLs. Successful static URLs are excluded. Browser retry requires a fresh document and its dependencies; these guarded requests may repeat. This focused result is incomplete for whole-project comparison.'};
}
export function affectedResourceUrls(view:ScanView,finding:import('./types.js').Finding){const origins=retryOrigins(view),safe=(raw:string)=>{try{const u=new URL(raw);return origins.has(u.origin)&&!raw.includes('[redacted')&&!u.username&&!u.password&&!/secret|password|api[_-]?key|access[_-]?token|signature|(?:^|&)sig=/i.test(u.search);}catch{return false;}};return [...new Set(finding.occurrences.flatMap(o=>[o.url,...o.chain.filter(c=>/^https?:/.test(c))]).filter(safe).map(u=>new URL(u).href))].slice(0,50);}
/** Resume frontier items keep their original kind when it is a known static kind; legacy bare-extension hints are dropped. */
export function resumeFrontier(frontier:unknown[],limit:number):{url:string;kind:string}[]{const kinds=new Set(['asset','asset-hint','script','module','page','config','manifest','map','map-guess','source','sitemap','robots','framework-data','framework-manifest','css','stale-asset','websocket-origin']);const out:{url:string;kind:string}[]=[];for(const w of frontier.slice(0,limit)){if(!w||typeof w!=='object'||typeof(w as any).url!=='string')continue;const kind=typeof(w as any).kind==='string'&&kinds.has((w as any).kind)?(w as any).kind:'asset';if(['asset','asset-hint'].includes(kind)&&isBareExtensionPath((w as any).url))continue;out.push({url:(w as any).url,kind});}return out;}
