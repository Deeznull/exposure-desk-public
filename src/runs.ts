import {createHash} from 'node:crypto';
import {domainToUnicode} from 'node:url';
import {registrableDomain,effectiveScope} from './domain-scope.js';
import type {ScanView,RunLaunch,RunTrigger,ScanConfig,DomainScope,ProfileKind} from './types.js';
import {describeProfile} from './profiles.js';
/** Pre-2.5 builds materialized this constant name for every unnamed scan; lists label such runs by host instead of renaming stored records. */
export const LEGACY_DEFAULT_NAME='Authorized website';
export const TRIGGERS:RunTrigger[]=['manual','queue','schedule','retry','resume','rescan','demo','deployment'];
export const TRIGGER_LABELS:Record<RunTrigger,string>={manual:'Manual start',queue:'Queued',schedule:'Scheduled',retry:'Focused retry',resume:'Resumed checkpoint',rescan:'Affected-resource rescan',demo:'Synthetic demo',deployment:'Deployment trigger'};
export const RUN_ID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
/** Allow-listed failure: the dashboard returns its message, code and details; every other exception stays a generic 400. */
export class SafeError extends Error{constructor(message:string,readonly code:string,readonly status=400,readonly details:Record<string,string|number|boolean|null>={}){super(message);}}
const hostOf=(raw:string)=>{try{const h=new URL(raw).hostname;return domainToUnicode(h)||h;}catch{return '';}};
/** Unicode hostname of the first seed, plus " + N more" distinct seed hosts; at most 100 characters. No public suffix list is needed. */
export function defaultProjectName(urls:readonly string[]){const hosts=[...new Set(urls.map(hostOf).filter(Boolean))];if(!hosts.length)return LEGACY_DEFAULT_NAME;const suffix=hosts.length>1?` + ${hosts.length-1} more`:'';return hosts[0].length+suffix.length>100?hosts[0].slice(0,99-suffix.length)+'…'+suffix:hosts[0]+suffix;}
export function scopeFingerprint(config:Pick<ScanConfig,'urls'|'relatedOrigins'>){return JSON.stringify([[...new Set(config.urls||[])].sort(),[...new Set(config.relatedOrigins||[])].sort()]);}
export interface ScopeCounts {enteredSeeds:number;explicitOrigins:number;authorizedOrigins:number;automaticOrigins:number;contactedOrigins:number|null;domainGroups:number;domains:string[];insideNotScannedOrigins:number|null;thirdPartyOrigins:number|null;
  /** Government, military, intelligence and law-enforcement hosts refused without a request; 0 for records from builds without the rule. */
  protectedHosts:number;mode:DomainScope;recorded:{origins:boolean;scope:boolean}}
const originOf=(raw:string)=>{try{return new URL(raw).origin;}catch{return '';}};
const groupKey=(origin:string)=>{const d=registrableDomain(origin);if(d)return d;try{return new URL(origin).hostname;}catch{return origin;}};
/** Separate counts: entered seeds, domain groups, authorized origins, origins actually contacted (requests > 0) and exclusions.
 * Older records without `origins` or `scope` fall back to the config and report contacted/excluded as not recorded (null); nothing is invented. */
export function scopeCounts(v:Pick<ScanView,'config'>&Partial<Pick<ScanView,'origins'|'scope'|'resources'>>):ScopeCounts{
  const config=v.config||{} as ScanConfig,urls=Array.isArray(config.urls)?config.urls:[],related=Array.isArray(config.relatedOrigins)?config.relatedOrigins:[];
  const explicit=new Set([...urls.map(originOf),...related].filter(Boolean));const origins=Array.isArray(v.origins)?v.origins:undefined;
  const authorized=origins?[...new Set(origins.map(o=>o.origin))]:[...explicit];
  const groups=new Map<string,string>();for(const o of authorized){const key=groupKey(o);if(!groups.has(key))groups.set(key,domainToUnicode(key)||key);}
  let inside:number|null=null,third:number|null=null;
  if(v.scope&&typeof v.scope==='object'){const set=new Set<string>();for(const g of v.scope.groups||[])for(const n of g.notAdmitted||[])for(const e of n.examples||[])set.add(e);for(const e of v.scope.excluded?.examples||[])if(['exact-origin-mode','outside-host-subtree'].includes(e.reason))set.add(e.origin);inside=set.size;third=(v.scope.excluded?.thirdPartyOrigins??0)+(v.scope.excluded?.overflow??0);}
  else if(Array.isArray(v.resources)){const seedGroups=new Set(urls.map(u=>groupKey(originOf(u))));const a=new Set<string>(),b=new Set<string>();for(const r of v.resources)if(r.status==='blocked'&&r.reason==='scope'){const o=originOf(r.url);if(!o)continue;(seedGroups.has(groupKey(o))?a:b).add(o);}inside=a.size;third=b.size;}
  return {enteredSeeds:new Set(urls).size,explicitOrigins:explicit.size,authorizedOrigins:authorized.length,automaticOrigins:origins?origins.filter(o=>o.authorization?.type==='same-registrable-domain').length:0,contactedOrigins:origins?origins.filter(o=>(o.requests||0)>0).length:null,domainGroups:groups.size,domains:[...groups.values()].slice(0,20),insideNotScannedOrigins:inside,thirdPartyOrigins:third,protectedHosts:v.scope&&typeof v.scope==='object'&&v.scope.protected?v.scope.protected.hosts||0:0,mode:effectiveScope(config),recorded:{origins:!!origins,scope:!!v.scope}};
}
export interface RunSummary {id:string;shortId:string;projectId:string|null;projectName:string|null;name:string;label:string;primaryHost:string;state:string;phase:string|null;startedAt:string|null;endedAt:string|null;savedAt:string|null;
  trigger:RunTrigger|null;triggerSource:'recorded'|'inferred'|'unavailable';triggerLabel:string;previousRunId:string|null;relation:string|null;live:boolean;interrupted:boolean;build:string|null;
  scope:ScopeCounts;counts:{resources:number;findings:number;pending:number;deferred:number|null};profile:RunProfile}
/** Profile label for lists. Records from builds before 2.6 carry no profile and are labeled "Legacy preset" (with their stored preset name), never re-mapped. */
export interface RunProfile {kind:ProfileKind;label:string;recorded:boolean;limitedByProfile?:number}
/** Profile of a configuration (saved project or queued job): legacy presets keep their stored name. */
export function configProfile(config:Partial<ScanConfig>):RunProfile{const d=describeProfile(config);return {kind:d.kind,label:d.label,recorded:true};}
export function runProfile(v:Partial<Pick<ScanView,'profile'|'config'>>):RunProfile{if(v.profile&&typeof v.profile.label==='string')return {kind:v.profile.kind,label:v.profile.label,recorded:true,...(typeof v.profile.profileLimit?.count==='number'&&v.profile.profileLimit.count>0?{limitedByProfile:v.profile.profileLimit.count}:{})};const d=describeProfile(v.config||{});return d.kind==='profile'||d.kind==='custom-profile'?{kind:d.kind,label:d.label,recorded:false}:{kind:'legacy-preset',label:typeof v.config?.preset==='string'?'Legacy preset: '+v.config.preset:'Legacy preset',recorded:false};}
/** Summary of one run from a full view, a retained history record or a live scanner's brief. Older records without `launch` are labeled, never guessed beyond the documented inferences. */
export function runSummary(src:{view:Partial<ScanView>&Pick<ScanView,'id'|'config'>;projectId?:string;projectName?:string;savedAt?:string;live?:boolean;phase?:string}):RunSummary{
  const v=src.view,launch=v.launch as RunLaunch|undefined,urls=Array.isArray(v.config?.urls)?v.config.urls:[];
  let trigger:RunTrigger|null=null,triggerSource:RunSummary['triggerSource']='unavailable',previousRunId:string|null=null,relation:string|null=null;
  if(launch&&TRIGGERS.includes(launch.trigger)){trigger=launch.trigger;triggerSource='recorded';previousRunId=launch.previousRunId&&RUN_ID.test(launch.previousRunId)?launch.previousRunId:null;relation=launch.relation||null;}
  else if(v.retry?.sourceScan){trigger='retry';triggerSource='inferred';previousRunId=RUN_ID.test(v.retry.sourceScan)?v.retry.sourceScan:null;relation='retry';}
  else if(v.config?.developmentFixtureOrigin&&String(v.name||'').startsWith('DEMO ·')){trigger='demo';triggerSource='inferred';}
  const primaryHost=urls.length?hostOf(urls[0]):'',name=typeof v.name==='string'?v.name:'';
  const usable=(n?:string|null)=>!!n&&n.trim()!==''&&n!==LEGACY_DEFAULT_NAME;
  const label=usable(src.projectName)?src.projectName!:usable(name)?name:primaryHost||name||'Unnamed run';
  const c=v.counts;
  return {id:v.id,shortId:v.id.slice(0,8),projectId:src.projectId??null,projectName:src.projectName??null,name,label,primaryHost,state:String(v.state||'unknown'),phase:src.phase??null,startedAt:v.startedAt??null,endedAt:v.endedAt??null,savedAt:src.savedAt??null,
    trigger,triggerSource,triggerLabel:trigger?TRIGGER_LABELS[trigger]+(triggerSource==='inferred'?' (inferred)':''):'Trigger not recorded',previousRunId,relation,live:!!src.live,interrupted:v.stopReason==='application-interrupted',build:v.build?.version??null,
    scope:scopeCounts(v as ScanView),counts:{resources:c?.resources??0,findings:c?.findings??(Array.isArray(v.findings)?v.findings.length:0),pending:c?.pending??0,deferred:typeof c?.deferred==='number'?c.deferred:null},profile:runProfile(v)};
}
export const runTime=(r:Pick<RunSummary,'startedAt'|'savedAt'>)=>{const t=Date.parse(r.startedAt||r.savedAt||'');return Number.isFinite(t)?t:0;};
/** One-line scope count text shared by the CLI and reports. */
export function scopeCountLine(s:ScopeCounts){const n=(k:number,one:string,many=one+'s')=>`${k} ${k===1?one:many}`;return [n(s.enteredSeeds,'entered seed'),n(s.domainGroups,'domain group')+(s.domains.length?` (${s.domains.join(', ')})`:''),n(s.authorizedOrigins,'authorized origin'),s.contactedOrigins===null?'contacted: not recorded':`${s.contactedOrigins} contacted`,...(s.automaticOrigins?[n(s.automaticOrigins,'automatically admitted origin')]:[]),...(s.insideNotScannedOrigins?[`${n(s.insideNotScannedOrigins,'same-domain origin')} not scanned`]:[]),...(s.thirdPartyOrigins?[`${n(s.thirdPartyOrigins,'third-party origin')} excluded`]:[]),...(s.protectedHosts?[`${n(s.protectedHosts,'government/military/law-enforcement host')} refused (never scanned)`]:[]),s.mode].join(' · ');}
const stable=(v:unknown):unknown=>Array.isArray(v)?v.map(stable):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,stable((v as any)[k])])):v;
/** Idempotent request identifiers: a replay of the same identifier and body returns the first result (even while it is still in flight); a different body is refused.
 * Entries hold a body digest and the result only, live in memory for 10 minutes, and are capped at 500. Identifiers are never persisted or sent anywhere. */
export class RequestLedger {
  private entries=new Map<string,{at:number;fingerprint:string;result:Promise<unknown>}>();
  constructor(readonly ttlMs=600000,readonly max=500,readonly now:()=>number=()=>Date.now()){}
  get size(){return this.entries.size;}
  async once<T>(scope:string,requestId:unknown,body:unknown,fn:()=>Promise<T>):Promise<{value:T;duplicate:boolean}>{
    if(requestId===undefined||requestId===null||requestId==='')return {value:await fn(),duplicate:false};
    if(typeof requestId!=='string'||!/^[A-Za-z0-9_-]{8,80}$/.test(requestId))throw new SafeError('Invalid request identifier','request-id-invalid',400);
    const now=this.now();for(const [k,e]of this.entries)if(now-e.at>this.ttlMs)this.entries.delete(k);
    const key=scope+'\0'+requestId,fingerprint=createHash('sha256').update(JSON.stringify(stable(body&&typeof body==='object'?{...body as object,requestId:undefined}:body))).digest('hex');
    const prior=this.entries.get(key);if(prior){if(prior.fingerprint!==fingerprint)throw new SafeError('This request identifier was already used for a different request','request-id-reused',409);return {value:await prior.result as T,duplicate:true};}
    const result=fn();this.entries.set(key,{at:now,fingerprint,result});while(this.entries.size>this.max)this.entries.delete(this.entries.keys().next().value!);
    try{return {value:await result,duplicate:false};}catch(e){if(this.entries.get(key)?.result===result)this.entries.delete(key);throw e;}
  }
}
