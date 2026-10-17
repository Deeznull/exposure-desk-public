import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import { lookup } from 'node:dns/promises';
import {canonicalIp,metadataAddress,publicAddress,certificateNames} from './net/address-guard.js';
export {canonicalIp,publicAddress,certificateNames} from './net/address-guard.js';
import { normalizeUrl } from './config.js';
import type { ScanConfig, Gap, Resource, OriginAuthorization, GapCause, AbortReason } from './types.js';
import {ScopePolicy,websiteHost} from './domain-scope.js';
import {protectedHost} from './protected-hosts.js';
import type { Evidence } from './evidence.js';
import { createGunzip, createBrotliDecompress, createInflate } from 'node:zlib';
import { decodeText, contentDecision } from './decoding.js';
import { httpDisposition } from './response-status.js';
import {OriginControl,TurnClock,abortReason,type OriginState,type WorkUnit} from './origin-control.js';
import {AnalysisInterrupted,AnalysisFailure} from './detectors.js';
import {performance} from 'node:perf_hooks';
import {createHash} from 'node:crypto';
import {BUILD} from './build-info.js';
import {programLimiter,type ProgramLimiter} from './program/limiter.js';
import type {BlockMonitor,BlockObservation,BlockDecision} from './mass/block.js';
import {programScope} from './program/settings.js';
import type {ProgramConfig} from './types.js';
/** Outbound header profile v2 (2.5): one policy for static and browser-routed requests, applied after preflight so credential screening still sees every header the page supplied.
 * Static requests carry an honest product token (no build, OS or user details); browser requests keep Chromium's real User-Agent. Nothing browser-like is fabricated. */
export const HEADER_PROFILE='v2';
export const PRODUCT_USER_AGENT=`Mozilla/5.0 (compatible; ExposureDesk/${BUILD.version.split(/[.-]/).slice(0,2).join('.')})`;
export function acceptLanguage(locale='en-US'){const base=locale.split('-')[0];return base&&base!==locale?`${locale},${base};q=0.9`:locale;}
export function outboundHeaders(target:URL,kind:string,supplied:Record<string,string>,profile:{staticUserAgent?:'product'|'none';browserLocale?:string;program?:ProgramConfig},authorized:(origin:string)=>boolean):Record<string,string>{
  const out:Record<string,string>={accept:'text/html,application/json,text/plain,*/*;q=0.5','accept-encoding':'gzip, br, deflate',host:target.host};
  if(kind==='browser'){for(const [k,v]of Object.entries(supplied)){const name=k.toLowerCase();if(typeof v!=='string')continue;
    // Site-created cookies (same-origin only, enforced by the browser route), content negotiation and genuine fetch metadata pass; Origin and Referer only name authorized initiators, and Referer is cut to strict-origin.
    if(['accept','content-type','cookie','user-agent','sec-fetch-site','sec-fetch-mode','sec-fetch-dest','sec-fetch-user'].includes(name))out[name]=v;
    else if(name==='origin'){try{const o=new URL(v).origin;if(v!=='null'&&o!=='null'&&authorized(o))out.origin=o;}catch{}}
    else if(name==='referer'){try{const r=new URL(v);if(['http:','https:'].includes(r.protocol)&&authorized(r.origin)&&!(r.protocol==='https:'&&target.protocol==='http:'))out.referer=r.origin+'/';}catch{}}}}
  else if(profile.staticUserAgent!=='none')out['user-agent']=PRODUCT_USER_AGENT;
  out['accept-language']=acceptLanguage(profile.browserLocale);
  // Program (2.8): identification headers and a User-Agent suffix, only toward URLs inside the program scope (preflight already refuses the rest; checked again here).
  // The suffix is appended to the honest product token, or to Chromium's own User-Agent for browser requests; it never replaces either.
  const program=profile.program;
  if(program&&programScope(program).allows(target)){for(const [k,v]of Object.entries(program.headers))out[k.toLowerCase()]=v;if(program.userAgentSuffix&&out['user-agent'])out['user-agent']+=' '+program.userAgentSuffix;}
  return out;
}
export class PolicyError extends Error { recorded=false; constructor(readonly code:string){super(code);} }
/** A successfully downloaded body whose analysis was cut by a turn-only interruption; the scanner may resume it once without a new request. */
export class AnalysisDeferred extends Error { constructor(readonly response:ResponseData,readonly cause:GapCause){super('analysis-deferred');} }
export type Resolver=(host:string)=>Promise<{address:string;family:number}[]>;
const defaultResolver:Resolver=host=>lookup(host,{all:true,verbatim:true});
export interface ResponseData {url:string;status:number;headers:Record<string,string|string[]>;body:Buffer;partial:boolean;chain:string[];resource?:Resource;text?:string;analyzed?:boolean;resumed?:boolean}
export interface Exclusion {origin:string;class:string;reason:string;count:number;urls:string[];firstSeenIn?:string;kinds:string[]}
export interface AnalysisMetrics {engineMs:number;cacheHits:number;engineCalls:number;engineScreened?:number;failures:Set<string>;url?:string;attemptId?:number}
/** Refusals that are recorded (blocked resource, gap with the same code) but do not make the target incomplete. `invalid-url` (2.9.1): a discovered URL whose host is not a website host,
 * or that is not a valid HTTP(S) URL, is informational, like an out-of-scope or protected host; saved records keep the `incomplete` flag they were written with. */
export const NON_INCOMPLETE_BLOCKS=['scope','protected-host','credential-in-request','method','destructive-get','dashboard-isolation','websocket-disabled','browser-background-denied','invalid-url'];
/** Informational refusals that the JSONL `target-end.gaps` still lists (as before 2.9.1, when they were incomplete), marked `informational: true`. */
export const INFORMATIONAL_GAPS=['invalid-url'];
const ADMISSION_FAILURES=['auto-origin-limit','private-address','metadata','dns-timeout','dns-empty','dns-invalid','dns-failure'];
/** Low-impact keep-alive (2.6): an idle connection closes after this long (or 1 s before the server's announced Keep-Alive timeout), below the common 5 s server default. */
export const CONNECTION_IDLE_MS=4000;
/** Low-impact run response cache: identical GETs already downloaded through guarded transport in this run, held in memory only and dropped when the run ends. */
export const RUN_CACHE_BYTES=64*1024*1024;
const CACHEABLE_STATUS=[200,404,410];
/** A connection is reused only for the same origin, the same validated pinned address and the same TLS server name. */
export function connectionKey(u:URL,address:string){return [u.protocol,u.hostname.toLowerCase(),u.port||(u.protocol==='https:'?'443':'80'),canonicalIp(address),net.isIP(u.hostname)?'':u.hostname.toLowerCase()].join('|');}
const headerText=(headers:Record<string,string|string[]|undefined>,name:string)=>{const v=headers[name];return Array.isArray(v)?v.join(', '):v===undefined?'':String(v);};
/** Freshness lifetime (RFC 9111, private cache) of a response; 0 means it is never reused. Set-Cookie, no-store, no-cache, private, Vary: * and stale or
 * unparsable expiry are uncacheable; without explicit freshness only the Last-Modified heuristic (10%) applies, as in Chromium. Conditional revalidation is never used. */
export function cacheLifetimeMs(headers:Record<string,string|string[]|undefined>,status:number,receivedAt=Date.now()):number{
  if(!CACHEABLE_STATUS.includes(status)||headerText(headers,'set-cookie'))return 0;
  const cc=headerText(headers,'cache-control').toLowerCase(),directives=new Map(cc.split(',').map(d=>d.trim()).filter(Boolean).map(d=>{const at=d.indexOf('=');return at<0?[d,'']:[d.slice(0,at).trim(),d.slice(at+1).trim().replace(/^"|"$/g,'')];}));
  if(['no-store','no-cache','private'].some(d=>directives.has(d))||!cc&&/no-cache/i.test(headerText(headers,'pragma'))||headerText(headers,'vary').split(',').some(v=>v.trim()==='*'))return 0;
  const date=Date.parse(headerText(headers,'date')),base=Number.isFinite(date)?date:receivedAt,age=Math.max(0,Number(headerText(headers,'age'))||0)*1000;
  let lifetime=0;
  if(directives.has('max-age')){const n=Number(directives.get('max-age'));lifetime=Number.isFinite(n)&&n>0?n*1000:0;}
  else if(headerText(headers,'expires')){const e=Date.parse(headerText(headers,'expires'));lifetime=Number.isFinite(e)?e-base:0;}
  else{const modified=Date.parse(headerText(headers,'last-modified'));lifetime=Number.isFinite(modified)&&modified<base?Math.floor((base-modified)/10):0;}
  return Math.max(0,lifetime-age);
}
/** The stored request's values of every header named by Vary must equal the new request's. */
export function varyMatches(vary:string,stored:Record<string,string>,current:Record<string,string>){return vary.split(',').map(v=>v.trim().toLowerCase()).filter(Boolean).every(name=>(stored[name]??'').trim()===(current[name]??'').trim());}
/** Run-cache eligibility of an outbound request: no cookie, no Authorization and no cross-origin Origin (a same-origin module script carries its own origin). */
const reusableRequest=(url:string,h:Record<string,string>)=>!h.cookie&&!h.authorization&&(!h.origin||h.origin===new URL(url).origin);
interface CacheEntry {status:number;headers:Record<string,string|string[]>;body:Buffer;request:Record<string,string>;freshUntil:number}
/** Per request attempt. `socket` is the connection openPinned opened for it, which the request's own timer and cancellation end while it is still connecting. */
type ConnectionHooks={connected?:()=>void;ready?:()=>void;socket?:net.Socket};
export class Transport {
  bytes=0;wireBytes=0;requests=0;attemptedUrls:string[]=[];
  /** Connection and reuse accounting (2.6). Every connection is counted, in every traffic level; reuse and the run cache are Low-impact only. */
  /** Connections attempted (a refused or timed-out connect counts: it still reached the network), reused kept-alive connections, TLS handshakes started after TCP connected
   * (a failed certificate check counts), browser requests served from the run cache, and requests not sent because the run cache answered. */
  connectionsOpened=0;connectionsReused=0;tlsHandshakes=0;browserCacheHits=0;requestsAvoided=0;
  /** Requests sent once more on a fresh connection after a kept-alive connection failed before any response (never after a timeout or a 429/503 answer). */
  connectionReplays=0;
  /** Low-impact: keep-alive to the same validated pinned address and TLS name, and the run response cache. Normal and legacy settings open one connection per request, as in 2.5. */
  readonly lowImpact:boolean;
  private pools=new Map<string,{key:string;ip:string;agent:http.Agent}>();private closed=false;
  /** Every socket carries the canonical address it was validated and pinned to; a socket that already served a request is a reuse. */
  private socketPins=new WeakMap<net.Socket,string>();private servedSockets=new WeakSet<net.Socket>();private cache=new Map<string,CacheEntry>();private cacheBytes=0;
  /** The run cache's byte limit (one entry may use at most a quarter); fixed per transport, never configurable from a scan configuration. */
  private cacheLimit=RUN_CACHE_BYTES;
  /** Low-impact: identical cacheable GETs in flight (from the scheduler's dispatch through the permit wait to the response); a second one waits and is then served from the run cache. */
  private inflight=new Map<string,Promise<void>>();
  private wallStarted=Date.now();private projectStarted=performance.now();private active=0;private nextAt=0;private attemptSequence=0;
  get started(){return this.wallStarted;}set started(value:number){this.wallStarted=value;this.projectStarted=performance.now()-Math.max(0,Date.now()-value);}
  private origins:Set<string>;private privateOrigins:Set<string>;private controller=new AbortController();
  readonly projectSignal=this.controller.signal;readonly originControl:OriginControl;deniedPorts=new Set<number>();
  /** Live attempts by phase (no URLs leave the process); browser readiness separates local queueing from network waiting with it. */
  readonly live=new Map<number,{phase:string;kind:string;url:string}>();
  livePhases(kind?:string){let localQueue=0,network=0;for(const a of this.live.values()){if(kind&&a.kind!==kind)continue;if(['scheduler','preflight','rate-wait','cache-wait'].includes(a.phase))localQueue++;else network++;}return {localQueue,network};}
  readonly authorizations=new Map<string,OriginAuthorization>();
  /** The one scope policy. Scope grants eligibility only; `origins` stays the sole authorized set. */
  readonly scope:ScopePolicy;
  /** Program-wide gate shared by every transport of the same program in this process (2.8); absent outside program runs. */
  readonly program?:ProgramLimiter;
  private autoLimitGap?:Gap;private autoLimitOrigins=new Set<string>();
  /** Third-party and exact-origin-mode exclusions take no inventory or audit slots beyond a bounded first record per origin. */
  readonly exclusions=new Map<string,Exclusion>();exclusionOverflow=0;exclusionReferences=0;
  /** In-domain origins that scope made eligible but admission refused, by reason. */
  readonly notAdmitted=new Map<string,{origin:string;reason:string;count:number;examples:string[]}>();
  /** Hard rule: government, military, intelligence and law-enforcement hosts are never contacted. References are counted per host (bounded like exclusions); they never make a run incomplete. */
  readonly protectedHosts=new Map<string,{host:string;count:number;urls:string[];kinds:string[]}>();protectedOverflow=0;protectedReferences=0;
  get authorizedOrigins(){return [...this.origins];}
  isAuthorized(raw:string){try{return this.origins.has(new URL(raw).origin);}catch{return false;}}
  sameDomainSeed(raw:string){return this.scope.eligibleSeed(raw);}
  onOriginAdmitted?:(origin:string,authorization:OriginAuthorization)=>void;
  get signal(){return this.originControl.signal;}
  constructor(readonly config:ScanConfig,readonly evidence:Evidence,readonly onResource:(r:Resource)=>void,readonly onGap:(g:Gap)=>void,readonly resolver:Resolver=defaultResolver){
    this.origins=new Set([...config.urls.map(u=>new URL(u).origin),...config.relatedOrigins]);
    this.privateOrigins=new Set([...config.privateOrigins,...(config.developmentFixtureOrigin?[config.developmentFixtureOrigin]:[])]);
    this.originControl=new OriginControl(config,this.projectSignal);this.originControl.projectLimit={remainingMs:at=>this.projectRemainingMs(at),expire:()=>this.expire()};this.scope=new ScopePolicy(config);this.lowImpact=config.traffic==='low-impact';this.program=config.program?programLimiter(config.program):undefined;
    for(const origin of this.origins){const authorization:OriginAuthorization={type:config.urls.some(u=>new URL(u).origin===origin)?'explicit-seed':'explicit-related'};this.authorizations.set(origin,authorization);this.originControl.get(origin).authorization=authorization;}
  }
  private projectStopCause:'cancelled'|'duration-limit'|'blocked'='cancelled';
  private cause(signal:AbortSignal){if(this.projectSignal.aborted)return this.projectStopCause;const r=abortReason(signal,'origin-deadline');return r?.kind==='work-turn-limit'?'work-turn-limit':r?.kind==='analysis-turn-limit'?'analysis-turn-limit':r?.kind==='user-cancelled'?'cancelled':'duration-limit';}
  /** Structured cause for the current (or given) aborted signal; never raw exception text. */
  abortCause(signal:AbortSignal=this.signal):GapCause|undefined{const r=abortReason(signal,this.projectSignal.aborted?(this.projectStopCause==='cancelled'?'user-cancelled':'project-deadline'):'origin-deadline');return r?{kind:r.kind,origin:r.origin||this.originControl.current?.origin}:undefined;}
  get stopCause(){return this.signal.aborted?this.cause(this.signal):this.originControl.expired()?'duration-limit':'cancelled';}
  cancel(){if(!this.projectSignal.aborted){this.projectStopCause='cancelled';this.controller.abort({kind:'user-cancelled'} satisfies AbortReason);this.originControl.cancel();}}
  expire(url?:string){if(url)this.originControl.expire(url);else{this.projectStopCause='duration-limit';this.controller.abort({kind:'project-deadline'} satisfies AbortReason);this.originControl.cancel();}}
  // Block detection (2.8): a target stopped only after repeated refusals/challenges/resets. block() records a 'blocked' gap and aborts the project like a cancel — it never changes User-Agent, headers, proxy or IP and never retries around the block (delay() throws the aborted stop cause).
  blockMonitor?:BlockMonitor;blocked?:BlockDecision;
  private observeBlock(o:BlockObservation){if(!this.blockMonitor||this.blocked)return;const d=this.blockMonitor.observe(o);if(d)this.block(d);}
  block(d:BlockDecision){if(this.projectSignal.aborted)return;this.blocked=d;this.projectStopCause='blocked';this.onGap({code:'blocked',detail:d.detail,incomplete:true});this.controller.abort({kind:'user-cancelled'} satisfies AbortReason);this.originControl.cancel();}
  /** In mass mode the time every open website of this scan only waited for shared analysis capacity is not charged (OriginControl.projectExcludedMs). `now`: the clock
   * reading to use, so a check that compares this with a website's time left reads both at one instant. */
  projectRemainingMs(now=performance.now()){return Math.max(0,(this.config.projectMaxDurationMs??this.config.maxDurationMs)-(now-this.projectStarted-this.originControl.projectExcludedMs(now)));}
  /** The one decision every time-limit timer and check makes, so a wait ends the same way whichever of them runs first: once the clock reads the scan's limit as
   * reached (at or before the given website's), the scan's limit expires; once it reads only the website's, that website's limit expires. Returns false while the
   * clock reads neither as reached (a timer then sets itself again for the time still left). Both are read at one instant: a website starts no earlier than the scan,
   * but read a moment after the scan it could look past its limit while the scan, read before, still had time left, and only the website would expire. */
  expireReached(origin?:string){const now=performance.now(),project=this.projectRemainingMs(now),website=origin?this.originControl.remainingMs(origin,now):Infinity;if(project>0&&website>0)return false;if(project<=website)this.expire();else this.originControl.expire(origin);return true;}
  remainingMs(){const now=performance.now(),project=this.projectRemainingMs(now);return this.originControl.current?Math.min(project,this.originControl.remainingMs(undefined,now)):project;}
  /** Timer for one wait (DNS answer, response, browser session): `onTimeout` runs after `timeoutMs`, unless the scan's or the current website's time limit comes first.
   * Then this timer expires that limit, which aborts the wait through its signal as a duration limit, so the wait ends the same way whether this timer or the
   * scan's own deadline timer runs first. A limit counts as reached only when the clock reads it: Node can run a timer up to 1 ms early, and a website admitted
   * meanwhile can extend the scan's limit; the timer is set again for the time still left. */
  limitTimer(timeoutMs:number,onTimeout:()=>void):{clear():void}{
    const at=performance.now(),state=this.originControl.current;let handle:ReturnType<typeof setTimeout>|undefined;
    const arm=()=>{const now=performance.now(),limit=Math.min(this.projectRemainingMs(now),state?this.originControl.remainingMs(state.origin,now):Infinity),wait=timeoutMs-(now-at);
      handle=wait<=limit?setTimeout(onTimeout,Math.max(1,wait)):setTimeout(()=>{if(!this.expireReached(state?.origin))arm();},Math.max(1,limit));};
    arm();return {clear:()=>clearTimeout(handle)};
  }
  checkBudget(){this.checkBudgetExceptCount();if(this.requests>=this.config.maxResources)throw new PolicyError('request-count-limit');if(this.bytes>=this.config.maxTotalBytes||this.bytes>=this.config.maxDecodedTotalBytes)throw new PolicyError('total-byte-limit');const origin=this.originControl.current;if(origin&&origin.requests>=(this.config.originMaxResources??this.config.maxResources))throw new PolicyError('origin-request-count-limit');if(origin&&origin.bytes>=(this.config.originMaxTotalBytes??this.config.maxTotalBytes))throw new PolicyError('origin-byte-limit');}
  private noteNotAdmitted(origin:string,reason:string,url:string){const key=origin||url;let entry=this.notAdmitted.get(key);if(!entry){if(this.notAdmitted.size>=500)return;entry={origin:key,reason,count:0,examples:[]};this.notAdmitted.set(key,entry);}entry.count++;entry.reason=reason;if(entry.examples.length<3&&!entry.examples.includes(url))entry.examples.push(url);}
  recordBlocked(url:string,code:string,chain:string[]=[],kind='request',provenance?:Resource['provenance']){
    const decision=this.scope.classify(url),inDomain=decision.class==='in-domain'||decision.reason==='exact-origin-mode'||decision.reason==='outside-host-subtree';
    if(code==='protected-host'){
      const host=protectedHost(url)?.host||decision.origin||url;this.protectedReferences++;let entry=this.protectedHosts.get(host);
      if(entry){entry.count++;if(entry.urls.length<8&&!entry.urls.includes(url))entry.urls.push(url);if(!entry.kinds.includes(kind)&&entry.kinds.length<8)entry.kinds.push(kind);}
      else if(this.protectedHosts.size<500){this.protectedHosts.set(host,{host,count:1,urls:[url],kinds:[kind]});this.onResource({url,status:'blocked',analysis:'skipped',reason:code,bytes:0,chain,kind,provenance});}
      else this.protectedOverflow++;
      if(inDomain)this.noteNotAdmitted(decision.origin,code,url);
      const hosts=this.protectedHosts.size+this.protectedOverflow,refs=this.protectedReferences;
      this.onGap({code,detail:`${refs} reference${refs===1?'':'s'} to ${hosts} government, military, intelligence or law-enforcement host${hosts===1?'':'s'} ${refs===1?'was':'were'} not requested: Exposure Desk never scans such websites (built-in rule, no override). They are not counted as websites and do not make the scan incomplete.`,incomplete:false,count:refs,examples:[...this.protectedHosts.keys()].slice(0,10)});
      return;
    }
    if(code==='scope'){
      const key=decision.origin||url,reason=decision.reason||'third-party';this.exclusionReferences++;let entry=this.exclusions.get(key);
      if(entry){entry.count++;if(entry.urls.length<8&&!entry.urls.includes(url))entry.urls.push(url);if(!entry.kinds.includes(kind)&&entry.kinds.length<8)entry.kinds.push(kind);}
      else if(this.exclusions.size<500){entry={origin:key,class:decision.class,reason,count:1,urls:[url],firstSeenIn:[...chain].reverse().find(c=>/^https?:/.test(c)),kinds:[kind]};this.exclusions.set(key,entry);this.onResource({url,status:'blocked',analysis:'skipped',reason:code,bytes:0,chain,kind,provenance});}
      else this.exclusionOverflow++;
      if(inDomain)this.noteNotAdmitted(decision.origin,reason,url);
      const program=[...this.exclusions.values()].filter(e=>e.reason==='program-out-of-scope').length,third=[...this.exclusions.values()].filter(e=>e.reason!=='program-out-of-scope'&&(e.reason==='third-party'||!['exact-origin-mode','outside-host-subtree'].includes(e.reason))).length,inside=this.exclusions.size-third-program;
      this.onGap({code:'scope',detail:`${third} third-party origin${third===1?'':'s'}${inside?` and ${inside} origin${inside===1?'':'s'} inside the entered domain but outside the configured scope`:''}${program?` and URLs on ${program} origin${program===1?'':'s'} outside the program scope`:''} were referenced (${this.exclusionReferences} references${this.exclusionOverflow?`, ${this.exclusionOverflow} beyond the 500-origin summary`:''}) and not scanned. Excluded origins are not counted as websites.`,incomplete:false,count:this.exclusionReferences,examples:[...this.exclusions.keys()].slice(0,10)});
      return;
    }
    if(ADMISSION_FAILURES.includes(code)&&inDomain)this.noteNotAdmitted(decision.origin,code,url);
    this.onResource({url,status:'blocked',analysis:'skipped',reason:code,bytes:0,chain,kind,provenance});
    if(code==='auto-origin-limit')return; // The aggregate retains unique counts and examples.
    this.onGap({code,url,detail:code==='credential-in-request'?'Locally observed credential-bearing request was blocked before transmission.':`Request blocked: ${code}.`,incomplete:!NON_INCOMPLETE_BLOCKS.includes(code),...(provenance?{attribution:provenance.attribution,targetOrigin:provenance.targetOrigin}:{})});
  }
  protectedView(){return {hosts:this.protectedHosts.size+this.protectedOverflow,references:this.protectedReferences,overflow:this.protectedOverflow,examples:[...this.protectedHosts.values()].map(e=>({host:e.host,count:e.count,kinds:[...e.kinds],urls:[...e.urls]}))};}
  exclusionsView(){const examples=[...this.exclusions.values()].map(e=>({origin:e.origin,count:e.count,reason:e.reason,firstSeenIn:e.firstSeenIn,kinds:[...e.kinds],urls:[...e.urls]}));return {thirdPartyOrigins:examples.filter(e=>!['exact-origin-mode','outside-host-subtree','program-out-of-scope'].includes(e.reason)).length,references:this.exclusionReferences,overflow:this.exclusionOverflow,examples};}
  async preflight(rawUrl:string,method='GET',headers:Record<string,string>={},body='',chain:string[]=[],discoveredFrom?:string):Promise<string>{
    if(rawUrl.length>4096||body.length>65536||Object.values(headers).join().length>65536)throw new PolicyError('request-data-limit');
    // Inspect the exact supplied data before normalization or any DNS/network activity.
    const supplied=[rawUrl,...Object.entries(headers).map(([k,v])=>`${k}=${v}`),body,...Object.entries(this.config.program?.headers||{}).map(([k,v])=>`${k}=${v}`)].join('\n');
    // Mass mode: a wait for shared analysis capacity during this screening counts as a preflight wait (2.9).
    const candidates=await this.originControl.waitCause('preflight',()=>this.evidence.detector.inspect(supplied,this.evidence.analysis));
    let containsPrivate=false;
    for(const c of candidates){
      this.evidence.add(c,supplied,rawUrl,chain,'Locally observed candidate request; blocked candidates were never sent');
      if(c.category==='private-credential'||c.category==='suspicious')containsPrivate=true;
    }
    // Unknown Authorization credentials and sensitive named URL/body/header fields fail closed too.
    const auth=Object.entries(headers).find(([name])=>name.toLowerCase()==='authorization')?.[1];
    if(auth){const value=auth.replace(/^(?:Bearer|Basic)\s+/i,'');this.evidence.add({value,original:auth,index:supplied.indexOf(auth),rule:'unverified-request-authorization',provider:'Unknown',category:'suspicious',severity:'medium',confidence:'low',reasons:['Authorization credential in candidate request. Shared/privileged versus fresh anonymous-session status is unknown; request blocked without verification.'],transformations:[]},supplied,rawUrl,chain,'Locally observed outgoing credential; not transmitted');containsPrivate=true;}
    for(const [name,value]of Object.entries(headers))if(/^(?:x-api-key|api-key|xi-api-key|x-auth-key|cf-access-client-secret|x-amz-security-token|x-postmark-server-token|x-postmark-account-token|ocp-apim-subscription-key)$/i.test(name)&&value){this.evidence.add({value,original:value,index:supplied.indexOf(value),rule:'unverified-request-private-header',provider:'Unknown',category:'suspicious',severity:'medium',confidence:'high',reasons:['Authentication header in candidate request; blocked locally without testing the value.'],transformations:[]},supplied,rawUrl,chain,'Locally observed authentication header; never transmitted');containsPrivate=true;}
    try{const u=new URL(rawUrl);if(u.username||u.password){const value=u.password||u.username;this.evidence.add({value,original:value,index:rawUrl.indexOf(value),rule:'url-userinfo',provider:'Unknown',category:'suspicious',severity:'medium',confidence:'high',reasons:['URL contains user credentials; request was never transmitted.'],transformations:[]},rawUrl,rawUrl,chain,'Locally observed URL user information');containsPrivate=true;}}catch{}
    // Decode parameter names as well as values before transmission. A percent-
    // escaped field name must not bypass the unknown-authentication guard.
    const authField=/(?:secret|password|passwd|api[_-]?key|access[_-]?token|auth[_-]?token|signature|^sig$)/i;
    const inspectFields=(encoded:string,offset:number)=>{for(const field of encoded.split('&')){const at=field.indexOf('=');if(at<0)continue;try{const name=decodeURIComponent(field.slice(0,at).replace(/\+/g,' ')),original=field.slice(at+1),value=decodeURIComponent(original.replace(/\+/g,' '));if(value&&authField.test(name)){containsPrivate=true;this.evidence.add({value,original,index:offset+encoded.indexOf(field)+at+1,rule:'unverified-request-auth-field',provider:'Unknown',category:'suspicious',severity:'medium',confidence:'high',reasons:['Explicit authentication field in an outgoing candidate; blocked locally without validation.'],transformations:original===value?[]:['URL form decoding']},supplied,rawUrl,chain,'Locally observed authentication parameter; not transmitted');}}catch{}}};
    try{const query=new URL(rawUrl).search;if(query)inspectFields(query.slice(1),rawUrl.indexOf(query)+1);}catch{}
    if(body){const offset=supplied.lastIndexOf(body);inspectFields(body,offset);for(const m of body.matchAll(/"(client[_-]?secret|password|passwd|signing[_-]?secret)"\s*:\s*("(?:\\.|[^"\\])*")/gi)){try{const value=JSON.parse(m[2]);if(value){containsPrivate=true;this.evidence.add({value,original:m[2],index:offset+m.index!+m[0].indexOf(m[2]),rule:'unverified-request-auth-field',provider:'Unknown',category:'suspicious',severity:'medium',confidence:'high',reasons:['Explicit private authentication field in a JSON request; blocked locally.'],transformations:['JSON literal decoding']},supplied,rawUrl,chain,'Locally observed JSON authentication field; not transmitted');}}catch{}}}
    if(/[?&](?:[^=&]{0,40}(?:secret|password|access[_-]?token|auth[_-]?token)[^=&]{0,20})=[^&#]+/i.test(rawUrl)||/\b(?:client_secret|password|signing_secret)\s*[=:]\s*[^\s&]+/i.test(body))containsPrivate=true;
    // A protected host is counted as such even when the request also carries a credential (the evidence above is kept either way).
    if(containsPrivate)throw new PolicyError(protectedHost(rawUrl)?'protected-host':'credential-in-request');
    let url:string;try{url=normalizeUrl(rawUrl);}catch{throw new PolicyError(protectedHost(rawUrl)?'protected-host':'invalid-url');}
    // Hard rule before scope, admission, DNS or any socket, for explicit seeds, related and admitted origins alike; no setting skips it.
    if(protectedHost(url))throw new PolicyError('protected-host');
    // Every request (seeds, redirect hops, browser subrequests, maps) needs a website host before scope, admission or DNS; the lenient parse above only canonicalizes.
    if(!websiteHost(new URL(url).hostname))throw new PolicyError('invalid-url');
    const u=new URL(url),decision=this.scope.classify(url);
    // Program scope (2.8) narrows every request, seeds and redirects included: an origin or path outside it is never contacted and is recorded as excluded.
    if(decision.reason==='program-out-of-scope')throw new PolicyError('scope');
    // Scope grants eligibility only: one policy for seeds, related origins and in-domain discovery. Admission still follows every safety guard.
    if(!this.origins.has(u.origin)&&decision.class!=='in-domain')throw new PolicyError('scope');
    if(this.deniedPorts.has(Number(u.port||(u.protocol==='https:'?443:80))))throw new PolicyError('dashboard-isolation');
    if(!['GET','HEAD'].includes(method)&&!(method==='POST'&&this.config.readOnlyPostEndpoints.includes(url)))throw new PolicyError('method');
    if(/(?:^|\/)(?:logout|delete|destroy|remove|unsubscribe|purchase|checkout|send|generate|reset|revoke|rotate|activate|deactivate|drop|truncate)(?:[/.?-]|$)/i.test(u.pathname+u.search)||/[?&](?:action|do|operation|cmd)=(?:delete|remove|send|buy|generate|logout|reset|revoke)/i.test(u.search))throw new PolicyError('destructive-get');
    if(!this.origins.has(u.origin)){
      const seed=decision.seed;
      if(!seed)throw new PolicyError('scope');
      // Admission never inherits private-origin exceptions. DNS is checked again on
      // every actual request, with socket pinning and TLS validation unchanged.
      await this.addresses(url,true);
      if(this.signal.aborted)throw new PolicyError(this.stopCause);
      if(!this.origins.has(u.origin)){
        // The cap counts only automatically admitted, distinct, canonical origins after the public DNS check.
        const count=[...this.authorizations.values()].filter(a=>a.type==='same-registrable-domain').length;
        if(count>=(this.config.maxAutoDiscoveredOrigins??50)){
          if(!this.autoLimitOrigins.has(u.origin)){
            this.autoLimitOrigins.add(u.origin);
            if(!this.autoLimitGap){this.autoLimitGap={code:'auto-origin-limit',detail:`Automatic same-domain origin limit (${this.config.maxAutoDiscoveredOrigins??50}) reached; additional discovered origins were not scanned.`,incomplete:true,count:0,examples:[]};this.onGap(this.autoLimitGap);}
            this.autoLimitGap.count=this.autoLimitOrigins.size;
            if(this.autoLimitGap.examples!.length<10)this.autoLimitGap.examples!.push(u.origin);
            // Send an updated aggregate because consumers may copy gap records.
            this.onGap({...this.autoLimitGap,examples:[...this.autoLimitGap.examples!]});
          }
          throw new PolicyError('auto-origin-limit');
        }
        const authorization:OriginAuthorization={type:'same-registrable-domain',discoveredFrom:discoveredFrom||[...chain].reverse().find(s=>/^https?:\/\//i.test(s))||seed,seed,registrableDomain:decision.registrableDomain!,scope:this.scope.mode};
        this.origins.add(u.origin);this.authorizations.set(u.origin,authorization);this.originControl.get(u.origin).authorization=authorization;
        this.onOriginAdmitted?.(u.origin,authorization);
      }
    }
    return url;
  }
  async addresses(url:string,requirePublic=false):Promise<{address:string;family:number}[]>{
    const signal=this.signal;
    const u=new URL(url),host=u.hostname.replace(/^\[|\]$/g,'');
    if(protectedHost(u.hostname))throw new PolicyError('protected-host'); // never even a DNS query
    if(['metadata.google.internal','metadata','instance-data'].includes(host.toLowerCase())||(net.isIP(host)&&metadataAddress(host)))throw new PolicyError('metadata');
    const answers:{address:string;family:number}[]=net.isIP(host)?[{address:host,family:net.isIP(host)}]:await new Promise((resolve,reject)=>{let settled=false;const done=(error?:unknown,value?:{address:string;family:number}[])=>{if(settled)return;settled=true;timer.clear();signal.removeEventListener('abort',cancel);error?reject(error):resolve(value!);};const cancel=()=>done(new PolicyError(this.cause(signal)));const timer=this.limitTimer(this.config.timeoutMs,()=>done(new PolicyError('dns-timeout')));signal.addEventListener('abort',cancel,{once:true});if(signal.aborted)cancel();else Promise.resolve(this.resolver(host)).then(a=>done(undefined,a),e=>done(e));});
    if(!answers.length)throw new PolicyError('dns-empty');
    if(answers.some(a=>!net.isIP(a.address)))throw new PolicyError('dns-invalid');
    // Metadata credentials stay forbidden even when a private origin is explicitly approved.
    if(answers.some(a=>metadataAddress(a.address)))throw new PolicyError('metadata');
    const automaticallyAuthorized=this.authorizations.get(u.origin)?.type==='same-registrable-domain';
    if((requirePublic||automaticallyAuthorized||!this.privateOrigins.has(u.origin))&&answers.some(a=>!publicAddress(a.address)))throw new PolicyError('private-address');
    // Even a permitted private origin cannot alias a dashboard's listening port.
    if(this.deniedPorts.has(Number(u.port||(u.protocol==='https:'?443:80))))throw new PolicyError('dashboard-isolation');
    return answers;
  }
  async delay(ms:number){
    const signal=this.signal;if(ms<=0)return;if(signal.aborted)throw new PolicyError(this.stopCause);if(ms>=this.remainingMs()){this.onGap({code:'backoff-beyond-deadline',detail:'Required scheduler/rate-limit backoff exceeds the remaining scan deadline; no early retry is sent. Use fresh budgets later.',incomplete:true});throw new PolicyError('duration-limit');}
    // A backoff is this website's own wait (politeness): it stays charged, also while another unit of its work waits for shared analysis capacity.
    const working=this.originControl.busy();
    try{await new Promise<void>((resolve,reject)=>{const stop=()=>{clearTimeout(t);signal.removeEventListener('abort',stop);reject(new PolicyError(this.cause(signal)));};const t=setTimeout(()=>{signal.removeEventListener('abort',stop);resolve();},ms);signal.addEventListener('abort',stop,{once:true});if(signal.aborted)stop();});}finally{working();}
  }
  /** Abortable idle wait that records no gap; for settle and launch polling. */
  async sleep(ms:number){const signal=this.signal;if(ms<=0||signal.aborted)return;const working=this.originControl.busy();try{await new Promise<void>(resolve=>{const stop=()=>{clearTimeout(t);resolve();};const t=setTimeout(()=>{signal.removeEventListener('abort',stop);resolve();},ms);signal.addEventListener('abort',stop,{once:true});});}finally{working();}}
  private permits:{origin:OriginState;signal:AbortSignal;resolve:()=>void;reject:(e:Error)=>void;stop:()=>void;unit?:WorkUnit}[]=[];
  private permitTimer?:ReturnType<typeof setTimeout>;private lastOrigin='';private peakActive=0;
  private pumpPermits(){
    clearTimeout(this.permitTimer);this.permitTimer=undefined;
    const remove=(item:typeof this.permits[number],code:string)=>{this.permits.splice(this.permits.indexOf(item),1);item.signal.removeEventListener('abort',item.stop);item.reject(new PolicyError(code));};
    // A website whose limit the clock reads as reached loses its queued requests as 'duration-limit' and is expired (after they are removed), as its timer would.
    const reached=new Set<string>();
    for(const item of [...this.permits]){const due=!item.signal.aborted&&this.originControl.remainingMs(item.origin.origin)<=0;if(due)reached.add(item.origin.origin);const code=item.signal.aborted?(this.cause(item.signal)):due?'duration-limit':this.requests>=this.config.maxResources?'request-count-limit':this.bytes>=this.config.maxTotalBytes||this.bytes>=this.config.maxDecodedTotalBytes?'total-byte-limit':item.origin.requests>=(this.config.originMaxResources??this.config.maxResources)?'origin-request-count-limit':item.origin.bytes>=(this.config.originMaxTotalBytes??this.config.maxTotalBytes)?'origin-byte-limit':undefined;if(code){this.program?.forget(item);remove(item,code);}}
    for(const origin of reached)this.expireReached(origin);
    // Mass mode: the websites whose next request is ready under every limit of its own target but waits for a program-wide slot that other targets hold.
    let held:Set<string>|undefined,programHeld=false;
    while(this.permits.length&&this.active<(this.config.globalConcurrency??this.config.concurrency)){
      const now=this.originControl.now(),origins=[...this.originControl.states.keys()],last=origins.indexOf(this.lastOrigin),order=[...origins.slice(last+1),...origins.slice(0,last+1)];
      const activeOrigins=[...this.originControl.states.values()].filter(s=>s.activeRequests>0).length;
      const drainForWaitingOrigin=activeOrigins>=(this.config.maxActiveOrigins??4)&&this.permits.some(p=>!p.origin.activeRequests&&Math.max(p.origin.nextAt,p.origin.pauseUntil)<=now);
      const blocked=(state:OriginState)=>drainForWaitingOrigin&&state.activeRequests>0||state.activeRequests>=(this.config.originConcurrency??this.config.concurrency)||!state.activeRequests&&activeOrigins>=(this.config.maxActiveOrigins??4),readyAt=(state:OriginState)=>Math.max(this.nextAt,state.nextAt,state.pauseUntil);
      let item:typeof this.permits[number]|undefined,next=Infinity;
      for(const origin of order){const candidate=this.permits.find(p=>p.origin.origin===origin);if(!candidate)continue;const state=candidate.origin;if(blocked(state))continue;const ready=readyAt(state);if(ready<=now){item=candidate;break;}next=Math.min(next,ready);}
      if(!item){if(Number.isFinite(next))this.permitTimer=setTimeout(()=>this.pumpPermits(),Math.max(1,Math.ceil(next-now)));break;}
      // Program gate (2.8), on top of the global and per-origin limits: program-wide concurrency (woken on any program release) and request rate.
      // Fair turns (2.9): this transport waits in the program's queue of targets and is pumped again on its turn (the limiter's one timer or a release).
      if(this.program){const wait=this.program.delay(this);if(wait>0){this.program.hold(item,()=>this.pumpPermits(),this);programHeld=true;
        if(this.originControl.excludeSharedWaits&&this.program.heldByOthers(this))held=new Set(this.permits.filter(p=>!blocked(p.origin)&&readyAt(p.origin)<=now).map(p=>p.origin.origin));
        break;}this.program.acquire(item,this);}
      this.permits.splice(this.permits.indexOf(item),1);item.signal.removeEventListener('abort',item.stop);this.lastOrigin=item.origin.origin;this.active++;this.peakActive=Math.max(this.peakActive,this.active);item.origin.activeRequests++;item.origin.peakRequests=Math.max(item.origin.peakRequests,item.origin.activeRequests);this.nextAt=now+1000/this.config.requestsPerSecond;item.origin.nextAt=now+1000/(this.config.originRequestsPerSecond??this.config.requestsPerSecond);this.requests++;item.origin.requests++;item.unit?.work();item.resolve();
    }
    // A queued request is its website's own work (charged) unless it only waits for the program slots other targets hold; a wait after this target's own grant, or for
    // the website's own pacing, backoff, pause or concurrency, stays charged.
    for(const p of this.permits){if(held?.has(p.origin.origin))p.unit?.wait('programSlot');else p.unit?.work();}
    // No request of this transport waits for the program limit now: it gives up its place in the program's queue, so the next target's turn is not held up.
    if(this.program&&!programHeld)this.program.leave(this);
  }
  private async reserve(unit?:WorkUnit){this.checkBudget();const origin=this.originControl.current!,signal=this.signal;await new Promise<void>((resolve,reject)=>{const item={origin,signal,resolve,reject,unit,stop:()=>{const i=this.permits.indexOf(item);if(i>=0)this.permits.splice(i,1);signal.removeEventListener('abort',item.stop);reject(new PolicyError(this.cause(signal)));this.pumpPermits();}};this.permits.push(item);signal.addEventListener('abort',item.stop,{once:true});if(signal.aborted)item.stop();else this.pumpPermits();});}
  private release(){this.active--;const origin=this.originControl.current;if(origin)origin.activeRequests--;this.program?.release(this);this.pumpPermits();}
  coordinator(){return {activeRequests:this.active,queuedRequests:this.permits.length,peakActiveRequests:this.peakActive,activeOrigins:[...this.originControl.states.values()].filter(s=>s.activeRequests).length,pausedUntil:Math.max(0,...[...this.originControl.states.values()].map(s=>s.pauseUntil)),...(this.program?{program:this.program.stats()}:{})};}
  /** Opens one connection to the validated, pinned address: TLS with SNI and certificate validation for https, and the socket's remote address must equal the pin before any request byte is written. */
  private openPinned(u:URL,pin:{address:string;family:number},callback:(e:Error|null,s?:net.Socket)=>void,hooks?:ConnectionHooks){
    // Last-ditch guard: no socket is ever opened for a protected host, whichever path reached here.
    if(protectedHost(u.hostname)){callback(new PolicyError('protected-host'));return undefined;}
    const secure=u.protocol==='https:',origin=this.originControl.peek(u.href);this.connectionsOpened++;if(origin)origin.connectionsOpened++;
    // A server whose certificate names a protected host (an owner name aliasing a government service, which DNS answers alone cannot show) gets no request byte.
    const finish=(s:net.Socket)=>{try{if(!s.remoteAddress||canonicalIp(s.remoteAddress)!==canonicalIp(pin.address))throw new PolicyError('connection-address-mismatch');if(secure&&certificateNames((s as tls.TLSSocket).getPeerCertificate()).some(n=>protectedHost(n)))throw new PolicyError('protected-host');this.socketPins.set(s,canonicalIp(pin.address));hooks?.ready?.();callback(null,s);}catch(e){s.destroy();callback(e as Error);}};
    const connect={host:pin.address,port:Number(u.port||(secure?443:80)),family:pin.family};
    const socket=secure?tls.connect({...connect,servername:net.isIP(u.hostname)?undefined:u.hostname,rejectUnauthorized:true},()=>finish(socket)):net.connect(connect,()=>finish(socket));
    // No idle timer of its own: the request that opened it times the whole attempt (connect, TLS, headers, body) with one timer, and ends a connection still being
    // opened through hooks.socket. Two timers for one wait raced on a late event loop (Node runs whole timer lists in order), so the same never-answered request could
    // end as 'connection-timeout' or as 'request-timeout'. A kept-alive connection idle in the pool is closed by its agent's idle timeout.
    if(hooks)hooks.socket=socket;
    socket.once('connect',()=>{if(secure){this.tlsHandshakes++;if(origin)origin.tlsHandshakes++;}hooks?.connected?.();});socket.once('error',e=>callback(e));return undefined;
  }
  /** Low-impact: one keep-alive agent per origin, bound to one validated pinned address and TLS name (at most one connection at a time). A different pin — a changed DNS answer — retires the old connections first. */
  private pooledAgent(u:URL,pin:{address:string;family:number}):http.Agent{
    const key=connectionKey(u,pin.address),current=this.pools.get(u.origin);if(current?.key===key)return current.agent;this.retire(u.origin);
    // TCP keep-alive probes would start only after 30 s, so none is sent before the 4 s idle close.
    const options={keepAlive:true,keepAliveMsecs:30000,maxSockets:1,maxFreeSockets:1,timeout:CONNECTION_IDLE_MS};
    const agent=u.protocol==='https:'?new https.Agent(options):new http.Agent(options);
    // Every new connection repeats the pinned connect, TLS validation and socket-address check; per-request timing hooks travel with the request options (cleared when that request ends).
    (agent as any).createConnection=(opts:{exposureConnection?:ConnectionHooks}|undefined,callback:(e:Error|null,s?:net.Socket)=>void)=>this.openPinned(u,pin,callback,opts?.exposureConnection);
    this.pools.set(u.origin,{key,ip:canonicalIp(pin.address),agent});return agent;
  }
  private retire(origin:string){const pool=this.pools.get(origin);if(pool){pool.agent.destroy();this.pools.delete(origin);}}
  /** Closes every kept-alive connection and drops the run cache (scan end); a late request afterwards uses a one-off connection and no cache. */
  close(){this.closed=true;for(const origin of [...this.pools.keys()])this.retire(origin);this.cache.clear();this.cacheBytes=0;}
  /** Low-impact run cache: an identical GET is served from memory after the same preflight, only for uncredentialed requests (no cookie, Authorization or cross-origin Origin) whose Vary-selected
   * headers equal the stored request's, and only while fresh (200, 404 and 410 answers). Decoded bytes count against the same budgets; no request, connection or wire byte is used. */
  private usable(url:string,allowed:Record<string,string>){const entry=this.cache.get(url);if(!entry||this.closed)return;if(Date.now()>=entry.freshUntil){this.evict(url);return;}return varyMatches(headerText(entry.headers,'vary'),entry.request,allowed)?entry:undefined;}
  /** Callers check eligibility first: Low-impact, a bodiless GET, a reusable request and no bounded probe sample. */
  private fromCache(url:string,allowed:Record<string,string>,kind:string,chain:string[],timings:NonNullable<Resource['timings']>,entered:number):ResponseData|undefined{
    const entry=this.usable(url,allowed);if(!entry)return;
    const origin=this.originControl.current,size=entry.body.length;
    if(this.bytes+size>this.config.maxTotalBytes||this.bytes+size>this.config.maxDecodedTotalBytes||origin&&origin.bytes+size>(this.config.originMaxTotalBytes??this.config.maxTotalBytes))return;
    this.bytes+=size;this.requestsAvoided++;if(kind==='browser')this.browserCacheHits++;if(origin){origin.bytes+=size;origin.requestsAvoided++;if(kind==='browser')origin.browserCacheHits++;}
    this.cache.delete(url);this.cache.set(url,entry);timings.totalMs=Date.now()-entered;
    const resource:Resource={url,timings,status:entry.status>=400?'http-error':'downloaded',code:entry.status,bytes:size,partial:false,chain,kind,analysis:'pending',servedFrom:'run-cache',contentType:String(entry.headers['content-type']||''),httpDisposition:httpDisposition(entry.status,entry.headers)};this.onResource(resource);
    return {url,status:entry.status,headers:{...entry.headers},body:entry.body,partial:false,chain,resource};
  }
  private store(url:string,r:ResponseData,request:Record<string,string>){
    if(this.closed||!reusableRequest(url,request))return;
    const lifetime=cacheLifetimeMs(r.headers,r.status),size=r.body.length;if(lifetime<=0||size>this.cacheLimit/4)return;
    this.evict(url);while(this.cacheBytes+size>this.cacheLimit&&this.cache.size)this.evict(this.cache.keys().next().value!);
    this.cache.set(url,{status:r.status,headers:{...r.headers},body:r.body,request:{...request},freshUntil:Date.now()+lifetime});this.cacheBytes+=size;
  }
  private evict(url:string){const e=this.cache.get(url);if(e){this.cacheBytes-=e.body.length;this.cache.delete(url);}}
  async one(rawUrl:string,options:{method?:string;headers?:Record<string,string>;body?:string;chain?:string[];kind?:string}={}):Promise<ResponseData>{
    // Exact scope is still checked by preflight; unauthorized URLs never acquire an origin clock.
    let authorized=false;try{authorized=this.origins.has(new URL(rawUrl).origin);}catch{}
    if(authorized&&this.originControl.current?.origin!==new URL(rawUrl).origin)return this.originControl.run(rawUrl,()=>this.one(rawUrl,options));
    const {method='GET',headers={},body='',chain=[],kind='http'}=options,signal=this.signal;
    let url=rawUrl;let reserved=false,settleInflight:(()=>void)|undefined;const entered=Date.now(),timings:NonNullable<Resource['timings']>={},attemptId=++this.attemptSequence;let phase='scheduler',phaseAt=entered,received=0;const live={phase,kind,url:rawUrl};this.live.set(attemptId,live);const unit=this.originControl.unit();const phaseStart=(next:string)=>{phase=next;live.phase=next;phaseAt=Date.now();};
    try{
      this.checkBudget();phaseStart('preflight');url=await this.preflight(rawUrl,method,headers,body,chain);timings.preflightMs=Date.now()-phaseAt;
      if(this.originControl.current?.origin!==new URL(url).origin)return await this.originControl.run(url,()=>this.one(url,options));
      // The request is this website's own work from here on (preflight screening is not: a wait it has for the shared detector is marked by the detector itself).
      unit.work();
      const u=new URL(url),secure=u.protocol==='https:';
      // Never forward proxy, operator environment, dashboard authentication or arbitrary hop-by-hop headers; see outboundHeaders for the full table.
      let allowed=outboundHeaders(u,kind,headers,this.config,o=>this.origins.has(o));
      const sampleLimit=kind==='deep'&&/\.(?:sql|bak|log)$/.test(u.pathname)?Math.min(131072,this.config.maxResourceBytes):this.config.maxResourceBytes;
      // Deduplicated before any request is sent: an identical eligible GET already on its way is awaited, then the run cache answers if its response is reusable.
      // A cached answer still needs the same DNS check as a request (a refused answer refuses the copy too); bounded probe samples never use the cache.
      const cacheable=this.lowImpact&&!this.closed&&method==='GET'&&!body&&sampleLimit===this.config.maxResourceBytes&&reusableRequest(url,allowed);
      const cachedAnswer=async()=>{if(!cacheable||!this.usable(url,allowed))return;phaseStart('dns');const at=phaseAt;try{await this.addresses(url);}catch(e){this.retire(u.origin);throw e;}timings.dnsMs=Date.now()-at;return this.fromCache(url,allowed,kind,chain,timings,entered);};
      for(let pending=cacheable?this.inflight.get(url):undefined;pending;pending=this.inflight.get(url)){
        if(signal.aborted)throw new PolicyError(this.cause(signal));phaseStart('cache-wait');await new Promise<void>(resolve=>{const stop=()=>resolve();signal.addEventListener('abort',stop,{once:true});void pending!.then(()=>{signal.removeEventListener('abort',stop);resolve();});});if(signal.aborted)throw new PolicyError(this.cause(signal));
        const cached=await cachedAnswer();if(cached)return cached;
      }
      const cached=await cachedAnswer();if(cached)return cached;
      if(cacheable&&!this.inflight.has(url))this.inflight.set(url,new Promise<void>(resolve=>settleInflight=resolve));
      let result:ResponseData|undefined;
      // A kept-alive connection the server closed while idle can fail before any response; that GET is sent once more on a fresh connection, under a new permit (paced and counted).
      for(let replayed=false;!result;){
        phaseStart('rate-wait');await this.reserve(unit);reserved=true;timings.queueMs=timings.rateWaitMs=Date.now()-phaseAt;if(kind==='browser')this.originControl.current!.browserRequests++;this.attemptedUrls.push(url);phaseStart('dns');
        // DNS is checked again before every request, including one that would reuse a kept-alive connection; a refused answer retires that connection.
        let addresses:{address:string;family:number}[];try{addresses=await this.addresses(url);}catch(e){this.retire(u.origin);throw e;}
        // Sent headers are settled after DNS, as in 2.5 (an origin admitted while this request waited is named in Origin/Referer); the early copy only selected the cached answer.
        timings.dnsMs=Date.now()-phaseAt;this.checkBudgetExceptCount();allowed=outboundHeaders(u,kind,headers,this.config,o=>this.origins.has(o));phaseStart('connect');
        // The kept-alive pin stays while it is still in the freshly validated answer (round-robin DNS reorders answers); otherwise the first answer is pinned.
        const kept=this.lowImpact?this.pools.get(u.origin)?.ip:undefined,pin=addresses.find(a=>kept!==undefined&&canonicalIp(a.address)===kept)||addresses[0],pinned=canonicalIp(pin.address),pooled=this.lowImpact&&!this.closed?this.pooledAgent(u,pin):undefined;
        const hooks:ConnectionHooks={connected:()=>{if(secure){timings.connectMs=Date.now()-phaseAt;phaseStart('tls');}},ready:()=>{if(secure)timings.tlsMs=Date.now()-phaseAt;else timings.connectMs=Date.now()-phaseAt;phaseStart('headers');}};
        const agent=pooled||(secure?new https.Agent({keepAlive:false}):new http.Agent({keepAlive:false}));
        if(!pooled)(agent as any).createConnection=(_opts:unknown,callback:(e:Error|null,s?:net.Socket)=>void)=>this.openPinned(u,pin,callback,hooks);
        let reused=false,responded=false;received=0;
        try{result=await new Promise<ResponseData>((resolve,reject)=>{
          let settled=false;const chunks:Buffer[]=[];let size=0;
          // A one-off agent is destroyed with its connection; a kept-alive connection survives only a complete response and is destroyed on every other outcome.
          const cleanup=(complete:boolean)=>{timer.clear();signal.removeEventListener('abort',cancel);if(!pooled)agent.destroy();else if(!complete)req.destroy();};
          const fail=(e:Error)=>{if(settled)return;settled=true;cleanup(false);reject(pooled&&reused&&!responded&&!signal.aborted&&!(e instanceof PolicyError)&&['GET','HEAD'].includes(method)&&!body?Object.assign(new Error('reused-connection-reset'),{replay:true,original:e}):e);};
          const req=(secure?https:http).request(url,{method,headers:allowed,agent,exposureConnection:hooks} as http.RequestOptions,res=>{responded=true;timings.headersMs=Date.now()-phaseAt;phaseStart('body');
            const done=(partial=false)=>{if(settled)return;settled=true;timings.bodyMs=Date.now()-phaseAt;const h:Record<string,string|string[]>={};for(const [k,v]of Object.entries(res.headers))if(v!==undefined)h[k]=v;const data={url,status:res.statusCode||0,headers:h,body:Buffer.concat(chunks),partial,chain};resolve(data);cleanup(!partial);};
            const encoding=String(res.headers['content-encoding']||'identity').toLowerCase();
            const decoder=encoding==='gzip'?createGunzip():encoding==='br'?createBrotliDecompress():encoding==='deflate'?createInflate():undefined;
            if(!['identity','gzip','br','deflate'].includes(encoding)){this.onGap({code:'encoding-unsupported',url,detail:'Unsupported or stacked content encoding; response not inspected.',incomplete:true});done(true);res.destroy();return;}
            let wireSize=0;
            res.on('data',(b:Buffer)=>{wireSize+=b.length;this.wireBytes+=b.length;const origin=this.originControl.current!;origin.wireBytes+=b.length;if(wireSize>this.config.maxWireResourceBytes||this.wireBytes>this.config.maxTotalBytes||origin.wireBytes>(this.config.originMaxTotalBytes??this.config.maxTotalBytes)){this.onGap({code:'wire-size-limit',url,detail:'Compressed/wire byte budget reached; response partial.',incomplete:true});done(true);decoder?.destroy();res.destroy();req.destroy();}});
            const stream=decoder?res.pipe(decoder):res;
            stream.on('data',(b:Buffer)=>{
              if(settled)return;
              const origin=this.originControl.current!,remaining=Math.min(sampleLimit-size,this.config.maxTotalBytes-this.bytes,this.config.maxDecodedTotalBytes-this.bytes,(this.config.originMaxTotalBytes??this.config.maxTotalBytes)-origin.bytes);
              const keep=b.subarray(0,Math.max(0,remaining));chunks.push(keep);size+=keep.length;received=size;this.bytes+=keep.length;origin.bytes+=keep.length;
              if(keep.length<b.length||size>=sampleLimit||this.bytes>=this.config.maxTotalBytes||this.bytes>=this.config.maxDecodedTotalBytes||origin.bytes>=(this.config.originMaxTotalBytes??this.config.maxTotalBytes)){this.onGap({code:sampleLimit<this.config.maxResourceBytes?'content-sample-limit':'size-limit',url,detail:sampleLimit<this.config.maxResourceBytes?'Deployment log/backup probe retained only a bounded 128 KiB prefix; remaining content unknown.':'Decoded response inspected only up to resource/origin/project byte limit.',incomplete:true});done(true);decoder?.destroy();res.destroy();req.destroy();}
            });stream.on('end',()=>done());stream.on('error',()=>{this.onGap({code:'decompression-failure',url,detail:'Response decompression failed.',incomplete:true});fail(new PolicyError('response-failure'));});res.on('error',()=>fail(new PolicyError('response-failure')));
          });
          // Every socket must still be the one validated and pinned for this request's address before a byte is written. A reused one is counted
          // and has no connect or TLS phase. The request's own timer times it; the agent's 4 s idle timeout closes it only while it waits in the pool.
          req.on('socket',s=>{if(this.socketPins.get(s)!==pinned||!s.remoteAddress||canonicalIp(s.remoteAddress)!==pinned){req.destroy(new PolicyError('connection-address-mismatch'));return;}reused=this.servedSockets.has(s);this.servedSockets.add(s);if(reused){this.connectionsReused++;const o=this.originControl.peek(url);if(o)o.connectionsReused++;timings.connectionReused=true;}if(phase==='connect'||phase==='tls')phaseStart('headers');});
          // Before its connection is handed over (connect, TLS) the request has no socket, so ending it also ends the connection being opened, with the same error.
          const end=(e:Error)=>{req.destroy(e);if(hooks.socket&&!hooks.socket.destroyed)hooks.socket.destroy(e);};
          const cancel=()=>end(new PolicyError(this.cause(signal)));signal.addEventListener('abort',cancel,{once:true});
          const timer=this.limitTimer(this.config.timeoutMs,()=>end(new PolicyError('request-timeout')));
          req.on('error',e=>fail(e));if(signal.aborted){cancel();return;}if(body)req.write(body);req.end();
        });}catch(e){if((e as {replay?:boolean}).replay&&!replayed){replayed=true;delete timings.connectionReused;delete timings.headersMs;delete timings.bodyMs;this.connectionReplays++;const o=this.originControl.peek(url);if(o)o.connectionReplays++;reserved=false;this.release();continue;}throw (e as {original?:Error}).original||e;}finally{delete hooks.connected;delete hooks.ready;}
      }
      timings.totalMs=Date.now()-entered;result.resource={url,attemptId,timings,status:result.status>=400?'http-error':result.status>=300?'redirect':'downloaded',code:result.status,bytes:result.body.length,partial:result.partial,chain,kind,analysis:'pending',requestHeaderNames:Object.keys(allowed).sort(),contentType:String(result.headers['content-type']||''),httpDisposition:httpDisposition(result.status,result.headers)};this.onResource(result.resource);if(this.blockMonitor&&!this.blocked)this.observeBlock({status:result.status,disposition:httpDisposition(result.status,result.headers,result.body.subarray(0,16384).toString('latin1')),retryAfter:result.headers['retry-after']!==undefined});
      if(cacheable&&!result.partial)this.store(url,result,allowed);
      if(result.status===429||result.status===503){const value=String(result.headers['retry-after']||''),seconds=Number(value),retry=value?Number.isFinite(seconds)?Math.max(0,seconds*1000):Math.max(0,Date.parse(value)-Date.now()):2000,origin=this.originControl.current!;origin.pauseUntil=Math.max(origin.pauseUntil,this.originControl.now()+(Number.isFinite(retry)?retry:2000));this.onGap({code:'rate-limit',url,detail:'Rate limit/unavailability observed; backing off this origin without aggressive retries.',incomplete:true});}
      return result;
    }catch(e){if(e instanceof PolicyError&&e.recorded)throw e;
      // A cancelled or interrupted detector call inside preflight is a cancellation, never a network failure.
      const code=e instanceof PolicyError?e.code:e instanceof AnalysisInterrupted?(e.reason?.kind==='user-cancelled'?'cancelled':e.reason?.kind==='work-turn-limit'?'work-turn-limit':e.reason?.kind==='analysis-turn-limit'?'analysis-turn-limit':signal.aborted?this.cause(signal):'cancelled'):phase==='preflight'?'preflight-failure':'network-failure',network=['network-failure','dns-timeout','dns-empty','dns-invalid','connection-timeout','request-timeout','response-failure'].includes(code),interrupted=['cancelled','work-turn-limit','analysis-turn-limit'].includes(code)||code==='duration-limit'&&['dns','connect','tls','headers','body','preflight'].includes(phase);
      timings.totalMs=Date.now()-entered;if(/timeout/.test(code))timings.timeoutPhase=phase;if(['dns','connect','tls','headers','body'].includes(phase))(timings as Record<string,number|string|boolean>)[phase+'Ms']=Date.now()-phaseAt;
      if(network&&this.blockMonitor&&!this.blocked)this.observeBlock({reset:true});if(!network&&!interrupted&&code!=='preflight-failure')this.recordBlocked(url,code,chain,kind);
      else{const cause=interrupted?(e instanceof AnalysisInterrupted&&e.reason?{kind:e.reason.kind,origin:e.reason.origin||this.originControl.current?.origin}:this.abortCause(signal)):undefined;if(cause)timings.interruption=cause.kind;this.onResource({url,attemptId,timings,status:'failed',analysis:'failed',bytes:received,partial:received>0,chain,kind,reason:code});this.onGap({code,url,attemptId,detail:code==='cancelled'?'Active request cancelled.':interrupted?`Request interrupted during ${phase} by ${cause?.kind||code}; the attempt was not completed.`:code==='preflight-failure'?'Local request screening did not finish; the request was never sent. Raw exception omitted.':'Network attempt failed during '+phase+'; timings distinguish local processing from network waits. A timeout does not establish a remote cause. Raw exception omitted.',incomplete:true,...(cause?{cause:{...cause,phase}}:{})});}
      const error=new PolicyError(code);error.recorded=true;throw error;}finally{unit.end();this.live.delete(attemptId);if(reserved)this.release();if(settleInflight){this.inflight.delete(url);settleInflight();}}
  }

  checkWorkBudget(){this.checkBudgetExceptCount();}
  /** A time limit this check finds reached by the clock is expired here, as its timer would, so the scan's or website's signal and stop cause agree with the error. */
  private checkBudgetExceptCount(){if(this.signal.aborted)throw new PolicyError(this.stopCause);if(this.remainingMs()<=0){this.expireReached(this.originControl.current?.origin);throw new PolicyError('duration-limit');}}
  /** Analysis runs detached from the request turn: only the project, the response's own origin and a fresh analysis turn can interrupt it. */
  async analyze(r:ResponseData,evidence='Unauthenticated HTTP response'):Promise<string>{
    let authorized=false;try{authorized=this.origins.has(new URL(r.url).origin);}catch{}
    if(!authorized)return this.analyzeTurn(r,evidence);
    const turn=new AbortController(),limit=this.config.analysisTurnMs??60000;
    if(this.originControl.excludeSharedWaits){
      // Mass mode: the turn's limit is charged only while the turn is not just waiting for shared analysis capacity; a timer that runs before the charged time reaches it is set again.
      const clock=new TurnClock(this.originControl);let timer:ReturnType<typeof setTimeout>|undefined;
      const arm=()=>{clearTimeout(timer);timer=undefined;if(clock.paused||clock.ended||turn.signal.aborted)return;const left=limit-clock.charged();if(left<=0){turn.abort({kind:'analysis-turn-limit',turn:'analysis'} satisfies AbortReason);return;}timer=setTimeout(arm,Math.max(1,left));timer.unref();};
      clock.onResume=arm;arm();
      try{return await this.originControl.run(r.url,()=>this.analyzeTurn(r,evidence),turn.signal,{inherit:false,turn:clock});}finally{clock.onResume=undefined;clearTimeout(timer);}
    }
    const timer=setTimeout(()=>turn.abort({kind:'analysis-turn-limit',turn:'analysis'} satisfies AbortReason),limit);timer.unref();
    try{return await this.originControl.run(r.url,()=>this.analyzeTurn(r,evidence),turn.signal,{inherit:false});}finally{clearTimeout(timer);}
  }
  private async analyzeTurn(r:ResponseData,evidence:string):Promise<string>{const start=this.originControl.now(),origin=this.originControl.current,metrics:AnalysisMetrics={engineMs:0,cacheHits:0,engineCalls:0,failures:new Set<string>(),url:r.url,attemptId:r.resource?.attemptId};try{this.checkBudgetExceptCount();return await this.evidence.detector.measure(metrics,()=>this.analyzeMeasured(r,evidence,metrics));}finally{if(origin)origin.analysisMs+=this.originControl.now()-start;}}
  private async analyzeMeasured(r:ResponseData,evidence:string,metrics:AnalysisMetrics){
    if(r.analyzed)return r.text||'';r.analyzed=true;const analysisStarted=Date.now();let interrupted:GapCause|undefined;const finishTiming=()=>{if(r.resource){r.resource.timings||={};r.resource.timings.analysisMs=Date.now()-analysisStarted;r.resource.timings.analyzedAt=Date.now();r.resource.timings.engineMs=metrics.engineMs;if(interrupted)r.resource.timings.interruption=interrupted.kind;r.resource.analyzers||={};const skipped=r.resource.analysis==='skipped';r.resource.analyzers.directText={status:r.resource.analysis==='analyzed'?'inspected':r.resource.analysis==='failed'?'failed':r.resource.analysis==='deferred'?'deferred':skipped?'unsupported':'not-attempted',reason:r.resource.reason,...(interrupted?{cause:interrupted}:{})};r.resource.analyzers.offlineEngine={status:this.evidence.detector.version==='unavailable'||skipped?'unsupported':metrics.failures.size?'incomplete':metrics.engineCalls||metrics.cacheHits||metrics.engineScreened?'inspected':interrupted?'deferred':'not-attempted',reused:metrics.cacheHits>0,reason:metrics.failures.size?'Offline engine failed during this inspection':interrupted?'Interrupted before the offline engine ran':skipped?r.resource.reason:undefined};}};try{
    if(r.status===304){if(r.resource){r.resource.analysis='skipped';r.resource.reason='not-modified-without-trusted-body';}this.onGap({code:'not-modified-without-body',url:r.url,detail:'304 response contains no trusted matching cached document. No previous analysis reused; resource coverage unknown. Refetch without conditional headers within current request limits.',incomplete:true});return '';}
    if(r.partial)this.onGap({code:'complete-document-unavailable',url:r.url,detail:'Download/decode was truncated. Retained prefix receives text detection; complete-document parser, JSON and module reconstruction are incomplete.',incomplete:true});
    // Interruptions are typed and separated from genuine detector exceptions. A turn-only interruption after a successful download defers the body instead of discarding it.
    const classify=(e:unknown,analyzer:'headers'|'text'):{interrupted:boolean;cause:GapCause}=>{if(e instanceof AnalysisInterrupted){const reason=e.reason||abortReason(this.signal)||this.abortCause()||{kind:'user-cancelled'};return {interrupted:true,cause:{kind:reason.kind,origin:(reason as AbortReason).origin||this.originControl.current?.origin,phase:e.phase,analyzer}};}if(e instanceof AnalysisFailure)return {interrupted:false,cause:{kind:e.code,phase:e.phase,analyzer}};return {interrupted:false,cause:{kind:'analysis-exception',analyzer}};};
    const interruption=(cause:GapCause):string=>{interrupted=cause;const live=!this.projectSignal.aborted&&!this.originControl.expired(r.url),deferrable=live&&cause.kind==='analysis-turn-limit'&&!r.resumed&&(this.config.analysisBacklogBytes??0)>0;if(r.resource){r.resource.analysis=deferrable?'pending':'deferred';r.resource.reason=deferrable?'analysis-deferred':'analysis-interrupted';if(r.resource.status==='downloaded'&&!deferrable)r.resource.status='failed';}if(deferrable){r.analyzed=false;throw new AnalysisDeferred(r,cause);}this.onGap({code:'analysis-interrupted',url:r.url,attemptId:r.resource?.attemptId,detail:`Analysis was interrupted (${cause.kind}${cause.phase?' during '+cause.phase:''}) after the body was downloaded; the body was not retained. Retry with fresh budgets.`,incomplete:true,cause});return '';};
    let headerFailed=false;try{await this.evidence.inspect(JSON.stringify(r.headers),r.url,r.chain,'Unauthenticated response headers');}catch(e){const c=classify(e,'headers');if(c.interrupted)return interruption(c.cause);headerFailed=true;this.onGap({code:'header-analysis-failure',url:r.url,attemptId:r.resource?.attemptId,detail:'Response headers downloaded, but detector analysis failed; raw exception withheld.',incomplete:true,cause:c.cause});}
    const decision=contentDecision(r.body,r.headers);
    if(decision.binary){if(r.resource){if(r.status>=200&&r.status<300)r.resource.status=headerFailed?'failed':'skipped';r.resource.analysis=headerFailed?'failed':'skipped';r.resource.reason=headerFailed?'header-analysis-failure':decision.reason;}return '';}
    try{r.text=decodeText(r.body,r.headers,r.partial);}catch{if(r.resource){if(r.status>=200&&r.status<300)r.resource.status='failed';r.resource.analysis='failed';r.resource.reason='text-decoding';}this.onGap({code:'text-decoding',url:r.url,detail:'Response text has unsupported or invalid encoding; inspection incomplete.',incomplete:true});return '';}
    if(r.resource){r.resource.httpDisposition=httpDisposition(r.status,r.headers,r.text);r.resource.contentHash=createHash('sha256').update(r.text).digest('hex');}
    try{await this.evidence.inspect(r.text,r.url,r.chain,r.status>=400?`Bounded HTTP ${r.status} error response; successful application content was unavailable`:evidence);
      if(r.resource){if(r.status>=200&&r.status<300)r.resource.status=headerFailed?'failed':'scanned';r.resource.analysis=headerFailed?'failed':'analyzed';r.resource.textBytes=Buffer.byteLength(r.text);if(headerFailed)r.resource.reason='header-analysis-failure';else if(r.resource.reason==='analysis-deferred')delete r.resource.reason;}return r.text;
    }catch(e){const c=classify(e,'text');if(c.interrupted)return interruption(c.cause);if(r.resource){if(r.status>=200&&r.status<300)r.resource.status='failed';r.resource.analysis='failed';r.resource.reason='detector-analysis-failure';}this.onGap({code:'detector-analysis-failure',url:r.url,attemptId:r.resource?.attemptId,detail:'Text was decoded, but detector analysis failed. Linked public resources can still be discovered; raw exception withheld.',incomplete:true,cause:c.cause});return r.text;}
    }finally{finishTiming();}
  }
  async get(url:string,chain:string[]=[],kind='http'):Promise<ResponseData>{
    const visited=new Set<string>();
    for(let i=0;i<6;i++){
      if(visited.has(url))throw new PolicyError('redirect-loop');visited.add(url);
      const request=async()=>{for(let retry=0;;retry++){const origin=this.originControl.current;try{const response=await this.one(url,{chain,kind});if([429,503].includes(response.status)){if(retry<(this.config.maxRetries||0)){if(origin)origin.retries++;await this.analyze(response).catch(e=>{if(!(e instanceof AnalysisDeferred))throw e;});await this.delay(Math.max(100,(origin?.pauseUntil||0)-this.originControl.now()));continue;}if(origin)origin.retryExhausted++;}return response;}catch(e){if(!(e instanceof PolicyError)||!['network-failure','dns-timeout','connection-timeout','request-timeout','response-failure'].includes(e.code))throw e;if(retry>=(this.config.maxRetries||0)){if(origin)origin.retryExhausted++;throw e;}if(origin)origin.retries++;await this.delay(Math.min(1000,250*2**retry));}}};
      const r:ResponseData=this.origins.has(new URL(url).origin)?await this.originControl.run(url,request):await request();
      // All bounded bodies/headers may disclose credentials. Successful artifact
      // confirmation remains a separate scanner decision, including SPA fallbacks.
      const redirect=[301,302,303,307,308].includes(r.status)&&typeof r.headers.location==='string';
      try{await this.analyze(r);}catch(e){if(!(e instanceof AnalysisDeferred)||!redirect)throw e;}
      if(redirect){
        const next=new URL(r.headers.location as string,url).href;chain=[...chain,url,'HTTP redirect'];url=next;continue;
      }
      return {...r,chain};
    }
    this.onGap({code:'redirect-limit',url,detail:'Redirect chain exceeded six hops.',incomplete:true});throw new PolicyError('redirect-limit');
  }
}
