import {FairScheduler,workPriority} from './scheduler.js';
import {workClass,resourceType,imageRendition} from './resource-types.js';
import { randomUUID,createHash } from 'node:crypto';
import * as cheerio from 'cheerio';
import { resolveScanConfig, normalizeUrl, applyWebsiteSizing, explicitWebsites } from './config.js';
import { describeProfile, coverageScope, profileAllocation, computerCaps, resourceUse, startEstimate, isRecommended, TRAFFIC_NOTES, HARD_CEILINGS, QUICK_SCRIPTS_PER_WEBSITE, LOW_IMPACT_LIMITS, COVERAGE_LABELS, coverageQueryVariants, type Computer } from './profiles.js';
import { longRunNote } from './presets.js';
import { readComputer } from './computer.js';
import { Detector, RULE_VERSION, AnalysisFailure, type AnalysisScope } from './detectors.js';
import { Evidence } from './evidence.js';
import { PolicyError, Transport, AnalysisDeferred, HEADER_PROFILE, PRODUCT_USER_AGENT, acceptLanguage, type ResponseData, type Resolver } from './transport.js';
import type { ScanConfig, ScanView, WorkItem, Gap, Resource, ScopeView, GapCause, Candidate, AnalysisView, DiscoveryView, ProfileView, Coverage, Traffic } from './types.js';
import { inspectBrowser } from './browser.js';
import { AnyMap, originalPositionFor } from '@jridgewell/trace-mapping';
import { decodeText } from './decoding.js';
import { references, extract, resolve as resolveReferences, extractionContextKey, isBareExtensionPath, DISCOVERY_VERSION, type Reference, type Extraction } from './discovery.js';
import { httpExplanation } from './response-status.js';
import { coverage, importantUnresolved } from './coverage.js';
import { BUILD } from './build-info.js';
import {SemanticPool,moduleGroups,GROUP_MARGIN_MS,VIEW_INSPECTION_MS,type SemanticSource,type SemanticResult,type SemanticView} from './semantic.js';
import {analysisTimeFactor,currentTimeFactor,scaleMs,type TimeFactor} from './machine-speed.js';
import {FifoBudget} from './fifo-budget.js';
import {TurnClock} from './origin-control.js';
import {registrableDomain,scopeSource,discoveredLimit,websiteHost} from './domain-scope.js';
import {applyAssessment} from './finding-assessment.js';
import {protectedHost} from './protected-hosts.js';
// w2-wire: optional recon collector (built in init when recon/rebuild output was requested); the CLI/desk write its result.
import { ReconCollector, scopeFromPolicy, type MapSink, type ReconLimits } from './recon/index.js';
import { programScope } from './program/settings.js';// w2-wire: program scope narrows the recon host lists.
import type { ParseCollector } from './mass/parse-collector.js';
export {isBareExtensionPath};
type SemanticOutcome={status:'inspected'|'incomplete'|'failed'|'deferred';reason?:string;cause?:GapCause;signature?:string;deterministic?:boolean};
const DETERMINISTIC_SEMANTIC=/^semantic-(?:parser-failure|jsx-mutation-unknown|mutation-budget|alias-mutation-budget|provenance-budget|source-limit|memory-ceiling)$/;
const AGGREGATE_GAPS=new Set(['quick-coverage-boundary','profile-query-variants','auto-origin-limit','scope','protected-host','browser-background-denied','asset-html-fallback','expected-asset-html-fallback','legacy-exact-origin-scope','discovery-reference-limit','bare-extension-literals']);
export class Scanner {
  retry?:import('./retry.js').RetryPlan;
  /** How this run was started (dashboard, queue, schedule, CLI…). Local metadata only: it never reaches targets, headers or browser contexts. */
  launch?:import('./types.js').RunLaunch;
  acquisitionMode:NonNullable<ScanView['acquisitionMode']>='external';
  id=randomUUID();state:ScanView['state']='ready';config:ScanConfig;detector:Detector;evidence:Evidence;transport:Transport;
  resources:Resource[]=[];limitations:Gap[]=[];queue:WorkItem[]=[];pages:string[]=[];
  startedAt?:string;endedAt?:string;private seen=new Set<string>();private variants=new Map<string,Set<string>>();private maps=0;
  stage='Ready';browserStatus:NonNullable<ScanView['browserStatus']>={requested:false,launch:false,runtimePages:0,isolation:'unverified'};
  private schedule=new FairScheduler(()=>this.queue,[]);private websiteWaiting:()=>(w:Pick<WorkItem,'url'>)=>boolean=()=>()=>false;private pageAttempts=0;private firstJavaScript?:number;firstBrowserDocument?:number;/* The browser's entry document goes out before a website's optional and low-value work (workPriority 2 and above): `browserHeld` lists the websites whose
   * explicit browser page has started and whose document has not been answered, `browserDue` (one pass of the scan loop) those whose explicit browser page starts in that pass. */
  private browserHeld=new Set<string>();private browserDue=new Set<string>();private browserReleased=()=>{};private routeFailures=new Map<string,number>();private imageGroups=new Map<string,Resource>();private skippedImageUrls=new Set<string>();
  stopReason='not-started';private discoveries=new Map<string,string[][]>();private deferred:WorkItem[]=[];
  /** Query-string variants skipped only by Low-impact's stated one-variant boundary: kept in the run data (uninspected, checkpoint frontier), never deferred, incomplete or retried. */
  private profileLimited:WorkItem[]=[];private profileSkipped=new Set<string>();private profileSkippedByPath=new Map<string,number>();
  private inventory=new Map<string,WorkItem>();private robotsDone=new Set<string>();private browserOriginsDone=new Set<string>();private browserPeak=0;
  private admissions=new Set<Promise<void>>();private admissionUrls=new Set<string>();private admissionTail:Promise<void>=Promise.resolve();
  browserAnalysis={capturedDebugger:0,reusedDebugger:0,ownedHelpers:0,verifiedMirrors:0};private modules=new Map<string,SemanticSource>();private moduleBytes=0;private documentMaps=new Map<string,Record<string,string>>();
  private moduleDocuments=new Map<string,string>();private moduleAliases=new Map<string,string>();
  private graph:NonNullable<ScanView['discoveryGraph']>['edges']=[];private semanticStats?:ScanView['semantic'];private analysisSpent=new Map<string,number>();
  /** Scope provenance for the report: where the effective scope came from, plus admitted roots that receive discovery priority. */
  scopeSource:ScopeView['source']='default';private admittedRoots=new Set<string>();
  /** Semantic outcome registry keyed by canonical module URL; aliases (including late ones) are applied from it. */
  private semanticOutcomes=new Map<string,SemanticOutcome>();private semanticEvidence=new Map<string,{candidate:Candidate;view:SemanticView;text:string;chain:string[];label?:string}[]>();private moduleVariants=new Map<string,number>();private moduleHashes=new Map<string,string>();
  private groupAttempts=new Map<string,{outcome:'completed'|'incomplete'|'failed'|'cancelled'|'timeout';sliceMs:number;attempts:number;deterministic:boolean}>();
  /** Bodies whose analysis was interrupted by a turn only; resumed once without a new request. */
  private backlog:{item:WorkItem;response:ResponseData;cause:GapCause;bytes:number;discoverKind:string;evidence?:string}[]=[];private backlogBytes=0;private backlogStats={resumed:0,deferred:0,dropped:0};
  private interruptions:Record<string,number>={};private analysisJobs=new Map<string,{jobs:number;reusedVerdicts:number;queueWaitMs:number;startupMs:number;workerMs:number;cleanupMs:number;viewInspectionMs:number;outcomes:Record<string,number>}>();private analysisActiveJobs=0;
  discoverySummary:DiscoveryView={rejected:{bareExtension:0,nonUrlContext:0,dottedIdentifier:0,glob:0,examples:[]},unresolved:0,observedOnly:0,fallbacks:{},reusedDiscoveries:0,syntax:{},sinks:{},windowed:0,referenceLimit:0};
  graphEdge(from:string,reference:string,context:string,kind:string,to?:string,status='candidate',extra:{certainty?:string;sink?:string;method?:string}={}){if(this.graph.length>=4000){this.gap({code:'discovery-graph-limit',detail:'4000 discovery edges retained; additional provenance omitted.',incomplete:true});return;}const key=from+'\0'+reference+'\0'+context;if(!this.graphKeys.has(key)){this.graphKeys.add(key);this.graph.push({from,to,reference,context,kind,status,...(extra.certainty?{certainty:extra.certainty}:{}),...(extra.sink?{sink:extra.sink}:{}),...(extra.method?{method:extra.method}:{})});}}
  private graphKeys=new Set<string>();
  /** Write the registered semantic outcome (or the live/terminal placeholder) to every record at this URL, including aliases. */
  applySemantic(url:string){const canonical=this.moduleAliases.get(url)||url,outcome=this.semanticOutcomes.get(canonical),alias=canonical!==url;for(const r of this.resources){if(r.url!==url)continue;r.analyzers||={};if(!this.config.semanticAnalysis){r.analyzers.semantic={status:'unsupported',reason:'Semantic analyzer disabled'};continue;}if(outcome)r.analyzers.semantic={status:outcome.status,reason:alias?'Shares '+canonical+(outcome.reason?': '+outcome.reason:''):outcome.reason,...(alias?{reused:true}:{}),...(outcome.cause?{cause:outcome.cause}:{})};else if(this.modules.has(canonical))r.analyzers.semantic=['running','ready'].includes(this.state)?{status:'not-attempted',reason:alias?'Exact text with matching import context; syntax analysis shares '+canonical:'Admitted; analysis pending',...(alias?{reused:true}:{})}:{status:'deferred',reason:'Run ended before analysis',...(alias?{reused:true}:{})};}}
  private replayEvidence(alias:string,canonical:string){const entries=this.semanticEvidence.get(canonical);if(!entries)return;for(const e of entries.slice(0,64)){const v=e.view,label=alias.includes('#debugger-')?'debugger mirror (exact captured/downloaded content)':v.label;this.evidence.add({...e.candidate,constituents:v.constituents.map(p=>p.url===canonical?{...p,url:alias,label}:p)},e.text,alias,[...(this.discoveries.get(alias)?.[0]||[]),'equivalent source','reconstructed constant'],label?'Exact runtime capture mirror; reconstructed locally':'Exact downloaded source with matching import context; reconstructed locally',label);}}
  addModule(text:string,url:string,label?:string,imports:Record<string,string>={},mirrorOf?:string){
    if(!this.config.semanticAnalysis){this.applySemantic(url);return;}
    // An alias stands for the exact text of its canonical module; both are compared with the new text before any shortcut.
    const existing=this.modules.get(url),aliasOf=this.moduleAliases.get(url),known=existing||(aliasOf!==undefined?this.modules.get(aliasOf):undefined);
    if(existing||aliasOf!==undefined){
      // Re-admission never resets a recorded outcome. Differing text at one URL (canonical or alias) gets a bounded variant key instead of silently winning or losing.
      if(!known||known.text===text){this.applySemantic(url);return;}
      const n=this.moduleVariants.get(url)||0;if(n>=2){this.gap({code:'semantic-module-variant',url,detail:'More than two differing texts were observed at one URL; later variants were not analyzed separately.',incomplete:true});this.applySemantic(url);return;}
      this.moduleVariants.set(url,n+1);const variant=url+'#variant-'+createHash('sha256').update(text).digest('hex').slice(0,8);this.gap({code:'semantic-module-variant',url,detail:'Differing text was observed at the same URL; each variant is analyzed under a bounded variant key.',incomplete:false});this.addModule(text,variant,label,imports,mirrorOf);this.applySemantic(url);return;
    }
    const mirror=mirrorOf&&this.modules.get(mirrorOf)?.text===text?this.modules.get(mirrorOf):undefined;const equivalent=mirror||(!/\b(?:import|export)\b/.test(text)?[...this.modules.values()].find(m=>new URL(m.url).origin===new URL(url).origin&&m.text===text&&JSON.stringify(m.imports||{})===JSON.stringify(imports)):undefined);
    if(equivalent){if(this.moduleAliases.size<1000){this.moduleAliases.set(url,equivalent.url);this.applySemantic(url);this.replayEvidence(url,equivalent.url);}else this.gap({code:'semantic-alias-limit',url,detail:'1000 equivalent source locations retained; further mirror attribution omitted.',incomplete:true});return;}
    const size=Buffer.byteLength(text);if(this.modules.size>=1000||[...this.modules.values()].filter(m=>new URL(m.url).origin===new URL(url).origin).length>=200||this.moduleBytes+size>this.config.maxAnalysisBytes!||[...this.modules.values()].filter(m=>new URL(m.url).origin===new URL(url).origin).reduce((n,m)=>n+Buffer.byteLength(m.text),0)+size>this.config.originAnalysisBytes!||size>this.config.maxModuleAnalysisBytes!){this.semanticOutcomes.set(url,{status:'incomplete',reason:'Complete-document admission limit',deterministic:true});this.applySemantic(url);this.gap({code:'semantic-source-limit',url,detail:'Complete-document admission reached the configured per-module/per-website/shared retained-source byte cap or 200 modules per website/1000 shared. Direct/chunked detection remains available.',incomplete:true});return;}
    this.moduleBytes+=size;this.modules.set(url,{url,text,label,imports});this.moduleHashes.set(url,createHash('sha256').update(text).digest('hex'));this.applySemantic(url);
  }
  private recordSemanticOutcome(url:string,outcome:SemanticOutcome){this.semanticOutcomes.set(url,outcome);this.applySemantic(url);for(const [alias,canonical]of this.moduleAliases)if(canonical===url)this.applySemantic(alias);}
  private async reconstruct(origin:string){if(!this.config.semanticAnalysis){this.gap({code:'semantic-disabled',detail:'Constant propagation and cross-module reconstruction disabled.',incomplete:true});return;}const groups=moduleGroups([...this.modules.values()]).filter(g=>g.some(m=>new URL(m.url).origin===origin));if(!groups.length)return;
    const result:SemanticResult={views:[],gaps:[],resources:[],stats:{modules:0,nodes:0,views:0,elapsedMs:0}};
    const allocation=this.transport.originControl.get(origin).budget.effective.analysisMs;const stats=this.analysisStatsFor(origin);
    for(const group of groups){const signature=origin+':'+createHash('sha256').update(group.map(m=>m.url+'|'+(this.moduleHashes.get(m.url)||'')+'|'+JSON.stringify(m.imports||{})).sort().join('\n')).digest('hex');
      const remaining=allocation-(this.analysisSpent.get(origin)||0),slice=Math.min(scaleMs(this.config.semanticSliceMs!,this.timeFactor.factor),Math.max(0,remaining));
      // Known verdicts are not re-parsed: completed, deterministic or already timed out at this slice. A turn cancellation is retried once.
      const prior=this.groupAttempts.get(signature);if(prior&&(prior.outcome==='completed'||prior.deterministic||prior.outcome==='timeout'&&prior.sliceMs>=slice||prior.outcome==='cancelled'&&prior.attempts>=2)){stats.reusedVerdicts++;continue;}
      if(remaining<=0){for(const m of group)if(!this.semanticOutcomes.has(m.url))this.recordSemanticOutcome(m.url,{status:'incomplete',reason:'Website analysis time allocation exhausted',cause:{kind:'analysis-allocation-exhausted',origin,analyzer:'semantic'}});result.gaps.push({url:group[0].url,code:'semantic-website-budget',detail:'Website static analysis time allocation exhausted; downloaded dependency groups remain unknown. Effective and maximum allocations are in the website dashboard.'});continue;}
      this.transport.checkWorkBudget();const skip:Record<string,string>={};for(const m of this.modules.values()){const o=this.semanticOutcomes.get(m.url);if(o?.deterministic&&o.status!=='inspected')skip[this.moduleHashes.get(m.url)||'']=o.reason||o.status;}
      const at=performance.now(),queueWait=Math.max(0,at-Math.max(...group.map(m=>this.moduleAdmittedAt.get(m.url)||at)));this.analysisActiveJobs++;let r:SemanticResult;try{r=await this.pool.run(group,this.transport.signal,Math.min(this.transport.remainingMs(),remaining,slice+scaleMs(GROUP_MARGIN_MS,this.timeFactor.factor)),{sliceMs:slice,memoryMb:Math.floor(this.caps.analysisMemoryMb/this.caps.analysisWorkers),maxMemoryMb:this.caps.analysisMemoryMb,skip,sharedWait:()=>this.transport.originControl.sharedWait('parser'),sharedHold:()=>this.transport.originControl.sharedHold()});}finally{this.analysisActiveJobs--;}
      // The allocation is charged from the moment the job holds a parser worker (startup, parsing, propagation, cleanup). The wait for a free worker or for analysis memory that
      // other analysis holds (a detector's large-text inspection, another website's parser) is queue wait: on a slow or small computer it would otherwise use up the allocation unparsed.
      const elapsed=performance.now()-at,poolWait=Math.min(elapsed,Math.max(0,r.stats.queueWaitMs||0)),charged=elapsed-poolWait;this.analysisSpent.set(origin,(this.analysisSpent.get(origin)||0)+charged);
      stats.jobs++;stats.queueWaitMs+=queueWait+poolWait;stats.startupMs+=r.stats.startupMs||0;stats.workerMs+=r.stats.workerMs??r.stats.elapsedMs;stats.cleanupMs+=r.stats.cleanupMs||0;
      result.views.push(...r.views);result.gaps.push(...r.gaps);const reported:NonNullable<SemanticResult['resources']>=r.resources||group.map(m=>({url:m.url,status:'incomplete' as const,reason:'Worker did not complete'}));result.resources!.push(...reported);for(const k of ['modules','nodes','views','elapsedMs'] as const)result.stats[k]+=r.stats[k];
      const codes=r.gaps.map(g=>g.code),cancelled=codes.includes('semantic-cancelled'),timeout=codes.includes('semantic-time-limit'),failed=codes.includes('semantic-worker-failure'),deterministicGroup=reported.every(x=>x.status==='inspected'||x.deterministic)&&!cancelled&&!timeout&&!failed;
      for(const m of group){const x=reported.find(o=>o.url===m.url),status=x?.status||'incomplete',deterministic=x?.deterministic??(status==='inspected'||status==='failed');const cause:GapCause|undefined=cancelled?{...(this.transport.abortCause()||{kind:'user-cancelled'}),analyzer:'semantic'}:timeout?{kind:'semantic-time-limit',origin,analyzer:'semantic'}:failed?{kind:'worker-failure',origin,analyzer:'semantic'}:undefined;if(status==='inspected'||!this.semanticOutcomes.get(m.url)||this.semanticOutcomes.get(m.url)!.status!=='inspected')this.recordSemanticOutcome(m.url,{status,reason:x?.reason||(r.resources?undefined:'Worker did not complete'),signature,deterministic,...(cause?{cause}:{})});stats.outcomes[status]=(stats.outcomes[status]||0)+1;}
      const completed=reported.every(x=>x.status==='inspected')&&!r.gaps.some(g=>/budget|limit|cancel|failure|unresolved/.test(g.code));
      this.groupAttempts.set(signature,{outcome:completed?'completed':cancelled?'cancelled':timeout?'timeout':failed?'failed':'incomplete',sliceMs:slice,attempts:(prior?.attempts||0)+1,deterministic:!completed&&deterministicGroup});
      if(cancelled){const kind=this.transport.abortCause()?.kind||'user-cancelled';this.interruptions[kind]=(this.interruptions[kind]||0)+1;}
    }
    const analyzedUrls=new Set(result.resources!.map(r=>r.url));this.limitations=this.limitations.filter(g=>!(g.url&&analyzedUrls.has(g.url)&&g.code==='semantic-import-unresolved'));
    const prev=this.semanticStats||{modules:0,nodes:0,views:0,elapsedMs:0};this.semanticStats={modules:prev.modules+result.stats.modules,nodes:prev.nodes+result.stats.nodes,views:prev.views+result.stats.views,elapsedMs:prev.elapsedMs+result.stats.elapsedMs};for(const g of result.gaps)this.gap({...g,incomplete:true});
    let joined='';const segments=result.views.map(v=>{const start=joined.length;joined+=v.text+'\n/* '+ '_SEMANTIC_BOUNDARY_'.repeat(32)+' */\n';return {v,start,end:start+v.text.length};});if(!joined)return;
    this.transport.checkWorkBudget();const candidates:import('./types.js').Candidate[]=[];const viewBudget=scaleMs(VIEW_INSPECTION_MS,this.timeFactor.factor),deadline=Date.now()+viewBudget,viewsAt=performance.now();
    const prioritized=[...segments].sort((a,b)=>Number(!a.v.sink)-Number(!b.v.sink)||Number(!/key|token|secret|password|authorization/i.test(a.v.text))-Number(!/key|token|secret|password|authorization/i.test(b.v.text)));
    for(let i=0;i<prioritized.length;i++){this.transport.checkWorkBudget();if(Date.now()>deadline){this.gap({code:'semantic-format-budget',detail:`Reconstructed-view website inspection exceeded ${viewBudget} ms; ${prioritized.length-i} views remain uninspected by context rules. Offline batch inspection remains separate.`,incomplete:true});break;}const s=prioritized[i];
      // A view over 128 KiB is inspected in a budgeted analysis process (the scan's analysis memory), never by an unbounded whole-document parse on the main thread.
      let found:Candidate[];try{found=await this.detector.inspectBounded(s.v.text,this.analysis);}catch(e){if(!(e instanceof AnalysisFailure))throw e;this.gap({code:'detector-analysis-failure',url:s.v.url,detail:'A reconstructed view was built, but its detector analysis failed; other views and the joined-view inspection are kept.',incomplete:true});continue;}
      candidates.push(...found.map(c=>({...c,index:s.start+c.index})));if(i%16===15)await new Promise<void>(resolve=>setImmediate(resolve));}
    for(const c of await this.detector.inspect(joined,this.analysis))if(!candidates.some(x=>x.value===c.value&&x.index===c.index&&x.category===c.category))candidates.push(c);
    stats.viewInspectionMs+=performance.now()-viewsAt;
    for(const c of candidates){if(this.transport.signal.aborted)break;const segment=segments.find(s=>c.index>=s.start&&c.index<s.end);if(!segment||c.index+c.original.length>segment.end)continue;const v=segment.v,source=this.modules.get(this.moduleAliases.get(v.url)||v.url)!;const candidate={...c,index:v.start,original:v.original,transformations:[...new Set([...v.steps,...c.transformations])],constituents:v.constituents,sink:v.sink};this.evidence.add(candidate,source.text,v.url,[...(this.discoveries.get(v.url)?.[0]||[]),'reconstructed constant',...(v.sink?[v.sink]:[])],'Unambiguous static reconstruction from publicly downloaded sources',v.label);const stored=this.semanticEvidence.get(v.url)||[];if(stored.length<256){stored.push({candidate,view:v,text:source.text,chain:this.discoveries.get(v.url)?.[0]||[],label:v.label});this.semanticEvidence.set(v.url,stored);}let replayed=0;for(const [alias,canonical]of this.moduleAliases){if(canonical!==v.url)continue;if(replayed++>=64){this.gap({code:'semantic-alias-occurrence-limit',detail:'Equivalent source replay bounded to 64 occurrences per finding view; remaining locations retained in resource audit.',incomplete:true});break;}const label=alias.includes('#debugger-')?'debugger mirror (exact captured/downloaded content)':v.label;this.evidence.add({...candidate,constituents:v.constituents.map(p=>p.url===canonical?{...p,url:alias,label}:p)},source.text,alias,[...(this.discoveries.get(alias)?.[0]||[]),'equivalent source','reconstructed constant'],label?'Exact runtime capture mirror; reconstructed locally':'Exact downloaded source with matching import context; reconstructed locally',label);}}
  }
  private moduleAdmittedAt=new Map<string,number>();
  private analysisStatsFor(origin:string){let s=this.analysisJobs.get(origin);if(!s){s={jobs:0,reusedVerdicts:0,queueWaitMs:0,startupMs:0,workerMs:0,cleanupMs:0,viewInspectionMs:0,outcomes:{}};this.analysisJobs.set(origin,s);}return s;}
  readonly pool:SemanticPool;
  /** False when the parser pool is a mass run's shared pool (mass-run.ts buildShared): the run, not the target, ends its workers. */
  private ownsPool:boolean;
  /** The analysis memory setting (MiB) as one budget for every analysis heap of this scan: parser workers and the detector's large-text workers. */
  readonly analysisMemory:FifoBudget;
  /** This scan's side of every detector call: its analysis memory, its current origin signal and its own gap callbacks. A detector shared by concurrent scans reports each call only to the scan that made it. */
  readonly analysis:AnalysisScope;
  /** Codes of this scan's own offline-engine failures (interruptions excluded), from its scope; a shared detector's `issues` also hold other scans' failures. */
  readonly engineFailures=new Set<string>();
  /** Profile, sizing basis and start estimate; the live view adds the current shared caps, admitted websites and (Quick) what was not examined. */
  private profileBase!:Omit<ProfileView,'sizing'|'completion'|'notExamined'>&{sizing:Pick<ProfileView['sizing'],'explicitWebsites'|'discoveredLimit'|'perWebsite'>};
  /** Quick check: first-party scripts admitted per website, and discovered URLs outside the target set by category (never requested). */
  private quickScripts=new Map<string,Set<string>>();private quickSkips=new Map<string,{urls:Set<string>;examples:string[]}>();private projectTimer?:ReturnType<typeof setTimeout>;private timerClosed=false;
  /** This computer when the scan started (profile scans) and the local resource caps it allows: analysis workers, analysis memory and browser websites at once. */
  readonly computer?:Computer;readonly caps:ReturnType<typeof computerCaps>;
  /** The analysis time factor (machine-speed.ts): its measurement starts with the first scanner of the process (off the scan's critical path) and is fixed when the scan starts. */
  timeFactor:TimeFactor=currentTimeFactor();private timeFactorPending=analysisTimeFactor();
  /** w2-wire: recon lists collector; present only when the caller requested recon or source rebuild output. Built in init(), read by the CLI/desk after run(). */
  recon?:ReconCollector;private reconRequest?:{limits?:Partial<ReconLimits>;rebuilder?:MapSink};
  constructor(input:Partial<ScanConfig>,options:{detector?:Detector;resolver?:Resolver;deniedPorts?:number[];correlationKey?:Buffer;computer?:Computer;analysisMemory?:FifoBudget;semanticPool?:SemanticPool;excludeSharedWaits?:boolean;parseCollector?:ParseCollector;recon?:{limits?:Partial<ReconLimits>;rebuilder?:MapSink}}={}){
    this.scopeSource=scopeSource(input);this.config=resolveScanConfig(input);this.reconRequest=options.recon;this.parseCollector=options.parseCollector;
    // Ready options lower (never raise) their local resource use on a small or busy computer; the configuration keeps the option values, the scan runs with the caps.
    this.computer=options.computer??(this.config.coverage?readComputer():undefined);this.caps=computerCaps(this.config,this.computer);
    {const c=this.config,websites=explicitWebsites(c),limit=discoveredLimit(c),profile=c.coverage&&c.traffic?profileAllocation(c as ScanConfig&{coverage:Coverage;traffic:Traffic}):undefined;
      this.profileBase={...describeProfile(c),...(c.coverage&&c.traffic?coverageScope(c.coverage,c.traffic):{examines:[],skips:[]}),trafficNote:c.traffic?TRAFFIC_NOTES[c.traffic]:'Legacy or custom settings apply as stored. Nothing hides the scan from the websites.',estimate:((e)=>{const long=longRunNote(c,e);return long?{...e,longRun:long}:e;})(startEstimate(c,websites,limit,this.computer)),
        sizing:{explicitWebsites:websites,discoveredLimit:limit,perWebsite:{pages:c.originMaxPages!,resources:c.originMaxResources!,bytes:c.originMaxTotalBytes!,decodedBytes:profile?profile.decodedBytes:c.maxDecodedTotalBytes,maps:c.originMaxMaps!,browserPages:c.originBrowserPages!,durationMs:c.originMaxDurationMs!,requestsPerSecond:c.originRequestsPerSecond!,concurrency:c.originConcurrency!}}};}this.schedule=new FairScheduler(()=>this.queue,this.config.urls,w=>this.blockedWork(w),()=>this.admittedRoots,()=>this.websiteWaiting());this.detector=options.detector||new Detector();
    if(!options.detector)this.detector.syntheticFixture=!!this.config.developmentFixtureOrigin&&[...this.config.urls.map(u=>new URL(u).origin),...this.config.relatedOrigins].every(o=>o===this.config.developmentFixtureOrigin);
    this.evidence=new Evidence(this.detector,options.correlationKey,this.config.sensitiveFields);this.browserStatus.requested=this.config.browser;
    // Every analysis call of this scan passes its scope (`inspect(text, this.analysis)`: this budget, this scan's signal and gap callbacks), so a detector shared by concurrent scans never holds a heap from another scan's budget
    // nor reports a limit or failure to another scan; a detector of its own also defaults to them.
    this.analysisMemory=options.analysisMemory??new FifoBudget(this.caps.analysisMemoryMb);if(!options.detector)this.detector.analysisMemory=this.analysisMemory;
    this.ownsPool=!options.semanticPool;this.pool=options.semanticPool??new SemanticPool(this.caps.analysisWorkers,Math.floor(this.caps.analysisMemoryMb/this.caps.analysisWorkers),this.analysisMemory);
    this.transport=new Transport(this.config,this.evidence,r=>{r.resourceType=resourceType(r);if(r.resourceType==='javascript'&&r.analysis==='analyzed'&&this.firstJavaScript===undefined)this.firstJavaScript=Date.now()-this.transport.started;r.discoveryChains=this.discoveries.get(r.url);try{if(/^https?:/.test(r.url)&&this.transport.isAuthorized(r.url))this.transport.originControl.get(r.url).budget.response(r);}catch{}if(this.resources.length<6000)this.resources.push(r);else this.gap({code:'audit-record-limit',detail:'Resource audit record limit reached; additional records omitted.',incomplete:true});if(this.modules.has(r.url)||this.moduleAliases.has(r.url)||this.semanticOutcomes.has(r.url))this.applySemantic(r.url);},g=>this.gap(g),options.resolver);
    // Mass mode: other targets share this process's analysis capacity, so this target's clocks do not run while it only waits for that capacity (OriginControl.excludeSharedWaits).
    if(options.excludeSharedWaits){const control=this.transport.originControl;control.excludeSharedWaits=true;control.onProjectResume=()=>this.armProjectTimer();}
    this.analysis={memory:this.analysisMemory,signal:()=>this.transport.signal,sharedWait:()=>this.transport.originControl.sharedWait(),sharedHold:()=>this.transport.originControl.sharedHold(),turnOwner:()=>{const control=this.transport.originControl;return control.excludeSharedWaits&&control.currentCause()==='preflight'?this.transport:undefined;},onLimit:detail=>this.gap({code:'decoded-inspection-limit',detail,incomplete:true}),onFailure:(code,context)=>{if(code!=='engine-cancelled')this.engineFailures.add(code);if(context?.cause){const kind=context.cause.kind;this.interruptions[kind]=(this.interruptions[kind]||0)+1;}this.gap({code,url:context?.url,attemptId:context?.attemptId,detail:code==='engine-cancelled'?'Offline inspection was interrupted before it finished; the cause is recorded. Direct evidence is retained.':'Offline inspection did not finish for this origin; direct evidence is retained.',incomplete:true,...(context?.cause?{cause:context.cause}:{})});}};
    this.evidence.analysis=this.analysis;if(!options.detector){const own=this.detector,scope=this.analysis;own.signalProvider=()=>this.transport.signal;own.onLimit=detail=>scope.onLimit!(detail);own.onFailure=(code,context)=>scope.onFailure!(code,context);}
    for(const p of options.deniedPorts||[])this.transport.deniedPorts.add(p);
    this.transport.onOriginAdmitted=(origin,authorization)=>{
      // Profile scans size shared caps per admitted website (bounded by the hard maxima); the per-website allocation is the admitted origin's own budget.
      if(this.config.coverage!==undefined){applyWebsiteSizing(this.config,this.transport.authorizedOrigins.length);this.armProjectTimer();}
      const chain=authorization.type==='same-registrable-domain'?[authorization.seed,authorization.discoveredFrom,'same-registrable-domain discovery']:[];
      this.admittedRoots.add(origin+'/');this.admittedRoots.add(origin+'/robots.txt');
      this.enqueue('/robots.txt',origin,0,chain,'robots');this.enqueue(origin+'/',origin,0,chain,'page');
    };
    this.evidence.startTriage(()=>this.gap({code:'finding-triage-worker',detail:'Parallel finding triage worker unavailable; offline classification completed in the scan process.',incomplete:false}));
  }
  gap(g:Gap){if(AGGREGATE_GAPS.has(g.code)&&g.count!==undefined){const existing=this.limitations.find(x=>x.code===g.code&&x.url===g.url&&(g.origin===undefined||x.origin===g.origin));if(existing){Object.assign(existing,g);return;}}else if(g.code==='auto-origin-limit'){const existing=this.limitations.find(x=>x.code===g.code);if(existing){Object.assign(existing,g);return;}}if(g.cause&&['analysis-interrupted','engine-cancelled'].includes(g.code))this.interruptions[g.cause.kind]=(this.interruptions[g.cause.kind]||0)+(g.code==='engine-cancelled'?0:1);g={...g,origin:g.origin||this.transport?.originControl.current?.origin};if(this.limitations.length===1999){this.limitations.push({code:'coverage-record-limit',detail:'Further individual coverage records omitted because the audit limit was reached.',incomplete:true});return;}if(this.limitations.length<1999&&!this.limitations.some(x=>x.code===g.code&&x.url===g.url&&x.origin===g.origin&&x.detail===g.detail&&x.attemptId===g.attemptId))this.limitations.push(g);}
  /** Fixes this scan's analysis time factor when it starts and rescales the website budgets created before then (run() and the local-artifact scan call it). */
  async resolveTimeFactor(){this.timeFactor=await this.timeFactorPending;this.transport.originControl.setTimeFactor(this.timeFactor.factor);return this.timeFactor;}
  async init(companyFile?:string){await this.detector.init(companyFile);this.initRecon();}
  /** w2-wire: build the recon collector once the scope policy and detector are ready. classify = scan scope; secretFilter = detector (fail-closed so a flagged value is never listed).
   * w2-mass: public and idempotent, because a mass run initialises its shared detector once and skips init() per scan, then calls this directly (src/cli/mass-run.ts). */
  initRecon(){
    if(this.reconRequest&&!this.recon){
      // classify = scan scope; a program's out-of-scope rules narrow it further, so a host inside the entered domain but outside the program scope is listed out-of-scope (program-out-of-scope), matching how the run skips it.
      const base=scopeFromPolicy(this.transport.scope),prog=this.config.program?programScope(this.config.program):undefined;
      const classify=prog?(url:string)=>{const d=base(url),scope=typeof d==='string'?d:d.scope;return scope==='in-scope'&&!prog.allows(url)?{scope:'out-of-scope' as const,reason:'program-out-of-scope'}:d;}:base;
      // secretFilter = detector (fail-closed so a flagged value is never listed).
      this.recon=new ReconCollector({classify,secretFilter:v=>{try{return this.detector.inspectWindowed(v,false,this.analysis).length>0;}catch{return true;}},...(this.reconRequest.rebuilder?{rebuilder:this.reconRequest.rebuilder}:{}),...(this.reconRequest.limits?{limits:this.reconRequest.limits}:{})});
    }}
  /** The project deadline follows the current shared duration cap; profile scans can raise it when a website is admitted. */
  /** The scan's limit counts as reached only when the clock reads it (Node can run a timer up to 1 ms early, and a website admitted meanwhile can extend the limit); until then the timer is set again for the time still left. */
  private armProjectTimer(){clearTimeout(this.projectTimer);if(this.state!=='running'||this.timerClosed||this.transport.originControl.projectPaused)return;this.projectTimer=setTimeout(()=>{if(!this.transport.expireReached())this.armProjectTimer();},Math.max(1,this.transport.projectRemainingMs()));}
  /** Quick check's target set per website: entry documents, robots.txt, first-party scripts and modules (bounded; entry-document bundles are discovered first), source maps, framework manifests,
   * the web app manifest, referenced configuration files, deployment paths and explicitly supplied URLs. Replayed earlier-deployment assets count only when they are scripts, source maps or configuration. Anything else is recorded as not examined: never requested, never counted as unfinished. */
  private quickTarget(url:string,kind:string,certainty?:WorkItem['certainty']):boolean{
    if(this.config.urls.includes(url)||this.admittedRoots.has(url)||this.retry?.selected.some(w=>w.url===url)||['robots','deep','baseline','map','map-section','framework-manifest','manifest'].includes(kind))return true;
    const u=new URL(url),variants=this.variants.get(u.origin+u.pathname);let category:string;
    if(variants&&!variants.has(u.search)&&variants.size>=this.config.queryVariants)category='Query-string variants';
    else if(kind==='page')category='Linked pages';else if(kind==='sitemap')category='Sitemaps';else if(kind==='map-guess')category='Adjacent source-map guesses';
    else if(kind==='asset-hint'||certainty==='heuristic')category='Heuristic URL hints';
    else{const type=resourceType({url,kind});
      if(type==='configuration'||type==='source-map')return true;
      if(type==='javascript'){const bound=u.origin+(kind==='stale-asset'?' replay':'');let scripts=this.quickScripts.get(bound);if(!scripts){scripts=new Set();this.quickScripts.set(bound,scripts);}if(scripts.has(url))return true;if(scripts.size<QUICK_SCRIPTS_PER_WEBSITE){scripts.add(url);return true;}category='Scripts beyond the per-website bound';}
      else category=kind==='stale-asset'?'Earlier-deployment assets other than scripts, source maps and configuration':'Stylesheets, fonts and other assets';}
    let e=this.quickSkips.get(category);if(!e){e={urls:new Set(),examples:[]};this.quickSkips.set(category,e);}
    if(!e.urls.has(url)&&e.urls.size<5000){e.urls.add(url);if(e.examples.length<5)e.examples.push(url);}
    return false;
  }
  private admitDiscovery(known:WorkItem,base:string,admitted:()=>void){
    const {url,chain,kind}=known;
    if(this.admissionUrls.has(url))return;this.admissionUrls.add(url);
    if(this.admissions.size>=6000){this.admissionUrls.delete(url);this.defer(known,'origin-admission-queue-limit');this.gap({code:'origin-admission-queue-limit',url,detail:'Automatic origin validation queue is bounded to 6000 discovered URLs; remaining work was not admitted.',incomplete:true});return;}
    // DNS admission runs alongside scan work, with a bounded serial DNS queue. The chain is built
    // outside every origin turn, so the discovering origin's deadline cannot fail other hosts' admission.
    const task=this.transport.originControl.detached(()=>this.admissionTail.then(async()=>{
      try{if(this.transport.projectSignal.aborted)throw new PolicyError(this.transport.stopCause);await this.transport.preflight(url,'GET',{},'',chain,base);admitted();}
      catch(e){const code=e instanceof PolicyError?e.code:'dns-failure';this.transport.recordBlocked(url,code,chain,kind);if(code==='auto-origin-limit')this.defer(known,code);}
    }).finally(()=>{this.admissions.delete(task);this.admissionUrls.delete(url);}));
    this.admissionTail=task;this.admissions.add(task);
  }
  private rejectHint(reason:keyof DiscoveryView['rejected']&string,raw:string){const r=this.discoverySummary.rejected;if(reason!=='examples')(r as any)[reason]++;if(r.examples.length<8)r.examples.push(raw.slice(0,64));}
  enqueue(raw:string,base:string,depth:number,chain:string[],kind='asset',discoveredFrom=base,meta:{certainty?:WorkItem['certainty'];context?:string}={}){
    raw=raw.trim();if(!raw||/^[#`]|[<>`{}]/.test(raw))return;
    if(raw.startsWith('data:')){if(kind==='map')void this.inlineMap(raw,base,chain);return;}
    if(/^(?:javascript|mailto|tel|blob|about):/i.test(raw))return;
    let url:string;try{url=new URL(raw,base).href;}catch{return;}
    // Local inspection preserves candidates even if normalization or scope later rejects them.
    for(const c of this.detector.inspectWindowed(url,false,this.analysis))this.evidence.add(c,url,base,chain,'Discovered URL in public content; no request yet');
    if(/^wss?:/i.test(url)){
      if(protectedHost(url)){this.transport.recordBlocked(url,'protected-host',chain,kind);return;}
      this.transport.recordBlocked(url,'websocket-disabled',chain,kind);
      const counterpart=new URL(url);counterpart.protocol=counterpart.protocol==='wss:'?'https:':'http:';
      // Only the corresponding HTTP(S) origin is eligible. The WebSocket URL,
      // including its authentication fields, is screened; its path is never fetched.
      if(!this.transport.isAuthorized(counterpart.href)&&this.transport.sameDomainSeed(counterpart.href))this.admitDiscovery({url:counterpart.href,depth,chain,kind:'websocket-origin',enqueuedAt:Date.now()},discoveredFrom,()=>{});
      return;
    }
    try{const parsed=new URL(url);if(parsed.username||parsed.password){const value=parsed.password||parsed.username;this.evidence.add({value,original:value,index:url.indexOf(value),rule:'url-userinfo',provider:'Unknown',category:'suspicious',severity:'medium',confidence:'high',reasons:['Discovered URL contains user credentials; it was never requested.'],transformations:[]},url,base,chain,'Locally observed URL user information in public content');this.transport.recordBlocked(url,protectedHost(url)?'protected-host':'credential-in-request',chain,kind);return;}}catch{}
    try{url=normalizeUrl(url);}catch{this.transport.recordBlocked(url,'invalid-url',chain,kind);return;}
    // Hard rule: a government, military, intelligence or law-enforcement host is refused before images, scope, inventory, admission or DNS (counted, never
    // incomplete). The URL string itself was already inspected locally above.
    if(protectedHost(url)){this.transport.recordBlocked(url,'protected-host',chain,kind);return;}
    // A discovered URL (link, script, map, redirect target) whose host is not a website host is refused before images, scope, admission or DNS, the same rule
    // new input follows (websiteHost); it is counted as invalid-url, never requested.
    if(!websiteHost(new URL(url).hostname)){this.transport.recordBlocked(url,'invalid-url',chain,kind);return;}
    // Image bodies are never requested on any origin, so their bounded family record comes before scope classification.
    if(this.skipImage(url,chain,kind))return;
    // Classification happens before the inventory, so excluded third-party or out-of-scope URLs take no inventory or audit slots.
    const inDomain=this.transport.isAuthorized(url)||!!this.transport.sameDomainSeed(url);
    // Program scope (2.8): a URL outside it (another origin, or a path outside a URL-prefix rule) is recorded as excluded and takes no inventory slot; preflight checks every request again.
    if(!inDomain||this.transport.scope.program&&!this.transport.scope.program.allows(url)){this.transport.recordBlocked(url,'scope',chain,kind);return;}
    if(['asset-hint','asset'].includes(kind)&&meta.certainty!=='confirmed'&&meta.certainty!=='contextual'&&isBareExtensionPath(url)){this.rejectHint('bareExtension',raw);this.graphEdge(base,raw,'Bare extension literal rejected as a URL hint; no request made',kind,url,'rejected',{certainty:'heuristic'});this.gap({code:'bare-extension-literals',detail:`${this.discoverySummary.rejected.bareExtension} bare extension literals (such as ".json" or ".woff") were not treated as URLs; only contextual uses are acquired.`,incomplete:false,count:this.discoverySummary.rejected.bareExtension,examples:[...this.discoverySummary.rejected.examples]});return;}
    // Quick check never requests, admits or inventories work outside its target set.
    if(this.config.coverage==='quick'&&!this.quickTarget(url,kind,meta.certainty))return;
    const known:WorkItem={url,depth,chain:chain.slice(-18),kind,enqueuedAt:Date.now(),...(meta.certainty?{certainty:meta.certainty}:{}),...(meta.context?{context:meta.context}:{})};
    if(!this.inventory.has(url)){if(this.inventory.size<6000)this.inventory.set(url,known);else{this.gap({code:'inventory-limit',detail:'Known-resource inventory is bounded to 6000 URLs; additional discovery is not included in coverage counts.',incomplete:true});return;}}
    else if(meta.certainty&&(meta.certainty!=='heuristic'||!this.inventory.get(url)!.certainty))this.inventory.get(url)!.certainty=meta.certainty==='heuristic'?this.inventory.get(url)!.certainty||'heuristic':meta.certainty;
    if(['map','map-guess'].includes(kind)&&this.config.maxMaps===0){this.defer(known,'source-maps-disabled');this.gap({code:'source-maps-disabled',url,detail:'Source-map acquisition disabled by the configured map limit.',incomplete:true});return;}
    const paths=this.discoveries.get(url)||[];if(paths.length<40&&!paths.some(p=>JSON.stringify(p)===JSON.stringify(chain)))paths.push(chain.slice(-18));this.discoveries.set(url,paths);
    for(const r of this.resources)if(r.url===url)r.discoveryChains=paths;
    if(this.retry?.excluded.includes(url)){this.graphEdge(base,url,'Focused retry excluded a previously successful static URL',kind,url,'retry-excluded');return;}if(this.seen.has(url)||this.profileSkipped.has(url)||this.deferred.some(w=>w.url===url))return;
    if(!this.transport.isAuthorized(url)){this.admitDiscovery(known,discoveredFrom,()=>this.enqueue(url,base,depth,chain,kind,discoveredFrom,meta));return;}
    this.transport.originControl.get(url).budget.discover(known);if(depth>this.config.maxDepth&&kind==='page'){this.defer(known,'crawl-depth');this.gap({code:'crawl-depth',url,detail:'Discovered page beyond configured depth.',incomplete:true});return;}
    const u=new URL(url),key=u.origin+u.pathname;let v=this.variants.get(key);if(!v){v=new Set();this.variants.set(key,v);}
    if(!v.has(u.search)&&v.size>=this.config.queryVariants){if(this.profileLimits(key,v.size)){this.profileLimit(known);return;}this.defer(known,'query-variants');this.gap({code:'query-variants',url,detail:'Query variation limit reached.',incomplete:true});return;}v.add(u.search);
    if(this.seen.size>=this.config.maxResources){const important=workPriority({url,kind},this.config.urls,this.admittedRoots)<2;const optional=important?this.queue.findIndex(w=>workPriority(w,this.config.urls,this.admittedRoots)>workPriority({url,kind},this.config.urls,this.admittedRoots)&&w.kind!=='robots'&&!this.config.urls.includes(w.url)):-1;if(optional>=0){const removed=this.queue.splice(optional,1)[0];this.seen.delete(removed.url);this.defer(removed,'displaced-by-important-resource');this.gap({code:'discovery-budget',url:removed.url,detail:'Queued optional or low-value work displaced by an important resource within the existing frontier limit.',incomplete:true});}else{this.defer(known,'discovery-budget');this.gap({code:'discovery-budget',detail:'Bounded frontier admission reached; important assets can displace queued optional or low-value work. Deferred URLs remain uninspected.',incomplete:true});return;}}
    this.seen.add(url);this.queue.push({...known,chain:chain.slice(-18)});
  }
  private inlineTasks:Promise<void>[]=[];
  async inlineMap(data:string,url:string,chain:string[]){
    const task=(async()=>{
      const match=/^data:application\/(?:json|octet-stream)(?:;charset=[^;,]+)?(;base64)?,([\s\S]+)$/i.exec(data);
      if(!match||data.length>this.config.maxResourceBytes*1.5){this.gap({code:'inline-map-invalid',url,detail:'Inline map invalid or exceeds encoded size limit.',incomplete:true});return;}
      try{const text=match[1]?Buffer.from(match[2],'base64').toString('utf8'):decodeURIComponent(match[2]);if(Buffer.byteLength(text)>this.config.maxResourceBytes)throw new Error('size');await this.map(text,url,[...chain,'inline source map']);}catch{this.gap({code:'inline-map-invalid',url,detail:'Inline map could not be fully decoded.',incomplete:true});}
    })();this.inlineTasks.push(task);await task;
  }
  private sourceUrl(name:string,sourceRoot:string,mapUrl:string):string|undefined{
    // Virtual webpack/vite paths are labels, not network targets. Network source
    // references must resolve within scope, and cannot contain path traversal.
    if(!name||name.length>2048||sourceRoot.length>2048||/^(?:webpack|vite|file|node|data|blob):/i.test(name)||/^(?:webpack|vite|file|node|data|blob):/i.test(sourceRoot))return;
    let decoded:string;try{decoded=decodeURIComponent(name+' '+sourceRoot);}catch{return;}
    const parents=(decoded.match(/(?:^|\/)\.\.(?=\/|\s|$)/g)||[]).length,available=new URL(mapUrl).pathname.split('/').filter(Boolean).length-1;
    if(parents>available||name.includes('\\')||sourceRoot.includes('\\')){this.gap({code:'source-traversal',url:mapUrl,detail:'Source reference climbs beyond the public URL root or uses a filesystem separator; retained as a label.',incomplete:true});return;}
    try{const base=sourceRoot?new URL(sourceRoot.endsWith('/')?sourceRoot:sourceRoot+'/',mapUrl).href:mapUrl;return new URL(name,base).href;}catch{return;}
  }
  async map(text:string,url:string,chain:string[],mapDepth=0,ancestors=new Set<string>()):Promise<any>{
    this.transport.checkWorkBudget();const owner=this.transport.originControl.get(url);owner.budget.discover({url,depth:mapDepth,chain,kind:'map'});
    if(owner.maps>=owner.budget.effective.maps){this.markMap(url,false,'Origin source-map budget');this.gap({code:'origin-map-budget',url,detail:'Origin source-map limit reached.',incomplete:true});return;}
    if(this.maps>=this.config.maxMaps){this.gap({code:'map-budget',url,detail:'Source-map count limit reached.',incomplete:true});return;}
    await this.evidence.inspect(text,url,chain,'Public source map JSON');
    let j:any;try{j=JSON.parse(text);if(j.version!==3||!Array.isArray(j.sections)&&(!Array.isArray(j.sources)||typeof j.mappings!=='string'))throw new Error('schema');}catch{this.markMap(url,false,'Invalid JSON/version/structure or HTML fallback');this.gap({code:'invalid-map',url,detail:'Invalid source map JSON/version/structure or HTML fallback; HTTP/text analysis is separate.',incomplete:true});return;}this.maps++;owner.maps++;this.markMap(url,true);
    if(mapDepth>this.config.maxMapDepth||ancestors.has(url)){this.gap({code:'map-depth-cycle',url,detail:'Indexed map depth limit or cycle reached.',incomplete:true});return;}
    if(Array.isArray(j.sections)){
      if(j.sections.length>this.config.maxMapSections){this.gap({code:'map-section-limit',url,detail:'Indexed source map has too many sections.',incomplete:true});this.markMap(url,false,'Section analysis budget');return;}
      const nextAncestors=new Set([...ancestors,url]);let priorLine=-1,priorColumn=-1;const sections=[];
      for(const section of j.sections){const o=section.offset;if(!o||!Number.isInteger(o.line)||!Number.isInteger(o.column)||o.line<0||o.column<0||o.line<priorLine||(o.line===priorLine&&o.column<=priorColumn)|| (!!section.map===!!section.url)||(section.url&&typeof section.url!=='string')||(section.map&&typeof section.map!=='object')){this.gap({code:'invalid-map-section',url,detail:'Invalid, overlapping or unordered section offset/reference.',incomplete:true});this.markMap(url,false,'Invalid section offset/reference');return;}priorLine=o.line;priorColumn=o.column;
        let child:any;const label=[...chain,url,`section ${o.line}:${o.column}`];
        try{if(section.map){const value=JSON.stringify(section.map);if(Buffer.byteLength(value)>this.config.maxResourceBytes)throw new Error('size');child=await this.map(value,url+'#section-'+mapDepth+'-'+o.line+'-'+o.column,label,mapDepth+1,nextAncestors);}else{const ref=new URL(section.url,url).href;if(protectedHost(ref)){this.transport.recordBlocked(ref,'protected-host',label,'map-section');continue;}const r=await this.transport.get(ref,label,'map-section');if(r.status>=400||r.partial)throw new Error('unavailable');child=await this.map(decodeText(r.body,r.headers),r.url,label,mapDepth+1,nextAncestors);}}catch(e){if(e instanceof PolicyError&&e.code==='protected-host')continue;this.gap({code:'map-section-unavailable',url,detail:'Indexed section unavailable, outside scope or over budget.',incomplete:true});}
        if(!child){this.markMap(url,false,'Indexed child unavailable/incomplete');return;}sections.push({offset:o,map:child});
      }
      const resolved={version:3,sections};this.attachMapping(resolved,url,chain);return resolved;
    }
    if(!Array.isArray(j.sources)||!j.sources.every((s:unknown)=>typeof s==='string')||(j.sourcesContent&&!Array.isArray(j.sourcesContent))){this.gap({code:'invalid-map',url,detail:'Invalid source map sources.',incomplete:true});this.markMap(url,false,'Invalid sources/source content schema');return;}
    this.evidence.observe(url,'public-source-map','Public source map was accessible; this observation alone does not establish a private credential leak.',chain);
    await this.recon?.addSourceMap(url,j,{inline:chain[chain.length-1]==='inline source map'});// w2-wire: list the map and (when requested) rebuild its sources.
    if(j.sources.length>this.config.maxMapSources){this.markMap(url,false,'Source count exceeds inspection budget');this.gap({code:'partial-map',url,detail:'Source-map sources exceed per-map limit.',incomplete:true});}
    for(let i=0;i<Math.min(j.sources.length,this.config.maxMapSources);i++){
      this.transport.checkWorkBudget();if(i%8===7)await new Promise<void>(resolve=>setImmediate(resolve));
      const label=j.sources[i],content=j.sourcesContent?.[i],source=this.sourceUrl(label,typeof j.sourceRoot==='string'?j.sourceRoot:'',url);
      if(typeof content==='string'){
        const bytes=Buffer.byteLength(content);
        if(bytes>this.config.maxResourceBytes){this.markMap(url,false,'Embedded source exceeds inspection limit');this.gap({code:'source-size-limit',url,detail:'Embedded source exceeds inspection limit.',incomplete:true});continue;}
        // Decoded sources are bounded by map input + count. Their line/column are
        // in the extracted source; sourceLabel retains the exact original label.
        await this.evidence.inspect(content,url,[...chain,'sourcesContent',label],'Source embedded in publicly reachable source map',label);
        const sourceId=url+'#embedded-source-'+i;const imports:Record<string,string>={};for(const match of content.matchAll(/\b(?:import|export)\s+(?:[^;\n]{0,500}?\bfrom\s*)?["']([^"']+)["']/g)){try{const target=new URL(match[1],new URL(label,'webpack:///')).href,index=j.sources.findIndex((name:string)=>new URL(name,'webpack:///').href===target);if(index>=0&&typeof j.sourcesContent?.[index]==='string')imports[match[1]]=url+'#embedded-source-'+index;}catch{}}this.addModule(content,sourceId,label,imports);this.moduleAdmittedAt.set(sourceId,performance.now());await this.discover(content,source||url,1,[...chain,'sourcesContent',label],'source',{},false,url);
      }else if(source)this.enqueue(source,url,1,[...chain,url,'source reference'],'source');
      else {this.markMap(url,false,'Source content unavailable');this.gap({code:'unavailable-source',url,detail:'Map source has no embedded content and no safely fetchable HTTP reference.',incomplete:true});}
    }
    this.attachMapping(j,url,chain);try{return {...j,sources:new AnyMap(j,url).resolvedSources,sourceRoot:''};}catch{return j;}
  }
  private markMap(url:string,valid:boolean,reason?:string){for(const r of this.resources.filter(r=>r.url===url)){r.sourceMap={valid,reason};r.analyzers||={};r.analyzers.sourceMap={status:valid?'inspected':'failed',reason};}}
  private attachMapping(map:any,url:string,chain:string[]){
    if(typeof map.mappings!=='string'&&!map.sections)return;
    try{const tracer=new AnyMap(map,url);const generated=[...chain].reverse().find(s=>/^https?:/.test(s)&&/\.m?js(?:[?#]|$)/.test(s))||url.replace(/\.map(?:#.*)?$/,'');
      for(const f of this.evidence.findings.values())for(const o of f.occurrences)if(o.url===generated&&o.coordinates==='generated'&&o.line!==undefined&&o.column!==undefined){const p=originalPositionFor(tracer,{line:o.line,column:o.column-1});if(p.source&&p.line!==null&&p.column!==null)o.originalPosition={source:p.source,line:p.line,column:p.column+1,precision:'mapped-segment',approximate:true};}
    }catch{this.gap({code:'map-mapping-invalid',url,detail:'Mapping data invalid; extracted coordinates remain available.',incomplete:true});}
  }
  async discover(text:string,url:string,depth:number,chain:string[],kind:string,headers:Record<string,string|string[]>={},complete=true,discoveredFrom=url){
    this.recon?.add({url,kind,contentType:String(headers['content-type']||''),text,headers});// w2-wire: feed every discovered/captured resource to recon (sync, never throws).
    const next=[...chain,url];
    if(kind==='map'||kind!=='source'&&kind!=='runtime-capture'&&resourceType({url,kind,contentType:String(headers['content-type']||'')})==='source-map'){await this.map(text,url,chain);return;}
    if(kind==='robots'){
      for(const m of text.matchAll(/^\s*Sitemap:\s*(\S+)/gim))this.enqueue(m[1],url,depth,next,'sitemap');
      // Respect exclusions for page crawling; directives are handled below.
      return;
    }
    if(kind==='sitemap'||/^\s*<\?xml|<urlset|<sitemapindex/i.test(text)){
      try{const $=cheerio.load(text.slice(0,1024*1024),{xml:true});$('loc').each((_,e)=>{const loc=$(e).text();this.enqueue(loc,url,depth,next,/<sitemapindex/i.test(text)?'sitemap':'page');});}catch{this.gap({code:'xml-parser',url,detail:'Could not parse XML discovery content.',incomplete:true});}
    }
    const documentUrl=[...chain].reverse().find(c=>/^https?:/.test(c)&&! /\.(?:m?js|css|map|json)(?:[?#]|$)/i.test(c))||this.config.urls.find(u=>new URL(u).origin===new URL(url).origin)||url;
    const documentKey=kind==='page'||/text\/html/.test(String(headers['content-type']))?url:this.moduleDocuments.get(url)||documentUrl;
    let imports=this.documentMaps.get(documentKey);if(!imports){imports={};this.documentMaps.set(documentKey,imports);}
    const before=this.discoverySummary.rejected.bareExtension,{refs,repeated}=this.extractReferences(text,url,/text\/x-component/.test(String(headers['content-type']))?'framework-data':kind,documentUrl,imports);
    if(this.discoverySummary.rejected.bareExtension>before)this.gap({code:'bare-extension-literals',detail:`${this.discoverySummary.rejected.bareExtension} bare extension literals (such as ".json" or ".woff") were not treated as URLs; only contextual uses are acquired.`,incomplete:false,count:this.discoverySummary.rejected.bareExtension,examples:[...this.discoverySummary.rejected.examples]});
    if(complete&&(/text\/html/.test(String(headers['content-type']))||kind==='page')){const $=cheerio.load(text.slice(0,1024*1024));$('script:not([src])').each((i,e)=>{const type=$(e).attr('type')||'';if(!/json|importmap/.test(type)){this.addModule($(e).html()||'',url+'#inline-'+i,'inline script '+i,imports);this.moduleAdmittedAt.set(url+'#inline-'+i,performance.now());}});}
    else if(complete&&(/javascript/.test(String(headers['content-type']))||/\.m?js(?:[?#]|$)/.test(url)||kind==='module'||kind==='source')){this.addModule(text,url,kind==='source'?'source-map embedded source':undefined,imports);this.moduleAdmittedAt.set(url,performance.now());}
    let unresolvedEdges=0;
    // An identical (text, URL, document, import map) tuple was already processed: provenance is already merged and every reference already went through enqueue.
    for(const ref of repeated?[]:refs){
      let to:string|undefined;try{if(!ref.unresolved)to=new URL(ref.raw,ref.base).href;}catch{}
      if(to&&ref.kind==='module'){const prior=this.moduleDocuments.get(to);if(prior&&prior!==documentKey&&JSON.stringify(this.documentMaps.get(prior))!==JSON.stringify(imports))this.gap({code:'module-document-context-conflict',url:to,detail:'One module was referenced under differing document import maps; bare imports may be ambiguous. Only the first recorded document context is analyzed.',incomplete:true});else if(!prior)this.moduleDocuments.set(to,documentKey);}
      if(ref.unresolved){this.discoverySummary.unresolved++;if(unresolvedEdges++<25)this.graphEdge(url,ref.raw,ref.context,ref.kind,to,'unresolved',{certainty:ref.certainty,sink:ref.sink,method:ref.method});if(ref.kind==='module')this.gap({code:'unresolved-module-reference',url,detail:'Bare/scoped import lacks supported import-map resolution; not guessed or fetched.',incomplete:true});continue;}
      this.graphEdge(url,ref.raw,ref.context,ref.kind,to,ref.acquire===false?'observed':'candidate',{certainty:ref.certainty,sink:ref.sink,method:ref.method});
      if(ref.acquire===false){this.discoverySummary.observedOnly++;continue;}
      if(ref.raw.startsWith('data:')&&ref.kind==='map')await this.inlineMap(ref.raw,url,next);
      else this.enqueue(ref.raw,ref.base,ref.kind==='page'?depth+1:depth,[...next,ref.context],ref.kind,discoveredFrom,{certainty:ref.certainty==='unresolved'?undefined:ref.certainty,context:ref.context});
    }
    if(/(?:json|yaml)/.test(String(headers['content-type']))||/openapi|swagger/i.test(url)){try{const j=JSON.parse(text);if(j.openapi||j.swagger)this.evidence.observe(url,'public-api-description',`Public API description observed (${String(j.openapi||j.swagger).slice(0,20)}); schemas/configuration inspected locally. Documented operations and server URLs were not executed.`,chain);}catch{}}
    for(const header of ['sourcemap','x-sourcemap'])if(typeof headers[header]==='string')this.enqueue(headers[header] as string,url,depth,next,'map');
    for(const m of String(headers.link||'').slice(0,16384).matchAll(/<([^>]{1,2048})>([^,]*)/g))if(/\brel\s*=\s*["']?(?:modulepreload|preload)\b/i.test(m[2])&&/\.(?:m?js|css|json)(?:[?#]|$)/.test(m[1]))this.enqueue(m[1],url,depth,[...next,'HTTP Link preload'],'asset',discoveredFrom,{certainty:'confirmed',context:'HTTP Link preload'});
    if(this.config.adjacentMaps&&/\.m?js$/i.test(new URL(url).pathname)&&!new URL(url).search)this.enqueue(url+'.map',url,depth,next,'map-guess');
    if(kind==='manifest'){
      try{const j=JSON.parse(text);if(typeof j.start_url==='string')this.enqueue(j.start_url,url,depth,next,'page',discoveredFrom,{certainty:'confirmed',context:'manifest start_url'});for(const icon of (j.icons||[]).slice(0,20))if(typeof icon.src==='string')this.enqueue(icon.src,url,depth,next,'asset',discoveredFrom,{certainty:'confirmed',context:'manifest icon'});}catch{this.gap({code:'manifest-parser',url,detail:'Manifest JSON is invalid.',incomplete:true});}
    }
  }
  /** Discovery cache keyed by content hash and kind; resolution re-runs per base and import map, so provenance stays distinct. LRU: 256 entries / 8 MiB of text. */
  /** Mass runs: the process-wide collector of in-process parse garbage (ParseCollector), told of every structured extraction that was not a cache hit. */
  private readonly parseCollector?:ParseCollector;
  private discoveryCache=new Map<string,{extraction:Extraction;bytes:number}>();private discoveryCacheBytes=0;private processedDiscoveries=new Set<string>();
  /** Structured extraction over the whole document up to `maxDiscoveryBytes`; beyond it, only uncertain literal hints from bounded windows plus the trailing source-map comment. */
  private extractReferences(text:string,url:string,kind:string,documentUrl:string,imports:Record<string,string>):{refs:Reference[];repeated:boolean}{
    const cap=this.config.maxDiscoveryBytes??4*1024*1024;
    if(text.length<=cap){
      const hash=createHash('sha256').update(text).digest('hex'),key=DISCOVERY_VERSION+'|'+kind+'|'+extractionContextKey(url)+'|'+hash;let entry=this.discoveryCache.get(key);
      if(entry){this.discoveryCache.delete(key);this.discoveryCache.set(key,entry);this.discoverySummary.reusedDiscoveries++;}
      else{entry={extraction:extract(text,url,kind,{summary:this.discoverySummary}),bytes:text.length};this.parseCollector?.parsed(text.length);this.discoveryCache.set(key,entry);this.discoveryCacheBytes+=entry.bytes;while(this.discoveryCache.size>256||this.discoveryCacheBytes>8*1024*1024){const oldest=this.discoveryCache.keys().next().value!;this.discoveryCacheBytes-=this.discoveryCache.get(oldest)!.bytes;this.discoveryCache.delete(oldest);}}
      const tuple=hash+'|'+url+'|'+documentUrl+'|'+createHash('sha256').update(JSON.stringify(imports)).digest('hex').slice(0,16),repeated=this.processedDiscoveries.has(tuple);if(!repeated&&this.processedDiscoveries.size<20000)this.processedDiscoveries.add(tuple);
      return {refs:resolveReferences(entry.extraction,{url,documentUrl,imports}),repeated};
    }
    return {refs:this.windowedReferences(text,url,kind,documentUrl,imports,cap),repeated:false};
  }
  private windowedReferences(text:string,url:string,kind:string,documentUrl:string,imports:Record<string,string>,cap:number):Reference[]{
    this.gap({code:'discovery-document-limit',url,detail:`Structured discovery parses up to ${Math.round(cap/1048576)} MiB; this document was scanned in bounded windows for literal hints only, so sink context beyond the cap is unknown. Full retained text still receives chunked credential inspection.`,incomplete:true});this.discoverySummary.windowed++;
    const out:Reference[]=[],seen=new Set<string>(),window=1024*1024,overlap=65536;
    for(let start=0;start<text.length;start+=window-overlap){const slice=text.slice(start,Math.min(text.length,start+window));for(const ref of references(slice,url,kind,documentUrl,imports,{tokensOnly:true,summary:this.discoverySummary})){if(ref.kind==='map'||ref.unresolved||ref.acquire===false)continue;const key=ref.raw+'|'+ref.base;if(seen.has(key))continue;seen.add(key);out.push({...ref,certainty:'heuristic',context:ref.context+' (windowed; context beyond the discovery cap unknown)'});if(out.length>=5000)break;}if(out.length>=5000)break;}
    for(const m of text.slice(-4096).matchAll(/[#@]\s*sourceMappingURL\s*=\s*(\S+)/g))out.push({raw:m[1],base:url,kind:'map',context:'source-map comment',certainty:'confirmed'});
    return out;
  }
  private robots=new Map<string,{disallow:string[];allow:string[]}>();
  private robotsPermit(url:string){const u=new URL(url),r=this.robots.get(u.origin);if(!r)return true;const d=Math.max(0,...r.disallow.filter(p=>p&&u.pathname.startsWith(p.replace(/\*.*$/,''))).map(p=>p.length));const a=Math.max(0,...r.allow.filter(p=>u.pathname.startsWith(p.replace(/\*.*$/,''))).map(p=>p.length));return !d||a>=d;}
  private parseRobots(text:string,origin:string){
    let active=false;const rule={allow:[] as string[],disallow:[] as string[]};
    for(const line of text.split(/\r?\n/)){const m=/^\s*([\w-]+):\s*(.*?)\s*(?:#.*)?$/.exec(line);if(!m)continue;const k=m[1].toLowerCase();if(k==='user-agent')active=m[2]==='*';else if(active&&k==='disallow')rule.disallow.push(m[2]);else if(active&&k==='allow')rule.allow.push(m[2]);}this.robots.set(origin,rule);
  }
  private baselines=new Map<string,string[]>();
  private signature(text:string){return text.replace(/[a-f0-9]{16,}|\d{3,}|\/__exposure_baseline_[\w-]+/gi,'#').replace(/\s+/g,' ').trim().slice(0,8192);}
  private confirmDeep(url:string,r:ResponseData):boolean{
    const text=r.body.toString('utf8'),sig=this.signature(text);
    if(r.status!==200||/text\/html/i.test(String(r.headers['content-type']))||/<html|<!doctype|<form[^>]+(?:login|password)|<title[^>]*>[^<]*(?:not found|error|login)/i.test(text))return false;
    if(this.baselines.get(new URL(url).origin)?.includes(sig))return false;
    const p=new URL(url).pathname;
    if(p.endsWith('/.git/HEAD'))return /^(?:ref: refs\/heads\/[\w./-]+|[a-f0-9]{40,64})\s*$/i.test(text);
    // Profile scans add /.git/config (2.6); custom 2.5 path lists keep the generic confirmation below.
    if(p.endsWith('/.git/config')&&this.config.coverage!==undefined)return /^\s*\[(?:core|remote\s+"[^"\n]{1,200}"|branch\s+"[^"\n]{1,200}")\]\s*$/m.test(text);
    if(/\.env(?:\.|$)/.test(p))return /^\s*(?:export\s+)?[A-Z_][A-Z0-9_]{1,100}\s*=\s*\S+/m.test(text);
    if(p==='/.npmrc')return /(?:_authToken|registry\s*=|_auth\s*=)/.test(text);
    if(/(?:config|settings).*\.json$/.test(p)){try{const value=JSON.parse(text);return !!value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).some(k=>/environment|database|connection|server|endpoint|logging|secret|api|deployment/i.test(k));}catch{return false;}}
    if(/\.log$|\/debug(?:\/|$)/.test(p))return /Traceback \(most recent call last\)|(?:Error|Exception):|\bat\s+[\w.$]+\s*\([^\n]{1,200}:\d+:\d+\)|\[(?:ERROR|WARN|INFO)\]|(?:secret|api[_-]?key|password)\s*[:=]/i.test(text);
    if(/\.(?:sql|bak)$/.test(p))return /CREATE TABLE|INSERT INTO|<\?php|(?:password|secret|api_key)\s*[:=]/i.test(text);
    return /(?:password|secret|api[_-]?key|private[_-]?key|stack.?trace|exception|fatal error)\s*[:=]|"(?:apiKey|client_secret|database)"\s*:/i.test(text);
  }
  /** Owner decision 2.6: a variant the same coverage with Normal traffic would visit (its first variants per path, visited plus profile-skipped) is skipped by Low-impact's own boundary, not by an error or budget; later variants stay the coverage's own incomplete limit. */
  private profileLimits(path:string,visited:number){const c=this.config,skipped=this.profileSkippedByPath.get(path)||0;if(c.traffic!=='low-impact'||!c.coverage||c.queryVariants!==LOW_IMPACT_LIMITS.queryVariants||visited+skipped>=coverageQueryVariants(c.coverage))return false;this.profileSkippedByPath.set(path,skipped+1);return true;}
  private profileLimitView():NonNullable<ProfileView['profileLimit']>|undefined{const c=this.config,n=this.profileSkipped.size;if(!n||!c.coverage)return;const visitedBy=COVERAGE_LABELS[c.coverage]+' + Normal';
    return {rule:'query-variants',count:n,examples:this.profileLimited.slice(0,10).map(w=>w.url),visitedBy,note:`Low-impact examines one query-string variant per path, so ${n} other variant${n===1?' was':'s were'} not requested. This is the option's stated boundary, not an error; ${visitedBy} visits up to ${coverageQueryVariants(c.coverage)} variants per path. The skipped variants stay listed in the run data.`};}
  private profileLimit(w:WorkItem){w.deferredReason='profile-limit';const known=this.inventory.get(w.url);if(known)known.deferredReason='profile-limit';this.profileSkipped.add(w.url);if(this.profileLimited.length<2000)this.profileLimited.push(w);const p=this.profileLimitView()!;this.gap({code:'profile-query-variants',detail:'Limited by profile: '+p.note,incomplete:false,count:p.count,examples:p.examples});}
  private defer(w:WorkItem,reason='processing-incomplete'){w.deferredReason=reason;const known=this.inventory.get(w.url);if(known)known.deferredReason=reason;if(this.deferred.length<2000&&!this.deferred.some(x=>x.url===w.url))this.deferred.push(w);}
  /** Keep a successfully downloaded body whose analysis was interrupted by a turn only; it is re-analyzed once without a new request. */
  deferAnalysis(item:WorkItem,response:ResponseData,cause:GapCause,discoverKind=item.kind,evidence?:string){
    const bytes=response.body.length,limit=this.config.analysisBacklogBytes??0;
    if(this.backlog.length>=64||this.backlogBytes+bytes>limit||this.transport.projectSignal.aborted){this.backlogStats.dropped++;if(response.resource){response.resource.analysis='deferred';response.resource.reason='analysis-interrupted';}this.gap({code:'analysis-interrupted',url:item.url,attemptId:response.resource?.attemptId,detail:'Analysis was interrupted after download and the bounded backlog could not retain the body; retry with fresh budgets.',incomplete:true,cause});return;}
    this.backlog.push({item,response,cause,bytes,discoverKind,evidence});this.backlogBytes+=bytes;this.interruptions[cause.kind]=(this.interruptions[cause.kind]||0)+1;
  }
  private async resumeAnalysis(entry:typeof this.backlog[number]){
    const {item,response:r}=entry;r.resumed=true;r.analyzed=false;this.backlogStats.resumed++;
    try{const text=await this.transport.analyze(r,entry.evidence);if(r.resource?.analysis==='deferred')this.backlogStats.deferred++;else if(r.resource?.analysis==='analyzed')await this.transport.originControl.run(item.url,()=>this.discover(text,r.url,item.depth,r.chain,entry.discoverKind,r.headers,!r.partial));}
    catch(e){if(e instanceof AnalysisDeferred){if(r.resource){r.resource.analysis='deferred';r.resource.reason='analysis-interrupted';}this.backlogStats.deferred++;this.gap({code:'analysis-interrupted',url:item.url,attemptId:r.resource?.attemptId,detail:'Resumed analysis was interrupted again; the body was not retained a second time.',incomplete:true,cause:e.cause});}else{const code=e instanceof PolicyError?e.code:'processing-failure';this.gap({code,url:item.url,detail:'Resumed analysis of a retained body did not complete.',incomplete:true});}}
  }
  private blockedWork(w:WorkItem){
    if(!this.transport)return;const origin=new URL(w.url).origin;
    if(w.kind==='page'&&!this.robotsDone.has(origin)&&this.queue.some(q=>q.kind==='robots'&&new URL(q.url).origin===origin)||w.kind==='page'&&[...this.schedule.active.keys()].some(q=>q.kind==='robots'&&new URL(q.url).origin===origin))return 'Awaiting bounded robots prerequisite';
    if([...this.schedule.active.keys()].filter(q=>new URL(q.url).origin===origin).length>=(this.config.originConcurrency??this.config.concurrency))return 'Origin work concurrency';
    if((this.browserHeld.has(origin)||this.browserDue.has(origin))&&workPriority(w,this.config.urls,this.admittedRoots)>=2)return 'Awaiting the browser entry document';
    return undefined;
  }
  /** The browser turn of `origin` has its entry document answered (or the request failed), or the turn has ended: the website's optional work may go out again. */
  browserDocumentSettled(origin:string){if(this.browserHeld.delete(origin))this.browserReleased();}
  skipImage(url:string,chain:string[],kind='image'){const rendition=imageRendition(url);let raster=false;try{raster=kind==='image'&&/\.(?:png|jpe?g|gif|webp|avif|ico)$/i.test(new URL(url).pathname);}catch{}if(!rendition&&!raster)return false;for(const c of this.detector.inspectWindowed(url,false,this.analysis))this.evidence.add(c,url,chain.find(c=>/^https?:/.test(c))||url,chain,'Discovered image URL inspected locally; body intentionally skipped');if(rendition)for(const c of this.detector.inspectWindowed(rendition.source,false,this.analysis))this.evidence.add(c,rendition.source,url,chain,'Decoded image source URL inspected locally; no capability followed');if(this.skippedImageUrls.has(url))return true;this.skippedImageUrls.add(url);const family=rendition?.family||url;let record=this.imageGroups.get(family);if(!record){record={url,status:'skipped',analysis:'skipped',resourceType:'image',bytes:0,chain,kind:'image',reason:rendition?'image-rendition':'raster-image-body',discoveryCount:0,examples:[],analyzers:{directText:{status:'inspected',reason:'URL string inspected locally; image body skipped'}}};if(this.imageGroups.size<500){this.imageGroups.set(family,record);this.resources.push(record);}else this.gap({code:'image-family-record-limit',detail:'Image-family audit rows limited to 500; overall rendition count retained, further source families unknown in the summary.',incomplete:true});}record.discoveryCount=(record.discoveryCount||0)+1;if(record.examples!.length<4)record.examples!.push(url);return true;}
  /** Scanner-level registry of runtime capture content hashes: a capture repeated in a later browser session reuses the canonical record and adds provenance only. */
  private runtimeCaptureHashes=new Map<string,string>();
  registerRuntimeCapture(hash:string,captureUrl:string,owner:string):string|undefined{const canonical=this.runtimeCaptureHashes.get(hash);if(!canonical){if(this.runtimeCaptureHashes.size<4096)this.runtimeCaptureHashes.set(hash,captureUrl);return undefined;}const record=this.resources.find(r=>r.url===canonical&&r.kind==='runtime-capture');if(record){record.discoveryCount=(record.discoveryCount||1)+1;record.examples||=[];if(record.examples.length<8&&!record.examples.includes(owner))record.examples.push(owner);}this.graphEdge(owner,canonical,'Identical runtime capture observed again; canonical capture reused','debugger-script',canonical,'identical-runtime-capture');this.discoverySummary.reusedDiscoveries++;return canonical;}
  /** Fingerprints of documents served by each origin (root pages, browser documents and baseline probes), kept as hashes only. */
  private documentFingerprints=new Map<string,Map<string,string>>();
  htmlFingerprint(text:string){return createHash('sha256').update(this.signature(text.slice(0,262144)).replace(/nonce="[^"]*"|nonce='[^']*'|(?:csrf|xsrf)[\w-]*["']?\s*(?:content|value)?\s*[=:]\s*["'][^"']*["']|[A-Za-z0-9+/]{24,}={0,2}/g,'#')).digest('hex');}
  rememberDocument(url:string,text:string){const origin=new URL(url).origin;let m=this.documentFingerprints.get(origin);if(!m){m=new Map();this.documentFingerprints.set(origin,m);}const hash=this.htmlFingerprint(text);if(m.size<64&&!m.has(hash))m.set(hash,url);return hash;}
  /** Classify HTML answering a non-navigational request before any promotion to a browser page. */
  classifyHtmlForAsset(url:string,kind:string,text:string,chain:string[]):NonNullable<Resource['fallback']>{
    const expected=kind==='page'?'page':['script','module','source'].includes(kind)||/\.m?js(?:[?#]|$)/i.test(url)?'script':['map','map-guess','map-section'].includes(kind)?'map':kind==='manifest'?'manifest':['config','framework-data','framework-manifest'].includes(kind)||/\.json(?:[?#]|$)/i.test(url)?'json':kind==='css'||/\.css(?:[?#]|$)/i.test(url)?'css':kind==='sitemap'?'sitemap':kind==='asset-hint'?'hint':'asset';
    const hash=this.htmlFingerprint(text),known=this.documentFingerprints.get(new URL(url).origin)?.get(hash),sig=this.signature(text);
    if(known&&known!==url)return {type:'spa-fallback',sameAs:known,expected};
    if(this.baselines.get(new URL(url).origin)?.includes(sig))return {type:'spa-fallback',expected};
    if(/<form\b[\s\S]{0,8000}type\s*=\s*["']?password/i.test(text)||/<title[^>]*>[^<]*(?:log ?in|sign ?in)/i.test(text)||chain.some(c=>/HTTP redirect/.test(c))&&/(?:^|\/)(?:login|signin|sign-in|auth)(?:[/?#]|$)/i.test(new URL(url).pathname))return {type:'login',expected};
    if(/<title[^>]*>[^<]*(?:not found|404)|<h1[^>]*>[^<]*(?:not found|404)/i.test(text))return {type:'soft-404',expected};
    return {type:'html-for-asset',expected};
  }
  private async process(item:WorkItem){
    const {url,depth,chain,kind}=item;
    const owner=this.transport.originControl.current;
    if(kind==='page'&&!this.robotsPermit(url)){if(this.config.robotsPolicy==='owner-authorized-audit')this.gap({code:'robots-owner-audit',url,detail:'Robots exclusion retained as evidence; operator explicitly enabled authorized public-surface auditing. No access controls were bypassed.',incomplete:false});else{this.resources.push({url,status:'skipped',analysis:'skipped',bytes:0,chain,kind,reason:'robots-exclusion'});this.gap({code:'robots-exclusion',url,detail:'Public page excluded by robots.txt. The owner-authorized audit setting can include it without authenticating.',incomplete:true});return;}}
    if(kind==='page'&&(this.pageAttempts>=this.config.maxPages||owner&&owner.pages>=owner.budget.effective.pages)){this.defer(item,'page-budget');this.gap({code:'page-budget',url,detail:'Project or origin page attempt limit reached, including failed attempts. Discovered scripts and configuration retain their own opportunities.',incomplete:true});return;}const group=new URL(url).origin+new URL(url).pathname.split('/').slice(0,2).join('/');if(kind==='page'&&!this.config.urls.includes(url)&&(this.routeFailures.get(group)||0)>=3){this.defer(item,'route-group-backoff');this.gap({code:'route-group-backoff',url,detail:'Three optional pages in one route group repeatedly failed. Further pages in that group deferred; assets and other groups remain eligible. Use a focused retry with fresh budgets.',incomplete:true});return;}if(kind==='page'){this.pageAttempts++;if(owner)owner.pages++;}
    try{
      const r=await this.transport.get(url,chain,kind);let text=r.text||'';if(kind==='page')this.routeFailures.delete(group);if(r.resource){r.resource.resourceType=resourceType(r.resource);if(item.certainty)r.resource.certainty=item.certainty;if(r.resource.resourceType==='javascript'&&r.resource.analysis==='analyzed'&&this.firstJavaScript===undefined)this.firstJavaScript=Date.now()-this.transport.started;}
      if(r.partial)this.gap({code:'semantic-incomplete-document',url,detail:'A truncated response cannot participate in complete-document static reconstruction. Retained text still inspected.',incomplete:true});
      if(r.status>=400){const disposition=r.resource?.httpDisposition,code=['authentication-challenge','http-refusal','suspected-bot-challenge'].includes(disposition||'')?disposition!:'http-unavailable';this.gap({code,url,detail:httpExplanation(r.status,disposition),incomplete:!['deep','baseline','map-guess','robots','sitemap','framework-manifest','asset-hint'].includes(kind)&&item.certainty!=='heuristic'});if(text&&!['deep','baseline','map-guess'].includes(kind)&&/text\/html/i.test(String(r.headers['content-type'])))await this.discover(text,r.url,depth,r.chain,kind,r.headers);return;}
      if(r.resource?.analysis==='skipped'||r.resource?.reason==='text-decoding')return;
      if(/<form\b[\s\S]{0,8000}type\s*=\s*["']?password/i.test(text))this.gap({code:'login-form-present',url,detail:'Password form observed. Public content and linked scripts are still inspected; no form was submitted and authenticated areas remain outside coverage.',incomplete:false});
      if(kind==='baseline'){const origin=new URL(url).origin;this.baselines.set(origin,[...(this.baselines.get(origin)||[]),this.signature(text)]);if(/text\/html/i.test(String(r.headers['content-type']))||/^\s*(?:<!doctype html|<html)/i.test(text))this.rememberDocument(url,text);return;}
      if(kind==='deep'){
        if(!this.confirmDeep(url,r)){if(r.resource){r.resource.status='skipped';r.resource.reason='unconfirmed-soft404-login-spa-or-limit';}return;}
        await this.transport.analyze(r);
        this.evidence.observe(url,'published-sensitive-file','Content confirms a deployment/configuration/metadata file at a public HTTP path. Inspection was bounded; no repository reconstruction or bulk dump download.'+(r.partial?' Only the bounded prefix was inspected; remaining content is unknown.':''),chain);
        return;
      }
      if(kind==='robots'){this.parseRobots(text,new URL(url).origin);await this.discover(text,r.url,depth,r.chain,kind,r.headers);return;}
      if(kind==='map-guess'){
        let valid=false;try{const value=JSON.parse(text);valid=value.version===3&&(Array.isArray(value.sources)||Array.isArray(value.sections));}catch{}
        if(!valid){if(r.resource){r.resource.status='skipped';r.resource.reason='optional-map-not-present';}this.gap({code:'map-unavailable',url,detail:'Adjacent map check returned fallback/non-map content.',incomplete:false});return;}
        await this.transport.analyze(r);await this.map(text,r.url,[...chain,url]);return;
      }
      const html=/text\/html|application\/xhtml/i.test(String(r.headers['content-type']))||!String(r.headers['content-type']||'').trim()&&/^\s*(?:<!doctype html|<html|<head|<body)/i.test(text)||/text\/plain/i.test(String(r.headers['content-type']))&&/^\s*(?:<!doctype html|<html)/i.test(text);
      if(html&&kind==='page'&&r.status>=200&&r.status<300)this.rememberDocument(r.url,text);
      // HTML answering a non-navigational request is classified first. Only real page kinds can become browser candidates;
      // a fallback shell is never navigated, and an identical shell is not re-discovered.
      if(html&&kind!=='page'&&!['sitemap','robots','baseline','deep'].includes(kind)){
        const fallback=this.classifyHtmlForAsset(r.url,kind,text,r.chain);if(r.resource)r.resource.fallback=fallback;this.discoverySummary.fallbacks[fallback.type]=(this.discoverySummary.fallbacks[fallback.type]||0)+1;
        const confirmedAsset=['script','map','manifest'].includes(fallback.expected)&&item.certainty!=='heuristic'&&kind!=='asset-hint';
        if(confirmedAsset)this.gap({code:'expected-asset-html-fallback',url,detail:`Expected ${fallback.expected} content but received HTML (${fallback.type}${fallback.sameAs?' identical to '+fallback.sameAs:''}); the referenced asset is unavailable.`,incomplete:true});
        else{const n=Object.values(this.discoverySummary.fallbacks).reduce((a,b)=>a+b,0);this.gap({code:'asset-html-fallback',detail:`${n} non-navigational request${n===1?'':'s'} received HTML instead of the expected asset (application fallback, login or soft-404 pages); none were promoted to browser pages.`,incomplete:false,count:n,examples:Object.entries(this.discoverySummary.fallbacks).map(([k,v])=>k+': '+v)});}
        if(fallback.sameAs){this.graphEdge(r.url,fallback.sameAs,'HTML fallback identical to an already discovered document; not re-discovered','page',fallback.sameAs,'fallback-duplicate');return;}
        await this.discover(text,r.url,depth,r.chain,kind,r.headers,!r.partial);return;
      }
      // Discovered pages are still inspected, but login and soft-404 documents are never promoted to browser candidates; explicit routes bypass this list entirely.
      if(kind==='page'&&html){const fb=this.classifyHtmlForAsset(r.url,'page',text,r.chain);if(fb.type==='login'||fb.type==='soft-404'){if(r.resource)r.resource.fallback={...fb,expected:'page'};this.discoverySummary.fallbacks[fb.type]=(this.discoverySummary.fallbacks[fb.type]||0)+1;}else if(!this.pages.includes(r.url))this.pages.push(r.url);}
      await this.discover(text,r.url,depth,r.chain,kind,r.headers,!r.partial);
    }catch(e){if(e instanceof AnalysisDeferred){this.deferAnalysis(item,e.response,e.cause);return;}const code=e instanceof PolicyError?e.code:'processing-failure';if(code==='protected-host'){/* a redirect into a protected host: deferred like an out-of-scope redirect, never a gap */if(!protectedHost(url))this.defer(item,code);return;}if(kind==='page'&&['request-timeout','connection-timeout','dns-timeout','network-failure','response-failure'].includes(code))this.routeFailures.set(group,(this.routeFailures.get(group)||0)+1);this.defer(item,code);if(['request-count-limit','duration-limit','total-byte-limit','cancelled'].includes(code)){if(code!=='duration-limit'&&['not-started','running'].includes(this.stopReason))this.stopReason=code;if(this.deferred.length<2000&&!this.deferred.some(w=>w.url===url))this.deferred.push(item);}if(!(e instanceof PolicyError&&e.recorded)&&!['scope','method','credential-in-request','destructive-get','private-address','metadata','dashboard-isolation'].includes(code))this.gap({code,url,detail:'Resource could not be fully processed.',incomplete:true,...(['cancelled','work-turn-limit','duration-limit'].includes(code)?{cause:this.transport.abortCause()}:{})});}
  }
  async inspectQueuedLazyAsset(item:WorkItem){
    const index=this.queue.indexOf(item);if(index<0||this.blockedWork(item)||this.websiteWaiting()(item)||this.schedule.active.size>=(this.config.globalConcurrency??this.config.concurrency)||item.notBefore&&item.notBefore>Date.now())return false;
    this.queue.splice(index,1);this.schedule.active.set(item,Date.now());
    try{await this.process(item);return true;}finally{this.schedule.finish(item);}
  }
  /** Browser navigation candidates: explicit routes are never filtered; other candidates are real server documents, ordered distinct-fingerprint pages first, with asset-derived, login and soft-404 pages excluded. */
  browserNavigationCandidates():string[]{
    if(this.retry)return this.retry.browserUrls;
    const explicit=[...new Set([...this.config.urls,...(this.config.browserNavigationUrls||[])])];
    const fingerprintOf=new Map<string,string>();for(const m of this.documentFingerprints.values())for(const [hash,u]of m)fingerprintOf.set(u,hash);
    const rows=this.pages.filter(u=>!explicit.includes(u)).filter(u=>{const r=[...this.resources].reverse().find(x=>x.url===u&&x.code!==undefined);return !r?.fallback||!['login','soft-404'].includes(r.fallback.type);});
    const distinct=rows.filter(u=>fingerprintOf.has(u)),shell=rows.filter(u=>!fingerprintOf.has(u));
    const queued=this.queue.filter(w=>w.kind==='page'&&!w.chain.some(c=>/sitemap|robots/i.test(c))&&w.chain.some(c=>this.config.urls.includes(c))).map(w=>w.url);
    const waiting=new Set<string>();for(const w of this.queue)if(workPriority(w,this.config.urls,this.admittedRoots)===0&&w.certainty!=='heuristic')waiting.add(new URL(w.url).origin);
    return [...explicit,...[...new Set([...distinct,...shell,...queued])].filter(u=>!waiting.has(new URL(u).origin))];
  }
  async run(){
    if(this.state!=='ready')throw new Error('Scan already started');
    this.state='running';this.stopReason='running';await this.resolveTimeFactor();this.startedAt=new Date().toISOString();this.transport.started=Date.now();
    const control=this.transport.originControl,project=this.transport.projectSignal,initialDetectorIssues=this.detector.setupIssues;
    this.armProjectTimer();
    const running=new Set<Promise<void>>(),browserRunning=new Set<string>(),deepDone=new Set<string>(),analysisDone=new Map<string,number>();
    const browserAttempted=new Set<string>(),browserAttemptsByOrigin=new Map<string,number>();const analysisOrigins=new Set<string>();let browserAttempts=0,analysisActive=0,backlogActive=0;
    const authorized=this.transport.authorizedOrigins;
    for(const origin of authorized)control.get(origin);
    const own=(url:string)=>new URL(url).origin;
    const activeAt=(origin:string)=>[...this.schedule.active.keys()].some(w=>own(w.url)===origin);
    // A work turn is cut after `limit`. In mass mode the limit counts the website's charged time, so a turn is not cut while its website only waits for capacity other targets hold.
    const turn=<T>(url:string,task:()=>Promise<T>,limit=this.config.workTurnMs??30000,kind:'static'|'browser'='static')=>{const stop=new AbortController(),reached=()=>stop.abort({kind:'work-turn-limit',turn:kind,origin:own(url)});
      if(control.excludeSharedWaits){const cancel=control.chargedTimer(url,limit,reached);return control.run(url,task,stop.signal).finally(cancel);}
      const timer=setTimeout(reached,limit);return control.run(url,task,stop.signal).finally(()=>clearTimeout(timer));};
    const launch=(task:()=>Promise<void>)=>{const p=task().catch(()=>{}).finally(()=>running.delete(p));running.add(p);};
    // Websites at once (ready options): a website that has not started waits while `maxActiveOrigins` started websites still have work, so its clock starts with its own first turn
    // and a Low-impact website's requests stay close enough to reuse its connection. Only work the websites in progress could run now holds a slot: while nothing runs and they have none, nothing waits, so the scan never stalls.
    // 2.5 configurations keep round-robin over every website.
    const websiteSlots=this.config.coverage!==undefined?this.config.maxActiveOrigins??4:0;
    this.websiteWaiting=()=>{
      if(!websiteSlots)return ()=>false;
      const open=new Set<string>([...browserRunning,...analysisOrigins]);for(const w of this.schedule.active.keys())open.add(own(w.url));
      for(const s of control.states.values())if(s.started!==undefined&&s.ended===undefined&&!control.expired(s.origin))open.add(s.origin);
      // A started website with queued work keeps its slot between turns.
      for(const w of this.queue){if(open.size>=websiteSlots)break;const o=own(w.url);if(!open.has(o)&&control.peek(o)?.started!==undefined&&!control.expired(o))open.add(o);}
      if(open.size<websiteSlots||!running.size&&!this.queue.some(w=>open.has(own(w.url))&&!this.blockedWork(w)))return ()=>false;
      return w=>{const o=own(w.url);return !open.has(o)&&control.peek(o)?.started===undefined;};
    };
    const browserCandidates=()=>this.browserNavigationCandidates();
    const explicitBrowserUrls=new Set(this.retry?this.retry.browserUrls:[...this.config.urls,...(this.config.browserNavigationUrls||[])]);
    const browserEligible=(url:string)=>(explicitBrowserUrls.has(url)||browserAttempts+[...explicitBrowserUrls].filter(u=>!browserAttempted.has(u)&&!(control.peek(u)&&control.expired(u))).length<this.config.browserPages)&&!browserAttempted.has(url)&&!(control.peek(url)&&control.expired(url))&&!browserRunning.has(own(url))&&
      (browserAttemptsByOrigin.get(own(url))||0)<(this.config.originBrowserPages??this.config.browserPages)&&
      !this.queue.some(w=>own(w.url)===own(url)&&this.config.urls.includes(w.url))&&
      ![...this.schedule.active.keys()].some(w=>own(w.url)===own(url)&&this.config.urls.includes(w.url))&&
      (!(control.peek(url)&&control.soft(url))||this.config.urls.includes(url)||(this.config.browserNavigationUrls||[]).includes(url));
    try{
      this.stage='Fair entry-document bootstrap and prioritized resource inspection';
      // Robots prerequisites are queued, never awaited serially across origins.
      for(const origin of new Set((this.retry?this.retry.selected.filter(w=>w.kind==='page').map(w=>w.url):this.config.urls).map(own)))this.enqueue('/robots.txt',origin,0,[],'robots');
      if(this.retry){for(const item of this.retry.selected)this.enqueue(item.url,this.config.urls[0],0,item.chain,item.kind);this.gap({code:'focused-retry',detail:this.retry.note,incomplete:true});}
      else for(const url of this.config.urls)this.enqueue(url,url,0,[],'page');
      // Approved in-domain browser routes are pre-admitted, so routes and discovery agree and no origin clock starts before admission.
      if(!this.retry&&this.config.coverage!=='quick')for(const route of this.config.browserNavigationUrls||[])if(!this.transport.isAuthorized(route)&&this.transport.sameDomainSeed(route))this.admitDiscovery({url:route.split('#')[0],depth:0,chain:['explicitly approved browser route'],kind:'page',enqueuedAt:Date.now()},this.config.urls[0],()=>{});
      for(const url of this.config.staleAssetUrls||[]){this.graphEdge('previous authorized scan or owner deployment manifest',url,'Exact stale asset replay under current policy','stale-asset',url);this.enqueue(url,this.config.urls[0],0,['previous authorized scan or owner deployment manifest'],'stale-asset');}
      if(!this.retry&&this.config.coverage!=='quick')for(const origin of new Set(this.config.urls.map(own)))this.enqueue('/sitemap.xml',origin,0,[],'sitemap');
      while(!project.aborted){
        // At 90%, optional/low-value work is deferred with provenance. No budget is raised.
        const importantByOrigin=new Map<string,number>();for(const item of this.queue)if(workPriority(item,this.config.urls,this.admittedRoots)<2){const origin=own(item.url);importantByOrigin.set(origin,(importantByOrigin.get(origin)||0)+1);}for(const origin of this.transport.authorizedOrigins)control.get(origin).budget.pending(importantByOrigin.get(origin)||0);
        for(const item of [...this.queue]){let reason:string|undefined;
          const o=control.get(item.url);
          if(control.expired(item.url))reason='origin-duration-limit';
          else if((control.soft(item.url)||o.budget.signals.responseMs>1000&&control.remainingMs(item.url)<o.budget.signals.responseMs*4)&&workPriority(item,this.config.urls,this.admittedRoots)>=2)reason='origin-soft-deadline';
          else if(o.requests>=o.budget.effective.resources)reason='origin-request-count-limit';
          else if(o.bytes>=o.budget.effective.bytes&&workPriority(item,this.config.urls,this.admittedRoots)>=2)reason='origin-byte-limit';
          else if(this.transport.requests>=this.config.maxResources)reason='request-count-limit';
          else if(this.transport.bytes>=Math.min(this.config.maxTotalBytes,this.config.maxDecodedTotalBytes))reason='total-byte-limit';
          if(reason){this.queue.splice(this.queue.indexOf(item),1);this.defer(item,reason);this.gap({code:reason,url:item.url,origin:own(item.url),detail:'Discovered work deferred at the configured origin or project boundary.',incomplete:true});}
        }
        // A website whose explicit browser page starts in this pass keeps its optional and low-value work back until the browser's document is answered (browserHeld): with a free
        // browser the order is the browser's entry document, then optional pages, as for deployment paths below.
        this.browserDue.clear();if(this.config.browser&&browserAttempts<this.config.browserPages&&browserRunning.size<this.caps.browserWebsites)for(const url of explicitBrowserUrls)if(browserEligible(url))this.browserDue.add(own(url));
        // Bounded asynchronous work window; completions replenish capacity individually.
        while(this.schedule.active.size<(this.config.globalConcurrency??this.config.concurrency)){
          const item=this.schedule.take(true);if(!item)break;
          launch(()=>turn(item.url,async()=>{try{await this.process(item);}catch(e){this.defer(item,e instanceof PolicyError?e.code:'processing-failure');this.gap({code:e instanceof PolicyError?e.code:'processing-failure',url:item.url,detail:'Origin work stopped; other authorized origins retain their turns.',incomplete:true});}finally{if(item.kind==='robots')this.robotsDone.add(own(item.url));this.schedule.finish(item);}}));
        }
        // Retained bodies are re-analyzed once in a backlog lane with fresh analysis turns; no request is made.
        while(this.backlog.length&&backlogActive<this.caps.analysisWorkers){const entry=this.backlog.shift()!;this.backlogBytes-=entry.bytes;backlogActive++;launch(()=>this.resumeAnalysis(entry).finally(()=>{backlogActive--;}));}
        // One navigation per browser turn. Queued origins get a turn before any
        // origin receives another; each turn uses a fresh guarded session.
        if(this.config.browser&&browserAttempts<this.config.browserPages){
          const candidates=browserCandidates().filter(browserEligible).sort((a,b)=>Number(!explicitBrowserUrls.has(a))-Number(!explicitBrowserUrls.has(b))||(browserAttemptsByOrigin.get(own(a))||0)-(browserAttemptsByOrigin.get(own(b))||0));
          for(const url of candidates){const origin=own(url);if(browserRunning.size>=this.caps.browserWebsites||browserAttempts>=this.config.browserPages)break;if(!browserEligible(url)||this.websiteWaiting()({url}))continue;
            browserAttempted.add(url);browserAttempts++;browserAttemptsByOrigin.set(origin,(browserAttemptsByOrigin.get(origin)||0)+1);browserRunning.add(origin);if(explicitBrowserUrls.has(url))this.browserHeld.add(origin);control.get(origin).browserAttempts++;this.browserPeak=Math.max(this.browserPeak,browserRunning.size);
            launch(()=>turn(origin,async()=>{const working=control.busy();try{await inspectBrowser(this,{urls:[url]});}finally{working();browserRunning.delete(origin);}},120000,'browser').finally(()=>this.browserDocumentSettled(origin)));
          }
        }
        this.browserDue.clear();
        for(const origin of this.transport.authorizedOrigins){
          const o=control.get(origin);if(o.started!==undefined&&!control.expired(origin)&&!analysisOrigins.has(origin)&&analysisActive<this.caps.analysisWorkers){const count=[...this.modules.values()].filter(m=>own(m.url)===origin).length;if(count>0&&analysisDone.get(origin)!==count){analysisDone.set(origin,count);analysisActive++;analysisOrigins.add(origin);launch(()=>control.run(origin,async()=>{const at=control.now();try{await this.reconstruct(origin);}catch(e){this.gap({code:e instanceof PolicyError?e.code:'analysis-failure',origin,detail:'Incremental origin analysis did not complete.',incomplete:true});}finally{o.analysisMs+=control.now()-at;analysisActive--;analysisOrigins.delete(origin);}},undefined,{inherit:false,turn:control.excludeSharedWaits?new TurnClock(control):undefined}));}}if(o.started===undefined||control.expired(origin)||o.activeRequests>0||this.resources.some(r=>r.analysis==='pending'&&own(r.url)===origin)||activeAt(origin)||browserRunning.has(origin)||analysisOrigins.has(origin)||this.queue.some(w=>own(w.url)===origin)||this.backlog.some(b=>own(b.item.url)===origin))continue;
          // Ready options: a website whose browser turn waits for a browser slot other websites hold queues its deployment paths meanwhile, so its time allowance is not spent idle
          // (a small computer has one browser website at once). A free browser keeps the order browser pages, then deployment paths; 2.5 configurations keep that order always.
          const deepNow=this.config.deep&&!deepDone.has(origin)&&this.config.urls.some(u=>own(u)===origin)&&!control.soft(origin);
          if(this.config.browser&&browserAttempts<this.config.browserPages&&browserCandidates().some(u=>own(u)===origin&&browserEligible(u))&&!(deepNow&&websiteSlots&&browserRunning.size>=this.caps.browserWebsites))continue;
          if(deepNow){
            // Both soft-404 baseline probes are kept at every traffic setting: they guard deployment-path precision against catch-all answers that vary.
            deepDone.add(origin);for(let i=0;i<2;i++)this.enqueue('/'+randomUUID().replaceAll('-','').slice(0,24),origin,0,[],'baseline');for(const p of this.config.deepPaths)this.enqueue(p,origin,0,[],'deep');continue;
          }
          const count=[...this.modules.values()].filter(m=>own(m.url)===origin).length;
          if(analysisActive<this.caps.analysisWorkers&&analysisDone.get(origin)!==count){analysisDone.set(origin,count);analysisActive++;analysisOrigins.add(origin);
            launch(()=>control.run(origin,async()=>{const at=control.now();try{await this.reconstruct(origin);}catch(e){this.gap({code:e instanceof PolicyError?e.code:'analysis-failure',origin,detail:'Origin analysis did not complete.',incomplete:true});}finally{o.analysisMs+=control.now()-at;analysisActive--;analysisOrigins.delete(origin);}},undefined,{inherit:false,turn:control.excludeSharedWaits?new TurnClock(control):undefined}));
          }else if(analysisDone.get(origin)===count)control.finish(origin);
        }
        if(running.size||this.admissions.size||this.backlog.length){await Promise.race([...running,...this.admissions,...(this.browserHeld.size?[new Promise<void>(r=>{this.browserReleased=r;})]:[]),...(this.backlog.length&&!running.size&&!this.admissions.size?[Promise.resolve()]:[])]);continue;}
        const waits=this.websiteWaiting();if(this.queue.some(w=>!this.blockedWork(w)&&!waits(w)&&(!w.notBefore||w.notBefore<=Date.now())))continue;
        if(this.queue.length){const due=this.queue.map(w=>w.notBefore||0).filter(t=>t>Date.now());if(due.length){await new Promise(r=>setTimeout(r,Math.min(50,Math.max(1,Math.min(...due)-Date.now()))));continue;} // No eligible work: preserve it as deferred.
          for(const item of this.queue.splice(0))this.defer(item,'scheduler-blocked');
        }
        // A phase may just have queued deployment work.
        if(this.transport.authorizedOrigins.some(o=>!control.expired(o)&&analysisDone.get(o)!==[...this.modules.values()].filter(m=>own(m.url)===o).length&&control.get(o).started!==undefined))continue;
        break;
      }
      await Promise.allSettled(running);if(this.config.browser)for(const url of this.config.browserNavigationUrls||[])if(!browserAttempted.has(url)){this.defer({url,depth:0,chain:['explicitly approved browser route'],kind:'browser-page'},'approved-browser-route-uninspected');this.gap({code:'approved-browser-route-uninspected',url,detail:'Explicitly approved application route did not receive a browser turn within the configured page/deadline/scope limits.',incomplete:true});}await Promise.allSettled(this.inlineTasks);await Promise.allSettled(this.admissions);await Promise.allSettled(running);
    }catch(e){this.stopReason=e instanceof PolicyError?e.code:'scan-failure';this.gap({code:this.stopReason,detail:'Scan stopped before planned coverage finished.',incomplete:true});}
    finally{if(!project.aborted&&this.transport.remainingMs()<=0)this.transport.expire();this.timerClosed=true;clearTimeout(this.projectTimer);for(const origin of this.transport.authorizedOrigins)control.finish(origin);this.transport.close();}
    if(project.aborted){this.stopReason=this.transport.stopCause;for(const item of this.queue.splice(0))this.defer(item,this.stopReason);this.gap({code:this.stopReason,detail:'Project stop propagated to network, browser and analysis work; retained results remain reviewable.',incomplete:true,cause:this.transport.abortCause(project)});}
    this.finalizeLifecycle();
    if(this.config.coverage==='quick'){const n=new Set([...this.quickSkips.values()].flatMap(e=>[...e.urls])).size;this.gap({code:'quick-coverage-boundary',detail:`Quick check examined common secret locations only: entry documents, their scripts and modules, source maps, manifests, configuration files and deployment paths. ${n} discovered URL${n===1?' was':'s were'} outside its target set and not requested; linked pages, sitemaps and the isolated browser were not examined. This does not show that the site has no other exposures; Standard or Deep audit examines more.`,incomplete:false,count:n,examples:[...this.quickSkips.values()].flatMap(e=>e.examples).slice(0,10)});}
    for(const g of this.limitations)if(g.url&&['http-unavailable','http-refusal','authentication-challenge','suspected-bot-challenge','text-decoding','unrouted-browser-traffic','request-timeout','network-failure','rate-limit','header-analysis-failure','analysis-interrupted','preflight-failure'].includes(g.code)&&this.resources.some(r=>r.url===g.url&&r.status==='scanned'&&!r.partial&&r.analysis==='analyzed')){g.incomplete=false;g.detail+=' Required text recovered through another guarded attempt.';}
    for(const issue of initialDetectorIssues)this.gap({code:'detector-unavailable',detail:issue,incomplete:true});
    await this.evidence.triage?.flush();this.evidence.triage?.close();if(this.evidence.dismissedAuditLimited)this.gap({code:'dismissed-audit-limit',detail:'Masked dismissed observation audit reached 1000 rows; further dismissals counted but individual evidence omitted.',incomplete:true});if(this.evidence.exposureAnalysisLimited)this.gap({code:'exposure-structure-limit',detail:'Some JSON-like content exceeded 4 MiB/10000 fields/32 levels or was not valid JSON. Structural exposure checks are incomplete; credential inspection remains separate.',incomplete:true});
    this.endedAt=new Date().toISOString();this.state=project.aborted&&this.transport.stopCause==='cancelled'?'cancelled':this.limitations.some(g=>g.incomplete)||this.deferred.length?'incomplete':'completed';
    if(['not-started','running'].includes(this.stopReason)&&this.transport.requests>=this.config.maxResources&&this.deferred.length)this.stopReason='request-count-limit';
    if(['not-started','running'].includes(this.stopReason))this.stopReason=control.snapshots().some(o=>o.deadlineReached)?'origin-deadline-reached':this.state==='cancelled'?'operator-cancelled':'discovered-frontier-drained';
    const issues=this.lifecycleIssues(this.view());if(issues.length){this.gap({code:'lifecycle-inconsistency',detail:'Lifecycle invariant violated after the run ended: '+issues.join('; ')+'. Unresolved work is never marked complete.',incomplete:true});}
    if(this.state==='completed'&&(issues.length||this.view().coverage?.assessment!=='configured-checks-completed'))this.state='incomplete';
    // Quick check ends when its target set is done: completed with quick coverage, never "no secrets". An unfinished target set stays incomplete with its reasons.
    if(this.config.coverage==='quick'&&this.state==='completed')this.stopReason='quick-target-set-done';
    this.stage=this.state==='completed'?this.config.coverage==='quick'?'Completed — quick coverage':this.profileSkipped.size?'Completed — limited by profile':'Configured checks finished':'Stopped with coverage limitations';return this.view();
  }
  /** Every piece of unfinished work gets an explicit terminal state before the final verdict; nothing unresolved is marked complete. */
  private finalizeLifecycle(){
    const project=this.transport.projectSignal,cause=project.aborted?this.transport.abortCause(project):undefined,own=(u:string)=>{try{return new URL(u).origin;}catch{return '';}};
    for(const item of this.queue.splice(0))this.defer(item,cause?.kind||'late-discovery-after-drain');
    for(const b of this.backlog.splice(0)){const r=b.response.resource;if(r){r.analysis='deferred';r.reason='analysis-deferred';}this.backlogStats.deferred++;this.gap({code:'analysis-interrupted',url:b.item.url,attemptId:r?.attemptId,detail:'Downloaded body was retained for deferred analysis but the run ended before it could be resumed.',incomplete:true,cause:b.cause});}this.backlogBytes=0;
    for(const r of this.resources)if(r.code!==undefined&&r.analysis==='pending'&&r.status!=='blocked'){r.analysis='deferred';r.reason||=cause?'analysis-'+cause.kind:'run-ended-before-analysis';}
    for(const url of this.modules.keys())if(!this.semanticOutcomes.has(url)){const origin=own(url),state=this.transport.originControl.peek(origin),allocation=state?.budget.effective.analysisMs??0,kind=state?.controller.signal.aborted?'origin-deadline':(this.analysisSpent.get(origin)||0)>=allocation&&allocation>0?'analysis-allocation-exhausted':cause?cause.kind:'run-ended-before-analysis';this.semanticOutcomes.set(url,{status:'deferred',reason:kind==='analysis-allocation-exhausted'?'Website analysis time allocation exhausted before this module was analyzed':kind==='run-ended-before-analysis'?'Run ended before analysis':'Analysis interrupted: '+kind,cause:{kind,origin,analyzer:'semantic'}});}
    for(const url of new Set([...this.modules.keys(),...this.moduleAliases.keys(),...this.semanticOutcomes.keys()]))this.applySemantic(url);
    for(const r of this.resources)for(const [name,a]of Object.entries(r.analyzers||{}))if(a&&a.status==='not-attempted'&&name!=='debugger'){a.status='deferred';a.reason||='Run ended before this analyzer ran';}
    const perOrigin=new Map<string,{count:number;examples:string[]}>();for(const r of this.resources){if(r.status==='blocked'||r.status==='skipped')continue;const unfinished=r.analysis==='deferred'||Object.entries(r.analyzers||{}).some(([n,a])=>n!=='debugger'&&a&&(a.status==='deferred'||a.status==='incomplete'));if(!unfinished)continue;const origin=own(r.url);const e=perOrigin.get(origin)||{count:0,examples:[]};e.count++;if(e.examples.length<10&&!e.examples.includes(r.url))e.examples.push(r.url);perOrigin.set(origin,e);}
    for(const [origin,e]of perOrigin)this.gap({code:'analysis-unfinished',origin,detail:`${e.count} downloaded resource${e.count===1?'':'s'} did not finish every configured analyzer (deferred or partial). Each resource carries its terminal analyzer state and cause.`,incomplete:true,count:e.count,examples:e.examples});
    if(this.config.scopeReview){const inside=[...this.transport.notAdmitted.values()].filter(n=>n.reason==='exact-origin-mode');if(inside.length)this.gap({code:'legacy-exact-origin-scope',detail:`This project was saved before domain scope became the default and still scans only its exact origins. ${inside.length} origin${inside.length===1?'':'s'} inside the entered domain ${inside.length===1?'was':'were'} referenced but not scanned. Adopt domain scope from the project card to include them.`,incomplete:false,count:inside.length,examples:inside.slice(0,10).map(n=>n.origin)});}
  }
  private lifecycleIssues(view:ScanView){const issues:string[]=[];const rows=view.coverage?.inventory||[];if(rows.some(r=>r.state==='pending'))issues.push('pending inventory rows after the run ended');if(view.counts.pending)issues.push('live work counted after the run ended');if(view.resources.some(r=>Object.entries(r.analyzers||{}).some(([n,a])=>n!=='debugger'&&a?.status==='not-attempted')))issues.push('not-attempted analyzers after the run ended');if((view.websites?.importantUninspected||0)>0&&view.coverage?.assessment==='configured-checks-completed')issues.push('important unresolved work with a completed verdict');return issues;}
  cancel(){this.transport.cancel();}
  fail(){this.gap({code:'scan-failure',detail:'Scan processing failed; retained redacted results remain reviewable. Check build parity and diagnostics before re-fetching authorized seeds.',incomplete:true});this.endedAt=new Date().toISOString();this.state='incomplete';this.stopReason='scan-failure';this.stage='Failed with recoverable results';}
  dispose(){this.cancel();this.transport.close();if(this.ownsPool)void this.pool.dispose();this.evidence.clear();this.modules.clear();this.groupAttempts.clear();this.semanticOutcomes.clear();this.semanticEvidence.clear();this.moduleHashes.clear();this.analysisSpent.clear();this.inventory.clear();this.moduleBytes=0;this.graph=[];this.graphKeys.clear();this.resources=[];this.limitations=[];this.queue=[];this.deferred=[];this.backlog=[];this.backlogBytes=0;this.pages=[];this.config.urls=[];this.imageGroups.clear();this.skippedImageUrls.clear();this.routeFailures.clear();this.discoveries.clear();this.documentMaps.clear();this.moduleDocuments.clear();this.moduleAliases.clear();this.documentFingerprints.clear();this.discoveryCache.clear();this.discoveryCacheBytes=0;this.processedDiscoveries.clear();this.runtimeCaptureHashes.clear();this.quickScripts.clear();this.quickSkips.clear();clearTimeout(this.projectTimer);this.schedule.active.clear();this.schedule.dispatches.length=0;}
  private schedulerView(){const result=this.schedule.view();for(const [name,value]of Object.entries(result.classes))value.deferred=this.deferred.filter(w=>workClass(w,this.config.urls)===name).length;return result;}
  private scopeView():ScopeView{
    const base=this.transport.scope.describe(this.scopeSource),snapshots=this.transport.originControl.snapshots();
    for(const g of base.groups){g.admittedOrigins=[...this.transport.authorizations].filter(([,a])=>a.type==='same-registrable-domain'&&a.registrableDomain===g.registrableDomain).map(([o])=>o);g.contactedOrigins=snapshots.filter(o=>o.requests>0&&this.transport.isAuthorized(o.origin)&&registrableDomain(o.origin)===g.registrableDomain).map(o=>o.origin);const byReason=new Map<string,{count:number;examples:string[]}>();for(const n of this.transport.notAdmitted.values()){if(registrableDomain(n.origin)!==g.registrableDomain)continue;const e=byReason.get(n.reason)||{count:0,examples:[]};e.count+=n.count;if(e.examples.length<10)e.examples.push(n.origin);byReason.set(n.reason,e);}g.notAdmitted=[...byReason].map(([reason,e])=>({reason,...e}));}
    base.autoAdmitted=[...this.transport.authorizations.values()].filter(a=>a.type==='same-registrable-domain').length;base.excluded=this.transport.exclusionsView();base.protected=this.transport.protectedView();return base;
  }
  private analysisView():AnalysisView{const origins:AnalysisView['origins']={};for(const o of this.transport.originControl.states.values()){if(!this.transport.isAuthorized(o.origin))continue;const s=this.analysisJobs.get(o.origin);origins[o.origin]={allocationMs:o.budget.effective.analysisMs,maximumMs:o.budget.maximum.analysisMs,chargedMs:Math.round(this.analysisSpent.get(o.origin)||0),queueWaitMs:Math.round(s?.queueWaitMs||0),startupMs:Math.round(s?.startupMs||0),workerMs:Math.round(s?.workerMs||0),cleanupMs:Math.round(s?.cleanupMs||0),viewInspectionMs:Math.round(s?.viewInspectionMs||0),jobs:s?.jobs||0,reusedVerdicts:s?.reusedVerdicts||0,outcomes:{...(s?.outcomes||{})}};}return {origins,interruptions:{...this.interruptions},backlog:{items:this.backlog.length,bytes:this.backlogBytes,...this.backlogStats},timeFactor:this.timeFactorView(),note:'chargedMs is the elapsed allocation charge (worker startup, parsing, propagation and cleanup, bounded by the slice); workerMs is the parser-reported time inside the worker; queueWaitMs is time between module admission and job start, plus the wait for a free parser worker or for analysis memory (never charged). viewInspectionMs is not charged to the allocation.'+(this.timeFactor.factor!==1?` Analysis time budgets ×${this.timeFactor.factor} for this computer (${this.timeFactor.detail}): allocations, group slice and time limits are scaled; memory and the scan's duration limit are not.`:'')};}
  /** The analysis time factor and the budgets it gives (next to the per-website allocations, which already include it). */
  private timeFactorView():NonNullable<AnalysisView['timeFactor']>{const f=this.timeFactor,slice=scaleMs(this.config.semanticSliceMs!,f.factor);return {factor:f.factor,source:f.source,detail:f.detail,...(f.speedRatio!==undefined?{speedRatio:f.speedRatio}:{}),...(f.cpus!==undefined?{cpus:f.cpus}:{}),sliceMs:slice,groupTimeoutMs:slice+scaleMs(GROUP_MARGIN_MS,f.factor),viewInspectionMs:scaleMs(VIEW_INSPECTION_MS,f.factor)};}
  /** Affected assets per finding: the current deployment, a previous deployment only (reached solely through history or manifest replay), or a local artifact. */
  private assignAssets(){const byUrl=new Map<string,Resource>();for(const r of this.resources)if(r.code!==undefined)byUrl.set(r.url,r);const previous=(c:string[])=>c.length>0&&['authorized project history','previous authorized scan or owner deployment manifest'].includes(c[0]);
    for(const f of this.evidence.findings.values()){const seen=new Map<string,NonNullable<import('./types.js').Finding['assets']>[number]>();for(const o of f.occurrences){if(seen.size>=50)break;const url=o.url.split('#')[0];if(seen.has(url))continue;const r=byUrl.get(url),chains=r?.discoveryChains?.length?r.discoveryChains:[o.chain];seen.set(url,{url,deployment:url.startsWith('file:')?'local-only':chains.every(previous)?'previous-only':'current',...(r?.code!==undefined?{status:r.code}:{})});}f.assets=[...seen.values()];applyAssessment(f);}}
  view():ScanView{
    this.assignAssets();
    const summary=coverage(this.config,this.resources,[...this.queue,...this.deferred,...this.schedule.active.keys(),...this.backlog.map(b=>b.item)],this.state,this.browserStatus.runtimePages,{additionalEntryUrls:[...this.transport.authorizations].filter(([,a])=>a.type==='same-registrable-domain').map(([o])=>o+'/'),authorizedOrigins:this.transport.authorizedOrigins,inventory:this.inventory.values(),deferred:this.deferred,gaps:this.limitations,runtimePagesByOrigin:new Map(this.transport.originControl.snapshots().map(o=>[o.origin,o.browserPages])),stopReason:this.stopReason,inDomain:u=>this.transport.scope.inDomain(u),live:new Set([...this.queue,...this.schedule.active.keys(),...this.backlog.map(b=>b.item)].map(w=>w.url))});
    const unresolved=importantUnresolved(summary.inventory);
    const v:ScanView={retry:this.retry,...(this.launch?{launch:{...this.launch}}:{}),schema:'exposure-scan/1',acquisitionMode:this.acquisitionMode,build:BUILD,id:this.id,name:this.config.name,state:this.state,startedAt:this.startedAt,endedAt:this.endedAt,elapsedMs:this.startedAt?Date.parse(this.endedAt||new Date().toISOString())-Date.parse(this.startedAt):0,config:this.config,
      counts:{resources:this.transport.requests,scanned:this.resources.filter(r=>r.status==='scanned').length,blocked:this.resources.filter(r=>r.status==='blocked').length,bytes:this.transport.bytes,pending:this.queue.length+this.schedule.active.size+this.admissions.size+this.backlog.length+this.analysisActiveJobs,deferred:this.deferred.length,findings:this.evidence.findings.size},
      accounting:{networkAttempts:this.transport.requests,blockedEvents:this.resources.filter(r=>r.status==='blocked').length,uniqueResources:new Set(this.transport.attemptedUrls).size,repeatedRequests:Math.max(0,this.transport.requests-new Set(this.transport.attemptedUrls).size),downloadedBytes:this.transport.wireBytes,retainedDecodedBytes:this.transport.bytes,textAnalyzedBytes:this.resources.reduce((n,r)=>n+(r.textBytes||0),0),intentionalSkips:this.resources.filter(r=>r.status==='skipped'||r.analysis==='skipped'&&r.status!=='blocked').length,httpErrors:this.resources.filter(r=>!!r.code&&r.code>=400&&!r.servedFrom).length,networkFailures:this.resources.filter(r=>r.status==='failed'&&r.attemptId!==undefined&&['network-failure','dns-timeout','dns-empty','dns-invalid','connection-timeout','request-timeout','response-failure'].includes(r.reason||'')).length,timeouts:this.resources.filter(r=>r.status==='failed'&&/timeout/.test(r.reason||'')).length,failedAttempts:this.resources.filter(r=>r.status==='failed'&&r.attemptId!==undefined).length,successfulResponses:this.resources.filter(r=>r.code!==undefined&&r.code>=200&&r.code<300&&!r.servedFrom).length,discoveredUrls:new Set([...this.seen,...this.deferred.map(w=>w.url),...this.skippedImageUrls]).size,reusedTextInspections:this.detector.cacheHits,runtimeCaptures:this.browserAnalysis.capturedDebugger,reusedDiscoveries:this.discoverySummary.reusedDiscoveries,verifiedMirrors:this.browserAnalysis.verifiedMirrors,connectionsOpened:this.transport.connectionsOpened,connectionsReused:this.transport.connectionsReused,connectionReplays:this.transport.connectionReplays,tlsHandshakes:this.transport.tlsHandshakes,browserCacheHits:this.transport.browserCacheHits,requestsAvoided:this.transport.requestsAvoided,protectedHostBlocks:this.transport.protectedReferences,coverageGaps:this.limitations.filter(g=>g.incomplete).length},stopReason:this.stopReason,uninspected:[...this.queue,...this.deferred,...this.profileLimited].slice(0,2000),origins:this.transport.originControl.snapshots().filter(o=>this.transport.isAuthorized(o.origin)).map(o=>({...o,authorization:this.transport.authorizations.get(o.origin),completion:summary.origins[o.origin]?.assessment})),coverage:summary,
      scheduler:{...this.schedulerView(),peakBrowserOrigins:this.browserPeak,pageAttempts:this.pageAttempts,timeToFirstJavaScriptMs:this.firstJavaScript??this.resources.filter(r=>resourceType(r)==='javascript'&&r.analysis==='analyzed'&&r.timings?.analyzedAt).map(r=>r.timings!.analyzedAt!-this.transport.started).sort((a,b)=>a-b)[0],timeToFirstBrowserDocumentMs:this.firstBrowserDocument},aggregatedSkips:[{reason:'Known raster image bodies / Next image renditions intentionally skipped after local URL inspection; distinct source images stay separate',count:this.skippedImageUrls.size,families:this.imageGroups.size,examples:[...this.skippedImageUrls].slice(0,8)}].filter(g=>g.count>0),dismissedObservations:this.evidence.dismissedView(),websites:{mode:this.config.sizingMode!,count:this.transport.authorizedOrigins.length,analysisMs:[...this.analysisSpent.values()].reduce((a,b)=>a+b,0),analysisMsMeaning:'elapsed allocation charge (includes worker startup and cleanup, not the wait for a worker or analysis memory); see analysis.origins for the breakdown',importantUninspected:unresolved.total,limits:[...this.transport.originControl.states.values()].filter(o=>this.transport.isAuthorized(o.origin)).map(o=>o.budget.snapshot([...this.queue,...this.deferred],unresolved.byOrigin.get(o.origin)||0))},findingTriage:this.evidence.triage?.view(),engines:{websiteRules:RULE_VERSION,gitleaks:this.detector.version,ruleDigest:this.detector.ruleDigest,companyRules:this.detector.companyVersion},findings:[...this.evidence.findings.values()],resources:this.resources,limitations:this.limitations,stage:this.stage,browserStatus:this.browserStatus,semantic:this.semanticStats,discoveryGraph:{limit:4000,edges:this.graph.map(e=>({...e,status:e.to?this.resources.find(r=>r.url===e.to)?.analysis||e.status:e.status}))},requestProfile:this.requestProfile(),profile:this.profileView(),scope:this.scopeView(),analysis:this.analysisView(),discovery:{...this.discoverySummary,rejected:{...this.discoverySummary.rejected,examples:[...this.discoverySummary.rejected.examples]},fallbacks:{...this.discoverySummary.fallbacks},syntax:{...this.discoverySummary.syntax},sinks:{...this.discoverySummary.sinks}}};
    return this.evidence.redact(v);
  }
  /** Scan profile with live sizing: current shared caps (grown as websites are admitted), which hard ceilings bind, and for Quick check the completion and the not-examined categories. */
  profileView():ProfileView{
    const c=this.config,b=this.profileBase,quick=c.coverage==='quick';
    const total={pages:c.maxPages,resources:c.maxResources,bytes:c.maxTotalBytes,decodedBytes:c.maxDecodedTotalBytes,maps:c.maxMaps,browserPages:c.browserPages,projectDurationMs:c.projectMaxDurationMs??c.maxDurationMs,requestsPerSecond:c.requestsPerSecond,concurrency:c.globalConcurrency??c.concurrency};
    const ceilings={pages:HARD_CEILINGS.pages,resources:HARD_CEILINGS.resources,bytes:HARD_CEILINGS.bytes,decodedBytes:HARD_CEILINGS.decodedBytes,maps:HARD_CEILINGS.maps,browserPages:HARD_CEILINGS.browserPages,projectDurationMs:HARD_CEILINGS.projectDurationMs,originDurationMs:HARD_CEILINGS.originDurationMs};
    const admittedWebsites=[...(this.transport?.authorizations.values()||[])].filter(a=>a.type==='same-registrable-domain').length;
    return {...b,...(isRecommended(c.coverage,c.traffic)&&!c.profileCustomized?{recommended:true}:{}),examines:[...b.examines],skips:[...b.skips],resourceUse:resourceUse(c,b.sizing.explicitWebsites+admittedWebsites,this.computer),sizing:{...b.sizing,perWebsite:{...b.sizing.perWebsite},admittedWebsites,total,ceilings,cappedBy:(['pages','resources','bytes','decodedBytes','maps','browserPages','projectDurationMs'] as const).filter(k=>total[k]>=ceilings[k])},
      ...(quick&&this.state==='completed'?{completion:'quick-coverage' as const}:this.state==='completed'&&this.profileSkipped.size?{completion:'profile-limited' as const}:{}),...(this.profileSkipped.size?{profileLimit:this.profileLimitView()}:{}),...(quick?{notExamined:[...this.quickSkips].map(([category,e])=>({category,count:e.urls.size,examples:[...e.examples]}))}:{})};
  }
  /** What targets can see of this run's requests; reports and comparisons explain header-profile changes with it. */
  requestProfile():NonNullable<ScanView['requestProfile']>{return {headerProfile:HEADER_PROFILE,staticUserAgent:this.config.staticUserAgent==='none'?null:PRODUCT_USER_AGENT,acceptLanguage:acceptLanguage(this.config.browserLocale),browserLocale:this.config.browserLocale||'en-US',browserTimezone:this.config.browserTimezone||'UTC',referrer:'strict-origin, authorized initiators only',egress:'direct from this computer to the checked address; system proxies and proxy variables are not used'};}
  /** Cheap listing data for live runs: no coverage, resources or findings are computed or redacted. */
  brief():Pick<ScanView,'id'|'name'|'state'|'startedAt'|'endedAt'|'launch'|'build'|'stopReason'|'retry'|'config'|'origins'|'scope'|'counts'|'profile'>{
    const snapshots=this.transport.originControl.snapshots().filter(o=>this.transport.isAuthorized(o.origin)),sv=this.scopeView();
    return this.evidence.redact({id:this.id,name:this.config.name,state:this.state,startedAt:this.startedAt,endedAt:this.endedAt,...(this.launch?{launch:{...this.launch}}:{}),build:BUILD,stopReason:this.stopReason,...(this.retry?{retry:{...this.retry,selected:[],excluded:[]}}:{}),config:{...this.config},profile:this.profileView(),origins:snapshots.map(o=>({...o,authorization:this.transport.authorizations.get(o.origin)})),scope:{...sv,excluded:{...sv.excluded,examples:sv.excluded.examples.filter(e=>['exact-origin-mode','outside-host-subtree'].includes(e.reason)).map(e=>({origin:e.origin,count:e.count,reason:e.reason,kinds:[],urls:[]}))}},
      counts:{resources:this.transport.requests,scanned:this.resources.filter(r=>r.status==='scanned').length,blocked:this.resources.filter(r=>r.status==='blocked').length,bytes:this.transport.bytes,pending:this.queue.length+this.schedule.active.size+this.admissions.size+this.backlog.length+this.analysisActiveJobs,deferred:this.deferred.length,findings:this.evidence.findings.size}});
  }
  checkpoint(){
    // No response bodies, full values, fingerprint key or unvalidated URLs persist.
    // A restart re-fetches the authorized seeds to reconstruct evidence, then resumes
    // the safe discovered frontier. Counters/time budgets begin a new run.
    const safe=(url:string)=>!this.detector.inspectWindowed(url,false,this.analysis).some(c=>c.category==='private-credential'||c.category==='suspicious');
    return this.evidence.redact({schema:'exposure-checkpoint/1',createdAt:new Date().toISOString(),config:{...this.config,urls:this.config.urls.filter(safe)},frontier:[...this.queue,...this.deferred,...this.backlog.map(b=>({...b.item,deferredReason:'analysis-deferred'}))].filter(w=>safe(w.url)),redactedReview:this.view(),resume:'Fresh unauthenticated scan of seeds plus safe frontier; previous full values are not persisted.'});
  }
}
