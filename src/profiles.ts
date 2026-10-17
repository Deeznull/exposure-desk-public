import type {ScanConfig,Coverage,Traffic,ProfileKind,ProfileEstimate,WebsiteAllocation,ResourceUse} from './types.js';
/** Scan profiles (2.6): Coverage × Traffic with per-website allocations sized by website count. Pure data and arithmetic only: no I/O, shared by the scanner, CLI and dashboard.
 * The six profiles are the dashboard's ready options: each sets every number, including local memory and analysis workers, and adjusts itself to the website count and (lowering only) this computer. */
const MiB=1024*1024;
export const COVERAGES:Coverage[]=['quick','standard','deep'];
export const TRAFFICS:Traffic[]=['low-impact','normal'];
export const COVERAGE_LABELS:Record<Coverage,string>={quick:'Quick check',standard:'Standard',deep:'Deep audit'};
export const TRAFFIC_LABELS:Record<Traffic,string>={'low-impact':'Low-impact',normal:'Normal'};
/** The ready option marked "Recommended": the default for new projects on the scan page and in the CLI. */
export const RECOMMENDED:{coverage:Coverage;traffic:Traffic}={coverage:'standard',traffic:'normal'};
export const isRecommended=(coverage?:Coverage,traffic?:Traffic)=>coverage===RECOMMENDED.coverage&&traffic===RECOMMENDED.traffic;
export type LegacyPreset='quick'|'standard'|'thorough'|'exhaustive';
/** Profile equivalent of each legacy preset. Descriptive only: a legacy preset keeps its own stored numbers until the owner switches the project to profiles. */
export const LEGACY_PROFILES:Record<LegacyPreset,{coverage:Coverage;traffic:Traffic;note?:string}>={quick:{coverage:'quick',traffic:'normal'},standard:{coverage:'standard',traffic:'normal'},thorough:{coverage:'deep',traffic:'normal',note:'single-website pacing'},exhaustive:{coverage:'deep',traffic:'normal'}};
/** Owner's ceiling for analysis memory (MiB): no option, configuration file, CLI flag or saved project may exceed it (makeConfig refuses larger values). */
export const ANALYSIS_MEMORY_CEILING_MB=512;
/** Hard maxima that website-count sizing never exceeds (the same bounds makeConfig validates): shared caps, 8 websites at once, 4 browser websites at once, 12 requests at once and 20 requests/s in total, and the analysis-memory ceiling. */
export const HARD_CEILINGS={pages:500,resources:2000,bytes:500*MiB,decodedBytes:500*MiB,browserPages:50,maps:100,originDurationMs:3600000,projectDurationMs:360005000,requestsPerSecond:20,globalConcurrency:12,activeOrigins:8,browserOrigins:4,analysisMemoryMb:ANALYSIS_MEMORY_CEILING_MB} as const;
/** Additional deployment paths probed by every profile (legacy presets keep the 2.5 list): WordPress configuration backups and Git configuration. Each is confirmed by content before analysis. */
export const PROFILE_EXTRA_DEEP_PATHS=['/wp-config.php.bak','/.git/config'];
/** Quick check examines at most this many first-party scripts and modules per website (entry-document bundles first). */
export const QUICK_SCRIPTS_PER_WEBSITE=40;
/** Per-run options a profile sets by default but a run may override without becoming custom (deployment triggers request history replay). */
export const RUN_OPTION_KEYS=new Set(['staleAssetCheck']);
/** Shared caps and global pacing are derived from the per-website allocation and the website count; every other profile key is a per-website or coverage setting. */
export const SHARED_KEYS=new Set(['maxPages','maxResources','maxTotalBytes','maxDecodedTotalBytes','maxMaps','browserPages','projectMaxDurationMs','requestsPerSecond','globalConcurrency']);
/** Upper bound of each shared cap (an owner-entered limit above it is rejected). */
export const SHARED_CEILINGS:Record<string,number>={maxPages:HARD_CEILINGS.pages,maxResources:HARD_CEILINGS.resources,maxTotalBytes:HARD_CEILINGS.bytes,maxDecodedTotalBytes:HARD_CEILINGS.decodedBytes,maxMaps:HARD_CEILINGS.maps,browserPages:HARD_CEILINGS.browserPages,projectMaxDurationMs:HARD_CEILINGS.projectDurationMs,requestsPerSecond:HARD_CEILINGS.requestsPerSecond,globalConcurrency:HARD_CEILINGS.globalConcurrency};
/** Low-impact is a ceiling on load, never a floor: a custom Low-impact profile may be slower or less parallel than these values, never faster. Global pacing follows from them (at most 1 request/s and 2 at once). */
export const LOW_IMPACT_LIMITS={originRequestsPerSecond:.5,originConcurrency:1,concurrency:1,maxActiveOrigins:2,maxBrowserOrigins:1,maxRetries:0,queryVariants:1} as const;
export function enforceLowImpact<T extends Partial<ScanConfig>>(c:T):T{
  if(c.traffic!=='low-impact')return c;const r=c as Record<string,unknown>;
  for(const [k,max]of Object.entries(LOW_IMPACT_LIMITS))if(typeof r[k]==='number'&&(r[k] as number)>max)r[k]=max;
  if(c.adjacentMaps===true)c.adjacentMaps=false;return c;
}
const COVERAGE:Record<Coverage,{settings:Partial<ScanConfig>;allocation:Omit<WebsiteAllocation,'requestsPerSecond'|'concurrency'>}>={
  quick:{settings:{browser:false,deep:true,maxDepth:1,queryVariants:1,adjacentMaps:false,staleAssetCheck:false,sizingMode:'website-count',maxResourceBytes:8*MiB,maxWireResourceBytes:16*MiB,maxMapSources:40,browserScrollSteps:0},allocation:{pages:8,resources:100,bytes:40*MiB,decodedBytes:80*MiB,maps:10,browserPages:1,durationMs:120000}},
  standard:{settings:{browser:true,deep:true,maxDepth:3,queryVariants:3,adjacentMaps:true,staleAssetCheck:false,sizingMode:'website-count',maxResourceBytes:12*MiB,maxWireResourceBytes:16*MiB,maxMapSources:40,browserScrollSteps:2},allocation:{pages:30,resources:200,bytes:120*MiB,decodedBytes:160*MiB,maps:30,browserPages:5,durationMs:300000}},
  deep:{settings:{browser:true,deep:true,maxDepth:5,queryVariants:3,adjacentMaps:true,staleAssetCheck:true,sizingMode:'adaptive',maxResourceBytes:24*MiB,maxWireResourceBytes:24*MiB,maxMapSources:80,browserScrollSteps:5},allocation:{pages:80,resources:600,bytes:300*MiB,decodedBytes:400*MiB,maps:80,browserPages:15,durationMs:3600000}}
};
/** Query-string variants per path the coverage itself visits (its Normal-traffic value); Low-impact's lower value is that option's stated boundary. */
export const coverageQueryVariants=(c:Coverage)=>COVERAGE[c].settings.queryVariants??1;
/** Local resource use of each coverage, so nobody sets memory by hand: analysis memory (one budget for the parser and large-text worker heaps) and parallel analysis workers. Traffic does not change it. */
export const COVERAGE_RESOURCES:Record<Coverage,{maxAnalysisMemoryMb:number;analysisConcurrency:number}>={quick:{maxAnalysisMemoryMb:256,analysisConcurrency:1},standard:{maxAnalysisMemoryMb:256,analysisConcurrency:2},deep:{maxAnalysisMemoryMb:ANALYSIS_MEMORY_CEILING_MB,analysisConcurrency:2}};
/** Websites scanned at once, and websites with the isolated browser at once, per option (Quick check uses no browser). Low-impact never exceeds LOW_IMPACT_LIMITS. */
export const PARALLEL_WEBSITES:Record<Coverage,Record<Traffic,{websites:number;browser:number}>>={quick:{normal:{websites:6,browser:0},'low-impact':{websites:2,browser:0}},standard:{normal:{websites:4,browser:2},'low-impact':{websites:2,browser:1}},deep:{normal:{websites:3,browser:2},'low-impact':{websites:2,browser:1}}};
/** One plain line per ready option, for the option cards and CLI help. */
export const OPTION_SUMMARIES:Record<`${Coverage}+${Traffic}`,string>={
  'quick+normal':'Common secret locations only, no browser: the fastest first look.','quick+low-impact':'Common secret locations only, no browser, with fewer and slower requests.',
  'standard+normal':'Static discovery to depth 3 plus a few isolated-browser pages per website: a good default.','standard+low-impact':'Standard coverage with fewer and slower requests; takes longer.',
  'deep+normal':'Every place possible within the hard ceilings, with the longest time allowance.','deep+low-impact':'Deep coverage with fewer and slower requests; the longest scans.'
};
/** Low-impact keeps the coverage targets and lowers load: about 0.5 requests/s and one connection per website, at most two websites and two requests at once, no retries, one query variant, no adjacent-map guessing, fewer browser pages and a longer time allowance. */
const LOW_IMPACT_BROWSER_PAGES:Record<Coverage,number>={quick:1,standard:3,deep:6};
/** Normal per-website pace; Low-impact's time allowance grows by the ratio of the two paces (within the hard ceilings). */
const NORMAL_REQUESTS_PER_SECOND=2;
export function profileTables(coverage:Coverage,traffic:Traffic){
  const c=COVERAGE[coverage],low=traffic==='low-impact',parallel=PARALLEL_WEBSITES[coverage][traffic];
  const allocation:WebsiteAllocation={...c.allocation,requestsPerSecond:low?LOW_IMPACT_LIMITS.originRequestsPerSecond:NORMAL_REQUESTS_PER_SECOND,concurrency:low?1:coverage==='deep'?3:2};
  if(low){allocation.browserPages=LOW_IMPACT_BROWSER_PAGES[coverage];allocation.durationMs=Math.min(HARD_CEILINGS.originDurationMs,Math.ceil(allocation.durationMs*NORMAL_REQUESTS_PER_SECOND/LOW_IMPACT_LIMITS.originRequestsPerSecond));}
  // A browser-free option keeps the smallest valid browser setting (1); it is inert while the browser is off and reported as none.
  const pacing={maxActiveOrigins:parallel.websites,maxBrowserOrigins:Math.max(1,parallel.browser),maxRetries:low?0:1};
  return {allocation,pacing,settings:{...c.settings,...COVERAGE_RESOURCES[coverage],...(low?{queryVariants:1,adjacentMaps:false}:{})} as Partial<ScanConfig>};
}
/** Shared caps for `websites` websites: per-website allocation × websites, bounded by the hard ceilings. Global pacing grows only with the websites that may be active at once. */
export function sharedCaps(a:WebsiteAllocation,websites:number,maxActiveOrigins:number){
  const n=Math.max(1,Math.floor(websites)),active=Math.min(n,maxActiveOrigins);
  return {maxPages:Math.min(HARD_CEILINGS.pages,a.pages*n),maxResources:Math.min(HARD_CEILINGS.resources,a.resources*n),maxTotalBytes:Math.min(HARD_CEILINGS.bytes,a.bytes*n),maxDecodedTotalBytes:Math.min(HARD_CEILINGS.decodedBytes,a.decodedBytes*n),maxMaps:Math.min(HARD_CEILINGS.maps,a.maps*n),browserPages:Math.min(HARD_CEILINGS.browserPages,a.browserPages*n),projectMaxDurationMs:Math.min(HARD_CEILINGS.projectDurationMs,a.durationMs*n+5000),requestsPerSecond:Math.min(HARD_CEILINGS.requestsPerSecond,Math.round(a.requestsPerSecond*active*100)/100),globalConcurrency:Math.min(HARD_CEILINGS.globalConcurrency,a.concurrency*active)};
}
/** Every configuration value a profile sets for one website; shared caps are the single-website values and are sized when a scan starts and when a website is admitted. */
export function profileSettings(coverage:Coverage,traffic:Traffic,deepPaths:string[]):Partial<ScanConfig>{
  const {allocation:a,pacing,settings}=profileTables(coverage,traffic);
  return {...settings,...pacing,deepPaths:[...deepPaths,...PROFILE_EXTRA_DEEP_PATHS.filter(p=>!deepPaths.includes(p))],
    originMaxPages:a.pages,originMaxResources:a.resources,originMaxTotalBytes:a.bytes,originMaxMaps:a.maps,originBrowserPages:a.browserPages,originMaxDurationMs:a.durationMs,maxDurationMs:a.durationMs,
    originRequestsPerSecond:a.requestsPerSecond,originConcurrency:a.concurrency,concurrency:a.concurrency,...sharedCaps(a,1,pacing.maxActiveOrigins)};
}
export const profileLabel=(coverage:Coverage,traffic:Traffic)=>COVERAGE_LABELS[coverage]+' + '+TRAFFIC_LABELS[traffic];
/** How a configuration was chosen. Older configurations without coverage are a legacy preset (or custom); their numbers are never re-mapped. */
export function describeProfile(config:Partial<ScanConfig>):{kind:ProfileKind;label:string;coverage?:Coverage;traffic?:Traffic;legacyPreset?:string;equivalent?:{coverage:Coverage;traffic:Traffic;note?:string}}{
  if(config.coverage&&config.traffic){const label=profileLabel(config.coverage,config.traffic);return config.profileCustomized?{kind:'custom-profile',label:`Custom (based on ${label})`,coverage:config.coverage,traffic:config.traffic}:{kind:'profile',label,coverage:config.coverage,traffic:config.traffic};}
  const preset=typeof config.preset==='string'?config.preset:undefined;
  if(preset&&preset in LEGACY_PROFILES){const equivalent=LEGACY_PROFILES[preset as LegacyPreset];return {kind:'legacy-preset',label:`Legacy preset: ${preset}`,legacyPreset:preset,equivalent:{...equivalent}};}
  return {kind:'custom',label:'Custom',...(preset?{legacyPreset:preset}:{})};
}
export const COVERAGE_EXAMINES:Record<Coverage,string[]>={
  quick:['Entry documents and their inline scripts','Referenced first-party scripts and modules (up to '+QUICK_SCRIPTS_PER_WEBSITE+' per website, entry-document bundles first)','Referenced source maps','Framework build manifests and chunk tables (Next, Vite, webpack)','Web app manifest and referenced configuration files','robots.txt (respected)','High-value deployment paths (.env variants, config.json, .git/HEAD, backups)'],
  standard:['Static discovery to depth 3: entry documents, linked pages and sitemaps','Scripts, modules, source maps (with adjacent-map checks) and configuration','High-value deployment paths','A few isolated-browser pages per website with debugger capture'],
  deep:['Full static discovery to depth 5, linked pages and sitemaps','Isolated-browser routes with debugger capture','Source maps with adjacent-map checks','Query variants','All deployment paths','Stale assets from project history or a deployment manifest when supplied','Registrable-domain discovery (with domain scope)','Adaptive per-website allocations and long durations']
};
export const COVERAGE_SKIPS:Record<Coverage,string[]>={
  quick:['Linked pages and sitemaps (nothing beyond the entry documents is crawled)','Isolated-browser runtime: runtime-only values, lazy routes and debugger capture','Adjacent source-map guessing','Query-string variants','Scripts beyond the per-website bound','Stylesheets, fonts, images and heuristic URL hints','Replay of earlier-deployment assets other than scripts, source maps and configuration (replayed scripts have their own bound)'],
  standard:['Pages more than 3 links from an entry document','Browser pages beyond the per-website allocation','Replay of assets from earlier scans'],
  deep:['Anything beyond the hard ceilings (500 pages, 2000 resources, 500 MiB and 60 minutes per website)']
};
export const TRAFFIC_NOTES:Record<Traffic,string>={
  normal:'Normal pacing for the chosen coverage. Requests carry the honest Exposure Desk User-Agent.',
  'low-impact':'Low-impact reduces load: fewer and slower requests over one kept-alive connection per website, no second download of a file the website marks cacheable (the isolated browser reuses this run’s uncredentialed downloads), fewer browser pages and no retries. It does not hide the scan: websites still see every request, this computer’s IP address and the honest Exposure Desk User-Agent. No spoofing, evasion timing, proxy rotation or rate-limit bypass is used, and the scanner is not undetectable. Custom settings can make a Low-impact scan slower, never faster.'
};
/** What the chosen coverage examines and skips; Low-impact adds its own reductions to the skip list. */
export function coverageScope(coverage:Coverage,traffic:Traffic){return {examines:[...COVERAGE_EXAMINES[coverage]],skips:[...COVERAGE_SKIPS[coverage],...(traffic==='low-impact'&&coverage!=='quick'?['Adjacent source-map guessing and extra query-string variants (Low-impact)','Retries after timeouts or 429/503 answers (Low-impact)']:[])]};}
const BROWSER_PAGE_MS=6000;
/** Low-impact keeps one connection per website open between requests; it is opened again after an idle pause, a DNS change or a server close. Expected: one for static discovery, one for the deployment-path probes and one per browser page. */
const LOW_IMPACT_CONNECTION_PHASES=2;
const expectedConnections=(config:ScanConfig,requests:number,browserPages:number,websites:number)=>config.traffic==='low-impact'?Math.min(requests,(LOW_IMPACT_CONNECTION_PHASES*websites)+browserPages):requests;
/** Pure estimate from a configuration (unsized: as saved or entered) and website counts. Requests and bytes are upper bounds of the allocation;
 * time is the pacing needed to use that allocation, never more than the time ceilings. Scans stop earlier when websites have less to examine. */
export function estimateScan(config:ScanConfig,explicitWebsites:number,discoveredLimit=0):ProfileEstimate{
  const n=Math.max(1,explicitWebsites),perRps=config.originRequestsPerSecond??config.requestsPerSecond,maxActive=config.maxActiveOrigins??4;
  const per={requests:config.originMaxResources??config.maxResources,bytes:config.originMaxTotalBytes??config.maxTotalBytes,browserPages:config.browser?config.originBrowserPages??config.browserPages:0,durationMs:config.originMaxDurationMs??config.maxDurationMs};
  const browserMs=(pages:number,parallel:number)=>Math.ceil(pages/Math.max(1,parallel))*BROWSER_PAGE_MS;
  const perPaced=Math.min(per.durationMs,Math.ceil(per.requests/perRps*1000)+browserMs(per.browserPages,1));
  const totals=(websites:number)=>{
    const sized=sizedTotals(config,websites),requests=Math.min(sized.maxResources,per.requests*websites),active=Math.min(websites,maxActive),rate=Math.min(sized.requestsPerSecond,perRps*active);
    const pages=config.browser?Math.min(sized.browserPages,per.browserPages*websites):0,paced=Math.ceil(requests/rate*1000)+browserMs(pages,Math.min(websites,config.maxBrowserOrigins??2));
    return {websites,requests,connections:expectedConnections(config,requests,pages,websites),connectionsMax:requests,bytes:Math.min(sized.maxTotalBytes,per.bytes*websites),browserPages:pages,durationMs:sized.projectMaxDurationMs,pacedMs:Math.min(sized.projectMaxDurationMs,paced)};
  };
  const total=totals(n),withDiscovered=discoveredLimit>0?totals(n+discoveredLimit):undefined,expected=total.pacedMs;
  return {websites:{explicit:n,discoveredLimit},perWebsite:{...per,connections:expectedConnections(config,per.requests,per.browserPages,1),connectionsMax:per.requests,pacedMs:perPaced},total,...(withDiscovered?{withDiscovered}:{}),expectedMinutes:Math.max(1,Math.ceil(expected/60000)),
    basis:config.traffic==='low-impact'?'Requests and bytes are upper bounds of the allocation. Low-impact keeps one connection per website open between requests: expect about two per website plus one per browser page (opened again after a pause, a DNS change or a server close), and at most one per request. Files the run already downloaded are not downloaded again while the website marks them cacheable. Time is what the pacing needs to use the whole allocation, capped by the duration ceilings. Scans stop earlier when websites have less to examine.':'Requests, connections and bytes are upper bounds of the allocation (Normal traffic opens one connection per request); time is what the pacing needs to use the whole allocation, capped by the duration ceilings. Scans stop earlier when websites have less to examine.'};
}
/** Per-website allocation of a profile configuration: its own per-website values (as entered for a custom profile) and the coverage's decoded-bytes allowance. */
export function profileAllocation(config:Partial<ScanConfig>&{coverage:Coverage;traffic:Traffic}):WebsiteAllocation{
  const t=profileTables(config.coverage,config.traffic).allocation,bytes=config.originMaxTotalBytes??t.bytes;
  return {pages:config.originMaxPages??t.pages,resources:config.originMaxResources??t.resources,bytes,decodedBytes:Math.max(t.decodedBytes,bytes),maps:config.originMaxMaps??t.maps,browserPages:config.originBrowserPages??t.browserPages,durationMs:config.originMaxDurationMs??t.durationMs,requestsPerSecond:config.originRequestsPerSecond??t.requestsPerSecond,concurrency:config.originConcurrency??t.concurrency};
}
/** Shared caps of a profile configuration for `websites` websites: allocation × websites within the hard ceilings, and never above an owner-entered limit (`sharedLimits`). */
export function profileShared(config:Partial<ScanConfig>&{coverage:Coverage;traffic:Traffic},websites:number){
  const sized=sharedCaps(profileAllocation(config),websites,config.maxActiveOrigins??4) as Record<string,number>;
  for(const [k,v]of Object.entries(config.sharedLimits||{}))if(typeof v==='number'&&k in sized)sized[k]=Math.min(sized[k],v);
  return sized as ReturnType<typeof sharedCaps>;
}
const plural=(n:number,one:string,many=one+'s')=>`${n} ${n===1?one:many}`;
/** This computer, read when a scan starts and for the scan-page preview (`readComputer` in src/computer.ts). */
export interface Computer {cores:number;freeMemoryMb:number}
/** Below either value a computer is small: one analysis worker and one browser website. Analysis memory always stays within MEMORY_SHARE of the free memory, never below the configuration minimum (64 MiB per worker). */
export const SMALL_COMPUTER={cores:4,freeMemoryMb:2048} as const;
export const MEMORY_SHARE=.25;
const MIN_ANALYSIS_MEMORY_MB=64;
/** The local resource caps a scan runs with: the configuration's analysis workers, analysis memory and browser websites, lowered (never raised) for a small or busy computer.
 * Ready options and custom profiles only: legacy presets and custom settings without a profile run with their stored numbers, as in 2.5. */
export function computerCaps(config:Partial<ScanConfig>,computer?:Computer){
  const caps={analysisWorkers:config.analysisConcurrency??2,analysisMemoryMb:config.maxAnalysisMemoryMb??256,browserWebsites:config.maxBrowserOrigins??2},adjustments:ResourceUse['adjustments']=[];
  if(!computer||!config.coverage)return {...caps,adjustments};
  const cores=Math.max(1,Math.floor(computer.cores)),free=Math.max(0,Math.floor(computer.freeMemoryMb));
  const small=cores<SMALL_COMPUTER.cores?`this computer has ${plural(cores,'logical core')} (fewer than ${SMALL_COMPUTER.cores})`:free<SMALL_COMPUTER.freeMemoryMb?`this computer has ${free} MiB free memory (under ${SMALL_COMPUTER.freeMemoryMb/1024} GiB)`:undefined;
  if(small){
    if(caps.analysisWorkers>1){adjustments.push({setting:'analysisWorkers',from:caps.analysisWorkers,to:1,reason:small});caps.analysisWorkers=1;}
    if(config.browser&&caps.browserWebsites>1){adjustments.push({setting:'browserWebsitesAtOnce',from:caps.browserWebsites,to:1,reason:small});caps.browserWebsites=1;}
  }
  const share=Math.max(MIN_ANALYSIS_MEMORY_MB*caps.analysisWorkers,Math.floor(free*MEMORY_SHARE));
  if(share<caps.analysisMemoryMb){adjustments.push({setting:'analysisMemoryMb',from:caps.analysisMemoryMb,to:share,reason:`kept within a quarter of this computer’s ${free} MiB free memory`});caps.analysisMemoryMb=share;}
  return {...caps,adjustments};
}
const gib=(mb:number)=>(mb/1024).toFixed(1)+' GiB';
/** What an option uses for `websites` websites on this computer, in numbers and plain words: websites at once (never more than the websites in scope), browser websites at once, analysis memory and workers.
 * `option` holds the configuration's values, `used` the values after website-count and computer adjustment; `adjustments` lists every value lowered for this computer.
 * `discovered` (the scan page's discovered-website limit) adds `withDiscovered` when admitted websites could run more websites at once than the entered ones. */
export function resourceUse(config:Partial<ScanConfig>,websites:number,computer?:Computer,discovered=0):ResourceUse{
  const n=Math.max(1,Math.floor(websites)),caps=computerCaps(config,computer),browser=!!config.browser;
  const option={websitesAtOnce:config.maxActiveOrigins??4,browserWebsitesAtOnce:browser?config.maxBrowserOrigins??2:0,analysisMemoryMb:config.maxAnalysisMemoryMb??256,analysisWorkers:config.analysisConcurrency??2};
  const used={websitesAtOnce:Math.min(n,option.websitesAtOnce),browserWebsitesAtOnce:browser?Math.min(n,caps.browserWebsites):0,analysisMemoryMb:caps.analysisMemoryMb,analysisWorkers:caps.analysisWorkers};
  const more=Math.max(0,Math.floor(discovered)),reach=Math.min(n+more,option.websitesAtOnce),withDiscovered=more&&reach>used.websitesAtOnce?{websites:n+more,websitesAtOnce:reach,browserWebsitesAtOnce:browser?Math.min(n+more,caps.browserWebsites):0}:undefined;
  const lowered=(k:string)=>caps.adjustments.some(a=>a.setting===k),machine=computer?{cores:Math.max(1,Math.floor(computer.cores)),freeMemoryMb:Math.max(0,Math.floor(computer.freeMemoryMb))}:undefined;
  const summary=[`${plural(used.websitesAtOnce,'website')} at once, adjusted for ${plural(n,'website')}`,
    browser?`${used.browserWebsitesAtOnce} with the isolated browser at once${lowered('browserWebsitesAtOnce')?` (lowered from ${option.browserWebsitesAtOnce} for this computer)`:''}`:'no isolated browser',
    `${used.analysisMemoryMb} MiB analysis memory${lowered('analysisMemoryMb')?` (lowered from ${option.analysisMemoryMb} MiB for this computer)`:''}`,
    `${plural(used.analysisWorkers,'analysis worker')}${lowered('analysisWorkers')?` (lowered from ${option.analysisWorkers} for this computer)`:''}`];
  const computerNote=!config.coverage?'Legacy preset or custom settings: they run as entered and are not adjusted to this computer.':!machine?'This computer was not checked.':`This computer: ${plural(machine.cores,'logical core')}, ${gib(machine.freeMemoryMb)} free memory; ${caps.adjustments.length?'lowered '+caps.adjustments.map(a=>`${RESOURCE_LABELS[a.setting]} ${a.from} → ${a.to}`).join(', ')+'. Values are only ever lowered, never raised.':'nothing lowered.'}`;
  return {websites:n,option,used,...(withDiscovered?{withDiscovered}:{}),...(machine?{computer:machine}:{}),adjustments:caps.adjustments,summary,computerNote};
}
/** The start estimate a scan records: the pure estimate with the browser websites this computer allows. */
export function startEstimate(config:ScanConfig,websites:number,discovered:number,computer?:Computer):ProfileEstimate{const caps=computerCaps(config,computer);return estimateScan(caps.browserWebsites<(config.maxBrowserOrigins??2)?{...config,maxBrowserOrigins:caps.browserWebsites}:config,websites,discovered);}
export const RESOURCE_LABELS:Record<ResourceUse['adjustments'][number]['setting'],string>={analysisWorkers:'analysis workers',browserWebsitesAtOnce:'browser websites at once',analysisMemoryMb:'analysis memory (MiB)'};
/** Shared totals for a website count: profile sizing for profile configurations, legacy website-count growth otherwise (unchanged 2.5 behaviour for fixed or adaptive legacy settings). */
export function sizedTotals(config:ScanConfig,websites:number){
  const n=Math.max(1,websites);
  if(config.coverage&&config.traffic)return profileShared(config as ScanConfig&{coverage:Coverage;traffic:Traffic},n);
  const grow=(current:number,perOrigin:number,max:number)=>Math.min(max,Math.max(current,perOrigin*n)),scaled=config.sizingMode==='website-count';
  return {maxPages:scaled?grow(config.maxPages,config.originMaxPages!,HARD_CEILINGS.pages):config.maxPages,maxResources:scaled?grow(config.maxResources,config.originMaxResources!,HARD_CEILINGS.resources):config.maxResources,maxTotalBytes:scaled?grow(config.maxTotalBytes,config.originMaxTotalBytes!,HARD_CEILINGS.bytes):config.maxTotalBytes,maxDecodedTotalBytes:scaled?grow(config.maxDecodedTotalBytes,config.originMaxTotalBytes!,HARD_CEILINGS.decodedBytes):config.maxDecodedTotalBytes,maxMaps:scaled?grow(config.maxMaps,config.originMaxMaps!,HARD_CEILINGS.maps):config.maxMaps,browserPages:scaled?grow(config.browserPages,config.originBrowserPages!,HARD_CEILINGS.browserPages):config.browserPages,projectMaxDurationMs:scaled?grow(config.projectMaxDurationMs!,config.originMaxDurationMs!,HARD_CEILINGS.projectDurationMs):config.projectMaxDurationMs!,requestsPerSecond:config.requestsPerSecond,globalConcurrency:config.globalConcurrency!};
}
