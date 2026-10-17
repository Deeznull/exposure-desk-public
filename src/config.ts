import type { ScanConfig } from './types.js';
import { DOMAIN_SCOPES, ScopePolicy, validHostLabels, websiteHost } from './domain-scope.js';
import { defaultProjectName, SafeError } from './runs.js';
import { assertConfigNotProtected, assertNotProtected } from './protected-hosts.js';
import { normalizeProgramConfig, programScope } from './program/settings.js';
import { COVERAGES, TRAFFICS, LEGACY_PROFILES, SHARED_KEYS, SHARED_CEILINGS, RUN_OPTION_KEYS, HARD_CEILINGS, profileSettings, profileLabel, profileShared, enforceLowImpact, sizedTotals, type LegacyPreset } from './profiles.js';
export const deepPaths = ['/.env','/.env.local','/.env.production','/.env.backup','/config.json','/config.js','/.npmrc','/.git/HEAD','/debug','/debug/vars','/server.log','/error.log','/backup.sql','/index.php.bak','/config.php.bak'];
/** Profile resolution reads the raw input, like scope: omitted coverage and traffic leave a legacy preset or custom numbers exactly as given (never re-mapped).
 * An explicit profile fills every profile key from its tables; an explicit per-website value that differs makes it "Custom (based on …)", whose numbers are then kept as entered.
 * Shared caps are derived from the per-website allocation and sized by website count at scan start and on admission. In entered settings (JSON, CLI, API) a shared cap is the owner's
 * limit: website-count sizing never raises it, and it makes the profile custom. A configuration this build wrote carries `sharedLimits`, so its derived (possibly sized) shared caps
 * are re-derived rather than taken as limits. Low-impact pacing is a ceiling custom values cannot raise. A legacy preset name may accompany a profile only when its coverage agrees. */
function resolveProfile(input:Partial<ScanConfig>):Partial<ScanConfig>{
  const {coverage,traffic,profileCustomized}=input,raw=input as Record<string,unknown>;
  if(coverage===undefined&&traffic===undefined){if(profileCustomized!==undefined||input.sharedLimits!==undefined)throw new Error('Invalid setting: profileCustomized and sharedLimits require coverage and traffic');return input;}
  if(coverage!==undefined&&!COVERAGES.includes(coverage))throw new Error('Invalid setting: coverage');
  if(traffic!==undefined&&!TRAFFICS.includes(traffic))throw new Error('Invalid setting: traffic');
  if(profileCustomized!==undefined&&typeof profileCustomized!=='boolean')throw new Error('Invalid setting: profileCustomized');
  if(input.preset!==undefined&&!['quick','standard','thorough','exhaustive','custom'].includes(input.preset))throw new Error('Invalid preset');
  if(input.sizingMode==='fixed')throw new Error('Conflicting settings: profiles size shared caps by website count; fixed sizing needs a legacy preset or custom settings without coverage');
  const legacy=input.preset&&input.preset!=='custom'?LEGACY_PROFILES[input.preset as LegacyPreset]:undefined,c=coverage??legacy?.coverage??'standard',t=traffic??'normal';
  if(legacy&&coverage!==undefined&&legacy.coverage!==coverage)throw new Error(`Conflicting settings: preset ${input.preset} corresponds to ${profileLabel(legacy.coverage,legacy.traffic)}, not coverage ${coverage}`);
  const entered=input.sharedLimits===undefined?raw:input.sharedLimits as Record<string,unknown>,limits:Record<string,number>={};
  if(entered===null||typeof entered!=='object'||Array.isArray(entered))throw new Error('Invalid setting: sharedLimits');
  for(const [k,v]of Object.entries(entered)){
    if(!SHARED_KEYS.has(k)){if(entered!==raw)throw new Error('Invalid setting: sharedLimits');continue;}
    if(v===undefined)continue;
    if(typeof v!=='number'||!Number.isFinite(v)||v<=0||v>SHARED_CEILINGS[k]||(k!=='requestsPerSecond'&&!Number.isInteger(v)))throw new Error('Invalid setting: '+k);
    limits[k]=v;
  }
  const table=profileSettings(c,t,deepPaths);
  let customized=profileCustomized===true||Object.keys(limits).length>0;
  if(!customized)for(const [k,v]of Object.entries(table))if(!SHARED_KEYS.has(k)&&!RUN_OPTION_KEYS.has(k)&&raw[k]!==undefined&&JSON.stringify(raw[k])!==JSON.stringify(v)){customized=true;break;}
  const own=Object.fromEntries(Object.entries(input).filter(([k])=>!SHARED_KEYS.has(k)&&k!=='sharedLimits'));
  const out=enforceLowImpact(customized?{...table,...own}:{...own,...table,...Object.fromEntries([...RUN_OPTION_KEYS].filter(k=>raw[k]!==undefined).map(k=>[k,raw[k]]))}) as Partial<ScanConfig>;
  out.preset='custom';out.coverage=c;out.traffic=t;out.sharedLimits=limits as ScanConfig['sharedLimits'];if(customized)out.profileCustomized=true;else delete out.profileCustomized;
  return Object.assign(out,profileShared(out as Partial<ScanConfig>&{coverage:typeof c;traffic:typeof t},1));
}
export function normalizeUrl(input: string, base?: string): string {
  const u = new URL(input, base);
  if (!['http:', 'https:'].includes(u.protocol) || u.username || u.password) throw new Error('Only HTTP(S) URLs without user credentials are allowed');
  // Exactly one trailing dot is canonical for the same host; empty or wildcard labels are never a host.
  if (u.hostname.endsWith('.') && !u.hostname.endsWith('..')) u.hostname = u.hostname.slice(0, -1);
  if (!validHostLabels(u.hostname)) throw new Error('Invalid hostname label');
  if (u.href.length > 4096) throw new Error('URL too long');
  u.hash = ''; return u.href; // Preserve query order/escaping; targets may assign semantics to them.
}
const SCHEME=/^[A-Za-z][A-Za-z0-9+.-]*:\/\//;
/** The first host in a configuration's URL fields (seeds, related and private origins, development fixture origin, read-only POST endpoints, browser routes and stale assets)
 * that is not a website host (see websiteHost), cut to 100 characters. Works on raw input and on made configurations alike; entries that do not parse as HTTP(S) URLs are left to makeConfig. */
export function invalidHost(raw:unknown):string|undefined{
  if(!raw||typeof raw!=='object')return undefined;
  const c=raw as Record<string,unknown>,list=(v:unknown)=>Array.isArray(v)?v.filter((x):x is string=>typeof x==='string'):[];
  const parse=(s:string,base?:string)=>{try{const u=new URL(s,base);return u.protocol==='http:'||u.protocol==='https:'?u:undefined;}catch{return undefined;}};
  const seeds=list(c.urls).map(s=>parse(SCHEME.test(s.trim())?s.trim():'https://'+s.trim())),base=seeds[0]?.href;
  const absolute=[...list(c.relatedOrigins),...list(c.privateOrigins),...list(c.readOnlyPostEndpoints),...(typeof c.developmentFixtureOrigin==='string'?[c.developmentFixtureOrigin]:[])].map(s=>parse(s));
  const relative=[...list(c.browserNavigationUrls),...list(c.staleAssetUrls)].map(s=>parse(s,base));
  for(const u of [...seeds,...absolute,...relative])if(u&&!websiteHost(u.hostname))return u.hostname.slice(0,100);
  return undefined;
}
/** One message for every refusal of a non-website host: new input (CLI, configuration files, dashboard) and the start of a scan of a saved record that has one. */
export const invalidHostMessage=(host:string)=>`Refused: "${host}" is not a valid website host. A host uses letters, digits, hyphens and underscores (international names are converted automatically) or is an IP address. Nothing was requested.`;
/** The allow-listed refusal (code invalid-url, the reason --targets gives the same host): the dashboard returns its message and host, the CLI prints the message and exits 2. */
export const invalidHostError=(host:string)=>new SafeError(invalidHostMessage(host),'invalid-url',400,{host});
export const isInvalidHostError=(e:unknown):e is SafeError=>e instanceof SafeError&&e.code==='invalid-url';
export function assertWebsiteHosts(raw:unknown){const host=invalidHost(raw);if(host!==undefined)throw invalidHostError(host);}
/** makeConfig for new input: the protected-host rule first (inside makeConfig), then every host must be a website host. Saved records load through makeConfig and keep loading. */
export function makeNewConfig(raw:Partial<ScanConfig>):ScanConfig{const c=makeConfig(raw);assertWebsiteHosts(c);return c;}
export function exactOrigin(input: string): string {
  const u = new URL(normalizeUrl(input));
  if (u.pathname !== '/' || u.search) throw new Error('Origin entries must contain only scheme, host and port');
  return u.origin;
}
export function makeConfig(raw: Partial<ScanConfig>): ScanConfig {
  // Hard rule, before any other validation and with no override: a configuration naming a government, military, intelligence or law-enforcement host is refused.
  assertConfigNotProtected(raw);
  const input=resolveProfile(raw);
  const c: ScanConfig = { name: '', urls: [], relatedOrigins: [], privateOrigins: [], browser: false, maxAutoDiscoveredOrigins:50,
    autoScaleByWebsiteCount:false,originAnalysisMs:12000,semanticSliceMs:1600,maxModuleAnalysisBytes:4*1024*1024,maxAnalysisBytes:32*1024*1024,originAnalysisBytes:16*1024*1024,analysisConcurrency:2,maxAnalysisMemoryMb:256,browserLazyAssetLimit:20,sensitiveFields:[],
    workTurnMs:30000,analysisTurnMs:60000,analysisBacklogBytes:32*1024*1024,maxDiscoveryBytes:4*1024*1024,browserBaselineMs:750,browserLocale:'en-US',browserTimezone:'UTC',staticUserAgent:'product',
    deep: false,maxRetries:1, semanticAnalysis:true,debuggerScripts:true,staleAssetCheck:false,staleAssetUrls:[],robotsPolicy:'respect',browserNavigationUrls:[],readOnlyPostEndpoints: [], requestsPerSecond: 2, concurrency: 2, maxDepth: 3,
    maxPages: 30, maxResources: 200, maxResourceBytes: 8 * 1024 * 1024, maxTotalBytes: 80 * 1024 * 1024,
    timeoutMs: 10000, maxDurationMs: 120000, queryVariants: 3, browserPages: 5,
    browserSettleMs: 1000, maxMaps: 25, maxMapSources: 40, deepPaths, adjacentMaps: true, preset:'custom',maxWireResourceBytes:16*1024*1024,maxDecodedTotalBytes:160*1024*1024,maxMapDepth:4,maxMapSections:50,browserScrollSteps:0,browserScrollDelayMs:500, ...input };
  // Omitted new settings inherit legacy values; explicit old limits remain shared caps.
  c.sizingMode=input.sizingMode??(c.autoScaleByWebsiteCount?'website-count':'fixed');
  if(!['fixed','website-count','adaptive'].includes(c.sizingMode))throw new Error('Invalid sizing mode');
  // Scope is resolved from the raw input: omitted means domain scope (the default), an explicit false means exact-origin, and conflicting keys are an error.
  const flag=input.sameRegistrableDomainDiscovery;
  if(flag!==undefined&&typeof flag!=='boolean')throw new Error('Invalid setting: sameRegistrableDomainDiscovery');
  if(input.domainScope!==undefined&&!DOMAIN_SCOPES.includes(input.domainScope))throw new Error('Invalid setting: domainScope');
  if(input.domainScope&&typeof flag==='boolean'&&flag!==(input.domainScope!=='exact-origin'))throw new Error('Conflicting scope settings: domainScope and sameRegistrableDomainDiscovery disagree');
  c.domainScope=input.domainScope??(typeof flag==='boolean'?(flag?'registrable-domain':'exact-origin'):'registrable-domain');
  c.sameRegistrableDomainDiscovery=c.domainScope!=='exact-origin';
  if(c.scopeReview!==undefined){if(!c.scopeReview||typeof c.scopeReview!=='object'||c.scopeReview.reason!=='legacy-default-exact-origin'||typeof c.scopeReview.from!=='string'||c.scopeReview.from.length>40)throw new Error('Invalid setting: scopeReview');if(c.domainScope!=='exact-origin')delete c.scopeReview;else c.scopeReview={reason:'legacy-default-exact-origin',from:c.scopeReview.from};}
  if(c.originConcurrency===undefined)c.originConcurrency=c.concurrency; if(c.globalConcurrency===undefined)c.globalConcurrency=c.concurrency;
  if(c.originRequestsPerSecond===undefined)c.originRequestsPerSecond=c.requestsPerSecond; if(c.maxActiveOrigins===undefined)c.maxActiveOrigins=4; if(c.maxBrowserOrigins===undefined)c.maxBrowserOrigins=2;
  if(c.originMaxDurationMs===undefined)c.originMaxDurationMs=c.maxDurationMs; if(c.projectMaxDurationMs===undefined)c.projectMaxDurationMs=c.maxDurationMs; if(c.originMaxPages===undefined)c.originMaxPages=c.maxPages; if(c.originMaxResources===undefined)c.originMaxResources=c.maxResources;
  if(c.originMaxTotalBytes===undefined)c.originMaxTotalBytes=c.maxTotalBytes; if(c.originMaxMaps===undefined)c.originMaxMaps=c.maxMaps; if(c.originBrowserPages===undefined)c.originBrowserPages=c.browserPages;
  if (!Array.isArray(c.urls) || !c.urls.length || c.urls.length > 50) throw new Error('Supply 1–50 authorized URLs');
  c.urls = c.urls.map(u => normalizeUrl(/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(u.trim())?u.trim():'https://'+u.trim()));
  // A blank or omitted name is derived from the entered host; an explicit name (including the pre-2.5 constant) is kept as entered.
  if(c.name==null||typeof c.name==='string'&&!c.name.trim())c.name=defaultProjectName(c.urls);else if(typeof c.name==='string')c.name=c.name.trim();
  for (const field of ['relatedOrigins','privateOrigins'] as const) {
    if (!Array.isArray(c[field]) || c[field].length > 50) throw new Error('Invalid origin list');
    c[field] = c[field].map(exactOrigin);
  }
  if (c.developmentFixtureOrigin) {
    c.developmentFixtureOrigin = exactOrigin(c.developmentFixtureOrigin);
    const host = new URL(c.developmentFixtureOrigin).hostname;
    if (!['127.0.0.1','[::1]','localhost'].includes(host)) throw new Error('Development fixture must be a loopback origin');
  }
  if (!Array.isArray(c.readOnlyPostEndpoints) || c.readOnlyPostEndpoints.length > 20) throw new Error('Invalid POST endpoint list');
  c.readOnlyPostEndpoints = c.readOnlyPostEndpoints.map(u => normalizeUrl(u));
  if(!['respect','owner-authorized-audit'].includes(c.robotsPolicy!))throw new Error('Invalid robots policy');
  if(!Array.isArray(c.browserNavigationUrls)||c.browserNavigationUrls.length>10)throw new Error('Select at most ten read-only browser navigation URLs');
  c.browserNavigationUrls=c.browserNavigationUrls.map(u=>{const parsed=new URL(u,c.urls[0]),normalized=normalizeUrl(u,c.urls[0]);return normalized+parsed.hash;});
  if(!Array.isArray(c.sensitiveFields)||c.sensitiveFields.length>50||c.sensitiveFields.some(f=>!f||typeof f.path!=='string'||!/^\w[\w.-]{0,199}$/.test(f.path)||!['private','public'].includes(f.expectation)))throw new Error('Sensitive field expectations require up to 50 exact dot paths and private/public expectations');
  if(new Set(c.sensitiveFields.map(f=>f.path)).size!==c.sensitiveFields.length)throw new Error('Duplicate sensitive field expectation');
  if(!Array.isArray(c.staleAssetUrls)||c.staleAssetUrls.length>200)throw new Error('Stale assets require at most 200 exact URLs from authorized history or a deployment manifest');
  c.staleAssetUrls=c.staleAssetUrls.map(u=>normalizeUrl(u,c.urls[0]));
  // Program (2.8): validated again here so saved checkpoints keep enforcing it. It only narrows: every seed must be inside the program scope, and a related origin
  // must be one an in-scope rule covers. Its explicit analysis memory (up to 2048 MiB) is the only way above the ready-option ceiling.
  if(c.program!==undefined){
    c.program=normalizeProgramConfig(c.program);const scope=programScope(c.program);
    const outside=c.urls.find(u=>!scope.allows(u));if(outside)throw new Error('Outside the program scope: '+outside);
    const related=c.relatedOrigins.find(o=>!scope.originPossible(o));if(related)throw new Error('Related origin outside the program scope: '+related);
    if(c.program.userAgentSuffix&&c.staticUserAgent==='none')throw new Error('Conflicting settings: the program User-Agent suffix needs the product User-Agent (staticUserAgent "product")');
    if(c.program.analysisMemoryMb!==undefined)c.maxAnalysisMemoryMb=c.program.analysisMemoryMb;
  }
  // The canonical forms are checked again (IDN, case, trailing dot and port are already normalized by the protected-host matcher; this guards the derived values).
  assertNotProtected([...c.urls,...c.relatedOrigins,...c.privateOrigins,...(c.developmentFixtureOrigin?[c.developmentFixtureOrigin]:[]),...c.readOnlyPostEndpoints,...c.browserNavigationUrls,...c.staleAssetUrls]);
  // Approved routes and read-only POST endpoints must sit on an explicit origin, or inside the domain scope when that scope admits discovery (same policy as discovery).
  const policy=new ScopePolicy(c),inScope=(u:string)=>{const d=policy.classify(u);return d.class==='explicit-seed'||d.class==='explicit-related'||d.class==='in-domain';};
  if(c.browserNavigationUrls.some(u=>!inScope(u)))throw new Error('Browser navigation requires an explicitly approved exact origin or a host inside the domain scope');
  if(c.readOnlyPostEndpoints.some(u=>!inScope(u)))throw new Error('Read-only POST endpoints must sit inside the authorized scope');
  const limits: Record<string, [number, number]> = {
    originAnalysisMs:[100,120000],semanticSliceMs:[100,10000],maxModuleAnalysisBytes:[1024,16*1024*1024],maxAnalysisBytes:[1024,128*1024*1024],originAnalysisBytes:[1024,128*1024*1024],analysisConcurrency:[1,4],maxAnalysisMemoryMb:[64,Math.max(HARD_CEILINGS.analysisMemoryMb,c.program?.analysisMemoryMb??0)],browserLazyAssetLimit:[0,100],
    workTurnMs:[1000,120000],analysisTurnMs:[1000,600000],analysisBacklogBytes:[0,256*1024*1024],maxDiscoveryBytes:[256*1024,16*1024*1024],browserBaselineMs:[0,3000],
    maxAutoDiscoveredOrigins:[0,50],originConcurrency:[1,8],originRequestsPerSecond:[0.1,20],maxActiveOrigins:[1,HARD_CEILINGS.activeOrigins],globalConcurrency:[1,HARD_CEILINGS.globalConcurrency],maxBrowserOrigins:[1,HARD_CEILINGS.browserOrigins],
    originMaxDurationMs:[100,3600000],projectMaxDurationMs:[100,360005000],originMaxPages:[1,500],originMaxResources:[1,2000],originMaxTotalBytes:[1024,500*1024*1024],originMaxMaps:[0,100],originBrowserPages:[1,50],
    maxRetries:[0,1],requestsPerSecond: [0.1, HARD_CEILINGS.requestsPerSecond], concurrency: [1, 8], maxDepth: [0, 10], maxPages: [1, 500],
    maxResources: [1, 2000], maxResourceBytes: [1024, 32 * 1024 * 1024], maxTotalBytes: [1024, 500 * 1024 * 1024],
    timeoutMs: [100, 30000], maxDurationMs: [100, 3600000], queryVariants: [1, 10], browserPages: [1, 50],
    browserSettleMs: [0, 5000], maxMaps: [0, 100], maxMapSources: [1, 100],maxWireResourceBytes:[1024,32*1024*1024],maxDecodedTotalBytes:[1024,500*1024*1024],maxMapDepth:[0,8],maxMapSections:[1,100],browserScrollSteps:[0,10],browserScrollDelayMs:[100,2000]
  };
  for (const [k, [min, max]] of Object.entries(limits)) {
    const n = (c as unknown as Record<string, unknown>)[k];
    if (typeof n !== 'number' || !Number.isFinite(n) || n < min || n > max || (!['requestsPerSecond','originRequestsPerSecond'].includes(k) && !Number.isInteger(n))) throw new Error(`Invalid setting: ${k}`);
  }
  if(c.maxAnalysisMemoryMb!<c.analysisConcurrency!*64)throw new Error('Analysis memory must allow at least 64 MiB for each concurrent parser');
  if (typeof c.name !== 'string' || c.name.length > 100) throw new Error('Invalid project name');
  if(!['quick','standard','thorough','exhaustive','custom'].includes(c.preset))throw new Error('Invalid preset');
  // Request privacy settings: a fixed language tag and IANA time zone (never the operating system's), and the static product token or none.
  if(typeof c.browserLocale!=='string'||!/^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8}){0,3}$/.test(c.browserLocale))throw new Error('Invalid setting: browserLocale');try{c.browserLocale=Intl.getCanonicalLocales(c.browserLocale)[0];}catch{throw new Error('Invalid setting: browserLocale');}
  if(typeof c.browserTimezone!=='string'||!/^(?:UTC|[A-Za-z_]+(?:\/[A-Za-z0-9_+-]+){1,2})$/.test(c.browserTimezone))throw new Error('Invalid setting: browserTimezone');try{new Intl.DateTimeFormat('en-US',{timeZone:c.browserTimezone});}catch{throw new Error('Invalid setting: browserTimezone');}
  if(!['product','none'].includes(c.staticUserAgent as string))throw new Error('Invalid setting: staticUserAgent');
  for (const k of ['browser','deep','adjacentMaps','semanticAnalysis','debuggerScripts','staleAssetCheck','sameRegistrableDomainDiscovery','autoScaleByWebsiteCount'] as const) if (typeof c[k] !== 'boolean') throw new Error(`Invalid setting: ${k}`);
  if (!Array.isArray(c.deepPaths) || c.deepPaths.length > 30 || c.deepPaths.some(p => typeof p !== 'string' || !/^\/[A-Za-z0-9._/-]{1,100}$/.test(p) || p.includes('..'))) throw new Error('Deep checks require at most 30 fixed paths');
  return c;
}

/** Explicit websites at scan start: distinct exact origins of the seeds and related origins. */
export const explicitWebsites=(c:Pick<ScanConfig,'urls'|'relatedOrigins'>)=>new Set([...c.urls.map(u=>new URL(u).origin),...c.relatedOrigins]).size;
/** Size shared caps for a website count, bounded by the hard maxima. Per-origin limits and per-origin request rates remain unchanged.
 * Profiles: per-website allocation × websites (global pacing grows with the websites allowed to be active at once). Legacy website-count: the 2.5 growth rule. Fixed and adaptive legacy settings: unchanged. */
export function applyWebsiteSizing(c:ScanConfig,websites:number):ScanConfig{return Object.assign(c,sizedTotals(c,websites));}
/** Scale shared scan budgets from the exact origins approved before the scan starts; profile scans grow them again when a discovered website is admitted.
 * Every scan start comes through here (CLI, dashboard, queue, schedule, trigger, retry, resume), so a non-website host is refused before any request. */
export function resolveScanConfig(input:Partial<ScanConfig>):ScanConfig {
  const c=makeNewConfig(input);
  if(c.coverage===undefined&&c.sizingMode!=='website-count')return c;
  return applyWebsiteSizing(c,explicitWebsites(c));
}
/** A saved ready option follows the current option tables: a stored, non-customized profile configuration (written by a 2.6 build: it carries `sharedLimits`) drops its stored option numbers,
 * so loading re-derives them from this build's tables. Analysis memory and workers became option settings in 2.6 P3b: a stored value that differs from the earlier default (256 MiB, 2 workers) was
 * the owner's choice, and one lower than the table is kept (the project then shows as a custom profile); values are never raised over an owner's choice.
 * Legacy presets, custom settings and custom profiles keep every stored number and are never re-mapped. */
const EARLIER_ANALYSIS_DEFAULTS:Record<string,number>={maxAnalysisMemoryMb:256,analysisConcurrency:2};
export function followReadyOption<T extends Partial<ScanConfig>>(config:T):T{
  if(!config||typeof config!=='object'||!config.coverage||!config.traffic||!COVERAGES.includes(config.coverage)||!TRAFFICS.includes(config.traffic)||config.profileCustomized!==undefined)return config;
  if(!config.sharedLimits||typeof config.sharedLimits!=='object'||Object.keys(config.sharedLimits).length)return config;
  const table=profileSettings(config.coverage,config.traffic,deepPaths) as Record<string,unknown>,out:Record<string,unknown>={...config};
  for(const k of Object.keys(table)){if(RUN_OPTION_KEYS.has(k))continue;const stored=(config as Record<string,unknown>)[k],earlier=EARLIER_ANALYSIS_DEFAULTS[k];if(earlier!==undefined&&typeof stored==='number'&&stored!==earlier&&stored<(table[k] as number))continue;delete out[k];}
  return out as T;
}
