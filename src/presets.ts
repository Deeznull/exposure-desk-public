import { makeConfig, normalizeUrl, deepPaths, resolveScanConfig, explicitWebsites, applyWebsiteSizing } from './config.js';
import { discoveredLimit } from './domain-scope.js';
import type { ScanConfig, Coverage, Traffic, ProfileEstimate } from './types.js';
import { COVERAGES, TRAFFICS, COVERAGE_LABELS, TRAFFIC_LABELS, LEGACY_PROFILES, HARD_CEILINGS, QUICK_SCRIPTS_PER_WEBSITE, RECOMMENDED, OPTION_SUMMARIES, SMALL_COMPUTER, MEMORY_SHARE, profileSettings, profileTables, profileLabel, coverageScope, TRAFFIC_NOTES, describeProfile, estimateScan, startEstimate, resourceUse, isRecommended, type Computer } from './profiles.js';
export { LEGACY_PROFILES } from './profiles.js';
const MiB=1024*1024;
export const presets:Record<string,Partial<ScanConfig>>={
  quick:{preset:'quick',browser:false,deep:false,maxDepth:1,maxPages:8,maxResources:60,maxResourceBytes:8*MiB,maxTotalBytes:40*MiB,maxDurationMs:90000,maxMaps:10,adjacentMaps:false},
  standard:{preset:'standard',browser:true,deep:false,maxDepth:3,maxPages:30,maxResources:200,maxResourceBytes:12*MiB,maxTotalBytes:120*MiB,maxDurationMs:300000,maxMaps:30,browserPages:5,browserScrollSteps:2},
  thorough:{preset:'thorough',browser:true,deep:true,maxDepth:5,maxPages:80,maxResources:600,maxResourceBytes:24*MiB,maxWireResourceBytes:24*MiB,maxTotalBytes:300*MiB,maxDecodedTotalBytes:400*MiB,maxDurationMs:900000,maxMaps:80,maxMapSources:80,browserPages:15,browserScrollSteps:5},
  exhaustive:{preset:'exhaustive',browser:true,deep:true,maxDepth:5,maxPages:80,maxResources:600,maxResourceBytes:24*MiB,maxWireResourceBytes:24*MiB,maxTotalBytes:300*MiB,maxDecodedTotalBytes:400*MiB,maxDurationMs:3600000,maxMaps:80,maxMapSources:80,browserPages:15,browserScrollSteps:5,concurrency:3,requestsPerSecond:8,originConcurrency:3,originRequestsPerSecond:2,maxActiveOrigins:4,globalConcurrency:12,maxBrowserOrigins:2,originMaxDurationMs:3600000},
  custom:{preset:'custom'}
};
export function presetConfig(name:string,input:Partial<ScanConfig>){
  if(!presets[name])throw new Error('Unknown preset');
  // With a profile, the preset name only supplies the coverage (and is checked against it); its legacy numbers are not merged in.
  if(input.coverage!==undefined||input.traffic!==undefined)return makeConfig({...input,preset:name as ScanConfig['preset']});
  const settings={...presets[name],...input,preset:name as ScanConfig['preset']};
  // Selecting a preset must not silently raise an explicitly supplied legacy cap.
  if(input.concurrency!==undefined&&input.globalConcurrency===undefined)settings.globalConcurrency=input.concurrency;
  if(input.concurrency!==undefined&&input.originConcurrency===undefined)settings.originConcurrency=input.concurrency;
  if(input.requestsPerSecond!==undefined&&input.originRequestsPerSecond===undefined)settings.originRequestsPerSecond=input.requestsPerSecond;
  if(input.maxDurationMs!==undefined&&input.originMaxDurationMs===undefined)settings.originMaxDurationMs=input.maxDurationMs;
  if(name==='exhaustive'&&input.maxDurationMs===undefined&&input.projectMaxDurationMs===undefined){
    const origins=new Set([...(input.urls||[]).map(u=>new URL(normalizeUrl(/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(u.trim())?u.trim():'https://'+u.trim())).origin),...(input.relatedOrigins||[]).map(u=>new URL(u).origin)]);
    settings.projectMaxDurationMs=Math.max(1,origins.size)*3600000+5000;
  }
  return makeConfig(settings);
}
/** A profile scan: coverage and traffic fill every profile key; explicit per-website values in `input` make it "Custom (based on …)". */
export function profileConfig(coverage:Coverage|undefined,traffic:Traffic|undefined,input:Partial<ScanConfig>){return makeConfig({...input,...(coverage?{coverage}:{}),...(traffic?{traffic}:{})});}
/** Owner-initiated switch of a legacy (or custom) configuration to a profile: scope, seeds, routes and privacy settings are kept; every profile-controlled number is replaced by the profile.
 * Without an explicit choice a legacy preset switches to its documented equivalent. Nothing calls this automatically. */
export function switchToProfile(config:Partial<ScanConfig>,coverage?:Coverage,traffic?:Traffic):ScanConfig{
  const equivalent=config.preset&&config.preset!=='custom'?LEGACY_PROFILES[config.preset as keyof typeof LEGACY_PROFILES]:undefined;
  const c=coverage??config.coverage??equivalent?.coverage,t=traffic??config.traffic??equivalent?.traffic??'normal';
  if(!c)throw new Error('Choose a coverage level to switch custom settings to a profile');
  const kept:Record<string,unknown>={...config};for(const k of [...Object.keys(profileSettings('deep','normal',deepPaths)),'preset','coverage','traffic','profileCustomized','sharedLimits','autoScaleByWebsiteCount'])delete kept[k];
  return makeConfig({...kept,coverage:c,traffic:t} as Partial<ScanConfig>);
}
/** What one ready option sets before any adjustment: websites at once, browser websites at once, analysis memory and workers, the per-website download cap and time allowance. */
export function optionFacts(coverage:Coverage,traffic:Traffic){
  const {allocation:a,pacing,settings}=profileTables(coverage,traffic);
  return {websitesAtOnce:pacing.maxActiveOrigins,browserWebsitesAtOnce:settings.browser?pacing.maxBrowserOrigins:0,analysisMemoryMb:settings.maxAnalysisMemoryMb!,analysisWorkers:settings.analysisConcurrency!,downloadBytes:a.bytes,durationMs:a.durationMs,requestsPerSecond:a.requestsPerSecond,concurrency:a.concurrency,pages:a.pages,browserPages:settings.browser?a.browserPages:0,depth:settings.maxDepth!};
}
/** The six ready options in display order (coverage, then Normal before Low-impact), with the Recommended mark. */
export const readyOptions=()=>COVERAGES.flatMap(c=>(['normal','low-impact'] as Traffic[]).map(t=>({id:`${c}+${t}`,coverage:c,traffic:t,label:profileLabel(c,t),recommended:isRecommended(c,t),summary:OPTION_SUMMARIES[`${c}+${t}`],facts:optionFacts(c,t)})));
/** Profile catalog for the dashboard and CLI: labels, the legacy mapping, the ready options (Recommended first among equals), every profile's per-website settings, what it examines and skips, the honest traffic notes, the hard ceilings and the computer rule. */
export function profileCatalog(){
  return {coverages:COVERAGES.map(id=>({id,label:COVERAGE_LABELS[id]})),traffics:TRAFFICS.map(id=>({id,label:TRAFFIC_LABELS[id],note:TRAFFIC_NOTES[id]})),legacy:LEGACY_PROFILES,ceilings:HARD_CEILINGS,quickScriptsPerWebsite:QUICK_SCRIPTS_PER_WEBSITE,
    recommended:{...RECOMMENDED,label:profileLabel(RECOMMENDED.coverage,RECOMMENDED.traffic)},options:readyOptions(),computer:{...SMALL_COMPUTER,memoryShare:MEMORY_SHARE},
    profiles:Object.fromEntries(COVERAGES.flatMap(c=>TRAFFICS.map(t=>[c+'+'+t,{coverage:c,traffic:t,label:profileLabel(c,t),recommended:isRecommended(c,t),settings:profileSettings(c,t,deepPaths),...coverageScope(c,t)}])))};
}
/** Very long estimates (over about 2 hours) say so and name Quick check as the faster choice. Nothing is switched automatically. */
export const LONG_RUN_MS=2*3600000;
const duration=(ms:number)=>ms<5400000?Math.max(1,Math.round(ms/60000))+' min':(ms/3600000).toFixed(1)+' h';
export function longRunNote(c:ScanConfig,estimate:ProfileEstimate):string|undefined{
  const longest=Math.max(estimate.total.pacedMs,estimate.withDiscovered?.pacedMs??0);if(longest<=LONG_RUN_MS)return;
  const label=describeProfile(c).label,websites=estimate.withDiscovered&&estimate.withDiscovered.pacedMs>estimate.total.pacedMs?estimate.withDiscovered.websites:estimate.total.websites;
  const lead=`${label} may take about ${duration(longest)} at this pacing for ${websites} website${websites===1?'':'s'}.`;
  if(c.coverage==='quick'&&!c.profileCustomized)return `${lead} It already uses the quickest coverage; fewer websites${c.traffic==='low-impact'?', Normal traffic':''} or exact-origin scope make it shorter. Nothing is switched automatically.`;
  let quick:number|undefined;try{const q=switchToProfile(c,'quick',c.traffic??'normal'),e=estimateScan(applyWebsiteSizing(q,estimate.websites.explicit),estimate.websites.explicit,estimate.websites.discoveredLimit);quick=Math.max(e.total.pacedMs,e.withDiscovered?.pacedMs??0);}catch{/* the comparison is optional */}
  return `${lead} Quick check${quick!==undefined?` would take about ${duration(quick)}`:' is much faster'}; consider it for a first look. Nothing is switched automatically.`;
}
/** Scan-page preview (the dashboard debounces it): the configuration the scan would start with (profile resolution and website-count sizing applied, as the scanner does), how it was chosen,
 * the website counts, the pure start estimate, the shared caps that reach a hard ceiling and what the coverage examines and skips. Low-impact adds the slower-pace note.
 * `resourceUse` says what the option uses for the entered websites on this computer (lowered, never raised); a very long estimate adds `longRun`. Nothing is contacted. */
export function profilePreview(input:Partial<ScanConfig>,computer?:Computer){
  const c=resolveScanConfig(input),websites=explicitWebsites(c),limit=discoveredLimit(c),base=startEstimate(c,websites,limit,computer),long=longRunNote(c,base),estimate={...base,...(long?{longRun:long}:{})},profile={...describeProfile(c),...(isRecommended(c.coverage,c.traffic)&&!c.profileCustomized?{recommended:true}:{})};
  const shared={pages:c.maxPages,resources:c.maxResources,bytes:c.maxTotalBytes,decodedBytes:c.maxDecodedTotalBytes,maps:c.maxMaps,browserPages:c.browserPages,projectDurationMs:c.projectMaxDurationMs??c.maxDurationMs},ceilings={pages:HARD_CEILINGS.pages,resources:HARD_CEILINGS.resources,bytes:HARD_CEILINGS.bytes,decodedBytes:HARD_CEILINGS.decodedBytes,maps:HARD_CEILINGS.maps,browserPages:HARD_CEILINGS.browserPages,projectDurationMs:HARD_CEILINGS.projectDurationMs};
  const cappedBy=(Object.keys(ceilings) as (keyof typeof ceilings)[]).filter(k=>shared[k]>=ceilings[k]);
  let slower:string|undefined;
  if(c.coverage&&c.traffic==='low-impact'){
    // The same coverage at Normal traffic, for comparison only (pure arithmetic on the profile tables; a custom profile is compared with its base profile).
    const normal={...c,...profileSettings(c.coverage,'normal',deepPaths),traffic:'normal',sharedLimits:{},profileCustomized:undefined} as ScanConfig,minutes=startEstimate(normal,websites,limit,computer).expectedMinutes;
    slower=`${profileLabel(c.coverage,'low-impact')} will take longer: about ${estimate.expectedMinutes} min at this pacing${minutes<estimate.expectedMinutes?`, against about ${minutes} min with Normal traffic`:''}. It does not hide the scan.`;
  }
  return {profile,config:c,websites:{explicit:websites,discoveredLimit:limit,scope:c.domainScope},estimate,sizing:{total:shared,ceilings,cappedBy},resourceUse:resourceUse(c,websites,computer,limit),
    ...(c.coverage&&c.traffic?coverageScope(c.coverage,c.traffic):{examines:[] as string[],skips:[] as string[]}),trafficNote:c.traffic?TRAFFIC_NOTES[c.traffic]:'Legacy or custom settings apply as stored. Nothing hides the scan from the websites.',...(slower?{slower}:{})};
}
