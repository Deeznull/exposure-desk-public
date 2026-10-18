import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cp, mkdtemp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { makeConfig, resolveScanConfig, deepPaths } from '../src/config.js';
import { presets, presetConfig, profileConfig, switchToProfile, profileCatalog } from '../src/presets.js';
import { COVERAGES, TRAFFICS, LEGACY_PROFILES, HARD_CEILINGS, PROFILE_EXTRA_DEEP_PATHS, DEEP_SCAN_EXTRA_PATHS, QUICK_SCRIPTS_PER_WEBSITE, profileSettings, profileLabel, describeProfile, estimateScan, sizedTotals } from '../src/profiles.js';
import { effectiveScope } from '../src/domain-scope.js';
import { Scanner } from '../src/scanner.js';
import { Detector, root } from '../src/detectors.js';
import { report } from '../src/reports.js';
import { runSummary, configProfile } from '../src/runs.js';
import { Store } from '../src/storage.js';
import { startDashboard } from '../src/dashboard.js';
import { egressTripwire, virtualNetwork } from './virtual-network.js';
import type { ScanConfig } from '../src/types.js';
const MiB=1024*1024,SITE='https://example.com/',publicDns=async()=>[{address:'93.184.216.34',family:4}];
const key=(name:string)=>'sk-proj-'+createHash('sha512').update('unit-profiles-'+name).digest('base64url').slice(0,64);
const sites=(n:number)=>Array.from({length:n},(_,i)=>`https://site${i}.example.com/`);
const SHARED=['maxPages','maxResources','maxTotalBytes','maxDecodedTotalBytes','maxMaps','browserPages','projectMaxDurationMs','requestsPerSecond','globalConcurrency'] as const;
const shared=(c:ScanConfig)=>Object.fromEntries(SHARED.map(k=>[k,c[k]]));
const LEGACY_FIXTURE=path.join(root,'test','fixtures','legacy-2.4');
async function legacyCopy(){const parent=process.env.EXPOSURE_DATA_DIR||path.join(root,'.cache');await mkdir(parent,{recursive:true});const dir=await mkdtemp(path.join(parent,'profiles-legacy-'));await cp(LEGACY_FIXTURE,dir,{recursive:true});return dir;}
const historyFiles=async(dir:string)=>{const names=(await readdir(path.join(dir,'scans'))).filter(f=>f.endsWith('.json')).sort();return Promise.all(names.map(async f=>[f,await readFile(path.join(dir,'scans',f),'utf8')]));};
/** Loopback fixture website; every request path is recorded so tests can show what Quick check never requested. */
async function serve(routes:Record<string,[type:string,body:string,status?:number]>){
  const arrivals:string[]=[];const server=http.createServer((req,res)=>{arrivals.push(req.url||'');const r=routes[req.url||''];if(!r){res.statusCode=404;res.end('not found');return;}res.statusCode=r[2]??200;res.setHeader('content-type',r[0]);res.end(r[1]);});
  await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));
  return {origin:'http://127.0.0.1:'+(server.address() as any).port,arrivals,close:()=>new Promise<void>(r=>{server.close(()=>r());server.closeAllConnections();})};
}

test('legacy presets and custom numbers resolve exactly as before: no profile keys, never re-mapped, the mapping is descriptive only',()=>{
  assert.deepEqual(LEGACY_PROFILES,{quick:{coverage:'quick',traffic:'normal'},standard:{coverage:'standard',traffic:'normal'},thorough:{coverage:'deep',traffic:'normal',note:'single-website pacing'},exhaustive:{coverage:'deep',traffic:'normal'}});
  for(const name of ['quick','standard','thorough','exhaustive','custom']){
    const c=presetConfig(name,{urls:[SITE]}),d=describeProfile(c);
    for(const k of ['coverage','traffic','profileCustomized'])assert.equal((c as any)[k],undefined,name+' gains no '+k);
    for(const [k,v]of Object.entries(presets[name]))assert.deepEqual((c as any)[k],v,name+' keeps its own '+k);
    assert.deepEqual(makeConfig(JSON.parse(JSON.stringify(c))),c,name+' reloads unchanged');assert.deepEqual(resolveScanConfig(c),c,name+' fixed sizing is unchanged');
    if(name==='custom')assert.deepEqual(d,{kind:'custom',label:'Custom',legacyPreset:'custom'});
    else{assert.equal(d.kind,'legacy-preset');assert.equal(d.label,'Legacy preset: '+name);assert.deepEqual(d.equivalent,LEGACY_PROFILES[name as keyof typeof LEGACY_PROFILES]);}
    assert.deepEqual(configProfile(c),{kind:d.kind,label:d.label,recorded:true},'queue jobs record how the configuration was chosen');
  }
  const custom=makeConfig({urls:[SITE],maxResources:77,originMaxResources:20});assert.equal(custom.maxResources,77);assert.equal(custom.originMaxResources,20);assert.equal(custom.coverage,undefined);
  // The legacy default website-count growth (2.5 rule) is unchanged: max(entered cap, per-origin × websites), bounded by the hard maxima; pacing is not scaled.
  const wc=makeConfig({urls:sites(3),sizingMode:'website-count'}),grown=resolveScanConfig({urls:sites(3),sizingMode:'website-count'});
  assert.equal(grown.maxResources,Math.min(2000,Math.max(wc.maxResources,wc.originMaxResources!*3)));assert.equal(grown.requestsPerSecond,wc.requestsPerSecond);assert.equal(grown.globalConcurrency,wc.globalConcurrency);
  assert.deepEqual(resolveScanConfig({urls:sites(3)}),makeConfig({urls:sites(3)}),'fixed legacy settings are not sized');
});
test('every coverage and traffic combination fills the profile tables; Low-impact only lowers load',()=>{
  for(const coverage of COVERAGES)for(const traffic of TRAFFICS){
    const c=makeConfig({urls:[SITE],coverage,traffic}),table=profileSettings(coverage,traffic,deepPaths),low=traffic==='low-impact',label=coverage+'+'+traffic;
    assert.equal(c.preset,'custom','older readers downgrade a profile to custom settings');assert.equal(c.coverage,coverage);assert.equal(c.traffic,traffic);assert.equal(c.profileCustomized,undefined);
    for(const [k,v]of Object.entries(table))assert.deepEqual((c as any)[k],v,label+' '+k);
    assert.deepEqual(makeConfig(JSON.parse(JSON.stringify(c))),c,label+' reloads unchanged');assert.deepEqual(profileConfig(coverage,traffic,{urls:[SITE]}),c);
    assert.deepEqual(describeProfile(c),{kind:'profile',label:profileLabel(coverage,traffic),coverage,traffic});
    assert.equal(c.browser,coverage!=='quick');assert.equal(c.deep,true);assert.equal(c.sizingMode,coverage==='deep'?'adaptive':'website-count');assert.equal(c.staleAssetCheck,coverage==='deep');
    assert.equal(c.originRequestsPerSecond,low?.5:2);assert.equal(c.originConcurrency,low?1:coverage==='deep'?3:2);assert.equal(c.maxActiveOrigins,{quick:low?2:6,standard:low?2:4,deep:low?2:3}[coverage],"ready-option websites at once");assert.equal(c.maxBrowserOrigins,coverage==="quick"||low?1:2);assert.deepEqual([c.maxAnalysisMemoryMb,c.analysisConcurrency],{quick:[256,1],standard:[256,2],deep:[512,2]}[coverage],"ready-option analysis memory and workers");assert.equal(c.maxRetries,low?0:1);
    if(low){assert.equal(c.queryVariants,1);assert.equal(c.adjacentMaps,false);assert.equal(c.originBrowserPages,{quick:1,standard:3,deep:6}[coverage]);assert.ok(c.originMaxDurationMs!>=makeConfig({urls:[SITE],coverage,traffic:'normal'}).originMaxDurationMs!);}
    for(const p of PROFILE_EXTRA_DEEP_PATHS)assert.ok(c.deepPaths.includes(p),label+' checks the high-value path '+p);
    for(const p of DEEP_SCAN_EXTRA_PATHS)assert.equal(c.deepPaths.includes(p),coverage!=='quick',label+(coverage==='quick'?' keeps the fuller list out of Quick: '+p:' checks '+p));
    assert.ok(deepPaths.every(p=>![...PROFILE_EXTRA_DEEP_PATHS,...DEEP_SCAN_EXTRA_PATHS].includes(p)),'the legacy deep-path list is unchanged');
    assert.equal(new Set(c.deepPaths).size,c.deepPaths.length,label+' has no duplicate deep paths');
    assert.ok(c.deepPaths.length<=30,label+' stays within the 30-path ceiling');
  }
  assert.equal(makeConfig({urls:[SITE],coverage:'quick',traffic:'normal'}).originMaxResources,100);assert.equal(makeConfig({urls:[SITE],coverage:'standard',traffic:'normal'}).originMaxResources,200);assert.equal(makeConfig({urls:[SITE],coverage:'deep',traffic:'normal'}).originMaxResources,600);
  const catalog=profileCatalog();assert.equal(Object.keys(catalog.profiles).length,6);assert.deepEqual(catalog.ceilings,HARD_CEILINGS);assert.match(catalog.traffics.find(t=>t.id==='low-impact')!.note,/does not hide the scan/);assert.match(catalog.traffics.find(t=>t.id==='low-impact')!.note,/not undetectable/);
});
test('explicit overrides: per-website edits and entered shared caps make "Custom (based on …)" (entered caps are never raised), run options do not, and presets must agree with the coverage',()=>{
  const base={urls:[SITE],coverage:'standard' as const,traffic:'normal' as const};
  const edited=makeConfig({...base,originMaxResources:50});assert.equal(edited.profileCustomized,true);assert.equal(edited.originMaxResources,50);assert.equal(edited.originMaxPages,30,'unedited keys keep the profile values');
  assert.equal(describeProfile(edited).label,'Custom (based on Standard + Normal)');assert.equal(describeProfile(edited).kind,'custom-profile');assert.deepEqual(makeConfig(JSON.parse(JSON.stringify(edited))),edited,'a custom profile reloads with its numbers as entered');
  assert.equal(makeConfig({...base,adjacentMaps:false}).profileCustomized,true);assert.equal(makeConfig({...base,originMaxResources:200}).profileCustomized,undefined,'a value equal to the profile is not an edit');
  const limited=resolveScanConfig({...base,urls:sites(4),maxResources:300,requestsPerSecond:1});assert.equal(limited.profileCustomized,true,'an entered shared cap is an edit');assert.deepEqual(limited.sharedLimits,{maxResources:300,requestsPerSecond:1});
  assert.equal(limited.maxResources,300,'website-count sizing never raises an entered cap');assert.equal(limited.requestsPerSecond,1);assert.equal(limited.globalConcurrency,8,'other shared caps still follow the website count');assert.deepEqual(sizedTotals(limited,50).maxResources,300);
  assert.equal(makeConfig({...base,maxResources:1999}).maxResources,200,'a limit above the allocation does not raise it');assert.equal(resolveScanConfig({...base,urls:sites(50),maxResources:1999}).maxResources,1999);
  assert.deepEqual(makeConfig(JSON.parse(JSON.stringify(limited))).sharedLimits,limited.sharedLimits,'limits survive saving');
  const running=resolveScanConfig({...base,urls:sites(3)}),reloaded=resolveScanConfig(JSON.parse(JSON.stringify(running)));assert.deepEqual(running.sharedLimits,{});assert.equal(reloaded.profileCustomized,undefined,'sized caps of a saved or running profile are derived, not limits');assert.deepEqual(shared(reloaded),shared(running));
  for(const bad of [{maxResources:-1},{requestsPerSecond:50},{maxPages:1.5},{sharedLimits:{maxDepth:3}},{sharedLimits:[]}])assert.throws(()=>makeConfig({...base,...bad} as any),/Invalid setting/);
  assert.throws(()=>makeConfig({urls:[SITE],sharedLimits:{}}),/require coverage and traffic/);
  const run=makeConfig({...base,staleAssetCheck:true});assert.equal(run.profileCustomized,undefined);assert.equal(run.staleAssetCheck,true,'a deployment-trigger run option does not turn the profile into custom settings');
  assert.equal(makeConfig({...base,profileCustomized:true}).profileCustomized,true);
  const agreed=presetConfig('thorough',{urls:[SITE],coverage:'deep'});assert.equal(agreed.preset,'custom');assert.equal(agreed.coverage,'deep');assert.equal(agreed.traffic,'normal');
  assert.throws(()=>presetConfig('quick',{urls:[SITE],coverage:'deep'}),/Conflicting settings: preset quick corresponds to Quick check \+ Normal, not coverage deep/);
  assert.throws(()=>makeConfig({urls:[SITE],preset:'standard',coverage:'quick'}),/Conflicting settings/);
  assert.equal(describeProfile(presetConfig('exhaustive',{urls:[SITE],traffic:'low-impact'})).label,'Deep audit + Low-impact','a legacy preset with traffic alone takes its coverage from the mapping');
  const quickLow=presetConfig('quick',{urls:[SITE],coverage:'quick',traffic:'low-impact'});assert.equal(quickLow.originMaxResources,100,'legacy numbers are not merged into a profile');assert.equal(quickLow.deep,true);
  assert.equal(presetConfig('custom',{urls:[SITE],coverage:'quick'}).coverage,'quick');
  assert.equal(makeConfig({urls:[SITE],traffic:'low-impact'}).coverage,'standard');assert.equal(makeConfig({urls:[SITE],coverage:'deep'}).traffic,'normal');assert.equal(profileConfig('quick',undefined,{urls:[SITE]}).traffic,'normal');
  for(const bad of [{coverage:'maximum'},{traffic:'stealth'},{coverage:'quick',traffic:'normal',profileCustomized:'yes'},{profileCustomized:true},{coverage:'quick',preset:'turbo'}])assert.throws(()=>makeConfig({urls:[SITE],...bad} as any),/Invalid/);
});
test('Low-impact is a ceiling: custom values and configuration files can make it slower, never faster; profiles never use fixed sizing',async()=>{
  const fast=makeConfig({urls:[SITE],coverage:'quick',traffic:'low-impact',maxDepth:2,requestsPerSecond:20,globalConcurrency:12,originRequestsPerSecond:3,originConcurrency:4,concurrency:4,maxActiveOrigins:6,maxBrowserOrigins:3,maxRetries:2,queryVariants:3,adjacentMaps:true});
  assert.equal(fast.profileCustomized,true);assert.equal(describeProfile(fast).label,'Custom (based on Quick check + Low-impact)');
  assert.deepEqual([fast.originRequestsPerSecond,fast.originConcurrency,fast.concurrency,fast.maxActiveOrigins,fast.maxBrowserOrigins,fast.maxRetries,fast.queryVariants,fast.adjacentMaps],[.5,1,1,2,1,0,1,false]);
  for(const n of [1,2,3,50]){const t=sizedTotals(fast,n);assert.ok(t.requestsPerSecond<=1&&t.globalConcurrency<=2,'global Low-impact pacing for '+n+' websites');}
  const slower=makeConfig({urls:[SITE],coverage:'standard',traffic:'low-impact',originRequestsPerSecond:.25});assert.equal(slower.originRequestsPerSecond,.25,'slower is allowed');assert.equal(resolveScanConfig({...slower,urls:sites(3)}).requestsPerSecond,.5);
  // A 2.5 configuration file plus --traffic low-impact keeps its other numbers but not its pacing.
  const file=JSON.parse(await readFile(path.join(root,'test','fixtures','legacy-2.5','config.example.json'),'utf8')).projects[0],c=resolveScanConfig({...file,traffic:'low-impact'});
  assert.equal(describeProfile(c).label,'Custom (based on Standard + Low-impact)');assert.ok(c.originRequestsPerSecond!<=.5&&c.originConcurrency!<=1&&c.requestsPerSecond<=1&&c.globalConcurrency!<=2&&c.maxActiveOrigins!<=2&&c.maxRetries===0&&c.queryVariants===1&&c.adjacentMaps===false);
  assert.throws(()=>makeConfig({urls:[SITE],coverage:'quick',sizingMode:'fixed'}),/fixed sizing/);assert.equal(makeConfig({urls:[SITE],coverage:'quick',sizingMode:'adaptive'}).profileCustomized,true);
});
test('switching a legacy or custom configuration to a profile is explicit and keeps scope, seeds and names',()=>{
  const legacy=presetConfig('thorough',{urls:[SITE,'https://shop.example.org/'],name:'Owner sites',domainScope:'exact-origin',requestsPerSecond:3}),frozen=JSON.stringify(legacy);
  const switched=switchToProfile(legacy);assert.equal(describeProfile(switched).label,'Deep audit + Normal');assert.deepEqual(switched.urls,legacy.urls);assert.equal(switched.name,'Owner sites');assert.equal(effectiveScope(switched),'exact-origin');
  assert.equal(switched.originMaxResources,600);assert.equal(switched.profileCustomized,undefined,'legacy numbers are replaced, not treated as edits');assert.equal(switched.deepPaths.length,deepPaths.length+PROFILE_EXTRA_DEEP_PATHS.length+DEEP_SCAN_EXTRA_PATHS.length,'a Deep audit probes the full curated list');assert.equal(JSON.stringify(legacy),frozen,'the saved configuration object is not modified');
  assert.equal(describeProfile(switchToProfile(legacy,'quick','low-impact')).label,'Quick check + Low-impact');
  assert.throws(()=>switchToProfile(makeConfig({urls:[SITE],maxResources:77})),/Choose a coverage level/);assert.equal(switchToProfile(makeConfig({urls:[SITE],maxResources:77}),'standard').maxResources,200);
  const reset=switchToProfile(makeConfig({urls:[SITE],coverage:'standard',traffic:'normal',originMaxResources:50}));assert.equal(reset.profileCustomized,undefined);assert.equal(reset.originMaxResources,200);
});
test('website-count sizing for 1, 3 and 50 websites: per-website allocation × websites, pacing by active websites, hard ceilings never exceeded',()=>{
  const quick=(n:number,traffic:'normal'|'low-impact'='normal')=>resolveScanConfig({urls:sites(n),coverage:'quick',traffic});
  assert.deepEqual(shared(quick(1)),{maxPages:8,maxResources:100,maxTotalBytes:40*MiB,maxDecodedTotalBytes:80*MiB,maxMaps:10,browserPages:1,projectMaxDurationMs:125000,requestsPerSecond:2,globalConcurrency:2});
  assert.deepEqual(shared(quick(3)),{maxPages:24,maxResources:300,maxTotalBytes:120*MiB,maxDecodedTotalBytes:240*MiB,maxMaps:30,browserPages:3,projectMaxDurationMs:365000,requestsPerSecond:6,globalConcurrency:6});
  assert.deepEqual(shared(quick(50)),{maxPages:400,maxResources:2000,maxTotalBytes:500*MiB,maxDecodedTotalBytes:500*MiB,maxMaps:100,browserPages:50,projectMaxDurationMs:6005000,requestsPerSecond:12,globalConcurrency:12});
  assert.deepEqual(shared(resolveScanConfig({urls:sites(3),coverage:'standard',traffic:'normal'})),{maxPages:90,maxResources:600,maxTotalBytes:360*MiB,maxDecodedTotalBytes:480*MiB,maxMaps:90,browserPages:15,projectMaxDurationMs:905000,requestsPerSecond:6,globalConcurrency:6});
  assert.deepEqual(shared(resolveScanConfig({urls:sites(50),coverage:'deep',traffic:'normal'})),{maxPages:500,maxResources:2000,maxTotalBytes:500*MiB,maxDecodedTotalBytes:500*MiB,maxMaps:100,browserPages:50,projectMaxDurationMs:180005000,requestsPerSecond:6,globalConcurrency:9});
  assert.deepEqual(shared(resolveScanConfig({urls:sites(3),coverage:'deep',traffic:'low-impact'})),{maxPages:240,maxResources:1800,maxTotalBytes:500*MiB,maxDecodedTotalBytes:500*MiB,maxMaps:100,browserPages:18,projectMaxDurationMs:10805000,requestsPerSecond:1,globalConcurrency:2});
  for(const n of [1,3,50]){const c=quick(n);assert.equal(c.originMaxResources,100,'per-website limits stay per website');assert.equal(c.originRequestsPerSecond,2);const low=quick(n,'low-impact');assert.ok(low.requestsPerSecond<=1&&low.globalConcurrency!<=2,'Low-impact stays at or below 1 request/s and 2 at once overall');}
  assert.equal(resolveScanConfig({urls:[SITE],relatedOrigins:['https://cdn.example.net'],coverage:'quick',traffic:'normal'}).maxResources,200,'related origins are explicit websites');
  assert.equal(resolveScanConfig({urls:[SITE,SITE+'app/',SITE+'shop/'],coverage:'quick',traffic:'normal'}).maxResources,100,'websites are distinct origins, not seeds');
  for(const coverage of COVERAGES)for(const traffic of TRAFFICS){
    const configs=[makeConfig({urls:[SITE],coverage,traffic}),makeConfig({urls:[SITE],coverage,traffic,originMaxResources:500,originMaxPages:300,originMaxDurationMs:3600000})];
    for(const c of configs)for(const n of [1,2,3,4,5,10,49,50,51,100,150,1000]){const t=sizedTotals(c,n),label=`${coverage}+${traffic}${c.profileCustomized?' (custom)':''} × ${n}`;
      assert.ok(t.maxPages<=HARD_CEILINGS.pages&&t.maxResources<=HARD_CEILINGS.resources&&t.maxTotalBytes<=HARD_CEILINGS.bytes&&t.maxDecodedTotalBytes<=HARD_CEILINGS.decodedBytes&&t.maxMaps<=HARD_CEILINGS.maps&&t.browserPages<=HARD_CEILINGS.browserPages&&t.projectMaxDurationMs<=HARD_CEILINGS.projectDurationMs&&t.requestsPerSecond<=HARD_CEILINGS.requestsPerSecond&&t.globalConcurrency<=HARD_CEILINGS.globalConcurrency,label+' exceeds a hard ceiling: '+JSON.stringify(t));
      assert.ok(t.maxResources>=Math.min(HARD_CEILINGS.resources,c.originMaxResources!),label+' leaves one website its allocation');}
  }
  assert.equal(sizedTotals(makeConfig({urls:[SITE],coverage:'deep',traffic:'normal'}),150).projectMaxDurationMs,HARD_CEILINGS.projectDurationMs);
});
test('the start estimate is a pure function of the configuration and the website counts',()=>{
  const quick=makeConfig({urls:[SITE],coverage:'quick',traffic:'normal'}),frozen=JSON.stringify(quick);
  const one=estimateScan(quick,1);assert.deepEqual(one.total,{websites:1,requests:100,connections:100,connectionsMax:100,bytes:40*MiB,browserPages:0,durationMs:125000,pacedMs:50000});assert.equal(one.expectedMinutes,1);assert.equal(one.withDiscovered,undefined);assert.match(one.basis,/upper bounds/);
  const three=estimateScan(quick,3,50);assert.equal(three.total.requests,300);assert.equal(three.total.pacedMs,50000,'three websites run in parallel at the per-website pace');assert.equal(three.withDiscovered!.requests,HARD_CEILINGS.resources);assert.equal(three.websites.discoveredLimit,50);
  assert.equal(JSON.stringify(quick),frozen,'estimating never changes the configuration');assert.deepEqual(estimateScan(quick,3,50),three);
  const deepNormal=estimateScan(makeConfig({urls:[SITE],coverage:'deep',traffic:'normal'}),1),deepLow=estimateScan(makeConfig({urls:[SITE],coverage:'deep',traffic:'low-impact'}),1);
  assert.equal(deepNormal.expectedMinutes,7);assert.equal(deepLow.expectedMinutes,21);assert.ok(deepLow.total.requests===deepNormal.total.requests&&deepLow.total.browserPages<deepNormal.total.browserPages,'Low-impact keeps the coverage targets and lowers browser load');
  for(const e of [one,three,deepNormal,deepLow])assert.ok(e.total.pacedMs<=e.total.durationMs);
  const legacy=estimateScan(presetConfig('thorough',{urls:[SITE]}),1);assert.ok(legacy.total.requests>0&&legacy.expectedMinutes>=1,'legacy configurations get an estimate too');
});
test('domain-scope admissions size a profile scan per admitted website; legacy settings do not grow; linked pages are never admitted by Quick check',{timeout:120000},async()=>{
  const hosts={'https://example.com':{'/':{body:'<script src="https://api.example.com/app.js"></script><script src="https://static.example.com/lib.js"></script><a href="https://blog.example.com/">blog</a>'}},'https://api.example.com':{'/app.js':{type:'text/javascript',body:'void 0;'}},'https://static.example.com':{'/lib.js':{type:'text/javascript',body:'void 0;'}},'https://blog.example.com':{'/':{body:'blog'}}};
  const trip=egressTripwire();try{
    const s=new Scanner({urls:['https://example.com'],coverage:'quick',traffic:'normal',semanticAnalysis:false},{detector:new Detector('disabled'),resolver:publicDns});
    try{const net=virtualNetwork(s,hosts);const v=await s.run(),admitted=v.origins!.filter(o=>o.authorization?.type==='same-registrable-domain').map(o=>o.origin).sort();
      assert.deepEqual(admitted,['https://api.example.com','https://static.example.com']);assert.equal(v.profile!.sizing.admittedWebsites,2);assert.equal(v.profile!.sizing.explicitWebsites,1);assert.equal(v.profile!.sizing.discoveredLimit,50);
      assert.deepEqual(shared(v.config),{maxPages:24,maxResources:300,maxTotalBytes:120*MiB,maxDecodedTotalBytes:240*MiB,maxMaps:30,browserPages:3,projectMaxDurationMs:365000,requestsPerSecond:6,globalConcurrency:6});assert.equal(v.config.originMaxResources,100);
      assert.deepEqual(v.profile!.sizing.total,{pages:24,resources:300,bytes:120*MiB,decodedBytes:240*MiB,maps:30,browserPages:3,projectDurationMs:365000,requestsPerSecond:6,concurrency:6});assert.equal(v.profile!.estimate.total.requests,100,'the start estimate is kept as made at start');
      assert.ok(!net.arrivals.some(a=>a.url.includes('blog.example.com')));assert.ok(v.profile!.notExamined!.some(n=>n.category==='Linked pages'&&n.examples.includes('https://blog.example.com/')));
      for(const origin of admitted)assert.ok(net.arrivals.filter(a=>a.url.startsWith(origin)).length<=100);
    }finally{s.dispose();}
    const capped=new Scanner({urls:['https://example.com'],coverage:'quick',traffic:'normal',semanticAnalysis:false,maxAutoDiscoveredOrigins:1},{detector:new Detector('disabled'),resolver:publicDns});
    try{virtualNetwork(capped,hosts);const v=await capped.run();assert.equal(v.profile!.sizing.admittedWebsites,1);assert.equal(v.config.maxResources,200,'sizing follows the admission cap');assert.equal(v.config.projectMaxDurationMs,245000);assert.equal(v.profile!.sizing.discoveredLimit,1);}finally{capped.dispose();}
    const legacyInput={urls:['https://example.com'],sizingMode:'website-count' as const,browser:false,deep:false,semanticAnalysis:false,adjacentMaps:false,requestsPerSecond:20},before=resolveScanConfig(legacyInput);
    const legacy=new Scanner(legacyInput,{detector:new Detector('disabled'),resolver:publicDns});
    try{virtualNetwork(legacy,hosts);const v=await legacy.run();assert.ok(v.origins!.filter(o=>o.authorization?.type==='same-registrable-domain').length>=2);assert.deepEqual(shared(v.config),shared(before),'legacy website-count settings do not grow on admission');assert.equal(v.profile!.kind,'custom');assert.equal(v.profile!.notExamined,undefined);}finally{legacy.dispose();}
    assert.deepEqual(trip.violations,[],'nothing reached the real network');
  }finally{trip.restore();}
});
const QUICK_SITE=():Record<string,[string,string,number?]>=>({
  '/':['text/html','<html><head><link rel="manifest" href="/manifest.webmanifest"><link rel="stylesheet" href="/site.css"></head><body><a href="/about">About</a><script src="/app.js"></script><img src="/logo.png"></body></html>'],
  '/robots.txt':['text/plain','User-agent: *\nAllow: /\nSitemap: /sitemap.xml'],
  '/app.js':['text/javascript','import("./chunk.js");fetch("/config/runtime.json");const hint="/hidden/hint.js";import("./chunk.js?v=2");\n//# sourceMappingURL=app.js.map'],
  '/app.js.map':['application/json',JSON.stringify({version:3,sources:['src/app.ts'],sourcesContent:['export const k="'+key('map')+'"'],mappings:''})],
  '/chunk.js':['text/javascript','export const c=1;'],'/config/runtime.json':['application/json',JSON.stringify({apiKey:key('runtime')})],'/.env':['text/plain','OPENAI_API_KEY='+key('env')],
  '/manifest.webmanifest':['application/manifest+json',JSON.stringify({name:'Fixture',start_url:'/start',icons:[{src:'/icon.png'}]})],
  '/about':['text/html','<script src="/about.js"></script><a href="/deep-page">deeper</a>'],'/about.js':['text/javascript','void 0;'],'/sitemap.xml':['application/xml','<urlset><url><loc>/deep-page</loc></url></urlset>'],'/deep-page':['text/html','deep'],'/site.css':['text/css','body{}']
});
test('Quick check requests only its target set and completes with honest quick coverage and an explicit not-examined list',{timeout:120000},async()=>{
  const routes=QUICK_SITE();routes['/old.js']=['text/javascript','void 0;'];routes['/old-page']=['text/html','old'];routes['/old.css']=['text/css','b{}'];
  const site=await serve(routes);const s=new Scanner({urls:[site.origin],developmentFixtureOrigin:site.origin,coverage:'quick',traffic:'normal'},{detector:new Detector()});
  // A deployment trigger replays earlier URLs: Quick check acquires replayed scripts (with their own bound), never replayed pages or stylesheets.
  try{await s.init();for(const p of ['/old.js','/old-page','/old.css'])s.enqueue(site.origin+p,site.origin,0,['authorized project history'],'stale-asset');const v=await s.run(),o=site.origin;
    for(const p of ['/old.js','/','/robots.txt','/app.js','/app.js.map','/chunk.js','/config/runtime.json','/manifest.webmanifest','/.env','/.git/HEAD','/wp-config.php.bak','/.git/config'])assert.ok(site.arrivals.includes(p),p+' is in the Quick target set');
    const never=['/old-page','/old.css','/about','/about.js','/sitemap.xml','/deep-page','/site.css','/hidden/hint.js','/chunk.js?v=2','/start','/icon.png','/logo.png','/chunk.js.map'];for(const p of never)assert.ok(!site.arrivals.includes(p),p+' must never be requested');
    assert.equal(v.state,'completed');assert.equal(v.stopReason,'quick-target-set-done');assert.equal(v.stage,'Completed — quick coverage');assert.equal(v.coverage!.assessment,'configured-checks-completed');assert.equal(v.browserStatus?.requested,false);
    assert.equal(v.profile!.kind,'profile');assert.equal(v.profile!.label,'Quick check + Normal');assert.equal(v.profile!.completion,'quick-coverage');assert.equal(v.config.preset,'custom');
    const notExamined=new Map(v.profile!.notExamined!.map(n=>[n.category,n]));
    for(const [category,url] of [['Linked pages','/about'],['Sitemaps','/sitemap.xml'],['Query-string variants','/chunk.js?v=2'],['Heuristic URL hints','/hidden/hint.js'],['Stylesheets, fonts and other assets','/site.css'],['Earlier-deployment assets other than scripts, source maps and configuration','/old-page'],['Earlier-deployment assets other than scripts, source maps and configuration','/old.css']])assert.ok(notExamined.get(category)?.examples.includes(o+url),category+' lists '+url);
    const boundary=v.limitations.find(g=>g.code==='quick-coverage-boundary')!;assert.equal(boundary.incomplete,false,'the Quick boundary is a stated scope, not unfinished work');assert.ok(v.profile!.notExamined!.every(n=>n.count===n.examples.length));assert.equal(boundary.count,new Set(v.profile!.notExamined!.flatMap(n=>n.examples)).size,'each URL is counted once across categories');assert.match(boundary.detail,/does not show that the site has no other exposures/);
    // Raster images keep their 2.5 record (never requested, listed as intentionally skipped); everything else outside the target set takes no inventory slot.
    const outside=never.filter(p=>p!=='/logo.png');assert.ok(!v.coverage!.inventory!.some(r=>outside.some(p=>r.url===o+p)),'work outside the target set takes no inventory slot');assert.ok(!v.resources.some(r=>outside.some(p=>r.url===o+p)),'and no audit record');
    assert.ok(v.findings.some(f=>f.provider==='OpenAI'&&f.occurrences.some(x=>x.url.endsWith('/.env'))));assert.ok(v.findings.some(f=>f.occurrences.some(x=>x.url.endsWith('/config/runtime.json'))));
    assert.deepEqual(runSummary({view:v}).profile,{kind:'profile',label:'Quick check + Normal',recorded:true});
    const json=JSON.parse(report(s,'json'));assert.equal(json.profile.completion,'quick-coverage');assert.equal(json.profile.coverage,'quick');assert.equal(json.profile.sizing.total.resources,100);assert.ok(json.profile.notExamined.length>=5,'redaction keeps the profile fields');
    const html=report(s,'html');assert.match(html,/Scan profile/);assert.match(html,/completed — quick coverage/);assert.match(html,/Not examined \(Quick check\): Linked pages/);assert.match(html,/Start estimate: up to 100 requests/);
    assert.equal(JSON.parse(report(s,'sarif')).runs[0].invocations[0].properties.profile.label,'Quick check + Normal');
  }finally{s.dispose();await site.close();}
});
test('Quick check bounds first-party scripts per website in discovery order and still completes; a custom Quick profile keeps the target set',{timeout:120000},async()=>{
  const n=QUICK_SCRIPTS_PER_WEBSITE+5,routes:Record<string,[string,string]>={'/':['text/html',Array.from({length:n},(_,i)=>`<script src="/s${i}.js"></script>`).join('')]};for(let i=0;i<n;i++)routes[`/s${i}.js`]=['text/javascript',`var s${i}=${i};`];
  const site=await serve(routes);const s=new Scanner({urls:[site.origin],developmentFixtureOrigin:site.origin,coverage:'quick',traffic:'normal',deep:false,originRequestsPerSecond:20,requestsPerSecond:20},{detector:new Detector()});
  try{await s.init();const v=await s.run(),scripts=site.arrivals.filter(p=>/^\/s\d+\.js$/.test(p));
    assert.equal(v.profile!.label,'Custom (based on Quick check + Normal)');assert.equal(scripts.length,QUICK_SCRIPTS_PER_WEBSITE);assert.deepEqual(scripts.sort(),Array.from({length:QUICK_SCRIPTS_PER_WEBSITE},(_,i)=>`/s${i}.js`).sort(),'entry-document scripts are admitted in discovery order');
    const beyond=v.profile!.notExamined!.find(e=>e.category==='Scripts beyond the per-website bound')!;assert.equal(beyond.count,5);assert.deepEqual(beyond.examples,Array.from({length:5},(_,i)=>`${site.origin}/s${QUICK_SCRIPTS_PER_WEBSITE+i}.js`));
    assert.equal(v.state,'completed');assert.equal(v.profile!.completion,'quick-coverage');assert.equal(v.stopReason,'quick-target-set-done');
  }finally{s.dispose();await site.close();}
});
test('an unfinished Quick target set stays incomplete with its reasons and never claims quick coverage',{timeout:120000},async()=>{
  const routes=QUICK_SITE();routes['/app.js']=['text/plain','temporarily unavailable',503];
  const site=await serve(routes);const s=new Scanner({urls:[site.origin],developmentFixtureOrigin:site.origin,coverage:'quick',traffic:'normal',deep:false,maxRetries:0,originRequestsPerSecond:20,requestsPerSecond:20},{detector:new Detector()});
  try{await s.init();const v=await s.run();
    assert.equal(v.state,'incomplete');assert.notEqual(v.stopReason,'quick-target-set-done');assert.equal(v.stage,'Stopped with coverage limitations');assert.equal(v.profile!.completion,undefined);
    assert.ok(v.limitations.some(g=>g.incomplete&&g.url===site.origin+'/app.js'),'the unfinished target is a stated reason');assert.ok(v.limitations.some(g=>g.code==='quick-coverage-boundary'&&!g.incomplete));
    assert.doesNotMatch(report(s,'html'),/completed — quick coverage/);
  }finally{s.dispose();await site.close();}
});
test('2.4 and 2.5 projects and records load unchanged: no profile keys appear, runs say "Legacy preset", reports say the profile was not recorded, and a switch is explicit',{timeout:60000},async()=>{
  // The 2.5 example files (frozen in test/fixtures/legacy-2.5) and the unchanged adaptive and fixture files stay legacy; the 2.6 examples choose ready options and reload unchanged too.
  for(const file of ['examples/config.example.json','examples/exhaustive.config.example.json','examples/exact-origin.config.example.json']){const raw=JSON.parse(await readFile(path.join(root,file),'utf8'));for(const input of raw.projects||[raw]){const c=makeConfig(input);assert.equal(describeProfile(c).kind,'profile',file);assert.ok(c.coverage&&c.traffic,file);assert.deepEqual(makeConfig(JSON.parse(JSON.stringify(c))),c,file+' reloads unchanged');}}
  for(const file of ['test/fixtures/legacy-2.5/config.example.json','test/fixtures/legacy-2.5/exhaustive.config.example.json','examples/adaptive.config.example.json','test/fixtures/legacy-2.5/exact-origin.config.example.json','examples/fixture.config.json']){const raw=JSON.parse(await readFile(path.join(root,file),'utf8'));for(const input of raw.projects||[raw]){const c=makeConfig(input);for(const k of ['coverage','traffic','profileCustomized'])assert.equal((c as any)[k],undefined,file);assert.deepEqual(makeConfig(JSON.parse(JSON.stringify(c))),c,file+' reloads unchanged');assert.notEqual(describeProfile(c).kind,'profile');}}
  const dir=await legacyCopy();try{
    const st=await new Store(dir,true).init(),before=await historyFiles(dir);
    for(const p of st.projects){for(const k of ['coverage','traffic','profileCustomized'])assert.equal((p.config as any)[k],undefined);assert.deepEqual(makeConfig(p.config),p.config,'loading never re-maps a saved configuration');assert.ok(['legacy-preset','custom'].includes(describeProfile(p.config).kind));}
    for(const h of st.history){assert.equal(h.view.profile,undefined);const summary=runSummary({view:h.view,projectId:h.projectId,savedAt:h.savedAt});assert.equal(summary.profile.recorded,false);assert.match(summary.profile.label,/^Legacy preset/);}
    const old=st.history[0].view,viewer=new Scanner({urls:old.config.urls},{detector:new Detector('disabled')});(viewer as any).view=()=>old;
    try{assert.match(report(viewer,'html'),/Legacy preset[^<]*\(profile not recorded by build/);assert.equal(JSON.parse(report(viewer,'json')).profile,undefined);}finally{viewer.dispose();}
    const target=st.projects[0];await assert.rejects(st.switchProfile(target.id,false,'quick'),/authorization/);
    const switched=await st.switchProfile(target.id,true,'quick','low-impact');assert.equal(describeProfile(switched.config).label,'Quick check + Low-impact');assert.equal(effectiveScope(switched.config),'exact-origin','switching never widens the saved scope');assert.equal(switched.config.scopeReview?.reason,'legacy-default-exact-origin');
    st.close();const reopened=await new Store(dir,true).init();try{assert.equal(reopened.projects.find(p=>p.id===target.id)!.config.coverage,'quick');assert.ok(reopened.projects.filter(p=>p.id!==target.id).every(p=>p.config.coverage===undefined),'other projects are untouched');}finally{reopened.close();}
    assert.deepEqual(await historyFiles(dir),before,'history files are never rewritten');
  }finally{await rm(dir,{recursive:true,force:true});}
});
test('dashboard: the workspace lists the profile catalog and a saved project switches to a profile only with authorization',{timeout:60000},async()=>{
  // Opening the copied 2.4 workspace recovers its interrupted run once; history is compared from then on.
  const dir=await legacyCopy();try{const app=await startDashboard({port:0,persistent:true,dataDir:dir,syntheticData:true}),before=await historyFiles(dir);
    try{const login=await fetch(app.origin+'/api/login',{method:'POST',headers:{'Content-Type':'application/json',Origin:app.origin,'X-Dashboard-Request':'1'},body:JSON.stringify({token:app.token})}),cookie=login.headers.get('set-cookie')!.split(';')[0],{csrf}=await login.json() as any;
      const headers={'Content-Type':'application/json',Origin:app.origin,'X-Dashboard-Request':'1','X-CSRF-Token':csrf,Cookie:cookie},workspace=async()=>await(await fetch(app.origin+'/api/workspace',{headers:{Cookie:cookie}})).json() as any;
      const w=await workspace();assert.equal(Object.keys(w.profiles.profiles).length,6);assert.deepEqual(w.profiles.legacy,LEGACY_PROFILES);assert.equal(w.profiles.ceilings.resources,2000);const id=w.projects[0].id;
      assert.ok((await fetch(app.origin+'/api/projects/profile',{method:'POST',headers,body:JSON.stringify({id,coverage:'standard'})})).status>=400,'switching requires the authorization acknowledgement');
      const ok=await fetch(app.origin+'/api/projects/profile',{method:'POST',headers,body:JSON.stringify({id,authorized:true,coverage:'standard',traffic:'low-impact'})});assert.equal(ok.status,200);const p=await ok.json() as any;assert.equal(p.config.coverage,'standard');assert.equal(p.config.traffic,'low-impact');
      const after=await workspace();assert.equal(after.projects.find((x:any)=>x.id===id).config.coverage,'standard');assert.ok(after.projects.filter((x:any)=>x.id!==id).every((x:any)=>x.config.coverage===undefined));
      const runs=await(await fetch(app.origin+'/api/runs',{headers:{Cookie:cookie}})).json() as any;assert.ok(runs.history.length>0&&runs.history.every((r:any)=>r.profile.recorded===false&&/^Legacy preset/.test(r.profile.label)),'history keeps the profile it ran with (not recorded)');
    }finally{await app.close();}
    assert.deepEqual(await historyFiles(dir),before,'history files are never rewritten');
  }finally{await rm(dir,{recursive:true,force:true});}
});
test('CLI: --coverage and --traffic are documented and validated, conflicts stop before any request, and a Quick scan prints its profile and completion',{timeout:120000},async()=>{
  const cli=path.join(root,'dist/src/cli.js'),parent=process.env.EXPOSURE_DATA_DIR||path.join(root,'.cache');await mkdir(parent,{recursive:true});const dir=await mkdtemp(path.join(parent,'profiles-cli-')),env={...process.env,EXPOSURE_DATA_DIR:dir};
  const site=await serve(QUICK_SITE());
  try{const help=spawnSync(process.execPath,[cli,'help'],{encoding:'utf8',env,windowsHide:true});assert.match(help.stdout,/--coverage quick\|standard\|deep/);assert.match(help.stdout,/--traffic low-impact\|normal/);assert.match(help.stdout,/not hidden|does not hide/i);
    for(const args of [['--coverage','maximum'],['--traffic','stealth'],['--preset','quick','--coverage','deep']]){const r=spawnSync(process.execPath,[cli,'scan','--url',site.origin,...args,'--output',path.join(dir,'never.json')],{encoding:'utf8',env,windowsHide:true});assert.equal(r.status,2,args.join(' '));}
    assert.equal(site.arrivals.length,0,'invalid or conflicting profile flags stop before any request');
    const cfg=path.join(dir,'quick.config.json'),out=path.join(dir,'quick.json');await writeFile(cfg,JSON.stringify({urls:[site.origin],developmentFixtureOrigin:site.origin}));
    // Asynchronous child: the fixture website is served by this process, so its event loop must stay free.
    const run=await new Promise<{status:number|null;stdout:string;stderr:string}>((resolve,reject)=>{const child=spawn(process.execPath,[cli,'scan','--config',cfg,'--coverage','quick','--format','json','--output',out,'--fail-on','never'],{env,windowsHide:true});let stdout='',stderr='';child.stdout.on('data',d=>stdout+=d);child.stderr.on('data',d=>stderr+=d);child.on('error',reject);child.on('close',status=>resolve({status,stdout,stderr}));});
    assert.equal(run.status,0,run.stderr);assert.match(run.stdout,/Profile: Quick check \+ Normal · 1 website · up to 100 requests over one connection each and 40 MiB · about 1 min at this pacing/);assert.match(run.stdout,/Completed — quick coverage: .*This does not show that the site has no secrets\./);
    const json=JSON.parse(await readFile(out,'utf8'));assert.equal(json.profile.completion,'quick-coverage');assert.equal(json.config.coverage,'quick');assert.ok(!site.arrivals.includes('/about'));
  }finally{await site.close();await rm(dir,{recursive:true,force:true});}
});
