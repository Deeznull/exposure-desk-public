import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { makeConfig, resolveScanConfig, followReadyOption, deepPaths } from '../src/config.js';
import { profilePreview, profileCatalog, readyOptions, presetConfig, LONG_RUN_MS } from '../src/presets.js';
import { COVERAGES, TRAFFICS, HARD_CEILINGS, LOW_IMPACT_LIMITS, COVERAGE_RESOURCES, PARALLEL_WEBSITES, RECOMMENDED, SMALL_COMPUTER, MEMORY_SHARE, ANALYSIS_MEMORY_CEILING_MB, computerCaps, resourceUse, describeProfile, profileSettings } from '../src/profiles.js';
import { Scanner } from '../src/scanner.js';
import { SemanticPool } from '../src/semantic.js';
import { Detector, root } from '../src/detectors.js';
import { report } from '../src/reports.js';
import { Store } from '../src/storage.js';
import { startDashboard } from '../src/dashboard.js';
import { egressTripwire } from './virtual-network.js';
import { syntheticBundle } from './large-bundle.js';
import type { Coverage, Traffic, ScanConfig } from '../src/types.js';
/** 2.6 P3b: the six ready options (Coverage × Traffic) with their local resources and parallel websites, the Recommended default, the hard ceilings through every entry point and the automatic adjustment to the website count and to this computer (lowered, never raised). Local only: nothing is contacted. */
const SITE='https://www.example.com/',sites=(n:number)=>Array.from({length:n},(_,i)=>`https://site${i}.example.com/`);
const BIG={cores:16,freeMemoryMb:32768},plural=(n:number,w:string)=>`${n} ${w}${n===1?'':'s'}`;
const key=(name:string)=>'sk-proj-'+createHash('sha512').update('unit-ready-options-'+name).digest('base64url').slice(0,64);
async function temp(){const parent=process.env.EXPOSURE_DATA_DIR||path.join(root,'.cache');await mkdir(parent,{recursive:true});return mkdtemp(path.join(parent,'ready-options-'));}
async function serve(routes:Record<string,[string,string]>){const arrivals:string[]=[];const server=http.createServer((q,r)=>{arrivals.push(q.url||'');const x=routes[q.url||''];if(!x){r.statusCode=404;r.end('not found');return;}r.writeHead(200,{'content-type':x[0]});r.end(x[1]);});await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));const origin=`http://127.0.0.1:${(server.address() as any).port}`;return {origin,arrivals,close:()=>new Promise<void>(r=>{server.closeAllConnections();server.close(()=>r());})};}
const OPTIONS=COVERAGES.flatMap(c=>TRAFFICS.map(t=>[c,t] as [Coverage,Traffic]));

test('the option tables are the owner-approved values: memory and workers by coverage only, parallel websites by coverage and traffic, 512 MiB and the parallel maxima as ceilings',()=>{
  assert.deepEqual(COVERAGE_RESOURCES,{quick:{maxAnalysisMemoryMb:256,analysisConcurrency:1},standard:{maxAnalysisMemoryMb:256,analysisConcurrency:2},deep:{maxAnalysisMemoryMb:512,analysisConcurrency:2}},'Quick check was tuned from 128 to 256 MiB (fixture measurement: 128 MiB left a 1.25 MB bundle’s split key unparsed)');
  assert.deepEqual(PARALLEL_WEBSITES,{quick:{normal:{websites:6,browser:0},'low-impact':{websites:2,browser:0}},standard:{normal:{websites:4,browser:2},'low-impact':{websites:2,browser:1}},deep:{normal:{websites:3,browser:2},'low-impact':{websites:2,browser:1}}});
  assert.equal(ANALYSIS_MEMORY_CEILING_MB,512);assert.equal(HARD_CEILINGS.analysisMemoryMb,512);assert.equal(HARD_CEILINGS.activeOrigins,8);assert.equal(HARD_CEILINGS.browserOrigins,4);assert.equal(HARD_CEILINGS.globalConcurrency,12);assert.equal(HARD_CEILINGS.requestsPerSecond,20);
  for(const c of COVERAGES){const [normal,low]=TRAFFICS.map(t=>profileSettings(c,t,deepPaths));assert.equal(normal.maxAnalysisMemoryMb,low.maxAnalysisMemoryMb,c+': traffic does not change memory');assert.equal(normal.analysisConcurrency,low.analysisConcurrency,c+': traffic does not change workers');}
});

test('resolved values for all six options at 1, 3 and 10 websites: websites at once never exceed the websites in scope, estimates grow with the website count, nothing is lowered on a large computer',()=>{
  for(const [c,t] of OPTIONS){
    const parallel=PARALLEL_WEBSITES[c][t],memory=COVERAGE_RESOURCES[c],browser=c!=='quick';let previous=0;
    for(const n of [1,3,10]){
      const p=profilePreview({urls:sites(n),coverage:c,traffic:t},BIG),label=`${c}+${t} at ${n}`;
      assert.equal(p.profile.kind,'profile',label);assert.equal(p.websites.explicit,n,label);
      assert.equal(p.config.maxActiveOrigins,parallel.websites,label);assert.equal(p.config.maxBrowserOrigins,Math.max(1,parallel.browser),label);assert.equal(p.config.browser,browser,label);
      assert.equal(p.config.maxAnalysisMemoryMb,memory.maxAnalysisMemoryMb,label);assert.equal(p.config.analysisConcurrency,memory.analysisConcurrency,label);
      const u=p.resourceUse;assert.equal(u.websites,n,label);
      assert.deepEqual(u.option,{websitesAtOnce:parallel.websites,browserWebsitesAtOnce:parallel.browser,analysisMemoryMb:memory.maxAnalysisMemoryMb,analysisWorkers:memory.analysisConcurrency},label);
      assert.deepEqual(u.used,{websitesAtOnce:Math.min(n,parallel.websites),browserWebsitesAtOnce:Math.min(n,parallel.browser),analysisMemoryMb:memory.maxAnalysisMemoryMb,analysisWorkers:memory.analysisConcurrency},label);
      assert.deepEqual(u.adjustments,[],label+': a large computer never raises anything');assert.deepEqual(u.computer,BIG,label);
      assert.equal(u.summary[0],`${plural(Math.min(n,parallel.websites),'website')} at once, adjusted for ${plural(n,'website')}`,label);
      assert.equal(u.summary[1],browser?`${Math.min(n,parallel.browser)} with the isolated browser at once`:'no isolated browser',label);
      assert.match(u.computerNote,/nothing lowered\.$/,label);
      // Domain scope may admit up to 50 discovered websites: the preview says how many could then run at once.
      assert.equal(p.websites.discoveredLimit,50,label);assert.deepEqual(u.withDiscovered,n<parallel.websites?{websites:n+50,websitesAtOnce:parallel.websites,browserWebsitesAtOnce:parallel.browser}:undefined,label);
      assert.ok(p.estimate.total.pacedMs>=previous,label+': the time estimate grows with the website count');previous=p.estimate.total.pacedMs;
      assert.ok(p.config.globalConcurrency!<=HARD_CEILINGS.globalConcurrency&&p.config.requestsPerSecond<=HARD_CEILINGS.requestsPerSecond,label);
      assert.equal(p.estimate.longRun,undefined,label+': ready options stay under the long-scan threshold for 10 websites');
    }
  }
  // Every option at every website count up to the discovered limit stays within the hard maxima.
  for(const [c,t] of OPTIONS)for(let n=1;n<=50;n++){const r=resolveScanConfig({urls:sites(n),coverage:c,traffic:t});
    assert.ok(r.maxActiveOrigins!<=HARD_CEILINGS.activeOrigins&&r.maxBrowserOrigins!<=HARD_CEILINGS.browserOrigins&&r.globalConcurrency!<=HARD_CEILINGS.globalConcurrency&&r.requestsPerSecond<=HARD_CEILINGS.requestsPerSecond&&r.maxAnalysisMemoryMb!<=ANALYSIS_MEMORY_CEILING_MB,`${c}+${t} at ${n}`);}
});

test('Low-impact never exceeds LOW_IMPACT_LIMITS: ready options, custom values and configuration files can only make it slower',()=>{
  const within=(r:any,label:string)=>{for(const [k,v] of Object.entries(LOW_IMPACT_LIMITS))assert.ok(r[k]<=v,`${label}: ${k} ${r[k]} > ${v}`);};
  for(const c of COVERAGES)for(const n of [1,3,10,50]){within(resolveScanConfig({urls:sites(n),coverage:c,traffic:'low-impact'}),`${c} at ${n}`);
    const pushed=resolveScanConfig({urls:sites(n),coverage:c,traffic:'low-impact',maxActiveOrigins:8,maxBrowserOrigins:4,originConcurrency:8,originRequestsPerSecond:20,maxRetries:3});within(pushed,`custom ${c} at ${n}`);
    const u=resourceUse(pushed,n,BIG);assert.ok(u.used.websitesAtOnce<=LOW_IMPACT_LIMITS.maxActiveOrigins&&u.used.browserWebsitesAtOnce<=LOW_IMPACT_LIMITS.maxBrowserOrigins,`${c} at ${n}: used`);}
});

test('computer-based lowering: small or busy computers lower workers, browser websites and memory; values are never raised; legacy settings run as stored',()=>{
  const cfg=(c:Coverage,t:Traffic)=>resolveScanConfig({urls:[SITE],coverage:c,traffic:t});
  assert.deepEqual(SMALL_COMPUTER,{cores:4,freeMemoryMb:2048});assert.equal(MEMORY_SHARE,.25);
  for(const [c,t] of OPTIONS){const config=cfg(c,t),r=COVERAGE_RESOURCES[c],browser=PARALLEL_WEBSITES[c][t].browser;
    // Never raised: a huge computer keeps the option's values exactly.
    const big=computerCaps(config,{cores:128,freeMemoryMb:1024*1024});assert.deepEqual([big.analysisWorkers,big.analysisMemoryMb,big.adjustments],[r.analysisConcurrency,r.maxAnalysisMemoryMb,[]],`${c}+${t} big`);
    // Few cores: one worker and one browser website; plenty of free memory keeps memory.
    const cores=computerCaps(config,{cores:2,freeMemoryMb:16384});assert.equal(cores.analysisWorkers,1);assert.equal(cores.analysisMemoryMb,r.maxAnalysisMemoryMb);if(browser)assert.equal(cores.browserWebsites,1);
    assert.deepEqual(cores.adjustments.map(a=>a.setting),[...(r.analysisConcurrency>1?['analysisWorkers']:[]),...(browser>1?['browserWebsitesAtOnce']:[])],`${c}+${t} cores`);
    for(const a of cores.adjustments){assert.equal(a.reason,'this computer has 2 logical cores (fewer than 4)');assert.ok(a.to<a.from);}
    // Little free memory: small computer and memory within a quarter of the free memory.
    const busy=computerCaps(config,{cores:16,freeMemoryMb:1500});assert.equal(busy.analysisWorkers,1);assert.equal(busy.analysisMemoryMb,Math.min(r.maxAnalysisMemoryMb,375));
    if(r.maxAnalysisMemoryMb>375)assert.deepEqual(busy.adjustments.find(a=>a.setting==='analysisMemoryMb'),{setting:'analysisMemoryMb',from:r.maxAnalysisMemoryMb,to:375,reason:'kept within a quarter of this computer’s 1500 MiB free memory'});
    // A nearly full computer never goes below the configuration minimum of 64 MiB per worker.
    const tiny=computerCaps(config,{cores:1,freeMemoryMb:100});assert.deepEqual([tiny.analysisWorkers,tiny.analysisMemoryMb],[1,64]);assert.ok(tiny.adjustments.every(a=>a.to<a.from&&a.reason.length>10));
    assert.equal(tiny.adjustments[0].reason,r.analysisConcurrency>1||browser>1?'this computer has 1 logical core (fewer than 4)':'kept within a quarter of this computer’s 100 MiB free memory');
  }
  // Lower configured values stay lower: a custom profile with 64 MiB and one worker is never raised.
  const low=resolveScanConfig({urls:[SITE],coverage:'deep',traffic:'normal',maxAnalysisMemoryMb:64,analysisConcurrency:1,maxBrowserOrigins:1});assert.equal(describeProfile(low).kind,'custom-profile');
  assert.deepEqual(computerCaps(low,BIG),{analysisWorkers:1,analysisMemoryMb:64,browserWebsites:1,adjustments:[]});
  // Legacy presets and custom settings without a profile run as stored, as in 2.5.
  const legacy=resolveScanConfig(presetConfig('thorough',{urls:[SITE]})),u=resourceUse(legacy,1,{cores:1,freeMemoryMb:100});assert.deepEqual(u.adjustments,[]);assert.equal(u.used.analysisMemoryMb,legacy.maxAnalysisMemoryMb);assert.equal(u.computerNote,'Legacy preset or custom settings: they run as entered and are not adjusted to this computer.');
  // Plain words for the dashboard, CLI and report.
  const deep=resourceUse(cfg('deep','normal'),10,{cores:2,freeMemoryMb:1500});
  assert.deepEqual(deep.summary,['3 websites at once, adjusted for 10 websites','1 with the isolated browser at once (lowered from 2 for this computer)','375 MiB analysis memory (lowered from 512 MiB for this computer)','1 analysis worker (lowered from 2 for this computer)']);
  assert.equal(deep.computerNote,'This computer: 2 logical cores, 1.5 GiB free memory; lowered analysis workers 2 → 1, browser websites at once 2 → 1, analysis memory (MiB) 512 → 375. Values are only ever lowered, never raised.');
  assert.equal(resourceUse(cfg('quick','normal'),1).computerNote,'This computer was not checked.');
});

test('a scanner applies the computer caps to its pool and loops, records them in its profile view and keeps the option’s configuration, so checkpoints and retries stay the ready option',()=>{
  const s=new Scanner({urls:[SITE],coverage:'standard',traffic:'normal'},{computer:{cores:2,freeMemoryMb:1000}});
  try{
    assert.deepEqual({workers:s.caps.analysisWorkers,memory:s.caps.analysisMemoryMb,browser:s.caps.browserWebsites},{workers:1,memory:250,browser:1});
    assert.equal(s.pool.size,1,'the semantic pool starts one worker');
    assert.equal(s.config.maxAnalysisMemoryMb,256);assert.equal(s.config.analysisConcurrency,2);assert.equal(s.config.maxBrowserOrigins,2);assert.equal(describeProfile(s.config).label,'Standard + Normal');
    const v=s.profileView();assert.equal(v.recommended,true);assert.deepEqual(v.resourceUse!.adjustments.map(a=>[a.setting,a.from,a.to]),[['analysisWorkers',2,1],['browserWebsitesAtOnce',2,1],['analysisMemoryMb',256,250]]);
    assert.equal(describeProfile(resolveScanConfig(s.checkpoint().config)).label,'Standard + Normal','a checkpoint resumes as the ready option, not as custom settings');
  }finally{s.dispose();}
  const legacy=new Scanner(presetConfig('thorough',{urls:[SITE]}),{computer:{cores:1,freeMemoryMb:100}});
  try{assert.deepEqual(legacy.caps.adjustments,[]);assert.equal(legacy.caps.analysisWorkers,legacy.config.analysisConcurrency);assert.equal(legacy.pool.size,legacy.config.analysisConcurrency);}finally{legacy.dispose();}
});

test('Recommended: Standard + Normal is marked once in the catalog, the preview and the CLI help, and is the CLI default for a new scan',{timeout:120000},async()=>{
  assert.deepEqual(RECOMMENDED,{coverage:'standard',traffic:'normal'});
  const catalog=profileCatalog(),options=readyOptions();assert.deepEqual(catalog.recommended,{coverage:'standard',traffic:'normal',label:'Standard + Normal'});
  assert.deepEqual(options.map(o=>o.id),['quick+normal','quick+low-impact','standard+normal','standard+low-impact','deep+normal','deep+low-impact']);
  assert.deepEqual(options.filter(o=>o.recommended).map(o=>o.id),['standard+normal']);assert.deepEqual(Object.values(catalog.profiles).filter((p:any)=>p.recommended).map((p:any)=>p.label),['Standard + Normal']);
  for(const o of options){assert.equal(o.facts.websitesAtOnce,PARALLEL_WEBSITES[o.coverage][o.traffic].websites);assert.equal(o.facts.browserWebsitesAtOnce,PARALLEL_WEBSITES[o.coverage][o.traffic].browser);assert.equal(o.facts.analysisMemoryMb,COVERAGE_RESOURCES[o.coverage].maxAnalysisMemoryMb);assert.ok(o.summary.length>20);}
  assert.equal(profilePreview({urls:[SITE],coverage:'standard',traffic:'normal'}).profile.recommended,true);
  assert.equal(profilePreview({urls:[SITE],coverage:'standard',traffic:'low-impact'}).profile.recommended,undefined);
  assert.equal(profilePreview({urls:[SITE],coverage:'standard',traffic:'normal',maxPages:10}).profile.recommended,undefined,'a custom profile based on Standard + Normal is not the Recommended option');
  const cli=path.join(root,'dist/src/cli.js'),dir=await temp(),env={...process.env,EXPOSURE_DATA_DIR:dir};
  try{
    const help=spawnSync(process.execPath,[cli,'help'],{encoding:'utf8',env,windowsHide:true});assert.equal(help.status,0);
    assert.equal(help.stdout.match(/\(Recommended\)/g)?.length,1);assert.match(help.stdout,/Standard \+ Normal \(Recommended\) +4 +2 +256 MiB +2 /);assert.match(help.stdout,/Quick check \+ Normal +6 +none +256 MiB +1 /);assert.match(help.stdout,/Deep audit \+ Low-impact +2 +1 +512 MiB +2 /);
    assert.match(help.stdout,/Automatic adjustment \(always on\)/);assert.match(help.stdout,/only ever lowered, never raised/);assert.match(help.stdout,/Analysis memory never exceeds 512 MiB/);
    // A new scan without a preset, profile flags or configuration file uses the Recommended option; the child stops after printing its plan (the address is unroutable and private).
    // The promise settles on 'close' only, so the child has released its working directory before the cleanup below.
    const plan=(extra:string[])=>new Promise<{stdout:string;stderr:string}>((resolve,reject)=>{const child=spawn(process.execPath,[cli,'scan','--url','http://127.0.0.1:1/',...extra,'--output',path.join(dir,'never.json')],{cwd:dir,env,windowsHide:true});let stdout='',stderr='';const timer=setTimeout(()=>child.kill(),30000);
      child.stdout.on('data',d=>{stdout+=d;if(/\nUses: .*\n/.test(stdout))child.kill();});child.stderr.on('data',d=>stderr+=d);child.on('error',reject);child.on('close',()=>{clearTimeout(timer);resolve({stdout,stderr});});});
    const out=(await plan([])).stdout;
    assert.match(out,/\nProfile: Standard \+ Normal · 1 website /);// The plan reads this computer, so a small one (a 2-core CI runner) adds "(lowered from … for this computer)" after a value; the lowering itself is tested with injected computers above.
    const lowered=' (?:\\(lowered from \\d+(?: MiB)? for this computer\\) )?';
    assert.match(out,new RegExp('\\nUses: 1 website at once, adjusted for 1 website · 1 with the isolated browser at once'+lowered+'· \\d+ MiB analysis memory'+lowered+'· \\d analysis workers?\\b.*This computer: '));
    // --sizing is a 2.5 legacy flag: it keeps the 2.5 legacy default (every sizing mode accepted) instead of failing against the Recommended option.
    for(const sizing of ['fixed','website-count','adaptive']){const r=await plan(['--sizing',sizing]);assert.match(r.stdout,/\nProfile: (?!Standard \+ Normal)/,sizing+': '+r.stderr);assert.match(r.stdout,/\nUses: .*not adjusted to this computer/,sizing);}
  }finally{await rm(dir,{recursive:true,force:true,maxRetries:5});}
});

test('hard ceilings through configuration objects, configuration files and the CLI: values above 512 MiB or the parallel maxima are refused before any request',{timeout:60000},async()=>{
  const over={maxAnalysisMemoryMb:ANALYSIS_MEMORY_CEILING_MB+1,maxActiveOrigins:HARD_CEILINGS.activeOrigins+1,maxBrowserOrigins:HARD_CEILINGS.browserOrigins+1,globalConcurrency:HARD_CEILINGS.globalConcurrency+1,requestsPerSecond:HARD_CEILINGS.requestsPerSecond+1};
  for(const [k,v] of Object.entries(over))for(const base of [{},{coverage:'deep',traffic:'normal'},{preset:'exhaustive'}] as Partial<ScanConfig>[]){
    assert.throws(()=>makeConfig({urls:[SITE],...base,[k]:v}),/.+/,`${k}=${v} ${JSON.stringify(base)}`);assert.throws(()=>resolveScanConfig({urls:[SITE],...base,[k]:v}),/.+/,`${k}=${v} resolved`);}
  assert.throws(()=>makeConfig({urls:[SITE],maxAnalysisMemoryMb:1024}));
  // At the ceiling is accepted; Deep audit at 512 MiB is the ready option itself, Quick check at 512 MiB is a custom profile.
  assert.equal(describeProfile(resolveScanConfig({urls:[SITE],coverage:'deep',maxAnalysisMemoryMb:512})).label,'Deep audit + Normal');
  assert.equal(describeProfile(resolveScanConfig({urls:[SITE],coverage:'quick',maxAnalysisMemoryMb:512})).label,'Custom (based on Quick check + Normal)');
  const atMax=resolveScanConfig({urls:[SITE],maxActiveOrigins:8,maxBrowserOrigins:4,globalConcurrency:12,requestsPerSecond:20,maxAnalysisMemoryMb:512});assert.deepEqual([atMax.maxActiveOrigins,atMax.maxBrowserOrigins,atMax.globalConcurrency,atMax.requestsPerSecond,atMax.maxAnalysisMemoryMb],[8,4,12,20,512]);
  const site=await serve({'/':['text/html','<!doctype html><p>ceiling fixture</p>']}),cli=path.join(root,'dist/src/cli.js'),dir=await temp(),env={...process.env,EXPOSURE_DATA_DIR:dir};
  try{for(const [k,v] of Object.entries(over))for(const flags of [[],['--coverage','quick'],['--preset','standard']]){
      const cfg=path.join(dir,`${k}.config.json`);await writeFile(cfg,JSON.stringify({urls:[site.origin+'/'],developmentFixtureOrigin:site.origin,[k]:v}));
      const r=spawnSync(process.execPath,[cli,'scan','--config',cfg,...flags,'--output',path.join(dir,'never.json')],{encoding:'utf8',env,windowsHide:true,timeout:60000});
      assert.equal(r.status,2,`${k} ${flags.join(' ')}: ${r.stdout}`);assert.doesNotMatch(r.stdout,/Profile:/);}
    assert.deepEqual(site.arrivals,[],'out-of-range configuration files stop before any request');
  }finally{await site.close();await rm(dir,{recursive:true,force:true});}
});

test('dashboard: saved projects and scan starts refuse values above the ceilings, the preview applies the injected computer through redaction, and the workspace lists the six options with one Recommended',{timeout:60000},async()=>{
  const dir=await temp(),app=await startDashboard({port:0,persistent:true,dataDir:dir,syntheticData:true,computer:()=>({cores:2,freeMemoryMb:1000})});const trip=egressTripwire();
  try{
    const login=await fetch(app.origin+'/api/login',{method:'POST',headers:{'Content-Type':'application/json',Origin:app.origin,'X-Dashboard-Request':'1'},body:JSON.stringify({token:app.token})});const cookie=login.headers.get('set-cookie')!.split(';')[0],{csrf}=await login.json() as any;
    const headers={'Content-Type':'application/json',Origin:app.origin,'X-Dashboard-Request':'1','X-CSRF-Token':csrf,Cookie:cookie};
    const post=(route:string,data:unknown)=>fetch(app.origin+route,{method:'POST',headers,body:JSON.stringify(data)});
    for(const extra of [{maxAnalysisMemoryMb:1024},{maxAnalysisMemoryMb:513},{maxActiveOrigins:9},{maxBrowserOrigins:5},{globalConcurrency:13},{requestsPerSecond:21}])for(const base of [{coverage:'deep',traffic:'normal'},{}]){
      const config={name:'Ceiling',urls:[SITE],...base,...extra};
      assert.equal((await post('/api/projects/save',{config,authorized:true})).status,400,'save '+JSON.stringify(config));
      assert.equal((await post('/api/scans',{config,authorized:true,requestId:'ready-options-ceiling-01'})).status,400,'start '+JSON.stringify(config));
      assert.equal((await post('/api/profile/preview',{config})).status,400,'preview '+JSON.stringify(config));}
    assert.equal(app.scans.size,0,'nothing started');
    const ws=await(await fetch(app.origin+'/api/workspace',{headers:{Cookie:cookie}})).json() as any;assert.equal(ws.projects.length,0,'nothing saved');
    assert.deepEqual(ws.profiles.options.filter((o:any)=>o.recommended).map((o:any)=>o.label),['Standard + Normal']);assert.equal(ws.profiles.options.length,6);assert.deepEqual(ws.profiles.computer,{cores:4,freeMemoryMb:2048,memoryShare:.25});
    const saved=await(await post('/api/projects/save',{config:{name:'Deep at the ceiling',urls:[SITE],coverage:'deep',traffic:'normal',maxAnalysisMemoryMb:512},authorized:true})).json() as any;assert.equal(saved.config.maxAnalysisMemoryMb,512);
    const p=await(await post('/api/profile/preview',{config:{urls:[SITE],coverage:'standard',traffic:'normal'}})).json() as any;
    assert.equal(p.profile.recommended,true);assert.deepEqual(p.resourceUse.computer,{cores:2,freeMemoryMb:1000});
    assert.deepEqual(p.resourceUse.adjustments,[{setting:'analysisWorkers',from:2,to:1,reason:'this computer has 2 logical cores (fewer than 4)'},{setting:'browserWebsitesAtOnce',from:2,to:1,reason:'this computer has 2 logical cores (fewer than 4)'},{setting:'analysisMemoryMb',from:256,to:250,reason:'kept within a quarter of this computer’s 1000 MiB free memory'}],'adjustments survive the dashboard redaction');
    assert.equal(p.resourceUse.summary[0],'1 website at once, adjusted for 1 website');assert.match(p.resourceUse.computerNote,/Values are only ever lowered, never raised\.$/);assert.equal(p.estimate.longRun,undefined);
    const slow=await(await post('/api/profile/preview',{config:{urls:sites(10),coverage:'deep',traffic:'normal',originRequestsPerSecond:.2,maxActiveOrigins:1}})).json() as any;
    assert.match(slow.estimate.longRun,/^Custom \(based on Deep audit \+ Normal\) may take about [\d.]+ h at this pacing for 10 websites\. Quick check would take about \d+ min; consider it for a first look\. Nothing is switched automatically\.$/);assert.equal(slow.config.coverage,'deep','never switched automatically');
    assert.deepEqual(trip.violations,[]);
  }finally{trip.restore();await app.close();await rm(dir,{recursive:true,force:true});}
});

test('a long estimate names Quick check and switches nothing; only estimates over about 2 hours are flagged',()=>{
  const slow=profilePreview({urls:sites(10),coverage:'deep',traffic:'normal',originRequestsPerSecond:.2,maxActiveOrigins:1});
  assert.ok(slow.estimate.total.pacedMs>LONG_RUN_MS);assert.match(slow.estimate.longRun!,/Quick check would take about \d+ min/);assert.equal(slow.config.coverage,'deep');assert.equal(slow.config.originRequestsPerSecond,.2);
  const quick=profilePreview({urls:sites(10),coverage:'quick',traffic:'low-impact',originRequestsPerSecond:.1});assert.match(quick.estimate.longRun!,/Nothing is switched automatically\.$/);
  const fine=profilePreview({urls:sites(10),coverage:'deep',traffic:'normal',originRequestsPerSecond:.1});assert.ok(fine.estimate.total.pacedMs<=LONG_RUN_MS);assert.equal(fine.estimate.longRun,undefined);
});

test('saved ready options follow the current option tables; legacy presets, custom settings and custom profiles keep every stored number',()=>{
  const stored={...resolveScanConfig({urls:[SITE],coverage:'quick',traffic:'normal'})} as any;assert.deepEqual(stored.sharedLimits,{});assert.equal(stored.profileCustomized,undefined);
  const older={...stored,maxAnalysisMemoryMb:256,analysisConcurrency:2,maxActiveOrigins:4,maxBrowserOrigins:2};
  const followed=makeConfig(followReadyOption(older));assert.equal(followed.maxAnalysisMemoryMb,256);assert.equal(followed.analysisConcurrency,1);assert.equal(followed.maxActiveOrigins,6);assert.equal(describeProfile(followed).label,'Quick check + Normal');assert.deepEqual(followed.urls,[SITE]);
  const custom={...resolveScanConfig({urls:[SITE],coverage:'quick',traffic:'normal',maxPages:3})} as any;assert.equal(custom.profileCustomized,true);assert.deepEqual(followReadyOption(custom),custom);
  const legacy=makeConfig(presetConfig('standard',{urls:[SITE]}));assert.deepEqual(followReadyOption(legacy),legacy);
  // Analysis memory and workers became option settings in P3b: an earlier owner choice below the table is kept (and shows as custom), the earlier default follows the table, nothing is raised over a choice.
  const deepStored={...resolveScanConfig({urls:[SITE],coverage:'deep',traffic:'normal'})} as any;
  const earlierDefault=makeConfig(followReadyOption({...deepStored,maxAnalysisMemoryMb:256,analysisConcurrency:2}));assert.deepEqual([earlierDefault.maxAnalysisMemoryMb,earlierDefault.analysisConcurrency,describeProfile(earlierDefault).label],[512,2,'Deep audit + Normal']);
  const owner=makeConfig(followReadyOption({...deepStored,maxAnalysisMemoryMb:128,analysisConcurrency:1}));assert.deepEqual([owner.maxAnalysisMemoryMb,owner.analysisConcurrency,describeProfile(owner).label],[128,1,'Custom (based on Deep audit + Normal)']);
  const quickTwo=makeConfig(followReadyOption({...stored,analysisConcurrency:2,maxAnalysisMemoryMb:256}));assert.deepEqual([quickTwo.analysisConcurrency,describeProfile(quickTwo).label],[1,'Quick check + Normal'],'the earlier default of two workers follows Quick check’s one');
  const capped={...stored,sharedLimits:{maxPages:10}};assert.deepEqual(followReadyOption(capped),capped,'entered shared caps are kept as stored');
  for(const k of ['staleAssetCheck'])if(stored[k]!==undefined)assert.equal((followReadyOption(stored) as any)[k],stored[k],'run options stay');
});

test('the report and the scan record contain every adjustment for this computer, and Quick check still finds its synthetic keys',{timeout:120000},async()=>{
  const K={inline:key('inline'),app:key('app')},site=await serve({'/':['text/html',`<!doctype html><script>window.S={openai:${JSON.stringify(K.inline)}}</script><script src="/app.js"></script>`],'/app.js':['text/javascript',`const client={apiKey:${JSON.stringify(K.app)}};`],'/robots.txt':['text/plain','User-agent: *\nAllow: /\n']});
  const dir=await temp(),s=new Scanner({urls:[site.origin+'/'],developmentFixtureOrigin:site.origin,coverage:'quick',traffic:'normal'},{detector:new Detector(),computer:{cores:2,freeMemoryMb:600}});
  try{
    await s.init();const v=await s.run();
    const values=new Set([...s.evidence.findings.values()].map(f=>s.evidence.reveal(f.id).value));assert.ok(values.has(K.inline)&&values.has(K.app),'both synthetic keys found at the lowered memory');
    const expected=[{setting:'analysisMemoryMb',from:256,to:150,reason:'kept within a quarter of this computer’s 600 MiB free memory'}];
    assert.equal(v.profile!.label,'Quick check + Normal');assert.deepEqual(v.profile!.resourceUse!.adjustments,expected);assert.deepEqual(s.caps.analysisMemoryMb,150);
    assert.deepEqual(v.profile!.resourceUse!.summary,['1 website at once, adjusted for 1 website','no isolated browser','150 MiB analysis memory (lowered from 256 MiB for this computer)','1 analysis worker']);
    const json=JSON.parse(report(s,'json'));assert.deepEqual(json.profile.resourceUse.adjustments,expected);assert.equal(json.config.maxAnalysisMemoryMb,256,'the record keeps the option value next to the lowered one');
    const sarif=JSON.parse(report(s,'sarif'));assert.deepEqual(sarif.runs[0].invocations[0].properties.profile.resourceUse.adjustments,expected);
    const html=report(s,'html');assert.match(html,/Lowered for this computer: analysis memory \(MiB\) 256 → 150 \(kept within a quarter of this computer’s 600 MiB free memory\)/);assert.match(html,/Uses: 1 website at once, adjusted for 1 website/);
    for(const text of [JSON.stringify(json),JSON.stringify(sarif),html])assert.ok(!text.includes(K.inline)&&!text.includes(K.app),'redacted reports never contain the synthetic keys');
    assert.deepEqual(s.checkpoint().redactedReview.profile!.resourceUse!.adjustments,expected,'the checkpoint carries the adjustments');
    let store=await new Store(dir,true).init();await store.record(undefined,v);store.close();store=await new Store(dir,true).init();
    try{const h=store.history.find(x=>x.view.id===s.id)!;assert.deepEqual(h.view.profile!.resourceUse!.adjustments,expected,'the saved scan record keeps the adjustments');}finally{store.close();}
  }finally{s.dispose();await site.close();await rm(dir,{recursive:true,force:true});}
});

test('each coverage finds the synthetic keys of the large-bundle fixture at its ready-option memory (Quick check; Standard and Deep audit run in the browser suite)',{timeout:180000},async()=>{
  const bundle=syntheticBundle({seed:'ExposureDesk/ready-options/1',targetBytes:1252570}),K={inline:key('q-inline'),app:key('q-app'),map:key('q-map'),split:key('q-split'),bundle:bundle.value},half=K.split.length>>1;
  const site=await serve({'/':['text/html',`<!doctype html><script>window.S={openai:${JSON.stringify(K.inline)}}</script><script src="/app.js"></script><script type="module" src="/bundle.js"></script><script type="module" src="/main.js"></script>`],
    '/app.js':['text/javascript',`const client={apiKey:${JSON.stringify(K.app)}};\n//# sourceMappingURL=app.js.map`],'/app.js.map':['application/json',JSON.stringify({version:3,file:'app.js',sources:['src/c.ts'],sourcesContent:[`export const serverKey=${JSON.stringify(K.map)};`],names:[],mappings:'AAAA'})],
    '/main.js':['text/javascript',`import {a} from "./part.js";export const openaiKey=a+${JSON.stringify(K.split.slice(half))};`],'/part.js':['text/javascript',`export const a=${JSON.stringify(K.split.slice(0,half))};`],'/bundle.js':['text/javascript',bundle.text],'/robots.txt':['text/plain','User-agent: *\nAllow: /\n']});
  const s=new Scanner({urls:[site.origin+'/'],developmentFixtureOrigin:site.origin,coverage:'quick',traffic:'normal'},{detector:new Detector(),computer:BIG});
  try{await s.init();const v=await s.run();const values=new Set([...s.evidence.findings.values()].map(f=>s.evidence.reveal(f.id).value));
    assert.deepEqual(Object.entries(K).filter(([,x])=>!values.has(x)).map(([k])=>k),[],'Quick check at 256 MiB and one worker parses the 1.25 MB bundle group and finds every key');
    assert.equal(v.profile!.label,'Quick check + Normal');assert.equal(s.caps.analysisMemoryMb,256);assert.ok(!v.limitations.some(g=>g.code==='semantic-memory-ceiling'),'no group was left unparsed for memory');
  }finally{s.dispose();await site.close();}
});

test('the analysis memory is a ceiling for all parser heaps together: an exclusive (whole-ceiling) worker runs alone, idle workers end first, and no shared worker starts while it waits or runs',{timeout:60000},async()=>{
  const pool=new SemanticPool(2,128) as any,pause=(ms:number)=>new Promise(r=>setTimeout(r,ms)),heap=()=>[...pool.busy,...pool.idle].reduce((a:number,w:any)=>a+w.memoryMb,0);
  try{
    const a=await pool.acquire(128,false),b=await pool.acquire(128,false);await pool.release(b,false);assert.equal(pool.idle.length,1);assert.ok(heap()<=256);
    let exclusive:any;const waiting=pool.acquire(256,true).then((e:any)=>exclusive=e);await pause(30);assert.equal(exclusive,undefined,'the exclusive worker waits for busy workers');
    let shared:any;const later=pool.acquire(128,false).then((e:any)=>shared=e);await pause(30);assert.equal(shared,undefined,'no shared worker starts while an exclusive one waits');
    await pool.release(a,false);await waiting;assert.ok(exclusive);assert.equal(pool.idle.length,0,'idle workers end before the exclusive worker starts');assert.equal(heap(),256,'the exclusive worker holds the whole ceiling alone');
    await pause(30);assert.equal(shared,undefined,'no shared worker starts while the exclusive one runs');
    await pool.release(exclusive,true);await later;assert.ok(shared);assert.equal((shared as {memoryMb:number}).memoryMb,128);await pool.release(shared,false);
  }finally{await pool.dispose();}
});
