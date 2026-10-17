import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { mkdir, mkdtemp, readdir, rm } from 'node:fs/promises';
import { profilePreview } from '../src/presets.js';
import { discoveredLimit } from '../src/domain-scope.js';
import { makeConfig } from '../src/config.js';
import { trafficText, historyReport } from '../src/reports.js';
import { startDashboard } from '../src/dashboard.js';
import { root } from '../src/detectors.js';
import { egressTripwire } from './virtual-network.js';
/** 2.6 P3: the scan-page preview (pure function and endpoint), profile labels for projects, queue and routines, the report traffic line and the CLI help. Local only: nothing is contacted. */
const SITE='https://www.example.com/',sites=(n:number)=>Array.from({length:n},(_,i)=>`https://site${i}.example.com/`);
async function temp(){const parent=process.env.EXPOSURE_DATA_DIR||path.join(root,'.cache');await mkdir(parent,{recursive:true});return mkdtemp(path.join(parent,'profile-ui-'));}
test('profile preview resolves, sizes and estimates exactly as the scanner would, without contacting anything',()=>{
  const trip=egressTripwire();try{
    const input={urls:[SITE],coverage:'deep' as const,traffic:'normal' as const},frozen=JSON.stringify(input),p=profilePreview(input);
    assert.equal(JSON.stringify(input),frozen,'the input is not mutated');
    assert.deepEqual(p.profile,{kind:'profile',label:'Deep audit + Normal',coverage:'deep',traffic:'normal'});
    assert.deepEqual(p.websites,{explicit:1,discoveredLimit:50,scope:'registrable-domain'});
    assert.equal(p.estimate.total.requests,600);assert.equal(p.estimate.total.connections,600);assert.equal(p.estimate.expectedMinutes,7);assert.equal(p.estimate.withDiscovered!.websites,51);
    assert.equal(p.config.maxResources,600);assert.deepEqual(p.sizing.cappedBy,[]);assert.ok(p.examines.length&&p.skips.length);assert.equal(p.slower,undefined);
    // Low-impact: the slower-pace note compares with Normal and says the scan is not hidden; connections follow the keep-alive estimate.
    const low=profilePreview({urls:[SITE],coverage:'deep',traffic:'low-impact'});
    assert.equal(low.estimate.expectedMinutes,21);assert.equal(low.estimate.total.connections,8);assert.equal(low.estimate.total.connectionsMax,600);
    assert.equal(low.slower,'Deep audit + Low-impact will take longer: about 21 min at this pacing, against about 7 min with Normal traffic. It does not hide the scan.');
    assert.match(low.trafficNote,/does not hide the scan/);assert.ok(low.skips.some(s=>/Low-impact/.test(s)));
    // Website count: 3 entered websites size the shared caps; 50 reach the hard ceilings, which are reported.
    const three=profilePreview({urls:sites(3),coverage:'quick',traffic:'normal'});assert.equal(three.websites.explicit,3);assert.equal(three.config.maxResources,300);assert.equal(three.estimate.total.requests,300);
    const fifty=profilePreview({urls:sites(50),coverage:'deep',traffic:'normal'});assert.deepEqual(fifty.sizing.cappedBy,['pages','resources','bytes','decodedBytes','maps','browserPages']);assert.equal(fifty.config.maxResources,2000);
    // Discovered limit: exact-origin and IP or local seeds add no websites; the scanner uses the same helper.
    assert.equal(profilePreview({urls:[SITE],coverage:'quick',traffic:'normal',domainScope:'exact-origin'}).websites.discoveredLimit,0);
    assert.equal(profilePreview({urls:['http://127.0.0.1:8080/'],privateOrigins:['http://127.0.0.1:8080'],coverage:'quick',traffic:'normal'}).websites.discoveredLimit,0);
    assert.equal(discoveredLimit(makeConfig({urls:[SITE],maxAutoDiscoveredOrigins:7})),7);
    // Edits: a per-website number makes the profile custom; an entered shared cap is an owner limit that sizing never raises.
    const edited=profilePreview({urls:sites(3),coverage:'standard',traffic:'normal',originMaxResources:300,sharedLimits:{}});assert.deepEqual([edited.profile.kind,edited.profile.label],['custom-profile','Custom (based on Standard + Normal)']);assert.equal(edited.config.maxResources,900);
    const limited=profilePreview({urls:sites(3),coverage:'standard',traffic:'normal',sharedLimits:{maxResources:250}});assert.equal(limited.profile.kind,'custom-profile');assert.equal(limited.config.maxResources,250);assert.equal(limited.estimate.total.requests,250);
    // Legacy presets are described and estimated, never re-mapped.
    const legacy=profilePreview({urls:[SITE],preset:'thorough',maxResources:600,originMaxResources:600});assert.deepEqual([legacy.profile.kind,legacy.profile.label,legacy.config.coverage,legacy.config.preset],['legacy-preset','Legacy preset: thorough',undefined,'thorough']);assert.deepEqual(legacy.examines,[]);assert.equal(legacy.slower,undefined);
    assert.deepEqual(trip.violations,[]);
  }finally{trip.restore();}
});
test('preview endpoint keeps the dashboard security model, validates input and refuses protected hosts; projects, queue jobs and routines carry their profile',{timeout:60000},async()=>{
  const dir=await temp(),app=await startDashboard({port:0,persistent:true,dataDir:dir,syntheticData:true});const trip=egressTripwire();
  try{
    const anon=await fetch(app.origin+'/api/profile/preview',{method:'POST',headers:{'Content-Type':'application/json',Origin:app.origin,'X-Dashboard-Request':'1'},body:JSON.stringify({config:{urls:[SITE]}})});assert.equal(anon.status,401,'sign-in required');
    const login=await fetch(app.origin+'/api/login',{method:'POST',headers:{'Content-Type':'application/json',Origin:app.origin,'X-Dashboard-Request':'1'},body:JSON.stringify({token:app.token})});const cookie=login.headers.get('set-cookie')!.split(';')[0],{csrf}=await login.json() as any;
    const headers={'Content-Type':'application/json',Origin:app.origin,'X-Dashboard-Request':'1','X-CSRF-Token':csrf,Cookie:cookie};
    const post=(route:string,data:unknown,h:Record<string,string>=headers)=>fetch(app.origin+route,{method:'POST',headers:h,body:JSON.stringify(data)});
    assert.equal((await post('/api/profile/preview',{config:{urls:[SITE]}},{...headers,'X-CSRF-Token':''})).status,403,'CSRF token required');
    assert.equal((await post('/api/profile/preview',{config:{urls:[SITE]}},{...headers,Origin:'https://attacker.example'})).status,403,'foreign Origin rejected');
    assert.equal((await post('/api/profile/preview',{config:{urls:[SITE]}},{...headers,'X-Dashboard-Request':''})).status,403,'dashboard request header required');
    assert.notEqual((await fetch(app.origin+'/api/profile/preview',{headers:{Cookie:cookie}})).status,200,'POST only');
    const ok=await post('/api/profile/preview',{config:{urls:[SITE],coverage:'quick',traffic:'low-impact'}});assert.equal(ok.status,200);assert.equal(ok.headers.get('cache-control'),'no-store');const p=await ok.json() as any;
    assert.equal(p.profile.label,'Quick check + Low-impact');assert.equal(p.counts.domainGroups,1);assert.deepEqual(p.counts.domains,['example.com']);assert.equal(p.websites.discoveredLimit,50);assert.match(p.slower,/will take longer/);assert.ok(p.examines.length>3);
    const bad=await post('/api/profile/preview',{config:{urls:[SITE],coverage:'everything'}});assert.equal(bad.status,400);assert.equal((await bad.json() as any).error,'Request rejected. Check input, scan state and local coverage; raw exception withheld.','raw exceptions stay withheld');
    const fixed=await post('/api/profile/preview',{config:{urls:[SITE],coverage:'deep',sizingMode:'fixed'}});assert.equal(fixed.status,400);
    const gov=await post('/api/profile/preview',{config:{urls:['https://www.whitehouse.gov/'],coverage:'quick',traffic:'normal'}});assert.equal(gov.status,400);assert.equal((await gov.json() as any).code,'protected-host');
    assert.equal(app.scans.size,0,'a preview starts nothing');
    // Saving full evidence needs an unlocked vault: the refusal names the fix instead of the withheld-exception text, and starts nothing.
    const locked=await post('/api/scans',{config:{urls:[SITE],coverage:'quick',traffic:'normal'},saveEvidence:true,authorized:true});assert.equal(locked.status,409);const refusal=await locked.json() as any;
    assert.equal(refusal.code,'vault-locked');assert.match(refusal.error,/^Unlock the vault before saving evidence/);assert.equal(app.scans.size,0,'a refused start starts nothing');
    // Saved projects carry their profile description; legacy projects stay legacy until the owner switches.
    const legacy=await(await post('/api/projects/save',{config:{name:'Legacy site',urls:['https://legacy.example.org/'],preset:'thorough'},authorized:true})).json() as any;
    const profiled=await(await post('/api/projects/save',{config:{name:'Profile site',urls:['https://profile.example.org/'],coverage:'standard',traffic:'low-impact'},authorized:true})).json() as any;
    let ws=await(await fetch(app.origin+'/api/workspace',{headers:{Cookie:cookie}})).json() as any;const byId=(id:string)=>ws.projects.find((x:any)=>x.id===id);
    assert.deepEqual([byId(legacy.id).profile.kind,byId(legacy.id).profile.label,byId(legacy.id).profile.equivalent],['legacy-preset','Legacy preset: thorough',{coverage:'deep',traffic:'normal',note:'single-website pacing'}]);assert.equal(byId(legacy.id).config.coverage,undefined);
    assert.equal(byId(profiled.id).profile.label,'Standard + Low-impact');
    // Queue jobs show the profile recorded when queued (the runs list carries it to the queue view).
    app.desk.queue.push({id:'job-1',projectId:profiled.id,state:'queued',saveEvidence:false,source:'operator',trigger:'queue',requestedAt:new Date().toISOString(),profile:{kind:'profile',label:'Standard + Low-impact',recorded:true}});
    const runs=await(await fetch(app.origin+'/api/runs',{headers:{Cookie:cookie}})).json() as any;assert.equal(runs.queue.find((j:any)=>j.jobId==='job-1').profile.label,'Standard + Low-impact');app.desk.queue.length=0;
    await assert.rejects(app.desk.enqueue([profiled.id],true),(e:any)=>e.code==='vault-locked','a queued run that saves evidence needs the vault too');assert.equal(app.desk.queue.length,0);
    // The explicit switch changes only that project and never rewrites history.
    const before=await readdir(dir);assert.equal((await post('/api/projects/profile',{id:legacy.id,authorized:true})).status,200);ws=await(await fetch(app.origin+'/api/workspace',{headers:{Cookie:cookie}})).json() as any;
    assert.equal(byId(legacy.id).profile.label,'Deep audit + Normal');assert.equal(byId(profiled.id).profile.label,'Standard + Low-impact');assert.deepEqual((await readdir(dir)).filter(f=>f.startsWith('scans')),before.filter(f=>f.startsWith('scans')));
    assert.deepEqual(trip.violations,[]);
  }finally{trip.restore();await app.close();await rm(dir,{recursive:true,force:true});}
});
test('report traffic line renders the connection accounting and says when an older build did not record it',()=>{
  const line=trafficText({accounting:{networkAttempts:9,blockedEvents:0,uniqueResources:9,repeatedRequests:0,downloadedBytes:1,retainedDecodedBytes:1,textAnalyzedBytes:1,intentionalSkips:0,httpErrors:0,coverageGaps:0,connectionsOpened:2,connectionsReused:7,connectionReplays:1,tlsHandshakes:2,browserCacheHits:3,requestsAvoided:4} as any,build:{version:'x'} as any});
  assert.equal(line,'2 connections opened, 7 kept-alive reuses (1 replayed after a server close), 2 TLS handshakes, 4 downloads served from this run’s cache instead of the network (3 for the isolated browser). Websites still saw every request that was sent.');
  assert.equal(trafficText({accounting:undefined,build:{version:'2.4.0'} as any}),'Connection accounting not recorded by build 2.4.0.');
  // A tampered history record cannot inject markup through the profile numbers of the HTML report.
  const evil='<img src=x>',p=profilePreview({urls:[SITE],coverage:'quick',traffic:'normal'}),sizing={explicitWebsites:evil,admittedWebsites:evil,discoveredLimit:evil,perWebsite:{pages:evil,resources:evil,bytes:1,decodedBytes:1,maps:1,browserPages:1,durationMs:1,requestsPerSecond:evil,concurrency:evil},total:{pages:evil,resources:evil,bytes:1,decodedBytes:1,maps:1,browserPages:evil,projectDurationMs:1,requestsPerSecond:evil,concurrency:evil},ceilings:{},cappedBy:[]};
  const view={schema:'exposure-scan/1',id:'ffffffff-0000-4000-8000-0000000000cc',name:'Tampered',state:'completed',startedAt:'2026-01-01T00:00:00.000Z',endedAt:'2026-01-01T00:01:00.000Z',elapsedMs:1,config:p.config,counts:{resources:0,scanned:0,blocked:0,bytes:0,pending:0,findings:0},engines:{websiteRules:'x',gitleaks:'x',ruleDigest:'x',companyRules:'none'},findings:[],resources:[],limitations:[],
    profile:{kind:'profile',label:'Quick check + Normal',coverage:'quick',traffic:'normal',trafficNote:'n',examines:[],skips:[],sizing,estimate:{...p.estimate,expectedMinutes:evil,total:{...p.estimate.total,requests:evil,connections:evil}},notExamined:[{category:'c',count:evil,examples:[]}]}} as any;
  const html=historyReport(view,'html');assert.ok(!html.includes(evil),'stored values are escaped');assert.ok(html.includes('&lt;img src=x&gt;'));
});
test('CLI help describes every coverage and traffic level, the legacy mapping and the honest Low-impact limits',()=>{
  const help=spawnSync(process.execPath,[path.join(root,'dist','src','cli.js'),'help'],{encoding:'utf8',windowsHide:true}).stdout;
  for(const text of ['Quick check: entry documents','Standard: static discovery to depth 3','Deep audit: full static discovery','Normal: the usual pacing','Low-impact: about 0.5 requests/s and one kept-alive connection per website','it does not hide the scan','there is no spoofing, evasion timing, proxy rotation or rate-limit bypass','thorough ~ Deep audit + Normal with single-website pacing','connection and byte upper bounds'])assert.ok(help.includes(text),text);
});
