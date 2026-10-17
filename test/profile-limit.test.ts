import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { Detector } from '../src/detectors.js';
import { Scanner } from '../src/scanner.js';
import { focusedRetry } from '../src/retry.js';
import { runSummary } from '../src/runs.js';
import { Store } from '../src/storage.js';
import { report, historyReport, profileLimitText, outcomeLabel, trafficText } from '../src/reports.js';
import { egressTripwire, virtualNetwork } from './virtual-network.js';
import type { ScanView } from '../src/types.js';
/** 2.6 owner decision (2026-10-09): Low-impact's one-query-variant rule is a stated boundary. Only-that-boundary runs are "Limited by profile" (completed, no retry offer); a real gap keeps the run incomplete and also mentions the limit; old records load as stored. Virtual network and synthetic data only. */
// The pinned detector and semantic analysis run, so the only unvisited work in a clean run is what the profile itself skips.
const detector=new Detector();await detector.init();
const SITE='https://example.com/',publicDns=async()=>[{address:'93.184.216.34',family:4}];
const links=(n:number)=>Array.from({length:n},(_,i)=>`<a href="/list?page=${i+1}">${i+1}</a>`).join('');
async function run(variants:number,traffic:'low-impact'|'normal',extra:Record<string,{body:string;type?:string;status?:number}>={},script='/app.js'){
  const hosts={'https://example.com':{'/':{body:links(variants)+`<script src="${script}"></script>`},'/list':{body:'list'},'/app.js':{type:'text/javascript',body:'void 0;'},'/app.js.map':{type:'application/json',body:JSON.stringify({version:3,sources:['a.ts'],sourcesContent:['void 0'],mappings:''})},...extra}};
  const s=new Scanner({urls:[SITE],coverage:'standard',traffic,browser:false},{detector,resolver:publicDns});
  try{const net=virtualNetwork(s,hosts);const v=await s.run();return {s,v,arrivals:net.arrivals.map(a=>a.url),html:report(s,'html'),json:JSON.parse(report(s,'json')),sarif:JSON.parse(report(s,'sarif'))};}finally{s.dispose();}
}

test('profile limit only: Standard + Low-impact skips the variants Normal would visit, completes as "Limited by profile" and offers no retry; the variants stay in the run data',{timeout:120000},async()=>{
  const trip=egressTripwire();try{
    const low=await run(3,'low-impact'),normal=await run(3,'normal');
    assert.ok(low.arrivals.includes('https://example.com/list?page=1')&&!low.arrivals.some(u=>/page=[23]$/.test(u)),'Low-impact requests one variant per path');
    assert.ok(['page=1','page=2','page=3'].every(q=>normal.arrivals.includes('https://example.com/list?'+q)),'Standard + Normal visits all three');
    assert.equal(low.v.state,'completed','the stated boundary is not an incomplete scan');assert.equal(low.v.coverage!.assessment,'configured-checks-completed');assert.equal(low.v.stage,'Completed — limited by profile');
    assert.equal(low.v.limitations.some(g=>g.code==='query-variants'),false);assert.equal(low.v.limitations.some(g=>g.incomplete),false);
    const gap=low.v.limitations.filter(g=>g.code==='profile-query-variants');assert.equal(gap.length,1,'one aggregated note');assert.equal(gap[0].incomplete,false);assert.equal(gap[0].count,2);assert.match(gap[0].detail,/^Limited by profile: Low-impact examines one query-string variant per path, so 2 other variants were not requested\. This is the option's stated boundary, not an error; Standard \+ Normal visits up to 3 variants per path\./);
    const p=low.v.profile!;assert.equal(p.completion,'profile-limited');assert.deepEqual([p.profileLimit!.rule,p.profileLimit!.count,p.profileLimit!.visitedBy],['query-variants',2,'Standard + Normal']);assert.deepEqual(p.profileLimit!.examples.sort(),['https://example.com/list?page=2','https://example.com/list?page=3']);
    const kept=low.v.uninspected!.filter(w=>w.deferredReason==='profile-limit').map(w=>w.url).sort();assert.deepEqual(kept,['https://example.com/list?page=2','https://example.com/list?page=3'],'kept for a higher-coverage scan (checkpoint frontier)');
    assert.equal(low.v.counts.deferred,0);assert.equal(low.v.coverage!.inventory.some(r=>/page=[23]$/.test(r.url)),false,'outside the examined set, like Quick not-examined');
    assert.deepEqual(focusedRetry(low.v).selected.filter(w=>/page=/.test(w.url)),[],'no retry offer for the boundary');assert.deepEqual(focusedRetry(low.v,true).selected.filter(w=>/page=/.test(w.url)),[]);
    assert.equal(runSummary({view:low.v}).profile.limitedByProfile,2);assert.equal(runSummary({view:normal.v}).profile.limitedByProfile,undefined);
    assert.equal(outcomeLabel(low.v),'Limited by profile');assert.equal(low.json.outcome,'Limited by profile');assert.equal(low.json.state,'completed');assert.equal(low.json.profile.completion,'profile-limited');assert.equal(low.json.profile.profileLimit.count,2);
    assert.match(low.html,/Scan completed — Limited by profile/);assert.match(low.html,/<strong>Limited by profile<\/strong>/);assert.match(trafficText(low.v),/kept-alive reuse.*Limited by profile: Low-impact examines one/);
    const inv=low.sarif.runs[0].invocations[0];assert.equal(inv.executionSuccessful,true);assert.equal(inv.properties.outcome,'Limited by profile');
    assert.equal(normal.v.state,'completed');assert.equal(normal.v.profile!.profileLimit,undefined);assert.equal(normal.v.profile!.completion,undefined);assert.equal(profileLimitText(normal.v),'');assert.equal(outcomeLabel(normal.v),'completed');
    assert.deepEqual(trip.violations,[],'nothing reached the real network');
  }finally{trip.restore();}
});

test('profile limit plus a real gap: the run stays incomplete with its retry offer and also mentions the profile limit; variants past the coverage limit stay a real gap',{timeout:240000},async()=>{
  const trip=egressTripwire();try{
    // Five variants: page=1 visited, page=2..3 skipped by Low-impact's boundary, page=4..5 beyond Standard's own three — the same real gap Normal has.
    const low=await run(5,'low-impact'),normal=await run(5,'normal');
    assert.equal(low.v.state,'incomplete');assert.equal(low.v.profile!.completion,undefined);assert.equal(low.v.profile!.profileLimit!.count,2);
    const real=low.v.limitations.filter(g=>g.code==='query-variants');assert.deepEqual(real.map(g=>g.url).sort(),['https://example.com/list?page=4','https://example.com/list?page=5']);assert.ok(real.every(g=>g.incomplete));
    assert.deepEqual(normal.v.limitations.filter(g=>g.code==='query-variants').map(g=>g.url).sort(),real.map(g=>g.url).sort(),'Low-impact reports the same real gap as Normal');
    const retry=focusedRetry(low.v,true).selected.map(w=>w.url);assert.ok(retry.includes('https://example.com/list?page=4')&&!retry.includes('https://example.com/list?page=2'),'retry covers the real gap only');
    assert.match(profileLimitText(low.v),/^Also limited by profile: Low-impact examines one query-string variant per path, so 2 other variants were not requested/);assert.equal(outcomeLabel(low.v),'incomplete');assert.equal(low.json.outcome,'incomplete');
    assert.match(low.html,/Scan incomplete · /);assert.match(low.html,/Also limited by profile/);assert.equal(low.sarif.runs[0].invocations[0].executionSuccessful,false);
    // A failed script (a real gap of another kind) with only the boundary otherwise: still incomplete, still mentions the limit.
    const broken=await run(2,'low-impact',{'/gone.js':{body:'missing',status:404}},'/gone.js');
    assert.equal(broken.v.state,'incomplete');assert.equal(broken.v.profile!.profileLimit!.count,1);assert.match(profileLimitText(broken.v),/^Also limited by profile: .*1 other variant was not requested/);assert.equal(runSummary({view:broken.v}).profile.limitedByProfile,1);
    assert.deepEqual(trip.violations,[],'nothing reached the real network');
  }finally{trip.restore();}
});

test('old records load tolerantly and are never rewritten: a stored Low-impact run with the earlier incomplete query-variant gap stays incomplete and retryable',async()=>{
  const dir=await mkdtemp(path.join(process.env.EXPOSURE_DATA_DIR||os.tmpdir(),'profile-limit-')),id='0b6d2f1e-5a7c-4e2b-9d3f-1a2b3c4d5e6f';
  // A P2/P3-era profile record: the same shape without the 2.6 owner-decision fields.
  const shaper=new Scanner({urls:[SITE],coverage:'standard',traffic:'low-impact'},{detector:new Detector('disabled'),resolver:publicDns}),earlier=shaper.profileView();shaper.dispose();assert.equal(earlier.profileLimit,undefined);
  try{
    await mkdir(path.join(dir,'scans'),{recursive:true});
    const view={schema:'exposure-scan/1',id,name:'example.com',state:'incomplete',startedAt:'2026-10-08T10:00:00.000Z',endedAt:'2026-10-08T10:01:00.000Z',elapsedMs:60000,build:{version:'2.5.0-rc.1',id:'2.5.0-rc.1+4cb78d03776101e3',sourceDigest:'x'},
      config:{urls:[SITE],relatedOrigins:[],coverage:'standard',traffic:'low-impact',queryVariants:1,maxResources:200},counts:{resources:3,scanned:3,blocked:0,bytes:10,pending:0,deferred:1,findings:0},engines:{websiteRules:'website/2.5.0',gitleaks:'8.30.1',ruleDigest:'x',companyRules:'none'},findings:[],
      resources:[{url:SITE,status:'scanned',code:200,bytes:5,chain:[],kind:'page',analysis:'analyzed'}],limitations:[{code:'query-variants',url:'https://example.com/list?page=2',detail:'Query variation limit reached: Low-impact examines one query-string variant per path. The other variants stay uninspected; a Normal-traffic focused retry can examine them.',incomplete:true}],
      uninspected:[{url:'https://example.com/list?page=2',depth:1,chain:[SITE],kind:'page',enqueuedAt:1,deferredReason:'query-variants'}],
      profile:earlier};
    const file=path.join(dir,'scans',id+'.json'),stored=JSON.stringify({schema:'exposure-history/2',projectId:'p',savedAt:'2026-10-08T10:01:00.000Z',view});await writeFile(file,stored);
    const store=await new Store(dir,true).init(),h=store.history.find(x=>x.view.id===id)!;
    assert.ok(h,'the old record loads');assert.equal(h.view.state,'incomplete','kept as stored, never re-judged');assert.equal(h.view.profile!.completion,undefined);assert.equal(h.view.profile!.profileLimit,undefined);
    assert.equal(profileLimitText(h.view),'');assert.equal(outcomeLabel(h.view),'incomplete');assert.equal(runSummary({view:h.view}).profile.limitedByProfile,undefined);
    assert.deepEqual(focusedRetry(h.view as ScanView,true).selected.map(w=>w.url),['https://example.com/list?page=2'],'its stored retry offer is unchanged');
    assert.equal(JSON.parse(historyReport(h.view,'json')).outcome,'incomplete');assert.doesNotMatch(historyReport(h.view,'html'),/Limited by profile/);
    assert.equal(await readFile(file,'utf8'),stored,'never rewritten');
  }finally{await rm(dir,{recursive:true,force:true});}
});
