import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {createHash} from 'node:crypto';
import {makeConfig} from '../src/config.js';
import {Scanner} from '../src/scanner.js';
import {Detector,AnalysisInterrupted,type AnalysisScope} from '../src/detectors.js';
import type {FifoBudget} from '../src/fifo-budget.js';
import {Evidence} from '../src/evidence.js';
import {Transport,type Resolver} from '../src/transport.js';
import {abortReason} from '../src/origin-control.js';
import {analyzeModules,SemanticPool} from '../src/semantic.js';
import {focusedRetry,resumeFrontier} from '../src/retry.js';
import {syntheticBundle} from './large-bundle.js';
import type {Resource} from '../src/types.js';
const key=(name:string)=>'sk-proj-'+createHash('sha512').update('unit-lifecycle-'+name).digest('base64url').slice(0,64).replace(/[-_]/g,'A');
const detector=()=>new Detector('disabled');
const publicDns:Resolver=async()=>[{address:'93.184.216.34',family:4}];
async function fixture(handler:http.RequestListener){const server=http.createServer(handler);await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));return {origin:`http://127.0.0.1:${(server.address() as any).port}`,close:()=>new Promise<void>(r=>{server.close(()=>r());server.closeAllConnections();})};}
test('re-admitting a module never resets its outcome; late aliases inherit it with replayed evidence; differing text gets a bounded variant key',async()=>{
  const value=key('alias'),text='const a='+JSON.stringify(value.slice(0,30))+';const b='+JSON.stringify(value.slice(30))+';const apiKey=a+b;',o='https://unit.invalid',s=new Scanner({urls:[o]},{detector:detector()});
  try{const record=(url:string):Resource=>{const r:Resource={url,status:'scanned',analysis:'analyzed',code:200,bytes:text.length,chain:[],kind:'script'};s.resources.push(r);return r;};
    const first=record(o+'/a.js');s.addModule(text,o+'/a.js');assert.equal(first.analyzers!.semantic!.status,'not-attempted');await (s as any).reconstruct(o);assert.equal(first.analyzers!.semantic!.status,'inspected');
    s.addModule(text,o+'/a.js');assert.equal(first.analyzers!.semantic!.status,'inspected','re-admission must not reset the outcome');
    const late=record(o+'/b.js');s.addModule(text,o+'/b.js');assert.equal(late.analyzers!.semantic!.status,'inspected');assert.equal(late.analyzers!.semantic!.reused,true);assert.ok(late.analyzers!.semantic!.reason!.includes(o+'/a.js'));
    const f=[...s.evidence.findings.values()].find(f=>s.evidence.reveal(f.id).value===value)!;assert.ok(f);assert.ok(f.occurrences.some(x=>x.url===o+'/b.js'),'a late alias gains an occurrence through replayed evidence');
    s.transport.onResource({url:o+'/a.js',status:'scanned',analysis:'analyzed',code:200,bytes:text.length,chain:[],kind:'browser'});assert.equal(s.resources.filter(r=>r.url===o+'/a.js').at(-1)!.analyzers!.semantic!.status,'inspected','records created after the outcome get it immediately');
    s.addModule('const other=2;',o+'/a.js');assert.ok(s.limitations.some(g=>g.code==='semantic-module-variant'));assert.equal(first.analyzers!.semantic!.status,'inspected');
    const bad=record(o+'/bad.js');s.addModule('const broken = { ;',o+'/bad.js');await (s as any).reconstruct(o);assert.equal(bad.analyzers!.semantic!.status,'failed');const badAlias=record(o+'/bad2.js');s.addModule('const broken = { ;',o+'/bad2.js');assert.equal(badAlias.analyzers!.semantic!.status,'failed');assert.equal(badAlias.analyzers!.semantic!.reused,true);
    assert.equal(s.limitations.filter(g=>g.code==='semantic-parser-failure').length,1);for(let i=0;i<5;i++){s.addModule('const ok'+i+'=1;',o+'/ok'+i+'.js');await (s as any).reconstruct(o);}assert.equal(s.limitations.filter(g=>g.code==='semantic-parser-failure').length,1,'a deterministic failure is never re-parsed');assert.ok(s.view().analysis!.origins[o].reusedVerdicts>=5);
  }finally{s.dispose();}
});
// External review F-02: an alias URL once returned before its new text was compared, so changed bytes at the alias were never inspected.
test('changed text at an alias URL is compared with its canonical module and analyzed as a bounded variant, never silently reused',async()=>{
  const split=(name:string)=>{const value=key(name);return {value,text:'const left='+JSON.stringify(value.slice(0,29))+';const right='+JSON.stringify(value.slice(29))+';const apiKey=left+right;'};};
  const a=split('alias-first'),b=split('alias-changed'),o='https://unit.invalid',s=new Scanner({urls:[o],adjacentMaps:false},{detector:detector()});
  try{const record=(url:string,text:string):Resource=>{const r:Resource={url,status:'scanned',analysis:'analyzed',code:200,bytes:Buffer.byteLength(text),chain:[],kind:'script'};s.resources.push(r);s.addModule(text,url);return r;};
    const found=(value:string)=>[...s.evidence.findings.values()].some(f=>s.evidence.reveal(f.id).value===value),variants=(incomplete:boolean)=>s.limitations.filter(g=>g.code==='semantic-module-variant'&&g.url===o+'/mirror.js'&&g.incomplete===incomplete).length;
    const first=record(o+'/bundle.js',a.text),mirror=record(o+'/mirror.js',a.text);await (s as any).reconstruct(o);assert.ok(found(a.value));assert.equal(mirror.analyzers!.semantic!.reused,true,'identical text is an alias');
    record(o+'/mirror.js',a.text);assert.equal(variants(false)+variants(true),0,'identical text at the alias stays a plain alias');
    record(o+'/mirror.js',b.text);await (s as any).reconstruct(o);assert.ok(found(b.value),'the changed text at the alias is reconstructed and inspected');
    assert.equal(variants(false),1);assert.equal(first.analyzers!.semantic!.status,'inspected');assert.equal(mirror.analyzers!.semantic!.status,'inspected','the alias keeps its first verdict; the variant has its own');
    for(let i=0;i<2;i++)record(o+'/mirror.js','const changed'+i+'='+i+';');assert.equal(variants(true),1,'variants stay bounded: a third differing text is an explicit incomplete gap');
  }finally{s.dispose();}
});
test('interruption causes are structured; analysis never inherits another origin\'s turn; typed detector failures keep their cause',async()=>{
  const t=new Transport(makeConfig({urls:['https://example.com']}),new Evidence(detector()),()=>{},()=>{},publicDns);t.cancel();assert.equal(t.abortCause(t.projectSignal)!.kind,'user-cancelled');
  const p=new Transport(makeConfig({urls:['https://example.com']}),new Evidence(detector()),()=>{},()=>{},publicDns);p.expire();assert.equal(p.abortCause(p.projectSignal)!.kind,'project-deadline');
  const o=new Transport(makeConfig({urls:['https://example.com']}),new Evidence(detector()),()=>{},()=>{},publicDns);o.originControl.get('https://example.com/');o.originControl.expire('https://example.com/');assert.deepEqual(abortReason(o.originControl.get('https://example.com/').controller.signal),{kind:'origin-deadline',origin:'https://example.com',turn:undefined});o.cancel();
  assert.equal(abortReason({aborted:true,reason:'work-turn-limit'} as any)!.kind,'work-turn-limit');assert.equal(abortReason({aborted:true,reason:'origin-duration-limit'} as any)!.kind,'origin-deadline');assert.equal(abortReason({aborted:false} as any),undefined);
  const s=new Scanner({urls:['https://a.example.com','https://b.example.com'],semanticAnalysis:false},{detector:detector(),resolver:publicDns});
  try{const stop=new AbortController();stop.abort({kind:'work-turn-limit',turn:'static'});const r={url:'https://b.example.com/x.js',status:200,headers:{'content-type':'text/javascript'},body:Buffer.from('const k=1;'),partial:false,chain:[]};
    const text=await s.transport.originControl.run('https://a.example.com/',()=>s.transport.analyze(r as any),stop.signal);assert.equal(text,'const k=1;','analysis of B runs although A\'s turn is aborted');
  }finally{s.dispose();}
  const failing=new Detector('deliberately-unavailable');failing.version='8.30.1';const gaps:any[]=[];const fs=new Scanner({urls:['https://c.example.com']},{detector:failing,resolver:publicDns});
  try{const r={url:'https://c.example.com/x.js',status:200,headers:{'content-type':'text/javascript'},body:Buffer.from('const k=1;'),partial:false,chain:[]};await fs.transport.analyze(r as any);const gap=fs.limitations.find(g=>g.code==='engine-inspection-failure')!;assert.ok(gap);assert.equal(gap.url,'https://c.example.com/x.js');assert.equal(gap.cause?.kind,'engine-exception');assert.ok(!fs.limitations.some(g=>g.code==='engine-cancelled'));}finally{fs.dispose();gaps.length=0;}
  // A cancelled or failing detector call inside preflight is never a network failure.
  class PreflightDetector extends Detector{override async inspect(text:string){if(text.includes('/throw'))throw new Error('synthetic');if(text.includes('/interrupt'))throw new AnalysisInterrupted({kind:'work-turn-limit',turn:'static'},'engine-queue');return this.inspectSync(text);}}
  const records:Resource[]=[],pgaps:any[]=[],pt=new Transport(makeConfig({urls:['https://example.com']}),new Evidence(new PreflightDetector('disabled')),r=>records.push(r),g=>pgaps.push(g),publicDns);
  await assert.rejects(pt.one('https://example.com/throw'),/preflight-failure/);await assert.rejects(pt.one('https://example.com/interrupt'),/work-turn-limit/);
  assert.ok(records.some(r=>r.url==='https://example.com/throw'&&r.status==='failed'&&r.reason==='preflight-failure'));assert.ok(records.some(r=>r.url==='https://example.com/interrupt'&&r.status==='failed'&&r.reason==='work-turn-limit'));assert.ok(pgaps.some(g=>g.code==='work-turn-limit'&&g.cause?.kind==='work-turn-limit'));assert.ok(!pgaps.some(g=>g.code==='network-failure'));pt.cancel();
});
test('a turn-only interruption after a successful download defers the body, resumes once and then ends in a terminal deferred state with its cause',async()=>{
  const value=key('deferred');let slowed=0,always=false;
  class SlowDetector extends Detector{override async inspect(text:string,scope?:AnalysisScope|FifoBudget){if(text.includes('SLOW_BODY')&&(always||slowed===0)){slowed++;const signal=this.signalOf(scope);await new Promise<void>((_,reject)=>{const stop=()=>reject(new AnalysisInterrupted(abortReason(signal),'engine-queue'));if(signal?.aborted)stop();else signal?.addEventListener('abort',stop,{once:true});});}return this.inspectSync(text);}}
  const f=await fixture((req,res)=>{if(req.url==='/'){res.setHeader('content-type','text/html');res.end('<html>SLOW_BODY<script src="/app.js"></script></html>');}else if(req.url==='/app.js'){res.setHeader('content-type','text/javascript');res.end('const apiKey="'+value+'";');}else{res.statusCode=404;res.end('missing');}});
  try{const s=new Scanner({urls:[f.origin],developmentFixtureOrigin:f.origin,requestsPerSecond:20,adjacentMaps:false,semanticAnalysis:false,analysisTurnMs:1000,maxDurationMs:20000},{detector:new SlowDetector('disabled')});const v=await s.run();
    assert.ok(v.findings.some(x=>s.evidence.reveal(x.id).value===value),'discovery continues after the resumed analysis');assert.equal(v.analysis!.backlog.resumed,1);assert.equal(v.analysis!.backlog.deferred,0);assert.ok((v.analysis!.interruptions['analysis-turn-limit']||0)>=1);
    assert.ok(!v.limitations.some(g=>g.code==='detector-analysis-failure'||g.code==='header-analysis-failure'));const page=v.resources.find(r=>r.url===f.origin+'/'&&r.kind==='page')!;assert.equal(page.analysis,'analyzed');assert.equal(page.status,'scanned');assert.equal(page.timings?.interruption,'analysis-turn-limit');assert.ok(!v.limitations.some(g=>g.code==='analysis-interrupted'&&g.incomplete));s.dispose();
    always=true;slowed=0;const again=new Scanner({urls:[f.origin],developmentFixtureOrigin:f.origin,requestsPerSecond:20,adjacentMaps:false,semanticAnalysis:false,analysisTurnMs:1000,maxDurationMs:20000},{detector:new SlowDetector('disabled')});const w=await again.run();
    const deferred=w.resources.find(r=>r.url===f.origin+'/'&&r.kind==='page')!;assert.equal(deferred.analysis,'deferred');assert.equal(deferred.reason,'analysis-interrupted');const gap=w.limitations.find(g=>g.code==='analysis-interrupted')!;assert.ok(gap);assert.equal(gap.cause?.kind,'analysis-turn-limit');assert.equal(gap.url,f.origin+'/');assert.ok(gap.attemptId);assert.equal(gap.incomplete,true);
    assert.equal(w.analysis!.backlog.resumed,1);assert.equal(w.analysis!.backlog.deferred,1);assert.ok(!w.limitations.some(g=>g.code==='detector-analysis-failure'));assert.equal(w.coverage!.inventory.find(r=>r.url===f.origin+'/')!.state,'deferred');assert.ok(w.limitations.some(g=>g.code==='analysis-unfinished'&&g.origin===f.origin));assert.equal(w.state,'incomplete');assert.ok(!w.limitations.some(g=>g.code==='lifecycle-inconsistency'));again.dispose();
  }finally{await f.close();}
});
test('cancellation and origin deadlines leave explicit terminal states with consistent counts',async()=>{
  const f=await fixture((req,res)=>{if(req.url==='/'){res.setHeader('content-type','text/html');res.end('<html>'+Array.from({length:6},(_,i)=>'<script src="/s'+i+'.js"></script>').join('')+'<script src="/slow.js"></script></html>');}else if(req.url==='/slow.js'){const t=setTimeout(()=>{res.setHeader('content-type','text/javascript');res.end('const slow=1;');},2500);res.once('close',()=>clearTimeout(t));}else if(req.url?.endsWith('.js')){res.setHeader('content-type','text/javascript');res.end('export const v'+req.url.length+'='+JSON.stringify(req.url)+';');}else{res.statusCode=404;res.end('missing');}});
  const check=(v:import('../src/types.js').ScanView)=>{assert.equal(v.counts.pending,0,'no live work after the run');assert.ok(!v.coverage!.inventory.some(r=>r.state==='pending'),'no pending inventory rows');assert.ok(!v.resources.some(r=>Object.entries(r.analyzers||{}).some(([n,a])=>n!=='debugger'&&a?.status==='not-attempted')),'no not-attempted analyzers');assert.ok(!v.limitations.some(g=>g.code==='lifecycle-inconsistency'));assert.equal(typeof v.counts.deferred,'number');assert.notEqual(v.coverage!.assessment,'configured-checks-completed');const unresolved=v.coverage!.inventory.filter(r=>['javascript','jsonConfig','sourceMaps','runtimeCaptures','browserRuntime','entryDocuments'].includes(r.category)&&['pending','deferred','partial','failed'].includes(r.state)).length;assert.equal(v.websites!.importantUninspected,unresolved,'one definition of important unresolved work');};
  try{const s=new Scanner({urls:[f.origin],developmentFixtureOrigin:f.origin,requestsPerSecond:20,adjacentMaps:false,maxDurationMs:20000,timeoutMs:5000},{detector:detector()});const job=s.run();setTimeout(()=>s.cancel(),500);const v=await job;
    assert.equal(v.state,'cancelled');check(v);assert.ok(v.limitations.some(g=>g.code==='cancelled'&&g.cause?.kind==='user-cancelled'));assert.ok(v.resources.some(r=>r.analysis==='deferred'||r.reason==='cancelled'),'interrupted work is recorded');s.dispose();
    const d=new Scanner({urls:[f.origin],developmentFixtureOrigin:f.origin,requestsPerSecond:20,adjacentMaps:false,originMaxDurationMs:700,maxDurationMs:10000,timeoutMs:5000,maxRetries:0},{detector:detector()});const w=await d.run();
    assert.equal(w.state,'incomplete');check(w);const semantic=w.resources.filter(r=>r.analyzers?.semantic).map(r=>r.analyzers!.semantic!);assert.ok(semantic.length>0);assert.ok(semantic.every(a=>['inspected','incomplete','deferred','failed','unsupported'].includes(a.status)));for(const a of semantic.filter(a=>a.status==='deferred'))assert.ok(['origin-deadline','analysis-allocation-exhausted','run-ended-before-analysis','project-deadline'].includes(a.cause?.kind||''),JSON.stringify(a));
    if(semantic.some(a=>a.status==='deferred'))assert.ok(w.limitations.some(g=>g.code==='analysis-unfinished'&&g.origin===f.origin));d.dispose();
  }finally{await f.close();}
});
test('a 1,252,570-byte synthetic bundle is discovered past the 1 MiB mark, reconstructed from constants near the end, and bare literals inside it are never fetched',async()=>{
  const bundle=syntheticBundle();assert.equal(bundle.bytes,1252570);const arrivals:string[]=[];
  const f=await fixture((req,res)=>{arrivals.push(req.url!);if(req.url==='/'){res.setHeader('content-type','text/html');res.end('<html><script type="module" src="/bundle.js"></script></html>');}else if(req.url==='/bundle.js'){res.setHeader('content-type','text/javascript');res.end(bundle.text);}else if(req.url===bundle.lateChunk.replace('./','/')){res.setHeader('content-type','text/javascript');res.end('export const late=1;');}else if(req.url==='/tail.js'){res.setHeader('content-type','text/javascript');res.end('self.onmessage=null;');}else if(req.url==='/bundle.js.map'){res.setHeader('content-type','application/json');res.end(JSON.stringify({version:3,sources:[],mappings:''}));}else{res.statusCode=404;res.end('missing');}});
  try{const s=new Scanner({urls:[f.origin],developmentFixtureOrigin:f.origin,requestsPerSecond:20,adjacentMaps:false,originAnalysisMs:30000,semanticSliceMs:10000,maxDurationMs:90000,timeoutMs:10000},{detector:detector()});const started=Date.now(),v=await s.run();
    const found=[...s.evidence.findings.values()].find(x=>s.evidence.reveal(x.id).value===bundle.value);assert.ok(found,'the split key near the end is reconstructed');const occurrence=found!.occurrences.find(o=>o.exposure==='static-reconstruction')!;assert.ok(occurrence);assert.ok(occurrence.constituents!.length>=3);assert.ok(occurrence.constituents!.every(c=>c.start>1024*1024),'constituents sit past the 1 MiB mark');
    assert.ok(![...s.evidence.findings.values()].some(x=>s.evidence.reveal(x.id).value===bundle.mutated),'a binding mutated in a nested function is never completed');assert.ok(![...s.evidence.findings.values()].some(x=>s.evidence.reveal(x.id).value.includes('your_api_key_here')),'placeholder splits produce no finding');
    assert.ok(arrivals.includes(bundle.lateChunk.replace('./','/')),'the late dynamic import past 1 MiB is discovered');assert.ok(arrivals.includes('/tail.js'),'the worker URL past 1 MiB is discovered');assert.ok(arrivals.includes('/bundle.js.map'),'the trailing source-map comment is discovered');assert.ok(!arrivals.some(u=>/\/\.(?:json|woff|css)$/.test(u)),'bare extension literals never become requests');
    const resource=v.resources.find(r=>r.url===f.origin+'/bundle.js')!;assert.equal(resource.analyzers!.semantic!.status,'inspected');const row=v.coverage!.inventory.find(r=>r.url===f.origin+'/bundle.js')!;assert.ok(['inspected','unsupported'].includes(row.state),'the bundle row is resolved (unsupported only because the offline engine is disabled in this fixture): '+row.state+' '+row.reason);assert.ok(!v.limitations.some(g=>g.code==='discovery-document-limit'));assert.ok(v.discovery!.rejected.bareExtension>=1);assert.ok(v.discovery!.rejected.nonUrlContext>=1);assert.equal(v.discovery!.syntax.module>=1,true);
    const a=v.analysis!.origins[f.origin];assert.ok(a.jobs>=1);assert.ok(a.chargedMs>=a.workerMs);assert.ok(a.startupMs>=0);console.log(JSON.stringify({largeBundle:{bytes:bundle.bytes,elapsedMs:Date.now()-started,analysis:a,semantic:v.semantic,discovery:v.discovery}}));s.dispose();
  }finally{await f.close();}
});
test('worker pool accounting adds up and the one-shot wrapper keeps its API; memory ceilings stay explicit',async()=>{
  const o='https://unit.invalid',s=new Scanner({urls:[o],analysisConcurrency:2},{detector:detector()});
  try{for(let i=0;i<30;i++)s.addModule('const v'+i+'="value'+i+'";','https://unit.invalid/m'+i+'.js');await (s as any).reconstruct(o);const a=s.view().analysis!.origins[o];assert.ok(a.jobs>=1);assert.ok(a.chargedMs>=a.workerMs);assert.ok(a.startupMs>=0&&a.cleanupMs>=0);assert.ok(s.pool.spawns<=2+s.pool.respawns);assert.ok(s.view().websites!.analysisMsMeaning!.includes('elapsed'));}finally{s.dispose();}
  const pool=new SemanticPool(1,64);try{const r=await pool.run([{url:'https://unit.invalid/huge.js',text:'x'.repeat(2*1024*1024)}],undefined,2500,{memoryMb:64,maxMemoryMb:64});assert.ok(r.gaps.some(g=>g.code==='semantic-memory-ceiling'));assert.equal(r.resources![0].status,'incomplete');assert.equal(r.resources![0].deterministic,true);}finally{await pool.dispose();}
  const one=await analyzeModules([{url:'https://unit.invalid/a.js',text:'const a="sk-proj-";'}]);assert.equal(one.resources![0].status,'inspected');assert.ok(typeof one.stats.workerMs==='number');assert.ok(typeof one.stats.chargedMs==='number');
});
test('the analysis allocation of a website is charged from its parser worker on: waiting for a free worker or for analysis memory is queue wait, never allocation',async()=>{
  const o='https://unit.invalid',s=new Scanner({urls:[o],analysisConcurrency:1,originAnalysisMs:1500},{detector:detector()});
  try{await s.resolveTimeFactor();for(const n of ['a','b'])s.addModule('const '+n+'="value-'+n+'";','https://unit.invalid/'+n+'.js');
    // Another analysis heap holds all of the scan's analysis memory for longer than the whole allocation, as a detector's large-text inspection can on a slow computer.
    // Both independent groups are still parsed: the wait is reported as queue wait, and only worker startup, parsing and cleanup are charged.
    const allocation=s.transport.originControl.get(o).budget.effective.analysisMs,held=s.analysisMemory.capacity;await s.analysisMemory.acquire(held);
    const released=new Promise<void>(resolve=>setTimeout(()=>{s.analysisMemory.release(held);resolve();},allocation+500));
    await (s as any).reconstruct(o);await released;const v=s.view(),a=v.analysis!.origins[o];
    assert.equal(a.jobs,2);assert.equal(a.outcomes.inspected,2,'both dependency groups parsed');assert.ok(!v.limitations.some(g=>g.code==='semantic-website-budget'),'allocation not exhausted by the wait');
    assert.ok(a.queueWaitMs>=allocation,'the memory wait is reported as queue wait');assert.ok(a.chargedMs<allocation,'the wait is not charged');assert.ok(a.chargedMs>=a.workerMs);
    assert.match(v.analysis!.note,/queueWaitMs[^.]*analysis memory/);}finally{s.dispose();}
});
test('focused retry selects deferred or partial analyzers and skips bare hints; checkpoints keep deferred bodies as frontier',()=>{
  const o='https://unit.invalid',s=new Scanner({urls:[o]},{detector:detector()});
  try{const view=s.view();view.state='incomplete';view.resources=[{url:o+'/deferred.js',kind:'script',status:'scanned',analysis:'analyzed',code:200,bytes:1,chain:[],analyzers:{semantic:{status:'deferred',reason:'Run ended before analysis'}}},{url:o+'/partial.js',kind:'script',status:'scanned',analysis:'analyzed',code:200,bytes:1,chain:[],analyzers:{semantic:{status:'incomplete',reason:'Mutation safety ceiling'}}},{url:o+'/done.js',kind:'script',status:'scanned',analysis:'analyzed',code:200,bytes:1,chain:[],analyzers:{semantic:{status:'inspected'}}},{url:o+'/body.html',kind:'page',status:'downloaded',analysis:'deferred',code:200,bytes:1,chain:[]}];view.uninspected=[{url:o+'/.json',kind:'asset-hint',depth:0,chain:[]},{url:o+'/.woff',kind:'asset',depth:0,chain:[]}];
    const plan=focusedRetry(view,true);assert.deepEqual(plan.selected.map(w=>w.url).sort(),[o+'/body.html',o+'/deferred.js',o+'/partial.js']);assert.deepEqual(plan.excluded,[o+'/done.js']);
    s.deferAnalysis({url:o+'/late.js',depth:0,chain:[],kind:'script'},{url:o+'/late.js',status:200,headers:{},body:Buffer.from('x'),partial:false,chain:[]},{kind:'analysis-turn-limit'});assert.ok(s.checkpoint().frontier.some((w:any)=>w.url===o+'/late.js'&&w.deferredReason==='analysis-deferred'));
    assert.deepEqual(resumeFrontier([{url:o+'/a.js'},{url:o+'/.json',kind:'asset-hint'},{url:o+'/p',kind:'page'},{url:o+'/x',kind:'not-a-kind'}],10),[{url:o+'/a.js',kind:'asset'},{url:o+'/p',kind:'page'},{url:o+'/x',kind:'asset'}]);
  }finally{s.dispose();}
});
test('above maxDiscoveryBytes the windowed tokenizer yields only heuristic hints: the cap gap is recorded, bare literals are rejected and no windowed output is admitted as a module',async()=>{
  const o='https://unit.invalid',url=o+'/huge.js',filler=Array.from({length:6000},(_,i)=>`function f${i}(){return "${'x'.repeat(30)}${i}";}`).join('\n');
  const text=filler+'\nfetch("/api/beyond-cap.json").catch(()=>{});const ext=".json";const font=".woff";\n//# sourceMappingURL=huge.js.map\n';assert.ok(text.length>256*1024);
  const s=new Scanner({urls:[o],maxDiscoveryBytes:256*1024,adjacentMaps:false},{detector:detector()});
  try{await s.discover(text,url,1,[o+'/'],'script',{'content-type':'text/javascript'});const v=s.view();
    assert.equal(v.discovery!.windowed,1);assert.ok(v.limitations.some(g=>g.code==='discovery-document-limit'&&g.url===url&&g.incomplete),'the cap is an incomplete gap on the document');
    const beyond=s.queue.find(w=>w.url===o+'/api/beyond-cap.json');assert.ok(beyond,'a literal beyond the cap is still a hint');assert.equal(beyond!.certainty,'heuristic');assert.match(beyond!.context||'',/windowed/);
    assert.ok(s.queue.every(w=>w.certainty!=='confirmed'||w.kind==='map'),'no sink beyond the cap is confirmed; only the trailing source-map comment is');assert.ok(s.queue.some(w=>w.url===o+'/huge.js.map'&&w.kind==='map'));
    assert.ok(v.discovery!.rejected.bareExtension>=2);assert.ok(!s.queue.some(w=>/\/\.(?:json|woff)$/.test(w.url)),'bare extension literals never become URLs');
    assert.deepEqual([...(s as any).modules.keys()],[url],'only the script itself is a module; windowed output never reaches addModule');
  }finally{s.dispose();}
});
