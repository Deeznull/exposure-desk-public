import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {mkdtemp,rm,readFile,writeFile} from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {createHash} from 'node:crypto';
import {EventEmitter} from 'node:events';
import {attachDebuggerTargets} from '../src/browser-debugger.js';
import {makeConfig,resolveScanConfig} from '../src/config.js';
import {WebsiteBudget} from '../src/adaptive-budget.js';
import {analyzeModules,moduleGroups} from '../src/semantic.js';
import {Scanner} from '../src/scanner.js';
import {Detector} from '../src/detectors.js';
import {Evidence} from '../src/evidence.js';
import {Store} from '../src/storage.js';
import {report} from '../src/reports.js';
import {exposureChecks} from '../src/exposure-checks.js';
import {scanArtifacts} from '../src/artifact-scan.js';
const key=(name:string)=>'sk-proj-'+createHash('sha512').update('unit-completeness-'+name).digest('base64url').slice(0,64);
const detector=()=>new Detector('disabled');

test('cancellation settles a debugger command when a dead target never replies',async()=>{
 const root=new EventEmitter() as any,stop=new AbortController();let captured:any;
 root.send=async(method:string)=>method==='Target.getTargetInfo'?{targetInfo:{targetId:'isolated-page',browserContextId:'fresh-context'}}:method==='Debugger.getScriptSource'?new Promise(()=>{}):{};
 root.detach=async()=>{};
 const targets=await attachDebuggerTargets({newCDPSession:async()=>root} as any,{url:()=> 'https://fixture.invalid/'} as any,channel=>{captured=channel;},()=>{},()=>{},stop.signal);
 root.emit('Debugger.scriptParsed',{scriptId:'late-script',executionContextId:1});assert.ok(captured);
 const pending=captured.send('Debugger.getScriptSource',{scriptId:'late-script'}),began=performance.now();stop.abort();
 await assert.rejects(pending,/cancelled/);assert.ok(performance.now()-began<1000);
 captured=undefined;root.emit('Debugger.scriptParsed',{scriptId:'after-stop',executionContextId:1});assert.equal(captured,undefined);
 await targets.close();
});
test('adaptive mode keeps explicit hard caps and old website-count settings compatible',()=>{
 const base={urls:['https://one.invalid','https://two.invalid'],maxDurationMs:1000,maxResources:40,maxTotalBytes:8192};const adaptive=resolveScanConfig({...base,sizingMode:'adaptive'});
 assert.equal(adaptive.maxResources,40);assert.equal(adaptive.maxTotalBytes,8192);assert.equal(adaptive.projectMaxDurationMs,1000);
 assert.equal(resolveScanConfig({...base,autoScaleByWebsiteCount:true}).maxResources,80);
 assert.throws(()=>makeConfig({...base,sizingMode:'magic' as any}));assert.throws(()=>makeConfig({...base,maxAnalysisMemoryMb:64,analysisConcurrency:2}));
 assert.throws(()=>makeConfig({...base,sensitiveFields:[{path:'x',expectation:'private'},{path:'x',expectation:'public'}]}));
 const hash=makeConfig({...base,browserNavigationUrls:['https://one.invalid/#/settings']});assert.ok(hash.browserNavigationUrls![0].endsWith('#/settings'));assert.throws(()=>makeConfig({...base,browserNavigationUrls:['https://outside.invalid/app']}));
});
test('website allocations grow independently from actual demand and explain pending important assets',()=>{
 const config=makeConfig({urls:['https://one.invalid','https://two.invalid'],sizingMode:'adaptive',originMaxResources:100,originMaxMaps:8,originAnalysisMs:6000});const a=new WebsiteBudget(config.urls[0],config),b=new WebsiteBudget(config.urls[1],config);
 for(let i=0;i<20;i++)a.discover({url:config.urls[0]+'/a'+i+'.js',kind:'script',depth:0,chain:[]});a.response({url:config.urls[0]+'/bundle.js',kind:'script',resourceType:'javascript',bytes:4*1024*1024,status:'downloaded',chain:[],timings:{headersMs:1200}});a.pending(20);
 assert.ok(a.effective.resources>b.effective.resources);assert.ok(a.effective.analysisMs>b.effective.analysisMs);assert.ok(a.effective.resources<=100);assert.ok(a.effective.analysisMs<=6000);assert.ok(a.reasons.some(r=>r.includes('bundle bytes')));assert.ok(a.reasons.some(r=>r.startsWith('Slow responses')));
 assert.equal(a.snapshot([{url:config.urls[0]+'/pending.js',kind:'module',depth:0,chain:[],deferredReason:'hard-cap'}]).importantUninspected[0].reason,'hard-cap');
});
test('dependency grouping preserves re-exports, isolates unrelated vendor pressure and keeps computed-key evidence',async()=>{
 const value=key('group'),origin='https://unit.invalid/',sources=[{url:origin+'parts.js',text:'export const p="sk-proj-";export const tail='+JSON.stringify(value.slice(8))+';'},{url:origin+'main.js',text:'import {p,tail} from "./parts.js";const config={["api"+"Key"]:p+tail};'},{url:origin+'vendor.js',text:'const huge=['+'1,'.repeat(18000)+'1];'}];
 const groups=moduleGroups(sources);assert.equal(groups.length,2);assert.ok(groups.some(g=>g.length===2));
 const r=await analyzeModules(groups.find(g=>g.length===2)!);const view=r.views.find(v=>v.text.includes(value))!;assert.ok(view);assert.ok(view.constituents.some(p=>p.url.endsWith('parts.js')));assert.ok(view.constituents.some(p=>p.representation==='"api"'));assert.ok(view.steps.includes('Constant concatenation'));
});
for(const extension of ['ts','tsx'])test('static '+extension+' syntax preserves original positions without executing application functions',async()=>{
 const value=key(extension),text='// é\nconst prefix: string = "sk-proj-";\nconst suffix: string = '+JSON.stringify(value.slice(8))+';\nconst config = {apiKey: prefix+suffix} as const;\n'+(extension==='tsx'?'export default function App(){return <div>{unknown()}</div>;}':'function unknown(){throw new Error("must never execute");}');
 const r=await analyzeModules([{url:'https://unit.invalid/app.'+extension,text}]);assert.ok(!r.gaps.some(g=>g.code==='semantic-parser-failure'));
 const view=r.views.find(v=>v.text.includes(value))!;assert.ok(view);for(const p of view.constituents){assert.equal(text.slice(p.start,p.end),p.representation);assert.equal(p.line,text.slice(0,p.start).split('\n').length);}assert.ok(view.steps.some(s=>s.includes('TypeScript/JSX')));
});
test('SDK import aliases preserve provider context and unknown expressions stay unknown',async()=>{
 const token='sanitized-unit-auth-material',text='import Client from "openai";const Alias=Client;const value="sanitized-unit-"+"auth-material";new Alias({["api"+"Key"]:value});const missing=value+runtimeUnknown();';
 const r=await analyzeModules([{url:'https://unit.invalid/sdk.js',text}]);assert.ok(r.views.some(v=>v.text.startsWith('OpenAI(')&&detector().inspectSync(v.text).some(c=>c.value===token&&c.provider==='OpenAI')));assert.ok(!r.views.some(v=>v.original.includes('runtimeUnknown')));
});
test('large complete module tails are reconstructed within configured admission bounds',async()=>{
 const value=key('tail'),s=new Scanner({urls:['https://unit.invalid']},{detector:detector()}),text='/*'+'ordinary '.repeat(130000)+'*/const prefix="sk-proj-";const apiKey=prefix+'+JSON.stringify(value.slice(8))+';';
 try{s.addModule(text,'https://unit.invalid/large.js');await (s as any).reconstruct('https://unit.invalid');assert.ok([...s.evidence.findings.values()].some(f=>s.evidence.reveal(f.id).value===value));assert.ok(!s.limitations.some(g=>g.code==='semantic-source-limit'));}finally{s.dispose();}
 const limited=new Scanner({urls:['https://unit.invalid'],maxModuleAnalysisBytes:1024},{detector:detector()});try{limited.addModule(text,'https://unit.invalid/large.js');assert.ok(limited.limitations.some(g=>g.code==='semantic-source-limit'));}finally{limited.dispose();}
});
test('virtual source-map TypeScript imports reconstruct split values with exact labeled constituents',async()=>{
 const value=key('map'),s=new Scanner({urls:['https://unit.invalid']},{detector:detector()});try{await s.map(JSON.stringify({version:3,sources:['webpack:///src/parts.ts','webpack:///src/main.tsx'],sourcesContent:['export const prefix: string="sk-proj-";','import {prefix} from "./parts.ts";const apiKey=prefix+'+JSON.stringify(value.slice(8))+';'],mappings:''}),'https://unit.invalid/app.js.map',[]);await (s as any).reconstruct('https://unit.invalid');const f=[...s.evidence.findings.values()].find(f=>s.evidence.reveal(f.id).value===value)!;assert.ok(f);assert.ok(f.occurrences[0].constituents!.some(p=>p.label==='webpack:///src/parts.ts'));assert.ok(f.occurrences[0].constituents!.some(p=>p.label==='webpack:///src/main.tsx'));}finally{s.dispose();}
});
test('dismissed observations retain a masked audit and stronger evidence can re-enter review',async()=>{
 const e=new Evidence(detector());e.startTriage(()=>{});try{await e.inspect('const publishableKey="pk_live_A4b9C8d7E6f5G4h3I2j1K0l9";','https://unit.invalid',[],'Public response');await e.triage!.flush();assert.equal(e.findings.size,0);assert.equal(e.dismissedView().length,1);assert.ok(!JSON.stringify(e.dismissedView()).includes('pk_live_'));assert.ok(e.dismissedView()[0].triage!.reason.includes('Public'));assert.equal(Object.keys(e.full()).length,0);}finally{e.clear();}
});
test('structural data checks distinguish password hashes, owner expectations, configuration and ordinary hashes',async()=>{
 const hash='$2b$12$'+'a'.repeat(53),text=JSON.stringify({user:{password_hash:hash,internalNumber:'UNIT-548'},integrity:'a'.repeat(64)}),s=new Scanner({urls:['https://unit.invalid'],sensitiveFields:[{path:'user.internalNumber',expectation:'private'}]},{detector:detector()});
 try{await s.evidence.inspect(text,'https://unit.invalid/api',[],'Public response');await s.evidence.triage!.flush();assert.ok([...s.evidence.findings.values()].some(f=>f.exposureKind==='password-hash'));for(const format of ['json','html','sarif'] as const){const output=report(s,format);assert.ok(!output.includes(hash));assert.ok(!output.includes('UNIT-548'));assert.ok(output.includes('unverified'));}assert.equal(exposureChecks(text,[{path:'user.password_hash',expectation:'public'}]).candidates.length,0);assert.equal(exposureChecks(JSON.stringify({hash:'abc'.repeat(30),password:'placeholder'})).candidates.length,0);}finally{s.dispose();}
});
test('project feedback persists across restart, stays scoped, expires and reverses suppression',async()=>{
 const dir=await mkdtemp(path.join(os.tmpdir(),'exposure-feedback-'));let store=await new Store(dir,true).init();try{const project=await store.project({urls:['https://unit.invalid']},true),other=await store.project({urls:['https://other.invalid']},true),value=key('feedback'),e=new Evidence(detector(),await store.key(project.id));const id=e.add(detector().inspectSync(value)[0],value,'https://unit.invalid',[],'Public response'),f=e.findings.get(id)!;
 await store.feedback(project.id,f,'false-positive','Synthetic reviewed fixture',new Date(Date.now()+60000).toISOString());assert.equal(f.feedback!.decision,'false-positive');assert.ok(f.suppression);store.close();store=await new Store(dir,true).init();delete f.feedback;delete f.suppression;store.applyReviews(project.id,[f]);assert.equal(f.feedback!.decision,'false-positive');const independent={...f,suppression:undefined,feedback:undefined};store.applyReviews(other.id,[independent]);assert.equal(independent.feedback,undefined);await store.feedback(project.id,f,'confirmed','Owner confirmed publication');assert.equal(f.suppression,undefined);await store.feedback(project.id,f,'unreviewed','');assert.equal(f.feedback!.decision,'unreviewed');assert.ok(!(await readFile(path.join(dir,'workspace.json'),'utf8')).includes(value));e.clear();}finally{store.close();await rm(dir,{recursive:true,force:true});}
});
test('multi-website adaptive scans enforce shared and independent request caps while checkpointing important gaps',async()=>{
 const servers:http.Server[]=[],origins:string[]=[];for(let site=0;site<2;site++){const server=http.createServer((req,res)=>{res.setHeader('Content-Type',req.url==='/'?'text/html':'text/javascript');res.end(req.url==='/'?Array.from({length:8},(_,i)=>'<script src="/a'+i+'.js"></script>').join(''):'void 0;');});await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));servers.push(server);origins.push('http://127.0.0.1:'+(server.address() as any).port);}
 const s=new Scanner({urls:origins,privateOrigins:origins,sizingMode:'adaptive',originMaxResources:6,maxResources:12,requestsPerSecond:20,originRequestsPerSecond:20,maxDurationMs:10000,browser:false,adjacentMaps:false,semanticAnalysis:false,maxRetries:0},{detector:detector()});try{const v=await s.run();assert.ok(v.origins!.every(o=>o.requests<=6));assert.ok(s.transport.requests<=12);assert.equal(v.websites!.count,2);assert.ok(v.websites!.importantUninspected>0);assert.equal((s.checkpoint() as any).config.sizingMode,'adaptive');}finally{s.dispose();for(const server of servers)await new Promise<void>(r=>{server.close(()=>r());server.closeAllConnections();});}
});

test('literal password hashes and plaintext internal stacks remain masked in every routine report',async()=>{
 const hash='$2b$12$'+'b'.repeat(53),stack='Error: synthetic failure\n    at handler (/srv/unit/server.js:19:7)',s=new Scanner({urls:['https://unit.invalid']},{detector:detector()});
 try{await s.evidence.inspect('const password_hash='+JSON.stringify(hash)+';','https://unit.invalid/config.js',[],'Public response');await s.evidence.inspect(stack,'https://unit.invalid/error.log',[],'Public response');await s.evidence.triage!.flush();assert.ok([...s.evidence.findings.values()].some(f=>f.exposureKind==='password-hash'));assert.ok([...s.evidence.findings.values()].some(f=>f.exposureKind==='debug-output'));for(const format of ['json','html','sarif'] as const){const output=report(s,format);assert.ok(!output.includes(hash));assert.ok(!output.includes('/srv/unit/server.js'));}}finally{s.dispose();}
});

test('local artifact TypeScript and JSX imports retain evidence without acquiring any website',async()=>{
 const dir=await mkdtemp(path.join(os.tmpdir(),'exposure-local-complete-')),value=key('local-tsx');let scan:Scanner|undefined;
 try{await writeFile(path.join(dir,'parts.ts'),'export const prefix: string="sk-proj-";');await writeFile(path.join(dir,'app.tsx'),'import {prefix} from "./parts.ts";const apiKey=prefix+'+JSON.stringify(value.slice(8))+';export default function App(){return <div/>;}');scan=await scanArtifacts(dir,{detector:detector()});const f=[...scan.evidence.findings.values()].find(f=>scan!.evidence.reveal(f.id).value===value);assert.ok(f);assert.ok(f.occurrences.some(o=>o.constituents?.some(c=>c.url.endsWith('/parts.ts'))));assert.ok(f.occurrences.every(o=>o.exposure==='local-only'));assert.equal(scan.transport.requests,0);}finally{scan?.dispose();await rm(dir,{recursive:true,force:true});}
});

test('short sensitive values cannot corrupt configuration enums or leak through arbitrary object keys',()=>{
 const e=new Evidence(detector());try{e.add({value:'private',original:'private',index:0,provider:'Website',rule:'unit-short',category:'suspicious',severity:'medium',confidence:'medium',reasons:[],transformations:[]},'private','https://unit.invalid',[],'Public response');const v=e.redact({category:'private-credential',reason:'private-address',sensitiveFields:[{path:'profile.id',expectation:'private'}],nested:{private:'private'}});assert.equal(v.category,'private-credential');assert.equal(v.reason,'private-address');assert.equal(v.sensitiveFields[0].expectation,'private');assert.ok(!Object.hasOwn(v.nested,'private'));assert.ok(!Object.values(v.nested).includes('private'));}finally{e.clear();}
});
