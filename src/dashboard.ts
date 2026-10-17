import http from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { Scanner } from './scanner.js';
import { Detector, root } from './detectors.js';
import { Evidence } from './evidence.js';
import { report } from './reports.js';
import { makeNewConfig } from './config.js';
import { ScopePolicy, scopeSource } from './domain-scope.js';
import type { ScanConfig, ProgramConfig, Finding } from './types.js';
import { Desk } from './desk.js';
import { ProtectedHostError, isProtectedHostError, PROTECTED_HOST_MESSAGE } from './protected-hosts.js';
import { compareScans, type History } from './storage.js';
import { runSummary, runTime, scopeCounts, defaultProjectName, LEGACY_DEFAULT_NAME, SafeError, type RunSummary } from './runs.js';
import { presets, presetConfig, profileCatalog, profilePreview } from './presets.js';
import { describeProfile, type Computer } from './profiles.js';
import { readComputer } from './computer.js';
import { diagnose } from './diagnostics.js';
import { validateRules, previewRules, ruleDigest } from './rules.js';
import { spawn } from 'node:child_process';
import { createFixture } from './fixture.js';
import { BUILD } from './build-info.js';
import {pipelineSelfTest} from './pipeline-self-test.js';
import { RECON_FILES } from './recon/index.js';// w2-wire: allow-list for recon file downloads.
import { submissionMarkdown } from './submission/index.js';// w2-wire: masked per-finding submission Markdown.
import { readdir } from 'node:fs/promises';// w3-ui: lists a run's recon files for the scan view.
import { checkOneKey, LiveCheckRefused, type CheckEnv } from './live-check/egress.js';// w8: the one explicit live-key-check egress path.
import { recipeFor, allRecipes } from './live-check/recipes.js';
import { runLiveCheckAll, type LiveCheckAllProgress } from './live-check/run-all.js';
function equal(a:string,b:string){const x=Buffer.from(a),y=Buffer.from(b);return x.length===y.length&&timingSafeEqual(x,y);}
async function jsonBody(req:http.IncomingMessage){
  if(!String(req.headers['content-type']).startsWith('application/json'))throw new Error('JSON required');
  const chunks:Buffer[]=[];let size=0;
  for await(const chunk of req){size+=chunk.length;if(size>131072)throw new Error('Request too large');chunks.push(chunk);}
  return JSON.parse(Buffer.concat(chunks).toString());
}
export async function startDashboard(options:{port?:number;projects?:Partial<ScanConfig>[];companyRules?:string;persistent?:boolean;dataDir?:string;syntheticData?:boolean;portFallback?:boolean;onShutdown?:()=>void;instanceNonce?:string;computer?:()=>Computer;liveCheckEnv?:CheckEnv}={}){
  const token=randomBytes(24).toString('base64url'),session=randomBytes(32).toString('base64url'),csrf=randomBytes(24).toString('base64url');
  const scans=new Map<string,Scanner>();const jobs=new Set<Promise<unknown>>();
  const masker=new Evidence(new Detector());
  const projects=(options.projects||[]).map(c=>makeNewConfig(c));let origin='';
  const desk=new Desk(scans,()=>[(server.address() as any).port],options.companyRules,options.computer);
  let demo:Awaited<ReturnType<typeof createFixture>>|undefined,repair:{running:boolean;action:string;result:string}={running:false,action:'',result:''},diagnostic:any;
  const projectName=(id?:string)=>id?desk.store?.projects.find(p=>p.id===id)?.config.name:undefined;
  // History summaries are cached per stored record object (a new record replaces the object), so polling never rescans every retained view.
  const summaryCache=new WeakMap<object,{name?:string;summary:RunSummary}>();
  const historySummary=(h:History)=>{const name=projectName(h.projectId),hit=summaryCache.get(h);if(hit&&hit.name===name)return hit.summary;const summary=runSummary({view:h.view,projectId:h.projectId,projectName:name,savedAt:h.savedAt});summaryCache.set(h,{name,summary});return summary;};
  const liveSummary=(s:Scanner,phase?:string)=>{const pid=desk.projectOf(s);return runSummary({view:s.brief(),projectId:pid,projectName:projectName(pid),savedAt:desk.store?.history.find(h=>h.view.id===s.id)?.savedAt,live:true,phase});};
  const runs=(limit=50)=>{
    const active=desk.activeScan(),live=[...scans.values()].map(s=>liveSummary(s));if(active&&!scans.has(active.id))live.push(liveSummary(active,'starting'));
    const ids=new Set(live.map(r=>r.id)),all=[...live,...(desk.store?.history||[]).filter(h=>!ids.has(h.view.id)).map(historySummary)].sort((a,b)=>runTime(b)-runTime(a));
    const current=active?all.find(r=>r.id===active.id)||null:null,history=all.filter(r=>r.id!==current?.id);
    return {schema:'exposure-runs/1',storage:desk.store?'persistent':'memory-only',current,latest:current?null:history[0]||null,history:history.slice(0,limit),
      queue:desk.queue.slice(-20).map(j=>({jobId:j.id,projectId:j.projectId,label:(n=>n&&n!==LEGACY_DEFAULT_NAME?n:defaultProjectName(desk.store?.projects.find(p=>p.id===j.projectId)?.config.urls||[]))(projectName(j.projectId)),state:j.state,trigger:j.trigger||(j.source==='schedule'?'schedule':'queue'),requestedAt:j.requestedAt||null,runId:j.scanId||null,...(j.reason?{reason:j.reason}:{}),...(j.profile?{profile:j.profile}:{})})),
      counts:{activeRuns:active&&scans.has(active.id)?1:0,startingRuns:active&&!scans.has(active.id)?1:0,queuedRuns:desk.queue.filter(j=>j.state==='queued').length,retainedRuns:desk.store?.history.length||0,inMemoryRuns:scans.size,listed:Math.min(limit,history.length),total:all.length}};
  };
  /** Review actions shared by live and retained scans. Patches merge (status changes keep suppressions; feedback keeps status); owner records and lifecycle tracks need a saved project. */
  const reviewAction=async(action:string,projectId:string|undefined,f:import('./types.js').Finding,b:any,scrub:(s:string)=>string)=>{
    if(!projectId||!desk.store)throw new Error('Persistent scoped reviews require a saved project');const store=desk.store;
    if(action==='suppress'){if(typeof b.reason!=='string'||b.reason.trim().length<3||b.reason.length>500||!Number.isFinite(Date.parse(b.expires))||Date.parse(b.expires)<=Date.now())throw new Error('Reason and future expiry required');return store.review(projectId,f,{reason:scrub(b.reason),expires:b.expires});}
    if(action==='unsuppress')return store.review(projectId,f,{clearSuppression:true});
    if(action==='status'){if(!['open','reviewing','removed'].includes(b.status))throw new Error('Invalid review status');if(b.status==='removed')return store.lifecycle(projectId,f,'report-removed',scrub(String(b.note||'')));return store.review(projectId,f,{status:b.status,...(b.status==='open'?{clear:['removalReported'] as ('removalReported')[]}:{})});}
    if(action==='owner-record')return store.ownerRecord(projectId,f,{...b,permissionsNote:typeof b.permissionsNote==='string'?scrub(b.permissionsNote):b.permissionsNote,spendLimitNote:typeof b.spendLimitNote==='string'?scrub(b.spendLimitNote):b.spendLimitNote});
    if(action==='lifecycle')return store.lifecycle(projectId,f,b.lifecycle,scrub(String(b.note||'')),b.replacement);
    throw new Error('Unknown review action');};
  // w3-ui: the allow-listed recon files on disk for a run, so the dashboard shows download links only when they exist. recon.json is written last,
  // so until it is present the set is incomplete and none are listed. Names come from the fixed allow-list only; nothing is read.
  const reconFiles=async(id:string):Promise<string[]>=>{if(!desk.store)return [];try{const names=new Set(await readdir(path.join(desk.store.dir,'recon',id)));return names.has('recon.json')?RECON_FILES.filter(n=>names.has(n)):[];}catch{return [];}};
  // w8: live key check (2.9). Off unless the program file opts in; a found key is only ever sent on an explicit per-finding action with a per-send confirmation.
  const liveCheckJobs=new Map<string,{progress:LiveCheckAllProgress;controller:AbortController}>();
  const idleProgress=(total=0):LiveCheckAllProgress=>({total,done:0,running:false,cancelled:false,haltedProviders:[],results:{},skipped:[]});
  const liveCheckOne=async(program:ProgramConfig|undefined,f:Finding,key:string,confirm:unknown,projectId:string|undefined)=>{
    if(!program?.liveKeyChecks?.enabled)throw new Error('Live key checks are off. Set "liveKeyChecks": {"enabled": true} in the program file after reading the program rules.');
    if(confirm!=='send-one-key-to-provider')throw new Error('Explicit confirmation required to send this one key to its provider');
    let result;try{result=await checkOneKey({rule:f.rule,key,provider:f.provider},options.liveCheckEnv);}
    catch(e){if(e instanceof LiveCheckRefused)throw new SafeError('That endpoint is refused for live key checks (protected host, metadata, non-HTTPS, or a connection-address mismatch) and is never contacted.',e.code,400);throw e;}
    if(projectId&&desk.store)await desk.store.recordLiveCheck(projectId,f,result);
    f.liveCheck=result;                                 // reflect immediately in the in-memory view (persisted above when a project is saved)
    return result;
  };
  const liveCheckItems=(findings:Finding[],keyOf:(f:Finding)=>string|undefined)=>findings.map(f=>({f,recipe:recipeFor(f.rule)})).filter(x=>!!x.recipe).map(({f,recipe})=>({correlation:f.correlation||f.id,rule:f.rule,provider:recipe!.provider,key:keyOf(f)||'',f})).filter(i=>i.key);
  const liveCheckAll=(id:string,program:ProgramConfig|undefined,items:{correlation:string;rule:string;provider:string;key:string;f:Finding}[],confirm:unknown,projectId:string|undefined)=>{
    if(!program?.liveKeyChecks?.enabled||!program.liveKeyChecks.checkAll)throw new Error('"Check all" is not allowed by the program file. Set "liveKeyChecks": {"enabled": true, "checkAll": true}.');
    if(confirm!=='send-all-keys-one-at-a-time')throw new Error('Explicit confirmation required to check all keys one at a time');
    if(!items.length)throw new Error('No live-checkable keys in this scan');
    const existing=liveCheckJobs.get(id);if(existing?.progress.running)throw new Error('A check-all run is already in progress for this scan');
    const controller=new AbortController(),job={progress:{...idleProgress(items.length),running:true},controller};liveCheckJobs.set(id,job);
    const task=(async()=>{await runLiveCheckAll(items.map(({f,...i})=>i),{env:options.liveCheckEnv,signal:controller.signal,onProgress:p=>job.progress=p});
      for(const it of items){const r=job.progress.results[it.correlation];if(!r)continue;try{if(projectId&&desk.store)await desk.store.recordLiveCheck(projectId,it.f,r);it.f.liveCheck=r;}catch{}}})();
    jobs.add(task);void task.catch(()=>{}).finally(()=>jobs.delete(task));
    return job.progress;
  };
  const server=http.createServer(async(req,res)=>{
    res.setHeader('Cache-Control','no-store');res.setHeader('Pragma','no-cache');res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('X-Frame-Options','DENY');res.setHeader('Referrer-Policy','no-referrer');
    res.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
    const send=(code:number,value:unknown)=>{res.writeHead(code,{'Content-Type':'application/json; charset=utf-8'});res.end(JSON.stringify(value));};
    try{
      if(req.headers.host!==new URL(origin).host){send(403,{error:'Host rejected'});return;}
      if(req.headers.origin&&req.headers.origin!==origin){send(403,{error:'Origin rejected'});return;}
      if(req.headers['sec-fetch-site']&&req.headers['sec-fetch-site']!=='same-origin'&&req.headers['sec-fetch-site']!=='none'){send(403,{error:'Cross-site request rejected'});return;}
      const u=new URL(req.url||'/',origin);
      if(req.method==='GET'&&u.pathname==='/health'){send(200,{application:'Exposure Desk',instance:options.instanceNonce||'development',build:BUILD});return;}
      if(!u.pathname.startsWith('/api/')){
        if(req.method!=='GET'){send(405,{error:'Method rejected'});return;}
        const files:Record<string,[string,string]>={'/':['index.html','text/html'],'/app.js':['app.js','text/javascript'],'/style.css':['style.css','text/css']};
        const file=files[u.pathname];if(!file){send(404,{error:'Not found'});return;}
        res.writeHead(200,{'Content-Type':file[1]+'; charset=utf-8'});res.end(await readFile(path.join(root,'public',file[0])));return;
      }
      if(!['GET','POST'].includes(req.method||'')){send(405,{error:'Method rejected'});return;}
      if(req.method==='POST'&&(req.headers.origin!==origin||req.headers['x-dashboard-request']!=='1')){send(403,{error:'Origin and request header required'});return;}
      if(u.pathname==='/api/login'&&req.method==='POST'){
        const b=await jsonBody(req);if(typeof b.token!=='string'||!equal(b.token,token)){send(401,{error:'Launch token rejected'});return;}
        res.setHeader('Set-Cookie',`exposure_session=${session}; HttpOnly; SameSite=Strict; Path=/`);send(200,{ok:true,csrf});return;
      }
      const cookie=String(req.headers.cookie||'').split(';').map(s=>s.trim()).find(s=>s.startsWith('exposure_session='))?.slice(17)||'';
      if(!equal(cookie,session)){send(401,{error:'Sign in with the per-launch token'});return;}
      if(req.method==='POST'&&!equal(String(req.headers['x-csrf-token']||''),csrf)){send(403,{error:'CSRF token rejected'});return;}
      if(req.method==='GET'&&u.pathname==='/api/session'){send(200,{csrf});return;}
      if(req.method==='GET'&&u.pathname==='/api/projects'){send(200,masker.redact(projects));return;}
      if(req.method==='GET'&&u.pathname==='/api/workspace'){send(200,masker.redact({projects:(desk.store?.projects||[]).map(p=>{const refusal=desk.store!.refusal(p.id);return refusal?{...p,config:desk.store!.editableConfig(p),profile:describeProfile(p.config),blocked:{code:refusal.code,host:refusal.host,reason:refusal.message}}:(h=>h?{...p,profile:describeProfile(p.config),hostWarning:{code:h.code,host:h.details.host,reason:h.message}}:{...p,profile:describeProfile(p.config)})(desk.store!.hostRefusal(p.id));}),history:desk.store?.history.map(h=>({...historySummary(h),projectId:h.projectId,id:h.view.id,name:h.view.name,state:h.view.state,startedAt:h.view.startedAt,counts:h.view.counts,browserStatus:h.view.browserStatus}))||[],settings:desk.store?.settings,storageError:desk.storageError,dataLocation:desk.store?.dir||options.dataDir,queue:desk.queue,notifications:desk.notifications,alerts:(desk.store?.alerts||[]).slice(-100),vault:desk.vault?.status(),presets,profiles:profileCatalog(),repair}));return;}
      if(req.method==='GET'&&u.pathname==='/api/diagnostics'){const checks=await diagnose({dir:options.dataDir,synthetic:options.syntheticData});diagnostic={...checks,browser:diagnostic?.browser||checks.browser,pipeline:diagnostic?.pipeline};send(200,diagnostic);return;}
      if(req.method==='POST'&&u.pathname==='/api/setup'){
        const b=await jsonBody(req);if(repair.running||[...scans.values()].some(s=>s.state==='running'))throw new Error('Stop scans before setup');
        if(!['gitleaks','browser','runtime','browser-suite','full-pipeline'].includes(b.action))throw new Error('Unsupported setup action');
        repair={running:true,action:b.action,result:'Working'};send(202,{ok:true});
        const task=(async()=>{try{if(b.action==='full-pipeline'){const pipeline=await pipelineSelfTest();diagnostic??=await diagnose({dir:options.dataDir,synthetic:options.syntheticData});diagnostic.pipeline=pipeline;if(desk.store)await desk.store.atomic('diagnostic-results.json',pipeline);repair.result='Full-pipeline self-test '+pipeline.status+'; '+pipeline.summary.found+'/'+pipeline.summary.planted+' fixtures observed. Refresh checks for individual results.';}else if(b.action==='runtime'){diagnostic=await diagnose({dir:options.dataDir,runtime:true,synthetic:options.syntheticData});repair.result=diagnostic.browser.launch==='available'?'Runtime check finished; see separate isolation status':'Browser launch blocked; runtime coverage unavailable';}else{
          const args=b.action==='gitleaks'?[path.join(root,'scripts/install-gitleaks.mjs')]:b.action==='browser'?[path.join(root,'node_modules/playwright/cli.js'),'install','chromium']:[path.join(root,'scripts/test.mjs'),'--browser'];
          const code=await new Promise<number>(resolve=>{const child=spawn(process.execPath,args,{cwd:root,stdio:'ignore',windowsHide:true,env:process.env});child.once('error',()=>resolve(2));child.once('exit',c=>resolve(c??2));});repair.result=code===0?'Completed':'Failed. Check dependency access, Windows IPC or Linux shared libraries. No safeguards were disabled.';if(b.action==='gitleaks'&&code===0&&process.env.EXPOSURE_TOOLS_DIR)process.env.GITLEAKS_PATH=path.join(process.env.EXPOSURE_TOOLS_DIR,process.platform==='win32'?'gitleaks.exe':'gitleaks');if(b.action==='browser-suite'){diagnostic??=await diagnose({dir:options.dataDir,synthetic:options.syntheticData});diagnostic.browser.networkIsolation=code===0?'passed-full-suite':'failed';}
        }}catch{repair.result='Setup failed; check filesystem/network permissions or required OS libraries';}finally{repair.running=false;}})();jobs.add(task);void task.finally(()=>jobs.delete(task));return;
      }
      if(req.method==='GET'&&u.pathname==='/api/diagnostic-result'){const value=diagnostic||{browser:{launch:'not-run',networkIsolation:'not-run',runtimeScan:'not-run'}};if(!value.pipeline&&desk.store)try{value.pipeline=JSON.parse(await readFile(path.join(desk.store.dir,'diagnostic-results.json'),'utf8'));}catch{}send(200,value);return;}
      if(req.method==='GET'&&u.pathname==='/api/coverage-registry'){send(200,JSON.parse(await readFile(path.join(root,'coverage-registry.json'),'utf8')));return;}
      if(req.method==='POST'&&u.pathname==='/api/config/preview'){const b=await jsonBody(req);send(200,makeNewConfig(b.config));return;}
      // The browser has no public suffix list: the server computes the scope preview (mode, domain groups, warnings) from the raw input.
      if(req.method==='POST'&&u.pathname==='/api/scope/preview'){const b=await jsonBody(req);const input=b.config&&typeof b.config==='object'?b.config:{};const config=makeNewConfig(input);send(200,masker.redact({...new ScopePolicy(config).describe(scopeSource(input)),suggestedName:defaultProjectName(config.urls),counts:scopeCounts({config})}));return;}
      // Scan-page profile preview (debounced by the page): resolution, website counts, the pure estimate and the coverage lists. Computed locally; nothing is contacted.
      if(req.method==='POST'&&u.pathname==='/api/profile/preview'){const b=await jsonBody(req);const input=b.config&&typeof b.config==='object'&&!Array.isArray(b.config)?b.config:{};const preview=profilePreview(input,(options.computer||readComputer)());send(200,masker.redact({...preview,counts:scopeCounts({config:preview.config})}));return;}
      // Seed URLs are checked on the main thread with the bounded main-thread inspection (never a whole-document parse); the 128 KiB request-body cap bounds their total size.
      if(req.method==='POST'&&u.pathname==='/api/projects/save'){if(!desk.store)throw new Error('Protected storage unavailable');const b=await jsonBody(req);const config=makeNewConfig(b.config);if(config.urls.some(v=>masker.detector.inspectWindowed(v).some(c=>['private-credential','suspicious'].includes(c.category))))throw new Error('Credential-bearing seed cannot be saved');const p=await desk.store.project(masker.redact(config),b.authorized===true,b.id);send(200,p);return;}
      // Owner-initiated switch of a saved legacy (or custom) project to a scan profile; legacy projects are never switched automatically.
      if(req.method==='POST'&&u.pathname==='/api/projects/profile'){if(!desk.store)throw new Error('Protected storage unavailable');const b=await jsonBody(req);const p=await desk.store.switchProfile(b.id,b.authorized===true,typeof b.coverage==='string'?b.coverage:undefined,typeof b.traffic==='string'?b.traffic:undefined);send(200,masker.redact(p));return;}
      if(req.method==='POST'&&u.pathname==='/api/projects/delete'){const b=await jsonBody(req);if(!desk.store?.projects.some(p=>p.id===b.id))throw new Error('Project not found');await desk.cancelProject(b.id);for(const [id,s]of scans)if(desk.scanProjects.get(id)===b.id){s.cancel();while(s.state==='running')await new Promise(r=>setTimeout(r,50));await desk.waitForScan(id);s.dispose();scans.delete(id);}await desk.store.deleteProject(b.id);send(200,{ok:true});return;}
      if(req.method==='POST'&&u.pathname==='/api/queue'){const b=await jsonBody(req);const {value:jobs,duplicate}=await desk.requests.once('queue',b.requestId,b,()=>desk.enqueue(b.projectIds,b.saveEvidence===true));send(202,{jobs,duplicate});return;}
      if(req.method==='GET'&&u.pathname==='/api/runs'){const limit=Math.min(200,Math.max(1,Math.floor(Number(u.searchParams.get('limit')||50))||50));send(200,masker.redact(runs(limit)));return;}
      if(req.method==='POST'&&u.pathname==='/api/queue/cancel'){desk.cancelQueue();send(200,{ok:true});return;}
      if(req.method==='POST'&&u.pathname==='/api/schedule'){const b=await jsonBody(req);const p=desk.store?.projects.find(p=>p.id===b.projectId);if(!p||!b.authorized||!Number.isFinite(b.intervalHours)||b.intervalHours<1||b.intervalHours>8760)throw new Error('Saved authorized project and interval 1–8760 hours required');const refusal=desk.store!.refusal(p.id)??(b.enabled===true?desk.store!.hostRefusal(p.id):undefined);if(refusal)throw refusal;p.schedule={...p.schedule,enabled:b.enabled===true,intervalHours:b.intervalHours,nextRun:new Date(Date.now()+b.intervalHours*3600000).toISOString(),missed:p.schedule?.missed||0};await desk.store!.save();send(200,p.schedule);return;}
      if(req.method==='POST'&&u.pathname==='/api/alerts/ack'){const b=await jsonBody(req);if(!desk.store)throw new Error('Storage unavailable');await desk.store.acknowledge(b.all===true?'all':b.ids);send(200,{ok:true});return;}
      // Deployment triggers are opt-in per saved project with the same authorization acknowledgement as schedules; requests arrive only as CLI-written files.
      if(req.method==='POST'&&u.pathname==='/api/deployment-trigger'){const b=await jsonBody(req);const p=desk.store?.projects.find(p=>p.id===b.projectId);const minutes=b.minIntervalMinutes??p?.deploymentTrigger?.minIntervalMinutes??10,perDay=b.maxPerDay??p?.deploymentTrigger?.maxPerDay??24;if(!p||b.authorized!==true||!Number.isInteger(minutes)||minutes<1||minutes>1440||!Number.isInteger(perDay)||perDay<1||perDay>96)throw new Error('Saved authorized project, interval 1–1440 minutes and 1–96 scans per day required');const refusal=desk.store!.refusal(p.id)??(b.enabled===true?desk.store!.hostRefusal(p.id):undefined);if(refusal)throw refusal;p.deploymentTrigger={...p.deploymentTrigger,enabled:b.enabled===true,minIntervalMinutes:minutes,maxPerDay:perDay,recent:p.deploymentTrigger?.recent||[]};await desk.store!.save();send(200,p.deploymentTrigger);return;}
      if(req.method==='POST'&&u.pathname==='/api/settings'){const b=await jsonBody(req);if(!desk.store)throw new Error('Storage unavailable');for(const [k,min,max]of [['retentionDays',1,3650],['maxScans',1,1000],['vaultMinutes',1,60]] as const){if(!Number.isInteger(b[k])||b[k]<min||b[k]>max)throw new Error('Invalid retention/timeout setting');desk.store.settings[k]=b[k];}await desk.store.save();await desk.store.prune();if(desk.vault?.status().unlocked)desk.vault.touch();send(200,desk.store.settings);return;}
      if(req.method==='GET'&&u.pathname==='/api/rules'){send(200,{rules:desk.store?.rules||[],versions:desk.store?.ruleVersions.map(v=>({version:v.version,at:v.at}))||[]});return;}
      // The static live-check recipe table (our own source, never scanned content): the dashboard uses it to label the confirm dialog with the endpoint host and to offer the button only for findings that have a documented read-only check.
      if(req.method==='GET'&&u.pathname==='/api/live-check/recipes'){send(200,{recipes:allRecipes().map(r=>({provider:r.provider,rules:r.rules,host:r.host,method:r.method,path:r.path,doc:r.doc}))});return;}
      if(req.method==='POST'&&u.pathname==='/api/rules'){const b=await jsonBody(req);const rules=validateRules(b.rules);if(b.preview){send(200,previewRules(rules,b.sample));return;}if(!desk.store)throw new Error('Storage unavailable');if([...scans.values()].some(s=>s.state==='running'))throw new Error('Wait for scan before changing rules');desk.store.rules=rules;desk.store.ruleVersions.push({version:ruleDigest(rules),at:new Date().toISOString(),rules});desk.store.ruleVersions=desk.store.ruleVersions.slice(-20);await desk.store.atomic('company-rules.json',{rules});await desk.store.save();send(200,{version:ruleDigest(rules)});return;}
      if(req.method==='POST'&&u.pathname.startsWith('/api/vault/')){const b=await jsonBody(req);if(!desk.vault)throw new Error('Protected storage unavailable');const action=u.pathname.split('/').at(-1);if(action==='unlock')await desk.vault.unlock(b.password,b.create===true);else if(action==='lock')desk.vault.lock();else if(action==='delete'){if(b.confirm!=='delete-encrypted-evidence')throw new Error('Confirm vault deletion');await desk.vault.delete();}else if(action==='save'){if(b.confirm!=='save-full-evidence')throw new Error('Confirm evidence persistence');const s=scans.get(b.scanId);if(!s||s.state==='running'||!desk.store?.history.some(h=>h.view.id===s.id))throw new Error('Completed saved project scan required');await desk.vault.put(s.id,s.evidence.full());}else throw new Error('Unknown vault action');send(200,desk.vault.status());return;}
      if(req.method==='GET'&&u.pathname==='/api/compare'){const a=desk.store?.history.find(h=>h.view.id===u.searchParams.get('before')),b=desk.store?.history.find(h=>h.view.id===u.searchParams.get('after'));if(!a||!b)throw new Error('Select two saved scans');send(200,compareScans(a,b));return;}
      if(req.method==='POST'&&u.pathname==='/api/demo'){if(!demo)demo=await createFixture(0,{minimalDiscovery:true});const s=await desk.start({name:'DEMO · synthetic local exposures',urls:[demo.origin+'/.env'],developmentFixtureOrigin:demo.origin,requestsPerSecond:20,browser:false,adjacentMaps:false},undefined,false,undefined,undefined,{trigger:'demo'});send(202,{id:s.id,shortId:s.id.slice(0,8),demo:true});return;}
      if(req.method==='POST'&&u.pathname==='/api/shutdown'){send(200,{ok:true});setTimeout(()=>options.onShutdown?options.onShutdown():void close(),100);return;}
      // Compatibility list (current in-memory scans, then retained history). Rows are built from cheap briefs and cached summaries, never from full views.
      if(req.method==='GET'&&u.pathname==='/api/scans'){const row=(r:RunSummary,extra:Record<string,unknown>)=>({id:r.id,shortId:r.shortId,name:r.name,label:r.label,state:r.state,startedAt:r.startedAt,trigger:r.trigger,triggerLabel:r.triggerLabel,live:r.live,...extra});send(200,masker.redact([...scans.values()].map(s=>row(liveSummary(s),{counts:s.brief().counts,scope:s.transport.scope.mode as string|undefined})).concat((desk.store?.history||[]).filter(h=>!scans.has(h.view.id)).map(h=>row(historySummary(h),{counts:h.view.counts,scope:h.view.scope?.mode})))));return;}
      if(req.method==='POST'&&u.pathname==='/api/scans'){
        // Starting a scan requires the explicit authorization acknowledgement on the server, not only in the form. `requestId` is accepted for idempotent replays (reserved).
        // A replayed requestId with the same body returns the first run (duplicate:true), even while that start is still in flight; repeatOf links a deliberate repeat.
        const b=await jsonBody(req);if(b.authorized!==true)throw new Error('Explicit website authorization is required to start a scan');const {value:started,duplicate}=await desk.requests.once('scans',b.requestId,b,async()=>{const p=desk.store?.projects.find(p=>p.id===b.projectId);if(b.projectId&&!p)throw new Error('Project not found');const refusal=p&&desk.store!.refusal(p.id);if(refusal)throw refusal;const profile={...(typeof b.coverage==='string'?{coverage:b.coverage}:{}),...(typeof b.traffic==='string'?{traffic:b.traffic}:{})},input=b.preset?presetConfig(b.preset,{...b.config,...profile}):{...b.config,...profile};const s=await desk.start(input,p?.id,b.saveEvidence===true,undefined,undefined,{trigger:'manual',repeatOf:typeof b.repeatOf==='string'?b.repeatOf:undefined});return {id:s.id,launch:s.launch};});send(202,{id:started.id,shortId:started.id.slice(0,8),duplicate,launch:started.launch});return;
      }
      if(req.method==='POST'&&u.pathname==='/api/resume'){
        // A checkpoint-supplied launch or trigger is ignored; the previous run is linked only when its id is a UUID that exists locally.
        const b=await jsonBody(req);if(b.checkpoint?.schema!=='exposure-checkpoint/1')throw new Error('Invalid checkpoint');const previous=b.checkpoint.redactedReview?.id;const s=await desk.start(b.checkpoint.config,undefined,false,b.checkpoint.frontier,undefined,{trigger:'resume',previousRunId:desk.knownRun(previous)?previous:undefined});send(202,{id:s.id,shortId:s.id.slice(0,8)});return;
      }
      // w2-wire: download one recon file for a run. GET only (no state change); the file name must be in the fixed allow-list, so no path can be traversed. Recon lists are masked by construction.
      const reconDl=/^\/api\/scans\/([a-f0-9-]+)\/recon\/([a-zA-Z0-9._-]+)$/.exec(u.pathname);
      if(reconDl){if(req.method!=='GET'){send(405,{error:'Method rejected'});return;}if(!desk.store){send(404,{error:'Recon lists are available only for stored runs'});return;}if(!(RECON_FILES as readonly string[]).includes(reconDl[2])){send(404,{error:'Unknown recon file'});return;}
        let body:Buffer;try{body=await readFile(path.join(desk.store.dir,'recon',reconDl[1],reconDl[2]));}catch{send(404,{error:'No recon list for this run'});return;}
        res.writeHead(200,{'Content-Type':(reconDl[2].endsWith('.json')?'application/json':'text/plain')+'; charset=utf-8','Content-Disposition':`attachment; filename="${reconDl[2]}"`});res.end(body);return;}
      const m=/^\/api\/scans\/([a-f0-9-]+)(?:\/([a-z]+(?:-[a-z]+)?))?$/.exec(u.pathname);const s=m?scans.get(m[1]):undefined;
      const h=m?desk.store?.history.find(h=>h.view.id===m[1]):undefined;
      if(m&&req.method==='GET'&&m[2]==='livecheck-progress'){send(200,masker.redact(liveCheckJobs.get(m[1])?.progress||idleProgress()));return;}
      if(!s&&h){desk.store!.applyReviews(h.projectId,h.view.findings);if(req.method==='GET'&&!m![2]){send(200,{...h.view,run:historySummary(h),reconFiles:await reconFiles(h.view.id)});return;}if(req.method!=='POST'){send(405,{error:'Use explicit POST action'});return;}const b=await jsonBody(req);const f=h.view.findings.find(f=>f.id===b.findingId);
        if(m![2]==='retryplan'||m![2]==='retry'){if(h.view.state==='running')throw new Error('Wait for the scan to stop');const {focusedRetry}=await import('./retry.js');const plan=focusedRetry(h.view,b.includeOptional===true);if(m![2]==='retryplan'){send(200,plan);return;}if(!plan.selected.length&&!plan.browserUrls.length)throw new Error('No safe important retry candidates; review exclusions or select optional pages');const next=await desk.start({...h.view.config,deep:false,staleAssetCheck:false,staleAssetUrls:[]},h.projectId,false,undefined,plan,{trigger:'retry',previousRunId:h.view.id});send(202,{id:next.id,shortId:next.id.slice(0,8)});return;}
        if(m![2]==='delete'){await desk.store!.deleteScan(h.view.id);send(200,{ok:true});return;}
        if(m![2]==='reveal'){if(!['reveal','copy'].includes(b.action))throw new Error('Explicit reveal required');const values=await desk.vault!.get(h.view.id);if(!values[b.findingId])throw new Error('Old redacted history has no full values');send(200,values[b.findingId]);return;}
        if(m![2]==='livecheck'){const values=await desk.vault!.get(h.view.id);const key=values[b.findingId]?.value;if(!f||!key)throw new Error('Saved encrypted evidence is required to check this key; the redacted history has no full value');send(200,masker.redact(await liveCheckOne(h.view.config.program,f,key,b.confirm,h.projectId)));return;}
        if(m![2]==='livecheck-all'){const values=await desk.vault!.get(h.view.id);const items=liveCheckItems(h.view.findings,x=>values[x.id]?.value);send(200,masker.redact(liveCheckAll(h.view.id,h.view.config.program,items,b.confirm,h.projectId)));return;}
        if(m![2]==='livecheck-cancel'){liveCheckJobs.get(h.view.id)?.controller.abort();send(200,{ok:true});return;}
        if(m![2]==='export'){if(!['json','html','sarif'].includes(b.format))throw new Error('Unknown format');const {historyReport}=await import('./reports.js');let full;if(b.full){if(b.confirm!=='sensitive-local-export')throw new Error('Sensitive export confirmation required');full=await desk.vault!.get(h.view.id);}res.writeHead(200,{'Content-Type':b.format==='html'?'text/html':'application/json'});res.end(historyReport(h.view,b.format,full));return;}
        if(m![2]==='rescan'&&f){const {affectedResourceUrls}=await import('./retry.js');const urls=affectedResourceUrls(h.view,f);if(!urls.length)throw new Error('No safe affected public source URL; rescan the approved project seeds');const next=await desk.start({...h.view.config,urls,deep:false},h.projectId,false,undefined,undefined,{trigger:'rescan',previousRunId:h.view.id});send(202,{id:next.id,shortId:next.id.slice(0,8)});return;}
        if(m![2]==='feedback'&&f){if(!h.projectId)throw new Error('Save an authorized project for scoped feedback');await desk.store!.feedback(h.projectId,f,b.decision,masker.scrub(String(b.reason||'')),b.expires);send(200,{ok:true});return;}if(['suppress','unsuppress','status','owner-record','lifecycle'].includes(m![2]||'')&&f){await reviewAction(m![2]==='owner-record'?'owner-record':m![2]!,h.projectId,f,b,v=>masker.scrub(v));send(200,{ok:true});return;}
        if(m![2]==='checkpoint'){send(200,{schema:'exposure-checkpoint/1',config:h.view.config,frontier:h.view.uninspected||[],redactedReview:h.view,resume:'Recovered history: re-fetch authorized seeds and retained safe frontier with fresh budgets. Full values are not in this checkpoint.'});return;}
        // w2-wire: masked submission Markdown for a retained finding, built from the redacted history view and re-masked; no saved evidence is read.
        if(m![2]==='submission'&&f){const r=submissionMarkdown([f],h.view);send(200,masker.redact({markdown:r[0]?.markdown||'',title:r[0]?.title||'',fileName:r[0]?.fileName||''}));return;}
        send(400,{error:'This action is unavailable for retained redacted history. Review/export the saved result or start a fresh authorized scan; full values require saved encrypted evidence.'});return;
      }
      if(!s){send(410,{error:'This scan is no longer in memory or retained history. Select saved history or re-fetch the authorized seeds. Check protected storage and retention settings.',code:'scan-unavailable',recoverable:false});return;}
      if(req.method==='GET'&&!m![2]){send(200,{...s.view(),run:liveSummary(s),reconFiles:await reconFiles(s.id)});return;}
      if(req.method!=='POST'){send(405,{error:'Use explicit POST action'});return;}
      const b=await jsonBody(req);
      switch(m![2]){
        case 'retryplan':case 'retry':{if(s.state==='running')throw new Error('Wait for the scan to stop');const {focusedRetry}=await import('./retry.js');const plan=focusedRetry(s.view(),b.includeOptional===true);if(m![2]==='retryplan'){send(200,plan);return;}if(!plan.selected.length&&!plan.browserUrls.length)throw new Error('No safe important retry candidates; review exclusions or select optional pages');const next=await desk.start({...s.config,deep:false,staleAssetCheck:false,staleAssetUrls:[]},desk.scanProjects.get(s.id),false,undefined,plan,{trigger:'retry',previousRunId:s.id});send(202,{id:next.id,shortId:next.id.slice(0,8)});return;}
        case 'cancel':s.cancel();send(200,{ok:true});return;
        case 'checkpoint':send(200,s.checkpoint());return;
        case 'delete':if(s.state==='running')throw new Error('Cancel and wait before deleting');await desk.waitForScan(s.id);s.dispose();scans.delete(s.id);if(h)await desk.store!.deleteScan(s.id);send(200,{ok:true});return;
        case 'reveal':if(!['reveal','copy'].includes(b.action))throw new Error('Explicit reveal or copy action required');send(200,s.evidence.reveal(b.findingId));return;
        case 'feedback':{const f=s.evidence.findings.get(b.findingId),pid=desk.scanProjects.get(s.id)||h?.projectId;if(!f||!pid||!desk.store)throw new Error('Save an authorized project for scoped feedback');await desk.store.feedback(pid,f,b.decision,s.evidence.scrub(String(b.reason||'')),b.expires);send(200,{ok:true});return;}
        case 'suppress':{s.evidence.suppress(b.findingId,b.reason,b.expires);const pid=desk.scanProjects.get(s.id)||h?.projectId;if(pid&&desk.store){const f=s.evidence.findings.get(b.findingId)!;await desk.store.review(pid,f,{reason:f.suppression!.reason,expires:f.suppression!.expires});}send(200,{ok:true});return;}
        case 'unsuppress':{const f=s.evidence.findings.get(b.findingId);if(!f)throw new Error('Finding not found');delete f.suppression;const pid=desk.scanProjects.get(s.id)||h?.projectId;if(pid&&desk.store)await desk.store.review(pid,f,{clearSuppression:true});send(200,{ok:true});return;}
        case 'status':{const f=s.evidence.findings.get(b.findingId);if(!f||!['open','reviewing','removed'].includes(b.status))throw new Error('Invalid review status');const pid=desk.scanProjects.get(s.id)||h?.projectId;if(pid&&desk.store)await reviewAction('status',pid,f,b,v=>s.evidence.scrub(v));else f.remediationStatus=b.status;send(200,{ok:true});return;}
        case 'owner-record':case 'lifecycle':{const f=s.evidence.findings.get(b.findingId);if(!f)throw new Error('Finding not found');await reviewAction(m![2]!,desk.scanProjects.get(s.id)||h?.projectId,f,b,v=>s.evidence.scrub(v));send(200,{ok:true});return;}
        case 'rescan':{const f=s.evidence.findings.get(b.findingId);if(!f)throw new Error('Finding not found');const {affectedResourceUrls}=await import('./retry.js');const urls=affectedResourceUrls(s.view(),f);if(!urls.length)throw new Error('No safe affected public source URL; rescan the approved project seeds');const next=await desk.start({...s.config,urls,deep:false},desk.scanProjects.get(s.id),false,undefined,undefined,{trigger:'rescan',previousRunId:s.id});send(202,{id:next.id,shortId:next.id.slice(0,8)});return;}
        case 'export':{
          if(!['json','html','sarif'].includes(b.format))throw new Error('Unknown report format');if(b.full&&b.confirm!=='sensitive-local-export')throw new Error('Explicit sensitive export confirmation required');
          const out=report(s,b.format,b.full===true);res.writeHead(200,{'Content-Type':b.format==='html'?'text/html; charset=utf-8':'application/json; charset=utf-8','Content-Disposition':`attachment; filename="scan-${s.id}${b.full?'.sensitive':''}.${b.format==='sarif'?'sarif.json':b.format}"`});res.end(out);return;
        }
        // w2-wire: masked submission Markdown for one finding, built server-side from the redacted view (no secrets passed) and re-masked for defence in depth.
        case 'submission':{const v=s.view();const f=v.findings.find(x=>x.id===b.findingId);if(!f)throw new Error('Finding not found');const r=submissionMarkdown([f],v);send(200,masker.redact({markdown:r[0]?.markdown||'',title:r[0]?.title||'',fileName:r[0]?.fileName||''}));return;}
        case 'livecheck':{const f=s.evidence.findings.get(b.findingId);if(!f)throw new Error('Finding not found');const key=s.evidence.reveal(b.findingId).value;const pid=desk.scanProjects.get(s.id)||h?.projectId;send(200,masker.redact(await liveCheckOne(s.config.program,f,key,b.confirm,pid)));return;}
        case 'livecheck-all':{const items=liveCheckItems([...s.evidence.findings.values()],f=>{try{return s.evidence.reveal(f.id).value;}catch{return undefined;}});const pid=desk.scanProjects.get(s.id)||h?.projectId;send(200,masker.redact(liveCheckAll(s.id,s.config.program,items,b.confirm,pid)));return;}
        case 'livecheck-cancel':liveCheckJobs.get(s.id)?.controller.abort();send(200,{ok:true});return;
        default:send(404,{error:'Action not found'});return;
      }
    }catch(e){if(!res.headersSent){if(e instanceof SafeError)send(e.status,{error:e.message,code:e.code,...e.details});else if(isProtectedHostError(e))send(400,{error:e instanceof ProtectedHostError?e.message:PROTECTED_HOST_MESSAGE,code:'protected-host',...(e instanceof ProtectedHostError?{host:e.host}:{})});else send(400,{error:'Request rejected. Check input, scan state and local coverage; raw exception withheld.'});}else res.end();}
  });
  server.requestTimeout=10000;server.headersTimeout=10000;
  async function listen(port:number){await new Promise<void>((resolve,reject)=>{const error=(e:Error)=>reject(e);server.once('error',error);server.listen(port,'127.0.0.1',()=>{server.removeListener('error',error);resolve();});});}
  try{await listen(options.port??4317);}catch(e:any){if(options.portFallback&&e.code==='EADDRINUSE')await listen(0);else throw e;}origin=`http://127.0.0.1:${(server.address() as any).port}`;
  if(options.persistent)await desk.init(options.dataDir,options.syntheticData);
  let closing=false;const close=async()=>{if(closing)return;closing=true;await desk.close();await Promise.allSettled([...jobs]);for(const s of scans.values())s.dispose();scans.clear();masker.clear();await demo?.close();await new Promise<void>(r=>{server.close(()=>r());server.closeIdleConnections();});};
  return {server,origin,token,scans,desk,close};
}


