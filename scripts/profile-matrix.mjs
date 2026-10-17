// Ready-option measurement matrix (2.6, archive/notes/UPGRADE_SCAN_PROFILES_PLAN.md §5): every coverage × traffic option on local HTTPS loopback fixtures (single site, 1.25 MB bundle,
// 3 and 10 subdomains of one registrable domain) on the source build (current, small), and as the baseline an extracted earlier release: the same six ready options on a 2.6.0 or later
// release (prev) or the 2.5.0-rc.1 release with its legacy presets (base). Row ids start with the measured build's version: major.minor for the source build (2.7/…, 2.7-small/…), the
// full version for prev rows (2.6.0/…), 2.5 for base rows. Synthetic, nonfunctional keys; an egress tripwire fails a run that opens any non-loopback socket. One scan per child process (scripts/profile-matrix-case.mjs), one at a time unless --jobs says otherwise. results.jsonl in the work folder keeps
// one row per case, keyed by the build, measurement harness and Node version that produced it, so a run repeats only cases that are missing, failed, or were measured by another build
// or harness; replaced rows move to results-history.jsonl. A serial run also repeats rows measured alongside other cases, so serial numbers can always be had from a plain run.
// Needs a source checkout build (dist/test helpers). Usage: node scripts/profile-matrix.mjs [--work DIR] [--baseline <extracted earlier Windows x64 release folder>] [--jobs N|auto]
//          [--only PATTERNS] [--rerun] [--min-free-mb N] [--timeout-min N] <resources|prev|base|current|small ...>   (v26 is the 2.6 name of current; prev and base need --baseline)
//        node scripts/profile-matrix.mjs [--work DIR] [--baseline DIR] [--jobs N|auto] [--only PATTERNS] [--rerun] status <phases ...>   (what a run would repeat and why; runs nothing)
//        node scripts/profile-matrix.mjs [--work DIR] [--baseline DIR] report   (writes matrix.md and matrix.json in the work folder; --baseline also checks the baseline rows are current)
// Acceptance checks cover the source build's rows; the baseline rows are compared with them (recall) and shown in the table.
// --only takes comma-separated case-id patterns (* matches anything; a pattern without * matches ids containing it). --rerun repeats the selected cases even when current.
// --jobs N (auto: a quarter of the logical cores, at most 4) runs up to N cases at once, longest first, starting another only while --min-free-mb (default 4096) is free. Cases measured
// alongside others can take longer than serial ones, so the report marks them; a run whose computer drops below the app's own small-computer threshold would show in "Settings as recorded".
import {spawn,spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {appendFileSync,existsSync,mkdirSync,readFileSync,renameSync,rmSync,statSync,writeFileSync} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
const project=path.dirname(path.dirname(fileURLToPath(import.meta.url))),argv=process.argv.slice(2),opt=n=>{const i=argv.indexOf('--'+n);if(i<0)return undefined;const v=argv[i+1];argv.splice(i,2);return v;};
const flag=n=>{const i=argv.indexOf('--'+n);if(i<0)return false;argv.splice(i,1);return true;};
const here=path.resolve(opt('work')??path.join(project,'.cache','profile-matrix')),baseDir=opt('baseline'),results=path.join(here,'results.jsonl'),history=path.join(here,'results-history.jsonl'),logs=path.join(here,'logs'),data=path.join(here,'data');
const source=path.join(project,'dist'),base=baseDir&&path.join(path.resolve(baseDir),'dist'),helpers=path.join(project,'dist','test'),caseScript=path.join(project,'scripts','profile-matrix-case.mjs');
// Row labels from the builds' versions, read as text (the build is imported only to key rows): major.minor of the source build, the baseline's full version.
const versionOf=dist=>{try{return /"version"\s*:\s*"([^"]+)"/.exec(readFileSync(path.join(dist,'src','build-info.js'),'utf8'))?.[1];}catch{return undefined;}};
const curLabel=versionOf(source)?.split(/[.-]/).slice(0,2).join('.')??'current',prevLabel=(base&&versionOf(base))||'baseline';
const isCurrent=id=>id.startsWith(curLabel+'/')||id.startsWith(curLabel+'-small/');
const jobsArg=opt('jobs'),only=opt('only')?.split(',').map(s=>s.trim()).filter(Boolean),rerun=flag('rerun'),minFreeMb=Number(opt('min-free-mb')??4096),timeoutMin=Number(opt('timeout-min')??75);
const autoJobs=Math.max(1,Math.min(4,Math.floor(os.availableParallelism()/4))),jobs=jobsArg==null?1:jobsArg==='auto'?autoJobs:Number(jobsArg);
if(!Number.isInteger(jobs)||jobs<1)throw new Error('--jobs takes a whole number of at least 1, or auto');
if(!(minFreeMb>=0)||!(timeoutMin>0))throw new Error('--min-free-mb takes a number of MiB and --timeout-min a positive number of minutes');
if(!process.env.EXPOSURE_DATA_DIR&&argv[0]!=='report'&&argv[0]!=='status')process.env.EXPOSURE_DATA_DIR=data;
mkdirSync(logs,{recursive:true});mkdirSync(data,{recursive:true});
const OPTIONS=[];for(const coverage of ['quick','standard','deep'])for(const traffic of ['normal','low-impact'])OPTIONS.push({coverage,traffic});
const FIXTURES=[{fixture:'single',websites:1},{fixture:'bundle',websites:1},{fixture:'multi',websites:3},{fixture:'multi',websites:10}];
const SMALL={cores:2,freeMemoryMb:1024};
// Baseline phases first, so the report lists the baseline rows above the source build's.
const phases={
  resources:()=>[{id:'resources',mode:'resources',dist:source}],
  prev:()=>FIXTURES.flatMap(f=>OPTIONS.map(o=>({id:`${prevLabel}/${o.coverage}+${o.traffic}/${f.fixture}x${f.websites}`,dist:base,baseline:true,...f,...o}))),
  base:()=>FIXTURES.flatMap(f=>['quick','standard','thorough'].map(preset=>({id:`2.5/${preset}/${f.fixture}x${f.websites}`,dist:base,...f,preset}))),
  current:()=>FIXTURES.flatMap(f=>OPTIONS.map(o=>({id:`${curLabel}/${o.coverage}+${o.traffic}/${f.fixture}x${f.websites}`,dist:source,...f,...o}))),
  small:()=>[...OPTIONS.map(o=>({id:`${curLabel}-small/${o.coverage}+${o.traffic}/bundlex1`,dist:source,fixture:'bundle',websites:1,computer:SMALL,...o})),
    ...OPTIONS.filter(o=>o.traffic==='normal').map(o=>({id:`${curLabel}-small/${o.coverage}+${o.traffic}/multix10`,dist:source,fixture:'multi',websites:10,computer:SMALL,...o}))],
};
Object.defineProperty(phases,'v26',{value:phases.current,enumerable:false});// the 2.6 name, kept for existing commands
const allSpecs=()=>Object.values(phases).flatMap(p=>p());
const pattern=p=>p.includes('*')?new RegExp('^'+p.split('*').map(s=>s.replace(/[.+?^${}()|[\]\\]/g,'\\$&')).join('.*')+'$'):{test:id=>id.includes(p)};
const selected=id=>!only||only.some(p=>pattern(p).test(id));

// What a row was measured with: the build of the dist it scanned, the measurement harness (this case script and the dist/test helpers it loads) and Node.
const digest=files=>{const h=createHash('sha256');for(const f of files)h.update(readFileSync(f)).update('\0');return h.digest('hex').slice(0,16);};
const harness=()=>digest([caseScript,...['virtual-network.js','tls-fixture.js','large-bundle.js'].map(f=>path.join(helpers,f))]);
async function keyFor(dist){const f=path.join(dist,'src','build-info.js');if(!existsSync(f))throw new Error(`no src/build-info.js in ${dist}`);
  return {build:(await import(pathToFileURL(f).href+'?'+statSync(f).mtimeMs)).BUILD.id,harness:harness(),node:process.version};}
// Why a row does not count as current (undefined when it does). Rows from before keys were recorded count when their build matches, since the harness then was not recorded.
// A row measured alongside other cases counts only for a run with at least as many jobs.
function staleness(r,cur,runJobs=Infinity){
  if(r.error)return 'failed: '+String(r.error).split('\n')[0];
  if(!r.key)return r.build===cur.build?undefined:r.build?`measured by build ${r.build}, now ${cur.build}`:'no build recorded';
  if(r.key.build!==cur.build)return `measured by build ${r.key.build}, now ${cur.build}`;
  if(r.key.harness!==cur.harness)return 'measurement harness changed';
  if(r.key.node!==cur.node)return `measured on Node ${r.key.node}, now ${cur.node}`;
  if((r.run?.jobs??1)>runJobs)return `measured alongside other cases (--jobs ${r.run.jobs}); a run with fewer jobs repeats it`;
}

const readRows=f=>existsSync(f)?readFileSync(f,'utf8').split('\n').filter(Boolean).map(l=>JSON.parse(l)):[];
const load=()=>{const m=new Map();for(const r of readRows(results))m.set(r.id,r);return m;};// the last row for an id wins
const replaceFile=(from,to)=>{for(let i=0;;i++)try{return renameSync(from,to);}catch(e){if(i>=20||!['EPERM','EBUSY','EACCES'].includes(e.code))throw e;Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,100);}};
// One row per case: the row it replaces (and any duplicate an older runner appended) moves to results-history.jsonl, and results.jsonl is rewritten whole, never left half written.
function store(row){const all=readRows(results),old=all.filter(r=>r.id===row.id);
  if(old.length)appendFileSync(history,old.map(r=>JSON.stringify({...r,replacedAt:new Date().toISOString()})+'\n').join(''));
  writeFileSync(results+'.tmp',[...all.filter(r=>r.id!==row.id),row].map(r=>JSON.stringify(r)+'\n').join(''));replaceFile(results+'.tmp',results);}
const durations=()=>{const m=new Map();for(const r of [...readRows(history),...readRows(results)])if(r.durationMs)m.set(r.id,r.durationMs);return m;};// the latest time measured for each case
// Wall time for these durations on n lanes, longest first (what the scheduler does).
const lanes=(ms,n)=>{const l=Array(n).fill(0);for(const d of [...ms].sort((a,b)=>b-a))l[l.indexOf(Math.min(...l))]+=d;return Math.max(0,...l);};
const minutes=ms=>`${Math.round(ms/60000)} min`;

async function plan(names){
  if(!names.length)throw new Error('name the phases to run: '+Object.keys(phases).join(', ')+' (or status <phases>, or report)');
  const specs=[];for(const p of names){if(!phases[p])throw new Error(`unknown phase "${p}": use ${Object.keys(phases).join(', ')}, status or report`);for(const s of phases[p]())if(selected(s.id)&&!specs.some(x=>x.id===s.id))specs.push(s);}
  if(specs.some(s=>s.preset||s.baseline)&&!base)throw new Error('--baseline <extracted release folder> is required for the prev phase (2.6.0 or later) and the base phase (2.5.0-rc.1)');
  const keys=new Map();for(const d of new Set(specs.map(s=>s.dist)))keys.set(d,await keyFor(d));
  const have=load();return specs.map(spec=>{const r=have.get(spec.id);return {spec,reason:!r?'not measured yet':rerun?'--rerun':staleness(r,keys.get(spec.dist),jobs)};});}

const running=new Set();
const killTree=c=>{if(c.exitCode!==null||c.signalCode!==null)return;// the case child starts Chromium and gitleaks; take them down with it
  if(process.platform==='win32')spawnSync('taskkill',['/pid',String(c.pid),'/T','/F'],{stdio:'ignore',windowsHide:true});else try{process.kill(-c.pid,'SIGKILL');}catch{c.kill('SIGKILL');}};
function runCase(spec){return new Promise(resolve=>{
  const full={...spec,helpers,dataDir:path.join(data,spec.id.replace(/[^\w.+-]+/g,'_'))},rel=path.relative(data,full.dataDir);
  if(!rel||rel.startsWith('..')||path.isAbsolute(rel))throw new Error(`case data folder outside ${data}: ${full.dataDir}`);
  // A fresh data folder: nothing an earlier run of this case left (browser profile, temporary files) carries over.
  try{rmSync(full.dataDir,{recursive:true,force:true,maxRetries:5,retryDelay:200});}catch(e){console.error(`could not clear ${full.dataDir} (${e.code||e.message}); running in it`);}
  mkdirSync(full.dataDir,{recursive:true});
  const child=spawn(process.execPath,['--expose-gc',caseScript,Buffer.from(JSON.stringify(full)).toString('base64')],{cwd:here,env:{...process.env,EXPOSURE_DATA_DIR:full.dataDir},stdio:['ignore','pipe','pipe'],detached:process.platform!=='win32'});
  running.add(child);let stdout='',stderr='',settled=false,timedOut=false;child.stdout.on('data',d=>stdout+=d);child.stderr.on('data',d=>{if(stderr.length<200000)stderr+=d;});
  const timer=setTimeout(()=>{timedOut=true;stderr+=`\n[profile-matrix] stopped after ${timeoutMin} min\n`;killTree(child);},timeoutMin*60000);
  const finish=(code,err)=>{if(settled)return;settled=true;clearTimeout(timer);running.delete(child);writeFileSync(path.join(logs,full.dataDir.split(path.sep).pop()+'.log'),stderr+'\n'+stdout.slice(-4000));
    const line=stdout.split('\n').find(l=>l.startsWith('RESULT '));resolve(line?JSON.parse(line.slice(7)):{id:spec.id,error:err?`could not start the case: ${err.message}`:timedOut?`stopped after ${timeoutMin} min without a result`:`child exited ${code} without a result`,stderr:stderr.slice(-1500)});};
  child.on('error',e=>finish(null,e));child.on('close',code=>finish(code));});}
const summary=(r,t)=>r.error?'ERROR '+String(r.error).split('\n')[0]:r.mode==='resources'?`${r.rows.length} recorded settings`:`${r.state}${r.completion?'/'+r.completion:''} ${Math.round((Date.now()-t)/1000)}s req=${r.server?.requests} tcp=${r.server?.tcpConnections} recall=${r.recall?.found}/${r.recall?.planted} findings=${r.precision?.findings} rss=${r.peakRssMb}`;
const safeKey=async d=>{try{return await keyFor(d);}catch(e){return {error:e.message};}};

async function run(names){
  const planned=await plan(names),todo=planned.filter(p=>p.reason);
  if(!planned.length)return console.log(`no case matches --only ${only?.join(',')}`);
  if(!todo.length)return console.log(`nothing to run: all ${planned.length} selected cases are current`);
  for(const s of ['SIGINT','SIGTERM','SIGHUP'])process.on(s,()=>{for(const c of running)killTree(c);process.exit(130);});
  // Longest first when several run at once, so the longest case does not start last; resources (no network, seconds) always runs first and alone.
  const last=durations(),known=id=>last.get(id)??Infinity,first=todo.filter(p=>p.spec.mode==='resources'),rest=todo.filter(p=>p.spec.mode!=='resources');
  if(jobs>1)rest.sort((a,b)=>known(b.spec.id)-known(a.spec.id));
  let n=0,failed=0;const t0=Date.now();
  const one=async p=>{const t=Date.now();if(jobs===1)process.stdout.write(p.spec.id+' … ');
    const before=await safeKey(p.spec.dist);let r=await runCase(p.spec);const after=await safeKey(p.spec.dist);
    if(before.error||after.error)r={...r,error:r.error??`could not read the build: ${before.error??after.error}`};
    else if(JSON.stringify(before)!==JSON.stringify(after))r={...r,error:r.error??'the build or measurement harness changed while this case ran; rerun it'};
    store({...r,key:before.error?undefined:before,run:{jobs,startedAt:new Date(t).toISOString()}});n++;if(r.error)failed++;
    console.log((jobs===1?'':p.spec.id+' … ')+summary(r,t)+(jobs===1?'':` (${n}/${todo.length})`));};
  for(const p of first)await one(p);
  await new Promise(done=>{let active=0,wait=null,told=false;const queue=[...rest];
    const pump=()=>{while(queue.length&&active<jobs){const free=os.freemem()/1048576;
        if(active&&free<minFreeMb){if(!told)console.log(`waiting for memory: ${Math.round(free)} MiB free, another case starts at ${minFreeMb} MiB`);told=true;wait??=setTimeout(()=>{wait=null;pump();},5000);return;}
        told=false;active++;one(queue.shift()).catch(e=>{failed++;console.error('runner error:',e);}).finally(()=>{active--;pump();});}
      if(!queue.length&&!active)done();};
    pump();});
  console.log(`ran ${n} of ${planned.length} selected cases (${planned.length-todo.length} already current) in ${minutes(Date.now()-t0)} with --jobs ${jobs}; ${failed} failed`);
}

function status(names){return plan(names).then(planned=>{const last=durations(),todo=planned.filter(p=>p.reason),ms=todo.map(p=>last.get(p.spec.id)).filter(Boolean),unknown=todo.length-ms.length;
  for(const p of todo)console.log(`${p.spec.id} — ${p.reason}`);
  const est=ms.length?`; about ${minutes(lanes(ms,1))} one at a time, ${minutes(lanes(ms,jobs>1?jobs:autoJobs))} with --jobs ${jobs>1?jobs:autoJobs}${unknown?` (${unknown} without an earlier time not counted)`:''}`:'';
  console.log(`${planned.length} selected; ${planned.length-todo.length} current; ${todo.length} to run${est}`);});}

if(argv[0]==='report')await report();else if(argv[0]==='status')await status(argv.slice(1));else await run(argv);

async function report(){
  const have=load(),order=allSpecs().map(s=>s.id),rows=[...order.filter(id=>have.has(id)).map(id=>have.get(id)),...[...have.values()].filter(r=>!order.includes(r.id))],by=new Map(rows.map(r=>[r.id,r]));
  // Freshness: each row against the current build of what it scanned (the baseline rows only with --baseline).
  const distOf=new Map(allSpecs().map(s=>[s.id,s.dist])),cur=new Map();for(const d of new Set([source,base].filter(Boolean)))cur.set(d,await safeKey(d));
  const fresh=rows.map(r=>{const k=cur.get(distOf.get(r.id));return {id:r.id,reason:r.error?'failed: '+String(r.error).split('\n')[0]:!k||k.error?null:staleness(r,k),checked:!!k&&!k.error};});
  const staleIds=new Set(fresh.filter(f=>f.reason&&!f.reason.startsWith('failed')).map(f=>f.id)),together=r=>(r.run?.jobs??1)>1,parallel=rows.filter(together);
  const expected=(r)=>{// keys inside each coverage's stated boundary (single-site copies): Quick crawls no linked pages, Standard reaches depth 3, Deep depth 5; every coverage covers the bundle fixture.
    if(r.preset)return null;if(r.fixture==='bundle')return r.recall.planted;return {quick:6,standard:7,deep:8}[r.coverage]*r.websites;};
  const opt=r=>r.preset?`2.5 ${r.preset}`:`${r.coverage}+${r.traffic}`,pct=(a,b)=>b?Math.round(100*a/b)+'%':'—',mib=b=>(b/1048576).toFixed(2);
  // Analysis heap: builds with analysis processes (2.7 and later) list each role's processes × heap limit and the most heap limit held at once; earlier builds the parser worker's
  // sampled heap peak/limit. Analysis RSS: an upper bound on the analysis processes' combined peak RSS, outside the scan process's peak RSS (— for builds without them).
  const roles=r=>Object.entries(r.analysisChildren?.byRole||{}).map(([role,x])=>`${role} ${x.children}×${x.limits.join('/')}`).join(', ')||'none started';
  const heapOf=r=>{if(r.analysisChildren)return `${roles(r)}; ≤${r.analysisChildren.concurrentHeapMb??'?'} at once`;const w=r.workerHeap||{},sem=Object.entries(w).find(([n])=>/semantic/.test(n));return sem?`${sem[1].peakTotalMb.toFixed(0)}/${(sem[1].limits||[sem[1].limitMb]).join('+')}`:'—';};
  const childRss=r=>r.analysisChildren?String(r.analysisChildren.concurrentPeakRssMb):'—';
  const lines=['| Run | Option | Fixture | State | Time s | Requests | TCP | TLS | Wire MiB | Browser nav | Peak RSS MiB | Analysis heap MiB (worker peak/limit, or processes×limit) | Analysis processes RSS MiB (bound) | Acquisition | Analysis | Recall (in scope) | Precision (credential findings) | Est. conns |','|'+'---|'.repeat(18)];
  for(const r of rows.filter(r=>r.mode==='scan')){const c=r.coverageView||{};
    lines.push(`| ${r.id.split('/')[0]} | ${opt(r)} | ${r.fixture}×${r.websites} | ${r.error?'error':r.state+(r.completion?' ('+r.completion+')':'')}${staleIds.has(r.id)?' · stale':''}${together(r)?' · alongside':''} | ${(r.durationMs/1000).toFixed(1)} | ${r.server.requests} | ${r.server.tcpConnections} | ${r.server.tlsHandshakes} | ${mib(r.server.wireBytes)} | ${r.browser?.navigations??'—'} | ${r.peakRssMb} | ${heapOf(r)} | ${childRss(r)} | ${pct(c.downloaded,c.discovered)} | ${pct(c.analyzed,c.downloaded)} | ${r.recall.found}/${r.recall.planted} ${expected(r)==null?'':` (${expected(r)} expected)`} | ${r.precision.matched}/${r.precision.findings}${r.precision.decoysReported?' decoys '+r.precision.decoysReported:''} | ${r.estimate?.connections??'—'} |`);}
  const fr=[...[...cur].map(([d,k])=>`- ${d===base?prevLabel+' baseline':curLabel+' source build'}: ${k.error?`not checked (${k.error})`:`${k.build}, harness ${k.harness}, Node ${k.node}`}`),
    ...(base?[]:['- baseline rows not checked: run report with --baseline <extracted release folder>']),
    `- ${fresh.filter(f=>f.checked&&!f.reason).length} of ${rows.length} rows current; ${staleIds.size} stale; ${fresh.filter(f=>f.reason?.startsWith('failed')).length} failed; ${parallel.length} measured alongside other cases ("alongside": their times can be longer than a serial run's)`,
    ...fresh.filter(f=>f.reason).map(f=>`- ${f.id}: ${f.reason}`)];
  // Resource use as recorded (no network): what each option used for 1, 3 and 10 websites on this computer and on an injected small computer; * marks a lowered value.
  const res=rows.find(r=>r.mode==='resources'),ru=[];
  if(res){const cols=[...new Set(res.rows.map(x=>x.computer+'|'+x.websites))],cell=x=>{const u=x.resourceUse?.used||{},low=new Set((x.resourceUse?.adjustments||[]).map(a=>a.setting)),m=(k,t)=>`${u[k]}${low.has(k)?'*':''}${t}`;return `${m('websitesAtOnce','')} / ${m('browserWebsitesAtOnce','')} / ${m('analysisMemoryMb',' MiB')} / ${m('analysisWorkers','')}`;};
    ru.push(`| Option (websites at once / browser websites / analysis memory / workers) | ${cols.map(c=>{const [comp,n]=c.split('|');return `${comp==='this computer'?'This computer':'Small computer'}, ${n} website${n==='1'?'':'s'}`;}).join(' | ')} |`,'|'+'---|'.repeat(cols.length+1));
    for(const o of OPTIONS)ru.push(`| ${o.coverage}+${o.traffic} | ${cols.map(c=>{const x=res.rows.find(x=>x.computer+'|'+x.websites===c&&x.coverage===o.coverage&&x.traffic===o.traffic);return x?cell(x):'—';}).join(' | ')} |`);
    const comp=res.rows.find(x=>x.computer==='this computer')?.resourceUse?.computer;if(comp)ru.push('',`This computer: ${comp.cores} logical cores, ${(comp.freeMemoryMb/1024).toFixed(1)} GiB free memory when recorded. Small computer: 2 cores and 1 GiB free memory, injected.`);}
  // Acceptance checks
  const checks=[],get=(v,o,f)=>by.get(`${v}/${o}/${f}`);
  for(const f of FIXTURES.map(f=>`${f.fixture}x${f.websites}`))for(const c of ['quick','standard','deep']){const n=get(curLabel,c+'+normal',f),l=get(curLabel,c+'+low-impact',f);if(!n||!l)continue;
    // Quick has no query variants or adjacent source-map guesses to leave out (and retries are rare on loopback), so Low-impact sends the same requests over far fewer connections;
    // Normal may send fewer when its soft deadline deferred work (origin-soft-deadline gaps). Standard and Deep must send fewer requests.
    const deferred=(x)=>(x.incompleteGaps||[]).filter(([g])=>g==='origin-soft-deadline').reduce((a,[,k])=>a+k,0);
    if(c==='quick')checks.push({check:`Low-impact fewer connections than Normal, requests no more than Normal's — ${c} ${f}`,pass:l.server.requests<=n.server.requests+deferred(n)&&l.server.tcpConnections<n.server.tcpConnections,detail:`requests ${l.server.requests} vs ${n.server.requests}${deferred(n)?` (+${deferred(n)} Normal deferred at its soft deadline)`:''}; TCP ${l.server.tcpConnections} vs ${n.server.tcpConnections}`});
    else checks.push({check:`Low-impact fewer requests and connections than Normal — ${c} ${f}`,pass:l.server.requests<n.server.requests&&l.server.tcpConnections<n.server.tcpConnections,detail:`requests ${l.server.requests} vs ${n.server.requests}; TCP ${l.server.tcpConnections} vs ${n.server.tcpConnections}`});
    if(c==='deep')checks.push({check:`Deep+Low-impact keeps Deep+Normal recall — ${f}`,pass:l.recall.found>=n.recall.found,detail:`${l.recall.found}/${l.recall.planted} vs ${n.recall.found}/${n.recall.planted}`});}
  for(const f of FIXTURES.map(f=>`${f.fixture}x${f.websites}`))for(const t of ['normal','low-impact']){const q=get(curLabel,'quick+'+t,f),s=get(curLabel,'standard+'+t,f),d=get(curLabel,'deep+'+t,f);if(!q||!s||!d)continue;
    checks.push({check:`Quick reports its limits — ${t} ${f}`,pass:(q.state==='completed'?/quick/i.test(q.stage||'')&&q.completion==='quick-coverage':q.state==='incomplete')&&!!q.statedLimits?.includes('quick-coverage-boundary'),detail:`${q.state}, stage "${q.stage}"; stated limits: ${q.statedLimits?.join(', ')||'none'}; not examined: ${q.notExamined?.join(', ')||'none listed'}; gaps ${q.incompleteGaps?.map(([c,n])=>c+' ×'+n).join(', ')||'none'}`});
    checks.push({check:`Quick fastest — ${t} ${f}`,pass:q.durationMs<=s.durationMs&&q.durationMs<=d.durationMs,detail:`${(q.durationMs/1000).toFixed(1)} s vs Standard ${(s.durationMs/1000).toFixed(1)} s, Deep ${(d.durationMs/1000).toFixed(1)} s${[q,s,d].some(together)?' (some measured alongside other cases)':''}`});}
  const scans=rows.filter(r=>r.mode==='scan'&&!r.preset&&isCurrent(r.id));
  for(const r of scans){const o=r.resourceUse?.option||{},h=Object.entries(r.workerHeap||{});
    const u=r.resourceUse?.used||{},heapOk=h.every(([n,x])=>x.peakTotalMb<=512&&(x.limitMb==null||x.peakUsedMb<=x.limitMb*1.05)),sem=h.find(([n])=>/semantic/.test(n));
    // A parser worker gets the option's analysis memory split across its workers; one oversized dependency group may use the whole allowance alone.
    const split=l=>[Math.floor(u.analysisMemoryMb/u.analysisWorkers),u.analysisMemoryMb].includes(l),optionOk=u.analysisMemoryMb<=o.analysisMemoryMb&&o.analysisMemoryMb<=512;
    const memOk=!sem||(sem[1].limits||[sem[1].limitMb]).every(l=>l<=u.analysisMemoryMb&&optionOk&&split(l));
    // Analysis processes (2.7 and later): parser limits split the same way, every limit within the setting, the limits held at once within it, and none ran out of memory.
    const ch=r.analysisChildren,byRole=Object.values(ch?.byRole||{}),childOk=!ch||(optionOk&&byRole.every(x=>x.limits.every(l=>l<=u.analysisMemoryMb)&&!x.outOfMemory)&&(ch.byRole.parser?.limits||[]).every(split)&&(ch.concurrentHeapMb??Infinity)<=u.analysisMemoryMb);
    const heapText=ch?`analysis processes ${roles(r)} MiB, at most ${ch.concurrentHeapMb} MiB of heap limits at once of ${u.analysisMemoryMb} MiB for ${u.analysisWorkers} parser worker${u.analysisWorkers===1?"":"s"}; out of memory ${byRole.reduce((n,x)=>n+x.outOfMemory,0)}; their RSS ≤${ch.concurrentPeakRssMb} MiB outside the setting`
      :`parser worker heap ${sem?sem[1].peakTotalMb.toFixed(0)+' MiB of '+(sem[1].limits||[sem[1].limitMb]).join('/')+' MiB per worker, '+u.analysisMemoryMb+' MiB for '+u.analysisWorkers+' workers':'—'}`;
    checks.push({check:`Within limits — ${r.id}`,pass:!r.error&&heapOk&&memOk&&childOk&&(r.server.peakWebsitesInFlight??0)<=(u.websitesAtOnce??0)&&(r.browser.peakBrowserOrigins??0)<=(o.browserWebsitesAtOnce??0)&&r.peakRssMb<4096&&r.egressViolations.length===0,
      detail:`${heapText}; browser websites ${r.browser.peakBrowserOrigins??0} ≤ ${o.browserWebsitesAtOnce}; websites in flight ${r.server.peakWebsitesInFlight} ≤ ${u.websitesAtOnce} used (option ${o.websitesAtOnce}); RSS ${r.peakRssMb} MiB; egress violations ${r.egressViolations.length}`});
    checks.push({check:`Finds its keys at its memory setting — ${r.id}`,pass:r.recall.found>=expected(r)&&!(r.memoryGaps||[]).length,detail:`${r.recall.found}/${expected(r)} in scope (${r.recall.planted} planted); missing: ${r.recall.missing.join(', ')||'none'}; memory gaps ${(r.memoryGaps||[]).join(',')||'none'}`});
    // The same option and fixture on the previous release (prev rows): recall must not drop.
    const p=by.get(r.id.replace(curLabel+'/',prevLabel+'/'));if(base&&p&&p.id!==r.id&&!p.error)checks.push({check:`Keeps the ${prevLabel} recall — ${r.id}`,pass:r.recall.found>=p.recall.found,detail:`${r.recall.found}/${r.recall.planted} vs ${p.recall.found}/${p.recall.planted}; scan-process peak RSS ${r.peakRssMb} vs ${p.peakRssMb} MiB; ${(r.durationMs/1000).toFixed(1)} vs ${(p.durationMs/1000).toFixed(1)} s`});}
  if(res)for(const x of res.rows){const adj=x.resourceUse?.adjustments||[];checks.push({check:`Adjustment only lowers — ${x.coverage}+${x.traffic} ${x.websites} websites, ${x.computer}`,pass:adj.every(a=>a.to<=a.from),detail:adj.map(a=>`${a.setting} ${a.from}→${a.to}`).join('; ')||'none'});}
  // Each scan used the settings the resources phase recorded for its option, website count and computer: a scan that found less free memory (other cases or programs) and lowered them shows here.
  if(res)for(const r of scans.filter(r=>!r.error)){const x=res.rows.find(x=>x.computer===r.computer&&x.websites===r.websites&&x.coverage===r.coverage&&x.traffic===r.traffic);if(!x)continue;
    const a=r.resourceUse?.used||{},b=x.resourceUse?.used||{},diff=[...new Set([...Object.keys(a),...Object.keys(b)])].filter(k=>a[k]!==b[k]),free=r.resourceUse?.computer?.freeMemoryMb;
    checks.push({check:`Settings as recorded — ${r.id}`,pass:!diff.length,detail:diff.length?`${diff.map(k=>`${k} ${a[k]} (recorded ${b[k]})`).join('; ')}${free!=null?`; ${free} MiB free when the scan started`:''}`:'same as the resources phase'});}
  writeFileSync(path.join(here,'matrix.md'),`# P4 measurement matrix (generated ${new Date().toISOString()})\n\n${lines.join('\n')}\n\n## Freshness\n\n${fr.join('\n')}\n\n## Resource use (recorded, no network)\n\n${ru.join('\n')}\n\n## Acceptance checks\n\n${checks.map(c=>`- ${c.pass?'PASS':'FAIL'} ${c.check}: ${c.detail}`).join('\n')}\n`);
  writeFileSync(path.join(here,'matrix.json'),JSON.stringify({schema:'exposure-profile-matrix/1',generatedAt:new Date().toISOString(),tables:{runs:lines,resourceUse:ru},labels:{source:curLabel,baseline:base?prevLabel:null},freshness:{current:Object.fromEntries([...cur].map(([d,k])=>[d===base?'base':'source',k])),rows:fresh.filter(f=>f.reason),alongside:parallel.map(r=>r.id)},checks,rows},null,1));
  console.log(`rows ${rows.length}; checks ${checks.length}; failing ${checks.filter(c=>!c.pass).length}${staleIds.size?`; stale ${staleIds.size}`:''}${fresh.some(f=>f.reason?.startsWith('failed'))?`; failed ${fresh.filter(f=>f.reason?.startsWith('failed')).length}`:''}`);for(const c of checks.filter(c=>!c.pass))console.log('FAIL',c.check,'—',c.detail);
}
