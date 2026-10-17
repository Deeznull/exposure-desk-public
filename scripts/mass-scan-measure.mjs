// Mass-scan measurement (2.8.0). Runs the built command line (`dist/src/cli.js scan --targets …`) the way a user does, against local loopback fixtures only, with synthetic,
// nonfunctional keys. Never a real host: the fixture answers on 127.0.0.0/8, the template allows exactly its origins, and the scan process carries an egress tripwire
// (scripts/mass-scan-preload.mjs) that refuses and records any other socket or DNS lookup.
//
// Fixture: 50 loopback origins (127.0.0.1 … 127.0.0.50 on one port; 50 ports on 127.0.0.1 if the computer cannot bind them). Target i is page /t<n> of origin i mod 50,
// so neighbouring targets are different websites. Each page holds its own key inline and loads the origin's /static/app.js, whose key every target of that origin
// shares (cross-target de-duplication). Everything else answers 404. The block fixture makes 2 of every 5 origins answer every request with HTTP 429 or 403.
//
// Runs (all with --state, so every run is in mass mode and they compare like with like; --fail-on never; --jsonl --silent):
//   c1, c4, c16       --authorized, --concurrency 1 / 4 / 16
//   program-c64       a program file (authorized, scope = the fixture origins, 50 requests per second, 64 targets and 64 requests at once), --concurrency 64
//   resume-reader     c4 interrupted by closing its output reader after 40 % of the targets ended, then the same command again
//   resume-kill       c4 ended by a forced process kill after 40 % of the targets ended, then the same command again
//                     (c4, not c16: a resume only skips targets that completed. Before the w5-fix shared-wait change, quick targets at 16 at once ran
//                     out of their per-website time allowance while waiting for the shared analysis, which left nothing to skip; c4 keeps the rows comparable)
//   block-halt        c16 against the block fixture
//   large-c1, large-c4, large-c16
//                     the large-bundle fixture (2.9): --large-targets targets (16) with the Recommended ready option (Standard + Normal), --authorized,
//                     --concurrency 1 / 4 / 16. Each origin's /static/app.js is then its own ~1.25 MB bundle built from the frozen G5 corpus bundle
//                     (scripts/eval-2.5-corpus.mjs) with the origin's number and key in front, so no two targets serve the same text (the detector's result
//                     cache and the discovery memo of texts acorn rejects cannot share work between targets); even origins serve it with its syntax error
//                     corrected (it parses), odd origins the frozen broken text (both parses fail). The scan process's peak must stay within the 512 MiB
//                     ready-option ceiling; a row over it is reported and fails the measurement (exit code 1), as an egress violation does.
//   extra rows with --extra coverage:traffic:concurrency:targets (for example standard:normal:4:200)
// Per run: wall time, requests and requests per second at the fixture, targets per second, the scan process's peak RSS, the analysis memory budget(s) the scans drew
// from (capacity and peak), the analysis child processes' heap limits held at once and peak RSS, recall of the planted keys by location, the JSON Lines summary.
//
// usage: node scripts/mass-scan-measure.mjs [--out FILE] [--work DIR] [--targets N] [--block-targets N] [--large-targets N] [--coverage quick] [--traffic normal] [--only name,…] [--extra c:t:n:targets]… [--keep-reports]
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {createHash} from 'node:crypto';
import {existsSync,readFileSync} from 'node:fs';
import {mkdir,readFile,rm,writeFile} from 'node:fs/promises';
import {fileURLToPath,pathToFileURL} from 'node:url';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const argv=process.argv.slice(2),opt=(name,fallback)=>{const i=argv.indexOf('--'+name);return i>=0?argv[i+1]:fallback;},all=name=>argv.flatMap((a,i)=>a==='--'+name?[argv[i+1]]:[]),flag=name=>argv.includes('--'+name);
const dataRoot=process.env.EXPOSURE_DATA_DIR&&path.isAbsolute(process.env.EXPOSURE_DATA_DIR)?process.env.EXPOSURE_DATA_DIR:path.join(root,'.cache');
const out=path.resolve(opt('out',path.join(root,'benchmarks','mass-scan.json'))),work=path.resolve(opt('work',path.join(dataRoot,'mass-scan-measure')));
const TARGETS=Number(opt('targets',1000)),BLOCK_TARGETS=Number(opt('block-targets',200)),COVERAGE=opt('coverage','quick'),TRAFFIC=opt('traffic','normal'),ORIGINS=50,only=opt('only')?.split(',');
const LARGE_TARGETS=Number(opt('large-targets',16)),READY_CEILING_MB=512;
const INTERRUPT_SHARE=0.4,BLOCKED=k=>k%5<2,keepReports=flag('keep-reports');
if(!(Number.isInteger(TARGETS)&&TARGETS>=ORIGINS&&Number.isInteger(BLOCK_TARGETS)&&BLOCK_TARGETS>=ORIGINS))throw new Error('--targets and --block-targets must be whole numbers of at least '+ORIGINS);
if(!(Number.isInteger(LARGE_TARGETS)&&LARGE_TARGETS>=1&&LARGE_TARGETS<=ORIGINS))throw new Error('--large-targets must be a whole number from 1 to '+ORIGINS+' (one target per origin, so every target has its own bundle)');
const cli=path.join(root,'dist','src','cli.js'),preload=path.join(root,'scripts','mass-scan-preload.mjs');
if(!existsSync(cli))throw new Error('Build first: npm run build');
const build=JSON.parse(readFileSync(path.join(root,'BUILD_INFO.json'),'utf8')).build?.id;
const key=label=>'sk-proj-'+createHash('sha512').update('ExposureDesk/w4-mass/1/'+label).digest('base64url').slice(0,64).replace(/[-_]/g,'Q');

// ---- large-bundle fixture: origin k's own ~1.25 MB bundle (the frozen G5 text; for even k with its syntax error corrected, so it parses) ----------------------
let g5Text;const bundles=new Map(),G5_BREAK='}});\nn.u=',G5_FIXED='}}]);\nn.u=';
async function loadG5(){if(g5Text)return;g5Text=(await import(pathToFileURL(path.join(root,'scripts','eval-2.5-corpus.mjs')).href)).corpus().groups.G5.bundle.text;if(g5Text.split(G5_BREAK).length!==2)throw new Error('the G5 bundle changed: its one syntax error is not where the large-bundle fixture expects it');}
const parseableBundle=k=>k%2===0;
function largeBundle(k,host){let b=bundles.get(k);if(!b){b=`/* mass-scan-measure origin ${k} */var __massMeasure={apiKey:${JSON.stringify(key(host+'/app'))}};\n`+(parseableBundle(k)?g5Text.replace(G5_BREAK,G5_FIXED):g5Text);bundles.set(k,b);}return b;}
const largeInfo=targets=>{const ks=Array.from({length:Math.min(targets,ORIGINS)},(_,k)=>k);return {bytes:[...new Set(ks.map(k=>Buffer.byteLength(largeBundle(k,new URL(fixture.origins[k]).host))))].sort((x,y)=>x-y),parseable:ks.filter(parseableBundle).length,broken:ks.filter(k=>!parseableBundle(k)).length};};

// ---- loopback fixture -------------------------------------------------------------------------------------------------------------------------------------------
const fixture={servers:[],origins:[],addressing:'',block:false,large:false,arrivals:new Map(),userAgents:new Set(),requests:0,inflight:0,peakInflight:0,firstAt:0,lastAt:0};
const reset=(block,large=false)=>{fixture.block=block;fixture.large=large;fixture.arrivals=new Map();fixture.userAgents=new Set();fixture.requests=0;fixture.peakInflight=0;fixture.firstAt=0;fixture.lastAt=0;};
function handler(k){
  const host=()=>new URL(fixture.origins[k]).host;
  return (req,res)=>{
    const p=(req.url||'/').split('?')[0],now=Date.now();fixture.requests++;fixture.firstAt||=now;fixture.lastAt=now;fixture.userAgents.add(String(req.headers['user-agent']||''));
    const id=k+' '+p;fixture.arrivals.set(id,(fixture.arrivals.get(id)||0)+1);fixture.inflight++;fixture.peakInflight=Math.max(fixture.peakInflight,fixture.inflight);
    let ended=false;const end=()=>{if(!ended){ended=true;fixture.inflight--;}};res.on('close',end);res.on('finish',end);
    if(fixture.block&&BLOCKED(k)){res.writeHead(k%2?429:403,{'content-type':'text/plain'});res.end(k%2?'Too many requests':'Forbidden');return;}
    const page=/^\/t(\d+)$/.exec(p);
    if(p==='/robots.txt'){res.writeHead(200,{'content-type':'text/plain'});res.end('User-agent: *\nAllow: /\n');}
    else if(p==='/static/app.js'&&fixture.large){res.writeHead(200,{'content-type':'text/javascript'});res.end(largeBundle(k,host()));}
    else if(p==='/static/app.js'){res.writeHead(200,{'content-type':'text/javascript'});res.end(`const client={apiKey:${JSON.stringify(key(host()+'/app'))}};\n`);}
    else if(page){res.writeHead(200,{'content-type':'text/html'});res.end(`<!doctype html><html><head><title>Target ${page[1]}</title><script>window.S={openai:${JSON.stringify(key(host()+'/t'+page[1]))}}</script><script src="/static/app.js"></script></head><body><p>Synthetic mass-scan fixture.</p></body></html>`);}
    else{res.writeHead(404,{'content-type':'text/plain'});res.end('not found');}
  };
}
const listen=(server,port,host)=>new Promise((resolve,reject)=>{const fail=e=>{server.off('listening',ok);reject(e);},ok=()=>{server.off('error',fail);resolve(server.address().port);};server.once('error',fail);server.once('listening',ok);server.listen(port,host);});
async function startFixture(){
  const make=k=>{const s=http.createServer(handler(k));s.keepAliveTimeout=5000;return s;};
  try{
    const first=make(0),port=await listen(first,0,'127.0.0.1');fixture.servers.push(first);fixture.origins.push(`http://127.0.0.1:${port}`);
    for(let k=1;k<ORIGINS;k++){const s=make(k);await listen(s,port,`127.0.0.${k+1}`);fixture.servers.push(s);fixture.origins.push(`http://127.0.0.${k+1}:${port}`);}
    fixture.addressing=`127.0.0.1 to 127.0.0.${ORIGINS}, one port`;
  }catch{
    await stopFixture();fixture.servers=[];fixture.origins=[];
    for(let k=0;k<ORIGINS;k++){const s=make(k),port=await listen(s,0,'127.0.0.1');fixture.servers.push(s);fixture.origins.push(`http://127.0.0.1:${port}`);}
    fixture.addressing=`127.0.0.1, ${ORIGINS} ports`;
  }
}
async function stopFixture(){await Promise.all(fixture.servers.map(s=>new Promise(r=>{s.close(()=>r());s.closeAllConnections?.();})));}
const targetUrl=i=>`${fixture.origins[i%ORIGINS]}/t${Math.floor(i/ORIGINS)}`;

// ---- one CLI run ------------------------------------------------------------------------------------------------------------------------------------------------
function runCli(dir,args,{interruptAfter,interrupt}={}){
  return new Promise((resolve,reject)=>{
    const env={...process.env,EXPOSURE_DATA_DIR:path.join(dir,'data'),MASS_MEASURE_OUT:path.join(dir,'process.json')};delete env.EXPOSURE_ANALYSIS_TIME_FACTOR;delete env.NODE_OPTIONS;
    const t0=performance.now(),child=spawn(process.execPath,['--import',pathToFileURL(preload).href,cli,'scan',...args],{cwd:dir,env,windowsHide:true,stdio:['ignore','pipe','pipe']});
    const events=[];let buffer='',stderr='',ended=0,interruptedAt=null;
    const stop=()=>{if(interruptedAt!=null)return;interruptedAt=Math.round(performance.now()-t0);if(interrupt==='kill')child.kill('SIGKILL');else child.stdout.destroy();};
    child.stdout.on('data',d=>{buffer+=d;let n;while((n=buffer.indexOf('\n'))>=0){const line=buffer.slice(0,n);buffer=buffer.slice(n+1);if(!line.trim())continue;let e;try{e=JSON.parse(line);}catch{continue;}events.push(e);
      if(e.event==='target-end'&&++ended>=interruptAfter)stop();}});
    child.stdout.on('error',()=>{});child.stderr.on('data',d=>{if(stderr.length<20000)stderr+=d;});
    const timer=setTimeout(()=>child.kill('SIGKILL'),4*3600*1000);
    child.on('error',reject);
    child.on('close',(code,signal)=>{clearTimeout(timer);resolve({code,signal,wallMs:Math.round(performance.now()-t0),events,stderr:stderr.trim().slice(0,4000),interruptedAt});});
  });
}
const isAlive=pid=>{try{process.kill(pid,0);return true;}catch{return false;}};
const wait=ms=>new Promise(r=>setTimeout(r,ms));

async function prepare(name,{targets,program}){
  const dir=path.join(work,name);await rm(dir,{recursive:true,force:true});await mkdir(path.join(dir,'data'),{recursive:true});await mkdir(path.join(dir,'reports'),{recursive:true});
  const list=path.join(dir,'targets.txt'),tpl=path.join(dir,'template.json');
  await writeFile(list,Array.from({length:targets},(_,i)=>targetUrl(i)).join('\n')+'\n');
  await writeFile(tpl,JSON.stringify({privateOrigins:fixture.origins,browser:false}));
  let programDir;if(program){programDir=path.join(dir,'program');await mkdir(programDir,{recursive:true});
    await writeFile(path.join(programDir,'program.json'),'// Synthetic loopback measurement program\n'+JSON.stringify({schema:'exposure-program/1',name:'mass-measure',authorized:true,scope:{in:fixture.origins.map(o=>o+'/')},rate:{requestsPerSecond:50},concurrency:{targets:64,requests:64}},null,1));}
  return {dir,list,tpl,programDir,state:path.join(dir,'run.state')};
}
const cliArgs=(p,{coverage,traffic,concurrency,program})=>['--targets',p.list,'--config',p.tpl,'--coverage',coverage,'--traffic',traffic,'--state',p.state,'--concurrency',String(concurrency),'--jsonl','--silent','--fail-on','never','--output',path.join(p.dir,'reports','r.json'),...(program?['--program',p.programDir]:['--authorized'])];

// Recall by location: a target's own key is found at its page, the shared key at its origin's /static/app.js.
function analyse(events,targets){
  const of=e=>events.filter(x=>x.event===e),urls=Array.from({length:targets},(_,i)=>targetUrl(i));
  const inline=new Set(),shared=new Set(),unexpected=[];let duplicates=0;
  for(const f of of('finding')){const i=f.target-1,locations=(f.locations||[]).map(l=>String(l.url).split('#')[0]);if(f.duplicateOf!=null)duplicates++;
    if(locations.includes(urls[i]))inline.add(i);else if(locations.some(u=>u===fixture.origins[i%ORIGINS]+'/static/app.js'))shared.add(i%ORIGINS);else unexpected.push({target:f.target,rule:f.rule,locations});}
  const ends=of('target-end'),statuses={},stops={};for(const e of ends){statuses[e.status]=(statuses[e.status]||0)+1;stops[e.stopReason??'none']=(stops[e.stopReason??'none']||0)+1;}
  const summary=of('summary')[0]??null;
  return {targetStarts:of('target-start').length,targetEnds:ends.length,targetStatuses:statuses,stopReasons:stops,findingEvents:of('finding').length,duplicateEvents:duplicates,
    inlineKeysFound:inline.size,sharedKeysFound:shared.size,unexpectedFindings:unexpected.length,unexpectedSample:unexpected.slice(0,5),
    summary:summary&&{targets:summary.targets,scanned:summary.scanned,notStarted:summary.notStarted,skipped:summary.skipped,interrupted:summary.interrupted,exit:summary.exit,concurrency:summary.concurrency,statuses:summary.statuses,halted:summary.halted,uniqueFindings:summary.uniqueFindings,sharedFindings:Array.isArray(summary.sharedFindings)?summary.sharedFindings.length:summary.sharedFindings,findings:summary.findings,program:summary.program??null,effectiveConcurrency:summary.effectiveConcurrency??null,sharedWaitMs:summary.sharedWaitMs??null,sharedWaitByCause:summary.sharedWaitByCause??null,memoryGate:summary.memory??null},
    inline,ended:new Set(ends.map(e=>e.target-1))};
}
async function processStats(dir){try{return JSON.parse(await readFile(path.join(dir,'process.json'),'utf8'));}catch{return null;}}
const pageArrivals=i=>fixture.arrivals.get((i%ORIGINS)+' /t'+Math.floor(i/ORIGINS))||0;

async function measure(name,{targets=TARGETS,coverage=COVERAGE,traffic=TRAFFIC,concurrency,program=false,block=false,large=false}){
  if(large)await loadG5();
  const p=await prepare(name,{targets,program});reset(block,large);
  const r=await runCli(p.dir,cliArgs(p,{coverage,traffic,concurrency,program})),stats=await processStats(p.dir),a=analyse(r.events,targets);
  const row=describe(name,{targets,coverage,traffic,concurrency,program,block,...(large?{largeBundle:largeInfo(targets)}:{})},r,stats,a);
  if(large)row.withinReadyCeiling=row.peakRssMb!=null&&row.peakRssMb<=READY_CEILING_MB;
  if(!keepReports)await rm(path.join(p.dir,'reports'),{recursive:true,force:true});
  return row;
}
function describe(name,settings,r,stats,a){
  const seconds=r.wallMs/1000,{inline,ended,...view}=a;
  const memory=stats&&{peakRssMb:stats.peakRssMb,maxRssMb:stats.maxRssMb,cpuMs:stats.cpuMs,scans:stats.scans,analysisBudgets:stats.analysisBudgets,analysisChildren:{...stats.analysisChildren,pids:undefined},timeFactor:stats.timeFactor,egressViolations:stats.egressViolations,final:stats.final};
  const b=stats?.analysisBudgets,c=stats?.analysisChildren,cap=b?.capacities?.length===1?b.capacities[0]:null;
  return {name,...settings,exit:r.code,signal:r.signal,wallMs:r.wallMs,requests:fixture.requests,requestsPerSecond:+(fixture.requests/seconds).toFixed(1),targetsPerSecond:+((a.summary?.scanned??a.targetEnds)/seconds).toFixed(2),
    peakConnectionsInFlight:fixture.peakInflight,userAgents:fixture.userAgents.size,...memory,
    budgetCheck:stats?{oneSharedBudget:b.distinct===1,capacityMb:cap,peakMb:b.peak,peakWithinCapacity:cap!=null&&b.peak<=cap,concurrentChildHeapMb:c.concurrentHeapMb,childHeapWithinCapacity:cap!=null&&c.concurrentHeapMb<=cap,readyOptionCeiling:cap!=null&&cap<=512}:null,
    ...view,stderr:r.stderr||undefined};
}

async function resume(name,{interrupt,targets=TARGETS,coverage=COVERAGE,traffic=TRAFFIC,concurrency=4}){
  const p=await prepare(name,{targets});const args=cliArgs(p,{coverage,traffic,concurrency});
  reset(false);const first=await runCli(p.dir,args,{interruptAfter:Math.round(targets*INTERRUPT_SHARE),interrupt}),firstStats=await processStats(p.dir),a1=analyse(first.events,targets);
  const firstRequests=fixture.requests,firstPages=new Map(Array.from({length:targets},(_,i)=>[i,pageArrivals(i)]));
  // After a forced kill the analysis children must end with their parent (they exit when the IPC channel closes).
  await wait(5000);const childPids=firstStats?.analysisChildren?.pids||[],orphans=childPids.filter(isAlive);
  let saved;try{saved=JSON.parse(await readFile(p.state,'utf8'));}catch(e){saved={error:String(e)};}
  const done=new Set((saved.targets||[]).filter(t=>t.status==='done').map(t=>t.index));
  reset(false);const second=await runCli(p.dir,args),secondStats=await processStats(p.dir),a2=analyse(second.events,targets);
  const rescannedDone=[...done].filter(i=>pageArrivals(i)>0),startedDone=second.events.filter(e=>e.event==='target-start'&&done.has(e.target-1)).length;
  // Recall over both runs from the per-target JSON reports (a target finished by the first run keeps its first-run report; the resumed run writes the others), so a
  // target that finished after the output reader closed still counts.
  const reportFound=async i=>{try{const v=JSON.parse(await readFile(path.join(p.dir,'reports',`r-${i+1}.json`),'utf8'));return (v.findings||[]).some(f=>(f.occurrences||[]).some(o=>String(o.url).split('#')[0]===targetUrl(i)));}catch{return false;}};
  let foundEither=0;for(let i=0;i<targets;i++)if(a1.inline.has(i)||a2.inline.has(i)||await reportFound(i))foundEither++;
  const row={name,targets,coverage,traffic,concurrency,interrupt:interrupt==='kill'?'forced process kill':'output reader closed',interruptAfterTargetEnds:Math.round(targets*INTERRUPT_SHARE),
    first:{exit:first.code,signal:first.signal,wallMs:first.wallMs,interruptedAtMs:first.interruptedAt,requests:firstRequests,targetEndsSeen:a1.targetEnds,stateReadable:!saved.error,stateDone:done.size,stateStatuses:countBy(saved.targets||[],t=>t.status),peakRssMb:firstStats?.peakRssMb,analysisChildren:firstStats?.analysisChildren?.spawned,orphanedAnalysisProcesses:orphans.length},
    second:describe(name+' (resume)',{targets,coverage,traffic,concurrency},second,secondStats,a2),
    checks:{firstRunDone:done.size>0,skippedEqualsDone:a2.summary?.skipped===done.size,doneTargetsStarted:startedDone,doneTargetPagesRequested:rescannedDone.length,accounted:a2.summary?a2.summary.scanned+a2.summary.notStarted+a2.summary.skipped===targets:false,
      inlineKeysFoundAcrossBoth:foundEither,noOrphans:orphans.length===0,firstPagesRequested:[...firstPages.values()].filter(n=>n>0).length}};
  if(!keepReports)await rm(path.join(p.dir,'reports'),{recursive:true,force:true});
  return row;
}
const countBy=(list,f)=>list.reduce((m,x)=>{const k=f(x);m[k]=(m[k]||0)+1;return m;},{});

await mkdir(work,{recursive:true});await startFixture();
const plan=[
  ['c1',()=>measure('c1',{concurrency:1})],
  ['c4',()=>measure('c4',{concurrency:4})],
  ['c16',()=>measure('c16',{concurrency:16})],
  ['program-c64',()=>measure('program-c64',{concurrency:64,program:true})],
  ['resume-reader',()=>resume('resume-reader',{interrupt:'reader'})],
  ['resume-kill',()=>resume('resume-kill',{interrupt:'kill'})],
  ['block-halt',()=>measure('block-halt',{targets:BLOCK_TARGETS,concurrency:16,block:true})],
  ...[1,4,16].map(n=>['large-c'+n,()=>measure('large-c'+n,{targets:LARGE_TARGETS,coverage:'standard',traffic:'normal',concurrency:n,large:true})]),
  ...all('extra').map(spec=>{const [coverage,traffic,n,t]=spec.split(':');const name=`${coverage}-${traffic}-c${n}`;return [name,()=>measure(name,{coverage,traffic,concurrency:Number(n),targets:Number(t)||TARGETS})];}),
];
const previous=existsSync(out)?JSON.parse(readFileSync(out,'utf8')):null,rows=[];
try{
  for(const [name,run] of plan){if(only&&!only.includes(name))continue;process.stdout.write(`mass-scan: ${name} …\n`);const t=performance.now();const row=await run();rows.push(row);
    process.stdout.write(`mass-scan: ${name} done in ${Math.round((performance.now()-t)/1000)} s: ${JSON.stringify(row.second?row.checks:{exit:row.exit,wallMs:row.wallMs,rps:row.requestsPerSecond,peakRssMb:row.peakRssMb,budget:row.budgetCheck,...(row.largeBundle?{withinReadyCeiling:row.withinReadyCeiling}:{}),inline:row.inlineKeysFound,shared:row.sharedKeysFound,summary:row.summary})}\n`);}
}finally{await stopFixture();}
// --only replaces the named rows of an earlier result for the same build and fixture; anything else starts a new file.
const keep=previous&&previous.build===build&&previous.fixture?.targets===TARGETS&&only?previous.runs.filter(r=>!rows.some(n=>n.name===r.name)):[];
const order=plan.map(([n])=>n),runs=[...keep,...rows].sort((x,y)=>order.indexOf(x.name)-order.indexOf(y.name));
const result={schema:'exposure-mass-measure/1',build,date:new Date().toISOString(),node:process.version,platform:`${process.platform} ${process.arch}`,cpu:os.cpus()[0]?.model?.trim(),cores:os.availableParallelism(),totalMemoryMb:Math.round(os.totalmem()/1048576),
  fixture:{origins:ORIGINS,addressing:fixture.addressing,targets:TARGETS,blockTargets:BLOCK_TARGETS,blockedOrigins:`2 of every 5 origins answer every request with HTTP 429 or 403`,keys:'synthetic, nonfunctional sk-proj- values: one per target page, one per origin shared by its targets',realHosts:0,
    largeBundle:{targets:LARGE_TARGETS,bundle:'origin k serves its own copy of the frozen G5 bundle (1,252,570 bytes, scripts/eval-2.5-corpus.mjs) at /static/app.js, preceded by a comment with k and a statement holding the origin key; even k with the syntax error corrected (parses), odd k unchanged (both parses fail)',readyCeilingMb:READY_CEILING_MB}},
  settings:{coverage:COVERAGE,traffic:TRAFFIC,state:'--state on every run (mass mode)',failOn:'never'},runs};
await mkdir(path.dirname(out),{recursive:true});await writeFile(out,JSON.stringify(result,null,1)+'\n');
const violations=runs.flatMap(r=>[...(r.egressViolations||[]),...(r.second?.egressViolations||[])]);
const over=runs.filter(r=>r.largeBundle&&!r.withinReadyCeiling);
process.stdout.write(`mass-scan: wrote ${path.relative(root,out)}; egress violations: ${violations.length}${over.length?`; large-bundle runs over the ${READY_CEILING_MB} MiB ready-option ceiling: ${over.map(r=>r.name+' '+r.peakRssMb+' MiB').join(', ')}`:''}\n`);
if(violations.length||over.length)process.exitCode=1;
