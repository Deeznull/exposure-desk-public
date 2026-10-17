// Before/after evaluation on the frozen 2.5 corpus. Each (implementation × group × repetition) runs in its own child process with an
// egress tripwire, an isolated EXPOSURE_DATA_DIR and only loopback servers or a virtual network; implementations alternate B, F, B, F.
// Usage: node scripts/eval-2.5.mjs --implementations <baselineDir> <newDir> [--repeat 3] [--groups G1,G2] [--output benchmarks/2.5/evaluation.json]
import {spawn} from 'node:child_process';
import {createHash} from 'node:crypto';
import {mkdir,mkdtemp,readFile,writeFile,rm} from 'node:fs/promises';
import {createReadStream} from 'node:fs';
import net from 'node:net';import tls from 'node:tls';import dns from 'node:dns';import http from 'node:http';
import {syncBuiltinESMExports} from 'node:module';
import os from 'node:os';import path from 'node:path';import {fileURLToPath,pathToFileURL} from 'node:url';
const here=path.dirname(fileURLToPath(import.meta.url)),root=path.dirname(here),args=process.argv.slice(2);
const BASELINE_ID='2.4.0-rc.1+5d5acf0f7f18d7e6';
const opt=(name,fallback)=>{const i=args.indexOf('--'+name);return i<0?fallback:args[i+1];};
const sha=async file=>{const h=createHash('sha256');for await(const c of createReadStream(file))h.update(c);return h.digest('hex');};
const median=v=>{const s=[...v].sort((a,b)=>a-b);return s.length?s.length%2?s[(s.length-1)/2]:(s[s.length/2-1]+s[s.length/2])/2:null;};
if(args[0]==='--child')await child(args[1],args[2],Number(args[3]),args[4],args[5]);else await parent();

async function parent(){
  const {corpus,corpusDigest,seed,g5Fixed}=await import('./eval-2.5-corpus.mjs');const freeze=JSON.parse(await readFile(path.join(root,'benchmarks/2.5/corpus-freeze.json'),'utf8'));
  if(freeze.corpusDigest!==corpusDigest)throw new Error('Corpus digest differs from the freeze record; the evaluation refuses to run on a changed corpus.');
  const i=args.indexOf('--implementations');if(i<0)throw new Error('--implementations <baselineDir> <newDir> required');const impls=args.slice(i+1).filter(a=>!a.startsWith('--')).slice(0,2).map(p=>path.resolve(p));if(impls.length!==2)throw new Error('two implementations required');
  const repeat=Number(opt('repeat','3')),groups=(opt('groups','G1,G2,G3,G4,G5,G5F,G6,G7,G8,G9')).split(','),output=path.resolve(opt('output',path.join(root,'benchmarks/2.5/evaluation.json')));
  const work=await mkdtemp(path.join(process.env.EXPOSURE_DATA_DIR||os.tmpdir(),'eval-2.5-'));const fixtures=path.join(work,'corpus.json');const frozen=corpus();await writeFile(fixtures,JSON.stringify({...frozen,groups:{...frozen.groups,G5F:g5Fixed()}}));
  const runs=[];const started=Date.now();
  try{for(let rep=0;rep<repeat;rep++)for(const group of groups)for(const [k,impl]of (rep%2?[...impls].reverse():impls).entries()){
    const out=path.join(work,`${group}-${rep}-${k}.json`),dataDir=await mkdtemp(path.join(work,'data-'));const t=Date.now();
    const code=await new Promise(resolve=>{const c=spawn(process.execPath,[fileURLToPath(import.meta.url),'--child',impl,group,String(rep),fixtures,out],{cwd:impl,stdio:['ignore','ignore','pipe'],windowsHide:true,env:{...process.env,EXPOSURE_DATA_DIR:dataDir,HTTP_PROXY:'',HTTPS_PROXY:'',ALL_PROXY:''}});let err='';c.stderr.on('data',d=>{err+=d;if(err.length>4000)err=err.slice(-4000);});const timer=setTimeout(()=>c.kill(),15*60000);c.on('exit',x=>{clearTimeout(timer);resolve({code:x,err});});});
    let result;try{result=JSON.parse(await readFile(out,'utf8'));}catch{result={group,implementation:impl,error:'child-failed',exit:code.code,stderr:code.err.split('\n').slice(-6).join('\n')};}
    runs.push({...result,rep,wallMs:Date.now()-t});await rm(dataDir,{recursive:true,force:true}).catch(()=>{});process.stdout.write(`${group} rep ${rep} ${path.basename(impl)} ${result.error?'ERROR':'ok'} ${Date.now()-t} ms\n`);}}
  finally{await rm(work,{recursive:true,force:true}).catch(()=>{});}
  const summary={};for(const group of groups){summary[group]={};for(const impl of impls){const rs=runs.filter(r=>r.group===group&&r.implementation===impl);const ok=rs.filter(r=>!r.error);summary[group][impl===impls[0]?'baseline':'new']={build:ok[0]?.build?.id??null,runs:rs.length,errors:rs.length-ok.length,wallMsMedian:median(ok.map(r=>r.wallMs)),wallMs:ok.map(r=>r.wallMs),maxRssKiB:ok.length?Math.max(...ok.map(r=>r.maxRssKiB||0)):null,retainedHeapKiB:ok.some(r=>Number.isFinite(r.retainedHeapKiB))?Math.max(...ok.map(r=>r.retainedHeapKiB??0)):null,metrics:ok[0]?.metrics??null,metricsStable:ok.every(r=>JSON.stringify(r.stable)===JSON.stringify(ok[0].stable))};}}
  const result={schema:'exposure-next-evaluation/1',seed,corpusDigest,frozenAt:freeze.frozenAt,freezeNote:freeze.note,implementations:{baseline:impls[0],new:impls[1]},repeat,startedAt:new Date(started).toISOString(),elapsedMs:Date.now()-started,limitations:'Synthetic local fixtures on one Windows host; loopback servers and a virtual network only; Node maxRSS includes workers but not Chromium or Gitleaks children. retainedHeapKiB is the main-thread V8 heap after a full collection at the end of the child, read after the peak; it excludes workers and child processes. No statistical or open-web accuracy claim.',summary,runs};
  await mkdir(path.dirname(output),{recursive:true});await writeFile(output,JSON.stringify(result,null,2));console.log(JSON.stringify({output,groups:Object.fromEntries(Object.entries(summary).map(([g,v])=>[g,{baselineErrors:v.baseline.errors,newErrors:v.new.errors}]))}));
}

function tripwire(){const saved={connect:net.connect,createConnection:net.createConnection,tls:tls.connect,lookup:dns.lookup,pl:dns.promises.lookup},violations=[];const loop=h=>['127.0.0.1','::1','localhost','local-pipe'].includes(h);
  const host=a=>{const x=a[0];if(x&&typeof x==='object')return String(x.host??x.hostname??(x.path?'local-pipe':''));return typeof a[1]==='string'?a[1]:typeof x==='string'&&!/^\d+$/.test(x)?'local-pipe':'localhost';};
  const guard=(o,l)=>function(...a){const h=host(a);if(!loop(h)){violations.push(l+' '+h);throw new Error('egress tripwire '+h);}return o.apply(this,a);};
  net.connect=guard(saved.connect,'net.connect');net.createConnection=guard(saved.createConnection,'net.createConnection');tls.connect=guard(saved.tls,'tls.connect');
  dns.lookup=function(h,...r){if(loop(h))return saved.lookup.call(this,h,...r);violations.push('dns '+h);throw new Error('egress tripwire dns '+h);};dns.promises.lookup=async(h,...r)=>{if(loop(h))return saved.pl(h,...r);violations.push('dns '+h);throw new Error('egress tripwire dns '+h);};syncBuiltinESMExports();return violations;}

async function serve(routes,catchAll){const arrivals=[];const server=http.createServer((req,res)=>{let body='';req.on('data',c=>body+=c);req.on('end',()=>{const url=req.url||'/',p=url.split('?')[0];arrivals.push({method:req.method,url,headers:{...req.headers},browser:/Chrome/.test(String(req.headers['user-agent']||''))});const r=routes[url]??routes[p];if(r){res.writeHead(r.status||200,{'content-type':r.type||'text/html',...(r.headers||{})});res.end(r.body);}else if(catchAll!==undefined){res.writeHead(200,{'content-type':'text/html'});res.end(catchAll);}else{res.writeHead(404,{'content-type':'text/plain'});res.end('missing');}});});
  await new Promise(r=>server.listen(0,'127.0.0.1',r));return {origin:`http://127.0.0.1:${server.address().port}`,arrivals,close:()=>new Promise(r=>{server.close(()=>r());server.closeAllConnections();})};}

async function child(impl,group,rep,fixturesFile,out){
  const violations=tripwire();const corpus=JSON.parse(await readFile(fixturesFile,'utf8')),g=corpus.groups[group];
  const imp=name=>import(pathToFileURL(path.join(impl,'dist/src',name+'.js')).href);
  const [{Scanner},{Detector},{Evidence},{BUILD}]=await Promise.all(['scanner','detectors','evidence','build-info'].map(imp));
  // The baseline must be the untouched 2.4.0-rc.1 build: identity and every compiled file hash are checked first (files the release packages leave out, as in release-preflight, are skipped).
  const info=JSON.parse(await readFile(path.join(impl,'BUILD_INFO.json'),'utf8'));if(info.build.id!==BUILD.id)throw new Error('BUILD_INFO mismatch');const {excludedFromRelease}=await import('./release-files.mjs');for(const f of info.compiled.filter(f=>!excludedFromRelease(f.path)))if(await sha(path.join(impl,f.path))!==f.sha256)throw new Error('compiled file changed: '+f.path);
  const isNew=BUILD.id!==BASELINE_ID,t0=performance.now();let metrics={},stable={};
  const scanner=(config,opts={})=>new Scanner({adjacentMaps:false,requestsPerSecond:20,maxDurationMs:60000,...config},{detector:new Detector('disabled'),...opts});
  const valuesOf=(s,v)=>v.findings.filter(f=>['private-credential','suspicious'].includes(f.category)).map(f=>{try{return s.evidence.reveal(f.id).value;}catch{return null;}}).filter(Boolean);
  const histogram=list=>list.reduce((m,k)=>(m[k]=(m[k]||0)+1,m),{});
  if(group==='G1'){
    const lookups=[];const resolver=async host=>{lookups.push(host);return (g.dns[host]||['93.184.216.34']).map(address=>({address,family:address.includes(':')?6:4}));};
    const runVariant=async(seed,hosts,variant)=>{const config={urls:[seed],semanticAnalysis:false,browser:false,maxResources:200,maxDurationMs:30000,...variant,...(variant.domainScope==='registrable-domain'?{sameRegistrableDomainDiscovery:true}:{})};const s=scanner(config,{resolver}),arrivals=[];
      s.transport.one=async(raw,o={})=>{s.transport.checkBudget?.();const url=await s.transport.preflight(raw,o.method||'GET',o.headers||{},o.body||'',o.chain||[]);await s.transport.addresses(url);s.transport.checkBudget?.();const u=new URL(url),r=hosts[u.origin]?.[u.pathname];arrivals.push(url);const status=r?.status??(r?200:404),text=r?.body??'';const resource={url,bytes:text.length,status:status>=400?'http-error':status>=300?'redirect':'downloaded',analysis:'pending',code:status,kind:o.kind||'http',chain:o.chain||[]};s.transport.onResource(resource);s.transport.requests++;if(s.transport.originControl.current)s.transport.originControl.current.requests++;return {url,status,headers:{'content-type':'text/html',...(r?.headers||{})},body:Buffer.from(text),partial:false,chain:o.chain||[],resource};};
      const v=await s.run();const contacted=[...new Set(arrivals.map(a=>new URL(a).origin))];s.dispose();return {v,contacted};};
    const referenced=new Set(['example.com',...Object.keys(g.hosts).map(o=>new URL(o).hostname),...Object.keys(g.dns),'example.com.evil.net','notexample.com','xn--exmple-cua.com','cdn.thirdparty.net','creds.example.com','evil.example.net','bbb.example.com']);
    for(const [name,variant]of Object.entries(g.variants)){lookups.length=0;const {v,contacted}=await runVariant(g.seed,g.hosts,variant);const admitted=(v.origins||[]).filter(o=>o.authorization?.type==='same-registrable-domain').length;
      metrics[name]={positivesContacted:g.positives.filter(o=>contacted.includes(o)).length,positives:g.positives.length,negativesContacted:g.negatives.filter(o=>contacted.includes(o)),forbiddenContacted:g.forbidden.filter(o=>contacted.includes(o)),automaticallyAdmitted:admitted,guessedLookups:[...new Set(lookups.filter(h=>!referenced.has(h)))],requests:v.accounting?.networkAttempts??v.counts.resources,state:v.state,scopeMode:v.scope?.mode??(v.config.sameRegistrableDomainDiscovery?'registrable-domain (2.4 flag)':'exact-origin (2.4 flag)')};}
    const t=g.tenants,{v:tv,contacted}=await runVariant(t.seed,t.hosts,{domainScope:'registrable-domain'});metrics.privateSuffixTenants={positivesContacted:t.positives.filter(o=>contacted.includes(o)).length,negativesContacted:t.negatives.filter(o=>contacted.includes(o)),state:tv.state};
  }
  if(group==='G2'||group==='G3'){
    const f=await serve(g.files,g.catchAll);try{const s=scanner({urls:[f.origin+'/'],developmentFixtureOrigin:f.origin,browser:true,browserPages:5,semanticAnalysis:false,...(group==='G3'?{browserNavigationUrls:g.explicitRoutes.map(r=>f.origin+r)}:{})});const v=await s.run();
      const navigated=v.resources.filter(r=>r.kind==='browser'&&r.provenance?.resourceType==='document').map(r=>new URL(r.url).pathname),paths=f.arrivals.map(a=>a.url.split('?')[0]);
      if(group==='G2')metrics={falseHintRequests:g.falseHints.filter(p=>paths.includes(p)),keptRequests:g.kept.filter(p=>paths.includes(p)),falseHintBrowserNavigations:navigated.filter(p=>g.falseHints.includes(p)),browserNavigations:navigated.length,requests:f.arrivals.length,rejected:v.discovery?.rejected??'not recorded'};
      else metrics={assetHintNavigations:navigated.filter(p=>g.assetHints.includes(p)),explicitRouteNavigated:g.explicitRoutes.every(r=>navigated.includes(r)),loginNavigated:navigated.includes(g.loginPath),browserNavigations:navigated.length,fallbacks:v.discovery?.fallbacks??'not recorded',requests:f.arrivals.length};
      s.dispose();}finally{await f.close();}
  }
  if(group==='G4'){
    const routes={...g.files,'/':{type:'text/html',body:Array.from({length:g.pages},(_,i)=>`<a href="/p/${i+1}">${i+1}</a>`).join('')+g.mirrors.map(m=>`<script src="${m}"></script>`).join('')+g.bases.map(b=>`<a href="${b}index.html">base ${b}</a>`).join('')}};
    for(let i=1;i<=g.pages;i++)routes['/p/'+i]={type:'text/html',body:'<html><body><div id="app"></div><script src="/main.js"></script></body></html>'};for(const b of g.bases){routes[b+'index.html']={type:'text/html',body:`<html><head><base href="${b}"></head><body><script src="main.js"></script></body></html>`};routes[b+'main.js']=g.files['/main.js'];}
    const f=await serve(routes);try{const s=scanner({urls:[f.origin+'/'],developmentFixtureOrigin:f.origin,browser:false,semanticAnalysis:false,maxPages:40});const v=await s.run();const values=valuesOf(s,v),hit=v.findings.find(x=>{try{return g.expected.includes(s.evidence.reveal(x.id).value);}catch{return false;}});
      metrics={requests:f.arrivals.length,expectedFound:g.expected.filter(x=>values.includes(x)).length,findingsForValue:v.findings.filter(x=>{try{return g.expected.includes(s.evidence.reveal(x.id).value);}catch{return false;}}).length,occurrences:hit?.occurrences.length??0,reusedTextInspections:v.accounting?.reusedTextInspections??null,reusedDiscoveries:v.accounting?.reusedDiscoveries??'not recorded',repeatedRequests:v.accounting?.repeatedRequests??null};s.dispose();}finally{await f.close();}
  }
  if(group==='G5'||group==='G5F'||group==='G6'){
    const b=g.group==='G6'?corpus.groups.G5.bundle:g.bundle;const routes={'/':{type:'text/html',body:`<html><body><script src="/${b.name}"></script></body></html>`},['/'+b.name]:{type:'text/javascript',body:b.text},['/'+b.late]:{type:'text/javascript',body:'export const late=1;'},['/'+b.chunk]:{type:'text/javascript',body:'self.chunk=1;'},['/'+b.worker]:{type:'text/javascript',body:'self.onmessage=()=>{};'},['/main.js.map']:{type:'application/json',body:'{"version":3,"sources":[],"mappings":""}'}};
    const runOnce=async(extra,engine,cancelAfterMs)=>{const f=await serve(routes);try{const s=scanner({urls:[f.origin+'/'],developmentFixtureOrigin:f.origin,browser:false,semanticAnalysis:true,maxResourceBytes:4*1024*1024,...extra},{detector:engine?new Detector():new Detector('disabled')});if(engine)await s.init();
        let watcher;if(cancelAfterMs!==undefined)watcher=setInterval(()=>{if(f.arrivals.some(a=>a.url==='/'+b.name)){clearInterval(watcher);setTimeout(()=>s.cancel(),cancelAfterMs);}},10);
        const v=await s.run();clearInterval(watcher);const values=valuesOf(s,v),bundle=v.resources.find(r=>r.url===f.origin+'/'+b.name&&r.code===200),paths=f.arrivals.map(a=>a.url.split('?')[0]),analyzers=v.resources.flatMap(r=>Object.values(r.analyzers||{}).map(a=>a.status));
        const finished=!['running','ready'].includes(v.state),nonTerminal=finished?analyzers.filter(x=>['not-attempted','pending'].includes(x)).length+v.resources.filter(r=>r.analysis==='pending').length:null;
        const consistency={statePendingFree:v.state!=='completed'||(v.counts.pending===0&&!(v.coverage?.inventory||[]).some(r=>r.state==='pending')),inventoryPending:(v.coverage?.inventory||[]).filter(r=>r.state==='pending').length,countsPending:v.counts.pending,countsDeferred:v.counts.deferred??'not recorded',importantUninspected:v.websites?.importantUninspected??null,verdict:v.coverage?.assessment??null};
        const r={state:v.state,stopReason:v.stopReason,tp:b.expected.filter(x=>values.includes(x)).length,targets:b.expected.length,fp:b.negatives.filter(x=>values.includes(x)).length,otherPrivateOrSuspicious:values.filter(x=>!b.expected.includes(x)&&!b.negatives.includes(x)).length,bundleAnalyzers:bundle?Object.fromEntries(Object.entries(bundle.analyzers||{}).map(([k,a])=>[k,a.status])):null,analyzerHistogram:histogram(analyzers),nonTerminal,consistency,lateChunkRequested:paths.includes('/'+b.late),chunkRequested:paths.includes('/'+b.chunk),workerRequested:paths.includes('/'+b.worker),gapCodes:[...new Set(v.limitations.map(x=>x.code))].sort(),interruptions:v.analysis?.interruptions??'not recorded',analysisCharged:v.analysis?Object.values(v.analysis.origins).reduce((n,o)=>n+o.chargedMs,0):v.websites?.analysisMs??null,requests:f.arrivals.length};s.dispose();return r;}finally{await f.close();}};
    if(group==='G5'||group==='G5F'){metrics={engineOff:await runOnce({},false),engineOn:await runOnce({},true)};const twice=await (async()=>{routes['/'].body=`<html><body><script src="/${b.name}"></script><script src="/${b.name}?v=2"></script><script src="/${b.name}"></script></body></html>`;return runOnce({},false);})();metrics.loadedTwiceWithMirror=twice;}
    else for(const [name,variant]of Object.entries(g.variants)){const {cancelAfterMs,...config}=variant;metrics[name]=await runOnce(config,false,cancelAfterMs);}
  }
  if(group==='G7'){
    const run=async engine=>{const d=engine?new Detector():new Detector('disabled');if(engine)await d.init();const rows=[];
      for(const c of g.cases){const e=new Evidence(d);e.startTriage?.(()=>{});await e.inspect(c.text,c.url,[],'Synthetic public response');await e.triage?.flush?.();
        const match=v=>c.expect.valueMatch==='contains-pgp'?v.includes(c.value.split('\n').slice(2,3).join('')):v===c.value;const found=[...e.findings.values()].filter(f=>{try{return match(e.reveal(f.id).value);}catch{return false;}});
        const rank={information:0,'public-identifier':1,suspicious:2,'private-credential':3},best=found.sort((a,b)=>rank[b.category]-rank[a.category])[0],dismissed=(e.dismissedView?.()||[]).some(f=>found.length===0&&f.masked);
        rows.push({id:c.id,expected:c.expect,observed:best?{category:best.category,provider:best.provider,priority:best.priority?.level??null,financial:best.financialPriority??null,environment:best.environment??null,impacts:(best.impacts||[]).map(i=>i.kind),qualifiers:best.qualifiers??null}:{category:dismissed?'dismissed':'none'}});e.clear();}
      const pos=rows.filter(r=>r.expected.detect===true),neg=rows.filter(r=>r.expected.detect===false),hit=r=>['private-credential','suspicious'].includes(r.observed.category);
      const tp=pos.filter(hit).length,fp=neg.filter(hit).length,confusion={};for(const r of rows){const k=(r.expected.category||(r.expected.detect===false?'none':'any'))+' → '+r.observed.category;confusion[k]=(confusion[k]||0)+1;}
      const withPriority=rows.filter(r=>r.expected.priority);const prio=isNew?{evaluated:withPriority.length,matched:withPriority.filter(r=>r.observed.priority===r.expected.priority).length,mismatches:withPriority.filter(r=>r.observed.priority!==r.expected.priority).map(r=>({id:r.id,expected:r.expected.priority,observed:r.observed.priority}))}:'n/a (no priority in this build)';
      return {positives:pos.length,negatives:neg.length,tp,fn:pos.length-tp,fp,precision:tp+fp?tp/(tp+fp):null,recall:pos.length?tp/pos.length:null,categoryMismatches:pos.filter(r=>r.expected.category&&hit(r)&&r.observed.category!==r.expected.category).map(r=>({id:r.id,expected:r.expected.category,observed:r.observed.category})),missed:pos.filter(r=>!hit(r)).map(r=>r.id),falsePositives:neg.filter(hit).map(r=>r.id),confusion,priority:prio,rows};};
    metrics={engineOff:await run(false),engineOn:await run(true)};
  }
  if(group==='G8'){
    const f=await serve(g.files);try{const s=scanner({urls:[f.origin+g.page],developmentFixtureOrigin:f.origin,browser:true,browserPages:1,semanticAnalysis:false});const v=await s.run();
      const browser=f.arrivals.filter(a=>a.browser),statics=f.arrivals.filter(a=>!a.browser),report=browser.find(a=>a.url.startsWith('/report?')),q=report?new URL(report.url,f.origin).searchParams:null;
      const leaks=f.arrivals.filter(a=>Object.entries(a.headers).some(([k,v])=>k!=='host'&&g.sensitive.some(x=>String(v).includes(x)))).map(a=>a.url);
      metrics={staticUserAgent:[...new Set(statics.map(a=>a.headers['user-agent']??null))],staticAcceptLanguage:[...new Set(statics.map(a=>a.headers['accept-language']??null))],browserAcceptLanguage:[...new Set(browser.map(a=>a.headers['accept-language']??null))],browserLanguageReported:q?.get('lang')??null,browserTimeZoneReported:q?.get('tz')??null,refererValues:[...new Set(browser.map(a=>a.headers.referer??null))].map(r=>r&&r.replace(f.origin,'<origin>')),headersRepeatingPagePathOrQuery:leaks.length,isolation:v.browserStatus?.isolation??null,cleanup:v.browserStatus?.cleanup??'not recorded',staticHeaderNames:[...new Set(statics.flatMap(a=>Object.keys(a.headers)))].sort(),browserHeaderNames:[...new Set(browser.flatMap(a=>Object.keys(a.headers)))].sort()};
      stable={staticUserAgent:metrics.staticUserAgent};s.dispose();}finally{await f.close();}
  }
  if(group==='G9'){
    const {startDashboard}=await imp('dashboard');const slow=http.createServer((req,res)=>{setTimeout(()=>{res.writeHead(req.url==='/'?200:404,{'content-type':'text/html'});res.end('<html>slow</html>');},req.url==='/'?1500:10);});await new Promise(r=>slow.listen(0,'127.0.0.1',r));const origin=`http://127.0.0.1:${slow.address().port}`;
    const app=await startDashboard({port:0});try{const login=await fetch(app.origin+'/api/login',{method:'POST',headers:{'Content-Type':'application/json',Origin:app.origin,'X-Dashboard-Request':'1'},body:JSON.stringify({token:app.token})});const cookie=login.headers.get('set-cookie').split(';')[0],{csrf}=await login.json();
      const headers={'Content-Type':'application/json',Origin:app.origin,'X-Dashboard-Request':'1','X-CSRF-Token':csrf,Cookie:cookie},body=JSON.stringify({authorized:true,requestId:'eval-duplicate-start-01',config:{urls:[origin+'/'],developmentFixtureOrigin:origin,requestsPerSecond:20,adjacentMaps:false,browser:false,semanticAnalysis:false}});
      const first=fetch(app.origin+'/api/scans',{method:'POST',headers,body});await new Promise(r=>setTimeout(r,g.gapMs));const second=fetch(app.origin+'/api/scans',{method:'POST',headers,body});const [a,b2]=await Promise.all([first,second]);const ja=await a.json().catch(()=>({})),jb=await b2.json().catch(()=>({}));
      for(let i=0;i<100&&[...app.scans.values()].some(s=>s.state==='running');i++)await new Promise(r=>setTimeout(r,100));
      metrics={statuses:[a.status,b2.status],runsCreated:app.scans.size,sameRunReturned:!!ja.id&&ja.id===jb.id,duplicateFlag:jb.duplicate??ja.duplicate??'not supported',secondError:jb.error?String(jb.error).slice(0,80):null,secondCode:jb.code??null};
    }finally{await app.close();await new Promise(r=>{slow.close(()=>r());slow.closeAllConnections();});}
  }
  const elapsedMs=Math.round(performance.now()-t0),maxRssKiB=process.resourceUsage().maxRSS,retainedHeapKiB=await retainedHeap();
  await writeFile(out,JSON.stringify({group,implementation:impl,build:BUILD,rep,metrics,stable,elapsedMs,maxRssKiB,retainedHeapKiB,egressViolations:violations}));
  process.exit(0);
}
/** Main-thread V8 heap after a full GC, read at the very end of the child (after maxRSS) so the measured run is unchanged; null if gc cannot be exposed late. */
async function retainedHeap(){try{const [{default:v8},{default:vm}]=await Promise.all([import('node:v8'),import('node:vm')]);v8.setFlagsFromString('--expose-gc');vm.runInNewContext('gc')();return Math.round(process.memoryUsage().heapUsed/1024);}catch{return null;}}
