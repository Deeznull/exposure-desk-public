// Ready-option measurement child (run by scripts/profile-matrix.mjs): one scan per process (clean peak RSS). Local HTTPS loopback fixtures only; synthetic, nonfunctional keys.
// argv[2] = base64 JSON spec: {id, dist, helpers, fixture:'single'|'bundle'|'multi', websites, coverage?, traffic?, preset?, computer?, mode?:'scan'|'resources'}
import {createRequire,syncBuiltinESMExports} from 'node:module';
import path from 'node:path';
import https from 'node:https';
import tls from 'node:tls';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {existsSync} from 'node:fs';
const require=createRequire(import.meta.url);
const spec=JSON.parse(Buffer.from(process.argv[2],'base64').toString('utf8'));
const out=r=>{process.stdout.write('RESULT '+JSON.stringify(r)+'\n');};
// Analysis worker heap high-water mark: every worker_threads.Worker is tracked and sampled every 25 ms (a busy worker answers at its next safe point).
const wt=require('node:worker_threads'),Base=wt.Worker,live=new Set(),heap={};
class Tracked extends Base{constructor(file,opts){super(file,opts);const name=path.basename(file instanceof URL?file.pathname:String(file));this.__n=name;live.add(this);this.once('exit',()=>live.delete(this));
  const limit=opts?.resourceLimits?.maxOldGenerationSizeMb??null,h=heap[name]??={workers:0,peakUsedMb:0,peakTotalMb:0,limitMb:null,limits:[]};h.workers++;if(limit!=null){h.limitMb=Math.max(h.limitMb??0,limit);if(!h.limits.includes(limit))h.limits.push(limit);}}}
wt.Worker=Tracked;syncBuiltinESMExports();
let peakRss=process.memoryUsage.rss();
const sampler=setInterval(()=>{peakRss=Math.max(peakRss,process.memoryUsage.rss());for(const w of live)w.getHeapStatistics().then(s=>{const h=heap[w.__n];h.peakUsedMb=Math.max(h.peakUsedMb,s.used_heap_size/1048576);h.peakTotalMb=Math.max(h.peakTotalMb,s.total_heap_size/1048576);},()=>{});},25);
const imp=f=>import(pathToFileURL(f).href);
const {egressTripwire}=await imp(path.join(spec.helpers,'virtual-network.js')),{loopbackCertificate}=await imp(path.join(spec.helpers,'tls-fixture.js'));
const {Scanner}=await imp(path.join(spec.dist,'src','scanner.js')),{Detector}=await imp(path.join(spec.dist,'src','detectors.js'));
// Analysis child processes (builds that run the parser and large-text inspection in children; absent in older builds): each child's heap limit, startup time and peak RSS (the child reports it with every reply).
const children=[],processModule=path.join(spec.dist,'src','analysis-process.js');
if(existsSync(processModule))(await imp(processModule)).analysisProcesses.events.on('spawn',info=>children.push(info));
const J=JSON.stringify,key=label=>'sk-proj-'+createHash('sha512').update('ExposureDesk/p4-matrix/1/'+label).digest('base64url').slice(0,64).replace(/[-_]/g,'Q');
const hosts=spec.fixture==='single'?['www.example.com']:spec.fixture==='bundle'?['bundle.example.com']:Array.from({length:spec.websites},(_,i)=>`s${i+1}.example.com`);

if(spec.mode==='resources'){
  // Recorded adjusted values only (no network): profileView().resourceUse and estimate for 1/3/10 websites, this computer and an injected small one.
  const rows=[];for(const n of [1,3,10])for(const computer of [undefined,{cores:2,freeMemoryMb:1024}])for(const coverage of ['quick','standard','deep'])for(const traffic of ['normal','low-impact']){
    const s=new Scanner({urls:Array.from({length:n},(_,i)=>`https://s${i+1}.example.com/`),coverage,traffic},{detector:new Detector('disabled'),...(computer?{computer}:{})});
    try{const p=s.profileView();rows.push({websites:n,computer:computer?'small (2 cores, 1 GiB free)':'this computer',coverage,traffic,label:p.label,resourceUse:p.resourceUse,caps:s.caps,estimate:p.estimate});}finally{s.dispose?.();}}
  clearInterval(sampler);out({id:spec.id,mode:'resources',rows});process.exit(0);
}

const port0={v:0},planted=new Map(),PLACEHOLDER='sk-proj-'+'X'.repeat(40),decoys=[PLACEHOLDER];
function single(h,origin){
  const k=l=>{const v=key(h+'/'+l);planted.set(v,h+':'+l);return v;},K={inline:k('inline'),app:k('app'),map:k('map'),split:k('split'),env:k('env'),config:k('config'),d3:k('depth3'),d5:k('depth5')},half=K.split.length>>1;
  const page=(title,body)=>({type:'text/html',body:`<!doctype html><html><head><title>${title}</title></head><body>${body}</body></html>`});
  return {'/':{type:'text/html',body:`<!doctype html><html><head><title>Shop ${h}</title><script>window.S={openai:${J(K.inline)}}</script><script src="/app.js"></script><script type="module" src="/main.js"></script></head><body><!-- OPENAI_API_KEY=your_api_key_here --><a href="/about">About</a> <a href="/blog">Blog</a> <a href="/list?page=1">1</a> <a href="/list?page=2">2</a> <a href="/list?page=3">3</a></body></html>`},
    '/about':page('About','<p>Synthetic fixture.</p><a href="/">Home</a>'),'/blog':page('Blog','<a href="/blog/post">Post</a>'),'/blog/post':page('Post','<a href="/blog/post/notes">Notes</a>'),
    '/blog/post/notes':page('Notes','<script src="/notes.js"></script><a href="/archive">Archive</a>'),'/notes.js':{type:'text/javascript',body:`window.notes={apiKey:${J(K.d3)}};`},
    '/archive':page('Archive','<a href="/archive/old">Old</a>'),'/archive/old':page('Old','<script src="/old.js"></script>'),'/old.js':{type:'text/javascript',body:`window.old={apiKey:${J(K.d5)}};`},
    '/list':page('List','<p>list</p><script src="/list.js"></script>'),'/list.js':{type:'text/javascript',body:'window.list=1;'},
    '/app.js':{type:'text/javascript',body:`const client={apiKey:${J(K.app)}};const example=${J(PLACEHOLDER)};\n//# sourceMappingURL=app.js.map`},
    '/app.js.map':{type:'application/json',body:J({version:3,file:'app.js',sources:['src/c.ts'],sourcesContent:[`export const serverKey=${J(K.map)};`],names:[],mappings:'AAAA'})},
    '/main.js':{type:'text/javascript',body:`import {a} from "./part.js";export const openaiKey=a+${J(K.split.slice(half))};`},'/part.js':{type:'text/javascript',body:`export const a=${J(K.split.slice(0,half))};`},
    '/.env':{type:'text/plain',body:`OPENAI_API_KEY=${K.env}\n`},'/config.json':{type:'application/json',body:J({openai:{apiKey:K.config},docs:'https://platform.openai.com/docs'})},
    '/robots.txt':{type:'text/plain',body:`User-agent: *\nAllow: /\nSitemap: ${origin}/sitemap.xml\n`},
    '/sitemap.xml':{type:'application/xml',body:`<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">${['/','/about','/blog'].map(p=>`<url><loc>${origin}${p}</loc></url>`).join('')}</urlset>`}};
}
const {syntheticBundle}=await imp(path.join(spec.helpers,'large-bundle.js'));
function bundleSite(h){
  const bundle=syntheticBundle({seed:'ExposureDesk/p4-matrix/bundle/1',targetBytes:1252570}),k=l=>{const v=key(h+'/'+l);planted.set(v,h+':'+l);return v;};
  const K={inline:k('inline'),app:k('app'),map:k('map'),env:k('env'),config:k('config'),split:k('split')},half=K.split.length>>1;planted.set(bundle.value,h+':bundle');decoys.push(bundle.mutated);
  return {'/':{type:'text/html',body:`<!doctype html><script>window.S={openai:${J(K.inline)}}</script><script src="/app.js"></script><script type="module" src="/bundle.js"></script><script type="module" src="/main.js"></script>`},
    '/app.js':{type:'text/javascript',body:`const client={apiKey:${J(K.app)}};\n//# sourceMappingURL=app.js.map`},'/app.js.map':{type:'application/json',body:J({version:3,file:'app.js',sources:['src/c.ts'],sourcesContent:[`export const serverKey=${J(K.map)};`],names:[],mappings:'AAAA'})},
    '/main.js':{type:'text/javascript',body:`import {a} from "./part.js";export const openaiKey=a+${J(K.split.slice(half))};`},'/part.js':{type:'text/javascript',body:`export const a=${J(K.split.slice(0,half))};`},
    '/bundle.js':{type:'text/javascript',body:bundle.text},'/bundle.js.map':{type:'application/json',body:J({version:3,file:'bundle.js',sources:['b.ts'],sourcesContent:['void 0'],names:[],mappings:''})},
    ['/'+bundle.lateChunk.slice(2)]:{type:'text/javascript',body:'export const late=1;'},'/tail.js':{type:'text/javascript',body:'self.onmessage=()=>{};'},
    '/.env':{type:'text/plain',body:`OPENAI_API_KEY=${K.env}\n`},'/config.json':{type:'application/json',body:J({openai:{apiKey:K.config}})},'/robots.txt':{type:'text/plain',body:'User-agent: *\nAllow: /\n'}};
}

// One HTTPS server on 127.0.0.1 for every fixture name (SNI certificate made in memory); counts are taken on the server, so 2.5 and 2.6 are measured the same way.
const {cert,key:tlsKey}=loopbackCertificate(hosts),sites=new Map(),inflight=new Map();
let requests=0,tcp=0,handshakes=0,resumed=0,wire=0,peakHosts=0;const sockets=new Set(),perHost={};
const server=https.createServer({cert,key:tlsKey},(req,res)=>{
  const host=String(req.headers.host||'').replace(/:\d+$/,''),u=new URL(req.url||'/','https://'+host),site=sites.get(host),r=site?.[u.pathname+u.search]??site?.[u.pathname];requests++;perHost[host]=(perHost[host]||0)+1;
  inflight.set(host,(inflight.get(host)||0)+1);peakHosts=Math.max(peakHosts,[...inflight.values()].filter(n=>n>0).length);let done=false;const end=()=>{if(!done){done=true;inflight.set(host,inflight.get(host)-1);}};res.on('close',end);res.on('finish',end);
  res.writeHead(r?.status??(r?200:404),{'content-type':r?.type||'text/plain'});res.end(req.method==='HEAD'?undefined:(r?.body??'not found'));});
server.on('connection',s=>{tcp++;sockets.add(s);s.on('close',()=>{wire+=s.bytesRead+s.bytesWritten;sockets.delete(s);});});
server.on('secureConnection',s=>{handshakes++;if(s.isSessionReused())resumed++;});
await new Promise(r=>server.listen(0,'127.0.0.1',r));const port=server.address().port;port0.v=port;
for(const h of hosts)sites.set(h,spec.fixture==='bundle'?bundleSite(h):single(h,`https://${h}:${port}`));
const origins=hosts.map(h=>`https://${h}:${port}`),resolver=async host=>hosts.includes(host)?[{address:'127.0.0.1',family:4}]:[];
const previousCa=tls.getCACertificates('default');tls.setDefaultCACertificates([...previousCa,cert]);
process.env.EXPOSURE_DATA_DIR=spec.dataDir;
const trip=egressTripwire();let s,v,error;const t0=performance.now();
try{
  const base={urls:origins.map(o=>o+'/'),privateOrigins:origins};
  // 2.5 legacy presets are applied the way its CLI/dashboard apply them (presetConfig); 2.6 options are part of the configuration.
  const input=spec.preset?(await imp(path.join(spec.dist,'src','presets.js'))).presetConfig(spec.preset,base):{...base,coverage:spec.coverage,traffic:spec.traffic};
  s=new Scanner(input,{detector:new Detector(),resolver,...(spec.computer?{computer:spec.computer}:{})});await s.init();v=await s.run();
}catch(e){error=String(e?.stack||e).slice(0,800);}
const durationMs=Math.round(performance.now()-t0);
trip.restore();clearInterval(sampler);peakRss=Math.max(peakRss,process.memoryUsage.rss());
for(const so of sockets)wire+=so.bytesRead+so.bytesWritten;
// Precision counts credential findings only (data-exposure findings such as a published .env file are not secrets); the rest are listed by rule.
const all=s?[...s.evidence.findings.values()].map(f=>({rule:f.rule,category:f.category,provider:f.provider,confidence:f.confidence,severity:f.severity,value:s.evidence.reveal(f.id).value})):[],findings=all.filter(f=>['private-credential','suspicious'].includes(f.category));
if(process.env.P4_DEBUG)for(const f of findings)process.stderr.write(`finding ${f.rule} ${f.category} ${f.value?.length} ${String(f.value).slice(0,14)}
`);
const match=val=>[...planted.keys()].find(p=>val===p||(val&&val.length>=20&&(p.includes(val)||val.includes(p))));
const found=new Set(findings.map(f=>match(f.value)).filter(Boolean)),matched=findings.filter(f=>match(f.value)),unmatched=findings.filter(f=>!match(f.value));
const sum=(o,k)=>Object.values(o||{}).reduce((a,g)=>a+(g[k]||0),0),groups=v?.coverage?.groups,a=v?.accounting||{};
// Per role: children started, heap limits, startup (spawn to ready) and peak RSS. `concurrentPeakRssMb` adds each child's peak RSS over its whole life, so it is an upper bound;
// `combinedPeakRssMb` = this process's peak RSS + that bound (conservative: the peaks need not coincide).
const childrenView=(()=>{if(!existsSync(processModule))return undefined;const now=Date.now(),byRole={};
  for(const c of children){const r=byRole[c.role]??={children:0,limits:[],startupMs:[],peakRssMb:0,outOfMemory:0};r.children++;if(!r.limits.includes(c.heapMb))r.limits.push(c.heapMb);if(c.startupMs!=null)r.startupMs.push(c.startupMs);r.peakRssMb=Math.max(r.peakRssMb,c.peakRssMb||0);if(c.exit?.outOfMemory)r.outOfMemory++;}
  const concurrent=size=>{const marks=children.flatMap(c=>[[c.spawnedAt,size(c)],[c.endedAt??now,-size(c)]]).sort((x,y)=>x[0]-y[0]||x[1]-y[1]);let live=0,peak=0;for(const [,d] of marks){live+=d;peak=Math.max(peak,live);}return peak;};
  // `concurrentHeapMb`: the most heap limit held at once by live children (spawn to exit), which the analysis memory setting bounds.
  const concurrentPeakRssMb=concurrent(c=>c.peakRssMb||0),concurrentHeapMb=concurrent(c=>c.heapMb||0);
  return {byRole,concurrentHeapMb,concurrentPeakRssMb,combinedPeakRssMb:Math.round(peakRss/1048576)+concurrentPeakRssMb};})();
const result={id:spec.id,mode:'scan',build:v?.build?.id,fixture:spec.fixture,websites:hosts.length,coverage:spec.coverage,traffic:spec.traffic,preset:spec.preset,computer:spec.computer?'small (2 cores, 1 GiB free)':'this computer',error,
  state:v?.state,stage:v?.stage,completion:v?.profile?.completion,notExamined:(v?.profile?.notExamined||[]).map(n=>n.category+' ×'+n.count),profileLimit:v?.profile?.profileLimit?.count,label:v?.profile?.label,resourceUse:v?.profile?.resourceUse,caps:s?.caps,estimate:v?.profile?.estimate,
  durationMs,peakRssMb:Math.round(peakRss/1048576),maxRssMb:Math.round(process.resourceUsage().maxRSS/1024),workerHeap:heap,analysisChildren:childrenView,
  parserJobs:Object.values(v?.analysis?.origins||{}).reduce((t,o)=>({jobs:t.jobs+(o.jobs||0),startupMs:t.startupMs+Math.round(o.startupMs||0),queueWaitMs:t.queueWaitMs+Math.round(o.queueWaitMs||0),workerMs:t.workerMs+Math.round(o.workerMs||0),
    outcomes:Object.entries(o.outcomes||{}).reduce((m,[k,n])=>(m[k]=(m[k]||0)+n,m),t.outcomes)}),{jobs:0,startupMs:0,queueWaitMs:0,workerMs:0,outcomes:{}}),
  analysisGaps:(v?.limitations||[]).filter(g=>/^semantic-|detector-analysis|worker/.test(g.code)).map(g=>g.code+(g.count>1?' ×'+g.count:'')),
  server:{requests,perHost,tcpConnections:tcp,tlsHandshakes:handshakes,tlsResumed:resumed,wireBytes:wire,peakWebsitesInFlight:peakHosts},
  scanner:{networkAttempts:a.networkAttempts,connectionsOpened:a.connectionsOpened,connectionsReused:a.connectionsReused,tlsHandshakes:a.tlsHandshakes,downloadedBytes:a.downloadedBytes,requestsAvoided:a.requestsAvoided,browserCacheHits:a.browserCacheHits},
  browser:{navigations:v?.browserStatus?.runtimePages,launched:v?.browserStatus?.launch,staticPageAttempts:v?.scheduler?.pageAttempts,browserPages:(v?.origins||[]).reduce((n,o)=>n+(o.browserPages||0),0),peakBrowserOrigins:v?.scheduler?.peakBrowserOrigins},
  coverageView:groups?{assessment:v.coverage.assessment,discovered:sum(groups,'discovered'),downloaded:sum(groups,'downloaded'),analyzed:sum(groups,'analyzed'),highValueLimited:v.coverage.highValueLimited}:undefined,
  counts:v?.counts,statedLimits:[...new Set((v?.limitations||[]).filter(g=>!g.incomplete).map(g=>g.code))],incompleteGaps:Object.entries((v?.limitations||[]).filter(g=>g.incomplete).reduce((m,g)=>(m[g.code]=(m[g.code]||0)+(g.count||1),m),{})),
  memoryGaps:(v?.limitations||[]).filter(g=>/memory/.test(g.code)).map(g=>g.code),
  recall:{planted:planted.size,found:found.size,missing:[...planted].filter(([p])=>!found.has(p)).map(([,l])=>l)},
  precision:{findings:findings.length,matched:matched.length,decoysReported:findings.filter(f=>decoys.includes(f.value)).length,unmatched:unmatched.map(f=>[f.rule,f.provider,f.confidence,f.severity].join('|')),otherFindings:all.filter(f=>!findings.includes(f)).map(f=>f.category+'|'+f.rule)},
  egressViolations:trip.violations};
s?.dispose?.();tls.setDefaultCACertificates(previousCa);server.closeAllConnections();await new Promise(r=>server.close(()=>r()));
out(result);process.exit(0);
