import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { domainToASCII } from 'node:url';
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { protectedHost, isProtectedHost, normalizeProtectedHost, configUrls, protectedConfigHost, ProtectedHostError, isProtectedHostError, PROTECTED_HOST_MESSAGE, PROTECTED_LIST, PROTECTED_TLDS, PROTECTED_ZONES, PROTECTED_PATTERNS, PROTECTED_BODIES } from '../src/protected-hosts.js';
import { makeConfig } from '../src/config.js';
import { presetConfig, profileConfig } from '../src/presets.js';
import { Transport, PolicyError, NON_INCOMPLETE_BLOCKS, certificateNames } from '../src/transport.js';
import { Evidence } from '../src/evidence.js';
import { Scanner } from '../src/scanner.js';
import { Detector, root } from '../src/detectors.js';
import { Store, migrateProjectConfig } from '../src/storage.js';
import { Desk } from '../src/desk.js';
import { startDashboard } from '../src/dashboard.js';
import { makeTrigger, writeTrigger } from '../src/triggers.js';
import { report } from '../src/reports.js';
import { runSummary, scopeCountLine } from '../src/runs.js';
import { egressTripwire } from './virtual-network.js';
import { loopbackCertificate, trusting } from './tls-fixture.js';
import { focusedRetry } from '../src/retry.js';
import type { Resource, ScanConfig } from '../src/types.js';
/** Hard rule (gov-block): Exposure Desk never sends a request to a government, military, intelligence, law-enforcement, judiciary or intergovernmental host.
 * Local fixtures only: protected names are never resolved (a recording resolver fails the test if asked) and the egress tripwire refuses every non-loopback socket or lookup. */
const message=(host:string)=>`Exposure Desk never scans government, military, intelligence or law-enforcement websites: ${host}`;
const refused=(host:string)=>(e:unknown)=>e instanceof ProtectedHostError&&e.code==='protected-host'&&e.host===host&&e.message===message(host);
const detector=new Detector('disabled');await detector.init();
async function temp(prefix:string){const parent=process.env.EXPOSURE_DATA_DIR||path.join(root,'.cache');await mkdir(parent,{recursive:true});return mkdtemp(path.join(parent,prefix));}
/** Loopback owner website: records the path and Host header of every arrival. */
async function owner(routes:Record<string,[type:string,body:string|((port:number)=>string),status?:number,headers?:Record<string,string>]>){
  const arrivals:{path:string;host:string}[]=[];let port=0;
  const server=http.createServer((req,res)=>{arrivals.push({path:req.url||'',host:String(req.headers.host)});const r=routes[req.url||''];if(!r){res.statusCode=404;res.end('not found');return;}res.writeHead(r[2]??200,{'content-type':r[0],...(r[3]||{})});res.end(typeof r[1]==='function'?r[1](port):r[1]);});
  await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));port=(server.address() as any).port;
  return {port,origin:`http://127.0.0.1:${port}`,arrivals,close:()=>new Promise<void>(r=>{server.close(()=>r());server.closeAllConnections();})};
}

test('2.9.0 additions: politie.be and policia.pt and their subdomains are protected; lookalikes are not',()=>{
  for(const host of ['politie.be','www.politie.be','https://www.politie.be/','policia.pt','www.policia.pt','POLICIA.PT.'])assert.ok(isProtectedHost(host),host+' is protected');
  for(const host of ['politie.be.example.com','notpolitie.be','policia.pt.example.org','mypolicia.pt'])assert.ok(!isProtectedHost(host),host+' is not protected');
});

test('matcher: government TLDs and zones, listed bodies and their subdomains are protected after normalization; lookalikes are not',()=>{
  for(const host of ['nasa.gov','www.nasa.gov','army.mil','www.who.int','nato.int','www.gov.uk','GOV.UK','WWW.Gov.Uk.','www.gov.uk..','https://user:secret@www.gov.uk:8443/path?q=1#frag','www.gov.uk:443','user@www.gov.uk','ws://chat.gov.uk/socket','www.police.uk','www.gouv.fr','impots.gouv.fr','www.gob.es','www.gob.mx','www.gov.br','www.eb.mil.br','www.gov.cn','www.gov.in','x.nic.in','www.city.osaka.lg.jp','www.go.jp','www.go.kr','www.gov.il','www.gov.ru','www.gv.at','www.gub.uy','www.msb.gov.tr','www.tsk.mil.tr','www.govt.nz','www.gc.ca','www.gouv.qc.ca','www.gov.au','www.nsw.gov.au',
    'europa.eu','ec.europa.eu','www.un.org','www.canada.ca','bund.de','www.bsi.bund.de','www.bundeswehr.de','www.admin.ch','kremlin.ru','en.kremlin.ru','government.ru','www.fsb.ru','www.cni.es','www.bankofengland.co.uk',
    'president.state.tx.us','www.ci.berkeley.ca.us','www.co.fairfax.va.us','www.fs.fed.us','home.cern','www.regione.lombardia.it','www.comune.milano.it','www.riik.ee','www.zh.ch'])assert.ok(isProtectedHost(host),host+' is protected');
  // Unicode and punycode spellings are one host: IDN input, its punycode form and full-width dots all match.
  for(const host of ['президент.рф','www.президент.рф',domainToASCII('президент.рф'),'www。gov。uk','ＷＷＷ.ＧＯＶ.ＵＫ','政府.香港','www.政府.香港'])assert.ok(isProtectedHost(host),host+' (IDN) is protected');
  // Raw spellings are read as WHATWG URL parsing (the transport and Chromium) reads them: backslashes, missing slashes, tabs and control characters.
  for(const raw of ['http:\\\\www.bund.de','http:/www.bund.de','\x01https://www.bund.de','ht\ttps://www.bund.de','https:www.gov.uk',' https://www.gov.uk/ '])assert.ok(isProtectedHost(raw),JSON.stringify(raw)+' is read as the transport reads it');
  assert.equal(normalizeProtectedHost('https://user:pw@WWW.Gov.UK.:8443/x'),'www.gov.uk');assert.equal(normalizeProtectedHost('www.президент.рф.'),domainToASCII('www.президент.рф'));
  assert.deepEqual(protectedHost('https://WWW.HMRC.GOV.UK./a'),{host:'www.hmrc.gov.uk',rule:'zone',entry:'gov.uk'});assert.deepEqual(protectedHost('a.b.europa.eu'),{host:'a.b.europa.eu',rule:'body',entry:'europa.eu'});
  assert.deepEqual(protectedHost('www.nasa.gov'),{host:'www.nasa.gov',rule:'tld',entry:'gov'});assert.equal(protectedHost('www.ci.berkeley.ca.us')!.rule,'pattern');
  // A label that merely contains or resembles "gov"/"mil"/"int" is not blocked, nor are ordinary domains under shared suffixes, IP literals or local names.
  for(const host of ['gov.example.com','mygov-shop.com','governance.io','government-contracts.example.net','example.gov.evil.com','gov.uk.example.com','notgov.uk','www.example.co.uk','gorizia.go.it','comune.gorizia.go.it','x.mi.us','ci.example.com','www.city.co.jp','mil.example.org','army.example.com',
    'police-supplies.com','www.nhs.uk','comune.example.it','int.example.com','intl.example.org','europa.example.eu','un.org.example.com','unicef-shop.example.com','bund.example.de','example.com','example.test','localhost','127.0.0.1','93.184.216.34','[::1]','http://[2001:db8::1]:8080/','','   '])assert.ok(!isProtectedHost(host),JSON.stringify(host)+' is not protected');
});

test('protected list: reviewed, normalized, frozen and sized; no zone is a shared commercial suffix',()=>{
  for(const list of [PROTECTED_TLDS,PROTECTED_ZONES,PROTECTED_PATTERNS,PROTECTED_BODIES])assert.ok(Object.isFrozen(list),'exported lists cannot be changed at run time');
  assert.deepEqual([...PROTECTED_TLDS].sort(),['cern','gov','int','mil','va',domainToASCII('政务')].sort());
  for(const entry of [...PROTECTED_ZONES,...PROTECTED_BODIES]){assert.match(entry,/^(?:[a-z0-9-]+\.)+[a-z0-9-]+$/,entry+' is a normalized ASCII name with at least two labels');assert.equal(normalizeProtectedHost(entry),entry);}
  for(const pattern of PROTECTED_PATTERNS)assert.match(pattern,/^(?:(?:[a-z0-9-]+|\*)\.)+[a-z0-9-]+$/,pattern);
  // Commercial or shared zones would be false positives for every customer under them.
  for(const shared of ['com','co.uk','org.uk','com.br','co.jp','or.jp','ne.jp','co.kr','com.au','co.nz','com.tr','com.cn','co.in','go.it','mi.it','mi.us','lg.ua','pol.dz','nic.za','github.io','cloudfront.net','azurewebsites.net','herokuapp.com'])
    assert.ok(!PROTECTED_ZONES.includes(shared)&&!PROTECTED_BODIES.includes(shared)&&!isProtectedHost('customer.'+shared),shared+' is not protected');
  assert.ok(PROTECTED_LIST.zones>=300&&PROTECTED_LIST.bodies>=250&&PROTECTED_LIST.patterns>=200,JSON.stringify(PROTECTED_LIST));
  assert.equal(new Set(PROTECTED_ZONES).size,PROTECTED_ZONES.length,'no duplicate zones');assert.equal(new Set(PROTECTED_BODIES).size,PROTECTED_BODIES.length,'no duplicate bodies');
});

test('configuration: a protected URL in any URL field refuses the whole scan before other validation, with the documented message',()=>{
  assert.throws(()=>makeConfig({urls:['https://www.example.gov/']}),refused('www.example.gov'));
  assert.throws(()=>makeConfig({urls:['WWW.GOV.UK.']}),refused('www.gov.uk'),'a seed without a scheme, uppercase and with a trailing dot');
  const owner='https://owner.example.com/';
  for(const [field,value,host] of [['relatedOrigins',['https://api.bund.de'],'api.bund.de'],['privateOrigins',['http://intranet.example.mil:8080'],'intranet.example.mil'],['readOnlyPostEndpoints',['https://forms.canada.ca/submit'],'forms.canada.ca'],
    ['browserNavigationUrls',['https://portal.europa.eu/login'],'portal.europa.eu'],['staleAssetUrls',['https://cdn.example.gov/old.js'],'cdn.example.gov'],['developmentFixtureOrigin','http://local.example.gov:8080','local.example.gov']] as const)
    assert.throws(()=>makeConfig({urls:[owner],[field]:value} as Partial<ScanConfig>),refused(host),field);
  assert.throws(()=>makeConfig({urls:['https://www.example.gov/'],coverage:'maximum' as any,requestsPerSecond:-1}),refused('www.example.gov'),'the rule wins over every other validation error');
  assert.equal(protectedConfigHost({urls:['owner.example.com'],staleAssetUrls:['/a.js','https://x.gouv.fr/b.js']}),'x.gouv.fr');assert.deepEqual(configUrls({urls:['owner.example.com'],staleAssetUrls:['/a.js']}),['https://owner.example.com','https://owner.example.com/a.js']);
  for(const make of [()=>presetConfig('exhaustive',{urls:['https://www.gov.uk/']}),()=>profileConfig('deep','low-impact',{urls:['https://www.gov.uk/']}),()=>new Scanner({urls:['https://www.gov.uk/']},{detector,resolver:async()=>assert.fail('no lookup')})])
    assert.throws(make,refused('www.gov.uk'),'presets, profiles and the Scanner constructor refuse before any network object exists');
  assert.ok(isProtectedHostError(new ProtectedHostError('x.gov'))&&isProtectedHostError(new PolicyError('protected-host'))&&!isProtectedHostError(new Error('scope')));
  assert.ok(NON_INCOMPLETE_BLOCKS.includes('protected-host'),'a protected-host block counts like out-of-scope, never as incomplete');
});

test('no override: no configuration key, preset, profile, scope, environment variable or matcher argument disables or narrows the rule',async()=>{
  const overrides={allowProtectedHosts:true,protectedHosts:false,protectedHostBlock:'off',governmentBlock:false,allowGovernment:true,overrideProtectedHosts:true,disableHardRules:true,unsafe:true,ownerAuthorizedGovernment:true,
    preset:'exhaustive',robotsPolicy:'owner-authorized-audit',domainScope:'exact-origin',privateOrigins:['https://www.gov.uk'],relatedOrigins:['https://www.gov.uk'],sameRegistrableDomainDiscovery:false} as any;
  assert.throws(()=>makeConfig({urls:['https://www.gov.uk/'],...overrides}),refused('www.gov.uk'));
  const names=['EXPOSURE_ALLOW_PROTECTED_HOSTS','EXPOSURE_PROTECTED_HOSTS','EXPOSURE_GOV_BLOCK','EXPOSURE_ALLOW_GOVERNMENT','EXPOSURE_UNSAFE','EXPOSURE_DISABLE_HARD_RULES'],saved=names.map(n=>process.env[n]);
  try{for(const n of names)process.env[n]=n.includes('BLOCK')||n==='EXPOSURE_PROTECTED_HOSTS'?'0':'1';assert.throws(()=>makeConfig({urls:['https://www.gov.uk/']}),refused('www.gov.uk'));assert.ok(isProtectedHost('www.gov.uk'));}
  finally{names.forEach((n,i)=>saved[i]===undefined?delete process.env[n]:process.env[n]=saved[i]);}
  // A valid configuration exposes no setting that could name the rule, and the matcher takes nothing but the host.
  assert.deepEqual(Object.keys(makeConfig({urls:['https://owner.example.com/']})).filter(k=>/protect|govern|military|override|hard.?rule/i.test(k)),[]);
  assert.equal(protectedHost.length,1);
  const source=await readFile(path.join(root,'src/protected-hosts.ts'),'utf8');assert.ok(!/process\.(?:env|argv)|readFile|require\(|import\(/.test(source),'the module reads no environment, arguments or files');
  // The CLI refuses whatever extra flags or environment variables are supplied.
  const dir=await temp('protected-cli-env-');try{const r=spawnSync(process.execPath,[path.join(root,'dist/src/cli.js'),'scan','--url','https://www.gov.uk/','--allow-government','--unsafe','--preset','exhaustive','--scope','exact-origin','--output',path.join(dir,'never.json')],
    {encoding:'utf8',windowsHide:true,timeout:60000,env:{...process.env,EXPOSURE_DATA_DIR:dir,...Object.fromEntries(names.map(n=>[n,'1']))}});
    assert.equal(r.status,2,r.stderr);assert.equal(r.stderr.trim(),message('www.gov.uk'));assert.deepEqual(await readdir(dir),[],'no report or data written');}finally{await rm(dir,{recursive:true,force:true});}
});

test('transport: every send path refuses a protected host before DNS or a socket, even if it were forced into the authorized set',async()=>{
  const trip=egressTripwire(),lookups:string[]=[],rows:Resource[]=[],gaps:any[]=[];
  try{const t=new Transport(makeConfig({urls:['https://owner.example.com/']}),new Evidence(detector),r=>rows.push(r),g=>gaps.push(g),async host=>{lookups.push(host);return [{address:'127.0.0.1',family:4}];});
    // Simulate a future path that bypasses configuration and scope: the transport itself still refuses.
    (t as any).origins.add('https://www.example.gov');(t as any).origins.add('https://portal.gov.uk');
    const code=(c:string)=>(e:unknown)=>e instanceof PolicyError&&e.code===c;
    await assert.rejects(t.preflight('https://www.example.gov/a'),code('protected-host'));
    await assert.rejects(t.preflight('https://WWW.EXAMPLE.GOV.:443/x'),code('protected-host'),'normalized before matching');
    await assert.rejects(t.one('https://www.example.gov/b'),code('protected-host'));
    await assert.rejects(t.get('https://portal.gov.uk/c',[],'asset'),code('protected-host'));
    await assert.rejects(t.addresses('https://www.example.gov/'),code('protected-host'),'not even a DNS query');
    await assert.rejects(t.preflight('https://www.example.gov/login?password=synthetic-not-a-secret'),code('protected-host'),'counted as protected even when the request also carries a credential');
    await assert.rejects(t.preflight('https://user:synthetic@portal.gov.uk/'),code('protected-host'));
    const pinned=await new Promise<Error|null>(resolve=>(t as any).openPinned(new URL('https://www.example.gov/'),{address:'127.0.0.1',family:4},(e:Error|null)=>resolve(e)));
    assert.ok(pinned instanceof PolicyError&&pinned.code==='protected-host','no socket is opened for a protected host');
    assert.deepEqual(lookups,[]);assert.equal(t.requests,0);assert.equal(t.connectionsOpened,0);assert.deepEqual(trip.violations,[]);
    const blocked=rows.filter(r=>r.reason==='protected-host');assert.deepEqual(blocked.map(r=>r.url),['https://www.example.gov/b','https://portal.gov.uk/c'],'one bounded row per host');assert.ok(blocked.every(r=>r.status==='blocked'&&r.bytes===0));
    const gap=gaps.filter(g=>g.code==='protected-host').at(-1);assert.equal(gap.incomplete,false);assert.equal(gap.count,2);assert.match(gap.detail,/never scans such websites \(built-in rule, no override\)/);
    assert.deepEqual(t.protectedView(),{hosts:2,references:2,overflow:0,examples:[{host:'www.example.gov',count:1,kinds:['http'],urls:['https://www.example.gov/b']},{host:'portal.gov.uk',count:1,kinds:['asset'],urls:['https://portal.gov.uk/c']}]});
    t.close();
  }finally{trip.restore();}
});

test('transport: a server whose TLS certificate names a protected host gets no request byte (an owner name aliasing a government service)',{timeout:60000},async()=>{
  const trip=egressTripwire();
  const run=async(names:string[])=>{const {cert,key}=loopbackCertificate(names);let handshakes=0,requests=0;
    const server=https.createServer({cert,key},(_q,res)=>{requests++;res.end('owner');});server.on('secureConnection',()=>handshakes++);await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));
    const origin=`https://owner.example.com:${(server.address() as any).port}`,rows:Resource[]=[],lookups:string[]=[];
    try{return await trusting(cert,async()=>{const t=new Transport(makeConfig({urls:[origin+'/'],privateOrigins:[origin],maxRetries:0}),new Evidence(detector),r=>rows.push(r),()=>{},async host=>{lookups.push(host);return [{address:'127.0.0.1',family:4}];});
      try{const outcome=await t.get(origin+'/').then(r=>r.status,(e:unknown)=>e);return {outcome,handshakes,requests,rows,lookups};}finally{t.close();}});}
    finally{await new Promise<void>(r=>{server.close(()=>r());server.closeAllConnections();});}};
  try{const aliased=await run(['owner.example.com','www.agency.example.gov']);
    assert.ok(aliased.outcome instanceof PolicyError&&aliased.outcome.code==='protected-host',String(aliased.outcome));assert.equal(aliased.requests,0,'the TLS handshake completed, but no HTTP request byte was written');
    assert.deepEqual([...new Set(aliased.lookups)],['owner.example.com']);assert.ok(aliased.rows.every(r=>r.bytes===0));
    const plain=await run(['owner.example.com']);assert.equal(plain.outcome,200,'an ordinary owner certificate is unaffected');assert.equal(plain.requests,1);
    assert.deepEqual(trip.violations,[]);
  }finally{trip.restore();}
  assert.deepEqual(certificateNames({subject:{CN:'owner.example.com'} as any,subjectaltname:'DNS:owner.example.com, DNS:*.agency.gov, IP Address:127.0.0.1'}),['owner.example.com','owner.example.com','agency.gov'],'wildcards count as their parent name; IP entries are ignored');
});

test('scan: redirect hops, discovered links, assets, source maps, sitemaps, WebSockets, checkpoint frontier and retry URLs to protected hosts send zero requests and leave the run complete',{timeout:120000},async()=>{
  const trip=egressTripwire(),lookups:string[]=[];
  const site=await owner({
    '/':['text/html',port=>`<!doctype html><html><head><title>Owner</title><link rel="stylesheet" href="https://static.army.mil/site.css"><script src="https://cdn.europa.eu/lib.js"></script></head><body>
      <a href="https://www.example.gov/forms">forms</a><a href="https://user:synthetic@intranet.example.gov/x">intranet</a><a href="http://portal.gov.uk/">portal</a><a href="/go">sign in</a><a href="http://owner.example.com:${port}/about">about</a><iframe src="https://forms.bund.de/embed"></iframe>
      <img src="https://img.example.gov/logo.png" alt=""><script src="/app.js"></script><script src="/b.js"></script><script>const socket=new WebSocket("wss://chat.example.gov/live");</script></body></html>`],
    '/app.js':['text/javascript','fetch("https://api.example.gov/v1/status").then(r=>r.json());\n//# sourceMappingURL=https://maps.example.mil/app.js.map'],
    '/go':['text/plain','moved',302,{location:'https://login.example.gov/start'}],
    '/b.js':['text/javascript','window.b=1;\n//# sourceMappingURL=/b.js.map'],'/b.js.map':['application/json',JSON.stringify({version:3,sections:[{offset:{line:0,column:0},url:'/section.map'}]})],
    '/section.map':['text/plain','moved',302,{location:'https://maps.example.gov/section.map'}],
    '/robots.txt':['text/plain','User-agent: *\nAllow: /\nSitemap: https://www.example.gov/sitemap.xml\nSitemap: /sitemap.xml\n'],
    '/sitemap.xml':['application/xml',port=>`<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://www.gov.uk/guidance</loc></url><url><loc>http://owner.example.com:${port}/about</loc></url></urlset>`],
    '/about':['text/html','<!doctype html><html><body><p>About</p><a href="https://kremlin.ru/">x</a></body></html>']});
  const origin=`http://owner.example.com:${site.port}`;
  try{const s=new Scanner({urls:[origin+'/'],privateOrigins:[origin],browser:false,semanticAnalysis:false,adjacentMaps:false,maxRetries:1,requestsPerSecond:20,originRequestsPerSecond:20,maxDurationMs:30000},
      {detector,resolver:async host=>{lookups.push(host);if(host==='owner.example.com')return [{address:'127.0.0.1',family:4}];throw new Error('unexpected lookup '+host);}});
    try{// A resumed checkpoint frontier is a local input too: it is refused the same way.
      s.enqueue('https://www.example.gov/frontier',origin+'/',0,['resumed checkpoint frontier'],'page');
      const v=await s.run();
      assert.deepEqual([...new Set(lookups)],['owner.example.com'],'no protected name was ever resolved');assert.deepEqual(trip.violations,[]);
      assert.ok(site.arrivals.length>=4&&site.arrivals.every(a=>a.host===`owner.example.com:${site.port}`),'every arrival is the owner website: '+JSON.stringify(site.arrivals));
      const hosts=new Set(v.resources.filter(r=>r.reason==='protected-host').map(r=>new URL(r.url).hostname));
      for(const h of ['www.example.gov','intranet.example.gov','portal.gov.uk','login.example.gov','cdn.europa.eu','static.army.mil','forms.bund.de','img.example.gov','chat.example.gov','maps.example.mil','maps.example.gov','www.gov.uk','kremlin.ru'])assert.ok(hosts.has(h),h+' is recorded as a protected-host block');
      assert.ok(!v.resources.some(r=>r.reason==='scope'&&isProtectedHost(r.url)),'a protected third-party host is recorded as protected, not merely out of scope');
      const rows=v.resources.filter(r=>isProtectedHost(r.url));assert.ok(rows.every(r=>r.bytes===0&&r.attemptId===undefined&&r.status==='blocked'&&r.reason==='protected-host'),'images included: every row on a protected host is a protected-host block: '+JSON.stringify(rows.map(r=>[r.url,r.status,r.kind,r.reason])));
      const gap=v.limitations.find(g=>g.code==='protected-host')!;assert.equal(gap.incomplete,false);assert.equal(v.limitations.filter(g=>g.code==='protected-host').length,1,'one aggregated gap');
      assert.equal(v.scope!.protected!.hosts,hosts.size);assert.equal(v.accounting!.protectedHostBlocks,v.scope!.protected!.references);assert.ok(v.scope!.protected!.references>=hosts.size);
      assert.ok(!(v.uninspected||[]).some(w=>isProtectedHost(w.url)),'no protected URL is ever queued for later');
      // The owner page that redirects into a protected host is deferred like an out-of-scope redirect (no gap), says why, and is never a retry candidate.
      assert.equal((v.uninspected||[]).find(w=>w.url===origin+'/go')?.deferredReason,'protected-host');assert.match(v.coverage!.inventory.find(r=>r.url===origin+'/go')!.reason!,/protected government, military, intelligence or law-enforcement host; never requested/);
      assert.ok(!focusedRetry(v,true).selected.some(w=>isProtectedHost(w.url)||w.url===origin+'/go'),'a retry plan never selects the rule\'s refusals');
      assert.equal(site.arrivals.filter(a=>a.path==='/section.map').length,1,'the redirecting map section was fetched once; its protected hop was not requested');
      assert.equal(site.arrivals.filter(a=>a.path==='/go').length,1,'the redirecting page was fetched once; its protected hop was not retried');
      // The disabled detector and semantic analysis are this fixture's own incomplete notes; the rule adds none.
      assert.deepEqual(v.limitations.filter(g=>g.incomplete).map(g=>g.code).sort(),['detector-unavailable','semantic-disabled'],'the protected references leave the run complete');
      assert.match(report(s,'html'),/hosts referenced and refused without any request: \d+/);assert.match(scopeCountLine(runSummary({view:v}).scope),/government\/military\/law-enforcement hosts? refused \(never scanned\)/);
      assert.equal(JSON.parse(report(s,'json')).accounting.protectedHostBlocks,v.accounting!.protectedHostBlocks);
    }finally{s.dispose();}
    // A focused retry plan runs only its selected items: a protected one among them is refused, the owner page is fetched.
    const before=site.arrivals.length,retry=new Scanner({urls:[origin+'/'],privateOrigins:[origin],browser:false,semanticAnalysis:false,adjacentMaps:false,requestsPerSecond:20,originRequestsPerSecond:20,maxDurationMs:30000},
      {detector,resolver:async host=>{lookups.push(host);if(host==='owner.example.com')return [{address:'127.0.0.1',family:4}];throw new Error('unexpected lookup '+host);}});
    try{retry.retry={sourceScan:randomUUID(),selected:[{url:'https://retry.example.mil/app.js',depth:0,chain:['previous run'],kind:'asset',enqueuedAt:Date.now()},{url:origin+'/about',depth:0,chain:['previous run'],kind:'page',enqueuedAt:Date.now()}],excluded:[],browserUrls:[],omitted:0,note:'synthetic retry'};
      const v=await retry.run();assert.ok(v.resources.some(r=>r.url==='https://retry.example.mil/app.js'&&r.reason==='protected-host'));assert.ok(site.arrivals.slice(before).some(a=>a.path==='/about'));
      assert.deepEqual([...new Set(lookups)],['owner.example.com']);assert.ok(site.arrivals.every(a=>a.host===`owner.example.com:${site.port}`));assert.deepEqual(trip.violations,[]);
    }finally{retry.dispose();}
  }finally{trip.restore();await site.close();}
});

test('scan: a protected name inside the seed\'s own domain (a US city government under a locality domain) is refused although domain scope would admit it',{timeout:120000},async()=>{
  const trip=egressTripwire(),lookups:string[]=[];
  const site=await owner({'/':['text/html',port=>`<!doctype html><html><body><a href="http://www.berkeley.ca.us:${port}/about">about</a><a href="http://ci.berkeley.ca.us:${port}/council">council</a><script src="http://ci.berkeley.ca.us:${port}/x.js"></script></body></html>`],
    '/about':['text/html','<!doctype html><p>about</p>']});
  const origin=`http://berkeley.ca.us:${site.port}`,www=`http://www.berkeley.ca.us:${site.port}`;
  try{assert.ok(!isProtectedHost('berkeley.ca.us')&&isProtectedHost('ci.berkeley.ca.us'));
    const s=new Scanner({urls:[origin+'/'],privateOrigins:[origin,www],browser:false,semanticAnalysis:false,adjacentMaps:false,requestsPerSecond:20,originRequestsPerSecond:20,maxDurationMs:30000},
      {detector,resolver:async host=>{lookups.push(host);if(['berkeley.ca.us','www.berkeley.ca.us'].includes(host))return [{address:'127.0.0.1',family:4}];throw new Error('unexpected lookup '+host);}});
    try{const v=await s.run();
      assert.ok(lookups.includes('www.berkeley.ca.us')&&v.resources.some(r=>new URL(r.url).hostname==='www.berkeley.ca.us'&&r.reason!=='scope'),'domain scope admitted the ordinary sibling (checked by DNS; a loopback answer then stays private)');
      assert.ok(!lookups.includes('ci.berkeley.ca.us'),'the protected sibling was never resolved');assert.ok(site.arrivals.every(a=>!a.host.startsWith('ci.')),'nor requested');
      const rows=v.resources.filter(r=>new URL(r.url).hostname==='ci.berkeley.ca.us');assert.ok(rows.length>0&&rows.every(r=>r.reason==='protected-host'&&r.status==='blocked'&&r.bytes===0),JSON.stringify(rows));
      assert.ok(v.scope!.protected!.hosts>=1);assert.ok(v.scope!.groups[0]!.notAdmitted.some(n=>n.reason==='protected-host'),'listed as inside the domain but not scanned, with the reason');assert.deepEqual(trip.violations,[]);
    }finally{s.dispose();}
  }finally{trip.restore();await site.close();}
});

test('saved projects: a blocked record from an older workspace keeps its exact record and legacy scope label; editing it out of the block keeps exact-origin scope',async()=>{
  const dir=await temp('protected-legacy-'),id=randomUUID(),now=new Date().toISOString();
  const legacy={id,config:{name:'Old portal',urls:['https://portal.example.gov/']},authorizedAt:now,createdAt:now};
  await writeFile(path.join(dir,'workspace.json'),JSON.stringify({schema:'exposure-workspace/2',projects:[legacy],reviews:{},settings:{retentionDays:90,maxScans:100,vaultMinutes:5},rules:[],ruleVersions:[],alerts:[]}));
  const file=async()=>JSON.parse(await readFile(path.join(dir,'workspace.json'),'utf8'));
  try{let st=await new Store(dir,true).init();assert.ok(st.isBlocked(id));assert.equal(st.blockedSources.get(id),'exposure-workspace/2');await st.save();st.close();
    const saved=await file();assert.deepEqual(saved.projects[0],legacy,'the record itself is carried unchanged');assert.deepEqual(saved.blockedSources,{[id]:'exposure-workspace/2'},'its source schema is kept beside it');
    st=await new Store(dir,true).init();const editable=st.editableConfig(st.projects[0]!) as any;
    assert.equal(editable.domainScope,'exact-origin');assert.deepEqual(editable.scopeReview,{reason:'legacy-default-exact-origin',from:'2.1–2.4.0-rc.1'},'the legacy label survives a save by a newer build');
    await assert.rejects(st.switchProfile(id,true),refused('portal.example.gov'),'refused even without a coverage level');
    const edited=await st.project({...editable,urls:['https://owner.example.com/']},true,id);assert.ok(!st.isBlocked(id));assert.equal(edited.config.domainScope,'exact-origin','editing the host out keeps the stored scope semantics');st.close();
    assert.equal((await file()).blockedSources,undefined,'nothing remains blocked');
  }finally{await rm(dir,{recursive:true,force:true});}
});

test('saved projects, queue, routines, deployment triggers and stale-asset replay: protected hosts are refused with the reason, never run and old records are never rewritten',{timeout:180000},async()=>{
  const trip=egressTripwire(),dir=await temp('protected-desk-'),site=await owner({'/':['text/html','<!doctype html><html><body><script src="/app.js"></script></body></html>'],'/app.js':['text/javascript','window.ok=1;'],'/old.js':['text/javascript','window.old=1;']});
  const blockedId=randomUUID(),now=new Date().toISOString(),past=new Date(Date.now()-7200000).toISOString();
  // A project saved by a build without the rule: it names a protected host and has a due routine and an enabled deployment trigger.
  const legacy={id:blockedId,config:{name:'Agency portal',urls:['https://portal.example.gov/'],preset:'standard'},authorizedAt:now,createdAt:now,schedule:{enabled:true,intervalHours:1,nextRun:past,missed:0},deploymentTrigger:{enabled:true,minIntervalMinutes:1,maxPerDay:24,recent:[]}};
  await writeFile(path.join(dir,'workspace.json'),JSON.stringify({schema:'exposure-workspace/3',projects:[legacy],reviews:{},settings:{retentionDays:90,maxScans:100,vaultMinutes:5},rules:[],ruleVersions:[],alerts:[]}));
  const stored=async()=>JSON.parse(await readFile(path.join(dir,'workspace.json'),'utf8')).projects.find((p:any)=>p.id===blockedId);
  const desk=new Desk(new Map(),()=>[]);
  try{await desk.init(dir,true);assert.equal(desk.storageError,'','the workspace stays available');const st=desk.store!;
    assert.ok(st.blocked.has(blockedId));assert.deepEqual(await stored(),legacy,'the old record is kept exactly as stored, schedule included');assert.ok(desk.notifications.some(n=>/Agency portal.*will never run/.test(n.text)));
    await assert.rejects(desk.enqueue([blockedId]),refused('portal.example.gov'));assert.equal(desk.queue.length,0);
    await desk.tick();assert.equal(desk.queue.length,0,'the routine never fires');assert.deepEqual(await stored(),legacy);assert.deepEqual(st.projects.find(p=>p.id===blockedId)!.schedule,legacy.schedule);
    const triggers=path.join(dir,'triggers');(desk as any).pumping=true;
    await writeTrigger(triggers,makeTrigger({projectId:blockedId}));await desk.processTriggers();assert.equal(st.alerts.at(-1)!.text,`Deployment trigger rejected: ${message('portal.example.gov')}.`);
    await assert.rejects(st.switchProfile(blockedId,true,'quick'),refused('portal.example.gov'),'switching a blocked project to a profile is refused, not saved');assert.deepEqual(await stored(),legacy);
    // Retry, rescan, resume and manual runs all start through Desk.start with the project id: refused there, whatever configuration they carry.
    await assert.rejects(desk.start({urls:[site.origin+'/'],developmentFixtureOrigin:site.origin},blockedId),refused('portal.example.gov'));assert.equal(site.arrivals.length,0);
    // An allowed project: a deployment trigger naming a protected asset is refused with the reason; a stale-asset history replay never contacts it.
    const p=await st.project({urls:[site.origin+'/'],developmentFixtureOrigin:site.origin,browser:false,semanticAnalysis:false,adjacentMaps:false,requestsPerSecond:20},true);p.deploymentTrigger={enabled:true,minIntervalMinutes:1,maxPerDay:24,recent:[]};await st.save();
    await writeTrigger(triggers,makeTrigger({projectId:p.id,assets:[site.origin+'/old.js','https://cdn.example.gov/old.js']}));await desk.processTriggers();assert.equal(st.alerts.at(-1)!.text,`Deployment trigger rejected: ${message('cdn.example.gov')}.`);assert.equal(desk.queue.length,0);
    (desk as any).pumping=false;
    st.history.push({schema:'exposure-history/2',projectId:p.id,savedAt:now,view:{id:randomUUID(),schema:'exposure-scan/1',name:'previous',state:'completed',startedAt:past,config:p.config,counts:{resources:2,scanned:2,blocked:0,bytes:0,pending:0,findings:0},findings:[],limitations:[],
      resources:[{url:'https://www.example.gov/old.js',code:200,kind:'asset',status:'downloaded',analysis:'analyzed',bytes:10,chain:[]},{url:site.origin+'/old.js',code:200,kind:'asset',status:'downloaded',analysis:'analyzed',bytes:10,chain:[]}]} as any});
    const s=await desk.start({...p.config,staleAssetCheck:true},p.id);while(s.state==='running')await new Promise(r=>setTimeout(r,50));
    const v=s.view();assert.ok(v.resources.some(r=>r.url==='https://www.example.gov/old.js'&&r.reason==='protected-host'),'the replayed protected URL is recorded as refused');assert.ok(site.arrivals.some(a=>a.path==='/old.js'),'the owner stale asset is replayed');
    assert.ok(site.arrivals.every(a=>a.host===new URL(site.origin).host));assert.deepEqual(trip.violations,[],'no lookup or socket left the machine');
    // Saving the project with an allowed configuration is the owner's explicit edit: it lifts the block.
    await st.project({urls:[site.origin+'/'],developmentFixtureOrigin:site.origin},true,blockedId);assert.ok(!st.blocked.has(blockedId));
    assert.ok(Date.parse(st.projects.find(p=>p.id===blockedId)!.schedule!.nextRun)>Date.now(),'an overdue routine does not fire the moment the block is lifted');
  }finally{(desk as any).pumping=false;desk.cancelQueue();await desk.close();trip.restore();await site.close();await rm(dir,{recursive:true,force:true});}
});

test('dashboard API: scans, previews, saves, queue, routines, triggers and profile switches naming protected hosts return the reason; the blocked project is listed with it',{timeout:120000},async()=>{
  const dir=await temp('protected-dashboard-'),blockedId=randomUUID(),now=new Date().toISOString();
  const legacy={id:blockedId,config:{name:'Ministry intranet',urls:['https://intranet.example.mil/']},authorizedAt:now,createdAt:now,schedule:{enabled:false,intervalHours:24,nextRun:now,missed:0}};
  await writeFile(path.join(dir,'workspace.json'),JSON.stringify({schema:'exposure-workspace/3',projects:[legacy],reviews:{},settings:{retentionDays:90,maxScans:100,vaultMinutes:5},rules:[],ruleVersions:[],alerts:[]}));
  const app=await startDashboard({port:0,persistent:true,dataDir:dir,syntheticData:true});
  try{const login=await fetch(app.origin+'/api/login',{method:'POST',headers:{'Content-Type':'application/json',Origin:app.origin,'X-Dashboard-Request':'1'},body:JSON.stringify({token:app.token})}),cookie=login.headers.get('set-cookie')!.split(';')[0],{csrf}=await login.json() as any;
    const headers={'Content-Type':'application/json',Origin:app.origin,'X-Dashboard-Request':'1','X-CSRF-Token':csrf,Cookie:cookie},post=(route:string,data:unknown)=>fetch(app.origin+route,{method:'POST',headers,body:JSON.stringify(data)});
    const expectRefusal=async(route:string,data:unknown,host:string)=>{const r=await post(route,data);assert.equal(r.status,400,route);assert.deepEqual(await r.json(),{error:message(host),code:'protected-host',host},route);};
    await expectRefusal('/api/scans',{authorized:true,config:{urls:['https://www.example.gov/']}},'www.example.gov');
    await expectRefusal('/api/scans',{authorized:true,preset:'quick',config:{urls:['https://owner.example.com/'],relatedOrigins:['https://cdn.europa.eu']}},'cdn.europa.eu');
    await expectRefusal('/api/scans',{authorized:true,projectId:blockedId,config:{urls:['https://owner.example.com/']}},'intranet.example.mil');
    await expectRefusal('/api/config/preview',{config:{urls:['https://www.gov.uk/']}},'www.gov.uk');await expectRefusal('/api/scope/preview',{config:{urls:['www.canada.ca']}},'www.canada.ca');
    await expectRefusal('/api/projects/save',{authorized:true,config:{urls:['https://www.bundeswehr.de/']}},'www.bundeswehr.de');
    await expectRefusal('/api/queue',{projectIds:[blockedId]},'intranet.example.mil');await expectRefusal('/api/schedule',{projectId:blockedId,authorized:true,enabled:true,intervalHours:24},'intranet.example.mil');
    await expectRefusal('/api/deployment-trigger',{projectId:blockedId,authorized:true,enabled:true},'intranet.example.mil');await expectRefusal('/api/projects/profile',{id:blockedId,authorized:true,coverage:'quick'},'intranet.example.mil');await expectRefusal('/api/projects/profile',{id:blockedId,authorized:true},'intranet.example.mil');
    await expectRefusal('/api/resume',{checkpoint:{schema:'exposure-checkpoint/1',config:{urls:['https://www.admin.ch/']},frontier:[]}},'www.admin.ch');
    assert.equal(app.scans.size,0,'no scan object was created');
    const w=await(await fetch(app.origin+'/api/workspace',{headers:{Cookie:cookie}})).json() as any,listed=w.projects.find((p:any)=>p.id===blockedId);
    assert.deepEqual(listed.blocked,{code:'protected-host',host:'intranet.example.mil',reason:message('intranet.example.mil')});assert.deepEqual(listed.config,migrateProjectConfig(legacy.config,'exposure-workspace/3'),'listed as it loads, so an edit keeps its scope');assert.equal(w.queue.length,0);
  }finally{await app.close();}
  try{assert.deepEqual(JSON.parse(await readFile(path.join(dir,'workspace.json'),'utf8')).projects.find((p:any)=>p.id===blockedId),legacy,'never rewritten');}finally{await rm(dir,{recursive:true,force:true});}
});

test('CLI: a protected seed, project file, checkpoint or trigger asset exits 2 with the message before any request',{timeout:120000},async()=>{
  const cli=path.join(root,'dist/src/cli.js'),dir=await temp('protected-cli-'),env={...process.env,EXPOSURE_DATA_DIR:dir},site=await owner({'/':['text/html','<!doctype html><p>owner</p>']});
  const run=(args:string[])=>spawnSync(process.execPath,[cli,...args],{encoding:'utf8',env,windowsHide:true,timeout:60000});
  try{let r=run(['scan','--url','https://WWW.Example.GOV./','--output',path.join(dir,'never.json')]);assert.equal(r.status,2);assert.equal(r.stderr.trim(),message('www.example.gov'));
    const cfg=path.join(dir,'projects.json');await writeFile(cfg,JSON.stringify({projects:[{urls:[site.origin+'/'],developmentFixtureOrigin:site.origin},{urls:['https://www.gouv.fr/']}]}));
    r=run(['scan','--config',cfg,'--output',path.join(dir,'never.json')]);assert.equal(r.status,2);assert.equal(r.stderr.trim(),message('www.gouv.fr'));assert.equal(site.arrivals.length,0,'every entry is checked before the first one runs');
    const checkpoint=path.join(dir,'checkpoint.json');await writeFile(checkpoint,JSON.stringify({schema:'exposure-checkpoint/1',config:{urls:['https://www.admin.ch/']},frontier:[]}));
    r=run(['scan','--resume',checkpoint,'--output',path.join(dir,'never.json')]);assert.equal(r.status,2);assert.equal(r.stderr.trim(),message('www.admin.ch'));
    r=run(['dashboard','--config',cfg,'--port','0']);assert.equal(r.status,2);assert.equal(r.stderr.trim(),message('www.gouv.fr'));
    const st=await new Store(dir,true).init(),p=await st.project({urls:[site.origin+'/'],developmentFixtureOrigin:site.origin},true);p.deploymentTrigger={enabled:true,minIntervalMinutes:1,maxPerDay:24,recent:[]};await st.save();st.close();
    const manifest=path.join(dir,'assets.json');await writeFile(manifest,JSON.stringify(['/app.js','https://cdn.example.gov/app.js']));
    r=run(['trigger','--data-dir',dir,'--project',p.id,'--assets',manifest]);assert.equal(r.status,2);assert.equal(r.stderr.trim(),'Trigger not written: '+message('cdn.example.gov'));
    assert.deepEqual(await readdir(path.join(dir,'triggers')),[],'no trigger file was written');assert.ok(!(await readdir(dir)).includes('never.json'));assert.equal(site.arrivals.length,0);
  }finally{await site.close();await rm(dir,{recursive:true,force:true});}
});
