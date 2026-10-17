import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir, rm } from 'node:fs/promises';
import path from 'node:path';
import { Detector, root } from '../src/detectors.js';
import { Evidence } from '../src/evidence.js';
import { makeConfig, normalizeUrl } from '../src/config.js';
import { Transport, PolicyError, publicAddress } from '../src/transport.js';
import { Scanner } from '../src/scanner.js';
import { report, exitState } from '../src/reports.js';
import { createFixture, synthetic, syntheticJwt } from '../src/fixture.js';
const detector=new Detector();detector.syntheticFixture=true;await detector.init();
test('pinned Gitleaks offline adapter executes, versions rules and recognizes additional detector',async()=>{
  assert.ok(detector.version==='8.30.1','Pinned engine must execute, not silently fall back');assert.ok(detector.ruleDigest.length===64);
  const result=await detector.inspect('SLACK_TOKEN=xoxb-123456789012-1234567890123-'+('Ab9Cx7Dy5Ez3Fh1Gi0Jk8Lm6').slice(0,24));
  assert.ok(result.some(c=>c.rule.startsWith('gitleaks:')),'Established engine should provide a finding beyond website rules');assert.ok(detector.issues.length===0);
});
test('provider classifications distinguish private credentials and client identifiers',()=>{
  const c=detector.inspectSync(Object.entries(synthetic).map(([k,v])=>`${k}=${JSON.stringify(v)}`).join('\n'));
  for(const provider of ['OpenAI','Anthropic','Stripe','Supabase','GitHub','Hugging Face','Replicate','SendGrid','AWS'])assert.ok(c.some(x=>x.provider===provider),`Provider missing: ${provider}`);
  assert.ok(c.some(x=>x.value===synthetic.publicStripe&&x.category==='public-identifier'));
  assert.ok(c.some(x=>x.value===synthetic.publicSupabase&&x.category==='public-identifier'));
  assert.ok(c.some(x=>x.value===synthetic.google&&x.category==='suspicious'));
  assert.ok(c.find(x=>x.value===synthetic.anthropic)?.provider==='Anthropic','Anthropic must not be mislabeled OpenAI');
});
test('anonymous/session JWTs, UUIDs, ordinary hashes and placeholders do not become private secrets',async()=>{
  const c=await detector.inspect(`api_key=your_api_key_here\nsession=${syntheticJwt.session}\ncsrf_token=abcde12345678901234567890\nhash=0123456789abcdef0123456789abcdef\nuuid=123e4567-e89b-12d3-a456-426614174000\npublic_key=abcdEfgh1234567890`);
  assert.ok(!c.some(x=>x.category==='private-credential'),'Negative examples must not be escalated');
  const j=detector.inspectSync(`${syntheticJwt.anon}\n${syntheticJwt.service}`);assert.ok(j.some(x=>x.value===syntheticJwt.anon&&x.category==='public-identifier'));assert.ok(j.some(x=>x.value===syntheticJwt.service&&x.category==='private-credential'));
});
test('bounded Base64, percent decoding, escaped strings and static concatenation preserve original representation and location',()=>{
  const encoded=Buffer.from(synthetic.stripe).toString('base64');const percent=synthetic.github.split('').map(c=>'%'+c.charCodeAt(0).toString(16)).join('');
  const concat=JSON.stringify(synthetic.openai.slice(0,25))+' + '+JSON.stringify(synthetic.openai.slice(25));const escaped=JSON.stringify(synthetic.hf).replace('hf_',String.raw`\u0068f_`);
  const text=`prefix\nencoded="${encoded}"; percent="${percent}"; joined=${concat};escaped=${escaped};`;
  const c=detector.inspectSync(text);
  for(const value of [synthetic.stripe,synthetic.github,synthetic.openai,synthetic.hf])assert.ok(c.some(x=>x.value===value&&x.transformations.length>0&&x.original!==value));
  assert.ok(c.find(x=>x.value===synthetic.openai&&x.transformations.length)?.index===text.indexOf(concat));
  detector.inspectSync('globalThis.__exposureFixtureExecution=true; throw new Error("must not execute");');assert.ok((globalThis as any).__exposureFixtureExecution===undefined,'Static analysis must not evaluate JavaScript');
});
test('HMAC deduplication preserves occurrences, source positions and per-session key separation',()=>{
  const e=new Evidence(detector),text='π\nOPENAI_API_KEY="'+synthetic.openai+'"';const candidate=detector.inspectSync(text).find(x=>x.value===synthetic.openai)!;
  e.add(candidate,text,'https://example.com/a.js',['page','bundle'],'Public resource');e.add(candidate,text,'https://example.com/b.js',['page','bundle'],'Public resource');e.add(candidate,text,'https://example.com/a.js',['page','bundle'],'Public resource');
  const f=[...e.findings.values()][0];assert.ok(e.findings.size===1&&f.occurrences.length===2);assert.ok(f.occurrences[0].line===2&&f.occurrences[0].column===17);assert.ok(f.occurrences[0].byteOffset===Buffer.byteLength(text.slice(0,candidate.index)));
  assert.ok(new Evidence(detector).fingerprint(synthetic.openai)!==f.fingerprint);
});
test('redaction recursively protects values, representations, URLs, keys and neighboring evidence',()=>{
  const e=new Evidence(detector),text=`value=${synthetic.openai}; other=${synthetic.github}`;
  for(const c of detector.inspectSync(text))e.add(c,text,'https://example.com/?api_key='+synthetic.openai,[],'Public');
  const safe=JSON.stringify(e.redact({[synthetic.github]:text,urls:['https://user:pass@example.com/?password=short'],nested:[e.full()],anonymous:syntheticJwt.session}));
  assert.ok(!safe.includes(synthetic.openai)&&!safe.includes(synthetic.github)&&!safe.includes('user:pass')&&!safe.includes('password=short'));
  assert.ok(!safe.includes(syntheticJwt.session),'An ordinary anonymous/session JWT should still be masked in unrelated evidence');
  const id=[...e.findings.values()].find(f=>f.provider==='OpenAI')!.id;const reveal=e.reveal(id);assert.ok(reveal.value===synthetic.openai);assert.ok(!reveal.locations[0].context.includes(synthetic.github));
});
test('deduplication upgrades a generic review value when stronger private credential evidence arrives',()=>{
  const e=new Evidence(detector),generic='API_KEY='+synthetic.context,db='postgres://fixture:'+synthetic.context+'@db.example.invalid/app';
  for(const c of detector.inspectSync(generic))e.add(c,generic,'https://example.com/config',[],'Public');for(const c of detector.inspectSync(db))e.add(c,db,'https://example.com/api',[],'Public');
  const f=[...e.findings.values()].find(f=>e.reveal(f.id).value===synthetic.context)!;assert.ok(f.category==='private-credential'&&f.severity==='high'&&f.provider==='Database');assert.ok(f.occurrences.length===2);
});
test('structured quoted credentials with punctuation remain exact review items without evaluating expressions',()=>{
  const value='S3cret!With@Punctuation?+',text=JSON.stringify({OAUTH_CLIENT_SECRET:value,password:'dictionarypassword'});const c=detector.inspectSync(text);
  assert.ok(c.some(c=>c.value===value&&c.category==='private-credential'&&c.provider==='OAuth'&&c.credentialSet?.state==='partial'&&c.credentialSet.missing.includes('client ID')));assert.ok(c.some(c=>c.value==='dictionarypassword'&&c.category==='suspicious'));
  assert.ok(!c.some(c=>c.value==='S3cret'),'Punctuation must not cause a partial credential value');
});
test('strict origin normalization and bounded settings reject scope/userinfo/traps',()=>{
  assert.ok(normalizeUrl('https://EXAMPLE.com:443/a?b=2&a=1#x')==='https://example.com/a?b=2&a=1');
  assert.throws(()=>makeConfig({urls:['file:///etc/passwd']}));assert.throws(()=>makeConfig({urls:['https://user:pass@example.com']}));assert.throws(()=>makeConfig({urls:['https://example.com'],relatedOrigins:['https://example.com/path']}));assert.throws(()=>makeConfig({urls:['https://example.com'],concurrency:100}));assert.throws(()=>makeConfig({urls:['https://example.com'],deepPaths:['/../dump']}));
});
test('SSRF blocks private, special, mapped, metadata and mixed DNS answers; explicit private scope remains exact',async()=>{
  for(const address of ['127.0.0.1','10.0.0.1','169.254.169.254','172.16.0.1','192.168.0.1','100.64.0.1','0.0.0.0','224.0.0.1','::1','fe80::1','fc00::1','::ffff:127.0.0.1','2001:db8::1'])assert.ok(!publicAddress(address),`Must block ${address}`);
  assert.ok(publicAddress('8.8.8.8'));const cfg=makeConfig({urls:['https://example.com']}),e=new Evidence(detector);
  const t=new Transport(cfg,e,()=>{},()=>{},async()=>[{address:'8.8.8.8',family:4},{address:'127.0.0.1',family:4}]);await assert.rejects(t.addresses('https://example.com'),x=>x instanceof PolicyError&&x.code==='private-address');
  const p=new Transport(makeConfig({urls:['http://intranet.test:80'],privateOrigins:['http://intranet.test']}),e,()=>{},()=>{},async()=>[{address:'10.0.0.1',family:4}]);assert.ok((await p.addresses('http://intranet.test'))[0].address==='10.0.0.1');await assert.rejects(p.addresses('http://intranet.test:81'),x=>x instanceof PolicyError&&x.code==='private-address');await assert.rejects(p.addresses('http://169.254.169.254'),x=>x instanceof PolicyError&&x.code==='metadata');
  for(const address of ['169.254.169.254','169.254.170.2','169.254.170.23','::ffff:169.254.169.254','100.100.100.200','fd00:ec2::254','fd00:ec2::23','fd20:ce::254']){
    const alias=new Transport(makeConfig({urls:['http://intranet.test'],privateOrigins:['http://intranet.test']}),e,()=>{},()=>{},async()=>[{address,family:address.includes(':')?6:4}]);
    await assert.rejects(alias.addresses('http://intranet.test'),x=>x instanceof PolicyError&&x.code==='metadata');assert.equal(alias.requests,0);
  }
});
test('DNS is resolved once for the actual pinned connection, including a changing resolver',async()=>{
  const f=await createFixture();try{
    let calls=0;const config=makeConfig({urls:[f.origin+'/clean'],developmentFixtureOrigin:f.origin});const t=new Transport(config,new Evidence(detector),()=>{},()=>{},async()=>{calls++;return calls===1?[{address:'127.0.0.1',family:4}]:[{address:'169.254.169.254',family:4}];});
    // Use an authorized explicit hostname resolving to the fixture's loopback address.
    const u=new URL(f.origin);const alias=`http://fixture.test:${u.port}`;const t2=new Transport(makeConfig({urls:[alias+'/clean'],privateOrigins:[alias]}),new Evidence(detector),()=>{},()=>{},t.resolver);
    const r=await t2.one(alias+'/clean');assert.ok(r.status===200&&calls===1,'Transport must not re-resolve after validation');
  }finally{await f.close();}
});
test('preflight blocks credential-bearing URL, encoded URL, headers, body and unauthorized methods before any request',async()=>{
  const f=await createFixture();try{
    const t=new Transport(makeConfig({urls:[f.origin],developmentFixtureOrigin:f.origin}),new Evidence(detector),()=>{},()=>{});
    const cases:{url:string;headers?:Record<string,string>;method?:string;body?:string}[]=[{url:f.origin+'/collect?api_key='+synthetic.openai},{url:f.origin+'/collect?api_key='+Buffer.from(synthetic.stripe).toString('base64')},{url:f.origin+'/collect',headers:{'x-api-key':synthetic.github}},{url:f.origin+'/collect',method:'POST',body:JSON.stringify({api_key:synthetic.supabase})},{url:f.origin+'/write',method:'POST'},{url:f.origin+'/delete'},{url:f.origin+'/collect',headers:{authorization:'Bearer opaque-token'}},{url:f.other+'/external'}];
    for(const c of cases)await assert.rejects(t.one(c.url,{...c}));assert.ok(f.arrivals.length===0,'No blocked request may reach either fixture server');assert.ok(t.requests===0);
    const post=new Transport(makeConfig({urls:[f.origin],developmentFixtureOrigin:f.origin,readOnlyPostEndpoints:[f.origin+'/clean']}),new Evidence(detector),()=>{},()=>{});assert.ok((await post.one(f.origin+'/clean',{method:'POST',body:'query=read-only'})).status===200);await assert.rejects(post.one(f.origin+'/write',{method:'POST'}));
  }finally{await f.close();}
});
test('each redirect is scope and credential checked before following',async()=>{
  const f=await createFixture();try{
    const t=new Transport(makeConfig({urls:[f.origin],developmentFixtureOrigin:f.origin,requestsPerSecond:20}),new Evidence(detector),()=>{},()=>{});
    await assert.rejects(t.get(f.origin+'/redirect-secret'));await assert.rejects(t.get(f.origin+'/redirect-out'));assert.ok(!f.arrivals.some(a=>/collect|external:/.test(a.path)),'Redirect destinations must receive no request');
  }finally{await f.close();}
});
test('dashboard port cannot be requested even if origin is explicitly scoped',async()=>{
  const config=makeConfig({urls:['http://127.0.0.1:4317'],privateOrigins:['http://127.0.0.1:4317']});const t=new Transport(config,new Evidence(detector),()=>{},()=>{});t.deniedPorts.add(4317);await assert.rejects(t.one(config.urls[0]),x=>x instanceof PolicyError&&x.code==='dashboard-isolation');assert.ok(t.requests===0);
});
test('crawl fixture covers chains/maps/deep checks and produces redacted reports with honest incomplete state',async()=>{
  const fixture=await createFixture();try{
    const s=new Scanner({urls:[fixture.origin],developmentFixtureOrigin:fixture.origin,deep:true,requestsPerSecond:20,maxResourceBytes:32768,maxResources:160,timeoutMs:2500,maxDurationMs:180000});await s.init();await s.run();const v=s.view();
    assert.ok(v.state==='incomplete'&&exitState(s)===2);for(const provider of ['OpenAI','Anthropic','Stripe','Supabase','Hugging Face','Replicate','SendGrid','AWS'])assert.ok(v.findings.some(f=>f.provider===provider),`Fixture coverage missing ${provider}`);
    assert.ok(!v.findings.some(f=>f.rule==='public-source-map'));assert.ok(v.resources.some(r=>r.sourceMap?.valid));assert.ok(v.findingTriage!.removedInsignificant>0);assert.ok(v.findings.some(f=>f.rule==='published-sensitive-file'&&f.occurrences.some(o=>o.url.endsWith('/.git/HEAD'))));
    assert.ok(!v.findings.some(f=>f.rule==='published-sensitive-file'&&f.occurrences.some(o=>/\.env.local|\.env.production/.test(o.url))),'SPA and soft404 do not prove file exposure');
    assert.ok(v.findings.some(f=>f.occurrences.some(o=>o.chain.some(c=>c.includes('app.min.js'))&&o.chain.includes('sourcesContent'))));assert.ok(v.findings.some(f=>f.occurrences.some(o=>o.transformations.some(t=>t.includes('Base64')))));
    for(const code of ['size-limit','authentication-challenge','network-failure','rate-limit','scope','credential-in-request','robots-exclusion'])assert.ok(v.limitations.some(g=>g.code===code),`Coverage note missing: ${code}`);
    assert.ok(!fixture.arrivals.some(a=>/collect|write|delete|external:|upgrade:/.test(a.path)));
    const paths=[JSON.stringify(v),JSON.stringify(s.checkpoint()),report(s,'json'),report(s,'html'),report(s,'sarif')];const secrets=Object.values(s.evidence.full()).map(x=>x.value).filter(x=>!x.startsWith('observation:'));
    for(const out of paths)assert.ok(secrets.every(secret=>!out.includes(secret)),'All default serialized output paths must be redacted');
    const full=report(s,'json',true);assert.ok(full.includes(synthetic.openai),'Deliberate full export must retain complete value');
    const findings=[...s.evidence.findings.values()];const key=findings.find(f=>f.provider==='OpenAI')!;const reveal=s.evidence.reveal(key.id);assert.ok(reveal.value===synthetic.openai);assert.ok(reveal.representations.length>1,'Raw and reconstructed representations retained');
    const reportDir=process.env.EXPOSURE_TEST_OUTPUT||path.join(root,'.cache','test-output');await mkdir(reportDir,{recursive:true});for(const format of ['json','html','sarif'] as const)await writeFile(path.join(reportDir,`fixture.${format==='sarif'?'sarif.json':format}`),report(s,format),{mode:0o600});
  }finally{await fixture.close();}
});
test('source-map parser failures, virtual sources, sourceRoot and traversal produce bounded coverage',async()=>{
  const s=new Scanner({urls:['https://example.com'],maxMapSources:1,maxMaps:3});s.detector.version='unavailable';
  await s.map('{invalid','https://example.com/a.js.map',[]);await s.map(JSON.stringify({version:3,sources:['../../secret.ts'],names:[],mappings:''}),'https://example.com/a.js.map',[]);
  await s.map(JSON.stringify({version:3,sourceRoot:'/source/',sources:['a.ts','b.ts'],sourcesContent:[null,null],names:[],mappings:''}),'https://example.com/a.js.map',[]);assert.ok(s.queue.some(w=>w.url==='https://example.com/source/a.ts'));assert.ok(!s.queue.some(w=>w.url.includes('secret.ts')));
  for(const code of ['invalid-map','source-traversal','partial-map'])assert.ok(s.limitations.some(g=>g.code===code));
});
test('cancellation aborts live requests and leaves resumable redacted frontier',async()=>{
  const f=await createFixture();try{
    const s=new Scanner({urls:[f.origin+'/slow'],developmentFixtureOrigin:f.origin,requestsPerSecond:20,maxDurationMs:60000});await s.init();const job=s.run();setTimeout(()=>s.cancel(),500);await job;assert.ok(s.state==='cancelled'&&exitState(s)===2);assert.ok(JSON.stringify(s.checkpoint()).includes('exposure-checkpoint/1'));
  }finally{await f.close();}
});
test('resource/total byte and duration budgets cannot become clean successes',async()=>{
  const f=await createFixture();try{
    const s=new Scanner({urls:[f.origin+'/big'],developmentFixtureOrigin:f.origin,maxTotalBytes:2048,maxResourceBytes:2048,requestsPerSecond:20,maxDurationMs:60000});await s.init();await s.run();assert.ok(s.transport.bytes<=2048&&s.state==='incomplete');
    const t=new Transport(makeConfig({urls:[f.origin],developmentFixtureOrigin:f.origin,maxDurationMs:100}),new Evidence(detector),()=>{},()=>{});t.started=Date.now()-1000;await assert.rejects(t.one(f.origin+'/clean'),x=>x instanceof PolicyError&&x.code==='duration-limit');assert.ok(t.requests===0);
  }finally{await f.close();}
});
test('missing/failed detector reports incomplete; healthy clean fixture and policy exit states are distinct',async()=>{
  const f=await createFixture(0,{minimalDiscovery:true});try{
    const healthy=new Scanner({urls:[f.origin+'/clean'],developmentFixtureOrigin:f.origin,requestsPerSecond:20,adjacentMaps:false});await healthy.init();await healthy.run();assert.ok(healthy.state==='completed'&&exitState(healthy)===0,'Healthy clean fixture must complete');
    const bad=new Scanner({urls:[f.origin+'/clean'],developmentFixtureOrigin:f.origin,requestsPerSecond:20},{detector:new Detector(path.join(root,'.tools','missing-detector'))});await bad.init();await bad.run();assert.ok(bad.state==='incomplete'&&exitState(bad)===2);
    const exposure=new Scanner({urls:[f.origin+'/.env'],developmentFixtureOrigin:f.origin,requestsPerSecond:20,adjacentMaps:false});await exposure.init();await exposure.run();assert.ok(exposure.state==='completed'&&exitState(exposure)===1);
    for(const finding of exposure.evidence.findings.values())exposure.evidence.suppress(finding.id,'Reviewed synthetic fixture',new Date(Date.now()+100000).toISOString());assert.ok(exitState(exposure)===0);assert.ok(exposure.view().findings.every(f=>f.suppression));
  }finally{await f.close();}
});
test('reports render malicious target evidence as inert escaped text',()=>{
  const s=new Scanner({urls:['https://example.com'],name:'<img src=x onerror=alert(1)>'});const text=`<script>alert(1)</script>PRIVATE_API_KEY=${synthetic.openai}`;
  for(const c of detector.inspectSync(text))s.evidence.add(c,text,'https://example.com/',[],text);
  const html=report(s,'html');assert.ok(!html.includes('<script>')&&!html.includes('<img src=x'));assert.ok(html.includes('&lt;script&gt;'));assert.ok(html.includes("default-src 'none'"));
});
test('query variations, depth and resource discovery limits are recorded',()=>{
  const s=new Scanner({urls:['https://example.com'],queryVariants:1,maxDepth:1,maxResources:2});s.enqueue('/a?q=1','https://example.com',0,[],'page');s.enqueue('/a?q=2','https://example.com',0,[],'page');s.enqueue('/deep','https://example.com',2,[],'page');s.enqueue('/b','https://example.com',0,[]);s.enqueue('/c','https://example.com',0,[]);assert.ok(s.queue.length===2);for(const code of ['query-variants','crawl-depth','discovery-budget'])assert.ok(s.limitations.some(g=>g.code===code));
});
