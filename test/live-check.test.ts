import test from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { readFile, readdir, mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { loopbackCertificate, trusting } from './tls-fixture.js';
import { egressTripwire } from './virtual-network.js';
import { checkOneKey, LiveCheckRefused, type CheckEnv } from '../src/live-check/egress.js';
import { runLiveCheckAll, type LiveCheckItem, type LiveCheckAllProgress } from '../src/live-check/run-all.js';
import { recipeFor, allRecipes, verifyHosts, SLACK_REVOKED_ERRORS, type VerifyRecipe } from '../src/live-check/recipes.js';
import { Store } from '../src/storage.js';
import { Evidence } from '../src/evidence.js';
import { Detector, root } from '../src/detectors.js';
import { Transport, PolicyError } from '../src/transport.js';
import { makeConfig } from '../src/config.js';
import { normalizeProgramConfig } from '../src/program/settings.js';
import type { Finding } from '../src/types.js';

/**
 * Live key check (2.9). Loopback mock providers only (127.0.0.1 HTTPS servers reached through the code-only CheckEnv seam) and synthetic keys only; the
 * egress tripwire proves nothing reaches a real external host. Covers: off by default / no request without a recipe, each verdict state per presentation style,
 * fail-closed unknown provider, protected-host refusal, the paced run-all driver (one at a time, cancel, halt on the first 429/403), masking in stored state and
 * redacted reports, old review/program files still loading, the scan transport still refusing 'credential-in-request', and the import-graph isolation of live-check.
 */

// A single loopback HTTPS server standing in for every provider recipe host. It decides the HTTP status/body from the *presented synthetic key* so one server
// exercises every verdict path, and records exactly what each request carried so a test can prove only the one documented header (and nothing from a scan) was sent.
interface Arrival { host:string; path:string; method:string; headers:Record<string,string|string[]|undefined>; body:string; presented:string }
function mockProviders(opts:{cert:string;key:string;delayMs?:number}){
  const arrivals:Arrival[]=[];let inFlight=0,maxInFlight=0;
  const verdictFor=(host:string,presented:string)=>{
    switch(presented){
      case 'live':return {status:200,body:'{"ok":true}'};
      case 'revoked':return {status:401,body:'{"error":"unauthorized"}'};
      case 'forbidden':return {status:403,body:'{"error":"forbidden"}'};   // revoked for SendGrid, http-error (unknown) elsewhere
      case 'rate':return {status:429,body:'{"error":"rate"}'};
      case 'servererror':return {status:500,body:'{"error":"boom"}'};
      case 'redirect':return {status:302,body:'',location:'https://www.example.gov/moved'};
      default:return {status:200,body:'{"ok":true}'};                      // a real synthetic key (dashboard happy path) counts as live
    }
  };
  const server=https.createServer({cert:opts.cert,key:opts.key},(req,res)=>{
    inFlight++;maxInFlight=Math.max(maxInFlight,inFlight);
    let body='';req.on('data',c=>body+=c);req.on('end',()=>{
      const host=String(req.headers.host||'').split(':')[0],auth=String(req.headers['authorization']||'');
      const presented=String(req.headers['x-api-key']||req.headers['private-token']||'')
        ||(auth.startsWith('Bearer ')?auth.slice(7):auth.startsWith('Basic ')?Buffer.from(auth.slice(6),'base64').toString('utf8').replace(/:$/,''):'');
      arrivals.push({host,path:req.url||'',method:req.method||'',headers:req.headers,body,presented});
      const finish=()=>{
        if((req.url||'').startsWith('/api/auth.test')){ // Slack: 200 + {ok}
          const map:Record<string,unknown>={live:{ok:true},revoked:{ok:false,error:'invalid_auth'},weird:{ok:false,error:'mystery'}};
          res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify(map[presented]??{ok:false,error:'mystery'}));inFlight--;return;
        }
        const v=verdictFor(host,presented) as any;
        res.writeHead(v.status,{'content-type':'application/json',...(v.location?{location:v.location}:{})});res.end(v.body);inFlight--;
      };
      if(opts.delayMs)setTimeout(finish,opts.delayMs);else finish();
    });
  });
  return {server,arrivals,get maxInFlight(){return maxInFlight;}};
}
const listen=(server:https.Server)=>new Promise<number>(r=>server.listen(0,'127.0.0.1',()=>r((server.address() as any).port)));
const tmp=async(prefix:string)=>{const base=process.env.EXPOSURE_DATA_DIR||path.join(root,'.cache');await mkdir(base,{recursive:true});return mkdtemp(path.join(base,prefix));};
const close=(server:https.Server)=>new Promise<void>(r=>{server.closeAllConnections?.();server.close(()=>r());});
// Loopback env seam: resolve every recipe host to 127.0.0.1, require loopback (production requires public), and inject the mock port. recipes defaults to the real table.
const loopbackEnv=(port:number,extra:Partial<CheckEnv>={}):CheckEnv=>({resolver:async()=>[{address:'127.0.0.1',family:4}],allowLoopback:true,port,timeoutMs:4000,...extra});

test('off by default: no recipe for a rule means no request is made and the verdict fails closed to unknown/no-recipe',async()=>{
  const trip=egressTripwire();
  try{
    const r=await checkOneKey({rule:'not-a-real-provider',key:'sk-synthetic-xxxxxxxxxxxxxxxxxxxxxxxx',provider:'Nobody'});
    assert.equal(r.result,'unknown');assert.equal(r.reason,'no-recipe');assert.equal(r.status,undefined);
    assert.deepEqual(trip.violations,[],'a rule with no recipe never opens a socket or resolves a host');
  }finally{trip.restore();}
});

test('a per-finding check returns the right verdict for each result state, using each provider presentation style, and sends only the one documented header',async()=>{
  const {cert,key}=loopbackCertificate(verifyHosts());
  const mock=mockProviders({cert,key}),port=await listen(mock.server),trip=egressTripwire();
  try{await trusting(cert,async()=>{
    const env=loopbackEnv(port);
    // bearer (GitHub) across every status
    assert.equal((await checkOneKey({rule:'github',key:'live'},env)).result,'live');
    const revoked=await checkOneKey({rule:'github',key:'revoked'},env);assert.equal(revoked.result,'revoked');assert.equal(revoked.status,401);
    const ghForbidden=await checkOneKey({rule:'github',key:'forbidden'},env);assert.equal(ghForbidden.result,'unknown');assert.equal(ghForbidden.reason,'http-error');
    const limited=await checkOneKey({rule:'github',key:'rate'},env);assert.equal(limited.result,'unknown');assert.equal(limited.reason,'rate-limited');assert.equal(limited.status,429);
    const weird=await checkOneKey({rule:'github',key:'servererror'},env);assert.equal(weird.result,'unknown');assert.equal(weird.reason,'http-error');
    const redirected=await checkOneKey({rule:'github',key:'redirect'},env);assert.equal(redirected.result,'unknown');assert.equal(redirected.reason,'redirect');assert.equal(redirected.status,302);
    // SendGrid declares 403 as revoked; the same 403 is only http-error for GitHub above.
    assert.equal((await checkOneKey({rule:'sendgrid',key:'forbidden'},env)).result,'revoked');
    // header (GitLab PRIVATE-TOKEN), x-api-key (Anthropic), basic (Stripe)
    assert.equal((await checkOneKey({rule:'gitlab',key:'live'},env)).result,'live');
    assert.equal((await checkOneKey({rule:'anthropic',key:'live'},env)).result,'live');
    assert.equal((await checkOneKey({rule:'stripe-secret',key:'live'},env)).result,'live');
    // Slack signal (200 + {ok})
    assert.equal((await checkOneKey({rule:'gitleaks:slack-bot-token',key:'live'},env)).result,'live');
    assert.equal((await checkOneKey({rule:'gitleaks:slack-bot-token',key:'revoked'},env)).result,'revoked');
    const slackWeird=await checkOneKey({rule:'gitleaks:slack-user-token',key:'weird'},env);assert.equal(slackWeird.result,'unknown');assert.equal(slackWeird.reason,'unexpected-shape');

    // Only the documented header carried the key, nothing else from a scan. Inspect the GitHub 'live' arrival.
    const gh=mock.arrivals.find(a=>a.host==='api.github.com'&&a.presented==='live')!;
    assert.ok(gh,'the GitHub request arrived');assert.equal(gh.headers['authorization'],'Bearer live');
    assert.equal(gh.headers['user-agent'],'ExposureDesk','honest product User-Agent only');
    assert.equal(gh.headers['accept'],'application/vnd.github+json');
    for(const forbidden of ['cookie','referer','x-forwarded-for','x-bug-bounty','origin'])assert.equal(gh.headers[forbidden],undefined,'no '+forbidden+' header is sent');
    const stripe=mock.arrivals.find(a=>a.host==='api.stripe.com')!;assert.ok(String(stripe.headers['authorization']).startsWith('Basic '),'Stripe uses HTTP basic');
    const anthropic=mock.arrivals.find(a=>a.host==='api.anthropic.com')!;assert.equal(anthropic.headers['x-api-key'],'live');assert.equal(anthropic.headers['anthropic-version'],'2023-06-01');
    const gitlab=mock.arrivals.find(a=>a.host==='gitlab.com')!;assert.equal(gitlab.headers['private-token'],'live');assert.equal(gitlab.headers['authorization'],undefined);
    assert.ok(mock.arrivals.every(a=>a.body===''||a.method==='POST'),'only POST recipes send a body');
    assert.deepEqual(trip.violations,[],'nothing reached the real network');
  });}finally{trip.restore();await close(mock.server);}
});

test('a protected-host endpoint (defence in depth) is refused with LiveCheckRefused before any DNS or socket, with no override',async()=>{
  const trip=egressTripwire();
  try{
    // A recipe seam that (hypothetically) names a government host: the dial guard refuses it and never resolves or connects.
    const recipes=(_r:string):VerifyRecipe=>({provider:'X',rules:['x'],host:'portal.example.gov',method:'GET',path:'/me',present:'bearer',signal:'status',live:[200],revoked:[401],doc:'test'});
    await assert.rejects(
      checkOneKey({rule:'x',key:'live'},{recipes,resolver:async()=>assert.fail('a protected host must never be resolved'),allowLoopback:true}),
      e=>e instanceof LiveCheckRefused&&e.code==='protected-host');
    assert.deepEqual(trip.violations,[],'no socket or lookup for a protected host');
  }finally{trip.restore();}
});

test('run-all is paced and strictly one key at a time, and cancel stops the remaining keys',async()=>{
  const {cert,key}=loopbackCertificate(verifyHosts());
  const mock=mockProviders({cert,key,delayMs:15}),port=await listen(mock.server),trip=egressTripwire();
  try{await trusting(cert,async()=>{
    const items:LiveCheckItem[]=[
      {correlation:'a'.repeat(64),rule:'github',provider:'GitHub',key:'live'},
      {correlation:'b'.repeat(64),rule:'openai',provider:'OpenAI',key:'live'},
      {correlation:'c'.repeat(64),rule:'anthropic',provider:'Anthropic',key:'live'}];
    const started=Date.now();
    const final=await runLiveCheckAll(items,{env:loopbackEnv(port),perProviderPauseMs:0});
    assert.equal(final.running,false);assert.equal(final.done,3);assert.equal(Object.keys(final.results).length,3);
    assert.equal(mock.maxInFlight,1,'only one request is ever in flight at a time');
    assert.ok(Date.now()-started>=45,'three serial 15ms requests take at least 45ms');
    for(const c of items.map(i=>i.correlation))assert.equal(final.results[c]!.result,'live');

    // Cancel after the first result: the rest are not checked.
    const controller=new AbortController();
    const cancelled=await runLiveCheckAll(items,{env:loopbackEnv(port),perProviderPauseMs:0,signal:controller.signal,onProgress:p=>{if(p.done>=1)controller.abort();}});
    assert.equal(cancelled.cancelled,true);assert.ok(cancelled.done<3,'cancel stops before every key is checked: '+cancelled.done);
  });}finally{trip.restore();await close(mock.server);}
});

test('run-all halts a provider on its first 429 or 403 and skips that provider\'s remaining keys',async()=>{
  const {cert,key}=loopbackCertificate(verifyHosts());
  const mock=mockProviders({cert,key}),port=await listen(mock.server),trip=egressTripwire();
  try{await trusting(cert,async()=>{
    const items:LiveCheckItem[]=[
      {correlation:'1'.repeat(64),rule:'github',provider:'GitHub',key:'rate'},   // 429 -> halts GitHub
      {correlation:'2'.repeat(64),rule:'github',provider:'GitHub',key:'live'},   // skipped
      {correlation:'3'.repeat(64),rule:'openai',provider:'OpenAI',key:'forbidden'}, // 403 -> halts OpenAI
      {correlation:'4'.repeat(64),rule:'openai',provider:'OpenAI',key:'live'},   // skipped
      {correlation:'5'.repeat(64),rule:'anthropic',provider:'Anthropic',key:'live'}]; // unaffected
    const final=await runLiveCheckAll(items,{env:loopbackEnv(port),perProviderPauseMs:0});
    assert.deepEqual([...final.haltedProviders].sort(),['GitHub','OpenAI']);
    assert.ok(final.skipped.includes('2'.repeat(64))&&final.skipped.includes('4'.repeat(64)),'remaining keys of a halted provider are skipped');
    assert.equal(final.results['5'.repeat(64)]!.result,'live','an unaffected provider still runs');
    assert.equal(mock.arrivals.filter(a=>a.host==='api.github.com').length,1,'the halted GitHub provider made exactly one request');
  });}finally{trip.restore();await close(mock.server);}
});

test('the key is masked everywhere: it is never in the stored review state or a redacted report, and a redacted progress keeps its correlation keys and verdict fields',async()=>{
  const dir=await tmp('live-mask-');
  try{
    const synthetic='sk-proj-'+'T3BlbkFJ'+'x9Qw7Zr2Kd8Lm5Np1Vc6Hs4Gj0Yb3Af7Ei2Rt9Uo';// realistic high-entropy synthetic, not a low-entropy placeholder the detector ignores; split so repository secret scanners do not flag the literal
    const masker=new Evidence(new Detector());
    // A result object never carries the key; even if a secret-looking string were embedded in a free field, redact scrubs it while enum/control/schema fields survive.
    const result={result:'live',checkedAt:'2026-10-14T00:00:00.000Z',provider:'OpenAI',endpointHost:'api.openai.com',status:200,reason:'http-error',note:'leak '+synthetic};
    const red=masker.redact(result) as any;
    assert.equal(red.result,'live');assert.equal(red.reason,'http-error');assert.equal(red.endpointHost,'api.openai.com');assert.equal(red.status,200);
    assert.ok(!JSON.stringify(red).includes(synthetic),'any embedded secret is scrubbed from a redacted report');
    const corr='f'.repeat(64);
    const progress:LiveCheckAllProgress={total:1,done:1,running:false,cancelled:false,haltedProviders:['OpenAI'],results:{[corr]:{result:'revoked',checkedAt:'2026-10-14T00:00:00.000Z',provider:'OpenAI',reason:'http-error'}},skipped:[]};
    const redProgress=masker.redact(progress) as any;
    assert.ok(redProgress.results[corr],'the 64-hex correlation key survives redaction');
    assert.equal(redProgress.results[corr].result,'revoked');assert.deepEqual(redProgress.haltedProviders,['OpenAI']);

    // Stored review state: recordLiveCheck persists the verdict (never the key) and applyReviews copies it onto findings, including history views.
    const st=await new Store(dir,true).init(),p=await st.project({urls:['https://www.example.com/']},true);
    const f:Finding={id:'0'.repeat(32),fingerprint:'0'.repeat(32),correlation:'a'.repeat(64),category:'private-credential',provider:'OpenAI',rule:'openai',severity:'high',confidence:'high',reasons:[],masked:'[redacted: 51 characters]',validity:'unverified',impact:'',remediation:'',occurrences:[{url:'https://www.example.com/app.js',chain:['https://www.example.com/'],transformations:[],excerpt:'[redacted]',evidence:'Public response',exposure:'public-response',environment:'production'}]} as Finding;
    await st.recordLiveCheck(p.id,f,{result:'live',checkedAt:'2026-10-14T00:00:00.000Z',provider:'OpenAI',endpointHost:'api.openai.com',status:200});
    assert.equal(st.reviews[p.id]['a'.repeat(64)].liveCheck!.result,'live','the verdict is stored in the review state');
    const workspace=await readFile(path.join(dir,'workspace.json'),'utf8');assert.ok(!workspace.includes(synthetic),'no key value is ever written to the workspace');
    const fresh:Finding={...f,liveCheck:undefined} as Finding;st.applyReviews(p.id,[fresh]);
    assert.equal(fresh.liveCheck!.result,'live','applyReviews copies the stored verdict onto a finding');
    // recordLiveCheck fails closed without a saved project.
    await assert.rejects(st.recordLiveCheck('no-such-project',f,{result:'live',checkedAt:'x',provider:'OpenAI'}),/Saved project required/);
    st.close();
  }finally{await rm(dir,{recursive:true,force:true});}
});

test('old review and program files still load: a review without a liveCheck and a program without liveKeyChecks are accepted unchanged',async()=>{
  const dir=await tmp('live-legacy-');
  try{
    // A pre-2.9 workspace: a review patch with no liveCheck field.
    const pid='11111111-1111-1111-1111-111111111111',corr='b'.repeat(64);
    const workspace={schema:'exposure-workspace/4',projects:[{id:pid,name:'legacy',config:{urls:['https://www.example.com/']}}],reviews:{[pid]:{[corr]:{reviewedAt:'2026-01-01T00:00:00.000Z',status:'reviewing'}}},settings:{retentionDays:90,maxScans:100,vaultMinutes:5}};
    await writeFile(path.join(dir,'workspace.json'),JSON.stringify(workspace),{mode:0o600});
    const st=await new Store(dir,true).init();
    assert.equal(st.reviews[pid][corr].status,'reviewing','a legacy review without liveCheck loads');
    assert.equal(st.reviews[pid][corr].liveCheck,undefined);
    st.close();
    // A pre-2.9 program config (no liveKeyChecks) normalizes without error and leaves checks off.
    const program=normalizeProgramConfig({id:'0123456789abcdef',scope:{in:['example.com'],out:[]},requestsPerSecond:2,concurrency:{targets:1,requests:4},headers:{}});
    assert.equal(program.liveKeyChecks,undefined,'absent means no key is ever sent');
  }finally{await rm(dir,{recursive:true,force:true});}
});

test('the scan transport still refuses a credential-in-request: the live key check is a separate, explicit egress path',async()=>{
  const evidence=new Evidence(new Detector(),randomBytes(32));
  const t=new Transport(makeConfig({urls:['https://ok.example.com/']}),evidence,()=>{},()=>{});
  try{
    await assert.rejects(
      t.preflight('https://ok.example.com/x','GET',{authorization:'Bearer '+'sk-proj-'+'A'.repeat(48)}),
      e=>e instanceof PolicyError&&(e as PolicyError).code==='credential-in-request');
  }finally{t.close();}
});

test('the recipe table is exact-match and fails closed; every recipe names one HTTPS host documented by a doc URL',()=>{
  assert.equal(recipeFor('openai')!.provider,'OpenAI');
  assert.equal(recipeFor('OPENAI'),undefined,'lookup is exact; a near-match is not accepted');
  assert.equal(recipeFor(undefined),undefined);
  assert.equal(recipeFor(''),undefined);
  for(const r of allRecipes()){
    assert.ok(r.rules.length>0&&r.host&&r.path.startsWith('/'),'a recipe names a host and a path: '+r.provider);
    assert.ok(/^https:\/\//.test(r.doc),'each recipe carries its provider doc URL: '+r.provider);
    assert.ok(['bearer','header','basic','x-api-key'].includes(r.present));
    if(r.present==='header')assert.ok(r.headerName,'header presentation needs a header name');
  }
  assert.ok(SLACK_REVOKED_ERRORS.includes('invalid_auth'));
  assert.deepEqual(verifyHosts(),[...new Set(allRecipes().map(r=>r.host))].sort());
});

// Compile-time guard: the caller can never choose the endpoint; only the recipe table does, so CheckOneKeyInput has no `url`.
// @ts-expect-error url is not a property of CheckOneKeyInput
void ((): unknown=>checkOneKey({rule:'github',key:'x',url:'https://attacker.example'}));

test('import-graph isolation: the scanner, transport and mass-run never import the live-check egress path',async()=>{
  const here=path.dirname(fileURLToPath(import.meta.url));              // .../dist/test
  const srcDir=path.resolve(here,'../src');
  const seen=new Set<string>();
  const specifiers=async(file:string)=>{const text=await readFile(file,'utf8');const out:string[]=[];
    for(const m of text.matchAll(/(?:from|import)\s*\(?\s*['"]([^'"]+)['"]/g))out.push(m[1]!);return out;};
  const visit=async(file:string)=>{
    if(seen.has(file))return;seen.add(file);
    let specs:string[];try{specs=await specifiers(file);}catch{return;}
    for(const s of specs){if(!s.startsWith('.'))continue;const resolved=path.resolve(path.dirname(file),s);await visit(resolved);}
  };
  for(const entry of ['scanner.js','transport.js','mass/scheduler.js','mass/state.js'])await visit(path.join(srcDir,entry));
  const leaked=[...seen].filter(f=>f.replace(/\\/g,'/').includes('/live-check/'));
  assert.deepEqual(leaked,[],'no scan/crawl/transport/mass-run module may import live-check/*: '+leaked.join(', '));
  assert.ok([...seen].some(f=>f.endsWith('transport.js')),'the graph actually traversed (sanity)');
});

test('the egress path refuses a metadata address and treats a private/loopback address as not-allowlisted (address-class guard, same as the scan transport)',async()=>{
  const trip=egressTripwire();
  try{
    const recipes=(_r:string):VerifyRecipe=>({provider:'GitHub',rules:['github'],host:'api.github.com',method:'GET',path:'/user',present:'bearer',signal:'status',live:[200],revoked:[401],doc:'test'});
    // A DNS answer that resolves to the cloud metadata address is a hard refusal before any socket.
    await assert.rejects(
      checkOneKey({rule:'github',key:'live'},{recipes,resolver:async()=>[{address:'169.254.169.254',family:4}]}),
      e=>e instanceof LiveCheckRefused&&e.code==='metadata');
    // A private/loopback answer (production requires a public unicast address) fails closed to unknown/host-not-allowlisted, no request sent.
    for(const addr of ['10.0.0.5','127.0.0.1','192.168.1.1']){
      const r=await checkOneKey({rule:'github',key:'live'},{recipes,resolver:async()=>[{address:addr,family:4}]});
      assert.equal(r.result,'unknown');assert.equal(r.reason,'host-not-allowlisted','private address '+addr+' is not dialed');
    }
    assert.deepEqual(trip.violations,[],'no answer that fails the address-class guard ever opens a socket');
  }finally{trip.restore();}
});

test('the strict liveKeyChecks validator accepts a well-formed opt-in, splits per-finding from check-all, and refuses unknown or wrong-typed sub-keys',()=>{
  const base={id:'0123456789abcdef',scope:{in:['example.com'],out:[]},requestsPerSecond:2,concurrency:{targets:1,requests:4},headers:{}};
  assert.deepEqual(normalizeProgramConfig({...base,liveKeyChecks:{enabled:true}}).liveKeyChecks,{enabled:true});
  assert.deepEqual(normalizeProgramConfig({...base,liveKeyChecks:{enabled:true,checkAll:true}}).liveKeyChecks,{enabled:true,checkAll:true});
  assert.deepEqual(normalizeProgramConfig({...base,liveKeyChecks:{enabled:false,checkAll:true}}).liveKeyChecks,{enabled:false,checkAll:true});
  assert.throws(()=>normalizeProgramConfig({...base,liveKeyChecks:{enabled:true,unexpected:1}}),/unknown|unexpected/i);
  assert.throws(()=>normalizeProgramConfig({...base,liveKeyChecks:{enabled:'yes'}}),/enabled/);
  assert.throws(()=>normalizeProgramConfig({...base,liveKeyChecks:{checkAll:true}}),/enabled/);
  assert.throws(()=>normalizeProgramConfig({...base,liveKeyChecks:{enabled:true,checkAll:'maybe'}}),/checkAll/);
});
