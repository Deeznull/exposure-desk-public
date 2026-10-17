import http from 'node:http';
import {gzipSync} from 'node:zlib';
import {Scanner} from './scanner.js';
import {BUILD} from './build-info.js';
import {RULE_VERSION} from './detectors.js';
import {synthetic,syntheticJwt} from './fixture.js';

// Deliberately nonfunctional local fixtures. Result objects never contain values.
export async function pipelineSelfTest(){
 const startedAt=new Date().toISOString(),arrivals:{path:string;method:string}[]=[],externalArrivals:string[]=[];
 const secret='123e4567-e89b-42d3-a456-426614174006',encoded=Buffer.from('snyk_token="'+secret+'"').toString('base64');
 const opaque='Z7n2Q9r5T1w8Y3u6I4o0P9a7S2d5F8g1H6j3K4l9X0c2V7b8N';
 const values={cohere:opaque,mistral:opaque.split('').reverse().join(''),frame:'re_'+opaque.slice(0,30),postmark:'123e4567-e89b-12d3-a456-426614174008'};
 const runtime=(v:string)=>JSON.stringify([...v])+'.join("")';
 const other=http.createServer((req,res)=>{externalArrivals.push(req.url||'');res.end('excluded');});await new Promise<void>(r=>other.listen(0,'127.0.0.1',r));
 const excluded=`http://127.0.0.1:${(other.address() as any).port}`;
 let origin='',cookies=0,fresh=0;
 const app=`window.PUBLIC_CONFIG={cohere:{apiKey:${runtime(values.cohere)}}};localStorage.setItem("private_config",JSON.stringify({provider:"Mistral",apiKey:${runtime(values.mistral)}}));localStorage.setItem("session",${JSON.stringify(syntheticJwt.session)});fetch('/api/json');fetch('/headers');fetch('/error');fetch('/compressed');fetch('/encoded');fetch('/cookie');fetch('/fresh-'+localStorage.length);import('./lazy.js');Object.defineProperty(window,'GetterConfig',{get(){fetch('/getter-probe');return 'never';}});window.NestedConfig={};Object.defineProperty(window.NestedConfig,'apiKey',{get(){fetch('/getter-probe');return 'never';}});fetch('/collector?v='+${JSON.stringify(Buffer.from('snyk_token="'+secret+'"').toString('base64'))});fetch('/write',{method:'POST',body:'ordinary data'});fetch('/delete');fetch(${JSON.stringify(excluded+'/outside.js')});new WebSocket(location.origin.replace('http','ws')+'/socket');addEventListener('scroll',()=>{if(window.didScroll)return;window.didScroll=true;fetch('/scroll');});\n//# sourceMappingURL=entry.js.map`;
 const homepage=`<!doctype html><html><head><base href="/assets/"><link rel="modulepreload" href="lazy.js"></head><body style="min-height:3000px"><form><input type="password"></form><!--${synthetic.github}--><script src="entry.js"></script><iframe src="/frame"></iframe><a href="/error">Error</a><a href="/encoded">Encoded</a><a href="/compressed">Compressed</a><a href="/api/json">JSON</a><a href="/headers">Headers</a><script src="${excluded}/outside.js"></script><p>contentHash=${'a1b2c3d4'.repeat(8)} uuid=123e4567-e89b-12d3-a456-426614174000</p></body></html>`;
 const server=http.createServer((req,res)=>{
  const url=new URL(req.url||'/',origin||'http://fixture');arrivals.push({path:url.pathname,method:req.method||''});
  const send=(body:string,type='text/plain',status=200,headers:Record<string,string>={})=>{res.writeHead(status,{'content-type':type,...headers});res.end(body);};
  switch(url.pathname){
   case '/':send(homepage,'text/html',200,{'set-cookie':'anonymous_session=syntheticVisitor; SameSite=Lax; Path=/'});break;
   case '/assets/entry.js':send('const privateKey='+JSON.stringify(synthetic.openai)+';'+app,'text/javascript');break;
   case '/assets/lazy.js':send('const privatePayment='+JSON.stringify(synthetic.stripe)+';const client='+JSON.stringify(synthetic.publicStripe)+';const anonymous='+JSON.stringify(syntheticJwt.anon)+';','text/javascript');break;
   case '/api/json':send(JSON.stringify({secret:synthetic.supabase,publicKey:synthetic.publicSupabase}),'application/json');break;
   case '/headers':send('ordinary response','text/plain',200,{'x-debug-key':synthetic.sendgrid});break;
   case '/error':send(JSON.stringify({ANTHROPIC_API_KEY:synthetic.anthropic,stack:'Error: synthetic\n at example (app.js:2:3)'}),'application/json',403);break;
   case '/assets/entry.js.map':send(JSON.stringify({version:3,sources:['webpack://virtual/config.ts'],sourcesContent:['const hf='+JSON.stringify(synthetic.hf)],names:[],mappings:''}),'application/json');break;
   case '/compressed':res.writeHead(200,{'content-type':'text/plain','content-encoding':'gzip'});res.end(gzipSync(synthetic.replicate));break;
   case '/encoded':send(JSON.stringify({opaque:encoded}),'application/json');break;
   case '/frame':send('<html><body><script>window.FrameConfig={resend:{apiKey:'+runtime(values.frame)+'}};</script>Public frame</body></html>','text/html');break;
   case '/selected':send('<html><body><script>window.SelectedConfig={postmark:{serverToken:'+runtime(values.postmark)+'}};</script>Read-only selected page</body></html>','text/html');break;
   case '/scroll':send(JSON.stringify({provider:'AWS',accessKeyId:synthetic.awsId,secretAccessKey:synthetic.awsSecret}),'application/json');break;
   case '/cookie':if(String(req.headers.cookie).includes('anonymous_session=syntheticVisitor'))cookies++;send('cookie observed');break;
   case '/fresh-2':fresh++;send('fresh storage initialized by this visit');break;
   case '/.env':send(homepage,'text/html');break;
   case '/config.json':send('{"deployment":"fixture","logging":"debug"}','application/json');break;
   case '/robots.txt':send('User-agent: *\nAllow: /');break;
   case '/sitemap.xml':send('<urlset/>','application/xml');break;
   default:if(/^\/[a-f0-9]{24}$/.test(url.pathname))send(homepage,'text/html');else send('Absent fixture route','text/plain',404);
  }
 });await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));origin=`http://127.0.0.1:${(server.address() as any).port}`;
 const cases=[
  {id:'html-comment',value:synthetic.github,kind:'HTML'}, {id:'base-login-linked-script',value:synthetic.openai,kind:'JavaScript'},
  {id:'lazy-module',value:synthetic.stripe,kind:'JavaScript'}, {id:'json-response',value:synthetic.supabase,kind:'JSON'},
  {id:'response-header',value:synthetic.sendgrid,kind:'headers'}, {id:'virtual-map-source',value:synthetic.hf,kind:'embedded source'},
  {id:'403-error-response',value:synthetic.anthropic,kind:'error body'}, {id:'gzip-response',value:synthetic.replicate,kind:'compression'},
  {id:'encoded-engine-only',value:secret,kind:'Base64 / Gitleaks',requiredRule:'gitleaks:'},
  {id:'runtime-global',value:values.cohere,kind:'runtime',requiredEvidence:'runtime configuration'},
  {id:'fresh-storage',value:values.mistral,kind:'storage',requiredEvidence:'Storage created'},
  {id:'frame-runtime',value:values.frame,kind:'frame runtime',requiredEvidence:'runtime configuration'},
  {id:'selected-read-only-page',value:values.postmark,kind:'selected navigation',requiredEvidence:'runtime configuration'},
  {id:'bounded-scroll-response',value:synthetic.awsSecret,kind:'scroll fetch'},
  {id:'stripe-public-decoy',value:synthetic.publicStripe,kind:'public identifier',category:'public-identifier'},
  {id:'supabase-public-decoy',value:synthetic.publicSupabase,kind:'public identifier',category:'public-identifier'},
  {id:'anonymous-jwt-decoy',value:syntheticJwt.anon,kind:'public identifier',category:'public-identifier'}
 ];
 const scan=new Scanner({name:'Full-pipeline synthetic self-test',urls:[origin],developmentFixtureOrigin:origin,browser:true,browserPages:2,browserNavigationUrls:[origin+'/selected'],browserSettleMs:350,browserScrollSteps:2,browserScrollDelayMs:150,deep:true,deepPaths:['/.env','/config.json'],requestsPerSecond:20,concurrency:2,maxResources:180,maxDurationMs:180000,timeoutMs:15000,adjacentMaps:false});
 try{
  await scan.init();const view=await scan.run(),findings=[...scan.evidence.findings.values()];
  const results=cases.map(c=>{const f=findings.find(f=>scan.evidence.reveal(f.id).value===c.value&&f.category===(c.category||'private-credential'));const locations=f?.occurrences.filter(o=>!c.requiredEvidence||o.evidence.includes(c.requiredEvidence))||[];const rules=f?.reasons||[];const benignRemoved=c.category==='public-identifier'&&!f&&scan.evidence.triage?.wasRemoved(scan.evidence.fingerprint(c.value));const found=!!benignRemoved||!!f&&locations.length>0&&(!c.requiredRule||f.rule.startsWith(c.requiredRule)||rules.some(r=>r.includes('Gitleaks')));return{id:c.id,kind:c.kind,found,category:f?.category||c.category,triage:benignRemoved?'insignificant-removed':f?.triage?.category,rule:f?.rule,detectors:f?[...new Set([f.rule,...rules.filter(r=>/Gitleaks/.test(r)).map(()=>'gitleaks')])]:[],locations:locations.map(o=>({path:new URL(o.url.startsWith('http')?o.url:origin).pathname,sourceLabel:o.sourceLabel,line:o.line,transformations:o.transformations,evidence:o.evidence})),failure:found?undefined:'Seed not observed through required stage; review scan limitations and resource coverage.'};});
  const forbidden=['/collector','/write','/delete','/socket','/getter-probe'];
  const checks={offlineEngine:scan.detector.version==='8.30.1'&&!scan.detector.issues.length,browserExecuted:view.browserStatus!.launch&&view.browserStatus!.runtimePages===2,cookieSemantics:cookies>0,freshStorage:fresh>0,noGetterCalls:!arrivals.some(a=>a.path==='/getter-probe'),outboundIsolation:!arrivals.some(a=>forbidden.includes(a.path))&&externalArrivals.length===0,baseHref:arrivals.some(a=>a.path==='/assets/entry.js')&&!arrivals.some(a=>a.path==='/entry.js'),errorBodyAnalyzed:view.resources.some(r=>r.url.endsWith('/error')&&r.code===403&&r.analysis==='analyzed'),soft404Rejected:!view.findings.some(f=>f.rule==='published-sensitive-file'&&f.occurrences.some(o=>o.url.endsWith('/.env'))),configConfirmed:view.findings.some(f=>f.rule==='published-sensitive-file'&&f.occurrences.some(o=>o.url.endsWith('/config.json'))),scopeExclusionVisible:view.resources.some(r=>r.reason==='scope'),blockedEncodedEngineRequest:view.resources.some(r=>r.reason==='credential-in-request'&&r.url.includes('/collector'))};
  return{schema:'exposure-pipeline-self-test/1',startedAt,endedAt:new Date().toISOString(),build:BUILD,engines:view.engines,status:results.every(r=>r.found)&&Object.values(checks).every(Boolean)?'passed':'failed',checks,summary:{planted:results.length,found:results.filter(r=>r.found).length,missed:results.filter(r=>!r.found).length},results,scan:{state:view.state,stopReason:view.stopReason,browser:view.browserStatus,coverage:view.coverage,accounting:view.accounting,limitations:view.limitations},note:'Synthetic nonfunctional examples, local analysis only. Deliberate 403 and excluded origins make scan coverage incomplete; self-test passes only when each expected stage and isolation assertion is observed. Full browser isolation/UI suite is a separate required release check.'};
 }finally{scan.dispose();await new Promise<void>(r=>{server.close(()=>r());server.closeAllConnections();});await new Promise<void>(r=>{other.close(()=>r());other.closeAllConnections();});}
}
