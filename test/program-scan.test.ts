import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { root } from '../src/detectors.js';
import { PRODUCT_USER_AGENT, outboundHeaders } from '../src/transport.js';
import { programFromJson, PROGRAM_SCHEMA } from '../src/program/settings.js';
import { PROGRAM_AUTHORIZATION_REQUIRED } from '../src/cli/commands/scan.js';
/** 2.8 program runs from the CLI (w1-scope): scope enforcement on every request (seeds, scripts, redirects, other origins), identification headers and the
 * User-Agent suffix only toward in-scope URLs, target-list rejection, the authorization statement and the protected-host rule. Loopback fixtures only. */
const cli=path.join(root,'dist/src/cli.js');
async function temp(prefix:string){const parent=process.env.EXPOSURE_DATA_DIR||path.join(root,'.cache');await mkdir(parent,{recursive:true});return mkdtemp(path.join(parent,prefix));}
interface Arrival {url:string;headers:http.IncomingHttpHeaders}
async function serve(routes:(origin:string)=>Record<string,[status:number,type:string,body:string]>){
  const arrivals:Arrival[]=[];let origin='';
  const server=http.createServer((req,res)=>{arrivals.push({url:req.url||'',headers:req.headers});const r=routes(origin)[(req.url||'/').split('?')[0]!];if(!r){res.statusCode=404;res.end('not found');return;}res.statusCode=r[0];if(r[0]>=300&&r[0]<400)res.setHeader('location',r[2]);else res.setHeader('content-type',r[1]);res.end(r[0]>=300&&r[0]<400?'':r[2]);});
  await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));origin='http://127.0.0.1:'+(server.address() as any).port;
  return {origin,arrivals,close:()=>new Promise<void>(r=>{server.close(()=>r());server.closeAllConnections();})};
}
function run(args:string[],env:NodeJS.ProcessEnv,input=''){return new Promise<{status:number|null;stdout:string;stderr:string}>((resolve,reject)=>{const child=spawn(process.execPath,[cli,...args],{env,windowsHide:true});let stdout='',stderr='';const timer=setTimeout(()=>child.kill(),180000);
  child.stdout.on('data',d=>stdout+=d);child.stderr.on('data',d=>stderr+=d);child.stdin.on('error',()=>{});child.stdin.end(input);child.on('error',reject);child.on('close',status=>{clearTimeout(timer);resolve({status,stdout,stderr});});});}
const program=(dir:string,body:Record<string,unknown>)=>writeFile(path.join(dir,'program.json'),'// test program\n'+JSON.stringify({schema:'exposure-program/1',...body}));

test('a program run contacts only in-scope URLs, records the rest as program-out-of-scope, and sends its headers and User-Agent suffix only in scope',{timeout:240000},async()=>{
  const other=await serve(()=>({'/other.js':[200,'text/javascript','const other=1;']}));
  const site=await serve(origin=>({
    '/':[200,'text/html',`<!doctype html><title>program fixture</title><script src="/app.js"></script><script src="/admin/admin.js"></script><script src="/go.js"></script><script src="${other.origin}/other.js"></script>`],
    '/app.js':[200,'text/javascript','const ready=true;'],'/admin/admin.js':[200,'text/javascript','const admin=true;'],'/go.js':[302,'',`${origin}/admin/redirected.js`],'/admin/redirected.js':[200,'text/javascript','const r=1;'],
    '/robots.txt':[200,'text/plain','User-agent: *\nAllow: /\n']}));
  const dir=await temp('program-scan-'),env={...process.env,EXPOSURE_DATA_DIR:dir};try{
    const p=path.join(dir,'acme'),cfg=path.join(dir,'config.json'),out=path.join(dir,'report.json');await mkdir(p);
    await program(p,{name:'Fixture',authorized:true,scope:{in:[site.origin+'/'],out:[site.origin+'/admin/']},rate:{requestsPerSecond:20},concurrency:{targets:1,requests:4},headers:{'X-Bug-Bounty':'researcher-1'},userAgentSuffix:'researcher-1'});
    await writeFile(cfg,JSON.stringify({urls:[site.origin+'/'],developmentFixtureOrigin:site.origin,browser:false}));
    const r=await run(['scan','--config',cfg,'--program',p,'--coverage','quick','--output',out],env);
    // The redirect into /admin/ leaves go.js's target uninspected for scope reasons, so the run may honestly report itself incomplete (exit 2); it must still finish and write its report.
    assert.ok(r.status===0||r.status===2,r.stderr+r.stdout);assert.match(r.stdout,/exit [02]\. Redacted report written\./);assert.ok(existsSync(out));
    assert.match(r.stdout,/^Program: Fixture · 1 in-scope and 1 out-of-scope rules · up to 20 requests per second and 4 at once across the run · authorized in program\.json$/m);
    assert.match(r.stdout,/^Program limit: \d+ requests, \d+ waited for the program limit/m);
    const urls=site.arrivals.map(a=>a.url);
    assert.ok(urls.includes('/')&&urls.includes('/app.js')&&urls.includes('/go.js'),urls.join(' '));
    assert.ok(!urls.some(u=>u.startsWith('/admin/')),'paths outside the program scope are never requested, also after a redirect: '+urls.join(' '));
    assert.equal(other.arrivals.length,0,'another origin is never contacted');
    for(const a of site.arrivals){assert.equal(a.headers['x-bug-bounty'],'researcher-1',a.url);assert.equal(a.headers['user-agent'],PRODUCT_USER_AGENT+' researcher-1',a.url);}
    const j=JSON.parse(await readFile(out,'utf8')),examples=j.scope.excluded.examples as {origin:string;reason:string;urls:string[]}[];
    const excluded=examples.filter(e=>e.reason==='program-out-of-scope');
    assert.ok(excluded.some(e=>e.origin===other.origin),JSON.stringify(examples));
    assert.ok(excluded.some(e=>e.origin===site.origin&&e.urls.some(u=>u.endsWith('/admin/admin.js'))),JSON.stringify(examples));
    assert.ok(JSON.stringify(j).includes('outside the program scope'),'the scope gap names program exclusions');
  }finally{await site.close();await other.close();await rm(dir,{recursive:true,force:true});}
});

test('program refusals exit 2 before any request: no authorization, a seed outside the scope, a protected in-scope rule, an invalid file',{timeout:240000},async()=>{
  const site=await serve(()=>({'/':[200,'text/html','<!doctype html><title>x</title>']}));
  const dir=await temp('program-refuse-'),env={...process.env,EXPOSURE_DATA_DIR:dir};try{
    const p=path.join(dir,'acme'),cfg=path.join(dir,'config.json'),out=path.join(dir,'never.json');await mkdir(p);
    await writeFile(cfg,JSON.stringify({urls:[site.origin+'/'],developmentFixtureOrigin:site.origin,browser:false}));
    await program(p,{scope:{in:[site.origin+'/']}});
    let r=await run(['scan','--config',cfg,'--program',p,'--coverage','quick','--output',out],env);assert.equal(r.status,2);assert.equal(r.stderr.trim(),PROGRAM_AUTHORIZATION_REQUIRED);assert.equal(r.stdout,'');
    await program(p,{authorized:true,scope:{in:[site.origin+'/app/']}});
    r=await run(['scan','--config',cfg,'--program',p,'--coverage','quick','--output',out],env);assert.equal(r.status,2);assert.equal(r.stderr.trim(),`Refused: ${site.origin}/ is outside the program scope in ${path.join(p,'program.json')} (see: exposure-desk program check ${p}). Nothing was requested.`);
    await program(p,{authorized:true,scope:{in:[site.origin+'/','portal.example.gov']}});
    r=await run(['scan','--config',cfg,'--program',p,'--coverage','quick','--output',out],env);assert.equal(r.status,2);assert.match(r.stderr,/Exposure Desk never scans government, military, intelligence or law-enforcement websites: portal\.example\.gov/);
    await program(p,{authorized:true,scope:{in:[site.origin+'/']},headers:{Authorization:'Bearer x'}});
    r=await run(['scan','--config',cfg,'--program',p,'--coverage','quick','--output',out],env);assert.equal(r.status,2);assert.match(r.stderr,/Authorization is never set by a program/);
    await program(p,{authorized:true,scope:{in:[site.origin+'/']},typo:1});
    r=await run(['scan','--config',cfg,'--program',p,'--coverage','quick','--output',out],env);assert.equal(r.status,2);assert.match(r.stderr,/unknown field "typo"/);
    assert.equal(site.arrivals.length,0,'nothing was requested');assert.ok(!existsSync(out));
    // A folder without program.json keeps the 2.7 meaning (correlation key only): no authorization statement is needed for one website.
    const plain=path.join(dir,'plain');await mkdir(plain);r=await run(['scan','--config',cfg,'--program',plain,'--coverage','quick','--output',out],env);assert.equal(r.status,0,r.stderr);assert.doesNotMatch(r.stdout,/^Program/m);assert.ok(existsSync(path.join(plain,'.key')));
  }finally{await site.close();await rm(dir,{recursive:true,force:true});}
});

test('target lists: targets outside the program scope are rejected as out-of-scope; authorized:true in the file counts as --authorized for the rest',{timeout:300000},async()=>{
  const site=await serve(()=>({'/':[200,'text/html','<!doctype html><title>a</title>'],'/b/':[200,'text/html','<!doctype html><title>b</title>'],'/private/':[200,'text/html','<!doctype html><title>p</title>']}));
  const dir=await temp('program-targets-'),env={...process.env,EXPOSURE_DATA_DIR:dir};try{
    const p=path.join(dir,'acme'),tpl=path.join(dir,'template.json'),out=path.join(dir,'report.json');await mkdir(p);
    await writeFile(tpl,JSON.stringify({developmentFixtureOrigin:site.origin,browser:false}));
    await program(p,{authorized:true,scope:{in:[site.origin+'/'],out:[site.origin+'/private/']}});
    const input=`${site.origin}/\nintranet.example.mil\n${site.origin}/private/\n${site.origin}/b/\n`;
    const r=await run(['scan','--targets','-','--program',p,'--config',tpl,'--coverage','quick','--output',out,'--jsonl'],env,input);
    assert.equal(r.status,0,r.stderr);
    assert.match(r.stderr,/Rejected line 2: intranet\.example\.mil \(protected-host\)/);assert.match(r.stderr,new RegExp(`Rejected line 3: ${site.origin.replace(/[.]/g,'\\.')}/private/ \\(out-of-scope\\)`));
    const events=r.stdout.trim().split(/\r?\n/).map(l=>JSON.parse(l));const start=events.find(e=>e.type==='run-start'||e.event==='run-start');
    assert.ok(start,'run-start event');assert.equal(start.authorized,true);assert.deepEqual(start.rejected.map((x:any)=>[x.line,x.reason]),[[2,'protected-host'],[3,'out-of-scope']]);
    const summary=events.find(e=>e.type==='summary'||e.event==='summary');assert.ok(summary.program&&summary.program.granted>0,JSON.stringify(summary));
    assert.ok(!site.arrivals.some(a=>a.url.startsWith('/private/')),'the out-of-scope target was never requested');
  }finally{await site.close();await rm(dir,{recursive:true,force:true});}
});

test('outbound headers: program headers and the User-Agent suffix go on static and browser requests in scope only, after the 2.7 header policy',()=>{
  const program=programFromJson({schema:PROGRAM_SCHEMA,scope:{in:['*.acme.example','https://acme.example/app/'],out:['admin.acme.example']},headers:{'X-Bug-Bounty':'researcher-1'},userAgentSuffix:'researcher-1'},'/tmp/hdr').config;
  const chromium='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',ok=()=>true;
  const s=outboundHeaders(new URL('https://www.acme.example/a.js'),'http',{'x-bug-bounty':'spoof',authorization:'Bearer x'},{program},ok);
  assert.equal(s['user-agent'],PRODUCT_USER_AGENT+' researcher-1');assert.equal(s['x-bug-bounty'],'researcher-1');assert.equal(s.authorization,undefined);
  const b=outboundHeaders(new URL('https://acme.example/app/x'),'browser',{'user-agent':chromium,accept:'*/*'},{program},ok);
  assert.equal(b['user-agent'],chromium+' researcher-1','appended to the browser User-Agent, never replacing it');assert.equal(b['x-bug-bounty'],'researcher-1');assert.equal(b.accept,'*/*');
  for(const u of ['https://admin.acme.example/','https://acme.example/','https://acme.example/other','https://unrelated.example/']){
    for(const kind of ['http','browser']){const h=outboundHeaders(new URL(u),kind,{'user-agent':chromium},{program},ok);assert.equal(h['x-bug-bounty'],undefined,u+' '+kind);assert.ok(!String(h['user-agent']).endsWith('researcher-1'),u+' '+kind);}
  }
  const none=outboundHeaders(new URL('https://www.acme.example/'),'http',{},{program:{...program,userAgentSuffix:undefined,headers:{}}},ok);assert.equal(none['user-agent'],PRODUCT_USER_AGENT);
});
