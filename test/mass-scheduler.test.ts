import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { root } from '../src/detectors.js';
/** 2.8 mass scan (w2-mass): the concurrent-target scheduler. At most N targets run at once (N from --concurrency, or a program's concurrency.targets); every target scan
 * still shares one analysis budget and, with a program, one request limiter; a bad or over-limit --concurrency refuses the whole command (exit 2) before any request.
 * Loopback fixtures on 127.0.0.1 only. */
const cli=path.join(root,'dist/src/cli.js');
async function temp(prefix:string){const parent=process.env.EXPOSURE_DATA_DIR||path.join(root,'.cache');await mkdir(parent,{recursive:true});return mkdtemp(path.join(parent,prefix));}
/** A fixture that holds every entry request (`/t<n>`) until N are in flight at once (or a 2 s fallback), recording the peak number held simultaneously. Because a held
 * entry keeps its target active, the peak held equals the peak number of targets running at once — the scheduler can never let it exceed N. */
async function gateSite(n:number){
  const arrivals:string[]=[],userAgents=new Set<string|undefined>();let held=0,peak=0,waiters:(()=>void)[]=[],timer:NodeJS.Timeout|null=null;
  const flush=()=>{if(timer){clearTimeout(timer);timer=null;}const batch=waiters;waiters=[];for(const s of batch)s();};
  const server=http.createServer((req,res)=>{const p=(req.url||'/').split('?')[0]!;arrivals.push(p);userAgents.add(req.headers['user-agent']);
    if(/^\/t\d+$/.test(p)){held++;if(held>peak)peak=held;const send=()=>{held--;res.setHeader('content-type','text/html');res.end('<!doctype html><p>ok</p>');};waiters.push(send);if(held>=n)flush();else{if(timer)clearTimeout(timer);timer=setTimeout(flush,2000);}return;}
    if(p==='/robots.txt'){res.setHeader('content-type','text/plain');res.end('User-agent: *\nAllow: /\n');return;}
    res.statusCode=404;res.setHeader('content-type','text/plain');res.end('nf');});
  await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));
  return {origin:'http://127.0.0.1:'+(server.address() as any).port,arrivals,userAgents,get peak(){return peak;},close:()=>new Promise<void>(r=>{server.close(()=>r());server.closeAllConnections();})};
}
/** A plain fixture: any path is a 200 with a non-secret page; records arrivals and User-Agents. */
async function plainSite(){
  const arrivals:string[]=[],userAgents=new Set<string|undefined>();
  const server=http.createServer((req,res)=>{const p=(req.url||'/').split('?')[0]!;arrivals.push(p);userAgents.add(req.headers['user-agent']);if(p==='/robots.txt'){res.setHeader('content-type','text/plain');res.end('User-agent: *\nAllow: /\n');return;}res.setHeader('content-type','text/html');res.end('<!doctype html><p>ok</p>');});
  await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));
  return {origin:'http://127.0.0.1:'+(server.address() as any).port,arrivals,userAgents,close:()=>new Promise<void>(r=>{server.close(()=>r());server.closeAllConnections();})};
}
type Run={status:number|null;stdout:string;stderr:string;events:any[]};
function run(args:string[],env:NodeJS.ProcessEnv,input=''){return new Promise<Run>((resolve,reject)=>{const child=spawn(process.execPath,[cli,'scan',...args],{env,windowsHide:true});let stdout='',stderr='';const timer=setTimeout(()=>child.kill(),180000);
  child.stdout.on('data',d=>stdout+=d);child.stderr.on('data',d=>stderr+=d);child.stdin.on('error',()=>{});child.stdin.end(input);child.on('error',reject);
  child.on('close',status=>{clearTimeout(timer);resolve({status,stdout,stderr,events:args.includes('--jsonl')?stdout.split('\n').filter(Boolean).map(l=>JSON.parse(l)):[]});});});}
const of=(r:Run,event:string)=>r.events.filter(e=>e.event===event);

test('--concurrency N runs at most N targets at once (and genuinely more than one); the summary records the concurrency and every target still completes',{timeout:420000},async()=>{
  const N=4,M=8,site=await gateSite(N),dir=await temp('mass-sched-'),env={...process.env,EXPOSURE_DATA_DIR:dir};try{
    const tpl=path.join(dir,'template.json'),list=path.join(dir,'targets.txt');
    await writeFile(tpl,JSON.stringify({developmentFixtureOrigin:site.origin,browser:false}));
    await writeFile(list,Array.from({length:M},(_,i)=>`${site.origin}/t${i}`).join('\n')+'\n');
    const r=await run(['--targets',list,'--authorized','--config',tpl,'--coverage','quick','--concurrency',String(N),'--jsonl','--fail-on','never','--output',path.join(dir,'r.json')],env);
    assert.equal(r.status,0,r.stderr);
    assert.ok(site.peak<=N,`never more than ${N} targets in flight at once (observed ${site.peak})`);
    assert.ok(site.peak>=2,'more than one target genuinely ran at once (observed '+site.peak+')');
    assert.equal(site.peak,N,`the scheduler fills all ${N} lanes (observed ${site.peak})`);
    const [summary]=of(r,'summary');
    assert.equal(summary.concurrency,N);assert.equal(summary.scanned,M);assert.equal(summary.notStarted,0);
    assert.equal(summary.statuses.done,M,'every target completed: '+JSON.stringify(summary.statuses));
    assert.equal(site.userAgents.size,1,'one honest User-Agent across every concurrent target');
  }finally{await site.close();await rm(dir,{recursive:true,force:true,maxRetries:5});}
});

test('with a program, the concurrency defaults to the program and the run shares one request limiter (program stats in the summary)',{timeout:420000},async()=>{
  const site=await plainSite(),dir=await temp('mass-sched-program-'),env={...process.env,EXPOSURE_DATA_DIR:dir};try{
    const tpl=path.join(dir,'template.json'),list=path.join(dir,'targets.txt'),program=path.join(dir,'program');await mkdir(program,{recursive:true});
    await writeFile(tpl,JSON.stringify({developmentFixtureOrigin:site.origin,browser:false}));
    await writeFile(path.join(program,'program.json'),JSON.stringify({schema:'exposure-program/1',name:'Loopback',authorized:true,scope:{in:['127.0.0.1'],out:[]},rate:{requestsPerSecond:50},concurrency:{targets:3,requests:6}}));
    await writeFile(list,Array.from({length:5},(_,i)=>`${site.origin}/p${i}`).join('\n')+'\n');
    const r=await run(['--targets',list,'--program',program,'--config',tpl,'--coverage','quick','--jsonl','--fail-on','never','--output',path.join(dir,'r.json')],env);
    assert.equal(r.status,0,r.stderr);
    const [summary]=of(r,'summary');
    assert.equal(summary.concurrency,3,'concurrency defaults to the program concurrency.targets');
    assert.equal(summary.scanned,5);assert.equal(summary.rejected,0,'every 127.0.0.1 target is in scope');
    assert.ok(summary.program&&summary.program.granted>0,'the summary carries the shared program-limiter stats: '+JSON.stringify(summary.program));
    assert.ok(summary.program.peakActive>=1&&summary.program.peakActive<=6,'one shared request limiter bounds requests at once by the program (<=6): '+summary.program.peakActive);
  }finally{await site.close();await rm(dir,{recursive:true,force:true,maxRetries:5});}
});

test('a bad or over-limit --concurrency refuses the whole command (exit 2) before any request',{timeout:120000},async()=>{
  const site=await plainSite(),dir=await temp('mass-sched-refuse-'),env={...process.env,EXPOSURE_DATA_DIR:dir};try{
    const tpl=path.join(dir,'template.json');await writeFile(tpl,JSON.stringify({developmentFixtureOrigin:site.origin,browser:false}));
    const common=['--targets','-','--authorized','--config',tpl,'--coverage','quick','--output',path.join(dir,'r.json')];
    for(const [value,needle] of [['17','above 16 needs a program'],['65','cannot exceed 64'],['abc','whole number'],['0','at least 1']] as const){
      const r=await run([...common,'--concurrency',value],env,site.origin+'/\n');
      assert.equal(r.status,2,`--concurrency ${value} exits 2: ${r.stderr}`);
      assert.equal(r.stdout,'','--concurrency '+value+' prints nothing to standard output');
      assert.match(r.stderr,/Nothing was requested\.\s*$/,'the refusal states nothing was requested: '+r.stderr);
      assert.ok(r.stderr.includes(needle),`the refusal for ${value} explains why (${needle}): ${r.stderr}`);
    }
    assert.equal(site.arrivals.length,0,'no refusal ever reached the fixture');
  }finally{await site.close();await rm(dir,{recursive:true,force:true,maxRetries:5});}
});
