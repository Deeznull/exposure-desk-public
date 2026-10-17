import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { root } from '../src/detectors.js';
import { BlockMonitor, BLOCK_DEFAULTS } from '../src/mass/block.js';
/** 2.8 mass scan (w2-mass): block detection with NO evasion. A target that repeatedly refuses, rate-limits, serves a bot challenge or resets the connection is recorded
 * as blocked; the run only stops and backs off — it never changes the User-Agent, headers, proxy or IP, and never retries around a block. With at least three finished
 * targets and at least a quarter of them blocked, the program-wide halt starts no further target. Loopback fixtures only; no real website is ever contacted. */
const cli=path.join(root,'dist/src/cli.js');
async function temp(prefix:string){const parent=process.env.EXPOSURE_DATA_DIR||path.join(root,'.cache');await mkdir(parent,{recursive:true});return mkdtemp(path.join(parent,prefix));}
/** Every path answers with a Cloudflare-style challenge interstitial (status 403, cf-mitigated and "checking your browser"/"verify you are human" body), recording each
 * request's path and User-Agent so the test can prove nothing rotated. */
async function challengeSite(){
  const arrivals:string[]=[],userAgents=new Set<string|undefined>();
  const server=http.createServer((req,res)=>{arrivals.push((req.url||'/').split('?')[0]!);userAgents.add(req.headers['user-agent']);res.statusCode=403;res.setHeader('content-type','text/html');res.setHeader('cf-mitigated','challenge');res.end('<!doctype html><title>Just a moment...</title><h1>Checking your browser before accessing</h1><p>Please verify you are human.</p>');});
  await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));
  return {origin:'http://127.0.0.1:'+(server.address() as any).port,arrivals,userAgents,close:()=>new Promise<void>(r=>{server.close(()=>r());server.closeAllConnections();})};
}
type Run={status:number|null;stdout:string;stderr:string;events:any[]};
function run(args:string[],env:NodeJS.ProcessEnv,input=''){return new Promise<Run>((resolve,reject)=>{const child=spawn(process.execPath,[cli,'scan',...args],{env,windowsHide:true});let stdout='',stderr='';const timer=setTimeout(()=>child.kill(),180000);
  child.stdout.on('data',d=>stdout+=d);child.stderr.on('data',d=>stderr+=d);child.stdin.on('error',()=>{});child.stdin.end(input);child.on('error',reject);
  child.on('close',status=>{clearTimeout(timer);resolve({status,stdout,stderr,events:args.includes('--jsonl')?stdout.split('\n').filter(Boolean).map(l=>JSON.parse(l)):[]});});});}
const of=(r:Run,event:string)=>r.events.filter(e=>e.event===event);

test('BlockMonitor: a challenge trips at 2, plain 403/429/503 at 5, resets at 3; a normal response clears the streak; the detail states no evasion',()=>{
  assert.deepEqual(BLOCK_DEFAULTS,{statusStreak:5,challengeStreak:2,resetStreak:3});
  // A bot/challenge interstitial trips fast (two in a row).
  const m=new BlockMonitor();
  assert.equal(m.observe({status:403,disposition:'suspected-bot-challenge'}),undefined);
  const d=m.observe({status:403,disposition:'suspected-bot-challenge'});
  assert.ok(d&&d.kind==='challenge'&&d.status===403);
  assert.match(d.detail,/No evasion was attempted/);assert.match(d.detail,/no retry around the block/);
  assert.equal(m.observe({status:200}),d,'once blocked it stays blocked and never re-arms');
  // Plain refusals need five in a row.
  const s=new BlockMonitor();for(let i=0;i<4;i++)assert.equal(s.observe({status:403}),undefined);
  const sd=s.observe({status:403});assert.ok(sd&&sd.kind==='status'&&sd.status===403);assert.match(sd.reason,/HTTP 403/);
  // A normal response in the middle clears the streak.
  const c=new BlockMonitor();c.observe({status:429});c.observe({status:429});assert.equal(c.observe({status:200}),undefined);
  for(let i=0;i<4;i++)assert.equal(c.observe({status:429}),undefined);assert.ok(c.observe({status:429})?.kind==='status');
  // Connection resets trip at three.
  const r=new BlockMonitor();assert.equal(r.observe({reset:true}),undefined);assert.equal(r.observe({reset:true}),undefined);assert.ok(r.observe({reset:true})?.kind==='reset');
});

test('a single target behind a challenge ends blocked: target-end carries blocked + stopReason, exit 2, the User-Agent never changes and the arrivals stay bounded',{timeout:240000},async()=>{
  const site=await challengeSite(),dir=await temp('mass-block-one-'),env={...process.env,EXPOSURE_DATA_DIR:dir};try{
    const tpl=path.join(dir,'template.json');await writeFile(tpl,JSON.stringify({developmentFixtureOrigin:site.origin,browser:false}));
    const r=await run(['--targets','-','--config',tpl,'--coverage','quick','--jsonl','--output',path.join(dir,'r.json')],env,site.origin+'/\n');
    assert.equal(r.status,2,r.stderr);
    assert.match(r.events.map(e=>e.event).join(' '),/^run-start target-start (finding )*target-end summary$/);
    const [end]=of(r,'target-end');
    assert.equal(end.stopReason,'blocked');assert.notEqual(end.status,'completed');
    assert.ok(end.blocked&&end.blocked.kind==='challenge'&&end.blocked.status===403,'target-end carries the blocked object: '+JSON.stringify(end.blocked));
    assert.equal(end.exit,2);
    const [summary]=of(r,'summary');assert.equal(summary.interrupted,false,'a block is not an interruption');assert.equal(summary.exit,2);
    assert.equal(site.userAgents.size,1,'one honest User-Agent across every request — no rotation');
    assert.ok([...site.userAgents][0],'the User-Agent is a real, non-empty token');
    assert.ok(site.arrivals.length>=2&&site.arrivals.length<=30,'the run stops after a bounded number of requests, with no retry storm: '+site.arrivals.length);
  }finally{await site.close();await rm(dir,{recursive:true,force:true,maxRetries:5});}
});

test('program-wide halt: with at least three finished targets and at least a quarter blocked, no further target starts and the summary records halted:"blocked"',{timeout:420000},async()=>{
  const site=await challengeSite(),dir=await temp('mass-block-halt-'),env={...process.env,EXPOSURE_DATA_DIR:dir};try{
    const tpl=path.join(dir,'template.json'),list=path.join(dir,'targets.txt');
    await writeFile(tpl,JSON.stringify({developmentFixtureOrigin:site.origin,browser:false}));
    await writeFile(list,Array.from({length:8},(_,i)=>`${site.origin}/t${i}`).join('\n')+'\n');
    const r=await run(['--targets',list,'--authorized','--config',tpl,'--coverage','quick','--concurrency','2','--jsonl','--output',path.join(dir,'r.json')],env);
    assert.equal(r.status,2,r.stderr);
    const [summary]=of(r,'summary');
    assert.equal(summary.halted,'blocked','the run halts on the block rate');
    assert.ok((summary.statuses.blocked||0)>=3,'at least three targets were recorded blocked: '+JSON.stringify(summary.statuses));
    assert.ok(summary.notStarted>=1,'the halt left at least one target not started: '+JSON.stringify({scanned:summary.scanned,notStarted:summary.notStarted}));
    assert.equal(summary.scanned+summary.notStarted,8);
    for(const end of of(r,'target-end'))assert.ok(end.blocked&&end.blocked.kind==='challenge','every finished target was blocked');
    assert.equal(site.userAgents.size,1,'one honest User-Agent across the whole halted run');
  }finally{await site.close();await rm(dir,{recursive:true,force:true,maxRetries:5});}
});
