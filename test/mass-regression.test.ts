import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { root } from '../src/detectors.js';
/** 2.8 mass scan (w2-mass): the 2.7 regression (D9). Without --concurrency or --state a target list stays strictly sequential and the summary keeps exactly the 2.7 keys —
 * none of the mass-only fields (concurrency, statuses, halted, uniqueFindings, sharedFindings, skipped, state) appear, `finding` events gain no firstSeen/duplicateOf, and
 * a normal target-end carries no blocked object. A single configuration scan is likewise unchanged. Loopback fixtures and one synthetic, non-functional key only. */
const cli=path.join(root,'dist/src/cli.js');
const key=(name:string)=>'sk-proj-'+createHash('sha512').update('unit-mass-regression-'+name).digest('base64url').slice(0,64);
const K=key('shared');
async function temp(prefix:string){const parent=process.env.EXPOSURE_DATA_DIR||path.join(root,'.cache');await mkdir(parent,{recursive:true});return mkdtemp(path.join(parent,prefix));}
async function serve(routes:Record<string,[type:string,body:string]>){
  const arrivals:string[]=[];const server=http.createServer((req,res)=>{const p=(req.url||'/').split('?')[0]!;arrivals.push(p);const r=routes[p];if(!r){res.statusCode=404;res.end('not found');return;}res.setHeader('content-type',r[0]);res.end(r[1]);});
  await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));
  return {origin:'http://127.0.0.1:'+(server.address() as any).port,arrivals,close:()=>new Promise<void>(r=>{server.close(()=>r());server.closeAllConnections();})};
}
const SITE=(k:string)=>({'/':['text/html',`<!doctype html><script>window.S={openai:${JSON.stringify(k)}}</script><script src="/app.js"></script>`],'/app.js':['text/javascript',`const client={apiKey:${JSON.stringify(k)}};`],'/robots.txt':['text/plain','User-agent: *\nAllow: /\n']} as Record<string,[string,string]>);
type Run={status:number|null;stdout:string;stderr:string;events:any[]};
function run(args:string[],env:NodeJS.ProcessEnv,input=''){return new Promise<Run>((resolve,reject)=>{const child=spawn(process.execPath,[cli,'scan',...args],{env,windowsHide:true});let stdout='',stderr='';const timer=setTimeout(()=>child.kill(),180000);
  child.stdout.on('data',d=>stdout+=d);child.stderr.on('data',d=>stderr+=d);child.stdin.on('error',()=>{});child.stdin.end(input);child.on('error',reject);
  child.on('close',status=>{clearTimeout(timer);resolve({status,stdout,stderr,events:args.includes('--jsonl')?stdout.split('\n').filter(Boolean).map(l=>JSON.parse(l)):[]});});});}
const of=(r:Run,event:string)=>r.events.filter(e=>e.event===event);
// The 2.7 keys plus the three w2-wire output paths (recon, rebuild, submissionBundle; null when not asked for), which every summary carries.
const TWO_SEVEN_SUMMARY_KEYS=['at','event','exit','findings','interrupted','notStarted','rebuild','recon','rejected','scanned','schema','states','submissionBundle','targets'];

test('2.7 regression (D9): a plain target list stays sequential and its summary keeps exactly the 2.7 keys — no mass fields anywhere',{timeout:300000},async()=>{
  const a=await serve(SITE(K)),b=await serve(SITE(K)),dir=await temp('mass-regression-'),env={...process.env,EXPOSURE_DATA_DIR:dir};try{
    const tpl=path.join(dir,'template.json'),list=path.join(dir,'targets.txt');
    await writeFile(tpl,JSON.stringify({privateOrigins:[a.origin,b.origin],browser:false}));
    await writeFile(list,`${a.origin}/\n${b.origin}/\n`);
    const r=await run(['--targets',list,'--authorized','--config',tpl,'--coverage','quick','--jsonl','--fail-on','never','--output',path.join(dir,'r.json')],env);
    assert.equal(r.status,0,r.stderr);
    assert.match(r.events.map(e=>e.event).join(' '),/^run-start target-start (finding )+target-end target-start (finding )+target-end summary$/,'targets ran one after another, in order');
    const [summary]=of(r,'summary');
    assert.deepEqual(Object.keys(summary).sort(),TWO_SEVEN_SUMMARY_KEYS,'summary keeps exactly the 2.7 keys — no concurrency/statuses/halted/uniqueFindings/sharedFindings/skipped/state');
    for(const f of of(r,'finding'))assert.ok(!('firstSeen' in f)&&!('duplicateOf' in f),'no cross-target dedup fields without mass mode');
    for(const e of of(r,'target-end'))assert.ok(!('blocked' in e),'a normal target-end carries no blocked object');
    assert.equal(of(r,'run-start')[0].mode,'targets');
  }finally{await a.close();await b.close();await rm(dir,{recursive:true,force:true,maxRetries:5});}
});

test('2.7 regression (D9): a single configuration scan is unchanged — the summary keeps exactly the 2.7 keys',{timeout:240000},async()=>{
  const a=await serve(SITE(K)),dir=await temp('mass-regression-one-'),env={...process.env,EXPOSURE_DATA_DIR:dir};try{
    const cfg=path.join(dir,'one.json');await writeFile(cfg,JSON.stringify({urls:[a.origin+'/'],privateOrigins:[a.origin],browser:false}));
    const r=await run(['--config',cfg,'--coverage','quick','--jsonl','--fail-on','never','--output',path.join(dir,'r.json')],env);
    assert.equal(r.status,0,r.stderr);
    assert.match(r.events.map(e=>e.event).join(' '),/^run-start target-start (finding )+target-end summary$/);
    const [summary]=of(r,'summary');
    assert.deepEqual(Object.keys(summary).sort(),TWO_SEVEN_SUMMARY_KEYS);
    assert.equal(summary.targets,1);assert.equal(summary.scanned,1);assert.equal(summary.notStarted,0);
    for(const f of of(r,'finding'))assert.ok(!('firstSeen' in f)&&!('duplicateOf' in f));
  }finally{await a.close();await rm(dir,{recursive:true,force:true,maxRetries:5});}
});
