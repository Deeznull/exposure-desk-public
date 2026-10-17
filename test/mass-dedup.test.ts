import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { root } from '../src/detectors.js';
import { Dedup } from '../src/mass/dedup.js';
/** 2.8 mass scan (w2-mass): cross-target de-duplication. One exposure that appears on several targets is one entry in the run summary (`sharedFindings`) with its list of
 * targets; a target's `finding` events carry `firstSeen` (and `duplicateOf` when an earlier target already reported that id); each per-target report keeps its own
 * findings. Loopback fixtures and one synthetic, non-functional key only. */
const cli=path.join(root,'dist/src/cli.js');
const key=(name:string)=>'sk-proj-'+createHash('sha512').update('unit-mass-dedup-'+name).digest('base64url').slice(0,64);
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

test('Dedup unit: the first target wins firstSeen, later targets are marked duplicates, and the summary lists each shared id once with its sorted target list',()=>{
  const d=new Dedup();
  assert.deepEqual(d.see('a',2),{firstSeen:2,duplicate:false});
  assert.deepEqual(d.see('a',2),{firstSeen:2,duplicate:false},'the same target re-reporting its own id is not a cross-target duplicate');
  assert.deepEqual(d.see('a',5),{firstSeen:2,duplicate:true});
  assert.deepEqual(d.see('b',3),{firstSeen:3,duplicate:false});
  assert.equal(d.size,2,'two distinct ids seen across the run');
  assert.deepEqual(d.shared(),[{findingId:'a',firstSeen:2,targets:[2,5]}],'only ids on more than one target, ordered by first sighting, each with its sorted targets');
});

test('mass run: one exposure on several targets is one summary entry with firstSeen/duplicateOf on the events; per-target reports keep their own findings',{timeout:300000},async()=>{
  const a=await serve(SITE(K)),b=await serve(SITE(K)),dir=await temp('mass-dedup-'),env={...process.env,EXPOSURE_DATA_DIR:dir};try{
    const tpl=path.join(dir,'template.json'),list=path.join(dir,'targets.txt'),stateFile=path.join(dir,'run.state'),out=path.join(dir,'r.json');
    await writeFile(tpl,JSON.stringify({privateOrigins:[a.origin,b.origin],browser:false}));
    await writeFile(list,`${a.origin}/\n${b.origin}/\n`);
    // --state makes this a mass run at concurrency 1: sequential and deterministic, so firstSeen is always the lower target number.
    const r=await run(['--targets',list,'--authorized','--config',tpl,'--coverage','quick','--state',stateFile,'--jsonl','--output',out],env);
    assert.equal(r.status,1,r.stderr);
    assert.match(r.events.map(e=>e.event).join(' '),/^run-start target-start (finding )+target-end target-start (finding )+target-end summary$/);
    const cred=(t:number)=>of(r,'finding').filter(e=>e.target===t&&e.category==='private-credential');
    const [f1,f2]=[cred(1),cred(2)];assert.equal(f1.length,1);assert.equal(f2.length,1);
    const id=f1[0].findingId as string;assert.match(id,/^[0-9a-f]{64}$/);assert.equal(f2[0].findingId,id,'one run keeps one id for one exposure across targets');
    assert.equal(f1[0].firstSeen,1,'target 1 first saw the id');assert.ok(!('duplicateOf' in f1[0]),'the first sighting is not a duplicate');
    assert.equal(f2[0].firstSeen,1);assert.equal(f2[0].duplicateOf,1,'target 2 is a duplicate of target 1');
    const [summary]=of(r,'summary');
    assert.equal(summary.concurrency,1);
    assert.equal(summary.uniqueFindings,new Set(of(r,'finding').map(e=>e.findingId)).size,'uniqueFindings is the count of distinct findingIds');
    assert.ok(Array.isArray(summary.sharedFindings)&&summary.sharedFindings.some((s:any)=>s.findingId===id&&s.firstSeen===1&&s.targets.join(',')==='1,2'),'the shared finding lists both targets once: '+JSON.stringify(summary.sharedFindings));
    // Per-target reports still carry the finding (dedup only collapses the summary, never the report files).
    const ends=of(r,'target-end');assert.equal(ends.length,2);
    for(const e of ends){const report=JSON.parse(await readFile(e.report,'utf8'));assert.ok(report.findings.some((f:any)=>f.findingId===id),'report '+path.basename(e.report)+' keeps the finding');}
  }finally{await a.close();await b.close();await rm(dir,{recursive:true,force:true,maxRetries:5});}
});
