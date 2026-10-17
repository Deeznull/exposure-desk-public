import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { mkdir, mkdtemp, readdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { root } from '../src/detectors.js';
import { CliError } from '../src/cli/errors.js';
import { assertResumable, listHash, loadState, MASSRUN_SCHEMA, newState, settingsHash, writeState } from '../src/mass/state.js';
/** 2.8 mass scan (w2-mass): the resumable run-state file (D2). One owner-only, atomically-written JSON file records per-target status so an interrupted or re-invoked
 * target list resumes, re-running only the targets that did not finish and refusing (exit 2, one line) if the list or the run settings changed. The state layer is proven
 * at 1,000 synthetic targets; a small loopback run proves the end-to-end skip and refusal. */
const cli=path.join(root,'dist/src/cli.js');
async function temp(prefix:string){const parent=process.env.EXPOSURE_DATA_DIR||path.join(root,'.cache');await mkdir(parent,{recursive:true});return mkdtemp(path.join(parent,prefix));}
async function plainSite(){
  const arrivals:string[]=[];const server=http.createServer((req,res)=>{const p=(req.url||'/').split('?')[0]!;arrivals.push(p);if(p==='/robots.txt'){res.setHeader('content-type','text/plain');res.end('User-agent: *\nAllow: /\n');return;}res.setHeader('content-type','text/html');res.end('<!doctype html><p>ok</p>');});
  await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));
  return {origin:'http://127.0.0.1:'+(server.address() as any).port,arrivals,close:()=>new Promise<void>(r=>{server.close(()=>r());server.closeAllConnections();})};
}
type Run={status:number|null;stdout:string;stderr:string;events:any[]};
function run(args:string[],env:NodeJS.ProcessEnv,input=''){return new Promise<Run>((resolve,reject)=>{const child=spawn(process.execPath,[cli,'scan',...args],{env,windowsHide:true});let stdout='',stderr='';const timer=setTimeout(()=>child.kill(),180000);
  child.stdout.on('data',d=>stdout+=d);child.stderr.on('data',d=>stderr+=d);child.stdin.on('error',()=>{});child.stdin.end(input);child.on('error',reject);
  child.on('close',status=>{clearTimeout(timer);resolve({status,stdout,stderr,events:args.includes('--jsonl')?stdout.split('\n').filter(Boolean).map(l=>JSON.parse(l)):[]});});});}
const of=(r:Run,event:string)=>r.events.filter(e=>e.event===event);

test('run-state at 1,000 synthetic targets: owner-only atomic write, resume skips done targets, and a changed list or settings refuses',{timeout:120000},async()=>{
  const dir=await temp('mass-state-');try{
    const urls=Array.from({length:1000},(_,i)=>`http://127.0.0.1:9/t${i}`);
    const settings={coverage:'quick',traffic:null,full:false};
    const file=path.join(dir,'run.state');
    const state=newState(urls,settings);
    assert.equal(state.schema,MASSRUN_SCHEMA);assert.equal(state.targets.length,1000);
    assert.ok(state.targets.every((t,i)=>t.index===i&&t.status==='pending'),'a fresh state has every target pending, in order');
    await writeState(file,state);
    if(process.platform!=='win32'){const st=await stat(file);assert.equal(st.mode&0o777,0o600,'the run-state file is owner-only');}
    assert.ok(!(await readdir(dir)).some(f=>f.includes('.tmp')),'the atomic temp file is renamed away, never left behind');
    // 600 targets done, persisted and reloaded: resume re-runs only the 400 that did not finish.
    for(let i=0;i<600;i++)state.targets[i]!.status='done';
    await writeState(file,state);
    const loaded=await loadState(file);assert.ok(loaded);
    const notDone=loaded!.targets.filter(t=>t.status!=='done').map(t=>t.index);
    assert.equal(notDone.length,400);assert.equal(notDone[0],600,'resume picks up at the first unfinished target');
    assert.doesNotThrow(()=>assertResumable(loaded!,urls,settings,file),'the same list and settings resume');
    // A changed list refuses.
    const changed=[...urls];changed[500]='http://127.0.0.1:9/CHANGED';
    assert.throws(()=>assertResumable(loaded!,changed,settings,file),(e:unknown)=>e instanceof CliError&&/different target list/.test(e.message)&&/Nothing was requested\.$/.test(e.message));
    // A changed setting refuses.
    assert.throws(()=>assertResumable(loaded!,urls,{...settings,coverage:'deep'},file),(e:unknown)=>e instanceof CliError&&/different run settings/.test(e.message)&&/Nothing was requested\.$/.test(e.message));
    // A missing file is a first run (undefined); a wrong schema refuses.
    assert.equal(await loadState(path.join(dir,'nope.state')),undefined);
    await writeFile(path.join(dir,'bad.state'),JSON.stringify({schema:'other/1'}));
    await assert.rejects(loadState(path.join(dir,'bad.state')),(e:unknown)=>e instanceof CliError&&/schema/.test((e as CliError).message));
    // listHash is order-sensitive; settingsHash is stable for equal settings.
    assert.notEqual(listHash(urls),listHash([...urls].reverse()));assert.equal(listHash(urls),listHash([...urls]));
    assert.equal(settingsHash(settings),settingsHash({...settings}));assert.notEqual(settingsHash(settings),settingsHash({...settings,full:true}));
  }finally{await rm(dir,{recursive:true,force:true,maxRetries:5});}
});

test('--state end to end: a second run with the same list skips the done targets and requests nothing; a changed list refuses before any request',{timeout:300000},async()=>{
  const site=await plainSite(),dir=await temp('mass-resume-cli-'),env={...process.env,EXPOSURE_DATA_DIR:dir};try{
    const tpl=path.join(dir,'template.json'),list=path.join(dir,'targets.txt'),stateFile=path.join(dir,'run.state'),out=path.join(dir,'r.json');
    await writeFile(tpl,JSON.stringify({developmentFixtureOrigin:site.origin,browser:false}));
    await writeFile(list,`${site.origin}/r0\n${site.origin}/r1\n${site.origin}/r2\n`);
    const first=await run(['--targets',list,'--authorized','--config',tpl,'--coverage','quick','--state',stateFile,'--jsonl','--fail-on','never','--output',out],env);
    assert.equal(first.status,0,first.stderr);
    const s1=of(first,'summary')[0];assert.equal(s1.scanned,3);assert.equal(s1.skipped,0);assert.equal(s1.statuses.done,3);
    const persisted=await loadState(stateFile);assert.ok(persisted&&persisted.targets.length===3&&persisted.targets.every(t=>t.status==='done'),'every target is recorded done');
    const afterFirst=site.arrivals.length;assert.ok(afterFirst>0,'the first run made requests');
    // Resume: everything is done, so nothing is scanned and nothing is requested.
    const second=await run(['--targets',list,'--authorized','--config',tpl,'--coverage','quick','--state',stateFile,'--jsonl','--fail-on','never','--output',out],env);
    assert.equal(second.status,0,second.stderr);
    const s2=of(second,'summary')[0];assert.equal(s2.scanned,0);assert.equal(s2.skipped,3);assert.equal(s2.notStarted,0);assert.equal(s2.statuses.done,3);
    assert.equal(of(second,'target-start').length,0,'no target was re-run');
    assert.equal(site.arrivals.length,afterFirst,'the resume requested nothing');
    // A changed list refuses before any request.
    const changed=path.join(dir,'changed.txt');await writeFile(changed,`${site.origin}/r0\n${site.origin}/r1\n${site.origin}/r2\n${site.origin}/r3\n`);
    const before=site.arrivals.length;
    const third=await run(['--targets',changed,'--authorized','--config',tpl,'--coverage','quick','--state',stateFile,'--jsonl','--fail-on','never','--output',out],env);
    assert.equal(third.status,2,third.stderr);
    assert.ok(third.stderr.includes('resume refused')&&third.stderr.includes('Nothing was requested.'),'the refusal is one clear line: '+third.stderr);
    assert.equal(of(third,'target-start').length,0,'nothing was scanned');
    assert.equal(site.arrivals.length,before,'the refused resume requested nothing');
    // A changed --config settings template refuses too: the remaining targets would otherwise run with different settings.
    const tpl2=path.join(dir,'template2.json');await writeFile(tpl2,JSON.stringify({developmentFixtureOrigin:site.origin,browser:false,maxDepth:1}));
    const fourth=await run(['--targets',list,'--authorized','--config',tpl2,'--coverage','quick','--state',stateFile,'--jsonl','--fail-on','never','--output',out],env);
    assert.equal(fourth.status,2,fourth.stderr);
    assert.ok(fourth.stderr.includes('different run settings')&&fourth.stderr.includes('Nothing was requested.'),'a changed template refuses: '+fourth.stderr);
    assert.equal(of(fourth,'target-start').length,0,'nothing was scanned');
    assert.equal(site.arrivals.length,before,'the refused resume requested nothing');
    // The state file still shows the original three done (the refusal never rewrote it).
    const after=await loadState(stateFile);assert.ok(after&&after.targets.length===3);
  }finally{await site.close();await rm(dir,{recursive:true,force:true,maxRetries:5});}
});
