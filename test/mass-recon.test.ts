import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { root } from '../src/detectors.js';
import { readEarlierRecon } from '../src/cli/mass-run.js';
import { loadState, writeState } from '../src/mass/state.js';
/**
 * w2-mass × w2-wire: the per-target recon lists, submission Markdown (`--format md`) and submission bundle are written by runTargets in mass
 * mode too (concurrency > 1, where the shared detector skips Scanner.init() and Scanner.initRecon() builds the collector), and a resumed run
 * (`--state`) adds the targets an earlier run finished to the merged recon set and to the bundle. Masking holds everywhere outside owner-only
 * files. Loopback fixtures and synthetic, nonfunctional keys only.
 */
const cli=path.join(root,'dist/src/cli.js');
const key=(name:string)=>'sk-proj-'+createHash('sha512').update('unit-mass-recon-'+name).digest('base64url').slice(0,64);
const KA=key('a'),KB=key('b');
async function temp(prefix:string){const parent=process.env.EXPOSURE_DATA_DIR||path.join(root,'.cache');await mkdir(parent,{recursive:true});return mkdtemp(path.join(parent,prefix));}
/** A page, a script carrying one synthetic key that points at an endpoint with a parameter, and a second page. */
function fixture(k:string):Record<string,[string,string]>{
  return {'/':['text/html',`<!doctype html><title>mass recon fixture</title><a href="/about">About</a><script src="/app.js"></script>`],
    '/app.js':['text/javascript',`const client={apiKey:${JSON.stringify(k)}};fetch('/api/data?token=opaque');`],
    '/about':['text/html','<!doctype html><title>about</title>'],
    '/robots.txt':['text/plain','User-agent: *\nAllow: /\n']};
}
async function serve(routes:Record<string,[string,string]>){
  const arrivals:string[]=[];const server=http.createServer((req,res)=>{const p=(req.url||'/').split('?')[0]!;arrivals.push(p);const r=routes[p];if(!r){res.statusCode=404;res.end('not found');return;}res.setHeader('content-type',r[0]);res.end(r[1]);});
  await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));
  return {origin:'http://127.0.0.1:'+(server.address() as any).port,arrivals,close:()=>new Promise<void>(r=>{server.close(()=>r());server.closeAllConnections();})};
}
type Run={status:number|null;stdout:string;stderr:string;events:any[]};
function run(args:string[],env:NodeJS.ProcessEnv,input=''){return new Promise<Run>((resolve,reject)=>{const child=spawn(process.execPath,[cli,'scan',...args],{env,windowsHide:true});let stdout='',stderr='';const timer=setTimeout(()=>child.kill(),240000);
  child.stdout.on('data',d=>stdout+=d);child.stderr.on('data',d=>stderr+=d);child.stdin.on('error',()=>{});child.stdin.end(input);child.on('error',reject);
  child.on('close',status=>{clearTimeout(timer);resolve({status,stdout,stderr,events:stdout.split('\n').filter(Boolean).map(l=>JSON.parse(l))});});});}
const noSecret=(text:string,label:string)=>{for(const k of [KA,KB])for(const part of [k,k.slice(8,40),k.slice(-24)])assert.ok(!text.includes(part),`masked (${label})`);};
async function noSecretIn(dir:string){for(const f of await readdir(dir,{withFileTypes:true})){const p=path.join(dir,f.name);if(f.isDirectory())await noSecretIn(p);else noSecret(await readFile(p,'utf8'),path.relative(dir,p));}}

test('readEarlierRecon reads a finished target\'s recon.json back and leaves out anything that is not a recon result',async()=>{
  const dir=await temp('mass-recon-read-');try{
    assert.equal(await readEarlierRecon(path.join(dir,'missing')),undefined,'a missing folder is left out');
    const good={schema:'exposure-recon/1',generatedAt:'2026-10-11T00:00:00.000Z',resources:{seen:2,scanned:2,skipped:0,truncated:0,maps:0},limits:{},counts:{urls:1},dropped:{},redactions:0,inlineSourceMaps:0,lists:{urls:[{value:'http://127.0.0.1/a',source:'http://127.0.0.1/'}]}};
    const put=async(name:string,body:string)=>{const d=path.join(dir,name);await mkdir(d);await writeFile(path.join(d,'recon.json'),body);return d;};
    assert.deepEqual(await readEarlierRecon(await put('good',JSON.stringify(good))),good,'a recon result is returned as written');
    assert.equal(await readEarlierRecon(await put('garbled','{not json')),undefined,'unreadable JSON is left out');
    assert.equal(await readEarlierRecon(await put('schema',JSON.stringify({...good,schema:'other/1'}))),undefined,'another schema is left out');
    assert.equal(await readEarlierRecon(await put('counter',JSON.stringify({...good,resources:{...good.resources,seen:'2'}}))),undefined,'a non-numeric counter is left out');
    assert.equal(await readEarlierRecon(await put('item',JSON.stringify({...good,lists:{urls:[{value:7}]}}))),undefined,'a list item without a string value is left out');
    assert.equal(await readEarlierRecon(await put('nolists',JSON.stringify({...good,lists:null}))),undefined,'missing lists are left out');
  }finally{await rm(dir,{recursive:true,force:true});}
});

test('--concurrency 2 --recon --format md: each target writes its recon folder and Markdown draft, the merged set is written, and the JSON Lines paths match',{timeout:360000},async()=>{
  const a=await serve(fixture(KA)),b=await serve(fixture(KB)),dir=await temp('mass-recon-md-'),env={...process.env,EXPOSURE_DATA_DIR:dir};try{
    const tpl=path.join(dir,'tpl.json'),reconDir=path.join(dir,'recon'),reports=path.join(dir,'reports');
    await writeFile(tpl,JSON.stringify({privateOrigins:[a.origin,b.origin],browser:false}));
    const r=await run(['--targets','-','--authorized','--config',tpl,'--coverage','quick','--concurrency','2','--recon',reconDir,'--format','md','--jsonl','--fail-on','never','--output',path.join(reports,'r.md')],env,`${a.origin}/\n${b.origin}/\n`);
    assert.equal(r.status,0,r.stderr);
    const start=r.events.find(e=>e.event==='run-start'),summary=r.events.find(e=>e.event==='summary'),ends=r.events.filter(e=>e.event==='target-end');
    assert.equal(summary.concurrency,2,'a mass run (shared detector, init() skipped per scan)');assert.ok(start);
    assert.equal(ends.length,2);
    // Each target: its own <n>-<host> recon folder with a full set of lists, recorded on its target-end event.
    const expected=new Map([[1,path.join(reconDir,'1-127.0.0.1')],[2,path.join(reconDir,'2-127.0.0.1')]]);
    for(const e of ends){
      assert.equal(e.recon,expected.get(e.target),'target-end.recon is this target\'s folder');assert.ok(path.isAbsolute(e.recon));
      const files=await readdir(e.recon);assert.ok(files.includes('recon.json')&&files.includes('urls.txt')&&files.includes('endpoints.txt'),files.join(' '));
      const result=JSON.parse(await readFile(path.join(e.recon,'recon.json'),'utf8'));assert.equal(result.schema,'exposure-recon/1');
      assert.ok(result.lists.urls.some((u:any)=>u.value.includes('/app.js')),'the collector ran in mass mode (initRecon): the script is listed');
      assert.ok(result.lists.endpoints.some((u:any)=>u.value.includes('/api/data')),'the endpoint is listed');
      // The report path is the target's Markdown draft, written and masked.
      assert.ok(path.isAbsolute(e.report)&&e.report.endsWith('.md')&&!e.report.endsWith('.sensitive.md'),e.report);assert.ok(existsSync(e.report),'the Markdown draft exists at target-end.report');
      const draft=await readFile(e.report,'utf8');assert.ok(/^#/m.test(draft),'the draft is Markdown');noSecret(draft,'md draft '+e.target);
    }
    assert.notEqual(ends[0].report,ends[1].report,'one draft per target');
    // The merged top-level set sits beside the per-target folders and sums them.
    const entries=await readdir(reconDir);assert.ok(entries.includes('recon.json')&&entries.includes('urls.txt'),entries.join(' '));
    const merged=JSON.parse(await readFile(path.join(reconDir,'recon.json'),'utf8'));
    const per=await Promise.all([...expected.values()].map(async d=>JSON.parse(await readFile(path.join(d,'recon.json'),'utf8'))));
    assert.equal(merged.resources.seen,per[0].resources.seen+per[1].resources.seen,'the merged set sums both targets');
    assert.equal(summary.recon,path.resolve(reconDir));assert.equal(summary.rebuild,null);assert.equal(summary.submissionBundle,null);
    noSecret(r.stdout,'stdout');noSecret(r.stderr,'stderr');await noSecretIn(reconDir);
  }finally{await a.close();await b.close();await rm(dir,{recursive:true,force:true});}
});

test('--state resume with --recon and --submission-bundle: the targets an earlier run finished join the merged recon set and the bundle',{timeout:420000},async()=>{
  const a=await serve(fixture(KA)),b=await serve(fixture(KB)),dir=await temp('mass-recon-resume-'),env={...process.env,EXPOSURE_DATA_DIR:dir};try{
    const tpl=path.join(dir,'tpl.json'),reconDir=path.join(dir,'recon'),stateFile=path.join(dir,'run.state'),list=`${a.origin}/\n${b.origin}/\n`;
    await writeFile(tpl,JSON.stringify({privateOrigins:[a.origin,b.origin],browser:false}));
    const common=['--targets','-','--authorized','--config',tpl,'--coverage','quick','--concurrency','2','--recon',reconDir,'--state',stateFile,'--jsonl','--fail-on','never','--output',path.join(dir,'reports','r.json')];
    const first=await run([...common,'--submission-bundle',path.join(dir,'bundle1')],env,list);
    assert.equal(first.status,0,first.stderr);
    const firstMerged=JSON.parse(await readFile(path.join(reconDir,'recon.json'),'utf8'));
    const persisted=await loadState(stateFile);assert.ok(persisted&&persisted.targets.every(t=>t.status==='done'&&t.recon),'every target records its recon folder');
    assert.equal(persisted!.targets[0]!.recon,path.join(reconDir,'1-127.0.0.1'));
    // Mark the second target unfinished, as an interrupted run would have left it, and resume into a new bundle folder.
    const t2=persisted!.targets[1]!;t2.status='pending';delete t2.report;delete t2.recon;await writeState(stateFile,persisted!);
    const arrivalsA=a.arrivals.length;
    const second=await run([...common,'--submission-bundle',path.join(dir,'bundle2')],env,list);
    assert.equal(second.status,0,second.stderr);
    assert.equal(a.arrivals.length,arrivalsA,'the finished target is not requested again');
    assert.deepEqual(second.events.filter(e=>e.event==='target-end').map(e=>e.target),[2],'only the unfinished target runs');
    const summary=second.events.find(e=>e.event==='summary');
    // The merged set still covers both targets: the first one's lists come from its recon.json.
    const merged=JSON.parse(await readFile(path.join(reconDir,'recon.json'),'utf8'));
    assert.equal(merged.resources.seen,firstMerged.resources.seen,'the resumed merged set includes the target the earlier run finished');
    assert.deepEqual(merged.lists.urls.map((u:any)=>u.value),firstMerged.lists.urls.map((u:any)=>u.value),'same merged URL list as the uninterrupted run');
    assert.equal(summary.recon,path.resolve(reconDir));
    // The bundle includes the earlier target (from its JSON report) and the resumed one, with no "not included" notice.
    assert.equal(summary.submissionBundle,path.resolve(path.join(dir,'bundle2')));assert.ok(!/not included/.test(second.stderr),second.stderr);
    const drafts=async(d:string)=>(await readdir(d)).filter(f=>f.endsWith('.md')).sort();
    const d1=await drafts(path.join(dir,'bundle1')),d2=await drafts(path.join(dir,'bundle2'));assert.equal(d2.length,d1.length,'as many drafts as the uninterrupted run: '+d2.join(' '));
    // Draft names carry the finding id, which is per run: the earlier target keeps its id (read from its JSON report), the rescanned one gets a new one.
    const slug=(name:string)=>name.slice('finding-'.length,-'.md'.length);
    const report1=(await readFile(persisted!.targets[0]!.report!,'utf8')).toLowerCase(),report2=(await readFile(second.events.find(e=>e.event==='target-end').report,'utf8')).toLowerCase();
    const findings=d2.filter(n=>n!=='index.md');assert.equal(findings.length,2,findings.join(' '));
    assert.equal(findings.filter(n=>report1.includes(slug(n))).length,1,'one draft is the finding of the target the earlier run finished, from its JSON report');assert.ok(d1.includes(findings.find(n=>report1.includes(slug(n)))!),'with the same name as in the uninterrupted run');
    assert.equal(findings.filter(n=>report2.includes(slug(n))).length,1,'one draft is the finding of the resumed target');
    noSecret(first.stdout+first.stderr+second.stdout+second.stderr,'terminal and JSON Lines');
    await noSecretIn(reconDir);await noSecretIn(path.join(dir,'bundle1'));await noSecretIn(path.join(dir,'bundle2'));
  }finally{await a.close();await b.close();await rm(dir,{recursive:true,force:true});}
});

test('--state resume with --format md --submission-bundle: a target the earlier run finished has no JSON report, so it is left out of the bundle with a notice',{timeout:420000},async()=>{
  const a=await serve(fixture(KA)),b=await serve(fixture(KB)),dir=await temp('mass-recon-omit-'),env={...process.env,EXPOSURE_DATA_DIR:dir};try{
    const tpl=path.join(dir,'tpl.json'),stateFile=path.join(dir,'run.state'),list=`${a.origin}/\n${b.origin}/\n`;
    await writeFile(tpl,JSON.stringify({privateOrigins:[a.origin,b.origin],browser:false}));
    const common=['--targets','-','--authorized','--config',tpl,'--coverage','quick','--concurrency','2','--format','md','--state',stateFile,'--jsonl','--fail-on','never','--output',path.join(dir,'reports','r.md')];
    const first=await run([...common,'--submission-bundle',path.join(dir,'bundle1')],env,list);
    assert.equal(first.status,0,first.stderr);assert.ok(!/not included/.test(first.stderr),'nothing is left out of an uninterrupted run');
    const persisted=await loadState(stateFile);assert.ok(persisted&&persisted.targets.every(t=>t.status==='done'&&t.report!.endsWith('.md')),'the state records the Markdown drafts');
    const t2=persisted!.targets[1]!;t2.status='pending';delete t2.report;await writeState(stateFile,persisted!);
    const second=await run([...common,'--submission-bundle',path.join(dir,'bundle2')],env,list);
    assert.equal(second.status,0,second.stderr);
    assert.match(second.stderr,/Submission bundle: 1 target finished by an earlier run is not included because its report is not a readable JSON report/);
    const summary=second.events.find(e=>e.event==='summary');assert.equal(summary.submissionBundle,path.resolve(path.join(dir,'bundle2')),'the resumed target still gets a bundle');
    const drafts=(await readdir(path.join(dir,'bundle2'))).filter(f=>f.startsWith('finding-'));assert.equal(drafts.length,1,'only the resumed target: '+drafts.join(' '));
    noSecret(first.stdout+first.stderr+second.stdout+second.stderr,'terminal and JSON Lines');await noSecretIn(path.join(dir,'bundle2'));
  }finally{await a.close();await b.close();await rm(dir,{recursive:true,force:true});}
});
