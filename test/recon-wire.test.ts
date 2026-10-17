import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { root } from '../src/detectors.js';
import { Scanner } from '../src/scanner.js';
import { mergeReconResults, reconTargetDir, openReconOutput } from '../src/cli/recon-output.js';
import { SourceRebuilder, LIST_NAMES, type ReconItem, type ReconResult, type ListName } from '../src/recon/index.js';
import { Args } from '../src/cli/args.js';
import { CliError } from '../src/cli/errors.js';
import { programFromJson, PROGRAM_SCHEMA } from '../src/program/settings.js';
/**
 * w2-wire: recon lists (`--recon`), source rebuild (`--rebuild-sources`), submission Markdown (`--format md`, `--submission-bundle`) wired into the
 * scanner and the CLI. Hard rules under test: recon lists and the submission Markdown stay masked on the terminal, on standard output and on JSON Lines;
 * only an owner-only file on disk may hold an unmasked value. Loopback fixtures and synthetic, nonfunctional keys only.
 */
const cli=path.join(root,'dist/src/cli.js');
const key=(name:string)=>'sk-proj-'+createHash('sha512').update('unit-recon-'+name).digest('base64url').slice(0,64);
const K=key('shared');
async function temp(prefix:string){const parent=process.env.EXPOSURE_DATA_DIR||path.join(root,'.cache');await mkdir(parent,{recursive:true});return mkdtemp(path.join(parent,prefix));}
/** Loopback fixture: a page, a script that carries one synthetic key and points at an endpoint with a parameter, and the script's source map (the key lives in its sourcesContent). */
function fixture(k:string){
  const map=JSON.stringify({version:3,file:'app.js',sourceRoot:'',sources:['src/secrets.ts'],sourcesContent:[`export const OPENAI_API_KEY=${JSON.stringify(k)};`],names:[],mappings:''});
  const routes:Record<string,[string,string]>={
    '/':['text/html',`<!doctype html><title>recon fixture</title><a href="/about">About</a><script src="/app.js"></script>`],
    '/app.js':['text/javascript',`const client={apiKey:${JSON.stringify(k)}};fetch('/api/data?token=opaque');\n//# sourceMappingURL=app.js.map`],
    '/app.js.map':['application/json',map],
    '/about':['text/html','<!doctype html><title>about</title>'],
    '/robots.txt':['text/plain','User-agent: *\nAllow: /\n']};
  return routes;
}
async function serve(routes:Record<string,[string,string]>){
  const arrivals:string[]=[];const server=http.createServer((req,res)=>{const p=(req.url||'/').split('?')[0]!;arrivals.push(p);const r=routes[p];if(!r){res.statusCode=404;res.end('not found');return;}res.setHeader('content-type',r[0]);res.end(r[1]);});
  await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));
  return {origin:'http://127.0.0.1:'+(server.address() as any).port,arrivals,close:()=>new Promise<void>(r=>{server.close(()=>r());server.closeAllConnections();})};
}
type Run={status:number|null;stdout:string;stderr:string;events:any[]};
function run(args:string[],env:NodeJS.ProcessEnv,input=''){return new Promise<Run>((resolve,reject)=>{const child=spawn(process.execPath,[cli,...args],{env,windowsHide:true});let stdout='',stderr='';const timer=setTimeout(()=>child.kill(),180000);
  child.stdout.on('data',d=>stdout+=d);child.stderr.on('data',d=>stderr+=d);child.stdin.on('error',()=>{});child.stdin.end(input);child.on('error',reject);
  child.on('close',status=>{clearTimeout(timer);resolve({status,stdout,stderr,events:args.includes('--jsonl')?stdout.split('\n').filter(Boolean).map(l=>JSON.parse(l)):[]});});});}
const noSecret=(text:string,label:string)=>{for(const part of [K,K.slice(8,40),K.slice(-24)])assert.ok(!text.includes(part),`masked (${label})`);};

const item=(value:string,extra:Partial<ReconItem>={}):ReconItem=>({value,source:'http://127.0.0.1/',...extra});
const emptyDropped=()=>Object.fromEntries(LIST_NAMES.map(n=>[n,{'over-limit':0,'too-long':0,secret:0}])) as ReconResult['dropped'];
function mk(lists:Partial<Record<ListName,ReconItem[]>>,over:Partial<ReconResult>={}):ReconResult{
  const full=Object.fromEntries(LIST_NAMES.map(n=>[n,lists[n]||[]])) as Record<ListName,ReconItem[]>;
  return {schema:'exposure-recon/1',generatedAt:'2026-10-10T00:00:00.000Z',resources:{seen:1,scanned:1,skipped:0,truncated:0,maps:0},limits:{} as any,
    counts:Object.fromEntries(LIST_NAMES.map(n=>[n,full[n].length])) as ReconResult['counts'],dropped:emptyDropped(),redactions:0,inlineSourceMaps:0,lists:full,...over};
}

test('mergeReconResults unions lists by value, keeps the most permissive host scope and sums the counters; reconTargetDir names per-target folders',()=>{
  const a=mk({urls:[item('https://x/a')],hosts:[item('x',{scope:'out-of-scope'}),item('y',{scope:'third-party'})]},{resources:{seen:2,scanned:2,skipped:1,truncated:0,maps:1},redactions:1,inlineSourceMaps:1,dropped:{...emptyDropped(),urls:{'over-limit':3,'too-long':0,secret:2}}});
  const b=mk({urls:[item('https://x/a'),item('https://x/b')],hosts:[item('x',{scope:'in-scope'})]},{resources:{seen:5,scanned:4,skipped:0,truncated:1,maps:2},redactions:4,inlineSourceMaps:2,dropped:{...emptyDropped(),urls:{'over-limit':1,'too-long':0,secret:0}}});
  const m=mergeReconResults([a,b]);
  assert.deepEqual(m.lists.urls.map(i=>i.value),['https://x/a','https://x/b'],'union by value, sorted, de-duplicated');
  const hosts=Object.fromEntries(m.lists.hosts.map(h=>[h.value,h.scope]));
  assert.equal(hosts['x'],'in-scope','a host keeps its most permissive scope across targets');
  assert.equal(hosts['y'],'third-party');
  assert.deepEqual(m.resources,{seen:7,scanned:6,skipped:1,truncated:1,maps:3},'counters summed');
  assert.equal(m.redactions,5);assert.equal(m.inlineSourceMaps,3);
  assert.deepEqual(m.dropped.urls,{'over-limit':4,'too-long':0,secret:2},'dropped counts summed');
  assert.equal(m.counts.urls,2);assert.equal(m.counts.hosts,2);
  // A single result is returned unchanged.
  assert.equal(mergeReconResults([a]),a);
  const r='/tmp/recon';
  assert.equal(reconTargetDir(r,1,false,'http://127.0.0.1:8080/'),r,'one target writes into the root');
  assert.equal(reconTargetDir(r,2,true,'http://127.0.0.1:8080/'),path.join(r,'2-127.0.0.1'),'many targets get <n>-<host>');
  assert.equal(reconTargetDir(r,3,true,'not a url'),path.join(r,'3-target'),'an unparseable seed falls back to <n>-target');
});

test('SourceRebuilder.create refuses a folder that is not empty; openReconOutput maps that to a CliError (exit 2)',async()=>{
  const dir=await temp('recon-rebuild-');try{
    const target=path.join(dir,'out');await mkdir(target);await writeFile(path.join(target,'stray.txt'),'x');
    await assert.rejects(SourceRebuilder.create(target,{protect:false}),(e:any)=>e?.name==='ReconOutputError'&&e.code==='output-not-empty');
    const args=new Args(['scan','--rebuild-sources',target]);
    await assert.rejects(openReconOutput(args,{syntheticFixture:true}),(e:any)=>e instanceof CliError&&e.exitCode===2&&/new or empty/.test(e.message));
    // A fresh folder is accepted.
    const fresh=path.join(dir,'fresh');const ok=await openReconOutput(new Args(['scan','--rebuild-sources',fresh]),{syntheticFixture:true});
    assert.ok(ok.enabled&&ok.rebuilder);await ok.rebuilder!.finish();
  }finally{await rm(dir,{recursive:true,force:true});}
});

test('program scope narrows the recon host lists: the authorized seed host stays in-scope, a program-excluded host is listed out-of-scope (program-out-of-scope); no key is listed',async()=>{
  // The program authorizes the seed and excludes admin. The recon host verdict runs the program scope on top of the transport scope, so a host
  // the transport would call in-scope but the program excludes is narrowed to out-of-scope with the program reason; the authorized seed is kept.
  const program=programFromJson({schema:PROGRAM_SCHEMA,authorized:true,scope:{in:['https://acme.example/'],out:['admin.acme.example']}},'/tmp/recon-prog').config;
  const scan=new Scanner({urls:['https://acme.example/'],program,browser:false},{recon:{}});
  try{await scan.init();
    assert.ok(scan.recon,'the collector is built when recon output is requested');
    scan.recon!.add({url:'https://acme.example/app.js',kind:'script',contentType:'text/javascript',text:`const u=['https://acme.example/a','https://admin.acme.example/x'];const k=${JSON.stringify(K)};`});
    const hosts=Object.fromEntries(scan.recon!.result().lists.hosts.map(h=>[h.value,[h.scope,h.reason]]));
    assert.equal(hosts['acme.example'][0],'in-scope','the authorized seed host stays in scope under the program');
    assert.equal(hosts['admin.acme.example'][0],'out-of-scope','a program out-of-scope host is classified out-of-scope');
    assert.equal(hosts['admin.acme.example'][1],'program-out-of-scope','with the program reason recorded on the host entry');
    for(const list of Object.values(scan.recon!.result().lists))for(const it of list)noSecret(it.value,'host list value');
  }finally{scan.dispose();}
});

test('scan --recon --rebuild-sources --jsonl: recon lists are written and masked, the rebuild holds the public source, and no value reaches the terminal, standard output or JSON Lines',{timeout:300000},async()=>{
  const site=await serve(fixture(K)),dir=await temp('recon-cli-'),env={...process.env,EXPOSURE_DATA_DIR:dir};try{
    const cfg=path.join(dir,'one.json'),reconDir=path.join(dir,'recon'),rebuildDir=path.join(dir,'rebuild'),out=path.join(dir,'r.json');
    await writeFile(cfg,JSON.stringify({urls:[site.origin+'/'],developmentFixtureOrigin:site.origin,browser:false,adjacentMaps:true}));
    const r=await run(['scan','--config',cfg,'--coverage','standard','--recon',reconDir,'--rebuild-sources',rebuildDir,'--jsonl','--output',out],env);
    assert.ok(r.status===0||r.status===1,r.stderr);
    // The recon files exist and carry the discovered surface.
    const files=await readdir(reconDir);assert.ok(files.includes('recon.json')&&files.includes('urls.txt')&&files.includes('hosts.txt'),files.join(' '));
    const urls=await readFile(path.join(reconDir,'urls.txt'),'utf8');assert.ok(urls.includes('/app.js')&&urls.includes('/about'),urls);
    assert.ok((await readFile(path.join(reconDir,'js.txt'),'utf8')).includes('/app.js'),'the script is listed under js');
    assert.ok((await readFile(path.join(reconDir,'sourcemaps.txt'),'utf8')).includes('/app.js.map'),'the source map is listed');
    assert.ok((await readFile(path.join(reconDir,'endpoints.txt'),'utf8')).includes('/api/data'),'the endpoint is listed');
    assert.ok((await readFile(path.join(reconDir,'parameters.txt'),'utf8')).includes('token'),'the parameter name is listed');
    assert.equal((await readFile(path.join(reconDir,'hosts-in-scope.txt'),'utf8')).trim(),'127.0.0.1','the loopback host is in scope');
    // The rebuild reconstructs the public source, which legitimately contains the key: proof the rebuilder ran. This folder is never printed.
    const rebuilt=await readFile(path.join(rebuildDir,'src','secrets.ts'),'utf8').catch(async()=>{
      // The manifest records the file; find whichever path the rebuilder chose.
      const manifest=JSON.parse(await readFile(path.join(rebuildDir,'MANIFEST.json'),'utf8'));const first=manifest.files?.[0]?.path;return first?readFile(path.join(rebuildDir,first),'utf8'):'';});
    assert.ok(rebuilt.includes(K),'the rebuilt source holds the verbatim public value');
    // Masking everywhere it must hold: terminal, JSON Lines and every recon file.
    noSecret(r.stdout,'stdout');noSecret(r.stderr,'stderr');
    for(const f of files)noSecret(await readFile(path.join(reconDir,f),'utf8'),'recon/'+f);
    // The JSON Lines events carry the recon and rebuild paths.
    const end=r.events.find(e=>e.event==='target-end'),summary=r.events.find(e=>e.event==='summary');
    assert.equal(end.recon,reconDir);assert.ok(path.isAbsolute(end.report));
    assert.equal(summary.recon,reconDir);assert.equal(summary.rebuild,rebuildDir);assert.equal(summary.submissionBundle,null);
  }finally{await site.close();await rm(dir,{recursive:true,force:true});}
});

test('scan --format md and --submission-bundle write masked submission Markdown; summary carries the bundle path and no value is printed',{timeout:300000},async()=>{
  const site=await serve(fixture(K)),dir=await temp('recon-md-'),env={...process.env,EXPOSURE_DATA_DIR:dir};try{
    const cfg=path.join(dir,'one.json'),md=path.join(dir,'draft.md'),bundle=path.join(dir,'bundle');
    await writeFile(cfg,JSON.stringify({urls:[site.origin+'/'],developmentFixtureOrigin:site.origin,browser:false}));
    const r=await run(['scan','--config',cfg,'--coverage','standard','--format','md','--output',md,'--submission-bundle',bundle,'--jsonl'],env);
    assert.equal(r.status,1,r.stderr);
    const draft=await readFile(md,'utf8');assert.ok(/^#/m.test(draft)&&/[Ss]teps to [Rr]eproduce|Summary|Exposed/.test(draft),'the Markdown looks like a submission draft');
    noSecret(draft,'md draft');
    const index=await readFile(path.join(bundle,'index.md'),'utf8');assert.ok(index.length>0);noSecret(index,'bundle index');
    const bundleFiles=(await readdir(bundle)).filter(f=>f.endsWith('.md'));assert.ok(bundleFiles.length>=2,'one draft per finding plus index');
    for(const f of bundleFiles){const t=await readFile(path.join(bundle,f),'utf8');noSecret(t,'bundle/'+f);assert.ok(!f.endsWith('.sensitive.md'),'masked bundle has no sensitive file');}
    const summary=r.events.find(e=>e.event==='summary');assert.equal(summary.submissionBundle,path.resolve(bundle));
    noSecret(r.stdout,'stdout');noSecret(r.stderr,'stderr');
  }finally{await site.close();await rm(dir,{recursive:true,force:true});}
});

test('scan --targets --recon writes one folder per target plus a merged top-level set',{timeout:360000},async()=>{
  const a=await serve(fixture(K)),b=await serve(fixture(K)),dir=await temp('recon-targets-'),env={...process.env,EXPOSURE_DATA_DIR:dir};try{
    const tpl=path.join(dir,'tpl.json'),reconDir=path.join(dir,'recon');
    await writeFile(tpl,JSON.stringify({privateOrigins:[a.origin,b.origin],browser:false}));
    const r=await run(['scan','--targets','-','--authorized','--config',tpl,'--coverage','quick','--recon',reconDir,'--jsonl','--fail-on','never','--output',path.join(dir,'r.json')],env,`${a.origin}/\n${b.origin}/\n`);
    assert.equal(r.status,0,r.stderr);
    const entries=await readdir(reconDir);
    assert.ok(entries.includes('1-127.0.0.1')&&entries.includes('2-127.0.0.1'),'a <n>-<host> subfolder per target: '+entries.join(' '));
    assert.ok(entries.includes('recon.json')&&entries.includes('urls.txt'),'the merged top-level set is written beside the subfolders');
    const merged=JSON.parse(await readFile(path.join(reconDir,'recon.json'),'utf8'));assert.ok(merged.counts.urls>=1);
    const ends=r.events.filter(e=>e.event==='target-end');assert.deepEqual(ends.map(e=>e.recon).sort(),[path.join(reconDir,'1-127.0.0.1'),path.join(reconDir,'2-127.0.0.1')].sort());
    assert.equal(r.events.find(e=>e.event==='summary').recon,reconDir);
    for(const f of entries){const p=path.join(reconDir,f);const stat=await readdir(p).catch(()=>null);if(stat)for(const inner of stat)noSecret(await readFile(path.join(p,inner),'utf8'),f+'/'+inner);else noSecret(await readFile(p,'utf8'),f);}
  }finally{await a.close();await b.close();await rm(dir,{recursive:true,force:true});}
});
