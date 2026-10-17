import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdtemp, mkdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { root } from '../src/detectors.js';
import { main } from '../src/cli/index.js';
import { JSONL_SCHEMA } from '../src/cli/output.js';
/** 3.0 CLI (w1-core): JSON Lines events, --silent, masking and stable finding ids (--program). Loopback fixtures with synthetic, nonfunctional keys only. */
const cli=path.join(root,'dist/src/cli.js'),pause=(ms:number)=>new Promise(r=>setTimeout(r,ms));
const key=(name:string)=>'sk-proj-'+createHash('sha512').update('unit-jsonl-'+name).digest('base64url').slice(0,64);
const K=key('shared'),Q=key('query');
async function temp(prefix:string){const parent=process.env.EXPOSURE_DATA_DIR||path.join(root,'.cache');await mkdir(parent,{recursive:true});return mkdtemp(path.join(parent,prefix));}
/** Loopback fixture website recording every request path; a `hold` path never answers until the server closes. */
async function serve(routes:Record<string,[type:string,body:string]>,hold?:string){
  const arrivals:string[]=[];const server=http.createServer((req,res)=>{const p=(req.url||'/').split('?')[0]!;arrivals.push(p);if(p===hold)return;const r=routes[p];if(!r){res.statusCode=404;res.end('not found');return;}res.setHeader('content-type',r[0]);res.end(r[1]);});
  await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));
  return {origin:'http://127.0.0.1:'+(server.address() as any).port,arrivals,close:()=>new Promise<void>(r=>{server.close(()=>r());server.closeAllConnections();})};
}
/** The same synthetic key inline in the page and in its script: one finding with two occurrences. */
const SITE=(k:string)=>({'/':['text/html',`<!doctype html><script>window.S={openai:${JSON.stringify(k)}}</script><script src="/app.js"></script>`],'/app.js':['text/javascript',`const client={apiKey:${JSON.stringify(k)}};`],'/robots.txt':['text/plain','User-agent: *\nAllow: /\n']} as Record<string,[string,string]>);
type Run={status:number|null;stdout:string;stderr:string;events:any[]};
/** Asynchronous child: the fixtures are served by this process, so its event loop must stay free. Settles on 'close', after the child released its directory. */
function run(args:string[],env:NodeJS.ProcessEnv,input=''){return new Promise<Run>((resolve,reject)=>{const child=spawn(process.execPath,[cli,'scan',...args],{env,windowsHide:true});let stdout='',stderr='';const timer=setTimeout(()=>child.kill(),180000);
  child.stdout.on('data',d=>stdout+=d);child.stderr.on('data',d=>stderr+=d);child.stdin.on('error',()=>{});child.stdin.end(input);child.on('error',reject);
  child.on('close',status=>{clearTimeout(timer);resolve({status,stdout,stderr,events:args.includes('--jsonl')?stdout.split('\n').filter(Boolean).map(l=>JSON.parse(l)):[]});});});}
const names=(r:Run)=>r.events.map(e=>e.event).join(' ');
const credentialIds=(r:Run,target:number)=>r.events.filter(e=>e.event==='finding'&&e.target===target&&e.category==='private-credential').map(e=>e.findingId as string);
const of=(r:Run,event:string)=>r.events.filter(e=>e.event===event);

test('--jsonl: one event per line in order, every line carries the schema, values are masked, readable lines move to standard error and the exit code follows --fail-on',{timeout:300000},async()=>{
  const a=await serve(SITE(K)),b=await serve(SITE(K)),dir=await temp('jsonl-events-'),env={...process.env,EXPOSURE_DATA_DIR:dir};try{
    const tpl=path.join(dir,'template.json'),list=path.join(dir,'targets.txt'),out=path.join(dir,'r.json');await writeFile(tpl,JSON.stringify({privateOrigins:[a.origin,b.origin],browser:false}));
    await writeFile(list,`intranet.example.mil\n${a.origin}/\n${b.origin}/ [200] [fixture]\n${a.origin}/\n`);
    const r=await run(['--targets',list,'--authorized','--config',tpl,'--coverage','quick','--jsonl','--output',out],env);
    assert.equal(r.status,1,r.stderr);assert.ok(r.stdout.endsWith('\n'));
    for(const e of r.events){assert.equal(e.schema,JSONL_SCHEMA);assert.ok(!Number.isNaN(Date.parse(e.at)),'at is a timestamp');}
    assert.match(names(r),/^run-start target-start (finding )+target-end target-start (finding )+target-end summary$/);
    const [start]=of(r,'run-start');assert.match(start.version,/^\d+\.\d+\.\d+/);
    assert.deepEqual({...start,schema:undefined,at:undefined,version:undefined},{schema:undefined,at:undefined,version:undefined,event:'run-start',mode:'targets',targets:2,rejected:[{line:1,input:'intranet.example.mil',reason:'protected-host'},{line:4,input:a.origin+'/',reason:'duplicate'}],authorized:true,program:false,format:'json',failOn:'private-credential'});
    const starts=of(r,'target-start'),ends=of(r,'target-end');assert.deepEqual(starts.map(s=>[s.target,s.url]),[[1,a.origin+'/'],[2,b.origin+'/']]);assert.ok(starts.every(s=>typeof s.runId==='string'&&Array.isArray(s.urls)&&typeof s.name==='string'));
    for(const f of of(r,'finding')){assert.match(f.findingId,/^[0-9a-f]{64}$/);assert.match(f.masked,/^\[redacted: \d+ characters\]$/);assert.ok(f.locations.length>=1&&f.locations.every((l:any)=>l.url.startsWith(f.target===1?a.origin:b.origin)));assert.equal(f.validity,'unverified');assert.equal(typeof f.suppressed,'boolean');}
    const [one,two]=[credentialIds(r,1),credentialIds(r,2)];assert.equal(one.length,1);assert.deepEqual(two,one,'one run keeps one id for one exposure across targets');const shared=of(r,'finding').find(f=>f.findingId===one[0]&&f.target===1)!;assert.ok(shared.occurrences>=2);assert.deepEqual([...new Set(shared.locations.map((l:any)=>new URL(l.url).pathname))].sort(),['/','/app.js'],'one finding for the page and its script');
    for(const [i,e] of ends.entries()){assert.equal(e.target,i+1);assert.equal(e.status,'completed');assert.equal(e.exit,1);assert.equal(typeof e.stopReason,'string');assert.ok(Array.isArray(e.gaps));assert.equal(e.findings,of(r,'finding').filter(f=>f.target===i+1).length);assert.ok(path.isAbsolute(e.report)&&existsSync(e.report));assert.equal(path.basename(e.report),`r-${i+1}.json`);assert.equal(e.recon,null,'no recon folder without --recon');}
    const [summary]=of(r,'summary');assert.deepEqual({...summary,schema:undefined,at:undefined},{schema:undefined,at:undefined,event:'summary',targets:2,scanned:2,notStarted:0,rejected:2,findings:of(r,'finding').length,states:{completed:2},interrupted:false,exit:1,recon:null,rebuild:null,submissionBundle:null},'recon, rebuild and submissionBundle are null when their flags are not used');
    // Masking: no event, readable line or redacted report contains the key or a fragment of it.
    for(const text of [r.stdout,r.stderr,await readFile(ends[0].report,'utf8')])for(const part of [K,K.slice(8,40),K.slice(-24)])assert.ok(!text.includes(part),'masked');
    assert.match(r.stderr,/^Rejected line 1: intranet\.example\.mil \(protected-host\)$/m);assert.match(r.stderr,/^Target 1\/2: /m);assert.match(r.stderr,/^Run #[0-9a-f]{8} /m);assert.ok(r.stderr.includes(`Finding ${one[0]} · `),'the readable finding line names the same id');
    assert.ok(!r.stdout.split('\n').filter(Boolean).some(l=>!l.startsWith('{"schema":"exposure-jsonl/1",')),'standard output carries events only');
    const report=JSON.parse(await readFile(ends[1].report,'utf8'));assert.ok(report.findings.some((f:any)=>f.findingId===one[0]&&f.correlation===one[0]),'the report carries the same findingId');
    const never=await run(['--targets','-','--config',tpl,'--coverage','quick','--jsonl','--fail-on','never','--output',path.join(dir,'never.json')],env,a.origin+'/\n');
    assert.equal(never.status,0,never.stderr);assert.equal(of(never,'target-end')[0].exit,0);assert.equal(of(never,'summary')[0].exit,0);assert.equal(of(never,'run-start')[0].failOn,'never');assert.equal(of(never,'run-start')[0].authorized,false,'one target needs no --authorized');
  }finally{await a.close();await b.close();await rm(dir,{recursive:true,force:true});}
});

test('masking: a key in a target URL never reaches the terminal or the events; --full-secrets changes only the report file on disk',{timeout:240000},async()=>{
  const site=await serve(SITE(K)),dir=await temp('jsonl-mask-'),env={...process.env,EXPOSURE_DATA_DIR:dir};try{
    const tpl=path.join(dir,'template.json'),out=path.join(dir,'full.json');await writeFile(tpl,JSON.stringify({developmentFixtureOrigin:site.origin,browser:false}));
    const full=await run(['--targets','-','--config',tpl,'--coverage','quick','--jsonl','--full-secrets','--output',out],env,site.origin+'/\n');assert.equal(full.status,1,full.stderr);
    for(const text of [full.stdout,full.stderr])assert.ok(!text.includes(K)&&!text.includes(K.slice(8,40)),'terminal and events stay masked with --full-secrets');
    assert.equal(of(full,'target-end')[0].report,out);assert.ok((await readFile(out,'utf8')).includes(K),'the sensitive export on disk is the only place with the value');
    const queried=await run(['--targets','-','--config',tpl,'--coverage','quick','--jsonl','--output',path.join(dir,'q.json')],env,`${site.origin}/?api_key=${Q}\n`);
    assert.ok([0,1,2].includes(queried.status!));assert.match(names(queried),/^run-start target-start (finding )*target-end summary$/);
    for(const text of [queried.stdout,queried.stderr,await readFile(path.join(dir,'q.json'),'utf8')])assert.ok(!text.includes(Q)&&!text.includes(Q.slice(8,40)),'a key in the target URL is masked everywhere');
  }finally{await site.close();await rm(dir,{recursive:true,force:true});}
});

test('--silent prints no plan or progress lines, only results; with --jsonl standard error stays empty',{timeout:240000},async()=>{
  const site=await serve(SITE(K)),dir=await temp('jsonl-silent-'),env={...process.env,EXPOSURE_DATA_DIR:dir};try{
    const cfg=path.join(dir,'one.json');await writeFile(cfg,JSON.stringify({urls:[site.origin+'/'],developmentFixtureOrigin:site.origin,browser:false}));
    const loud=await run(['--config',cfg,'--coverage','quick','--output',path.join(dir,'loud.json')],env),quiet=await run(['--config',cfg,'--coverage','quick','--silent','--output',path.join(dir,'quiet.json')],env);
    assert.equal(loud.status,1);assert.equal(quiet.status,1);assert.equal(quiet.stderr,'');assert.match(loud.stdout,/^Run #/m);assert.match(loud.stdout,/^Profile: /m);
    const lines=quiet.stdout.split(/\r?\n/).filter(Boolean);assert.ok(lines.length>=2);
    for(const l of lines)assert.match(l,/^(?:completed|incomplete)(?: \(Limited by profile\))?: \d+ findings; |^Finding [0-9a-f]{64} · |^Completed — quick coverage: |^No supported exposure detected/,l);
    const anon=(ls:string[])=>ls.map(l=>l.replace(/^Finding [0-9a-f]{64}/,'Finding ID'));
    assert.deepEqual(anon(lines),anon(loud.stdout.split(/\r?\n/).filter(l=>/^(?:completed|incomplete)|^Finding |^Completed — quick|^No supported/.test(l))),'the same results as without --silent (ids differ: each run has its own key)');
    const both=await run(['--targets','-','--config',cfg,'--coverage','quick','--jsonl','--silent','--output',path.join(dir,'both.json')],env,site.origin+'/\n');
    assert.equal(both.status,1);assert.equal(both.stderr,'');assert.match(names(both),/^run-start target-start (finding )+target-end summary$/);
  }finally{await site.close();await rm(dir,{recursive:true,force:true});}
});

test('stable ids: with --program DIR one exposure keeps its findingId across targets and runs (also the SARIF fingerprint); without it each run has its own key',{timeout:420000},async()=>{
  const a=await serve(SITE(K)),b=await serve(SITE(K)),dir=await temp('jsonl-program-'),env={...process.env,EXPOSURE_DATA_DIR:dir};try{
    const tpl=path.join(dir,'template.json'),program=path.join(dir,'program'),keyFile=path.join(program,'.key');await writeFile(tpl,JSON.stringify({privateOrigins:[a.origin,b.origin],browser:false}));
    const common=['--config',tpl,'--coverage','quick','--jsonl','--fail-on','never'];
    const first=await run(['--targets','-','--authorized','--program',program,...common,'--output',path.join(dir,'first.json')],env,`${a.origin}/\n${b.origin}/\n`);assert.equal(first.status,0,first.stderr);
    const id=credentialIds(first,1)[0]!;assert.match(id,/^[0-9a-f]{64}$/);assert.deepEqual(credentialIds(first,2),[id],'same id across targets');assert.equal(of(first,'run-start')[0].program,true);
    const st=await stat(keyFile);assert.equal(st.size,32);assert.ok(st.isFile());
    if(process.platform==='win32'){const acl=spawnSync('icacls',[keyFile],{encoding:'utf8',windowsHide:true});assert.equal(acl.status,0);const grants=acl.stdout.split(/\r?\n/).filter(l=>/:\(/.test(l));assert.equal(grants.length,1,'one owner-only grant: '+acl.stdout);assert.ok(!grants[0]!.includes('(I)'),'no inherited grant');}
    else assert.equal(st.mode&0o777,0o600);
    const saved=await readFile(keyFile);
    const second=await run(['--targets','-','--program',program,...common,'--format','sarif','--output',path.join(dir,'second.sarif')],env,`${b.origin}/\n`);assert.equal(second.status,0,second.stderr);
    assert.deepEqual(credentialIds(second,1),[id],'same id in a later run of the same program');assert.deepEqual(await readFile(keyFile),saved,'the key is reused, never replaced');
    const sarif=JSON.parse(await readFile(path.join(dir,'second.sarif'),'utf8'));assert.ok(sarif.runs[0].results.some((x:any)=>x.partialFingerprints?.['exposureDesk/correlation/v2']===id),'findingId is the SARIF correlation fingerprint');assert.ok(sarif.runs[0].results.some((x:any)=>x.partialFingerprints?.['exposureDesk/correlation/v2']===id&&x.properties?.findingId===id),'SARIF result properties carry the findingId');
    const x=await run(['--targets','-',...common,'--output',path.join(dir,'x.json')],env,`${a.origin}/\n`),y=await run(['--targets','-',...common,'--format','html','--output',path.join(dir,'y.html')],env,`${a.origin}/\n`);
    const [ix,iy]=[credentialIds(x,1)[0]!,credentialIds(y,1)[0]!];assert.match(ix,/^[0-9a-f]{64}$/);assert.notEqual(ix,iy,'without --program each run has its own key');assert.ok((await readFile(path.join(dir,'y.html'),'utf8')).includes('Finding ID <code>'+iy+'</code>'),'the HTML report shows the findingId');assert.notEqual(ix,id);assert.notEqual(iy,id);
    // A damaged key or a key path that is not a regular file refuses the run before any request.
    const before=a.arrivals.length,bad=path.join(dir,'bad'),odd=path.join(dir,'odd');await mkdir(bad);await writeFile(path.join(bad,'.key'),'too short');await mkdir(path.join(odd,'.key'),{recursive:true});
    let r=await run(['--targets','-','--program',bad,...common,'--output',path.join(dir,'never.json')],env,`${a.origin}/\n`);assert.equal(r.status,2);assert.equal(r.stderr.trim(),'Program key is invalid (expected 32 bytes): '+path.join(bad,'.key'));assert.equal(r.stdout,'');
    r=await run(['--targets','-','--program',odd,...common,'--output',path.join(dir,'never.json')],env,`${a.origin}/\n`);assert.equal(r.status,2);assert.equal(r.stdout,'');
    assert.equal(a.arrivals.length,before,'nothing was requested');assert.ok(!existsSync(path.join(dir,'never.json')));
  }finally{await a.close();await b.close();await rm(dir,{recursive:true,force:true});}
});

test('Ctrl+C cancels the running target and starts no further one: target-end cancelled, summary interrupted, exit 2',{timeout:180000},async()=>{
  // In-process, so the interrupt is the same on every platform: the scan's own SIGINT listener is the only one while it runs.
  const site=await serve({'/':['text/html','<!doctype html><script src="/slow.js"></script>'],'/b/':['text/html','<!doctype html><p>never requested</p>']},'/slow.js'),dir=await temp('jsonl-interrupt-');
  const list=path.join(dir,'targets.txt'),tpl=path.join(dir,'template.json');await writeFile(list,`${site.origin}/\n${site.origin}/b/\n`);await writeFile(tpl,JSON.stringify({developmentFixtureOrigin:site.origin,browser:false}));
  const listeners={SIGINT:process.listeners('SIGINT'),SIGTERM:process.listeners('SIGTERM')},writes={out:process.stdout.write,err:process.stderr.write},previous=process.exitCode;let out='',code:typeof process.exitCode;
  const capture=(add:(s:string)=>void)=>((chunk:unknown,...rest:unknown[])=>{add(String(chunk));const cb=rest.find(x=>typeof x==='function') as (()=>void)|undefined;cb?.();return true;}) as typeof process.stdout.write;
  process.removeAllListeners('SIGINT');process.removeAllListeners('SIGTERM');process.stdout.write=capture(s=>out+=s);process.stderr.write=capture(()=>{});
  try{
    const done=main(['scan','--targets',list,'--authorized','--config',tpl,'--coverage','quick','--jsonl','--output',path.join(dir,'r.json')]);
    for(const end=Date.now()+60000;!site.arrivals.includes('/slow.js');){if(Date.now()>end)throw new Error('the first target never reached its held script');await pause(50);}
    assert.equal(process.listenerCount('SIGINT'),1,'the scan listens for Ctrl+C');process.emit('SIGINT' as any,'SIGINT' as any);await done;code=process.exitCode;
    assert.equal(process.listenerCount('SIGINT'),0,'the listener is removed when the scan ends');
  }finally{process.stdout.write=writes.out;process.stderr.write=writes.err;process.exitCode=previous;for(const [s,fns] of Object.entries(listeners))for(const fn of fns)process.on(s as NodeJS.Signals,fn as any);await site.close();}
  try{
    const events=out.split('\n').filter(Boolean).map(l=>JSON.parse(l));assert.equal(code,2);
    assert.match(events.map(e=>e.event).join(' '),/^run-start target-start (finding )*target-end summary$/);
    const end=events.find(e=>e.event==='target-end'),summary=events.find(e=>e.event==='summary');assert.equal(end.status,'cancelled');assert.equal(end.stopReason,'cancelled');assert.equal(end.exit,2);
    assert.deepEqual({targets:summary.targets,scanned:summary.scanned,notStarted:summary.notStarted,interrupted:summary.interrupted,exit:summary.exit},{targets:2,scanned:1,notStarted:1,interrupted:true,exit:2});
    assert.ok(!site.arrivals.includes('/b/'),'the second target was never requested');
  }finally{await rm(dir,{recursive:true,force:true,maxRetries:5});}
});

test('a closed --jsonl reader (for example `| head -1`) stops the run like Ctrl+C: no stack trace, no further target, exit 2',{timeout:240000},async()=>{
  const a=await serve(SITE(K)),b=await serve(SITE(K)),dir=await temp('jsonl-closed-'),env={...process.env,EXPOSURE_DATA_DIR:dir};try{
    const tpl=path.join(dir,'template.json');await writeFile(tpl,JSON.stringify({privateOrigins:[a.origin,b.origin],browser:false}));
    const r=await new Promise<{status:number|null;first:string;stderr:string}>((resolve,reject)=>{
      const child=spawn(process.execPath,[cli,'scan','--targets','-','--authorized','--config',tpl,'--coverage','quick','--jsonl','--fail-on','never','--output',path.join(dir,'r.json')],{env,windowsHide:true});
      let first='',stderr='';const timer=setTimeout(()=>child.kill(),180000);
      // The reader takes the first event and goes away, as `head -1` does.
      child.stdout.on('data',d=>{if(first)return;first=String(d).split('\n')[0]!;child.stdout.destroy();});child.stderr.on('data',d=>stderr+=d);
      child.stdin.on('error',()=>{});child.stdin.end(`${a.origin}/\n${b.origin}/\n`);child.on('error',reject);child.on('close',status=>{clearTimeout(timer);resolve({status,first,stderr});});});
    assert.equal(JSON.parse(r.first).event,'run-start');
    assert.equal(r.status,2,r.stderr);assert.doesNotMatch(r.stderr,/EPIPE|EOF|Error|\n\s+at /,'no raw exception reaches the terminal');
    assert.equal(b.arrivals.length,0,'no further target is started once the reader is gone');
  }finally{await a.close();await b.close();await rm(dir,{recursive:true,force:true,maxRetries:5});}
});
