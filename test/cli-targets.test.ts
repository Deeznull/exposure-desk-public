import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { root } from '../src/detectors.js';
import { parseTargets, readTargets, echo, MAX_LINE, MAX_TARGETS, MAX_TARGET_BYTES } from '../src/cli/targets.js';
import { Args, FLAGS } from '../src/cli/args.js';
import { FORMATS, formatName } from '../src/cli/formats.js';
import { CliError } from '../src/cli/errors.js';
import { AUTHORIZATION_REQUIRED } from '../src/cli/commands/scan.js';
/** 3.0 CLI (w1-core): target lists (file or standard input), the --authorized rule for more than one target, the command and flag registries, and the 2.6 paths unchanged.
 * Loopback fixtures only; protected names appear as strings and are never resolved or contacted. */
const cli=path.join(root,'dist/src/cli.js');
const message=(host:string)=>`Exposure Desk never scans government, military, intelligence or law-enforcement websites: ${host}`;
async function temp(prefix:string){const parent=process.env.EXPOSURE_DATA_DIR||path.join(root,'.cache');await mkdir(parent,{recursive:true});return mkdtemp(path.join(parent,prefix));}
/** Loopback fixture website recording every request path. */
async function serve(routes:Record<string,[type:string,body:string]>){
  const arrivals:string[]=[];const server=http.createServer((req,res)=>{arrivals.push(req.url||'');const r=routes[(req.url||'/').split('?')[0]!];if(!r){res.statusCode=404;res.end('not found');return;}res.setHeader('content-type',r[0]);res.end(r[1]);});
  await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));
  return {origin:'http://127.0.0.1:'+(server.address() as any).port,arrivals,close:()=>new Promise<void>(r=>{server.close(()=>r());server.closeAllConnections();})};
}
const SITE=()=>({'/':['text/html','<!doctype html><title>targets fixture</title><a href="/b/">b</a><script src="/app.js"></script>'],'/b/':['text/html','<!doctype html><p>second target</p>'],'/app.js':['text/javascript','const ready=true;'],'/robots.txt':['text/plain','User-agent: *\nAllow: /\n']} as Record<string,[string,string]>);
/** Asynchronous child: the fixture is served by this process, so its event loop must stay free. Settles on 'close', after the child released its directory. */
function run(args:string[],env:NodeJS.ProcessEnv,input=''){return new Promise<{status:number|null;stdout:string;stderr:string}>((resolve,reject)=>{const child=spawn(process.execPath,[cli,...args],{env,windowsHide:true});let stdout='',stderr='';const timer=setTimeout(()=>child.kill(),120000);
  child.stdout.on('data',d=>stdout+=d);child.stderr.on('data',d=>stderr+=d);child.stdin.on('error',()=>{});child.stdin.end(input);child.on('error',reject);child.on('close',status=>{clearTimeout(timer);resolve({status,stdout,stderr});});});}

test('target lists: hosts, URLs, httpx lines and httpx -json lines; comments, blank lines and duplicates skipped; every rejected line keeps its number and reason',()=>{
  const lines=[String.fromCharCode(0xFEFF)+'# program targets','','example.com','https://Example.COM/','https://example.com:443/ [200] [Example Domain] [nginx]','  http://shop.example.net/cart?item=1#top [301,200] [Shop]  ','[200] https://app.example.org/login',
    '{"timestamp":"2026-10-10T00:00:00Z","url":"https://api.example.org/v1","status_code":200}','ftp://files.example.com/','https://user:hunter2@example.com/admin?token=abc123','https://bad..example.com/','intranet.example.mil','https://portal.example.gov/login [200]','https://portal.example.gov./other','PORTAL.EXAMPLE.GOV:8443',
    '{"input":"intranet.example.mil","status_code":200}','# done','x'.repeat(MAX_LINE)+'.example.com','*.example.com','{not json','https://{braces}.example.com/'];
  const r=parseTargets(lines.join('\r\n'));
  assert.deepEqual(r.accepted,[{line:3,url:'https://example.com/'},{line:6,url:'http://shop.example.net/cart?item=1'},{line:7,url:'https://app.example.org/login'},{line:8,url:'https://api.example.org/v1'}]);
  assert.deepEqual(r.rejected.map(x=>[x.line,x.reason]),[[4,'duplicate'],[5,'duplicate'],[9,'unsupported-scheme'],[10,'credentials-in-url'],[11,'invalid-url'],[12,'protected-host'],[13,'protected-host'],[14,'protected-host'],[15,'protected-host'],[16,'protected-host'],[18,'line-too-long'],[19,'invalid-url'],[20,'invalid-url'],[21,'invalid-url']]);
  const echoed=r.rejected.map(x=>x.input).join('\n');assert.ok(!echoed.includes('hunter2')&&!echoed.includes('abc123'),'a rejected line never echoes user info or a query');assert.ok(r.rejected.every(x=>x.input.length<=200));
  assert.equal(r.rejected.find(x=>x.line===10)!.input,'https://[redacted]@example.com/admin');assert.equal(r.rejected.find(x=>x.line===12)!.input,'intranet.example.mil');
  assert.equal(echo('https://a:b@example.com/x?y=1#z'),'https://[redacted]@example.com/x');assert.equal(echo('example.com/p#f'),'example.com/p');
  // LF and lone CR line ends; a list with nothing accepted is empty, not an error.
  assert.deepEqual(parseTargets('a.example.com\rb.example.com\nhttps://a.example.com').accepted.map(t=>t.url),['https://a.example.com/','https://b.example.com/']);
  assert.deepEqual(parseTargets('# only comments\n\n   \n'),{accepted:[],rejected:[]});
});

test('target lists: the protected-host rule runs on every line before anything else and has no exception; the target limit is enforced',()=>{
  // Protected names in any accepted form: bare host, URL, port, trailing dot, case, a path, an httpx line and a JSON line.
  const blocked=['intranet.example.mil','https://intranet.example.mil/','http://INTRANET.EXAMPLE.MIL:8080/x','www.example.gov.','https://www.example.gov/login?next=/ [403] [Login]','{"url":"https://cdn.example.gov/app.js"}','ministry.example.gouv.fr'];
  const r=parseTargets(blocked.join('\n'));assert.deepEqual(r.accepted,[]);assert.deepEqual(r.rejected.map(x=>x.reason),blocked.map(()=>'protected-host'));
  // A protected line that is also too long, malformed or duplicated is still reported as protected.
  assert.equal(parseTargets('intranet.example.mil/'+'a'.repeat(MAX_LINE)).rejected[0]!.reason,'protected-host');assert.deepEqual(parseTargets('www.example.gov\nwww.example.gov').rejected.map(x=>x.reason),['protected-host','protected-host']);
  const many=Array.from({length:MAX_TARGETS+2},(_,i)=>`h${i}.example.com`).join('\n'),limited=parseTargets(many);
  assert.equal(limited.accepted.length,MAX_TARGETS);assert.deepEqual(limited.rejected.map(x=>[x.line,x.reason]),[[MAX_TARGETS+1,'target-limit'],[MAX_TARGETS+2,'target-limit']]);
});

test('target files: unreadable or oversized lists are refused with a safe message; a readable file is parsed like standard input',async()=>{
  const dir=await temp('cli-targets-files-');try{
    await assert.rejects(readTargets(path.join(dir,'missing.txt')),(e:unknown)=>e instanceof CliError&&e.exitCode===2&&e.message==='Targets list could not be read: '+path.join(dir,'missing.txt'));
    const big=path.join(dir,'big.txt');await writeFile(big,Buffer.alloc(MAX_TARGET_BYTES+1,0x61));await assert.rejects(readTargets(big),(e:unknown)=>e instanceof CliError&&e.message==='Targets list is larger than 16 MiB');
    const file=path.join(dir,'list.txt');await writeFile(file,'# list\nexample.com\nexample.com\n');assert.deepEqual(await readTargets(file),{accepted:[{line:2,url:'https://example.com/'}],rejected:[{line:3,input:'example.com',reason:'duplicate'}]});
  }finally{await rm(dir,{recursive:true,force:true});}
});

test('command and flag registries: --help and -h anywhere print help and exit 0; every documented flag is registered; formats are a registry',()=>{
  assert.equal(new Args(['--help']).command,'help');assert.equal(new Args(['-h']).command,'help');assert.equal(new Args([]).command,'dashboard');assert.ok(new Args(['scan','--url','x','-h']).help);assert.ok(!new Args(['scan','--url','x']).help);
  assert.equal(new Args(['scan','--targets','-']).option('targets'),'-');assert.throws(()=>new Args(['scan','--targets']).option('targets'),/Missing option value/);assert.throws(()=>new Args(['scan','--targets','--jsonl']).option('targets'),/Missing option value/);
  assert.ok(new Args(['scan','--jsonl','--silent']).flag('silent'));assert.ok(!new Args(['scan','--jsonl']).flag('authorized'));
  assert.deepEqual(Object.keys(FORMATS),['json','html','sarif','md']);assert.equal(formatName(undefined),'json');assert.equal(formatName('sarif'),'sarif');assert.equal(formatName('md'),'md');assert.equal(FORMATS.md.extension,'md');assert.throws(()=>formatName('pdf'),/Unknown format/);
  const outputs:string[]=[];for(const args of [['help'],['--help'],['-h'],['scan','--help'],['scan','-h'],['scan','--targets','-','--help'],['artifacts','--help'],['doctor','-h']]){const r=spawnSync(process.execPath,[cli,...args],{encoding:'utf8',windowsHide:true,timeout:60000});assert.equal(r.status,0,args.join(' '));assert.equal(r.stderr,'',args.join(' '));outputs.push(r.stdout);}
  assert.ok(outputs.every(o=>o===outputs[0]),'one help text');const help=outputs[0]!;
  for(const s of ['--targets FILE|-','[--authorized]','[--program DIR]','[--jsonl]','[--silent]','docs/JSONL.md','protected-host','exits 2 before any request','--full-secrets affects only report files on disk','\nExit codes:'])assert.ok(help.includes(s),s);
  const documented=[...new Set(help.match(/--[a-z][a-z-]*/g))].map(f=>f.slice(2));assert.deepEqual(documented.filter(f=>!Object.hasOwn(FLAGS,f)),[],'every flag in the help is in the registry');
  for(const name of ['targets','authorized','jsonl','silent','program'])assert.ok((FLAGS as any)[name].commands.includes('scan'));
});

test('more than one target needs --authorized: refused with exit 2 before any request, from a file or standard input, with or without --jsonl',{timeout:120000},async()=>{
  const site=await serve(SITE()),dir=await temp('cli-targets-auth-'),env={...process.env,EXPOSURE_DATA_DIR:dir};try{
    const tpl=path.join(dir,'template.json'),list=path.join(dir,'targets.txt'),out=path.join(dir,'never.json');await writeFile(tpl,JSON.stringify({developmentFixtureOrigin:site.origin}));const text=`${site.origin}/\n${site.origin}/b/ [200] [b]\n`;await writeFile(list,text);
    for(const [args,input] of [[['--targets',list],''],[['--targets','-'],text],[['--targets',list,'--jsonl'],''],[['--targets','-','--jsonl','--silent'],text]] as [string[],string][]){
      const r=await run(['scan',...args,'--config',tpl,'--coverage','quick','--output',out],env,input);assert.equal(r.status,2,args.join(' '));assert.equal(r.stderr.trim(),AUTHORIZATION_REQUIRED,args.join(' '));assert.equal(r.stdout,'','no event and no plan line');
    }
    assert.match(AUTHORIZATION_REQUIRED,/--authorized/);assert.equal(site.arrivals.length,0,'nothing was requested');assert.ok(!existsSync(out));
  }finally{await site.close();await rm(dir,{recursive:true,force:true});}
});

test('target refusals: no accepted line, conflicting inputs and an unreadable list exit 2 before any request; rejected lines are listed with their reasons',{timeout:120000},async()=>{
  const site=await serve(SITE()),dir=await temp('cli-targets-refuse-'),env={...process.env,EXPOSURE_DATA_DIR:dir};try{
    const out=path.join(dir,'never.json'),list=path.join(dir,'targets.txt'),tpl=path.join(dir,'template.json'),two=path.join(dir,'two.json'),cp=path.join(dir,'checkpoint.json');
    await writeFile(list,'# nothing scannable\nintranet.example.mil\nftp://files.example.com/\n');await writeFile(tpl,JSON.stringify({developmentFixtureOrigin:site.origin}));
    await writeFile(two,JSON.stringify({projects:[{urls:[site.origin+'/'],developmentFixtureOrigin:site.origin},{urls:[site.origin+'/b/'],developmentFixtureOrigin:site.origin}]}));await writeFile(cp,JSON.stringify({schema:'exposure-checkpoint/1',config:{urls:[site.origin+'/']},frontier:[]}));
    let r=await run(['scan','--targets',list,'--authorized','--output',out],env);assert.equal(r.status,2);
    assert.deepEqual(r.stderr.trim().split(/\r?\n/),['Rejected line 2: intranet.example.mil (protected-host)','Rejected line 3: ftp://files.example.com/ (unsupported-scheme)','No target to scan: the list has no accepted line. Nothing was requested.']);
    r=await run(['scan','--targets','-','--jsonl','--output',out],env,'');assert.equal(r.status,2);assert.equal(r.stderr.trim(),'No target to scan: the list has no accepted line. Nothing was requested.');assert.equal(r.stdout,'');
    r=await run(['scan','--targets',path.join(dir,'missing.txt'),'--output',out],env);assert.equal(r.status,2);assert.equal(r.stderr.trim(),'Targets list could not be read: '+path.join(dir,'missing.txt'));
    await writeFile(list,site.origin+'/\n');
    for(const extra of [['--url',site.origin+'/'],['--resume',cp]]){r=await run(['scan','--targets',list,...extra,'--output',out],env);assert.equal(r.status,2,extra[0]);assert.equal(r.stderr.trim(),'--targets cannot be combined with --url or --resume');}
    r=await run(['scan','--targets',list,'--config',two,'--output',out],env);assert.equal(r.status,2);assert.match(r.stderr,/--config FILE holds one settings template/);
    // Flags are validated before the first request, also with a target list.
    for(const extra of [['--format','pdf'],['--fail-on','sometimes'],['--coverage','maximum'],['--scope','everything']]){r=await run(['scan','--targets',list,'--config',tpl,...extra,'--output',out],env);assert.equal(r.status,2,extra.join(' '));}
    // A protected host in the template refuses the whole command with the fixed message.
    await writeFile(tpl,JSON.stringify({developmentFixtureOrigin:site.origin,relatedOrigins:['https://cdn.example.gov']}));r=await run(['scan','--targets',list,'--config',tpl,'--output',out],env);assert.equal(r.status,2);assert.equal(r.stderr.trim(),message('cdn.example.gov'));
    assert.equal(site.arrivals.length,0,'nothing was requested');assert.ok(!existsSync(out));
  }finally{await site.close();await rm(dir,{recursive:true,force:true});}
});

test('a protected or duplicate line is rejected and the remaining targets run one after another; reports are numbered per target',{timeout:240000},async()=>{
  const site=await serve(SITE()),dir=await temp('cli-targets-run-'),env={...process.env,EXPOSURE_DATA_DIR:dir};try{
    const tpl=path.join(dir,'template.json'),out=path.join(dir,'report.json');await writeFile(tpl,JSON.stringify({developmentFixtureOrigin:site.origin,browser:false}));
    const input=`# from stdin\nintranet.example.mil\n${site.origin}/ [200] [fixture]\n${site.origin}/\n{"url":"${site.origin}/b/","status_code":200}\n`;
    const r=await run(['scan','--targets','-','--authorized','--config',tpl,'--coverage','quick','--output',out],env,input);
    assert.equal(r.status,0,r.stderr);assert.deepEqual(r.stderr.trim().split(/\r?\n/),['Rejected line 2: intranet.example.mil (protected-host)','Rejected line 4: '+site.origin+'/ (duplicate)']);
    const t1=r.stdout.indexOf(`Target 1/2: ${site.origin}/\n`),t2=r.stdout.indexOf(`Target 2/2: ${site.origin}/b/\n`);assert.ok(t1>=0&&t2>t1,r.stdout);
    assert.equal(r.stdout.match(/\nProfile: Quick check \+ Normal · 1 website /g)?.length,2);assert.equal(r.stdout.match(/^completed: 0 findings; .*exit 0\. Redacted report written\.$/gm)?.length,2);
    assert.ok(!r.stdout.includes('{"schema"'),'no JSON Lines without --jsonl');
    const files=(await readdir(dir)).filter(f=>f.startsWith('report')).sort();assert.deepEqual(files,['report-1.json','report-2.json']);
    const reports=await Promise.all(files.map(async f=>JSON.parse(await readFile(path.join(dir,f),'utf8'))));assert.deepEqual(reports.map(j=>j.config.urls),[[site.origin+'/'],[site.origin+'/b/']]);assert.deepEqual(reports.map(j=>j.launch.interface),['cli','cli']);
    assert.ok(site.arrivals.includes('/')&&site.arrivals.includes('/b/'));
  }finally{await site.close();await rm(dir,{recursive:true,force:true});}
});

test('2.6 paths unchanged: a configuration with several websites needs no --authorized, keeps its report names and plan lines, and prints no target lines',{timeout:240000},async()=>{
  const site=await serve(SITE()),dir=await temp('cli-targets-legacy-'),env={...process.env,EXPOSURE_DATA_DIR:dir};try{
    const one=path.join(dir,'one.json'),two=path.join(dir,'two.json'),out=path.join(dir,'single.json'),multi=path.join(dir,'multi.json');
    await writeFile(one,JSON.stringify({urls:[site.origin+'/'],developmentFixtureOrigin:site.origin}));await writeFile(two,JSON.stringify({projects:[{urls:[site.origin+'/'],developmentFixtureOrigin:site.origin},{urls:[site.origin+'/b/'],developmentFixtureOrigin:site.origin}]}));
    let r=await run(['scan','--config',one,'--coverage','quick','--output',out],env);assert.equal(r.status,0,r.stderr);assert.equal(r.stderr,'');
    assert.match(r.stdout,/^Run #[0-9a-f]{8} · .* \(CLI\) · /);assert.match(r.stdout,/\nProfile: Quick check \+ Normal · 1 website /);assert.match(r.stdout,/\nScope: /);assert.match(r.stdout,/\nScope counts: /);assert.match(r.stdout,/\ncompleted: 0 findings; /);assert.match(r.stdout,/No supported exposure detected in inspected coverage/);
    assert.ok(!/^Target /m.test(r.stdout)&&!r.stdout.includes('{"schema"'));assert.ok(existsSync(out),'the exact --output path');
    r=await run(['scan','--config',two,'--coverage','quick','--output',multi],env);assert.equal(r.status,0,r.stderr);assert.equal(r.stdout.match(/^Run #/gm)?.length,2);assert.ok(!/^Target /m.test(r.stdout));
    assert.ok(existsSync(path.join(dir,'multi-1.json'))&&existsSync(path.join(dir,'multi-2.json')));
  }finally{await site.close();await rm(dir,{recursive:true,force:true});}
});
