import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { root } from '../src/detectors.js';
/**
 * w2-wire: `exposure-desk report submit` renders submission Markdown offline from saved JSON scan reports. Hard rule under test: the Markdown is
 * masked on standard output, and `--full-secrets` is refused when it would print to standard output (an unmasked value can only reach a file).
 * Loopback fixtures and synthetic, nonfunctional keys only.
 */
const cli=path.join(root,'dist/src/cli.js');
const K='sk-proj-'+createHash('sha512').update('unit-report-submit').digest('base64url').slice(0,64);
async function temp(prefix:string){const parent=process.env.EXPOSURE_DATA_DIR||path.join(root,'.cache');await mkdir(parent,{recursive:true});return mkdtemp(path.join(parent,prefix));}
async function serve(k:string){
  const routes:Record<string,[string,string]>={'/':['text/html',`<!doctype html><script>const c={apiKey:${JSON.stringify(k)}};</script><script src="/app.js"></script>`],'/app.js':['text/javascript',`const client={apiKey:${JSON.stringify(k)}};`],'/robots.txt':['text/plain','User-agent: *\nAllow: /\n']};
  const server=http.createServer((req,res)=>{const p=(req.url||'/').split('?')[0]!;const r=routes[p];if(!r){res.statusCode=404;res.end('not found');return;}res.setHeader('content-type',r[0]);res.end(r[1]);});
  await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));
  return {origin:'http://127.0.0.1:'+(server.address() as any).port,close:()=>new Promise<void>(r=>{server.close(()=>r());server.closeAllConnections();})};
}
type Run={status:number|null;stdout:string;stderr:string};
function run(args:string[],env:NodeJS.ProcessEnv){return new Promise<Run>((resolve,reject)=>{const child=spawn(process.execPath,[cli,...args],{env,windowsHide:true});let stdout='',stderr='';const timer=setTimeout(()=>child.kill(),180000);
  child.stdout.on('data',d=>stdout+=d);child.stderr.on('data',d=>stderr+=d);child.on('error',reject);child.on('close',status=>{clearTimeout(timer);resolve({status,stdout,stderr});});});}
const noSecret=(t:string,l:string)=>{for(const part of [K,K.slice(8,40),K.slice(-24)])assert.ok(!t.includes(part),'masked ('+l+')');};

test('report submit round-trip: a masked JSON report renders masked Markdown to standard output and to --out; --full-secrets without a destination is refused',{timeout:300000},async()=>{
  const site=await serve(K),dir=await temp('report-submit-'),env={...process.env,EXPOSURE_DATA_DIR:dir};try{
    const cfg=path.join(dir,'one.json'),report=path.join(dir,'scan.json');
    await writeFile(cfg,JSON.stringify({urls:[site.origin+'/'],developmentFixtureOrigin:site.origin,browser:false}));
    // Produce a real masked JSON scan report.
    const scan=await run(['scan','--config',cfg,'--coverage','quick','--output',report],env);
    assert.equal(scan.status,1,scan.stderr);assert.ok(existsSync(report));
    const json=JSON.parse(await readFile(report,'utf8'));assert.equal(json.schema,'exposure-scan/1');assert.ok(json.findings.length>=1);
    noSecret(await readFile(report,'utf8'),'masked scan report');
    // Submit to standard output: masked Markdown, grouped by findingId.
    const toStdout=await run(['report','submit',report],env);
    assert.equal(toStdout.status??0,0,toStdout.stderr);assert.ok(/^#/m.test(toStdout.stdout),'Markdown on standard output');
    noSecret(toStdout.stdout,'report submit stdout');
    assert.ok(/redacted|\[redacted/i.test(toStdout.stdout),'the exposed value is shown masked');
    // Submit to a file: still masked (the source report carries no secrets).
    const outFile=path.join(dir,'draft.md');const toFile=await run(['report','submit',report,'--out',outFile],env);
    assert.equal(toFile.status??0,0,toFile.stderr);assert.match(toFile.stdout,/\(masked\)/);
    noSecret(await readFile(outFile,'utf8'),'report submit --out file');
    // --full-secrets without --out/--bundle is refused before anything is written.
    const refused=await run(['report','submit',report,'--full-secrets'],env);
    assert.equal(refused.status,2);assert.match(refused.stderr,/--full-secrets writes an unmasked value only to a file/);assert.equal(refused.stdout,'');
    // A non-report JSON is refused with the file named.
    const bad=path.join(dir,'bad.json');await writeFile(bad,JSON.stringify({hello:'world'}));
    const badRun=await run(['report','submit',bad],env);assert.equal(badRun.status,2);assert.match(badRun.stderr,/exposure-scan\/1/);
  }finally{await site.close();await rm(dir,{recursive:true,force:true});}
});
