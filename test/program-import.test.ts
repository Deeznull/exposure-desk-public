import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { root } from '../src/detectors.js';
import { CliError } from '../src/cli/errors.js';
import { Args, FLAGS } from '../src/cli/args.js';
import { parseCsv, importHackerOneCsv, importBountyTargets, readImport, writeImportedProgram, importedProgramText } from '../src/program/import.js';
import { loadProgram, programFromJson, stripJsonComments } from '../src/program/settings.js';
import { PROGRAM_USAGE } from '../src/cli/commands/program.js';
/** 2.8 offline scope import and the `program` command (w1-scope). Synthetic fixtures in test/fixtures/program on .example/.test names; nothing is fetched or requested. */
const FIXTURES=path.join(root,'test','fixtures','program'),cli=path.join(root,'dist/src/cli.js');
async function temp(prefix:string){const parent=process.env.EXPOSURE_DATA_DIR||path.join(root,'.cache');await mkdir(parent,{recursive:true});return mkdtemp(path.join(parent,prefix));}
const run=(args:string[],env:NodeJS.ProcessEnv)=>spawnSync(process.execPath,[cli,...args],{encoding:'utf8',windowsHide:true,timeout:60000,env});

test('CSV parser: quoted fields, doubled quotes, embedded line breaks, CRLF and a BOM',()=>{
  assert.deepEqual(parseCsv('﻿a,b\r\n"x, y","say ""hi""\nthere"\n\n,\n'),[['a','b'],['x, y','say "hi"\nthere']]);
  assert.throws(()=>parseCsv('a\n"open'),(e:unknown)=>e instanceof CliError&&/unterminated/.test(e.message));
});

test('HackerOne CSV: web and IP assets become rules, ineligible ones go out of scope, protected hosts are refused, the rest is skipped with a reason',async()=>{
  const r=importHackerOneCsv(await readFile(path.join(FIXTURES,'hackerone-scope.csv'),'utf8'),'hackerone-scope.csv');
  assert.deepEqual(r.in,['app.acme.example','*.acme.example','https://api.acme.test/v2/','staging.acme.example','beta.acme.example','192.0.2.0/24']);
  assert.deepEqual(r.out,['legacy.acme.example']);assert.equal(r.platform,'hackerone');
  assert.deepEqual(r.protected,[{asset:'portal.example.gov',host:'portal.example.gov'}]);
  assert.deepEqual(r.skipped.map(s=>[s.asset,s.type]),[['com.acme.mobile','google_play_app_id'],['Main web application','other'],['*.com','wildcard']]);
  assert.match(r.skipped[2]!.reason,/public suffix/);assert.match(r.skipped[0]!.reason,/not a website, URL, wildcard, IP address or CIDR/);
  assert.throws(()=>importHackerOneCsv('name,type\nx,y\n','f.csv'),(e:unknown)=>e instanceof CliError&&/identifier and asset_type/.test(e.message));
  assert.throws(()=>importHackerOneCsv('','f.csv'),/is empty/);
});

test('bounty-targets JSON: one program chosen by handle, id, name or URL segment; ambiguous or missing handles are refused',async()=>{
  const h1=await readFile(path.join(FIXTURES,'hackerone_data.json'),'utf8');
  const acme=importBountyTargets(h1,'hackerone_data.json','ACME');
  assert.deepEqual(acme.in,['www.acme.example','*.shop.acme.example']);assert.deepEqual(acme.out,['old.acme.example','blog.acme.example','https://www.acme.example/admin/']);
  assert.deepEqual(acme.protected.map(p=>p.host),['intranet.example.mil']);assert.deepEqual(acme.skipped.map(s=>s.type),['apple_store_app_id']);assert.equal(acme.name,'Acme Example');assert.equal(acme.platform,'hackerone');
  for(const handle of ['1002','globex test','globex'])assert.deepEqual(importBountyTargets(h1,'hackerone_data.json',handle).in,['globex.test'],handle);
  assert.throws(()=>importBountyTargets(h1,'hackerone_data.json','shared name'),(e:unknown)=>e instanceof CliError&&/2 programs .* match/.test(e.message));
  assert.throws(()=>importBountyTargets(h1,'hackerone_data.json','nobody'),/No program named nobody/);
  assert.throws(()=>importBountyTargets(h1,'hackerone_data.json',undefined),/lists 5 programs; choose one with --handle NAME/);
  assert.throws(()=>importBountyTargets('{','x.json','a'),/not valid JSON/);assert.throws(()=>importBountyTargets('[{"name":"x"}]','x.json','x'),/not a bounty-targets-data file/);
  // Bugcrowd: a target described in words falls back to its uri; a single program needs no handle.
  const bc=importBountyTargets(await readFile(path.join(FIXTURES,'bugcrowd_data.json'),'utf8'),'bugcrowd_data.json',undefined);
  assert.deepEqual(bc.in,['https://portal.initech.test','api.initech.test','*.initech.test']);assert.deepEqual(bc.out,['status.initech.test']);assert.equal(bc.platform,'bugcrowd');
  assert.deepEqual(bc.skipped.map(s=>[s.type,s.asset]),[['android','Initech for Android'],['network','198.51.100.0/24']]);
});

test('import output: a commented program.json with authorized false, validated before it is written, never replacing an existing file',async()=>{
  const dir=await temp('program-import-');try{
    const r=await readImport('hackerone-csv',path.join(FIXTURES,'hackerone-scope.csv'));
    const text=importedProgramText(r);assert.match(text,/^\/\/ Exposure Desk program settings/);assert.match(text,/Refused \(never scanned: government, military, intelligence or law-enforcement\): portal\.example\.gov/);assert.match(text,/Skipped google_play_app_id: com\.acme\.mobile/);
    const raw=JSON.parse(stripJsonComments(text));assert.equal(raw.authorized,false);assert.ok(!raw.scope.in.includes('portal.example.gov'));
    const file=await writeImportedProgram(dir,r);assert.equal(file,path.join(dir,'program.json'));const loaded=await loadProgram(dir);assert.equal(loaded!.authorized,false);assert.deepEqual(loaded!.config.scope.in,r.in);
    await assert.rejects(writeImportedProgram(dir,r),(e:unknown)=>e instanceof CliError&&/already exists/.test(e.message));
    const mobile=importBountyTargets(await readFile(path.join(FIXTURES,'hackerone_data.json'),'utf8'),'hackerone_data.json','nothing-web');
    await assert.rejects(writeImportedProgram(path.join(dir,'mobile'),mobile),(e:unknown)=>e instanceof CliError&&/Nothing to import/.test(e.message));
    await assert.rejects(readImport('intigriti-api',path.join(FIXTURES,'hackerone-scope.csv')),/Unknown --platform value/);
    await assert.rejects(readImport('hackerone-csv',path.join(dir,'missing.csv')),/could not be read/);await assert.rejects(readImport('hackerone-csv',FIXTURES),/must be a regular file/);
    await assert.rejects(readImport('hackerone-csv',path.join(FIXTURES,'hackerone-scope.csv'),'acme'),/--handle applies to bounty-targets files/);
    // Hostile text in an imported file only ever lands in comments, flattened to one line: it cannot add JSON fields.
    const hostile=importHackerOneCsv('identifier,asset_type\n"evil.acme.example */ ,""authorized"":true //",OTHER\n','h.csv');const hostileText=importedProgramText({...hostile,in:['acme.example']});
    assert.equal(JSON.parse(stripJsonComments(hostileText)).authorized,false);assert.ok(programFromJson(JSON.parse(stripJsonComments(hostileText)),dir));
  }finally{await rm(dir,{recursive:true,force:true});}
});

test('program command: init, check and import from the CLI; usage errors and refusals exit 2; the flags are registered for program only',async()=>{
  const dir=await temp('program-cli-'),env={...process.env,EXPOSURE_DATA_DIR:dir};try{
    assert.deepEqual(new Args(['program','import','--platform','hackerone-csv','--file','a.csv','--handle','x','out','--jsonl']).positionals(),['import','out']);
    for(const name of ['platform','file','handle'] as const)assert.deepEqual(FLAGS[name].commands,['program']);
    let r=run(['program'],env);assert.equal(r.status,2);assert.equal(r.stderr.trim(),PROGRAM_USAGE);
    r=run(['program','delete',dir],env);assert.equal(r.status,2);assert.equal(r.stderr.trim(),PROGRAM_USAGE);
    const p=path.join(dir,'acme');
    r=run(['program','check',p],env);assert.equal(r.status,2);assert.match(r.stderr,/Folder not found/);
    r=run(['program','init',p],env);assert.equal(r.status,0,r.stderr);assert.match(r.stdout,/Wrote .*program\.json/);
    r=run(['program','init',p],env);assert.equal(r.status,2);assert.match(r.stderr,/already exists\. Nothing was changed\./);
    r=run(['program','check',p],env);assert.equal(r.status,2);assert.match(r.stderr,/scope\.in has no rules/);
    const text=(await readFile(path.join(p,'program.json'),'utf8')).replace('"in": []','"in": ["*.acme.example", "acme.example"]');await writeFile(path.join(p,'program.json'),text);
    r=run(['program','check',p],env);assert.equal(r.status,0,r.stderr);assert.match(r.stdout,/^Program: My program\n/);assert.match(r.stdout,/\n {2}in {3}\*\.acme\.example \(subdomains of acme\.example only; not acme\.example itself\)\n/);assert.match(r.stdout,/Authorized: no/);assert.match(r.stdout,/Program file is valid\.\n$/);
    const imported=path.join(dir,'imported');
    r=run(['program','import','--platform','bounty-targets','--file',path.join(FIXTURES,'hackerone_data.json'),'--handle','acme',imported],env);assert.equal(r.status,0,r.stderr);
    assert.match(r.stderr,/^Refused: intranet\.example\.mil \(protected host intranet\.example\.mil;/m);assert.match(r.stderr,/^Skipped apple_store_app_id: id123456789/m);assert.match(r.stdout,/2 in-scope and 3 out-of-scope rules, 1 assets skipped, 1 protected hosts refused\./);assert.match(r.stdout,/"authorized" is false/);
    r=run(['program','check',imported],env);assert.equal(r.status,0,r.stderr);assert.match(r.stdout,/Program: Acme Example on hackerone/);
    r=run(['program','import','--platform','bounty-targets','--file',path.join(FIXTURES,'hackerone_data.json'),imported],env);assert.equal(r.status,2);assert.match(r.stderr,/choose one with --handle NAME/);
    r=run(['program','import','--platform','hackerone-csv',imported],env);assert.equal(r.status,2);assert.equal(r.stderr.trim(),PROGRAM_USAGE);
  }finally{await rm(dir,{recursive:true,force:true});}
});
