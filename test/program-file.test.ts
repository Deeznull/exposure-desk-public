import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { root } from '../src/detectors.js';
import { CliError } from '../src/cli/errors.js';
import { makeConfig } from '../src/config.js';
import { HARD_CEILINGS } from '../src/profiles.js';
import { PROGRAM_SCHEMA, PROGRAM_LIMITS, describeProgram, loadProgram, normalizeProgramConfig, programFromJson, programId, programTemplate, stripJsonComments } from '../src/program/settings.js';
/** 2.8 program.json (w1-scope): validation of every field, unknown-field refusal, header and User-Agent suffix policy, the protected-host rule and the scan-configuration hook.
 * Offline: no request is made; names are .example/.test and protected names appear only as strings. */
async function temp(prefix:string){const parent=process.env.EXPOSURE_DATA_DIR||path.join(root,'.cache');await mkdir(parent,{recursive:true});return mkdtemp(path.join(parent,prefix));}
const base=(extra:Record<string,unknown>={})=>({schema:PROGRAM_SCHEMA,scope:{in:['*.acme.example','acme.example'],out:['legacy.acme.example']},...extra});
const refuses=(raw:unknown,message:RegExp)=>assert.throws(()=>programFromJson(raw,'/tmp/p'),(e:unknown)=>e instanceof CliError&&e.exitCode===2&&message.test(e.message),message.source);

test('a minimal program gets the documented defaults; authorized is false unless the file says true',()=>{
  const p=programFromJson(base(),'/tmp/p');
  assert.equal(p.authorized,false);assert.deepEqual(p.config.scope,{in:['*.acme.example','acme.example'],out:['legacy.acme.example']});
  assert.equal(p.config.requestsPerSecond,5);assert.deepEqual(p.config.concurrency,{targets:4,requests:16});assert.deepEqual(p.config.headers,{});assert.equal(p.config.userAgentSuffix,undefined);assert.equal(p.config.analysisMemoryMb,undefined);
  assert.match(p.config.id,/^[0-9a-f]{16}$/);assert.equal(p.config.id,programId('/tmp/p'));assert.notEqual(programId('/tmp/p'),programId('/tmp/q'));
  const full=programFromJson(base({name:'Acme',platform:'hackerone',authorized:true,rate:{requestsPerSecond:50},concurrency:{targets:64,requests:64},headers:{'X-Bug-Bounty':'researcher-1','X-HackerOne-Research':'researcher-1'},userAgentSuffix:'researcher-1 (bounty)',analysisMemoryMb:2048}),'/tmp/p');
  assert.equal(full.authorized,true);assert.equal(full.config.requestsPerSecond,50);assert.deepEqual(full.config.concurrency,{targets:64,requests:64});assert.equal(full.config.analysisMemoryMb,2048);assert.equal(full.config.userAgentSuffix,'researcher-1 (bounty)');
  assert.ok(describeProgram(full).some(l=>l==='Headers: X-Bug-Bounty: researcher-1; X-HackerOne-Research: researcher-1'));assert.ok(describeProgram(full).some(l=>l.startsWith('  out  legacy.acme.example')));
});

test('unknown fields, wrong types and out-of-range limits are refused at every level',()=>{
  refuses([],/one JSON object/);refuses({...base(),extra:1},/unknown field "extra"/);refuses({...base(),schema:'exposure-program/2'},/"schema" must be/);
  refuses(base({scope:{in:['acme.example'],out:[],also:[]}}),/scope: unknown field "also"/);refuses(base({rate:{requestsPerSecond:5,burst:10}}),/rate: unknown field "burst"/);refuses(base({concurrency:{targets:1,origins:2}}),/concurrency: unknown field "origins"/);
  refuses(base({authorized:'yes'}),/"authorized" must be true or false/);refuses({schema:PROGRAM_SCHEMA},/"scope" must be an object/);refuses(base({scope:{in:[],out:[]}}),/scope\.in has no rules/);refuses(base({scope:{in:'acme.example'}}),/must be an array/);
  refuses(base({rate:{requestsPerSecond:51}}),/rate\.requestsPerSecond must be a number from 0\.1 to 50/);refuses(base({rate:{requestsPerSecond:0}}),/from 0\.1 to 50/);refuses(base({rate:{requestsPerSecond:'5'}}),/from 0\.1 to 50/);
  refuses(base({concurrency:{targets:65}}),/concurrency\.targets must be a whole number from 1 to 64/);refuses(base({concurrency:{requests:1.5}}),/whole number/);refuses(base({concurrency:{requests:0}}),/from 1 to 64/);
  refuses(base({analysisMemoryMb:4096}),/analysisMemoryMb must be a whole number from 64 to 2048/);refuses(base({name:''}),/name must be printable text/);refuses(base({platform:'h1\nx'}),/platform must be printable text/);
  refuses(base({scope:{in:['*'],out:[]}}),/scope\.in: Scope rule "\*"/);refuses(base({scope:{in:['*.com'],out:[]}}),/public suffix/);
  refuses(base({scope:{in:Array.from({length:PROGRAM_LIMITS.rules+1},(_,i)=>`h${i}.acme.example`),out:[]}}),/more than 10000 rules/);
});

test('hard rules: a protected host can never be in scope (excluding one is allowed); program headers are identification headers only',()=>{
  for(const rule of ['portal.example.gov','*.example.mil','https://intranet.example.mil/app/','ministry.example.gouv.fr'])refuses(base({scope:{in:['acme.example',rule],out:[]}}),/Exposure Desk never scans government, military, intelligence or law-enforcement websites/);
  assert.deepEqual(programFromJson(base({scope:{in:['acme.example'],out:['portal.example.gov']}}),'/tmp/p').config.scope.out,['portal.example.gov']);
  for(const name of ['Authorization','Cookie','Host','User-Agent','Proxy-Authorization','Proxy-Connection','Origin','Referer','Accept','Sec-Fetch-Site','Forwarded','Transfer-Encoding'])refuses(base({headers:{[name]:'x'}}),/is never set by a program/);
  for(const name of ['X-Forwarded-For','X-Real-IP','X-Client-IP','X-Original-URL','X-HTTP-Method-Override','X-Amz-Date','X-Debug'])refuses(base({headers:{[name]:'x'}}),/routing, method-override and cloud headers are never sent/);
  for(const name of ['X-Api-Key','X-Auth-Token','X-Session','X-CSRF-Token','X-Signature','X-JWT','X-Bearer'])refuses(base({headers:{[name]:'x'}}),/looks like a credential header/);
  for(const name of ['Bug-Bounty','X-','X-Bug Bounty','X-Bug_Bounty'])refuses(base({headers:{[name]:'x'}}),/must be X-… identification headers/);
  refuses(base({headers:{'X-Bug-Bounty':'a\r\nX-Injected: 1'}}),/contains a line break/);refuses(base({headers:{'X-Bug-Bounty':'   '}}),/is empty/);refuses(base({headers:{'X-Bug-Bounty':'x'.repeat(257)}}),/longer than 256/);
  refuses(base({headers:{'X-Bug-Bounty':'café'}}),/printable ASCII/);refuses(base({headers:{'X-Bug-Bounty':1}}),/must be a string/);refuses(base({headers:{'X-Bug-Bounty':'a','x-bug-bounty':'b'}}),/listed twice/);
  refuses(base({headers:Object.fromEntries(Array.from({length:9},(_,i)=>[`X-Id-${i}`,'a']))}),/at most 8 headers/);
  // Short words inside longer names are not credentials (Assessor, Pinned, Signal).
  assert.ok(programFromJson(base({headers:{'X-Assessor':'a','X-Pinned-Program':'b','X-Signal':'c'}}),'/tmp/p'));
  for(const suffix of ['Mozilla/5.0','researcher Chrome/120','AppleWebKit','Safari','HeadlessChrome'])refuses(base({userAgentSuffix:suffix}),/must not contain browser product tokens/);
  refuses(base({userAgentSuffix:' padded'}),/without leading or trailing spaces/);refuses(base({userAgentSuffix:'a\nb'}),/line break/);refuses(base({userAgentSuffix:'x'.repeat(129)}),/longer than 128/);
});

test('program.json files: comments and a BOM are allowed, absent files mean a 2.7 key-only folder, broken files are refused, credential-looking values are never accepted or echoed',async()=>{
  const dir=await temp('program-file-');try{
    assert.equal(await loadProgram(dir),undefined,'no program.json: the 2.7 meaning of --program (key only)');
    assert.equal(await loadProgram(path.join(dir,'missing')),undefined);
    const file=path.join(dir,'program.json');
    await writeFile(file,'﻿// comment\n{ /* block */ "schema": "exposure-program/1", "name": "a // not a comment", "scope": {"in": ["acme.example"]}, "authorized": true }\n');
    const p=await loadProgram(dir);assert.equal(p!.config.name,'a // not a comment');assert.equal(p!.authorized,true);assert.equal(p!.file,file);
    await writeFile(file,'{ "schema": ');await assert.rejects(loadProgram(dir),(e:unknown)=>e instanceof CliError&&e.message.startsWith(file+' is not valid JSON'));
    await writeFile(file,'{ /* open ');await assert.rejects(loadProgram(dir),(e:unknown)=>e instanceof CliError&&/unterminated/.test(e.message));
    await writeFile(file,'x'.repeat(PROGRAM_LIMITS.fileBytes+1));await assert.rejects(loadProgram(dir),(e:unknown)=>e instanceof CliError&&/larger than 4 MiB/.test(e.message));
    await rm(file);await mkdir(file);await assert.rejects(loadProgram(dir),(e:unknown)=>e instanceof CliError&&/must be a regular file/.test(e.message));await rm(file,{recursive:true});
    // A synthetic credential in an identification header is refused before any request, and the value is not printed.
    const secret='ghp_'+'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8';
    await writeFile(file,JSON.stringify(base({headers:{'X-Bug-Bounty':secret}})));
    await assert.rejects(loadProgram(dir),(e:unknown)=>e instanceof CliError&&/looks like a credential/.test(e.message)&&!e.message.includes(secret));
    await writeFile(file,JSON.stringify(base({userAgentSuffix:secret})));await assert.rejects(loadProgram(dir),(e:unknown)=>e instanceof CliError&&!e.message.includes(secret));
    await writeFile(file,JSON.stringify(base({headers:{'X-Bug-Bounty':'researcher-1'},userAgentSuffix:'researcher-1'})));assert.equal((await loadProgram(dir))!.config.headers['X-Bug-Bounty'],'researcher-1');
  }finally{await rm(dir,{recursive:true,force:true});}
});

test('the init template is commented JSONC with authorized false and an empty scope that must be filled in',()=>{
  const text=programTemplate('Acme'),raw=JSON.parse(stripJsonComments(text));
  assert.equal(raw.authorized,false);assert.deepEqual(raw.scope,{in:[],out:[]});assert.equal(raw.rate.requestsPerSecond,5);assert.deepEqual(raw.concurrency,{targets:4,requests:16});assert.equal(raw.name,'Acme');
  assert.match(text,/^\/\/ Exposure Desk program settings/);assert.match(text,/X-Bug-Bounty/);assert.match(text,/subdomains only; add "example\.com" for the apex/);
  assert.throws(()=>programFromJson(raw,'/tmp/p'),/scope\.in has no rules/);
  raw.scope.in=['acme.example'];assert.equal(programFromJson(raw,'/tmp/p').authorized,false);
});

test('scan configuration: the program only narrows; seeds and related origins outside it are refused; its explicit memory is the only way above 512 MiB',()=>{
  const program=programFromJson(base({scope:{in:['*.acme.example','https://api.acme.test/v1/'],out:['legacy.acme.example']},analysisMemoryMb:1024,userAgentSuffix:'researcher-1'}),'/tmp/p').config;
  const c=makeConfig({urls:['https://app.acme.example/'],program});assert.deepEqual(c.program,program);assert.equal(c.maxAnalysisMemoryMb,1024);
  assert.deepEqual(makeConfig(JSON.parse(JSON.stringify(c))).program,program,'a saved program reloads unchanged');
  assert.throws(()=>makeConfig({urls:['https://legacy.acme.example/'],program}),/Outside the program scope: https:\/\/legacy\.acme\.example\//);
  assert.throws(()=>makeConfig({urls:['https://acme.example/'],program}),/Outside the program scope/,'the wildcard does not cover the apex');
  assert.throws(()=>makeConfig({urls:['https://api.acme.test/v2/'],program}),/Outside the program scope/);
  assert.ok(makeConfig({urls:['https://api.acme.test/v1/users'],program,relatedOrigins:['https://cdn.acme.example']}));
  assert.throws(()=>makeConfig({urls:['https://app.acme.example/'],program,relatedOrigins:['https://legacy.acme.example']}),/Related origin outside the program scope/);
  assert.throws(()=>makeConfig({urls:['https://app.acme.example/'],program,staticUserAgent:'none'}),/needs the product User-Agent/);
  // Without a program, the ready-option ceiling stays 512 MiB.
  assert.equal(HARD_CEILINGS.analysisMemoryMb,512);assert.throws(()=>makeConfig({urls:['https://app.acme.example/'],maxAnalysisMemoryMb:1024}));
  // A saved program is re-validated: tampering cannot widen it past the hard rules.
  for(const bad of [{...program,scope:{in:['*.com'],out:[]}},{...program,scope:{in:['portal.example.gov'],out:[]}},{...program,headers:{Authorization:'x'}},{...program,requestsPerSecond:500},{...program,extra:1},{...program,id:'../x'}])
    assert.throws(()=>makeConfig({urls:['https://app.acme.example/'],program:bad as any}));
  assert.throws(()=>normalizeProgramConfig({...program,concurrency:{targets:1}}),/program\.concurrency\.requests/);
});
