import {createHash} from 'node:crypto';
import {lstat,readFile} from 'node:fs/promises';
import path from 'node:path';
import type {ProgramConfig} from '../types.js';
import {CliError} from '../cli/errors.js';
import {protectedHost,PROTECTED_HOST_MESSAGE} from '../protected-hosts.js';
import {ProgramScope,RuleError,describeRule,parseRule,ruleHost} from './rules.js';
/** program.json (2.8): the settings file in a --program DIR folder, next to DIR/.key. Comments (// and /* *\/) are allowed so `program init` can explain each field.
 * Every error is a CliError (exit 2) raised before any request. Unknown fields are refused, so a typo never silently widens or loosens a run. */
export const PROGRAM_SCHEMA='exposure-program/1',PROGRAM_FILE='program.json';
export const PROGRAM_LIMITS={requestsPerSecond:{min:0.1,max:50,default:5},targets:{min:1,max:64,default:4},requests:{min:1,max:64,default:16},analysisMemoryMb:{min:64,max:2048},
  rules:10000,headers:8,headerName:64,headerValue:256,userAgentSuffix:128,name:100,platform:40,fileBytes:4*1024*1024} as const;
/** What a program file says, after validation. `authorized: true` counts as --authorized for every target in scope. */
export interface ProgramFile {dir:string;file:string;authorized:boolean;config:ProgramConfig}
const fail=(message:string):never=>{throw new CliError(message);};
const isObject=(v:unknown):v is Record<string,unknown>=>!!v&&typeof v==='object'&&!Array.isArray(v);
function onlyKeys(where:string,v:Record<string,unknown>,allowed:readonly string[]){
  const unknown=Object.keys(v).filter(k=>!allowed.includes(k));
  if(unknown.length)fail(`${where}: unknown field${unknown.length===1?'':'s'} ${unknown.map(k=>JSON.stringify(k)).join(', ')} (allowed: ${allowed.join(', ')})`);
}
/** Removes // and /* *\/ comments outside JSON strings; positions of everything else are kept (comments become spaces) so JSON errors still point at the right place. */
export function stripJsonComments(text:string):string{
  let out='',i=0,inString=false;
  while(i<text.length){
    const c=text[i]!,n=text[i+1];
    if(inString){out+=c;if(c==='\\'){out+=n??'';i+=2;continue;}if(c==='"')inString=false;i++;continue;}
    if(c==='"'){inString=true;out+=c;i++;continue;}
    if(c==='/'&&n==='/'){while(i<text.length&&text[i]!=='\n'){out+=' ';i++;}continue;}
    if(c==='/'&&n==='*'){const end=text.indexOf('*/',i+2);if(end<0)fail('program.json: unterminated /* comment');for(;i<end+2;i++)out+=text[i]==='\n'?'\n':' ';continue;}
    out+=c;i++;
  }
  return out;
}
/** Stable id for a program folder: the shared limiter and the report use it, never the raw path. */
export function programId(dir:string){const resolved=path.resolve(dir);return createHash('sha256').update(process.platform==='win32'?resolved.toLowerCase():resolved).digest('hex').slice(0,16);}
const PRINTABLE=/^[\x20-\x7e]*$/;
/** Header names a program may add: identification headers only (X-…). Credentials, client-address or routing overrides, method overrides and hop-by-hop headers never. */
const NEVER_NAMES=/^(?:authorization|proxy-.*|cookie|set-cookie|host|user-agent|connection|keep-alive|te|trailer|transfer-encoding|upgrade|content-length|content-type|origin|referer|accept.*|sec-.*|forwarded|via)$/i;
const CREDENTIAL_NAME=/(?:auth|token|secret|key|session|passw|pwd|cookie|csrf|xsrf|credential|signature|bearer|nonce|saml|login|cert|(?:^|-)(?:sig|jwt|otp|sso|pin|mfa)(?:-|$))/i;
const ROUTING_NAME=/^x-(?:forwarded(?:-.*)?|real-ip|client-ip|cluster-client-ip|originating-ip|remote-(?:ip|addr)|true-client-ip|host|original-(?:url|host)|rewrite-url|http-method(?:-override)?|method-override|override-.*|proxy.*|amz-.*|goog-.*|ms-.*|azure-.*|envoy-.*|middleware-.*|debug.*)$/i;
export function checkHeaderName(name:string){
  if(typeof name!=='string'||!name)fail('program.json headers: header names must be non-empty strings');
  if(/[\r\n]/.test(name))fail(`program.json headers: header name ${JSON.stringify(name)} contains a line break`);
  if(name.length>PROGRAM_LIMITS.headerName)fail(`program.json headers: header name is longer than ${PROGRAM_LIMITS.headerName} characters`);
  if(NEVER_NAMES.test(name))fail(`program.json headers: ${name} is never set by a program (only identification headers such as X-Bug-Bounty are allowed; the User-Agent can only get a suffix)`);
  if(!/^X-[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/i.test(name))fail(`program.json headers: ${JSON.stringify(name)} is not allowed; program headers must be X-… identification headers (letters, digits and hyphens)`);
  if(ROUTING_NAME.test(name))fail(`program.json headers: ${name} is not allowed; client-address, routing, method-override and cloud headers are never sent (no evasion)`);
  if(CREDENTIAL_NAME.test(name.slice(2)))fail(`program.json headers: ${name} looks like a credential header; program headers identify the researcher and never carry credentials`);
}
export function checkHeaderValue(name:string,value:unknown){
  if(typeof value!=='string')fail(`program.json headers: the value of ${name} must be a string`);
  const v=value as string;
  if(/[\r\n]/.test(v))fail(`program.json headers: the value of ${name} contains a line break`);
  if(!v.trim())fail(`program.json headers: the value of ${name} is empty`);
  if(v.length>PROGRAM_LIMITS.headerValue)fail(`program.json headers: the value of ${name} is longer than ${PROGRAM_LIMITS.headerValue} characters`);
  if(!PRINTABLE.test(v))fail(`program.json headers: the value of ${name} must be printable ASCII`);
}
/** Browser product tokens a suffix may not add: the suffix identifies the researcher; it never makes the product token look like a browser. */
const BROWSER_TOKEN=/(?:mozilla|applewebkit|gecko|khtml|chrome|chromium|crios|safari|firefox|fxios|edg|opr\/|opera|msie|trident|version\/|mobile\/|headless)/i;
export function checkUserAgentSuffix(v:unknown){
  if(typeof v!=='string')fail('program.json userAgentSuffix must be a string');
  const s=v as string;
  if(/[\r\n]/.test(s))fail('program.json userAgentSuffix contains a line break');
  if(!s.trim()||s!==s.trim())fail('program.json userAgentSuffix must be non-empty without leading or trailing spaces');
  if(s.length>PROGRAM_LIMITS.userAgentSuffix)fail(`program.json userAgentSuffix is longer than ${PROGRAM_LIMITS.userAgentSuffix} characters`);
  if(!PRINTABLE.test(s))fail('program.json userAgentSuffix must be printable ASCII');
  if(BROWSER_TOKEN.test(s))fail('program.json userAgentSuffix must not contain browser product tokens; it is appended to the honest Exposure Desk token and never replaces or disguises it');
}
function number(where:string,v:unknown,min:number,max:number,integer:boolean):number{
  if(typeof v!=='number'||!Number.isFinite(v)||v<min||v>max||integer&&!Number.isInteger(v))fail(`${where} must be ${integer?'a whole number':'a number'} from ${min} to ${max}`);
  return v as number;
}
function rules(where:string,v:unknown,inScope:boolean):string[]{
  if(!Array.isArray(v))fail(`${where} must be an array of scope rules`);
  const list=v as unknown[];
  if(list.length>PROGRAM_LIMITS.rules)fail(`${where} has more than ${PROGRAM_LIMITS.rules} rules`);
  const out:string[]=[];
  for(const r of list){
    let rule;try{rule=parseRule(r,inScope);}catch(e){if(e instanceof RuleError)fail(`${where}: ${e.message}`);throw e;}
    // Hard rule: a protected host can be excluded but never put in scope (the protected-host block runs before scope rules either way).
    const host=ruleHost(rule!);
    if(inScope&&host&&protectedHost(host))fail(`${where}: ${PROTECTED_HOST_MESSAGE}: ${protectedHost(host)!.host} (rule "${rule!.raw}")`);
    if(!out.includes(rule!.raw))out.push(rule!.raw);
  }
  return out;
}
function headers(v:unknown):Record<string,string>{
  if(!isObject(v))fail('program.json headers must be an object of header names and values');
  const entries=Object.entries(v as Record<string,unknown>);
  if(entries.length>PROGRAM_LIMITS.headers)fail(`program.json headers: at most ${PROGRAM_LIMITS.headers} headers`);
  const seen=new Set<string>(),out:Record<string,string>={};
  for(const [name,value] of entries){checkHeaderName(name);checkHeaderValue(name,value);const k=name.toLowerCase();if(seen.has(k))fail(`program.json headers: ${name} is listed twice`);seen.add(k);out[name]=value as string;}
  return out;
}
function text(where:string,v:unknown,max:number,pattern=PRINTABLE):string{
  if(typeof v!=='string'||!v.trim()||v.length>max||!pattern.test(v))fail(`${where} must be printable text of 1 to ${max} characters`);
  return (v as string).trim();
}
/** Validates the opt-in live-key-check block (2.9). Strict: unknown sub-keys are refused and `enabled` is required; `checkAll` defaults to false. Absent in the file means no key is ever sent. */
function liveKeyChecks(where:string,v:unknown):{enabled:boolean;checkAll?:boolean}{
  if(!isObject(v))fail(`${where} must be an object with "enabled" (and optional "checkAll")`);
  const o=v as Record<string,unknown>;onlyKeys(where,o,['enabled','checkAll']);
  if(typeof o.enabled!=='boolean')fail(`${where}.enabled must be true or false`);
  if(o.checkAll!==undefined&&typeof o.checkAll!=='boolean')fail(`${where}.checkAll must be true or false`);
  return {enabled:o.enabled as boolean,...(o.checkAll===true?{checkAll:true}:{})};
}
/** Validates a parsed program.json object. `dir` is the --program folder (its id keys the limiter). */
export function programFromJson(raw:unknown,dir:string,file=path.join(dir,PROGRAM_FILE)):ProgramFile{
  if(!isObject(raw))fail('program.json must contain one JSON object');
  const o=raw as Record<string,unknown>;
  onlyKeys('program.json',o,['schema','name','platform','authorized','scope','rate','concurrency','headers','userAgentSuffix','analysisMemoryMb','liveKeyChecks']);
  if(o.schema!==PROGRAM_SCHEMA)fail(`program.json: "schema" must be "${PROGRAM_SCHEMA}"`);
  if(o.authorized!==undefined&&typeof o.authorized!=='boolean')fail('program.json: "authorized" must be true or false');
  if(!isObject(o.scope))fail('program.json: "scope" must be an object with "in" and "out" rule arrays');
  const scope=o.scope as Record<string,unknown>;onlyKeys('program.json scope',scope,['in','out']);
  const inRules=rules('program.json scope.in',scope.in??[],true),outRules=rules('program.json scope.out',scope.out??[],false);
  if(!inRules.length)fail('program.json scope.in has no rules; add the program\'s in-scope hosts, wildcards or URL prefixes (see docs/PROGRAM.md)');
  let requestsPerSecond:number=PROGRAM_LIMITS.requestsPerSecond.default;
  if(o.rate!==undefined){if(!isObject(o.rate))fail('program.json: "rate" must be an object');const r=o.rate as Record<string,unknown>;onlyKeys('program.json rate',r,['requestsPerSecond']);if(r.requestsPerSecond!==undefined)requestsPerSecond=number('program.json rate.requestsPerSecond',r.requestsPerSecond,PROGRAM_LIMITS.requestsPerSecond.min,PROGRAM_LIMITS.requestsPerSecond.max,false);}
  let targets:number=PROGRAM_LIMITS.targets.default,requests:number=PROGRAM_LIMITS.requests.default;
  if(o.concurrency!==undefined){if(!isObject(o.concurrency))fail('program.json: "concurrency" must be an object');const c=o.concurrency as Record<string,unknown>;onlyKeys('program.json concurrency',c,['targets','requests']);
    if(c.targets!==undefined)targets=number('program.json concurrency.targets',c.targets,PROGRAM_LIMITS.targets.min,PROGRAM_LIMITS.targets.max,true);
    if(c.requests!==undefined)requests=number('program.json concurrency.requests',c.requests,PROGRAM_LIMITS.requests.min,PROGRAM_LIMITS.requests.max,true);}
  const config:ProgramConfig={id:programId(dir),scope:{in:inRules,out:outRules},requestsPerSecond,concurrency:{targets,requests},headers:o.headers===undefined?{}:headers(o.headers)};
  if(o.name!==undefined)config.name=text('program.json name',o.name,PROGRAM_LIMITS.name);
  if(o.platform!==undefined)config.platform=text('program.json platform',o.platform,PROGRAM_LIMITS.platform,/^[A-Za-z0-9][A-Za-z0-9 ._-]*$/);
  if(o.userAgentSuffix!==undefined){checkUserAgentSuffix(o.userAgentSuffix);config.userAgentSuffix=o.userAgentSuffix as string;}
  if(o.analysisMemoryMb!==undefined)config.analysisMemoryMb=number('program.json analysisMemoryMb',o.analysisMemoryMb,PROGRAM_LIMITS.analysisMemoryMb.min,PROGRAM_LIMITS.analysisMemoryMb.max,true);
  if(o.liveKeyChecks!==undefined)config.liveKeyChecks=liveKeyChecks('program.json liveKeyChecks',o.liveKeyChecks);
  return {dir:path.resolve(dir),file,authorized:o.authorized===true,config};
}
/** Re-validates a program carried in a scan configuration (saved checkpoints and resumed runs keep enforcing it). Throws CliError. */
export function normalizeProgramConfig(raw:unknown):ProgramConfig{
  if(!isObject(raw))fail('Invalid setting: program');
  const o=raw as Record<string,unknown>;
  onlyKeys('Invalid setting: program',o,['id','name','platform','scope','requestsPerSecond','concurrency','headers','userAgentSuffix','analysisMemoryMb','liveKeyChecks']);
  if(typeof o.id!=='string'||!/^[0-9a-f]{16}$/.test(o.id))fail('Invalid setting: program.id');
  if(!isObject(o.scope))fail('Invalid setting: program.scope');
  const s=o.scope as Record<string,unknown>;onlyKeys('Invalid setting: program.scope',s,['in','out']);
  const inRules=rules('program scope.in',s.in,true),outRules=rules('program scope.out',s.out,false);
  if(!inRules.length)fail('Invalid setting: program.scope.in has no rules');
  if(!isObject(o.concurrency))fail('Invalid setting: program.concurrency');
  const c=o.concurrency as Record<string,unknown>;onlyKeys('Invalid setting: program.concurrency',c,['targets','requests']);
  const config:ProgramConfig={id:o.id as string,scope:{in:inRules,out:outRules},
    requestsPerSecond:number('Invalid setting: program.requestsPerSecond',o.requestsPerSecond,PROGRAM_LIMITS.requestsPerSecond.min,PROGRAM_LIMITS.requestsPerSecond.max,false),
    concurrency:{targets:number('Invalid setting: program.concurrency.targets',c.targets,PROGRAM_LIMITS.targets.min,PROGRAM_LIMITS.targets.max,true),requests:number('Invalid setting: program.concurrency.requests',c.requests,PROGRAM_LIMITS.requests.min,PROGRAM_LIMITS.requests.max,true)},
    headers:headers(o.headers??{})};
  if(o.name!==undefined)config.name=text('Invalid setting: program.name',o.name,PROGRAM_LIMITS.name);
  if(o.platform!==undefined)config.platform=text('Invalid setting: program.platform',o.platform,PROGRAM_LIMITS.platform,/^[A-Za-z0-9][A-Za-z0-9 ._-]*$/);
  if(o.userAgentSuffix!==undefined){checkUserAgentSuffix(o.userAgentSuffix);config.userAgentSuffix=o.userAgentSuffix as string;}
  if(o.analysisMemoryMb!==undefined)config.analysisMemoryMb=number('Invalid setting: program.analysisMemoryMb',o.analysisMemoryMb,PROGRAM_LIMITS.analysisMemoryMb.min,PROGRAM_LIMITS.analysisMemoryMb.max,true);
  if(o.liveKeyChecks!==undefined)config.liveKeyChecks=liveKeyChecks('Invalid setting: program.liveKeyChecks',o.liveKeyChecks);
  return config;
}
/** Reads DIR/program.json; undefined when the folder has none (a 2.7 --program run: the correlation key only). */
export async function loadProgram(dir:string):Promise<ProgramFile|undefined>{
  const file=path.join(path.resolve(dir),PROGRAM_FILE);
  let st;try{st=await lstat(file);}catch(e:any){if(e?.code==='ENOENT'||e?.code==='ENOTDIR')return undefined;fail(`Cannot read ${file}`);}
  if(!st!.isFile())fail(`${file} must be a regular file`);
  if(st!.size>PROGRAM_LIMITS.fileBytes)fail(`${file} is larger than ${PROGRAM_LIMITS.fileBytes/1048576} MiB`);
  let text:string;try{text=await readFile(file,'utf8');}catch{return fail(`Cannot read ${file}`);}
  let parsed:unknown;try{parsed=JSON.parse(stripJsonComments(text.replace(/^﻿/,'')));}catch(e){if(e instanceof CliError)throw e;return fail(`${file} is not valid JSON${e instanceof SyntaxError?': '+e.message.replace(/[\r\n]+/g,' ').slice(0,200):''}`);}
  const program=programFromJson(parsed,dir,file);await screenProgramValues(program.config);return program;
}
/** Header values and the User-Agent suffix (each at most 256 characters) are screened with the local detector's windowed pass (no whole-document parse on the main thread) before any request: a program never sends a credential. The value is never printed. */
export async function screenProgramValues(config:ProgramConfig){
  const values=[...Object.values(config.headers),...(config.userAgentSuffix?[config.userAgentSuffix]:[])];if(!values.length)return;
  const {Detector}=await import('../detectors.js');const detector=new Detector('disabled');
  for(const v of values)if(detector.inspectWindowed(v).some(c=>c.category==='private-credential'||c.category==='suspicious'))fail('program.json: a header value or the User-Agent suffix looks like a credential; program headers identify the researcher and never carry credentials (the value is not shown)');
}
/** Compiled scope for a configuration's program (cached per program object). */
const compiled=new WeakMap<ProgramConfig,ProgramScope>();
export function programScope(program:ProgramConfig):ProgramScope{let s=compiled.get(program);if(!s){s=new ProgramScope(program.scope);compiled.set(program,s);}return s;}
/** The effective program settings and scope, one line each (printed by `program check` and before a program run). */
export function describeProgram(p:ProgramFile):string[]{
  const c=p.config,scope=programScope(c),lines:string[]=[];
  lines.push(`Program: ${c.name??'(unnamed)'}${c.platform?` on ${c.platform}`:''}`);
  lines.push(`File: ${p.file}`);
  lines.push(`Authorized: ${p.authorized?'yes (counts as --authorized for in-scope targets)':'no (each scan needs --authorized)'}`);
  lines.push(`Rate: ${c.requestsPerSecond} requests per second across the whole program run`);
  lines.push(`Concurrency: ${c.concurrency.targets} targets at once, ${c.concurrency.requests} requests at once across the run`);
  lines.push(`Headers: ${Object.keys(c.headers).length?Object.entries(c.headers).map(([k,v])=>`${k}: ${v}`).join('; '):'none'}`);
  lines.push(`User-Agent suffix: ${c.userAgentSuffix??'none'}`);
  if(c.analysisMemoryMb!==undefined)lines.push(`Analysis memory: ${c.analysisMemoryMb} MiB (explicit program setting; lowered automatically when this computer has less free memory)`);
  lines.push(`Live key checks: ${c.liveKeyChecks?.enabled?`enabled for per-finding checks${c.liveKeyChecks.checkAll?', including "check all"':''}`:'off (no found key is ever sent to any provider)'}`);
  lines.push(`Effective scope (${scope.in.length} in, ${scope.out.length} out; out-of-scope rules always win; anything not matched by an in rule is out of scope):`);
  for(const r of scope.in)lines.push('  in   '+describeRule(r));
  for(const r of scope.out)lines.push('  out  '+describeRule(r));
  lines.push('Government, military, intelligence and law-enforcement hosts are never scanned, whatever the scope says.');
  return lines;
}
/** The commented template `program init` writes; `authorized` stays false until the owner confirms the program's terms. */
export function programTemplate(name='My program'):string{
  return `// Exposure Desk program settings (${PROGRAM_SCHEMA}). Comments are allowed. See docs/PROGRAM.md.
// Check this file with:  exposure-desk program check DIR
{
  "schema": "${PROGRAM_SCHEMA}",
  "name": ${JSON.stringify(name)},
  // Optional: where the program runs (for your own records), e.g. "hackerone", "bugcrowd", "intigriti", "yeswehack".
  // "platform": "hackerone",

  // Set to true only after you have read the program's policy and it authorizes testing these assets.
  // true counts as --authorized for in-scope targets; it never widens the scope.
  "authorized": false,

  "scope": {
    // In-scope rules. Forms:
    //   "app.example.com"                  exact host (any scheme and port)
    //   "*.example.com"                    subdomains only; add "example.com" for the apex
    //   "https://api.example.com/v1/"      URL prefix: scheme, host, optional port and path prefix
    //   "192.0.2.10", "192.0.2.0/24"       IP address or CIDR block (URLs that name the address)
    "in": [],
    // Out-of-scope rules use the same forms and always win over in-scope rules.
    "out": []
  },

  // Program-wide request rate (default 5, at most 50 per second), on top of the per-website limits.
  "rate": { "requestsPerSecond": 5 },

  // Targets scanned at once and requests at once across the whole run (each at most 64).
  "concurrency": { "targets": 4, "requests": 16 },

  // Identification headers the program asks for (X-… names only; never credentials, cookies or routing headers).
  "headers": {
    // "X-Bug-Bounty": "your-handle"
  }

  // Appended to the honest Exposure Desk User-Agent token, never a replacement:
  // ,"userAgentSuffix": "your-handle"

  // Analysis memory in MiB (64-2048). Only set this when the computer has the memory; the ready options stay at 512 or less.
  // ,"analysisMemoryMb": 1024

  // Live key check (2.9), off unless set. It lets you check, one key at a time, whether a credential you already found
  // during authorized testing is still active, by calling that provider's own read-only "who am I" endpoint. No scan ever
  // sends a key; it only happens on an explicit per-finding action you start. "enabled" allows per-finding checks for this
  // program; add "checkAll": true to also allow the paced "check all". Some programs forbid using found keys at all — read
  // the program rules first. See docs/LIVE_KEY_CHECK.md.
  // ,"liveKeyChecks": { "enabled": false, "checkAll": false }
}
`;
}
