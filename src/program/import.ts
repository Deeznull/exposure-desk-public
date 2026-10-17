import {lstat,readFile,writeFile,mkdir} from 'node:fs/promises';
import path from 'node:path';
import {CliError} from '../cli/errors.js';
import {protectedHost} from '../protected-hosts.js';
import {PROGRAM_FILE,PROGRAM_SCHEMA,programFromJson,stripJsonComments} from './settings.js';
import {RuleError,parseRule,ruleHost} from './rules.js';
/** Offline scope import (2.8): a HackerOne scope CSV export, or one program from the bounty-targets-data JSON files (hackerone_data.json, bugcrowd_data.json,
 * intigriti_data.json, yeswehack_data.json). Files only: nothing is fetched. Web assets (URL, wildcard, domain) and IP/CIDR assets become rules; other asset types
 * are skipped with a reason. Out-of-scope or ineligible assets go to scope.out. Protected hosts are listed and refused. Import never sets "authorized". */
export const IMPORT_PLATFORMS=['hackerone-csv','bounty-targets'] as const;
export type ImportPlatform=typeof IMPORT_PLATFORMS[number];
export const MAX_IMPORT_BYTES=256*1024*1024;
export interface ImportSkip {asset:string;type:string;reason:string}
export interface ImportResult {name?:string;platform?:string;source:string;in:string[];out:string[];skipped:ImportSkip[];protected:{asset:string;host:string}[]}
const fail=(message:string):never=>{throw new CliError(message);};
const WEB_TYPES=new Set(['url','wildcard','domain','website','web','web-application','webapp','api','other-web']);
const IP_TYPES=new Set(['cidr','ip_address','ip-address','iprange','ip-range','ip']);
/** Printable, single-line and bounded: imported text only ever appears in comments and messages. */
const clean=(s:unknown,max=200)=>String(s??'').replace(/[\x00-\x1f\x7f]+/g,' ').replace(/\*\//g,'* /').trim().slice(0,max);
/** Splits one identifier into candidate rules: lists separated by commas or whitespace, with surrounding quotes, parentheses and angle brackets removed. */
function candidates(identifier:string){return identifier.split(/[,\s]+/).map(p=>p.replace(/^[("'<]+|[)"'>;]+$/g,'')).filter(Boolean);}
class Collector{
  readonly result:ImportResult;private seenIn=new Set<string>();private seenOut=new Set<string>();
  constructor(source:string,name?:string,platform?:string){this.result={source,in:[],out:[],skipped:[],protected:[],...(name?{name}:{}),...(platform?{platform}:{})};}
  add(identifier:unknown,type:unknown,inScope:boolean){
    const asset=clean(identifier,500),kind=clean(type,60).toLowerCase();
    if(!asset){this.result.skipped.push({asset:'(empty)',type:kind||'unknown',reason:'no identifier'});return;}
    if(!WEB_TYPES.has(kind)&&!IP_TYPES.has(kind)){this.result.skipped.push({asset:clean(asset),type:kind||'unknown',reason:`asset type ${kind||'unknown'} is not a website, URL, wildcard, IP address or CIDR`});return;}
    const parts=candidates(asset);
    for(const part of parts){
      let rule;try{rule=parseRule(part,inScope);}catch(e){if(!(e instanceof RuleError))throw e;this.result.skipped.push({asset:clean(part),type:kind,reason:e.message.replace(/^Scope rule "[^"]*": /,'')});continue;}
      const host=ruleHost(rule),match=host?protectedHost(host):undefined;
      // Hard rule: a protected host is never put in scope (excluding it is harmless and kept).
      if(inScope&&match){this.result.protected.push({asset:clean(part),host:match.host});continue;}
      const list=inScope?this.result.in:this.result.out,seen=inScope?this.seenIn:this.seenOut;
      if(!seen.has(rule.raw)){seen.add(rule.raw);list.push(rule.raw);}
    }
  }
}
/** RFC 4180 CSV (quoted fields, doubled quotes, CRLF or LF). */
export function parseCsv(text:string):string[][]{
  const rows:string[][]=[];let row:string[]=[],field='',i=0,quoted=false;
  const src=text.charCodeAt(0)===0xFEFF?text.slice(1):text;
  while(i<src.length){
    const c=src[i]!;
    if(quoted){if(c==='"'){if(src[i+1]==='"'){field+='"';i+=2;continue;}quoted=false;i++;continue;}field+=c;i++;continue;}
    if(c==='"'&&field===''){quoted=true;i++;continue;}
    if(c===','){row.push(field);field='';i++;continue;}
    if(c==='\r'||c==='\n'){row.push(field);field='';rows.push(row);row=[];i+=c==='\r'&&src[i+1]==='\n'?2:1;continue;}
    field+=c;i++;
  }
  if(quoted)fail('The CSV file has an unterminated quoted field');
  if(field!==''||row.length){row.push(field);rows.push(row);}
  return rows.filter(r=>r.some(f=>f.trim()));
}
const truthy=(v:unknown)=>v===true||typeof v==='string'&&/^(?:true|yes|1)$/i.test(v.trim());
const falsy=(v:unknown)=>v===false||typeof v==='string'&&/^(?:false|no|0)$/i.test(v.trim());
/** HackerOne scope CSV export (identifier, asset_type, eligible_for_submission, …). Rows not eligible for submission are out of scope. */
export function importHackerOneCsv(text:string,source:string,name?:string):ImportResult{
  const rows=parseCsv(text);if(!rows.length)fail(`${source} is empty`);
  const header=rows[0]!.map(h=>h.trim().toLowerCase()),col=(n:string)=>header.indexOf(n);
  const id=col('identifier'),type=col('asset_type'),eligible=col('eligible_for_submission');
  if(id<0||type<0)fail(`${source} is not a HackerOne scope CSV export (it needs identifier and asset_type columns)`);
  const c=new Collector(source,name,'hackerone');
  for(const row of rows.slice(1)){const inScope=!(eligible>=0&&falsy(row[eligible]));c.add(row[id],row[type],inScope);}
  return c.result;
}
type Entry=Record<string,unknown>;
const str=(v:unknown)=>typeof v==='string'?v:typeof v==='number'?String(v):undefined;
/** The platform a bounty-targets-data entry comes from, by its shape (or the file name). */
function platformOf(entry:Entry,file:string):string{
  const base=path.basename(file).toLowerCase();
  for(const p of ['hackerone','bugcrowd','intigriti','yeswehack','federacy'])if(base.startsWith(p))return p;
  if('company_handle' in entry)return 'intigriti';if('handle' in entry&&'offers_bounties' in entry)return 'hackerone';return 'bounty-targets';
}
/** Names an entry answers to: handle, id, name, company/handle (Intigriti) and the last path segment of its program URL; matched case-insensitively. */
function namesOf(e:Entry):string[]{
  const out=[str(e.handle),str(e.id),str(e.name),str(e.slug),str(e.code)];
  if(str(e.company_handle)&&str(e.handle))out.push(`${str(e.company_handle)}/${str(e.handle)}`);
  const url=str(e.url)||str(e.program_url);if(url){try{const seg=new URL(url).pathname.split('/').filter(Boolean);if(seg.length)out.push(seg[seg.length-1]!);}catch{}}
  return out.filter((v):v is string=>!!v).map(v=>v.trim().toLowerCase());
}
function assetsOf(e:Entry,which:'in_scope'|'out_of_scope'):Entry[]{const t=e.targets;if(!t||typeof t!=='object')return [];const list=(t as Entry)[which];return Array.isArray(list)?list.filter((x):x is Entry=>!!x&&typeof x==='object'):[];}
/** One program from a bounty-targets-data JSON file, chosen by --handle (handle, id, name, or the program URL's last segment). */
export function importBountyTargets(text:string,source:string,handle:string|undefined):ImportResult{
  let data:unknown;try{data=JSON.parse(text.charCodeAt(0)===0xFEFF?text.slice(1):text);}catch{return fail(`${source} is not valid JSON`);}
  const programs=(Array.isArray(data)?data:[data]).filter((x):x is Entry=>!!x&&typeof x==='object'&&!Array.isArray(x));
  if(!programs.length||!programs.some(p=>p.targets&&typeof p.targets==='object'))fail(`${source} is not a bounty-targets-data file (expected a list of programs with targets.in_scope)`);
  let chosen:Entry;
  if(handle===undefined){if(programs.length!==1)fail(`${source} lists ${programs.length} programs; choose one with --handle NAME`);chosen=programs[0]!;}
  else{const want=handle.trim().toLowerCase(),hits=programs.filter(p=>namesOf(p).includes(want));
    if(!hits.length)fail(`No program named ${clean(handle,100)} in ${source}`);
    if(hits.length>1)fail(`${hits.length} programs in ${source} match ${clean(handle,100)}; use a more specific handle`);chosen=hits[0]!;}
  const c=new Collector(source,clean(str(chosen.name)||str(chosen.handle)||handle,100)||undefined,platformOf(chosen,source));
  const add=(a:Entry,inScope:boolean)=>{
    const type=str(a.asset_type)??str(a.type)??'',ids=[str(a.asset_identifier),str(a.endpoint),str(a.target),str(a.uri)].filter((v):v is string=>!!v&&!!v.trim());
    // HackerOne marks some in-scope rows as not eligible for submission: those are out of scope for testing.
    const scope=inScope&&!falsy(a.eligible_for_submission);
    if(!ids.length){c.add('',type,scope);return;}
    // Bugcrowd and YesWeHack sometimes describe a target in words and give the address in uri: the first identifier that yields a rule wins.
    // When none does, the asset is reported once, with the skip reasons of its first identifier.
    const r=c.result,before=r.skipped.length,count=()=>r.in.length+r.out.length+r.protected.length,start=count();let firstSkips:ImportSkip[]|undefined;
    for(const id of ids){c.add(id,type,scope);const skips=r.skipped.splice(before);firstSkips??=skips;if(count()>start){r.skipped.push(...skips);return;}}
    r.skipped.push(...firstSkips!);
  };
  for(const a of assetsOf(chosen,'in_scope'))add(a,true);
  for(const a of assetsOf(chosen,'out_of_scope'))add(a,false);
  return c.result;
}
/** Reads the import file (a regular file, bounded) and returns the parsed scope. */
export async function readImport(platform:string,file:string,handle?:string):Promise<ImportResult>{
  if(!(IMPORT_PLATFORMS as readonly string[]).includes(platform))fail(`Unknown --platform value (use ${IMPORT_PLATFORMS.join(' or ')})`);
  let st;try{st=await lstat(file);}catch{return fail('Import file could not be read: '+file);}
  if(!st.isFile())fail('Import file must be a regular file: '+file);
  if(st.size>MAX_IMPORT_BYTES)fail(`Import file is larger than ${MAX_IMPORT_BYTES/1048576} MiB: ${file}`);
  const text=await readFile(file,'utf8'),source=path.basename(file);
  if(platform==='hackerone-csv'){if(handle!==undefined)fail('--handle applies to bounty-targets files; a HackerOne CSV export holds one program');return importHackerOneCsv(text,source,undefined);}
  return importBountyTargets(text,source,handle);
}
/** program.json text for an import: authorized stays false, and every skipped or refused asset is listed in a comment. */
export function importedProgramText(r:ImportResult,name?:string):string{
  const lines=[`// Exposure Desk program settings (${PROGRAM_SCHEMA}), imported offline from ${clean(r.source,100)}. See docs/PROGRAM.md.`,
    '// Review the scope against the program page, then set "authorized" to true only if the program authorizes testing these assets.',
    `// Imported: ${r.in.length} in-scope and ${r.out.length} out-of-scope rules; ${r.skipped.length} assets skipped; ${r.protected.length} protected hosts refused.`];
  for(const p of r.protected.slice(0,100))lines.push(`// Refused (never scanned: government, military, intelligence or law-enforcement): ${p.asset}`);
  for(const s of r.skipped.slice(0,200))lines.push(`// Skipped ${s.type}: ${clean(s.asset,120)} (${clean(s.reason,160)})`);
  if(r.skipped.length>200)lines.push(`// … and ${r.skipped.length-200} more skipped assets`);
  const body:Record<string,unknown>={schema:PROGRAM_SCHEMA,...(name??r.name?{name:clean(name??r.name,100)}:{}),...(r.platform?{platform:r.platform}:{}),authorized:false,scope:{in:r.in,out:r.out},rate:{requestsPerSecond:5},concurrency:{targets:4,requests:16},headers:{}};
  return lines.join('\n')+'\n'+JSON.stringify(body,null,2)+'\n';
}
/** Writes DIR/program.json from an import; refuses to replace an existing file. The written file is validated like any program file first. */
export async function writeImportedProgram(dir:string,r:ImportResult):Promise<string>{
  if(!r.in.length)fail(`Nothing to import: ${r.source} has no in-scope web or IP asset that can become a rule (${r.skipped.length} skipped, ${r.protected.length} protected). No file was written.`);
  const text=importedProgramText(r);programFromJson(JSON.parse(stripJsonComments(text)),dir);
  const file=path.join(path.resolve(dir),PROGRAM_FILE);await mkdir(path.dirname(file),{recursive:true});
  try{await writeFile(file,text,{flag:'wx',mode:0o600});}catch(e:any){if(e?.code==='EEXIST')fail(`${file} already exists; remove it or import into another folder. Nothing was changed.`);throw e;}
  return file;
}
