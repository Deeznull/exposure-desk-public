import {createHash,randomBytes} from 'node:crypto';
import {mkdir,readFile,rename,writeFile} from 'node:fs/promises';
import path from 'node:path';
import {CliError} from '../cli/errors.js';
/** Run-state file for a resumable mass run (2.8, D2). One owner-only JSON file for a `--targets` list, written atomically (temp + rename) so a crash never leaves a
 * half-written state. It records, per target, the last known status and where its report landed, plus a hash of the target list and of the run settings so a resume
 * refuses the moment either changed. It never holds a finding, a key or a body — only counts, paths and run ids. */
export const MASSRUN_SCHEMA='exposure-massrun/1';
export type TargetStatus='pending'|'running'|'done'|'failed'|'blocked'|'cancelled';
export interface TargetState {index:number;url:string;status:TargetStatus;report?:string;runId?:string;findings?:number;exit?:number;stopReason?:string|null;
  /** This target's recon folder (`--recon`), so a resumed run can add its lists to the merged top-level set. */
  recon?:string}
export interface MassRunState {schema:string;listHash:string;settingsHash:string;createdAt:string;updatedAt:string;targets:TargetState[]}
const sha=(s:string)=>createHash('sha256').update(s).digest('hex');
/** Order-sensitive hash of the accepted target URLs: reordering or editing the list is a change and refuses a resume. */
export const listHash=(urls:string[])=>sha(urls.join('\n'));
/** Hash of everything that changes how a target is scanned or what it writes per target (coverage/traffic/scope/preset/sizing/browser/deep/format/fail-on/full-secrets/program/company-rules/recon folder/--config settings template). */
export const settingsHash=(settings:unknown)=>sha(JSON.stringify(settings));
/** A fresh state for a list, every target pending. */
export function newState(urls:string[],settings:unknown):MassRunState{
  const now=new Date().toISOString();
  return {schema:MASSRUN_SCHEMA,listHash:listHash(urls),settingsHash:settingsHash(settings),createdAt:now,updatedAt:now,targets:urls.map((url,index)=>({index,url,status:'pending' as TargetStatus}))};
}
/** Reads the state file; undefined when it does not exist yet (a first run that will create it). A wrong schema is a refusal (exit 2). */
export async function loadState(file:string):Promise<MassRunState|undefined>{
  let text:string;try{text=await readFile(file,'utf8');}catch(e:any){if(e?.code==='ENOENT')return undefined;throw new CliError('Run-state file could not be read: '+file);}
  let parsed:any;try{parsed=JSON.parse(text);}catch{throw new CliError('Run-state file is not valid JSON: '+file);}
  if(parsed?.schema!==MASSRUN_SCHEMA)throw new CliError(`Run-state file schema must be "${MASSRUN_SCHEMA}": ${file}`);
  return parsed as MassRunState;
}
/** Refuses (exit 2, one line) when the resumed state does not match the current list or settings. */
export function assertResumable(state:MassRunState,urls:string[],settings:unknown,file:string){
  if(state.listHash!==listHash(urls))throw new CliError(`Run-state file ${file} was written for a different target list; resume refused. Start a new run or restore the original list. Nothing was requested.`);
  if(state.settingsHash!==settingsHash(settings))throw new CliError(`Run-state file ${file} was written with different run settings; resume refused. Match the original settings or start a new run. Nothing was requested.`);
}
/** Atomic owner-only write (temp file in the same directory, then rename). */
export async function writeState(file:string,state:MassRunState){
  state.updatedAt=new Date().toISOString();
  const resolved=path.resolve(file),dir=path.dirname(resolved);
  await mkdir(dir,{recursive:true});
  const tmp=path.join(dir,`.${path.basename(resolved)}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`);
  await writeFile(tmp,JSON.stringify(state,null,2),{mode:0o600});
  await rename(tmp,resolved);
}
