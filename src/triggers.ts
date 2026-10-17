import { readdir, readFile, lstat, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
/** Deployment trigger requests are files dropped into the operator-only data directory by the CLI; there is no listener, token or callback.
 * A trigger can only ask for a scan of an opted-in saved project, optionally replaying exact asset URLs; it never grants scope, budgets or evidence saving. */
export const TRIGGER_SCHEMA='exposure-trigger/1';
export const TRIGGER_MAX_BYTES=65536;
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
export interface TriggerRequest {schema:string;id:string;projectId:string;label?:string;assets?:string[];createdAt:string;notBefore:string;expiresAt:string}
export function makeTrigger(input:{projectId:string;label?:string;assets?:string[];delaySeconds?:number},now=Date.now()):TriggerRequest{
  if(!UUID.test(input.projectId))throw new Error('A saved project id is required');
  if(input.label!==undefined&&(typeof input.label!=='string'||input.label.length>80||/[\u0000-\u001f]/.test(input.label)))throw new Error('Labels are limited to 80 printable characters');
  const assets=input.assets||[];if(!Array.isArray(assets)||assets.length>200||assets.some(a=>typeof a!=='string'||a.length>4096||!/^https?:\/\//i.test(a)))throw new Error('At most 200 absolute HTTP(S) asset URLs');
  const delay=input.delaySeconds??0;if(!Number.isInteger(delay)||delay<0||delay>3600)throw new Error('Delay must be 0–3600 seconds');
  return {schema:TRIGGER_SCHEMA,id:randomUUID(),projectId:input.projectId,...(input.label?{label:input.label}:{}),...(assets.length?{assets}:{}),createdAt:new Date(now).toISOString(),notBefore:new Date(now+delay*1000).toISOString(),expiresAt:new Date(now+24*3600000).toISOString()};
}
export async function writeTrigger(dir:string,trigger:TriggerRequest){const text=JSON.stringify(trigger);if(Buffer.byteLength(text)>TRIGGER_MAX_BYTES)throw new Error('Trigger exceeds 64 KiB');await writeFile(path.join(dir,trigger.id+'.json'),text,{flag:'wx',mode:0o600});return trigger;}
/** Read pending trigger files once: links, hard links, foreign owners, oversized and malformed files are rejected and removed; expired files are removed and reported; files not yet due stay for a later tick. Unknown names are never touched. */
export async function readTriggers(dir:string,now=Date.now()){
  const accepted:TriggerRequest[]=[],expired:TriggerRequest[]=[],rejected:{file:string;reason:string}[]=[];let names:string[]=[];try{names=await readdir(dir);}catch{return {accepted,expired,rejected};}
  for(const name of names.filter(n=>/^[a-f0-9-]{36}\.json$/.test(n)).slice(0,50)){
    const file=path.join(dir,name),drop=async(reason:string)=>{rejected.push({file:name,reason});await rm(file,{force:true}).catch(()=>{});};
    let st;try{st=await lstat(file);}catch{continue;}
    if(st.isSymbolicLink()||!st.isFile()||st.nlink!==1){await drop('not a regular, singly linked file');continue;}
    if(process.platform!=='win32'&&st.uid!==process.getuid?.()){await drop('not owned by the operator');continue;}
    if(st.size>TRIGGER_MAX_BYTES){await drop('larger than 64 KiB');continue;}
    let t:TriggerRequest;try{t=JSON.parse(await readFile(file,'utf8'));}catch{await drop('unreadable JSON');continue;}
    if(!t||t.schema!==TRIGGER_SCHEMA||t.id+'.json'!==name||!UUID.test(String(t.projectId))||![t.createdAt,t.notBefore,t.expiresAt].every(d=>Number.isFinite(Date.parse(d)))||Date.parse(t.expiresAt)-Date.parse(t.createdAt)>24*3600000+60000||(t.assets!==undefined&&(!Array.isArray(t.assets)||t.assets.length>200||t.assets.some(a=>typeof a!=='string'||!/^https?:\/\//i.test(a))))||(t.label!==undefined&&(typeof t.label!=='string'||t.label.length>80))){await drop('invalid trigger fields');continue;}
    if(Date.parse(t.expiresAt)<now){expired.push(t);await rm(file,{force:true}).catch(()=>{});continue;}
    if(Date.parse(t.notBefore)>now)continue;
    await rm(file,{force:true});accepted.push(t);
  }
  return {accepted,expired,rejected};
}
