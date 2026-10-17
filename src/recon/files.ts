/**
 * Local output for recon lists and rebuilt sources. The output directory is never a symbolic link or junction; it is protected once
 * (Windows: owner-only DACL with inheritance through src/permissions.ts restrictWindows; elsewhere 0700) so every file created inside
 * inherits that protection, and files are created exclusively (`wx`, 0600) so an existing file or link is never followed or overwritten.
 */
import { randomBytes } from 'node:crypto';
import { chmod, lstat, mkdir, open, readdir, realpath, rename, rm } from 'node:fs/promises';
import path from 'node:path';
import { restrictWindows } from '../permissions.js';
import { ReconOutputError } from './types.js';
export interface OutputOptions {
  /** Refuse a directory that already has entries (the source-map rebuild needs a fresh tree). */
  requireEmpty?:boolean;
  /** Apply owner-only protection to the directory (default true). Tests with synthetic data may turn it off. */
  protect?:boolean;
}
const code=(e:unknown)=>(e as NodeJS.ErrnoException)?.code;
/** Create or check the output directory and return its resolved real path. */
export async function prepareOutputDir(dir:string,options:OutputOptions={}):Promise<string>{
  if(typeof dir!=='string'||!dir||dir.includes('\u0000'))throw new ReconOutputError('unsafe-output','The output folder name is not valid.');
  const resolved=path.resolve(dir);
  let st=await lstat(resolved).catch(e=>{if(code(e)==='ENOENT')return undefined;throw new ReconOutputError('unsafe-output','The output folder cannot be checked.');});
  if(!st){
    try{await mkdir(resolved,{recursive:true,mode:0o700});}catch{throw new ReconOutputError('write-failed','The output folder cannot be created.');}
    st=await lstat(resolved);
  }
  if(st.isSymbolicLink())throw new ReconOutputError('unsafe-output','The output folder is a symbolic link or junction; choose a plain folder.');
  if(!st.isDirectory())throw new ReconOutputError('output-not-directory','The output path exists and is not a folder.');
  if(options.requireEmpty&&(await readdir(resolved)).length)throw new ReconOutputError('output-not-empty','The output folder must be new or empty.');
  if(options.protect!==false){
    try{if(process.platform==='win32')restrictWindows(resolved,true);else await chmod(resolved,0o700);}
    catch{throw new ReconOutputError('unsafe-output','The output folder cannot be restricted to the current user; choose a folder you own on a local drive.');}
  }
  return await realpath(resolved);
}
/** Create `file` exclusively (never following or replacing anything) and write `data`. */
export async function writeNew(file:string,data:string|Uint8Array){
  const handle=await open(path.toNamespacedPath(file),'wx',0o600);
  try{await handle.writeFile(data);}catch(e){await handle.close().catch(()=>{});await rm(path.toNamespacedPath(file),{force:true}).catch(()=>{});throw e;}
  await handle.close();
}
/** Replace `name` inside `dir` atomically: written to a fresh exclusive temporary file, then renamed over the target (a link at the target is replaced, never followed). */
export async function replaceFile(dir:string,name:string,data:string){
  if(name.includes('/')||name.includes('\\')||name.startsWith('.'))throw new ReconOutputError('unsafe-output','Invalid output file name.');
  const tmp=path.join(dir,`.${name}.${randomBytes(6).toString('hex')}.tmp`);
  await writeNew(tmp,data);
  try{await rename(path.toNamespacedPath(tmp),path.toNamespacedPath(path.join(dir,name)));}catch(e){await rm(path.toNamespacedPath(tmp),{force:true}).catch(()=>{});throw new ReconOutputError('write-failed',`Cannot write ${name}.`);}
}
