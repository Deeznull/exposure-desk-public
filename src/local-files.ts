import { spawnSync } from 'node:child_process';
import { mkdir, mkdtemp, chmod, writeFile, readdir, readFile, lstat, rm } from 'node:fs/promises';
import path from 'node:path';
import { root } from './detectors.js';
import { restrictWindows } from './permissions.js';
import { dataLocation } from './storage.js';
export const privateParent=(syntheticFixture=false)=>process.env.EXPOSURE_DATA_DIR?path.join(process.env.EXPOSURE_DATA_DIR,'tmp'):syntheticFixture?path.join(root,'.cache','private'):path.join(dataLocation(),'tmp');
export async function privateDirectory(prefix='session-',syntheticFixture=false){
  const parent=privateParent(syntheticFixture);await mkdir(parent,{recursive:true,mode:0o700});
  const dir=await mkdtemp(path.join(parent,prefix));await chmod(dir,0o700);
  if(process.platform==='win32'&&!syntheticFixture){
    restrictWindows(dir,true);
  }
  return dir;
}
/** Each fresh browser profile carries a marker naming the owning scanner process, so a later start can sweep profiles left by a crash. */
export const PROFILE_MARKER='.exposure-desk-profile.json';
export async function writeProfileMarker(dir:string){await writeFile(path.join(dir,PROFILE_MARKER),JSON.stringify({schema:'exposure-browser-profile/1',ownerPid:process.pid,createdAt:new Date().toISOString()}),{mode:0o600,flag:'wx'});}
const alive=(pid:unknown)=>{if(!Number.isInteger(pid)||(pid as number)<=0)return false;try{process.kill(pid as number,0);return true;}catch(e:any){return e?.code==='EPERM';}};
/** Remove orphaned `browser-*` profiles: the owning process is gone, or the profile is older than 24 hours (unmarked pre-2.5 profiles only by age). Links and other names are never touched. */
export async function sweepStaleProfiles(parents:string[],now=Date.now()){let removed=0,kept=0;for(const parent of new Set(parents.map(p=>path.resolve(p)))){let names:string[]=[];try{names=await readdir(parent);}catch{continue;}for(const name of names){if(!/^browser-[A-Za-z0-9]{6}$/.test(name))continue;const dir=path.join(parent,name);try{const st=await lstat(dir);if(!st.isDirectory()||st.isSymbolicLink()){kept++;continue;}let marker:any;try{marker=JSON.parse(await readFile(path.join(dir,PROFILE_MARKER),'utf8'));}catch{}const created=Date.parse(marker?.createdAt||'')||st.mtimeMs,old=now-created>24*3600000;if(!old&&(!marker||alive(marker.ownerPid))){kept++;continue;}await rm(dir,{recursive:true,force:true,maxRetries:3,retryDelay:100});removed++;}catch{kept++;}}}return {removed,kept};}
export async function sensitiveWrite(file:string,data:string|Uint8Array,syntheticFixture=false){
  await writeFile(file,'',{mode:0o600,flag:'wx'});
  if(process.platform==='win32'&&!syntheticFixture){
    try{restrictWindows(file,false);}catch{const {rm}=await import('node:fs/promises');await rm(file,{force:true});throw new Error('Cannot restrict export ACL');}
  }
  await writeFile(file,data,{mode:0o600});
}
