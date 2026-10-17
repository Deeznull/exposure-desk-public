import { spawnSync } from 'node:child_process';
import { readFileSync,lstatSync } from 'node:fs';
import path from 'node:path';
import { applicationRoot } from './runtime-paths.js';
export function restrictWindows(target:string,directory:boolean){
  restrictWindowsBatch([{target,directory}]);
}
export function restrictWindowsBatch(targets:{target:string;directory:boolean}[]){
  if(process.platform!=='win32')return;
  for(const {target,directory}of targets){const stat=lstatSync(target);if(stat.isSymbolicLink()||(!directory&&stat.nlink!==1))throw new Error('Protected application files cannot be symbolic or hard links');}
  // Replace the DACL, rather than keeping potentially broad explicit grants.
  const script=readFileSync(path.join(applicationRoot,'src','windows-acl.ps1'),'utf8');
  for(let offset=0;offset<targets.length;offset+=16){
  const env:NodeJS.ProcessEnv={...process.env,EXPOSURE_ACL_TARGETS:JSON.stringify(targets.slice(offset,offset+16))};for(const key of Object.keys(env))if(['psmodulepath','psmoduleanalysiscachepath'].includes(key.toLowerCase()))delete env[key];
  // PowerShell 7's inherited module path can make Windows PowerShell 5 load incompatible modules.
  const r=spawnSync('powershell.exe',['-NoProfile','-NonInteractive','-Command',script],{encoding:'utf8',windowsHide:true,env});
  if(r.status!==0){const detail=r.stderr?.includes('OWNER_MISMATCH')?'owner-mismatch':r.stderr?.includes('ACL_UNPROTECTED')?'inheritance-not-protected':r.stderr?.includes('ACL_BROAD')?'unexpected-grant':(r.error as NodeJS.ErrnoException)?.code||'acl-application';throw new Error('Windows protected storage check failed ('+detail+'). '+(r.error?'PowerShell helper could not start; check application execution policy.':detail==='owner-mismatch'?'Choose a new operator-owned Exposure Desk folder; preserve existing data for authorized migration.':'Use an app-owned directory on a local NTFS volume; check controlled folder access or enterprise policy. Routine administrator access is not required.'));}
  }
}
