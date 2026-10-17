import { chmod, lstat, mkdir, readFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import path from 'node:path';
import { sensitiveWrite } from '../local-files.js';
import { restrictWindows } from '../permissions.js';
import { CliError } from './errors.js';
/** DIR/.key (32 random bytes) keys every findingId, so one exposure keeps its id across targets and runs. Created and re-checked like the other local secret
 * files: a regular single-link file, owner-only (Windows ACL or 0600). Program settings (program.json) are not read here. */
export async function programKey(dir:string):Promise<Buffer>{
  const file=path.join(path.resolve(dir),'.key');await mkdir(path.dirname(file),{recursive:true});
  try{const key=randomBytes(32);await sensitiveWrite(file,key);return key;}catch(e:any){if(e?.code!=='EEXIST')throw e;}
  const st=await lstat(file);if(!st.isFile()||st.nlink!==1)throw new CliError('Program key must be a regular file without links: '+file);
  const key=await readFile(file);if(key.length!==32)throw new CliError('Program key is invalid (expected 32 bytes): '+file);
  if(process.platform==='win32')restrictWindows(file,false);else await chmod(file,0o600);
  return key;
}
