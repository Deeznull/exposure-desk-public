// Checks the Linux x64 package downloaded from the draft GitHub Release that linux.yml attaches it to (workflow_dispatch with release_tag),
// and gives it back its package name so `sha256sum --check` and `release-summary.mjs --after-package` find it.
// The release assets have fixed names (exposure-desk-linux-x64.tar.gz and .sha256) because GitHub rewrites spaces in asset names;
// the .sha256 file keeps the line written by scripts/package-linux.mjs, which names the package.
// Usage: gh release download vX.Y.Z --pattern '*.tar.gz*' --dir artifacts
//        node scripts/linux-release-assets.mjs [--dir artifacts] [--version X.Y.Z | --any-version]
// --version defaults to package.json's version. Nothing is deleted: the two files are renamed only after the hash matches.
import {readFile,rename,stat} from 'node:fs/promises';
import {createReadStream,existsSync} from 'node:fs';
import {createHash} from 'node:crypto';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

export const assetName='exposure-desk-linux-x64.tar.gz';
const PACKAGE=/^Exposure Desk (\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?) Linux x64\.tar\.gz$/;

/** Parses a .sha256 line written by package-linux.mjs: 64 hex digits, two spaces (or ' *'), the package name. Anything else is refused. */
export function parseChecksumLine(content){
  const lines=String(content).replace(/\r/g,'').split('\n').filter(l=>l!=='');
  if(lines.length!==1)throw new Error('The .sha256 file must hold exactly one line');
  const m=/^([0-9a-f]{64}) [ *](.+)$/.exec(lines[0]);if(!m)throw new Error('The .sha256 file is not a SHA-256 checksum line');
  const v=PACKAGE.exec(m[2]);if(!v)throw new Error('The .sha256 file does not name an Exposure Desk Linux x64 package: '+JSON.stringify(m[2]));
  return {sha256:m[1],name:m[2],version:v[1]};
}

async function sha256(file){const h=createHash('sha256');for await(const chunk of createReadStream(file))h.update(chunk);return h.digest('hex');}

/** Verifies the downloaded assets in dir and renames them to the package name. Returns {name,version,bytes,sha256,renamed}. */
export async function restoreLinuxReleaseAssets(dir,{version}={}){
  const tar=path.join(dir,assetName),sidecar=tar+'.sha256';
  for(const f of [tar,sidecar])if(!existsSync(f))throw new Error('Missing '+f+' (download it with gh release download <tag> --pattern \'*.tar.gz*\' --dir '+dir+')');
  const expected=parseChecksumLine(await readFile(sidecar,'utf8'));
  if(version&&expected.version!==version)throw new Error(`The release assets hold version ${expected.version}, expected ${version}`);
  const actual=await sha256(tar);if(actual!==expected.sha256)throw new Error(`${tar} does not match its .sha256 file (${actual} != ${expected.sha256})`);
  const target=path.join(dir,expected.name),targetSidecar=target+'.sha256';
  // Never replace a different file that already carries the package name.
  if(existsSync(target)&&await sha256(target)!==actual)throw new Error(target+' already exists with different content; move it away first');
  if(existsSync(targetSidecar)&&(await readFile(targetSidecar,'utf8'))!==(await readFile(sidecar,'utf8')))throw new Error(targetSidecar+' already exists with different content; move it away first');
  await rename(tar,target);await rename(sidecar,targetSidecar);
  return {name:expected.name,version:expected.version,bytes:(await stat(target)).size,sha256:actual,checksumFileMatches:true,renamed:{[assetName]:expected.name,[assetName+'.sha256']:expected.name+'.sha256'}};
}

if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  const args=process.argv.slice(2),value=flag=>{const i=args.indexOf(flag);return i<0?undefined:args[i+1];};
  const root=path.dirname(path.dirname(fileURLToPath(import.meta.url)));
  const dir=path.resolve(value('--dir')??path.join(root,'artifacts'));
  const version=args.includes('--any-version')?undefined:value('--version')??JSON.parse(await readFile(path.join(root,'package.json'),'utf8')).version;
  try{console.log(JSON.stringify(await restoreLinuxReleaseAssets(dir,{version})));}
  catch(error){console.error(error.message);process.exitCode=1;}
}
