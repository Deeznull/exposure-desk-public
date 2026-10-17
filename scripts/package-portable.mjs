import {mkdir,readFile,writeFile,cp,readdir,stat} from 'node:fs/promises';
import {createReadStream,existsSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {releaseFiles,excludedFromRelease} from './release-files.mjs';
const root=fileURLToPath(new URL('../',import.meta.url));
const pkg=JSON.parse(await readFile(path.join(root,'package.json'),'utf8'));
if(process.platform!=='win32'||process.arch!=='x64')throw new Error('Portable builder requires Windows x64 and the supplied pinned distributions.');
const artifacts=path.join(root,'artifacts');await mkdir(artifacts,{recursive:true});
const common=releaseFiles;const {RULE_VERSION}=await import(pathToFileURL(path.join(root,'dist/src/detectors.js')).href);
// Always the Windows tar (bsdtar): a GNU tar earlier on PATH (for example from Git Bash) cannot write these ZIPs.
const tar=path.join(process.env.SystemRoot||'C:\\Windows','System32','tar.exe');if(!existsSync(tar))throw new Error('System32 tar.exe is required to write the ZIPs');
const prior=JSON.parse(await readFile(path.join(root,'PACKAGE_MANIFEST.json'),'utf8'));
async function hash(file){const h=createHash('sha256');for await(const chunk of createReadStream(file))h.update(chunk);return h.digest('hex');}
const buildManifest=JSON.parse(await readFile(path.join(root,'BUILD_INFO.json'),'utf8'));for(const f of [...buildManifest.inputs,...buildManifest.compiled])if(await hash(path.join(root,f.path))!==f.sha256)throw new Error('Build parity mismatch: '+f.path+'; run the supplied build first.');
if(await hash(path.join(root,'tools/gitleaks.exe'))!==prior.gitleaks.binarySha256)throw new Error('Pinned detector integrity mismatch');
const nodeVersion=spawnSync(path.join(root,'runtime/node.exe'),['--version'],{encoding:'utf8',windowsHide:true});
if(nodeVersion.status!==0)throw new Error('Bundled runtime could not execute ('+(nodeVersion.error?.code||nodeVersion.status)+'); allow local child-process execution before packaging.');
if(nodeVersion.stdout.trim()!=='v24.18.1')throw new Error('Pinned runtime version mismatch');
for(const type of ['Source','Windows x64']){
 const name=`Exposure Desk ${pkg.version} ${type}`,out=path.join(artifacts,name);
 if(existsSync(out)&&!process.argv.includes('--refresh'))throw new Error('Candidate already exists; --refresh only updates its allowlisted release files.');
 await mkdir(out,{recursive:true});
 for(const entry of common)await cp(path.join(root,entry),path.join(out,entry),{recursive:true,filter:source=>!excludedFromRelease(source)});
 // The supplied distributions are copied as files even when the project links to them (a git worktree joins runtime, node_modules and browser to the main checkout with junctions, which fs.cp would otherwise try to recreate as links).
 if(type==='Windows x64')for(const entry of ['runtime','node_modules','tools','browser'])if(!process.argv.includes('--refresh'))await cp(path.join(root,entry),path.join(out,entry),{recursive:true,dereference:true,filter:source=>!['debug.log','First Run'].includes(path.basename(source))});
 const manifest={application:`Exposure Desk ${pkg.version}`,build:buildManifest.build,detectorRules:RULE_VERSION,platform:type==='Source'?'source':'win32-x64',status:(pkg.version.includes('-')?'release candidate':'release')+'; Linux and broader Windows policy environments remain unverified',node:prior.node,gitleaks:prior.gitleaks,chromium:prior.chromium,provenance:'Reused supplied distributions. Recorded file hashes establish package integrity, not publisher signature verification.',files:[]};
 async function walk(dir){for(const entry of (await readdir(dir,{withFileTypes:true})).sort((a,b)=>a.name.localeCompare(b.name))){if(dir===out&&['.cache','reports','artifacts'].includes(entry.name))continue;const file=path.join(dir,entry.name);if(entry.isDirectory())await walk(file);else if(entry.name!=='PACKAGE_MANIFEST.json')manifest.files.push({path:path.relative(out,file).replaceAll('\\','/'),bytes:(await stat(file)).size,sha256:await hash(file)});}}
 await walk(out);await writeFile(path.join(out,'PACKAGE_MANIFEST.json'),JSON.stringify(manifest,null,2));
 if(process.argv.includes('--stage-only')){console.log(JSON.stringify({package:type,staged:out,files:manifest.files.length}));continue;}
 const zip=path.join(artifacts,name+'.zip');
 const result=spawnSync(tar,['-a','-cf',zip,'-C',artifacts,'--exclude',name+'/.cache','--exclude',name+'/reports','--exclude',name+'/artifacts',name],{stdio:'inherit',windowsHide:true});if(result.status!==0)throw new Error('ZIP creation failed');
 console.log(JSON.stringify({package:type,path:zip,files:manifest.files.length,bytes:(await stat(zip)).size,sha256:await hash(zip)}));
}
