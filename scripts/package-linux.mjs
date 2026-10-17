// Builds `artifacts/Exposure Desk <version> Linux x64.tar.gz`: the release files, the compiled application, its node_modules and the
// verified Linux distributions (Node.js in runtime/, Chrome for Testing in browser/, Gitleaks in tools/) fetched by scripts/fetch-linux-distributions.mjs.
// Linux x64 only (GNU tar). The Windows packager (scripts/package-portable.mjs) is separate and unchanged.
// Usage: node scripts/package-linux.mjs [--runtime DIR] [--browser DIR] --tools DIR [--summary FILE] [--replace] [--stage-only]
import {mkdir,readFile,writeFile,cp,readdir,lstat,readlink,chmod,rm,stat} from 'node:fs/promises';
import {createReadStream,existsSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {releaseFiles,excludedFromRelease} from './release-files.mjs';
if(process.platform!=='linux'||process.arch!=='x64')throw new Error('The Linux package is built on Linux x64.');
const root=fileURLToPath(new URL('../',import.meta.url));
const arg=(name,fallback)=>{const i=process.argv.indexOf(name);return path.resolve(i>0&&process.argv[i+1]?process.argv[i+1]:fallback);};
const runtime=arg('--runtime',path.join(root,'runtime')),browser=arg('--browser',path.join(root,'browser')),tools=arg('--tools',path.join(root,'.cache','linux-tools')),summaryFile=arg('--summary',path.join(root,'.cache','linux-distributions.json'));
const pkg=JSON.parse(await readFile(path.join(root,'package.json'),'utf8')),pins=JSON.parse(await readFile(path.join(root,'scripts','linux-distributions.json'),'utf8'));
const fetched=JSON.parse(await readFile(summaryFile,'utf8'));
async function hash(file){const h=createHash('sha256');for await(const chunk of createReadStream(file))h.update(chunk);return h.digest('hex');}
const buildManifest=JSON.parse(await readFile(path.join(root,'BUILD_INFO.json'),'utf8'));for(const f of [...buildManifest.inputs,...buildManifest.compiled])if(await hash(path.join(root,f.path))!==f.sha256)throw new Error('Build parity mismatch: '+f.path+'; run the supplied build first.');
const {RULE_VERSION}=await import(pathToFileURL(path.join(root,'dist/src/detectors.js')).href);
// The distributions must be the verified ones this release pins.
const run=(cmd,args)=>spawnSync(cmd,args,{encoding:'utf8'});
const nodeVersion=run(path.join(runtime,'bin','node'),['--version']);if(nodeVersion.stdout?.trim()!=='v'+pins.node.version)throw new Error('Bundled runtime is not Node.js '+pins.node.version);
if(fetched.node?.version!==pins.node.version||fetched.chromium?.version!==pins.chromium.version||fetched.gitleaks?.version!==pins.gitleaks.version)throw new Error('The fetched distributions do not match scripts/linux-distributions.json');
const toolManifest=JSON.parse(await readFile(path.join(tools,'manifest.json'),'utf8'));if(await hash(path.join(tools,'gitleaks'))!==toolManifest.binarySha256||toolManifest.binarySha256!==fetched.gitleaks.binarySha256)throw new Error('Pinned detector integrity mismatch');
if(!existsSync(path.join(browser,'chrome-linux64','chrome')))throw new Error('Bundled browser missing: chrome-linux64/chrome');
const artifacts=path.join(root,'artifacts'),name=`Exposure Desk ${pkg.version} Linux x64`,out=path.join(artifacts,name);await mkdir(artifacts,{recursive:true});
if(existsSync(out)){if(!process.argv.includes('--replace'))throw new Error('Candidate already exists; pass --replace to rebuild it.');await rm(out,{recursive:true,force:true});}
await mkdir(out,{recursive:true});
for(const entry of releaseFiles)await cp(path.join(root,entry),path.join(out,entry),{recursive:true,filter:source=>!excludedFromRelease(source)});
// Links inside the distributions stay links (Node.js keeps npm as bin/npm -> ../lib/node_modules/npm/bin/npm-cli.js; node_modules/.bin holds links), so their relative imports still resolve.
// A worktree may join runtime, node_modules and browser to another checkout with a link; the folder itself is resolved first.
const copyTree=async(from,to)=>{const real=(await lstat(from)).isSymbolicLink()?path.resolve(path.dirname(from),await readlink(from)):from;await cp(real,to,{recursive:true,verbatimSymlinks:true,filter:source=>!['debug.log','First Run'].includes(path.basename(source))});};
await copyTree(runtime,path.join(out,'runtime'));await copyTree(path.join(root,'node_modules'),path.join(out,'node_modules'));await copyTree(browser,path.join(out,'browser'));
await mkdir(path.join(out,'tools'),{recursive:true});for(const f of ['gitleaks','LICENSE','manifest.json'])if(existsSync(path.join(tools,f)))await cp(path.join(tools,f),path.join(out,'tools',f));
await chmod(path.join(out,'Start Exposure Desk.sh'),0o755);await chmod(path.join(out,'tools','gitleaks'),0o755);
const status=(pkg.version.includes('-')?'release candidate':'release')+'; Linux x64 package built and smoke-tested on GitHub-hosted Ubuntu; other Linux distributions remain unverified';
const manifest={application:`Exposure Desk ${pkg.version}`,build:buildManifest.build,detectorRules:RULE_VERSION,platform:'linux-x64',status,node:fetched.node,gitleaks:{version:fetched.gitleaks.version,archive:fetched.gitleaks.archive,archiveSha256:fetched.gitleaks.archiveSha256,binarySha256:fetched.gitleaks.binarySha256,source:fetched.gitleaks.source},chromium:fetched.chromium,
  provenance:'Downloaded in CI from the official sources and verified against the publisher checksums where they exist and the pins in scripts/linux-distributions.json. Recorded file hashes establish package integrity, not publisher signature verification.',files:[]};
async function walk(dir){for(const entry of (await readdir(dir,{withFileTypes:true})).sort((a,b)=>a.name<b.name?-1:a.name>b.name?1:0)){if(dir===out&&['.cache','reports','artifacts'].includes(entry.name))continue;const file=path.join(dir,entry.name),rel=path.relative(out,file).split(path.sep).join('/');
  if(entry.isSymbolicLink()){const target=await readlink(file);const resolved=path.resolve(path.dirname(file),target);if(path.isAbsolute(target)||!resolved.startsWith(out+path.sep))throw new Error('A link leaves the package: '+rel+' -> '+target);manifest.files.push({path:rel,symlink:target});}
  else if(entry.isDirectory())await walk(file);
  else if(entry.isFile()&&entry.name!=='PACKAGE_MANIFEST.json'){const info=await stat(file);manifest.files.push({path:rel,bytes:info.size,sha256:await hash(file),...(info.mode&0o111?{executable:true}:{})});}}}
await walk(out);await writeFile(path.join(out,'PACKAGE_MANIFEST.json'),JSON.stringify(manifest,null,2));
if(process.argv.includes('--stage-only')){console.log(JSON.stringify({package:'Linux x64',staged:out,files:manifest.files.length}));process.exit(0);}
// A reproducible archive: sorted names, numeric root ownership, the commit time as every timestamp, and gzip without a name or time stamp.
const tarball=path.join(artifacts,name+'.tar.gz'),epoch=process.env.SOURCE_DATE_EPOCH||String(Math.floor(Date.now()/1000));
const packed=spawnSync('tar',['--sort=name','--owner=0','--group=0','--numeric-owner','--mtime=@'+epoch,'--use-compress-program=gzip -n -9','-cf',tarball,'-C',artifacts,'--exclude',name+'/.cache','--exclude',name+'/reports','--exclude',name+'/artifacts',name],{stdio:'inherit'});
if(packed.status!==0)throw new Error('tar.gz creation failed');
const sha256=await hash(tarball);await writeFile(tarball+'.sha256',`${sha256}  ${path.basename(tarball)}\n`);
console.log(JSON.stringify({package:'Linux x64',path:tarball,files:manifest.files.length,bytes:(await stat(tarball)).size,sha256}));
