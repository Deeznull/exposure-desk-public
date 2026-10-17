// Downloads the third-party distributions of the Linux x64 package from their official sources and verifies every archive before it is unpacked:
//   Node.js     nodejs.org, checked against the release's SHASUMS256.txt and the pin in scripts/linux-distributions.json
//   Gitleaks    github.com/gitleaks, checked against the release's checksums file and the pin
//   Chromium    Chrome for Testing (the build Playwright uses), checked against the pin; Google publishes no checksum, so before a pin exists the
//               official download and the Playwright CDN mirror must give the same bytes
// Used by the Linux CI workflow and the Docker build only (never on an operator's machine). Linux x64 only.
// Usage: node scripts/fetch-linux-distributions.mjs [--runtime DIR] [--browser DIR] [--tools DIR] [--summary FILE]
import {mkdir,writeFile,readFile,copyFile,chmod,rm,mkdtemp} from 'node:fs/promises';
import {createWriteStream,createReadStream,existsSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {Readable} from 'node:stream';
import {pipeline} from 'node:stream/promises';
import path from 'node:path';
import os from 'node:os';
import {fileURLToPath} from 'node:url';
if(process.platform!=='linux'||process.arch!=='x64')throw new Error('The Linux distributions are fetched on Linux x64 only.');
const root=fileURLToPath(new URL('../',import.meta.url));
const pins=JSON.parse(await readFile(path.join(root,'scripts','linux-distributions.json'),'utf8'));
const arg=name=>{const i=process.argv.indexOf(name);return i>0&&process.argv[i+1]?path.resolve(process.argv[i+1]):undefined;};
const targets={runtime:arg('--runtime'),browser:arg('--browser'),tools:arg('--tools')},summaryFile=arg('--summary')||path.join(root,'.cache','linux-distributions.json');
if(!targets.runtime&&!targets.browser&&!targets.tools)throw new Error('Name at least one of --runtime, --browser, --tools.');
const scratch=await mkdtemp(path.join(os.tmpdir(),'exposure-linux-dist-'));
const hex=/^[0-9a-f]{64}$/;
// Every download is HTTPS from an allowlisted official host, streamed to disk and hashed on the way.
const official=new Set(['nodejs.org','github.com','storage.googleapis.com','cdn.playwright.dev']);
// A failed connection or a server error is retried a few times (CI networks drop connections now and then); the bytes are still verified in full.
async function get(url){for(let attempt=1;;attempt++){try{const r=await fetch(url,{redirect:'follow',signal:AbortSignal.timeout(600000)});if(r.status<500||attempt===4)return r;await r.body?.cancel();}catch(e){if(attempt===4)throw e;console.error(`${url}: attempt ${attempt} failed (${e.cause?.code||e.message}); retrying`);}await new Promise(r=>setTimeout(r,5000*attempt));}}
async function download(url,name){const u=new URL(url);if(u.protocol!=='https:'||!official.has(u.hostname))throw new Error('Not an official source: '+url);
  const response=await get(url);if(!response.ok||!response.body)throw new Error(`Download failed (${response.status}): ${url}`);
  const file=path.join(scratch,name),hash=createHash('sha256');const body=Readable.fromWeb(response.body);body.on('data',chunk=>hash.update(chunk));
  await pipeline(body,createWriteStream(file,{mode:0o600}));return {file,sha256:hash.digest('hex')};}
async function text(url){const u=new URL(url);if(u.protocol!=='https:'||!official.has(u.hostname))throw new Error('Not an official source: '+url);const r=await get(url);if(!r.ok)throw new Error(`Download failed (${r.status}): ${url}`);return r.text();}
const listed=(sums,name)=>sums.split('\n').map(l=>l.trim().split(/\s+/)).find(([,file])=>file===name||file==='*'+name)?.[0]?.toLowerCase();
function pinned(label,observed,pin){if(pin==null){console.error(`${label}: no pin recorded yet; observed ${observed}`);return;}if(!hex.test(pin))throw new Error(label+': malformed pin');if(observed!==pin)throw new Error(`${label}: checksum ${observed} differs from the pin ${pin}`);}
function run(command,args){const r=spawnSync(command,args,{stdio:['ignore','pipe','pipe'],encoding:'utf8'});if(r.status!==0)throw new Error(`${command} ${args.join(' ')} failed: ${r.error?.message||r.stderr}`);return r.stdout;}
async function sha(file){const h=createHash('sha256');for await(const c of createReadStream(file))h.update(c);return h.digest('hex');}
const summary={platform:'linux-x64'};
try{
  if(targets.runtime){const p=pins.node,sums=await text(p.checksums),expected=listed(sums,p.archive);if(!expected)throw new Error('Node.js checksum list has no '+p.archive);
    const {file,sha256}=await download(p.source,p.archive);if(sha256!==expected)throw new Error(`Node.js archive checksum ${sha256} differs from SHASUMS256.txt ${expected}`);pinned('Node.js archive',sha256,p.archiveSha256);
    await rm(targets.runtime,{recursive:true,force:true});await mkdir(targets.runtime,{recursive:true});run('tar',['-xJf',file,'-C',targets.runtime,'--strip-components=1','--no-same-owner']);
    const version=run(path.join(targets.runtime,'bin','node'),['--version']).trim();if(version!=='v'+p.version)throw new Error('Unpacked Node.js reports '+version);
    summary.node={version:p.version,source:p.source,archiveSha256:sha256,checksumProvenance:'nodejs.org SHASUMS256.txt and the recorded pin'};}
  if(targets.browser){const p=pins.chromium,{file,sha256}=await download(p.source,'chrome-linux64.zip');
    if(p.archiveSha256==null){const mirror=await download(p.mirror,'chrome-linux64-mirror.zip');if(mirror.sha256!==sha256)throw new Error(`Chromium download ${sha256} and Playwright mirror ${mirror.sha256} differ`);}
    pinned('Chromium archive',sha256,p.archiveSha256);
    await rm(targets.browser,{recursive:true,force:true});await mkdir(targets.browser,{recursive:true});run('unzip',['-q',file,'-d',targets.browser]);
    const chrome=path.join(targets.browser,'chrome-linux64','chrome');if(!existsSync(chrome))throw new Error('Unpacked Chromium has no chrome-linux64/chrome');await chmod(chrome,0o755);
    summary.chromium={version:p.version,playwright:p.playwright,source:p.source,archiveSha256:sha256,checksumProvenance:p.checksumProvenance};}
  if(targets.tools){const p=pins.gitleaks,sums=await text(p.checksums),expected=listed(sums,p.archive);if(!expected)throw new Error('Gitleaks checksum list has no '+p.archive);
    const {file,sha256}=await download(p.source,p.archive);if(sha256!==expected)throw new Error(`Gitleaks archive checksum ${sha256} differs from the release checksums ${expected}`);pinned('Gitleaks archive',sha256,p.archiveSha256);
    const unpacked=path.join(scratch,'gitleaks');await mkdir(unpacked);run('tar',['-xzf',file,'-C',unpacked,'--no-same-owner']);
    const binary=path.join(unpacked,'gitleaks'),binarySha256=await sha(binary);pinned('Gitleaks binary',binarySha256,p.binarySha256);
    await mkdir(targets.tools,{recursive:true});await copyFile(binary,path.join(targets.tools,'gitleaks'));await chmod(path.join(targets.tools,'gitleaks'),0o755);
    if(existsSync(path.join(unpacked,'LICENSE')))await copyFile(path.join(unpacked,'LICENSE'),path.join(targets.tools,'LICENSE'));
    const version=run(path.join(targets.tools,'gitleaks'),['version']).trim();if(!version.includes(p.version))throw new Error('Unpacked Gitleaks reports '+version);
    // The same manifest shape as the Windows tools/manifest.json; the doctor reports the detector as verified when the binary matches it.
    const manifest={version:p.version,archive:p.archive,archiveSha256:sha256,binarySha256};await writeFile(path.join(targets.tools,'manifest.json'),JSON.stringify(manifest,null,2)+'\n');
    summary.gitleaks={...manifest,source:p.source};}
  await mkdir(path.dirname(summaryFile),{recursive:true});await writeFile(summaryFile,JSON.stringify(summary,null,2)+'\n');
  console.log(JSON.stringify(summary));
}finally{await rm(scratch,{recursive:true,force:true});}
