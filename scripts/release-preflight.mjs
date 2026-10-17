// Release preflight (read-only): every earlier release archive still matches its recorded checksums (artifacts/SHA256SUMS-<x.y>.txt up to 2.6.0-rc.1, SHA256SUMS-<full version>.txt after), the historical records are present,
// the baseline snapshot is the untouched build of the current release (candidate) in artifacts/ARCHIVE_INDEX.json, and the pinned runtime, detector and browser are the expected ones.
// Usage: node scripts/release-preflight.mjs [--baseline DIR] [--output FILE]
import {createHash} from 'node:crypto';
import {createReadStream,existsSync} from 'node:fs';
import {readFile,writeFile,mkdir,readdir} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const root=path.dirname(path.dirname(fileURLToPath(import.meta.url))),args=process.argv.slice(2),opt=n=>{const i=args.indexOf('--'+n);return i<0?undefined:args[i+1];};
const sha=async f=>{const h=createHash('sha256');for await(const c of createReadStream(f))h.update(c);return h.digest('hex');};
const checks={};const fail=[];const record=(name,ok,detail)=>{checks[name]={ok,...(detail?{detail}:{})};if(!ok)fail.push(name);};
const version=JSON.parse(await readFile(path.join(root,'package.json'),'utf8')).version;
const sums=(await readdir(path.join(root,'artifacts'))).map(f=>/^SHA256SUMS-(\d+\.\d+(?:\.\d+)?(?:-[0-9A-Za-z.]+)?)\.txt$/.exec(f)?.[1]).filter(v=>v&&v!==version);record('earlier release checksum files',sums.length>0,sums.join(', '));
for(const v of sums){for(const line of (await readFile(path.join(root,'artifacts',`SHA256SUMS-${v}.txt`),'utf8')).trim().split('\n')){const [hash,...rest]=line.split(/\s+/),name=rest.join(' ');const file=path.join(root,'artifacts',name);record(`${v} archive: ${name}`,existsSync(file)&&await sha(file)===hash);}
  for(const f of [`release-${v}-results.json`,`final-parity-${v}.json`])record('historical record: '+f,existsSync(path.join(root,'artifacts',f)));}
for(const f of ['release-2.3.1-results.json','final-parity-2.3.1.json','release-2.3-results.json','release-2.2-results.json'])record('historical record: '+f,existsSync(path.join(root,'artifacts',f)));
const index=JSON.parse(await readFile(path.join(root,'artifacts/ARCHIVE_INDEX.json'),'utf8')),current=index.releases.find(r=>/^current release/.test(r.status))??index.releases.at(-1);
const baseline=opt('baseline');if(baseline){const info=JSON.parse(await readFile(path.join(baseline,'BUILD_INFO.json'),'utf8'));// An extracted release package omits the files every release excludes; its PACKAGE_MANIFEST.json, when present, is checked as well.
  const {excludedFromRelease}=await import('./release-files.mjs'),listed=[...info.inputs,...info.compiled].filter(f=>!excludedFromRelease(f.path)),pm=existsSync(path.join(baseline,'PACKAGE_MANIFEST.json'))?JSON.parse(await readFile(path.join(baseline,'PACKAGE_MANIFEST.json'),'utf8')):null;
  let mismatches=0;for(const f of [...listed,...(pm?.files||[])])if(!existsSync(path.join(baseline,f.path))||await sha(path.join(baseline,f.path))!==f.sha256)mismatches++;
  record('baseline is '+current.build,info.build.id===current.build&&(!pm||pm.build.id===current.build)&&mismatches===0,{buildFiles:listed.length,excluded:info.inputs.length+info.compiled.length-listed.length,packageFiles:pm?.files.length??0,mismatches});}
const node=spawnSync(path.join(root,'runtime/node.exe'),['--version'],{encoding:'utf8',windowsHide:true});record('bundled Node v24.18.1',node.stdout?.trim()==='v24.18.1',node.stdout?.trim());
const tools=JSON.parse(await readFile(path.join(root,'tools/manifest.json'),'utf8'));record('Gitleaks 8.30.1 binary hash',await sha(path.join(root,'tools/gitleaks.exe'))===tools.binarySha256);
record('Chrome for Testing 153.0.8010.12',existsSync(path.join(root,'browser/chrome-win64/153.0.8010.12.manifest')));
record('BIP39 wordlist digest',await sha(path.join(root,'rules/bip39-english.txt'))==='2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda');
record('System32 tar.exe present',existsSync(path.join(process.env.SystemRoot||'C:\\Windows','System32','tar.exe')));
const freeze=JSON.parse(await readFile(path.join(root,'benchmarks/2.5/corpus-freeze.json'),'utf8')),{corpusDigest}=await import('./eval-2.5-corpus.mjs');record('evaluation corpus unchanged since freeze',freeze.corpusDigest===corpusDigest,{frozenAt:freeze.frozenAt});
const result={schema:'exposure-release-preflight/1',at:new Date().toISOString(),ok:!fail.length,failed:fail,checks};
const out=opt('output');if(out){await mkdir(path.dirname(path.resolve(out)),{recursive:true});await writeFile(out,JSON.stringify(result,null,2));}
console.log(JSON.stringify({ok:result.ok,failed:fail}));process.exitCode=fail.length?1:0;
