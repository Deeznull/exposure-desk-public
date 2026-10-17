import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { readFileSync, existsSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { root, ENGINE_VERSION } from '../src/detectors.js';
import { bundledBrowserPath, browserSandboxArgs, browserCrashArgs, gitleaksName } from '../src/runtime-paths.js';
import { diagnose } from '../src/diagnostics.js';
const read=(f:string)=>readFileSync(path.join(root,f),'utf8');
const hex=/^[0-9a-f]{64}$/;

test('platform paths: each package finds its own bundled browser and detector, other platforms have none',()=>{
  assert.equal(bundledBrowserPath('win32','/app'),path.join('/app','browser','chrome-win64','chrome.exe'));
  assert.equal(bundledBrowserPath('linux','/app'),path.join('/app','browser','chrome-linux64','chrome'));
  assert.equal(bundledBrowserPath('darwin','/app'),undefined);
  assert.equal(gitleaksName('win32'),'gitleaks.exe');assert.equal(gitleaksName('linux'),'gitleaks');
});

test('browser sandbox: Chromium keeps its sandbox unless a Linux container operator opts out explicitly, never on Windows',()=>{
  assert.deepEqual(browserSandboxArgs('linux',{}),[]);
  assert.deepEqual(browserSandboxArgs('linux',{EXPOSURE_BROWSER_NO_SANDBOX:'1'}),['--no-sandbox']);
  for(const value of ['0','true','yes',''])assert.deepEqual(browserSandboxArgs('linux',{EXPOSURE_BROWSER_NO_SANDBOX:value}),[],'only the exact value 1 opts out: '+JSON.stringify(value));
  assert.deepEqual(browserSandboxArgs('win32',{EXPOSURE_BROWSER_NO_SANDBOX:'1'}),[]);
  assert.deepEqual(browserSandboxArgs('darwin',{EXPOSURE_BROWSER_NO_SANDBOX:'1'}),[]);
});

test('doctor reports the browser sandbox setting on Linux only',async()=>{
  const previous=process.env.EXPOSURE_BROWSER_NO_SANDBOX;
  try{
    delete process.env.EXPOSURE_BROWSER_NO_SANDBOX;let sandbox=(await diagnose({synthetic:true})).checks.find((c:any)=>c.name==='Browser sandbox');
    if(process.platform!=='linux'){assert.equal(sandbox,undefined);return;}
    assert.equal(sandbox?.status,'chromium-sandbox');
    process.env.EXPOSURE_BROWSER_NO_SANDBOX='1';sandbox=(await diagnose({synthetic:true})).checks.find((c:any)=>c.name==='Browser sandbox');
    assert.equal(sandbox?.status,'container-isolation');assert.match(sandbox.detail,/docs\/LINUX\.md/);
  }finally{if(previous===undefined)delete process.env.EXPOSURE_BROWSER_NO_SANDBOX;else process.env.EXPOSURE_BROWSER_NO_SANDBOX=previous;}
});

test('Linux distributions: same versions as the Windows package, official sources, recorded pins',()=>{
  const pins=JSON.parse(read('scripts/linux-distributions.json')),windows=JSON.parse(read('PACKAGE_MANIFEST.json'));
  const browsers=JSON.parse(read('node_modules/playwright-core/browsers.json')).browsers,chromium=browsers.find((b:any)=>b.name==='chromium');
  const playwright=JSON.parse(read('node_modules/playwright/package.json')).version;
  assert.equal(pins.platform,'linux-x64');
  assert.equal(pins.node.version,windows.node.version);assert.equal(pins.node.source,`https://nodejs.org/dist/v${pins.node.version}/node-v${pins.node.version}-linux-x64.tar.xz`);assert.equal(pins.node.checksums,`https://nodejs.org/dist/v${pins.node.version}/SHASUMS256.txt`);
  assert.equal(pins.gitleaks.version,ENGINE_VERSION);assert.equal(pins.gitleaks.version,windows.gitleaks.version);
  assert.equal(pins.gitleaks.source,`https://github.com/gitleaks/gitleaks/releases/download/v${ENGINE_VERSION}/${pins.gitleaks.archive}`);assert.equal(pins.gitleaks.archive,`gitleaks_${ENGINE_VERSION}_linux_x64.tar.gz`);
  assert.equal(pins.chromium.version,chromium.browserVersion);assert.equal(pins.chromium.version,windows.chromium.version);assert.equal(pins.chromium.playwright,playwright);
  assert.equal(pins.chromium.source,`https://storage.googleapis.com/chrome-for-testing-public/${pins.chromium.version}/linux64/chrome-linux64.zip`);
  assert.equal(pins.chromium.mirror,`https://cdn.playwright.dev/builds/cft/${pins.chromium.version}/linux64/chrome-linux64.zip`);
  for(const [name,value] of [['node',pins.node.archiveSha256],['gitleaks archive',pins.gitleaks.archiveSha256],['gitleaks binary',pins.gitleaks.binarySha256],['chromium',pins.chromium.archiveSha256]])assert.match(String(value),hex,name+' pin must be a recorded SHA-256');
  const fetcher=read('scripts/fetch-linux-distributions.mjs');for(const host of ['nodejs.org','github.com','storage.googleapis.com','cdn.playwright.dev'])assert.ok(fetcher.includes(`'${host}'`),'allowlisted source '+host);
  assert.match(fetcher,/protocol!=='https:'/);
});

test('Linux launcher: LF line endings, prefers the bundled runtime, otherwise requires Node.js 24-26',()=>{
  const text=read('Start Exposure Desk.sh');assert.ok(!text.includes('\r'),'LF only');assert.ok(text.startsWith('#!/usr/bin/env sh\n'));
  assert.match(text,/\$APP_DIR\/runtime\/bin\/node" "\$APP_DIR\/scripts\/launch\.mjs"/);assert.match(text,/-lt 24/);assert.match(text,/-gt 26/);
  const launch=read('scripts/launch.mjs');assert.match(launch,/'gitleaks\.exe':'gitleaks'\),installedTool/);assert.match(launch,/'lib','node_modules','npm','bin','npm-cli\.js'/);
});

test('Linux package and Windows package stay separate: the Windows packager has no Linux branch, both ship the shared release list including the Linux guide',async()=>{
  const windows=read('scripts/package-portable.mjs'),linux=read('scripts/package-linux.mjs');
  assert.match(windows,/process\.platform!=='win32'/);assert.ok(!windows.includes('linux'),'The Windows packager has no Linux branch');
  assert.match(linux,/process\.platform!=='linux'/);assert.match(linux,/for\(const entry of releaseFiles\)/);
  // w3-docs (2.8): docs/LINUX.md and the other 2.8 guides joined the shared list, so the README and user guide links resolve in both packages.
  const {releaseFiles}=await import(pathToFileURL(path.join(root,'scripts','release-files.mjs')).href);
  for(const doc of ['docs/LINUX.md','docs/PROGRAM.md','docs/MASS_SCAN.md','docs/RECON.md','docs/SUBMISSION.md','docs/releases/MIGRATION_2.8.md'])assert.ok(releaseFiles.includes(doc),'shared release list includes '+doc);
  assert.match(linux,/Build parity mismatch/);assert.match(linux,/Pinned detector integrity mismatch/);assert.match(linux,/verbatimSymlinks:true/);assert.match(linux,/A link leaves the package/);
  assert.ok(existsSync(path.join(root,'docs','LINUX.md')));
});

test('container image: pinned base, non-root user, data volume, loopback dashboard, no published port',()=>{
  const docker=read('docker/Dockerfile');
  const bases=[...docker.matchAll(/^ARG NODE_IMAGE=(.+)$/gm)].map(m=>m[1]);assert.equal(bases.length,1);assert.match(bases[0],/^node:24\.18\.1-bookworm-slim@sha256:[0-9a-f]{64}$/);
  for(const from of docker.matchAll(/^FROM (\S+)/gm))assert.equal(from[1],'${NODE_IMAGE}','every stage uses the pinned base');
  assert.match(docker,/^USER exposure:exposure$/m);assert.match(docker,/--uid 10001/);assert.match(docker,/^VOLUME \["\/data"\]$/m);assert.match(docker,/EXPOSURE_DATA_DIR=\/data/);
  assert.match(docker,/^ENTRYPOINT \["\/usr\/bin\/tini", "--", "node", "\/app\/dist\/src\/cli\.js"\]$/m);assert.ok(!/^EXPOSE /m.test(docker),'no published port');
  assert.match(docker,/EXPOSURE_BROWSER_NO_SANDBOX=1/);assert.match(docker,/chmod -R a-w \/app/);assert.match(docker,/fetch-linux-distributions\.mjs/);
  const ignore=read('docker/Dockerfile.dockerignore').split('\n');for(const entry of ['.git','node_modules','dist','runtime','browser','.cache','artifacts','data'])assert.ok(ignore.includes(entry),'.dockerignore excludes '+entry);
  const dashboard=read('src/dashboard.ts');assert.match(dashboard,/listen\(port,'127\.0\.0\.1'/);
});

test('Linux workflow: SHA-pinned actions, pull requests into v3 and main plus manual runs, superseded runs cancelled',()=>{
  const flow=read('.github/workflows/linux.yml');
  const uses=[...flow.matchAll(/uses:\s*(\S+)/g)].map(m=>m[1]);assert.ok(uses.length>=4);for(const u of uses)assert.match(u,/^[\w.-]+\/[\w.-]+@[0-9a-f]{40}$/,'action pinned to a full commit SHA: '+u);
  assert.match(flow,/pull_request:\n\s+branches: \[v3, main\]/);assert.match(flow,/workflow_dispatch:/);
  assert.match(flow,/cancel-in-progress: true/);assert.match(flow,/permissions:\n\s+contents: read/);assert.match(flow,/persist-credentials: false/);
  for(const step of ['npm ci','node scripts/build.mjs','scripts/test.mjs','package-linux.mjs','packaged-smoke.mjs','sha256sum --check','docker build','docker-smoke.mjs'])assert.ok(flow.includes(step),'workflow step '+step);
  const jobs=flow.slice(flow.indexOf('\njobs:\n'));assert.deepEqual([...jobs.matchAll(/^  ([\w-]+):$/gm)].map(m=>m[1]),['suites','package','docker'],'the same jobs (suites runs nonbrowser and browser)');
  assert.equal((flow.match(/runs-on: ubuntu-24\.04/g)||[]).length,3);
});

/** The YAML text of one job, and the steps of that job split at each '      - ' item. */
function workflowJob(flow:string,job:string){const start=flow.indexOf('\n  '+job+':\n');assert.ok(start>=0,'job '+job);const rest=flow.slice(start+1),next=rest.search(/\n  [\w-]+:\n/);return next<0?rest:rest.slice(0,next+1);}
const workflowSteps=(job:string)=>job.split(/\n(?=      - )/).slice(1);

test('Linux workflow: the package is attached to a draft release only on a manual run with a validated tag; pull requests and plain runs upload nothing',()=>{
  const flow=read('.github/workflows/linux.yml'),pkg=workflowJob(flow,'package'),steps=workflowSteps(pkg);
  // Inputs: release_tag (string, empty by default) and the old artifact upload as an opt-in that is off by default.
  assert.match(flow,/workflow_dispatch:\n\s+inputs:\n\s+release_tag:\n(?:\s+.+\n)*?\s+type: string\n(?:\s+.+\n)*?\s+default: ''\n/);
  assert.match(flow,/upload_artifact:\n(?:\s+.+\n)*?\s+type: boolean\n(?:\s+.+\n)*?\s+default: false\n/);
  // Write access only in the package job; the workflow default and every other job stay read-only.
  assert.match(flow,/^permissions:\n  contents: read\n/m);
  assert.equal((flow.match(/contents: write/g)||[]).length,1,'one write grant');
  assert.match(pkg,/^    permissions:\n      contents: write\n/m,'job-level grant on the package job');
  for(const job of ['suites','docker'])assert.doesNotMatch(workflowJob(flow,job),/permissions:/,job+' inherits contents: read');
  const guard="if: github.event_name == 'workflow_dispatch' && inputs.release_tag != ''";
  const attach=steps.find(s=>s.includes('gh release upload'));assert.ok(attach,'release upload step');
  assert.ok(attach.includes(guard),'the release step runs only on a manual run with a tag');
  assert.doesNotMatch(flow,/pull_request_target/);
  // Every step that can upload is guarded to workflow_dispatch; the artifact upload needs its own opt-in.
  const uploads=steps.filter(s=>/gh release|upload-artifact/.test(s));assert.equal(uploads.length,2);
  for(const s of uploads)assert.match(s,/^\s+if: github\.event_name == 'workflow_dispatch' && /m);
  const artifact=steps.find(s=>s.includes('upload-artifact'));assert.ok(artifact);assert.match(artifact,/if: github\.event_name == 'workflow_dispatch' && inputs\.upload_artifact\n/);
  // The tag reaches the shell only through the environment and is checked against ^v1.2.3$ before use (fail fast, and again in the upload step).
  assert.doesNotMatch(flow,/run:[^\n]*\$\{\{\s*(?:inputs|github\.event\.inputs)\./,'no input interpolated into a one-line run');
  for(const s of steps){const run=s.split(/\n        run: \|\n/)[1];if(run)assert.doesNotMatch(run,/\$\{\{/,'no expression interpolated into a run script');}
  const check=/\[\[ !? ?"\$RELEASE_TAG" =~ \^v\[0-9\]\+\\\.\[0-9\]\+\\\.\[0-9\]\+\$ \]\]/;
  const first=steps.findIndex(s=>s.includes('RELEASE_TAG: ${{ inputs.release_tag }}'));assert.ok(first>=0&&first<steps.findIndex(s=>s.includes('actions/checkout')),'tag checked before checkout');
  assert.ok(steps[first].includes(guard));assert.match(steps[first],check);
  assert.match(attach,/RELEASE_TAG: \$\{\{ inputs\.release_tag \}\}/);assert.match(attach,check);
  assert.ok(attach.indexOf('=~')<attach.indexOf('gh release'),'validated before the first gh call');
  // After the checksum and the packaged smoke; draft only; never published, never deleted; an already published release is refused.
  const order=['sha256sum --check','packaged-smoke.mjs','gh release upload'].map(t=>pkg.indexOf(t));assert.ok(order[0]>=0&&order[0]<order[1]&&order[1]<order[2]);
  assert.match(attach,/gh release create "\$RELEASE_TAG" --draft --target "\$GITHUB_SHA"/);
  assert.match(attach,/gh release upload "\$RELEASE_TAG" [^\n]+ --clobber\n/);
  assert.match(attach,/already published/);assert.match(attach,/--json isDraft --jq \.isDraft\)" = "true" \]/);
  assert.doesNotMatch(flow,/gh release delete|delete-asset|--draft=false|--latest|gh api[^\n]*-X\s*DELETE|gh release edit[^\n]*--draft/);
  assert.match(attach,/GH_TOKEN: \$\{\{ github\.token \}\}/);
  // Run id, commit and SHA-256 in the job summary and the log on every run.
  const record=steps.find(s=>s.includes('GITHUB_STEP_SUMMARY')&&!s.includes('gh release'));assert.ok(record&&!/\n\s+if:/.test(record),'recorded on every run');
  for(const v of ['$GITHUB_RUN_ID','$GITHUB_SHA','sha256sum'])assert.ok(record.includes(v),'record holds '+v);
});

test('Linux release assets: the downloaded package is checked against its .sha256 file and gets its package name back; a mismatch renames nothing',async()=>{
  const {restoreLinuxReleaseAssets,parseChecksumLine,assetName}=await import(pathToFileURL(path.join(root,'scripts/linux-release-assets.mjs')).href);
  const {mkdtemp,mkdir,writeFile,readdir,readFile,rm}=await import('node:fs/promises');const made:string[]=[];const {createHash}=await import('node:crypto');
  const parent=process.env.EXPOSURE_DATA_DIR||path.join(root,'.cache');await mkdir(parent,{recursive:true});
  const content=Buffer.from('synthetic tar placeholder\n'),sum=createHash('sha256').update(content).digest('hex'),name='Exposure Desk 9.8.7 Linux x64.tar.gz';
  const setup=async(line:string,data=content)=>{const dir=await mkdtemp(path.join(parent,'linux-assets-'));made.push(dir);await writeFile(path.join(dir,assetName),data);await writeFile(path.join(dir,assetName+'.sha256'),line);return dir;};
  try{
  assert.equal(assetName,'exposure-desk-linux-x64.tar.gz');
  assert.deepEqual(parseChecksumLine(`${sum}  ${name}\n`),{sha256:sum,name,version:'9.8.7'});
  for(const bad of [`${sum}  ../${name}\n`,`${sum}  evil.tar.gz\n`,`${sum.slice(1)}  ${name}\n`,`${sum}  ${name}\n${sum}  ${name}\n`])assert.throws(()=>parseChecksumLine(bad));
  const ok=await setup(`${sum}  ${name}\n`);const result=await restoreLinuxReleaseAssets(ok,{version:'9.8.7'});
  assert.equal(result.sha256,sum);assert.equal(result.name,name);assert.equal(result.bytes,content.length);
  assert.deepEqual((await readdir(ok)).sort(),[name,name+'.sha256']);assert.equal(await readFile(path.join(ok,name+'.sha256'),'utf8'),`${sum}  ${name}\n`);
  const wrong=await setup(`${sum}  ${name}\n`,Buffer.from('changed'));await assert.rejects(restoreLinuxReleaseAssets(wrong,{}),/does not match/);
  assert.deepEqual((await readdir(wrong)).sort(),[assetName,assetName+'.sha256']);
  const other=await setup(`${sum}  ${name}\n`);await assert.rejects(restoreLinuxReleaseAssets(other,{version:'9.8.8'}),/expected 9\.8\.8/);
  const clash=await setup(`${sum}  ${name}\n`);await writeFile(path.join(clash,name),'different');await assert.rejects(restoreLinuxReleaseAssets(clash,{}),/already exists/);
  assert.equal(await readFile(path.join(clash,name),'utf8'),'different');
  }finally{for(const dir of made)await rm(dir,{recursive:true,force:true});}
});

test('crash handling switch: Windows keeps --disable-crashpad-for-testing; Linux omits it because it makes the network service abort, and every launch site uses the helper',()=>{
  assert.deepEqual(browserCrashArgs('win32'),['--disable-crashpad-for-testing']);
  assert.deepEqual(browserCrashArgs('linux'),[]);
  for(const file of ['src/browser.ts','test/browser.test.ts','test/repair-browser.test.ts']){
    const text=readFileSync(path.join(root,file),'utf8');
    assert.doesNotMatch(text,/'--disable-crashpad-for-testing'/,file+' passes the switch only through browserCrashArgs()');
    assert.match(text,/\.\.\.browserCrashArgs\(\)/,file);
  }
  const launch=readFileSync(path.join(root,'src/browser.ts'),'utf8');
  for(const kept of ['--disable-breakpad','--disable-crash-reporter'])assert.ok(launch.includes(`'${kept}'`),kept+' stays on every platform');
});
