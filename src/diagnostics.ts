import { existsSync } from 'node:fs';
import { readFile, rm } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { chromium } from 'playwright';
import { root, ENGINE_VERSION } from './detectors.js';
import { dataLocation, restrictDirectory } from './storage.js';
import { Scanner } from './scanner.js';
import { createFixture } from './fixture.js';
import { BUILD } from './build-info.js';
import { RULE_VERSION } from './detectors.js';
import { bundledBrowserPath, browserSandboxArgs } from './runtime-paths.js';
export function browserPath(){const bundled=bundledBrowserPath(process.platform,root)||'';return process.env.SCANNER_CHROMIUM_PATH|| (existsSync(chromium.executablePath())?chromium.executablePath():existsSync(bundled)?bundled:chromium.executablePath());}
export function detectorPath(){return process.env.GITLEAKS_PATH|| (existsSync(path.join(root,'tools',process.platform==='win32'?'gitleaks.exe':'gitleaks'))?path.join(root,'tools',process.platform==='win32'?'gitleaks.exe':'gitleaks'):path.join(root,'.tools',process.platform==='win32'?'gitleaks.exe':'gitleaks'));}
export async function diagnose(options:{dir?:string;runtime?:boolean;synthetic?:boolean}={}){
  const dir=options.dir||dataLocation();const checks:{name:string;status:string;detail:string;action?:string}[]=[];
  checks.push({name:'Node runtime',status:/^v(?:24|25|26)\./.test(process.version)?'installed':'unsupported',detail:process.version});
  checks.push({name:'Operating system',status:['win32','linux'].includes(process.platform)?'supported':'unsupported',detail:`${process.platform} ${process.arch}`});
  try{await restrictDirectory(dir,options.synthetic);await restrictDirectory(path.join(dir,'diagnostic'),options.synthetic);await rm(path.join(dir,'diagnostic'),{recursive:true,force:true});checks.push({name:'Protected writable application data',status:'ready',detail:dir});}catch(e){checks.push({name:'Protected writable application data',status:'blocked',detail:dir+' — '+(e instanceof Error?e.message:'Filesystem permission check failed')+' Protected persistence is disabled; configure EXPOSURE_DATA_DIR to a dedicated operator-owned application folder.'});}
  const detector=detectorPath();let verified=false;
  try{const manifest=JSON.parse(await readFile(path.join(path.dirname(detector),'manifest.json'),'utf8'));verified=manifest.version===ENGINE_VERSION&&createHash('sha256').update(await readFile(detector)).digest('hex')===manifest.binarySha256;}catch{}
  const detectorExec=existsSync(detector)?spawnSync(detector,['version'],{stdio:'ignore',windowsHide:true}).status===0:false;
  checks.push({name:'Offline detector',status:detectorExec?verified?'verified':'installed-unverified':existsSync(detector)?'blocked':'missing',detail:`Gitleaks ${ENGINE_VERSION}; ${verified?'binary matches verified installer manifest':'repair to install a checksum-verified binary'}; version process ${detectorExec?'executed':'unavailable'}`,action:'gitleaks'});
  checks.push({name:'Dedicated Chromium',status:existsSync(browserPath())?'installed':'missing',detail:'Must launch with a fresh protected profile. Installation is not a launch/security check.',action:'browser'});
  const tar=spawnSync('tar',['--version'],{stdio:'ignore',windowsHide:true});checks.push({name:'Archive extraction',status:tar.status===0?'ready':'missing',detail:'tar is required to install official archives'});
  if(process.platform==='linux'&&existsSync(browserPath())){const libs=spawnSync('ldd',[browserPath()],{encoding:'utf8',windowsHide:true});checks.push({name:'Chromium OS libraries',status:libs.status===0&&!libs.stdout?.includes('not found')?'available':'missing-or-unchecked',detail:'Shared-library check only. Successful sandboxed launch and runtime checks are still required.'});}
  if(process.platform==='linux')checks.push(browserSandboxArgs().length?{name:'Browser sandbox',status:'container-isolation',detail:'EXPOSURE_BROWSER_NO_SANDBOX=1: Chromium runs without its own sandbox; the container (non-root, no capabilities, read-only) is the isolation boundary. Use it only inside a container (docs/LINUX.md).'}:{name:'Browser sandbox',status:'chromium-sandbox',detail:'Chromium keeps its own sandbox, which needs unprivileged user namespaces (docs/LINUX.md).'});
  let parity='unverified';try{const manifest=JSON.parse(await readFile(path.join(root,'BUILD_INFO.json'),'utf8'));parity=manifest.build.id===BUILD.id?'verified':'mismatch';for(const entry of [...manifest.inputs,...manifest.compiled])if(createHash('sha256').update(await readFile(path.join(root,entry.path))).digest('hex')!==entry.sha256){parity='mismatch';break;}}catch{}
  checks.unshift({name:'Application build and file parity',status:parity,detail:`${BUILD.id}; website rules ${RULE_VERSION}. ${parity==='verified'?'Source, compiled files, frontend and dependency lock match the build manifest.':'Run the supplied build or use an intact package; the build manifest is missing or files differ.'}`});
  const result:any={at:new Date().toISOString(),build:BUILD,detectorRules:RULE_VERSION,applicationRoot:root,parity,checks,browser:{launch:'not-run',networkIsolation:'not-run',runtimeScan:'not-run'},dataLocation:dir,osRepair:process.platform==='linux'?'If Chromium reports missing shared libraries, review Playwright’s install-deps chromium instructions; installing OS packages may require administrator privileges. The app never runs sudo.':'Windows 10/11 x64 or arm64 with ordinary user browser sandbox support. No administrator setup is required.'};
  if(options.runtime){const f=await createFixture(0,{minimalDiscovery:true});try{const s=new Scanner({name:'Local diagnostic fixture',urls:[f.origin+'/clean'],developmentFixtureOrigin:f.origin,browser:true,adjacentMaps:false,requestsPerSecond:20,maxDurationMs:60000,maxResources:50,timeoutMs:3000,browserSettleMs:200,browserScrollSteps:1});await s.init();await s.run();result.browser.launch=s.browserStatus.launch?'available':'blocked';result.browser.runtimeScan=s.browserStatus.runtimePages>0&&s.state==='completed'?'completed':s.browserStatus.runtimePages>0?'partial':'unavailable';result.browser.networkIsolation='not-verified';result.browser.detail='This synthetic runtime check is separate from the full browser request-isolation and UI suite. Run that suite using the diagnostics action.';result.browser.limitations=s.view().limitations;s.dispose();}finally{await f.close();}}
  return result;
}
