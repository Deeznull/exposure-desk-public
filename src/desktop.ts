import { readFile, writeFile, rm } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { startDashboard } from './dashboard.js';
import { dataLocation, restrictDirectory } from './storage.js';
import { BUILD } from './build-info.js';
import { applicationRoot } from './runtime-paths.js';
export function openDashboard(url:string){const u=new URL(url);if(u.hostname!=='127.0.0.1'||u.protocol!=='http:'||u.search)throw new Error('Only the local dashboard can be opened');if(process.env.EXPOSURE_NO_OPEN==='1')return;const child=process.platform==='win32'?spawn('rundll32.exe',['url.dll,FileProtocolHandler',url],{stdio:'ignore',windowsHide:true}):spawn('xdg-open',[url],{stdio:'ignore'});child.on('error',()=>console.log('Open the dashboard address displayed below in your browser.'));child.unref();}
export async function launch(){
  const dir=dataLocation();let protectedData=true;try{await restrictDirectory(dir);}catch{protectedData=false;}
  const file=path.join(dir,'instance.json'),nonce=randomBytes(24).toString('base64url');
  if(protectedData){try{const prior=JSON.parse(await readFile(file,'utf8'));if(prior.pid&&prior.origin&&prior.nonce){const u=new URL(prior.origin);if(u.hostname!=='127.0.0.1'||u.protocol!=='http:'||u.search||u.username||u.password||u.pathname!=='/')throw new Error('Invalid instance');process.kill(prior.pid,0);const r=await fetch(prior.origin+'/health',{signal:AbortSignal.timeout(1500)}),health=await r.json() as any;if(health.application==='Exposure Desk'&&health.instance===prior.nonce){if(health.build?.id!==BUILD.id)console.log(`Existing instance build: ${health.build?.id||'unknown (older instance has no build metadata)'}. Requested build: ${BUILD.id}. Stop the existing app in Settings and launch this package again to use the upgrade. Existing data is preserved.`);else console.log(`Build: ${health.build.id}`);console.log(`Exposure Desk is already running: ${prior.origin}\nSign-in token: ${prior.token}`);openDashboard(prior.origin);return;}}}catch{}
    try{await writeFile(file,JSON.stringify({pid:process.pid,nonce:Math.random().toString(36)}),{flag:'wx',mode:0o600});}catch{try{const prior=JSON.parse(await readFile(file,'utf8'));process.kill(prior.pid,0);console.log('Exposure Desk is starting in another window. Wait briefly, then open its dashboard.');return;}catch{await rm(file,{force:true});await writeFile(file,JSON.stringify({pid:process.pid}),{flag:'wx',mode:0o600});}}
  }
  let closing=false,app:Awaited<ReturnType<typeof startDashboard>>;const close=async()=>{if(closing)return;closing=true;console.log('Stopping scans and locking evidence…');await app.close();if(protectedData)await rm(file,{force:true});process.exitCode=0;};
  try{app=await startDashboard({port:4317,portFallback:true,persistent:true,dataDir:dir,instanceNonce:nonce,onShutdown:()=>void close()});}catch{if(protectedData)await rm(file,{force:true});throw new Error('Dashboard startup failed. Check loopback availability and data directory permissions.');}
  if(protectedData)await writeFile(file,JSON.stringify({pid:process.pid,origin:app.origin,token:app.token,nonce,applicationRoot,build:BUILD}),{mode:0o600});
  console.log(`Build: ${BUILD.id}`);
  console.log(`\nExposure Desk is ready: ${app.origin}\n\nSign-in token (copy into the local page):\n${app.token}\n\nKeep this launch window open. Use Stop Exposure Desk in Settings or Ctrl+C to shut down.\nData: ${dir}${protectedData?'':'\nProtected storage blocked; the dashboard will explain available memory-only features.'}`);openDashboard(app.origin);process.on('SIGINT',()=>void close());process.on('SIGTERM',()=>void close());
}
