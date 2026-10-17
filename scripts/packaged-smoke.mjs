import {spawn,spawnSync,execFileSync} from 'node:child_process';
import {readFile,mkdir,rm} from 'node:fs/promises';
import {createReadStream,lstatSync,readlinkSync,statSync,readdirSync,realpathSync} from 'node:fs';
import {createHash,randomUUID} from 'node:crypto';
import http from 'node:http';
import path from 'node:path';
import os from 'node:os';
import {pathToFileURL,fileURLToPath} from 'node:url';
import assert from 'node:assert/strict';
const target=path.resolve(process.argv[2]||'.');
const manifest=JSON.parse(await readFile(path.join(target,'PACKAGE_MANIFEST.json'),'utf8'));
const linux=process.platform==='linux';
// A Linux package also records its links (they must still be the same links) and the files that must stay executable (the launcher, runtime, browser and detector).
for(const entry of manifest.files){const file=path.resolve(target,entry.path);assert.ok(file.startsWith(target+path.sep));if(entry.symlink!==undefined){assert.ok(lstatSync(file).isSymbolicLink(),'Packaged link was replaced: '+entry.path);assert.equal(readlinkSync(file),entry.symlink,'Packaged link changed: '+entry.path);continue;}if(entry.executable)assert.ok(statSync(file).mode&0o100,'Packaged file lost its executable bit: '+entry.path);const hash=createHash('sha256');for await(const chunk of createReadStream(file))hash.update(chunk);assert.equal(hash.digest('hex'),entry.sha256,'Packaged file checksum mismatch: '+entry.path);}
if(process.argv.includes('--integrity-only')){console.log(JSON.stringify({manifestHashes:true,files:manifest.files.length,platform:manifest.platform}));process.exit(0);}
// Verification data never touches the operator's application data: it lives under EXPOSURE_VERIFY_ROOT (default: the system temp folder) and is removed afterwards.
const verifyRoot=path.resolve(process.env.EXPOSURE_VERIFY_ROOT||path.join(os.tmpdir(),'exposure-desk-verification')),data=path.join(verifyRoot,'packaged-'+randomUUID());await mkdir(data,{recursive:true});
const env={...process.env,EXPOSURE_DATA_DIR:data,EXPOSURE_NO_OPEN:'1'};
const delay=ms=>new Promise(r=>setTimeout(r,ms));
const processes=[];
const blocker=http.createServer((req,res)=>res.end('synthetic port conflict'));await new Promise((resolve,reject)=>blocker.listen(4317,'127.0.0.1',resolve).once('error',reject));
// Each platform's own launcher is started directly from the package folder (whose path has spaces): Start Exposure Desk.cmd through cmd.exe, Start Exposure Desk.sh by its executable bit.
function start(){const child=linux?spawn(path.join(target,'Start Exposure Desk.sh'),[],{cwd:target,env,stdio:['pipe','pipe','pipe']}):spawn('cmd.exe',['/d','/s','/c','""'+path.join(target,'Start Exposure Desk.cmd')+'""'],{cwd:target,env,windowsHide:true,windowsVerbatimArguments:true,stdio:['pipe','pipe','pipe']});processes.push(child);let output='';child.stdout.on('data',b=>output+=b);child.stderr.on('data',b=>output+=b);return {child,output:()=>output};}
async function ready(run){for(let i=0;i<300;i++){const text=run.output(),origin=text.match(/(?:ready|already running): (http:\/\/127\.0\.0\.1:\d+)/)?.[1];if(origin){const instance=JSON.parse(await readFile(path.join(data,'instance.json'),'utf8'));return {origin,token:instance.token};}assert.ok(run.child.exitCode===null,'Packaged launcher exited before ready');await delay(100);}throw new Error('Packaged launcher readiness timeout');}
async function login(instance){const response=await fetch(instance.origin+'/api/login',{method:'POST',headers:{'Content-Type':'application/json',Origin:instance.origin,'X-Dashboard-Request':'1'},body:JSON.stringify({token:instance.token})});assert.equal(response.status,200);const {csrf}=await response.json();const headers={'Content-Type':'application/json',Origin:instance.origin,'X-Dashboard-Request':'1','X-CSRF-Token':csrf,Cookie:response.headers.get('set-cookie').split(';')[0]};return {get:route=>fetch(instance.origin+route,{headers}),post:(route,value={})=>fetch(instance.origin+route,{method:'POST',headers,body:JSON.stringify(value)})};}
async function exited(child){for(let i=0;i<200&&child.exitCode===null;i++)await delay(100);assert.equal(child.exitCode,0,'Launcher must shut down normally');}
try{
 const first=start(),instance=await ready(first);assert.notEqual(new URL(instance.origin).port,'4317');const api=await login(instance);
 const workspace=await(await api.get('/api/workspace')).json();assert.ok(!workspace.storageError,'Ordinary-user protected storage must initialize');
 const saved=await(await api.post('/api/projects/save',{authorized:true,config:{name:'Synthetic packaged persistence',urls:['https://example.invalid'],browser:false,deep:false}})).json();assert.ok(saved.id);
 const second=start(),same=await ready(second);assert.equal(same.origin,instance.origin);await exited(second.child);
 const demo=await(await api.post('/api/demo')).json();let scan;for(let i=0;i<300;i++){scan=await(await api.get('/api/scans/'+demo.id)).json();if(scan.state!=='running')break;await delay(100);}assert.equal(scan.state,'completed');const {synthetic}=await import(pathToFileURL(path.join(target,'dist/src/fixture.js')));assert.ok(!JSON.stringify(scan).includes(synthetic.openai));const finding=scan.findings.find(f=>f.provider==='OpenAI');assert.ok(finding);const revealed=await(await api.post('/api/scans/'+demo.id+'/reveal',{findingId:finding.id,action:'reveal'})).json();assert.equal(revealed.value,synthetic.openai);
 const cancelling=await(await api.post('/api/demo')).json();assert.equal((await api.post('/api/scans/'+cancelling.id+'/cancel')).status,200);
 await api.post('/api/shutdown');await exited(first.child);
 const restart=start(),next=await login(await ready(restart));const after=await(await next.get('/api/workspace')).json();assert.ok(after.projects.some(p=>p.id===saved.id));await next.post('/api/projects/delete',{id:saved.id});await next.post('/api/shutdown');await exited(restart.child);
 // Analysis processes: a scan run by the bundled runtime starts the parser and large-text processes with that runtime, and none is running afterwards (scripts/packaged-analysis-check.mjs).
 const runtime=linux?realpathSync(path.join(target,'runtime','bin','node')):path.join(target,'runtime','node.exe'),checkData=path.join(data,'analysis-check');await mkdir(checkData,{recursive:true});
 const check=spawnSync(runtime,[path.join(path.dirname(fileURLToPath(import.meta.url)),'packaged-analysis-check.mjs'),target,checkData],{cwd:checkData,env:{...env,EXPOSURE_DATA_DIR:checkData},encoding:'utf8',windowsHide:true,timeout:300000});
 const analysis=JSON.parse(/^RESULT (.*)$/m.exec(check.stdout||'')?.[1]||'null');assert.ok(analysis,'Analysis process check gave no result: '+String(check.error||check.stderr||'').slice(-800));
 assert.equal(analysis.error,undefined,'Analysis process check failed: '+analysis.error);// A text over 128 KiB always carries the stated window limit (decoded-inspection-limit), which makes the scan incomplete; any other limit fails the check.
 assert.ok(analysis.state==='completed'||analysis.state==='incomplete'&&analysis.limits.every(l=>l.startsWith('decoded-inspection-limit:')),'Analysis process check scan ended '+analysis.state+': '+analysis.limits.join('; '));assert.ok(analysis.found,'Analysis process check: the synthetic key was not found');assert.ok(!analysis.leaked,'Analysis process check: the report holds the unmasked key');
 const samePath=value=>linux?String(value):String(value).toLowerCase(),bundled=samePath(runtime);
 assert.equal(samePath(analysis.runtime),bundled,'Analysis process check must run with the bundled runtime');
 const roles={parser:0,detector:0};for(const c of analysis.children){roles[c.role]++;assert.equal(samePath(c.executable),bundled,'Analysis process '+c.pid+' ('+c.role+') runs '+c.executable);assert.equal(c.running,false,'Analysis process '+c.pid+' is still running');}
 assert.ok(roles.parser>0&&roles.detector>0,'Expected parser and large-text analysis processes, got '+JSON.stringify(roles));assert.equal(analysis.live,0);
 // Nothing started from the package (launcher runtime, analysis processes, browser) is left running.
 // Linux: every process whose executable (/proc/<pid>/exe) lies in the package folder; Windows: the same through Win32_Process.ExecutablePath.
 const fromPackage=()=>linux?readdirSync('/proc').filter(p=>/^\d+$/.test(p)).filter(p=>{try{return readlinkSync('/proc/'+p+'/exe').startsWith(realpathSync(target)+path.sep);}catch{return false;}}).length:Number(execFileSync('powershell.exe',['-NoProfile','-NonInteractive','-Command','@(Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith($env:EXPOSURE_SMOKE_TARGET,[StringComparison]::OrdinalIgnoreCase) }).Count'],{encoding:'utf8',windowsHide:true,env:{...process.env,EXPOSURE_SMOKE_TARGET:target+path.sep}}).trim());
 let remaining=fromPackage();for(let i=0;i<30&&remaining>0;i++){await delay(500);remaining=fromPackage();}assert.equal(remaining,0,'A process started from the package is still running');
 console.log(JSON.stringify({manifestHashes:true,launcherPathWithSpaces:true,portConflict:true,protectedPersistence:true,existingInstance:true,authenticatedDemo:true,maskedDefaults:true,deliberateReveal:true,cancel:true,shutdown:true,restart:true,analysisProcesses:{...roles,bundledRuntime:true,runningAfterScan:0},noPackageProcessLeft:true}));
}finally{for(const child of processes)if(child.exitCode===null)child.kill();await new Promise(r=>blocker.close(r));assert.ok(path.resolve(data).startsWith(verifyRoot+path.sep));await rm(data,{recursive:true,force:true,maxRetries:10,retryDelay:100});}
