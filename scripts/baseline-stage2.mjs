import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import path from 'node:path';
const manifest=JSON.parse(await readFile('BUILD_INFO.json','utf8'));
if(manifest.build.id!=='2.2.0-rc.1+8399b64166f5075d')throw new Error('This historical baseline runner only applies to the preserved 2.2 build; results must not be overwritten by newer source.');
const mismatches=[];
for(const e of [...manifest.inputs,...manifest.compiled])if(createHash('sha256').update(await readFile(e.path)).digest('hex')!==e.sha256)mismatches.push(e.path);
const {BUILD}=await import('../dist/src/build-info.js');
const {startDashboard}=await import('../dist/src/dashboard.js');
const app=await startDashboard({port:0});
const health=await(await fetch(app.origin+'/health')).json();await app.close();
let priorInstance={status:'no responding registered instance'};
try{const prior=JSON.parse(await readFile(path.join(process.env.LOCALAPPDATA||path.join(process.env.USERPROFILE,'AppData','Local'),'Exposure Desk','instance.json'),'utf8'));const u=new URL(prior.origin);if(u.hostname==='127.0.0.1'&&u.protocol==='http:'){const h=await(await fetch(u.origin+'/health',{signal:AbortSignal.timeout(1500)})).json();priorInstance={status:'responding',build:h.build,applicationRoot:prior.applicationRoot};}}catch{}
await mkdir('benchmarks/stage2-baseline',{recursive:true});
for(const name of ['results.json','pipeline-results.json','framework-results.json'])await writeFile('benchmarks/stage2-baseline/'+name,await readFile('benchmarks/'+name));
const record={at:new Date().toISOString(),build:manifest.build,compiledBuild:BUILD,launchedBuild:health.build,parity:mismatches.length?'mismatch':'verified',mismatches,priorInstance,runs:[]};
await writeFile('benchmarks/stage2-baseline/verification.json',JSON.stringify(record,null,2));
if(mismatches.length||BUILD.id!==health.build?.id)throw new Error('Baseline parity failed');
for(const [name,args]of [
 ['nonbrowser',['--test','--test-isolation=none','--test-concurrency=1',...['core','dashboard','upgrade','coverage','providers','reliability'].map(n=>'dist/test/'+n+'.test.js')]],
 ['browser',['--test','--test-isolation=none','dist/test/browser.test.js']],
 ['benchmark',['dist/scripts/benchmark.js']],['pipeline',['dist/scripts/pipeline-self-test.js']]
]){const start=Date.now(),r=spawnSync(process.execPath,args,{encoding:'utf8',windowsHide:true,maxBuffer:16*1024*1024});await writeFile('benchmarks/stage2-baseline/'+name+'.log',(r.stdout||'')+(r.stderr||''));const summary={name,exit:r.status,elapsedMs:Date.now()-start,counts:(r.stdout||'').match(/# (?:tests|pass|fail|skipped|duration_ms) .*/g)};record.runs.push(summary);await writeFile('benchmarks/stage2-baseline/verification.json',JSON.stringify(record,null,2));console.log(JSON.stringify(summary));}
