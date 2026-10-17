// Repeated Chromium cancellation stress: runs the browser tests whose names match "cancel" N times (default 20), each pass in a fresh Node process,
// and prints one aggregate summary in the test runner's spec format. Usage: node scripts/cancel-stress.mjs [--runs N]. Requires EXPOSURE_DATA_DIR (a temporary folder).
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
const cwd=fileURLToPath(new URL('../',import.meta.url)),args=process.argv.slice(2),i=args.indexOf('--runs'),runs=i<0?20:Math.max(1,Number(args[i+1])||20);
if(!process.env.EXPOSURE_DATA_DIR){console.error('Set EXPOSURE_DATA_DIR to a temporary folder; verification never uses the application data directory.');process.exit(2);}
const files=['dist/test/origins-browser.test.js','dist/test/repair-browser.test.js'],total={tests:0,pass:0,fail:0,cancelled:0,skipped:0,todo:0},began=performance.now();
for(let run=1;run<=runs;run++){
  const r=spawnSync(process.execPath,['--test','--test-isolation=none','--test-concurrency=1','--test-timeout=120000','--test-name-pattern=cancel',...files],{cwd,encoding:'utf8',windowsHide:true,timeout:300000,env:{...process.env,EXPOSURE_TEST_OUTPUT:process.env.EXPOSURE_TEST_OUTPUT||path.join(cwd,'.cache','test-output')}});
  const out=(r.stdout||'')+(r.stderr||''),n=k=>Number((out.match(new RegExp('^ℹ '+k+' (\\d+)','m'))||[])[1]??NaN),counts=Object.fromEntries(Object.keys(total).map(k=>[k,n(k)]));
  // A pass that hung, crashed or printed no summary counts as one failure.
  if(r.status!==0||!(counts.tests>0)){total.tests++;total.fail++;console.log(`pass ${run}: failed (exit ${r.status??r.signal})`);for(const line of out.split('\n').filter(l=>/^\s*✖|not ok|Error/.test(l)).slice(0,10))console.log('  '+line.trim());continue;}
  for(const k of Object.keys(total))total[k]+=counts[k];console.log(`pass ${run}: ${counts.pass}/${counts.tests} passed`);
}
for(const [k,v] of Object.entries(total))console.log(`ℹ ${k} ${v}`);console.log(`ℹ duration_ms ${(performance.now()-began).toFixed(3)}`);
process.exitCode=total.fail||total.cancelled||total.pass!==total.tests?1:0;
