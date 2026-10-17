// Run by scripts/packaged-smoke.mjs with a package's bundled runtime: <package>\runtime\node.exe packaged-analysis-check.mjs <package folder> <data folder>.
// Scans one loopback page whose script is larger than 128 KiB (so the parser and the large-text checks run in analysis processes) and records,
// for every analysis process, the executable it runs (read while it is alive) and whether it is still running after the scan.
// Only 127.0.0.1 and the package's synthetic, nonfunctional fixture key are used.
import http from 'node:http';
import path from 'node:path';
import {execFileSync} from 'node:child_process';
import {readlinkSync} from 'node:fs';
import {pathToFileURL} from 'node:url';
const [target,data]=process.argv.slice(2).map(p=>path.resolve(p));
process.env.EXPOSURE_DATA_DIR=data;
const imp=f=>import(pathToFileURL(path.join(target,'dist','src',f)).href);
const {analysisProcesses}=await imp('analysis-process.js'),{Scanner}=await imp('scanner.js'),{report}=await imp('reports.js'),{synthetic}=await imp('fixture.js');
// Linux reads /proc/<pid>/exe; Windows asks Win32_Process.
const executableOf=pid=>{if(process.platform==='linux'){try{return readlinkSync('/proc/'+Number(pid)+'/exe');}catch{return null;}}try{return execFileSync('powershell.exe',['-NoProfile','-NonInteractive','-Command',`(Get-CimInstance Win32_Process -Filter "ProcessId=${Number(pid)}").ExecutablePath`],{encoding:'utf8',windowsHide:true}).trim()||null;}catch{return null;}};
const alive=pid=>{try{process.kill(pid,0);return true;}catch(e){return e.code==='EPERM';}};
// `spawn` is emitted before the scan sends the new process anything, and an analysis process waits for its first job, so it is running while its executable is read.
const children=[];analysisProcesses.events.on('spawn',info=>children.push({role:info.role,heapMb:info.heapMb,pid:info.pid,executable:executableOf(info.pid)}));
const filler=Array.from({length:4000},(_,i)=>`function step${i}(value){return value*${i%97}+${i%13};}`).join('\n');
const pages={'/':{type:'text/html',body:'<!doctype html><html><head><title>Synthetic analysis check</title><script src="/app.js"></script></head><body>Synthetic analysis check</body></html>'},
  '/app.js':{type:'text/javascript',body:`${filler}\nvar syntheticConfig={openaiKey:${JSON.stringify(synthetic.openai)}};\n`}};
const server=http.createServer((req,res)=>{const page=pages[new URL(req.url,'http://127.0.0.1').pathname];res.writeHead(page?200:404,{'content-type':page?.type||'text/plain'});res.end(req.method==='HEAD'?undefined:page?.body??'not found');});
await new Promise(r=>server.listen(0,'127.0.0.1',r));const origin=`http://127.0.0.1:${server.address().port}`;
let state,limits,found=false,leaked=true,error;
try{
  const scan=new Scanner({name:'Synthetic packaged analysis check',urls:[origin+'/'],developmentFixtureOrigin:origin,domainScope:'exact-origin',coverage:'quick',traffic:'normal'});
  await scan.init();await scan.run();const view=JSON.parse(report(scan,'json',false));scan.dispose();
  state=view.state;limits=(view.limitations||[]).filter(g=>g.incomplete).map(g=>g.code+": "+String(g.detail).slice(0,200));found=view.findings.some(f=>f.provider==='OpenAI');leaked=JSON.stringify(view).includes(synthetic.openai);
}catch(e){error=String(e?.stack||e).slice(0,800);}
finally{server.close();}
// Every analysis process has ended once the scan has finished; allow a moment for the operating system to remove ended processes.
for(let i=0;i<50&&(analysisProcesses.live>0||children.some(c=>alive(c.pid)));i++)await new Promise(r=>setTimeout(r,100));
console.log('RESULT '+JSON.stringify({state,limits,found,leaked,error,runtime:process.execPath,live:analysisProcesses.live,children:children.map(c=>({...c,running:alive(c.pid)}))}));
