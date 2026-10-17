import {AnalysisChild} from '../src/analysis-process.js';
/** Test helper (run as its own process by analysis-isolation.test): starts one idle parser process, prints its pid, then either stays alive until it is killed outright (`stay`) or exits normally (`exit`). */
const mode=process.argv[2]||'stay',child=new AnalysisChild('parser',128,new URL('../src/semantic-worker.js',import.meta.url));
child.on('message',(m:any)=>{if(m?.type!=='ready')return;process.stdout.write(JSON.stringify({pid:child.info.pid})+'\n');if(mode==='exit')setTimeout(()=>process.exit(0),50);});
if(mode==='stay')setInterval(()=>{},1000);
