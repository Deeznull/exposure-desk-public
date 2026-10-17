import {mkdir,writeFile} from 'node:fs/promises';
import {Scanner} from '../src/scanner.js';import {presetConfig} from '../src/presets.js';import {report} from '../src/reports.js';
// Exact user-supplied authorized origin only; discoveries cannot enlarge scope. Usage: node dist/scripts/target-recheck.js https://your-site.example/
const target=process.argv[2];if(!target||!/^https:\/\//.test(target))throw new Error('Supply the https:// origin you are authorized to recheck');
const scan=new Scanner(presetConfig('thorough',{name:'Authorized target recheck',urls:[target],relatedOrigins:[]}));await scan.init();
const timer=setInterval(()=>{const v=scan.view();console.log(JSON.stringify({state:v.state,stage:v.stage,elapsedMs:v.elapsedMs,accounting:v.accounting,pending:v.counts.pending}));},10000);
try{await scan.run();await mkdir('reports',{recursive:true});await writeFile('reports/target-recheck.json',report(scan,'json'));console.log(JSON.stringify({state:scan.state,accounting:scan.view().accounting,stopReason:scan.stopReason,browser:scan.browserStatus,gaps:scan.view().limitations.map(g=>({code:g.code,incomplete:g.incomplete}))}));}finally{clearInterval(timer);scan.dispose();}
