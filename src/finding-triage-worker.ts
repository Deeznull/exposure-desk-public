import {parentPort} from 'node:worker_threads';
import {classifyFinding} from './finding-triage-rules.js';
// One worker serves every scan in the process (finding-triage.ts): each batch names its client, and the answer names it back.
parentPort!.on('message',({client,rows}:{client:number;rows:any[]})=>parentPort!.postMessage({client,rows:rows.map(row=>({id:row.id,version:row.version,triage:classifyFinding(row.finding)}))}));
