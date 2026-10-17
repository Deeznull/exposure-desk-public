import {writeFile,mkdir} from 'node:fs/promises';
import {pipelineSelfTest} from '../src/pipeline-self-test.js';
const result=await pipelineSelfTest();await mkdir('benchmarks',{recursive:true});await writeFile('benchmarks/pipeline-results.json',JSON.stringify(result,null,2));console.log(JSON.stringify({...result,results:undefined,scan:{state:result.scan.state,browser:result.scan.browser,limitations:result.scan.limitations}}));if(result.status!=='passed')process.exitCode=1;
