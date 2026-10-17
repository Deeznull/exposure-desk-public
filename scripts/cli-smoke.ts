import { spawn } from 'node:child_process';
import { writeFile, readFile, rm } from 'node:fs/promises';
import path from 'node:path';
import assert from 'node:assert/strict';
import { createFixture, synthetic } from '../src/fixture.js';
import { privateDirectory } from '../src/local-files.js';
import { root } from '../src/detectors.js';
const fixture=await createFixture(0,{minimalDiscovery:true}),dir=await privateDirectory('cli-fixture-',true);
try{
  const cases=[{name:'clean',target:'/clean',expected:0,full:false},{name:'policy',target:'/.env',expected:1,full:false},{name:'incomplete',target:'/big',expected:2,full:false},{name:'full-export',target:'/.env',expected:1,full:true}];
  for(const c of cases){
    const config=path.join(dir,c.name+'.json'),output=path.join(dir,c.name+'.report.json');
    await writeFile(config,JSON.stringify({name:'Synthetic CLI test',urls:[fixture.origin+c.target],developmentFixtureOrigin:fixture.origin,requestsPerSecond:20,adjacentMaps:false,maxResourceBytes:2048,maxTotalBytes:8192}),{mode:0o600});
    const code=await new Promise<number>(resolve=>{const child=spawn(process.execPath,[path.join(root,'dist/src/cli.js'),'scan','--config',config,'--output',output,...(c.full?['--full-secrets']:[])],{stdio:'inherit',windowsHide:true});child.on('error',()=>resolve(2));child.on('close',code=>resolve(code??2));});
    assert.ok(code===c.expected,`CLI ${c.name} returned wrong exit state`);const text=await readFile(output,'utf8');assert.ok(c.full?text.includes(synthetic.openai):!text.includes(synthetic.openai),`CLI ${c.name} value handling failed`);console.log(`CLI smoke ${c.name}: passed (exit ${code}).`);
  }
}finally{await fixture.close();await rm(dir,{recursive:true,force:true});}
