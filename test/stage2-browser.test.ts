import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {Scanner} from '../src/scanner.js';
import {Detector,root} from '../src/detectors.js';
const {heldoutServer}=await import(pathToFileURL(path.join(root,'scripts/heldout-fixtures.mjs')).href);
test('held-out debugger, blocked request and late JSON fixtures prove their acquisition path by ablation',async()=>{
 const server=await heldoutServer();const measurements=[];
 try{for(const mode of ['enabled','no-debugger','no-browser']){
  const d=new Detector('deliberately-unavailable'),s=new Scanner({urls:[server.origin],developmentFixtureOrigin:server.origin,requestsPerSecond:20,browser:mode!=='no-browser',debuggerScripts:mode!=='no-debugger',browserSettleMs:350,adjacentMaps:false,maxDurationMs:40000,maxResources:150},{detector:d});
  const start=Date.now(),v=await s.run();if(mode!=='no-browser')assert.ok(v.browserStatus?.launch&&v.browserStatus.runtimePages>0,'Actual isolated browser required');
  for(const [id,disabled]of [['debugger-only','no-debugger'],['blocked-request-only','no-browser'],['late-application-json','no-browser']]){const expected=server.expected.find((x:any)=>x.id===id),found=[...s.evidence.findings.values()].find(f=>s.evidence.reveal(f.id).value===expected.value);assert.equal(!!found,mode!=='no-browser'&&mode!==disabled,id+' '+mode);if(found&&id==='blocked-request-only')assert.ok(found.occurrences.some(o=>o.exposure==='blocked-candidate'));if(found&&id==='debugger-only')assert.ok(found.occurrences.some(o=>o.exposure==='runtime-memory'&&o.sourceLabel?.includes('debugger')));}
  assert.ok(!server.arrivals.includes('/never-arrive'),'Credential candidate never transmitted');for(const row of server.expected.filter((x:any)=>/debugger|browser-request/.test(x.mechanism)))assert.ok(!JSON.stringify(v).includes(row.value));measurements.push({mode,elapsedMs:Date.now()-start,resources:v.counts.resources,state:v.state,gaps:v.limitations.map(g=>g.code)});s.dispose();
  if(mode!=='no-browser')assert.ok(v.discoveryGraph!.edges.some(e=>e.kind==='browser-request'&&e.to?.endsWith('/runtime-json')),'Observed application JSON has a request discovery edge');
 }console.log(JSON.stringify({stage2BrowserAblations:measurements}));}finally{await server.close();}
});
