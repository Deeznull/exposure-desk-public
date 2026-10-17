import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {createHash} from 'node:crypto';
import {Scanner} from '../src/scanner.js';
import {Detector} from '../src/detectors.js';
const key=(name:string)=>'sk-proj-'+createHash('sha512').update('browser-discovery-'+name).digest('base64url').slice(0,64).replace(/[-_]/g,'A');
test('repeated identical browser content is reused with distinct provenance; large routed scripts are verified as mirrors by hash; unique generated code still records the capture gap',{timeout:120000},async()=>{
  const arrivals:string[]=[],generated=key('generated'),big='/*'+'b'.repeat(300000)+'*/const bigKey="'+key('big')+'";',codes=(s:string)=>JSON.stringify([...s].map(c=>c.charCodeAt(0)));
  const shell=(route:string)=>'<!doctype html><html><head><title>App</title></head><body><div id="app">'+route+'</div><script src="/app.js"></script><script src="/big.js"></script><script>const e=".json",w=".woff";(0,eval)("void "+JSON.stringify(String.fromCharCode(...'+codes(generated)+')));(0,eval)("/*"+"u".repeat(200000)+"*/void 0");</script></body></html>';
  const server=http.createServer((req,res)=>{arrivals.push(req.url!);const p=req.url!;if(p==='/app.js'){res.setHeader('content-type','text/javascript');res.end('const t=".json";fetch("/data.json").catch(()=>{});');}else if(p==='/big.js'){res.setHeader('content-type','text/javascript');res.end(big);}else if(p==='/data.json'){res.setHeader('content-type','application/json');res.end('{"ok":true}');}else if(p==='/robots.txt'){res.end('User-agent: *');}else{res.setHeader('content-type','text/html');res.end(shell(p));}});
  await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));const origin=`http://127.0.0.1:${(server.address() as any).port}`;
  try{const s=new Scanner({urls:[origin],developmentFixtureOrigin:origin,browser:true,browserPages:3,browserNavigationUrls:[origin+'/a',origin+'/b'],browserSettleMs:200,browserBaselineMs:100,requestsPerSecond:20,adjacentMaps:false,maxDurationMs:90000,timeoutMs:5000,maxRetries:0,semanticAnalysis:false},{detector:new Detector('disabled')});const v=await s.run();
    assert.equal(v.browserStatus!.launch,true,'Chromium must actually run');assert.equal(v.browserStatus!.runtimePages,3,'navigations equal the explicit routes plus the seed');
    assert.ok(!arrivals.some(u=>u==='/.json'||u==='/.woff'),'bare literals in routed and captured scripts never become requests');assert.ok(arrivals.includes('/data.json'));
    assert.ok(v.accounting!.reusedDiscoveries!>0,'identical shells and scripts hit the discovery cache');assert.ok(s.browserAnalysis.reusedDebugger>0,'identical captures across sessions are reused');
    const captures=v.resources.filter(r=>r.kind==='runtime-capture');const hashes=captures.map(r=>r.contentHash);assert.equal(new Set(hashes).size,hashes.length,'one runtime-capture row per content hash');assert.ok(captures.some(r=>(r.discoveryCount||0)>=2&&(r.examples||[]).length>=2),'repeated captures add owner provenance to the canonical record');
    assert.ok([...s.evidence.findings.values()].some(f=>s.evidence.reveal(f.id).value===generated));
    const document=v.resources.find(r=>r.url===origin+'/'&&r.kind==='browser'&&r.provenance?.resourceType==='document')!;assert.ok(document);assert.equal(document.analyzers?.semantic,undefined,'the page URL is never a module key for captured scripts');
    assert.ok(v.accounting!.verifiedMirrors!>0,'a large routed script is verified as a debugger mirror by content hash');assert.ok(!v.limitations.some(g=>g.code==='debugger-script-size'&&/verified|big\.js/.test(g.detail)));assert.ok(v.limitations.some(g=>g.code==='debugger-script-size'),'unique oversized generated code still records the capture gap');
    assert.ok(s.browserAnalysis.ownedHelpers>0,'scanner-authored helpers are excluded from captures');console.log(JSON.stringify({discoveryBrowser:{reusedDiscoveries:v.accounting!.reusedDiscoveries,reusedDebugger:s.browserAnalysis.reusedDebugger,verifiedMirrors:v.accounting!.verifiedMirrors,captures:captures.length,requests:v.accounting!.networkAttempts}}));s.dispose();
  }finally{await new Promise<void>(r=>{server.close(()=>r());server.closeAllConnections();});}
});
