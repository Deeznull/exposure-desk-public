import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createHash } from 'node:crypto';
import { Scanner } from '../src/scanner.js';
import { Detector } from '../src/detectors.js';
/**
 * w2-wire: with a real browser, recon captures the runtime URLs and JavaScript the page loads at runtime, classifies the loopback host
 * in scope, and still never records a credential value. Loopback fixture and a synthetic, nonfunctional key only.
 */
const K='sk-proj-'+createHash('sha512').update('recon-wire-browser').digest('base64url').slice(0,64).replace(/[-_]/g,'A');

test('browser recon: runtime-loaded URLs and scripts are listed, the loopback host is in scope, and no value is recorded',{timeout:120000},async()=>{
  const shell='<!doctype html><html><head><title>App</title></head><body><div id="app"></div><script src="/runtime.js"></script></body></html>';
  const server=http.createServer((req,res)=>{const p=(req.url||'/').split('?')[0]!;
    if(p==='/runtime.js'){res.setHeader('content-type','text/javascript');res.end(`const apiKey=${JSON.stringify(K)};fetch('/api/runtime?token=opaque').catch(()=>{});`);return;}
    if(p==='/api/runtime'){res.setHeader('content-type','application/json');res.end('{"ok":true}');return;}
    if(p==='/robots.txt'){res.setHeader('content-type','text/plain');res.end('User-agent: *\nAllow: /\n');return;}
    res.setHeader('content-type','text/html');res.end(shell);});
  await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));const origin=`http://127.0.0.1:${(server.address() as any).port}`;
  try{
    const s=new Scanner({urls:[origin+'/'],developmentFixtureOrigin:origin,browser:true,browserPages:2,browserSettleMs:200,browserBaselineMs:100,requestsPerSecond:20,adjacentMaps:false,maxDurationMs:90000,timeoutMs:5000,maxRetries:0,semanticAnalysis:false},{detector:new Detector('disabled'),recon:{}});
    await s.init();// builds the recon collector (run() alone does not)
    const v=await s.run();
    assert.equal(v.browserStatus!.launch,true,'Chromium must actually run');
    const recon=s.recon!.result();
    const urls=recon.lists.urls.map(i=>i.value),js=recon.lists.js.map(i=>i.value),hosts=recon.lists.hosts;
    assert.ok(js.some(u=>u.endsWith('/runtime.js')),'the runtime script is listed under js: '+js.join(','));
    assert.ok(urls.some(u=>u.includes('/api/runtime')),'the runtime fetch URL is listed: '+urls.join(','));
    assert.ok(hosts.some(h=>h.value==='127.0.0.1'&&h.scope==='in-scope'),'the loopback host is in scope');
    const blob=JSON.stringify(recon);for(const part of [K,K.slice(8,40),K.slice(-24)])assert.ok(!blob.includes(part),'recon lists must not contain a value');
    console.log(JSON.stringify({reconBrowser:{urls:urls.length,js:js.length,endpoints:recon.counts.endpoints,hosts:hosts.length}}));
    s.dispose();
  }finally{await new Promise<void>(r=>{server.close(()=>r());server.closeAllConnections();});}
});
