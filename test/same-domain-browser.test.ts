import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {Scanner} from '../src/scanner.js';
import {Detector} from '../src/detectors.js';
test('actual browser discovery with automatic scope cannot authorize private DNS, credentials or unrelated redirects',{timeout:30000},async()=>{
  const arrivals:string[]=[],dns:string[]=[];let origin='',port=0;
  const server=http.createServer((req,res)=>{
    arrivals.push(req.headers.host+req.url!);
    if(req.url==='/'){
      res.setHeader('content-type','text/html');res.end(`<html><script>
        fetch('http://api.example.com:${port}/private');
        new WebSocket('ws://socket.example.com:${port}/events');
        fetch('/redirect');
        window.RuntimeConfig={endpoint:'http://config.example.com:${port}/configuration'};
      </script><script src="http://unsafe.example.com:${port}/app.js?api_key=private"></script></html>`);
    }else if(req.url==='/redirect'){res.writeHead(302,{location:`http://unrelated.com:${port}/destination`});res.end();}
    else if(req.url==='/robots.txt'){res.end('User-agent: *');}
    else{res.statusCode=404;res.end('missing');}
  });await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));port=(server.address() as any).port;origin=`http://example.com:${port}`;
  const s=new Scanner({urls:[origin],privateOrigins:[origin,`http://api.example.com:${port}`,`http://config.example.com:${port}`],sameRegistrableDomainDiscovery:true,browser:true,browserPages:1,browserSettleMs:30,semanticAnalysis:false,adjacentMaps:false,maxRetries:0,requestsPerSecond:20,maxDurationMs:20000,timeoutMs:1000},{detector:new Detector('disabled'),resolver:async host=>{dns.push(host);return [{address:'127.0.0.1',family:4}];}});
  try{
    const view=await s.run();assert.equal(view.browserStatus!.launch,true);assert.equal(view.browserStatus!.runtimePages,1);
    assert.equal(view.origins!.filter(o=>o.authorization?.type==='same-registrable-domain').length,0);
    assert.ok(s.resources.some(r=>r.reason==='private-address'&&r.url.includes('api.example.com')));
    assert.ok(s.resources.some(r=>r.reason==='private-address'&&r.url.includes('config.example.com')));
    assert.ok(view.resources.some(r=>r.reason==='websocket-disabled'));
    assert.ok(view.resources.some(r=>r.reason==='credential-in-request'&&r.url.includes('unsafe.example.com')));
    assert.ok(view.resources.some(r=>r.reason==='scope'&&r.url.includes('unrelated.com')));
    assert.ok(!dns.includes('unsafe.example.com')&&!dns.includes('unrelated.com'));
    assert.ok(arrivals.every(a=>a.startsWith('example.com:')),'Only the explicitly authorized seed receives network traffic');
    assert.ok(!arrivals.some(a=>a.includes('/private')||a.includes('/destination')||a.includes('/events')||a.includes('/configuration')));
  }finally{s.dispose();await new Promise<void>(r=>{server.close(()=>r());server.closeAllConnections();});}
});
