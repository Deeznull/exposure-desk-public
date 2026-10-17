import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import http from 'node:http';
import { Scanner } from '../src/scanner.js';
import { Detector } from '../src/detectors.js';
import { egressTripwire, virtualNetwork } from './virtual-network.js';
test('the egress tripwire refuses every non-loopback socket and DNS lookup while loopback fixtures keep working',async()=>{
  const trip=egressTripwire();try{assert.throws(()=>net.connect(443,'example.com'));assert.throws(()=>net.connect({host:'93.184.216.34',port:80}));const dns=await import('node:dns/promises');await assert.rejects(dns.lookup('example.com'));
    const server=http.createServer((_q,r)=>r.end('ok'));await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));const port=(server.address() as any).port;const body=await new Promise<string>((resolve,reject)=>{http.get({host:'127.0.0.1',port,path:'/'},res=>{let t='';res.on('data',c=>t+=c);res.on('end',()=>resolve(t));}).on('error',reject);});assert.equal(body,'ok');server.close();
    assert.deepEqual(trip.violations,['net.connect example.com','net.connect 93.184.216.34','dns.promises.lookup example.com']);
  }finally{trip.restore();}
});
test('virtual network: subdomains come only from references, private/metadata/mixed DNS and credential URLs never arrive, and the origin cap and per-origin budgets hold',{timeout:60000},async()=>{
  const trip=egressTripwire();const lookups:string[]=[];
  const dns:Record<string,{address:string;family:number}[]>={'internal.example.com':[{address:'10.0.0.5',family:4}],'meta.example.com':[{address:'169.254.169.254',family:4}],'mixed.example.com':[{address:'93.184.216.34',family:4},{address:'127.0.0.1',family:4}]};
  const resolver=async(host:string)=>{lookups.push(host);return dns[host]||[{address:'93.184.216.34',family:4}];};
  const links=['c1','c2','c3','c4','c5','c6'].map(n=>`<a href="https://${n}.example.com/">${n}</a>`).join('')+'<a href="https://internal.example.com/">i</a><a href="https://meta.example.com/">m</a><a href="https://mixed.example.com/">x</a><a href="https://user:pass@creds.example.com/">c</a><a href="https://example.com.evil.net/">deceptive</a><a href="https://notexample.com/">lookalike</a><script src="https://cdn.thirdparty.net/lib.js"></script>';
  const busy=Array.from({length:8},(_,i)=>`<a href="/p${i}">p${i}</a>`).join('');
  const hosts:Record<string,Record<string,{body:string}>>={'https://example.com':{'/':{body:links}},...Object.fromEntries(['c1','c2','c3','c4','c5','c6'].map(n=>[`https://${n}.example.com`,{'/':{body:busy}}]))};
  try{const s=new Scanner({urls:['https://example.com/'],domainScope:'registrable-domain',maxAutoDiscoveredOrigins:3,originMaxResources:3,semanticAnalysis:false,adjacentMaps:false,maxResources:120,maxDurationMs:20000,requestsPerSecond:20},{detector:new Detector('disabled'),resolver});
    const net=virtualNetwork(s,hosts);const v=await s.run();const contacted=new Set(net.arrivals.map(a=>new URL(a.url).origin));
    const admitted=(v.origins||[]).filter(o=>o.authorization?.type==='same-registrable-domain').map(o=>o.origin);assert.equal(admitted.length,3,'exactly the cap of automatically admitted origins');
    assert.ok(v.limitations.some(g=>g.code==='auto-origin-limit'&&(g.examples?.length||0)>0),'the cap is a visible gap with examples');
    for(const origin of admitted)assert.ok(net.arrivals.filter(a=>new URL(a.url).origin===origin).length<=3,'per-origin request ceiling for '+origin);
    for(const forbidden of ['https://internal.example.com','https://meta.example.com','https://mixed.example.com','https://creds.example.com','https://example.com.evil.net','https://notexample.com','https://cdn.thirdparty.net'])assert.ok(!contacted.has(forbidden),forbidden+' never arrives');
    const referenced=new Set(['example.com','c1.example.com','c2.example.com','c3.example.com','c4.example.com','c5.example.com','c6.example.com','internal.example.com','meta.example.com','mixed.example.com']);assert.ok(lookups.every(h=>referenced.has(h)),'no guessed hosts were resolved: '+[...new Set(lookups)].filter(h=>!referenced.has(h)).join(', '));
    assert.ok(!lookups.some(h=>/^(?:www|dev|staging|api|admin)\./.test(h)),'no subdomain enumeration');assert.deepEqual(trip.violations,[],'nothing reached the real network');
    s.dispose();
  }finally{trip.restore();}
});
