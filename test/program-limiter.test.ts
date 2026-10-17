import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { ProgramLimiter, programLimiter, FairTurns } from '../src/program/limiter.js';
import { Transport } from '../src/transport.js';
import { makeConfig } from '../src/config.js';
import { Evidence } from '../src/evidence.js';
import { Detector } from '../src/detectors.js';
import { programFromJson, PROGRAM_SCHEMA } from '../src/program/settings.js';
/** 2.8 program-wide limiter (w1-scope): rate and concurrency across every transport of one program, with wait statistics. Loopback fixtures only. */

test('limiter: concurrency gate, rate slots and wait statistics (virtual clock)',()=>{
  let now=0;const l=new ProgramLimiter('p',2,2,()=>now),waits:number[]=[];l.onWait=ms=>waits.push(ms);
  assert.equal(l.delay(),0);const a={},b={},c={};l.acquire(a);
  assert.equal(l.delay(),500,'2 per second: the next slot is 500 ms later');now=500;assert.equal(l.delay(),0);l.acquire(b);
  assert.equal(l.delay(),Infinity,'two in flight: wait for a release');let woke=0;l.hold(c,()=>woke++);l.hold(c,()=>woke++);
  now=1200;l.release();assert.equal(woke,2,'every waiter is woken once');assert.equal(l.delay(),0);l.acquire(c);
  assert.deepEqual(waits,[700]);l.release();l.release();l.release();
  assert.deepEqual(l.stats(),{requestsPerSecond:2,concurrency:2,active:0,peakActive:2,granted:3,waits:1,waitMs:700,maxWaitMs:700});
  const d={};l.hold(d);l.forget(d);now=5000;l.acquire(d);assert.equal(l.stats().waits,2);assert.equal(l.stats().waitMs,700,'a forgotten hold adds no wait time');
  assert.throws(()=>new ProgramLimiter('p',0,1),/Invalid program limits/);assert.throws(()=>new ProgramLimiter('p',1,0),/Invalid program limits/);
});

test('limiter registry: one limiter per program and limits in this process',()=>{
  const p={id:'0123456789abcdef',requestsPerSecond:5,concurrency:{targets:4,requests:16}};
  assert.equal(programLimiter(p),programLimiter({...p}));assert.notEqual(programLimiter(p),programLimiter({...p,requestsPerSecond:6}));assert.notEqual(programLimiter(p),programLimiter({...p,id:'fedcba9876543210'}));
});

test('transports of one program share its limit: requests across two websites never exceed the program concurrency and rate',{timeout:120000},async()=>{
  let active=0,peak=0;const starts:number[]=[];
  const server=http.createServer((req,res)=>{active++;peak=Math.max(peak,active);starts.push(performance.now());setTimeout(()=>{active--;res.setHeader('content-type','text/plain');res.end('ok '+req.url);},60);});
  await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));const origin='http://127.0.0.1:'+(server.address() as any).port;
  try{
    const program=programFromJson({schema:PROGRAM_SCHEMA,scope:{in:['127.0.0.1']},rate:{requestsPerSecond:20},concurrency:{targets:2,requests:2}},'program-limiter-'+process.pid).config;
    const make=()=>new Transport(makeConfig({urls:[origin+'/'],developmentFixtureOrigin:origin,program,globalConcurrency:8,originConcurrency:8,originRequestsPerSecond:20}),new Evidence(new Detector('disabled')),()=>{},()=>{});
    const t1=make(),t2=make();assert.equal(t1.program,t2.program,'one shared limiter');
    const results=await Promise.all([...Array.from({length:6},(_,i)=>t1.get(`${origin}/a${i}`)),...Array.from({length:6},(_,i)=>t2.get(`${origin}/b${i}`))]);
    assert.equal(results.length,12);assert.ok(peak<=2,`program concurrency respected (peak ${peak})`);
    const stats=t1.program!.stats();assert.equal(stats.granted,12);assert.equal(stats.active,0);assert.ok(stats.peakActive<=2);assert.ok(stats.waits>0,'some requests waited for the program limit');
    // 12 grants at 20 per second need at least 11 × 50 ms between the first and the last start.
    assert.ok(starts[starts.length-1]!-starts[0]!>=11*50-20,`rate respected (${Math.round(starts[starts.length-1]!-starts[0]!)} ms)`);
    assert.deepEqual(Object.keys(t1.coordinator().program!).sort(),['active','concurrency','granted','maxWaitMs','peakActive','requestsPerSecond','waitMs','waits']);
  }finally{await new Promise<void>(r=>{server.close(()=>r());server.closeAllConnections();});}
});

test('limiter: a wait is caused by other owners at the concurrency limit while another owner has a request in flight, and at the rate limit when another owner had the latest grant (w5-fix)',()=>{
  let now=0;const l=new ProgramLimiter('p',2,2,()=>now),a={},b={};
  assert.equal(l.heldByOthers(a),false,'no grant yet');
  l.acquire({},a);assert.equal(l.delay(),500);assert.equal(l.heldByOthers(a),false,'a wait after its own grant is the owner\'s own pacing');assert.equal(l.heldByOthers(b),true);
  now=500;l.acquire({},b);assert.equal(l.delay(),Infinity);assert.equal(l.heldByOthers(a),true,'b holds a slot');assert.equal(l.heldByOthers(b),true,'a holds a slot');
  l.release(a);assert.equal(l.delay(),500);assert.equal(l.heldByOthers(a),true,'b had the latest grant');assert.equal(l.heldByOthers(b),false);
  now=1000;l.acquire({},a);l.release(b);l.release(a);assert.equal(l.stats().active,0);
  const one=new ProgramLimiter('q',50,1,()=>now);one.acquire({},a);assert.equal(one.delay(),Infinity);
  assert.equal(one.heldByOthers(a),false,'only its own request is in flight');assert.equal(one.heldByOthers(b),true);
  one.release(a);now=2000;assert.equal(one.delay(),0);one.acquire();one.release();assert.equal(one.heldByOthers(b),false,'an acquire without an owner (outside a transport) is no other owner\'s grant');
});

test('program slots are shared in turn between targets: one target never takes a further slot while another target that waits has fewer (O2, 2.9)',{timeout:120000},async()=>{
  // 24 targets (one transport each) want 6 requests apiece; the program allows 50 per second. Each target's own pacing (20 per second) never binds before its turn comes
  // round again (24 targets at 50 per second is about 480 ms a round), so a fair limiter gives every target its n-th slot before any target gets its (n+2)-th.
  const order:string[]=[];
  const server=http.createServer((req,res)=>{order.push(req.url!.split('/')[1]!);setTimeout(()=>{res.setHeader('content-type','text/plain');res.end('ok');},20);});
  await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));const origin='http://127.0.0.1:'+(server.address() as any).port;
  try{
    const program=programFromJson({schema:PROGRAM_SCHEMA,scope:{in:['127.0.0.1']},rate:{requestsPerSecond:50},concurrency:{targets:24,requests:64}},'program-fair-'+process.pid).config;
    const targets=Array.from({length:24},(_,i)=>({key:'t'+i,transport:new Transport(makeConfig({urls:[origin+'/'],developmentFixtureOrigin:origin,program,globalConcurrency:8,originConcurrency:8,originRequestsPerSecond:20}),new Evidence(new Detector('disabled')),()=>{},()=>{})}));
    await Promise.all(targets.flatMap(({key,transport})=>Array.from({length:6},(_,i)=>transport.get(`${origin}/${key}/${i}`))));
    assert.equal(order.length,144);
    const counts=new Map(targets.map(t=>[t.key,0]));let worst=0,at=-1;
    for(const [i,key] of order.entries()){counts.set(key,counts.get(key)!+1);const open=[...counts.values()].filter(n=>n<6),spread=open.length?Math.max(...counts.values())-Math.min(...open):0;if(spread>worst){worst=spread;at=i;}}
    assert.ok(worst<=2,`a target took a further program slot while another waiting target had ${worst} fewer (at start ${at}): ${order.join(' ')}`);
    const stats=targets[0]!.transport.program!.stats();assert.equal(stats.granted,144);assert.equal(stats.active,0);
  }finally{await new Promise<void>(r=>{server.close(()=>r());server.closeAllConnections();});}
});

test('limiter: held targets get their turn first in, first out; a woken target with nothing ready loses its place; leave passes the turn on (virtual clock, O2, 2.9)',()=>{
  let now=0;const l=new ProgramLimiter('fair-q',1000,1,()=>now),order:string[]=[];
  const A={},B={},C={},D={},E={};
  const turn=(name:string,owner:object,go:boolean)=>()=>{order.push(name);if(go&&l.delay(owner)===0)l.acquire({},owner);};
  assert.equal(l.delay(A),0);l.acquire({},A);
  assert.equal(l.delay(B),Infinity,'concurrency 1 reached');
  l.hold({},turn('B',B,true),B);l.hold({},turn('C',C,false),C);l.hold({},turn('D',D,true),D);
  assert.equal(l.delay(D),Infinity,'others wait ahead of D');
  assert.equal(l.heldByOthers(D),true,'A has a request in flight');
  now=10;l.release(A);assert.deepEqual(order,['B'],'only the head is woken, and it takes the slot');
  now=20;l.release(B);assert.deepEqual(order,['B','C','D'],'C had nothing ready: it lost its place and D got the slot in the same turn');
  l.hold({},turn('E',E,true),E);l.hold({},turn('B2',B,true),B);l.leave(E);
  now=30;l.release(D);assert.deepEqual(order,['B','C','D','B2'],'E left the queue, so the turn passed on to B');
  now=40;l.release(B);assert.equal(l.stats().active,0);assert.equal(l.stats().granted,4);
  // Rate limit, not concurrency: the queue order decides who is held by others, and the one timer is cleared when the queue empties.
  now=0;const r=new ProgramLimiter('fair-r',1,10,()=>now),seen:string[]=[];
  r.acquire({},A);r.hold({},()=>{seen.push('B');if(r.delay(B)===0)r.acquire({},B);},B);r.hold({},()=>seen.push('C'),C);
  assert.equal(r.delay(B),1000);assert.equal(r.delay(C),Infinity,'B waits ahead of C');
  assert.equal(r.heldByOthers(C),true,'B is ahead of C');assert.equal(r.heldByOthers(A),true,'A has no place yet while B and C wait');
  assert.equal(r.heldByOthers(B),true,'the latest grant went to A');
  now=1000;r.leave(C);assert.deepEqual(seen,['B'],'the next slot went to B');
  assert.equal(r.heldByOthers(B),false,'after its own grant with nobody waiting, B paces itself');
  r.release(A);r.release(B);assert.equal(r.stats().active,0);
});

test('fair turns: one place per owner, first in first out; a later owner is not stuck behind an earlier owner\'s backlog; cancel and release (2.9.1)',async()=>{
  const t=new FairTurns(1),A={},B={},C={},order:string[]=[];const releases:(()=>void)[]=[];
  const take=(name:string,owner:object,signal?:AbortSignal)=>t.take(owner,signal,()=>new Error('cancelled '+name)).then(release=>{order.push(name);releases.push(release);});
  assert.equal(t.free(A),true);
  const a1=take('A1',A);await a1;assert.equal(t.free(A),false,'the one turn is taken');assert.equal(t.free(B),false);
  const pending=[take('A2',A),take('A3',A),take('A4',A)];
  pending.push(take('B1',B));const cancel=new AbortController(),c1=take('C1',C,cancel.signal).catch(e=>order.push(String(e.message)));pending.push(take('C2',C));
  await new Promise(r=>setImmediate(r));assert.deepEqual(order,['A1']);
  cancel.abort();await c1;assert.deepEqual(order,['A1','cancelled C1'],'a cancelled wait leaves the queue; the owner keeps its place for its other call');
  for(let i=0;i<5;i++){const r=releases.shift()!;r();r();await new Promise(res=>setImmediate(res));}
  await Promise.all(pending);
  assert.deepEqual(order,['A1','cancelled C1','A2','B1','C2','A3','A4'],'the turns go round the waiting owners (B and C do not wait behind all of A\'s calls)');
  releases.shift()!();assert.equal(t.free(A),true);
  const s=t.stats();assert.equal(s.active,0);assert.equal(s.granted,6);assert.equal(s.peakActive,1);
  // An already cancelled call never queues.
  const done=new AbortController();done.abort();await assert.rejects(t.take(B,done.signal,()=>new Error('pre-cancelled')),/pre-cancelled/);assert.equal(t.free(B),true);
  // Capacity 2: two owners go at once, a third waits for a release.
  const u=new FairTurns(2),r1=await u.take(A),r2=await u.take(B);let third=false;const p3=u.take(C).then(r=>{third=true;return r;});
  await new Promise(r=>setImmediate(r));assert.equal(third,false);r1();(await p3)();r2();assert.equal(u.stats().active,0);
});
