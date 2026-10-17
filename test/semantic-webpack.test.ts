import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import {pathToFileURL} from 'node:url';
import path from 'node:path';
import {Detector,root} from '../src/detectors.js';
import {Scanner} from '../src/scanner.js';
import {analyzeModules,type SemanticView} from '../src/semantic.js';
import {parseStaticSource} from '../src/semantic-syntax.js';
import {scanWebpack} from '../src/semantic-webpack.js';
// 2.9.1 (G5F): webpack cross-module constant exports. Synthetic placeholder keys only; the only server is loopback.
const {token}=await import(pathToFileURL(path.join(root,'scripts/heldout-fixtures.mjs')).href);
const {g5Fixed}=await import(pathToFileURL(path.join(root,'scripts/eval-2.5-corpus.mjs')).href);
const d=new Detector('deliberately-unavailable');
const STEP='Webpack module export constant';
const chunk=(modules:string,name='webpackChunkapp')=>`(self.${name}=self.${name}||[]).push([[1],{${modules}}]);`;
const key=(label:string)=>{const value='sk-proj-'+token('webpack-'+label,64);return {value,head:JSON.stringify(value.slice(8,40)),rest:JSON.stringify(value.slice(40)),tail:JSON.stringify(value.slice(8))};};
async function views(texts:string[]):Promise<SemanticView[]>{return (await analyzeModules(texts.map((text,i)=>({url:'https://fixture.invalid/chunk'+i+'.js',text})))).views;}
const found=(list:SemanticView[],value:string)=>list.filter(v=>d.inspectSync(v.text).some(c=>c.value===value));
async function positive(value:string,texts:string[]){
 for(const text of texts)assert.ok(!d.direct(text).some(c=>c.value===value),'the split value is not directly visible');
 const hits=found(await views(texts),value);assert.ok(hits.length,'reconstructed across webpack modules');
 for(const v of hits){assert.ok(v.steps.includes(STEP),v.steps.join(','));assert.ok(v.constituents.length>=2);assert.ok(v.constituents.every(c=>texts.some(t=>t.slice(c.start,c.end)===c.representation)));}
}
async function negative(value:string,texts:string[],label:string){const list=await views(texts);assert.ok(!list.some(v=>v.text.includes(value)),label+': '+list.map(v=>v.text.slice(0,60)).join(' | '));}

test('webpack exports.x= assignments are read across module ids (CommonJS-style parameter names)',async()=>{
 const {value,tail}=key('cjs');
 await positive(value,[chunk(`101:function(module,exports){exports.prefix="sk-proj-"},102:function(module,exports,__webpack_require__){var apiKey=__webpack_require__(101).prefix+${tail};exports.client={apiKey:apiKey}}`)]);
});
test('webpack 5 __webpack_require__.d object getters and a require alias',async()=>{
 const {value,head,rest}=key('getters');
 await positive(value,[chunk(`201:(e,t,n)=>{"use strict";n.r(t);n.d(t,{HEAD:()=>r});const r="sk-proj-"},202:(e,t,n)=>{"use strict";n.r(t);n.d(t,{MID:()=>m});const m=${head}},203:(e,t,n)=>{"use strict";n.r(t);var o=n(201),p=n(202);const apiKey=o.HEAD+p.MID+${rest};console.log(apiKey)}`)]);
});
test('webpack 4 __webpack_require__.d(exports, name, getter) form',async()=>{
 const {value,tail}=key('webpack4');
 await positive(value,[chunk(`301:function(e,t,n){"use strict";n.r(t);n.d(t,"a",function(){return r});var r="sk-proj-"},302:function(e,t,n){"use strict";var i=n(301);var token=i.a+${tail};t.k=token}`)]);
});
test('ES-module re-exports between module-id factories (getter returning another module export)',async()=>{
 const {value,tail}=key('reexport');
 await positive(value,[chunk(`401:(e,t,n)=>{n.d(t,{A:()=>r});const r="sk-proj-"},402:(e,t,n)=>{n.d(t,{B:()=>o.A});var o=n(401)},403:(e,t,n)=>{var s=n(402);const secret=s.B+${tail};t.cfg={secret}}`)]);
});
test('string concatenation across imported constants: direct require reads and a template literal',async()=>{
 const {value,head,rest}=key('concat');
 await positive(value,[chunk(`501:function(e,t){t.p="sk-proj-"},502:function(e,t){t.h=${head}},503:function(e,t,n){var p=n(501).p,h=n(502).h,c=\`\${p}\${h}\${${rest}}\`;t.client={apiKey:c}}`)]);
});
test('G5F bundle: the split key is reconstructed, the mutated, test and publishable negatives are not',async()=>{
 const b=g5Fixed().bundle,r=await analyzeModules([{url:'https://fixture.invalid/'+b.name,text:b.text}],undefined,120000,{sliceMs:30000,memoryMb:256,maxMemoryMb:256});
 assert.equal(r.stats.outcome,'completed');assert.ok(!r.gaps.some(g=>/budget|limit|failure/.test(g.code)),r.gaps.map(g=>g.code).join(','));
 assert.ok(found(r.views,b.expected[0]).some(v=>v.steps.includes(STEP)));
 for(const n of b.negatives)assert.ok(!r.views.some(v=>v.text.includes(n)),'negative '+n.slice(0,8));
});
test('non-constant, dynamic and cross-chunk webpack values stay unknown',async()=>{
 const cases:[string,(k:ReturnType<typeof key>)=>string[]][]=[
  ['exporter local written in a nested function',k=>[chunk(`1:function(e,t){var b="sk-proj-";function x(){b="changed"}t.p=b},2:function(e,t,n){var c=n(1).p+${k.tail};t.c={apiKey:c}}`)]],
  ['export written twice',k=>[chunk(`1:function(e,t){t.p="sk-proj-";t.p="sk-proj-"},2:function(e,t,n){var c=n(1).p+${k.tail};t.c={apiKey:c}}`)]],
  ['export written conditionally',k=>[chunk(`1:function(e,t){if(Date.now()>0)t.p="sk-proj-"},2:function(e,t,n){var c=n(1).p+${k.tail};t.c={apiKey:c}}`)]],
  ['export written inside a function',k=>[chunk(`1:function(e,t){function s(){t.p="sk-proj-"}s()},2:function(e,t,n){var c=n(1).p+${k.tail};t.c={apiKey:c}}`)]],
  ['dynamic require elsewhere in the group',k=>[chunk(`1:function(e,t){t.p="sk-proj-"},2:function(e,t,n){var c=n(1).p+${k.tail};t.c={apiKey:c}},3:function(e,t,n){var id=location.hash;n(id)}`)]],
  ['require cache access',k=>[chunk(`1:function(e,t){t.p="sk-proj-"},2:function(e,t,n){var c=n(1).p+${k.tail};t.c={apiKey:c}},3:function(e,t,n){n.c[1].exports.p="other"}`)]],
  ['exporter in another chunk (not in the analysed group)',k=>[chunk(`1:function(e,t){t.p="sk-proj-"}`),chunk(`2:function(e,t,n){var c=n(1).p+${k.tail};t.c={apiKey:c}}`)]],
  ['exports object escapes to unknown code',k=>[chunk(`1:function(e,t){t.p="sk-proj-";register(t)},2:function(e,t,n){var c=n(1).p+${k.tail};t.c={apiKey:c}}`)]],
  ['module object used',k=>[chunk(`1:function(e,t){t.p="sk-proj-";e.exports=window.cfg},2:function(e,t,n){var c=n(1).p+${k.tail};t.c={apiKey:c}}`)]],
  ['another factory hands the exports to unknown code',k=>[chunk(`1:function(e,t){t.p="sk-proj-"},2:function(e,t,n){var c=n(1).p+${k.tail};t.c={apiKey:c}},3:function(e,t,n){patch(n(1))}`)]],
  ['another factory writes the export',k=>[chunk(`1:function(e,t){t.p="sk-proj-"},2:function(e,t,n){var c=n(1).p+${k.tail};t.c={apiKey:c}},3:function(e,t,n){n(1).p="sk-live-"}`)]],
  ['alias used as a value',k=>[chunk(`1:function(e,t){t.p="sk-proj-"},2:function(e,t,n){var o=n(1);use(o);var c=o.p+${k.tail};t.c={apiKey:c}}`)]],
  ['object export read through a property',k=>[chunk(`1:function(e,t){t.cfg={p:"sk-proj-"}},2:function(e,t,n){var c=n(1).cfg.p+${k.tail};t.c={apiKey:c}},3:function(e,t,n){var x=n(1).cfg;mutate(x)}`)]],
  ['execution-order cycle',k=>[chunk(`1:function(e,t,n){var q=n(2).c;t.p="sk-proj-"},2:function(e,t,n){var c=n(1).p+${k.tail};t.c=c}`)]],
  ['duplicate module ids',k=>[chunk(`1:function(e,t){t.p="sk-proj-"},1:function(e,t){t.p="other"},2:function(e,t,n){var c=n(1).p+${k.tail};t.c={apiKey:c}}`)]],
  ['duplicate module ids across pushes',k=>[chunk(`1:function(e,t){t.p="sk-proj-"},2:function(e,t,n){var c=n(1).p+${k.tail};t.c={apiKey:c}}`)+chunk(`1:function(e,t){t.p="other"}`)]],
  ['top-level return in the exporter',k=>[chunk(`1:(e,t,n)=>{n.d(t,{p:()=>r});if(Date.now()<0)return;const r="sk-proj-"},2:function(e,t,n){var c=n(1).p+${k.tail};t.c={apiKey:c}}`)]],
  ['getter with statements',k=>[chunk(`1:(e,t,n)=>{n.d(t,{p:()=>{tick();return r}});const r="sk-proj-"},2:function(e,t,n){var c=n(1).p+${k.tail};t.c={apiKey:c}}`)]],
  ['getter defined twice',k=>[chunk(`1:(e,t,n)=>{n.d(t,{p:()=>r});n.d(t,{p:()=>s});const r="sk-proj-",s="other"},2:function(e,t,n){var c=n(1).p+${k.tail};t.c={apiKey:c}}`)]],
  ['export assigned before its local is declared',k=>[chunk(`1:function(e,t){t.p=r;var r="sk-proj-"},2:function(e,t,n){var c=n(1).p+${k.tail};t.c={apiKey:c}}`)]],
  ['import read before its declarator runs',k=>[chunk(`1:function(e,t){t.p="sk-proj-"},2:function(e,t,n){var c=p+${k.tail};var p=n(1).p;t.c={apiKey:c}}`)]],
  ['require parameter shadowed',k=>[chunk(`1:function(e,t){t.p="sk-proj-"},2:function(e,t,n){var c=n(1).p+${k.tail};function g(n){return n}t.c={apiKey:c}}`)]],
  ['chunk global read outside its push',k=>[chunk(`1:function(e,t){t.p="sk-proj-"},2:function(e,t,n){var c=n(1).p+${k.tail};t.c={apiKey:c}}`)+'var q=self.webpackChunkapp;']],
  ['dynamic global access',k=>[chunk(`1:function(e,t){t.p="sk-proj-"},2:function(e,t,n){var c=n(1).p+${k.tail};t.c={apiKey:c}},3:function(e,t){self[e.id]=t}`)]],
  ['unknown value in the concatenation',k=>[chunk(`1:function(e,t){t.p="sk-proj-"},2:function(e,t,n){var c=n(1).p+getTail()+${k.tail};t.c={apiKey:c}}`)]],
 ];
 for(const [label,build] of cases){const k=key(label);await negative(k.value,build(k),label);}
});
test('factory-local values that never cross a module boundary keep the 2.9.0 behaviour (no new views)',async()=>{
 const {tail}=key('local');
 assert.deepEqual(await views([chunk(`1:function(e,t){var k="sk-proj-"+${tail};t.k=k;t.o={apiKey:k}},2:function(e,t,n){var o={v:"sk-proj-"+${tail}};t.v=o}`)]),[]);
});
test('webpack scan stops at its operation ceiling and then resolves nothing',()=>{
 const ast=parseStaticSource(chunk(`1:function(e,t){t.p="sk-proj-"},2:function(e,t,n){var c=n(1).p+"x";t.c=c}`),'unit');
 const done=scanWebpack([{url:'u',ast}],1e6,Date.now()+60000);assert.equal(done.outcome,'completed');assert.equal(done.registries[0].factories.size,2);assert.ok(done.registries[0].factories.get('2')!.edges.has('1'));
 const stopped=scanWebpack([{url:'u',ast}],10,Date.now()+60000);assert.equal(stopped.outcome,'ceiling');assert.deepEqual(stopped.registries,[]);
 assert.equal(scanWebpack([{url:'u',ast:parseStaticSource('const a=1;','unit')}],1e6,Date.now()+60000).outcome,'none');
});
test('loopback scan reports a key split across webpack modules once, as a static reconstruction',async()=>{
 const {value,head,rest}=key('loopback'),js=chunk(`11:function(e,t){t.p="sk-proj-"},12:function(e,t){t.h=${head}},13:function(e,t,n){var p=n(11).p,h=n(12).h,c=p+h+${rest};t.client={apiKey:c}}`);
 const server=http.createServer((req,res)=>{if(req.url==='/'){res.setHeader('content-type','text/html');res.end('<!doctype html><html><body><script src="/main.0a1b2c.js"></script></body></html>');}else if(req.url==='/main.0a1b2c.js'){res.setHeader('content-type','text/javascript');res.end(js);}else{res.statusCode=404;res.end('missing');}});
 await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));const origin='http://127.0.0.1:'+(server.address() as any).port;
 try{const s=new Scanner({urls:[origin],developmentFixtureOrigin:origin,requestsPerSecond:20,browser:false,adjacentMaps:false},{detector:d});await s.run();
  const hits=[...s.evidence.findings.values()].filter(f=>s.evidence.reveal(f.id).value===value);assert.equal(hits.length,1);}
 finally{server.close();}
});
