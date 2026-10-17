import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import path from 'node:path';
import { mkdir, mkdtemp, readFile, readdir, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { root } from '../src/detectors.js';
import { ScopePolicy } from '../src/domain-scope.js';
import { ReconCollector, scopeFromPolicy, writeRecon, RECON_FILES, ReconOutputError, SourceRebuilder, type ReconResult, type ScopeClassifier } from '../src/recon/index.js';
const fixtures=path.join(root,'test','fixtures','recon');
const fixture=(name:string)=>readFileSync(path.join(fixtures,name),'utf8');
const base=process.env.EXPOSURE_DATA_DIR||path.join(root,'.cache');
async function tempDir(){await mkdir(base,{recursive:true});return mkdtemp(path.join(base,'recon-test-'));}
const shopScope:ScopeClassifier=u=>{const h=new URL(u).hostname;return h==='shop.example'||h.endsWith('.shop.example')?{scope:'in-scope',reason:'in-domain'}:h.endsWith('.vendor.example')?{scope:'third-party',reason:'third-party'}:{scope:'out-of-scope',reason:'no-public-suffix'};};
const fixedNow=()=>new Date('2026-10-10T00:00:00.000Z');
function feedFixtures(c:ReconCollector,o='https://shop.example'){
  c.add({url:o+'/',kind:'page',contentType:'text/html',text:fixture('shop.html')});
  c.add({url:o+'/static/app.js?v=42',kind:'script',contentType:'application/javascript',text:fixture('app.js')});
  c.add({url:o+'/robots.txt',kind:'robots',contentType:'text/plain',text:fixture('robots.txt')});
  c.add({url:o+'/sitemap.xml',kind:'sitemap',contentType:'application/xml',text:fixture('sitemap.xml')});
  c.add({url:o+'/static/site.css',kind:'css',contentType:'text/css',text:fixture('site.css')});
  c.add({url:o+'/static/app.js.map',kind:'map',contentType:'application/json',text:fixture('app.js.map')});
}
const values=(r:ReconResult,list:keyof ReconResult['lists'])=>r.lists[list].map(i=>i.value);

test('fixture site: every list is filled, deduplicated, sorted and value-free',()=>{
  const c=new ReconCollector({classify:shopScope,now:fixedNow});feedFixtures(c);feedFixtures(c);
  const r=c.result();
  assert.equal(r.schema,'exposure-recon/1');assert.equal(r.generatedAt,'2026-10-10T00:00:00.000Z');
  for(const list of Object.keys(r.lists) as (keyof ReconResult['lists'])[]){const v=values(r,list);assert.deepEqual(v,[...new Set(v)].sort((a,b)=>a<b?-1:a>b?1:0),list+' sorted and unique');assert.equal(r.counts[list],v.length);}
  for(const u of ['https://shop.example/account/settings?tab','https://shop.example/login?next','https://help.shop.example/articles/returns?ref','https://images.shop.example/logo.png','https://shop.example/products/red-mug?color&size','https://shop.example/static/theme.css','wss://realtime.shop.example/socket','https://telemetry.vendor.example/collect?app','https://legacy.shop.example/old/api'])assert.ok(values(r,'urls').includes(u),u);
  assert.ok(!values(r,'urls').some(u=>/#|=|sitemaps\.org|^mailto|^javascript|^data:/.test(u)),'no fragments, values, namespaces or non-http schemes');
  for(const e of ['/admin/','/internal/reports','/public/','/api/v1/cart','/api/v2/inventory','/api/v2/orders','/api/v2/products/{EXPR}/reviews','/api/v2/profile/avatar','/checkout/:step','/graphql','/orders/:id/invoice','/products/:slug','/search','/login','/socket','/v2'])assert.ok(values(r,'endpoints').includes(e),e);
  assert.ok(!values(r,'endpoints').includes('/collect'),'paths of third-party call sites are not endpoints');
  assert.ok(!values(r,'endpoints').some(e=>/\.(?:png|woff2|webp)$|^M\d/.test(e)),'static assets and SVG paths are not endpoints');
  for(const p of ['q','category','go','email','password','note','tab','next','ref','v','color','size','page','per_page','sort','filter[brand]','limit','warehouse','include_archived','app','session'])assert.ok(values(r,'parameters').includes(p),p);
  assert.deepEqual(values(r,'js'),['https://cdn.vendor.example/lib/widget.min.js','https://shop.example/static/app.js']);
  assert.deepEqual(values(r,'sourcemaps'),['https://shop.example/static/app.js.map','https://shop.example/static/site.css.map']);
  assert.deepEqual(values(r,'graphql'),['endpoint /graphql','mutation AddToCart','operation GetProduct','query GetProduct']);
  assert.deepEqual(r.lists.graphql.find(g=>g.value==='query GetProduct'),{value:'query GetProduct',source:'https://shop.example/static/app.js?v',type:'query',name:'GetProduct'});
  const hosts=Object.fromEntries(r.lists.hosts.map(h=>[h.value,h.scope]));
  assert.deepEqual(hosts,{'api.shop.example':'in-scope','assets.shop.example':'in-scope','cdn.vendor.example':'third-party','fonts.vendor.example':'third-party','help.shop.example':'in-scope','images.shop.example':'in-scope','legacy.shop.example':'in-scope','realtime.shop.example':'in-scope','shop.example':'in-scope','telemetry.vendor.example':'third-party'});
  assert.deepEqual(r.resources,{seen:12,scanned:10,skipped:0,truncated:0,maps:2});
});
test('provenance is the first cleaned source URL; source-map and embedded-source labels are cleaned too',()=>{
  const c=new ReconCollector({classify:shopScope});
  c.add({url:'https://shop.example/a.js?build=abc#x',kind:'script',text:'fetch("/api/one")'});
  c.add({url:'https://shop.example/b.js',kind:'script',text:'fetch("/api/one");fetch("/api/two")'});
  c.add({url:'webpack:///./src/c.ts?query=1',kind:'source',text:'fetch("/api/three")'});
  const by=Object.fromEntries(c.result().lists.endpoints.map(e=>[e.value,e.source]));
  assert.deepEqual(by,{'/api/one':'https://shop.example/a.js?build','/api/two':'https://shop.example/b.js','/api/three':'webpack:///./src/c.ts?query'});
});
test('bare host literals are listed only for the scanned site; resource hosts are always classified',()=>{
  const c=new ReconCollector({classify:u=>{const h=new URL(u).hostname;return h==='shop.example'?'in-scope':h==='www.shop.example'?{scope:'out-of-scope',reason:'exact-origin-mode'}:h==='deep.other.shop.example'?{scope:'out-of-scope',reason:'outside-host-subtree'}:{scope:'third-party',reason:'third-party'};}});
  c.add({url:'https://shop.example/a.js',kind:'script',text:'const a="www.shop.example",b="deep.other.shop.example",c="cdn.vendor.example",d="e.target",e="shop.example";'});
  const hosts=Object.fromEntries(c.result().lists.hosts.map(h=>[h.value,[h.scope,h.reason]]));
  assert.deepEqual(hosts,{'deep.other.shop.example':['out-of-scope','outside-host-subtree'],'shop.example':['in-scope',undefined],'www.shop.example':['out-of-scope','exact-origin-mode']});
});
test('a host seen over several origins takes its most permissive verdict; a throwing classifier fails closed',()=>{
  const c=new ReconCollector({classify:u=>new URL(u).protocol==='https:'?'in-scope':{scope:'out-of-scope',reason:'exact-origin-mode'}});
  c.add({url:'http://shop.example/',kind:'page',contentType:'text/html',text:'<a href="https://shop.example/x">x</a>'});
  assert.deepEqual(c.result().lists.hosts.map(h=>[h.value,h.scope,h.reason]),[['shop.example','in-scope',undefined]]);
  const bad=new ReconCollector({classify:()=>{throw new Error('boom');}});
  bad.add({url:'https://shop.example/',kind:'page',contentType:'text/html',text:''});
  assert.deepEqual(bad.result().lists.hosts.map(h=>[h.scope,h.reason]),[['out-of-scope','classifier-error']]);
});
test('scopeFromPolicy maps the scan scope policy and always puts protected hosts out of scope',()=>{
  // Pure classification: no request is made. example.com/example.net are RFC 2606 reserved names; protected hosts are synthetic example.gov/.mil names checked by name only.
  const classify=scopeFromPolicy(new ScopePolicy({urls:['https://shop.example.com/'],domainScope:'registrable-domain',relatedOrigins:['https://partner.example.net']} as any));
  assert.deepEqual(classify('https://shop.example.com/'),{scope:'in-scope',reason:'explicit-seed'});
  assert.deepEqual(classify('https://api.shop.example.com/'),{scope:'in-scope',reason:'in-domain'});
  assert.deepEqual(classify('https://partner.example.net/'),{scope:'in-scope',reason:'explicit-related'});
  assert.deepEqual(classify('https://cdn.example.org/'),{scope:'third-party',reason:'third-party'});
  assert.deepEqual(classify('https://10.0.0.1/'),{scope:'out-of-scope',reason:'ip-literal'});
  assert.deepEqual(classify('https://intranet.test/'),{scope:'out-of-scope',reason:'no-public-suffix'});
  assert.deepEqual(classify('https://api.example.gov/'),{scope:'out-of-scope',reason:'protected-host'});
  assert.deepEqual(classify('https://cdn.example.mil/'),{scope:'out-of-scope',reason:'protected-host'});
  const exact=scopeFromPolicy(new ScopePolicy({urls:['https://shop.example.com/'],domainScope:'exact-origin'} as any));
  assert.deepEqual(exact('https://api.shop.example.com/'),{scope:'out-of-scope',reason:'exact-origin-mode'});
});
test('caps: items per list, URL/endpoint/name lengths and scanned characters are enforced and counted',()=>{
  const c=new ReconCollector({classify:shopScope,limits:{maxItemsPerList:5,maxTextChars:2000,maxUrlLength:80,maxNameLength:16,maxEndpointLength:40}});
  const many=Array.from({length:20},(_,i)=>`fetch("/api/item${i}");`).join('');
  c.add({url:'https://shop.example/a.js',kind:'script',text:many});
  c.add({url:'https://shop.example/b.js',kind:'script',text:`fetch("/api/${'x'.repeat(60)}");params.append("${'n'.repeat(20)}",1);const u="https://shop.example/${'y'.repeat(100)}";`});
  c.add({url:'https://shop.example/c.js',kind:'script',text:' '.repeat(3000)+'fetch("/api/after-cap")'});
  const r=c.result();
  assert.equal(r.counts.endpoints,5);assert.ok(r.dropped.endpoints['over-limit']>=15);
  assert.ok(r.dropped.endpoints['too-long']>=1&&r.dropped.parameters['too-long']>=1&&r.dropped.urls['too-long']>=1,JSON.stringify(r.dropped));
  assert.equal(r.resources.truncated,1);assert.ok(!values(r,'endpoints').includes('/api/after-cap'));
  assert.deepEqual(new ReconCollector({classify:shopScope,limits:{maxItemsPerList:-1,maxUrlLength:1.5 as any}}).limits.maxItemsPerList,50000,'invalid limits fall back to defaults');
});
test('inline data: source maps are counted, never listed; images and binaries are skipped; add() never throws',()=>{
  const c=new ReconCollector({classify:shopScope});
  c.add({url:'https://shop.example/a.js',kind:'script',text:'x();\n//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozfQ=='});
  c.add({url:'https://shop.example/i.png',kind:'image',contentType:'image/png',text:'https://shop.example/hidden'});
  c.add({url:'https://shop.example/b.js',kind:'script',contentType:'text/javascript',text:'fetch("/x")',headers:{'SourceMap':'/b.js.map','x-sourcemap':'/b2.js.map'}});
  c.add(null as any);c.add({url:42 as any,kind:undefined as any,text:undefined as any});
  const r=c.result();
  assert.equal(r.inlineSourceMaps,1);assert.ok(!JSON.stringify(r.lists).includes('data:'));
  assert.ok(!values(r,'urls').includes('https://shop.example/hidden'));
  assert.deepEqual(values(r,'sourcemaps'),['https://shop.example/b.js.map','https://shop.example/b2.js.map']);
  assert.equal(r.resources.skipped,2);
});
test('writeRecon writes one line per item, the host split files and recon.json; it refuses links and replaces only its own files',async()=>{
  const dir=await tempDir();
  try{
    const c=new ReconCollector({classify:shopScope,now:fixedNow});feedFixtures(c);
    const r=c.result();
    const out=path.join(dir,'recon');
    await writeFile(path.join(dir,'keep.txt'),'x');
    const written=await writeRecon(out,r,{protect:false});
    assert.deepEqual(written.files,[...RECON_FILES]);
    assert.deepEqual((await readdir(out)).sort(),[...RECON_FILES].sort());
    assert.equal(await readFile(path.join(out,'urls.txt'),'utf8'),values(r,'urls').join('\n')+'\n');
    assert.equal(await readFile(path.join(out,'hosts-third-party.txt'),'utf8'),'cdn.vendor.example\nfonts.vendor.example\ntelemetry.vendor.example\n');
    assert.equal(await readFile(path.join(out,'hosts-out-of-scope.txt'),'utf8'),'');
    const json=JSON.parse(await readFile(path.join(out,'recon.json'),'utf8'));
    assert.equal(json.schema,'exposure-recon/1');assert.deepEqual(json.lists.endpoints[0],r.lists.endpoints[0]);assert.ok(json.lists.urls.every((i:any)=>typeof i.source==='string'&&i.source));
    assert.deepEqual(json.limits,r.limits);
    // A second write replaces the files atomically and leaves no temporary file.
    const tampered={...r,lists:{...r.lists,urls:[{value:'https://shop.example/ok',source:'x'},{value:'https://shop.example/a\nb',source:'x'},{value:'https://shop.example/?k='+'sk_live_'+'Ab9Cx7Dy5Ez3Fh1Gi0Jk8',source:'x'}]}};
    await writeRecon(out,tampered as ReconResult,{protect:false});
    assert.equal(await readFile(path.join(out,'urls.txt'),'utf8'),'https://shop.example/ok\n','lines with breaks or credential shapes are never written');
    assert.deepEqual((await readdir(out)).sort(),[...RECON_FILES].sort());
    if(process.platform!=='win32'){assert.equal((await stat(path.join(out,'recon.json'))).mode&0o777,0o600);}
    // Links and files are refused as the output folder.
    const target=await tempDir();
    let linked=false;try{await symlink(target,path.join(dir,'link'),'junction');linked=true;}catch{}
    if(linked)await assert.rejects(writeRecon(path.join(dir,'link'),r,{protect:false}),(e:any)=>e instanceof ReconOutputError&&e.code==='unsafe-output');
    await assert.rejects(writeRecon(path.join(dir,'keep.txt'),r,{protect:false}),(e:any)=>e instanceof ReconOutputError&&e.code==='output-not-directory');
    await rm(target,{recursive:true,force:true});
  }finally{await rm(dir,{recursive:true,force:true});}
});
test('writeRecon protects its folder by default (owner-only)',async()=>{
  const dir=await tempDir();
  try{
    const c=new ReconCollector({classify:shopScope});c.add({url:'https://shop.example/a.js',kind:'script',text:'fetch("/api/x")'});
    await writeRecon(path.join(dir,'out'),c.result());
    if(process.platform==='win32'){
      const {spawnSync}=await import('node:child_process');
      const acl=spawnSync('powershell.exe',['-NoProfile','-NonInteractive','-Command','(Get-Acl -LiteralPath $env:T).Access | ForEach-Object { $_.IdentityReference.Value }'],{encoding:'utf8',env:{...process.env,T:path.join(dir,'out','endpoints.txt')},windowsHide:true});
      const ids=acl.stdout.trim().split(/\r?\n/).filter(Boolean);
      assert.equal(new Set(ids).size,1,'one identity (the owner) on the written file: '+ids.join(', '));
    }else assert.equal((await stat(path.join(dir,'out'))).mode&0o777,0o700);
  }finally{await rm(dir,{recursive:true,force:true});}
});
test('loopback fixture: resources fetched from a local server feed the collector, and source maps never cause a request',async()=>{
  const requests:string[]=[];
  const server=http.createServer((req,res)=>{
    requests.push(req.url||'');
    const files:Record<string,[string,string]>={'/':['shop.html','text/html'],'/static/app.js':['app.js','application/javascript'],'/robots.txt':['robots.txt','text/plain'],'/sitemap.xml':['sitemap.xml','application/xml'],'/static/site.css':['site.css','text/css'],'/static/app.js.map':['app.js.map','application/json']};
    const f=files[(req.url||'').split('?')[0]];
    if(!f){res.writeHead(404).end();return;}
    res.writeHead(200,{'content-type':f[1]}).end(fixture(f[0]));
  });
  await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));
  const o=`http://127.0.0.1:${(server.address() as any).port}`;
  const dir=await tempDir();
  try{
    const rebuilder=await SourceRebuilder.create(path.join(dir,'sources'),{protect:false});
    const c=new ReconCollector({classify:u=>new URL(u).host===new URL(o).host?'in-scope':'third-party',rebuilder});
    for(const [p,kind] of [['/','page'],['/static/app.js?v=42','script'],['/robots.txt','robots'],['/sitemap.xml','sitemap'],['/static/site.css','css'],['/static/app.js.map','map']]){
      const res=await fetch(o+p);const text=await res.text();
      c.add({url:o+p,kind,contentType:res.headers.get('content-type')||'',text,headers:Object.fromEntries(res.headers)});
      if(kind==='map'){
        const map=JSON.parse(text);
        // A hostile twist on the fetched map: absolute loopback sources without content, and a section pointing at the server.
        map.sources.push(o+'/src/never-fetched.ts');
        await c.addSourceMap(o+p,map);
        await c.addSourceMap(o+'/static/sections.js.map',{version:3,sections:[{offset:{line:0,column:0},url:o+'/static/section-never-fetched.js.map'},{offset:{line:1,column:0},map:{version:3,sources:[o+'/src/remote-only.ts'],mappings:''}}]});
      }
    }
    const before=requests.length;
    const manifest=await rebuilder.finish();
    await new Promise(r=>setTimeout(r,50));
    assert.equal(requests.length,before,'finishing the rebuild made no request');
    assert.ok(!requests.some(u=>u.includes('never-fetched')||u.includes('remote-only')||u.startsWith('/src/')),JSON.stringify(requests));
    const r=c.result();
    assert.ok(values(r,'endpoints').includes('/api/v2/orders'));
    assert.ok(values(r,'sourcemaps').includes(o+'/static/app.js.map')&&values(r,'sourcemaps').includes(o+'/static/sections.js.map'));
    assert.deepEqual(manifest.files.map(f=>f.path),['node_modules/tiny-lib/index.js','shop/src/api/client.ts','shop/src/index.ts'],'webpack://shop/../x resolves to x inside the rebuild root');
    const reasons=manifest.notRecoverable.map(n=>[n.source,n.reason]).sort();
    assert.deepEqual(reasons,[[o+'/src/never-fetched.ts','no-sources-content'],[o+'/src/remote-only.ts','no-sources-content'],[o+'/static/section-never-fetched.js.map','section-url-not-fetched'],['webpack://shop/./src/missing.ts','no-sources-content']].sort());
  }finally{server.close();await rm(dir,{recursive:true,force:true});}
});
test('addSourceMap: map files are listed, inline maps are labelled by the embedding resource and never listed; rebuilder errors are contained',async()=>{
  const dir=await tempDir();
  try{
    const rebuilder=await SourceRebuilder.create(path.join(dir,'src'),{protect:false});
    const c=new ReconCollector({classify:shopScope,rebuilder});
    await c.addSourceMap('https://shop.example/static/app.js',{version:3,sources:['webpack:///./src/inline.ts'],sourcesContent:['x']},{inline:true});
    await c.addSourceMap('data:application/json;base64,e30=',{version:3,sources:['b.ts'],sourcesContent:['b']});
    await c.addSourceMap('https://shop.example/static/vendor.js.map?v=7#section-0-0-0',{version:3,sources:['c.ts'],sourcesContent:['c']});
    const m=await rebuilder.finish();
    assert.deepEqual(m.files.map(f=>[f.path,f.sourceMap]),[['b.ts','data:(inline source map)'],['c.ts','https://shop.example/static/vendor.js.map?v'],['src/inline.ts','inline:https://shop.example/static/app.js']]);
    const r=c.result();
    assert.deepEqual(values(r,'sourcemaps'),['https://shop.example/static/vendor.js.map']);
    assert.equal(r.inlineSourceMaps,0,'inline maps are counted from sourceMappingURL comments seen by add(), not twice');
    const throwing=new ReconCollector({classify:shopScope,rebuilder:{add:async()=>{throw new Error('disk full');}}});
    await throwing.addSourceMap('https://shop.example/x.js.map',{});
    assert.deepEqual(values(throwing.result(),'sourcemaps'),['https://shop.example/x.js.map']);
  }finally{await rm(dir,{recursive:true,force:true});}
});
