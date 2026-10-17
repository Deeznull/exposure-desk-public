import test from 'node:test';
import assert from 'node:assert/strict';
import { cleanUrl, cleanEndpoint, cleanLabel, secretShaped, containsKnownSecret, queryNames, redactPath, validParameterName, hostLiteral, REDACTED, EXPR } from '../src/recon/clean.js';
import { extractRecon, reconMode, inlineScripts, type ExtractSink, type GraphqlType } from '../src/recon/extract.js';
import { ReconCollector } from '../src/recon/collector.js';
import { synthetic, syntheticJwt } from '../src/fixture.js';
const o='https://shop.example';
/** A sink that records raw candidates, for checking the extraction passes alone. */
function recorder(){
  const r={urls:[] as string[],calls:[] as string[],endpoints:[] as string[],params:[] as string[],graphql:[] as string[],hosts:[] as string[],scripts:[] as string[],maps:[] as string[]};
  const sink:ExtractSink={url:(raw,base,callSite)=>{(callSite?r.calls:r.urls).push(base?new URL(raw,base).href:raw);},endpoint:raw=>r.endpoints.push(raw),param:n=>r.params.push(n),graphql:(t:GraphqlType,n)=>r.graphql.push(t+' '+n),hostLiteral:h=>r.hosts.push(h),script:(raw,base)=>r.scripts.push(new URL(raw,base).href),sourceMap:raw=>r.maps.push(raw)};
  return {r,sink};
}
const inScope=(u:string)=>{const h=new URL(u).hostname;return h==='shop.example'||h.endsWith('.shop.example')?'in-scope' as const:'third-party' as const;};
/** Every synthetic credential value, plus a distinctive tail of each, so a partially kept value is caught too. */
const SECRET_VALUES=[...Object.entries(synthetic).filter(([k])=>!['publicStripe','publicSupabase','privateKey'].includes(k)).map(([,v])=>v),...Object.values(syntheticJwt)];
const SECRET_PIECES=[...SECRET_VALUES,...SECRET_VALUES.map(v=>v.slice(-16)),'Ab9Cx7Dy5Ez3Fh1Gi0Jk8','c3ludGhldGljX25vbmZ1bmN0aW9uYWxfc2ln'];

test('cleanUrl drops query values, fragments and user info, keeps parameter names and resolves relative references',()=>{
  const c=cleanUrl('https://user:pw@Shop.Example:443/a/b?token=abc&x=1&x=2&flag#frag=1&mode=dark','https://ignored.example/')!;
  assert.equal(c.url,'https://shop.example/a/b?token&x&flag');
  assert.deepEqual(c.params,['token','x','flag','frag','mode']);
  assert.equal(c.host,'shop.example');
  assert.equal(cleanUrl('../c/d?e=f',o+'/a/b/index.html')!.url,o+'/a/c/d?e');
  assert.equal(cleanUrl('//cdn.shop.example/x.js',o+'/')!.url,'https://cdn.shop.example/x.js');
  assert.equal(cleanUrl('/p?a=1&amp;b=2',o)!.url,o+'/p?a&b');
  assert.equal(cleanUrl('wss://rt.shop.example/s?ticket=1')!.url,'wss://rt.shop.example/s?ticket');
  for(const bad of ['javascript:alert(1)','mailto:a@shop.example','data:text/html,x','file:///etc/passwd','ftp://shop.example/x','not a url','https://'])assert.equal(cleanUrl(bad),undefined,bad);
  assert.equal(cleanUrl(o+'/'+'a'.repeat(3000)),undefined,'over the URL length cap');
  assert.equal(cleanUrl(o+'/api/%7BEXPR%7D/x')!.url,o+'/api/{EXPR}/x');
});
test('credential-shaped path segments are redacted; ordinary identifiers, hashes and UUIDs are kept',()=>{
  for(const v of SECRET_VALUES)assert.equal(secretShaped(v),true,v.slice(0,12));
  for(const v of SECRET_VALUES){const c=cleanUrl(o+'/hook/'+encodeURIComponent(v)+'/x?k='+encodeURIComponent(v));assert.ok(c,v.slice(0,12));assert.equal(c.url,o+'/hook/'+REDACTED+'/x?k');assert.equal(c.redactions,1);}
  for(const keep of ['UsersController','getProductById','v2','index.html','3f2c1a7e-9b4d-4c2e-8f1a-0d6b5e4c3a21','da39a3ee5e6b4b0d3255bfef95601890afd80709','main.4f9c2b1a.chunk.js','node_modules','webpack','ProductListPageV2Container'])assert.equal(secretShaped(keep),false,keep);
  assert.equal(secretShaped('A'.repeat(8)+'0123456789abcdef0123456789ABCDEF'),true,'64-ish mixed hex/random token');
  assert.equal(secretShaped('0123456789abcdef0123456789abcdef'),true,'32-hex key-length segment');
  // Slack and Discord webhook capability paths: last segment always redacted.
  assert.equal(redactPath('/services/T0ABCDEFG/B0ABCDEFG/plainword').value,'/services/T0ABCDEFG/B0ABCDEFG/'+REDACTED);
  assert.equal(redactPath('/api/webhooks/123456789012345678/short').value,'/api/webhooks/123456789012345678/'+REDACTED);
  // Matrix (;name=value) path parameters keep only the name.
  assert.equal(redactPath('/a;jsessionid=XYZ123/b').value,'/a;jsessionid/b');
  assert.equal(containsKnownSecret('https://x.example/?q='+synthetic.github),true);
  assert.equal(containsKnownSecret('https://x.example/'+encodeURIComponent(synthetic.stripe)),true);
});
test('parameter names are validated and never carry values',()=>{
  assert.deepEqual(queryNames('?a=1&b&c=&a=2&=x&d%5B0%5D=1&e+f=2'),['a','b','c','d[0]']);
  assert.equal(validParameterName('filter[brand]'),true);
  assert.equal(validParameterName('x'.repeat(129)),false);
  assert.equal(validParameterName('has space'),false);
  assert.equal(validParameterName(synthetic.openai),false,'a key used as a name is not a name');
});
test('cleanEndpoint keeps routes as written and reduces queries to names',()=>{
  assert.deepEqual(cleanEndpoint('/api/v1/users?id=5&token=abc#x'),{path:'/api/v1/users',params:['id','token'],redactions:0});
  assert.equal(cleanEndpoint('api/v1//items')!.path,'api/v1/items');
  assert.equal(cleanEndpoint('/orders/:id/invoice')!.path,'/orders/:id/invoice');
  assert.equal(cleanEndpoint(`/v1/${EXPR}/files`)!.path,'/v1/{EXPR}/files');
  assert.deepEqual(cleanEndpoint('?page=1'),{path:'',params:['page'],redactions:0});
  for(const bad of ['/','//cdn.example/x','/a b','/123','/<script>'])assert.equal(cleanEndpoint(bad),undefined,bad);
  assert.equal(cleanEndpoint('/keys/'+synthetic.anthropic)!.path,'/keys/'+REDACTED);
});
test('cleanLabel strips control and bidi characters and secrets from non-http labels',()=>{
  assert.equal(cleanLabel('webpack:///./src/a\u0000b‮.ts?x=1'),'webpack:///./src/ab.ts?x');
  assert.equal(cleanLabel('webpack:///src/'+synthetic.github+'.ts'),'webpack:///src/'+REDACTED);
  assert.equal(cleanLabel('https://shop.example/a?k=v#f'),'https://shop.example/a?k');
});
test('hostLiteral accepts bare hostnames only',()=>{
  assert.equal(hostLiteral('API.Shop.Example.'),'api.shop.example');
  for(const bad of ['localhost','a.b/c','1.2.3.4','shop.example:8080','-x.example','x..example','e.target'.replace('target','1')])assert.equal(hostLiteral(bad),undefined,bad);
});
test('reconMode picks passes from kind, content type, path and the first bytes',()=>{
  assert.equal(reconMode('page','text/html; charset=utf-8',o+'/',''),'html');
  assert.equal(reconMode('other','',o+'/x','<!DOCTYPE html><html>'),'html');
  assert.equal(reconMode('script','',o+'/a.js','x'),'js');
  assert.equal(reconMode('source','','webpack:///src/a.ts','x'),'js');
  assert.equal(reconMode('other','application/javascript',o+'/a',''),'js');
  assert.equal(reconMode('map','application/json',o+'/a.js.map','{}'),'map');
  assert.equal(reconMode('other','',o+'/a.js.map','{"version":3,"mappings":""}'),'map');
  assert.equal(reconMode('robots','text/plain',o+'/robots.txt',''),'robots');
  assert.equal(reconMode('other','application/xml',o+'/sitemap.xml','<?xml version="1.0"?>\n<urlset>'),'sitemap');
  assert.equal(reconMode('css','',o+'/a.css',''),'css');
  assert.equal(reconMode('other','application/json',o+'/a',''),'json');
  assert.equal(reconMode('image','image/png',o+'/a.png',''),'skip');
  assert.equal(reconMode('other','application/octet-stream',o+'/a','PK\u0003\u0004\u0000'),'skip');
  assert.equal(reconMode('other','text/plain',o+'/notes',''),'text');
});
test('HTML passes: links, scripts, forms, field names, inline styles and inline scripts',()=>{
  const {r,sink}=recorder();
  extractRecon(`<a href="/a?x=1">a</a><a href='#top'>t</a><a href="javascript:void(0)">j</a><img src=//img.shop.example/i.png><script src="/s.js"></script>
<form action="/f?y=2"><input name="email"><select name='country'></select><textarea name=note></textarea></form><div style="background:url(/bg.webp)"></div>
<script>fetch("/api/x");</script><script type="application/json">{"u":"/api/y"}</script>`,o+'/dir/page',reconMode('page','text/html',o+'/',''),sink);
  assert.ok(r.urls.includes(o+'/a?x=1')&&r.urls.includes('https://img.shop.example/i.png')&&r.urls.includes(o+'/bg.webp'),JSON.stringify(r.urls));
  assert.ok(!r.urls.some(u=>u.startsWith('javascript')||u.endsWith('#top')));
  assert.deepEqual(r.scripts,[o+'/s.js']);
  assert.ok(r.endpoints.includes('/f')&&r.endpoints.includes('/api/x')&&r.endpoints.includes('/api/y'),JSON.stringify(r.endpoints));
  assert.deepEqual(r.params.sort(),['country','email','note']);
  assert.deepEqual(inlineScripts('<script src="/a.js"></script><SCRIPT>one()</SCRIPT><script>two()'),['one()','two()']);
});
test('JS passes: call sites, route tables, URL keys, template literals, parameters, GraphQL and source-map comments',()=>{
  const {r,sink}=recorder();
  extractRecon(`fetch("/api/v1/a");axios.post('/api/v1/b');$.getJSON("/c.json");app.get("/admin/users",h);router.post('/hooks/:id',h);
const x=new XMLHttpRequest();x.open("DELETE","/api/v1/d");new EventSource("/events");navigator.sendBeacon("https://t.vendor.example/c");
const routes=[{path:"/products/:slug"},{path:"M10 10L20 20"},{path:"/"}];<Route path="/checkout/:step" />;
const cfg={baseURL:"https://api.shop.example/v2",endpoint:"/svc/status",url:"not a url"};
fetch(\`/api/items/\${id}/detail?limit=\${n}\`);fetch(\`\${base}/v3/search\`);
const p=new URLSearchParams({page:1,"per_page":2});params.append("sort","x");searchParams.get('q');other.get("ignored");
axios.get("/i",{params:{warehouse:"w"}});
const q="query GetUser($id: ID!) { user(id: $id) { id } }",m=\`mutation AddItem { a }\`,s="subscription OnTick @live { t }";
send({operationName:"ListOrders"});
const host="assets.shop.example",dotted="window.location",img="/img/a.png",reg="/^a/",cmt="/*x*/";
const esc="https:\\/\\/legacy.shop.example\\/v1\\/old";
//# sourceMappingURL=app.js.map
`,o+'/static/app.js','js',sink);
  for(const e of ['/api/v1/a','/api/v1/b','/c.json','/admin/users','/hooks/:id','/api/v1/d','/events','/products/:slug','/checkout/:step','/svc/status','/api/items/{EXPR}/detail?limit={EXPR}','/v3/search','/i'])assert.ok(r.endpoints.includes(e),e+' in '+JSON.stringify(r.endpoints));
  assert.ok(!r.endpoints.some(e=>e.startsWith('M10')||e==='/'||e==='/img/a.png'||e==='/^a/'||e==='/*x*/'),JSON.stringify(r.endpoints));
  assert.ok(r.calls.includes('https://t.vendor.example/c')&&r.calls.includes('https://api.shop.example/v2'),JSON.stringify(r.calls));
  assert.ok(r.urls.includes('https://legacy.shop.example/v1/old'),'escaped slashes are unescaped');
  for(const p of ['page','per_page','sort','q','warehouse'])assert.ok(r.params.includes(p),p);
  assert.ok(!r.params.includes('ignored'),'get() on an unrelated identifier is not a parameter');
  assert.deepEqual(r.graphql.sort(),['mutation AddItem','operation ListOrders','query GetUser','subscription OnTick']);
  assert.ok(r.hosts.includes('assets.shop.example')&&r.hosts.includes('window.location'),'host literals are offered; the collector filters by scope');
  assert.deepEqual(r.maps,['app.js.map']);
});
test('robots, sitemap and CSS passes',()=>{
  let x=recorder();extractRecon('User-agent: *\nDisallow: /admin/\nAllow: /pub$\nDisallow: /\nDisallow:\nSitemap: https://shop.example/sm.xml\n',o+'/robots.txt','robots',x.sink);
  assert.deepEqual(x.r.endpoints,['/admin/','/pub']);assert.ok(x.r.urls.includes(o+'/sm.xml'));
  x=recorder();extractRecon('<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://shop.example/a?b=1&amp;c=2</loc></url><url><loc>/rel</loc></url></urlset>',o+'/sitemap.xml','sitemap',x.sink);
  assert.ok(x.r.urls.includes('https://shop.example/a?b=1&amp;c=2')&&x.r.urls.includes(o+'/rel'));assert.ok(!x.r.urls.some(u=>u.includes('sitemaps.org')),'namespace identifiers are not links');
  x=recorder();extractRecon('@import "/t.css";a{background:url( \'img/a.png\' )}b{background:url(data:image/png;base64,AA)}/*# sourceMappingURL=s.css.map */',o+'/c/s.css','css',x.sink);
  assert.ok(x.r.urls.includes(o+'/t.css')&&x.r.urls.includes(o+'/c/img/a.png'));assert.ok(!x.r.urls.some(u=>u.startsWith('data:')));assert.deepEqual(x.r.maps,['s.css.map']);
});
test('no synthetic credential value reaches any recon list or provenance, wherever it is planted',()=>{
  const c=new ReconCollector({classify:inScope});
  const planted=SECRET_VALUES.map(v=>{const e=encodeURIComponent(v);return [
    `https://shop.example/a?key=${e}`,`https://shop.example/hook/${e}/x`,`https://u:${e}@shop.example/p`,`https://shop.example/f#access_token=${e}`,
    `https://shop.example/m;sid=${e}/n`,`https://shop.example/${e}`,`/api/${e}/x`,`/api/x?k=${e}`
  ];}).flat();
  const js=planted.map((u,i)=>`fetch(${JSON.stringify(u)});const s${i}=${JSON.stringify(u)};`).join('\n')+'\n'+SECRET_VALUES.map((v,i)=>`params.append(${JSON.stringify(v)},1);const h${i}="${v}";const t${i}=\`/t/${v}/\${x}\`;`).join('\n');
  const html=`<html>${planted.map(u=>`<a href="${u}">x</a><form action="${u}"><input name="${SECRET_VALUES[0]}"></form>`).join('')}<script>${js}</script></html>`;
  c.add({url:o+'/?session='+encodeURIComponent(synthetic.stripe),kind:'page',contentType:'text/html',text:html});
  c.add({url:o+'/'+encodeURIComponent(synthetic.openai)+'/app.js',kind:'script',contentType:'text/javascript',text:js,headers:{sourcemap:'/m.map?sig='+synthetic.google}});
  c.add({url:'webpack:///src/'+synthetic.github+'.ts',kind:'source',text:js});
  const out=JSON.stringify(c.result());
  for(const piece of SECRET_PIECES){assert.ok(!out.includes(piece),'leaked '+piece.slice(0,10));assert.ok(!out.includes(encodeURIComponent(piece)),'leaked encoded '+piece.slice(0,10));}
  assert.ok(c.result().lists.urls.length>0&&c.result().redactions>0,'the planted URLs were still listed, redacted');
});
test('a caller secret filter drops flagged items and provenance labels',()=>{
  const c=new ReconCollector({classify:inScope,secretFilter:v=>v.includes('internal-only')});
  c.add({url:o+'/internal-only/app.js',kind:'script',text:'fetch("/api/internal-only/x");fetch("/api/ok")'});
  const r=c.result();
  assert.ok(!JSON.stringify(r.lists).includes('internal-only'));
  assert.equal(r.lists.endpoints.find(e=>e.value==='/api/ok')!.source,REDACTED);
  assert.ok(r.dropped.endpoints.secret>=1&&r.dropped.urls.secret>=1);
  const broken=new ReconCollector({classify:inScope,secretFilter:()=>{throw new Error('x');}});
  broken.add({url:o+'/a.js',kind:'script',text:'fetch("/api/ok")'});
  assert.equal(broken.result().counts.endpoints,0,'a failing filter fails closed');
});
test('extraction stays linear on hostile input',()=>{
  const c=new ReconCollector({classify:inScope});
  const hostile=['"'.repeat(400000),'fetch('.repeat(150000),'<script'.repeat(100000),'https://'.repeat(200000),'`${'.repeat(200000),'{path:"'.repeat(100000),'query A'.repeat(100000),'?a='.repeat(200000),'<a href="'.repeat(100000)];
  const start=Date.now();
  for(const text of hostile){c.add({url:o+'/h.js',kind:'script',text});c.add({url:o+'/h.html',kind:'page',contentType:'text/html',text});}
  assert.ok(Date.now()-start<20000,'took '+(Date.now()-start)+' ms');
});
