// Independent acceptance corpus. Seed and expected outcomes are fixed before implementation.
import {createHash} from 'node:crypto';
import http from 'node:http';
export const seed='ExposureDesk/stage2/heldout/20261006/73';
export function token(label,n=64){let s='';for(let i=0;s.length<n;i++)s+=createHash('sha256').update(seed+label+i).digest('base64url');return s.slice(0,n);}
const key=label=>'sk-proj-'+token(label);
export const corpus=[
 {id:'alias-chain',provider:'OpenAI',mechanism:'semantic',value:key('alias'),text:`const p="sk-proj-"; const a="${token('alias').slice(0,32)}"; const b="${token('alias').slice(32)}"; const x=p+a; const apiKey=x+b;`},
 {id:'template-array',provider:'Stripe',mechanism:'semantic',value:'sk_live_'+token('array',48).replace(/[_-]/g,'Z'),text:`const pieces=${JSON.stringify(['sk_live_',token('array',48).replace(/[_-]/g,'Z').slice(0,24),token('array',48).replace(/[_-]/g,'Z').slice(24)])}; const joined=pieces.join(''); const opts={apiKey:\`\${joined}\`}; const {apiKey:key}=opts; fetch('/read',{headers:{Authorization:'Bearer '+key}});`},
 {id:'encoded-engine',provider:'snyk',mechanism:'decoded-engine',value:'987e6543-e21b-42d3-a876-426614174073',text:'const payload="'+Buffer.from('SNYK_TOKEN="987e6543-e21b-42d3-a876-426614174073"').toString('base64')+'";'},
 {id:'literal-engine',provider:'snyk',mechanism:'engine',value:'987e6543-e21b-42d3-a876-426614174074',text:'SNYK_TOKEN="987e6543-e21b-42d3-a876-426614174074";'},
 {id:'large-end',provider:'OpenAI',mechanism:'chunked-text',value:key('end'),text:'/*'+('ordinary minified material '.repeat(150000))+'*/\nconst apiKey="'+key('end')+'";'},
 {id:'chunk-boundary',provider:'OpenAI',mechanism:'chunked-text',value:key('boundary'),text:' '.repeat(65536-19)+'"'+key('boundary')+'";'},
 {id:'late-decoding',provider:'OpenAI',mechanism:'decoded-priority',value:key('late'),text:Array.from({length:300},(_,i)=>'const v'+i+'="'+Buffer.from('innocuous message number '+i).toString('base64')+'";').join('')+'const apiKey=atob("'+Buffer.from(key('late')).toString('base64')+'");'},
 {id:'malformed',provider:'OpenAI',mechanism:'parser-isolation',value:key('malformed'),text:'const broken = { ;\n"'+key('malformed')+'";'},
 {id:'azure-connection',provider:'Azure',mechanism:'context',value:Buffer.from(token('azure')).toString('base64'),text:'DefaultEndpointsProtocol=https;AccountName=heldout;AccountKey='+Buffer.from(token('azure')).toString('base64')+';EndpointSuffix=core.windows.net'},
 {id:'sas-fragment',provider:'Azure',mechanism:'capability',value:'sv=2024-11-04&sp=r&se=2030-01-01&sr=b&sig='+encodeURIComponent(Buffer.from(token('sas',32)).toString('base64')),text:'SharedAccessSignature="sv=2024-11-04&sp=r&se=2030-01-01&sr=b&sig='+encodeURIComponent(Buffer.from(token('sas',32)).toString('base64'))+'"'},
 {id:'public-decoy',provider:'Stripe',mechanism:'negative',privateExpected:false,value:'pk_live_'+token('public',32).replace(/[_-]/g,'A'),text:'const publishableKey="pk_live_'+token('public',32).replace(/[_-]/g,'A')+'";'},
 {id:'clean',provider:'none',mechanism:'negative',privateExpected:false,text:'const content={description:"Ordinary docs",publicKey:"-----BEGIN PUBLIC KEY-----\\n'+token('pub')+'\\n-----END PUBLIC KEY-----"}; const id="'+token('id')+'";'},
 {id:'unknown-expression',provider:'none',mechanism:'negative',privateExpected:false,text:'const p="sk-proj-"; const q=getSecret(); const apiKey=p+q;'}
];
export async function heldoutServer(){
 const moduleKey=key('modules'),mapKey=key('map'),browserKey=key('generated'),blockedKey=key('blocked'),staleKey=key('stale'),lateKey=key('late-config');
 const expected=[{id:'module-split',provider:'OpenAI',mechanism:'cross-module',value:moduleKey},{id:'source-map-only',provider:'OpenAI',mechanism:'source-map',value:mapKey},{id:'debugger-only',provider:'OpenAI',mechanism:'debugger',value:browserKey},{id:'blocked-request-only',provider:'OpenAI',mechanism:'browser-request',value:blockedKey},{id:'stale-exact-url',provider:'OpenAI',mechanism:'stale-asset',value:staleKey},{id:'late-application-json',provider:'OpenAI',mechanism:'browser-json',value:lateKey}];
 const encode=v=>JSON.stringify([...v].map(c=>c.charCodeAt(0)));
 const routes={
 '/': ['text/html','<script type="importmap">'+JSON.stringify({imports:{parts:'/modules/parts'}})+'</script><script type="module" src="/modules/main"></script><script src="/app.js"></script><script src="/map.js"></script><link rel="manifest" href="/route-manifest.json">'],
 '/route-manifest.json':['application/json',JSON.stringify({routes:[{path:'/settings',module:'/modules/config'}]})],
 '/modules/parts':['text/javascript',`export const prefix="sk-proj-"; export const left="${token('modules').slice(0,31)}"; export const right="${token('modules').slice(31)}";`],
 '/modules/main':['text/javascript','import {prefix,left,right} from "parts"; const a=prefix+left; export const config={apiKey:a+right};'],
 '/modules/config':['text/javascript','export const deployment={environment:"production"};'],
 '/map.js':['text/javascript','void 0; //# sourceMappingURL=/map.js.map'],
 '/map.js.map':['application/json',JSON.stringify({version:3,sources:['webpack:///src/key.ts'],sourcesContent:['export const apiKey="'+mapKey+'";'],mappings:''})],
 '/app.js':['text/javascript',`setTimeout(()=>{ const g=String.fromCharCode(...${encode(browserKey)}); (0,eval)('void '+JSON.stringify(g)); const b=String.fromCharCode(...${encode(blockedKey)}); fetch('/never-arrive',{headers:{Authorization:'Bearer '+b}}).catch(()=>{}); fetch('/runtime-json').then(r=>r.json()); },120);`],
 '/runtime-json':['application/json',JSON.stringify({provider:'OpenAI',apiKey:lateKey})],
 '/previous-deployment.73':['text/javascript','const removedDeployment="'+staleKey+'";'],
 '/robots.txt':['text/plain','User-agent: *\n'], '/sitemap.xml':['text/xml','<urlset/>']
 };
 // Path purity: complete browser secret absent in every ordinary response; map secret absent in bundle.
 if(Object.values(routes).some(([,text])=>text.includes(browserKey)||text.includes(blockedKey)))throw new Error('Browser fixture leaked its complete value into static content');
 if(routes['/map.js'][1].includes(mapKey))throw new Error('Source map fixture leaked into bundle');
 const arrivals=[];const server=http.createServer((req,res)=>{arrivals.push(req.url);const row=routes[req.url];res.statusCode=row?200:404;res.setHeader('Content-Type',row?.[0]||'text/plain');res.end(row?.[1]||'missing');});await new Promise(r=>server.listen(0,'127.0.0.1',r));
 return {origin:'http://127.0.0.1:'+server.address().port,expected,arrivals,routes,close:()=>new Promise(r=>server.close(r))};
}
