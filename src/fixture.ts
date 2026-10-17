import http from 'node:http';
import { pathToFileURL } from 'node:url';
// Deterministic synthetic, nonfunctional examples. Never authenticate these.
// The GitHub value carries a matching offline CRC32 suffix (token structure only); it was never issued.
const mix='Ab9Cx7Dy5Ez3Fh1Gi0Jk8Lm6No4Pq2Rs9Tu7Vw5Xy3Za1Bc0De8';
export const synthetic={openai:'sk-proj-'+mix.repeat(2),anthropic:'sk-ant-api03-'+mix.repeat(2),stripe:'sk_live_'+mix,
  publicStripe:'pk_live_'+mix,publicSupabase:'sb_publishable_'+mix,supabase:'sb_secret_'+mix,
  github:'ghp_'+mix.slice(0,30)+'2ZCMPD',hf:'hf_'+mix.slice(0,34),replicate:'r8_'+mix.slice(0,40),
  google:'AIza'+mix.slice(0,35),sendgrid:'SG.'+mix.slice(0,22)+'.'+mix.slice(0,43),
  awsId:'AKIA'+'Z9Y8X7W6V5U4T3S2',awsSecret:mix.slice(0,40),
  signing:'whsec_'+mix,context:'Q9r7T2w8Y4u6I1o5P3a0S9d7F2g8H4j6K1l5Z3x0C9v7B2n8',
  privateKey:'-----BEGIN PRIVATE KEY-----\n'+Buffer.from('synthetic only, not an ASN.1 key').toString('base64')+'\n-----END PRIVATE KEY-----'};
function jwt(role:string){return ['eyJhbGciOiJIUzI1NiJ9',Buffer.from(JSON.stringify({role,iss:'supabase-fixture',exp:1900000000})).toString('base64url'),'c3ludGhldGljX25vbmZ1bmN0aW9uYWxfc2ln'].join('.');}
export const syntheticJwt={anon:jwt('anon'),service:jwt('service_role'),session:jwt('authenticated')};
export async function createFixture(port=0,options:{minimalDiscovery?:boolean}={}){
  const arrivals:{path:string;method:string}[]=[];let dashboardOrigin='http://127.0.0.1:4317';
  const external=http.createServer((req,res)=>{arrivals.push({path:'external:'+req.url,method:req.method||''});res.end('unscoped');});await new Promise<void>(r=>external.listen(0,'127.0.0.1',r));
  const other=`http://127.0.0.1:${(external.address() as any).port}`;
  const map=(content:string,label='src/config.ts')=>JSON.stringify({version:3,file:'app.min.js',sourceRoot:'./',sources:[label],sourcesContent:[content],names:[],mappings:''});
  const app=`window.PUBLIC_CONFIG={stripe:${JSON.stringify(synthetic.publicStripe)},supabase:${JSON.stringify(synthetic.publicSupabase)},firebase:{apiKey:${JSON.stringify(synthetic.google)},projectId:'public-fixture-id'}};window.__env={VITE_PRIVATE_API_KEY:${JSON.stringify(synthetic.openai)}};localStorage.setItem('session',${JSON.stringify(syntheticJwt.session)});localStorage.setItem('runtime_signing_secret',${JSON.stringify(synthetic.signing)});import('./lazy.js');fetch('/api/public');fetch('/collect?api_key='+${JSON.stringify(synthetic.anthropic)});fetch('/collect',{headers:{'x-api-key':${JSON.stringify(synthetic.github)}}});fetch('/collect',{method:'POST',body:JSON.stringify({api_key:${JSON.stringify(synthetic.supabase)}})});fetch('/write',{method:'POST',body:'ordinary-data'});fetch('/delete');fetch('/redirect-secret');fetch(${JSON.stringify(other+'/outside.js')});fetch(DASHBOARD_ORIGIN+'/api/scans');new WebSocket(location.origin.replace('http','ws')+'/socket');new Worker('/worker.js');window.addEventListener('scroll',()=>{if(window.scrolled)return;window.scrolled=true;fetch('/api/scroll');fetch('/scroll-collect?api_key='+${JSON.stringify(synthetic.stripe)});});navigator.serviceWorker.register('/sw.js').catch(()=>{});\n//# sourceMappingURL=app.min.js.map`;
  const server=http.createServer((req,res)=>{
    const u=new URL(req.url||'/','http://fixture');arrivals.push({path:req.url||'',method:req.method||''});
    const send=(body:string,type='text/plain',code=200,headers:Record<string,string>={})=>{res.writeHead(code,{'Content-Type':type,...headers});res.end(body);};
    switch(u.pathname){
      case '/':send(`<!doctype html><html><head><link rel="manifest" href="/manifest.webmanifest"><link rel="stylesheet" href="/site.css"></head><body style="min-height:4000px"><h1>Synthetic exposure fixture</h1><!--${synthetic.github}--><script>const DASHBOARD_ORIGIN=${JSON.stringify(dashboardOrigin)};window.fixtureMarker='loaded';</script><script src="/app.min.js"></script><script src="/inline.js"></script><script src="/conventional.js"></script><script src="/header-map.js"></script><script src="${other}/outside.js"></script><a href="/about">About</a><a href="/login">Login barrier</a><a href="/redirect-out">External redirect</a><a href="/big">Oversized response</a><a href="/fail">Failed response</a><a href="/rate">Rate limit</a><a href="/redirect-secret">Credential redirect</a><a href="/child">Child</a><a href="/slow">Slow</a><a href="/fallback">SPA fallback</a><p>Placeholder API_KEY=your_api_key_here; hash=0123456789abcdef0123456789abcdef; UUID=123e4567-e89b-12d3-a456-426614174000.</p></body></html>`,'text/html');break;
      case '/clean':send('<html><body><h1>Clean fixture</h1></body></html>','text/html');break;
      case '/about':send(`<html><body><p>REPLICATE_API_TOKEN="${synthetic.replicate}"</p><a href="/nested/page">Nested</a></body></html>`,'text/html');break;
      case '/nested/page':send(JSON.stringify({SENDGRID_API_KEY:synthetic.sendgrid}),'application/json');break;
      case '/child':send('<html><body><a href="/nested/page">Another path</a><iframe src="/frame"></iframe></body></html>','text/html');break;
      case '/frame':send(`<html><body><script>window.RUNTIME_CONFIG={OAUTH_CLIENT_SECRET:${JSON.stringify(synthetic.context)}};fetch('/api/frame')</script></body></html>`,'text/html');break;
      case '/api/frame':send(JSON.stringify({TWILIO_AUTH_TOKEN:synthetic.context}),'application/json');break;
      case '/app.min.js':send(app,'text/javascript');break;
      case '/app.min.js.map':send(map(`export const ANTHROPIC_API_KEY=${JSON.stringify(synthetic.anthropic)};\nexport const AWS_ACCESS_KEY_ID=${JSON.stringify(synthetic.awsId)};\nexport const AWS_SECRET_ACCESS_KEY=${JSON.stringify(synthetic.awsSecret)};`),'application/json');break;
      case '/lazy.js':send(`export const encoded=${JSON.stringify(Buffer.from(synthetic.stripe).toString('base64'))};export const assembled='${synthetic.openai.slice(0,25)}' + '${synthetic.openai.slice(25)}';export const escaped=${JSON.stringify(synthetic.hf).replace('hf_',String.raw`\u0068f_`)};`,'text/javascript');break;
      case '/inline.js':send(`const n=1;\n//# sourceMappingURL=data:application/json;base64,${Buffer.from(map(`const HUGGINGFACE_TOKEN=${JSON.stringify(synthetic.hf)};`,'webpack://fixture/src/hf.ts')).toString('base64')}`,'text/javascript');break;
      case '/conventional.js':send('const n=1;','text/javascript');break;
      case '/conventional.js.map':send(map(`const SIGNING_SECRET=${JSON.stringify(synthetic.signing)}`),'application/json');break;
      case '/header-map.js':send('const n=2;','text/javascript',200,{'X-SourceMap':'/header.map'});break;
      case '/header.map':send(JSON.stringify({version:3,sourceRoot:'/sources/',sources:['source.ts'],names:[],mappings:''}),'application/json');break;
      case '/sources/source.ts':send(`export const privateKey=${JSON.stringify(synthetic.privateKey)};`);break;
      case '/invalid.map':send('{invalid','application/json');break;
      case '/traversal.map':send(JSON.stringify({version:3,sources:['../../private.ts'],names:[],mappings:''}),'application/json');break;
      case '/manifest.webmanifest':send(JSON.stringify({name:'Fixture',start_url:'/about',icons:[]}),'application/manifest+json');break;
      case '/site.css':send(`/* api_secret=${synthetic.context} */ body{font:16px system-ui;}`,'text/css');break;
      case '/robots.txt':send(options.minimalDiscovery?'User-agent: *\nSitemap: /sitemap.xml':'User-agent: *\nDisallow: /excluded\nSitemap: /sitemap.xml');break;
      case '/sitemap.xml':send(options.minimalDiscovery?'<?xml version="1.0"?><urlset/>':'<?xml version="1.0"?><urlset><url><loc>/about</loc></url><url><loc>/excluded</loc></url></urlset>','application/xml');break;
      case '/excluded':send('robots excluded');break;
      case '/api/scroll':send(JSON.stringify({lazy:'synthetic lazy content'}),'application/json');break;
      case '/api/public':send(JSON.stringify({SUPABASE_SERVICE_ROLE_KEY:syntheticJwt.service,anon:syntheticJwt.anon,session:syntheticJwt.session,DATABASE_URL:'postgres://fixture:'+synthetic.context+'@db.example.invalid/app',serviceAccount:{type:'service_account',private_key:synthetic.privateKey}}),'application/json');break;
      case '/.env':send(`OPENAI_API_KEY=${synthetic.openai}\nNEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=${synthetic.supabase}\n`);break;
      case '/.npmrc':send(`//registry.npmjs.org/:_authToken=${synthetic.context}`);break;
      case '/.git/HEAD':send('ref: refs/heads/main\n');break;
      case '/config.json':send(JSON.stringify({azure_client_secret:synthetic.context}),'application/json');break;
      case '/backup.sql':send('CREATE TABLE fixture (id int);\n'+'unrelated-data,'.repeat(150000));break;
      case '/.env.local':send('<html><body><div id="app">SPA application</div></body></html>','text/html');break;
      case '/.env.production':send('File not found. Please try a different address.');break;
      case '/login':send('<html><body><form><input type="password" name="password"></form></body></html>','text/html',401);break;
      case '/redirect-out':res.writeHead(302,{Location:other+'/redirect-target'});res.end();break;
      case '/redirect-secret':res.writeHead(302,{Location:'/collect?api_key='+synthetic.openai});res.end();break;
      case '/collect':case '/write':case '/delete':send('Should never be called');break;
      case '/big':send('x'.repeat(2*1024*1024));break;
      case '/fail':req.socket.destroy();break;
      case '/rate':send('Rate limited','text/plain',429,{'Retry-After':'1'});break;
      case '/slow':{const timer=setTimeout(()=>send('Slow response'),1500);req.on('close',()=>clearTimeout(timer));break;}
      case '/worker.js':send(`fetch('/collect?api_key='+${JSON.stringify(synthetic.openai)});fetch('/write',{method:'POST'});`,'text/javascript');break;
      case '/sw.js':send(`const PRIVATE_API_KEY=${JSON.stringify(synthetic.github)};`,'text/javascript');break;
      case '/fallback':send('<html><body><div id="app">SPA application</div></body></html>','text/html');break;
      default:send('File not found. Please try a different address.');
    }
  });
  server.on('upgrade',(req,socket)=>{arrivals.push({path:'upgrade:'+req.url,method:'UPGRADE'});socket.destroy();});
  await new Promise<void>(r=>server.listen(port,'127.0.0.1',r));
  const origin=`http://127.0.0.1:${(server.address() as any).port}`;
  return {origin,other,arrivals,setDashboardOrigin:(o:string)=>{dashboardOrigin=o;},close:async()=>{await Promise.all([server,external].map(s=>new Promise<void>(r=>{s.close(()=>r());s.closeAllConnections();})));}};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  const fixture=await createFixture(4321);console.log(`Synthetic fixture: ${fixture.origin}. All sample credentials are nonfunctional. Ctrl+C to stop.`);process.on('SIGINT',()=>void fixture.close());
}

