// Independent dynamic application fixture, frozen before the matched comparison.
import http from 'node:http';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
import {writeFile} from 'node:fs/promises';
const implementation=path.resolve(process.argv[2]||'.'),output=process.argv[3]||'benchmarks/upgrade-acquisition.json';
const {Scanner}=await import(pathToFileURL(path.join(implementation,'dist/src/scanner.js')).href),{Detector}=await import(pathToFileURL(path.join(implementation,'dist/src/detectors.js')).href);
const seed='ExposureDesk/acquisition-heldout/20261007/952',value=name=>'sk-proj-'+createHash('sha512').update(seed+name).digest('base64url').slice(0,64),codes=name=>JSON.stringify([...value(name)].map(c=>c.charCodeAt(0)));
const generated=name=>`(0,eval)('void '+JSON.stringify(String.fromCharCode(...${codes(name)})));`;
const routes={
 '/':['text/html','<script type="module" src="/main.js"></script><script src="/map.js"></script><script>new Worker("/worker.js");</script><iframe src="FRAME_ORIGIN/frame"></iframe>'],
 '/parts.js':['text/javascript','export const prefix="sk-proj-";'],
 '/main.js':['text/javascript','import {prefix} from "./parts.js";const apiKey=prefix+'+JSON.stringify(value('module').slice(8))+';'],
 '/map.js':['text/javascript','void 0;//# sourceMappingURL=/map.js.map'],
 '/map.js.map':['application/json',JSON.stringify({version:3,sources:['webpack:///config/prefix.ts','webpack:///config/app.tsx'],sourcesContent:['export const prefix: string = "sk-proj-";','import {prefix} from "./prefix.ts";const apiKey: string = prefix+'+JSON.stringify(value('map').slice(8))+';export default function App(){return <main>ordinary</main>;}'],mappings:''})],
 '/worker.js':['text/javascript',generated('worker')+`fetch('/blocked?api_key=nonfunctional-owner-example').catch(()=>{});fetch('/safe').catch(()=>{});`],
 '/frame':['text/html','<script>'+generated('iframe')+`fetch('/redirect').catch(()=>{});</script>`],
 '/settings':['text/html','<script>'+generated('route')+'</script>'],
 '/safe':['application/json','{"theme":"light","publicLabel":"ordinary","digest":"'+createHash('sha256').update('ordinary').digest('hex')+'"}'],
 '/robots.txt':['text/plain','User-agent: *\n'], '/sitemap.xml':['text/xml','<urlset/>']
};
const expected=['module','map','worker','iframe','route'].map(id=>({id,provider:'OpenAI',framework:id==='map'?'TypeScript/React':'ESM',channel:id==='module'?'cross-module':id==='map'?'source-map':id==='route'?'approved-route':'descendant-debugger',value:value(id)}));
const corpusDigest=createHash('sha256').update(JSON.stringify({seed,routes,expected})).digest('hex'),arrivals=[];let frameOrigin='';
const server=http.createServer((req,res)=>{arrivals.push(req.url);if(req.url==='/redirect'){res.writeHead(302,{location:'http://unapproved.invalid/escape'});res.end();return;}const route=routes[req.url];res.statusCode=route?200:404;res.setHeader('Content-Type',route?.[0]||'text/plain');res.end((route?.[1]||'missing').replaceAll('FRAME_ORIGIN',frameOrigin));});await new Promise(r=>server.listen(0,'127.0.0.1',r));const port=server.address().port,origin='http://primary.example.com:'+port;frameOrigin='http://isolated.example.net:'+port;
const scan=new Scanner({urls:[origin],relatedOrigins:[frameOrigin],privateOrigins:[origin,frameOrigin],browser:true,browserPages:2,browserNavigationUrls:[origin+'/settings#/approved'],browserLazyAssetLimit:5,browserSettleMs:100,adjacentMaps:false,requestsPerSecond:20,originRequestsPerSecond:20,maxDurationMs:30000,timeoutMs:1500,maxRetries:0},{detector:new Detector('disabled'),resolver:async()=>[{address:'127.0.0.1',family:4}]});
try{const start=performance.now(),view=await scan.run();const values=[...scan.evidence.findings.values()].filter(f=>f.category==='private-credential').map(f=>scan.evidence.reveal(f.id).value),rows=expected.map(e=>({...e,value:undefined,detected:values.includes(e.value)})),resources=['/','/parts.js','/main.js','/map.js','/map.js.map','/worker.js','/frame','/settings','/safe'],inspected=resources.filter(p=>view.resources.some(r=>{try{return new URL(r.url).pathname===p&&r.analysis==='analyzed'&&r.code>=200&&r.code<300;}catch{return false;}}));
const result={build:view.build,seed,corpusDigest,rows,targets:rows.length,detected:rows.filter(r=>r.detected).length,falsePositives:values.filter(v=>!expected.some(e=>e.value===v)).length,acquisition:{knownResources:resources.length,inspected:inspected.length,uninspected:resources.filter(p=>!inspected.includes(p)),runtimePages:view.browserStatus?.runtimePages,runtimeCaptures:view.accounting?.runtimeCaptures,networkAttempts:view.accounting?.networkAttempts,forbiddenArrivals:arrivals.filter(u=>u.startsWith('/blocked')||u.includes('/escape')).length},elapsedMs:performance.now()-start,maxRssKiB:process.resourceUsage().maxRSS,gaps:view.limitations.map(g=>g.code),limitations:['One synthetic dynamic application group, no population accuracy inference.','Matched settings, seed, bodies and installed Chromium; two explicitly approved browser routes.','Node peak RSS includes worker memory; native browser child memory is not included.']};await writeFile(output,JSON.stringify(result,null,2));console.log(JSON.stringify(result));if(!view.browserStatus?.launch||view.browserStatus.runtimePages<1||result.acquisition.forbiddenArrivals)process.exitCode=1;
}finally{scan.dispose();await new Promise(r=>{server.close(r);server.closeAllConnections();});}
