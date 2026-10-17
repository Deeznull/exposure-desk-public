// Frozen acceptance data: do not tune provider rules against these cases.
import {createHash} from 'node:crypto';
export const seed='ExposureDesk/acceptance/20261007/418';
const token=(name,n=64)=>createHash('sha512').update(seed+name).digest('base64url').slice(0,n);
const key=name=>'sk-proj-'+token(name);
const source=(name,text)=>({url:'https://acceptance.invalid/'+name,text});
export const corpus=[];
function add(id,provider,framework,channel,sources,expected=[],options={}){corpus.push({id,group:id.split('/')[0],split:'evaluation',provider,framework,channel,sources,expected,...options});}
for(const [provider,prefix] of [['OpenAI','sk-proj-'],['Anthropic','sk-ant-api03-'],['Stripe','sk_live_'],['Groq','gsk_']]){
 const value=prefix+token(provider).replace(/[-_]/g,'Q');
 add('literal-'+provider,provider,'plain','text',[source('literal.js','const apiKey='+JSON.stringify(value)+';')],[value]);
 add('split-'+provider,provider,'ESM','semantic',[source('parts.js','export const left='+JSON.stringify(value.slice(0,25))+';'),source('main.js','import {left} from "./parts.js"; const apiKey=left+'+JSON.stringify(value.slice(25))+';')],[value]);
}
add('typescript', 'OpenAI','TypeScript','semantic',[source('config.ts','export const prefix: string = "sk-proj-"; export const tail: string = '+JSON.stringify(token('ts'))+'; const apiKey: string = prefix+tail;')],[key('ts')]);
add('tsx','OpenAI','React','semantic',[source('app.tsx','const prefix="sk-proj-"; const suffix='+JSON.stringify(token('tsx'))+'; const config={apiKey:prefix+suffix}; export default function App(){return <main>Public application</main>;}')],[key('tsx')]);
add('sdk-alias','OpenAI','ESM','semantic',[source('sdk.js','import Vendor from "openai"; const a="sk-proj-"; const b='+JSON.stringify(token('sdk'))+'; new Vendor({["api"+"Key"]:a+b});')],[key('sdk')]);
add('bundle-tail','OpenAI','minified','semantic',[source('bundle.js','/*'+'ordinary vendor text '.repeat(58000)+'*/const p="sk-proj-";const apiKey=p+'+JSON.stringify(token('bundle'))+';')],[key('bundle')]);
add('dependencies-pressure','OpenAI','ESM','semantic',Array.from({length:24},(_,i)=>source('vendor'+i+'.js','const unused=['+'1,'.repeat(10000)+'1];')).concat([source('parts.js','export const prefix="sk-proj-";'),source('main.js','import {prefix} from "./parts.js";const apiKey=prefix+'+JSON.stringify(token('graph'))+';')]),[key('graph')]);
add('hash-bcrypt','Website','JSON','exposure',[source('api.json',JSON.stringify({user:{password_hash:'$2b$12$'+token('bcrypt',53).replace(/[-_]/g,'.')}}))],[],{expectedRules:['exposed-password-hash']});
add('hash-argon','Website','JSON','exposure',[source('api.json',JSON.stringify({passwordHash:'$argon2id$v=19$m=65536,t=3,p=1$c2FuaXRpemVk$'+token('argon',32)}))],[],{expectedRules:['exposed-password-hash']});
add('sensitive-owner','Website','JSON','exposure',[source('api.json',JSON.stringify({profile:{nationalId:'SYNTHETIC-OWNER-418'}}))],[],{expectedRules:['sensitive-response-field'],sensitiveFields:[{path:'profile.nationalId',expectation:'private'}]});
add('private-config','Website','JSON','exposure',[source('config.json',JSON.stringify({database:{host:'db.internal',password:'sanitized-owner-secret-418'},debug:true}))],[],{expectedRules:['private-configuration']});
add('debug-detail','Website','Express','exposure',[source('error.json',JSON.stringify({stack:'Error: synthetic failure\n at handler (/srv/private/application.js:81:9)\n at run (/srv/private/router.js:29:4)'}))],[],{expectedRules:['detailed-debug-output']});
for(let i=0;i<20;i++)add('ordinary-'+i,'none',i%2?'JSON':'plain','negative',[source('config'+i+'.json',JSON.stringify({id:token('id'+i,32),hash:createHash('sha256').update('ordinary'+i).digest('hex'),theme:'light',cacheKey:'render-'+i,environment:'production',publicPath:'/assets',count:i}))]);
for(const [i,value] of ['pk_live_'+token('public',32).replace(/[-_]/g,'A'),'sb_publishable_'+token('pubsup',40),'YOUR_API_KEY_HERE','REPLACE_ME','example_secret','00000000000000000000000000000000'].entries())add('public-placeholder-'+i,'none','plain','negative',[source('public.js','const publicConfig={publishableKey:'+JSON.stringify(value)+'};')]);
add('unknown-expression','none','ESM','negative',[source('dynamic.js','const p="sk-proj-";const apiKey=p+getUnknown();')]);
add('mutated-alias','none','ESM','negative',[source('mutation.js','const a={prefix:"sk-proj-"};const b=a;b.prefix=getUnknown();const apiKey=a.prefix+'+JSON.stringify(token('mutated'))+';')]);
add('public-hash','none','JSON','negative',[source('docs.json',JSON.stringify({integrity:'a'.repeat(64),password_hash:'$2b$12$'+token('publichash',53).replace(/[-_]/g,'.')}))],[],{sensitiveFields:[{path:'password_hash',expectation:'public'}]});
add('public-owner','none','JSON','negative',[source('profile.json',JSON.stringify({profile:{nationalId:'SANITIZED-PUBLIC-EXAMPLE'}}))],[],{sensitiveFields:[{path:'profile.nationalId',expectation:'public'}]});
export const corpusDigest=createHash('sha256').update(JSON.stringify(corpus)).digest('hex');
