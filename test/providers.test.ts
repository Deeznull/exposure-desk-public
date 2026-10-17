import test from 'node:test';
import assert from 'node:assert/strict';
import { Detector } from '../src/detectors.js';
import { Evidence } from '../src/evidence.js';
import { providerCases,negativeCases } from './provider-fixtures.js';
import { syntheticBundle } from './large-bundle.js';
import { synthetic } from '../src/fixture.js';
import { createHash } from 'node:crypto';
import type { Candidate } from '../src/types.js';
for(const example of providerCases)test('provider benchmark: '+example.id,()=>{
 const d=new Detector(),found=d.inspectSync(example.text),matches=found.filter(c=>c.value===example.value&&c.provider===example.provider&&c.category===(example.category||'private-credential'));
 assert.ok(matches.length>0,'Planted synthetic credential must be detected under its provider and category');
 if(example.set)assert.ok(matches.some(c=>c.credentialSet?.state===example.set),'Credential set completeness must match source evidence');
 for(const c of matches)assert.ok(c.index>=0&&c.index<example.text.length&&example.text.includes(c.original),'Source representation/location must refer to actual source');
 const e=new Evidence(d);for(const c of found)e.add(c,example.text,'https://synthetic.invalid/config.js',[],'offline synthetic fixture');assert.ok(!JSON.stringify(e.redact([...e.findings.values()])).includes(example.value),'Routine evidence must stay redacted');
 if(example.environment)assert.ok([...e.findings.values()].some(f=>f.provider===example.provider&&f.environment===example.environment));
});
for(const negative of negativeCases)test('provider negative benchmark: '+negative.id,()=>{const found=new Detector().inspectSync(negative.text);if(negative.id==='unrelated-objects')assert.ok(!found.some(c=>c.credentialSet?.state==='complete'),'Separate credential objects cannot form a complete set');else assert.ok(!found.some(c=>c.category==='private-credential'),'Public values, placeholders, hashes and dynamic references must not become private credentials');});
test('provider reconstruction inspects minified Base64/percent/escape/split values at true source locations',()=>{
 const sample=providerCases.find(c=>c.id==='openai-project')!,d=new Detector();for(const representation of [JSON.stringify(sample.value),JSON.stringify(Buffer.from(sample.value).toString('base64')),JSON.stringify(sample.value.replace(/./g,c=>'%'+c.charCodeAt(0).toString(16))),JSON.stringify(sample.value.slice(0,30))+'+'+JSON.stringify(sample.value.slice(30)),JSON.stringify(sample.value).replace('sk-','\\u0073k-')]){const text='const a='+representation+';';const c=d.inspectSync(text).find(c=>c.value===sample.value);assert.ok(c);assert.ok(text.includes(c.original)&&c.index>=0);}
});
test('realistic large bundle retains a late planted secret and endpoint-only evidence stays information',async()=>{
 const d=new Detector(),sample=providerCases.find(c=>c.id==='openai-project')!,text='/*'+'generated code padding;'.repeat(100000)+'*/\n'+sample.text;
 assert.ok(d.inspectSync(text).some(c=>c.value===sample.value&&c.index>2000000));const e=new Evidence(d);await e.inspect('const endpoint="https://api.openai.com/v1/responses";','https://synthetic.invalid/app.js',[],'synthetic');assert.ok([...e.findings.values()].every(f=>f.category==='information'));assert.ok(e.findings.size>0);
});
test('private signing keys receive provider attribution from their own object rather than another service account',()=>{const d=new Detector(),e=new Evidence(d),google=providerCases.find(c=>c.id==='google-service-account')!,coinbase=providerCases.find(c=>c.id==='coinbase-signing')!,different='-----BEGIN PRIVATE KEY-----\n'+Buffer.from('a distinct synthetic nonfunctional key').toString('base64')+'\n-----END PRIVATE KEY-----';const text='const google='+google.text+';const coinbase='+coinbase.text.replace(JSON.stringify(coinbase.value),JSON.stringify(different))+';';for(const c of d.inspectSync(text))e.add(c,text,'https://synthetic.invalid/config.js',[],'synthetic');assert.ok([...e.findings.values()].some(f=>f.provider==='Google Cloud'&&f.credentialSet?.state==='complete'));assert.ok([...e.findings.values()].some(f=>f.provider==='Coinbase'&&f.credentialSet?.state==='complete'));});
// External review (2026-10): synthetic values derived from labels; nonfunctional by construction.
const derived=(label:string,n:number)=>{let s='';for(let i=0;s.length<n;i++)s+=createHash('sha256').update('ExposureDesk/external-review/'+label+i).digest('base64');return s.slice(0,n);};
const privateAt=(found:Candidate[],value:string)=>found.filter(c=>c.value===value&&c.category==='private-credential').map(c=>c.provider+'/'+(c.credentialSet?.state||'')).sort();
test('large bundles keep provider context: credential objects past the window size are classified as in a small file, components stay non-private',()=>{
 const d=new Detector(),session='ASIA'+derived('aws-id',16).toUpperCase().replace(/[^A-Z0-9]/g,'Q'),secret=derived('aws-secret',40),azure=derived('azure-secret',40),sid='AC'+createHash('sha256').update('twilio-sid').digest('hex').slice(0,32),token=createHash('sha256').update('twilio-token').digest('hex').slice(0,32),lone='AKIA'+derived('aws-lone',16).toUpperCase().replace(/[^A-Z0-9]/g,'Q');
 const module=`const credentials={provider:"AWS",accessKeyId:${JSON.stringify(session)},secretAccessKey:${JSON.stringify(secret)}};function s3(){return new AWS.S3({credentials});}const azure={clientSecret:${JSON.stringify(azure)}};const twilio={accountSid:${JSON.stringify(sid)},authToken:${JSON.stringify(token)}};const ids={accountSid:${JSON.stringify(sid)},accessKeyId:${JSON.stringify(lone)}};`;
 const small=d.inspectSync(module),bundle=syntheticBundle({targetBytes:400000}).text.replace('\n//# sourceMapping','\n'+module+'\n//# sourceMapping'),large=d.inspectSync(bundle);
 assert.ok(bundle.length>131072*2&&bundle.indexOf(module)>131072);
 for(const value of [secret,azure,token]){assert.ok(privateAt(small,value).length,'small-file reference classification');assert.deepEqual(privateAt(large,value),privateAt(small,value),'a large bundle keeps the enclosing object, scope and provider');}
 for(const value of [session,sid,lone])assert.ok(!large.some(c=>c.value===value&&c.category==='private-credential'),'identifiers and lone components stay non-private');
 assert.ok(large.some(c=>c.value===secret&&c.category==='private-credential'&&c.index===bundle.indexOf(JSON.stringify(secret))&&c.original===JSON.stringify(secret)),'location is the literal in the bundle');
 // Text that is not JavaScript keeps window-only results; nothing is invented.
 const prose='padding words without code; '.repeat(6000)+`secretAccessKey ${secret}`;assert.ok(!d.inspectSync(prose).some(c=>c.value===secret&&c.category==='private-credential'));
});
test('plain-text configuration: PHP constants, env files and debug-page tables carry framework signing keys and database passwords; placeholders stay quiet',()=>{
 const d=new Detector(),password=derived('db-password',20).replace(/[+/=]/g,'_'),salt=derived('wp-auth',60).replace(/\+/g,'!').replace(/\//g,'#')+'$%(;',nonce=derived('wp-nonce',64),appKey='base64:'+Buffer.from(derived('laravel',32)).subarray(0,32).toString('base64'),client=derived('oauth-client',48).replace(/[+/=]/g,'x'),session=derived('session',40);
 const wp=`<?php\n/** The name of the database */\ndefine( 'DB_NAME', 'shop' );\n\n/** Database username */\ndefine( 'DB_USER', 'shop' );\n\n/** Database password */\ndefine( 'DB_PASSWORD', '${password}' );\n\ndefine( 'DB_HOST', 'localhost' );\n\ndefine('AUTH_KEY', "${salt}");\ndefine('NONCE_SALT', '${nonce}');\n`;
 let found=d.inspectSync(wp);assert.deepEqual(privateAt(found,password),['Database/private-material']);assert.deepEqual(privateAt(found,salt),['Application signing/private-material']);assert.deepEqual(privateAt(found,nonce),['Application signing/private-material']);
 const sample=`<?php\ndefine( 'DB_NAME', 'database_name_here' );\ndefine( 'DB_USER', 'username_here' );\ndefine( 'DB_PASSWORD', 'password_here' );\ndefine( 'DB_HOST', 'localhost' );\ndefine( 'AUTH_KEY', 'put your unique phrase here' );\ndefine( 'NONCE_SALT', 'put your unique phrase here' );\n`;
 assert.ok(!d.inspectSync(sample).some(c=>c.category==='private-credential'),'the wp-config sample placeholders are not credentials');
 const env=`APP_NAME=Shop\nAPP_KEY=${appKey}\nSESSION_SECRET=${session}\n\nDB_CONNECTION=mysql\nDB_HOST=127.0.0.1\nDB_USERNAME=shop\nDB_PASSWORD=${password}\n`;
 found=d.inspectSync(env);assert.deepEqual(privateAt(found,appKey),['Application signing/private-material']);assert.deepEqual(privateAt(found,session),['Application signing/private-material']);assert.deepEqual(privateAt(found,password),['Database/private-material']);
 for(const quiet of ['APP_KEY=\nDB_HOST=127.0.0.1\nDB_PASSWORD=secret\n',`APP_KEY=${appKey.slice(7)}\n`,`DB_PASSWORD=${password}\n`,'DB_HOST=db\nDB_PASSWORD=${DATABASE_PASSWORD_FROM_VAULT}\n','SESSION_SECRET="keyboard cat and more words"\nDB_HOST=db\nDB_PASSWORD="two words here"\n'])
  assert.ok(!d.inspectSync(quiet).some(c=>c.category==='private-credential'&&['Database','Application signing'].includes(c.provider)),'empty, unprefixed, context-free, templated and space-separated values are not framework or database credentials (never a truncated value)');
 const page=`<h2>Environment</h2><table><tr><th>APP_KEY</th><td>${appKey}</td></tr><tr><th>APP_ENV</th><td>production</td></tr><tr><th>OAUTH_CLIENT_SECRET</th><td>${client}</td></tr><tr><td>SECRET_KEY</td><td class="code"><pre>&#39;********************&#39;</pre></td></tr></table>`;
 found=d.inspectSync(page);assert.deepEqual(privateAt(found,appKey),['Application signing/private-material']);assert.deepEqual(privateAt(found,client),['OAuth/partial']);assert.ok(found.filter(c=>c.value===appKey).every(c=>page.slice(c.index,c.index+appKey.length)===appKey));
 assert.ok(!found.some(c=>/^\*+$/.test(c.value)),'masked debug values are not findings');
});
test('service-account endpoints and key identifiers are not private credentials; the key stays a complete Google Cloud credential',()=>{
 const google=providerCases.find(c=>c.id==='google-service-account')!,keyId=createHash('sha1').update('service-account-key-id').digest('hex'),account=JSON.parse(google.text);
 const text=JSON.stringify({...account,project_id:'synthetic-project',private_key_id:keyId,client_id:'100000000000000000001',auth_uri:'https://accounts.google.com/o/oauth2/auth',token_uri:'https://oauth2.googleapis.com/token'});
 const found=new Detector().inspectSync(text);assert.ok(found.some(c=>c.value===google.value&&c.provider==='Google Cloud'&&c.credentialSet?.state==='complete'));
 assert.deepEqual(found.filter(c=>c.category==='private-credential'&&c.value!==google.value).map(c=>c.rule+':'+c.value.length),[],'only the private key is private');
 assert.ok(found.some(c=>c.value===keyId&&c.category==='public-identifier'));
});
test('hex strings decode statically to their text at the source representation; binary digests do not, and character-code calls stay runtime-only',()=>{
 const d=new Detector(),value=synthetic.anthropic,hex=Buffer.from(value).toString('hex'),codes=[...value].map(c=>c.charCodeAt(0)).join(',');
 for(const text of [`const legacy="${hex}";`,`const legacy='${hex.toUpperCase()}';`]){const original=text.slice(text.indexOf('=')+2,-2);
  const c=d.inspectSync(text).find(c=>c.value===value&&c.category==='private-credential');assert.ok(c);assert.equal(c.original,original);assert.equal(c.index,text.indexOf(original));assert.deepEqual(c.transformations,['Hex decoding']);}
 const digests=`const integrity="${createHash('sha256').update('a').digest('hex')}${createHash('sha256').update('b').digest('hex')}";`;
 assert.ok(!d.inspectSync(digests).some(c=>c.transformations.includes('Hex decoding')));
 // String.fromCharCode is a function call: browser debugger capture sees its result; static analysis never evaluates it (the ablation fixtures rely on this boundary).
 for(const text of [`const k=String.fromCharCode(...[${codes}]);`,`const k=String.fromCharCode(${codes});`])assert.ok(!d.inspectSync(text).some(c=>c.value===value));
});
