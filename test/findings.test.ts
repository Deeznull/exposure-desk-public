import test from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import tls from 'node:tls';
import dns from 'node:dns';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { Detector, root, detectDirect } from '../src/detectors.js';
import { Evidence } from '../src/evidence.js';
import { assessFinding, knownPublicExample } from '../src/finding-assessment.js';
import { canonicalProvider, capability } from '../src/provider-capabilities.js';
import { bip39Valid, pemStructure } from '../src/key-material.js';
import { synthetic } from '../src/fixture.js';
import type { Finding, Candidate } from '../src/types.js';
// Regression seed (the frozen evaluation corpus uses a different one). Every value is synthetic and generated here, never funded or used.
const SEED='ExposureDesk/regression-2.5/findings/1';
const bytes=(label:string,n:number)=>{const parts:Buffer[]=[];for(let i=0;Buffer.concat(parts).length<n;i++)parts.push(createHash('sha256').update(SEED+'\0'+label+'\0'+i).digest());return Buffer.concat(parts).subarray(0,n);};
const alnum=(label:string,n:number)=>[...bytes(label,n)].map(b=>'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'[b%62]).join('');
const hex=(label:string,n:number)=>bytes(label,Math.ceil(n/2)).toString('hex').slice(0,n);
const sha=(b:Buffer)=>createHash('sha256').update(b).digest();
const words=readFileSync(path.join(root,'rules','bip39-english.txt'),'utf8').trim().split('\n');
function mnemonic(entropy:Buffer){let bits=[...entropy].map(b=>b.toString(2).padStart(8,'0')).join('')+[...sha(entropy)].map(b=>b.toString(2).padStart(8,'0')).join('').slice(0,entropy.length/4);const out:string[]=[];for(let i=0;i<bits.length;i+=11)out.push(words[parseInt(bits.slice(i,i+11),2)]);return out.join(' ');}
const B58='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const base58=(b:Buffer)=>{let n=BigInt('0x'+b.toString('hex'));let s='';while(n>0n){s=B58[Number(n%58n)]+s;n/=58n;}for(const x of b){if(x)break;s='1'+s;}return s;};
const check=(p:Buffer)=>base58(Buffer.concat([p,sha(sha(p)).subarray(0,4)]));
const N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const scalar=(label:string)=>{for(let i=0;;i++){const h=hex(label+i,64);if(BigInt('0x'+h)>0n&&BigInt('0x'+h)<N)return h;}};
const wif=(label:string,testnet=false)=>check(Buffer.concat([Buffer.from([testnet?0xef:0x80]),Buffer.from(scalar(label),'hex'),Buffer.from([1])]));
const ext=(label:string,version:string,priv=true)=>check(Buffer.concat([Buffer.from(version,'hex'),Buffer.alloc(9),bytes(label+'c',32),priv?Buffer.concat([Buffer.alloc(1),Buffer.from(scalar(label),'hex')]):Buffer.concat([Buffer.from([2]),bytes(label+'p',32)])]));
const mutate=(s:string,at=12)=>s.slice(0,at)+(s[at]==='A'?'B':'A')+s.slice(at+1);
async function findings(text:string,url='https://www.example.com/assets/app.js'){const e=new Evidence(new Detector('disabled'));await e.inspect(text,url,[],'Public response');const out=[...e.findings.values()].map(f=>({...f,value:e.reveal(f.id).value}));e.clear();return out;}
const of=(list:Awaited<ReturnType<typeof findings>>,value:string)=>list.filter(f=>f.value===value&&['private-credential','suspicious'].includes(f.category));
const base=(over:Partial<Finding>):Finding=>({id:'x',fingerprint:'x',category:'private-credential',provider:'Stripe',rule:'stripe-secret',severity:'high',confidence:'high',reasons:[],masked:'[redacted]',validity:'unverified',impact:'',remediation:'',occurrences:[{url:'https://www.example.com/app.js',chain:[],transformations:[],excerpt:'',evidence:'',exposure:'public-response',environment:'production'}],...over} as Finding);

test('priority matrix: financial priority follows impact type, completeness, exposure, environment, documentation, public examples and owner records; severity never changes',()=>{
  const level=(f:Finding,ctx={})=>assessFinding(f,ctx).priority.level;
  const pem=base({provider:'Private signing key',rule:'private-key',severity:'critical'}),a=assessFinding(pem);assert.equal(a.priority.level,'urgent');assert.equal(a.financialPriority,'none','a signing key is critical but not financial');assert.deepEqual(a.impacts.map(i=>i.kind),['signing-encryption']);
  const live=assessFinding(base({}));assert.equal(live.priority.level,'urgent');assert.equal(live.financialPriority,'urgent');assert.ok(live.impact.includes('never estimated')&&live.impact.includes('Not established'));
  const test=base({occurrences:[{...base({}).occurrences[0],environment:'test'}]});assert.equal(level(test),'review');assert.equal(assessFinding(test).financialPriority,'review');
  const paypal=base({provider:'PayPal',rule:'provider-context:paypal',credentialSet:{state:'partial',components:['client secret'],missing:['client ID'],context:'x'}});const p=assessFinding(paypal);assert.equal(p.priority.level,'urgent');assert.ok(p.priority.basis.includes('only an identifier component is missing'));assert.ok(p.qualifiers.includes('partial-missing-identifier'));
  const asia=base({provider:'AWS',rule:'provider-context:aws',credentialSet:{state:'partial',components:['access-key ID','secret access key'],missing:['session token'],context:'x'}});assert.equal(level(asia),'review');assert.ok(assessFinding(asia).qualifiers.includes('partial-missing-secret'));
  assert.equal(level(base({occurrences:[{...base({}).occurrences[0],exposure:'blocked-candidate'}]})),'high');assert.equal(level(base({occurrences:[{...base({}).occurrences[0],exposure:'local-only'}]})),'high');
  assert.equal(level(base({qualifiers:['known-public-example']})),'low');assert.equal(level(base({occurrences:[{...base({}).occurrences[0],documentation:true}]})),'review');
  assert.equal(level(base({}),{owner:{restrictions:'restricted',recordedAt:'x',source:'owner-statement'}}),'review');
  assert.equal(level(base({}),{lifecycle:{revocation:{state:'owner-confirmed',at:'x',note:'',replacement:'replaced'},website:{state:'observed'}}}),'review');
  assert.equal(level(base({}),{lifecycle:{revocation:{state:'owner-confirmed',at:'x',note:'',replacement:'replaced'},website:{state:'not-observed'}}}),'low');
  assert.equal(level(base({category:'suspicious'})),'review');assert.equal(level(base({category:'public-identifier'})),'none');assert.equal(level(base({confidence:'medium'})),'high');
  for(const f of [pem,test,asia])assert.equal(f.severity,assessFinding(f).priority&&f.severity,'technical severity is preserved');
});

test('environment aggregates across occurrences independent of order; production wins; sandbox hosts are test evidence',async()=>{
  const value='sk_live_'+alnum('env',24),c=(environment:Candidate['environment']):Candidate=>({value,original:value,index:0,rule:'stripe-secret',provider:'Stripe',category:'private-credential',severity:'high',confidence:'high',reasons:['x'],transformations:[],environment});
  const run=async(order:Candidate['environment'][])=>{const e=new Evidence(new Detector('disabled'));order.forEach((env,i)=>e.add({...c(env),value:'rk_x_'+alnum('order',20)},'x','https://www.example.com/'+i+'.js',[],'Public response'));const f=[...e.findings.values()][0];const r=f.environment;e.clear();return r;};
  assert.equal(await run(['test','unknown','test']),await run(['unknown','test','test']));assert.equal(await run(['test','unknown','test']),'unknown');assert.equal(await run(['test','test']),'test');assert.equal(await run(['test','production','test']),'production');
  const basic=Buffer.from('client:'+alnum('pp',32)).toString('base64');const paypal=of(await findings(`fetch("https://api-m.sandbox.paypal.com/v1/oauth2/token",{method:"POST",headers:{Authorization:"Basic ${basic}"}});`),basic);assert.equal(paypal.length,1);assert.equal(paypal[0].environment,'test');assert.equal(paypal[0].priority!.level,'review');
  const sq='EAAA'+alnum('square',60);const square=of(await findings(`fetch("https://connect.squareupsandbox.com/v2/payments",{headers:{Authorization:"Bearer ${sq}"}});`),sq);assert.equal(square[0]?.environment,'test');
});

test('Gitleaks rule prefixes map to canonical providers and groups',()=>{
  for(const [prefix,name,group]of [['plaid','Plaid','payments'],['gocardless','GoCardless','payments'],['gcp','Google Cloud','cloud'],['private','Private signing key','signing'],['kucoin','KuCoin','crypto'],['pypi','PyPI','deployment'],['telegram','Telegram','messaging']] as const){assert.equal(canonicalProvider(prefix,'gitleaks:'+prefix+'-x'),name);assert.equal(capability(name).group,group);}
  assert.equal(canonicalProvider('unknownvendor','gitleaks:unknownvendor-token'),'unknownvendor','unknown prefixes keep their name');assert.equal(capability('unknownvendor').group,'other');
});

test('usage context finds opaque signing secrets and credentials sent to unmapped hosts; verification, hashing and dynamic values stay negative',async()=>{
  const k=(l:string)=>alnum(l,32);
  for(const [id,code,value] of [['jwt.sign',`const t=jwt.sign({sub:1},"${k('jwt')}",{expiresIn:"1h"});`,k('jwt')],['createHmac',`require("crypto").createHmac("sha256","${k('hmac')}").update(b);`,k('hmac')],['CryptoJS.AES',`CryptoJS.AES.encrypt(data,"${k('aes')}");`,k('aes')],['SignJWT',`await new SignJWT({a:1}).setProtectedHeader({alg:"HS256"}).sign(new TextEncoder().encode("${k('jose')}"));`,k('jose')],['importKey',`crypto.subtle.importKey("raw",new TextEncoder().encode("${k('subtle')}"),{name:"HMAC",hash:"SHA-256"},false,["sign"]);`,k('subtle')],['jwtSecret field',`const settings={jwtSecret:"${k('field')}",issuer:"app"};`,k('field')],['sessionSecret const',`const sessionSecret="${k('session')}";`,k('session')]] as const){
    const f=of(await findings(code),value);assert.equal(f[0]?.category,'private-credential',id);assert.equal(f[0]?.provider,'Application signing',id);assert.equal(f[0]?.exposureGroup,'signing',id);}
  const bearer=alnum('bearer',40),b=of(await findings(`fetch("https://api.billing-partner.example.com/v1/charges",{headers:{Authorization:"Bearer ${bearer}"}});`),bearer);assert.equal(b[0]?.category,'suspicious');assert.equal(b[0]?.provider,'example.com (unreviewed provider)');
  const pair=Buffer.from('svc:'+alnum('basic',20)).toString('base64'),bp=of(await findings(`axios.get("https://reports.partner-api.example.net/x",{headers:{Authorization:"Basic ${pair}"}});`),pair);assert.equal(bp[0]?.category,'private-credential','decoded Basic user:password is a complete credential');
  const sdk=alnum('sdk',32),s=of(await findings(`const p=new Pusher({appId:"1234567",key:"${alnum('sdkkey',20)}",secret:"${sdk}",cluster:"eu"});`),sdk);assert.equal(s[0]?.category,'private-credential');assert.match(s[0]!.provider,/Pusher \(unreviewed provider\)/);
  for(const [id,code,value] of [['jwt.verify',`jwt.verify(token,"${k('verify')}");`,k('verify')],['createHash',`crypto.createHash("sha256").update("${k('hash')}").digest("hex");`,k('hash')],['CryptoJS.SHA256',`CryptoJS.SHA256("${k('sha')}").toString();`,k('sha')],['dynamic bearer','fetch("https://api.example.org/me",{headers:{Authorization:"Bearer "+token}});','Bearer '],['env key','jwt.sign(p,process.env.JWT_SECRET);','process.env.JWT_SECRET']] as const)assert.equal(of(await findings(code),value).length,0,id);
  const pk='pk_live_'+alnum('pk',24);assert.ok((await findings(`Stripe("${pk}")`)).filter(f=>f.value===pk).every(f=>f.category==='public-identifier'));
});

test('seed phrases need the exact word count, every word in the list and a valid checksum; slices, prose, swapped words and published vectors stay out of urgent findings',async()=>{
  const m12=mnemonic(bytes('m12',16)),m24=mnemonic(bytes('m24',32));assert.ok(bip39Valid(m12)&&bip39Valid(m24));
  const a=of(await findings(`const wallet={mnemonic:"${m12}"};`),m12);assert.equal(a[0]?.category,'private-credential');assert.equal(a[0]?.provider,'Wallet seed phrase');assert.equal(a[0]?.priority?.level,'urgent');assert.deepEqual(a[0]?.impacts?.map(i=>i.kind),['payment-asset-access']);
  assert.equal(of(await findings(`const w=ethers.Wallet.fromPhrase("${m24}");`),m24)[0]?.category,'private-credential');
  const swapped=m12.split(' ');swapped[3]=swapped[3]==='zoo'?'zone':'zoo';assert.equal(of(await findings(`const wallet={mnemonic:"${swapped.join(' ')}"};`),swapped.join(' ')).length,0,'bad checksum');
  // An alphabetical run of list words with a valid checksum is a wordlist slice, not a wallet.
  let sorted='';for(let i=0;i<words.length&&!sorted;i++){const head=words.slice(0,11);const cand=[...head,words[100+i]].join(' ');if(bip39Valid(cand))sorted=cand;}assert.ok(sorted);assert.equal(of(await findings(`const wallet={mnemonic:"${sorted}"};`),sorted).length,0,'alphabetical slice');
  assert.equal((await findings(`const list="${words.join(' ')}";`)).filter(f=>f.provider==='Wallet seed phrase').length,0,'bundled wordlist');
  assert.equal((await findings('<p>Enter your 12-word recovery phrase to continue. Lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor.</p>','https://www.example.com/')).filter(f=>f.provider==='Wallet seed phrase').length,0,'prose');
  const vector='abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';assert.ok(knownPublicExample(vector));const v=(await findings(`const cfg={mnemonic:"${vector}"};`)).filter(f=>f.value===vector);assert.ok(v.every(f=>f.priority?.level==='low'&&f.qualifiers?.includes('known-public-example')),'published test vectors are low priority');
});

test('a missing or altered wordlist disables only seed-phrase checks and is reported; wallet keys are still found',()=>{
  const dir=mkdtempSync(path.join(process.env.EXPOSURE_DATA_DIR||path.join(root,'.cache'),'bip39-'));try{const bad=path.join(dir,'english.txt');writeFileSync(bad,readFileSync(path.join(root,'rules','bip39-english.txt'),'utf8').replace('abandon','abandom'));
    const script=`import {Detector} from ${JSON.stringify(pathToFileURL(path.join(root,'dist/src/detectors.js')).href)};const d=new Detector('missing-binary');await d.init();const m=${JSON.stringify(mnemonic(bytes('child',16)))},w=${JSON.stringify(wif('child'))};const found=d.inspectSync('const a={mnemonic:"'+m+'"};const b="'+w+'";');console.log(JSON.stringify({issues:d.issues,seed:found.some(c=>c.rule==='bip39-mnemonic'),wif:found.some(c=>c.rule==='wif-private-key')}));`;
    const r=spawnSync(process.execPath,['--input-type=module','-e',script],{env:{...process.env,EXPOSURE_BIP39_WORDLIST:bad},encoding:'utf8',windowsHide:true});const out=JSON.parse(r.stdout.trim().split('\n').at(-1)!);
    assert.ok(out.issues.some((i:string)=>/BIP39 wordlist/.test(i)));assert.equal(out.seed,false);assert.equal(out.wif,true);
  }finally{rmSync(dir,{recursive:true,force:true});}
});

test('wallet keys are structural: WIF and extended keys need valid checksums and versions; hex keys need a key name or wallet constructor and an in-range scalar; Solana keys need fromSecretKey',async()=>{
  const main=wif('main'),testnet=wif('test',true),xprv=ext('xprv','0488ade4'),xpub=ext('xpub','0488b21e',false);
  const w=of(await findings(`const backup="${main}";`),main);assert.equal(w[0]?.rule,'wif-private-key');assert.equal(w[0]?.priority?.level,'urgent');
  assert.equal(of(await findings(`const backup="${mutate(main)}";`),mutate(main)).length,0,'one-character mutation');
  const t=of(await findings(`const backup="${testnet}";`),testnet);assert.equal(t[0]?.environment,'test');assert.equal(t[0]?.priority?.level,'review');
  assert.equal(of(await findings(`const root="${xprv}";`),xprv)[0]?.rule,'extended-private-key');assert.ok((await findings(`const watch="${xpub}";`)).some(f=>f.value===xpub&&f.category==='public-identifier'));
  const k1=scalar('k1'),k2=scalar('k2');assert.equal(of(await findings(`const signer={privateKey:"0x${k1}"};`),'0x'+k1)[0]?.provider,'Wallet private key');assert.equal(of(await findings(`const w=new ethers.Wallet("${k2}",provider);`),k2)[0]?.provider,'Wallet private key');
  for(const name of ['txHash','hash','integrity','address','blockHash'])assert.equal(of(await findings(`const r={${name}:"0x${k1}"};`),'0x'+k1).length,0,name);
  assert.equal(of(await findings(`const s={privateKey:"0x${'0'.repeat(64)}"};`),'0x'+'0'.repeat(64)).length,0,'zero');assert.equal(of(await findings(`const s={privateKey:"0x${N.toString(16)}"};`),'0x'+N.toString(16)).length,0,'at the curve order');
  const ints=[...bytes('sol',64)],sol='['+ints.join(',')+']';assert.equal(of(await findings(`const kp=Keypair.fromSecretKey(Uint8Array.from([${ints.join(', ')}]));`),sol)[0]?.rule,'solana-secret-key');assert.equal(of(await findings(`const weights=[${ints.join(',')}];`),sol).length,0,'64 integers elsewhere');
});

test('PEM, JWK and PGP structure: DER bodies verify, encrypted keys are qualified, truncated examples are documentation; public JWKs produce nothing',async()=>{
  const der=Buffer.concat([Buffer.from('308204bc020100300d06092a864886f70d0101010500048204a6','hex'),bytes('der',1190)]),pem='-----BEGIN PRIVATE KEY-----\n'+der.toString('base64').match(/.{1,64}/g)!.join('\n')+'\n-----END PRIVATE KEY-----';
  assert.equal(pemStructure(pem).structure,'verified');const f=(await findings(`const key=${JSON.stringify(pem)};`)).find(f=>f.rule==='private-key')!;assert.equal(f.keyStructure,'verified');assert.equal(f.priority?.level,'urgent');
  const enc='-----BEGIN ENCRYPTED PRIVATE KEY-----\n'+bytes('enc',600).toString('base64').match(/.{1,64}/g)!.join('\n')+'\n-----END ENCRYPTED PRIVATE KEY-----';const e=(await findings(`const key=${JSON.stringify(enc)};`)).find(f=>f.rule==='private-key')!;assert.ok(e.qualifiers?.includes('encrypted-material'));
  const doc='-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...your key here...\n-----END RSA PRIVATE KEY-----';assert.equal(pemStructure(doc).structure,'truncated');
  const legacy=(await findings(synthetic.privateKey)).find(f=>f.rule==='private-key');assert.ok(legacy,'the legacy synthetic key is still detected');assert.notEqual(legacy!.keyStructure,'truncated');
  const d=Buffer.from(bytes('jwk',32)).toString('base64url');assert.equal(of(await findings(`const jwk={"kty":"EC","crv":"P-256","x":"${bytes('x',32).toString('base64url')}","y":"${bytes('y',32).toString('base64url')}","d":"${d}"};`),d)[0]?.provider,'JWK private key');
  assert.equal((await findings(`const jwks={"keys":[{"kty":"EC","crv":"P-256","x":"${bytes('x2',32).toString('base64url')}","y":"${bytes('y2',32).toString('base64url')}"}]};`)).filter(f=>['private-credential','suspicious'].includes(f.category)).length,0,'public JWKS');
  const k=bytes('oct',32).toString('base64url');assert.equal(of(await findings(`const key={"kty":"oct","k":"${k}","alg":"HS256"};`),k)[0]?.provider,'Application signing');
  const pgp='-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n'+bytes('pgp',400).toString('base64').match(/.{1,64}/g)!.join('\n')+'\n=QWER\n-----END PGP PRIVATE KEY BLOCK-----';assert.ok((await findings(`const armored=${JSON.stringify(pgp)};`)).some(f=>f.rule==='pgp-private-key'&&f.category==='private-credential'));
});

test('documentation context lowers priority but never hides a finding; the same value in a deployed asset stays urgent',async()=>{
  const key='sk_live_'+alnum('docs',24),docs=`<html><body><h2>Configure</h2><pre><code>STRIPE_KEY=${key}</code></pre></body></html>`;
  const e=new Evidence(new Detector('disabled'));await e.inspect(docs,'https://www.example.com/docs/payments',[],'Public response');let f=[...e.findings.values()].find(f=>e.reveal(f.id).value===key)!;assert.equal(f.priority?.level,'review');assert.ok(f.qualifiers?.includes('documentation-context'));
  await e.inspect(`Stripe("${key}")`,'https://www.example.com/assets/app.js',[],'Public response');f=[...e.findings.values()].find(f=>e.reveal(f.id).value===key)!;assert.equal(f.priority?.level,'urgent','one deployed occurrence clears the documentation qualifier');e.clear();
  const docKey='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',g=new Evidence(new Detector('disabled'));g.startTriage(()=>{});await g.inspect(`<pre><code>AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=${docKey}</code></pre>`,'https://www.example.com/docs/aws',[],'Public response');await g.triage!.flush();
  assert.ok(![...g.findings.values()].some(f=>g.reveal(f.id).value===docKey),'the published AWS documentation example is dismissed from findings');assert.ok(g.dismissedView().some(f=>f.qualifiers?.includes('known-public-example')),'and kept in the masked dismissed audit');g.clear();
});

test('detection never contacts anything: no socket, TLS connection or DNS lookup happens while every structural and usage check runs',async()=>{
  const saved={connect:net.connect,createConnection:net.createConnection,tls:tls.connect,lookup:dns.lookup};let attempts=0;const trip=(..._a:unknown[])=>{attempts++;throw new Error('network tripwire');};
  (net as any).connect=trip;(net as any).createConnection=trip;(tls as any).connect=trip;(dns as any).lookup=trip;
  try{const text=[`const wallet={mnemonic:"${mnemonic(bytes('trip',16))}"};`,`const k="${wif('trip')}";`,`const s={privateKey:"0x${scalar('trip')}"};`,`jwt.sign(p,"${alnum('trip',32)}");`,`fetch("https://api.unknown-issuer.example.com/v1",{headers:{Authorization:"Bearer ${alnum('tripb',40)}"}});`,`const pem=${JSON.stringify(synthetic.privateKey)};`].join('\n');
    const found=detectDirect(text);assert.ok(found.length>=5);await findings(text);assert.equal(attempts,0);
  }finally{(net as any).connect=saved.connect;(net as any).createConnection=saved.createConnection;(tls as any).connect=saved.tls;(dns as any).lookup=saved.lookup;}
});
