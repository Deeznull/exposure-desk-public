// Frozen before/after evaluation corpus for 2.4.0-rc.1 → 2.5.0-rc.1. Synthetic, nonfunctional values only; generated deterministically from the seed.
// It imports no product code, so both implementations are measured on identical inputs. Regression tests use different seeds.
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
export const seed='ExposureDesk/eval-2.5/20261008/1';
export const WORDLIST_SHA256='2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda';
const wordlistText=readFileSync(new URL('../rules/bip39-english.txt',import.meta.url),'utf8');
export const wordlistDigest=createHash('sha256').update(wordlistText).digest('hex');
if(wordlistDigest!==WORDLIST_SHA256)throw new Error('BIP39 wordlist digest mismatch; the corpus cannot be generated');
const words=wordlistText.trim().split('\n');
const block=(label,i)=>createHash('sha256').update(seed+'\0'+label+'\0'+i).digest();
const bytes=(label,n)=>{const parts=[];let have=0;for(let i=0;have<n;i++){const b=block(label,i);parts.push(b);have+=b.length;}return Buffer.concat(parts).subarray(0,n);};
const alnum=(label,n)=>{const a='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';return [...bytes(label,n)].map(b=>a[b%62]).join('');};
const hex=(label,n)=>bytes(label,Math.ceil(n/2)).toString('hex').slice(0,n);
const b64url=(buf)=>Buffer.from(buf).toString('base64url');
const sha256=(b)=>createHash('sha256').update(b).digest();
const B58='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58(buf){let n=BigInt('0x'+(Buffer.from(buf).toString('hex')||'0'));let s='';while(n>0n){s=B58[Number(n%58n)]+s;n/=58n;}for(const b of buf){if(b!==0)break;s='1'+s;}return s;}
const base58check=(payload)=>base58(Buffer.concat([payload,sha256(sha256(payload)).subarray(0,4)]));
const N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
/** A scalar 1 ≤ k < n for secp256k1, as 64 hex characters. */
function scalar(label){for(let i=0;;i++){const h=hex(label+'/'+i,64),k=BigInt('0x'+h);if(k>0n&&k<N)return h;}}
function mnemonic(entropy){const ent=entropy.length*8,cs=ent/32,hash=sha256(entropy);let bits='';for(const b of entropy)bits+=b.toString(2).padStart(8,'0');bits+=[...hash].map(b=>b.toString(2).padStart(8,'0')).join('').slice(0,cs);const out=[];for(let i=0;i<bits.length;i+=11)out.push(words[parseInt(bits.slice(i,i+11),2)]);return out.join(' ');}
function invalidMnemonic(label,count){for(let i=0;;i++){const b=bytes(label+'/'+i,count*2),picked=[];for(let j=0;j<count;j++)picked.push(words[((b[2*j]<<8)|b[2*j+1])%2048]);const phrase=picked.join(' ');if(!validMnemonic(phrase))return phrase;}}
function validMnemonic(phrase){const list=phrase.split(' ');if(![12,15,18,21,24].includes(list.length))return false;let bits='';for(const w of list){const i=words.indexOf(w);if(i<0)return false;bits+=i.toString(2).padStart(11,'0');}const cs=list.length/3,ent=bits.slice(0,bits.length-cs),entropy=Buffer.from(ent.match(/.{8}/g).map(x=>parseInt(x,2)));return [...sha256(entropy)].map(b=>b.toString(2).padStart(8,'0')).join('').slice(0,cs)===bits.slice(-cs);}
const wif=(label,testnet=false)=>base58check(Buffer.concat([Buffer.from([testnet?0xef:0x80]),Buffer.from(scalar(label),'hex'),Buffer.from([0x01])]));
function extendedKey(label,kind){const version=Buffer.from(kind==='xprv'?'0488ade4':'0488b21e','hex'),depth=Buffer.from([0]),fingerprint=Buffer.alloc(4),child=Buffer.alloc(4),chain=bytes(label+'/chain',32);const key=kind==='xprv'?Buffer.concat([Buffer.from([0]),Buffer.from(scalar(label),'hex')]):Buffer.concat([Buffer.from([0x02]),bytes(label+'/pub',32)]);return base58check(Buffer.concat([version,depth,fingerprint,child,chain,key]));}
const mutate=(s,at=10)=>s.slice(0,at)+(s[at]==='A'?'B':'A')+s.slice(at+1);
/** DER-shaped PKCS#8 body around random inner bytes: structurally plausible, never a usable key. */
function pkcs8Pem(label){const inner=bytes(label,1190);const der=Buffer.concat([Buffer.from('308204bc020100300d06092a864886f70d0101010500048204a6','hex'),inner]);return '-----BEGIN PRIVATE KEY-----\n'+der.toString('base64').match(/.{1,64}/g).join('\n')+'\n-----END PRIVATE KEY-----';}
const doc=(id,text,url,expect,value,extra={})=>({id,group:'G7',url:url||`https://acceptance.invalid/assets/${id}.js`,text,value,expect,...extra});
function walletCases(){
  const m12=mnemonic(bytes('m12',16)),m24=mnemonic(bytes('m24',32)),m24b=mnemonic(bytes('m24b',32)),k1=scalar('hex-privateKey'),k2=scalar('hex-wallet'),sol=[...bytes('solana',64)];
  const opaque=(l,n=32)=>alnum(l,n),stripeLive='sk_live_'+alnum('stripe-live',24),stripeTest='sk_test_'+alnum('stripe-test',24),awsId='AKIA'+alnum('aws-id',16).toUpperCase(),awsSecret=alnum('aws-secret',40),asia='ASIA'+alnum('asia-id',16).toUpperCase();
  const jwkD=b64url(bytes('jwk-d',32)),pgp='-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n'+bytes('pgp',600).toString('base64').match(/.{1,64}/g).join('\n')+'\n=abcd\n-----END PGP PRIVATE KEY BLOCK-----';
  const pos=(id,text,value,expect)=>doc(id,text,undefined,{detect:true,...expect},value);
  const neg=(id,text,value,expect={})=>doc(id,text,undefined,{detect:false,...expect},value);
  return [
    pos('bip39-12-context',`const config={mnemonic:${JSON.stringify(m12)},network:"mainnet"};`,m12,{category:'private-credential',impact:'payment-asset-access',priority:'urgent'}),
    pos('bip39-24-fromPhrase',`const w=ethers.Wallet.fromPhrase(${JSON.stringify(m24)});`,m24,{category:'private-credential',impact:'payment-asset-access',priority:'urgent'}),
    pos('bip39-24-no-context',`const words=${JSON.stringify(m24b)};render(words);`,m24b,{category:'private-credential'}),
    pos('wif-mainnet',`const backup=${JSON.stringify(wif('wif-main'))};`,wif('wif-main'),{category:'private-credential',impact:'payment-asset-access'}),
    pos('wif-testnet',`const backup=${JSON.stringify(wif('wif-test',true))};`,wif('wif-test',true),{category:'private-credential',environment:'test',priority:'review'}),
    pos('xprv',`const root=${JSON.stringify(extendedKey('xprv','xprv'))};`,extendedKey('xprv','xprv'),{category:'private-credential',impact:'payment-asset-access'}),
    pos('hex-privateKey-field',`const signer={privateKey:"0x${k1}",chainId:1};`,'0x'+k1,{category:'private-credential',impact:'payment-asset-access'}),
    pos('hex-wallet-sink',`const wallet=new ethers.Wallet("0x${k2}",provider);`,'0x'+k2,{category:'private-credential',impact:'payment-asset-access'}),
    pos('solana-fromSecretKey',`const kp=Keypair.fromSecretKey(Uint8Array.from([${sol.join(',')}]));`,'['+sol.join(',')+']',{category:'private-credential',impact:'payment-asset-access',valueMatch:'contains-bytes'}),
    pos('pem-pkcs8',`const key=${JSON.stringify(pkcs8Pem('pem'))};`,pkcs8Pem('pem'),{category:'private-credential',impact:'signing-encryption',financial:'none'}),
    pos('jwk-ec-d',`const jwk={"kty":"EC","crv":"P-256","x":"${b64url(bytes('jwk-x',32))}","y":"${b64url(bytes('jwk-y',32))}","d":"${jwkD}"};`,jwkD,{category:'private-credential',impact:'signing-encryption'}),
    pos('jwt-sign-sink',`const token=jwt.sign({sub:user.id},${JSON.stringify(opaque('jwt-sign'))},{expiresIn:"1h"});`,opaque('jwt-sign'),{category:'private-credential',impact:'signing-encryption'}),
    pos('hmac-sink',`const sig=crypto.createHmac("sha256",${JSON.stringify(opaque('hmac'))}).update(body).digest("hex");`,opaque('hmac'),{category:'private-credential',impact:'signing-encryption'}),
    pos('cryptojs-aes-sink',`const enc=CryptoJS.AES.encrypt(JSON.stringify(data),${JSON.stringify(opaque('aes'))}).toString();`,opaque('aes'),{category:'private-credential',impact:'signing-encryption'}),
    pos('bearer-unmapped-host',`fetch("https://api.billing-partner.example.com/v1/charges",{headers:{Authorization:"Bearer ${opaque('bearer',40)}"}});`,opaque('bearer',40),{category:'suspicious'}),
    pos('camel-jwtSecret',`const settings={jwtSecret:${JSON.stringify(opaque('jwtSecret'))},issuer:"app"};`,opaque('jwtSecret'),{category:'private-credential',impact:'signing-encryption'}),
    pos('stripe-live',`const stripe=Stripe(${JSON.stringify(stripeLive)});`,stripeLive,{category:'private-credential',impact:'payment-asset-access',priority:'urgent',financial:'urgent'}),
    pos('pgp-private',`const armored=${JSON.stringify(pgp)};`,pgp,{category:'private-credential',impact:'signing-encryption',valueMatch:'contains-pgp'}),
    pos('aws-complete-pair',`const aws={accessKeyId:"${awsId}",secretAccessKey:"${awsSecret}"};`,awsSecret,{category:'private-credential',impact:'cloud-spending',priority:'urgent',financial:'urgent'}),
    pos('stripe-test',`const stripe=Stripe(${JSON.stringify(stripeTest)});`,stripeTest,{category:'private-credential',environment:'test',priority:'review'}),
    pos('paypal-sandbox-host',`fetch("https://api-m.sandbox.paypal.com/v1/oauth2/token",{method:"POST",headers:{Authorization:"Basic ${Buffer.from('client:'+opaque('paypal-sb')).toString('base64')}"}});`,Buffer.from('client:'+opaque('paypal-sb')).toString('base64'),{category:'private-credential',environment:'test'}),
    pos('aws-asia-no-session',`const aws={accessKeyId:"${asia}",secretAccessKey:"${alnum('asia-secret',40)}"};`,alnum('asia-secret',40),{category:'private-credential',priority:'review'}),
    pos('paypal-secret-only',`const paypal={clientSecret:${JSON.stringify(opaque('paypal-secret',48))}};`,opaque('paypal-secret',48),{category:'private-credential',priority:'urgent'}),
    doc('docs-aws-example','<html><body><h1>Setup</h1><pre><code>AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY</code></pre></body></html>','https://acceptance.invalid/docs/setup',{detect:'any',priority:'low',qualifier:'known-public-example'},'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'),
    doc('docs-context-generic',`<html><body><h2>Example</h2><pre><code>const settings={jwtSecret:${JSON.stringify(opaque('docs-jwt'))}};</code></pre></body></html>`,'https://acceptance.invalid/docs/auth',{detect:'any',priority:'review',qualifier:'documentation-context'},opaque('docs-jwt')),
    neg('neg-txHash',`const receipt={txHash:"0x${hex('tx',64)}",blockHash:"0x${hex('block',64)}"};`,'0x'+hex('tx',64)),
    neg('neg-sha256-hash',`const hash="${hex('digest',64)}";verify(hash);`,hex('digest',64)),
    neg('neg-address',`const address="0x${hex('addr',40)}";`,'0x'+hex('addr',40)),
    neg('neg-xpub',`const watch=${JSON.stringify(extendedKey('xpub','xpub'))};`,extendedKey('xpub','xpub'),{category:'public-identifier'}),
    neg('neg-wif-bad-checksum',`const backup=${JSON.stringify(mutate(wif('wif-bad')))};`,mutate(wif('wif-bad'))),
    neg('neg-pixel-array',`const pixels=[${[...bytes('pixels',64)].join(',')}];draw(pixels);`,'['+[...bytes('pixels',64)].join(',')+']',{valueMatch:'contains-bytes'}),
    doc('neg-bip39-test-vector',`const config={mnemonic:"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"};`,undefined,{detect:'any',priority:'low',qualifier:'known-public-example'},'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'),
    neg('neg-recovery-prose','<html><body><label>Enter your 12-word recovery phrase to continue</label><input name="phrase"></body></html>','Enter your 12-word recovery phrase to continue'),
    neg('neg-random-words',`const config={mnemonic:${JSON.stringify(invalidMnemonic('random-words',12))}};`,invalidMnemonic('random-words',12)),
    neg('neg-jwt-verify',`jwt.verify(token,"-----BEGIN PUBLIC KEY-----\\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE${b64url(bytes('pub',48))}\\n-----END PUBLIC KEY-----");`,'-----BEGIN PUBLIC KEY-----'),
    neg('neg-createHash',`const etag=crypto.createHash("sha256").update(${JSON.stringify(opaque('hash-input'))}).digest("hex");`,opaque('hash-input')),
    neg('neg-cryptojs-sha',`const id=CryptoJS.SHA256(${JSON.stringify(opaque('sha-input'))}).toString();`,opaque('sha-input')),
    neg('neg-bearer-concat','fetch("https://api.example.com/me",{headers:{Authorization:"Bearer "+token}});','Bearer '),
    neg('neg-stripe-publishable',`Stripe(${JSON.stringify('pk_live_'+alnum('pk',24))});`,'pk_live_'+alnum('pk',24),{category:'public-identifier'}),
    neg('neg-zero-key',`const signer={privateKey:"0x${'0'.repeat(64)}"};`,'0x'+'0'.repeat(64)),
    neg('neg-key-at-order',`const signer={privateKey:"0x${N.toString(16)}"};`,'0x'+N.toString(16)),
    neg('neg-solana-elsewhere',`const weights=[${[...bytes('weights',64)].join(',')}];`,'['+[...bytes('weights',64)].join(',')+']',{valueMatch:'contains-bytes'}),
  ];
}
/** 1,252,570-byte webpack-style bundle (eval seed): ~2,400 modules, negatives throughout, a key split across safe constants in the last ~3%, a lazy chunk table, a worker URL and a source map comment past the first MiB. */
function largeBundle({fixed=false}={}){
  const target=1252570,key='sk-proj-'+alnum('bundle-key',64),mutated='sk-proj-'+alnum('bundle-mutated',64),late='late.'+hex('late',8)+'.js',chunk='chunk.'+hex('chunk',8)+'.js';
  const head=key.slice(8,40),rest=key.slice(40);
  const mod=i=>`${i}:function(e,t,n){"use strict";var a=n(${(i*7)%2400}),o={".woff":"font/woff",".json":"application/json"};function r${i}(s){return s.endsWith(".json")?o[".json"]:a.map${i%9}(s)}t.ext${i}=".woff";t.r${i}=r${i}},`;
  const tail=`9001:function(e,t){t.p="sk-proj-"},9002:function(e,t){t.h=${JSON.stringify(head)}},9003:function(e,t,n){var p=n(9001).p,h=n(9002).h,c=p+h+${JSON.stringify(rest)};t.client={apiKey:c}},9004:function(e,t){var b="sk-proj-",m=${JSON.stringify(mutated.slice(8))};function x(){m="changed"}t.k=b+m},9005:function(e,t){t.cfg={stripe:"sk_test_${alnum('bundle-test',24)}",publishable:"pk_live_${alnum('bundle-pk',24)}",apiKey:"your_api_key_here",json:".json"}},9006:function(e,t){t.u=window.location.host+"/v1/"+e.id}}${fixed?']':''});\nn.u=function(e){return {7:"${chunk}"}[e]};import("./${late}");new Worker(new URL("./worker.${hex('worker',6)}.js",import.meta.url));\n//# sourceMappingURL=main.js.map\n`;
  let body='(self.webpackChunkapp=self.webpackChunkapp||[]).push([[179],{';let i=0;const reserve=Buffer.byteLength(tail)+64;while(Buffer.byteLength(body)+reserve<target){const m=mod(i++);if(Buffer.byteLength(body)+Buffer.byteLength(m)+reserve>target)break;body+=m;}
  const pad=target-Buffer.byteLength(body)-Buffer.byteLength(tail);if(pad>=4)body+='/*'+'p'.repeat(pad-4)+'*/';const text=body+tail;
  return {text,bytes:Buffer.byteLength(text),modules:i,expected:[key],negatives:[mutated,'sk_test_'+alnum('bundle-test',24),'pk_live_'+alnum('bundle-pk',24)],late,chunk,worker:`worker.${hex('worker',6)}.js`};
}
/** G5F (2.9): the G5 bundle with its frozen syntax error corrected (the webpack push now closes its module object and array: `}}]);`), so a parser
 * reads the whole file and split-key reconstruction is actually measured. Kept outside corpus() so the frozen 2.5 digest is unchanged; same byte size,
 * same key, negatives, late chunk and worker. */
export function g5Fixed(){return {group:'G5F',bundle:{name:'main.'+hex('main',8)+'.js',...largeBundle({fixed:true})}};}
export function corpus(){
  const bundle=largeBundle();
  const G1={group:'G1',seed:'https://example.com/',hosts:{
    'https://example.com':{'/':{type:'text/html',body:'<a href="https://aaa.example.com/">a</a><a href="https://x.y.example.com/">b</a><a href="https://xn--bcher-kva.example.com/">idn</a><a href="http://example.com:8080/">port</a><a href="https://example.com.evil.net/">deceptive</a><a href="https://notexample.com/">lookalike</a><a href="https://xn--exmple-cua.com/">homograph</a><script src="https://cdn.thirdparty.net/lib.js"></script><a href="https://internal.example.com/">i</a><a href="https://meta.example.com/">m</a><a href="https://mixed.example.com/">x</a><a href="https://user:pass@creds.example.com/">c</a><a href="https://hop.example.com/out">r1</a><a href="https://hop.example.com/in">r2</a>'+['c1','c2','c3','c4','c5','c6'].map(n=>`<a href="https://${n}.example.com/">${n}</a>`).join('')}},
    'https://aaa.example.com':{'/':{type:'text/html',body:'aaa'}},'https://x.y.example.com':{'/':{type:'text/html',body:'nested'}},'https://xn--bcher-kva.example.com':{'/':{type:'text/html',body:'idn'}},'http://example.com:8080':{'/':{type:'text/html',body:'port'}},
    'https://hop.example.com':{'/out':{status:302,headers:{location:'https://evil.example.net/'}},'/in':{status:302,headers:{location:'https://bbb.example.com/'}}},'https://bbb.example.com':{'/':{type:'text/html',body:'bbb'}},
    ...Object.fromEntries(['c1','c2','c3','c4','c5','c6'].map(n=>[`https://${n}.example.com`,{'/':{type:'text/html',body:n}}]))},
    dns:{'internal.example.com':['10.0.0.5'],'meta.example.com':['169.254.169.254'],'mixed.example.com':['93.184.216.34','127.0.0.1']},
    variants:{default:{},explicitDomain:{domainScope:'registrable-domain'},exactOnly:{sameRegistrableDomainDiscovery:false},cap3:{domainScope:'registrable-domain',maxAutoDiscoveredOrigins:3}},
    positives:['https://aaa.example.com','https://x.y.example.com','https://xn--bcher-kva.example.com','http://example.com:8080','https://bbb.example.com'],
    negatives:['https://example.com.evil.net','https://notexample.com','https://xn--exmple-cua.com','https://cdn.thirdparty.net','https://evil.example.net'],forbidden:['https://internal.example.com','https://meta.example.com','https://mixed.example.com','https://creds.example.com'],
    tenants:{seed:'https://tenant-b.github.io/',hosts:{'https://tenant-b.github.io':{'/':{type:'text/html',body:'<a href="https://tenant-a.github.io/">other tenant</a><a href="https://docs.tenant-b.github.io/">own</a>'}},'https://docs.tenant-b.github.io':{'/':{type:'text/html',body:'own'}},'https://tenant-a.github.io':{'/':{type:'text/html',body:'other'}}},positives:['https://docs.tenant-b.github.io'],negatives:['https://tenant-a.github.io']}};
  const shell='<!doctype html><html><head><title>App</title></head><body><div id="root"></div><script src="/main.js"></script></body></html>';
  const G2={group:'G2',files:{'/':{type:'text/html',body:shell},'/main.js':{type:'text/javascript',body:'var a={ext:".css"};var t=".json",f=\'.woff\';function k(n){return n.endsWith(".js")}fetch("config.json").then(r=>r.json());import("./chunk-a.js");new Worker(new URL("./w.js",import.meta.url));var m={1:"chunk-b"};self.__chunkUrl=function(i){return "/"+m[i]+".js"};'},'/config.json':{type:'application/json',body:'{"feature":true}'},'/chunk-a.js':{type:'text/javascript',body:'export const a=1;'},'/w.js':{type:'text/javascript',body:'self.onmessage=()=>{};'},'/manifest.json':{type:'application/json',body:'{"start_url":"/","icons":[{"src":"/icon.png"}]}'}},catchAll:shell,falseHints:['/.json','/.woff','/.css','/.js'],kept:['/config.json','/chunk-a.js','/w.js']};
  const G3={group:'G3',files:{'/':{type:'text/html',body:shell.replace('</body>','<link rel="preload" href="/assets/app.css" as="style"><a href="/login">Sign in</a></body>')},'/main.js':{type:'text/javascript',body:'fetch("/assets/data.json");import("/assets/lazy.js");'}},catchAll:shell,assetHints:['/assets/data.json','/assets/lazy.js','/assets/app.css'],explicitRoutes:['/dashboard'],loginPath:'/login'};
  const G4={group:'G4',pages:12,files:{'/main.js':{type:'text/javascript',body:'const settings={apiKey:"'+'sk-proj-'+alnum('g4-key',64)+'"};fetch("/api/ping");'},'/api/ping':{type:'application/json',body:'{}'}},mirrors:['/main.js?v=1','/main.js?v=2'],bases:['/a/','/b/'],expected:['sk-proj-'+alnum('g4-key',64)]};
  const G5={group:'G5',bundle:{name:'main.'+hex('main',8)+'.js',...bundle}};
  const G6={group:'G6',variants:{shortDeadline:{maxDurationMs:4000,projectMaxDurationMs:4000},cancelAfterDownload:{cancelAfterMs:150},smallSlices:{semanticSliceMs:100}}};
  const G7={group:'G7',cases:walletCases()};
  const G8={group:'G8',page:'/account/settings?ref=newsletter&uid=123',files:{'/account/settings':{type:'text/html',body:'<!doctype html><html><body><link rel="stylesheet" href="/style.css"><script src="/app.js"></script></body></html>'},'/app.js':{type:'text/javascript',body:"fetch('/report?lang='+encodeURIComponent(navigator.language)+'&tz='+encodeURIComponent(Intl.DateTimeFormat().resolvedOptions().timeZone));"},'/style.css':{type:'text/css',body:'body{}'}},sensitive:['/account/settings','uid=123','ref=newsletter']};
  const G9={group:'G9',gapMs:50};
  return {seed,wordlistDigest,groups:{G1,G2,G3,G4,G5,G6,G7,G8,G9}};
}
const serialized=JSON.stringify(corpus());
export const corpusDigest=createHash('sha256').update(serialized).digest('hex');
export const corpusBytes=Buffer.byteLength(serialized);
/** Structural self-check of the generated fixtures (run before freezing): positives are well formed and negatives are not, so a detector result reflects the detector, not the corpus. */
export function selfCheck(){
  const c=corpus(),byId=Object.fromEntries(c.groups.G7.cases.map(x=>[x.id,x]));const decode58=s=>{let n=0n;for(const ch of s){const i=B58.indexOf(ch);if(i<0)return null;n=n*58n+BigInt(i);}let h=n.toString(16);if(h.length%2)h='0'+h;const lead=s.match(/^1*/)[0].length;return Buffer.concat([Buffer.alloc(lead),Buffer.from(h,'hex')]);};
  const checksumOk=s=>{const b=decode58(s);if(!b||b.length<5)return false;return sha256(sha256(b.subarray(0,-4))).subarray(0,4).equals(b.subarray(-4));};
  return {mnemonic12:validMnemonic(byId['bip39-12-context'].value),mnemonic24:validMnemonic(byId['bip39-24-fromPhrase'].value)&&validMnemonic(byId['bip39-24-no-context'].value),vector:validMnemonic(byId['neg-bip39-test-vector'].value),randomWordsInvalid:!validMnemonic(byId['neg-random-words'].value),
    wifMain:checksumOk(byId['wif-mainnet'].value)&&decode58(byId['wif-mainnet'].value)[0]===0x80,wifTest:checksumOk(byId['wif-testnet'].value)&&decode58(byId['wif-testnet'].value)[0]===0xef,wifBadInvalid:!checksumOk(byId['neg-wif-bad-checksum'].value),
    xprv:checksumOk(byId['xprv'].value)&&decode58(byId['xprv'].value).length===82&&byId['xprv'].value.startsWith('xprv'),xpub:checksumOk(byId['neg-xpub'].value)&&byId['neg-xpub'].value.startsWith('xpub'),
    hexInRange:['hex-privateKey-field','hex-wallet-sink'].every(id=>{const k=BigInt(byId[id].value);return k>0n&&k<N;}),zeroAndOrderOut:BigInt(byId['neg-zero-key'].value)===0n&&BigInt(byId['neg-key-at-order'].value)===N,
    bundleBytes:c.groups.G5.bundle.bytes===1252570,fixedBundleBytes:g5Fixed().bundle.bytes===1252570};
}
