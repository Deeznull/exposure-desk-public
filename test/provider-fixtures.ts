import { synthetic } from '../src/fixture.js';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { root } from '../src/detectors.js';
export interface ProviderCase {id:string;text:string;value:string;provider:string;category?:string;set?:string;environment?:string}
const opaque=(length=40)=>'Ab9Cx7Dy5Ez3Fh1Gi0Jk8Lm6No4Pq2RsTuVwXyZ'.repeat(5).slice(0,length);
const cases:ProviderCase[]=[];
const field=(provider:string,key:string,value=opaque(),set='private-material')=>{cases.push({id:provider.toLowerCase().replace(/[^a-z0-9]/g,'-')+'-'+key,text:JSON.stringify({provider,[key]:value}),value,provider,set});};
for(const provider of ['OpenAI','Anthropic','Cohere','Replicate','Hugging Face','ElevenLabs','Stability AI','Groq','Mistral','Perplexity','OpenRouter','DigitalOcean','SendGrid','Mailgun','Vercel','Netlify','Heroku','Sentry','Square'])field(provider,'apiKey');
for(const [id,value,provider,category,environment]of [
 ['openai-project',synthetic.openai,'OpenAI','private-credential','unknown'],['anthropic-api',synthetic.anthropic,'Anthropic','private-credential','unknown'],
 ['hf',synthetic.hf,'Hugging Face','private-credential','unknown'],['replicate',synthetic.replicate,'Replicate','private-credential','unknown'],['sendgrid',synthetic.sendgrid,'SendGrid','private-credential','unknown'],
 ['groq','gsk_'+opaque(52),'Groq','private-credential','unknown'],['perplexity','pplx-'+opaque(48),'Perplexity','private-credential','unknown'],['openrouter','sk-or-v1-'+opaque(64),'OpenRouter','private-credential','unknown'],
 ['digitalocean-pat','dop_v1_'+('a1b2c3d4'.repeat(8)),'DigitalOcean','private-credential','unknown'],['digitalocean-oauth','doo_v1_'+('a1b2c3d4'.repeat(8)),'DigitalOcean','private-credential','unknown'],
 ['bedrock-long','ABSK'+opaque(120),'AWS Bedrock','private-credential','unknown'],['bedrock-short','bedrock-api-key-'+opaque(120),'AWS Bedrock','private-credential','unknown'],
 ['stripe-org','sk_org_'+opaque(48),'Stripe','private-credential','unknown'],['stripe-sk-live','sk_live_'+opaque(24),'Stripe','private-credential','production'],['stripe-rk-live','rk_live_'+opaque(24),'Stripe','private-credential','production'],['stripe-sk-test','sk_test_'+opaque(24),'Stripe','private-credential','test'],['stripe-rk-test','rk_test_'+opaque(24),'Stripe','private-credential','test'],['stripe-pk-live','pk_live_'+opaque(24),'Stripe','public-identifier','production'],['stripe-pk-test','pk_test_'+opaque(24),'Stripe','public-identifier','test'],['stripe-webhook','whsec_'+opaque(32),'Stripe','private-credential','unknown'],
 ['google-api',synthetic.google,'Google / Gemini','suspicious','unknown'],['sentry-auth','sntryu_'+opaque(64),'Sentry','private-credential','unknown'],['mailgun-public','pubkey-'+('a1b2c3d4'.repeat(4)),'Mailgun','public-identifier','unknown'],
 ['cloudflare-user','cfut_'+opaque(48),'Cloudflare','private-credential','unknown'],['cloudflare-account','cfat_'+opaque(48),'Cloudflare','private-credential','unknown'],['cloudflare-global','cfk_'+opaque(48),'Cloudflare','private-credential','unknown'],['cloudflare-access','cfast_'+opaque(48),'Cloudflare','private-credential','unknown'],
 ['github',synthetic.github,'GitHub','private-credential','unknown'],['supabase',synthetic.supabase,'Supabase','private-credential','unknown']
])cases.push({id,text:'const token='+JSON.stringify(value)+';',value,provider,category,environment});
const relation=(id:string,provider:string,fields:Record<string,string>,key:string,set='complete')=>cases.push({id,provider,text:JSON.stringify({provider,...fields}),value:fields[key],set});
relation('aws-long','AWS',{accessKeyId:'AKIAAB9CX7DY5EZ3FH1G',secretAccessKey:opaque(40)},'secretAccessKey');
relation('aws-temp','AWS',{accessKeyId:'ASIAAB9CX7DY5EZ3FH1G',secretAccessKey:opaque(40),sessionToken:opaque(120)},'secretAccessKey');
relation('aws-temp-partial','AWS',{accessKeyId:'ASIAAB9CX7DY5EZ3FH1G',secretAccessKey:opaque(40)},'secretAccessKey','partial');
relation('route53','AWS Route53',{accessKeyId:'AKIAAB9CX7DY5EZ3FH1G',secretAccessKey:opaque(40)},'secretAccessKey');
relation('azure-client','Azure',{clientId:'123e4567-e89b-12d3-a456-426614174000',tenantId:'123e4567-e89b-12d3-a456-426614174001',clientSecret:opaque()},'clientSecret');
relation('paypal-complete','PayPal',{clientId:opaque(24),clientSecret:opaque()},'clientSecret');relation('paypal-partial','PayPal',{clientSecret:opaque()},'clientSecret','partial');
relation('braintree','Braintree',{merchantId:opaque(16),publicKey:opaque(16),privateKey:opaque(32)},'privateKey');
relation('twilio-auth','Twilio',{accountSid:'AC'+('a1b2c3d4'.repeat(4)),authToken:'a1b2c3d4'.repeat(4)},'authToken');
relation('twilio-api','Twilio',{apiKeySid:'SK'+('a1b2c3d4'.repeat(4)),secret:opaque(32)},'secret');
relation('kraken','Kraken',{apiKey:opaque(56),secret:Buffer.from(opaque(64)).toString('base64')},'secret');
relation('binance','Binance',{apiKey:opaque(64),secretKey:opaque(64)},'secretKey');
relation('coinbase-exchange','Coinbase',{apiKey:opaque(32),secret:opaque(64),passphrase:opaque(16)},'secret');
relation('vonage','Vonage',{apiKey:'a1b2c3d4',apiSecret:opaque(16)},'apiSecret');
relation('godaddy','GoDaddy',{apiKey:opaque(24),secret:opaque(24)},'secret');
relation('namecheap','Namecheap',{apiKey:opaque(32),apiUser:'synthetic-user',username:'synthetic-user',clientIp:'203.0.113.1'},'apiKey');
relation('cloudflare-global-pair','Cloudflare',{globalApiKey:'a1b2c3d4'.repeat(5),email:'synthetic@invalid.test'},'globalApiKey');field('Cloudflare','apiToken');
relation('oauth-secret','OAuth',{clientId:'synthetic-public-client',clientSecret:opaque()},'clientSecret');
relation('google-service-account','Google Cloud',{type:'service_account',client_email:'synthetic@invalid.iam.gserviceaccount.com',private_key:synthetic.privateKey},'private_key');
relation('coinbase-signing','Coinbase',{name:'organizations/synthetic/apiKeys/synthetic',privateKey:synthetic.privateKey},'privateKey');
relation('vonage-signing','Vonage',{applicationId:'123e4567-e89b-12d3-a456-426614174000',privateKey:synthetic.privateKey},'privateKey');
for(const provider of ['OpenAI','Anthropic','Google Cloud','AWS Bedrock'])field(provider,'accessToken',opaque(80));
field('GoDaddy','pat');
cases.push({id:'env-crlf-location',provider:'GoDaddy',text:'PUBLIC_NAME=synthetic\r\n\r\nexport GODADDY_PAT="'+opaque()+'"\r\n',value:opaque(),set:'private-material'});
cases.push({id:'qualified-json-openai',provider:'OpenAI',text:JSON.stringify({OPENAI_API_KEY:opaque()}),value:opaque(),set:'private-material'});
cases.push({id:'qualified-json-aws',provider:'AWS',text:JSON.stringify({AWS_ACCESS_KEY_ID:'ASIAAB9CX7DY5EZ3FH1G',AWS_SECRET_ACCESS_KEY:opaque(),AWS_SESSION_TOKEN:opaque(100)}),value:opaque(),set:'complete'});
for(const [id,value,provider]of [
 ['openai-legacy','sk-'+opaque(48),'OpenAI'],['openai-service-account','sk-svcacct-'+opaque(80),'OpenAI'],
 ['anthropic-admin','sk-ant-admin01-'+opaque(80),'Anthropic'],['anthropic-oauth','sk-ant-oat01-'+opaque(80),'Anthropic'],
 ['sentry-service','sntrys_'+opaque(64),'Sentry'],['digitalocean-refresh','dor_v1_'+('a1b2c3d4'.repeat(8)),'DigitalOcean'],
 ['digitalocean-application','doa_v1_'+('a1b2c3d4'.repeat(8)),'DigitalOcean']
])cases.push({id,value,provider,text:'const credential='+JSON.stringify(value)+';'});
cases.push({id:'sdk-variable-split',provider:'Mistral',text:'const credential="'+opaque().slice(0,20)+'" + "'+opaque().slice(20)+'"; const client=new Mistral({apiKey:credential});',value:opaque(),set:'private-material'});
cases.push({id:'request-header',provider:'ElevenLabs',text:'fetch("https://api.elevenlabs.io/v1/models",{headers:{"xi-api-key":"'+opaque(32)+'"}})',value:opaque(32),set:'private-material'});
cases.push({id:'azure-account-key',provider:'Azure',text:'DefaultEndpointsProtocol=https;AccountName=synthetic;AccountKey='+Buffer.from(opaque(64)).toString('base64')+';EndpointSuffix=core.windows.net',value:Buffer.from(opaque(64)).toString('base64'),set:'complete'});
cases.push({id:'azure-sas',provider:'Azure',text:'https://synthetic.blob.core.windows.net/container/file?sv=2025-01-05&sp=r&sr=b&sig='+encodeURIComponent(Buffer.from(opaque(32)).toString('base64')),value:Buffer.from(opaque(32)).toString('base64'),set:'private-material'});
// Wallet, key and signing families (2.5): structurally valid synthetic values generated from a fixture seed; never funded or used.
const fx=(label:string,n:number)=>{const parts:Buffer[]=[];let have=0;for(let i=0;have<n;i++){const b=createHash('sha256').update('ExposureDesk/provider-fixtures/2.5\0'+label+'\0'+i).digest();parts.push(b);have+=b.length;}return Buffer.concat(parts).subarray(0,n);};
const sha=(b:Buffer)=>createHash('sha256').update(b).digest(),B58='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const b58check=(p:Buffer)=>{const b=Buffer.concat([p,sha(sha(p)).subarray(0,4)]);let n=BigInt('0x'+b.toString('hex')),s='';while(n>0n){s=B58[Number(n%58n)]+s;n/=58n;}for(const x of b){if(x)break;s='1'+s;}return s;};
const bip39=readFileSync(path.join(root,'rules','bip39-english.txt'),'utf8').trim().split('\n');
const mnemonicOf=(e:Buffer)=>{const bits=[...e].map(b=>b.toString(2).padStart(8,'0')).join('')+[...sha(e)].map(b=>b.toString(2).padStart(8,'0')).join('').slice(0,e.length/4);const w:string[]=[];for(let i=0;i<bits.length;i+=11)w.push(bip39[parseInt(bits.slice(i,i+11),2)]);return w.join(' ');};
const walletKey=fx('hex-key',32).toString('hex'),phrase=mnemonicOf(fx('mnemonic',16)),solana=[...fx('solana',64)],jwkD=fx('jwk-d',32).toString('base64url'),signing=opaque(32).replace(/A/g,'q'),pgp='-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n'+fx('pgp',300).toString('base64').match(/.{1,64}/g)!.join('\n')+'\n=Ab9C\n-----END PGP PRIVATE KEY BLOCK-----';
const wifValue=b58check(Buffer.concat([Buffer.from([0x80]),fx('wif',32),Buffer.from([1])])),xprvValue=b58check(Buffer.concat([Buffer.from('0488ade4','hex'),Buffer.alloc(9),fx('chain',32),Buffer.alloc(1),fx('xprv',32)]));
cases.push({id:'wallet-mnemonic-field',provider:'Wallet seed phrase',text:'const wallet={mnemonic:'+JSON.stringify(phrase)+'};',value:phrase,set:'private-material'});
cases.push({id:'wallet-wif',provider:'Wallet private key',text:'const backup='+JSON.stringify(wifValue)+';',value:wifValue,set:'private-material'});
cases.push({id:'wallet-xprv',provider:'Wallet extended private key',text:'const root='+JSON.stringify(xprvValue)+';',value:xprvValue,set:'private-material'});
cases.push({id:'wallet-hex-constructor',provider:'Wallet private key',text:'const wallet=new ethers.Wallet("0x'+walletKey+'",provider);',value:'0x'+walletKey,set:'private-material'});
cases.push({id:'wallet-solana',provider:'Wallet private key',text:'const kp=Keypair.fromSecretKey(Uint8Array.from(['+solana.join(',')+']));',value:'['+solana.join(',')+']',set:'private-material'});
cases.push({id:'jwk-ec-private',provider:'JWK private key',text:JSON.stringify({kty:'EC',crv:'P-256',x:fx('jwk-x',32).toString('base64url'),y:fx('jwk-y',32).toString('base64url'),d:jwkD}),value:jwkD,set:'private-material'});
cases.push({id:'pgp-private-block',provider:'PGP private key',text:'const armored='+JSON.stringify(pgp)+';',value:pgp,category:'private-credential'});
cases.push({id:'signing-jwt-sign',provider:'Application signing',text:'const token=jwt.sign({sub:1},'+JSON.stringify(signing)+');',value:signing,set:'private-material'});
export const providerCases=cases;
for(const provider of ['Azure AI','Resend'])field(provider,'apiKey');
field('Postmark','serverToken','123e4567-e89b-12d3-a456-426614174002');field('Postmark','accountToken','123e4567-e89b-12d3-a456-426614174003');
relation('postmark-smtp','Postmark',{accessKey:opaque(24),secretKey:opaque(32)},'secretKey');
cases.push({id:'postmark-header',provider:'Postmark',text:'fetch("https://api.postmarkapp.com/server",{headers:{"X-Postmark-Server-Token":"123e4567-e89b-12d3-a456-426614174004"}})',value:'123e4567-e89b-12d3-a456-426614174004',set:'private-material'});
cases.push({id:'azure-ai-request',provider:'Azure AI',text:'fetch("https://synthetic.openai.azure.com/openai/v1/responses",{headers:{"api-key":"'+opaque(32)+'"}})',value:opaque(32),set:'private-material'});
cases.push({id:'azure-ai-sdk',provider:'Azure AI',text:'const client=new AzureOpenAI({apiKey:"'+opaque(32)+'",endpoint:"https://synthetic.openai.azure.com"})',value:opaque(32),set:'private-material'});
cases.push({id:'resend-prefix',provider:'Resend',text:'const r="re_'+opaque(40)+'";',value:'re_'+opaque(40)});
cases.push({id:'resend-sdk',provider:'Resend',text:'const client=new Resend("'+opaque(40)+'")',value:opaque(40),set:'private-material'});
for(const [id,provider,value]of [
 ['aws-signed-url','AWS','https://synthetic.s3.amazonaws.com/object?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAAB9CX7DY5EZ3FH1G%2F20261006%2Feu-west-1%2Fs3%2Faws4_request&X-Amz-Signature='+('a1b2c3d4'.repeat(8))+'&X-Amz-Expires=60'],
 ['google-signed-url','Google Cloud','https://storage.googleapis.com/synthetic/object?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Credential=synthetic%40invalid.test&X-Goog-Signature='+('a1b2c3d4'.repeat(8))],
 ['slack-webhook-capability','Slack','https://hooks.slack.com/services/T12AB34CD/B56EF78GH/'+opaque(24)],
 ['discord-webhook-capability','Discord','https://discord.com/api/webhooks/112233445566778899/'+opaque(68)]
])cases.push({id,provider,value,text:JSON.stringify({url:value}),set:'private-material'});
cases.push({id:'zapier-hook-capability',provider:'Zapier',category:'suspicious',value:'https://hooks.zapier.com/hooks/catch/1234567/ab9cx7/',text:'fetch("https://hooks.zapier.com/hooks/catch/1234567/ab9cx7/",{method:"POST"})'});
// Detection-quality update (2026-10): bare formats adapted from Nosey Parker (Apache-2.0) and secretlint (MIT) rules, own formats and
// passwords in non-web service URLs. Values are synthetic and nonfunctional.
for(const [id,value,provider]of [
 ['dockerhub-pat','dckr_pat_'+opaque(27),'Docker Hub'],['firecrawl-key','fc-'+'a1b2c3d4'.repeat(4),'Firecrawl'],['google-oauth-secret','GOCSPX-'+opaque(28),'Google OAuth'],
 ['google-oauth-access-token','ya29.a0'+opaque(80),'Google OAuth'],['jina-key','jina_'+opaque(60),'Jina'],['square-oauth-secret','sq0csp-'+opaque(43),'Square'],['tavily-key','tvly-dev-'+opaque(32),'Tavily'],
 ['figma-pat','figd_'+opaque(40),'Figma'],['tailscale-key','tskey-auth-'+opaque(12)+'-'+opaque(32),'Tailscale'],['vercel-token','vcp_'+opaque(40),'Vercel'],['vercel-ai-gateway','vck_'+opaque(40),'Vercel AI Gateway'],
 ['braintree-access-token','access_token$production$'+'a1b2c3d4'.repeat(2)+'$'+'a1b2c3d4'.repeat(4),'Braintree']
])cases.push({id,provider,value,text:'const key="'+value+'";'});
for(const [id,provider,url]of [
 ['cloudinary-url','Cloudinary','cloudinary://123456789012345:'+opaque(27)+'@synthetic-cloud'],['ftp-url-password','FTP / SFTP','sftp://deploy:'+opaque(20)+'@files.example.com/www'],
 ['mail-url-password','Mail server','smtps://mailer:'+opaque(20)+'@smtp.example.com:465'],['broker-url-password','Message broker','amqps://svc:'+opaque(20)+'@broker.example.com/vhost'],
 ['ldap-url-password','LDAP','ldaps://reader:'+opaque(20)+'@ldap.example.com'],['redis-url-empty-user','Database','redis://:'+opaque(20)+'@cache.example.com:6379/0']
])cases.push({id,provider,value:url.startsWith('cloudinary:')?opaque(27):opaque(20),text:'const SERVICE_URL="'+url+'";'});
// Gitleaks (MIT) and Nosey Parker (Apache-2.0) ports, see THIRD_PARTY_NOTICES.md. Values are synthetic and nonfunctional: fixed filler or
// hashes of fixture labels, never real tokens.
const hexOf=(label:string,n:number)=>fx(label,Math.ceil(n/2)).toString('hex').slice(0,n),b64Of=(label:string,n:number)=>fx(label,n).toString('base64');
export const portedCases:[string,string,string][]=[
 ['linear-api-key','lin_api_'+opaque(40),'Linear'],['planetscale-token','pscale_tkn_'+opaque(43),'PlanetScale'],['planetscale-password','pscale_pw_'+opaque(43),'PlanetScale'],
 ['doppler-service','dp.st.dev.'+opaque(43),'Doppler'],['doppler-personal','dp.pt.'+opaque(43),'Doppler'],
 ['dynatrace-token','dt0c01.'+opaque(24).toUpperCase()+'.'+opaque(64).toUpperCase(),'Dynatrace'],
 ['grafana-service-account','glsa_'+opaque(32)+'_'+hexOf('glsa',8),'Grafana'],['grafana-cloud','glc_eyJ'+b64Of('glc',96),'Grafana'],
 ['vault-service','hvs.'+opaque(95),'HashiCorp Vault'],['vault-batch','hvb.'+opaque(150),'HashiCorp Vault'],
 ['terraform-cloud','Ab9Cx7Dy5Ez3Fh.atlasv1.'+opaque(67),'HCP Terraform'],['postman-api-key','PMAK-'+opaque(24)+'-'+opaque(34),'Postman'],
 ['sourcegraph-token','sgp_'+hexOf('sg-id',16)+'_'+hexOf('sg',40),'Sourcegraph'],['sourcegraph-legacy','sgp_'+hexOf('sg-legacy',40),'Sourcegraph'],['segment-token','sgp_'+opaque(64),'Segment'],
 ['flyio-org','fo1_'+opaque(43),'Fly.io'],['flyio-macaroon','fm2_'+b64Of('fly',150),'Fly.io'],['pulumi-token','pul-'+hexOf('pulumi',40),'Pulumi'],['prefect-token','pnu_'+opaque(36),'Prefect'],
 ['shippo-token','shippo_live_'+hexOf('shippo',40),'Shippo'],['duffel-token','duffel_test_'+opaque(43),'Duffel'],['easypost-key','EZAK'+opaque(54),'EasyPost'],
 ['atlassian-api-token','ATATT3xFfGF0'+opaque(150)+'='+hexOf('atlassian',8).toUpperCase(),'Atlassian'],['artifactory-api-key','AKCp'+opaque(69),'JFrog Artifactory'],
 ['1password-service-account','ops_eyJ'+b64Of('1password',240),'1Password'],['1password-secret-key','A3-AB9CX7-DY5EZ3FH1GI-0JK8L-M6NO4-PQ2RS','1Password'],
 ['notion-token','ntn_'+'40215837196'+opaque(35),'Notion'],['harness-token','pat.'+opaque(22)+'.'+opaque(24)+'.'+opaque(20),'Harness'],
 ['readme-api-key','rdme_'+opaque(70).toLowerCase(),'ReadMe'],['maxmind-license-key',opaque(6)+'_'+opaque(29)+'_mmk','MaxMind'],['openshift-user-token','sha256~'+opaque(43),'OpenShift'],
 ['newrelic-user-key','NRAK-'+opaque(27).toUpperCase(),'New Relic'],['newrelic-insert-key','NRII-'+opaque(32),'New Relic'],['newrelic-license-key',opaque(6)+hexOf('nral',30)+'NRAL','New Relic'],
 ['stackhawk-key','hawk.'+opaque(20)+'.'+opaque(20),'StackHawk'],['adafruit-io-key','aio_'+opaque(28),'Adafruit IO'],['mapbox-secret-token','sk.eyJ1Ijoi'+opaque(60)+'.'+opaque(22),'Mapbox']
];
for(const [id,value,provider]of portedCases)cases.push({id:'ported-'+id,provider,value,text:'const key="'+value+'";'});
export const negativeCases=[
 {id:'wallet-lookalikes',text:'const receipt={txHash:"0x'+fx('tx',32).toString('hex')+'"};const pixels=['+[...fx('pixels',64)].join(',')+'];const watch={address:"0x'+fx('addr',20).toString('hex')+'"};const bad='+JSON.stringify(wifValue.slice(0,20)+(wifValue[20]==='A'?'B':'A')+wifValue.slice(21))+';jwt.verify(token,"'+opaque(32)+'");'},
 {id:'wallet-invalid-phrase',text:'const wallet={mnemonic:"'+bip39.slice(1000,1012).join(' ')+'"};'},
 {id:'placeholders',text:'OPENAI_API_KEY="your_api_key_here"; MISTRAL_API_KEY="replace_me";const Cohere={apiKey:"YOUR_API_KEY_HERE"};'},
 {id:'public-identifiers',text:'const firebase={projectId:"synthetic",appId:"1:123:web:abc"};const sentryDSN="https://abc123@sentry.io/123";const oauth={clientId:"public-client-name"};const stripe={apiKey:"pk_live_'+opaque(24)+'"};const mailgun={apiKey:"pubkey-'+('a1b2c3d4'.repeat(4))+'"};'},
 {id:'ordinary-hashes',text:'const contentHash="'+('a1b2c3d4'.repeat(8))+'";const uuid="123e4567-e89b-12d3-a456-426614174000";'},
 {id:'provider-public-test-marker',text:'const postmark={serverToken:"POSTMARK_API_TEST"};const resend={domainId:"123e4567-e89b-12d3-a456-426614174000"};'},
 {id:'unsigned-storage-links',text:'const bucket="https://synthetic.s3.amazonaws.com/public.json";const cloud="https://storage.googleapis.com/public/data";'},
 {id:'unrelated-objects',text:'const first={provider:"AWS",accessKeyId:"ASIAAB9CX7DY5EZ3FH1G"};const second={provider:"AWS",secretAccessKey:"'+opaque()+'"};'},
 {id:'ported-near-misses',text:'const refs=['+['lin_api_'+opaque(20),'pscale_tkn_'+opaque(16),'dp.xx.'+opaque(43),'dt0c01.'+opaque(10)+'.'+opaque(64),'glsa_'+opaque(32)+'_zzzzqqqq',
  'hvs.'+opaque(30),'PMAK-'+opaque(24),'sgp_'+'a1b2c3d4'.repeat(2),'pul-'+opaque(40),'shippo_demo_'+'a1b2c3d4'.repeat(5),'EZAK'+opaque(20),'ATATT3xFfGF0'+opaque(60),'AKCp'+opaque(40),
  'ntn_'+opaque(46),'sha256-'+Buffer.from(opaque(32)).toString('base64'),'hawk.'+opaque(10)+'.'+opaque(20),'aio_'+opaque(10),'sk.'+opaque(40),'pk.eyJ1Ijoi'+opaque(60)+'.'+opaque(22),
  opaque(6)+'_'+opaque(29)+'_mm','A3-AB9CX7-DY5EZ-0JK8L-M6NO4-PQ2RS','fo1_'+opaque(20),'pnu_'+opaque(20),'rdme_'+opaque(70),'duffel_prod_'+opaque(43),'nrak-'+opaque(27),'NRJS-'+'a1b2c3d4'.repeat(2)+'a1b'].map(v=>JSON.stringify(v)).join(',')+'];a.pat.b.sat.c;hawk.init();'},
 {id:'reassigned-variable',text:'let token="'+opaque()+'";token=dynamic();new Mistral({apiKey:token});'}
];
