import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomUUID } from 'node:crypto';
import { crc32 } from 'node:zlib';
import { Detector, decodeCharacterReferences } from '../src/detectors.js';
import { Evidence } from '../src/evidence.js';
import { capabilities } from '../src/capabilities.js';
import { capability } from '../src/provider-capabilities.js';
import { classifyFinding } from '../src/finding-triage-rules.js';
import { placeholderValue } from '../src/placeholders.js';
import { tokenChecksum } from '../src/token-checksums.js';
import { synthetic } from '../src/fixture.js';
import { historyReport } from '../src/reports.js';
import { makeConfig } from '../src/config.js';
import { BUILD } from '../src/build-info.js';
import type { Candidate, Finding, ScanView } from '../src/types.js';
// Detection-quality update (GitHub comparison, 2026-10): synthetic values derived from labels; nonfunctional by construction.
const derive=(label:string,n:number,format:'hex'|'alnum')=>{let s='';for(let i=0;s.length<n;i++){const h=createHash('sha256').update('ExposureDesk/github-compare/'+label+i);s+=format==='hex'?h.digest('hex'):h.digest('base64').replace(/[^A-Za-z0-9]/g,'');}return s.slice(0,n);};
const alnum=(label:string,n:number)=>derive(label,n,'alnum'),hex=(label:string,n:number)=>derive(label,n,'hex');
const GENERIC_REMEDIATION=/^Revoke and replace the exposed credential at its issuer/;
const credentials=(found:Candidate[])=>found.filter(c=>c.category==='private-credential'||c.category==='suspicious');
/** Adds every candidate to a fresh evidence store and returns the plain assessment and triage of the finding that matches. */
function assessed(text:string,match:(f:any)=>boolean,extra:Candidate[]=[]){
  const d=new Detector('disabled'),e=new Evidence(d);
  try{for(const c of [...d.inspectSync(text),...extra])e.add(c,text,'https://synthetic.invalid/config.js',[],'offline synthetic fixture');
    const f=[...e.findings.values()].find(match);if(!f)return undefined;
    return {confidence:f.confidence,qualifiers:[...(f.qualifiers||[])],priority:f.priority!.level,basis:[...f.priority!.basis],reasons:[...f.reasons],triage:classifyFinding({...f,exposures:f.occurrences.map(o=>o.exposure||'public-response')}).category};
  }finally{e.clear();}
}

test('template references, documentation placeholders and masked filler are recognized offline',()=>{
  for(const v of ['${DB_PASSWORD}','$DB_PASSWORD','${1}','{{ password }}','{{ .Values.apiKey }}','${{ secrets.API_KEY }}','%DB_PASSWORD%','@DB_PASSWORD@','%s','{0}','true','null',
    '<your-api-key>','your_api_key_here','REPLACE_ME','changeme','pre-${process.env.SECRET}-post','${env:API_TOKEN}','sk-proj-'+'X'.repeat(48),'sk_live_'+'*'.repeat(24),'xxxxxxxxxxxxxxxx','********',''])
    assert.equal(placeholderValue(v),true,v);
  for(const v of [alnum('random-token',40),'sk-proj-'+alnum('openai',48),'${DB_PASSWORD:-'+alnum('fallback',18)+'}','x'+alnum('few-x',30),
    // Long key bodies with padding runs and whitespace-separated material are never filler.
    'MII'+'A'.repeat(40)+alnum('key-body',400),'AAAAAAAAAAAAAAAAAAAA '+alnum('spaced',30)])
    assert.equal(placeholderValue(v),false,v);
});

test('templated database URLs and configuration fields produce no credential finding while literal values still do',()=>{
  const d=new Detector('disabled');
  for(const text of ['const url="postgres://app:${DB_PASSWORD}@db.example.com:5432/app";','{"host":"db.example.com","user":"app","password":"${DB_PASSWORD}","apiKey":"{{ secrets.API_KEY }}"}',
    'DATABASE_URL=mysql://app:%DB_PASSWORD%@db.example.com/app','OPENAI_API_KEY="sk-proj-'+'X'.repeat(48)+'"','STRIPE_SECRET_KEY="sk_live_'+'*'.repeat(24)+'"','smtp_url: "smtp://mailer:${SMTP_PASSWORD}@smtp.example.com:587"'])
    assert.deepEqual(credentials(d.inspectSync(text)).map(c=>c.rule),[],text);
  const literal=alnum('db-literal',20),fallback='${DB_PASSWORD:-'+alnum('db-fallback',18)+'}';
  assert.ok(d.inspectSync(`const url="postgres://app:${literal}@db.example.com:5432/app";`).some(c=>c.value===literal&&c.rule==='database-password'&&c.category==='private-credential'));
  assert.ok(d.inspectSync(`const url="postgres://app:${fallback}@db.example.com:5432/app";`).some(c=>c.value===fallback&&c.rule==='database-password'),'A literal fallback default is a value, not only a reference');
});

const prefixCases:{rule:string;provider:string;value:string;confidence?:string}[]=[
  {rule:'dockerhub-pat',provider:'Docker Hub',value:'dckr_pat_'+alnum('docker',27)},
  {rule:'firecrawl-key',provider:'Firecrawl',value:'fc-'+hex('firecrawl',32),confidence:'medium'},
  {rule:'google-oauth-secret',provider:'Google OAuth',value:'GOCSPX-'+alnum('gocspx',28)},
  {rule:'google-oauth-access-token',provider:'Google OAuth',value:'ya29.a0'+alnum('ya29',60)+'-'+alnum('ya29-tail',40),confidence:'medium'},
  {rule:'jina-key',provider:'Jina',value:'jina_'+alnum('jina',60)},
  {rule:'square-oauth-secret',provider:'Square',value:'sq0csp-'+alnum('square',43)},
  {rule:'tavily-key',provider:'Tavily',value:'tvly-dev-'+alnum('tavily',32)},
  {rule:'tavily-key',provider:'Tavily',value:'tvly-'+alnum('tavily-plain',32)},
  {rule:'figma-pat',provider:'Figma',value:'figd_'+alnum('figma',40)},
  {rule:'tailscale-key',provider:'Tailscale',value:'tskey-auth-'+alnum('tailscale-id',12)+'-'+alnum('tailscale-secret',32)},
  {rule:'vercel-token',provider:'Vercel',value:'vcp_'+alnum('vercel',40)},
  {rule:'vercel-ai-gateway',provider:'Vercel AI Gateway',value:'vck_'+alnum('vercel-ai',40)},
  {rule:'braintree-access-token',provider:'Braintree',value:'access_token$production$'+hex('braintree-merchant',16)+'$'+hex('braintree-secret',32)},
];
for(const example of prefixCases)test('new provider format: '+example.rule+' '+example.value.slice(0,9),()=>{
  const text=`window.CONFIG={service:"${example.value}"};`,found=new Detector('disabled').inspectSync(text);
  const hit=found.find(c=>c.value===example.value&&c.rule===example.rule);
  assert.ok(hit,'Planted synthetic credential must be detected by its own rule');
  assert.equal(hit.provider,example.provider);assert.equal(hit.category,'private-credential');assert.equal(hit.confidence,example.confidence||'high');
  assert.equal(text.slice(hit.index,hit.index+hit.original.length),hit.original,'Location must refer to the actual source');
  assert.doesNotMatch(capability(hit.provider,hit.rule).remediation[0],GENERIC_REMEDIATION,'Each new provider has its own remediation');
});
test('new provider formats reject truncated, filler and look-alike values',()=>{
  const d=new Detector('disabled'),rules=new Set(prefixCases.map(c=>c.rule));
  for(const text of ['"dckr_pat_'+alnum('short',20)+'"','"fc-'+hex('upper',32).toUpperCase()+'"','"GOCSPX-'+alnum('short',12)+'"','"ya29.short"','"jina_'+alnum('short',40)+'"',
    '"vcp_short"','see tskey-auth for details','"figd_'+'x'.repeat(48)+'"','"access_token$sandbox$'+hex('bt-sandbox',16)+'$'+hex('bt-sandbox-secret',32)+'"','"tvly-'+'X'.repeat(32)+'"'])
    assert.deepEqual(d.inspectSync(text).filter(c=>rules.has(c.rule)).map(c=>c.rule),[],text);
});

test('credentials in non-web service URLs are private, while http(s) userinfo and credential-free URLs are not service passwords',()=>{
  const d=new Detector('disabled'),pw=alnum('userinfo',20);
  for(const [rule,provider,url] of [['ftp-password','FTP / SFTP',`sftp://deploy:${pw}@files.example.com/www`],['ftp-password','FTP / SFTP',`ftp://deploy:${pw}@ftp.example.com/`],
    ['mail-server-password','Mail server',`smtps://mailer%40example.com:${pw}@smtp.example.com:465`],['mail-server-password','Mail server',`imap://inbox:${pw}@mail.example.com`],
    ['message-broker-password','Message broker',`amqps://svc:${pw}@broker.example.com/vhost`],['message-broker-password','Message broker',`mqtt://device:${pw}@mqtt.example.com:1883`],
    ['ldap-password','LDAP',`ldaps://cn=reader,dc=example,dc=com:${pw}@ldap.example.com`],['database-password','Database',`redis://:${pw}@cache.example.com:6379/0`],
    ['cloudinary-url','Cloudinary',`cloudinary://123456789012345:${pw}@synthetic-cloud`]]){
    const text=`const SERVICE_URL="${url}";`,hit=d.inspectSync(text).find(c=>c.value===pw&&c.rule===rule);
    assert.ok(hit,url);assert.equal(hit.provider,provider);assert.equal(hit.category,'private-credential');
    assert.doesNotMatch(capability(hit.provider,hit.rule).remediation[0],GENERIC_REMEDIATION);
  }
  const service=/^(?:ftp|mail-server|message-broker|ldap|database)-password$/;
  for(const text of ['"ftp://ftp.example.com/pub/readme.txt"','"sftp://deploy@files.example.com/www"',`"https://deploy:${pw}@www.example.com/"`,'"ldap://ldap.example.com/dc=example,dc=com"'])
    assert.deepEqual(d.inspectSync(text).filter(c=>service.test(c.rule)).map(c=>c.rule),[],text);
});

test('Discord webhooks are private capability URLs and Zapier catch hooks need review',()=>{
  const discord=`https://discord.com/api/webhooks/112233445566778899/${alnum('discord',68)}`,zapier=`https://hooks.zapier.com/hooks/catch/1234567/${alnum('zapier',6).toLowerCase()}/`;
  const d=new Detector('disabled'),found=d.inspectSync(`fetch("${discord}");fetch("${zapier}");`);
  const hook=found.find(c=>c.rule==='capability:discord-webhook-url');assert.ok(hook);assert.equal(hook.provider,'Discord');assert.equal(hook.category,'private-credential');assert.equal(hook.value,discord);
  const zap=found.find(c=>c.rule==='capability:zapier-hook-url');assert.ok(zap);assert.equal(zap.provider,'Zapier');assert.equal(zap.category,'suspicious');assert.equal(zap.confidence,'medium');
  assert.equal(capability('Discord','capability:discord-webhook-url').group,'messaging');
  const zapAssessment=assessed(`fetch("${zapier}");`,f=>f.provider==='Zapier');assert.equal(zapAssessment?.priority,'review');
  for(const url of ['https://discord.com/api/webhooks/123/abc','https://discord.com.example.net/api/webhooks/112233445566778899/'+alnum('look-alike',68),'https://hooks.zapier.com/hooks/standard/1234567/abcdef/','https://ptb.discord.com/api/channels/112233445566778899'])
    assert.deepEqual(capabilities(`"${url}"`).map(c=>c.rule),[],url);
  assert.ok(capabilities(`"${discord.replace('https://discord.com','https://canary.discordapp.com')}"`).some(c=>c.rule==='capability:discord-webhook-url'));
});

test('GitHub token checksum: a matching CRC32 suffix is structure only and a mismatch lowers priority without hiding the finding',()=>{
  // Independent Base62 encoder (BigInt) cross-checks the product implementation.
  const base62=(n:bigint)=>{const A='0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';let s='';while(n>0n){s=A[Number(n%62n)]+s;n/=62n;}return s.padStart(6,'0');};
  const body=alnum('github-body',30),suffix=base62(BigInt(crc32(body)>>>0)),valid='ghp_'+body+suffix,wrong='ghp_'+body+(suffix[5]==='A'?suffix.slice(0,5)+'B':suffix.slice(0,5)+'A');
  for(const prefix of ['ghp_','gho_','ghu_','ghs_'])assert.equal(tokenChecksum(prefix+body+suffix),'valid',prefix);
  assert.equal(tokenChecksum(wrong),'mismatch');assert.equal(tokenChecksum(synthetic.github),'valid','The shipped synthetic fixture carries a matching suffix');
  for(const other of ['ghr_'+alnum('refresh',76),'github_pat_'+alnum('fine-grained',82),'ghp_'+alnum('long',37),'sk_live_'+alnum('stripe',24)])assert.equal(tokenChecksum(other),undefined,other);
  const good=assessed(`const GITHUB_TOKEN="${valid}";`,f=>f.provider==='GitHub'&&f.category==='private-credential')!;
  assert.equal(good.confidence,'high');assert.ok(!good.qualifiers.includes('checksum-mismatch'));assert.equal(good.priority,'urgent');assert.equal(good.triage,'direct-leak');
  assert.ok(good.reasons.some(r=>/checksum matches/.test(r)&&/not validity/.test(r)),'A match is reported as structure, never validity');
  const bad=assessed(`const GITHUB_TOKEN="${wrong}";`,f=>f.provider==='GitHub'&&f.category==='private-credential');
  assert.ok(bad,'A checksum mismatch never removes the finding');
  assert.equal(bad.confidence,'medium');assert.ok(bad.qualifiers.includes('checksum-mismatch'));assert.equal(bad.priority,'review');assert.equal(bad.triage,'high-potential-leak');
  assert.ok(bad.basis.some(b=>/checksum/.test(b)));
  // Another pass (for example the Gitleaks engine) reporting the same value at high confidence is still qualified by value.
  const engine:Candidate={value:wrong,original:wrong,index:0,rule:'gitleaks:github-pat',provider:'GitHub',category:'private-credential',severity:'high',confidence:'high',reasons:['Engine match'],transformations:[]};
  const merged=assessed('',f=>f.provider==='GitHub',[engine])!;assert.ok(merged.qualifiers.includes('checksum-mismatch'));assert.equal(merged.priority,'review');assert.equal(merged.triage,'high-potential-leak');
});

test('HTML attribute JSON with encoded quotes is decoded once for the configuration passes',()=>{
  assert.equal(decodeCharacterReferences('&quot;a&quot; &#39;b&#x27; &amp;lt; &copy; &#0; &#xD800; &#x1F600;'),'"a" \'b\' &lt; &copy; &#0; &#xD800; \u{1F600}');
  const secret=alnum('html-secret',22),d=new Detector('disabled');
  for(const text of [`<div data-config="{&quot;password&quot;:&quot;${secret}&quot;,&quot;user&quot;:&quot;app&quot;}"></div>`,`<div data-settings='{&#34;apiSecret&#34;:&#x22;${secret}&#x22;}'></div>`]){
    const hit=d.inspectSync(text).find(c=>c.value===secret);
    assert.ok(hit,text);assert.ok(hit.transformations.includes('HTML character-reference decoding'));
    assert.equal(text.slice(hit.index,hit.index+hit.original.length),hit.original,'Location must refer to the encoded attribute in the source');
  }
  // Links with &amp; separators carry no encoded quote and create no decoded view.
  const link=`<a href="/search?q=${alnum('query',12)}&amp;page=2&amp;sort=asc">next</a>`;
  assert.ok(!d.inspectSync(link).some(c=>c.transformations.includes('HTML character-reference decoding')));
  // Many encoded attributes stay bounded and the first ones are still inspected.
  const many=`<div data-config="{&quot;password&quot;:&quot;${secret}&quot;}"></div>`+'<i data-x="{&quot;n&quot;:&quot;0123456789&quot;}"></i>'.repeat(2000);
  const started=Date.now();assert.ok(d.inspectSync(many).some(c=>c.value===secret));assert.ok(Date.now()-started<10000);
});

test('SARIF rules carry remediation help, security tags and severity, and active owner suppressions become SARIF suppressions',()=>{
  const SITE='https://www.example.com',APP=SITE+'/assets/app.js',later=new Date(Date.now()+86400000).toISOString(),earlier=new Date(Date.now()-86400000).toISOString();
  const finding=(id:string,over:Partial<Finding>):Finding=>({id,fingerprint:id,category:'private-credential',provider:'Stripe',rule:'stripe-secret',severity:'high',confidence:'high',reasons:[],masked:'[redacted: 32 characters]',validity:'unverified',impact:'',remediation:'Roll the Stripe secret key in the dashboard.',occurrences:[{url:APP,chain:[SITE+'/'],transformations:[],excerpt:'[redacted]',evidence:'Public response',exposure:'public-response',environment:'production'}],...over} as Finding);
  const findings=[finding('a'.repeat(32),{suppression:{reason:'Owner accepted: rotated key pending removal',expires:later,reviewedAt:earlier}}),finding('b'.repeat(32),{suppression:{reason:'Expired acceptance',expires:earlier,reviewedAt:earlier}}),
    finding('c'.repeat(32),{category:'suspicious',provider:'Zapier',rule:'capability:zapier-hook-url',severity:'medium',confidence:'medium',remediation:''}),
    finding('d'.repeat(32),{category:'information',provider:'Website',rule:'published-sensitive-file',severity:'low',confidence:'high',remediation:'Remove the file from the public web root.'})];
  const view={schema:'exposure-scan/1',id:randomUUID(),name:'www.example.com',state:'completed',startedAt:earlier,endedAt:earlier,elapsedMs:1,config:makeConfig({urls:[SITE+'/']}),build:BUILD,counts:{resources:1,scanned:1,blocked:0,bytes:10,pending:0,findings:findings.length},engines:{websiteRules:'website/2.6.0',gitleaks:'8.30.1',ruleDigest:'d',companyRules:'none'},findings,
    resources:[{url:SITE+'/',status:'scanned',code:200,bytes:5,chain:[],kind:'page',analysis:'analyzed',analyzers:{directText:{status:'inspected'}}}],limitations:[],launch:{trigger:'manual',requestedAt:earlier},analysis:{origins:{},interruptions:{},backlog:{items:0,bytes:0,resumed:0,deferred:0,dropped:0},note:''}} as unknown as ScanView;
  const sarif=JSON.parse(historyReport(view,'sarif')),run=sarif.runs[0],rule=(id:string)=>run.tool.driver.rules.find((r:any)=>r.id===id);
  assert.deepEqual(run.tool.driver.rules.map((r:any)=>r.id).sort(),['capability:zapier-hook-url','published-sensitive-file','stripe-secret']);
  const stripe=rule('stripe-secret');
  assert.deepEqual(stripe.properties.tags,['security','secret','external/cwe/cwe-798']);assert.equal(stripe.properties['security-severity'],'8.0');assert.equal(stripe.properties.precision,'high');
  assert.equal(stripe.defaultConfiguration.level,'error');assert.match(stripe.shortDescription.text,/^Stripe: private credential$/);
  assert.match(stripe.help.text,/^Roll the Stripe secret key in the dashboard\. .*not established/);assert.match(stripe.fullDescription.text,/validity, permissions and any loss are not established/);
  const zap=rule('capability:zapier-hook-url');assert.equal(zap.properties['security-severity'],'5.5');assert.equal(zap.properties.precision,'medium');assert.equal(zap.defaultConfiguration.level,'warning');assert.match(zap.help.text,/^Remove the value from public content/);
  const file=rule('published-sensitive-file');assert.deepEqual(file.properties.tags,['security','external/cwe/cwe-200']);assert.equal(file.properties['security-severity'],'3.0');assert.equal(file.defaultConfiguration.level,'note');
  assert.ok(!JSON.stringify(run.tool.driver.rules).includes(APP),'Rule metadata never carries locations');
  const [active,expired]=run.results;
  assert.deepEqual(active.suppressions,[{kind:'external',status:'accepted',justification:'Owner accepted: rotated key pending removal',properties:{expires:later,reviewedAt:earlier}}]);
  assert.equal(expired.suppressions,undefined,'An expired owner suppression is not a SARIF suppression');assert.equal(expired.properties.suppression.reason,'Expired acceptance','The record stays in the properties');
  assert.equal(run.results[2].level,'warning');assert.equal(run.results[3].level,'note');
});
