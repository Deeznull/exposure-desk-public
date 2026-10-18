import { parse, parseExpressionAt } from 'acorn';
import { parse as parseHost } from 'tldts';
import type { Candidate } from './types.js';
import { placeholderValue } from './placeholders.js';
interface Field {name:string;value:string;index:number;original:string;steps:string[]}
interface Context {fields:Field[];label:string;provider?:string;environment?:string}
export const providerNames=['OpenAI','Anthropic','Cohere','Replicate','Hugging Face','ElevenLabs','Stability AI','Groq','Mistral','Perplexity','Google / Gemini','Google Cloud','AWS','AWS Bedrock','OpenRouter','Azure AI','Azure','DigitalOcean','Stripe','PayPal','Braintree','Square','Coinbase','Kraken','Binance','Twilio','SendGrid','Mailgun','Postmark','Resend','Vonage','Cloudflare','AWS Route53','GoDaddy','Namecheap','Vercel','Netlify','Heroku','Sentry','OAuth'];
const clean=(s:string)=>String(s).toLowerCase().replace(/[^a-z0-9]/g,'');
const identify=(s:string)=>{const n=clean(s);if(/azureopenai|azureai|azurekeycredential/.test(n))return 'Azure AI';if(/^(?:coapikey|xiapikey)$/.test(n))return n==='coapikey'?'Cohere':'ElevenLabs';return [...providerNames].sort((a,b)=>b.length-a.length).find(p=>n.includes(clean(p.replace(' / Gemini','')))||p==='Google / Gemini'&&/gemini/.test(n)||p==='Hugging Face'&&/huggingface/.test(n));};
const fake=(s:string)=>/your[_ -]|placeholder|replace.?me|example(?:key|secret)|changeme|^POSTMARK_API_TEST$|^(?:null|undefined|x{8,}|0{8,}|<[^>]+>)$/i.test(s)||placeholderValue(s);
const sensitive=(n:string)=>/secret|password|passwd|privatekey|apikey|token|accountkey|storagekey|signingkey|pat$/.test(clean(n));
const entropy=(s:string)=>{const c=new Map<string,number>();for(const x of s)c.set(x,(c.get(x)||0)+1);return [...c.values()].reduce((h,n)=>h-(n/s.length)*Math.log2(n/s.length),0);};
/** Usage context (all static): literal keys passed to signing/encryption calls, credentials sent to request hosts, unknown SDK constructors and signing-secret field names. Nothing is evaluated or sent. */
const SIGNING_NAME=/(?:jwt|session|cookie|webhook|signing|hmac|encryption|aes)(?:secret|key)$/;
const REQUEST=/^(?:fetch|axios(?:\.(?:get|post|put|patch|delete|request|create))?|\$\.ajax|ky(?:\.\w+)?|request|got(?:\.\w+)?)$/;
const AUTH_HEADERS=new Set(['authorization','xapikey','apikey','xauthtoken','xaccesstoken','xapitoken']);
const NOT_SDK=/^(?:fetch|axios|Object|JSON|Array|Promise|Map|Set|WeakMap|WeakSet|Error|URL|URLSearchParams|Request|Response|Headers|FormData|Intl|Date|RegExp|Proxy|Reflect|console|require|define|import|Worker|Blob|File|Event|CustomEvent|MutationObserver|IntersectionObserver|ResizeObserver|Vue|React|Component|createElement|h|jsx|jsxs|styled|css|t|i18n)\b/;
const SANDBOX_HOSTS=new Set(['api-m.sandbox.paypal.com','api.sandbox.paypal.com','connect.squareupsandbox.com','api.ote-godaddy.com','sandbox.plaid.com','api.sandbox.braintreegateway.com','api.sandbox.checkout.com','sandbox-api.coinbase.com','testnet.binance.vision']);
const singleProviders=new Set(['OpenAI','Anthropic','Cohere','Replicate','Hugging Face','ElevenLabs','Stability AI','Groq','Mistral','Perplexity','OpenRouter','Azure AI','DigitalOcean','SendGrid','Mailgun','Postmark','Resend','Vercel','Netlify','Heroku','Sentry','Square']);
/** Source text that can yield a contextual credential (sensitive or provider names, signing sinks, request authorization, SDK secret fields). Used only to skip unrelated subtrees of a large document; it never creates a finding. */
export const CONTEXT_FOCUS=new RegExp(['secret','passw','private.?key','api.?key','token','authori[sz]ation','access.?key','account.?(?:key|sid)','storage.?key','signing','\\.sign\\b','jwt','hmac','cipher','importkey','cryptojs','credential','service_account','client.?(?:id|email)','tenant','merchant','passphrase','gemini',...providerNames.map(p=>p.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean).join('[^a-z0-9]{0,3}'))].join('|'),'i');
/** Plain-text configuration groups: env lines per paragraph, all PHP define() constants of the text (PHP constants are global) and the name/value rows of each HTML table (framework debug pages). Values are taken whole or not at all. */
function textGroups(text:string){const groups:{fields:Field[];label:string}[]=[];
  for(const block of text.matchAll(/[\s\S]+?(?:\r?\n[ \t]*\r?\n|$)/g)){const paragraph=block[0],offset=block.index!,fields:Field[]=[];for(const m of paragraph.matchAll(/(?:^|\n)[ \t]*(?:export[ \t]+)?([A-Z][A-Z0-9_]{2,100})[ \t]*=[ \t]*(?:"([^\s"]{4,2048})"|'([^\s']{4,2048})'|([^\s"']{4,2048}))(?=[ \t]*(?:#[^\n]*)?(?:\r?\n|$))/g)){const v=m[2]??m[3]??m[4];fields.push({name:m[1],value:v,index:offset+m.index!+m[0].lastIndexOf(v),original:v,steps:[]});}if(fields.length)groups.push({fields,label:'qualified environment block'});}
  const defines:Field[]=[];for(const m of text.matchAll(/\bdefine\(\s*(['"])([A-Z][A-Z0-9_]{2,100})\1\s*,\s*(?:'([^'\\\n]{4,2048})'|"([^"\\\n]{4,2048})")\s*\)/g)){const v=m[3]??m[4];defines.push({name:m[2],value:v,index:m.index!+m[0].lastIndexOf(v),original:v,steps:[]});}if(defines.length)groups.push({fields:defines,label:'PHP configuration constants'});
  let tables=0;for(const t of text.matchAll(/<table\b[\s\S]{0,262144}?<\/table\s*>/gi)){if(++tables>64)break;const fields:Field[]=[];
    for(const m of t[0].matchAll(/<t([hd])\b[^>]*>\s*([A-Z][A-Z0-9_]{2,100})\s*<\/t\1\s*>\s*<td\b[^>]*>\s*(?:<(?:pre|code)\b[^>]*>\s*)?(?:&#0?39;|&quot;|['"])?([^\s<>"'&]{4,2048})(?:&#0?39;|&quot;|['"])?\s*(?:<\/(?:pre|code)\s*>\s*)?<\/td\s*>/g))fields.push({name:m[2],value:m[3],index:t.index!+m.index!+m[0].lastIndexOf(m[3]),original:m[3],steps:['HTML table cell']});
    if(fields.length)groups.push({fields,label:'settings table of a debug page'});}
  return groups;}
const FRAMEWORK_SIGNING=/^(?:(?:SECURE_)?AUTH|LOGGED_IN|NONCE)_(?:KEY|SALT)$|^SECRET_KEY_BASE$/,DB_SECRET=/^(?:DB|DATABASE|MYSQL|MARIADB|POSTGRES(?:QL)?|PG|MONGO(?:DB)?|MSSQL)_?(?:PASSWORD|PASSWD|PASS|PWD)$/,DB_CONTEXT=/^(?:DB|DATABASE|MYSQL|MARIADB|POSTGRES(?:QL)?|PG|MONGO(?:DB)?|MSSQL)_?(?:HOST|HOSTNAME|SERVER|PORT|USER|USERNAME|NAME|DATABASE|CONNECTION)$/;
export function contextualCredentials(text:string,options:{ast?:any;focus?:RegExp;nodeLimit?:number}={}):Candidate[]{
  const contexts:Context[]=[],out:Candidate[]=[],{focus}=options,nodeLimit=options.nodeLimit||100000;let ast:any=options.ast,nodes=0,hostEnvironment:string|undefined;
  // A caller-supplied whole-document parse (large texts) replaces the local parse; the plain-text fallbacks below are then left to the caller's windows.
  if(!ast)try{ast=/^\s*\{/.test(text)?parseExpressionAt(text,text.indexOf('{'),{ecmaVersion:'latest'}):parse(text,{ecmaVersion:'latest',sourceType:'module',allowReturnOutsideFunction:true});}catch{}
  const emit=(f:Field,provider:string,category:Candidate['category']='private-credential',set?:Candidate['credentialSet'])=>{
    if(!f.value||fake(f.value)||f.value.length>12000)return;
    const prefixed=/^(?:sk|rk|pk)_test_|sandbox|testnet/i.test(f.value)||/sandbox|testnet/i.test(f.name),environment=hostEnvironment?'test':prefixed?'test':/^(?:sk|rk|pk)_live_/.test(f.value)?'production':'unknown';
    out.push({value:f.value,original:f.original,index:f.index,rule:'provider-context:'+clean(provider),provider,category,severity:category==='public-identifier'?'info':category==='suspicious'?'medium':'high',confidence:category==='suspicious'?'medium':'high',reasons:['Literal authentication material in '+provider+' configuration or request construction; validity, expiry, permissions and restrictions are unknown.'],transformations:f.steps,environment,environmentSource:hostEnvironment?'sandbox request host':prefixed?'value or field name':environment==='production'?'value prefix':undefined,credentialSet:set});
  };
  const value=(n:any,env:Map<string,any>,depth=0):Field|undefined=>{if(!n||depth>12)return;
    if(n.type==='Literal'&&typeof n.value==='string')return {name:'',value:n.value,index:n.start,original:text.slice(n.start,n.end),steps:/\\/.test(text.slice(n.start,n.end))?['Static string-escape decoding']:[]};
    if(n.type==='TemplateLiteral'&&!n.expressions.length)return {name:'',value:n.quasis[0].value.cooked,index:n.start,original:text.slice(n.start,n.end),steps:['Static template literal']};
    if(n.type==='Identifier'){const init=env.get(n.name);if(init&&init!==n){const f=value(init,env,depth+1);if(f)return {...f,steps:[...f.steps,'Static const variable reference (location is declaration)']};}}
    if(n.type==='BinaryExpression'&&n.operator==='+'){const a=value(n.left,env,depth+1),b=value(n.right,env,depth+1);if(a&&b&&a.value.length+b.value.length<=12000)return {name:'',value:a.value+b.value,index:n.start,original:text.slice(n.start,n.end),steps:['Static string concatenation (no execution)']};}
  };
  const keyName=(p:any)=>p?.type==='Property'&&!p.computed?String(p.key?.name??p.key?.value??''):'';
  const sinkSecret=(arg:any,env:Map<string,any>,sink:string)=>{const f=value(arg,env);if(!f||fake(f.value)||f.value.length<6||f.value.length>4096||/^-----BEGIN [A-Z ]*PUBLIC KEY/.test(f.value))return;out.push({value:f.value,original:f.original,index:f.index,rule:'signing-sink',provider:'Application signing',category:'private-credential',severity:'high',confidence:entropy(f.value)>=3.2?'high':'medium',reasons:[`Literal secret passed to ${sink}; it can sign or decrypt as the application. Validity and use are not tested.`],transformations:f.steps,environment:'unknown',credentialSet:{state:'private-material',components:['signing or encryption secret'],missing:[],context:sink}});};
  const signingField=(f:Field)=>{const n=clean(f.name);if(!SIGNING_NAME.test(n)||/public|publishable/.test(n)||fake(f.value)||f.value.length>4096)return;const key=/key$/.test(n);if(f.value.length<(key?16:6)||key&&entropy(f.value)<3.2)return;out.push({value:f.value,original:f.original,index:f.index,rule:'signing-secret-field',provider:'Application signing',category:'private-credential',severity:'high',confidence:entropy(f.value)>=3.2?'high':'medium',reasons:[`Literal value of the signing or encryption secret field ${f.name}; it can forge tokens, cookies or webhooks. Validity is not tested.`],transformations:f.steps,environment:'unknown',credentialSet:{state:'private-material',components:['signing secret'],missing:[],context:'signing-secret field name'}});};
  /** Credentials literally attached to a request for a host with no mapped provider: the registrable domain names the issuer; Basic user:password is a complete private credential. */
  const requestCredentials=(n:any,host:string,env:Map<string,any>)=>{const domain=parseHost(host,{allowPrivateDomains:true}).domain||host,provider=domain+' (unreviewed provider)';
    for(const a of n.arguments||[]){if(a?.type!=='ObjectExpression')continue;const headers=a.properties.find((p:any)=>clean(keyName(p))==='headers')?.value;if(headers?.type!=='ObjectExpression')continue;
      for(const p of headers.properties){const name=clean(keyName(p));if(!AUTH_HEADERS.has(name))continue;const f=value(p.value,env);if(!f||fake(f.value))continue;const scheme=/^(Bearer|Token|Basic)\s+(\S{8,4096})$/i.exec(f.value);if(name==='authorization'&&!scheme)continue;const token=scheme?scheme[2]:f.value;if(token.length<8)continue;
        let decoded='';if(scheme?.[1].toLowerCase()==='basic')try{decoded=Buffer.from(token,'base64').toString('utf8');}catch{}const pair=/^[\x21-\x7e]{1,200}:[\x20-\x7e]{3,500}$/.test(decoded);
        out.push({value:token,original:f.original,index:f.index+Math.max(0,f.original.indexOf(token)),rule:'request-credential',provider,category:pair?'private-credential':'suspicious',severity:pair?'high':'medium',confidence:'high',reasons:[`Literal ${scheme?scheme[1]+' ':''}credential in the ${keyName(p)} header of a request to ${domain}; the issuer is not a mapped provider. Validity and scope are not tested.`],transformations:f.steps,environment:hostEnvironment?'test':'unknown',...(hostEnvironment?{environmentSource:'sandbox request host'}:{}),credentialSet:pair?{state:'complete',components:['username','password'],missing:[],context:'HTTP Basic authorization header'}:{state:'private-material',components:['request authorization credential'],missing:[],context:'request header to an unmapped host'}});}}};
  const usage=(n:any,calleeText:string,env:Map<string,any>)=>{const args=n.arguments||[];
    if(/^(?:jwt|jsonwebtoken|jws|JWT)\.sign$/.test(calleeText)&&args.length>=2)sinkSecret(args[1],env,calleeText+' (signing key argument)');
    if(/^jws\.sign$/.test(calleeText)&&args[0]?.type==='ObjectExpression'){const p=args[0].properties.find((p:any)=>clean(keyName(p))==='secret');if(p)sinkSecret(p.value,env,'jws.sign secret');}
    if(/(?:^|\.)createHmac$/.test(calleeText)&&args.length>=2)sinkSecret(args[1],env,'createHmac key argument');
    if(/(?:^|\.)create(?:Cipher|Decipher)iv$/.test(calleeText)&&args.length>=2)sinkSecret(args[1],env,calleeText.split('.').pop()+' key argument');
    if(/^CryptoJS\.Hmac\w+$/.test(calleeText)&&args.length>=2)sinkSecret(args[1],env,calleeText+' key argument');
    if(/^CryptoJS\.(?:AES|TripleDES|DES|Rabbit|RC4|RC4Drop)\.(?:encrypt|decrypt)$/.test(calleeText)&&args.length>=2)sinkSecret(args[1],env,calleeText+' key argument');
    const encoded=(a:any)=>a?.type==='CallExpression'&&/encode$/.test(text.slice(a.callee.start,a.callee.end))?a.arguments?.[0]:a;
    if(/(?:^|\.)subtle\.importKey$/.test(calleeText)&&value(args[0],env)?.value==='raw')sinkSecret(encoded(args[1]),env,'crypto.subtle.importKey raw key');
    if(/\.sign$/.test(calleeText)&&n.callee?.object&&/SignJWT\(/.test(text.slice(n.callee.object.start,n.callee.object.end)))sinkSecret(encoded(args[0]),env,'SignJWT.sign key');
    if(/(?:^|\.)setRequestHeader$/.test(calleeText)&&args.length>=2){const name=clean(value(args[0],env)?.value||''),f=value(args[1],env);const scheme=f&&/^(Bearer|Token|Basic)\s+(\S{8,4096})$/i.exec(f.value);if(f&&AUTH_HEADERS.has(name)&&(name!=='authorization'||scheme)&&!fake(f.value)){const token=scheme?scheme[2]:f.value;out.push({value:token,original:f.original,index:f.index+Math.max(0,f.original.indexOf(token)),rule:'request-credential',provider:'Unknown host (unreviewed provider)',category:'suspicious',severity:'medium',confidence:'high',reasons:['Literal credential set as a request header; the destination is not statically known. Validity and scope are not tested.'],transformations:f.steps,environment:'unknown'});}}
    // Unknown SDK constructors: an identifier plus a secret field in one literal options object.
    const first=args[0],root=calleeText.split('.')[0];if(first?.type==='ObjectExpression'&&calleeText&&!NOT_SDK.test(root)&&!identify(calleeText)&&!REQUEST.test(calleeText)){const fields:Field[]=[];for(const p of first.properties){const name=keyName(p),f=name?value(p.value,env):undefined;if(f)fields.push({...f,name});}
      const secret=fields.find(f=>/^(?:secret|apisecret|clientsecret|privatekey|secretkey|appsecret|secretaccesskey|apikeysecret)$/.test(clean(f.name))&&!fake(f.value)&&f.value.length>=8&&entropy(f.value)>=3),id=fields.find(f=>/^(?:appid|applicationid|clientid|keyid|apikeyid|accountid|accesskeyid|key|apikey|username|user|projectid|cluster|tenantid)$/.test(clean(f.name))&&f.value.length>=3);
      if(secret)out.push({value:secret.value,original:secret.original,index:secret.index,rule:'sdk-constructor-secret',provider:calleeText.replace(/^new/,'')+' (unreviewed provider)',category:id?'private-credential':'suspicious',severity:id?'high':'medium',confidence:'medium',reasons:[`Literal ${secret.name} passed to ${calleeText}${id?' with its identifier '+id.name:''}; the SDK is not a mapped provider. Validity and permissions are not tested.`],transformations:secret.steps,environment:'unknown',credentialSet:id?{state:'complete',components:[id.name,secret.name],missing:[],context:'one SDK options object'}:{state:'partial',components:[secret.name],missing:['identifier'],context:'one SDK options object'}});}
  };
  const walk=(n:any,env:Map<string,any>,label='',depth=0)=>{if(!n||typeof n!=='object'||focus&&typeof n.start==='number'&&n.end-n.start<=16384&&!focus.test(text.slice(n.start,n.end))||++nodes>nodeLimit||depth>80)return;
    if(n.type==='Program'||n.type==='BlockStatement'){
      const local=new Map(env),flat:Field[]=[];
      for(const stmt of n.body||[])if(stmt.type==='VariableDeclaration'&&stmt.kind==='const')for(const d of stmt.declarations)if(d.id.type==='Identifier'){if(local.has(d.id.name))local.delete(d.id.name);else local.set(d.id.name,d.init);}
      // An identifier assigned later is not a safe static binding.
      const assignments=(x:any)=>{if(!x||typeof x!=='object'||/Function/.test(x.type))return;if(x.type==='AssignmentExpression'&&x.left?.type==='Identifier')local.delete(x.left.name);for(const v of Object.values(x))if(Array.isArray(v))v.forEach(assignments);else if(v&&typeof v==='object')assignments(v);};for(const stmt of n.body||[])assignments(stmt);
      for(const stmt of n.body||[])if(stmt.type==='VariableDeclaration')for(const d of stmt.declarations){const f=value(d.init,local);if(f&&d.id.type==='Identifier')flat.push({...f,name:d.id.name});}
      for(const f of flat)signingField(f);
      // Only qualified same-provider variable names in one lexical scope can pair.
      for(const provider of providerNames){const fields=flat.filter(f=>identify(f.name)===provider);if(fields.length)contexts.push({fields,provider,label:'qualified names in one lexical scope',environment:hostEnvironment});}
      for(const stmt of n.body||[])walk(stmt,local,label,depth+1);return;
    }
    if(/Function/.test(n.type)){const local=new Map(env);for(const p of n.params||[])if(p.type==='Identifier')local.delete(p.name);walk(n.body,local,label,depth+1);return;}
    if(n.type==='ObjectExpression'){
      const fields:Field[]=[];for(const p of n.properties||[]){if(p.type!=='Property'||p.computed||p.kind!=='init')continue;const f=value(p.value,env);if(f)fields.push({...f,name:p.key.name||p.key.value||''});}
      for(const f of fields)signingField(f);
      const provider=identify(label)||identify(fields.find(f=>clean(f.name)==='provider')?.value||'');contexts.push({fields,label,provider,environment:hostEnvironment});
      if(!provider)for(const named of new Set(fields.map(f=>identify(f.name)).filter((p):p is string=>!!p)))contexts.push({fields:fields.filter(f=>identify(f.name)===named),label:'qualified fields in one literal object',provider:named,environment:hostEnvironment});
    }
    if(n.type==='VariableDeclarator'){walk(n.init,env,n.id.name||label,depth+1);return;}
    if(n.type==='Property'){const name=n.key?.name||n.key?.value||'';walk(n.value,env,identify(name)?name:label,depth+1);return;}
    if(n.type==='AssignmentExpression'){const name=n.left?.property?.name||n.left?.name||'';walk(n.right,env,identify(name)?name:label,depth+1);return;}
    if(n.type==='NewExpression'||n.type==='CallExpression'){
      const callee=n.callee?.name||n.callee?.property?.name||label,calleeText=n.callee&&typeof n.callee.start==='number'?text.slice(n.callee.start,n.callee.end).replace(/\s+/g,''):'';
      usage(n,calleeText,env);if(n.callee?.type==='MemberExpression')walk(n.callee.object,env,label,depth+1);
      let provider=identify(callee);const endpoint=value(n.arguments?.[0],env)?.value||(n.arguments?.[0]?.type==='ObjectExpression'?value(n.arguments[0].properties.find((p:any)=>clean(keyName(p))==='baseurl')?.value,env)?.value:'')||'';
      const hosts:Record<string,string>={'api.openai.com':'OpenAI','api.anthropic.com':'Anthropic','api.cohere.com':'Cohere','api.elevenlabs.io':'ElevenLabs','api.mistral.ai':'Mistral','api.perplexity.ai':'Perplexity','openrouter.ai':'OpenRouter','api.groq.com':'Groq','api.stability.ai':'Stability AI','api.stripe.com':'Stripe','api-m.paypal.com':'PayPal','api-m.sandbox.paypal.com':'PayPal','api.cloudflare.com':'Cloudflare','api.vercel.com':'Vercel','api.netlify.com':'Netlify','api.godaddy.com':'GoDaddy','api.ote-godaddy.com':'GoDaddy','api.heroku.com':'Heroku','api.sendgrid.com':'SendGrid','api.mailgun.net':'Mailgun','api.kraken.com':'Kraken','api.binance.com':'Binance','api.coinbase.com':'Coinbase','api.namecheap.com':'Namecheap','rest.nexmo.com':'Vonage','connect.squareup.com':'Square','connect.squareupsandbox.com':'Square'};
      let host='';try{host=new URL(endpoint).hostname;provider=hosts[host]||(/\.(?:openai|services\.ai|models\.ai)\.azure\.com$/.test(host)?'Azure AI':host==='api.postmarkapp.com'?'Postmark':host==='api.resend.com'?'Resend':provider);}catch{}
      // A sandbox or testnet request host is environment evidence for every credential attached to that request.
      const prior=hostEnvironment;if(SANDBOX_HOSTS.has(host)||/(?:^|\.)(?:sandbox|testnet)[.-]/.test(host))hostEnvironment='test';
      try{if(!provider&&host&&REQUEST.test(calleeText))requestCredentials(n,host,env);
      for(const a of n.arguments||[]){if(provider){const f=value(a,env);if(f&&!/^https?:/.test(f.value)&&! /^(?:fetch|request|get|post)$/i.test(callee)&&singleProviders.has(provider))emit({...f,name:'apiKey'},provider,'private-credential',{state:'private-material',components:['SDK authentication argument'],missing:[],context:'Literal SDK constructor argument'});walk(a,env,provider,depth+1);}else walk(a,env,callee,depth+1);}}finally{hostEnvironment=prior;}return;
    }
    for(const [k,v]of Object.entries(n)){if(['start','end','key'].includes(k))continue;if(Array.isArray(v))v.forEach(x=>walk(x,env,label,depth+1));else if(v&&typeof v==='object')walk(v,env,label,depth+1);}
  };walk(ast,new Map());
  // Bounded plain-text configuration fallback (env paragraphs, PHP constants, debug-page tables). Pair only explicitly qualified names in one group.
  if(!options.ast)for(const group of textGroups(text)){
    for(const provider of providerNames){const fields=group.fields.filter(f=>identify(f.name)===provider);if(fields.length)contexts.push({fields,label:group.label,provider});}
    const dbContext=group.fields.filter(f=>DB_CONTEXT.test(f.name)&&!fake(f.value)).map(f=>f.name);
    for(const f of group.fields){
      // Framework signing material: WordPress authentication keys and salts, Rails SECRET_KEY_BASE, Laravel APP_KEY in its base64: form, and *_SECRET/*_KEY signing names.
      const framework=FRAMEWORK_SIGNING.test(f.name)&&f.value.length>=32&&entropy(f.value)>=3.5&&!/unique phrase/i.test(f.value)||f.name==='APP_KEY'&&/^base64:[A-Za-z0-9+/]{22,86}={0,2}$/.test(f.value);
      if(framework&&!fake(f.value)){out.push({value:f.value,original:f.original,index:f.index,rule:'signing-secret-field',provider:'Application signing',category:'private-credential',severity:'high',confidence:'high',reasons:[`Literal value of the framework signing or encryption key ${f.name} in a ${group.label}; it can forge sessions, cookies or encrypted payloads. Validity is not tested.`],transformations:f.steps,environment:'unknown',credentialSet:{state:'private-material',components:['signing secret'],missing:[],context:group.label}});continue;}
      signingField(f);
      // A database password beside its host, user or database name in one configuration group.
      if(DB_SECRET.test(f.name)&&dbContext.length&&f.value.length>=8&&f.value.length<=512&&entropy(f.value)>=3&&!fake(f.value)&&!/^(?:password|passwd|secret|changeme|root|admin|example|test|database|postgres|mysql)\w{0,6}$|\$\{|^[$%]/i.test(f.value))
        emit(f,'Database','private-credential',{state:'private-material',components:['database password',...dbContext.map(n=>n.toLowerCase().replace(/_/g,' '))].slice(0,6),missing:[],context:group.label});
    }
  }
  for(const ctx of contexts){hostEnvironment=ctx.environment;
    const fields=ctx.fields;let provider=ctx.provider;
    if(fields.some(f=>clean(f.name)==='type'&&f.value==='service_account'))provider='Google Cloud';
    if(!provider&&fields.some(f=>/^(accesskeyid|secretaccesskey|awssessiontoken)$/.test(clean(f.name))))provider='AWS';
    if(!provider&&fields.some(f=>clean(f.name)==='tenantid'))provider='Azure';
    if(!provider)continue;
    const has=(re:RegExp)=>fields.filter(f=>re.test(clean(f.name))&&!fake(f.value)),names=fields.map(f=>clean(f.name));
    const componentSpecs:Record<string,[RegExp,string][]>={
      AWS:[[/accesskeyid$/,'access-key ID'],[/secretaccesskey$/,'secret access key']],
      'AWS Bedrock':[[/accesskeyid$/,'access-key ID'],[/secretaccesskey$/,'secret access key']],
      'AWS Route53':[[/accesskeyid$/,'access-key ID'],[/secretaccesskey$/,'secret access key']],
      'Google Cloud':[[/privatekey$/,'private key'],[/clientemail$/,'client email']],
      Azure:[[/clientsecret$/,'client secret'],[/clientid$/,'client ID'],[/tenantid$/,'tenant ID']],
      PayPal:[[/clientsecret$/,'client secret'],[/clientid$/,'client ID']],
      OAuth:[[/clientsecret$/,'client secret'],[/clientid$/,'client ID']],
      Postmark:names.some(n=>/accesskey$|secretkey$/.test(n))?[[/accesskey$/,'SMTP access key'],[/secretkey$/,'SMTP secret key']]:[],
      Cloudflare:names.some(n=>/glob(?:al)?apikey|xauthkey/.test(n))?[[/(?:globalapikey|xauthkey)$/,'global API key'],[/(?:email|xauthemail)$/,'account email']]:[],
      Braintree:[[/privatekey$/,'private key'],[/publickey$/,'public key'],[/merchantid$/,'merchant ID']],
      Twilio:names.some(n=>/authtoken$/.test(n))?[[/authtoken$/,'auth token'],[/accountsid$/,'account SID']]:[[/(?:apikey)?secret$/,'API secret'],[/(?:apikey|keysid|apisid|apikeysid)$/,'API key SID']],
      Kraken:[[/secret(?:key)?$/,'private signing secret'],[/apikey$/,'API key']],
      Binance:[[/secret(?:key)?$/,'private signing secret'],[/apikey$/,'API key']],
      Coinbase:names.some(n=>/passphrase$/.test(n))?[[/secret$/,'signing secret'],[/apikey$/,'API key'],[/passphrase$/,'passphrase']]:[[/(?:privatekey|apisecret|keysecret)$/,'private signing key'],[/(?:name|keyname|apikey)$/,'key name']],
      Vonage:names.some(n=>/privatekey$/.test(n))?[[/privatekey$/,'private key'],[/applicationid$/,'application ID']]:[[/apisecret$/,'API secret'],[/apikey$/,'API key']],
      GoDaddy:[[/secret$/,'API secret'],[/apikey$/,'API key']],
      Namecheap:[[/apikey$/,'API key'],[/apiuser$/,'API user'],[/username$/,'username'],[/clientip$/,'approved client IP']]
    };
    const specs=componentSpecs[provider]||[],components=specs.filter(([re])=>has(re).length===1).map(([,name])=>name),missing=specs.filter(([re])=>has(re).length!==1).map(([,name])=>name);
    if(/^AWS/.test(provider)&&has(/accesskeyid$/).some(f=>/^ASIA/.test(f.value))){if(has(/sessiontoken$/).length===1)components.push('session token');else missing.push('session token');}
    for(const f of fields){const n=clean(f.name),qualified=identify(f.name);if(qualified&&qualified!==provider)continue;
      // Endpoints and key identifiers beside a sensitive word are not secrets (token_uri, auth_url, private_key_id).
      if(/(?:uri|url|endpoint)$/.test(n)&&/^https?:\/\//i.test(f.value))continue;
      if(/(?:privatekey|signingkey|secret|token|password)id$/.test(n)){emit(f,provider,'public-identifier');continue;}
      if(/public|publishable|clientid$|tenantid$|merchantid$|accountsid$|keyname$|projectid$|subscriptionid$|apikeysid$/.test(n)&&!sensitive(n)){emit(f,provider,'public-identifier');continue;}
      const auth=/authorization$/.test(n)&&/^(Bearer|Basic|sso-key)\s+/i.test(f.value);
      if(!sensitive(n)&&!auth&&!/xauthkey$/.test(n))continue;
      if(/session|csrf|nonce|public|publishable|anontoken/.test(n)&&!/^AWS/.test(provider))continue;
      if((/apikey$/.test(n)&&['AWS','Twilio','Kraken','Binance','Coinbase','GoDaddy'].includes(provider))||/accesskeyid$/.test(n)){emit(f,provider,'suspicious',{state:'partial',components,missing:missing.length?missing:['private signing material'],context:ctx.label});continue;}
      if(f.value.length<8)continue; // Explicit provider authentication context can establish a UUID-shaped secret.
      const actual=auth?{...f,value:f.value.replace(/^(?:Bearer|Basic|sso-key)\s+/i,'')}:f;
      const relationship:Candidate['credentialSet']=specs.length&&!/accesstoken|bearertoken|pat$/.test(n)?{state:missing.length?'partial':'complete',components,missing,context:ctx.label}:{state:'private-material',components:[auth?'authorization token':f.name],missing:[],context:ctx.label};
      emit(actual,provider==='Google / Gemini'&&/accesstoken|privatekey/.test(n)?'Google Cloud':provider,provider==='Google / Gemini'&&!/accesstoken|privatekey/.test(n)?'suspicious':'private-credential',auth?{state:'private-material',components:['authorization credential'],missing:[],context:ctx.label}:relationship);
      if(out.at(-1)?.value===actual.value&&fields.some(x=>/environment|mode|sandbox|testnet/.test(clean(x.name))&&/^(?:test|sandbox|testnet)$/i.test(x.value)))out.at(-1)!.environment='test';
      // AWS secret access key: carry its paired public access-key ID (and session token for ASIA temporary keys) so a live check can SigV4-sign. The secret itself never leaves the machine.
      if(/^AWS/.test(provider)&&/secretaccesskey$/.test(n)&&out.at(-1)?.value===actual.value){const akid=has(/accesskeyid$/),tok=has(/sessiontoken$/);if(akid.length===1)out.at(-1)!.companions={accessKeyId:akid[0].value,...(tok.length===1?{sessionToken:tok[0].value}:{})};}
    }
  }
  hostEnvironment=undefined;if(options.ast)return out;
  // Azure storage connection strings and scoped SAS are contextual secrets, not account IDs.
  for(const m of text.matchAll(/\bAccountName=([^;\s"']{1,100});AccountKey=([A-Za-z0-9+/]{40,128}={0,2})/g))emit({name:'AccountKey',value:m[2],index:m.index!+m[0].indexOf(m[2]),original:m[2],steps:[]},'Azure','private-credential',{state:'complete',components:['storage account name','account key'],missing:[],context:'Azure connection string'});
  for(const m of text.matchAll(/https?:\/\/[^\s"'<>]{1,4096}/g)){try{const u=new URL(m[0]);if(/\.(?:blob|file|queue|table)\.core\.windows\.net$/.test(u.hostname)&&u.searchParams.has('sig')&&u.searchParams.has('sv')){const sig=u.searchParams.get('sig')!;emit({name:'SAS signature',value:sig,index:m.index!+m[0].indexOf('sig=')+4,original:u.search.match(/[?&]sig=([^&]+)/)?.[1]||sig,steps:['URL query decoding']},'Azure','private-credential',{state:'private-material',components:['scoped SAS signature'],missing:[],context:'Storage SAS parameters present; grants, expiry and validity unverified'});}}catch{}}
  return out;
}
