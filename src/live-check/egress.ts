import type { LiveCheckResult } from '../types.js';
import { pinnedDial, DialError, type DialResolver } from '../net/pinned-dial.js';
import { recipeFor, SLACK_REVOKED_ERRORS, type VerifyRecipe } from './recipes.js';
import { signV4, amzDate } from './sigv4.js';
/** The single explicit egress path for a live key check. It is reached only by a per-finding user action or the paced run-all driver; no scan, crawler or mass-run code calls it (enforced by the import-graph test). It sends exactly one request, to the key's own provider recipe endpoint, with the key in the one documented header and nothing else from the scan. */
export interface CheckOneKeyInput { rule:string; key:string; provider?:string; companions?:{accessKeyId?:string;sessionToken?:string}; }
/** Code-only test seam. Never built from config, environment variables or scanned content: only the dashboard/CLI test entry points pass it, and only with loopback mock providers. */
export interface CheckEnv { recipes?:(rule:string)=>VerifyRecipe|undefined; resolver?:DialResolver; allowLoopback?:boolean; port?:number; timeoutMs?:number; }
/** A hard refusal (protected host, metadata address, non-HTTPS, pin mismatch). Recipes never target these, so it is pure defence in depth; the dashboard maps it to 400 protected-host and the CLI to an error. */
export class LiveCheckRefused extends Error { constructor(readonly code:string){super(code);} }
const REFUSE=new Set(['protected-host','metadata','insecure','connection-address-mismatch']);
export async function checkOneKey(input:CheckOneKeyInput,env:CheckEnv={}):Promise<LiveCheckResult>{
  const checkedAt=new Date().toISOString(),provider=input.provider||input.rule;
  const recipe=(env.recipes||recipeFor)(input.rule);
  if(!recipe)return {result:'unknown',checkedAt,provider,reason:'no-recipe'};            // fail closed: no recipe, no request
  const endpointHost=recipe.host;
  const url=`https://${recipe.host}${env.port?':'+env.port:''}${recipe.path}`;
  const headers:Record<string,string>={...(recipe.headers||{})};
  const basic=recipe.present==='basic'?Buffer.from(input.key+':','utf8'):undefined;
  if(recipe.present==='bearer')headers['authorization']='Bearer '+input.key;
  else if(recipe.present==='x-api-key')headers['x-api-key']=input.key;
  else if(recipe.present==='header')headers[recipe.headerName!.toLowerCase()]=input.key;
  else if(recipe.present==='basic')headers['authorization']='Basic '+basic!.toString('base64');
  else if(recipe.present==='aws-sigv4'){
    const akid=input.companions?.accessKeyId,token=input.companions?.sessionToken;
    // Need the paired public access-key ID; ASIA temporary keys also need a session token. Without them we cannot sign, so we send nothing and return unknown.
    if(!akid||!/^(?:AKIA|ASIA)[A-Z0-9]{16}$/.test(akid)||/^ASIA/.test(akid)&&!token)
      return {result:'unknown',checkedAt,provider:recipe.provider,endpointHost,reason:'incomplete-credential'};
    // The secret access key only derives the signing key here; the key itself is never put in a header or sent.
    Object.assign(headers,signV4({method:recipe.method,host:recipe.host,path:recipe.path,headers:recipe.headers||{},body:recipe.body||'',region:recipe.region!,service:recipe.service!,accessKeyId:akid,secretAccessKey:input.key,sessionToken:token,amzDate:amzDate()}));
  }
  try{
    const resp=await pinnedDial({url,method:recipe.method,headers,body:recipe.body!==undefined?Buffer.from(recipe.body):undefined,timeoutMs:env.timeoutMs??8000,resolver:env.resolver,allowLoopback:env.allowLoopback});
    const status=resp.status,base={checkedAt,provider:recipe.provider,endpointHost,status};
    if(status>=300&&status<400)return {result:'unknown',...base,reason:'redirect'};     // never followed
    if(recipe.signal==='slack-ok')return {...slackVerdict(resp.body),...base};
    if(recipe.signal==='aws-sts')return {...stsVerdict(status,resp.body),...base};
    if(recipe.live.includes(status))return {result:'live',...base};
    if(recipe.revoked.includes(status))return {result:'revoked',...base};               // only the recipe's declared statuses
    if(status===429)return {result:'unknown',...base,reason:'rate-limited'};
    if(status>=400)return {result:'unknown',...base,reason:'http-error'};                // conservative: not revoked unless declared
    return {result:'unknown',...base,reason:'unexpected-shape'};
  }catch(e){
    const code=e instanceof DialError?e.code:'network';
    if(REFUSE.has(code))throw new LiveCheckRefused(code);                                // surfaced, never a silent pass
    const reason=code==='host-not-allowlisted'?'host-not-allowlisted':code==='tls-untrusted'?'tls-untrusted':code==='timeout'?'timeout':'network';
    return {result:'unknown',checkedAt,provider:recipe.provider,endpointHost,reason};
  }finally{
    basic?.fill(0);                                                                      // zero the one buffer we made from the key
    for(const k of ['authorization','x-api-key','x-amz-security-token','x-amz-date',recipe.headerName?.toLowerCase()||''])delete headers[k];
  }
}
/** Slack auth.test returns 200 with {ok} in the body. Parse only the `ok` boolean and a known revoked-error string; anything else is unknown. */
function slackVerdict(body:Buffer):{result:LiveCheckResult['result'];reason?:LiveCheckResult['reason']}{
  try{const j=JSON.parse(body.toString('utf8'));
    if(j&&j.ok===true)return {result:'live'};
    if(j&&j.ok===false&&typeof j.error==='string'&&SLACK_REVOKED_ERRORS.includes(j.error))return {result:'revoked'};
  }catch{}
  return {result:'unknown',reason:'unexpected-shape'};
}
/** STS GetCallerIdentity verdict. 200 means the key signed and is active (live). A failure carries an XML <Code>: the few codes that mean the key no longer works are revoked, throttling is rate-limited, and anything else stays unknown. The secret is never sent — only the access-key ID, the signature and the optional session token. */
function stsVerdict(status:number,body:Buffer):{result:LiveCheckResult['result'];reason?:LiveCheckResult['reason']}{
  if(status===200)return {result:'live'};
  const text=body.toString('utf8'),code=text.match(/<Code>([^<]+)<\/Code>/)?.[1]||'';
  if(/^Throttling/.test(code)||code==='RequestLimitExceeded')return {result:'unknown',reason:'rate-limited'};
  if(code==='InvalidClientTokenId'||code==='ExpiredToken'||code==='ExpiredTokenException'||code==='SignatureDoesNotMatch'&&!/expired/i.test(text))return {result:'revoked'};
  return {result:'unknown',reason:status===429?'rate-limited':'http-error'};
}
