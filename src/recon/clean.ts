/**
 * Recon item cleaning: every URL, endpoint, parameter name and provenance label passes through here before it can reach a recon list.
 * No credential value may survive: query and fragment values are dropped (names kept), user info is dropped, `;name=value` path
 * parameters keep only the name, and path segments shaped like credentials are replaced with `{redacted}`. Pure functions, no I/O.
 */
export const REDACTED='{redacted}';
export const EXPR='{EXPR}';
/** Credential shapes from the detection rules (prefix plus body), matched anywhere inside one decoded path segment or name. Synthetic examples live in the tests. */
const KNOWN_SECRETS:readonly RegExp[]=[
  /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{16}\b/,
  /\bAIza[0-9A-Za-z_-]{30,}/,
  /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}/,/\bgithub_pat_[A-Za-z0-9_]{20,}/,/\bglpat-[A-Za-z0-9_-]{16,}/,
  /\bxox[abposre]-[A-Za-z0-9-]{8,}/,/\bxapp-\d-[A-Za-z0-9-]{8,}/,
  /\b(?:sk|rk)_(?:live|test|org)_[A-Za-z0-9_]{8,}/,/\bwhsec_[A-Za-z0-9+/=_-]{8,}/,
  /\bsk-(?:proj-|ant-(?:api|admin)\d{2}-|or-v1-|svcacct-)?[A-Za-z0-9_-]{20,}/,
  /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/,/\bhf_[A-Za-z0-9]{20,}/,/\br8_[A-Za-z0-9]{20,}/,/\bsb_secret_[A-Za-z0-9_-]{8,}/,
  /\bshp(?:at|ss|ca|pa)_[A-Fa-f0-9]{16,}/,/\bnpm_[A-Za-z0-9]{30,}/,/\bpypi-[A-Za-z0-9_-]{30,}/,/\bdo[pora]_v1_[a-f0-9]{32,}/,
  /\bgsk_[A-Za-z0-9_-]{20,}/,/\bpplx-[A-Za-z0-9_-]{20,}/,/\bre_[A-Za-z0-9]{20,}/,/\bkey-[0-9a-f]{32}\b/,/\bSK[0-9a-f]{32}\b/,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}(?:\.[A-Za-z0-9_-]*)?/,
  /\b(?:bot)?\d{8,12}:[A-Za-z0-9_-]{30,}/,
  /-----BEGIN[ A-Z]{0,40}PRIVATE KEY/,
  /\b(?:AccountKey|SharedAccessKey|sig|password|passwd|secret)=/i
];
const entropy=(s:string)=>{const counts=new Map<string,number>();for(const c of s)counts.set(c,(counts.get(c)||0)+1);let h=0;for(const n of counts.values())h-=(n/s.length)*Math.log2(n/s.length);return h;};
const classOf=(c:string)=>c>='a'&&c<='z'?1:c>='A'&&c<='Z'?2:c>='0'&&c<='9'?3:4;
/** A random-looking token: long, mixed case with digits, high entropy and frequent character-class switches. Hex content hashes (no upper case) and UUIDs are kept. */
function randomToken(part:string){
  if(part.length<24||!/^[A-Za-z0-9_+/=-]+$/.test(part)||!/[a-z]/.test(part)||!/[A-Z]/.test(part)||!/[0-9]/.test(part))return false;
  let switches=0;for(let i=1;i<part.length;i++)if(classOf(part[i])!==classOf(part[i-1]))switches++;
  return switches/(part.length-1)>=0.4&&entropy(part)>=3.5;
}
const decode=(s:string)=>{try{return decodeURIComponent(s);}catch{return s;}};
/** True when a known credential shape occurs anywhere in `raw` (raw and percent-decoded): the last check on every finished recon line. */
export function containsKnownSecret(raw:string):boolean{const s=decode(raw);return KNOWN_SECRETS.some(r=>r.test(raw)||r.test(s));}
/** True when one path segment, name or token looks like a credential value. */
export function secretShaped(raw:string):boolean{
  const s=decode(raw);if(!s)return false;
  if(KNOWN_SECRETS.some(r=>r.test(s)))return true;
  if(/^[0-9a-f]{32,}$/i.test(s)&&/[0-9]/.test(s)&&/[a-f]/i.test(s)&&!/^[0-9a-f]{40}$/.test(s))return true; // a whole hex segment of key length; lower-case 40-hex commit IDs stay
  return s.split(/[.:@~!$'()*,]/).some(randomToken);
}
/** Path with `;name=value` path parameters reduced to names and credential-shaped segments redacted. Separators are kept as found. */
export function redactPath(path:string):{value:string;redactions:number}{
  let redactions=0;
  const value=path.split('/').map(segment=>{
    if(!segment||segment===EXPR)return segment;
    const [head,...matrix]=segment.split(';');
    const keep=matrix.map(p=>p.split('=')[0]).filter(n=>validParameterName(decode(n)));
    let out=head;
    // Webhook-style capability paths: the token segment is redacted even when it is short or plain.
    if(secretShaped(head)){out=REDACTED;redactions++;}
    return out+keep.map(n=>';'+n).join('');
  }).join('/');
  // Slack and Discord webhook paths carry the secret in the last segment, whatever its shape.
  const hook=/^(.*\/services\/T[A-Z0-9]{6,20}\/B[A-Z0-9]{6,20}\/)([^/]+)$|^(.*\/api(?:\/v\d{1,2})?\/webhooks\/\d{15,20}\/)([^/]+)$/.exec(value);
  if(hook&&(hook[2]||hook[4])!==REDACTED){redactions++;return {value:(hook[1]||hook[3])+REDACTED,redactions};}
  return {value,redactions};
}
/** A parameter name worth listing: short, printable ASCII without separators, and not itself a credential. */
export function validParameterName(name:string,max=128){return name.length>0&&name.length<=max&&/^[A-Za-z0-9_.\-[\]$@:]+$/.test(name)&&!secretShaped(name);}
/** Names from a query or fragment string (`?a=1&b` → `a`, `b`); values are never returned. */
export function queryNames(query:string,max=64):string[]{
  const out:string[]=[];
  for(const part of query.replace(/^[?#]/,'').split(/[&;]/)){if(out.length>=max)break;if(!part)continue;const name=decode(part.split('=')[0].replace(/\+/g,' '));if(validParameterName(name)&&!out.includes(name))out.push(name);}
  return out;
}
const HTML_AMP=/&(?:amp|#0*38|#x0*26);/gi;
export interface CleanUrl {url:string;host:string;pathname:string;params:string[];redactions:number}
/**
 * Canonical recon form of an absolute http(s)/ws(s) URL, resolved against `base` when relative: user info and fragment dropped, query reduced to
 * `?name&name`, credential-shaped path segments redacted. Undefined when it is not such a URL, is too long, or has no host.
 */
export function cleanUrl(raw:string,base?:string,maxLength=2048):CleanUrl|undefined{
  if(!raw||raw.length>maxLength*2)return;
  let u:URL;try{u=new URL(raw.trim().replace(HTML_AMP,'&'),base);}catch{return;}
  if(!['http:','https:','ws:','wss:'].includes(u.protocol)||!u.hostname)return;
  const params=[...queryNames(u.search),...queryNames(/^#[^/!]*=/.test(u.hash)?u.hash:'')].filter((n,i,a)=>a.indexOf(n)===i);
  const query=queryNames(u.search);
  if(u.origin.length+u.pathname.length>maxLength)return;
  u.username='';u.password='';u.hash='';u.search='';
  const path=redactPath(u.pathname.replace(/%7BEXPR%7D/gi,EXPR));
  const url=u.origin+path.value+(query.length?'?'+query.map(n=>encodeURIComponent(n).replace(/%5B/g,'[').replace(/%5D/g,']')).join('&'):'');
  if(url.length>maxLength||/[\s\u0000-\u001f\u007f]/.test(url))return;
  return {url,host:u.hostname.toLowerCase(),pathname:path.value,params,redactions:path.redactions};
}
const ENDPOINT_CHARS=/^[A-Za-z0-9\-._~%!$&'()*+,;=:@/{}[\]]+$/;
export interface CleanEndpoint {path:string;params:string[];redactions:number}
/** Recon form of a path or API route as written (`/api/users/:id`, `api/v1/items`, `/v1/{EXPR}/files`): query and fragment reduced to names, credential-shaped segments redacted. */
export function cleanEndpoint(raw:string,maxLength=1024):CleanEndpoint|undefined{
  let s=raw.trim().replace(HTML_AMP,'&');if(!s||s.length>maxLength*2)return;
  const q=s.search(/[?#]/),query=q>=0?s.slice(q):'';if(q>=0)s=s.slice(0,q);
  const params=queryNames(query.startsWith('#')?(/^#[^/!]*=/.test(query)?query:''):query.split('#')[0]);
  if(!s||s==='/'||s.startsWith('//')||!ENDPOINT_CHARS.test(s)||!/[A-Za-z]/.test(s.replace(/\{EXPR\}/g,'')))return params.length?{path:'',params,redactions:0}:undefined;
  const path=redactPath(s.replace(/\/{2,}/g,'/'));
  if(path.value.length>maxLength)return;
  return {path:path.value,params,redactions:path.redactions};
}
/** A provenance or label string that is not an http(s) URL (for example `webpack:///src/a.ts`): control characters removed, query values dropped, secrets redacted, capped. */
export function cleanLabel(raw:string,maxLength=1024):string{
  const http=cleanUrl(raw,undefined,maxLength);if(http)return http.url;
  let s=String(raw).replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g,'').slice(0,maxLength*2);
  const q=s.search(/[?#]/);let query='';if(q>=0){query=s.slice(q);s=s.slice(0,q);}
  const names=queryNames(query.split('#')[0]);
  const scheme=/^[A-Za-z][A-Za-z0-9+.-]{0,31}:\/*/.exec(s)?.[0]||'';
  s=scheme+redactPath(s.slice(scheme.length)).value+(names.length?'?'+names.join('&'):'');
  return s.length>maxLength?s.slice(0,maxLength):s;
}
/** Hostname syntax for bare host literals (`api.shop.example`): at least two labels, an alphabetic top label, no port or path. */
export function hostLiteral(raw:string):string|undefined{
  const s=raw.trim().toLowerCase().replace(/\.$/,'');
  if(s.length<4||s.length>253||!/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/.test(s))return;
  return s;
}
