import net from 'node:net';
import ipaddr from 'ipaddr.js';
import {parse} from 'tldts';
/** Program scope rules (2.8). A rule is one of:
 *  - an exact host (`app.example.com`): that host on any scheme and port;
 *  - a wildcard (`*.example.com`): subdomains only, never the apex (the apex needs its own rule);
 *  - a URL prefix with optional scheme, port and path (`https://api.example.com:8443/v1/`, `example.com/app`, `*.example.com/api/`);
 *  - an IP literal (`192.0.2.10`, `[2001:db8::1]`) or a CIDR block (`192.0.2.0/24`), matched against IP-literal URLs only (names are never resolved for scope).
 * Matching is on the canonical URL (lowercase punycode host); out-of-scope rules always win. Pure: no DNS and no I/O. */
export type RuleKind='host'|'wildcard'|'url'|'ip'|'cidr';
export interface ScopeRule {raw:string;kind:RuleKind;
  /** Exact host (lowercase punycode, or a canonical IP) for host, ip and exact-host url rules. */
  host?:string;
  /** Wildcard base for wildcard rules and wildcard-host url rules (`*.base`). */
  base?:string;
  scheme?:'http:'|'https:';port?:string;
  /** Path prefix for url rules; absent or `/` means any path. */
  path?:string;
  cidr?:[ipaddr.IPv4|ipaddr.IPv6,number];
}
export class RuleError extends Error{constructor(message:string){super(message);this.name='RuleError';}}
export const MAX_RULE_LENGTH=2048;
const LABEL=/^(?!-)[a-z0-9-]{1,63}(?<!-)$/;
const canonicalIp=(s:string)=>{const a=ipaddr.process(s);return a.kind()==='ipv6'?a.toNormalizedString():a.toString();};
const bareHost=(h:string)=>h.replace(/^\[|\]$/g,'');
const defaultPort=(scheme:string)=>scheme==='https:'?'443':'80';
/** Lowercase punycode host without a trailing dot, or undefined when it is not a valid DNS name. */
function dnsName(input:string,minLabels=2):string|undefined{
  let host:string;try{host=new URL('http://'+input+'/').hostname;}catch{return undefined;}
  host=host.replace(/\.$/,'');if(!host||host.length>253||net.isIP(bareHost(host)))return undefined;
  // At least two labels for a host: a single-label name is never a public website (and imported descriptions such as "Main" must not become rules). A wildcard base may be one label (*.com) so the public-suffix check below can name it.
  const labels=host.split('.');return labels.length>=minLabels&&labels.every(l=>LABEL.test(l))?host:undefined;
}
/** Parses the host part of a rule: an IP literal, `*.base` or a DNS name. */
function hostPart(raw:string,text:string,inScope:boolean):{host?:string;base?:string;ip?:boolean}{
  const bare=bareHost(text);
  if(net.isIP(bare)){if(net.isIP(bare)===6&&!/^\[.*\]$/.test(text)&&text.includes(']'))throw new RuleError(`Scope rule "${raw}": malformed IPv6 literal`);return {host:canonicalIp(bare),ip:true};}
  if(text.startsWith('*.')){const base=dnsName(text.slice(2),1);if(!base)throw new RuleError(`Scope rule "${raw}": "${text}" is not a valid wildcard (use *.example.com)`);
    // A wildcard over a public suffix (*.com, *.co.uk, *.github.io) would cover unrelated owners; an in-scope rule must name a registrable domain or deeper.
    if(inScope&&!parse(base,{allowPrivateDomains:true}).domain)throw new RuleError(`Scope rule "${raw}": a wildcard over the public suffix "${base}" is too broad; name the program's own domain`);
    return {base};}
  if(text.includes('*'))throw new RuleError(`Scope rule "${raw}": only a leading "*." wildcard is supported (for example *.example.com)`);
  const host=dnsName(text);if(!host)throw new RuleError(`Scope rule "${raw}": "${text}" is not a valid host name`);
  return {host};
}
/** Parses one rule; `inScope` applies the stricter in-scope checks (no wildcard over a public suffix). Throws RuleError with a message naming the rule. */
export function parseRule(input:unknown,inScope=true):ScopeRule{
  if(typeof input!=='string')throw new RuleError('Scope rules must be strings');
  const raw=input.trim();
  if(!raw)throw new RuleError('Scope rules must not be empty');
  if(raw.length>MAX_RULE_LENGTH)throw new RuleError(`Scope rule is longer than ${MAX_RULE_LENGTH} characters`);
  if(/[\s\x00-\x1f\x7f]/.test(raw))throw new RuleError(`Scope rule "${raw.replace(/[\x00-\x1f\x7f]/g,'?')}" contains whitespace or control characters`);
  if(raw==='*'||raw==='*.*'||/^\*[^.]/.test(raw))throw new RuleError(`Scope rule "${raw}": a bare "*" is not a scope rule; name the program's domain (for example *.example.com)`);
  // CIDR block (an address with a prefix length and nothing else).
  if(/^\[?[0-9a-f:.]+\]?\/\d{1,3}$/i.test(raw)){
    const text=raw.replace(/^\[|\](?=\/)/g,'');
    if(!ipaddr.isValidCIDR(text))throw new RuleError(`Scope rule "${raw}": invalid CIDR block`);
    const [addr,bits]=ipaddr.parseCIDR(text),address=addr.kind()==='ipv6'&&(addr as ipaddr.IPv6).isIPv4MappedAddress()?(addr as ipaddr.IPv6).toIPv4Address():addr,prefix=address===addr?bits:bits-96;
    if(prefix<0)throw new RuleError(`Scope rule "${raw}": invalid CIDR block`);
    if(inScope&&prefix<(address.kind()==='ipv4'?8:32))throw new RuleError(`Scope rule "${raw}": a block wider than /${address.kind()==='ipv4'?8:32} is too broad for in-scope`);
    return {raw,kind:'cidr',cidr:[address,prefix]};
  }
  const scheme=/^([A-Za-z][A-Za-z0-9+.-]*):\/\//.exec(raw);
  const looksUrl=!!scheme||/[/?#]/.test(raw)||/^(?:\[[^\]]*\]|[^:\]]+):\d+$/.test(raw);
  if(!looksUrl){
    const part=hostPart(raw,raw,inScope);
    return part.ip?{raw,kind:'ip',host:part.host}:part.base?{raw,kind:'wildcard',base:part.base}:{raw,kind:'host',host:part.host};
  }
  let rest=raw,ruleScheme:ScopeRule['scheme'];
  if(scheme){const s=scheme[1]!.toLowerCase();if(s!=='http'&&s!=='https')throw new RuleError(`Scope rule "${raw}": only http and https URLs can be in a program scope`);ruleScheme=(s+':') as ScopeRule['scheme'];rest=raw.slice(scheme[0].length);}
  const end=rest.search(/[/?#]/),authority=end<0?rest:rest.slice(0,end);let path=end<0?'':rest.slice(end);
  if(!authority)throw new RuleError(`Scope rule "${raw}": missing host`);
  if(authority.includes('@'))throw new RuleError(`Scope rule "${raw}": user information is not allowed in a scope rule`);
  if(/[?#]/.test(path))throw new RuleError(`Scope rule "${raw}": query strings and fragments are not supported in scope rules; use a path prefix`);
  const portMatch=/^(\[[^\]]*\]|[^:]+)(?::(\d{1,5}))?$/.exec(authority);
  if(!portMatch)throw new RuleError(`Scope rule "${raw}": invalid host or port`);
  const port=portMatch[2];if(port!==undefined&&(Number(port)<1||Number(port)>65535))throw new RuleError(`Scope rule "${raw}": invalid port`);
  const part=hostPart(raw,portMatch[1]!,inScope);
  // A trailing "*" or "/*" on the path means the same prefix; any other "*" in a path is unsupported.
  path=path.replace(/\/?\*$/,'/');
  if(path.includes('*'))throw new RuleError(`Scope rule "${raw}": only a trailing "*" is supported in a path`);
  let pathname:string|undefined;
  if(path&&path!=='/'){try{pathname=new URL(path,'http://rule.invalid').pathname;}catch{throw new RuleError(`Scope rule "${raw}": invalid path`);}}
  const rule:ScopeRule={raw,kind:'url',...(part.base?{base:part.base}:{host:part.host}),...(ruleScheme?{scheme:ruleScheme}:{}),...(port!==undefined?{port:String(Number(port))}:{}),...(pathname&&pathname!=='/'?{path:pathname}:{})};
  return rule;
}
function urlHost(u:URL){const h=u.hostname.toLowerCase().replace(/\.$/,''),bare=bareHost(h);return net.isIP(bare)?{host:canonicalIp(bare),ip:true}:{host:h,ip:false};}
function hostMatches(rule:ScopeRule,host:string,ip:boolean){
  if(rule.kind==='cidr'){if(!ip)return false;const a=ipaddr.process(host),[net0,bits]=rule.cidr!;return a.kind()===net0.kind()&&(a as ipaddr.IPv4).match(net0 as ipaddr.IPv4,bits);}
  if(rule.base!==undefined)return !ip&&host.endsWith('.'+rule.base);
  return rule.host===host;
}
function pathMatches(rule:ScopeRule,pathname:string){
  const p=rule.path;if(!p)return true;
  return p.endsWith('/')?pathname.startsWith(p):pathname===p||pathname.startsWith(p+'/');
}
function originMatches(rule:ScopeRule,u:URL){
  if(rule.kind!=='url')return true;
  if(rule.scheme&&u.protocol!==rule.scheme)return false;
  const port=u.port||defaultPort(u.protocol);
  if(rule.port!==undefined)return port===rule.port;
  if(rule.scheme)return port===defaultPort(rule.scheme);
  return true;
}
/** True when this rule matches the URL (host, scheme, port and path). */
export function ruleMatches(rule:ScopeRule,u:URL):boolean{
  if(!['http:','https:'].includes(u.protocol))return false;
  const {host,ip}=urlHost(u);
  return hostMatches(rule,host,ip)&&originMatches(rule,u)&&pathMatches(rule,u.pathname);
}
export interface ScopeCheck {allowed:boolean;reason:'in-scope'|'out-of-scope-rule'|'not-in-scope';rule?:string}
/** Compiled program scope: out rules win, then any in rule admits. Rules are indexed by host and wildcard base so a check is proportional to the host's label count. */
export class ProgramScope {
  readonly in:ScopeRule[];readonly out:ScopeRule[];
  private index:{in:Index;out:Index};
  constructor(scope:{in:readonly string[];out:readonly string[]}){
    this.in=scope.in.map(r=>parseRule(r,true));this.out=scope.out.map(r=>parseRule(r,false));
    this.index={in:indexRules(this.in),out:indexRules(this.out)};
  }
  private candidates(which:'in'|'out',host:string,ip:boolean){
    const idx=this.index[which],out:ScopeRule[]=[...(idx.hosts.get(host)||[])];
    if(ip)out.push(...idx.cidrs);
    else{const labels=host.split('.');for(let i=1;i<labels.length;i++){const hit=idx.bases.get(labels.slice(i).join('.'));if(hit)out.push(...hit);}}
    return out;
  }
  check(u:URL):ScopeCheck{
    if(!['http:','https:'].includes(u.protocol))return {allowed:false,reason:'not-in-scope'};
    const {host,ip}=urlHost(u);
    const out=this.candidates('out',host,ip).find(r=>hostMatches(r,host,ip)&&originMatches(r,u)&&pathMatches(r,u.pathname));
    if(out)return {allowed:false,reason:'out-of-scope-rule',rule:out.raw};
    const hit=this.candidates('in',host,ip).find(r=>hostMatches(r,host,ip)&&originMatches(r,u)&&pathMatches(r,u.pathname));
    return hit?{allowed:true,reason:'in-scope',rule:hit.raw}:{allowed:false,reason:'not-in-scope'};
  }
  allows(u:URL|string){try{return this.check(typeof u==='string'?new URL(u):u).allowed;}catch{return false;}}
  /** Origin level (for related origins): some in rule covers this origin on some path, and no out rule excludes the whole origin. */
  originPossible(u:URL|string){
    let url:URL;try{url=typeof u==='string'?new URL(u):u;}catch{return false;}
    const {host,ip}=urlHost(url);
    if(this.candidates('out',host,ip).some(r=>!r.path&&hostMatches(r,host,ip)&&originMatches(r,url)))return false;
    return this.candidates('in',host,ip).some(r=>hostMatches(r,host,ip)&&originMatches(r,url));
  }
  /** One readable line per rule, in-scope first. */
  describe():string[]{return [...this.in.map(r=>'in   '+describeRule(r)),...this.out.map(r=>'out  '+describeRule(r))];}
}
interface Index {hosts:Map<string,ScopeRule[]>;bases:Map<string,ScopeRule[]>;cidrs:ScopeRule[]}
function indexRules(rules:ScopeRule[]):Index{
  const idx:Index={hosts:new Map(),bases:new Map(),cidrs:[]};
  const add=(m:Map<string,ScopeRule[]>,k:string,r:ScopeRule)=>{const l=m.get(k);if(l)l.push(r);else m.set(k,[r]);};
  for(const r of rules){if(r.kind==='cidr')idx.cidrs.push(r);else if(r.base!==undefined)add(idx.bases,r.base,r);else add(idx.hosts,r.host!,r);}
  return idx;
}
export function describeRule(r:ScopeRule):string{
  const host=r.base!==undefined?'*.'+r.base:r.kind==='cidr'?r.cidr![0].toString()+'/'+r.cidr![1]:r.host!.includes(':')?'['+r.host+']':r.host!;
  switch(r.kind){
    case 'host':return `${host} (this host only, any scheme and port)`;
    case 'wildcard':return `${host} (subdomains of ${r.base} only; not ${r.base} itself)`;
    case 'ip':return `${host} (this IP address, when a URL names it directly)`;
    case 'cidr':return `${host} (IP addresses in this block, when a URL names them directly)`;
    default:return `${r.scheme?r.scheme.slice(0,-1)+'://':''}${host}${r.port?':'+r.port:''}${r.path||'/'} (${r.scheme?r.scheme.slice(0,-1):'http and https'}, ${r.port?'port '+r.port:r.scheme?'default port':'any port'}, ${r.path?'paths under '+r.path:'any path'}${r.base!==undefined?', subdomains only':''})`;
  }
}
/** The host part a rule names (for protected-host checks): the exact host, the wildcard base, or undefined for IP rules. */
export function ruleHost(r:ScopeRule):string|undefined{return r.kind==='cidr'||r.kind==='ip'?undefined:r.base??r.host;}
