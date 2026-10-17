/**
 * Recon collector: fed every downloaded or captured resource `(url, kind, contentType, text)`, it builds deduplicated, sorted lists of URLs,
 * endpoints, hosts (classified by the caller's scope function), parameter names, JavaScript files, source maps and GraphQL operations/endpoints.
 * Every item is cleaned before it is stored (src/recon/clean.ts): query values, fragments and user info are dropped, credential-shaped path
 * segments are redacted, and a finished item that still contains a known credential shape (or that the caller's secret filter flags) is dropped.
 * Nothing here fetches anything. `add` never throws, so recon can never fail a scan.
 */
import { cleanEndpoint, cleanLabel, cleanUrl, containsKnownSecret, hostLiteral, REDACTED, validParameterName, type CleanUrl } from './clean.js';
import { extractRecon, reconMode, type ExtractSink, type GraphqlType } from './extract.js';
import { DEFAULT_RECON_LIMITS, LIST_NAMES, type DroppedCounts, type HostScope, type ListName, type ReconItem, type ReconLimits, type ReconResource, type ReconResult, type ScopeClassifier, type ScopeVerdict, type SecretFilter } from './types.js';
import { protectedHost } from '../protected-hosts.js';
import type { ScopeDecision } from '../domain-scope.js';
/** Anything that can take a parsed source map for rebuilding (src/recon/rebuild.ts SourceRebuilder). */
/** `inline`: the map was embedded (`sourceMappingURL=data:`) in the resource at `mapUrl`, so `mapUrl` is that resource, not a map file. */
export interface SourceMapOptions {inline?:boolean}
export interface MapSink {add(mapUrl:string,map:unknown,options?:SourceMapOptions):Promise<unknown>}
export interface ReconCollectorOptions {
  classify:ScopeClassifier;
  limits?:Partial<ReconLimits>;
  /** Extra credential screen applied to each new item and provenance label. */
  secretFilter?:SecretFilter;
  /** Receives every parsed source map passed to addSourceMap. */
  rebuilder?:MapSink;
  /** Clock for `generatedAt` (tests). */
  now?:()=>Date;
}
/** Bare host literals from script strings are listed only when they belong to the scanned site: in scope, or the same registrable domain outside the mode. */
const SAME_SITE_REASONS=new Set(['exact-origin-mode','outside-host-subtree']);
const GRAPHQL_PATH=/graphi?ql|(?:^|[/_.-])gql(?:$|[/_.-])/i;
const JS_PATH=/\.(?:m|c)?js$/i,MAP_PATH=/\.map$/i;
/** JS and source-map lists name files: query names are dropped there (they stay in urls). */
const bare=(u:string)=>u.replace(/\?.*$/,'');
const compare=(a:string,b:string)=>a<b?-1:a>b?1:0;
const SCOPE_RANK:Record<HostScope,number>={'in-scope':2,'third-party':1,'out-of-scope':0};
/**
 * Adapter from the scanner's ScopePolicy to a recon scope function. Protected (government, military, …) hosts are always out of scope;
 * explicit seeds, explicit related origins and in-domain origins are in scope; other registrable domains are third-party; everything else
 * (exact-origin mode, outside the host subtree, no public suffix, IP literal, …) is out of scope with the policy's reason.
 */
export function scopeFromPolicy(policy:{classify(raw:string):ScopeDecision}):ScopeClassifier{
  return url=>{
    if(protectedHost(url))return {scope:'out-of-scope',reason:'protected-host'};
    const d=policy.classify(url);
    if(d.class!=='outside')return {scope:'in-scope',reason:d.class};
    if(d.reason==='third-party')return {scope:'third-party',reason:'third-party'};
    return {scope:'out-of-scope',reason:d.reason||'outside'};
  };
}
const emptyDropped=():DroppedCounts=>({'over-limit':0,'too-long':0,secret:0});
export class ReconCollector {
  readonly limits:ReconLimits;
  private lists=Object.fromEntries(LIST_NAMES.map(n=>[n,new Map<string,ReconItem>()])) as Record<ListName,Map<string,ReconItem>>;
  private dropped=Object.fromEntries(LIST_NAMES.map(n=>[n,emptyDropped()])) as Record<ListName,DroppedCounts>;
  private origins=new Map<string,ScopeVerdict>();
  private resources={seen:0,scanned:0,skipped:0,truncated:0,maps:0};
  private redactions=0;private inline=0;
  constructor(private options:ReconCollectorOptions){
    const limits={...DEFAULT_RECON_LIMITS};
    for(const [k,v] of Object.entries(options.limits||{}))if(Number.isInteger(v)&&(v as number)>0)(limits as any)[k]=v;
    this.limits=limits;
  }
  /** Feed one resource. Synchronous, bounded by the limits, never throws. */
  add(resource:ReconResource):void{
    try{this.addResource(resource);}catch{this.resources.skipped++;}
  }
  /**
   * Record a parsed (flat or sectioned) source map and pass it to the rebuilder. Never throws; never fetches.
   * A map file URL is listed in `sourcemaps`; an inline map (`data:` URL, or `{inline:true}` with the URL of the resource that embedded it)
   * is not listed, and is not counted again here: `inlineSourceMaps` counts the `sourceMappingURL=data:` comments seen by add().
   */
  async addSourceMap(mapUrl:string,map:unknown,options:SourceMapOptions={}):Promise<void>{
    const inline=options.inline===true||/^data:/i.test(String(mapUrl||''));
    try{if(!inline){const c=cleanUrl(mapUrl,undefined,this.limits.maxUrlLength);if(c){const source=this.label(mapUrl);this.takeUrl(c,source);this.put('sourcemaps',bare(c.url),source);}}}catch{}
    if(this.options.rebuilder)try{await this.options.rebuilder.add(mapUrl,map,options.inline===true?{inline:true}:undefined);}catch{}
  }
  private label(url:string){
    const c=cleanUrl(url,undefined,this.limits.maxUrlLength),s=c?c.url:cleanLabel(url,this.limits.maxUrlLength);
    return this.flagged(s)?REDACTED:s;
  }
  private flagged(value:string){
    if(containsKnownSecret(value))return true;
    try{return this.options.secretFilter?.(value)===true;}catch{return true;}
  }
  private addResource(r:ReconResource){
    this.resources.seen++;
    const url=String(r.url||''),text=typeof r.text==='string'?r.text:'',source=this.label(url);
    const mode=reconMode(String(r.kind||''),String(r.contentType||''),url,text);
    const self=cleanUrl(url,undefined,this.limits.maxUrlLength);
    if(self){this.takeUrl(self,source);if(mode==='js'&&!/^data:/i.test(url))this.put('js',bare(self.url),source);}
    for(const [name,value] of Object.entries(r.headers||{}))if(/^(?:x-)?sourcemap$/i.test(name)&&typeof value==='string')this.sink(source).sourceMap(value,url);
    if(mode==='skip'){this.resources.skipped++;return;}
    if(mode==='map'){this.resources.maps++;if(self)this.put('sourcemaps',bare(self.url),source);return;}
    let body=text;if(body.length>this.limits.maxTextChars){body=body.slice(0,this.limits.maxTextChars);this.resources.truncated++;}
    this.resources.scanned++;
    extractRecon(body,url,mode,this.sink(source),this.limits.maxMatchesPerPattern);
  }
  private sink(source:string):ExtractSink{
    const L=this.limits;
    const tooLongUrl=(raw:string)=>{if(raw.length>L.maxUrlLength)this.dropped.urls['too-long']++;};
    return {
      url:(raw,base,callSite)=>{if(/^data:/i.test(raw))return;const c=cleanUrl(raw,base,L.maxUrlLength);if(!c)return tooLongUrl(raw);this.takeUrl(c,source);if(callSite&&c.pathname!=='/'&&this.verdict(new URL(c.url).origin.replace(/^ws(s?):/,'http$1:')).scope==='in-scope')this.put('endpoints',c.pathname,source);if(JS_PATH.test(c.pathname))this.put('js',bare(c.url),source);if(MAP_PATH.test(c.pathname))this.put('sourcemaps',bare(c.url),source);},
      endpoint:raw=>{const c=cleanEndpoint(raw,L.maxEndpointLength);if(!c){if(raw.length>L.maxEndpointLength)this.dropped.endpoints['too-long']++;return;}this.redactions+=c.redactions;for(const p of c.params)this.param(p,source);if(c.path){this.put('endpoints',c.path,source);if(GRAPHQL_PATH.test(c.path))this.graphql('endpoint',c.path,source);}},
      param:name=>this.param(name,source),
      graphql:(type,name)=>this.graphql(type,name,source),
      hostLiteral:raw=>{const host=hostLiteral(raw);if(!host||host.length>L.maxHostLength)return;const v=this.verdict('https://'+host);if(v.scope==='in-scope'||SAME_SITE_REASONS.has(v.reason||''))this.host(host,v,source);},
      script:(raw,base)=>{const c=cleanUrl(raw,base,L.maxUrlLength);if(!c)return tooLongUrl(raw);this.takeUrl(c,source);this.put('js',bare(c.url),source);},
      sourceMap:(raw,base)=>{if(/^data:/i.test(raw)){this.inline++;return;}const c=cleanUrl(raw,base,L.maxUrlLength);if(!c)return tooLongUrl(raw);this.takeUrl(c,source);this.put('sourcemaps',bare(c.url),source);}
    };
  }
  /** A cleaned URL: listed under urls, its host classified, its parameter names listed, GraphQL endpoints noted. */
  private takeUrl(c:CleanUrl,source:string){
    this.redactions+=c.redactions;
    this.put('urls',c.url,source);
    for(const p of c.params)this.param(p,source);
    if(c.host.length<=this.limits.maxHostLength){const origin=new URL(c.url).origin.replace(/^ws(s?):/,'http$1:');this.host(c.host,this.verdict(origin),source);}
    else this.dropped.hosts['too-long']++;
    if(GRAPHQL_PATH.test(c.pathname))this.graphql('endpoint',c.url,source);
  }
  private verdict(origin:string):ScopeVerdict{
    const key=origin.toLowerCase(),known=this.origins.get(key);if(known)return known;
    let v:ScopeVerdict;
    try{const r=this.options.classify(origin+'/');v=typeof r==='string'?{scope:r}:{scope:r.scope,reason:r.reason};if(!(v.scope in SCOPE_RANK))v={scope:'out-of-scope',reason:'classifier-error'};}catch{v={scope:'out-of-scope',reason:'classifier-error'};}
    if(this.origins.size>=this.limits.maxItemsPerList)this.origins.clear();
    this.origins.set(key,v);return v;
  }
  /** One host, possibly reached over several origins: the most permissive verdict wins (in-scope over third-party over out-of-scope). */
  private host(host:string,v:ScopeVerdict,source:string){
    const existing=this.lists.hosts.get(host);
    if(existing){if(SCOPE_RANK[v.scope]>SCOPE_RANK[existing.scope!]){existing.scope=v.scope;existing.reason=v.reason;if(v.reason===undefined)delete existing.reason;}return;}
    this.put('hosts',host,source,v.reason===undefined?{scope:v.scope}:{scope:v.scope,reason:v.reason});
  }
  private param(name:string,source:string){
    if(name.length>this.limits.maxNameLength){this.dropped.parameters['too-long']++;return;}
    if(validParameterName(name,this.limits.maxNameLength))this.put('parameters',name,source);
  }
  private graphql(type:GraphqlType|'endpoint',name:string,source:string){
    if(type!=='endpoint'&&!validParameterName(name,this.limits.maxNameLength))return;
    this.put('graphql',type+' '+name,source,type==='endpoint'?{type}:{type,name});
  }
  private put(list:ListName,value:string,source:string,extra?:Partial<ReconItem>){
    const items=this.lists[list];if(items.has(value))return;
    const max=list==='urls'||list==='js'||list==='sourcemaps'?this.limits.maxUrlLength:list==='endpoints'?this.limits.maxEndpointLength:list==='hosts'?this.limits.maxHostLength:list==='parameters'?this.limits.maxNameLength:this.limits.maxUrlLength+16;
    if(value.length>max){this.dropped[list]['too-long']++;return;}
    if(!value||/[\u0000-\u001f\u007f\u2028\u2029]/.test(value))return; // one item per line: never a line break
    if(this.flagged(value)){this.dropped[list].secret++;return;}
    if(items.size>=this.limits.maxItemsPerList){this.dropped[list]['over-limit']++;return;}
    items.set(value,{value,source,...extra});
  }
  /** Snapshot of all lists, each sorted by value (code-unit order). */
  result():ReconResult{
    const lists={} as Record<ListName,ReconItem[]>,counts={} as Record<ListName,number>,dropped={} as Record<ListName,DroppedCounts>;
    for(const name of LIST_NAMES){lists[name]=[...this.lists[name].values()].map(i=>({...i})).sort((a,b)=>compare(a.value,b.value));counts[name]=lists[name].length;dropped[name]={...this.dropped[name]};}
    return {schema:'exposure-recon/1',generatedAt:(this.options.now?.()||new Date()).toISOString(),resources:{...this.resources},limits:{...this.limits},counts,dropped,redactions:this.redactions,inlineSourceMaps:this.inline,lists};
  }
}
