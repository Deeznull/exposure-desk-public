/**
 * Recon extraction: static, linear-time pattern passes over one resource's text. Nothing is parsed into an AST, evaluated or fetched.
 * Every regular expression has bounded repetition, and every pass stops after `maxMatches`, so hostile input costs time proportional to its size.
 * Raw candidates go to a sink; the collector cleans them (src/recon/clean.ts) before anything is listed.
 */
import { EXPR } from './clean.js';
export type ReconMode='html'|'css'|'js'|'json'|'robots'|'sitemap'|'map'|'text'|'skip';
export type GraphqlType='query'|'mutation'|'subscription'|'operation';
export interface ExtractSink {
  /** An absolute URL, or a relative reference to resolve against `base`. `callSite` marks a URL passed to a request call or URL key: its path is also an endpoint when its host is in scope. */
  url(raw:string,base?:string,callSite?:boolean):void;
  /** A path or API route as written. */
  endpoint(raw:string):void;
  param(name:string):void;
  graphql(type:GraphqlType,name:string):void;
  hostLiteral(host:string):void;
  script(raw:string,base:string):void;
  sourceMap(raw:string,base:string):void;
}
const JS_KINDS=new Set(['script','module','source','runtime-capture','worker','framework-manifest']);
const MAP_KINDS=new Set(['map','map-guess','map-section']);
/** Which passes apply to one resource, from its scan kind, content type, URL and first bytes. */
export function reconMode(kind:string,contentType:string,url:string,text:string):ReconMode{
  const type=contentType.toLowerCase(),head=text.slice(0,512).trimStart();let path='';try{path=new URL(url).pathname.toLowerCase();}catch{}
  if(kind==='image'||/^(?:image|font|audio|video)\//.test(type)||text.slice(0,4096).includes('\u0000'))return 'skip';
  if(MAP_KINDS.has(kind)||/sourcemap/.test(type)||path.endsWith('.map')&&/^\{/.test(head)&&/"mappings"|"sections"/.test(text.slice(0,65536)))return 'map';
  if(kind==='robots'||path.endsWith('/robots.txt'))return 'robots';
  if(kind==='sitemap'||/^<\?xml[\s\S]{0,400}<(?:urlset|sitemapindex)\b/i.test(head)||/^<(?:urlset|sitemapindex)\b/i.test(head))return 'sitemap';
  if(/html|xhtml/.test(type)||kind==='page'||kind==='browser-page'||/^(?:<!doctype html|<html|<head|<body)/i.test(head))return 'html';
  if(/\/css/.test(type)||kind==='css'||path.endsWith('.css'))return 'css';
  if(JS_KINDS.has(kind)||/javascript|ecmascript|typescript|jsx/.test(type)||/\.(?:m|c)?jsx?$|\.tsx?$/.test(path))return 'js';
  if(/json/.test(type)||kind==='manifest'||kind==='config'||kind==='framework-data'||/^[{[]/.test(head))return 'json';
  return 'text';
}
const ABSOLUTE=/\b(?:https?|wss?):\/\/(?:\[[0-9A-Fa-f:.]{2,45}\])?[^\s"'`<>\\^|{}()[\]]{0,2048}/gi;
const PROTOCOL_RELATIVE=/(["'(=]\s{0,4})(\/\/(?:[A-Za-z0-9-]{1,63}\.){1,10}[A-Za-z]{2,63}(?::\d{1,5})?(?:\/[^\s"'`<>\\^|{}()[\]]{0,2048})?)/g;
const STRING=/"([^"\\\n]{0,2048})"|'([^'\\\n]{0,2048})'|`([^`\\]{0,2048})`/g;
const TEMPLATE_PART=/\$\{[^{}`]{0,200}\}/g;
const CALL=/\b(?:fetch|axios(?:\.(?:get|post|put|patch|delete|head|options|request))?|ajax|getJSON|sendBeacon|EventSource|WebSocket|Request|\$http(?:\.(?:get|post|put|patch|delete|head|jsonp))?|(?:http|api|client|request|superagent|ky|got|\$|app|router|server)\.(?:get|post|put|patch|delete|head|options|all|route))\s*\(\s*(["'`])([^"'`\\\n]{1,2048})\1/g;
const XHR=/\.open\(\s*["'](?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)["']\s*,\s*(["'`])([^"'`\\\n]{1,2048})\1/gi;
const URL_KEY=/\b(?:url|uri|endpoint|baseURL|baseUrl|apiUrl|apiURL|apiPath|apiEndpoint|action|path|route|redirectTo)["']?\s*[:=]\s*(["'`])([^"'`\\\n]{1,1024})\1/g;
const JSX_ROUTE=/<Route\b[^>]{0,500}?\bpath\s*=\s*\{?\s*["'`]([^"'`\n]{1,512})["'`]/g;
const MAP_COMMENT=/[#@][ \t]{0,8}sourceMappingURL[ \t]{0,8}=[ \t]{0,8}([^\s'"*]{1,4096})/g;
const GRAPHQL_OP=/\b(query|mutation|subscription)[ \t\r\n]{1,8}([_A-Za-z][_0-9A-Za-z]{0,127})[ \t\r\n]{0,8}(?=[({@])/g;
const GRAPHQL_NAME=/\boperationName["']?\s*[:=]\s*["']([_A-Za-z][_0-9A-Za-z]{0,127})["']/g;
const PARAM_CALL=/\b([A-Za-z_$][\w$]{0,63})\.(?:append|set|get|getAll|has)\(\s*["']([^"'\n]{1,128})["']/g;
const PARAM_OBJECT=/(?:new\s+URLSearchParams|JSON\.stringify|qs\.stringify|querystring\.stringify|stringify)\s*\(\s*\{([^{}]{0,2000})\}|\b(?:params|data|body|query|variables|form|searchParams)\s*:\s*\{([^{}]{0,2000})\}/g;
const OBJECT_KEY=/(?:^|[,{\s])["']?([A-Za-z_$][\w$-]{0,127})["']?\s*(?=[:,]|$)/g;
const QUERY_NAME=/[?&]([A-Za-z0-9_.\-[\]]{1,128})=/g;
const HTML_ATTR=/\b(?:href|src|action|formaction|data-src|data-href|data-url|poster|manifest)\s*=\s*(?:"([^"]{0,2048})"|'([^']{0,2048})'|([^\s"'<>`]{1,2048}))/gi;
const HTML_SCRIPT=/<script\b[^>]{0,2000}?\bsrc\s*=\s*(?:"([^"]{1,2048})"|'([^']{1,2048})'|([^\s"'<>`]{1,2048}))/gi;
const HTML_FIELD=/<(?:input|select|textarea|button)\b[^>]{0,2000}?\bname\s*=\s*(?:"([^"]{1,128})"|'([^']{1,128})'|([^\s"'<>`]{1,128}))/gi;
const HTML_FORM=/<form\b[^>]{0,2000}?\baction\s*=\s*(?:"([^"]{1,2048})"|'([^']{1,2048})'|([^\s"'<>`]{1,2048}))/gi;
const CSS_URL=/url\(\s{0,8}["']?([^"')\s]{1,2048})|@import\s{1,8}["']([^"']{1,2048})["']/gi;
const ROBOTS=/^[ \t]*(?:(dis)?allow)[ \t]*:[ \t]*(\S{1,1024})/gim;
const ROBOTS_SITEMAP=/^[ \t]*sitemap[ \t]*:[ \t]*(\S{1,2048})/gim;
const SITEMAP_LOC=/<loc>\s{0,8}([^<\s]{1,2048})\s{0,8}<\/loc>/gi;
/** XML and SVG namespace identifiers are names, not links. */
const NAMESPACE=/^https?:\/\/(?:www\.w3\.org|www\.sitemaps\.org|schemas\.xmlsoap\.org|schemas\.openxmlformats\.org|schemas\.microsoft\.com|ns\.adobe\.com|purl\.org|xmlns\.com)\//i;
const SVG_PATH=/^[MmLlHhVvCcSsQqTtAaZz][\d.,\s-]/;
const STATIC_ASSET=/\.(?:png|jpe?g|gif|webp|avif|svg|ico|bmp|tiff?|woff2?|ttf|otf|eot|css|mp[34]|webm|ogg|wav|flac|pdf)$/i;
const ROUTE_PATH=/^(?:\/|[A-Za-z0-9_\-:.{}*]+(?:\/[A-Za-z0-9_\-:.{}*]*)+$|:[A-Za-z_]\w*$|[A-Za-z][\w-]{1,63}\/?$)/;
const NOT_URL=/^(?:javascript|mailto|tel|sms|data|blob|about|chrome|chrome-extension|moz-extension|file):/i;
const PARAM_HOLDER=/param|search|query|form|body|data|qs|url/i;
function* matches(re:RegExp,text:string,max:number){re.lastIndex=0;let m:RegExpExecArray|null,n=0;while(n++<max&&(m=re.exec(text))){if(m[0]==='')re.lastIndex++;yield m;}}
const first=(m:RegExpExecArray,...groups:number[])=>{for(const g of groups)if(m[g]!==undefined)return m[g];return undefined;};
/** Unescape JSON/JS forward slashes so `https:\/\/host\/a` is seen as a URL; every other escape is left alone. */
const unescapeSlashes=(text:string)=>text.includes('\\')?text.replace(/\\u002[fF]|\\x2[fF]|\\\//g,'/'):text;
/** Inline script bodies of an HTML document, found with indexOf so an unterminated tag costs one linear pass. */
export function inlineScripts(html:string,maxScripts=1000):string[]{
  const out:string[]=[],lower=html.toLowerCase();let at=0;
  while(out.length<maxScripts){const open=lower.indexOf('<script',at);if(open<0)break;const gt=lower.indexOf('>',open);if(gt<0)break;const close=lower.indexOf('</script',gt);const body=html.slice(gt+1,close<0?html.length:close);if(!/\bsrc\s*=/.test(lower.slice(open,gt))&&body.trim())out.push(body);if(close<0)break;at=close+8;}
  return out;
}
/** A route or path literal from a route-table, URL key or call site; SVG path data and prose are refused. */
function routeLike(value:string){return !/\s/.test(value)&&!SVG_PATH.test(value)&&ROUTE_PATH.test(value)&&!NOT_URL.test(value);}
function absoluteLike(value:string){return /^(?:https?|wss?):\/\//i.test(value)||value.startsWith('//');}
/** Script, JSON and inline-script passes. */
function scriptPasses(text:string,url:string,sink:ExtractSink,max:number){
  for(const m of matches(MAP_COMMENT,text,max))sink.sourceMap(m[1],url);
  for(const m of matches(STRING,text,max)){
    let value=first(m,1,2,3)!;if(!value||value.length<2)continue;
    if(m[3]!==undefined){value=value.replace(TEMPLATE_PART,EXPR);if(value.includes('${'))continue;}
    value=unescapeSlashes(value);
    if(value.startsWith(EXPR+'/'))value=value.slice(EXPR.length);
    if(absoluteLike(value)){if(value.includes(EXPR))sink.url(value);continue;} // template URLs; plain absolute URLs are taken by the whole-text pass
    if(value.startsWith('/')&&!value.startsWith('//')){if(!/\s/.test(value)&&!STATIC_ASSET.test(value.replace(/[?#].*$/,''))&&!/^\/[*/]|^\/\^|[*]\/$/.test(value))sink.endpoint(value);}
    else if(/^[?&][A-Za-z0-9_.\-[\]]{1,128}=/.test(value)){for(const q of matches(QUERY_NAME,value,64))sink.param(q[1]);}
    else{const host=/^[A-Za-z0-9.-]{4,253}$/.test(value)&&value.includes('.')?value:undefined;if(host)sink.hostLiteral(host);}
  }
  const call=(value:string)=>{value=unescapeSlashes(value.replace(TEMPLATE_PART,EXPR));if(value.startsWith(EXPR+'/'))value=value.slice(EXPR.length);if(value==='/')return;if(absoluteLike(value))sink.url(value,url,true);else if(routeLike(value.replace(/[?#].*$/,''))||value.startsWith('/'))sink.endpoint(value);};
  for(const m of matches(CALL,text,max))call(m[2]);
  for(const m of matches(XHR,text,max))call(m[2]);
  for(const m of matches(URL_KEY,text,max)){const v=m[2];if(absoluteLike(v)||routeLike(v.replace(/[?#].*$/,'')))call(v);}
  for(const m of matches(JSX_ROUTE,text,max))if(routeLike(m[1]))sink.endpoint(m[1]);
  for(const m of matches(GRAPHQL_OP,text,max))sink.graphql(m[1] as GraphqlType,m[2]);
  for(const m of matches(GRAPHQL_NAME,text,max))sink.graphql('operation',m[1]);
  for(const m of matches(PARAM_CALL,text,max))if(PARAM_HOLDER.test(m[1]))sink.param(m[2]);
  for(const m of matches(PARAM_OBJECT,text,max)){const body=first(m,1,2)||'';for(const k of matches(OBJECT_KEY,body,256))sink.param(k[1]);}
}
/**
 * Run the passes that apply to `mode` over `text` (already capped by the caller), resolving relative references against `url`.
 * `maxMatches` bounds each pattern's iterations for this one resource.
 */
export function extractRecon(text:string,url:string,mode:ReconMode,sink:ExtractSink,maxMatches=50000){
  if(mode==='skip'||mode==='map')return;
  const slashed=unescapeSlashes(text);
  for(const m of matches(ABSOLUTE,slashed,maxMatches))if(!NAMESPACE.test(m[0]))sink.url(m[0].replace(/[.,;:!?$*]+$/,''));
  for(const m of matches(PROTOCOL_RELATIVE,slashed,maxMatches))sink.url(m[2].replace(/[.,;:!?$*]+$/,''),url);
  if(mode==='robots'){
    for(const m of matches(ROBOTS,text,maxMatches)){const path=m[2].replace(/\$$/,'');if(path.startsWith('/')&&path!=='/')sink.endpoint(path);}
    for(const m of matches(ROBOTS_SITEMAP,text,maxMatches))sink.url(m[1],url);
    return;
  }
  if(mode==='sitemap'){for(const m of matches(SITEMAP_LOC,text,maxMatches))sink.url(m[1],url);return;}
  if(mode==='css'){for(const m of matches(CSS_URL,text,maxMatches)){const raw=first(m,1,2)!;if(!NOT_URL.test(raw)&&!raw.startsWith('#'))sink.url(raw,url);}for(const m of matches(MAP_COMMENT,text,maxMatches))sink.sourceMap(m[1],url);return;}
  if(mode==='html'){
    for(const m of matches(HTML_ATTR,text,maxMatches)){const raw=first(m,1,2,3)!.trim();if(raw&&!NOT_URL.test(raw)&&!raw.startsWith('#')&&!raw.startsWith('{'))sink.url(raw,url);}
    for(const m of matches(HTML_SCRIPT,text,maxMatches)){const raw=first(m,1,2,3)!.trim();if(raw&&!NOT_URL.test(raw))sink.script(raw,url);}
    for(const m of matches(HTML_FORM,text,maxMatches)){const raw=first(m,1,2,3)!.trim();if(raw&&!NOT_URL.test(raw)&&!raw.startsWith('#')){let path='';try{path=new URL(raw,url).pathname;}catch{}if(path&&path!=='/')sink.endpoint(path);}}
    for(const m of matches(HTML_FIELD,text,maxMatches))sink.param(first(m,1,2,3)!);
    for(const m of matches(CSS_URL,text,maxMatches)){const raw=first(m,1,2)!;if(!NOT_URL.test(raw)&&!raw.startsWith('#'))sink.url(raw,url);}
    for(const body of inlineScripts(text))scriptPasses(body,url,sink,maxMatches);
    return;
  }
  if(mode==='js'||mode==='json')scriptPasses(text,url,sink,maxMatches);
}
