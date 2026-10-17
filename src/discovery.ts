import * as cheerio from 'cheerio';
import { parse, tokenizer } from 'acorn';
import { createHash } from 'node:crypto';
export type Certainty='confirmed'|'contextual'|'heuristic'|'unresolved';
export interface Reference {raw:string;base:string;kind:string;context:string;unresolved?:boolean;certainty?:Certainty;sink?:string;method?:string;acquire?:boolean}
/** Base roles let one extraction be resolved under another URL, document or import map without re-parsing; `absolute:` bases are kept verbatim. */
export interface ExtractedReference {raw:string;role:string;kind:string;context:string;unresolved?:boolean;certainty?:Certainty;sink?:string;method?:string;acquire?:boolean}
export interface Extraction {version:string;refs:ExtractedReference[];importMap:[string,string][];htmlBaseRaw?:string;manifestBaseRaw?:string}
export interface DiscoverySummary {rejected:{bareExtension:number;nonUrlContext:number;dottedIdentifier:number;glob:number;examples:string[]};syntax:Record<string,number>;sinks:Record<string,number>;referenceLimit:number}
export interface ReferenceOptions {tokensOnly?:boolean;summary?:DiscoverySummary;nodeBudget?:number;deadlineMs?:number}
export const DISCOVERY_VERSION='2.5.0';
/** Large texts that acorn rejected as both a module and a script, by sha256. acorn's parse is deterministic for one text and the fixed options below, so
 * a repeat of the same text (one broken bundle seen again by a later scan in the same process) goes straight to the token pass with an identical result,
 * instead of paying two failed full parses again. Only a SyntaxError from both modes is remembered, never a RangeError from stack depth; at most
 * UNPARSEABLE_MAX digests (about 40 KiB), oldest evicted first; memory only. */
const UNPARSEABLE_MIN_BYTES=64*1024,UNPARSEABLE_MAX=512,unparseable=new Set<string>();
export function rememberUnparseable(digest:string,moduleError:unknown,scriptError:unknown){
  if(!(moduleError instanceof SyntaxError&&scriptError instanceof SyntaxError)||unparseable.has(digest))return false;
  if(unparseable.size>=UNPARSEABLE_MAX)unparseable.delete(unparseable.values().next().value!);
  unparseable.add(digest);return true;
}
export const unparseableMemo={get size(){return unparseable.size;},has:(digest:string)=>unparseable.has(digest),clear:()=>unparseable.clear()};
/** The last path segment is only an extension (`/.json`, `/.woff`): a bare literal, never a URL hint. Explicit seeds and routes are never guarded. */
export function isBareExtensionPath(url:string){try{const p=new URL(url).pathname,last=p.slice(p.lastIndexOf('/')+1);return /^\.[A-Za-z0-9]{1,10}$/.test(last);}catch{return false;}}
const EXPR='{EXPR}';
const asset=(s:string)=>s.length<=2048&&!/^[#`]|[\s<>`{}]/.test(s)&&/\.(?:m?js|json|css|map|woff2?)(?:[?#]|$)/i.test(s);
const networkReference=(s:string)=>s.length<=2048&&/^(?:https?|wss?):\/\//i.test(s)&&!/[\s<>`{}]/.test(s);
const NAMESPACES=new Set(['http://www.w3.org/2000/svg','http://www.w3.org/1999/xlink','http://www.w3.org/1999/xhtml','http://www.w3.org/1998/Math/MathML','http://www.w3.org/XML/1998/namespace','http://www.w3.org/2000/xmlns/']);
const NON_URL_METHODS=new Set(['endsWith','startsWith','includes','indexOf','lastIndexOf','split','replace','replaceAll','match','test','hasOwnProperty','localeCompare','padEnd','padStart','trim']);
const COMPARISON=new Set(['==','===','!=','!==','in','<','>','<=','>=']);
/** Generic literal classifier for unconsumed string tokens and JSON values. Accepts heuristic hints; rejects bare extensions, non-URL contexts, dotted identifiers and globs with a counted reason. */
export function classifyLiteral(value:string,nonUrlContext=false):'accept'|'bareExtension'|'nonUrlContext'|'dottedIdentifier'|'glob'|'skip'{
  if(NAMESPACES.has(value))return 'skip';
  const looksLikeUrl=asset(value)||networkReference(value);if(!looksLikeUrl)return 'skip';
  if(nonUrlContext)return 'nonUrlContext';
  if(/^\*?\.(?:m?js|json|css|map|woff2?)(?:[?#].*)?$/i.test(value))return 'bareExtension';
  if(/[*{}]/.test(value.replace(/^https?:\/\//,'')))return 'glob';
  if(networkReference(value))return 'accept';
  if(value.includes('/')){const stem=value.slice(value.lastIndexOf('/')+1).replace(/[?#].*$/,'');return /^\.[A-Za-z0-9]{1,10}$/.test(stem)?'bareExtension':'accept';}
  const name=value.replace(/[?#].*$/,''),segments=name.split('.');
  if(segments.length>=3&&!/^(?:min|bundle|chunk|esm|cjs|umd|prod|dev|module|legacy|modern|worker|client|server|\d+|[0-9a-f]{6,}|[\w-]*[0-9a-f]{6,})$/i.test(segments[segments.length-2]))return 'dottedIdentifier';
  return 'accept';
}
/** Context-independent part of the cache key: the only URL facts the extractor consults. */
export function extractionContextKey(url:string){let next=false,vite=false;try{next=url.includes('/_next/');vite=/\/assets\/[^/]+$/.test(new URL(url).pathname);}catch{}return (next?'n':'-')+(vite?'v':'-');}
/** Static references only. No target expressions or bundler callbacks are evaluated. One parse per document (module, then script, then tokens only). The result is base-relative and reusable. */
export function extract(text:string,url:string,kind:string,options:ReferenceOptions={}):Extraction{
  const refs:ExtractedReference[]=[],importMap:[string,string][]=[],summary=options.summary,limit=5000;let overflow=false,htmlBaseRaw:string|undefined,manifestBaseRaw:string|undefined;
  const note=(name:string)=>{if(summary)summary.sinks[name]=(summary.sinks[name]||0)+1;};
  const syntax=(name:string)=>{if(summary)summary.syntax[name]=(summary.syntax[name]||0)+1;};
  const reject=(reason:'bareExtension'|'nonUrlContext'|'dottedIdentifier'|'glob',value:string)=>{if(!summary)return;summary.rejected[reason]++;if(summary.rejected.examples.length<8)summary.rejected.examples.push(value.slice(0,64));};
  const push=(raw:string,role:string,kind:string,context:string,extra:Partial<ExtractedReference>={})=>{if(!raw||raw.trim().startsWith('#'))return;if(refs.length>=limit){if(!overflow){overflow=true;if(summary)summary.referenceLimit++;}return;}refs.push({raw:raw.trim(),role,kind,context,...extra});};
  const embeddedUrls=(value:string,role:string)=>{for(const m of value.matchAll(/"((?:https?|wss?):(?:\\\/|\/){2}(?:\\.|[^"\\]){1,2048})"/g))try{const raw=JSON.parse('"'+m[1]+'"');if(networkReference(raw))push(raw,role,'asset','Serialized hydration/runtime URL',{certainty:'heuristic'});}catch{}};
  const scripts:{text:string;role:string}[]=[];
  const css=(code:string,role:string)=>{for(const m of code.matchAll(/(?:url\(\s*|@import\s+)["']?([^\s"')]+)["']?\s*\)?/g))push(m[1],role,'asset','CSS reference',{certainty:'confirmed'});};
  const html=kind==='page'||/text\/html/.test(kind)||/^\s*(?:<!doctype|<html)|<script[\s>]/i.test(text);
  if(html){syntax('html');const $=cheerio.load(text);const b=$('base[href]').first().attr('href');if(b){try{new URL(b,url);htmlBaseRaw=b;}catch{}}const role='html-base';
    $('[href], [src], [srcset], [data-src]').each((_,e)=>{const el=$(e),tag=e.tagName,raw=el.attr('src')||el.attr('href')||el.attr('data-src');if(raw&&!['base','form'].includes(tag))push(raw,role,tag==='a'?'page':tag==='script'?el.attr('type')==='module'?'module':'script':tag==='img'?'image':['iframe','frame'].includes(tag)?'page':el.attr('rel')==='sitemap'?'sitemap':el.attr('rel')==='manifest'?'manifest':el.attr('rel')==='canonical'?'page':'asset',['iframe','frame'].includes(tag)?'frame document':'document/base URL',{certainty:'confirmed'});for(const entry of (el.attr('srcset')||'').split(',').slice(0,10))if(entry.trim())push(entry.trim().split(/\s/)[0],role,'image','document srcset',{certainty:'confirmed'});});
    $('astro-island').each((_,e)=>{for(const attr of ['component-url','renderer-url']){const raw=$(e).attr(attr);if(raw)push(raw,role,'asset','Astro island '+attr,{certainty:'confirmed'});}});
    $('script[type="importmap"]').each((_,e)=>{try{const data=JSON.parse($(e).html()||'');for(const [name,value]of Object.entries(data.imports||{}).slice(0,500))if(typeof value==='string')importMap.push([name,value]);}catch{}});
    $('script[type*="json"]').each((_,e)=>{const inner=extract($(e).html()||'',url,'framework-data',options);for(const ref of inner.refs)refs.push({...ref,role:ref.role==='script'?role:ref.role,context:'Inline framework/hydration JSON'});});
    $('script').each((_,e)=>{const el=$(e);if(!el.attr('src')&&!/json/.test(el.attr('type')||''))scripts.push({text:el.html()||'',role});});
    $('style').each((_,e)=>css($(e).text(),role));$('[style]').each((_,e)=>css($(e).attr('style')||'',role));
    try{const data=JSON.parse($('#__NEXT_DATA__').text());if(typeof data.buildId==='string'&&/^[\w-]{1,100}$/.test(data.buildId))for(const file of ['_buildManifest.js','_ssgManifest.js'])push(`/_next/static/${data.buildId}/${file}`,role,'framework-manifest','Next hydration build ID',{certainty:'confirmed'});}catch{}
  }else if(/\.css(?:[?#]|$)/i.test(url)||kind==='css'){syntax('css');css(text,'script');}
  else if(!/^\s*[{[]/.test(text)||/\.m?js(?:[?#]|$)/i.test(url)||kind==='source'||kind==='runtime-capture')scripts.push({text,role:'script'});
  if(/^\s*[{[]/.test(text)){try{const j=JSON.parse(text);syntax('json');let nodes=0;let role='script';
    if(kind==='manifest'||/manifest[^/]*\.json/.test(new URL(url).pathname)){manifestBaseRaw=new URL(url).pathname.includes('/.vite/')?'../':'./';role='manifest-build';}
    const walk=(v:any,key='',depth=0)=>{if(++nodes>20000||depth>32)return;if(typeof v==='string'){const urlKey=/^(?:module|file|chunk|src|url|component|config|manifest|start_url|href|path|entry|imports?|css|assets?)$/i.test(key);if(urlKey&&/^(?:\.?\.?\/|https?:)/.test(v)){push(v,role,'asset','manifest/application JSON field '+key,{certainty:'confirmed'});note('manifest-field');return;}const verdict=classifyLiteral(v);if(verdict==='accept')push(v,role,'asset','manifest/application JSON field '+key,{certainty:urlKey?'confirmed':'heuristic'});else if(verdict!=='skip')reject(verdict,v);else embeddedUrls(v,role);}else if(Array.isArray(v))v.slice(0,1000).forEach(x=>walk(x,key,depth+1));else if(v&&typeof v==='object')Object.entries(v).slice(0,1000).forEach(([k,x])=>{if(!['sourcesContent','sources','mappings','paths','servers'].includes(k)||!j.openapi&&!j.swagger)walk(x,k,depth+1);});};walk(j);
  }catch{}}
  for(const code of scripts)extractScript(code.text,code.role,url,push,note,syntax,reject,embeddedUrls,options);
  if(/\.css(?:[?#]|$)/i.test(url))for(const m of text.matchAll(/[#@]\s*sourceMappingURL\s*=\s*([^\s*]+)/g))push(m[1],'script','map','CSS source-map comment',{certainty:'confirmed'});
  // RSC/hydration streams can contain JSON strings without being a JSON document.
  if(kind==='framework-data'||/text\/x-component/.test(kind))embeddedUrls(text,'script');
  return {version:DISCOVERY_VERSION,refs,importMap,htmlBaseRaw,manifestBaseRaw};
}
/** Resolve a (possibly cached) extraction under the current URL, document and import map; import-map entries are replayed into `imports`. */
export function resolve(x:Extraction,ctx:{url:string;documentUrl:string;imports:Record<string,string>}):Reference[]{
  const safe=(base:string,relative:string)=>{try{return new URL(relative,base).href;}catch{return base;}};
  const htmlBase=x.htmlBaseRaw?safe(ctx.url,x.htmlBaseRaw):ctx.url,roots:Record<string,string>={script:ctx.url,document:ctx.documentUrl,'html-base':htmlBase,'vite-root':safe(ctx.url,'../'),'next-root':safe(ctx.url,'/_next/'),'manifest-build':safe(ctx.url,x.manifestBaseRaw||'./')};
  const out:Reference[]=[];
  for(const [name,value]of x.importMap){const target=safe(htmlBase,value);ctx.imports[name]=target;out.push({raw:value,base:htmlBase,kind:'module',context:'Import map entry',certainty:'confirmed'});}
  for(const ref of x.refs){const {role,...rest}=ref;
    if(role==='bare-import'){if(ctx.imports[ref.raw])out.push({...rest,raw:ctx.imports[ref.raw],base:ctx.url,context:'Import map resolved module',certainty:'confirmed',sink:'import'});else out.push({...rest,base:ctx.url,context:'Unresolved bare module specifier; no guessed URL',unresolved:true,certainty:'unresolved',sink:'import'});continue;}
    out.push({...rest,base:roots[role]??(role.startsWith('absolute:')?role.slice(9):ctx.url)});}
  return out;
}
export function references(text:string,url:string,kind:string,documentUrl=url,imports:Record<string,string>={},options:ReferenceOptions={}):Reference[]{return resolve(extract(text,url,kind,options),{url,documentUrl,imports});}
type Push=(raw:string,role:string,kind:string,context:string,extra?:Partial<ExtractedReference>)=>void;
/** Syntax-aware URL-use extraction (jsluice-style): recognized sinks carry their base role, method and certainty; concatenations fold literal parts and keep `{EXPR}` for unresolved parts. Nothing is evaluated. */
function extractScript(text:string,scriptRole:string,url:string,push:Push,note:(n:string)=>void,syntax:(n:string)=>void,reject:(r:'bareExtension'|'nonUrlContext'|'dottedIdentifier'|'glob',v:string)=>void,embeddedUrls:(v:string,role:string)=>void,options:ReferenceOptions){
  const used=new Set<number>(),nonUrl=new Set<number>(),viteRanges:{start:number;end:number}[]=[],tokens:{start:number;end:number;value:string}[]=[],maps:string[]=[];
  const nextLike=url.includes('/_next/');let viteAssets=false;try{viteAssets=/\/assets\/[^/]+$/.test(new URL(url).pathname);}catch{}
  const onComment=(_b:boolean,value:string)=>{const m=/^[#@]\s*sourceMappingURL\s*=\s*(\S+)/.exec(value.trim());if(m)maps.push(m[1]);};
  const onToken=(t:any)=>{if(t.type?.label==='string'&&typeof t.value==='string')tokens.push({start:t.start,end:t.end,value:t.value});};
  let ast:any,mode='tokens';
  if(!options.tokensOnly){
    const digest=text.length>=UNPARSEABLE_MIN_BYTES?createHash('sha256').update(text).digest('hex'):undefined;
    if(!digest||!unparseable.has(digest)){let moduleError:unknown,scriptError:unknown;
      try{ast=parse(text,{ecmaVersion:'latest',sourceType:'module',allowReturnOutsideFunction:true,allowHashBang:true,allowAwaitOutsideFunction:true,onToken,onComment});mode='module';}
      catch(e){moduleError=e;tokens.length=0;maps.length=0;try{ast=parse(text,{ecmaVersion:'latest',sourceType:'script',allowReturnOutsideFunction:true,allowHashBang:true,allowImportExportEverywhere:true,onToken,onComment});mode='script';}catch(e2){scriptError=e2;ast=undefined;tokens.length=0;maps.length=0;}}
      if(digest&&!ast)rememberUnparseable(digest,moduleError,scriptError);}
  }
  if(!ast){try{const lexer=tokenizer(text,{ecmaVersion:'latest',onComment});while(true){const t:any=lexer.getToken();if(t.type.label==='eof')break;if(t.type.label==='string'&&typeof t.value==='string')tokens.push({start:t.start,end:t.end,value:t.value});}}catch{ /* Syntactically unsupported code keeps the tokens read so far. */ }}
  syntax(mode);
  const literal=(n:any)=>n?.type==='Literal'&&typeof n.value==='string'?n.value:n?.type==='TemplateLiteral'&&n.expressions.length===0?n.quasis[0].value.cooked:undefined;
  const name=(n:any):string|undefined=>n?.type==='Identifier'?n.name:n?.type==='MemberExpression'&&!n.computed?name(n.object)+'.'+n.property?.name:n?.type==='MemberExpression'&&n.computed&&typeof literal(n.property)==='string'?name(n.object)+'.'+literal(n.property):n?.type==='ThisExpression'?'this':n?.type==='MetaProperty'?n.meta?.name+'.'+n.property?.name:undefined;
  const isMetaUrl=(n:any)=>n?.type==='MemberExpression'&&n.object?.type==='MetaProperty'&&n.property?.name==='url';
  // Fold literal concatenations and templates; alternatives (?:, ||, ??) yield up to 4 literal values; unknown parts become {EXPR}.
  const fold=(n:any,depth=0):string[]=>{if(!n||depth>32)return [EXPR];const v=literal(n);if(v!==undefined){used.add(n.start);return [v];}
    if(n.type==='TemplateLiteral'){used.add(n.start);let values=[''];for(let i=0;i<n.quasis.length;i++){const q=n.quasis[i].value.cooked??n.quasis[i].value.raw;values=values.map(x=>x+q);if(i<n.expressions.length){const parts=fold(n.expressions[i],depth+1);values=values.flatMap(x=>parts.map(p=>x+p)).slice(0,4);}}return values;}
    if(n.type==='BinaryExpression'&&n.operator==='+'){const a=fold(n.left,depth+1),b=fold(n.right,depth+1);return a.flatMap(x=>b.map(y=>x+y)).slice(0,4);}
    if(n.type==='ConditionalExpression'){return [...fold(n.consequent,depth+1),...fold(n.alternate,depth+1)].slice(0,4);}
    if(n.type==='LogicalExpression'&&['||','??'].includes(n.operator))return [...fold(n.left,depth+1),...fold(n.right,depth+1)].slice(0,4);
    if(n.type==='ParenthesizedExpression')return fold(n.expression,depth+1);
    return [EXPR];};
  const emit=(target:any,role:string,kind:string,context:string,sink:string,extra:{method?:string;contextual?:boolean;acquire?:boolean})=>{if(!target)return;const values=fold(target),direct=literal(target)!==undefined;note(sink);
    for(const value of values.slice(0,4)){if(!value||value.length>2048||/[\s<>`]/.test(value.replace(/\{EXPR\}/g,'')))continue;const unresolved=value.includes(EXPR);if(unresolved){if(!/[A-Za-z]/.test(value.replace(/\{EXPR\}/g,'')))continue;push(value,role,kind,context,{unresolved:true,certainty:'unresolved',sink,method:extra.method,acquire:false});continue;}
      const method=(extra.method||'GET').toUpperCase(),readable=['GET','HEAD'].includes(method),acquire=extra.acquire??(readable&&(networkReference(value)||asset(value)||kind==='page'||kind==='module'||kind==='websocket'));
      push(value,role,acquire?kind:kind==='page'?'page':'endpoint',context,{certainty:direct&&!extra.contextual?'confirmed':'contextual',sink,method:extra.method,acquire});}};
  if(ast){
    const budget=options.nodeBudget??3000000,deadline=Date.now()+(options.deadlineMs??1500);let visited=0,exhausted=false;const stack:any[]=[ast];
    while(stack.length){const n=stack.pop();if(!n||typeof n!=='object'||typeof n.type!=='string')continue;if(++visited>budget||(visited&4095)===0&&Date.now()>deadline){exhausted=true;break;}
      switch(n.type){
        case 'Property':if(n.key?.type==='Literal'||n.computed)nonUrl.add(n.key.start);break;
        case 'MemberExpression':if(n.computed&&n.property?.type==='Literal')nonUrl.add(n.property.start);break;
        case 'BinaryExpression':if(COMPARISON.has(n.operator)){if(n.left?.type==='Literal')nonUrl.add(n.left.start);if(n.right?.type==='Literal')nonUrl.add(n.right.start);}break;
        case 'SwitchCase':if(n.test?.type==='Literal')nonUrl.add(n.test.start);break;
        case 'TemplateLiteral':if(!used.has(n.start)&&n.expressions.length===0&&networkReference(literal(n)||'')){push(literal(n)!,scriptRole,'asset','Static runtime URL template',{certainty:'heuristic'});used.add(n.start);}break;
        case 'FunctionDeclaration':case 'VariableDeclarator':if(n.id?.name==='__vite__mapDeps')viteRanges.push({start:n.start,end:n.end});break;
        case 'ImportDeclaration':case 'ExportNamedDeclaration':case 'ExportAllDeclaration':case 'ImportExpression':{const v=literal(n.source);if(v!==undefined){used.add(n.source.start);note('import');if(/^(?:\.?\.?\/|https?:\/\/)/.test(v))push(v,scriptRole,'module','importing module',{certainty:'confirmed',sink:'import'});else push(v,'bare-import','module','Bare module specifier',{sink:'import'});}else if(n.type==='ImportExpression'&&n.source){emit(n.source,scriptRole,'module','Dynamic import with a computed specifier','import',{});}break;}
        case 'NewExpression':{const callee=name(n.callee)||'';
          if(callee==='URL'&&n.arguments.length>=2){const inner=n.arguments[0];if(isMetaUrl(n.arguments[1])){emit(inner,scriptRole,'asset','URL relative to import.meta.url','import-meta-url',{});}else if(/^(?:location\.href|document\.baseURI|location\.origin|window\.location\.href|window\.location\.origin|self\.location\.href|self\.location\.origin)$/.test(name(n.arguments[1])||''))emit(inner,'document','asset','URL relative to the document','new-url',{contextual:true});}
          else if(/^(?:Shared)?Worker$/.test(callee)){const arg=n.arguments[0];if(arg?.type==='NewExpression'&&name(arg.callee)==='URL'&&isMetaUrl(arg.arguments?.[1]))emit(arg.arguments[0],scriptRole,'asset','worker URL relative to import.meta.url','worker',{});else emit(arg,'document','asset','worker document base','worker',{});}
          else if(callee==='WebSocket'){emit(n.arguments[0],'document','websocket','WebSocket construction','websocket',{acquire:true});}
          else if(callee==='EventSource'){emit(n.arguments[0],'document','endpoint','EventSource construction','event-source',{acquire:false});}
          else if(callee==='Request'){emit(n.arguments[0],'document','asset','Request construction','fetch',{method:initMethod(n.arguments[1],literal)});}
          break;}
        case 'CallExpression':{const callee=name(n.callee)||'',prop=n.callee?.type==='MemberExpression'&&!n.callee.computed?n.callee.property?.name:undefined;
          if(/^(?:fetch|window\.fetch|globalThis\.fetch|self\.fetch)$/.test(callee)){emit(n.arguments[0],'document','asset','fetch call','fetch',{method:initMethod(n.arguments[1],literal)});}
          else if(/(?:^|\.)serviceWorker\.register$/.test(callee))emit(n.arguments[0],'document','asset','service worker registration','service-worker',{});
          else if(/^(?:importScripts|self\.importScripts)$/.test(callee))for(const a of n.arguments)emit(a,scriptRole,'asset','importScripts','import-scripts',{});
          else if(prop==='open'&&n.arguments.length>=2&&typeof literal(n.arguments[0])==='string'&&/^[A-Z]{3,7}$/i.test(literal(n.arguments[0])!)){used.add(n.arguments[0].start);emit(n.arguments[1],'document','asset','XMLHttpRequest open','xhr',{method:literal(n.arguments[0])!.toUpperCase()});}
          else if(/^(?:axios|\$|jQuery|got|ky|superagent)\.(?:get|head)$/.test(callee)||/^\$\.getJSON$/.test(callee))emit(n.arguments[0],'document','asset',callee+' request','request',{method:callee.endsWith('.head')?'HEAD':'GET'});
          else if(/^(?:axios|\$|jQuery|got|ky|superagent)\.(?:post|put|patch|delete)$/.test(callee))emit(n.arguments[0],'document','endpoint',callee+' request','request',{method:callee.split('.').pop()!.toUpperCase(),acquire:false});
          else if(/^(?:axios|\$\.ajax|jQuery\.ajax)$/.test(callee)){const arg=n.arguments[0];if(arg?.type==='ObjectExpression'){const urlProp=arg.properties.find((p:any)=>p.type==='Property'&&(p.key?.name==='url'||literal(p.key)==='url')),methodProp=arg.properties.find((p:any)=>p.type==='Property'&&['method','type'].includes(p.key?.name||literal(p.key)||''));const method=methodProp?literal(methodProp.value):'GET';emit(urlProp?.value,'document','asset',callee+' options','request',{method:method?.toUpperCase()});}else emit(arg,'document','asset',callee+' call','request',{method:'GET'});}
          else if(/^navigator\.sendBeacon$/.test(callee))emit(n.arguments[0],'document','endpoint','sendBeacon','beacon',{method:'POST',acquire:false});
          else if(/^(?:window\.|self\.|document\.)?location\.(?:assign|replace)$/.test(callee))emit(n.arguments[0],'document','page','location navigation','location',{contextual:true});
          else if(/^(?:window\.)?open$/.test(callee))emit(n.arguments[0],'document','page','window.open navigation','window-open',{contextual:true});
          else if(prop==='setAttribute'&&n.arguments.length>=2&&['src','href','data-src'].includes(literal(n.arguments[0])||'')){used.add(n.arguments[0].start);emit(n.arguments[1],'document','asset','element attribute assignment','attribute',{contextual:true});}
          else if(prop&&NON_URL_METHODS.has(prop))for(const a of n.arguments)if(a?.type==='Literal')nonUrl.add(a.start);
          break;}
        case 'AssignmentExpression':{const target=name(n.left)||'';
          if(/^(?:window\.|self\.|document\.)?location(?:\.href)?$/.test(target))emit(n.right,'document','page','location assignment','location',{contextual:true});
          else if(/\.(?:src|href)$/.test(target)&&!/^(?:window\.|self\.|document\.)?location/.test(target))emit(n.right,'document','asset','element src/href assignment','attribute',{contextual:true});
          break;}
      }
      for(const k in n){if(k==='start'||k==='end'||k==='type'||k==='loc'||k==='range')continue;const v=n[k];if(Array.isArray(v)){for(let i=v.length-1;i>=0;i--)if(v[i]&&typeof v[i]==='object')stack.push(v[i]);}else if(v&&typeof v==='object'&&typeof v.type==='string')stack.push(v);}
    }
    if(exhausted)note('walker-budget');
  }
  for(const m of maps)push(m,scriptRole,'map','source-map comment',{certainty:'confirmed'});
  // Generic literal pass over unconsumed tokens: sink context was recorded first, so only genuinely contextless literals are classified.
  for(const t of tokens){if(used.has(t.start))continue;const verdict=classifyLiteral(t.value,nonUrl.has(t.start));
    if(verdict==='skip'){embeddedUrls(t.value,scriptRole);continue;}if(verdict!=='accept'){reject(verdict,t.value);continue;}
    let role=scriptRole,context='static bundle literal',refKind='asset-hint',certainty:Certainty='heuristic';
    if(t.value.startsWith('static/')&&nextLike){role='next-root';context='Next build base';refKind='asset';certainty='confirmed';note('next-manifest');}
    else if(viteRanges.some(r=>t.start>=r.start&&t.end<=r.end)&&t.value.startsWith('assets/')&&viteAssets){role='vite-root';context='Vite dependency table build base';refKind='asset';certainty='confirmed';note('vite-map-deps');}
    push(t.value,role,refKind,context,{certainty});
  }
  // Webpack chunk tables: the quadratic regex only runs on bounded windows around each `+"."+{` marker.
  for(const marker of ['+"."+{',"+'.'+{"]){let from=0;while((from=text.indexOf(marker,from))>=0){const slice=text.slice(Math.max(0,from-10240),Math.min(text.length,from+10240));for(const m of slice.matchAll(/([A-Za-z_$][\w$]*)\s*\+\s*["']\.["']\s*\+\s*(\{[^{}]{1,10000}\})\s*\[\s*\1\s*\]\s*\+\s*["']\.js["']/g)){const publicPath=/\.p\s*=\s*["']([^"']{0,200})["']/.exec(text.slice(0,Math.min(text.length,from+10240)))?.[1]||'';note('webpack-chunk-map');for(const item of m[2].matchAll(/(?:["']?(\d{1,8})["']?)\s*:\s*["']([\w-]{1,80})["']/g))push(publicPath+item[1]+'.'+item[2]+'.js','document','asset','Webpack public build base',{certainty:'confirmed',sink:'webpack-chunk-map'});}from+=marker.length;}}
}
function initMethod(init:any,literal:(n:any)=>string|undefined):string|undefined{if(init?.type!=='ObjectExpression')return undefined;const p=init.properties.find((p:any)=>p.type==='Property'&&(p.key?.name==='method'||literal(p.key)==='method'));const v=p?literal(p.value):undefined;return v?v.toUpperCase():undefined;}
