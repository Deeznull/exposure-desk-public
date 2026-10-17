import type {Resource,WorkItem} from './types.js';
export type WorkClass='entryPages'|'javascript'|'sourceMaps'|'configuration'|'discovery'|'optionalPages'|'baseline'|'deployment'|'other'|'lowValue';
export type ResourceType='page'|'javascript'|'source-map'|'sitemap'|'configuration'|'image'|'baseline'|'deployment'|'runtime-capture'|'other';
export function resourceType(r:Pick<Resource,'url'|'kind'|'contentType'> & Partial<Resource>):ResourceType{
 if(r.resourceType)return r.resourceType;
 if(r.kind==='sitemap')return 'sitemap';
 if(['map','map-guess','map-section'].includes(r.kind))return 'source-map';
 if(r.kind==='baseline')return 'baseline';if(r.kind==='deep')return 'deployment';
 if(r.kind==='runtime-capture')return 'runtime-capture';if(r.kind==='image')return 'image';
 let pathname='';try{pathname=new URL(r.url).pathname;}catch{}
 if(/\.map$/i.test(pathname))return 'source-map';
 if(['script','module','source'].includes(r.kind)||/\.[cm]?js$/i.test(pathname)||/javascript|ecmascript/i.test(r.contentType||'')||r.provenance?.resourceType==='script')return 'javascript';
 if(['config','manifest','framework-data'].includes(r.kind)||/json|yaml/i.test(r.contentType||'')||/\.(?:json|env|config)$/i.test(pathname))return 'configuration';
 if(r.kind==='page'||/html/i.test(r.contentType||'')||r.provenance?.resourceType==='document')return 'page';return 'other';
}
export function workClass(w:Pick<WorkItem,'url'|'kind'>,entries:string[]=[]):WorkClass{if(entries.includes(w.url))return 'entryPages';const t=resourceType(w);let path='';try{path=new URL(w.url).pathname;}catch{}if(t==='image'||/\.(?:zip|tar|gz|rar|7z|woff2?|ttf|otf|png|jpe?g|gif|webp|avif|ico)$/i.test(path))return 'lowValue';return t==='javascript'?'javascript':t==='source-map'?'sourceMaps':t==='configuration'?'configuration':t==='sitemap'||w.kind==='robots'?'discovery':t==='page'?'optionalPages':t==='baseline'?'baseline':t==='deployment'?'deployment':'other';}
export function imageRendition(raw:string):{family:string;source:string}|undefined{try{const u=new URL(raw);if(u.pathname!=='/_next/image'||[...u.searchParams.keys()].some(k=>!['url','w','q'].includes(k))||['url','w','q'].some(k=>u.searchParams.getAll(k).length>1))return;const source=u.searchParams.get('url');if(!source||!/^\d{1,5}$/.test(u.searchParams.get('w')||'')||u.searchParams.has('q')&&!/^\d{1,3}$/.test(u.searchParams.get('q')!))return;if(Number(u.searchParams.get('w'))<1||u.searchParams.has('q')&&(Number(u.searchParams.get('q'))<1||Number(u.searchParams.get('q'))>100))return;const s=new URL(source,u);if(!['http:','https:'].includes(s.protocol)||s.username||s.password||/sig|token|key|credential|signature/i.test(s.search))return;return {family:u.origin+u.pathname+'|'+s.href,source:s.href};}catch{return;}}
