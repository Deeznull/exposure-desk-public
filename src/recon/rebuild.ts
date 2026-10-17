/**
 * Source-map rebuild: writes the original source tree from each map's `sources` + `sourcesContent` into a new, owner-only folder, plus
 * MANIFEST.json (path, sha256, bytes and source-map URL per file). Sources without embedded content are listed as not recoverable; they are
 * never fetched, and nothing in this module performs network I/O. Section maps are followed only when the section embeds its map.
 * Hostile maps are bounded by RebuildLimits and every path goes through sanitizeSourcePath, so nothing is written outside the folder.
 */
import { createHash } from 'node:crypto';
import { lstat, mkdir, realpath } from 'node:fs/promises';
import path from 'node:path';
import { cleanLabel, cleanUrl } from './clean.js';
import { prepareOutputDir, writeNew, type OutputOptions } from './files.js';
import { parseSourceMap, sanitizeSourcePath } from './sourcemap.js';
export interface RebuildLimits {
  maxFiles:number;maxTotalBytes:number;maxFileBytes:number;
  /** Sources read from one flat map; the rest are counted in the map summary. */
  maxSourcesPerMap:number;
  maxSectionDepth:number;maxSections:number;
  /** Entries kept in each of MANIFEST.json's notRecoverable and skipped lists; totals still count all. */
  maxListed:number;
  /** Characters of source-map text accepted by add(). */
  maxMapBytes:number;
  /** Source maps accepted. */
  maxMaps:number;
}
export const DEFAULT_REBUILD_LIMITS:Readonly<RebuildLimits>=Object.freeze({maxFiles:10000,maxTotalBytes:256*1024*1024,maxFileBytes:32*1024*1024,maxSourcesPerMap:50000,maxSectionDepth:4,maxSections:1000,maxListed:10000,maxMapBytes:64*1024*1024,maxMaps:1000});
export type NotRecoverableReason='no-sources-content'|'invalid-sources-content'|'section-url-not-fetched';
export type SkipReason='invalid-source-name'|'file-too-large'|'total-byte-limit'|'file-limit'|'write-failed'|'unsafe-directory';
export interface ManifestFile {path:string;sha256:string;bytes:number;sourceMap:string;source:string;alsoIn?:string[]}
export interface ManifestMap {sourceMap:string;sources:number;written:number;duplicates:number;notRecoverable:number;skipped:number;sourcesOverLimit:number;sections:number;error?:'invalid-map'|'map-too-large'|'section-depth-limit'|'section-limit'|'map-limit'}
export interface RebuildManifest {
  schema:'exposure-recon-sources/1';generatedAt:string;
  note:string;
  files:ManifestFile[];
  notRecoverable:{source:string;sourceMap:string;reason:NotRecoverableReason}[];
  skipped:{source:string;sourceMap:string;reason:SkipReason;path?:string}[];
  maps:ManifestMap[];
  totals:{maps:number;files:number;bytes:number;duplicates:number;notRecoverable:number;skipped:number;sourcesOverLimit:number};
  truncated:{notRecoverable:boolean;skipped:boolean;maps:boolean};
  limits:RebuildLimits;
}
export interface RebuildOptions extends Omit<OutputOptions,'requireEmpty'> {limits?:Partial<RebuildLimits>;now?:()=>Date}
const MANIFEST='MANIFEST.json';
const key=(p:string)=>p.normalize('NFC').toLowerCase();
/** Manifest label of a map: its cleaned URL; an inline map is named after the resource that embedded it (`inline:https://host/app.js`). */
const mapLabel=(url:string,inline=false)=>{if(/^data:/i.test(url))return 'data:(inline source map)';const u=cleanUrl(url)?.url||cleanLabel(url);return inline?'inline:'+u:u;};
/** `name~n.ext` (files) or `name~n` (folders). */
function bump(segment:string,n:number,file:boolean){const dot=file?segment.lastIndexOf('.'):-1;return dot>0?segment.slice(0,dot)+'~'+n+segment.slice(dot):segment+'~'+n;}
export class SourceRebuilder {
  readonly limits:RebuildLimits;
  private files=new Map<string,ManifestFile>();
  private dirs=new Set<string>();
  /** First-seen spelling of each folder, so `Src/a` and `src/b` share one folder on every file system. */
  private dirNames=new Map<string,string>();
  private madeDirs=new Map<string,Promise<void>>();
  private manifest:RebuildManifest;
  private queue:Promise<void>=Promise.resolve();
  private finished?:Promise<RebuildManifest>;
  private sections=0;
  private constructor(readonly dir:string,options:RebuildOptions){
    const limits={...DEFAULT_REBUILD_LIMITS};
    for(const [k,v] of Object.entries(options.limits||{}))if(Number.isInteger(v)&&(v as number)>0)(limits as any)[k]=v;
    this.limits=limits;
    this.manifest={schema:'exposure-recon-sources/1',generatedAt:(options.now?.()||new Date()).toISOString(),note:'Rebuilt only from sourcesContent embedded in public source maps. Sources without embedded content are listed as not recoverable and were never fetched. Files are verbatim public content and may contain credentials; this folder is owner-only.',files:[],notRecoverable:[],skipped:[],maps:[],totals:{maps:0,files:0,bytes:0,duplicates:0,notRecoverable:0,skipped:0,sourcesOverLimit:0},truncated:{notRecoverable:false,skipped:false,maps:false},limits};
    this.dirs.add('');
  }
  /** Prepare a new or empty folder (never a link; owner-only unless `protect:false`) and return a rebuilder writing into it. */
  static async create(dir:string,options:RebuildOptions={}){const real=await prepareOutputDir(dir,{requireEmpty:true,protect:options.protect});return new SourceRebuilder(real,options);}
  /** Rebuild from one source map (text or parsed object). Calls are serialized; never throws; never fetches. */
  add(mapUrl:string,map:unknown,options:{inline?:boolean}={}):Promise<void>{
    const run=this.queue.then(()=>this.finished?undefined:this.addMap(String(mapUrl||''),map,options.inline===true)).catch(()=>{});
    this.queue=run;return run;
  }
  /** Write MANIFEST.json after all queued maps; later calls return the same manifest. */
  finish():Promise<RebuildManifest>{
    if(!this.finished)this.finished=this.queue.then(async()=>{
      const m=this.manifest;m.files=[...this.files.values()].sort((a,b)=>a.path<b.path?-1:a.path>b.path?1:0);
      await writeNew(path.join(this.dir,MANIFEST),JSON.stringify(m,null,2)+'\n');return m;
    });
    return this.finished;
  }
  private listNotRecoverable(source:string,sourceMap:string,reason:NotRecoverableReason,summary?:ManifestMap){
    this.manifest.totals.notRecoverable++;if(summary)summary.notRecoverable++;
    if(this.manifest.notRecoverable.length<this.limits.maxListed)this.manifest.notRecoverable.push({source:cleanLabel(source),sourceMap,reason});else this.manifest.truncated.notRecoverable=true;
  }
  private listSkipped(source:string,sourceMap:string,reason:SkipReason,summary:ManifestMap,file?:string){
    this.manifest.totals.skipped++;summary.skipped++;
    if(this.manifest.skipped.length<this.limits.maxListed)this.manifest.skipped.push(file?{source:cleanLabel(source),sourceMap,reason,path:file}:{source:cleanLabel(source),sourceMap,reason});else this.manifest.truncated.skipped=true;
  }
  private async addMap(mapUrl:string,input:unknown,inline:boolean){
    const label=mapLabel(mapUrl,inline);
    const summary:ManifestMap={sourceMap:label,sources:0,written:0,duplicates:0,notRecoverable:0,skipped:0,sourcesOverLimit:0,sections:0};
    this.manifest.totals.maps++;
    if(this.manifest.maps.length>=this.limits.maxMaps){this.manifest.truncated.maps=true;return;}
    this.manifest.maps.push(summary);
    if(typeof input==='string'&&input.length>this.limits.maxMapBytes){summary.error='map-too-large';return;}
    const map=parseSourceMap(input,this.limits.maxMapBytes);
    if(!map){summary.error='invalid-map';return;}
    await this.walk(map,mapUrl,label,summary,0);
  }
  private async walk(map:Record<string,unknown>,mapUrl:string,label:string,summary:ManifestMap,depth:number){
    if(Array.isArray(map.sections)){
      if(depth>=this.limits.maxSectionDepth){summary.error='section-depth-limit';return;}
      for(const section of map.sections as unknown[]){
        if(this.sections>=this.limits.maxSections){summary.error='section-limit';return;}
        this.sections++;summary.sections++;
        const s=section&&typeof section==='object'?section as Record<string,unknown>:{};
        const inner=s.map&&typeof s.map==='object'&&!Array.isArray(s.map)?s.map as Record<string,unknown>:undefined;
        if(inner)await this.walk(inner,mapUrl,label,summary,depth+1);
        else if(typeof s.url==='string'){let ref=s.url;try{ref=new URL(s.url,mapUrl).href;}catch{}this.listNotRecoverable(ref,label,'section-url-not-fetched',summary);}
        else summary.error='invalid-map';
      }
      return;
    }
    if(!Array.isArray(map.sources)){summary.error='invalid-map';return;}
    const sources=map.sources as unknown[],contents=Array.isArray(map.sourcesContent)?map.sourcesContent as unknown[]:[];
    const root=typeof map.sourceRoot==='string'?map.sourceRoot:'';
    const n=Math.min(sources.length,this.limits.maxSourcesPerMap);
    summary.sources+=sources.length;
    if(sources.length>n){summary.sourcesOverLimit+=sources.length-n;this.manifest.totals.sourcesOverLimit+=sources.length-n;}
    for(let i=0;i<n;i++){
      const name=sources[i];
      if(typeof name!=='string'||!name){this.listSkipped('sources['+i+']',label,'invalid-source-name',summary);continue;}
      const full=root&&!/^[A-Za-z][A-Za-z0-9+.-]*:/.test(name)&&!name.startsWith('/')?root.replace(/\/?$/,'/')+name:name;
      const content=contents[i];
      if(content===undefined||content===null){this.listNotRecoverable(full,label,'no-sources-content',summary);continue;}
      if(typeof content!=='string'){this.listNotRecoverable(full,label,'invalid-sources-content',summary);continue;}
      await this.place(full,content,label,summary);
    }
  }
  private async place(source:string,content:string,label:string,summary:ManifestMap){
    const safe=sanitizeSourcePath(source);
    if(!safe){this.listSkipped(source,label,'invalid-source-name',summary);return;}
    if(content.length>this.limits.maxFileBytes){this.listSkipped(source,label,'file-too-large',summary,safe.path);return;}
    const data=Buffer.from(content,'utf8');
    if(data.length>this.limits.maxFileBytes){this.listSkipped(source,label,'file-too-large',summary,safe.path);return;}
    const sha256=createHash('sha256').update(data).digest('hex');
    const segments=safe.path.split('/');
    for(let i=0;i<segments.length-1;i++){const canon=this.dirNames.get(key(segments.slice(0,i+1).join("/")));if(canon)segments.splice(0,i+1,...canon.split("/"));}
    // Folders: a prefix that is already a file gets a `~n` folder name.
    for(let i=0;i<segments.length-1;i++){let n=1;const base=segments[i];while(this.files.has(key(segments.slice(0,i+1).join('/')))||i===0&&key(segments[0])===key(MANIFEST))segments[i]=bump(base,n++,false);}
    // File: identical content at the same path is recorded once; anything else in the way gets a `~n` file name.
    const baseName=segments[segments.length-1];
    for(let n=1;;n++){
      const rel=segments.join('/'),k=key(rel),existing=this.files.get(k);
      if(existing&&existing.sha256===sha256){if(existing.sourceMap!==label&&!(existing.alsoIn||[]).includes(label)){if((existing.alsoIn||=[]).length<100)existing.alsoIn.push(label);}summary.duplicates++;this.manifest.totals.duplicates++;return;}
      if(!existing&&!this.dirs.has(k)&&!(segments.length===1&&k===key(MANIFEST)))break;
      segments[segments.length-1]=bump(baseName,n,true);
    }
    if(this.manifest.totals.files>=this.limits.maxFiles){this.listSkipped(source,label,'file-limit',summary,segments.join('/'));return;}
    if(this.manifest.totals.bytes+data.length>this.limits.maxTotalBytes){this.listSkipped(source,label,'total-byte-limit',summary,segments.join('/'));return;}
    try{await this.makeDirs(segments.slice(0,-1));}catch{this.listSkipped(source,label,'unsafe-directory',summary,segments.join('/'));return;}
    for(let attempt=0;;attempt++){
      const rel=segments.join('/');
      try{await writeNew(path.join(this.dir,...segments),data);}
      catch(e){
        // The file system folded two names together that the case map did not (for example Unicode case folding): try the next free name.
        if((e as NodeJS.ErrnoException)?.code==='EEXIST'&&attempt<5){segments[segments.length-1]=bump(baseName,1000+attempt,true);if(!this.files.has(key(segments.join('/'))))continue;}
        this.listSkipped(source,label,'write-failed',summary,rel);return;
      }
      for(let i=1;i<segments.length;i++){const d=segments.slice(0,i).join('/');this.dirs.add(key(d));if(!this.dirNames.has(key(d)))this.dirNames.set(key(d),d);}
      this.files.set(key(rel),{path:rel,sha256,bytes:data.length,sourceMap:label,source:cleanLabel(source)});
      this.manifest.totals.files++;this.manifest.totals.bytes+=data.length;summary.written++;
      return;
    }
  }
  /** Create each folder level inside the output folder, refusing anything that is not a plain folder resolving inside it. */
  private async makeDirs(segments:string[]){
    for(let i=1;i<=segments.length;i++){
      const rel=segments.slice(0,i),k=key(rel.join('/'));
      let made=this.madeDirs.get(k);
      if(!made){
        made=(async()=>{
          const abs=path.join(this.dir,...rel);
          try{await mkdir(path.toNamespacedPath(abs),{mode:0o700});}catch(e){if((e as NodeJS.ErrnoException)?.code!=='EEXIST')throw e;}
          const st=await lstat(path.toNamespacedPath(abs));
          if(st.isSymbolicLink()||!st.isDirectory())throw new Error('unsafe-directory');
          const real=await realpath(abs);
          if(path.relative(this.dir,real)!==rel.join(path.sep)&&key(path.relative(this.dir,real))!==key(rel.join(path.sep)))throw new Error('unsafe-directory');
        })();
        this.madeDirs.set(k,made);
        made.catch(()=>this.madeDirs.delete(k));
      }
      await made;
    }
  }
}
/** Rebuild from a list of maps in one go and return the manifest. */
export async function rebuildSources(dir:string,maps:{url:string;map:unknown}[],options:RebuildOptions={}):Promise<RebuildManifest>{
  const r=await SourceRebuilder.create(dir,options);
  for(const m of maps)await r.add(m.url,m.map);
  return r.finish();
}
