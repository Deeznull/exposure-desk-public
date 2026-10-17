/**
 * w2-wire: CLI glue for recon lists (`--recon DIR`) and the source-map rebuild (`--rebuild-sources DIR`).
 *
 * The scanner builds a ReconCollector per target (src/scanner.ts); this module prepares the output folders, writes each target's lists,
 * merges them into the top-level set for a `--targets` run, finishes the shared rebuilder, and maps the recon layer's ReconOutputError to a
 * CliError (exit 2). Nothing here reveals a credential value: recon lists are masked and cleaned by the collector, and the rebuild tree holds
 * verbatim public source (owner-only folder) and is never printed, never in reports and never on JSON Lines.
 */
import path from 'node:path';
import { SourceRebuilder, writeRecon, ReconOutputError, LIST_NAMES, type ListName, type ReconItem, type ReconResult } from '../recon/index.js';
import type { Args } from './args.js';
import { CliError } from './errors.js';

/** The one-line warning printed before a `--rebuild-sources` run. */
export const rebuildNotice=(dir:string)=>`Rebuilding sources into ${path.resolve(dir)}: these files are the website's own public code, reconstructed verbatim from its published source maps, and may contain credentials. The folder is restricted to you; it is never printed, never included in reports and never sent anywhere.`;

export interface ReconOutput {
  /** The collector should run on every target. */
  enabled:boolean;
  /** Resolved `--recon` root (lists). Undefined when only `--rebuild-sources` was given. */
  reconDir?:string;
  /** Shared rebuilder for `--rebuild-sources` (one tree across all targets). */
  rebuilder?:SourceRebuilder;
}

const toCliError=(e:unknown):CliError=>e instanceof ReconOutputError?new CliError(e.message):new CliError(e instanceof Error?e.message:String(e));

/**
 * Validate the requested recon/rebuild folders before any request. The rebuild folder must be new or empty and is created owner-only here;
 * a failure (not a directory, not empty, cannot restrict) exits 2 with the recon layer's message. `syntheticFixture` skips the Windows ACL
 * step for loopback tests (the folder is still created 0700).
 */
export async function openReconOutput(args:Args,opts:{syntheticFixture?:boolean}={}):Promise<ReconOutput>{
  const reconDir=args.option('recon'),rebuildDir=args.option('rebuild-sources');
  if(reconDir===undefined&&rebuildDir===undefined)return {enabled:false};
  let rebuilder:SourceRebuilder|undefined;
  if(rebuildDir!==undefined){try{rebuilder=await SourceRebuilder.create(rebuildDir,{protect:opts.syntheticFixture?false:true});}catch(e){throw toCliError(e);}}
  return {enabled:true,reconDir,rebuilder};
}

/** Folder for one target's lists: the root itself for a single target, else `root/<index>-<host>`. */
export function reconTargetDir(root:string,index:number,many:boolean,seedUrl:string):string{
  if(!many)return root;
  let host='target';try{host=new URL(seedUrl).hostname||'target';}catch{/* keep fallback */}
  return path.join(root,`${index}-${host.replace(/[^A-Za-z0-9._-]/g,'_')}`);
}

/** Write one ReconResult as the standard set of files into `dir`. Maps a write error to exit 2. */
export async function writeTargetRecon(dir:string,result:ReconResult,opts:{syntheticFixture?:boolean}={}):Promise<{dir:string;files:string[]}>{
  try{return await writeRecon(dir,result,opts.syntheticFixture?{protect:false}:{});}catch(e){throw toCliError(e);}
}

const SCOPE_RANK:Record<string,number>={'in-scope':2,'third-party':1,'out-of-scope':0};
const byValue=(a:ReconItem,b:ReconItem)=>a.value<b.value?-1:a.value>b.value?1:0;

/**
 * Merge per-target results into the top-level set for a `--targets` run: lists are unioned by value (first provenance kept; a host keeps its
 * most permissive scope), and the resource, dropped, redaction and inline-map counters are summed. `counts` is recomputed by writeRecon.
 */
export function mergeReconResults(results:ReconResult[]):ReconResult{
  if(results.length===1)return results[0]!;
  const base=results[0]!;
  const lists={} as Record<ListName,ReconItem[]>;
  for(const name of LIST_NAMES){
    const map=new Map<string,ReconItem>();
    for(const r of results)for(const it of r.lists?.[name]||[]){
      const prev=map.get(it.value);
      if(!prev){map.set(it.value,{...it});continue;}
      if(name==='hosts'&&it.scope&&prev.scope&&(SCOPE_RANK[it.scope]??0)>(SCOPE_RANK[prev.scope]??0))map.set(it.value,{...it});
    }
    lists[name]=[...map.values()].sort(byValue);
  }
  const resources={seen:0,scanned:0,skipped:0,truncated:0,maps:0};
  const dropped=Object.fromEntries(LIST_NAMES.map(n=>[n,{'over-limit':0,'too-long':0,secret:0}]))as ReconResult['dropped'];
  let redactions=0,inlineSourceMaps=0;
  for(const r of results){
    resources.seen+=r.resources.seen;resources.scanned+=r.resources.scanned;resources.skipped+=r.resources.skipped;resources.truncated+=r.resources.truncated;resources.maps+=r.resources.maps;
    redactions+=r.redactions;inlineSourceMaps+=r.inlineSourceMaps;
    for(const n of LIST_NAMES){const d=r.dropped?.[n];if(d){dropped[n]['over-limit']+=d['over-limit'];dropped[n]['too-long']+=d['too-long'];dropped[n].secret+=d.secret;}}
  }
  const counts=Object.fromEntries(LIST_NAMES.map(n=>[n,lists[n].length]))as ReconResult['counts'];
  return {...base,resources,counts,dropped,redactions,inlineSourceMaps,lists};
}

/** After all targets: write the merged top-level set (multi-target only) and finish the rebuilder. Returns the paths and manifest totals for the summary. */
export async function finishReconOutput(out:ReconOutput,results:ReconResult[],many:boolean,opts:{syntheticFixture?:boolean}={}):Promise<{mergedDir?:string;rebuild?:{dir:string;files:number;maps:number}}>{
  const result:{mergedDir?:string;rebuild?:{dir:string;files:number;maps:number}}={};
  if(out.enabled&&out.reconDir!==undefined&&many&&results.length){const w=await writeTargetRecon(out.reconDir,mergeReconResults(results),opts);result.mergedDir=w.dir;}
  if(out.rebuilder){let manifest;try{manifest=await out.rebuilder.finish();}catch(e){throw toCliError(e);}result.rebuild={dir:out.rebuilder.dir,files:manifest.totals.files,maps:manifest.totals.maps};}
  return result;
}
