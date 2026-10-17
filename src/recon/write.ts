/** Writes a ReconResult as one `.txt` per list (one item per line) plus `recon.json` with provenance. */
import { containsKnownSecret } from './clean.js';
import { prepareOutputDir, replaceFile, type OutputOptions } from './files.js';
import { LIST_NAMES, type ListName, type ReconItem, type ReconResult } from './types.js';
export const RECON_FILES=['urls.txt','endpoints.txt','hosts.txt','hosts-in-scope.txt','hosts-out-of-scope.txt','hosts-third-party.txt','parameters.txt','js.txt','sourcemaps.txt','graphql.txt','recon.json'] as const;
const lines=(items:ReconItem[])=>items.length?items.map(i=>i.value).join('\n')+'\n':'';
/** A line that is safe to write: one line, and no known credential shape (a last check for results not built by ReconCollector). */
const safe=(i:ReconItem)=>typeof i?.value==='string'&&i.value.length>0&&!/[\u0000-\u001f\u007f\u2028\u2029]/.test(i.value)&&!containsKnownSecret(i.value);
/**
 * Write the recon files into `dir` (created when missing, never a link). Existing recon files there are replaced atomically; other files are left alone.
 * Returns the resolved folder and the file names written.
 */
export async function writeRecon(dir:string,result:ReconResult,options:Omit<OutputOptions,'requireEmpty'>={}):Promise<{dir:string;files:string[]}>{
  const out=await prepareOutputDir(dir,{protect:options.protect});
  const lists={} as Record<ListName,ReconItem[]>;
  for(const name of LIST_NAMES)lists[name]=(result.lists?.[name]||[]).filter(safe).map(i=>containsKnownSecret(i.source||'')?{...i,source:'{redacted}'}:i);
  const hosts=(scope:string)=>lists.hosts.filter(h=>h.scope===scope);
  const text:Record<string,string>={
    'urls.txt':lines(lists.urls),'endpoints.txt':lines(lists.endpoints),'hosts.txt':lines(lists.hosts),
    'hosts-in-scope.txt':lines(hosts('in-scope')),'hosts-out-of-scope.txt':lines(hosts('out-of-scope')),'hosts-third-party.txt':lines(hosts('third-party')),
    'parameters.txt':lines(lists.parameters),'js.txt':lines(lists.js),'sourcemaps.txt':lines(lists.sourcemaps),'graphql.txt':lines(lists.graphql)
  };
  const counts=Object.fromEntries(LIST_NAMES.map(n=>[n,lists[n].length]));
  text['recon.json']=JSON.stringify({...result,counts,lists},null,2)+'\n';
  for(const name of RECON_FILES)await replaceFile(out,name,text[name]);
  return {dir:out,files:[...RECON_FILES]};
}
