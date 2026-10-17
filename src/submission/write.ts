import { mkdir, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { restrictWindowsBatch } from '../permissions.js';
import { renderSubmission, submissionDocument, submissionIndex, type SubmissionOptions, type SubmissionReport, type SubmissionScan } from './markdown.js';

/** Disk writer for submission Markdown. This is the only place that can put an unmasked value into a report, and only when the caller asks
 * for `fullSecrets` and the scan supplies its revealed values. Unmasked files are named `*.sensitive.md`, created exclusively (an existing
 * file is never replaced), restricted to the current user (Windows ACL, mode 0600 elsewhere) before any content is written, and removed
 * again if any step fails. Terminal output and JSON Lines never go through here and stay masked. */
export interface WriteSubmissionOptions extends SubmissionOptions {
  /** `file`: every report in one Markdown file at `target`. `bundle`: `target` is a directory that gets one file per report plus `index.md`. */
  mode:'file'|'bundle';
  /** Put the revealed value into the "Exposed value" section. Needs `secrets` on the scans; without them the reports stay masked. */
  fullSecrets?:boolean;
  /** Synthetic test fixtures only: skip the Windows ACL step (mode 0600 still applies), as `sensitiveWrite` does. */
  syntheticFixture?:boolean;
}
export interface WrittenSubmission {
  mode:'file'|'bundle';
  /** Every file written, in order; in bundle mode the last one is `index.md`. */
  files:string[];
  /** Bundle mode only. */
  index?:string;
  /** The reports as written (`fileName` is relative to the bundle directory). */
  reports:SubmissionReport[];
  /** True when at least one written file holds an unmasked value. */
  sensitive:boolean;
}

/** `report.md` becomes `report.sensitive.md` (any other name gets `.sensitive.md` appended), so an unmasked file is visibly sensitive. */
export function sensitiveName(file:string):string{
  if(/\.sensitive\.md$/i.test(file))return file;
  return /\.md$/i.test(file)?file.replace(/\.md$/i,'.sensitive.md'):file+'.sensitive.md';
}

/** Create the sensitive files empty and exclusively, restrict them, then fill them. On failure, removes every file this call created. */
async function writeSensitive(files:{file:string;text:string}[],syntheticFixture:boolean){
  const created:string[]=[];
  try{
    for(const {file} of files){await writeFile(file,'',{mode:0o600,flag:'wx'});created.push(file);}
    if(process.platform==='win32'&&!syntheticFixture){
      try{restrictWindowsBatch(created.map(target=>({target,directory:false})));}
      catch(error){throw new Error('Cannot restrict the sensitive report files: '+(error instanceof Error?error.message:String(error)));}
    }
    for(const {file,text} of files)await writeFile(file,text,{mode:0o600,flag:'r+'});
  }catch(error){
    await Promise.all(created.map(file=>rm(file,{force:true}).catch(()=>{})));
    throw error;
  }
}

/** Writes submission reports to disk. Returns the paths written; with `fullSecrets` in `file` mode the path is the `.sensitive.md` variant of `target`. */
export async function writeSubmission(target:string,scans:SubmissionScan[],options:WriteSubmissionOptions):Promise<WrittenSubmission>{
  if(options.mode!=='file'&&options.mode!=='bundle')throw new Error('Submission mode must be file or bundle');
  const unmask=options.fullSecrets===true,reports=renderSubmission(scans,options,unmask),sensitive=reports.some(r=>r.sensitive);
  const fixture=options.syntheticFixture===true;
  if(options.mode==='file'){
    const file=path.resolve(sensitive?sensitiveName(target):target);
    await mkdir(path.dirname(file),{recursive:true,mode:0o700});
    const text=submissionDocument(reports);
    if(sensitive)await writeSensitive([{file,text}],fixture);else await writeFile(file,text,{mode:0o600});
    return {mode:'file',files:[file],reports,sensitive};
  }
  const dir=path.resolve(target);
  await mkdir(dir,{recursive:true,mode:0o700});
  const out=reports.map(r=>({file:path.join(dir,r.fileName),text:r.markdown,sensitive:r.sensitive}));
  // File names come from hex ids only; this guards the invariant anyway.
  for(const o of out)if(path.dirname(o.file)!==dir)throw new Error('Unsafe submission file name');
  const secret=out.filter(o=>o.sensitive),plain=out.filter(o=>!o.sensitive);
  if(secret.length)await writeSensitive(secret,fixture);
  for(const o of plain)await writeFile(o.file,o.text,{mode:0o600});
  const index=path.join(dir,'index.md');
  await writeFile(index,submissionIndex(reports,{generatedAt:options.generatedAt}),{mode:0o600});
  return {mode:'bundle',files:[...out.map(o=>o.file),index],index,reports,sensitive};
}
