/**
 * w2-wire: `exposure-desk report submit REPORT.json [REPORT2.json ...] [--out FILE | --bundle DIR] [--full-secrets]`.
 *
 * Offline: it reads one or more Exposure Desk JSON scan reports (schema exposure-scan/1) and renders submission Markdown drafts, grouping
 * findings with the same findingId across the reports into one draft. Masking: the Markdown is masked unless `--full-secrets` is set, and an
 * unmasked value can only come from a sensitive report that carries `secrets` and can only ever reach a file on disk. Without `--out`/`--bundle`
 * the masked Markdown goes to stdout, and `--full-secrets` is refused there because stdout must never hold an unmasked value.
 */
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import type { Args } from '../args.js';
import { CliError } from '../errors.js';
import { submissionInputFromReport, submissionReports, submissionDocument, writeSubmission, type SubmissionScan } from '../../submission/index.js';
export const REPORT_USAGE='Usage: exposure-desk report submit REPORT.json [REPORT2.json ...] [--out FILE | --bundle DIR] [--full-secrets]';
export async function report(args:Args){
  const [sub,...files]=args.positionals();
  if(sub!=='submit'||!files.length)throw new CliError(REPORT_USAGE);
  const out=args.option('out'),bundle=args.option('bundle'),full=args.flag('full-secrets');
  if(out!==undefined&&bundle!==undefined)throw new CliError('Choose one of --out FILE or --bundle DIR, not both.');
  if(full&&out===undefined&&bundle===undefined)throw new CliError('--full-secrets writes an unmasked value only to a file; add --out FILE or --bundle DIR. Nothing was written.');
  const scans:SubmissionScan[]=[];
  for(const f of files){
    let json:unknown;try{json=JSON.parse(await readFile(f,'utf8'));}catch{throw new CliError(`Cannot read ${f} as JSON.`);}
    try{scans.push(submissionInputFromReport(json));}catch(e){throw new CliError(e instanceof Error?`${f}: ${e.message}`:String(e));}
  }
  if(bundle!==undefined){const w=await writeSubmission(bundle,scans,{mode:'bundle',fullSecrets:full,groupBy:'findingId'});console.log(`Wrote ${w.reports.length} report${w.reports.length===1?'':'s'} to ${path.resolve(bundle)}${w.sensitive?' (includes unmasked values)':' (masked)'}.`);return;}
  if(out!==undefined){const w=await writeSubmission(out,scans,{mode:'file',fullSecrets:full,groupBy:'findingId'});console.log(`Wrote ${w.files[0]}${w.sensitive?' (includes unmasked values)':' (masked)'}.`);return;}
  process.stdout.write(submissionDocument(submissionReports(scans,{groupBy:'findingId'})));
}
