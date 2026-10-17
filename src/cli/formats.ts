import { report } from '../reports.js';
import type { Scanner } from '../scanner.js';
/** Output-format registry for report files on disk; --full-secrets adds values only to these files, never to terminal or JSON Lines output. */
// w2-wire: `md` is the masked submission Markdown draft; it is written by src/cli/submission-output.ts (writeSubmission), not by report().
export const FORMATS={json:{extension:'json'},html:{extension:'html'},sarif:{extension:'sarif.json'},md:{extension:'md'}} as const;
export type FormatName=keyof typeof FORMATS;
/** Formats render() produces through reports.ts; `md` goes through the submission writer instead. */
export type ReportFormat=Exclude<FormatName,'md'>;
export function formatName(value:string|undefined):FormatName{const f=value||'json';if(!Object.hasOwn(FORMATS,f))throw new Error('Unknown format');return f as FormatName;}
export const render=(scan:Scanner,format:ReportFormat,full:boolean)=>report(scan,format,full);
