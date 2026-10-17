import {lstat,mkdir,writeFile} from 'node:fs/promises';
import path from 'node:path';
import type {Args} from '../args.js';
import {CliError} from '../errors.js';
import {PROGRAM_FILE,describeProgram,loadProgram,programTemplate} from '../../program/settings.js';
import {readImport,writeImportedProgram} from '../../program/import.js';
export const PROGRAM_USAGE='Usage: exposure-desk program init DIR | program check DIR | program import --platform hackerone-csv|bounty-targets --file FILE [--handle NAME] DIR';
/** `program init|check|import` (2.8). Offline only: none of these sends a request. */
export async function program(args:Args){
  const [sub,dir,...extra]=args.positionals();
  if(!sub||!['init','check','import'].includes(sub)||!dir||extra.length)throw new CliError(PROGRAM_USAGE);
  if(sub==='init'){
    const file=path.join(path.resolve(dir),PROGRAM_FILE);await mkdir(path.dirname(file),{recursive:true});
    try{await writeFile(file,programTemplate(),{flag:'wx',mode:0o600});}catch(e:any){if(e?.code==='EEXIST')throw new CliError(`${file} already exists. Nothing was changed.`);throw e;}
    console.log(`Wrote ${file}. Add in-scope rules and review "authorized", then run: exposure-desk program check ${dir}`);return;
  }
  if(sub==='check'){
    const loaded=await loadProgram(dir);
    if(!loaded){let exists=false;try{exists=(await lstat(path.resolve(dir))).isDirectory();}catch{}throw new CliError(exists?`No ${PROGRAM_FILE} in ${dir} (create one with: exposure-desk program init ${dir})`:`Folder not found: ${dir}`);}
    for(const line of describeProgram(loaded))console.log(line);
    console.log('Program file is valid.');return;
  }
  const platform=args.option('platform'),file=args.option('file'),handle=args.option('handle');
  if(!platform||!file)throw new CliError(PROGRAM_USAGE);
  const result=await readImport(platform,file,handle);
  for(const p of result.protected)console.error(`Refused: ${p.asset} (protected host ${p.host}; government, military, intelligence and law-enforcement websites are never scanned)`);
  for(const s of result.skipped)console.error(`Skipped ${s.type}: ${s.asset} (${s.reason})`);
  const written=await writeImportedProgram(dir,result);
  console.log(`Wrote ${written}: ${result.in.length} in-scope and ${result.out.length} out-of-scope rules, ${result.skipped.length} assets skipped, ${result.protected.length} protected hosts refused.`);
  console.log(`"authorized" is false. Review the scope against the program page, then run: exposure-desk program check ${dir}`);
}
