import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { exitState } from '../../reports.js';
import { sensitiveWrite } from '../../local-files.js';
import type { Args } from '../args.js';
import { render } from '../formats.js';
export async function artifacts(args:Args){const directory=args.option('directory');if(!directory)throw new Error('Supply an owner-authorized artifact directory');const {scanArtifacts}=await import('../../artifact-scan.js'),scan=await scanArtifacts(directory),full=args.flag('full-secrets'),file=path.resolve(args.option('output')||'reports/local-artifacts.json');await mkdir(path.dirname(file),{recursive:true});const text=render(scan,'json',full);if(full)await sensitiveWrite(file,text);else await writeFile(file,text,{mode:0o600});console.log('Local-only artifact report written; public reachability untested.');process.exitCode=exitState(scan);scan.dispose();}
