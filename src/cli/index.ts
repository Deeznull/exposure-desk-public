import { readFile } from 'node:fs/promises';
import type { ScanConfig } from '../types.js';
import { ProtectedHostError, isProtectedHostError, PROTECTED_HOST_MESSAGE } from '../protected-hosts.js';
import { Args } from './args.js';
import { CliError } from './errors.js';
import { isInvalidHostError } from '../config.js';
import { artifacts } from './commands/artifacts.js';
import { launch } from './commands/launch.js';
import { trigger } from './commands/trigger.js';
import { doctor } from './commands/doctor.js';
import { help } from './commands/help.js';
import { cleanup } from './commands/cleanup.js';
import { dashboard } from './commands/dashboard.js';
import { scan } from './commands/scan.js';
import { program } from './commands/program.js';
import { report } from './commands/report.js';
import { checkKey } from './commands/check.js';
export async function loadProjects(file?:string):Promise<Partial<ScanConfig>[]>{if(!file)return [];const j=JSON.parse(await readFile(file,'utf8'));return Array.isArray(j.projects)?j.projects:Array.isArray(j)?j:[j];}
export async function main(argv:string[]){
  const args=new Args(argv);
  if(args.help)return help();
  if(args.command==='artifacts')return artifacts(args);
  if(args.command==='launch')return launch();
  if(args.command==='trigger')return trigger(args);
  if(args.command==='doctor')return doctor(args);
  if(args.command==='cleanup')return cleanup();
  if(args.command==='program')return program(args);
  if(args.command==='report')return report(args);
  if(args.command==='check-key')return checkKey(args);
  const projects=await loadProjects(args.option('config'));
  if(args.command==='dashboard')return dashboard(args,projects);
  if(args.command==='scan')return scan(args,projects);
  throw new Error('Unknown command');
}
/** Raw exception text never reaches the terminal: a protected host prints the fixed refusal, a CLI refusal or an invalid website host its own safe message, anything else a generic line. */
export function run(argv:string[]){void main(argv).catch(e=>{if(isProtectedHostError(e)){console.error(e instanceof ProtectedHostError?e.message:PROTECTED_HOST_MESSAGE);process.exitCode=2;return;}if(e instanceof CliError||isInvalidHostError(e)){console.error(e.message);process.exitCode=e instanceof CliError?e.exitCode:2;return;}console.error('Scanner failed. Check configuration, local installation and documented limits. Raw exception omitted.');process.exitCode=2;});}
