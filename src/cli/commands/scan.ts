import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import path from 'node:path';
import { Scanner } from '../../scanner.js';
import { exitState, profileLimitText } from '../../reports.js';
import { sensitiveWrite } from '../../local-files.js';
import type { ScanConfig } from '../../types.js';
import { presetConfig } from '../../presets.js';
import { COVERAGES, TRAFFICS, RECOMMENDED } from '../../profiles.js';
import { resumeFrontier } from '../../retry.js';
import { ScopePolicy, scopeSource } from '../../domain-scope.js';
import { RUN_ID, TRIGGER_LABELS, runSummary, scopeCountLine } from '../../runs.js';
import { assertConfigNotProtected } from '../../protected-hosts.js';
import { invalidHost, invalidHostMessage, normalizeUrl } from '../../config.js';
import { loadProgram, programScope } from '../../program/settings.js';
import { programLimiter } from '../../program/limiter.js';
import type { Args } from '../args.js';
import { CliError } from '../errors.js';
import { FORMATS, formatName, render, type ReportFormat } from '../formats.js';
import { Output, findingEvent, findingLine, gapSummary } from '../output.js';
import { programKey } from '../program.js';
import { echo, readTargets, type Rejected } from '../targets.js';
import { resolveConcurrency, runTargets } from '../mass-run.js';
// w2-wire: recon lists / source rebuild output, opened before any request. The per-target recon, Markdown and bundle writes live in runTargets (src/cli/mass-run.ts).
import { openReconOutput, rebuildNotice } from '../recon-output.js';
export const PROGRAM_AUTHORIZATION_REQUIRED='Refused: a program run needs --authorized or "authorized": true in program.json, your statement that the program authorizes testing its in-scope assets. Nothing was requested.';
export const AUTHORIZATION_REQUIRED='Refused: more than one target needs --authorized, your statement that you are authorized to test every listed target (for example, each one is in the scope of a program you accepted). Nothing was requested.';
/** New input (--url, --config entries and templates, a --resume checkpoint): a host that is not a website host refuses the command with one line, exit 2. */
const assertHosts=(input:unknown)=>{const host=invalidHost(input);if(host!==undefined)throw new CliError(invalidHostMessage(host));};
export async function scan(args:Args,projects:Partial<ScanConfig>[]){
  const out=new Output(args.flag('jsonl'),args.flag('silent')),targets=args.option('targets');
  let checkpoint:any;if(args.option('resume')){checkpoint=JSON.parse(await readFile(args.option('resume')!,'utf8'));if(checkpoint.schema!=='exposure-checkpoint/1')throw new Error('Invalid checkpoint');}
  let inputs:Partial<ScanConfig>[],rejected:Rejected[]=[];
  // Program (2.8): DIR/program.json, when present, is read and validated before anything else is checked or requested. Without it --program keeps the 2.7 meaning (the key only).
  const programDir=args.option('program'),programFile=programDir!==undefined?await loadProgram(programDir):undefined,authorized=args.flag('authorized')||programFile?.authorized===true;
  const inProgram=programFile?((u:string)=>programScope(programFile.config).allows(u)):undefined;
  if(targets!==undefined){
    if(checkpoint||args.option('url'))throw new CliError('--targets cannot be combined with --url or --resume');if(projects.length>1)throw new CliError('With --targets, --config FILE holds one settings template; its urls are replaced by each target');
    // The template is checked like any configuration; each target line is checked on its own while the list is read, before any request.
    const template:Partial<ScanConfig>={...projects[0]};assertConfigNotProtected(template);assertHosts(template);delete template.urls;delete template.name;
    const list=await readTargets(targets);rejected=list.rejected;
    // Program scope: a target outside it is rejected like any other line (out-of-scope rules win), after the protected-host rule.
    const accepted=inProgram?list.accepted.filter(t=>{if(inProgram(t.url))return true;rejected.push({line:t.line,input:echo(t.url),reason:'out-of-scope'});return false;}):list.accepted;rejected.sort((a,b)=>a.line-b.line);
    inputs=accepted.map(t=>({...template,urls:[t.url]}));
    for(const r of rejected)console.error(`Rejected line ${r.line}: ${r.input} (${r.reason})`);
    if(!inputs.length)throw new CliError('No target to scan: the list has no accepted line. Nothing was requested.');
    if(inputs.length>1&&!authorized)throw new CliError(AUTHORIZATION_REQUIRED);
  }else{
    inputs=checkpoint?[checkpoint.config]:projects.length?projects:[{urls:args.option('url')?[args.option('url')!]:[]}];
    // Every entry is checked before the first one runs: a configuration naming a protected host refuses the whole command up front.
    for(const input of inputs)assertConfigNotProtected(input);
    // Then every host must be a website host (the --targets rule), also before any request.
    for(const input of inputs)assertHosts(input);
    // A --url, configuration or checkpoint seed outside the program scope refuses the command up front.
    if(inProgram)for(const input of inputs)for(const raw of Array.isArray(input.urls)?input.urls:[]){if(typeof raw!=='string')continue;let url:string;try{url=normalizeUrl(/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(raw.trim())?raw.trim():'https://'+raw.trim());}catch{continue;}if(!inProgram(url))throw new CliError(`Refused: ${url} is outside the program scope in ${programFile!.file} (see: exposure-desk program check ${programDir}). Nothing was requested.`);}
  }
  // Every program run (a program.json now, or a saved program in a checkpoint) needs the authorization statement; the program file's own scope still applies.
  if((programFile||inputs.some(i=>i.program!==undefined))&&!authorized)throw new CliError(PROGRAM_AUTHORIZATION_REQUIRED);
  if(programFile)inputs=inputs.map(i=>({...i,program:programFile.config}));
  // Every flag is validated before the first request.
  const coverage=args.option('coverage'),traffic=args.option('traffic');if(coverage!==undefined&&!COVERAGES.includes(coverage as ScanConfig['coverage']&string))throw new Error('Unknown --coverage value');if(traffic!==undefined&&!TRAFFICS.includes(traffic as ScanConfig['traffic']&string))throw new Error('Unknown --traffic value');
  const scopeFlag=args.option('scope');if(scopeFlag!==undefined&&!['domain','exact-origin','host-subtree'].includes(scopeFlag))throw new Error('Unknown --scope value');
  const format=formatName(args.option('format')),failOn=args.option('fail-on')||'private-credential';if(!['private-credential','urgent','never'].includes(failOn))throw new Error('Unknown --fail-on value');
  // findingId is the keyed correlation HMAC: a program key keeps it across runs, otherwise one random key per run keeps it across this run's targets.
  const program=args.option('program'),correlationKey=program?await programKey(program):randomBytes(32),full=args.flag('full-secrets'),targeted=targets!==undefined,many=inputs.length>1;
  // Concurrent targets (2.8): validated up front so a bad or over-limit --concurrency refuses before run-start and before any request.
  const concurrency=resolveConcurrency(args,programFile,inputs.length);
  // w2-wire: prepare recon/rebuild output (validates and creates the --rebuild-sources folder before any request) and the per-run submission bundle.
  // Loopback fixtures skip owner-only folder protection, like the dashboard store and the submission output. Matches Scanner's syntheticFixture test for the raw seeds (relatedOrigins are added during a run, so they are empty here).
  const reconSynthetic=inputs.length>0&&inputs.every(i=>{const o=i.developmentFixtureOrigin;return !!o&&Array.isArray(i.urls)&&i.urls.length>0&&i.urls.every(u=>{try{return new URL(u).origin===o;}catch{return false;}});});
  const reconOut=await openReconOutput(args,{syntheticFixture:reconSynthetic}),submissionBundleDir=args.option('submission-bundle');
  out.event('run-start',{mode:targeted?'targets':checkpoint?'resume':projects.length?'config':'url',targets:inputs.length,rejected:rejected.map(r=>({line:r.line,input:r.input,reason:r.reason})),authorized,program:!!program,format,failOn});
  if(reconOut.rebuilder)out.info(rebuildNotice(args.option('rebuild-sources')!));
  if(programFile){const c=programFile.config;out.info(`Program: ${c.name??'(unnamed)'} · ${c.scope.in.length} in-scope and ${c.scope.out.length} out-of-scope rules · up to ${c.requestsPerSecond} requests per second and ${c.concurrency.requests} at once across the run · ${programFile.authorized?'authorized in program.json':'authorized with --authorized'}`);}
  // The per-target work (sequential at concurrency 1 — byte-identical to 2.7 — or a bounded scheduler above 1) lives in runTargets; it owns the SIGINT/SIGTERM/closed-reader stop, writes the reports, emits target/summary events and sets process.exitCode.
  await runTargets({out,inputs,rejected,checkpoint,projects,args,programFile,coverage,traffic,scopeFlag,format,failOn,correlationKey,full,targeted,many,concurrency,reconOut,reconSynthetic,submissionBundleDir});
}
