import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { Scanner } from '../scanner.js';
import { exitState, profileLimitText } from '../reports.js';
import { sensitiveWrite } from '../local-files.js';
import type { ScanConfig } from '../types.js';
import { presetConfig } from '../presets.js';
import { RECOMMENDED, type Computer } from '../profiles.js';
import { resumeFrontier } from '../retry.js';
import { ScopePolicy, scopeSource } from '../domain-scope.js';
import { RUN_ID, TRIGGER_LABELS, runSummary, scopeCountLine } from '../runs.js';
import { programLimiter } from '../program/limiter.js';
import { PROGRAM_LIMITS, type ProgramFile } from '../program/settings.js';
import { Detector } from '../detectors.js';
import { FifoBudget } from '../fifo-budget.js';
import { SemanticPool } from '../semantic.js';
import type { Args } from './args.js';
import { CliError } from './errors.js';
import { FORMATS, render, type FormatName, type ReportFormat } from './formats.js';
import { Output, findingEvent, findingLine, gapSummary } from './output.js';
import type { Rejected } from './targets.js';
import { BlockMonitor } from '../mass/block.js';
import { MassScheduler } from '../mass/scheduler.js';
import { MemoryGate, massMemoryCeilingMb } from '../mass/memory-gate.js';
import { ParseCollector } from '../mass/parse-collector.js';
import { Dedup } from '../mass/dedup.js';
import { loadState, newState, writeState, assertResumable, type MassRunState, type TargetState, type TargetStatus } from '../mass/state.js';
// w2-wire integration: per-target recon lists, the shared source rebuild, submission Markdown (--format md) and the run's submission bundle.
import { reconTargetDir, writeTargetRecon, finishReconOutput, type ReconOutput } from './recon-output.js';
import { writeSubmissionFile, submissionScanFrom, writeSubmissionBundle } from './submission-output.js';
import { submissionInputFromReport, type SubmissionScan } from '../submission/index.js';
import { LIST_NAMES, type ReconResult } from '../recon/index.js';

/** True when the configuration only ever contacts its own development fixture origin (loopback tests and the synthetic demo). Mirrors the Scanner constructor's own
 * `detector.syntheticFixture` test exactly, so a report write chooses the fixture path identically whether or not a shared detector is in use. */
export const isSynthetic=(c:Partial<ScanConfig>)=>!!c.developmentFixtureOrigin&&[...(c.urls??[]).map(u=>new URL(u).origin),...(c.relatedOrigins??[])].every(o=>o===c.developmentFixtureOrigin);

/** How many targets run at once. Without `--concurrency` it is the program's `concurrency.targets` (program default 4), or 1 with no program — so a plain target list
 * stays sequential and byte-for-byte the 2.7 output (see docs/MASS_SCAN.md and the frozen w1-core JSONL tests). A bad or over-limit value refuses the whole command,
 * exit 2, before any request: N must be a whole number ≥1; N>64 is always refused; N>16 is refused without a program that authorizes the pace. */
export function resolveConcurrency(args:Args,programFile:ProgramFile|undefined,inputCount:number):number{
  const raw=args.option('concurrency');let requested:number|undefined;
  if(raw!==undefined){
    if(!/^\d+$/.test(raw.trim()))throw new CliError('--concurrency must be a whole number of targets to run at once (1 or more). Nothing was requested.');
    requested=parseInt(raw.trim(),10);
    if(!(requested>=1))throw new CliError('--concurrency must be at least 1. Nothing was requested.');
    if(requested>PROGRAM_LIMITS.targets.max)throw new CliError(`--concurrency cannot exceed ${PROGRAM_LIMITS.targets.max} targets at once. Nothing was requested.`);
    if(requested>16&&!programFile)throw new CliError('--concurrency above 16 needs a program (--program DIR) whose rate and concurrency you accepted; without one, at most 16 targets run at once. Nothing was requested.');
  }
  const ceiling=requested??programFile?.config.concurrency.targets??1;
  return Math.max(1,Math.min(ceiling,Math.max(1,inputCount)));
}

export interface Shared {detector:Detector;budget:FifoBudget;computer:Computer|undefined;memMb:number;pool:SemanticPool;parseCollector:ParseCollector}
/** The one Detector and one analysis-memory FifoBudget a mass run shares across every target (so the analysis budget is never multiplied by N). A throwaway probe
 * Scanner reads this computer's analysis-memory cap (ready options ≤512 MiB; up to 2048 only with an explicit program setting) and the resolved Computer, then the
 * shared detector is initialised once. The parser pool is shared too: its workers hold no state between jobs, so a warm worker serves the next target's job instead of every
 * target starting (and ending) a parser process of its own, one at a time under the one budget. Exported for the budget test. */
export async function buildShared(probeInput:Partial<ScanConfig>,opts:{correlationKey?:Buffer;companyRules?:string}):Promise<Shared>{
  const probe=new Scanner(probeInput,{correlationKey:opts.correlationKey});const memMb=probe.caps.analysisMemoryMb,workers=probe.caps.analysisWorkers,computer=probe.computer;probe.dispose();
  const detector=new Detector();await detector.init(opts.companyRules);
  const budget=new FifoBudget(memMb);detector.analysisMemory=budget;detector.syntheticFixture=isSynthetic(probeInput);
  return {detector,budget,computer,memMb,pool:new SemanticPool(workers,Math.floor(memMb/workers),budget),parseCollector:new ParseCollector()};
}

/** A finished target's recon.json read back for a resumed run's merged set; undefined (left out) when it is missing or not a recon result. */
export async function readEarlierRecon(dir:string):Promise<ReconResult|undefined>{
  let j:any;try{j=JSON.parse(await readFile(path.join(dir,'recon.json'),'utf8'));}catch{return undefined;}
  const num=(v:unknown)=>typeof v==='number'&&Number.isFinite(v);
  const ok=!!j&&typeof j==='object'&&j.schema==='exposure-recon/1'&&!!j.resources&&typeof j.resources==='object'&&['seen','scanned','skipped','truncated','maps'].every(k=>num(j.resources[k]))&&num(j.redactions)&&num(j.inlineSourceMaps)
    &&!!j.lists&&typeof j.lists==='object'&&LIST_NAMES.every(n=>j.lists[n]===undefined||Array.isArray(j.lists[n])&&j.lists[n].every((it:any)=>!!it&&typeof it.value==='string'));
  return ok?j as ReconResult:undefined;
}

export interface RunTargetsContext {
  out:Output;inputs:Partial<ScanConfig>[];rejected:Rejected[];checkpoint:any;projects:Partial<ScanConfig>[];args:Args;programFile:ProgramFile|undefined;
  coverage:string|undefined;traffic:string|undefined;scopeFlag:string|undefined;format:FormatName;failOn:string;correlationKey:Buffer;full:boolean;targeted:boolean;many:boolean;concurrency:number;
  /** w2-wire: recon/rebuild output opened before run-start (src/cli/recon-output.ts), its fixture flag, and the --submission-bundle folder. */
  reconOut:ReconOutput;reconSynthetic:boolean;submissionBundleDir:string|undefined;
}

/** Runs the whole target list: at concurrency 1 a strict sequential loop (byte-identical to 2.7), above 1 a bounded scheduler sharing one Detector, one analysis
 * budget and one program limiter across targets. Owns the single SIGINT/SIGTERM/closed-reader stop (so `listenerCount('SIGINT')` stays 1 during the run), cross-target
 * dedup, the optional `--state` run-state file and the program-wide block halt. Sets `process.exitCode`. "Mass mode" (concurrency>1 or `--state`) is the only path that
 * adds fields to the summary and `finding` events; otherwise the run-start and summary stay exactly the 2.7 shape. */
export async function runTargets(ctx:RunTargetsContext){
  const {out,inputs,rejected,checkpoint,projects,args,programFile,coverage,traffic,scopeFlag,format,failOn,correlationKey,full,targeted,many,concurrency,reconOut,reconSynthetic,submissionBundleDir}=ctx;
  const stateFile=args.option('state'),mass=concurrency>1||stateFile!==undefined,companyRules=args.option('company-rules');
  const sizingPatch:Partial<ScanConfig>=args.option('sizing')?{sizingMode:args.option('sizing') as ScanConfig['sizingMode']}:{};
  // Builds the per-target configuration exactly as the 2.7 loop did (profile + Recommended ready option + preset + scope override + browser/deep flags), WITHOUT the
  // legacy --sizing patch; the Scanner adds that, and scopeSource() reads the un-patched object, matching 2.7 byte-for-byte.
  const buildBase=(i:number):Partial<ScanConfig>=>{
    const profile:Partial<ScanConfig>={...(coverage?{coverage:coverage as ScanConfig['coverage']}:{}),...(traffic?{traffic:traffic as ScanConfig['traffic']}:{})};
    const recommended=!args.option('preset')&&!args.option('sizing')&&!checkpoint&&!projects.length&&!coverage&&!traffic;if(recommended)Object.assign(profile,RECOMMENDED);const chosen=args.option('preset');
    const scopeOverride=scopeFlag?{domainScope:(scopeFlag==='domain'?'registrable-domain':scopeFlag) as ScanConfig['domainScope'],sameRegistrableDomainDiscovery:undefined}:{};
    return chosen?presetConfig(chosen,{...inputs[i],...profile,...scopeOverride,...(args.flag('browser')?{browser:true}:{}),...(args.flag('deep')?{deep:true}:{})}):{...inputs[i],...profile,...scopeOverride,...(args.flag('browser')?{browser:true}:{}),...(args.flag('deep')?{deep:true}:{})};
  };
  const buildInput=(i:number):Partial<ScanConfig>=>({...buildBase(i),...sizingPatch});

  // --state run-state (D2): resume a target list. Settings fingerprint covers everything that changes how a target is scanned, so a resume refuses on any change.
  // That includes the --config settings template: every entry is the template with its own target url, so the first entry minus its urls is the template.
  // The recon folder is part of the settings (a finished target's lists live there); --rebuild-sources and --submission-bundle are not: the rebuild folder must be new or
  // empty on every run, and the bundle is assembled at the end, including the targets an earlier run finished (from their JSON reports).
  let state:MassRunState|undefined,skipped=0,indices:number[],earlier:TargetState[]=[];let saveChain:Promise<void>=Promise.resolve();
  const saveState=()=>{if(!stateFile||!state)return Promise.resolve();const s=state;saveChain=saveChain.then(()=>writeState(stateFile,s));return saveChain;};
  if(stateFile!==undefined){
    if(!targeted)throw new CliError('--state resumes a target list and needs --targets FILE|-. Nothing was requested.');
    const urls=inputs.map(i=>(i.urls as string[])[0]);
    const settings={coverage:coverage??null,traffic:traffic??null,scope:scopeFlag??null,preset:args.option('preset')??null,sizing:args.option('sizing')??null,browser:args.flag('browser'),deep:args.flag('deep'),format,failOn,full,program:programFile?.config??null,companyRules:companyRules??null,recon:reconOut.reconDir!==undefined?path.resolve(reconOut.reconDir):null,template:(({urls:_u,...t})=>t)(inputs[0]??{})};
    const existing=await loadState(stateFile);
    if(existing){assertResumable(existing,urls,settings,stateFile);state=existing;}else state=newState(urls,settings);
    indices=state.targets.filter(t=>t.status!=='done').map(t=>t.index);skipped=state.targets.length-indices.length;earlier=state.targets.filter(t=>t.status==='done');
    await saveState();
  }else indices=inputs.map((_,i)=>i);

  let shared:Shared|undefined;if(mass&&indices.length)shared=await buildShared(buildInput(indices[0]!),{correlationKey,companyRules});

  let exit=0,ran=0,findings=0,interrupted=false,blocked=0,sharedWaitMs=0;const sharedWaitByCause={analysisMs:0,parserMs:0,preflightMs:0,programSlotMs:0};let halted:false|'blocked'=false;
  const states:Record<string,number>={},statuses:Record<string,number>={},active=new Map<number,Scanner>();
  const dedup=mass?new Dedup():undefined;let scheduler:MassScheduler|undefined;
  // w2-wire: recon results and submission inputs kept by target index, so the merged set and the bundle are in list order whatever order the targets finish in.
  const reconResults=new Map<number,ReconResult>(),bundleScans=new Map<number,SubmissionScan>();let allSynthetic=true;
  const reconOption=reconOut.enabled?{recon:reconOut.rebuilder?{rebuilder:reconOut.rebuilder}:{}}:{};
  // Terminal readability under concurrency: at 1, lines stream live in order (2.7). Above 1, each target's human-readable info/result lines are buffered and flushed as
  // one block when the target ends, while JSONL events stream live (each carries `target`). The periodic progress line is suppressed above 1.
  const makeChannel=()=>{
    if(concurrency===1)return {info:(l:string)=>out.info(l),result:(l:string)=>out.result(l),event:(n:'target-start'|'finding'|'target-end',d:Record<string,unknown>)=>out.event(n,d),flush:()=>{}};
    const buf:{k:'info'|'result';line:string}[]=[];
    return {info:(l:string)=>{buf.push({k:'info',line:l});},result:(l:string)=>{buf.push({k:'result',line:l});},event:(n:'target-start'|'finding'|'target-end',d:Record<string,unknown>)=>out.event(n,d),flush:()=>{for(const e of buf)e.k==='info'?out.info(e.line):out.result(e.line);buf.length=0;}};
  };

  const runOne=async(i:number)=>{
    const channel=makeChannel(),base=buildBase(i);
    const scan=mass?new Scanner({...base,...sizingPatch},{correlationKey,detector:shared!.detector,analysisMemory:shared!.budget,semanticPool:shared!.pool,computer:shared!.computer,excludeSharedWaits:true,parseCollector:shared!.parseCollector,...reconOption}):new Scanner({...base,...sizingPatch},{correlationKey,...reconOption});
    active.set(i,scan);
    // Block detection runs for every list target and every program run; a single --url scan with no program keeps the 2.7 transport exactly (no monitor attached).
    if(targeted||programFile)scan.transport.blockMonitor=new BlockMonitor();
    try{
      // Mass mode initialised its shared detector once (buildShared) and skips init(); the per-scan recon collector is still built here.
      if(!mass)await scan.init(companyRules);else scan.initRecon();
      if(interrupted)return; // Ctrl+C before this target ran: start nothing, emit nothing, no ran++ (2.7's break).
      const previous=checkpoint?.redactedReview?.id;
      scan.launch={trigger:checkpoint?'resume':'manual',interface:'cli',requestedAt:new Date().toISOString(),...(checkpoint&&typeof previous==='string'&&RUN_ID.test(previous)?{previousRunId:previous,relation:'resume' as const}:{})};
      const urls=scan.config.urls.map(u=>scan.evidence.scrub(u));channel.event('target-start',{target:i+1,url:urls[0],urls,runId:scan.id,name:scan.evidence.scrub(scan.config.name)});
      if(targeted)channel.info(`Target ${i+1}/${inputs.length}: ${urls[0]}`);
      channel.info(`Run #${scan.id.slice(0,8)} · ${TRIGGER_LABELS[scan.launch.trigger]} (CLI) · ${scan.evidence.scrub(scan.config.name)}`);
      const pv=scan.profileView(),est=pv.estimate;channel.info(`Profile: ${pv.label} · ${pv.sizing.explicitWebsites} website${pv.sizing.explicitWebsites===1?'':'s'}${pv.sizing.discoveredLimit?` (+ up to ${pv.sizing.discoveredLimit} discovered)`:''} · up to ${est.total.requests} requests over ${pv.traffic==='low-impact'?`about ${est.total.connections} kept-alive connections`:'one connection each'} and ${Math.round(est.total.bytes/1048576)} MiB · about ${est.expectedMinutes} min at this pacing${pv.traffic==='low-impact'?' · Low-impact: fewer, slower requests; the scan is not hidden':''}`);
      if(pv.resourceUse)channel.info(`Uses: ${pv.resourceUse.summary.join(' · ')}. ${pv.resourceUse.computerNote}`);if(est.longRun)channel.info('Long scan: '+est.longRun);
      const preview=new ScopePolicy(scan.config).describe(scopeSource(base));channel.info(scan.evidence.scrub('Scope: '+preview.summary+(preview.warnings.length?' Warning: '+preview.warnings.join(' '):'')+(preview.unsupportedSeeds.length?' Exact-only seeds: '+preview.unsupportedSeeds.map(s=>s.seed+' ('+s.reason+')').join(', '):'')));
      if(checkpoint)for(const w of resumeFrontier(checkpoint.frontier||[],scan.config.maxResources))scan.enqueue(w.url,scan.config.urls[0],0,['resumed checkpoint frontier'],w.kind);
      if(state){state.targets[i]!.status='running';state.targets[i]!.runId=scan.id;await saveState();}
      const progress=(!out.silent&&concurrency===1)?setInterval(()=>{const v=scan.view();out.info(`${v.state}: ${v.counts.scanned} resources, ${v.counts.findings} findings, ${v.counts.bytes} bytes`);},5000):undefined;
      try{await scan.run();}finally{clearInterval(progress);}ran++;
      let file=args.option('output')||path.join('reports',`scan-${scan.id}${full?'.sensitive':''}.${FORMATS[format].extension}`);
      if(many)file=file.replace(/(\.[^.]+)?$/,`-${i+1}$1`);
      await mkdir(path.dirname(path.resolve(file)),{recursive:true});let reportPath=path.resolve(file);const synthetic=isSynthetic(scan.config);
      // w2-wire: --format md writes a masked submission Markdown draft (a .sensitive.md file only with --full-secrets); other formats render as before.
      if(format==='md'){const w=await writeSubmissionFile(file,scan,full,synthetic);reportPath=w.files[0]!;}
      else{const text=render(scan,format as ReportFormat,full);if(full)await sensitiveWrite(reportPath,text,synthetic);else await writeFile(file,text,{mode:0o600});}
      // w2-wire: this target's recon lists (DIR/<n>-<host> in a list), kept for the merged top-level set, and its submission input for the bundle.
      let reconDir:string|null=null;
      if(reconOut.enabled&&scan.recon){const result=scan.recon.result();reconResults.set(i,result);if(reconOut.reconDir!==undefined){const w=await writeTargetRecon(reconTargetDir(reconOut.reconDir,i+1,many,scan.config.urls[0]||''),result,{syntheticFixture:synthetic});reconDir=w.dir;}}
      if(submissionBundleDir!==undefined){bundleScans.set(i,submissionScanFrom(scan,full));allSynthetic=allSynthetic&&synthetic;}
      const checkpointFile=args.option('checkpoint');if(checkpointFile)await writeFile(targeted&&many?checkpointFile.replace(/(\.[^.]+)?$/,`-${i+1}$1`):checkpointFile,JSON.stringify(scan.checkpoint(),null,2),{mode:0o600});
      const code=exitState(scan,failOn as 'urgent');exit=Math.max(exit,code);const v=scan.view();findings+=v.findings.length;states[v.state]=(states[v.state]||0)+1;
      channel.info('Scope counts: '+scopeCountLine(runSummary({view:v}).scope));channel.result(`${v.state}${v.profile?.completion==='profile-limited'?' (Limited by profile)':''}: ${v.counts.findings} findings; ${v.coverage?.assessment || 'coverage unavailable'}; ${v.limitations.length} coverage notes; exit ${code}. ${full?'Sensitive local export':'Redacted report'} written.`);
      for(const f of v.findings){channel.result(findingLine(f));const fid=f.findingId||f.correlation||f.id,ded=dedup?dedup.see(fid,i+1):undefined;channel.event('finding',{...findingEvent(i+1,f),...(ded?(ded.duplicate?{firstSeen:ded.firstSeen,duplicateOf:ded.firstSeen}:{firstSeen:ded.firstSeen}):{})});}
      for(const origin of v.origins||[])channel.info(JSON.stringify(origin));if(v.websites)channel.info(JSON.stringify({websites:v.websites}));
      if(v.profile?.completion==='quick-coverage')channel.result(`Completed — quick coverage: only common secret locations were examined; ${v.limitations.find(g=>g.code==='quick-coverage-boundary')?.count??0} discovered URLs outside the Quick target set were not requested. This does not show that the site has no secrets.`);
      if(v.profile?.profileLimit)channel.result(profileLimitText(v));
      if(!v.counts.findings)channel.result('No supported exposure detected in inspected coverage; undiscovered or uninspected resources remain unknown.');
      const b=scan.transport.blocked;
      // Mass mode: the time this target's scan clock did not run because every open website of it only waited for the shared analysis capacity (reported, not charged).
      // Its split by cause (2.9): parts that add up to sharedWaitMs exactly.
      const wait=mass?scan.transport.originControl.projectWait():undefined,waited=wait?.sharedWaitMs??0;sharedWaitMs+=waited;
      if(wait)for(const k of Object.keys(sharedWaitByCause) as (keyof typeof sharedWaitByCause)[])sharedWaitByCause[k]+=wait.sharedWaitByCause[k];
      channel.event('target-end',{target:i+1,url:urls[0],runId:scan.id,status:v.state,stopReason:v.stopReason,assessment:v.coverage?.assessment??null,completion:v.profile?.completion??null,findings:v.findings.length,coverageNotes:v.limitations.length,gaps:gapSummary(v),exit:code,report:reportPath,recon:reconDir,...(wait?{sharedWaitMs:waited,sharedWaitByCause:wait.sharedWaitByCause}:{}),...(b?{blocked:{kind:b.kind,reason:b.reason,...(b.status!==undefined?{status:b.status}:{})}}:{})});
      const status:TargetStatus=b?'blocked':v.state==='completed'?'done':v.state==='cancelled'?'cancelled':'failed';statuses[status]=(statuses[status]||0)+1;
      if(state){const t=state.targets[i]!;t.status=status;t.report=reportPath;if(reconDir)t.recon=reconDir;else delete t.recon;t.findings=v.findings.length;t.exit=code;t.stopReason=v.stopReason??null;await saveState();}
      if(b)blocked++;
      // Program-wide block halt: with at least 3 finished targets and at least a quarter of them blocked, start no further target (the running ones finish).
      if(mass&&halted===false&&ran>=3&&blocked/ran>=0.25){halted='blocked';scheduler?.halt();}
    }finally{active.delete(i);scan.dispose();channel.flush();}
  };

  // Exactly one SIGINT, one SIGTERM and one closed-reader handler for the whole run; each cancels every running target and starts no further one.
  const stop=()=>{interrupted=true;scheduler?.stop();for(const s of active.values())s.cancel();};
  out.onClosed=()=>{out.info('Standard output was closed by its reader; the run stops as with Ctrl+C.');stop();};
  // Memory-aware admission (mass mode above concurrency 1): the scan process stays within 512 MiB (or an explicit program analysisMemoryMb up to 2048), starting a
  // further target only while it fits; the concurrency reached is the run's effective concurrency. Since 2.9.1 a mass run at concurrency 1 (--state) samples memory the
  // same way, so its summary has `memory` like any other mass run; with one target at a time there is never a further target to admit, so nothing is gated.
  const gate=mass?new MemoryGate(massMemoryCeilingMb(programFile?.config.analysisMemoryMb)):undefined;
  const sched=new MassScheduler(indices,concurrency,runOne,gate&&concurrency>1?(n=>gate.admit(n)):undefined);scheduler=sched;
  const sampler=gate?setInterval(()=>gate.sample(sched.running),250):undefined;sampler?.unref();
  process.on('SIGINT',stop);process.on('SIGTERM',stop);
  try{await sched.run();}finally{clearInterval(sampler);process.removeListener('SIGINT',stop);process.removeListener('SIGTERM',stop);await shared?.pool.dispose();}

  if((interrupted||halted)&&(ran+skipped)<inputs.length)exit=Math.max(exit,2);
  // w2-wire: finish recon output (the merged top-level set for a list; the shared rebuild manifest) and write the submission bundle after the last target (on completion,
  // a halt and Ctrl+C alike). A resumed run adds the targets an earlier run finished: their recon.json lists, and their findings when their report is a JSON report.
  if(reconOut.reconDir!==undefined&&many)for(const t of earlier){const r=t.recon?await readEarlierRecon(t.recon):undefined;if(r)reconResults.set(t.index,r);}
  let omitted=0;
  if(submissionBundleDir!==undefined)for(const t of earlier){let added=false;if(format==='json'&&t.report){try{bundleScans.set(t.index,submissionInputFromReport(JSON.parse(await readFile(t.report,'utf8'))));allSynthetic=allSynthetic&&isSynthetic(inputs[t.index]!);added=true;}catch{/* left out, counted below */}}if(!added)omitted++;}
  const inOrder=<T,>(m:Map<number,T>)=>[...m.entries()].sort((a,b)=>a[0]-b[0]).map(e=>e[1]);
  const reconFinal=await finishReconOutput(reconOut,inOrder(reconResults),many,{syntheticFixture:reconSynthetic});
  if(reconFinal.rebuild)out.info(`Rebuilt sources: ${reconFinal.rebuild.files} file${reconFinal.rebuild.files===1?'':'s'} from ${reconFinal.rebuild.maps} source map${reconFinal.rebuild.maps===1?'':'s'} in ${reconFinal.rebuild.dir}.`);
  let submissionBundle:string|null=null;const scans=inOrder(bundleScans);
  if(omitted)out.info(`Submission bundle: ${omitted} target${omitted===1?'':'s'} finished by an earlier run ${omitted===1?'is':'are'} not included because ${omitted===1?'its report is':'their reports are'} not a readable JSON report; run "exposure-desk report submit" on the JSON reports to add them.`);
  if(submissionBundleDir!==undefined&&scans.length){const w=await writeSubmissionBundle(submissionBundleDir,scans,full,allSynthetic);submissionBundle=path.resolve(submissionBundleDir);out.info(`Submission bundle: ${w.reports.length} report${w.reports.length===1?'':'s'} in ${submissionBundle}${w.sensitive?' (includes unmasked values)':' (masked)'}.`);}
  const outputs={recon:reconOut.reconDir?path.resolve(reconOut.reconDir):null,rebuild:reconFinal.rebuild?reconFinal.rebuild.dir:null,submissionBundle};
  const programStats=programFile?programLimiter(programFile.config).stats():undefined;
  if(programStats)out.info(`Program limit: ${programStats.granted} requests, ${programStats.waits} waited for the program limit (${programStats.waitMs} ms in total), at most ${programStats.peakActive} at once.`);
  if(mass){
    if(state){for(const k of Object.keys(statuses))delete statuses[k];for(const t of state.targets)statuses[t.status]=(statuses[t.status]||0)+1;}else if(skipped)statuses.done=(statuses.done||0)+skipped;
    out.event('summary',{targets:inputs.length,scanned:ran,notStarted:inputs.length-ran-skipped,rejected:rejected.length,findings,states,interrupted,exit,...outputs,concurrency,statuses,halted:halted||null,uniqueFindings:dedup!.size,sharedFindings:dedup!.shared(),skipped,effectiveConcurrency:sched.peakActive,sharedWaitMs,sharedWaitByCause,...(gate?{memory:{...gate.stats(),...shared?.parseCollector.stats()}}:{}),...(stateFile?{state:path.resolve(stateFile)}:{}),...(programStats?{program:programStats}:{})});
  }else out.event('summary',{targets:inputs.length,scanned:ran,notStarted:inputs.length-ran,rejected:rejected.length,findings,states,interrupted,exit,...outputs,...(programStats?{program:programStats}:{})});
  process.exitCode=exit;
}
