/**
 * Live key check (2.9): `exposure-desk check-key FINDING-ID --program DIR --authorized [--run SCAN-ID] [--data-dir DIR]`.
 *
 * Sends exactly one found key to its issuing provider's documented, read-only "who am I" endpoint to learn whether it is still live. It is never part of a
 * scan and never automatic: it runs only here, on an explicit per-finding command. The gate is the same as the dashboard's — the program file must set
 * `"liveKeyChecks": {"enabled": true}` and the operator must pass `--authorized`. The key is read from the encrypted vault (unlocked with EXPOSURE_VAULT_PASSWORD,
 * no interactive prompt) and is never printed; only the masked verdict is shown and stored in the saved project's review state, never in the scan file.
 */
import type { Args } from '../args.js';
import { CliError } from '../errors.js';
import { Store } from '../../storage.js';
import { Vault } from '../../vault.js';
import { loadProgram } from '../../program/settings.js';
import { recipeFor } from '../../live-check/recipes.js';
import { checkOneKey, LiveCheckRefused } from '../../live-check/egress.js';
export const CHECK_USAGE='Usage: exposure-desk check-key FINDING-ID --program DIR --authorized [--run SCAN-ID] [--data-dir DIR]\n'+
  'Sends one found key to its provider\'s documented read-only identity endpoint to check whether it is still live. Off unless the program file opts in; the key is read from the unlocked vault (EXPOSURE_VAULT_PASSWORD) and is never printed.';
export async function checkKey(args:Args){
  const id=args.positionals()[0];
  if(!id)throw new CliError(CHECK_USAGE);
  const programDir=args.option('program');
  if(programDir===undefined)throw new CliError('Refused: live key checks need --program DIR whose program.json sets "liveKeyChecks": {"enabled": true}. Nothing was sent.');
  const program=await loadProgram(programDir);
  if(!program?.config.liveKeyChecks?.enabled)throw new CliError(`Refused: ${programDir}/program.json does not enable live key checks. Add "liveKeyChecks": {"enabled": true} after reading the program rules (docs/LIVE_KEY_CHECK.md). Nothing was sent.`);
  if(!args.flag('authorized'))throw new CliError('Refused: a live key check needs --authorized, your statement that this program permits an active check of the exposed key. Nothing was sent.');
  const store=await new Store(args.option('data-dir')).init();
  try{
    // Locate the finding by its findingId, correlation or fingerprint across saved history; --run narrows it when the same id is kept in more than one scan.
    const run=args.option('run');
    const matches=store.history.filter(h=>(!run||h.view.id===run)&&h.view.findings.some(f=>f.findingId===id||f.correlation===id||f.id===id));
    if(!matches.length)throw new CliError(run?`No saved finding ${id} in scan ${run}.`:`No saved finding ${id} in local history. Run a saved project scan first, or pass --run SCAN-ID.`);
    if(matches.length>1)throw new CliError(`Finding ${id} is in ${matches.length} saved scans (${matches.map(h=>h.view.id.slice(0,8)).join(', ')}). Choose one with --run SCAN-ID.`);
    const h=matches[0]!,f=h.view.findings.find(f=>f.findingId===id||f.correlation===id||f.id===id)!;
    if(f.category==='information')throw new CliError('That finding is a public observation, not a credential; nothing to check.');
    const recipe=recipeFor(f.rule);
    let key='',companions:{accessKeyId?:string;sessionToken?:string}|undefined;
    if(recipe){
      const password=process.env.EXPOSURE_VAULT_PASSWORD;
      if(!password)throw new CliError('Set EXPOSURE_VAULT_PASSWORD to the vault password so the key can be read for the check. Nothing was sent.');
      const vault=new Vault(store);await vault.init();
      try{await vault.unlock(password);}catch{throw new CliError('Vault unlock failed. Check EXPOSURE_VAULT_PASSWORD, or restore the encrypted evidence vault.');}
      let values;try{values=await vault.get(h.view.id);}catch{throw new CliError(`No saved full value for scan ${h.view.id.slice(0,8)} (redacted history has no key). Re-run the authorized scan with full evidence saved. Nothing was sent.`);}
      key=values[f.id]?.value;companions=values[f.id]?.companions;
      if(!key)throw new CliError('The saved evidence has no full value for this finding. Nothing was sent.');
      vault.lock();
    }
    let result;
    try{result=await checkOneKey({rule:f.rule,key,provider:f.provider,companions});}
    catch(e){if(e instanceof LiveCheckRefused)throw new CliError('Refused: that endpoint is a protected host, a metadata address, non-HTTPS, or its connection address did not match the pin, and is never contacted. Nothing was sent.');throw e;}
    key='';
    if(h.projectId)await store.recordLiveCheck(h.projectId,f,result);
    // Masked verdict only; the key is never printed.
    const line=result.result==='live'?'LIVE — the provider accepted this key':result.result==='revoked'?'revoked — the provider rejected this key':'unknown ('+(result.reason||'inconclusive')+')';
    console.log(`Live key check · ${f.provider} (${f.rule}) · ${f.masked}`);
    console.log(`Result: ${line}${result.endpointHost?' · '+result.endpointHost:''}${result.status?' · HTTP '+result.status:''} · checked ${result.checkedAt}`);
    if(!h.projectId)console.log('Not stored: this scan is not a saved project, so the verdict is shown but not persisted.');
    else console.log('Stored in the project review state (never in the scan file); the key stays masked everywhere.');
  }finally{store.close();}
}
