/** Flag registry: every CLI flag, whether it takes a value, and the commands that read it. Unknown flags are tolerated as in 2.6 (no flag can relax a hard rule). */
export const FLAGS={
  config:{value:'FILE',commands:['dashboard','scan']},port:{value:'PORT',commands:['dashboard']},'company-rules':{value:'FILE',commands:['dashboard','scan']},history:{commands:['dashboard']},'data-dir':{value:'DIR',commands:['dashboard','trigger','check-key']},
  // Live key check (2.9): `check-key FINDING-ID` sends exactly one found key to its provider's documented read-only endpoint. --run disambiguates when the id is in more than one saved scan; --authorized is the explicit opt-in.
  run:{value:'SCAN-ID',commands:['check-key']},
  url:{value:'URL',commands:['scan']},targets:{value:'FILE|-',commands:['scan']},authorized:{commands:['scan','check-key']},'fail-on':{value:'private-credential|urgent|never',commands:['scan']},coverage:{value:'quick|standard|deep',commands:['scan']},traffic:{value:'low-impact|normal',commands:['scan']},
  preset:{value:'quick|standard|thorough|exhaustive|custom',commands:['scan']},scope:{value:'domain|exact-origin|host-subtree',commands:['scan']},browser:{commands:['scan']},deep:{commands:['scan']},sizing:{value:'fixed|website-count|adaptive',commands:['scan']},
  format:{value:'json|html|sarif|md',commands:['scan']},output:{value:'FILE',commands:['scan','artifacts']},'full-secrets':{commands:['scan','artifacts','report']},checkpoint:{value:'FILE',commands:['scan']},resume:{value:'FILE',commands:['scan']},concurrency:{value:'N',commands:['scan']},state:{value:'FILE',commands:['scan']},
  // w2-wire: recon lists and source rebuild (scan); submission Markdown (scan and the report command).
  recon:{value:'DIR',commands:['scan']},'rebuild-sources':{value:'DIR',commands:['scan']},'submission-bundle':{value:'DIR',commands:['scan']},out:{value:'FILE',commands:['report']},bundle:{value:'DIR',commands:['report']},
  program:{value:'DIR',commands:['scan','check-key']},platform:{value:'hackerone-csv|bounty-targets',commands:['program']},file:{value:'FILE',commands:['program']},handle:{value:'NAME',commands:['program']},jsonl:{commands:['scan']},silent:{commands:['scan']},
  project:{value:'ID',commands:['trigger']},label:{value:'TEXT',commands:['trigger']},assets:{value:'FILE',commands:['trigger']},base:{value:'URL',commands:['trigger']},delay:{value:'SECONDS',commands:['trigger']},
  directory:{value:'DIR',commands:['artifacts']},runtime:{commands:['doctor']},help:{commands:['*']}
} as const satisfies Record<string,{value?:string;commands:readonly string[]}>;
export type FlagName=keyof typeof FLAGS;
type ValueFlag={[K in FlagName]:typeof FLAGS[K] extends {value:string}?K:never}[FlagName];
type BooleanFlag=Exclude<FlagName,ValueFlag>;
export class Args{
  readonly command:string;private rest:string[];
  constructor(argv:string[]){const rest=[...argv],first=rest.shift()||'dashboard';this.command=['--help','-h'].includes(first)?'help':first;this.rest=rest;}
  get help(){return this.command==='help'||this.rest.includes('--help')||this.rest.includes('-h');}
  flag(name:BooleanFlag){return this.rest.includes('--'+name);}
  /** Arguments that are neither flags nor flag values (e.g. `program check DIR` gives ['check','DIR']). */
  positionals(){const out:string[]=[];for(let i=0;i<this.rest.length;i++){const a=this.rest[i]!;if(a.startsWith('--')){const f=(FLAGS as Record<string,{value?:string}>)[a.slice(2)];if(f?.value)i++;continue;}if(a==='-h')continue;out.push(a);}return out;}
  option(name:ValueFlag){const i=this.rest.indexOf('--'+name);if(i<0)return undefined;const v=this.rest[i+1];if(!v||v.startsWith('--'))throw new Error('Missing option value');return v;}
}
