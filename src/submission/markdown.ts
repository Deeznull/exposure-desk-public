import { randomBytes } from 'node:crypto';
import type { Category, Finding, Occurrence, PriorityLevel, ScanView, Severity } from '../types.js';
import { BUILD } from '../build-info.js';
import { capability, canonicalProvider } from '../provider-capabilities.js';
import { IMPACT_TEXT, NOT_ESTABLISHED } from '../finding-assessment.js';
import { mdCode, mdFence, mdText, plainLine, shellQuote, titleText } from './escape.js';

/** Submission Markdown (2.8.0, w1-report): editable bug-bounty report drafts built from the redacted scan view. Offline and pure: no request,
 * no platform API, no key use. Values are masked; `renderSubmission(…, unmask=true)` is reachable only through the disk writer (write.ts). */

/** What the renderer reads from a scan view. Saved views from older builds may lack any optional field. */
export type SubmissionView=Pick<ScanView,'id'|'name'>&Partial<Pick<ScanView,'findings'|'config'|'build'|'engines'|'startedAt'|'endedAt'|'acquisitionMode'|'state'>>;
/** Revealed values keyed by `Finding.id` (the record `Evidence.full()` returns, a vault record, or `secrets` in a sensitive JSON report). */
export type SecretRecord=Record<string,unknown>;
/** One scan: its redacted view, the findings to report (default `reportableFindings(view)`) and, optionally, its revealed values. */
export interface SubmissionScan {view:SubmissionView;findings?:Finding[];secrets?:SecretRecord}
export interface SubmissionOptions {
  /** `findingId` (default) merges findings with the same stable id across scans/targets into one report; `finding` keeps one report per finding per scan. */
  groupBy?:'findingId'|'finding';
  /** Shown as the generation date; default now. */
  generatedAt?:string|Date;
  /** Locations with full reproduction steps per report (default 3, 1–20); further locations are still listed under the affected URLs. */
  maxLocations?:number;
}
export interface SubmissionReport {
  /** Grouping key: `id:<findingId>` or `run:<runId>:<finding.id>`. */
  key:string;
  /** Safe file name inside a bundle (`finding-<id>.md`, `.sensitive.md` with unmasked values); never derived from site content. */
  fileName:string;
  /** Plain one-line title for a platform's title field (controls removed; not Markdown-escaped, so do not paste it into Markdown). */
  title:string;
  markdown:string;
  findingId?:string;
  findings:{runId:string;id:string}[];
  /** Scan targets (seed URLs) the finding was reported in. */
  targets:string[];
  category:Category; severity:Severity; priority:PriorityLevel|'not-recorded'; provider:string;
  /** True only when the Markdown holds at least one unmasked value (disk writer with full secrets). */
  sensitive:boolean;
}

const PRIORITY_RANK:Record<string,number>={urgent:4,high:3,review:2,low:1,none:0,'not-recorded':-1};
const SEVERITY_RANK:Record<Severity,number>={critical:4,high:3,medium:2,low:1,info:0};
const CATEGORY_LABEL:Record<Category,string>={'private-credential':'private credential','suspicious':'possible credential','public-identifier':'public client identifier','information':'information exposure'};
const EXPOSURE_KIND_LABEL:Record<string,string>={'password-hash':'password hashes','sensitive-response':'sensitive data in a public response','private-config':'private configuration','debug-output':'debug output'};
const REFERENCES={
  credential:['[CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)','[CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)','[OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)'],
  information:['[CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)','[CWE-540: Inclusion of Sensitive Information in Source Code](https://cwe.mitre.org/data/definitions/540.html)']};
const DEFAULT_CATEGORIES:Category[]=['private-credential','suspicious'];
const REDACTED=/\[redacted/i;

/** The findings a hunter would normally report from one view: private and possible credentials that are not under an active suppression and
 * not marked false positive. Dismissed observations live outside `view.findings` and are never included. */
export function reportableFindings(view:Pick<SubmissionView,'findings'>,options:{categories?:Category[];includeSuppressed?:boolean;now?:number}={}):Finding[]{
  const categories=options.categories??DEFAULT_CATEGORIES,now=options.now??Date.now();
  return (view.findings||[]).filter(f=>categories.includes(f.category)&&f.feedback?.decision!=='false-positive'&&(options.includeSuppressed||!f.suppression||!(Date.parse(f.suppression.expires)>now)));
}

interface Entry {finding:Finding;view:SubmissionView;secret?:unknown;order:number}
const priorityOf=(f:Finding)=>(f.priority?.level??'not-recorded') as SubmissionReport['priority'];
const better=(a:Entry,b:Entry)=>PRIORITY_RANK[priorityOf(b.finding)]-PRIORITY_RANK[priorityOf(a.finding)]||SEVERITY_RANK[b.finding.severity]-SEVERITY_RANK[a.finding.severity]||a.order-b.order;

/** Strings of a revealed value that must never appear where a masked report is expected (value and representations of 8+ characters). */
function secretStrings(secret:unknown):string[]{
  if(!secret||typeof secret!=='object')return [];const s=secret as {value?:unknown;representations?:unknown},out:string[]=[];
  if(typeof s.value==='string')out.push(s.value);if(Array.isArray(s.representations))for(const r of s.representations)if(typeof r==='string')out.push(r);
  return out.filter(v=>v.length>=8);
}
const revealedValue=(secret:unknown)=>secret&&typeof secret==='object'&&typeof (secret as {value?:unknown}).value==='string'?(secret as {value:string}).value:undefined;
const httpUrl=(raw:string)=>{try{const u=new URL(raw);return u.protocol==='http:'||u.protocol==='https:'?u:undefined;}catch{return undefined;}};
const safeDecode=(s:string)=>{try{return decodeURIComponent(s);}catch{return s;}};
/** A plain GET target for a public resource: no fragment, no user info, and no query parameter that carried a redacted value. A value in the path or host makes the URL unusable (the request would carry the value), so none is returned. */
export function publicGetUrl(raw:string):{url?:string;droppedQuery:boolean;valueInUrl:boolean}{
  const u=httpUrl(raw);if(!u)return {droppedQuery:false,valueInUrl:false};
  u.hash='';u.username='';u.password='';
  if(REDACTED.test(safeDecode(u.pathname))||REDACTED.test(safeDecode(u.host)))return {droppedQuery:false,valueInUrl:true};
  const params=[...u.searchParams],kept=params.filter(([k,v])=>!REDACTED.test(k)&&!REDACTED.test(v));
  if(kept.length!==params.length)u.search=kept.length?new URLSearchParams(kept).toString():'';
  return {url:u.href,droppedQuery:kept.length!==params.length,valueInUrl:false};
}
const hostOf=(raw:string)=>httpUrl(raw)?.host;
function resourceKind(o:Occurrence|undefined):string{
  if(!o)return 'a public resource';
  if(o.exposure==='local-only')return 'an owner-supplied local file';
  if(o.exposure==='runtime-memory')return 'page runtime data';
  if(o.exposure==='blocked-candidate')return 'a request built by a public page';
  const p=(httpUrl(o.url)?.pathname||'').toLowerCase();
  if(/\.(?:m|c)?js$/.test(p))return o.coordinates==='extracted-source'?'source code published in a public file':'a public JavaScript file';
  if(/\.map$/.test(p))return 'a public source map';
  if(/\.json$/.test(p))return 'a public JSON file';
  if(/\.css$/.test(p))return 'a public stylesheet';
  if(p===''||p.endsWith('/')||/\.(?:html?|php|aspx?|jsp)$/.test(p))return 'a public page';
  return 'a public file';
}
const ruleLabel=(rule:string)=>{const r=rule.replace(/^[a-z]+:/,'').replace(/[-_]+/g,' ').trim();return r?r[0].toUpperCase()+r.slice(1):'Exposure';};
function headline(f:Finding,provider:string,kind:string,where:string){
  const by=provider&&provider!=='Website'?provider+' ':'';
  if(f.exposureKind)return `Unintended ${EXPOSURE_KIND_LABEL[f.exposureKind]||f.exposureKind} in ${kind} on ${where}`;
  if(f.category==='private-credential')return `Exposed ${by}credential in ${kind} on ${where}`;
  if(f.category==='suspicious')return `Possible ${by}credential exposed in ${kind} on ${where}`;
  if(f.category==='public-identifier')return `Public ${by}client identifier in ${kind} on ${where}`;
  return `${ruleLabel(f.rule)} on ${where}`;
}
const day=(v:string|Date|undefined)=>{const d=v===undefined?new Date():new Date(v);return Number.isFinite(d.getTime())?d.toISOString().slice(0,10):'unknown date';};

interface Context {unmask:boolean;scrub:(s:unknown)=>string;generatedAt?:string|Date;maxLocations:number}

function positionText(c:Context,o:Occurrence):string{
  const at=o.line!==undefined&&o.column!==undefined?`line ${o.line}, column ${o.column}`:'',offset=o.byteOffset!==undefined?` (byte offset ${o.byteOffset} of the decoded text)`:'';
  switch(o.coordinates){
    case 'extracted-source':return at?`${at} of the embedded source ${mdCode(c.scrub(o.sourceLabel||'unnamed source'))} inside this file`:`the embedded source ${mdCode(c.scrub(o.sourceLabel||'unnamed source'))} inside this file`;
    case 'approximate':return at?`about ${at}${offset}, after decoding (${mdText(c.scrub(o.transformations.join(', ')||'decoding'))}); the position refers to the decoded text`:'an encoded part of this file; the exact position was not recorded';
    case 'runtime-snapshot':return `page runtime data${o.sourceLabel?' ('+mdText(c.scrub(o.sourceLabel))+')':''}; no position in a static file`;
    case 'unavailable':return 'an exact position was not recorded';
    default:return at?at+offset:'an exact position was not recorded';
  }
}

function locationLine(c:Context,o:Occurrence,target?:string){
  const mapped=o.originalPosition?` · original source ${mdCode(c.scrub(o.originalPosition.source))} line ${o.originalPosition.line}, column ${o.originalPosition.column}${o.originalPosition.approximate?' (approximate)':''}`:'';
  return `- ${mdCode(c.scrub(o.url),500)} — ${positionText(c,o)}${mapped}${o.documentation?' · appears in documentation or example context':''}${target?' · target '+mdCode(c.scrub(target)):''}`;
}

function foundText(c:Context,o:Occurrence,n:number){
  const chain=o.chain.slice(0,8).map(x=>mdCode(c.scrub(x),200)).join(' → ')+(o.chain.length>8?` → … (${o.chain.length-8} more)`:'');
  const lines=[`**Location ${n}.** Found in ${mdCode(c.scrub(o.url),500)}${o.evidence?' — '+mdText(c.scrub(o.evidence),200):''}.`];
  if(chain)lines.push(`Discovery path: ${chain}.`);
  if(o.sourceLabel&&o.coordinates!=='extracted-source')lines.push(`Source label: ${mdText(c.scrub(o.sourceLabel),200)}.`);
  if(o.transformations.length)lines.push(`Decoding applied before detection: ${mdText(c.scrub(o.transformations.join(', ')),300)}.`);
  if(o.constituents?.length)lines.push(`The value is assembled from ${o.constituents.length} piece${o.constituents.length===1?'':'s'} in the code${o.sink?' and used in '+mdText(c.scrub(o.sink),120):''}.`);
  return lines.join('\n');
}

/** Steps for one location. Only plain unauthenticated GETs of public resources; the value is never part of a request. */
function steps(c:Context,o:Occurrence,n:number,masked:string):string{
  const out:string[]=[`**Location ${n}: ${mdCode(c.scrub(o.url),500)}**`];
  if(o.exposure==='local-only'){out.push('This value was found in owner-supplied local files, not on a public website, so there is nothing public to reproduce. It is not a public exposure.');return out.join('\n\n');}
  const page=o.chain.map(x=>c.scrub(x)).find(x=>publicGetUrl(x).url)||'';
  if(o.exposure==='blocked-candidate'){out.push(`The page ${mdCode(page||c.scrub(o.url),500)} builds a request that carries the value. Exposure Desk blocked that request, so the value was never sent. Open the page in a private browser window without logging in and look for the request in the developer tools Network panel. Do not send that request yourself.`);return out.join('\n\n');}
  if(o.exposure==='runtime-memory'||o.coordinates==='runtime-snapshot'){const target=publicGetUrl(c.scrub(o.url)).url||page;out.push(`The value appears while the page runs (${mdText(c.scrub(o.sourceLabel||o.evidence||'runtime data'),200)}). Open ${target?mdCode(target,500):'the page'} in a private browser window without logging in and look in the developer tools (Sources, Application or Console panel). Do not use the value.`);return out.join('\n\n');}
  if(o.constituents?.length){
    const pieces=o.constituents.slice(0,5),urls=[...new Set(pieces.map(p=>c.scrub(p.url)))];
    const gets=urls.map(u=>publicGetUrl(u)).filter(g=>g.url).map((g,i)=>`curl -sS --compressed -o exposed-resource-${i+1} ${shellQuote(g.url!)}`);
    if(gets.length)out.push('**Step 1.** Download the public file(s) with a plain GET (no login, no key):',mdFence(gets.join('\n'),'sh',4000,10));
    out.push(`**Step 2.** The value is put together from ${o.constituents.length} piece${o.constituents.length===1?'':'s'}: `+pieces.map(p=>`${mdCode(c.scrub(p.url),300)} line ${p.line}, column ${p.column}`).join('; ')+(o.constituents.length>5?`; and ${o.constituents.length-5} more`:'')+'.');
    out.push(`**Step 3.** Joined together, the pieces form the value shown masked as ${mdCode(masked)}.`);
    return out.join('\n\n');
  }
  const get=publicGetUrl(c.scrub(o.url));
  if(get.valueInUrl){out.push(`The address of this resource itself contains the value, so it is not requested here: a request to it would carry the value.${page&&page!==c.scrub(o.url)?' The resource is referenced from '+mdCode(page,500)+'; open that page in a private browser window without logging in to see the reference.':''}`);return out.join('\n\n');}
  if(!get.url){out.push(`This location is not a web address (${mdCode(c.scrub(o.url),300)}), so there is no request to repeat.`);return out.join('\n\n');}
  out.push('**Step 1.** Download the public resource with a plain, unauthenticated GET (no login, no cookies, no key):',mdFence(`curl -sS --compressed -o exposed-resource ${shellQuote(get.url)}`,'sh',5000,3));
  if(get.droppedQuery)out.push('A query parameter that held a redacted value was left out of this request. If the server needs it, open the page that references this file instead.');
  const coords=o.coordinates??(o.line!==undefined?'generated':'unavailable');
  if(coords==='generated'&&o.byteOffset!==undefined&&o.line!==undefined)
    out.push(`**Step 2.** Look at line ${o.line}, column ${o.column} (byte offset ${o.byteOffset} of the decoded text). This prints the text that starts there:`,mdFence(`tail -c +${o.byteOffset+1} exposed-resource | head -c 120`,'sh',200,2));
  else out.push(`**Step 2.** Look at ${positionText(c,o)}.`);
  out.push(`**Step 3.** The text there is the value shown masked as ${mdCode(masked)}.`);
  if(o.excerpt)out.push('Context recorded by Exposure Desk (values redacted):',mdFence(c.scrub(o.excerpt),'text',600,12));
  return out.join('\n\n');
}

function impactSection(c:Context,f:Finding,provider:string):string{
  const lines=['## Possible impact (unverified)',''];
  if(f.category==='information'||f.exposureKind){lines.push(mdText(c.scrub(f.impact),1000),'',`${NOT_ESTABLISHED} Exposure Desk did not verify any impact.`);return lines.join('\n');}
  const impacts=f.impacts?.length?f.impacts.map(i=>IMPACT_TEXT[i.kind]||i.text):capability(f.provider,f.rule).impacts.map(k=>IMPACT_TEXT[k]);
  if(impacts.length){lines.push(`If this is a working ${mdText(c.scrub(provider),120)} credential, whoever has it could possibly do the following. None of it was tested:`,'',...impacts.map(t=>'- '+mdText(t,1000)));}
  else lines.push(`The issuer and capability of this value are not mapped, so what it allows is unknown. If it is a working credential, its impact depends on what it grants, which was not tested.`);
  lines.push('',`${NOT_ESTABLISHED} Exposure Desk never used the value, so this impact is possible, not shown.`);
  if(f.environment==='test')lines.push('','The evidence points to a test or sandbox credential; that does not establish production access.');
  if(f.credentialSet?.state==='partial')lines.push('',`Only part of a credential set was found (missing: ${mdText(c.scrub(f.credentialSet.missing.join(', ')||'not recorded'),300)}). The missing part may be needed for any access.`);
  return lines.join('\n');
}

function remediationSection(c:Context,f:Finding,provider:string):string{
  const lines=['## Remediation',''];
  if(f.category==='information'||f.exposureKind){lines.push('- '+mdText(c.scrub(f.remediation),1500));return lines.join('\n');}
  const specific=capability(f.provider,f.rule).remediation;
  lines.push(`- Rotate or revoke the credential at ${mdText(c.scrub(provider),120)} first. Removing it from the website alone does not make it safe: copies stay in caches, archives and old deployments.`);
  for(const r of specific)lines.push('- '+mdText(r,1000));
  lines.push('- Remove the value from the public file and from the build: frontend bundles and source maps must not carry private credentials. Move the call behind a server-side component, redeploy, and delete stale copies of old bundles and source maps.',
    `- Check the ${mdText(c.scrub(provider),120)} access, usage and billing logs for use of the credential during the exposure window.`);
  return lines.join('\n');
}

function valueSection(c:Context,f:Finding,entries:Entry[],placeholder:string):{text:string;block?:string;sensitive:boolean}{
  const lines=['## Exposed value',`Masked: ${mdCode(f.masked)}`];
  if(f.keyStructure)lines.push(`Key structure: ${mdText(f.keyStructure)}.`);
  if(f.credentialSet)lines.push(`Credential set: ${mdText(f.credentialSet.state)}${f.credentialSet.components.length?'; components '+mdText(c.scrub(f.credentialSet.components.join(', ')),300):''}.`);
  if(!c.unmask)return {text:lines.join('\n\n'),sensitive:false};
  const value=entries.map(e=>revealedValue(e.secret)).find(v=>v!==undefined);
  if(value===undefined){lines.push('Full value: not available in this record (the run did not keep it). Only the masked form is shown.');return {text:lines.join('\n\n'),sensitive:false};}
  lines.push('**Sensitive: full value.** This local report file holds the unmasked value because full secrets were requested for a report written to disk. Keep the file private, never commit or share it, and follow the program\'s rules on how to submit secrets.',placeholder);
  return {text:lines.join('\n\n'),block:mdFence(value,'text',Number.MAX_SAFE_INTEGER,Number.MAX_SAFE_INTEGER),sensitive:true};
}

function renderGroup(c:Context,group:Entry[],fileName:string,key:string):SubmissionReport{
  const primary=[...group].sort(better)[0]!,f=primary.finding,provider=canonicalProvider(f.provider,f.rule);
  const severity=group.map(e=>e.finding.severity).sort((a,b)=>SEVERITY_RANK[b]-SEVERITY_RANK[a])[0]!,priority=priorityOf(primary.finding);
  const located:{o:Occurrence;entry:Entry}[]=[];const seen=new Set<string>();
  for(const entry of [...group].sort(better))for(const o of entry.finding.occurrences){const k=[o.url,o.line,o.column,o.byteOffset,o.sourceLabel,o.transformations.join()].join('\0');if(seen.has(k))continue;seen.add(k);located.push({o,entry});}
  const targets=[...new Set(group.map(e=>c.scrub(e.view.config?.urls?.[0]||e.view.name)))];
  const hosts=[...new Set(located.map(l=>hostOf(c.scrub(l.o.url))).filter((h):h is string=>!!h))];
  const where=hosts.length>1?`${hosts.length} assets`:hosts[0]||(targets.length===1?hostOf(targets[0]!)||targets[0]!:`${targets.length} targets`);
  const title=titleText(c.scrub(headline(f,provider,resourceKind(located[0]?.o),where)));
  const placeholder='EXPOSURE-DESK-VALUE-'+randomBytes(12).toString('hex');
  const value=valueSection(c,f,group,placeholder);
  const findingId=f.findingId||f.correlation;
  const runs=[...new Set(group.map(e=>e.view.id))];
  const rules=f.assessment?.ruleVersion||primary.view.engines?.websiteRules;
  const local=located.length>0&&located.every(l=>l.o.exposure==='local-only')||primary.view.acquisitionMode==='local-artifacts';
  const qualifiers=new Set(group.flatMap(e=>e.finding.qualifiers||[]));
  const caveats:string[]=[];
  if(qualifiers.has('known-public-example'))caveats.push('The value matches a published documentation example or test vector. It is probably not a real credential; check before you submit.');
  if(qualifiers.has('checksum-mismatch'))caveats.push('The value\'s built-in checksum does not match. It may be a placeholder, truncated or altered.');
  if(qualifiers.has('encrypted-material'))caveats.push('The material is encrypted; the passphrase was not found.');
  if(located.some(l=>l.o.documentation))caveats.push('At least one location is in documentation or example context.');
  if(f.environment==='test')caveats.push('The evidence points to a test or sandbox environment.');
  if(local)caveats.push('Found in owner-supplied local files only; public reachability was not tested. This is not a public exposure.');
  const scanned=primary.view.startedAt||primary.view.endedAt,found=scanned?day(scanned):'date not recorded';
  const md:string[]=[
    `# ${mdText(title,200)}`,
    `**Draft for review.** Generated by Exposure Desk ${mdText(BUILD.version)} on ${day(c.generatedAt)}. Every section is plain, editable Markdown: check and edit it before you submit.`,
    `**Validity not tested.** Exposure Desk did not test whether this key or value is valid and never sent it anywhere. Validity, permissions, restrictions, balances and any loss are not established.`,
    '## Summary',
    [`- **Asset (target):** ${targets.map(t=>mdCode(t,500)).join(', ')}`,
     `- **Affected URL${located.length===1?'':'s'}:** ${located.length} location${located.length===1?'':'s'}, listed below`,
     ...(findingId?[`- **Finding ID:** ${mdCode(findingId)}`]:[]),
     `- **Type:** ${mdText(c.scrub(provider),120)} · ${CATEGORY_LABEL[f.category]}${f.exposureKind?' · '+mdText(EXPOSURE_KIND_LABEL[f.exposureKind]||f.exposureKind):''} (rule ${mdCode(c.scrub(f.rule))})`,
     `- **Exposure Desk priority:** ${mdText(priority)}${f.priority?.version?' ('+mdText(f.priority.version)+')':''}${f.priority?.basis?.length?' — '+mdText(c.scrub(f.priority.basis.slice(0,6).join('; ')),600):''}`,
     `- **Exposure Desk severity:** ${mdText(severity)} · confidence ${mdText(f.confidence)}`,
     `- **Platform severity:** set it yourself under the program's rules and severity guidance. The Exposure Desk priority and severity above are not a platform rating.`,
     `- **Found:** ${found}${runs.length===1?' · run '+mdCode(runs[0]!.slice(0,8)):` · ${runs.length} runs`}`].join('\n'),
    summaryText(c,f,provider,located.map(l=>l.o),primary.view),
    ...(caveats.length?['**Caveats:**\n'+caveats.map(x=>'- '+x).join('\n')]:[]),
    '## Affected URLs and locations',
    located.slice(0,20).map(l=>locationLine(c,l.o,targets.length>1?c.scrub(l.entry.view.config?.urls?.[0]||l.entry.view.name):undefined)).join('\n')+(located.length>20?`\n- … and ${located.length-20} more`:''),
    '## How it was found',
    primary.view.acquisitionMode==='local-artifacts'?'Exposure Desk read owner-supplied local files; it made no request.':'Exposure Desk made only unauthenticated requests, the same a visitor without an account makes. It did not log in, guess passwords or use any found value.',
    located.slice(0,c.maxLocations).map((l,i)=>foundText(c,l.o,i+1)).join('\n\n'),
    ...(f.reasons.length?['Why Exposure Desk flagged it:\n'+f.reasons.slice(0,6).map(r=>'- '+mdText(c.scrub(r),400)).join('\n')]:[]),
    `Detection: rule ${mdCode(c.scrub(f.rule))}${rules?' · rules '+mdCode(c.scrub(rules)):''} · confidence ${mdText(f.confidence)}.`,
    '## Steps to reproduce',
    'These steps only download public resources with plain GET requests. They never use the value: do not send it to the provider or anywhere else.',
    located.slice(0,c.maxLocations).map((l,i)=>steps(c,l.o,i+1,f.masked)).join('\n\n')+(located.length>c.maxLocations?`\n\n${located.length-c.maxLocations} more location${located.length-c.maxLocations===1?' is':'s are'} listed under the affected URLs.`:''),
    value.text,
    impactSection(c,f,provider),
    remediationSection(c,f,provider),
    '## References',
    [...(f.category==='information'&&!f.exposureKind?REFERENCES.information:REFERENCES.credential).map(r=>'- '+r),
     `- Exposure Desk ${mdText(BUILD.version)}${findingId?' · finding '+mdCode(findingId):''} · rule ${mdCode(c.scrub(f.rule))}${rules?' · rules '+mdCode(c.scrub(rules)):''}`].join('\n'),
    '---',
    `Validity: not tested. Exposure Desk did not test whether this key is valid, made only unauthenticated GET requests to public resources, and never sent the value to ${mdText(c.scrub(provider),120)} or anywhere else.`];
  let markdown=md.join('\n\n')+'\n';
  // Belt and braces: no revealed value or representation may survive anywhere in the text; the only unmasked copy is put in afterwards.
  const secrets=[...new Set(group.flatMap(e=>secretStrings(e.secret)))].sort((a,b)=>b.length-a.length);
  for(const s of secrets)markdown=markdown.split(s).join('[redacted]');
  if(value.block)markdown=markdown.split(placeholder).join(value.block);
  return {key,fileName,title,markdown,...(findingId?{findingId}:{}),findings:group.map(e=>({runId:e.view.id,id:e.finding.id})),targets,category:f.category,severity,priority,provider:plainLine(c.scrub(provider),120),sensitive:value.sensitive};
}

function summaryText(c:Context,f:Finding,provider:string,occurrences:Occurrence[],view:SubmissionView):string{
  const o=occurrences[0],kind=resourceKind(o),url=o?mdCode(c.scrub(o.url),500):'an unrecorded location',more=occurrences.length>1?` It was found in ${occurrences.length} locations in total.`:'';
  if(view.acquisitionMode==='local-artifacts'||o?.exposure==='local-only')return `A value that looks like a ${mdText(c.scrub(provider),120)} ${CATEGORY_LABEL[f.category]} was found in owner-supplied local files at ${url}.${more}`;
  if(f.exposureKind)return `${kind[0]!.toUpperCase()+kind.slice(1)} at ${url} contains ${EXPOSURE_KIND_LABEL[f.exposureKind]||mdText(f.exposureKind)} that any visitor without an account can read.${more}`;
  if(f.category==='information')return `${mdText(ruleLabel(f.rule))}: ${kind} at ${url} is readable by any visitor without an account.${more}`;
  const what=f.category==='public-identifier'?`a ${mdText(c.scrub(provider),120)} public client identifier`:`a value that matches the format of a ${mdText(c.scrub(provider),120)} credential`;
  return `${kind[0]!.toUpperCase()+kind.slice(1)} at ${url} contains ${what}. Any visitor without an account can read it.${more} Exposure Desk did not test whether it works.`;
}

function scrubber(secrets:string[]){const list=[...new Set(secrets)].sort((a,b)=>b.length-a.length);return (v:unknown)=>{let s=String(v??'');for(const x of list)if(s.includes(x))s=s.split(x).join('[redacted]');return s;};}
const fileSlug=(e:Entry)=>(e.finding.findingId||e.finding.correlation||e.view.id.slice(0,8)+'-'+e.finding.id).toLowerCase().replace(/[^a-z0-9-]/g,'').slice(0,24)||'finding';

/** Internal: render reports. `unmask` puts the revealed value into the "Exposed value" section; only the disk writer passes true. */
export function renderSubmission(scans:SubmissionScan[],options:SubmissionOptions={},unmask=false):SubmissionReport[]{
  const entries:Entry[]=[];let order=0;
  for(const scan of scans)for(const finding of scan.findings??reportableFindings(scan.view))entries.push({finding,view:scan.view,secret:scan.secrets?.[finding.id],order:order++});
  const scrub=scrubber(entries.flatMap(e=>secretStrings(e.secret)));
  const c:Context={unmask,scrub,generatedAt:options.generatedAt,maxLocations:Math.min(20,Math.max(1,Math.floor(options.maxLocations??3)))};
  const groups=new Map<string,Entry[]>();
  for(const e of entries){const id=e.finding.findingId||e.finding.correlation,key=(options.groupBy??'findingId')==='findingId'&&id?'id:'+id:'run:'+e.view.id+':'+e.finding.id;const g=groups.get(key);if(g)g.push(e);else groups.set(key,[e]);}
  const ordered=[...groups.entries()].sort(([,a],[,b])=>better([...a].sort(better)[0]!,[...b].sort(better)[0]!));
  const used=new Set<string>();
  return ordered.map(([key,group])=>{const base='finding-'+fileSlug([...group].sort(better)[0]!);let name=base,n=2;while(used.has(name))name=base+'-'+n++;used.add(name);
    const r=renderGroup(c,group,name+'.md',key);if(r.sensitive)r.fileName=name+'.sensitive.md';return r;});
}

/** One masked Markdown report per finding of one scan view (`findings` are reported exactly as given; see `reportableFindings` for the usual
 * selection). `secrets`, when supplied, are used only to keep those values out of the text, never to print them. */
export function submissionMarkdown(findings:Finding[],view:SubmissionView,options:SubmissionOptions&{secrets?:SecretRecord}={}):SubmissionReport[]{
  return renderSubmission([{view,findings,secrets:options.secrets}],options,false);
}
/** Masked reports across several scans (for example one per target of a target list), one report per `findingId` group. */
export function submissionReports(scans:SubmissionScan[],options:SubmissionOptions={}):SubmissionReport[]{return renderSubmission(scans,options,false);}

/** `index.md` of a bundle: one line per report linking its file, with priority, severity, provider and targets. Holds no values. */
export function submissionIndex(reports:SubmissionReport[],options:{generatedAt?:string|Date}={}):string{
  const sensitive=reports.some(r=>r.sensitive);
  const lines=['# Submission drafts','',`Generated by Exposure Desk ${mdText(BUILD.version)} on ${day(options.generatedAt)}. ${reports.length} report${reports.length===1?'':'s'}, one file each. Exposure Desk did not test the validity of any value in them; review and edit every report before you submit it.`];
  if(sensitive)lines.push('','**Sensitive:** files ending in `.sensitive.md` hold unmasked values. Keep them private and never commit or share them.');
  lines.push('');
  if(!reports.length)lines.push('No findings were selected for submission.');
  reports.forEach((r,i)=>lines.push(`${i+1}. [${mdText(r.title,200)}](${r.fileName}) — priority ${mdText(r.priority)} · severity ${mdText(r.severity)} · ${mdText(r.provider,120)} · ${r.targets.slice(0,3).map(t=>mdCode(t,200)).join(', ')}${r.targets.length>3?` (+${r.targets.length-3})`:''}${r.findingId?' · '+mdCode(r.findingId.slice(0,16)):''}`));
  return lines.join('\n')+'\n';
}

/** All reports in one Markdown document (single-file output), separated by horizontal rules. */
export function submissionDocument(reports:SubmissionReport[]):string{
  if(!reports.length)return '# Submission drafts\n\nNo findings were selected for submission.\n';
  return reports.map(r=>r.markdown.trimEnd()).join('\n\n---\n\n')+'\n';
}

/** Reads a JSON report file (`scan --format json`, with `secrets` only when it is a sensitive full-secret export) as submission input. */
export function submissionInputFromReport(data:unknown):SubmissionScan{
  const d=data as Record<string,unknown>|null;
  if(!d||typeof d!=='object'||d.schema!=='exposure-scan/1'||typeof d.id!=='string'||typeof d.name!=='string'||!Array.isArray(d.findings))throw new Error('Not an Exposure Desk JSON scan report (schema exposure-scan/1)');
  const secrets=d.sensitive===true&&d.secrets&&typeof d.secrets==='object'&&!Array.isArray(d.secrets)?d.secrets as SecretRecord:undefined;
  return {view:d as unknown as SubmissionView,...(secrets?{secrets}:{})};
}
