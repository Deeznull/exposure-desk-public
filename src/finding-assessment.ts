import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import path from 'node:path';
import {applicationRoot} from './runtime-paths.js';
import type {Finding,ImpactKind,PriorityLevel,OwnerRecord,FindingLifecycle,ScanView} from './types.js';
import {capability,canonicalProvider,componentRole,remediationFor} from './provider-capabilities.js';
/** Pure, offline finding assessment: impacts, qualifiers, environment and priority. Nothing is verified; technical severity is never changed. */
export const PRIORITY_VERSION='priority/1';
export const IMPACT_TEXT:Record<ImpactKind,string>={
  'paid-usage':'Possible metered API, AI or messaging use billed to the owner.',
  'cloud-spending':'Possible creation or use of cloud resources billed to the owner.',
  'payment-asset-access':'Possible payment operations, payment data, exchange accounts or on-chain assets. Refund, transfer and withdrawal rights, balances and any loss amount are unknown and never estimated.',
  'account-takeover':'Possible control of repositories, packages, domains or DNS, bot accounts, user sessions or administrative APIs.',
  'signing-encryption':'Possible forged tokens or webhooks, forged signatures, or decryption of protected data.',
  'data-access':'Possible privileged access to data or infrastructure (non-financial).'};
export const NOT_ESTABLISHED='Not established: validity, permissions, restrictions, balances and any loss.';
const FINANCIAL:ImpactKind[]=['paid-usage','cloud-spending','payment-asset-access'];
const RANK:Record<PriorityLevel,number>={none:0,low:1,review:2,high:3,urgent:4};
const PUBLIC=['public-response','static-reconstruction','runtime-memory'];
/** Published documentation examples and test vectors, stored as SHA-256 digests only. */
let known:Set<string>|undefined;
export function knownPublicExample(value:string){if(!known){known=new Set();try{const j=JSON.parse(readFileSync(path.join(applicationRoot,'rules','known-public-examples.json'),'utf8'));for(const e of j.examples||[])if(typeof e.sha256==='string')known.add(e.sha256);}catch{}}return known.has(createHash('sha256').update(value).digest('hex'));}
/** Documentation context for one occurrence: inside <pre>/<code> or a fenced block, on a docs/blog/examples/README path, or beside example/sample/dummy wording. Target-controlled, so it only ever lowers priority. */
export function documentationContext(text:string,index:number,url:string){
  try{if(/(?:^|\/)(?:docs?|documentation|blog|examples?|samples?|readme(?:\.md)?|guides?|tutorials?)(?:\/|\.|$)/i.test(new URL(url).pathname))return true;}catch{}
  const before=text.slice(Math.max(0,index-4000),index),after=text.slice(index,index+4000);
  const open=(tag:string)=>{const o=before.toLowerCase().lastIndexOf('<'+tag),c=before.toLowerCase().lastIndexOf('</'+tag);return o>c&&o>=0&&after.toLowerCase().includes('</'+tag);};
  if(open('pre')||open('code'))return true;if(((before.match(/```/g)||[]).length%2)===1&&after.includes('```'))return true;
  return /\b(?:example|sample|dummy|placeholder|lorem)\b/i.test(text.slice(Math.max(0,index-120),index+120));
}
export function aggregateEnvironment(f:Pick<Finding,'occurrences'|'environment'>,owner?:OwnerRecord){
  const counts={production:0,test:0,unknown:0},sources=new Set<string>();let recorded=false;
  for(const o of f.occurrences){if(!o.environment)continue;recorded=true;counts[o.environment]++;if(o.environmentSource)sources.add(o.environmentSource);}
  if(owner?.environment)return {environment:owner.environment,evidence:{...counts,sources:['owner-statement',...sources]}};
  if(!recorded)return {environment:f.environment||'unknown',evidence:undefined};
  return {environment:counts.production?'production' as const:counts.test&&!counts.unknown?'test' as const:'unknown' as const,evidence:{...counts,sources:[...sources]}};
}
export interface Assessment {environment:NonNullable<Finding['environment']>;environmentEvidence?:Finding['environmentEvidence'];exposureGroup:NonNullable<Finding['exposureGroup']>;impacts:{kind:ImpactKind;text:string}[];qualifiers:string[];priority:NonNullable<Finding['priority']>;financialPriority:NonNullable<Finding['financialPriority']>;impact:string;remediation?:string}
export function assessFinding(f:Finding,context:{owner?:OwnerRecord;lifecycle?:FindingLifecycle}={}):Assessment{
  const owner=context.owner??f.ownerRecord,lifecycle=context.lifecycle??f.lifecycle,provider=canonicalProvider(f.provider,f.rule),cap=capability(provider,f.rule);
  const {environment,evidence}=aggregateEnvironment(f,owner);
  const credential=['private-credential','suspicious'].includes(f.category);
  const impacts=credential?cap.impacts.map(kind=>({kind,text:IMPACT_TEXT[kind]})):[];
  const q=new Set((f.qualifiers||[]).filter(x=>['known-public-example','encrypted-material','checksum-mismatch'].includes(x)));
  if(environment==='test')q.add('test-environment');
  const set=f.credentialSet;if(set?.state==='partial'){const roles=set.missing.map(componentRole);if(roles.includes('secret'))q.add('partial-missing-secret');else if(roles.length)q.add('partial-missing-identifier');}
  if(f.occurrences.length&&f.occurrences.every(o=>o.documentation))q.add('documentation-context');
  if(f.keyStructure==='encrypted')q.add('encrypted-material');if(f.keyStructure==='truncated')q.add('documentation-context');
  if(f.assets?.length&&f.assets.every(a=>a.deployment==='previous-only'))q.add('previous-deployment-only');
  const exposures=new Set(f.occurrences.map(o=>o.exposure||'public-response')),publicExposure=[...exposures].some(e=>PUBLIC.includes(e));
  let level:PriorityLevel='none';const basis:string[]=[];
  if(f.category==='private-credential'){
    const complete=!set||set.state!=='partial'||q.has('partial-missing-identifier'),critical=impacts.length>0||f.severity==='critical';
    if(f.confidence==='high'&&complete&&publicExposure&&critical){level='urgent';basis.push('private credential, high detection confidence','observed in public content or anonymous runtime evidence');if(q.has('partial-missing-identifier'))basis.push('only an identifier component is missing');}
    else{level='high';basis.push('private credential');if(f.confidence!=='high')basis.push(f.confidence+' detection confidence');if(!complete)basis.push('incomplete credential set');if(!critical)basis.push('no mapped high-impact capability');}
  }else if(f.category==='suspicious'){level='review';basis.push('possible credential or component needing review');}
  else if(f.category==='information'&&['password-hash','private-config'].includes(f.exposureKind||'')){level='review';basis.push('possible '+f.exposureKind+' exposure');}
  else basis.push(f.category==='public-identifier'?'public client identifier':'information only');
  const capTo=(max:PriorityLevel,why:string)=>{if(RANK[level]>RANK[max]){level=max;basis.push(why);}};
  if(!publicExposure&&exposures.size)capTo('high','only seen in a locally blocked request or owner-supplied local artifact');
  if(environment==='test')capTo('review',owner?.environment==='test'?'owner reports a test environment':'test or sandbox evidence on every occurrence');
  if(q.has('partial-missing-secret'))capTo('review','partial set: a secret component is missing');
  if(q.has('documentation-context'))capTo('review','every occurrence is in documentation or example context');
  if(q.has('checksum-mismatch'))capTo('review','the offline token checksum does not match the issuer format, typical of examples and edited copies');
  if(q.has('known-public-example'))capTo('low','matches a published documentation example or test vector');
  if(owner?.restrictions==='restricted')capTo('review','owner reports the credential is restricted');
  if(lifecycle?.revocation){if(lifecycle.website?.state==='not-observed')capTo('low','owner confirmed revocation and the value is no longer observed');else capTo('review','owner confirmed revocation; remove the value from the website');}
  const financial=impacts.some(i=>FINANCIAL.includes(i.kind)),financialPriority:Assessment['financialPriority']=level==='urgent'&&financial?'urgent':['high','review'].includes(level)&&financial?'review':'none';
  const impact=credential?(impacts.length?impacts.map(i=>i.text).join(' '):f.category==='suspicious'?'Potential credential or capability requiring operator review.':'Potential privileged access; the issuer and capability are not mapped.')+' '+NOT_ESTABLISHED+(environment==='test'?' Test or sandbox evidence does not establish production access.':''):f.impact;
  return {environment,environmentEvidence:evidence,exposureGroup:credential?cap.group:f.exposureGroup||'other',impacts,qualifiers:[...q].sort(),priority:{level,basis,version:PRIORITY_VERSION},financialPriority,impact,...(f.category==='private-credential'?{remediation:remediationFor(provider,f.rule)}:{})};
}
/** Apply the assessment in place (findings of live scans and loaded history views alike); identity, values and severity are untouched. */
export function applyAssessment(f:Finding,context:{owner?:OwnerRecord;lifecycle?:FindingLifecycle}={}){const a=assessFinding(f,context);f.environment=a.environment;if(a.environmentEvidence)f.environmentEvidence=a.environmentEvidence;f.exposureGroup=a.exposureGroup;f.impacts=a.impacts;f.qualifiers=a.qualifiers;f.priority=a.priority;f.financialPriority=a.financialPriority;f.impact=a.impact;if(a.remediation&&!/^Owner-supplied local artifact/.test(f.remediation||''))f.remediation=a.remediation;if(f.assessment)f.assessment.permissions=(context.owner??f.ownerRecord)?'owner-reported':'unknown';return f;}
/** Older saved views (no priority/1) are assessed when loaded; files are never rewritten. */
export function normalizeFindingAssessment(view:Pick<ScanView,'findings'>){for(const f of view.findings||[])if(f.priority?.version!==PRIORITY_VERSION)applyAssessment(f);return view;}
export const priorityRank=(f:Pick<Finding,'priority'>)=>RANK[f.priority?.level||'none'];
