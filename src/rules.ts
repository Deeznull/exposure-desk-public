import { RE2 } from 're2-wasm';
import { createHash } from 'node:crypto';
export interface CompanyRule {id:string;provider:string;pattern:string;group:number;example?:string}
export function validateRules(input:unknown):CompanyRule[]{
  if(!Array.isArray(input)||input.length>30)throw new Error('Use at most 30 declarative rules');
  const ids=new Set();return input.map(r=>{
    if(!r||typeof r!=='object'||typeof r.id!=='string'||!/^[-\w]{1,60}$/.test(r.id)||ids.has(r.id))throw new Error('Unique rule IDs must use letters, digits, underscores or hyphens');ids.add(r.id);
    if(typeof r.pattern!=='string'||r.pattern.length<1||r.pattern.length>500)throw new Error('Patterns must contain 1–500 characters');
    if(r.provider!==undefined&&(typeof r.provider!=='string'||r.provider.length>80))throw new Error('Provider name too long');
    const group=r.group??0;if(!Number.isInteger(group)||group<0||group>10)throw new Error('Capture group must be 0–10');
    let captures=0,inClass=false;for(let i=0;i<r.pattern.length;i++){const c=r.pattern[i];if(c==='\\'){i++;continue;}if(c==='[')inClass=true;if(c===']')inClass=false;if(!inClass&&c==='('&&(r.pattern[i+1]!=='?'||r.pattern.slice(i+1,i+3)==='?<'||r.pattern.slice(i+1,i+4)==='?P<'))captures++;}if(group>captures)throw new Error('Capture group is not present in this pattern');
    try{const re=new RE2(r.pattern,'gu');if(re.test(''))throw new Error('empty');}catch{throw new Error('Pattern incompatible with RE2 or matches empty text. Lookaround and backreferences are unsupported');}
    if(r.example!==undefined&&(typeof r.example!=='string'||r.example.length>4096))throw new Error('Synthetic example too large');
    return {id:r.id,provider:r.provider||'Company',pattern:r.pattern,group,example:r.example};
  });
}
export function compileRules(input:unknown){return validateRules(input).map(r=>({...r,regex:new RE2(r.pattern,'gu'),category:'suspicious' as const,severity:'medium' as const,confidence:'medium' as const}));}
export function ruleDigest(rules:unknown){return createHash('sha256').update(JSON.stringify(validateRules(rules))).digest('hex');}
export function previewRules(rules:unknown,text:string){
  if(typeof text!=='string'||text.length>65536)throw new Error('Sample limited to 64 KiB');
  return compileRules(rules).map(r=>{const matches=[];let m;while(matches.length<100&&(m=r.regex.exec(text)))matches.push({index:m.index,length:(m[r.group]||'').length,masked:`[redacted: ${(m[r.group]||'').length} characters]`});return {id:r.id,matches};});
}
