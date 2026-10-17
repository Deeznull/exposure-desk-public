import type {Candidate,ScanConfig} from './types.js';
import {parseExpressionAt} from 'acorn';
export const EXPOSURE_RULE_VERSION='exposure/1.0';
interface Field {path:string;name:string;value:string|number|boolean|null;start:number;end:number}
/** JSON tokens retain offsets in the actual response, including escapes and repeats. */
function fields(text:string):Field[]{
 const rows:Field[]=[];let i=0,nodes=0;const ws=()=>{while(/\s/.test(text[i]||'x'))i++;};
 const string=()=>{const start=i++;while(i<text.length){if(text[i]==='\\'){i+=2;continue;}if(text[i++]==='"')break;}return {value:JSON.parse(text.slice(start,i)),start,end:i};};
 const read=(path:string,depth=0):void=>{ws();if(depth>32||++nodes>10000)throw new Error('field-budget');
  if(text[i]==='{'){i++;ws();while(text[i]!=='}'){const k=string();ws();if(text[i++]!==':')throw new Error('json');read(path?path+'.'+k.value:k.value,depth+1);ws();if(text[i]!==',')break;i++;ws();}i++;return;}
  if(text[i]==='['){i++;ws();let index=0;while(text[i]!==']'){read(path+'.'+index++,depth+1);ws();if(text[i]!==',')break;i++;}i++;return;}
  const start=i;let value:any;if(text[i]==='"')value=string().value;else{while(i<text.length&&!/[\s,}\]]/.test(text[i]))i++;value=JSON.parse(text.slice(start,i));}rows.push({path,name:path.split('.').at(-1)!,value,start,end:i});
 };read('');return rows;
}
export function exposureChecks(text:string,expectations:NonNullable<ScanConfig['sensitiveFields']>=[]):{candidates:Candidate[];limited:boolean}{
 const candidates:Candidate[]=[];let rows:Field[]=[];let limited=false;
 if(/^\s*[\[{]/.test(text)){if(Buffer.byteLength(text)>4*1024*1024)limited=true;else try{JSON.parse(text);rows=fields(text);}catch(error){limited=error instanceof Error&&error.message==='field-budget';}}
 if(!rows.length&&Buffer.byteLength(text)<=4*1024*1024){let count=0;for(const m of text.matchAll(/\b(password[_-]?(?:hash|digest)|passwd[_-]?hash|bcrypt|argon2|ssn|nationalId|socialSecurityNumber)["']?\s*[:=]\s*("(?:\\.|[^"\\]){1,1000}"|'(?:\\.|[^'\\]){1,1000}')/gi)){if(count++>=10000){limited=true;break;}try{const literal=parseExpressionAt(m[2],0,{ecmaVersion:'latest'}) as any;if(literal.type==='Literal'&&typeof literal.value==='string'){const start=m.index!+m[0].lastIndexOf(m[2]);rows.push({path:m[1],name:m[1],value:literal.value,start,end:start+m[2].length});}}catch{}}}
 const expected=new Map(expectations.map(f=>[f.path,f.expectation]));
 const emit=(f:Field,rule:string,kind:NonNullable<Candidate['exposureKind']>,reason:string,confidence:Candidate['confidence']='medium')=>{const value=String(f.value);if(!value||/^(?:null|undefined|redacted|\*{3,}|example|your_|placeholder)/i.test(value))return;const original=text.slice(f.start,f.end);candidates.push({value,original,index:f.start,rule,provider:'Website',category:'information',severity:kind==='password-hash'?'high':'medium',confidence,reasons:[reason+' Exposure evidence is separate from credential validity or permissions; no access was tested.'],transformations:original.includes('\\')?['JSON/string literal decoding']:[],exposureKind:kind});};
 for(const f of rows){if(expected.get(f.path)==='public')continue;const name=f.name.toLowerCase().replace(/[_-]/g,''),v=String(f.value);
  if(/password|passwd|pwd|bcrypt|argon/.test(name)&&(/\$2[aby]\$(?:0[4-9]|[12][0-9]|3[01])\$[./A-Za-z0-9]{53}$/.test(v)||/^\$argon2(?:id|i|d)\$v=\d{1,2}\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]{8,}={0,2}\$[A-Za-z0-9+/]{16,}={0,2}$/.test(v)||/^pbkdf2_sha256\$\d+\$[^$\s]{4,128}\$[A-Za-z0-9+/]{20,}={0,2}$/.test(v)))emit(f,'exposed-password-hash','password-hash','Locally supported password-hash structure in a password-related response field ('+f.path+'); plausible unintended exposure.','high');
  else if(expected.get(f.path)==='private'||/^(?:ssn|socialsecuritynumber|nationalid|creditcardnumber|cvv|recoverycodes|mfasecret)$/.test(name))emit(f,'sensitive-response-field','sensitive-response',expected.has(f.path)?'Owner expects this exact response field to remain private ('+f.path+').':'Sensitive response field name and nonempty value ('+f.path+'); confirm intended audience.');
  if(/password|privatekey|secretaccesskey|clientsecret/.test(name)&&f.path.includes('.')&&rows.some(r=>/database|smtp|server|internal/i.test(r.path+' '+r.value)))emit(f,'private-configuration','private-config','Structured server/database configuration contains a sensitive field ('+f.path+'); review public publication.');
  if(/stack|trace|debug/.test(name)&&/\bat\s+[^\n]+\([^\n]*(?:\/srv\/|\/app\/|\/home\/|[A-Z]:\\)[^\n]*:\d+:\d+\)/.test(v))emit(f,'detailed-debug-output','debug-output','Detailed debug output includes internal filesystem paths and stack positions; review production error handling.','high');
 }
 if(!rows.length&&text.length<=4*1024*1024){let count=0;for(const m of text.matchAll(/(?:Error|Exception|Traceback)[^\n]{0,300}\n(?:[^\n]{0,300}\n){0,3}[^\n]{0,100}(?:\/srv\/|\/app\/|\/home\/|[A-Z]:\\)[^\n]{1,200}:\d+(?::\d+)?/g)){if(count++>=20)break;emit({path:'stack',name:'stack',value:m[0],start:m.index!,end:m.index!+m[0].length},'detailed-debug-output','debug-output','Public error stack includes internal filesystem paths and positions; intended audience needs review.','high');}}
 return {candidates,limited};
}
