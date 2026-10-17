import { readFile, stat } from 'node:fs/promises';
import { normalizeUrl } from '../config.js';
import { websiteHost } from '../domain-scope.js';
import { protectedHost } from '../protected-hosts.js';
import { CliError } from './errors.js';
export interface Target {line:number;url:string}
export interface Rejected {line:number;input:string;reason:'protected-host'|'invalid-url'|'unsupported-scheme'|'credentials-in-url'|'line-too-long'|'duplicate'|'target-limit'|'out-of-scope'}
export const MAX_TARGET_BYTES=16*1048576,MAX_TARGETS=100000,MAX_LINE=4096;
const SCHEME=/^[A-Za-z][A-Za-z0-9+.-]*:\/\//;
/** A rejected line is echoed without user info, query or fragment, and at most 200 characters, so a pasted credential never reaches the terminal. */
export const echo=(s:string)=>s.replace(/^((?:[A-Za-z][A-Za-z0-9+.-]*:\/\/)?)[^\s/?#]*@/,'$1[redacted]@').replace(/[?#].*$/,'').slice(0,200);
const jsonTarget=(line:string)=>{try{const j=JSON.parse(line),v=[j?.url,j?.input,j?.host].find(x=>typeof x==='string'&&x.trim());return v?String(v).trim():undefined;}catch{return undefined;}};
/** One target per line: a host name, a URL or an httpx-style line (its first URL token, or the url field of an httpx -json line). Blank lines and # comments are skipped. The protected-host rule runs on every line first and has no override. */
export function parseTargets(text:string):{accepted:Target[];rejected:Rejected[]}{
  const accepted:Target[]=[],rejected:Rejected[]=[],seen=new Set<string>();
  (text.charCodeAt(0)===0xFEFF?text.slice(1):text).split(/\r\n|\n|\r/).forEach((raw,i)=>{
    const line=raw.trim();if(!line||line.startsWith('#'))return;
    // An httpx -json line ({"url":…}) gives its url (or input/host) field; any other line its first URL token, else its first token.
    const json=line.startsWith('{')?jsonTarget(line):undefined,tokens=line.split(/\s+/),token=json??tokens.find(t=>SCHEME.test(t))??tokens[0]!,reject=(reason:Rejected['reason'])=>{rejected.push({line:i+1,input:echo(token),reason});};
    if(protectedHost(token))return reject('protected-host');
    if(line.length>MAX_LINE)return reject('line-too-long');if(line.startsWith('{')&&json===undefined)return reject('invalid-url');
    let u:URL;try{u=new URL(SCHEME.test(token)?token:'https://'+token);}catch{return reject('invalid-url');}
    if(!['http:','https:'].includes(u.protocol))return reject('unsupported-scheme');if(u.username||u.password)return reject('credentials-in-url');
    // A host is letters, digits, hyphens and underscores (IDN arrives as punycode) or an IP literal; anything else can never be a website (the rule configurations use too).
    if(!websiteHost(u.hostname))return reject('invalid-url');
    let url:string;try{url=normalizeUrl(u.href);}catch{return reject('invalid-url');}
    if(protectedHost(url))return reject('protected-host');
    if(seen.has(url))return reject('duplicate');if(accepted.length>=MAX_TARGETS)return reject('target-limit');
    seen.add(url);accepted.push({line:i+1,url});
  });
  return {accepted,rejected};
}
async function readStdin(){const chunks:Buffer[]=[];let n=0;for await(const c of process.stdin){n+=c.length;if(n>MAX_TARGET_BYTES)throw new CliError('Targets list is larger than 16 MiB');chunks.push(Buffer.from(c));}return Buffer.concat(chunks).toString('utf8');}
/** `-` reads standard input; anything else is a file path. */
export async function readTargets(source:string){
  let text:string;if(source==='-')text=await readStdin();else{let size:number;try{size=(await stat(source)).size;}catch{throw new CliError('Targets list could not be read: '+source);}if(size>MAX_TARGET_BYTES)throw new CliError('Targets list is larger than 16 MiB');text=await readFile(source,'utf8');}
  return parseTargets(text);
}
