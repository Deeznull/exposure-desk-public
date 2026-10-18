import { createHash, createHmac } from 'node:crypto';
/** AWS Signature Version 4 for the one AWS live-check request (STS GetCallerIdentity). The secret access key never leaves this computer: it only derives the
 * signing key here, and the request carries the access-key ID, the signature and (for temporary keys) the session token. Header-signed only, never a presigned URL. */
export interface SignInput {
  method:'GET'|'POST'; host:string; path:string; query?:string;   // query: already canonical (sorted, encoded); the live check never uses one
  headers:Readonly<Record<string,string>>; body:string;
  region:string; service:string;
  accessKeyId:string; secretAccessKey:string; sessionToken?:string;
  amzDate:string;                                                 // YYYYMMDD'T'HHMMSS'Z'
}
const sha256=(s:string)=>createHash('sha256').update(s,'utf8').digest('hex');
const hmac=(key:Buffer|string,s:string)=>createHmac('sha256',key).update(s,'utf8').digest();
export const amzDate=(d=new Date())=>d.toISOString().replace(/[-:]/g,'').replace(/\.\d{3}/,'');
/** The headers to add to the request: x-amz-date, x-amz-security-token (temporary keys) and authorization. */
export function signV4(i:SignInput):Record<string,string>{
  if(!/^\d{8}T\d{6}Z$/.test(i.amzDate))throw new Error('invalid amz date');
  const added:Record<string,string>={'x-amz-date':i.amzDate,...(i.sessionToken?{'x-amz-security-token':i.sessionToken}:{})};
  const all:Record<string,string>={};
  for(const [k,v] of Object.entries({...i.headers,host:i.host,...added}))all[k.toLowerCase()]=String(v).trim().replace(/\s+/g,' ');
  const names=Object.keys(all).sort(),signed=names.join(';');
  const canonical=[i.method,i.path,i.query||'',names.map(n=>n+':'+all[n]+'\n').join(''),signed,sha256(i.body)].join('\n');
  const day=i.amzDate.slice(0,8),scope=`${day}/${i.region}/${i.service}/aws4_request`;
  const toSign=['AWS4-HMAC-SHA256',i.amzDate,scope,sha256(canonical)].join('\n');
  const key=hmac(hmac(hmac(hmac('AWS4'+i.secretAccessKey,day),i.region),i.service),'aws4_request');
  const signature=createHmac('sha256',key).update(toSign,'utf8').digest('hex');key.fill(0);
  return {...added,authorization:`AWS4-HMAC-SHA256 Credential=${i.accessKeyId}/${scope}, SignedHeaders=${signed}, Signature=${signature}`};
}
