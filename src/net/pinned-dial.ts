import https from 'node:https';
import net from 'node:net';
import tls from 'node:tls';
import { lookup } from 'node:dns/promises';
import { protectedHost } from '../protected-hosts.js';
import { canonicalIp, metadataAddress, publicAddress, certificateNames, isLoopbackAddress } from './address-guard.js';
/** A single, hardened HTTPS request for the live-key-check egress path. It repeats the scan transport's full guard chain — protected-host refusal before any DNS query, metadata-address and address-class checks on every DNS answer, a pinned connect whose socket address must equal the resolved pin, and a protected-host re-check on the server certificate names — then sends exactly one request with no redirect following, no retry, one hard timeout and a capped, discarded body. It never logs. */
export class DialError extends Error { constructor(readonly code:string){super(code);} }
export type DialResolver=(host:string)=>Promise<{address:string;family:number}[]>;
export interface DialRequest { url:string; method:'GET'|'POST'; headers:Record<string,string>; body?:Buffer; timeoutMs:number;
  /** Internal test seam only. Never derived from config, env or scanned content: egress sets these solely from its code-only env object. */
  resolver?:DialResolver; allowLoopback?:boolean; }
export interface DialResponse { status:number; headers:Record<string,string|string[]>; body:Buffer; }
const BODY_CAP=64*1024;
const tlsUntrusted=new Set(['DEPTH_ZERO_SELF_SIGNED_CERT','SELF_SIGNED_CERT_IN_CHAIN','UNABLE_TO_VERIFY_LEAF_SIGNATURE','CERT_HAS_EXPIRED','ERR_TLS_CERT_ALTNAME_INVALID','HOSTNAME_MISMATCH']);
function mapError(e:any):Error{
  if(e instanceof DialError)return e;
  const code=String(e?.code||'');
  if(tlsUntrusted.has(code)||/^ERR_TLS/.test(code)||/certificate|self.signed|altname/i.test(String(e?.message||'')))return new DialError('tls-untrusted');
  if(code==='ETIMEDOUT'||code==='ERR_SOCKET_CONNECTION_TIMEOUT')return new DialError('timeout');
  return new DialError('network');
}
export async function pinnedDial(req:DialRequest):Promise<DialResponse>{
  const u=new URL(req.url);
  if(u.protocol!=='https:')throw new DialError('insecure');                        // every recipe endpoint is HTTPS
  if(protectedHost(u.hostname))throw new DialError('protected-host');              // never even a DNS query
  const host=u.hostname.replace(/^\[|\]$/g,'');
  if(['metadata.google.internal','metadata','instance-data'].includes(host.toLowerCase())||(net.isIP(host)&&metadataAddress(host)))throw new DialError('metadata');
  const resolver:DialResolver=req.resolver||(h=>lookup(h,{all:true,verbatim:true}));
  const answers=net.isIP(host)?[{address:host,family:net.isIP(host)}]:await resolver(host).catch(()=>{throw new DialError('network');});
  if(!answers||!answers.length)throw new DialError('network');
  if(answers.some(a=>!net.isIP(a.address)))throw new DialError('network');
  if(answers.some(a=>metadataAddress(a.address)))throw new DialError('metadata');
  // Address class, fail closed: production requires every answer to be a public unicast address; the loopback test seam (code-only) instead requires every answer to be loopback.
  if(req.allowLoopback===true){ if(answers.some(a=>!isLoopbackAddress(a.address)))throw new DialError('host-not-allowlisted'); }
  else if(answers.some(a=>!publicAddress(a.address)))throw new DialError('host-not-allowlisted');
  const pin=answers[0],port=Number(u.port||443);
  return await new Promise<DialResponse>((resolve,reject)=>{
    let settled=false,socket:net.Socket|undefined;
    const done=(e?:Error,v?:DialResponse)=>{if(settled)return;settled=true;clearTimeout(timer);try{socket?.destroy();}catch{}e?reject(e):resolve(v!);};
    const timer=setTimeout(()=>done(new DialError('timeout')),req.timeoutMs);timer.unref?.();
    const agent=new https.Agent({keepAlive:false,maxSockets:1});
    (agent as any).createConnection=(_opts:unknown,cb:(e:Error|null,s?:net.Socket)=>void)=>{
      const s=tls.connect({host:pin.address,port,servername:net.isIP(host)?undefined:host,rejectUnauthorized:true},()=>{
        try{ if(!s.remoteAddress||canonicalIp(s.remoteAddress)!==canonicalIp(pin.address))throw new DialError('connection-address-mismatch');
             if(certificateNames(s.getPeerCertificate()).some(n=>protectedHost(n)))throw new DialError('protected-host');     // owner name aliasing a government service
             cb(null,s);
        }catch(err){s.destroy();cb(err as Error);} });
      socket=s;s.once('error',err=>cb(err as Error));return s;
    };
    const r=https.request({method:req.method,host,port,path:u.pathname+u.search,headers:{...req.headers,host:u.host},agent},res=>{
      const chunks:Buffer[]=[];let size=0;
      res.on('data',c=>{size+=c.length;if(size<=BODY_CAP)chunks.push(c);else res.destroy();});
      res.on('end',()=>done(undefined,{status:res.statusCode||0,headers:res.headers as Record<string,string|string[]>,body:Buffer.concat(chunks)}));
      res.on('error',e=>done(mapError(e)));
    });
    r.on('error',e=>done(mapError(e)));
    if(req.body)r.write(req.body);
    r.end();
  });
}
