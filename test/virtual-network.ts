import net from 'node:net';
import tls from 'node:tls';
import dns from 'node:dns';
import { syncBuiltinESMExports } from 'node:module';
import type { Scanner } from '../src/scanner.js';
import type { Resource } from '../src/types.js';
/** Test-only egress tripwire: a socket to anything but loopback, or any DNS lookup, throws and is recorded, so a virtual-network test can never reach the internet. */
export function egressTripwire(){
  const saved={connect:net.connect,createConnection:net.createConnection,tls:tls.connect,lookup:dns.lookup,promisesLookup:dns.promises.lookup},violations:string[]=[];
  const hostOf=(args:any[])=>{const a=args[0];if(a&&typeof a==='object')return String(a.host??a.hostname??(a.path?'local-pipe':''));return typeof args[1]==='string'?args[1]:typeof a==='string'&&!/^\d+$/.test(a)?'local-pipe':'localhost';};
  const guard=(original:(...a:any[])=>any,label:string)=>function(this:unknown,...args:any[]){const host=hostOf(args);if(!['127.0.0.1','::1','localhost','local-pipe'].includes(host)){violations.push(label+' '+host);throw new Error('egress tripwire: '+label+' to '+host);}return original.apply(this,args);};
  (net as any).connect=guard(saved.connect,'net.connect');(net as any).createConnection=guard(saved.createConnection,'net.createConnection');(tls as any).connect=guard(saved.tls,'tls.connect');
  const loopback=(host:string)=>['127.0.0.1','::1','localhost'].includes(host);(dns as any).lookup=function(this:unknown,host:string,...rest:any[]){if(loopback(host))return (saved.lookup as any).call(this,host,...rest);violations.push('dns.lookup '+host);throw new Error('egress tripwire: dns.lookup '+host);};(dns.promises as any).lookup=async(host:string,...rest:any[])=>{if(loopback(host))return (saved.promisesLookup as any)(host,...rest);violations.push('dns.promises.lookup '+host);throw new Error('egress tripwire: dns.promises.lookup '+host);};
  syncBuiltinESMExports();
  return {violations,restore(){(net as any).connect=saved.connect;(net as any).createConnection=saved.createConnection;(tls as any).connect=saved.tls;(dns as any).lookup=saved.lookup;(dns.promises as any).lookup=saved.promisesLookup;syncBuiltinESMExports();}};
}
export interface VirtualResponse {type?:string;body?:string;status?:number;headers?:Record<string,string>}
/** Serve virtual hosts to a scanner while still calling the real preflight (scope, credentials, methods, destructive paths) and the real address checks (public, private, metadata and mixed DNS). No production seam: only this scanner's `transport.one` is replaced. */
export function virtualNetwork(s:Scanner,hosts:Record<string,Record<string,VirtualResponse>>){
  const arrivals:{url:string;kind:string;at:number}[]=[];
  s.transport.one=async(raw,options={})=>{
    // Budgets are checked before preflight and again, synchronously, right before the request is counted — as the real permit queue does.
    s.transport.checkBudget();const url=await s.transport.preflight(raw,options.method||'GET',options.headers||{},options.body||'',options.chain||[]);await s.transport.addresses(url);s.transport.checkBudget();
    const u=new URL(url),site=hosts[u.origin],r=site?.[u.pathname+u.search]??site?.[u.pathname];arrivals.push({url,kind:options.kind||'http',at:Date.now()});
    const status=r?.status??(r?200:404),text=r?.body??(r?'':'not found');
    const resource:Resource={url,bytes:Buffer.byteLength(text),status:status>=400?'http-error':status>=300?'redirect':'downloaded',analysis:'pending',code:status,kind:options.kind||'http',chain:options.chain||[]};s.transport.onResource(resource);s.transport.requests++;const origin=s.transport.originControl.current;if(origin)origin.requests++;
    return {url,status,headers:{'content-type':r?.type||'text/html',...(r?.headers||{})},body:Buffer.from(text),partial:false,chain:options.chain||[],resource};
  };
  return {arrivals};
}
