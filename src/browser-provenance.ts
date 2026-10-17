import type { Resource } from './types.js';
export type Provenance=NonNullable<Resource['provenance']>;
export interface ProxyEvent {seq:number;at:number;method:string;authority:string;url?:string;fetchDest?:string;purpose?:string;phase:string;pageUrl?:string}
export interface NetObservation {at:number;kind:'page'|'frame'|'worker';event:'request'|'failed'|'response'|'websocket';requestId?:string;frameId?:string;url:string;hostPort:string;type?:string;initiator?:string;failure?:string;viaProxy?:boolean}
type InScope=Set<string>|((origin:string)=>boolean);
const inScope=(authorized:InScope,origin:string)=>typeof authorized==='function'?authorized(origin):authorized.has(origin);
/** Candidate origins for a CONNECT authority or absolute URL: `host:443` may be https, `host:80` may be http, and an explicit port keeps both schemes. */
export function proxyOrigins(url:string):string[]{
  if(url.includes('://')){try{return [new URL(url).origin];}catch{return [];}}
  const m=/^(\[[^\]]+\]|[^:/]+)(?::(\d{1,5}))?$/.exec(url);if(!m)return [];const host=m[1].toLowerCase(),port=m[2];
  const candidates=port==='443'||port===undefined?['https://'+host]:port==='80'?['http://'+host]:['https://'+host+':'+port,'http://'+host+':'+port];
  return candidates.map(c=>{try{return new URL(c).origin;}catch{return '';}}).filter(Boolean);
}
export function hostPortOf(url:string){if(url.includes('://')){try{const u=new URL(url);return u.hostname.toLowerCase()+':'+(u.port||(u.protocol==='https:'||u.protocol==='wss:'?'443':'80'));}catch{return '';}}const m=/^(\[[^\]]+\]|[^:/]+)(?::(\d{1,5}))?$/.exec(url);return m?m[1].toLowerCase()+':'+(m[2]||'443'):'';}
/**
 * Fixed, documented list of Chrome-internal service hosts. The bundled Chrome for Testing 153 contacts them by itself, from the browser
 * process, with no page, frame or worker involved (identified with NetLog on Windows; the Linux CI probe saw the same hosts). No launch
 * switch or profile preference stops them in this build, and Chrome retries them with backoff for up to about 30 s after launch, so they
 * also arrive after the first navigation. The proxy still denies every one of them; this list only decides how a denied connection is
 * accounted. Only a CONNECT to port 443 of a listed host counts, and only when CDP network observation of every page, frame and worker was
 * active and complete for the attribution window, no observation of any kind (not even a routed request) names that host and port in the
 * window, no request header ties it to a page, and the host is not an authorized target origin. Anything else keeps today's accounting.
 */
export const CHROME_SERVICE_HOSTS:ReadonlyMap<string,string>=new Map([
  ['accounts.google.com','Google account cookie check (GaiaCookieManagerService ListAccounts), retried at about 0.5, 1.4, 4 and 12 s'],
  ['android.clients.google.com','GCM device check-in, at about 3-6 s and again at about 26-30 s'],
  ['update.googleapis.com','component updater check for the on-device model component'],
  ['www.google.com','AI Mode eligibility check (AimEligibilityService)'],
]);
/** The listed Chrome service host a deny-proxy event went to, or undefined. Exact host match, CONNECT to port 443 only. */
export function chromeServiceHost(event:Pick<ProxyEvent,'method'|'authority'|'url'>):string|undefined{
  if(event.method!=='CONNECT'||event.url)return undefined;
  const hostPort=hostPortOf(event.authority),at=hostPort.lastIndexOf(':');if(at<0||hostPort.slice(at+1)!=='443')return undefined;
  const host=hostPort.slice(0,at);return CHROME_SERVICE_HOSTS.has(host)?host:undefined;
}
/** Header-evidence attribution for plain-HTTP proxy requests; hostname alone never proves anything. */
export function proxyProvenance(url:string,headers:Record<string,unknown>,authorized:InScope):Provenance{
  const origins=proxyOrigins(url),targetOrigin=origins.some(o=>inScope(authorized,o));
  const dest=String(headers['sec-fetch-dest']||''),purpose=String(headers['sec-purpose']||headers.purpose||'');
  const attribution=/prefetch|prerender/.test(purpose)?'speculative':dest==='document'?'page':['iframe','frame'].includes(dest)?'frame':/worker/.test(dest)?'worker':'unknown';
  return {channel:'deny-proxy',attribution,targetOrigin,resourceType:dest||undefined,evidenceSource:attribution==='unknown'?'none':'header-derived',connectAuthority:url.includes('://')?undefined:url,candidates:origins,evidence:attribution==='unknown'?'No page/frame/worker initiator available on this proxy request. Hostname does not establish background or harmless traffic.':'Attribution from request fetch-destination/purpose headers; connection denied.'};
}
/** What the caller knows about its CDP network observation: active on every target channel, and whether the bounded record dropped old entries. */
export interface ObservationCoverage {cdpObserved?:boolean;truncated?:boolean}
/**
 * Pure classification of one deny-proxy event. Rules in order: CDP proof within a time window, header evidence, before any navigation,
 * a CONNECT to a listed Chrome service host that no page, frame or worker touched (see CHROME_SERVICE_HOSTS), otherwise unknown.
 * A hostname decides only in that fourth rule, and only with complete CDP observation (coverage defaults to none).
 */
export function classifyProxyEvent(event:ProxyEvent,observations:readonly NetObservation[],authorized:InScope,coverage:ObservationCoverage={}):Provenance{
  const base=proxyProvenance(event.url||event.authority,{'sec-fetch-dest':event.fetchDest||'','sec-purpose':event.purpose||''},authorized);base.phase=event.phase;
  const hostPort=hostPortOf(event.url||event.authority);
  const inWindow=observations.filter(o=>o.hostPort===hostPort&&o.at>=event.at-3000&&o.at<=event.at+1000);
  const matches=inWindow.filter(o=>o.event==='websocket'||o.viaProxy||/ERR_TUNNEL_CONNECTION_FAILED|ERR_PROXY_/.test(o.failure||''));
  if(matches.length){const kinds=new Set(matches.map(m=>m.kind));if(kinds.size===1){const m=matches[0];return {...base,attribution:m.kind,evidenceSource:'cdp-observation',frameId:m.frameId,initiator:m.initiator,resourceType:m.type||base.resourceType,evidence:`Matched a ${m.kind} network observation (${m.event}${m.failure?' '+m.failure:''}) within the attribution window; the request escaped routing and was denied at the proxy.`};}
    return {...base,attribution:'unknown',evidenceSource:'cdp-observation',candidates:[...kinds],evidence:'Several target channels ('+[...kinds].join(', ')+') observed matching traffic in the attribution window; the initiator is ambiguous and stays unknown.'};}
  if(base.attribution!=='unknown')return base;
  if(event.phase==='pre-navigation')return {...base,attribution:'background',evidenceSource:'pre-navigation',evidence:'Observed before any target document was requested in this fresh browser; proven browser background activity, denied at the proxy and never forwarded.'};
  const complete=coverage.cdpObserved===true&&(!coverage.truncated||observations.length>0&&observations[0].at<=event.at-3000);
  const service=complete&&!inWindow.length&&!base.targetOrigin?chromeServiceHost(event):undefined;
  if(service)return {...base,attribution:'background',evidenceSource:'chrome-service-host',evidence:`Chrome's own service connection (${CHROME_SERVICE_HOSTS.get(service)}): no page, frame or worker requested ${service} in the attribution window and no request header ties it to a page. Denied at the proxy and never forwarded.`};
  return base;
}
/** Detail text of the aggregate, informational `browser-background-denied` gap. */
export function backgroundDetail(b:{count:number;preNavigation:number;service:number}):string{
  const parts:string[]=[];if(b.preNavigation)parts.push(`${b.preNavigation} observed before any target document was requested`);
  if(b.service)parts.push(`${b.service} from Chrome's own services (Google account cookie check, GCM check-in, component update check, AI Mode eligibility check) that no page, frame or worker requested`);
  return `${b.count} browser background connection${b.count===1?' was':'s were'} denied at the proxy and never forwarded: ${parts.join('; ')}. They do not make the scan incomplete. A connection that a page, frame or worker made to the same host is accounted as that page's traffic, and any other unattributed connection keeps the scan incomplete.`;
}
