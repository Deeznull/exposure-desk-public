import http from 'node:http';
import type {Socket} from 'node:net';
import {createHash} from 'node:crypto';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { readFile, rm, readdir, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { existsSync } from 'node:fs';
import {performance} from 'node:perf_hooks';
import { chromium, type Frame, type Page, type Request } from 'playwright';
import { privateDirectory, writeProfileMarker } from './local-files.js';
import { PolicyError, AnalysisDeferred } from './transport.js';
import type { Scanner } from './scanner.js';
import { decodeText } from './decoding.js';
import { dedicatedBrowser, browserSandboxArgs, browserCrashArgs } from './runtime-paths.js';
import {attachTargets} from './browser-debugger.js';
import { classifyProxyEvent, backgroundDetail, proxyOrigins, type ProxyEvent, type NetObservation } from './browser-provenance.js';
import { extract, resolve as resolveReferences } from './discovery.js';
import {protectedHost} from './protected-hosts.js';
/** Chromium gets an allowlisted environment: no proxy variables, API keys or operator settings; temporary and home folders point into the fresh profile. */
export function browserEnvironment(dir:string):NodeJS.ProcessEnv{const tmp=path.join(dir,'tmp');if(process.platform==='win32'){const env:NodeJS.ProcessEnv={TEMP:tmp,TMP:tmp};for(const k of ['SystemRoot','windir','SystemDrive','PATH','PATHEXT','NUMBER_OF_PROCESSORS','PROCESSOR_ARCHITECTURE'])if(process.env[k])env[k]=process.env[k];return env;}return {PATH:process.env.PATH||'/usr/bin:/bin',HOME:dir,TMPDIR:tmp,XDG_CONFIG_HOME:path.join(dir,'config'),XDG_CACHE_HOME:path.join(dir,'cache'),XDG_DATA_HOME:path.join(dir,'data'),XDG_RUNTIME_DIR:tmp};}
const waitExit=(child:ChildProcess,ms:number)=>new Promise<boolean>(resolve=>{if(child.exitCode!==null||child.signalCode!==null)return resolve(true);const t=setTimeout(()=>resolve(false),ms);child.once('exit',()=>{clearTimeout(t);resolve(true);});});
async function boundedClose(close:()=>Promise<void>,ms:number){let timer:ReturnType<typeof setTimeout>|undefined,confirmed=false;try{await Promise.race([close().then(()=>{confirmed=true;}).catch(()=>{}),new Promise<void>(resolve=>{timer=setTimeout(resolve,ms);})]);return confirmed;}finally{clearTimeout(timer);}}
/** Scanner-authored page helpers; their exact source is excluded from runtime captures. Nothing here reads scanner state. */
const scrollHelper=()=>window.scrollBy(0,Math.min(window.innerHeight,900));
/** Page-leave guard, installed in every document by the init script (mode 'install') and, where the init script did not run (a popup's first about:blank),
 * by the scanner before it drains or closes the document. It is the first capturing listener for page-leave events and stops them before the page's own
 * handlers (capturing listeners run first at the window):
 * - a real (trusted) pagehide, pageswap or unload, and a trusted visibilitychange to hidden, always: Chromium sends the requests of a document that is being
 *   replaced, removed or closed without the route (a removed frame's requests have no known frame), so those handlers never run for real;
 * - every page-leave event, beforeunload and the page's own dispatches included, once the document has been left (mode 'drain' or 'arm').
 * Mode 'drain' runs the page-leave handlers once, through a synthetic pagehide, while the document is alive and routed: their beacons and keep-alive requests
 * reach the guarded transport (and its method policy). It returns whether the handlers ran (false once the document has been left).
 * document.open() erases the window's event listeners: the listeners are added again synchronously after open/write/writeln, for calls borrowed from another
 * realm through that document's own guard, and otherwise from a mutation observer on the document's children. A write to a document without a parser
 * opens it implicitly and runs the written scripts before it returns: the open is made explicit first, so the guard is back before those scripts add theirs
 * (listeners at the window run in the order they were added).
 * A cross-document navigation the document starts or receives (the navigation API's trusted navigate event; not a same-document, download, cancelled or
 * intercepted one) drains the document and its same-origin descendant frames in a task after the event, while the scanner holds the navigation (see
 * drainBefore): the scanner cannot reach a page whose main-frame navigation is pending. A navigation from a cross-origin document does not fire the event;
 * its documents leave without running their handlers.
 * mode: 'install', 'drain' or 'arm'. Nothing here reads scanner state; its exact source is excluded from runtime captures. */
const pageLeaveGuard=(mode:string)=>{
  const g=globalThis as any,key=Symbol.for('exposure-desk.page-leave');let state=g[key] as {add:()=>void;leave:(run:boolean)=>boolean;tree:(run:boolean)=>boolean}|undefined;
  if(!state){
    let left=false;const types=['beforeunload','pagehide','pageswap','unload','visibilitychange'];
    const guard=(e:Event)=>{if(left||e.isTrusted&&e.type!=='beforeunload'&&(e.type!=='visibilitychange'||document.visibilityState==='hidden'))e.stopImmediatePropagation();};
    const leave=(run:boolean)=>{add();if(left)return false;try{if(run)dispatchEvent(new PageTransitionEvent('pagehide',{persisted:false}));}finally{left=true;}return run;};
    const tree=(run:boolean)=>{let ran=leave(run);for(let i=0;i<frames.length;i++)try{if((frames[i] as any)[key]?.tree(run))ran=true;}catch{}return ran;};
    const later=setTimeout,navigation=g.navigation as (EventTarget&{transition?:unknown})|undefined;
    const navigate=(e:any)=>{if(left||!e?.isTrusted||e.destination?.sameDocument!==false||e.hashChange||e.downloadRequest!=null)return;later(()=>{if(!left&&!e.defaultPrevented&&!navigation?.transition)tree(true);},0);};
    const add=()=>{for(const type of types)try{addEventListener(type,guard,true);}catch{}try{navigation?.addEventListener('navigate',navigate);}catch{}};
    state=Object.freeze({add,leave,tree});try{Object.defineProperty(g,key,{value:state,enumerable:false,writable:false,configurable:false});}catch{}
    add();
    try{const proto=Document.prototype as any;for(const name of ['open','write','writeln']){const d=Object.getOwnPropertyDescriptor(proto,name),original=d?.value;if(typeof original!=='function')continue;
      Object.defineProperty(proto,name,{...d,value:function(this:Document,...args:unknown[]){if(name!=='open')try{if(this?.defaultView&&this.readyState!=='loading')this.open();}catch{}try{return original.apply(this,args);}finally{try{(this?.defaultView as any)?.[key]?.add();}catch{}}}});}}catch{}
    try{new MutationObserver(()=>state!.add()).observe(document,{childList:true});}catch{}
  }else state.add();
  return mode==='install'?false:state.leave(mode==='drain');
};
const snapshotHelper=(limit:number)=>{
  let used=0;const take=(s:string)=>{const n=s.slice(0,Math.max(0,limit-used));used+=n.length;return n;};
  const storage:Record<string,string>={};let truncated=false;
  for(const [label,store]of [['localStorage',globalThis.localStorage],['sessionStorage',globalThis.sessionStorage]] as const){for(let i=0;i<Math.min(store.length,100);i++){const k=store.key(i)!;storage[`${label}:${k}`]=take(store.getItem(k)||'');}if(store.length>100)truncated=true;}
  const globals:Record<string,string>={};
  const visited=new WeakSet<object>();let nodes=0;
  const snapshot=(v:any,depth=0):any=>{if(++nodes>2000||depth>5)return '[snapshot limit]';if(typeof v==='string')return v.slice(0,limit);if(v===null||typeof v==='number'||typeof v==='boolean')return v;if(typeof v!=='object')return undefined;if(visited.has(v))return '[cycle]';visited.add(v);const out:Record<string,unknown>={};for(const k of Object.getOwnPropertyNames(v).slice(0,100)){const property=Object.getOwnPropertyDescriptor(v,k);if(property&&'value'in property)out[k]=snapshot(property.value,depth+1);}return out;};
  for(const key of Object.getOwnPropertyNames(globalThis).filter(k=>/config|^__env|^__NEXT_DATA__|^__NUXT__|firebase|runtime/i.test(k)).slice(0,50)){
    const d=Object.getOwnPropertyDescriptor(globalThis,key);
    if(!d||!('value'in d))continue; // Never invoke target getters.
    try{const value=JSON.stringify(snapshot(d.value));if(value)globals[key]=take(value);}catch{}
  }
  const rendered=take(document.documentElement?.outerHTML||'');
  return {storage,globals,rendered,truncated:truncated||used>=limit};
};
export async function inspectBrowser(scan:Scanner,options:{urls?:string[]}={}){
  const {config,transport,evidence}=scan;const signal=transport.signal;const originOwner=transport.originControl.current;const began=transport.originControl.now();const cleanup=async(close:()=>Promise<void>,ms:number)=>{if(!await boundedClose(close,ms))scan.gap({code:'browser-cleanup-limit',detail:'Browser cleanup did not confirm within '+ms+' ms; target work remains stopped.',incomplete:true});};
  scan.gap({code:'browser-disabled-channels',detail:'Service workers, WebSockets, WebRTC, WebTransport and downloads are disabled; the per-visit profile and its caches are deleted afterwards. No clicks/forms or user gestures; only normal page loading. Browser coverage is bounded and may differ from an ordinary browser.',incomplete:false});
  const inScope=(origin:string)=>transport.isAuthorized(origin)||transport.scope.classify(origin).class==='in-domain';
  // Deny-proxy events are buffered with sequence, time and phase, then classified against CDP observations once the page's evidence exists.
  let phase='pre-navigation',pageUrl='',eventSeq=0;const events:ProxyEvent[]=[];let eventOverflow=0;const background={count:0,hosts:[] as string[],preNavigation:0,service:0};
  // CDP network observation state for the Chrome-service-host rule: it applies only while every target channel is observed and the bounded record is complete.
  const observation={complete:true,total:0};
  const proxyBlocked=(req:http.IncomingMessage,method:string)=>{
    const url=req.url||'unrouted browser traffic',text=[url,JSON.stringify(req.headers)].join('\n').slice(0,65536);
    for(const c of evidence.detector.inspectWindowed(text,false,evidence.analysis))evidence.add(c,text,url,['deny-only proxy'],'Locally blocked browser channel; never forwarded to target');
    if(events.length>=500){eventOverflow++;scan.gap({code:'browser-proxy-event-limit',detail:`Deny-proxy events beyond 500 per browser session were counted but not individually classified (${eventOverflow} further events).`,incomplete:true,count:eventOverflow});return;}
    events.push({seq:++eventSeq,at:performance.now(),method,authority:method==='CONNECT'?url:'',url:method==='CONNECT'?undefined:url,fetchDest:String(req.headers['sec-fetch-dest']||'')||undefined,purpose:String(req.headers['sec-purpose']||req.headers.purpose||'')||undefined,phase,pageUrl:pageUrl||undefined});
  };
  // Origins of the popup navigations the route aborted (see the route).
  const popupOrigins=new Set<string>();
  let classified=0;const classifyEvents=(observations:readonly NetObservation[])=>{
    for(;classified<events.length;classified++){const e=events[classified],provenance=classifyProxyEvent(e,observations,inScope,{cdpObserved:!!targets&&observation.complete,truncated:observation.total>observations.length}),target=proxyOrigins(e.url||e.authority)[0]||e.authority,url=e.url||target;
      if(provenance.attribution==='background'){background.count++;if(provenance.evidenceSource==='chrome-service-host')background.service++;else background.preNavigation++;const host=new URL(target).hostname;if(background.hosts.length<10&&!background.hosts.includes(host))background.hosts.push(host);transport.onResource({url,status:'blocked',analysis:'skipped',reason:'browser-background-denied',bytes:0,chain:['deny-only proxy',provenance.evidence],kind:'browser-proxy',provenance});scan.gap({code:'browser-background-denied',detail:backgroundDetail(background),incomplete:false,count:background.count,examples:[...background.hosts]});continue;}
      // Chromium may preconnect to a popup's host before the route aborts the popup: recorded, but not a dependency of the inspected page.
      const popupTraffic=(()=>{try{return popupOrigins.has(new URL(url).origin);}catch{return false;}})();
      if(protectedHost(url)){if(!popupTraffic)noteBlocked('scope',url);transport.recordBlocked(url,'protected-host',['deny-only proxy',provenance.evidence],'browser-proxy',provenance);continue;}
      if(!popupTraffic)noteBlocked('unrouted',url);transport.recordBlocked(url,'unrouted-browser-traffic',['deny-only proxy',provenance.evidence],'browser-proxy',provenance);}
    scan.browserStatus.background={count:background.count,hosts:[...background.hosts]};
  };
  const proxySockets=new Set<Socket>();const proxy=http.createServer((req,res)=>{proxyBlocked(req,req.method||'GET');res.writeHead(403,{'Connection':'close'});res.end();});
  proxy.on('connection',socket=>{proxySockets.add(socket);socket.on('error',()=>socket.destroy());socket.once('close',()=>proxySockets.delete(socket));});
  proxy.on('connect',(req,socket)=>{proxyBlocked(req,'CONNECT');socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');});
  proxy.on('upgrade',(req,socket)=>{proxyBlocked(req,'UPGRADE');socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');});
  await new Promise<void>(r=>proxy.listen(0,'127.0.0.1',r));
  const proxyPort=(proxy.address() as any).port;
  transport.deniedPorts.add(proxyPort);
  let dir:string|undefined,child:ReturnType<typeof spawn>|undefined,browser:Awaited<ReturnType<typeof chromium.connectOverCDP>>|undefined;
  // Isolation is reported as checked only after these are confirmed for this session; any false check marks the run's isolation failed.
  const checks:Record<string,boolean>={freshProfile:false,denyProxy:false,resolverBlocked:false,minimalEnvironment:false,ownDebugPort:false,routesBeforeNavigation:false,sharedWorkerDisabled:false};
  const pages:import('./types.js').PageReadiness[]=[];let current:import('./types.js').PageReadiness|undefined;
  // Blocked and unrouted dependencies of the page being loaded, by kind, with up to five example origins.
  const noteBlocked=(bucket:'scope'|'policy'|'unrouted',url:string)=>{if(!current)return;current.blocked[bucket]++;try{const o=new URL(url).origin;if(current.blocked.examples.length<5&&!current.blocked.examples.includes(o))current.blocked.examples.push(o);}catch{}};
  // A Playwright call can stay pending forever when the browser is killed mid-call (observed for newPage after a cancel), so every session await also settles on the stop and cleanup always runs.
  let stopSession=()=>{};const sessionStopped=new Promise<never>((_,reject)=>{stopSession=()=>reject(new Error('browser session stopped'));});sessionStopped.catch(()=>{});
  const live=<T>(p:Promise<T>):Promise<T>=>{p.catch(()=>{});return Promise.race([p,sessionStopped]);};
  const earlyStop=()=>{child?.kill();stopSession();};signal.addEventListener('abort',earlyStop,{once:true});
  let targets:Awaited<ReturnType<typeof attachTargets>>|undefined;
  try{
    transport.checkBudget();dir=await privateDirectory('browser-',scan.detector.syntheticFixture);checks.freshProfile=(await readdir(dir)).length===0;await writeProfileMarker(dir);await mkdir(path.join(dir,'tmp'),{recursive:true});
    const args=[`--user-data-dir=${dir}`,'--headless=new','--remote-debugging-port=0','--remote-debugging-address=127.0.0.1',
      `--proxy-server=http://127.0.0.1:${proxyPort}`,'--proxy-bypass-list=<-loopback>',
      '--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1','--disable-quic','--disable-background-networking','--disable-component-update','--disable-default-apps',
      '--disable-sync','--no-first-run','--no-default-browser-check','--disable-breakpad','--disable-crash-reporter',...browserCrashArgs(),'--disable-dev-shm-usage',
      '--disable-domain-reliability','--disable-client-side-phishing-detection','--disable-extensions',...browserSandboxArgs(),
      '--force-webrtc-ip-handling-policy=disable_non_proxied_udp','--webrtc-ip-handling-policy=disable_non_proxied_udp',
      '--disable-blink-features=WebTransport,DirectSockets,ServiceWorker,SharedWorker',
      '--disable-features=BackForwardCache,ServiceWorker,WebTransport,DirectSockets,Prerender2,SpeculationRules,PrefetchPrivacyChanges,OptimizationHints,OptimizationGuideModelDownloading,MediaRouter,Translate,PreconnectToSearch,AutofillServerCommunication,InterestFeedContentSuggestions',
      'about:blank'];
    // Launch only a bundled/new Chromium with a fresh private directory. CDP is
    // local and never passed to target pages; no existing browser is attached.
    const executable=process.env.SCANNER_CHROMIUM_PATH||(existsSync(chromium.executablePath())?chromium.executablePath():dedicatedBrowser()||chromium.executablePath());
    checks.denyProxy=args.includes(`--proxy-server=http://127.0.0.1:${proxyPort}`)&&args.includes('--proxy-bypass-list=<-loopback>');checks.resolverBlocked=args.includes('--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1');
    const env=browserEnvironment(dir);checks.minimalEnvironment=!Object.keys(env).some(k=>/proxy|key|token|secret|password/i.test(k));
    transport.checkBudget();child=spawn(executable,args,{stdio:'ignore',windowsHide:true,env});
    let launchError=false;child.on('error',()=>{launchError=true;});
    // The debugging endpoint comes from this fresh profile's DevToolsActivePort; connecting over ws:// keeps HTTP_PROXY/NO_PROXY out of the local CDP connection.
    let port=0,wsPath='';
    for(let i=0;i<100&&!signal.aborted;i++){
      if(launchError||child.exitCode!==null)throw new Error('browser launch failed');
      try{const lines=(await readFile(path.join(dir,'DevToolsActivePort'),'utf8')).split('\n');port=Number(lines[0]);wsPath=(lines[1]||'').trim();if(port&&/^\/devtools\/browser\/[\w-]+$/.test(wsPath))break;}catch{}
      await transport.sleep(100);
    }
    if(!port||!wsPath)throw new Error('browser launch timeout');transport.deniedPorts.add(port);
    browser=await live(chromium.connectOverCDP(`ws://127.0.0.1:${port}${wsPath}`,{timeout:config.timeoutMs}));checks.ownDebugPort=true;
    scan.browserStatus.launch=true;
    // An explicit locale and time zone: the operating system's language and zone never reach pages (the transport also overwrites Accept-Language).
    const context=await live(browser.newContext({serviceWorkers:'block',acceptDownloads:false,ignoreHTTPSErrors:false,viewport:{width:1280,height:900},locale:config.browserLocale||'en-US',timezoneId:config.browserTimezone||'UTC'}));
    const tasks=new Set<Promise<unknown>>(),resourceTasks=new Set<Promise<unknown>>();let lastActivity=Date.now(),analysisRunning=0,routing=true;
    // Analysis and debugger work waits for one of 128 slots; only routed requests count toward the request gate, so analysis backlog never aborts page requests.
    const analysisSlot=async<T>(task:()=>Promise<T>)=>{while(analysisRunning>=128&&!signal.aborted)await transport.sleep(10);analysisRunning++;try{return await task();}finally{analysisRunning--;}};
    const track=(p:Promise<unknown>,resource=false)=>{if(resource){lastActivity=Date.now();resourceTasks.add(p);}tasks.add(p);void p.finally(()=>{tasks.delete(p);if(resource){resourceTasks.delete(p);lastActivity=Date.now();}}).catch(()=>{});return p;};
    // Bounded readiness: one extension only while routed requests wait in the local rate-limit queue (never for denied or unrouted dependencies, which fail at once).
    const settle=async(url:string)=>{const began=Date.now();let deadline=began+Math.min(config.timeoutMs,Math.max(500,config.browserSettleMs*3)),extended=!!current?.extendedMs;
      while(!signal.aborted){if(!resourceTasks.size&&Date.now()-lastActivity>=config.browserSettleMs){if(current)current.settleMs=(current.settleMs||0)+Date.now()-began;return true;}
        if(Date.now()>=deadline){const q=transport.livePhases('browser');if(!extended&&q.localQueue>0&&resourceTasks.size){const extra=Math.max(0,Math.min(config.timeoutMs,Math.ceil(q.localQueue*1000/(config.originRequestsPerSecond??config.requestsPerSecond)),transport.remainingMs()-100));if(extra>0){extended=true;deadline+=extra;if(current)current.extendedMs=extra;continue;}}break;}
        await transport.sleep(50);}
      if(current)current.settleMs=(current.settleMs||0)+Date.now()-began;
      if(resourceTasks.size||Date.now()-lastActivity<config.browserSettleMs){const q=transport.livePhases('browser');if(current){current.pendingAtDeadline={localQueue:Math.max(current.pendingAtDeadline.localQueue,q.localQueue),network:Math.max(current.pendingAtDeadline.network,q.network)};for(const c of [...(q.localQueue?['local-rate-limit' as const]:[]),...(q.network?['network-wait' as const]:[]),'deadline' as const])if(!current.causes.includes(c))current.causes.push(c);}
        scan.gap({code:'browser-settle-deadline',url,detail:'Observed resource activity did not settle before the explicit page deadline'+(q.localQueue||q.network?` (${q.localQueue} request${q.localQueue===1?'':'s'} waiting in the local rate-limit queue, ${q.network} waiting on the network)`:'')+'; later modules/responses remain unknown.',incomplete:true});}return false;};
    const disableChannels=()=>{
      // Disable channels without dependable per-request interception. This contains
      // no scanner state or findings; it only removes outbound networking APIs and the cookie store API,
      // and keeps script-set cookies host-only like response cookies (a Domain attribute is dropped before storage).
      for(const key of ['RTCPeerConnection','webkitRTCPeerConnection','WebTransport','cookieStore'])try{Object.defineProperty(globalThis,key,{value:undefined,writable:false,configurable:false});}catch{}
      try{const d=Object.getOwnPropertyDescriptor(Document.prototype,'cookie'),get=d?.get,set=d?.set;if(get&&set)Object.defineProperty(Document.prototype,'cookie',{configurable:false,enumerable:d!.enumerable,get(){return get.call(this);},set(v){set.call(this,String(v).replace(/;\s*domain\s*=[^;]*/gi,''));}});}catch{}
    };
    // The page-leave guard is part of the init script, so it is the first listener of every document the init script runs in (see pageLeaveGuard).
    const ownedInit='('+disableChannels.toString()+')();('+pageLeaveGuard.toString()+')("install");';await live(context.addInitScript({content:ownedInit}));
    const ownedSources=[ownedInit,scrollHelper.toString(),snapshotHelper.toString(),pageLeaveGuard.toString()];
    checks.routesBeforeNavigation=true;
    // A frame evaluation that does not answer (a closing popup, a frame being replaced) never holds the scan: it is given up after `ms`.
    const within=<T>(p:Promise<T>,ms:number)=>{let timer:ReturnType<typeof setTimeout>|undefined;return Promise.race([live(p).catch(()=>undefined),new Promise<undefined>(r=>{timer=setTimeout(()=>r(undefined),ms);})]).finally(()=>clearTimeout(timer));};
    // The scanner's own page; every other page of the context is a popup (window.open, a target=_blank link or form), which is counted, never loaded and closed.
    // A popup's first navigation is requested before its frame exists (Playwright then has no frame for it): every page's frames exist before they navigate.
    let mainPage:Page|undefined;const fromPopup=(request:Request)=>{if(!mainPage)return false;try{return request.frame().page()!==mainPage;}catch{return request.isNavigationRequest();}};
    // Blocked requests sent by page-leave handlers the scanner runs (see drainBefore) are not page dependencies.
    let draining=0;
    // A WebSocket a page opens after its inspection has ended (the routing window is closed) is closed without inspection or discovery, as a request is aborted.
    await live(context.routeWebSocket('**/*',ws=>{if(!routing){ws.close({code:1008,reason:'Disabled'});return;}track(evidence.inspect(ws.url(),ws.url(),['observed WebSocket request'],'Locally observed WebSocket URL; channel disabled before connection'));scan.enqueue(ws.url(),options.urls?.[0]||config.urls[0],1,[options.urls?.[0]||config.urls[0],'observed WebSocket request'],'browser');ws.close({code:1008,reason:'Disabled'});}));
    const usedObservations=new WeakSet<NetObservation>();
    const workerObserved=(url:string,method:string)=>{const now=performance.now();for(const o of [...(targets?.observations()||[])].reverse()){if(o.kind!=='worker'||o.event!=='request'||o.url!==url||now-o.at>15000||usedObservations.has(o))continue;usedObservations.add(o);return true;}return false;};
    // Request sinks found in captured code, by channel kind. A worker may resume before this session's network observation is enabled;
    // a URL that is a request sink only in worker-channel code is then attributed to the worker with its own evidence label.
    const workerSinkUrls=new Set<string>(),pageSinkUrls=new Set<string>();
    const noteSinks=(kind:string,source:string,base:string,owner:string)=>{try{for(const ref of resolveReferences(extract(source,base,'runtime-capture'),{url:base,documentUrl:owner,imports:{}})){if(ref.unresolved||!ref.sink||!['fetch','xhr','request','import-scripts','worker','websocket','beacon','event-source','new-url'].includes(ref.sink))continue;let target='';try{target=new URL(ref.raw,ref.base).href;}catch{continue;}(kind==='worker'?workerSinkUrls:pageSinkUrls).add(target);}}catch{}};
    const workerBySource=(url:string)=>workerSinkUrls.has(url)&&!pageSinkUrls.has(url);
    const workerSourceEvidence='Playwright request routed through guarded Node transport; the URL is a request sink in code captured on a worker channel and in no page-channel capture. No network observation was available for the worker.';
    const reattributeFromSources=()=>{for(const r of scan.resources){if(r.kind!=='browser'||r.provenance?.channel!=='guarded-route'||r.provenance.attribution!=='page'||r.provenance.resourceType==='document'||!workerBySource(r.url))continue;r.provenance.attribution='worker';r.provenance.evidenceSource='worker-source';r.provenance.evidence=workerSourceEvidence;}};
    // Pre-navigation drain: a navigation a page starts itself (a link, a script, a frame navigating the top or itself) leaves the documents it replaces. Their
    // page-leave handlers run once while those documents are alive and routed, before the navigation is answered; the real page leave then stops at the guard.
    // A frame navigation drains that frame and its descendants here. A main-frame navigation cannot be drained from here: Chromium holds the page's DevTools
    // messages until the navigation commits, so the guard drains the page's frames itself from its navigate listener, which runs while the navigation is held.
    // Either way the navigation is held until the requests the handlers start are routed and answered (400 ms bound; 75 ms minimum for the guard's own drain). Blocks in that window
    // are not page dependencies. The scanner's own navigations (after its drain, see leave) are not held.
    const drainBefore=async(frame:Frame)=>{
      let main=false;const frames:Frame[]=[];
      try{if(!mainPage||frame.page()!==mainPage||!/^https?:/.test(frame.url()))return;main=frame===mainPage.mainFrame();if(main&&['pre-navigation','navigation','unload'].includes(phase))return;
        const walk=(f:Frame):void=>{frames.push(f);for(const c of f.childFrames())walk(c);};if(!main)walk(frame);}catch{return;}
      draining++;try{const before=new Set(resourceTasks);
        await Promise.all(frames.map(f=>within(f.evaluate(pageLeaveGuard,'drain'),1000)));
        const start=Date.now();while(Date.now()-start<400&&!signal.aborted){const fresh=[...resourceTasks].some(t=>!before.has(t));if(Date.now()-start>=(main?75:0)&&!fresh&&Date.now()-lastActivity>=50)break;await transport.sleep(25);}
      }finally{draining--;}
    };
    await live(context.route('**/*',route=>{
      const early=route.request(),popup=fromPopup(early);if(popup&&early.isNavigationRequest())try{popupOrigins.add(new URL(early.url()).origin);}catch{}
      // Hard rule: navigations and subrequests (images included) to a government, military, intelligence or law-enforcement host are aborted here, before any queue
      // or request. Popups are included (a popup is not a dependency of the inspected page).
      if(protectedHost(early.url())){if(!popup)noteBlocked('scope',early.url());transport.recordBlocked(early.url(),'protected-host',[popup?'browser popup':'observed browser request'],'browser');return route.abort('blockedbyclient');}
      // The routing window closes at the cleanup, with the capture window: a request a page timer starts after its inspection has ended is aborted, never sent
      // and not recorded, as requests after the session closes never were (its analysis would start after the cleanup's wait began and could stay pending).
      if(!routing)return route.abort('blockedbyclient');
      // A popup is never loaded. Its navigation is a discovered URL: enqueued, it gets the scan's own scope, protected-host and request rules (an out-of-scope URL is
      // recorded as excluded). Any other request of a popup (a document its opener wrote) is screened locally and recorded as blocked. The popup is closed (see 'page').
      if(popup){
        const url=early.url(),opener=mainPage?.mainFrame().url()||'',base=/^https?:/.test(opener)?opener:options.urls?.[0]||config.urls[0];
        if(early.isNavigationRequest()&&early.method()==='GET'&&/^https?:/.test(url))scan.enqueue(url,base,1,[base,'browser popup'],'page');
        else{const supplied=[url,JSON.stringify(early.headers()),early.postData()||''].join('\n').slice(0,65536);for(const c of evidence.detector.inspectWindowed(supplied,false,evidence.analysis))evidence.add(c,supplied,url,[base,'browser popup'],'Locally observed popup request; the popup was closed and the request never sent');transport.recordBlocked(url,'browser-popup',[base,'browser popup'],'browser');}
        return route.abort('blockedbyclient');
      }
      if(early.resourceType()==='image'&&scan.skipImage(early.url(),['observed browser image request'],'image'))return route.abort('blockedbyclient');
      if(resourceTasks.size>=Math.min(64,config.maxResources)){
        const req=route.request(),supplied=[req.url(),JSON.stringify(req.headers()),req.postData()||''].join('\n').slice(0,65536);
        for(const c of evidence.detector.inspectWindowed(supplied,false,evidence.analysis))evidence.add(c,supplied,req.url(),['browser request'],'Locally observed candidate; browser inspection queue full and request never sent');
        noteBlocked('policy',req.url());transport.recordBlocked(req.url(),'browser-queue-limit',[],'browser');return route.abort('blockedbyclient');
      }
      return track((async()=>{
      const leaving=draining>0||phase==='unload';
      const request=route.request(),url=request.url(),headers=await request.allHeaders(),body=request.postData()||'';
      let source='',parentFrame=false;try{source=request.frame().url();parentFrame=!!request.frame().parentFrame();}catch{}
      const navigation=request.isNavigationRequest(),chain=[source||'browser page','observed browser request'];
      if(navigation){try{await drainBefore(request.frame());}catch{}}
      scan.graphEdge(source||'isolated anonymous browser',url,'Observed request construction; script initiator unavailable','browser-request',url);
      // Every request carries its frame tree position (navigations included); worker requests are marked through a matching CDP observation after routing.
      const provenance:NonNullable<import('./types.js').Resource['provenance']>={channel:'guarded-route',attribution:request.serviceWorker()||request.resourceType()==='worker'?'worker':navigation||source?(parentFrame?'frame':'page'):'unknown',resourceType:request.resourceType(),source:source||undefined,targetOrigin:transport.isAuthorized(url),evidenceSource:'frame-tree',evidence:'Playwright request routed through guarded Node transport; frame tree position and resource type recorded. Missing initiator remains unknown.'};
      const markWorker=()=>{if(provenance.attribution==='worker')return;if(workerObserved(url,request.method())){provenance.attribution='worker';provenance.evidenceSource='cdp-observation';provenance.evidence='Playwright request routed through guarded Node transport; a matching worker-channel network observation attributes it to a worker.';}else if(!navigation&&workerBySource(url)){provenance.attribution='worker';provenance.evidenceSource='worker-source';provenance.evidence=workerSourceEvidence;}};
      try{
        // Site-created anonymous cookies may travel only within the same origin as the initiating document: the frame's own committed document
        // for its subresources; for a navigation, the embedding parent or the opening page (a new frame or popup has no committed http(s) document yet).
        // Only the scanner's own first top-level navigation has no initiating document. An unknown initiator never keeps a cookie.
        let principal='';try{const frame=request.frame(),parent=frame.parentFrame(),own=frame.url();if(!navigation)principal=own;else if(parent)principal=parent.url();else if(/^https?:/.test(own))principal=own;else{const opener=await frame.page().opener();principal=opener?opener.mainFrame().url():url;}}catch{}
        if(!/^https?:/.test(principal)||new URL(url).origin!==new URL(principal).origin)delete headers.cookie;
        if(headers.cookie){
          await evidence.inspect(headers.cookie,source||url,chain,'Fresh anonymous-visit cookies; not presumed privileged');
          // Provider-shaped secrets in cookies still fail closed. Ordinary session
          // values do not become serious findings just because they are random.
        }
        // The page's own document answered (or failed): the scan's optional work for the website may go out again (Scanner.browserHeld).
        let r=await transport.one(url,{method:request.method(),headers,body,chain,kind:'browser'}).finally(()=>{if(navigation&&!parentFrame)scan.browserDocumentSettled(new URL(url).origin);});
        markWorker();provenance.targetOrigin=transport.isAuthorized(url);if(r.resource?.servedFrom==='run-cache')provenance.evidence+=' Served from this run’s response cache (an identical, uncredentialed earlier guarded download); no request was sent.';if(r.resource)r.resource.provenance=provenance;
        const document=request.resourceType()==='document';
        // A fulfilled 3xx is followed by Chromium outside the route, so subresource redirects are followed here through the guarded transport
        // (each hop is preflighted and scope-checked by the transport) and the final response is delivered. Navigations keep the browser's own redirect.
        for(let hop=0;!document&&hop<6&&[301,302,303,307,308].includes(r.status)&&typeof r.headers.location==='string';hop++){
          const next=new URL(r.headers.location as string,r.url).href,hopChain=[...chain,r.url,'HTTP redirect'];
          track(analysisSlot(async()=>(async(prior:typeof r)=>{try{const text=await transport.analyze(prior,'Redirect response during unauthenticated browser loading');if(prior.resource?.analysis==='analyzed'&&text)await scan.discover(text,prior.url,1,chain,'browser',prior.headers);}catch(e){if(!(e instanceof AnalysisDeferred))throw e;}})(r)));
          r=await transport.one(next,{method:'GET',headers:{},body:'',chain:hopChain,kind:'browser'});if(r.resource)r.resource.provenance={...provenance,evidence:provenance.evidence+' Followed a same-scope redirect inside the guarded transport.'+(r.resource.servedFrom==='run-cache'?' Served from this run’s response cache; no request was sent.':'')};
        }
        // Response inspection must not hold browser delivery behind the native-engine queue.
        // Decode/check completeness before delivery; inspect the retained response separately.
        track(analysisSlot(async()=>{let text='';try{text=await transport.analyze(r,'Response during unauthenticated browser loading');}catch(e){if(e instanceof AnalysisDeferred){scan.deferAnalysis({url,depth:1,chain,kind:'browser'},e.response,e.cause,'browser','Response during unauthenticated browser loading');return;}throw e;}
          if(r.resource?.analysis!=='analyzed')return;const html=/text\/html|application\/xhtml/i.test(String(r.headers['content-type']))||/^\s*(?:<!doctype html|<html)/i.test(text.slice(0,512));
          if(r.status>=400){await scan.discover(text,r.url,1,chain,'error-response',r.headers);return;}
          if(/\.map(?:\?|$)/.test(url)){await scan.discover(text,r.url,1,chain,'map',r.headers);return;}
          if(document&&html){if(r.status>=200&&r.status<300)scan.rememberDocument(r.url,text);await scan.discover(text,r.url,1,chain,'page',r.headers);return;}
          if(html){const fallback=scan.classifyHtmlForAsset(r.url,request.resourceType()==='script'?'script':request.resourceType()==='stylesheet'?'css':'browser',text,chain);if(r.resource)r.resource.fallback=fallback;scan.discoverySummary.fallbacks[fallback.type]=(scan.discoverySummary.fallbacks[fallback.type]||0)+1;if(fallback.sameAs){scan.graphEdge(r.url,fallback.sameAs,'HTML fallback identical to an already discovered document; not re-discovered','page',fallback.sameAs,'fallback-duplicate');return;}await scan.discover(text,r.url,1,chain,'browser',{...r.headers,'content-type':'text/plain; charset=utf-8'});return;}
          await scan.discover(text,r.url,1,chain,'browser',r.headers);}));
        try{decodeText(r.body,r.headers,r.partial);}catch{throw new PolicyError('text-decoding');}
        if(r.partial)throw new PolicyError('partial-browser-response');
        if([301,302,303,307,308].includes(r.status)&&typeof r.headers.location==='string'){
          try{await transport.preflight(new URL(r.headers.location,url).href,'GET',{},'',chain);}catch(e){transport.recordBlocked(new URL(r.headers.location,url).href,e instanceof PolicyError?e.code:'redirect-policy',chain,'browser');throw e;}
        }
        if(/attachment/i.test(String(r.headers['content-disposition']))){transport.recordBlocked(url,'download-disabled',chain,'browser');throw new PolicyError('download-disabled');}
        const h:Record<string,string>={};
        for(const [k,v]of Object.entries(r.headers)){
          // Cross-origin privacy and policy still apply, including captured CSP.
          if(['content-length','transfer-encoding','connection','content-encoding','set-cookie','alt-svc','report-to','reporting-endpoints','nel'].includes(k))continue;
          if(typeof v==='string')h[k]=v;
        }
        if(r.headers['set-cookie']){
          // Let Chromium enforce Set-Cookie parsing through normal fulfilled headers. Cookies are stored host-only: a Domain attribute would let
          // Chromium attach one host's cookie to sibling hosts, where the route cannot tell who set it.
          h['set-cookie']=(Array.isArray(r.headers['set-cookie'])?r.headers['set-cookie']:[String(r.headers['set-cookie'])]).map(c=>c.replace(/;\s*domain\s*=[^;]*/gi,'')).join('\n');
        }
        await route.fulfill({status:r.status,headers:h,body:r.body});
      }catch(e){if(phase!=='unload'&&!leaving&&!draining)noteBlocked(e instanceof PolicyError?(['scope','protected-host'].includes(e.code)?'scope':'policy'):'policy',url);await new Promise(r=>setTimeout(r,20));markWorker();const blocked=[...scan.resources].reverse().find(r=>r.url===url&&r.kind==='browser'&&r.status==='blocked');if(blocked&&!blocked.provenance)blocked.provenance=provenance;await route.abort('blockedbyclient').catch(()=>{});}
    })(),true) as Promise<void>;
    }));
    context.on('page',p=>{p.on('dialog',d=>void d.dismiss());p.on('download',d=>void d.cancel());
      if(!mainPage||p===mainPage){mainPage=p;return;}
      // A popup (at any time, also after the inspection has ended): counted, its documents guarded and left without running their page-leave handlers (a closing
      // page's requests are not routed), then closed. The close is tracked, so the cleanup awaits it; a popup opened later still is closed with the context.
      const popups=scan.browserStatus.popups??(scan.browserStatus.popups={opened:0,closed:0});popups.opened++;p.once('close',()=>{popups.closed++;});
      track((async()=>{await Promise.all(p.frames().map(f=>within(f.evaluate(pageLeaveGuard,'arm'),500)));await boundedClose(()=>p.close({runBeforeUnload:false}),1500);})());
    });
    const close=()=>{child?.kill();stopSession();void context.close().catch(()=>{});};signal.addEventListener('abort',close,{once:true});
    // The session ends with the scan's or the website's time limit: the limit is expired, which closes it through the signal.
    const duration=transport.limitTimer(Infinity,close);
    try{
      const page=await live(context.newPage());mainPage=page;
      try{checks.sharedWorkerDisabled=await live(page.evaluate(()=>typeof (globalThis as any).SharedWorker==='undefined'));}catch{}
      scan.browserStatus.isolationChecks={...checks};scan.browserStatus.isolation=scan.browserStatus.isolation==='failed'||Object.values(checks).some(v=>!v)?'failed':'checked';
      let debuggerCount=0,debuggerBytes=0,pendingDebugger=0,debuggerEvents=0,comparedBytes=0;const capturedHashes=new Set<string>();
      // Scripts are captured while pages are inspected; the window closes at cleanup (see there).
      let capturing=true;
      // Page-leave drain, for every page that has a document. The page-leave handlers of the page and its frames run once while routes are active:
      // their beacons and keep-alive fetches go through the guarded transport (its method policy blocks them; they are never sent). The drain waits
      // until those requests are routed and answered (no routed request in flight, no request seen by the network observation since the dispatch
      // still open) within its 400 ms bound. Each document's page-leave guard then stops its handlers from running again when the page is left or
      // closed: Chromium sends such requests of a document being replaced or closed without the route (on Linux, also at the context close), so
      // they reached the deny proxy as unrouted traffic.
      const leave=async()=>{
        if(signal.aborted||page.isClosed()||!/^https?:/.test(page.url()))return;
        phase='unload';const since=performance.now();
        await Promise.all(page.frames().map(frame=>within(frame.evaluate(pageLeaveGuard,'drain'),1000)));
        const open=()=>{const seen=new Map<string,boolean>();for(const o of targets?.observations()||[]){if(o.at<since||!o.requestId)continue;if(o.event==='request'){if(!seen.has(o.requestId))seen.set(o.requestId,false);}else if(o.event==='failed'||o.event==='response')seen.set(o.requestId,true);}return [...seen.values()].includes(false);};
        const drainStart=Date.now();while(Date.now()-drainStart<400&&!signal.aborted&&!page.isClosed()){if(Date.now()-drainStart>=150&&!resourceTasks.size&&Date.now()-lastActivity>=100&&!open())break;await transport.sleep(25);}
      };
      const onScript=(session:{send:(method:string,params?:any)=>Promise<any>;url:()=>string;kind:string;key:string},event:any)=>{
        if(!capturing||!/^https?:/.test(session.url()))return;if(debuggerEvents++>=256){scan.gap({code:'debugger-event-limit',detail:'Source collection bounded to 256 non-owned script events (64 unique bodies). Further scripts unknown.',incomplete:true});return;}if(debuggerCount+pendingDebugger>=64){scan.gap({code:'debugger-script-count',detail:'Debugger source capture limited to 64 scripts per browser session.',incomplete:true});return;}
        pendingDebugger++;track(analysisSlot(async()=>{try{
          const owner=session.url(),reported=/^https?:/.test(String(event.url||''))&&!event.hasSourceURL?String(event.url):'';
          // A large script whose reported URL was already analyzed is verified as a mirror by content hash instead of recording a capture gap.
          if(event.length!==undefined&&event.length>131072){const analyzed=reported?scan.resources.find(r=>r.url===reported&&r.contentHash&&r.analysis==='analyzed'):undefined;const limit=Math.min(config.maxResourceBytes,8*1024*1024);
            if(analyzed&&event.length<=limit&&comparedBytes+event.length<=32*1024*1024){comparedBytes+=event.length;const result=await session.send('Debugger.getScriptSource',{scriptId:event.scriptId});const hash=createHash('sha256').update(result.scriptSource).digest('hex');if(hash===analyzed.contentHash){scan.browserAnalysis.verifiedMirrors++;scan.graphEdge(owner,reported,'Debugger script verified as an exact mirror of an analyzed response by content hash','debugger-script',reported,'verified-mirror');return;}}
            scan.gap({code:'debugger-script-size',url:page.url(),detail:'Debugger code limited to known-length scripts, 128 KiB per script and 4 MiB total; oversized unique source was not collected.',incomplete:true});return;}
          if(event.length===undefined||debuggerBytes+event.length>4194304){scan.gap({code:'debugger-script-size',url:page.url(),detail:'Debugger code limited to known-length scripts, 128 KiB per script and 4 MiB total; oversized/unknown source was not collected.',incomplete:true});return;}
          const result=await session.send('Debugger.getScriptSource',{scriptId:event.scriptId});const sourceBytes=Buffer.byteLength(result.scriptSource);if(sourceBytes>131072||debuggerBytes+sourceBytes>4194304){scan.gap({code:'debugger-script-size',url:page.url(),detail:'Captured source exceeds the 128 KiB UTF-8 per-source or 4 MiB total bound; text/semantic capture not inspected.',incomplete:true});return;}
          if(ownedSources.some(s=>result.scriptSource===s||result.scriptSource.includes(s))){scan.browserAnalysis.ownedHelpers++;return;}
          noteSinks(session.kind,result.scriptSource,reported||owner,owner);
          const sourceHash=createHash('sha256').update(result.scriptSource).digest('hex'),label=session.kind+' debugger script '+event.scriptId+(event.url?' (reported source URL; attribution unverified)':' (generated; no source URL)'),captureUrl=owner+'#debugger-'+session.key.replaceAll('/','-')+'-'+event.scriptId;
          // Repeated captures across sessions reuse the canonical capture: they count no session budget and add provenance, never a second record.
          const canonical=scan.registerRuntimeCapture(sourceHash,captureUrl,owner);
          if(canonical){scan.browserAnalysis.reusedDebugger++;await evidence.inspect(result.scriptSource,owner,[owner,'Debugger loaded script'],'Debugger captured code during isolated anonymous loading; local runtime evidence',label);return;}
          const duplicate=capturedHashes.has(sourceHash);if(duplicate)scan.browserAnalysis.reusedDebugger++;else{if(debuggerCount>=64)return;capturedHashes.add(sourceHash);debuggerCount++;debuggerBytes+=sourceBytes;scan.browserAnalysis.capturedDebugger++;if(originOwner)originOwner.runtimeCaptures++;}
          const capture:import('./types.js').Resource={url:captureUrl,kind:'runtime-capture',resourceType:'runtime-capture',bytes:sourceBytes,status:'downloaded',analysis:'pending',chain:[owner,'Debugger loaded script'],contentHash:sourceHash,analyzers:{debugger:{status:'inspected',reused:duplicate,contentHash:sourceHash}}};if(scan.resources.length<6000)scan.resources.push(capture);
          await evidence.inspect(result.scriptSource,owner,[owner,'Debugger loaded script'],'Debugger captured code during isolated anonymous loading; local runtime evidence',label);capture.analysis='analyzed';capture.analyzers!.directText={status:'inspected'};
          // Discovery uses the reported script URL (or the capture key) as its base and the page as the document; the capture is admitted once, below, never under the page URL.
          await scan.discover(result.scriptSource,reported||captureUrl,1,[owner,'Debugger loaded script'],'runtime-capture',{},true,owner);scan.addModule(result.scriptSource,captureUrl,label,{},reported||undefined);scan.graphEdge(owner,event.url||label,'Debugger loaded script; reported URL does not establish public reachability','debugger-script',undefined,'runtime-captured');
        }catch{scan.gap({code:'debugger-source-unavailable',url:page.url(),detail:'Debugger could not provide a parsed script source; other channels retained.',incomplete:true});}finally{pendingDebugger--;}}));
      };
      try{targets=await live(attachTargets(context,page,{scripts:config.debuggerScripts!==false,network:true,onScript,onGap:(code,detail)=>{if(code==='network-observation-unavailable')observation.complete=false;scan.gap({code,detail,incomplete:true});},onNetwork:()=>{observation.total++;},onOwned:()=>{scan.browserAnalysis.ownedHelpers++;},proxyPort},signal));}catch{observation.complete=false;scan.gap({code:config.debuggerScripts!==false?'debugger-unavailable':'network-observation-unavailable',detail:config.debuggerScripts!==false?'Debugger source interception unavailable; runtime storage/configuration and routed responses retained.':'CDP network observation unavailable; unrouted traffic attribution relies on header and phase evidence.',incomplete:true});}
      if(config.debuggerScripts===false)scan.gap({code:'debugger-disabled',detail:'Loaded generated script source capture disabled; browser-generated code may remain unseen.',incomplete:true});
      // Baseline idle window: traffic observed before any target document is requested is proven background activity. Chrome's own later
      // retries to the fixed CHROME_SERVICE_HOSTS list count as background only when no page, frame or worker touched that host (browser-provenance.ts).
      if(config.browserBaselineMs)await transport.sleep(config.browserBaselineMs);
      const urls=options.urls??[];
      if(scan.browserNavigationCandidates().length>config.browserPages)scan.gap({code:'browser-page-budget',detail:'Runtime inspection limited to configured page count.',incomplete:true});
      for(const url of urls){
        if(signal.aborted)break;transport.checkBudget();
        const navStarted=Date.now(),rec:import('./types.js').PageReadiness={url,verdict:'ready',causes:[],pendingAtDeadline:{localQueue:0,network:0},blocked:{scope:0,policy:0,unrouted:0,examples:[]}};current=rec;if(pages.length<50)pages.push(rec);
        try{
          phase='navigation';pageUrl=url;
          const navigation=await live(page.goto(url,{waitUntil:'commit',timeout:Math.max(1,Math.min(transport.remainingMs(),Math.max(20000,config.timeoutMs*4)))}));
          if(navigation&&navigation.status()>=200&&navigation.status()<300&&scan.firstBrowserDocument===undefined)scan.firstBrowserDocument=Date.now()-transport.started;
          rec.commitMs=Date.now()-navStarted;
          if(!navigation||navigation.status()<200||navigation.status()>=300){rec.verdict='failed';rec.causes.push('navigation-failed');scan.gap({code:'browser-page-http-unavailable',url,detail:'Runtime source inspection skipped because navigation did not return a successful public page.',incomplete:true});continue;}
          try{await live(page.waitForLoadState('domcontentloaded',{timeout:config.timeoutMs}));rec.domReadyMs=Date.now()-navStarted;}catch{rec.causes.push('dom-not-ready');scan.gap({code:'browser-readiness-timeout',url,detail:'A successful document committed but DOM readiness was not observed within the limit. Available rendered/config/storage content is still inspected; application readiness and missing scripts remain unknown.',incomplete:true});}
          phase='settle';await settle(url);if(targets)await live(targets.drain());transport.checkBudget();
          phase='scroll';for(let i=0;i<config.browserScrollSteps;i++){transport.checkBudget();await live(page.evaluate(scrollHelper));await transport.delay(config.browserScrollDelayMs);}
          if(config.browserLazyAssetLimit){let loaded=0;for(const item of [...scan.queue].filter(w=>/script|module/.test(w.kind)&&new URL(w.url).origin===new URL(url).origin).slice(0,config.browserLazyAssetLimit)){transport.checkBudget();try{if(await scan.inspectQueuedLazyAsset(item))loaded++;}catch{scan.gap({code:'lazy-asset-unavailable',url:item.url,detail:'Discovered lazy asset could not be inspected under existing request controls.',incomplete:true});}}if(loaded===config.browserLazyAssetLimit&&scan.queue.some(w=>/module/.test(w.kind)))scan.gap({code:'browser-lazy-asset-limit',url,detail:'Explicit lazy-asset count reached; remaining discovered modules retain static queue coverage.',incomplete:true});}
          // Await dispatched guarded requests under the shared scan deadline, then
          // snapshot runtime values before draining offline response analysis.
          await Promise.allSettled([...resourceTasks]);transport.checkBudget();
          phase='settle';await settle(url);if(targets)await live(targets.drain());reattributeFromSources();
          phase='snapshot';
          for(const frame of page.frames()){
            const frameUrl=frame.url();if(!frameUrl.startsWith('http'))continue;
            const navigationResource=[...scan.resources].reverse().find(r=>r.url===frameUrl.split('#')[0]&&r.kind==='browser'&&r.provenance?.resourceType==='document');
            if(!navigationResource||!navigationResource.code||navigationResource.code<200||navigationResource.code>=300)continue;
            const result=await live(frame.evaluate(snapshotHelper,Math.min(config.maxResourceBytes,262144)));
            const snapshots=[{text:JSON.stringify(result.globals),chain:[url,'runtime configuration'],description:'Own enumerable/static runtime configuration; getters were not invoked',label:'runtime globals (no source line)'},{text:JSON.stringify(result.storage),chain:[url,'fresh browser storage'],description:'Storage created by a fresh unauthenticated visit',label:'storage (no source line)'},{text:result.rendered,chain:[url,'rendered page'],description:'Rendered unauthenticated page',label:'rendered DOM snapshot'}];
            for(const snapshot of snapshots){for(const candidate of evidence.detector.inspectWindowed(snapshot.text,true,evidence.analysis))evidence.add(candidate,snapshot.text,frameUrl,snapshot.chain,snapshot.description,snapshot.label);track(evidence.inspect(snapshot.text,frameUrl,snapshot.chain,snapshot.description,snapshot.label));track(scan.discover(snapshot.text,frameUrl,1,snapshot.chain,snapshot.label==='rendered DOM snapshot'?'page':'framework-data'));}
            if(result.truncated)scan.gap({code:'runtime-size-limit',url:frameUrl,detail:'Runtime DOM/config/storage snapshot bounded by inspection budget.',incomplete:true});
          }
          scan.browserStatus.runtimePages++;if(originOwner)originOwner.browserPages++;
        }catch{rec.verdict='failed';if(!rec.causes.includes('navigation-failed'))rec.causes.push('navigation-failed');scan.gap({code:'browser-page-failure',url,detail:'Page load/runtime inspection unavailable, blocked or timed out; no login or user interaction attempted.',incomplete:true});}
        finally{await leave().catch(()=>{});classifyEvents(targets?.observations()||[]);if(rec.blocked.scope+rec.blocked.policy&&!rec.causes.includes('blocked-dependency'))rec.causes.push('blocked-dependency');if(rec.blocked.unrouted&&!rec.causes.includes('unrouted-dependency'))rec.causes.push('unrouted-dependency');if(rec.verdict!=='failed'&&rec.causes.length)rec.verdict='partial';scan.browserStatus.pages=[...(scan.browserStatus.pages||[]),rec].slice(-50);current=undefined;}
      }
      phase='cleanup';
      // The capture window closes before the wait below lists the tasks, so every capture started is analysed before the session returns. A script parsed from
      // now on (Chromium's own scripts about a second after loading, a page timer) would start after that list: its analysis could still be running when the scan
      // ends, leaving the capture pending ("Run ended before inspection"), or its source request could fail on the closing page. Such scripts are not captured,
      // as scripts parsed after the session closes never were.
      capturing=false;routing=false;
      // With both windows closed only work already started can add tasks (a routed response's analysis, a redirect hop), so the wait re-lists them until none is left.
      // After a stop, analysis and debugger tasks get one second to settle; a CDP call left pending by the killed browser never holds the stop.
      const settled=await Promise.race([(async()=>{while(tasks.size)await Promise.allSettled([...tasks]);return true;})(),sessionStopped.catch(()=>new Promise<boolean>(r=>setTimeout(()=>r(false),1000)))]);
      if(!settled)scan.gap({code:'browser-cleanup-limit',detail:'Some browser analysis tasks had not settled 1000 ms after the stop; target work remains stopped.',incomplete:true});
    }finally{duration.clear();signal.removeEventListener('abort',close);await boundedClose(()=>context.close(),1500);}
  }catch{scan.gap({code:'browser-unavailable',detail:'Isolated browser runtime could not finish. Install pinned Chromium and check local launch permissions. Static results remain available.',incomplete:true});}
  finally{classifyEvents(targets?.observations()||[]);signal.removeEventListener('abort',earlyStop);if(originOwner)originOwner.browserElapsedMs+=Math.max(0,transport.originControl.now()-began);
    // Close through a browser-level CDP session (a CDP-connected browser.close only disconnects), wait for the process to exit, then confirm the profile is gone.
    // After a cancel or deadline the process was already killed: cleanup stays prompt (short bounds, one removal pass, then a background retry and the startup sweep).
    const stopped=signal.aborted;
    if(browser){const viaCdp=!stopped&&await boundedClose(async()=>{const cdp=await browser!.newBrowserCDPSession();await cdp.send('Browser.close');},1500);if(!viaCdp)await boundedClose(()=>browser!.close(),500);}
    let exited=!child||await waitExit(child,stopped?1000:3000);if(child&&!exited){child.kill();exited=await waitExit(child,1500);if(!exited&&process.platform==='win32'&&child.pid){spawnSync(path.join(process.env.SystemRoot||'C:\\Windows','System32','taskkill.exe'),['/PID',String(child.pid),'/T','/F'],{stdio:'ignore',windowsHide:true});exited=await waitExit(child,1500);}else if(!exited&&process.platform!=='win32'){child.kill('SIGKILL');exited=await waitExit(child,1500);}}
    for(const socket of proxySockets)socket.destroy();await boundedClose(()=>new Promise<void>(r=>{proxy.close(()=>r());proxy.closeAllConnections();}),500);
    let removed=!dir;if(dir){for(let i=0;i<(stopped?2:5)&&!removed;i++){await boundedClose(()=>rm(dir!,{recursive:true,force:true,maxRetries:3,retryDelay:100}).catch(()=>{}),1000);removed=!existsSync(dir);if(!removed)await new Promise(r=>setTimeout(r,200));}if(!removed){const later=dir;setTimeout(()=>{void rm(later,{recursive:true,force:true,maxRetries:5,retryDelay:200}).catch(()=>{});},5000).unref();}if(!removed)scan.gap({code:'browser-cleanup',detail:'Fresh profile removal could not be confirmed; the next start removes orphaned profiles, or run cleanup after closing scanner processes.',incomplete:true});}
    scan.browserStatus.cleanup=scan.browserStatus.cleanup==='deferred'||!removed||!exited?'deferred':'confirmed';if(!exited)scan.gap({code:'browser-process-exit',detail:'The isolated browser process did not confirm exit within the cleanup bound.',incomplete:true});}
}
