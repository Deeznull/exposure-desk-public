import type {BrowserContext,Page,CDPSession} from 'playwright';
import {performance} from 'node:perf_hooks';
import type {NetObservation} from './browser-provenance.js';
type Channel={send:(method:string,params?:any)=>Promise<any>;on:(event:string,handler:(params:any)=>void)=>void;key:string;url:()=>string;kind:string};
export interface AttachOptions {scripts?:boolean;network?:boolean;onScript?:(channel:Channel,event:any)=>void;onNetwork?:(observation:NetObservation)=>void;onGap:(code:string,detail:string)=>void;onOwned?:()=>void;proxyPort?:number}
/** Attach only descendants of this page in its fresh isolated browser context. Observes `Network.*` on page, iframe and worker sessions (never intercepts) and optionally captures loaded scripts. */
export async function attachTargets(context:BrowserContext,page:Page,options:AttachOptions,signal?:AbortSignal){
 const {scripts=true,network=true,onScript,onNetwork,onGap,onOwned=()=>{},proxyPort}=options;
 const root=await context.newCDPSession(page);
 // A killed Chromium target can leave a root CDP reply unresolved. Bound root
 // commands as well as descendant commands, and settle them on scan cancellation.
 const send=(method:string,params?:any):Promise<any>=>new Promise((resolve,reject)=>{
  let settled=false;const done=(error?:Error,value?:any)=>{if(settled)return;settled=true;clearTimeout(timer);signal?.removeEventListener('abort',cancel);error?reject(error):resolve(value);};
  const cancel=()=>done(new Error('Debugger cancelled')),timer=setTimeout(()=>done(new Error('CDP target timeout')),1500);
  signal?.addEventListener('abort',cancel,{once:true});if(signal?.aborted){cancel();return;}
  (root.send as any)(method,params).then((value:any)=>done(undefined,value),()=>done(new Error('CDP delivery failed')));
 });
 const info=await send('Target.getTargetInfo'),contextId=info.targetInfo.browserContextId;
 if(!contextId)throw new Error('Isolated context identity unavailable');
 let targets=0,closed=false,mainFrameId='';const channels=new Set<Channel>(),pending=new Set<Promise<unknown>>(),observations:NetObservation[]=[],requestUrls=new Map<string,{url:string;kind:NetObservation['kind'];frameId?:string;type?:string;initiator?:string}>();
 const track=(p:Promise<unknown>)=>{pending.add(p);void p.finally(()=>pending.delete(p)).catch(()=>{});};
 const observe=(o:NetObservation)=>{if(observations.length>=2000)observations.shift();observations.push(o);onNetwork?.(o);};
 const hostPort=(url:string)=>{try{const u=new URL(url);return u.hostname.toLowerCase()+':'+(u.port||(/^(?:https|wss):$/.test(u.protocol)?'443':'80'));}catch{return '';}};
 const attach=async(channel:Channel)=>{
  channels.add(channel);const ownedWorlds=new Set<number>();
  const kind=(frameId?:string):NetObservation['kind']=>channel.kind==='worker'?'worker':channel.kind==='iframe'||frameId&&mainFrameId&&frameId!==mainFrameId?'frame':'page';
  if(scripts){
   channel.on('Runtime.executionContextCreated',event=>{const c=event.context;if(c.auxData?.isDefault===false&&/^__playwright_utility_world_page@[a-f0-9]+$/.test(c.name))ownedWorlds.add(c.id);});
   channel.on('Runtime.executionContextDestroyed',event=>ownedWorlds.delete(event.executionContextId));
   channel.on('Debugger.scriptParsed',event=>{if(closed||signal?.aborted)return;if(ownedWorlds.has(event.executionContextId))onOwned();else onScript?.(channel,event);});
  }
  if(network){
   channel.on('Network.requestWillBeSent',event=>{if(closed)return;const url=String(event.request?.url||'');if(!/^(?:https?|wss?):/.test(url))return;const k=kind(event.frameId),initiator=event.initiator?.url||event.initiator?.type;requestUrls.set(event.requestId,{url,kind:k,frameId:event.frameId,type:event.type,initiator});if(requestUrls.size>4000)requestUrls.delete(requestUrls.keys().next().value!);observe({at:performance.now(),kind:k,event:'request',requestId:String(event.requestId),frameId:event.frameId,url,hostPort:hostPort(url),type:event.type,initiator});});
   channel.on('Network.loadingFailed',event=>{if(closed)return;const r=requestUrls.get(event.requestId);if(!r)return;observe({at:performance.now(),kind:r.kind,event:'failed',requestId:String(event.requestId),frameId:r.frameId,url:r.url,hostPort:hostPort(r.url),type:r.type,initiator:r.initiator,failure:String(event.errorText||'').slice(0,80)});});
   channel.on('Network.responseReceived',event=>{if(closed)return;const r=requestUrls.get(event.requestId);if(!r)return;const remotePort=event.response?.remotePort,remoteIp=String(event.response?.remoteIPAddress||'');observe({at:performance.now(),kind:r.kind,event:'response',requestId:String(event.requestId),frameId:r.frameId,url:r.url,hostPort:hostPort(r.url),type:r.type,initiator:r.initiator,viaProxy:!!proxyPort&&remotePort===proxyPort&&/^(?:127\.0\.0\.1|::1|\[::1\])$/.test(remoteIp)});});
   channel.on('Network.webSocketCreated',event=>{if(closed)return;const url=String(event.url||'');observe({at:performance.now(),kind:channel.kind==='worker'?'worker':'page',event:'websocket',url,hostPort:hostPort(url),initiator:event.initiator?.url||event.initiator?.type});});
  }
  channel.on('Target.attachedToTarget',event=>track((async()=>{
   const target=event.targetInfo;
   channel.on('Target.targetInfoChanged',changed=>{if(changed.targetInfo.targetId===target.targetId&&changed.targetInfo.browserContextId===contextId)Object.assign(target,changed.targetInfo);});
   if(closed||++targets>24||target.browserContextId!==contextId||!['worker','iframe'].includes(target.type)){
    onGap('debugger-target-rejected','A debugger descendant was outside the isolated context, unsupported or over the 24-target cap; its channel remains uninspected.');
    await channel.send('Target.sendMessageToTarget',{sessionId:event.sessionId,message:JSON.stringify({id:1,method:'Runtime.runIfWaitingForDebugger'})}).catch(()=>{});await channel.send('Target.detachFromTarget',{sessionId:event.sessionId}).catch(()=>{});return;
   }
   const handlers=new Map<string,((params:any)=>void)[]>(),calls=new Map<number,{resolve:(v:any)=>void;reject:(e:Error)=>void;timer:ReturnType<typeof setTimeout>}>();let sequence=10;
   const child:Channel={key:channel.key+'/'+target.targetId,kind:target.type,url:()=>/^https?:/.test(target.url)?target.url:page.url(),on:(event,handler)=>{const list=handlers.get(event)||[];list.push(handler);handlers.set(event,list);},send:async(method,params={})=>{
    if(closed||signal?.aborted)throw new Error('closed');const id=sequence++;return new Promise((resolve,reject)=>{const timer=setTimeout(()=>{calls.delete(id);reject(new Error('CDP target timeout'));},1500);calls.set(id,{resolve,reject,timer});channel.send('Target.sendMessageToTarget',{sessionId:event.sessionId,message:JSON.stringify({id,method,params})}).catch(()=>{clearTimeout(timer);calls.delete(id);reject(new Error('CDP delivery failed'));});});
   }};
   channel.on('Target.receivedMessageFromTarget',message=>{if(message.sessionId!==event.sessionId)return;let data:any;try{data=JSON.parse(message.message);}catch{return;}if(data.id){const call=calls.get(data.id);if(call){clearTimeout(call.timer);calls.delete(data.id);data.error?call.reject(new Error('CDP command rejected')):call.resolve(data.result);}}else for(const handler of handlers.get(data.method)||[])handler(data.params);});
   channel.on('Target.detachedFromTarget',message=>{if(message.sessionId!==event.sessionId)return;for(const call of calls.values()){clearTimeout(call.timer);call.reject(new Error('Target detached'));}calls.clear();channels.delete(child);});
   if(target.type==='iframe')child.on('Page.frameNavigated',changed=>{if(!changed.frame.parentId||changed.frame.url)target.url=changed.frame.url;});
   try{await attach(child);if(target.type==='iframe')await child.send('Page.enable');}catch{onGap('debugger-target-unavailable','Dedicated worker or separate frame process could not enable debugger capture. Routed responses remain inspected.');}finally{await child.send('Runtime.runIfWaitingForDebugger').catch(()=>{});}
  })()));
  // Network observation is dispatched first so a paused worker's very first fetch is still observed once it resumes; the enables run concurrently.
  await Promise.all([...(network?[channel.send('Network.enable',{maxTotalBufferSize:1048576,maxResourceBufferSize:262144}).catch(()=>onGap('network-observation-unavailable','CDP network observation could not be enabled on this target; attribution of unrouted traffic falls back to header and phase evidence.'))]:[]),...(scripts?[channel.send('Runtime.enable').then(()=>channel.send('Debugger.enable',{maxScriptsCacheSize:4194304}))]:[])]);
  try{await channel.send('Target.setAutoAttach',{autoAttach:true,waitForDebuggerOnStart:true,flatten:false,filter:[{type:'worker',exclude:false},{type:'iframe',exclude:false},{exclude:true}]});}catch{onGap('debugger-descendants-unavailable','This browser target does not support recursive worker/frame debugger attachment; descendant generated code is unknown.');}
 };
 const channel:Channel={key:info.targetInfo.targetId,kind:'page',url:()=>page.url(),send,on:(event,handler)=>(root.on as any)(event,handler)};
 await attach(channel);
 if(network)try{const tree=await send('Page.getFrameTree');mainFrameId=String(tree?.frameTree?.frame?.id||'');}catch{}
 return {drain:async()=>{await Promise.allSettled([...pending]);},close:async()=>{closed=true;await root.send('Target.setAutoAttach',{autoAttach:false,waitForDebuggerOnStart:false,flatten:false}).catch(()=>{});await root.detach().catch(()=>{});},count:()=>channels.size,observations:()=>observations as readonly NetObservation[],mainFrameId:()=>mainFrameId};
}
/** Compatibility wrapper: script capture only, as before. */
export async function attachDebuggerTargets(context:BrowserContext,page:Page,onScript:(channel:Channel,event:any)=>void,onGap:(code:string,detail:string)=>void,onOwned:()=>void=()=>{},signal?:AbortSignal){return attachTargets(context,page,{scripts:true,network:false,onScript,onGap,onOwned},signal);}
