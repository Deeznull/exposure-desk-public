import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { Scanner } from '../src/scanner.js';
import { Detector } from '../src/detectors.js';
import { PRODUCT_USER_AGENT } from '../src/transport.js';
/** Loopback page-leave guard fixtures (2.9 O4). Each listed page gets its own fresh browser session (one page per session); page-leave handlers send beacons.
 * A real page leave (a navigation, a frame removal, a closing popup) sends such requests without the route, so they reach the deny proxy: that is the observable leak. */
const html=(body:string)=>'<!doctype html><html><head><meta charset="utf-8"></head><body>'+body+'</body></html>';
const beacon=(path:string)=>`addEventListener('pagehide',function(){navigator.sendBeacon('${path}','x');});`;
/** A JavaScript string literal that can sit inside an inline script. */
const js=(s:string)=>JSON.stringify(s).replace(/<\//g,'<\\/');
async function scan(pages:Record<string,string>,visit:string[],extra:Record<string,unknown>={},hook?:(s:Scanner)=>void){
  const arrivals:{path:string;url:string;method:string;ua:string}[]=[];
  const server=http.createServer((req,res)=>{const p=(req.url||'/').split('?')[0];arrivals.push({path:p,url:req.url||'/',method:req.method||'GET',ua:String(req.headers['user-agent']||'')});req.resume();if(pages[p]){res.writeHead(200,{'content-type':'text/html'});res.end(pages[p]);}else{res.writeHead(404,{'content-type':'text/plain'});res.end('missing');}});
  await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));const origin=`http://127.0.0.1:${(server.address() as any).port}`;
  const s=new Scanner({urls:[origin+visit[0]],browserNavigationUrls:visit.slice(1).map(p=>origin+p),developmentFixtureOrigin:origin,browser:true,browserPages:visit.length,requestsPerSecond:20,adjacentMaps:false,semanticAnalysis:false,browserSettleMs:300,maxDurationMs:90000,...extra},{detector:new Detector('disabled')});
  hook?.(s);
  try{const began=Date.now();const v=await s.run();const elapsed=Date.now()-began;
    const proxied=v.resources.filter(r=>r.kind==='browser-proxy').map(r=>r.url.replace(origin,'')+' '+(r.provenance?.phase||''));
    const routed=(p:string)=>v.resources.filter(r=>r.url===origin+p&&r.kind==='browser');
    console.log(JSON.stringify({visit,elapsed,runtimePages:v.browserStatus?.runtimePages,proxied,arrivals:arrivals.filter(a=>!visit.includes(a.path)).map(a=>a.method+' '+a.url+(a.ua===PRODUCT_USER_AGENT?'':' [browser]')),popups:v.browserStatus?.popups,leaveRequests:v.resources.filter(r=>/beacon|popup-/.test(r.url)).map(r=>r.url.replace(origin,'')+' '+r.kind+' '+(r.status||'')+' '+(r.reason||'')+' '+(r.provenance?.phase||'')),pages:v.browserStatus?.pages?.map(p=>p.verdict+':'+p.causes.join('|'))}));
    return {v,s,origin,arrivals,proxied,routed,elapsed};
  }finally{s.dispose();await new Promise<void>(r=>{server.close(()=>r());server.closeAllConnections();});}
}
const noLeak=(r:Awaited<ReturnType<typeof scan>>,re:RegExp,what:string)=>{
  assert.equal(r.v.browserStatus!.launch,true,'Chromium must actually run');
  assert.deepEqual(r.proxied.filter(p=>re.test(p)),[],what+': no page-leave request reaches the deny proxy as unrouted traffic');
  assert.deepEqual(r.arrivals.filter(a=>re.test(a.path)&&a.method!=='GET'),[],what+': the browser never sends a page-leave request to the target');
  for(const p of r.v.browserStatus!.pages!)assert.ok(!p.causes.includes('unrouted-dependency'),what+': no page has unrouted dependencies: '+JSON.stringify(p));
};

// Gap 1: document.open() (explicit, implicit through a late document.write, and borrowed from another realm) erases the window's event listeners, the guard's
// included. Each replaced document's page-leave handler leaves the page once, after the scanner's drain has run it: the real page leave that follows must not
// run the handler again (its beacon would go out unrouted).
test('page-leave guard survives document.open() and document.write() replacing the document',{timeout:180000},async()=>{
  const leaveOnce=(path:string,win:string)=>`var gone=false;addEventListener('pagehide',function(){navigator.sendBeacon('${path}','x');if(!gone){gone=true;setTimeout(function(){${win}.location.href='/a/after';},30);}});`;
  const later=(code:string)=>`addEventListener('load',function(){setTimeout(function(){${code}},0);});`;
  const r=await scan({
    '/a/one':html('<h1>One</h1><script>'+later(`document.open();document.write(${js('<h1>Replaced</h1><script>'+leaveOnce('/a/beacon-open','self')+'</script>')});document.close();`)+'</script>'),
    '/a/two':html('<h1>Two</h1><script>'+later(`document.write(${js('<h1>Written</h1><script>'+leaveOnce('/a/beacon-write','self')+'</script>')});document.close();`)+'</script>'),
    '/a/three':html('<h1>Three</h1><iframe src="/a/frame"></iframe>'),
    '/a/frame':html('<script>'+later(`var f=document.createElement('iframe');document.body.appendChild(f);f.contentWindow.Document.prototype.open.call(document);document.write(${js('<p>borrowed</p><script>'+leaveOnce('/a/beacon-borrowed','top')+'</script>')});document.close();`)+'</script>'),
    '/a/after':html('<h1>After</h1>'),
  },['/a/one','/a/two','/a/three']);
  noLeak(r,/\/a\/beacon/,'document.open');
  for(const p of ['/a/beacon-open','/a/beacon-write','/a/beacon-borrowed'])assert.deepEqual(r.routed(p).map(x=>x.reason),['method'],p+' runs once, routed, and is blocked by method policy (screened, never sent)');
  assert.equal(r.arrivals.filter(a=>a.path==='/a/after'&&a.ua!==PRODUCT_USER_AGENT).length,3,'each replaced document really left the page afterwards');
});

// Gap 2: popups. window.open, a noopener window, a target=_blank link and form, a popup the opener writes, and popups to an out-of-scope and a protected host.
// The popup blocker needs user activation; the scanner's own scroll steps grant it (Playwright evaluates with a user gesture), so a timer opens one popup per activation.
test('popups are counted and closed, never escape scope or the protected-host block, and their page-leave handlers never run unrouted',{timeout:180000},async()=>{
  const popup=html('<h1>Popup</h1><script>'+beacon('/b/beacon-popup')+'setInterval(function(){fetch("/b/popup-tick").catch(function(){});},50);</script>');
  const written='<h1>Written popup</h1><script>'+beacon('/b/beacon-written')+'fetch("/b/popup-written-fetch").catch(function(){});setInterval(function(){fetch("/b/popup-tick").catch(function(){});},50);</script>';
  const r=await scan({
    '/b/one':html('<h1>One</h1><form id="f" action="/b/popup-form" target="_blank" method="get"><input name="q" value="1"></form><a id="a" href="/b/popup-link" target="_blank">x</a><script>'+beacon('/b/beacon-one')+
      'var steps=[function(){window.open("/b/popup-open");},function(){window.open("/b/popup-noopener","_blank","noopener");},function(){document.getElementById("a").click();},function(){document.getElementById("f").submit();},'+
      `function(){var w=window.open("");if(w){w.document.write(${js(written)});w.document.close();}},`+
      'function(){window.open("http://outside.invalid/b/out");},function(){window.open("https://www.army.mil/b/protected");}];'+
      'var i=0,t=setInterval(function(){if(i>=steps.length){clearInterval(t);return;}if(navigator.userActivation&&navigator.userActivation.isActive)steps[i++]();},20);</script>'),
    '/b/two':html('<h1>Two</h1>'),
    '/b/popup-open':popup,'/b/popup-noopener':popup,'/b/popup-link':popup,'/b/popup-form':popup,
  },['/b/one','/b/two'],{browserScrollSteps:9,browserScrollDelayMs:150});
  noLeak(r,/\/b\/beacon/,'popups');
  assert.ok(r.v.resources.some(x=>x.url==='https://www.army.mil/b/protected'&&x.reason==='protected-host'),'a popup to a protected host is blocked by the hard rule');
  assert.ok(!r.v.resources.some(x=>x.url.startsWith('http://outside.invalid')&&x.status!=='blocked'),'a popup never reaches an out-of-scope host');
  assert.deepEqual(r.arrivals.filter(a=>a.path==='/b/popup-tick'||a.path==='/b/popup-written-fetch'),[],'popups never load or run requests');
  assert.deepEqual(r.arrivals.filter(a=>/^\/b\/popup-/.test(a.path)&&a.ua!==PRODUCT_USER_AGENT).map(a=>a.url),[],'popup documents are never loaded by the browser');
  // A popup's own requests (the written popup's fetch and timer) are aborted. One that reaches the route is screened and recorded as blocked; one sent before
  // Chromium attaches the new page is held and dropped with the closing popup (it reaches neither the target nor the deny proxy).
  for(const p of ['/b/popup-written-fetch','/b/popup-tick'])assert.ok(r.routed(p).every(x=>x.status==='blocked'&&x.reason==='browser-popup'),p+' is only recorded as a blocked popup request');
  const browserUa=r.arrivals.find(a=>a.path==='/b/one'&&a.ua!==PRODUCT_USER_AGENT)!.ua;assert.match(browserUa,/HeadlessChrome\//);for(const a of r.arrivals)assert.ok(a.ua===PRODUCT_USER_AGENT||a.ua===browserUa,a.path+' carries the honest product token or Chromium’s own User-Agent');
  const popups=r.v.browserStatus!.popups;assert.ok(popups&&popups.opened>=6,'popups are counted: '+JSON.stringify(popups));assert.equal(popups.closed,popups.opened,'every popup is closed');
});

// Gap 3: frames. A frame navigating the top, a frame removed right after it loads, srcdoc and about:blank frames, and a frame that navigates itself.
test('frames: top navigation from a frame, quickly removed frames and srcdoc/about:blank frames run their page-leave handlers at most once, routed',{timeout:180000},async()=>{
  const r=await scan({
    '/c/one':html('<h1>One</h1><iframe src="/c/top"></iframe><script>'+beacon('/c/beacon-one')+'</script>'),
    '/c/top':html('<script>'+beacon('/c/beacon-topframe')+'addEventListener("load",function(){setTimeout(function(){top.location="/c/landing";},50);});</script>'),
    '/c/landing':html('<h1>Landing</h1><iframe src="/c/quick"></iframe><iframe srcdoc="<script>'+beacon('/c/beacon-srcdoc')+'</script>"></iframe><iframe src="/c/self"></iframe><script>'+beacon('/c/beacon-landing')+
      'var b=document.createElement("iframe");document.body.appendChild(b);b.contentDocument.write("<script>'+beacon('/c/beacon-blank')+'<\\/script>");b.contentDocument.close();'+
      'document.querySelector("iframe").addEventListener("load",function(e){setTimeout(function(){e.target.remove();},0);});</script>'),
    '/c/quick':html('<script>'+beacon('/c/beacon-quick')+'</script>'),
    '/c/self':html('<script>'+beacon('/c/beacon-self')+'addEventListener("load",function(){setTimeout(function(){location.href="/c/self-next";},0);});</script>'),
    '/c/self-next':html('<p>next</p>'),
    '/c/two':html('<h1>Two</h1>'),
  },['/c/one','/c/two']);
  noLeak(r,/\/c\/beacon/,'frames');
  for(const p of ['/c/beacon-one','/c/beacon-topframe','/c/beacon-landing','/c/beacon-srcdoc','/c/beacon-blank','/c/beacon-self','/c/beacon-quick'])assert.ok(r.routed(p).length<=1&&r.routed(p).every(x=>x.reason==='method'),p+' runs at most once, routed: '+JSON.stringify(r.routed(p).map(x=>x.reason)));
  for(const p of ['/c/beacon-one','/c/beacon-topframe','/c/beacon-landing','/c/beacon-srcdoc','/c/beacon-blank','/c/beacon-self'])assert.equal(r.routed(p).length,1,p+' is drained, routed');
});

// Cleanup: work a page starts after its inspection has ended. From one second after the page is left, the page opens a WebSocket every 200 ms and one popup
// (the drain's evaluation is the activation). The capture of the page's inline script is held until the cleanup has begun plus 1.5 s, so the session stays open
// while that happens. A late WebSocket is closed without inspection or discovery, and a late popup is counted and closed.
test('WebSockets and popups a page starts after its inspection has ended are closed without new work',{timeout:120000},async()=>{
  const late:{url:string;afterCleanup:boolean}[]=[];let cleanupBegun=()=>false;
  const until=async(done:()=>boolean,ms:number)=>{const end=Date.now()+ms;while(!done()&&Date.now()<end)await new Promise(r=>setTimeout(r,20));};
  const r=await scan({
    // The late URLs are built at run time, so static discovery never finds them.
    '/d/one':html('<h1>Late work</h1><script>void "late-work-page";addEventListener("pagehide",function(){var n=0;setTimeout(function(){window.open(["","d","late-popup"].join("/"));setInterval(function(){try{new WebSocket("ws://"+location.host+["","d","late-ws-"].join("/")+(++n));}catch(e){}},200);},1000);});</script>'),
    '/d/late-popup':html('<h1>Late popup</h1>'),
  },['/d/one'],{browserSettleMs:200},s=>{
    cleanupBegun=()=>!!s.browserStatus.pages?.length;
    const inspect=s.evidence.inspect.bind(s.evidence) as (...args:any[])=>Promise<void>;
    s.evidence.inspect=(text:string,...rest:any[])=>{
      if(rest[1]?.[1]==='Debugger loaded script'&&text.includes('late-work-page'))return (async()=>{await until(cleanupBegun,30000);await new Promise(r=>setTimeout(r,1500));return inspect(text,...rest);})();
      return inspect(text,...rest);
    };
    const enqueue=s.enqueue.bind(s) as (...args:any[])=>void;
    (s as any).enqueue=(raw:string,...rest:any[])=>{if(/^wss?:.*late-ws/.test(raw))late.push({url:raw,afterCleanup:cleanupBegun()});return enqueue(raw,...rest);};
  });
  assert.equal(r.v.browserStatus!.launch,true,'Chromium must actually run');assert.equal(r.v.browserStatus!.runtimePages,1);
  assert.deepEqual(late.filter(l=>l.afterCleanup).map(l=>l.url.replace(r.origin.replace('http','ws'),'')),[],'a WebSocket started after the inspection ended adds no inspection or discovery');
  assert.deepEqual(r.v.resources.filter(x=>/late-/.test(x.url)).map(x=>[x.url.replace(r.origin,''),x.reason]),[],'nothing the page starts after its inspection ended is recorded');
  assert.deepEqual(r.arrivals.filter(a=>/late-/.test(a.path)),[],'nothing the page starts after its inspection ended reaches the website');
  const popups=r.v.browserStatus!.popups;assert.ok(popups&&popups.opened>=1,'the late popup is counted: '+JSON.stringify(popups));assert.equal(popups.closed,popups.opened,'the late popup is closed');
  console.log(JSON.stringify({lateWork:{late:late.length,afterCleanup:late.filter(l=>l.afterCleanup).length}}));
});
