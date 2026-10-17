import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import {mkdtemp,rm} from 'node:fs/promises';
import {Scanner} from '../src/scanner.js';
import {createFixture} from '../src/fixture.js';
import {diagnose} from '../src/diagnostics.js';
import {CHROME_SERVICE_HOSTS} from '../src/browser-provenance.js';
import {subjectGaps} from './browser-exit.js';
// Chrome for Testing opens its own service connections (Google account cookie check, GCM check-in, component update, AI Mode eligibility)
// and retries them for up to about 30 s. The deny-only proxy refuses every one; they must not make a loopback scan incomplete.
test('a real-browser loopback scan without other gaps ends complete; Chrome service connections stay denied, listed and informational',{timeout:120000},async()=>{
  // The default detector, as in the doctor runtime scan: a disabled detector is an incomplete gap of its own.
  const f=await createFixture(0,{minimalDiscovery:true});
  // A 5 s quiet settle keeps the page open past Chrome's retries at about 1.4, 3-6 and 4 s, so some land after the first navigation.
  try{const s=new Scanner({urls:[f.origin+'/clean'],developmentFixtureOrigin:f.origin,browser:true,adjacentMaps:false,requestsPerSecond:20,maxDurationMs:90000,maxResources:50,timeoutMs:20000,browserSettleMs:5000,browserScrollSteps:1});
    try{await s.init();const v=await s.run();
      assert.equal(v.browserStatus!.launch,true,'Chromium must actually run');assert.ok(v.browserStatus!.runtimePages>=1);
      const {open,exitNotConfirmed}=subjectGaps(v.limitations,'chrome background');assert.deepEqual(open.map(g=>[g.code,g.url||'',g.attribution||'']),[],'no incomplete gap remains');assert.equal(v.state,exitNotConfirmed?'incomplete':'completed');
      const proxied=v.resources.filter(r=>r.kind==='browser-proxy');assert.ok(proxied.length>0,'Chrome contacted its own services and the attempts are listed in the report');
      for(const r of proxied){const p=r.provenance!;assert.equal(r.status,'blocked');assert.equal(p.channel,'deny-proxy');assert.equal(p.attribution,'background',r.url);
        assert.ok(p.evidenceSource==='pre-navigation'||p.evidenceSource==='chrome-service-host',String(p.evidenceSource));
        if(p.evidenceSource==='chrome-service-host')assert.ok(CHROME_SERVICE_HOSTS.has(new URL(r.url).hostname),r.url);else assert.equal(p.phase,'pre-navigation');}
      const late=proxied.filter(r=>r.provenance!.evidenceSource==='chrome-service-host');assert.ok(late.length>0,'some Chrome service retries arrived after the first navigation and were attributed by the host list');assert.ok(late.every(r=>r.provenance!.phase!=='pre-navigation'));
      const gap=v.limitations.filter(g=>g.code==='browser-background-denied');assert.equal(gap.length,1);assert.equal(gap[0].incomplete,false);assert.equal(gap[0].count,v.browserStatus!.background!.count);assert.equal(gap[0].count,proxied.length);assert.match(gap[0].detail,/from Chrome's own services/);
      console.log(JSON.stringify({chromeBackground:{proxied:proxied.length,afterNavigation:late.length,hosts:v.browserStatus!.background!.hosts,state:v.state}}));
    }finally{s.dispose();}
  }finally{await f.close();}
});
test('doctor --runtime reports the browser available and the synthetic runtime scan completed',{timeout:120000},async()=>{
  const dir=await mkdtemp(path.join(os.tmpdir(),'chrome-background-doctor-'));
  try{const d=await diagnose({dir,runtime:true,synthetic:true});const {open,exitNotConfirmed}=subjectGaps<any>(d.browser.limitations||[],'doctor runtime');
    assert.equal(d.browser.launch,'available');assert.deepEqual(open.map((g:any)=>[g.code,g.url||'']),[],'no incomplete gap in the runtime scan');assert.equal(d.browser.runtimeScan,exitNotConfirmed?'partial':'completed');
  }finally{await rm(dir,{recursive:true,force:true});}
});
