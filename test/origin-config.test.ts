import test from 'node:test';
import assert from 'node:assert/strict';
import {makeConfig,resolveScanConfig} from '../src/config.js';
import {presetConfig,presets} from '../src/presets.js';

const MiB=1024*1024, urls=['https://one.example/','https://two.example/'];
test('legacy preset numerical and detection overrides remain unchanged',()=>{
  assert.deepEqual(presets.quick,{preset:'quick',browser:false,deep:false,maxDepth:1,maxPages:8,maxResources:60,maxResourceBytes:8*MiB,maxTotalBytes:40*MiB,maxDurationMs:90000,maxMaps:10,adjacentMaps:false});
  assert.deepEqual(presets.standard,{preset:'standard',browser:true,deep:false,maxDepth:3,maxPages:30,maxResources:200,maxResourceBytes:12*MiB,maxTotalBytes:120*MiB,maxDurationMs:300000,maxMaps:30,browserPages:5,browserScrollSteps:2});
  assert.deepEqual(presets.thorough,{preset:'thorough',browser:true,deep:true,maxDepth:5,maxPages:80,maxResources:600,maxResourceBytes:24*MiB,maxWireResourceBytes:24*MiB,maxTotalBytes:300*MiB,maxDecodedTotalBytes:400*MiB,maxDurationMs:900000,maxMaps:80,maxMapSources:80,browserPages:15,browserScrollSteps:5});
});
test('old configuration receives additive defaults without multiplying or raising explicit shared caps',()=>{
  const c=makeConfig({urls,concurrency:1,requestsPerSecond:.5,maxDurationMs:1234,maxPages:3,maxResources:7,maxTotalBytes:2048,maxMaps:2,browserPages:1});
  assert.equal(c.globalConcurrency,1);assert.equal(c.originConcurrency,1);assert.equal(c.originRequestsPerSecond,.5);
  assert.equal(c.originMaxDurationMs,1234);assert.equal(c.projectMaxDurationMs,1234);
  assert.equal(c.originMaxPages,3);assert.equal(c.originMaxResources,7);assert.equal(c.originMaxTotalBytes,2048);assert.equal(c.originMaxMaps,2);assert.equal(c.originBrowserPages,1);
  assert.equal(c.maxPages,3);assert.equal(c.maxResources,7);assert.equal(c.maxTotalBytes,2048);
});
test('Exhaustive uses bounded Thorough resource safeguards and the requested origin admission defaults',()=>{
  const c=presetConfig('exhaustive',{urls,relatedOrigins:['https://assets.example','https://one.example']});
  assert.equal(c.originConcurrency,3);assert.equal(c.originRequestsPerSecond,2);assert.equal(c.maxActiveOrigins,4);assert.equal(c.globalConcurrency,12);assert.equal(c.maxBrowserOrigins,2);
  assert.equal(c.requestsPerSecond,8);assert.equal(c.originMaxDurationMs,3600000);assert.equal(c.projectMaxDurationMs,3*3600000+5000);
  for(const key of ['maxPages','maxResources','maxResourceBytes','maxWireResourceBytes','maxTotalBytes','maxDecodedTotalBytes','maxMaps','maxMapSources','browserPages','browserScrollSteps'] as const)assert.equal(c[key],presets.thorough[key]);
  const old=presetConfig('exhaustive',{urls,concurrency:1,requestsPerSecond:.5,maxDurationMs:1000,maxPages:2,maxResources:4});
  assert.equal(old.globalConcurrency,1);assert.equal(old.originConcurrency,1);assert.equal(old.requestsPerSecond,.5);assert.equal(old.projectMaxDurationMs,1000);assert.equal(old.originMaxDurationMs,1000);assert.equal(old.maxPages,2);assert.equal(old.maxResources,4);
  assert.equal(presetConfig('exhaustive',{urls,concurrency:1,globalConcurrency:12}).globalConcurrency,12);
});
test('all new limits are validated and finite; rates alone permit fractional values',()=>{
  const bounds:Record<string,[number,number]>={originConcurrency:[1,8],originRequestsPerSecond:[.1,20],maxActiveOrigins:[1,8],globalConcurrency:[1,12],maxBrowserOrigins:[1,4],originMaxDurationMs:[100,3600000],projectMaxDurationMs:[100,360005000],originMaxPages:[1,500],originMaxResources:[1,2000],originMaxTotalBytes:[1024,500*MiB],originMaxMaps:[0,100],originBrowserPages:[1,50]};
  for(const [key,[min,max]]of Object.entries(bounds)){
    for(const n of [min,max])assert.equal((makeConfig({urls,[key]:n}) as any)[key],n);
    for(const n of [min-1,max+1,NaN,Infinity,null])assert.throws(()=>makeConfig({urls,[key]:n}),new RegExp(key));
    if(key!=='originRequestsPerSecond')assert.throws(()=>makeConfig({urls,[key]:min+.5}),new RegExp(key));
  }
  assert.equal(makeConfig({urls,originRequestsPerSecond:.25}).originRequestsPerSecond,.25);
});
test('optional website-count sizing uses distinct exact origins and keeps per-origin controls fixed',()=>{
  const input={urls:['https://one.example/a','https://one.example/b','https://two.example/'],relatedOrigins:['https://two.example','https://assets.example'],autoScaleByWebsiteCount:true,maxPages:20,originMaxPages:15,maxResources:40,originMaxResources:30,maxTotalBytes:10*MiB,originMaxTotalBytes:8*MiB,maxDecodedTotalBytes:16*MiB,browserPages:2,originBrowserPages:2,maxMaps:3,originMaxMaps:2,projectMaxDurationMs:1000,originMaxDurationMs:2000,requestsPerSecond:1,originRequestsPerSecond:.5};
  const base=makeConfig(input),scaled=resolveScanConfig(input);
  assert.equal(base.maxPages,20);assert.equal(base.maxResources,40);
  assert.equal(scaled.maxPages,45);assert.equal(scaled.maxResources,90);
  assert.equal(scaled.maxTotalBytes,24*MiB);assert.equal(scaled.maxDecodedTotalBytes,24*MiB);
  assert.equal(scaled.browserPages,6);assert.equal(scaled.maxMaps,6);assert.equal(scaled.projectMaxDurationMs,6000);
  assert.equal(scaled.originMaxPages,15);assert.equal(scaled.originMaxResources,30);assert.equal(scaled.originMaxTotalBytes,8*MiB);
  assert.equal(scaled.requestsPerSecond,1);assert.equal(scaled.originRequestsPerSecond,.5);
  assert.deepEqual(resolveScanConfig(scaled),scaled,'reusing an effective scan config must not multiply limits again');
  assert.equal(resolveScanConfig({...input,autoScaleByWebsiteCount:false}).maxResources,40);
  assert.throws(()=>makeConfig({...input,autoScaleByWebsiteCount:'yes' as any}),/autoScaleByWebsiteCount/);
});
test('website-count sizing respects project ceilings',()=>{
  const c=resolveScanConfig({urls:Array.from({length:50},(_,i)=>`https://site-${i}.example/`),autoScaleByWebsiteCount:true,maxPages:500,originMaxPages:500,maxResources:2000,originMaxResources:2000,maxTotalBytes:500*MiB,originMaxTotalBytes:500*MiB,browserPages:50,originBrowserPages:50,maxMaps:100,originMaxMaps:100,projectMaxDurationMs:100,originMaxDurationMs:3600000});
  assert.equal(c.maxPages,500);assert.equal(c.maxResources,2000);assert.equal(c.maxTotalBytes,500*MiB);
  assert.equal(c.browserPages,50);assert.equal(c.maxMaps,100);assert.equal(c.projectMaxDurationMs,180000000);
});
