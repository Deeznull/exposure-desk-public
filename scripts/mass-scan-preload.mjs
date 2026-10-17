// Mass-scan measurement preload: scripts/mass-scan-measure.mjs starts `node --import <this file> dist/src/cli.js scan …` with MASS_MEASURE_OUT set.
// It acts only in that scan process (analysis children are forked with their own execArgv and never load it) and changes no scan behaviour; it only observes:
// - an egress tripwire: a socket to anything outside 127.0.0.0/8 and ::1, or a DNS lookup of anything but localhost, throws and is recorded (loopback fixtures only);
// - the scan process's peak RSS, sampled every 25 ms, and its operating-system high-water mark;
// - every analysis memory budget a scan drew from (capacity and peak) and the ready-option analysis memory each scan was given;
// - the analysis child processes (heap limits held at once, peak RSS, out-of-memory ends) and their process ids, so the parent can check that none outlives the scan;
// - the analysis time factor in effect.
// The figures are written to MASS_MEASURE_OUT every second (so a forced stop leaves the last second) and at exit.
import net from 'node:net';
import tls from 'node:tls';
import dns from 'node:dns';
import path from 'node:path';
import {syncBuiltinESMExports} from 'node:module';
import {realpathSync,renameSync,writeFileSync} from 'node:fs';
import {pathToFileURL} from 'node:url';

const outFile=process.env.MASS_MEASURE_OUT,entry=process.argv[1]?realpathSync(process.argv[1]):'';
if(outFile&&path.basename(entry)==='cli.js'){
  const t0=performance.now(),violations=[],loopback=host=>/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)||['::1','[::1]','localhost','local-pipe'].includes(host);
  const hostOf=args=>{const a=args[0];if(a&&typeof a==='object')return String(a.host??a.hostname??(a.path?'local-pipe':'localhost'));return typeof args[1]==='string'?args[1]:typeof a==='string'&&!/^\d+$/.test(a)?'local-pipe':'localhost';};
  const guard=(original,label)=>function(...args){const host=hostOf(args);if(!loopback(host)){violations.push(label+' '+host);throw new Error('egress tripwire: '+label+' to '+host);}return original.apply(this,args);};
  net.connect=guard(net.connect,'net.connect');net.createConnection=guard(net.createConnection,'net.createConnection');tls.connect=guard(tls.connect,'tls.connect');
  const lookup=dns.lookup,promisesLookup=dns.promises.lookup;
  dns.lookup=function(host,...rest){if(host==='localhost')return lookup.call(this,host,...rest);violations.push('dns.lookup '+host);throw new Error('egress tripwire: dns.lookup '+host);};
  dns.promises.lookup=async(host,...rest)=>{if(host==='localhost')return promisesLookup(host,...rest);violations.push('dns.promises.lookup '+host);throw new Error('egress tripwire: dns.promises.lookup '+host);};
  syncBuiltinESMExports();

  const dist=path.dirname(entry),imp=f=>import(pathToFileURL(path.join(dist,f)).href);
  const [{Scanner},{analysisProcesses},{currentTimeFactor}]=await Promise.all([imp('scanner.js'),imp('analysis-process.js'),imp('machine-speed.js')]);
  // Every scan's analysis memory budget (one shared instance in mass mode) and the analysis memory its ready option gave it.
  const budgets=new Set(),settings=new Set();let scans=0;const run=Scanner.prototype.run;
  Scanner.prototype.run=function(...args){scans++;budgets.add(this.analysisMemory);settings.add(this.caps?.analysisMemoryMb);return run.apply(this,args);};
  const children=[];analysisProcesses.events.on('spawn',info=>children.push(info));
  let peakRss=process.memoryUsage.rss(),samples=0;
  const sampler=setInterval(()=>{samples++;peakRss=Math.max(peakRss,process.memoryUsage.rss());},25);sampler.unref();
  const concurrent=size=>{const now=Date.now(),marks=children.flatMap(c=>[[c.spawnedAt,size(c)],[c.endedAt??now,-size(c)]]).sort((x,y)=>x[0]-y[0]||x[1]-y[1]);let live=0,peak=0;for(const [,d] of marks){live+=d;peak=Math.max(peak,live);}return peak;};
  const snapshot=final=>{const tf=currentTimeFactor(),list=[...budgets];
    return {final,pid:process.pid,durationMs:Math.round(performance.now()-t0),scans,peakRssMb:Math.round(Math.max(peakRss,process.memoryUsage.rss())/1048576),maxRssMb:Math.round(process.resourceUsage().maxRSS/1024),rssSamples:samples,
      cpuMs:Math.round((process.cpuUsage().user+process.cpuUsage().system)/1000),
      analysisBudgets:{distinct:list.length,capacities:[...new Set(list.map(b=>b.capacity))],peak:Math.max(0,...list.map(b=>b.peak)),settingsMb:[...settings].filter(v=>v!=null)},
      analysisChildren:{spawned:children.length,live:analysisProcesses.live,concurrentHeapMb:concurrent(c=>c.heapMb||0),concurrentPeakRssMb:concurrent(c=>c.peakRssMb||0),peakChildRssMb:Math.max(0,...children.map(c=>c.peakRssMb||0)),
        heapLimitsMb:[...new Set(children.map(c=>c.heapMb))].sort((a,b)=>a-b),outOfMemory:children.filter(c=>c.exit?.outOfMemory).length,pids:children.map(c=>c.pid).filter(p=>typeof p==='number')},
      timeFactor:{factor:tf.factor,source:tf.source},egressViolations:violations};};
  const write=final=>{try{const tmp=outFile+'.tmp';writeFileSync(tmp,JSON.stringify(snapshot(final)));renameSync(tmp,outFile);}catch{}};
  const ticker=setInterval(()=>write(false),1000);ticker.unref();
  process.on('exit',()=>write(true));
}
