import {writeFile} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
const implementation=path.resolve(process.argv[3]||fileURLToPath(new URL('../',import.meta.url)));
const [{Scanner},{Detector},{BUILD}]=await Promise.all(['scanner','detectors','build-info'].map(name=>import(pathToFileURL(path.join(implementation,'dist/src/'+name+'.js')).href)));
import {corpus,corpusDigest,seed} from './upgrade-corpus.mjs';
const at=performance.now(),rows=[];
for(const c of corpus){
 const start=performance.now(),d=new Detector('disabled'),s=new Scanner({urls:['https://acceptance.invalid'],maxDurationMs:60000,sensitiveFields:c.sensitiveFields||[]},{detector:d});
 try{
  if(c.channel==='semantic'){for(const m of c.sources)s.addModule(m.text,m.url);await s.reconstruct('https://acceptance.invalid');}
  else for(const m of c.sources)await s.evidence.inspect(m.text,m.url,[],'Synthetic public response');
  await s.evidence.triage?.flush();
  const findings=[...s.evidence.findings.values()],privateValues=findings.filter(f=>f.category==='private-credential').map(f=>s.evidence.reveal(f.id).value),misses=c.expected.filter(v=>!privateValues.includes(v)),falsePositives=privateValues.filter(v=>!c.expected.includes(v));
  rows.push({id:c.id,group:c.group,split:c.split,provider:c.provider,framework:c.framework,channel:c.channel,targets:c.expected.length,detected:c.expected.length-misses.length,misses:misses.length,falsePositives:falsePositives.length,classificationErrors:findings.filter(f=>c.expected.includes(s.evidence.reveal(f.id).value)&&f.category!=='private-credential').length,expectedRules:c.expectedRules||[],observedRules:findings.map(f=>f.rule),exposureMisses:(c.expectedRules||[]).filter(r=>!findings.some(f=>f.rule===r)),exposureFalsePositives:findings.filter(f=>f.exposureKind&&!(c.expectedRules||[]).includes(f.rule)).length,analysisInspected:s.view().semantic?.modules||0,gaps:s.limitations.map(g=>g.code),elapsedMs:performance.now()-start});
 }finally{s.dispose();}
}
const sum=key=>rows.reduce((n,r)=>n+(r[key]||0),0),tp=sum('detected'),fp=sum('falsePositives'),targets=sum('targets');
const grouped=field=>Object.fromEntries([...new Set(rows.map(r=>r[field]))].map(group=>{const subset=rows.filter(r=>r[field]===group);return [group,{cases:subset.length,targets:subset.reduce((n,r)=>n+r.targets,0),detected:subset.reduce((n,r)=>n+r.detected,0),falsePositives:subset.reduce((n,r)=>n+r.falsePositives,0),exposureTargets:subset.reduce((n,r)=>n+r.expectedRules.length,0),exposureDetected:subset.reduce((n,r)=>n+r.expectedRules.length-r.exposureMisses.length,0),exposureFalsePositives:subset.reduce((n,r)=>n+r.exposureFalsePositives,0)}];}));
const result={build:BUILD,seed,corpusDigest,corpusCases:rows.length,trainingOverlap:false,targets,detected:tp,misses:sum('misses'),falsePositives:fp,precision:tp+fp?tp/(tp+fp):null,recall:targets?tp/targets:null,exposureTargets:rows.reduce((n,r)=>n+r.expectedRules.length,0),exposureMisses:rows.reduce((n,r)=>n+r.exposureMisses.length,0),exposureFalsePositives:sum('exposureFalsePositives'),classificationErrors:sum('classificationErrors'),elapsedMs:performance.now()-at,maxRssKiB:process.resourceUsage().maxRSS,byProvider:grouped('provider'),byFramework:grouped('framework'),byChannel:grouped('channel'),rows,limitations:['Synthetic, nonfunctional fixtures only; no owner response bodies supplied.','Text and semantic channels run without Gitleaks to isolate these changes. Acquisition/browser coverage measured separately.','Peak Node RSS includes worker memory, excludes Chromium and native detector child memory.','Related template variants remain in one evaluation split; no accuracy estimate for the open web.']};
await writeFile(process.argv[2]||'benchmarks/upgrade-evaluation.json',JSON.stringify(result,null,2));console.log(JSON.stringify({...result,rows:undefined}));
