// External synthetic detection corpus (ExposureDesk/detection-corpus/v2, written by a separate non-Claude AI and reviewed before use).
// Serves one corpus site at a time from 127.0.0.1 with an adapter for its site.json contract, scans it with this build (exact-origin scope,
// egress tripwire: any non-loopback socket or DNS lookup throws) and scores the redacted JSON report with the corpus scorer.
// The corpus itself stays outside the project: it contains realistic-looking synthetic credentials and must never be packaged or published.
// Only a reviewed copy is accepted: the scorer and the hash manifest are pinned, and every manifest entry is re-hashed before use.
// Output holds counts, ids, paths and providers only; never a value.
// Usage: node scripts/external-corpus.mjs --corpus <reviewed copy> --output <file.json> [--mode discovery|acquisition] [--preset thorough] [--browser] [--sites a,b]
//        [--coverage quick|standard|deep --traffic normal|low-impact]  (a ready option as shipped: its own pacing, browser and limits; --preset/--browser are then ignored)
//   discovery:   the scan starts at the site root only (product defaults; no corpus-specific seeds or paths).
//   acquisition: every path the corpus expects to be acquired, its entry points and stale assets are seeds, isolating detection from discovery.
import http from 'node:http';
import {createHash} from 'node:crypto';
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
const root=path.dirname(path.dirname(fileURLToPath(import.meta.url))),args=process.argv.slice(2);
const opt=(name,fallback)=>{const i=args.indexOf('--'+name);return i<0?fallback:args[i+1];};
const PINNED={'score.mjs':'5e01b10ec2d8e42e60003217ed49b89bd733307f8e1ba8c34636eb1ab2bea2be','corpus.sha256':'ef9187db6d80638de95cb1b0e4133d44187525a4c44a2a5989b49d1ad21b594a',seed:'ExposureDesk/detection-corpus/v2'};
const corpus=path.resolve(opt('corpus','')),output=opt('output'),mode=opt('mode','discovery'),preset=opt('preset','thorough'),browser=args.includes('--browser'),only=opt('sites')?.split(','),coverage=opt('coverage'),traffic=opt('traffic'),profile=coverage!==undefined||traffic!==undefined;
if(!opt('corpus')||!output||!['discovery','acquisition'].includes(mode)||profile&&(!['quick','standard','deep'].includes(coverage)||!['normal','low-impact'].includes(traffic)))throw new Error('Usage: --corpus <reviewed copy> --output <file.json> [--mode discovery|acquisition] [--preset thorough] [--browser] [--sites a,b] [--coverage quick|standard|deep --traffic normal|low-impact]');
if(!process.env.EXPOSURE_DATA_DIR)throw new Error('Set EXPOSURE_DATA_DIR to a temporary folder first');
const sha=b=>createHash('sha256').update(b).digest('hex');
// Integrity: pinned scorer and manifest, then every listed file.
for(const [file,expected] of Object.entries(PINNED))if(file!=='seed'&&sha(await readFile(path.join(corpus,file)))!==expected)throw new Error('Unreviewed corpus copy: '+file+' differs from the reviewed version');
const manifest=(await readFile(path.join(corpus,'corpus.sha256'),'utf8')).trim().split('\n').map(l=>({hash:l.slice(0,64),file:l.slice(66)}));
for(const {hash,file} of manifest){const p=path.resolve(corpus,file);if(!p.startsWith(corpus+path.sep))throw new Error('Manifest path escapes the corpus: '+file);if(sha(await readFile(p))!==hash)throw new Error('Corpus file changed: '+file);}
const index=JSON.parse(await readFile(path.join(corpus,'corpus-index.json'),'utf8'));if(index.seed!==PINNED.seed||!index.syntheticOnly)throw new Error('Unexpected corpus seed');
const {scoreReport}=await import(pathToFileURL(path.join(corpus,'score.mjs')).href);
const {egressTripwire}=await import(pathToFileURL(path.join(root,'dist/test/virtual-network.js')).href);
const {Scanner}=await import(pathToFileURL(path.join(root,'dist/src/scanner.js')).href),{presetConfig}=await import(pathToFileURL(path.join(root,'dist/src/presets.js')).href),{report}=await import(pathToFileURL(path.join(root,'dist/src/reports.js')).href);
const build=JSON.parse(await readFile(path.join(root,'BUILD_INFO.json'),'utf8')).build?.id;
/** The site.json HTTP contract: decode once, refuse traversal, NUL and backslashes, ignore queries, exact routes before the declared fallback; HEAD without a body. */
function serve(site){
  const dir=path.join(corpus,'sites',site.name,'files'),routes=new Map(site.files.map(f=>[f.path,f])),fb=site.http.fallback,arrivals=[];
  const body=async rel=>{const p=path.resolve(dir,rel);if(!p.startsWith(dir+path.sep))throw new Error('escape');return readFile(p);};
  const server=http.createServer(async(req,res)=>{try{
    let p='';try{p=decodeURIComponent(new URL(req.url||'/','http://fixture.invalid').pathname);}catch{res.writeHead(400);res.end();return;}
    arrivals.push({method:req.method,path:p});
    if(p.includes('\0')||p.includes('\\')||p.split('/').includes('..')){res.writeHead(400);res.end();return;}
    if(!['GET','HEAD'].includes(req.method||'')){res.writeHead(405,{allow:'GET, HEAD'});res.end();return;}
    const f=routes.get(p),excluded=!f&&fb.excludePrefixes.some(x=>p.startsWith(x)),b=await body(f?f.bodyPath:excluded?fb.excludedFallback:fb.bodyPath);
    res.writeHead(f?f.status:excluded?fb.excludedStatus:fb.status,{...(f?.headers||{}),'content-type':f?f.contentType:fb.contentType,'content-length':b.length});res.end(req.method==='HEAD'?undefined:b);
  }catch{res.writeHead(500);res.end();}});
  return new Promise(resolve=>server.listen(0,'127.0.0.1',()=>resolve({origin:`http://127.0.0.1:${server.address().port}`,arrivals,close:()=>new Promise(r=>{server.close(()=>r());server.closeAllConnections();})})));
}
const add=(into,group)=>{for(const [k,m] of Object.entries(group||{})){const t=into[k]||={truePositives:0,falsePositives:0,falseNegatives:0};t.truePositives+=m.truePositives;t.falsePositives+=m.falsePositives;t.falseNegatives+=m.falseNegatives;}};
const finish=g=>Object.fromEntries(Object.entries(g).sort().map(([k,m])=>[k,{...m,precision:m.truePositives+m.falsePositives?+(m.truePositives/(m.truePositives+m.falsePositives)).toFixed(3):null,recall:m.truePositives+m.falseNegatives?+(m.truePositives/(m.truePositives+m.falseNegatives)).toFixed(3):null}]));
const sites=[],byProvider={},byExpectedProvider={},byPlacement={},byOccurrencePlacement={},overall={};const tripwire=egressTripwire();
try{
  for(const entry of index.sites){if(only&&!only.includes(entry.name))continue;
    const site=JSON.parse(await readFile(path.join(corpus,entry.manifest),'utf8')),fixture=await serve(site),o=fixture.origin;
    const seeds=mode==='discovery'?['/']:[...new Set([...site.entryPoints,...site.files.filter(f=>f.acquisitionExpected).map(f=>f.path)])];
    const stale=mode==='acquisition'&&site.staleAssetUrls?.length?{staleAssetCheck:true,staleAssetUrls:site.staleAssetUrls.map(u=>o+u)}:{};
    const started=Date.now();let scan;
    try{
      const common={name:site.name,urls:seeds.map(p=>o+p),developmentFixtureOrigin:o,domainScope:'exact-origin',...stale};
      scan=new Scanner(profile?{...common,coverage,traffic}:presetConfig(preset,{...common,browser,requestsPerSecond:20,originRequestsPerSecond:20}));await scan.init();await scan.run();
      const view=JSON.parse(report(scan,'json',false)),score=scoreReport(view,site.name);
      add(byProvider,score.by.provider);add(byPlacement,score.by.placement);add(byOccurrencePlacement,score.byOccurrencePlacement);add(overall,{all:score.overall});
      // Detector families by the corpus's expected provider: a detected value counts for its family even when the product names a more specific provider (e.g. a private signing key).
      const missedIds=new Set(score.missed.map(m=>m.id)),family={};const bump=(k,field)=>{(family[k]||={truePositives:0,falsePositives:0,falseNegatives:0})[field]++;};
      for(const e of site.expectedFindings)bump(e.provider,missedIds.has(e.id)?'falseNegatives':'truePositives');for(const f of score.falsePositives)bump(f.provider,'falsePositives');add(byExpectedProvider,family);
      sites.push({name:site.name,state:view.state,durationMs:Date.now()-started,requests:fixture.arrivals.length,resources:view.resources.length,findings:view.findings.length,privateAlerts:view.findings.filter(f=>f.category==='private-credential').length,
        overall:score.overall,detection:score.detection,missed:score.missed.map(m=>({id:m.id,provider:m.provider,placement:m.placement,detectedAsOtherCategory:m.detectedAsOtherCategory})),
        falsePositives:score.falsePositives.map(f=>({provider:f.provider,placement:f.placement})),negativeAlerts:score.falsePositivesOnNegatives.map(n=>({negativeId:n.negativeId,kind:n.kind,provider:n.actualProvider})),
        classificationMistakes:score.classificationMistakes.map(c=>({expected:c.expected,fields:c.errors.map(e=>e.field)})),acquisitionMisses:score.acquisitionMisses.map(a=>a.path),inspectionMisses:score.inspectionMisses.map(a=>a.path),ambiguous:score.ambiguousMatches.length,
        incompleteGaps:[...new Set(view.limitations.filter(g=>g.incomplete).map(g=>g.code))].sort()});
      console.log(JSON.stringify({site:site.name,state:view.state,tp:score.overall.truePositives,fp:score.overall.falsePositives,fn:score.overall.falseNegatives,negativeAlerts:score.falsePositivesOnNegatives.length,ms:Date.now()-started}));
    }finally{scan?.dispose();await fixture.close();}
  }
}finally{tripwire.restore();}
if(tripwire.violations.length)throw new Error('Egress tripwire violations: '+tripwire.violations.join(', '));
const result={schema:'exposure-external-corpus-measurement/1',build,corpus:{seed:index.seed,corpusSha256:PINNED['corpus.sha256'],scoreSha256:PINNED['score.mjs'],sites:index.counts.sites,privateValues:index.counts.privateValues,negativeControls:index.counts.negativeControls},
  settings:profile?{mode,coverage,traffic,profile:'as shipped',scope:'exact-origin',egressViolations:0}:{mode,preset,browser,scope:'exact-origin',requestsPerSecond:20,egressViolations:0},overall:finish(overall).all||null,byExpectedProvider:finish(byExpectedProvider),byProvider:finish(byProvider),byPlacement:finish(byPlacement),byOccurrencePlacement:finish(byOccurrencePlacement),
  negativeAlerts:sites.reduce((n,s)=>n+s.negativeAlerts.length,0),sites};
await mkdir(path.dirname(path.resolve(output)),{recursive:true});await writeFile(output,JSON.stringify(result,null,2)+'\n');
console.log(JSON.stringify({output,overall:result.overall,negativeAlerts:result.negativeAlerts}));
