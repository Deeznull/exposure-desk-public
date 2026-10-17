import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, rm } from 'node:fs/promises';
import { chromium, type Page } from 'playwright';
import { startDashboard } from '../src/dashboard.js';
import { Scanner } from '../src/scanner.js';
import { Detector, root } from '../src/detectors.js';
import { COVERAGE_RESOURCES } from '../src/profiles.js';
import { dedicatedBrowser } from '../src/runtime-paths.js';
import { syntheticBundle } from './large-bundle.js';
/** 2.6 P3b ready options in the browser: what a small computer lowers (shown read-only), the long-scan notice, the Recommended option as the default of a new project, and the coverage recall of
 * Standard and Deep audit (isolated browser) at their ready-option memory. Local only: estimates contact nothing and the scans run against a loopback site. */
const key=(name:string)=>'sk-proj-'+createHash('sha512').update('unit-ready-options-browser-'+name).digest('base64url').slice(0,64);
async function temp(){const parent=process.env.EXPOSURE_DATA_DIR||path.join(root,'.cache');await mkdir(parent,{recursive:true});return mkdtemp(path.join(parent,'ready-options-browser-'));}
async function signIn(page:Page,app:{origin:string;token:string}){await page.goto(app.origin);await page.locator('#token').fill(app.token);await page.locator('#login-form button').click();await page.locator('#workspace').waitFor({state:'visible'});}
const text=async(page:Page,id:string)=>(await page.locator('#'+id).textContent())||'';
test('a small computer: the scan page shows every lowered value read-only, a very long estimate names Quick check without switching, and a new project saves the Recommended option',{timeout:90000},async()=>{
  const dir=await temp(),app=await startDashboard({port:0,persistent:true,dataDir:dir,syntheticData:true,computer:()=>({cores:2,freeMemoryMb:1000})});
  const browser=await chromium.launch({headless:true,executablePath:dedicatedBrowser()||chromium.executablePath()});
  try{const page=await browser.newPage(),errors:string[]=[],dialogs:string[]=[];page.setDefaultTimeout(10000);page.on('pageerror',e=>errors.push(e.message));page.on('dialog',d=>{dialogs.push(d.message());void d.dismiss();});
    await signIn(page,app);await page.locator('[data-view="new"]').click();await page.locator('#urls').fill('https://www.example.com/');
    const uses=page.locator('#option-uses'),row=async(name:string)=>(await uses.locator('tr').filter({has:page.getByRole('rowheader',{name,exact:true})}).locator('td').textContent())||'';
    await page.waitForFunction(()=>document.getElementById('option-uses')?.textContent?.includes('lowered'));
    assert.equal(await row('Websites at once'),'1 website at once, adjusted for 1 website · up to 4 once discovered websites are admitted');assert.equal(await row('Browser websites at once'),'1 (lowered from 2 for this computer)');
    assert.equal(await row('Analysis memory'),'250 MiB (lowered from 256 MiB for this computer)');assert.equal(await row('Analysis workers'),'1 (lowered from 2 for this computer)');
    const note=uses.locator('p.notice');assert.equal(await note.textContent(),'This computer: 2 logical cores, 1.0 GiB free memory; lowered analysis workers 2 → 1, browser websites at once 2 → 1, analysis memory (MiB) 256 → 250. Values are only ever lowered, never raised.');
    assert.equal(await page.locator('#option-uses-panel').locator('input,select,textarea,[contenteditable]').count(),0,'read-only');
    assert.equal(await text(page,'profile-label'),'Standard + Normal (Recommended)','the option keeps its name: lowering is an adjustment, not a different option');
    // A new project saved without choosing stores the Recommended option, not the lowered values.
    await page.locator('#authorized').check();await page.locator('#save-project').click();await page.waitForFunction(()=>document.getElementById('message')?.textContent==='Authorized project saved locally.');
    const project=app.desk.store!.projects[0];assert.deepEqual([project.config.coverage,project.config.traffic,project.config.profileCustomized,project.config.maxAnalysisMemoryMb,project.config.analysisConcurrency,project.config.maxBrowserOrigins],['standard','normal',undefined,256,2,2]);
    // Ready options stay under the long-scan threshold for ten websites; a slow custom file is flagged with Quick check named, and nothing is switched.
    await page.locator('#scan-advanced summary').click();await page.locator('#seed-urls').fill(Array.from({length:9},(_,i)=>`https://site${i}.example.net/`).join('\n'));
    await page.locator('label.option-card:has(#option-deep-low-impact)').click();await page.waitForFunction(()=>(document.getElementById('profile-estimate-line')?.textContent||'').startsWith('Deep audit + Low-impact · 10 websites'));assert.equal(await page.locator('#profile-long').isHidden(),true);
    await page.locator('#config-upload').setInputFiles({name:'slow.json',mimeType:'application/json',buffer:Buffer.from(JSON.stringify({urls:Array.from({length:10},(_,i)=>`https://site${i}.example.net/`),coverage:'deep',traffic:'normal',originRequestsPerSecond:.2,maxActiveOrigins:1}))});
    await page.waitForFunction(()=>(document.getElementById('profile-long')?.textContent||'').length>0);assert.equal(await page.locator('#profile-long').isVisible(),true);
    assert.match(await text(page,'profile-long'),/^Custom \(based on Deep audit \+ Normal\) may take about [\d.]+ h at this pacing for \d+ websites\. Quick check would take about \d+ min; consider it for a first look\. Nothing is switched automatically\.$/);
    assert.equal(await text(page,'profile-label'),'Custom (based on Deep audit + Normal)','nothing is switched');assert.equal(await page.locator('input[name="ready-option"]:checked').count(),0);
    assert.equal(await page.locator('#profile-long').getAttribute('role'),'status','the notice is announced');
    assert.deepEqual(errors,[]);assert.deepEqual(dialogs,[]);
  }finally{await browser.close();await app.close();await rm(dir,{recursive:true,force:true});}
});
test('Standard and Deep audit find every synthetic key of the large-bundle fixture at their ready-option memory, with the isolated browser',{timeout:240000},async()=>{
  const bundle=syntheticBundle({seed:'ExposureDesk/ready-options-browser/1',targetBytes:1252570}),K={inline:key('inline'),app:key('app'),map:key('map'),env:key('env'),config:key('config'),split:key('split'),bundle:bundle.value},half=K.split.length>>1;
  const routes:Record<string,[string,string]>={'/':['text/html',`<!doctype html><script>window.S={openai:${JSON.stringify(K.inline)}}</script><script src="/app.js"></script><script type="module" src="/bundle.js"></script><script type="module" src="/main.js"></script>`],
    '/app.js':['text/javascript',`const client={apiKey:${JSON.stringify(K.app)}};\n//# sourceMappingURL=app.js.map`],'/app.js.map':['application/json',JSON.stringify({version:3,file:'app.js',sources:['src/c.ts'],sourcesContent:[`export const serverKey=${JSON.stringify(K.map)};`],names:[],mappings:'AAAA'})],
    '/main.js':['text/javascript',`import {a} from "./part.js";export const openaiKey=a+${JSON.stringify(K.split.slice(half))};`],'/part.js':['text/javascript',`export const a=${JSON.stringify(K.split.slice(0,half))};`],'/bundle.js':['text/javascript',bundle.text],
    '/.env':['text/plain',`OPENAI_API_KEY=${K.env}\n`],'/config.json':['application/json',JSON.stringify({openai:{apiKey:K.config}})],'/robots.txt':['text/plain','User-agent: *\nAllow: /\n']};
  const server=http.createServer((q,r)=>{const x=routes[q.url||''];if(!x){r.statusCode=404;r.end('not found');return;}r.writeHead(200,{'content-type':x[0]});r.end(x[1]);});await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));const origin=`http://127.0.0.1:${(server.address() as any).port}`;
  try{for(const coverage of ['standard','deep'] as const){
    const s=new Scanner({urls:[origin+'/'],developmentFixtureOrigin:origin,coverage,traffic:'normal'},{detector:new Detector(),computer:{cores:16,freeMemoryMb:32768}});
    try{await s.init();const v=await s.run();const values=new Set([...s.evidence.findings.values()].map(f=>s.evidence.reveal(f.id).value));
      assert.deepEqual(Object.entries(K).filter(([,x])=>!values.has(x)).map(([k])=>k),[],coverage+' finds every synthetic key');
      assert.equal(s.caps.analysisMemoryMb,COVERAGE_RESOURCES[coverage].maxAnalysisMemoryMb);assert.equal(s.caps.analysisWorkers,COVERAGE_RESOURCES[coverage].analysisConcurrency);assert.deepEqual(v.profile!.resourceUse!.adjustments,[]);
      assert.ok(!v.limitations.some(g=>g.code==='semantic-memory-ceiling'),coverage+': no group was left unparsed for memory');
    }finally{s.dispose();}
  }}finally{server.closeAllConnections();await new Promise<void>(r=>server.close(()=>r()));}
});
