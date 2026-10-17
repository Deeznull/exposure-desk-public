import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import path from 'node:path';
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { chromium, type Page } from 'playwright';
import { startDashboard } from '../src/dashboard.js';
import { Detector, root } from '../src/detectors.js';
import { Scanner } from '../src/scanner.js';
import { report } from '../src/reports.js';
import { dedicatedBrowser } from '../src/runtime-paths.js';
import { virtualNetwork } from './virtual-network.js';
/** 2.6 scan page and UI (P3, ready options since P3b): the six ready options with Standard + Normal recommended, the live estimate, keyboard use, the read-only “What this option uses” panel,
 * stored settings (legacy presets, custom settings, JSON files) with a one-click switch and restore, the legacy banner on project cards, and the profile in runs, history and routines.
 * Local only: the estimates contact nothing, and the one scan runs against a loopback site. */
const pause=(ms:number)=>new Promise(r=>setTimeout(r,ms));
async function temp(){const parent=process.env.EXPOSURE_DATA_DIR||path.join(root,'.cache');await mkdir(parent,{recursive:true});return mkdtemp(path.join(parent,'profile-ui-'));}
async function site(){const server=http.createServer((req,res)=>{if(req.url==='/'){res.writeHead(200,{'content-type':'text/html'});res.end('<html><head><script src="/app.js"></script></head><body>synthetic profile page</body></html>');}else if(req.url==='/app.js'){res.writeHead(200,{'content-type':'application/javascript'});res.end('window.synthetic=1;');}else{res.writeHead(404,{'content-type':'text/plain'});res.end('not found');}});await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));const origin=`http://127.0.0.1:${(server.address() as any).port}`;return {origin,close:()=>new Promise<void>(r=>{server.close(()=>r());server.closeAllConnections();})};}
async function signIn(page:Page,app:{origin:string;token:string}){await page.goto(app.origin);await page.locator('#token').fill(app.token);await page.locator('#login-form button').click();await page.locator('#workspace').waitFor({state:'visible'});}
const text=async(page:Page,id:string)=>(await page.locator('#'+id).textContent())||'';
const upload=(page:Page,name:string,data:unknown)=>page.locator('#config-upload').setInputFiles({name,mimeType:'application/json',buffer:Buffer.from(JSON.stringify(data))});
test('scan page: six ready options with Standard + Normal recommended by default, keyboard use, live estimate, the read-only panel, stored settings with a one-click switch and restore, and saving',{timeout:90000},async()=>{
  const dir=await temp(),app=await startDashboard({port:0,persistent:true,dataDir:dir,syntheticData:true,computer:()=>({cores:16,freeMemoryMb:32768})});
  const browser=await chromium.launch({headless:true,executablePath:dedicatedBrowser()||chromium.executablePath()});
  try{const page=await browser.newPage(),errors:string[]=[],dialogs:string[]=[],previews:any[]=[];page.setDefaultTimeout(10000);page.on('pageerror',e=>errors.push(e.message));page.on('dialog',d=>{dialogs.push(d.message());void d.dismiss();});
    page.on('request',r=>{if(new URL(r.url()).pathname==='/api/profile/preview')previews.push(JSON.parse(r.postData()||'{}').config);});
    const lastPreview=async(check:(c:any)=>boolean)=>{for(let i=0;i<60;i++){const c=previews.at(-1);if(c&&check(c))return c;await pause(100);}assert.fail('expected preview request not sent: '+JSON.stringify(previews.at(-1)));};
    const line=()=>page.evaluate(()=>document.getElementById('profile-estimate-line')?.textContent||'');
    await signIn(page,app);await page.locator('[data-view="new"]').click();
    // Default: the Recommended option; one named group of six radios, each named by its card title and described by its summary and numbers.
    const group=page.getByRole('group',{name:/^Scan option/});assert.equal(await group.getByRole('radio').count(),6);
    assert.equal(await page.locator('#option-standard-normal').isChecked(),true);assert.equal(await text(page,'profile-label'),'Standard + Normal (Recommended)');
    assert.equal(await page.locator('.option-card .recommended').count(),1);assert.equal(await page.locator('label.option-card:has(#option-standard-normal) .recommended').textContent(),'Recommended');
    for(const name of ['Quick check + Normal','Quick check + Low-impact','Standard + Normal Recommended','Standard + Low-impact','Deep audit + Normal','Deep audit + Low-impact'])assert.equal(await group.getByRole('radio',{name,exact:true}).count(),1,name);
    await page.waitForFunction(()=>document.getElementById('option-quick-normal-facts')?.textContent==='6 websites at once · no browser · 256 MiB · 1 worker');
    assert.equal(await text(page,'option-deep-normal-facts'),'3 websites at once · 2 with the browser · 512 MiB · 2 workers');assert.equal(await text(page,'option-standard-low-impact-facts'),'2 websites at once · 1 with the browser · 256 MiB · 2 workers');assert.ok((await text(page,'option-standard-normal-summary')).length>20);
    assert.equal(await page.locator('#option-standard-normal').getAttribute('aria-describedby'),'option-standard-normal-summary option-standard-normal-facts');
    assert.match(await text(page,'option-description'),/depth 3/);assert.equal(await page.locator('#traffic-note').isHidden(),true);
    assert.equal(await page.locator('#scan-form input[type=number]').count(),0,'no number can be edited on the scan page');
    await page.locator('#urls').fill('https://www.example.com/');
    await page.waitForFunction(()=>/^Standard \+ Normal \(Recommended\) · 1 website \(\+ up to 50 discovered\) · up to 200 requests · about \d+ min at this pacing · 1 website at once, adjusted for 1 website$/.test(document.getElementById('profile-estimate-line')?.textContent||''));
    const table=await text(page,'profile-preview');assert.match(table,/Start estimate/);assert.match(table,/1 website entered · 1 domain group \(example\.com\) · up to 50 more discovered by domain scope/);assert.match(table,/What Standard examines/);assert.match(table,/Does not examine/);
    // The read-only panel: what the option uses for the entered websites on this computer.
    const uses=page.locator('#option-uses'),row=async(name:string)=>(await uses.locator('tr').filter({has:page.getByRole('rowheader',{name,exact:true})}).locator('td').textContent())||'';
    assert.equal(await text(page,'option-uses-title'),'What this option uses');assert.equal(await page.locator('#option-uses-panel').locator('input,select,textarea,[contenteditable]').count(),0,'read-only');
    assert.equal(await row('Websites at once'),'1 website at once, adjusted for 1 website · up to 4 once discovered websites are admitted');assert.equal(await row('Browser websites at once'),'1');assert.equal(await row('Analysis memory'),'256 MiB');assert.equal(await row('Analysis workers'),'2');assert.match(await row('Requests per website'),/^2 per second, \d+ at once$/);
    assert.match((await uses.textContent())!,/This computer: 16 logical cores, 32\.0 GiB free memory; nothing lowered\./);assert.match((await uses.textContent())!,/Read-only: the option sets these numbers/);
    const preview=await lastPreview(c=>c.coverage==='standard');assert.equal(preview.traffic,'normal');
    for(const k of ['maxResources','originMaxResources','maxAnalysisMemoryMb','analysisConcurrency','maxActiveOrigins','maxBrowserOrigins','requestsPerSecond','sharedLimits','preset','profileCustomized'])assert.equal(preview[k],undefined,k+' is not sent: the option sets it');
    // Ten websites: websites at once follow the website count (adjusted, never switched).
    await page.locator('#scan-advanced summary').click();await page.locator('#seed-urls').fill(Array.from({length:9},(_,i)=>`https://site${i}.example.net/`).join('\n'));
    await page.waitForFunction(()=>(document.getElementById('profile-estimate-line')?.textContent||'').endsWith(' · 4 websites at once, adjusted for 10 websites'));assert.equal(await row('Websites at once'),'4 websites at once, adjusted for 10 websites');assert.equal(await row('Browser websites at once'),'2');
    await page.locator('#seed-urls').fill('');await page.waitForFunction(()=>(document.getElementById('profile-estimate-line')?.textContent||'').endsWith(' · 1 website at once, adjusted for 1 website'));
    // Keyboard: one Tab stop for the group; arrows move and select with a visible focus ring; description, label, notes and estimate follow.
    await page.locator('#option-standard-normal').focus();await page.keyboard.press('ArrowRight');
    assert.equal(await page.locator('#option-standard-low-impact').isChecked(),true);assert.equal(await page.evaluate(()=>document.activeElement?.id),'option-standard-low-impact');
    assert.equal(await page.evaluate(()=>getComputedStyle(document.querySelector('#option-standard-low-impact + .option-body')!).outlineStyle),'solid','the focused option is visibly outlined');
    assert.equal(await text(page,'profile-label'),'Standard + Low-impact');assert.match(await text(page,'traffic-note'),/does not hide the scan/);assert.match(await text(page,'traffic-note'),/not undetectable/);
    await page.waitForFunction(()=>!document.getElementById('profile-slower')!.hidden&&document.getElementById('profile-slower')!.textContent!.startsWith('Standard + Low-impact will take longer: about'));
    await page.waitForFunction(()=>(document.getElementById('profile-estimate-line')?.textContent||'').startsWith('Standard + Low-impact · ')&&(document.getElementById('profile-estimate-line')?.textContent||'').endsWith(' · 1 website at once, adjusted for 1 website'));
    assert.match(await text(page,'profile-preview'),/Connections.*about \d+ \(at most 200\)/s);
    await page.keyboard.press('Tab');assert.notEqual(await page.evaluate(()=>(document.activeElement as HTMLInputElement)?.name),'ready-option','Tab leaves the group');
    await page.keyboard.press('Shift+Tab');assert.equal(await page.evaluate(()=>document.activeElement?.id),'option-standard-low-impact','Shift+Tab returns to the selected option');
    await page.keyboard.press('ArrowLeft');assert.equal(await page.locator('#option-standard-normal').isChecked(),true);assert.equal(await text(page,'profile-label'),'Standard + Normal (Recommended)');
    // Enter on an option never submits the scan form (authorization is unchecked here, so a submit would only show its refusal).
    await page.locator('#message').evaluate((e:HTMLElement)=>{e.textContent='';});await page.keyboard.press('Enter');await pause(200);assert.equal(await text(page,'message'),'','Enter on an option does not submit');assert.equal(await page.locator('#option-standard-normal').isChecked(),true);
    // Every card is a click target.
    await page.locator('label.option-card:has(#option-quick-normal)').click();assert.equal(await text(page,'profile-label'),'Quick check + Normal');assert.match(await text(page,'option-description'),/completed — quick coverage/);
    await page.waitForFunction(()=>document.getElementById('option-uses')?.textContent?.includes('None: no isolated browser'));assert.equal(await row('Analysis workers'),'1');assert.equal(await page.locator('#stage2-staleAssetCheck').isChecked(),false);
    await page.locator('label.option-card:has(#option-deep-normal)').click();assert.equal(await page.locator('#stage2-staleAssetCheck').isChecked(),true,'Deep audit revisits earlier assets');await page.waitForFunction(()=>document.getElementById('option-uses')?.textContent?.includes('512 MiB'));
    // Saving stores the option (no custom numbers); a new form returns to the Recommended option.
    await page.locator('#authorized').check();await page.locator('#save-project').click();await page.waitForFunction(()=>document.getElementById('message')?.textContent==='Authorized project saved locally.');
    const project=app.desk.store!.projects[0];assert.deepEqual([project.config.coverage,project.config.traffic,project.config.profileCustomized,project.config.maxAnalysisMemoryMb,project.config.staleAssetCheck],['deep','normal',undefined,512,true]);assert.deepEqual(project.config.sharedLimits,{});
    await page.locator('#project').selectOption('');assert.equal(await text(page,'profile-label'),'Standard + Normal (Recommended)');await page.locator('#project').selectOption(project.id);assert.equal(await text(page,'profile-label'),'Deep audit + Normal');assert.equal(await page.locator('#option-deep-normal').isChecked(),true);
    // A legacy JSON file loads as stored settings: no option is selected, the banner names the closest option, and one click switches (restorable).
    await upload(page,'legacy.json',{urls:['https://www.example.com/'],preset:'standard'});await page.waitForFunction(()=>document.getElementById('message')?.textContent?.startsWith('JSON specifications loaded'));
    assert.equal(await text(page,'profile-label'),'Legacy preset: standard');assert.equal(await group.locator('input:checked').count(),0);assert.equal(await page.locator('#profile-legacy').isVisible(),true);
    assert.equal(await text(page,'profile-legacy-text'),'Legacy preset: standard — from an older version. Its stored numbers apply until you switch; the closest ready option is Standard + Normal.');
    await page.waitForFunction(()=>document.getElementById('option-uses-title')?.textContent==='What the stored settings use');assert.match((await uses.textContent())!,/run as entered and are not adjusted to this computer/);assert.match((await uses.textContent())!,/Read-only: these numbers come from stored settings/);
    assert.equal(await page.locator('#stage2-staleAssetCheck').isChecked(),false);assert.equal(await page.locator('label.option-card.closest:has(#option-standard-normal)').count(),1,'the closest option is marked without keyboard focus');
    // Switch keeps keyboard focus on the chosen option; Restore puts back only the stored settings (the entered website stays) and returns focus to the switch.
    await page.getByRole('button',{name:'Switch to Standard + Normal (Recommended)'}).click();assert.equal(await page.locator('#option-standard-normal').isChecked(),true);assert.equal(await page.locator('#profile-legacy').isHidden(),true);assert.equal(await page.evaluate(()=>document.activeElement?.id),'option-standard-normal');assert.equal(await page.locator('.option-card.closest').count(),0);
    await page.locator('#urls').fill('https://www.example.org/');
    await page.getByRole('button',{name:'Restore Legacy preset: standard'}).click();assert.equal(await text(page,'profile-label'),'Legacy preset: standard');assert.equal(await page.locator('#profile-legacy').isVisible(),true);assert.equal(await group.locator('input:checked').count(),0);
    assert.equal(await page.locator('#urls').inputValue(),'https://www.example.org/','Restore keeps the entered website');assert.equal(await page.evaluate(()=>document.activeElement?.id),'profile-switch');
    // Saving after a switch ends the undo, so Restore cannot bring back settings the saved project no longer has.
    await page.locator('#profile-switch').click();assert.equal(await page.getByRole('button',{name:'Restore Legacy preset: standard'}).isVisible(),true);await page.locator('#authorized').check();await page.locator('#save-project').click();
    await page.waitForFunction(()=>document.getElementById('message')?.textContent==='Authorized project saved locally.');assert.equal(await page.locator('#profile-undo').isHidden(),true);
    const fromLegacy=app.desk.store!.projects.find(p=>p.config.urls[0]==='https://www.example.org/')!;assert.deepEqual([fromLegacy.config.coverage,fromLegacy.config.traffic,fromLegacy.config.preset==='standard'],['standard','normal',false]);
    // A file with its own numbers (a Quick check at 512 MiB) is a custom profile; values above the ceilings are refused and change nothing.
    await upload(page,'custom.json',{urls:['https://www.example.com/'],coverage:'quick',traffic:'normal',maxAnalysisMemoryMb:512});await page.waitForFunction(()=>document.getElementById('profile-label')?.textContent==='Custom (based on Quick check + Normal)');
    assert.equal(await text(page,'profile-legacy-text'),'Custom (based on Quick check + Normal): its own stored numbers, from an older version or a JSON file. They apply until you switch to a ready option.');await page.waitForFunction(()=>document.getElementById('option-uses')?.textContent?.includes('512 MiB'));
    await upload(page,'over.json',{urls:['https://www.example.com/'],coverage:'quick',maxAnalysisMemoryMb:1024});await page.waitForFunction(()=>/maxAnalysisMemoryMb/.test(document.getElementById('message')?.textContent||''));assert.equal(await text(page,'profile-label'),'Custom (based on Quick check + Normal)','a refused file changes nothing');
    await page.locator('#profile-switch').click();assert.equal(await text(page,'profile-label'),'Quick check + Normal');await page.waitForFunction(()=>document.getElementById('option-uses')?.textContent?.includes('256 MiB'));
    // A file without coverage never inherits the form's stored profile, preset or numbers: it loads as custom settings.
    await upload(page,'plain.json',{maxPages:12});await page.waitForFunction(()=>document.getElementById('profile-label')?.textContent==='Custom (from an older version)');assert.equal(await page.locator('#stage2-staleAssetCheck').isChecked(),false);
    assert.ok((await line()).startsWith('Quick check + Normal · '));
    assert.deepEqual(errors,[]);assert.deepEqual(dialogs,[]);
  }finally{await browser.close();await app.close();await rm(dir,{recursive:true,force:true});}
});
test('legacy projects: banner and one-click switch on the card and the scan page; runs, history and routines show the profile; reports carry the traffic accounting',{timeout:120000},async()=>{
  const dir=await temp(),local=await site();await mkdir(path.join(dir,'scans'),{recursive:true});
  const legacyRun='ffffffff-0000-4000-8000-0000000000bb',legacyFile=path.join(dir,'scans',legacyRun+'.json'),legacyRecord=JSON.stringify({schema:'exposure-history/2',savedAt:new Date().toISOString(),view:{schema:'exposure-scan/1',id:legacyRun,name:'Authorized website',state:'completed',startedAt:'2026-01-01T00:00:00.000Z',endedAt:'2026-01-01T00:01:00.000Z',elapsedMs:60000,config:{urls:['https://legacy-run.example.com/'],relatedOrigins:[],preset:'standard'},counts:{resources:2,scanned:2,blocked:0,bytes:5,pending:0,findings:0},engines:{websiteRules:'website/2.4.0',gitleaks:'8.30.1',ruleDigest:'x',companyRules:'none'},findings:[],resources:[],limitations:[]}});
  await writeFile(legacyFile,legacyRecord);
  const app=await startDashboard({port:0,persistent:true,dataDir:dir,syntheticData:true});
  const browser=await chromium.launch({headless:true,executablePath:dedicatedBrowser()||chromium.executablePath()});
  try{const store=app.desk.store!;
    const shop=await store.project({name:'Legacy shop',urls:['https://legacy-shop.example.org/'],preset:'thorough'},true),blog=await store.project({name:'Legacy blog',urls:['https://legacy-blog.example.org/'],preset:'quick'},true);
    // One finished profile run on the loopback site (a custom Quick check: a faster pace for the test).
    const scan=await app.desk.start({name:'Profile run',urls:[local.origin+'/'],developmentFixtureOrigin:local.origin,coverage:'quick',traffic:'normal',originRequestsPerSecond:20},undefined,false,undefined,undefined,{trigger:'manual'});
    for(let i=0;i<300&&scan.state==='running';i++)await pause(100);assert.equal(scan.state,'completed');
    const page=await browser.newPage(),errors:string[]=[],dialogs:string[]=[];page.setDefaultTimeout(10000);page.on('pageerror',e=>errors.push(e.message));page.on('dialog',d=>{dialogs.push(d.message());void d.dismiss();});
    await signIn(page,app);await page.locator('[data-view="projects"]').click();
    const shopAuthorized=store.projects.find(p=>p.id===shop.id)!.authorizedAt;const card=page.locator('#project-list article').filter({hasText:'Legacy shop'});
    await card.getByText('Legacy preset: thorough — from an older version. Its stored numbers apply until you switch; the closest ready option is Deep audit + Normal (single-website pacing).').waitFor();
    assert.equal(store.projects.find(p=>p.id===shop.id)!.config.coverage,undefined,'nothing changes until the owner clicks');
    // One click switches; focus returns to the project, and the message says what stays.
    await card.getByRole('button',{name:'Switch to Deep audit + Normal'}).click();await page.waitForFunction(()=>document.getElementById('message')?.textContent?.includes('Legacy shop now uses Deep audit + Normal'));
    assert.match(await text(page,'message'),/Scope, seeds, routes and privacy settings are unchanged; its earlier runs keep their recorded settings\./);await page.waitForFunction(id=>(document.activeElement as HTMLElement|null)?.dataset?.project===id,shop.id);
    assert.equal(store.projects.find(p=>p.id===shop.id)!.authorizedAt,shopAuthorized,'a switch keeps the authorization record');const switched=store.projects.find(p=>p.id===shop.id)!.config;assert.deepEqual([switched.coverage,switched.traffic,switched.urls],['deep','normal',['https://legacy-shop.example.org/']]);
    await page.waitForFunction(()=>[...document.querySelectorAll('#project-list article')].some(a=>a.textContent!.includes('Legacy shop')&&a.textContent!.includes('Deep audit + Normal · browser requested')&&!a.textContent!.includes('from an older version')));
    assert.equal(store.projects.find(p=>p.id===blog.id)!.config.coverage,undefined,'other projects are untouched');
    // Routines show the profile each project runs with.
    await page.locator('[data-view="settings"]').click();await page.waitForFunction(()=>document.getElementById('schedule-list')?.textContent?.includes('Profile: Legacy preset: quick'));assert.match(await text(page,'schedule-list'),/Profile: Deep audit \+ Normal/);
    // Scan-page switch: the banner names the closest option, no option is selected until the owner chooses, and focus moves to that option.
    await page.locator('[data-view="projects"]').click();const blogCard=page.locator('#project-list article').filter({hasText:'Legacy blog'});await blogCard.getByRole('button',{name:'Choose another option…'}).click();
    assert.equal(await page.locator('#profile-legacy').isVisible(),true);assert.equal(await text(page,'profile-legacy-text'),'Legacy preset: quick — from an older version. Its stored numbers apply until you switch; the closest ready option is Quick check + Normal.');
    assert.equal(await page.locator('input[name="ready-option"]:checked').count(),0);assert.equal(await page.evaluate(()=>document.activeElement?.id),'option-quick-normal','focus moves to the closest option');
    await page.waitForFunction(()=>document.getElementById('profile-preview')?.textContent?.includes('Legacy preset: quick: the stored numbers apply'));assert.equal(await text(page,'option-uses-title'),'What the stored settings use');
    await page.locator('#profile-switch').click();assert.equal(await page.locator('#option-quick-normal').isChecked(),true);assert.equal(await page.locator('#profile-legacy').isHidden(),true);await page.waitForFunction(()=>document.getElementById('message')?.textContent?.includes('save the project to keep it'));
    assert.equal(await page.getByRole('button',{name:'Restore Legacy preset: quick'}).isVisible(),true);
    assert.equal(store.projects.find(p=>p.id===blog.id)!.config.coverage,undefined,'nothing is saved until the owner saves');
    // A card switch of the project open in the form refreshes the form, so a later Save cannot undo the switch.
    await page.locator('label.option-card:has(#option-standard-normal)').click();assert.equal(await text(page,'profile-label'),'Standard + Normal (Recommended)');await page.locator('[data-view="projects"]').click();
    await blogCard.getByRole('button',{name:'Switch to Quick check + Normal'}).click();await page.waitForFunction(()=>document.getElementById('message')?.textContent?.includes('Legacy blog now uses Quick check + Normal'));
    await page.locator('[data-view="new"]').click();assert.equal(await text(page,'profile-label'),'Quick check + Normal');assert.equal(await page.locator('#profile-legacy').isHidden(),true);
    // Running scan and history: the profile, the honest Quick completion, the traffic received; older records say "Legacy preset".
    await page.locator('[data-view="running"]').click();await page.waitForFunction(()=>document.getElementById('run-history')?.textContent?.includes('legacy-run.example.com')||document.getElementById('current-run-body')?.textContent?.includes('Profile run'));
    const legacyRow=page.locator('#run-history .run-row').filter({hasText:'legacy-run.example.com'});assert.match((await legacyRow.textContent())!,/Legacy preset: standard/);
    const runText=(await page.locator('#current-run-body').textContent())!;assert.match(runText,/Custom \(based on Quick check \+ Normal\)/);
    await page.locator('#current-run-body').getByRole('button',{name:/^Open run/}).click();await page.waitForFunction(()=>document.getElementById('run-profile')?.textContent?.includes('Completed — quick coverage'));
    const panel=await text(page,'run-profile');assert.match(panel,/This does not show that the site has no secrets/);assert.match(panel,/Traffic: \d+ requests sent · \d+ connections? opened/);assert.match(panel,/Websites: 1 entered/);assert.match(panel,/Uses: 1 website at once, adjusted for 1 website/);
    await legacyRow.getByRole('button',{name:/^Open run/}).click();await page.waitForFunction(()=>document.getElementById('run-profile')?.textContent?.includes('profile not recorded'));assert.match(await text(page,'run-profile'),/^Legacy preset: standard — profile not recorded by unknown build\.Traffic: connection accounting not recorded by unknown build\./);
    await page.locator('[data-view="history"]').click();await page.waitForFunction(()=>document.getElementById('history-list')?.textContent?.includes('Legacy preset: standard'));
    // Reports: HTML shows the traffic line and what the option used, SARIF and JSON keep the profile and accounting.
    const html=report(scan,'html');assert.match(html,/<h2>Scan profile<\/h2>/);assert.match(html,/Traffic: \d+ connections? opened, \d+ kept-alive reuses?/);assert.match(html,/over one connection each/);assert.match(html,/Uses: 1 website at once, adjusted for 1 website/);
    const sarif=JSON.parse(report(scan,'sarif')).runs[0].invocations[0].properties;assert.equal(sarif.profile.label,'Custom (based on Quick check + Normal)');assert.equal(typeof sarif.accounting.connectionsOpened,'number');
    const json=JSON.parse(report(scan,'json'));assert.equal(json.profile.completion,'quick-coverage');assert.equal(json.run.profile.label,'Custom (based on Quick check + Normal)');assert.equal(json.profile.resourceUse.websites,1);
    assert.equal(await readFile(legacyFile,'utf8'),legacyRecord,'older history is never rewritten');assert.ok((await readdir(path.join(dir,'scans'))).includes(legacyRun+'.json'));
    assert.deepEqual(errors,[]);assert.deepEqual(dialogs,[]);
  }finally{await browser.close();await app.close();await local.close();await rm(dir,{recursive:true,force:true});}
});

test('Limited by profile (owner decision 2026-10-09): the run row, the run panel and the coverage note say so and no retry is offered; a run with a real gap stays incomplete and also mentions the limit',{timeout:180000},async()=>{
  // Two stored Standard + Low-impact runs made by the real scanner on the virtual network (synthetic data, nothing leaves the process).
  const detector=new Detector();await detector.init();const publicDns=async()=>[{address:'93.184.216.34',family:4}];
  const shape=async(name:string,variants:number,script='/app.js',extra:Record<string,{body:string;status?:number}>={})=>{
    const hosts={'https://example.com':{'/':{body:Array.from({length:variants},(_,i)=>`<a href="/list?page=${i+1}">${i+1}</a>`).join('')+`<script src="${script}"></script>`},'/list':{body:'list'},'/app.js':{type:'text/javascript',body:'void 0;'},'/app.js.map':{type:'application/json',body:JSON.stringify({version:3,sources:['a.ts'],sourcesContent:['void 0'],mappings:''})},...extra}};
    const s=new Scanner({urls:['https://example.com/'],coverage:'standard',traffic:'low-impact',browser:false},{detector,resolver:publicDns});try{virtualNetwork(s,hosts);const v=JSON.parse(JSON.stringify(await s.run()));v.name=name;return v;}finally{s.dispose();}};
  const limited=await shape('Limited run',3),both=await shape('Gap run',2,'/gone.js',{'/gone.js':{body:'missing',status:404}});assert.equal(limited.state,'completed');assert.equal(both.state,'incomplete');
  const dir=await temp();await mkdir(path.join(dir,'scans'),{recursive:true});
  for(const v of [limited,both])await writeFile(path.join(dir,'scans',v.id+'.json'),JSON.stringify({schema:'exposure-history/2',savedAt:new Date().toISOString(),view:v}));
  const app=await startDashboard({port:0,persistent:true,dataDir:dir,syntheticData:true});
  const browser=await chromium.launch({headless:true,executablePath:dedicatedBrowser()||chromium.executablePath()});
  try{const page=await browser.newPage(),errors:string[]=[];page.setDefaultTimeout(10000);page.on('pageerror',e=>errors.push(e.message));
    await signIn(page,app);await page.locator('[data-view="running"]').click();await page.waitForFunction(()=>document.getElementById('run-history')?.textContent?.includes('Gap run'));
    const row=page.locator('#run-history .run-row').filter({hasText:'Limited run'}),gapRow=page.locator('#run-history .run-row').filter({hasText:'Gap run'});
    assert.equal(await row.locator('.badge.completed').count(),1,'a non-error outcome');assert.equal(await row.locator('.badge.profile-limited').textContent(),'Limited by profile');
    assert.equal(await gapRow.locator('.badge.incomplete').count(),1);assert.equal(await gapRow.locator('.badge.profile-limited').count(),0);assert.match((await gapRow.textContent())!,/also limited by profile \(1 query variant not requested\)/);
    await row.getByRole('button',{name:/^Open run/}).click();await page.waitForFunction(()=>document.getElementById('run-profile')?.textContent?.includes('Limited by profile: Low-impact examines one query-string variant per path, so 2 other variants were not requested'));
    assert.match(await text(page,'run-profile'),/Standard \+ Normal visits up to 3 variants per path/);assert.match(await text(page,'coverage-note'),/Limited by profile/);
    assert.equal(await page.locator('#retry').isDisabled(),true,'nothing to retry');assert.match((await page.locator('#retry').getAttribute('title'))!,/outside this option’s stated boundary/);
    await gapRow.getByRole('button',{name:/^Open run/}).click();await page.waitForFunction(()=>document.getElementById('run-profile')?.textContent?.includes('Also limited by profile: '));
    assert.equal(await page.locator('#retry').isDisabled(),false,'a real gap keeps its retry offer');assert.match(await text(page,'coverage-note'),/Also limited by profile/);
    assert.deepEqual(errors,[]);
  }finally{await browser.close();await app.close();await rm(dir,{recursive:true,force:true});}
});
