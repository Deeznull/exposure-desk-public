import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { chromium } from 'playwright';
import { root } from '../src/detectors.js';
import { startDashboard } from '../src/dashboard.js';
import { dedicatedBrowser } from '../src/runtime-paths.js';
/** 2.7 host validation (w2-hosts): a project saved by an earlier build with an invalid host loads in the dashboard with a visible warning, stays editable,
 * and a scan start shows the server's refusal like any other validation error. Synthetic names only; nothing is requested. */
const message=(host:string)=>`Refused: "${host}" is not a valid website host. A host uses letters, digits, hyphens and underscores (international names are converted automatically) or is an IP address. Nothing was requested.`;
test('dashboard UI: a saved project with an invalid host shows the warning, stays selectable for editing, and queueing it shows the refusal',{timeout:120000},async()=>{
  const parent=process.env.EXPOSURE_DATA_DIR||path.join(root,'.cache');await mkdir(parent,{recursive:true});
  const dir=await mkdtemp(path.join(parent,'hosts-ui-')),badId='66666666-6666-4666-8666-666666666666',now=new Date().toISOString(),host='shop{old}.example.com';
  await writeFile(path.join(dir,'workspace.json'),JSON.stringify({schema:'exposure-workspace/3',projects:[{id:badId,createdAt:now,authorizedAt:now,config:{name:'Old shop',urls:['https://shop{old}.example.com/']}}],reviews:{},settings:{retentionDays:90,maxScans:100,vaultMinutes:5},rules:[],ruleVersions:[],alerts:[]}));
  const app=await startDashboard({port:0,persistent:true,dataDir:dir,syntheticData:true}),browser=await chromium.launch({headless:true,executablePath:dedicatedBrowser()||chromium.executablePath()});
  try{const page=await browser.newPage(),errors:string[]=[];page.on('pageerror',e=>errors.push(e.message));page.setDefaultTimeout(10000);
    await page.goto(app.origin);await page.locator('#token').fill(app.token);await page.locator('#login-form button').click();await page.locator('#workspace').waitFor({state:'visible'});await page.locator('[data-view="projects"]').click();
    const card=page.locator('#project-list article',{hasText:'Old shop'});await card.waitFor({state:'visible'});
    assert.ok((await card.textContent())!.includes('Cannot scan: "'+host+'" is not a valid website host (saved by an earlier version). Edit the project to correct the address and save it, or delete it. Nothing is requested until then.'),'the warning is shown on the card');
    assert.ok((await card.textContent())!.includes('https://shop{old}.example.com/'),'the saved address is displayed as stored');
    assert.deepEqual(await page.locator('#project option[value="'+badId+'"]').evaluate(o=>[(o as HTMLOptionElement).disabled,o.textContent]),[false,'Old shop (cannot scan: invalid host)'],'it stays selectable so it can be corrected');
    await card.getByRole('button',{name:'Queue scan'}).click();await page.waitForFunction(()=>document.getElementById('message')?.textContent?.startsWith('Refused:'));
    assert.equal(await page.locator('#message').textContent(),message(host),'the refusal is shown like any other validation error');
    assert.equal(app.scans.size,0);assert.deepEqual(errors,[]);
  }finally{await browser.close();await app.close();await rm(dir,{recursive:true,force:true});}
});
