// Captures the README/one-pager screenshots from a synthetic loopback fixture; it contacts no website.
// Run from the project root after a build, with an absolute EXPOSURE_DATA_DIR and SCANNER_CHROMIUM_PATH
// (and GITLEAKS_PATH) set:  node scripts/screenshots.mjs [outDir, default docs/screenshots]
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {createRequire} from 'node:module';
import {mkdirSync,rmSync} from 'node:fs';
const root=process.cwd(),out=path.resolve(process.argv[2]||'docs/screenshots');mkdirSync(out,{recursive:true});
const {createFixture}=await import(pathToFileURL(path.join(root,'dist/src/fixture.js')).href);
const {startDashboard}=await import(pathToFileURL(path.join(root,'dist/src/dashboard.js')).href);
const {chromium}=createRequire(path.join(root,'package.json'))('playwright');
const fixture=await createFixture(4321);
const app=await startDashboard({portFallback:true,projects:[{name:'Synthetic demo shop (local fixture)',urls:[fixture.origin],developmentFixtureOrigin:fixture.origin,coverage:'standard',traffic:'normal'}]});
fixture.setDashboardOrigin(app.origin);
const browser=await chromium.launch({executablePath:process.env.SCANNER_CHROMIUM_PATH,headless:true});
const context=await browser.newContext({viewport:{width:1366,height:900},deviceScaleFactor:1,acceptDownloads:true,colorScheme:'light'});
const page=await context.newPage();
const shot=async(name,opts={})=>{await page.waitForTimeout(400);await page.screenshot({path:path.join(out,name),...opts});console.log('saved',name);};
const log=m=>console.log(m);
try{
 await page.goto(app.origin+'/');
 await page.fill('#token',app.token);await page.click('#login-form button');
 await page.waitForSelector('#workspace:not([hidden])',{timeout:15000});
 await page.click('button[data-view="new"]');
 await page.click('#scan-advanced summary');await page.selectOption('#project','legacy-0');await page.waitForTimeout(800);await page.click('#scan-advanced summary');
 const card=page.locator('#option-standard-normal');if(await card.count())await card.click();
 await page.check('#authorized');await page.waitForTimeout(800);
 await page.evaluate(()=>window.scrollTo(0,0));await shot('1-new-scan.png',{fullPage:true,clip:{x:0,y:0,width:1366,height:1580}});
 await page.click('#start');
 await page.waitForSelector('section[data-page="running"]:not([hidden])',{timeout:20000});
 await page.waitForTimeout(9000);await page.evaluate(()=>{document.getElementById('message').style.visibility='hidden';});await page.evaluate(()=>window.scrollTo(0,0));
 await shot('2-running.png',{fullPage:true,clip:{x:0,y:0,width:1366,height:1260}});
 const t0=Date.now();
 while(Date.now()-t0<240000){const s=(await page.textContent('#state'))||'';if(/completed|incomplete|failed|cancelled/i.test(s))break;await page.waitForTimeout(2000);}
 log('state '+(await page.textContent('#state')));
 await page.click('button[data-view="findings"]');await page.waitForTimeout(1500);
 await page.evaluate(()=>{document.getElementById('message').style.visibility='hidden';});await page.evaluate(()=>window.scrollTo(0,0));await shot('3-findings.png',{fullPage:true,clip:{x:0,y:0,width:1366,height:1500}});
 const formats=await page.$$eval('#format option',o=>o.map(x=>x.value));log('formats '+formats.join(','));
 if(formats.includes('html'))await page.selectOption('#format','html');
 const [download]=await Promise.all([page.waitForEvent('download',{timeout:20000}),page.click('#export')]);
 const reportPath=path.join(out,'report.tmp.html');await download.saveAs(reportPath);log('report '+download.suggestedFilename());
 const rp=await context.newPage();await rp.goto(pathToFileURL(reportPath).href);await rp.waitForTimeout(800);await rp.setViewportSize({width:1100,height:900});await rp.screenshot({path:path.join(out,'4-report.png'),fullPage:true,clip:{x:0,y:0,width:1100,height:1300}});log('saved 4-report.png');await rp.close();rmSync(reportPath,{force:true});
 await page.click('button[data-view="new"]');
 await page.click('#scan-advanced summary');await page.selectOption('#project','');await page.click('#scan-advanced summary');await page.waitForTimeout(500);
 await page.evaluate(()=>{document.getElementById('message').style.visibility='';});await page.fill('#urls','https://portal.agency-example.gov/');
 await page.check('#authorized');await page.click('#start');await page.waitForTimeout(1500);await page.evaluate(()=>window.scrollTo(0,0));await page.waitForTimeout(300);
 await shot('5-protected-refused.png');
}catch(e){console.log('ERROR',e.message);await page.screenshot({path:path.join(out,'error.png'),fullPage:true}).catch(()=>{});}
finally{await browser.close();await app.close();await fixture.close();}
