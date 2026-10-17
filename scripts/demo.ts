import { createFixture } from '../src/fixture.js';
import { startDashboard } from '../src/dashboard.js';
const fixture=await createFixture(4321);
const clean=await createFixture(4322,{minimalDiscovery:true});
const app=await startDashboard({projects:[{name:'Synthetic demo shop (local fixture)',urls:[fixture.origin],developmentFixtureOrigin:fixture.origin,coverage:'standard',traffic:'normal'},{name:'Synthetic fixture · all modes',urls:[fixture.origin],developmentFixtureOrigin:fixture.origin,browser:true,deep:true,maxResourceBytes:65536,requestsPerSecond:10,maxResources:180,timeoutMs:3000,maxDurationMs:180000},{name:'Synthetic fixture · clean page',urls:[clean.origin+'/clean'],developmentFixtureOrigin:clean.origin,browser:false,deep:false,adjacentMaps:false,maxDepth:0,requestsPerSecond:10}]});
fixture.setDashboardOrigin(app.origin);
console.log(`Fixture: ${fixture.origin}\nDashboard: ${app.origin}\nPer-launch token: ${app.token}\nNew scan → Advanced → Saved project: pick a synthetic project, confirm authorization and start (docs/DEMO.md has a walkthrough). Ctrl+C to stop.`);
let stopping=false;process.on('SIGINT',()=>void(async()=>{if(stopping)return;stopping=true;await app.close();await fixture.close();await clean.close();})());
