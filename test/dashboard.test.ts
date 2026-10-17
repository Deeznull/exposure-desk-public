import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { startDashboard } from '../src/dashboard.js';
import { createFixture, synthetic } from '../src/fixture.js';
const pause=(ms:number)=>new Promise(r=>setTimeout(r,ms));
test('dashboard authentication, Host/Origin/CORS/CSRF isolation, deliberate reveal/copy/export, suppression and deletion',async()=>{
  const fixture=await createFixture(0,{minimalDiscovery:true}),app=await startDashboard({port:0});try{
    const initial=await(await fetch(app.origin)).text();assert.ok(!initial.includes(synthetic.openai)&&!initial.includes(app.token));assert.ok(initial.includes('Reveal')===false,'Initial HTML must not contain secret values');
    assert.ok((await fetch(app.origin+'/api/scans')).status===401);
    const bad=await fetch(app.origin+'/api/login',{method:'POST',headers:{'Content-Type':'application/json','Origin':'https://attacker.example','X-Dashboard-Request':'1'},body:JSON.stringify({token:app.token})});assert.ok(bad.status===403);assert.ok(!bad.headers.has('access-control-allow-origin'));
    const hostileHost=await new Promise<number>(resolve=>{http.get(app.origin+'/api/scans',{headers:{host:'attacker.example'}},r=>{r.resume();resolve(r.statusCode||0);});});assert.ok(hostileHost===403);
    const login=await fetch(app.origin+'/api/login',{method:'POST',headers:{'Content-Type':'application/json',Origin:app.origin,'X-Dashboard-Request':'1'},body:JSON.stringify({token:app.token})});assert.ok(login.status===200);const cookie=login.headers.get('set-cookie')!.split(';')[0];assert.ok(login.headers.get('set-cookie')!.includes('HttpOnly')&&login.headers.get('set-cookie')!.includes('SameSite=Strict'));const {csrf}=await login.json() as any;
    const headers={'Content-Type':'application/json',Origin:app.origin,'X-Dashboard-Request':'1','X-CSRF-Token':csrf,Cookie:cookie};
    const post=(route:string,data:unknown,h=headers)=>fetch(app.origin+route,{method:'POST',headers:h,body:JSON.stringify(data)});
    const noCsrf={...headers,'X-CSRF-Token':''};assert.ok((await post('/api/scans',{config:{urls:[fixture.origin]}},noCsrf)).status===403);
    assert.equal((await post('/api/scans',{config:{name:'Synthetic API test',urls:[fixture.origin+'/.env'],developmentFixtureOrigin:fixture.origin,requestsPerSecond:20,adjacentMaps:false}})).status,400,'Starting a scan requires the server-side authorization acknowledgement');
    const response=await post('/api/scans',{authorized:true,config:{name:'Synthetic API test',urls:[fixture.origin+'/.env'],developmentFixtureOrigin:fixture.origin,requestsPerSecond:20,adjacentMaps:false}});assert.ok(response.status===202);const {id}=await response.json() as any;
    let view:any;for(let i=0;i<150;i++){view=await(await fetch(app.origin+'/api/scans/'+id,{headers:{Cookie:cookie}})).json();if(view.state!=='running')break;await pause(100);}assert.ok(view.state==='completed');
    assert.ok(!JSON.stringify(view).includes(synthetic.openai),'Routine dashboard payload must not contain full value');assert.ok(!JSON.stringify(await(await fetch(app.origin+'/api/scans',{headers:{Cookie:cookie}})).json()).includes(synthetic.openai));
    const finding=view.findings.find((f:any)=>f.provider==='OpenAI');assert.ok(!!finding);
    assert.ok((await fetch(app.origin+`/api/scans/${id}/reveal`,{headers:{Cookie:cookie}})).status===405);
    assert.ok((await post(`/api/scans/${id}/reveal`,{findingId:finding.id})).status===400);
    for(const action of ['reveal','copy']){const r=await post(`/api/scans/${id}/reveal`,{findingId:finding.id,action});assert.ok(r.headers.get('cache-control')==='no-store');const full=await r.json() as any;assert.ok(full.value===synthetic.openai,'Deliberate value action must return exact full value');}
    for(const format of ['json','html','sarif']){const redacted=await(await post(`/api/scans/${id}/export`,{format})).text();assert.ok(!redacted.includes(synthetic.openai));const full=await(await post(`/api/scans/${id}/export`,{format,full:true,confirm:'sensitive-local-export'})).text();assert.ok(full.includes(synthetic.openai));}
    assert.ok((await post(`/api/scans/${id}/export`,{format:'json',full:true})).status===400);
    const checkpoint=await(await post(`/api/scans/${id}/checkpoint`,{})).text();assert.ok(!checkpoint.includes(synthetic.openai));
    const expires=new Date(Date.now()+60000).toISOString();assert.ok((await post(`/api/scans/${id}/suppress`,{findingId:finding.id,reason:'Reviewed synthetic test',expires})).status===200);view=await(await fetch(app.origin+'/api/scans/'+id,{headers:{Cookie:cookie}})).json();assert.ok(view.findings.find((f:any)=>f.id===finding.id).suppression.reason==='Reviewed synthetic test');
    assert.ok((await post(`/api/scans/${id}/unsuppress`,{findingId:finding.id})).status===200);
    const rescanned=await post(`/api/scans/${id}/rescan`,{findingId:finding.id});assert.ok(rescanned.status===202);const rescanId=(await rescanned.json() as any).id;
    for(let i=0;i<150;i++){const v=await(await fetch(app.origin+'/api/scans/'+rescanId,{headers:{Cookie:cookie}})).json() as any;if(v.state!=='running'){assert.ok(v.config.urls.every((u:string)=>u===fixture.origin+'/.env'));break;}await pause(100);}
    const resumed=await post('/api/resume',{checkpoint:JSON.parse(checkpoint)});assert.ok(resumed.status===202);const resumedId=(await resumed.json() as any).id;await post(`/api/scans/${resumedId}/cancel`,{});
    assert.ok((await post(`/api/scans/${id}/delete`,{})).status===200);assert.ok((await post(`/api/scans/${id}/reveal`,{findingId:finding.id,action:'reveal'})).status===410);
    assert.ok(!fixture.arrivals.some(a=>/collect|write|external:/.test(a.path)));
  }finally{await app.close();await fixture.close();}
});
test('dashboard serves scanned strings as text and has restrictive security headers',async()=>{
  const app=await startDashboard({port:0});try{
    const html=await fetch(app.origin);assert.ok(html.headers.get('content-security-policy')?.includes("frame-ancestors 'none'"));assert.ok(html.headers.get('x-frame-options')==='DENY');assert.ok(html.headers.get('x-content-type-options')==='nosniff');assert.ok(html.headers.get('cache-control')==='no-store');
    const js=await(await fetch(app.origin+'/app.js')).text();assert.ok(!js.includes('innerHTML')&&!js.includes('localStorage')&&!js.includes('sessionStorage'));
    assert.ok((await fetch(app.origin+'/.env')).status===404);assert.ok((await fetch(app.origin+'/api/scans',{headers:{Origin:'null'}})).status===403);
  }finally{await app.close();}
});
test('JSON scan specifications preview validates the same configuration used by scans',async()=>{
  const app=await startDashboard({port:0});try{
    assert.equal((await fetch(app.origin+'/api/config/preview',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'})).status,403);
    const login=await fetch(app.origin+'/api/login',{method:'POST',headers:{'Content-Type':'application/json',Origin:app.origin,'X-Dashboard-Request':'1'},body:JSON.stringify({token:app.token})});
    const {csrf}=await login.json() as any,cookie=login.headers.get('set-cookie')!.split(';')[0];
    const headers={'Content-Type':'application/json',Origin:app.origin,'X-Dashboard-Request':'1','X-CSRF-Token':csrf,Cookie:cookie};
    const post=(config:unknown)=>fetch(app.origin+'/api/config/preview',{method:'POST',headers,body:JSON.stringify({config})});
    const valid=await post({urls:['https://one.example/','https://two.example/'],autoScaleByWebsiteCount:true,maxPages:12});
    assert.equal(valid.status,200);const config=await valid.json() as any;
    assert.equal(config.maxPages,12,'preview retains editable base limits');assert.equal(config.autoScaleByWebsiteCount,true);
    assert.equal((await post({urls:['https://one.example/'],maxPages:9999})).status,400);
    assert.equal((await post({urls:['https://one.example/'],autoScaleByWebsiteCount:'yes'})).status,400);
  }finally{await app.close();}
});
