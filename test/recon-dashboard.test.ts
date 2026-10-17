import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { mkdtemp, mkdir, writeFile, stat, rm } from 'node:fs/promises';
import { startDashboard } from '../src/dashboard.js';
import { createFixture, synthetic } from '../src/fixture.js';
import { Store } from '../src/storage.js';
import { root } from '../src/detectors.js';
/**
 * w2-wire: the dashboard exposes recon lists and masked submission Markdown for a stored run. Hard rules under test: both carry the same
 * host/origin/CSRF checks as their neighbours, the recon download is GET-only over a fixed allow-list (no path traversal), and nothing served
 * holds a full synthetic value. Loopback fixture and synthetic keys only.
 */
const pause=(ms:number)=>new Promise(r=>setTimeout(r,ms));
async function temp(prefix:string){const parent=process.env.EXPOSURE_DATA_DIR||path.join(root,'.cache');await mkdir(parent,{recursive:true});return mkdtemp(path.join(parent,prefix));}

test('dashboard recon download and masked submission Markdown: auth/CSRF/allow-list, masking, and history after reload',{timeout:300000},async()=>{
  const fixture=await createFixture(0,{minimalDiscovery:true});
  const dataDir=await temp('recon-dash-');
  const app=await startDashboard({port:0,persistent:true,dataDir,syntheticData:true});
  let id='';
  try{
    // Log in and run one synthetic scan to completion so recon lists are written under the data dir.
    const login=await fetch(app.origin+'/api/login',{method:'POST',headers:{'Content-Type':'application/json',Origin:app.origin,'X-Dashboard-Request':'1'},body:JSON.stringify({token:app.token})});
    assert.equal(login.status,200);const {csrf}=await login.json() as any;const cookie=login.headers.get('set-cookie')!.split(';')[0];
    const headers={'Content-Type':'application/json',Origin:app.origin,'X-Dashboard-Request':'1','X-CSRF-Token':csrf,Cookie:cookie};
    const post=(route:string,data:unknown,h:Record<string,string>=headers)=>fetch(app.origin+route,{method:'POST',headers:h,body:JSON.stringify(data)});
    const started=await post('/api/scans',{authorized:true,config:{name:'Synthetic recon test',urls:[fixture.origin+'/'],developmentFixtureOrigin:fixture.origin,requestsPerSecond:20,adjacentMaps:false,browser:false}});
    assert.equal(started.status,202);id=(await started.json() as any).id;
    let view:any;for(let i=0;i<150;i++){view=await(await fetch(app.origin+'/api/scans/'+id,{headers:{Cookie:cookie}})).json();if(view.state!=='running')break;await pause(100);}
    // Any terminal state is fine (browser:false leaves runtime-only resources as gaps -> 'incomplete'); recon lists are written on finish regardless.
    assert.ok(view.state!=='running'&&view.state!=='queued',JSON.stringify(view).slice(0,400));
    assert.ok(view.findings.length>=1,'the inline fixture key is found by static analysis');
    // Recon lists are written during finish(), after the view turns terminal; wait until the last file (recon.json) is on disk.
    let reconReady=false;for(let i=0;i<100;i++){if((await fetch(app.origin+`/api/scans/${id}/recon/recon.json`,{headers:{Cookie:cookie}})).status===200){reconReady=true;break;}await pause(50);}
    assert.ok(reconReady,'recon lists are written after the scan finishes');

    // --- Recon download route ---
    // No session cookie -> 401 (gated like every other /api route, before the recon handler runs).
    assert.equal((await fetch(app.origin+`/api/scans/${id}/recon/urls.txt`)).status,401);
    // POST is rejected: without CSRF the generic POST gate (403) fires first; with CSRF the recon route itself answers 405 (GET only).
    assert.equal((await post(`/api/scans/${id}/recon/urls.txt`,{},{...headers,'X-CSRF-Token':''})).status,403);
    assert.equal((await post(`/api/scans/${id}/recon/urls.txt`,{})).status,405);
    // A name outside the fixed allow-list is a 404, never a file read.
    assert.equal((await fetch(app.origin+`/api/scans/${id}/recon/secrets.txt`,{headers:{Cookie:cookie}})).status,404);
    // A traversal attempt never serves a file: the URL parser normalises the dot segments away, so it cannot reach the allow-listed handler.
    assert.notEqual((await fetch(app.origin+`/api/scans/${id}/recon/..%2F..%2Fsettings.json`,{headers:{Cookie:cookie}})).status,200);
    // Allowed names are served as masked attachments.
    for(const name of ['urls.txt','recon.json']){
      const r=await fetch(app.origin+`/api/scans/${id}/recon/${name}`,{headers:{Cookie:cookie}});
      assert.equal(r.status,200,name);
      assert.match(r.headers.get('content-disposition')||'',new RegExp(`attachment; filename="${name.replace('.','\\.')}"`));
      const body=await r.text();
      for(const v of [synthetic.openai,synthetic.anthropic,synthetic.supabase,synthetic.stripe])assert.ok(!body.includes(v),`${name} must not contain a full value`);
      assert.ok(body.includes('127.0.0.1'),`${name} should list the loopback host`);
    }

    // --- Masked submission Markdown (live run in memory) ---
    const finding=view.findings.find((f:any)=>f.provider==='OpenAI')||view.findings[0];assert.ok(finding,'a finding to submit');
    assert.equal((await post(`/api/scans/${id}/submission`,{findingId:finding.id},{...headers,'X-CSRF-Token':''})).status,403,'submission needs CSRF like its neighbours');
    const unknown=await post(`/api/scans/${id}/submission`,{findingId:'no-such-finding'});assert.equal(unknown.status,400,'unknown finding is a 400');
    const sub=await post(`/api/scans/${id}/submission`,{findingId:finding.id});assert.equal(sub.status,200);
    const doc=await sub.json() as any;assert.ok(typeof doc.markdown==='string'&&doc.markdown.length>0);assert.ok('title' in doc&&'fileName' in doc);
    assert.ok(!JSON.stringify(doc).includes(synthetic.openai),'submission Markdown must be masked');
  }finally{await app.close();await fixture.close();}

  // --- History submission action: reload the persistent store so the run is retained history, not an in-memory scan ---
  const app2=await startDashboard({port:0,persistent:true,dataDir,syntheticData:true});
  try{
    const login=await fetch(app2.origin+'/api/login',{method:'POST',headers:{'Content-Type':'application/json',Origin:app2.origin,'X-Dashboard-Request':'1'},body:JSON.stringify({token:app2.token})});
    const {csrf}=await login.json() as any;const cookie=login.headers.get('set-cookie')!.split(';')[0];
    const headers={'Content-Type':'application/json',Origin:app2.origin,'X-Dashboard-Request':'1','X-CSRF-Token':csrf,Cookie:cookie};
    const hist=await(await fetch(app2.origin+'/api/scans/'+id,{headers:{Cookie:cookie}})).json() as any;
    const f=hist.findings.find((x:any)=>x.provider==='OpenAI')||hist.findings[0];assert.ok(f,'retained finding');
    const sub=await fetch(app2.origin+`/api/scans/${id}/submission`,{method:'POST',headers,body:JSON.stringify({findingId:f.id})});
    assert.equal(sub.status,200,'history submission action is available');
    const doc=await sub.json() as any;assert.ok(typeof doc.markdown==='string');assert.ok(!JSON.stringify(doc).includes(synthetic.openai),'history submission must be masked');
    // The recon download still resolves from the reloaded store.
    assert.equal((await fetch(app2.origin+`/api/scans/${id}/recon/recon.json`,{headers:{Cookie:cookie}})).status,200);
  }finally{await app2.close();await rm(dataDir,{recursive:true,force:true});}
});

test('Store.deleteScan removes the run\'s recon folder',async()=>{
  const dir=await temp('recon-store-');try{
    const store=await new Store(dir,true).init();
    const uuid='00000000-0000-4000-8000-000000000001';
    await mkdir(path.join(dir,'recon',uuid),{recursive:true});
    await writeFile(path.join(dir,'recon',uuid,'urls.txt'),'127.0.0.1\n');
    await store.deleteScan(uuid);
    await assert.rejects(stat(path.join(dir,'recon',uuid)),'recon/<id> must be gone');
    store.close();
  }finally{await rm(dir,{recursive:true,force:true});}
});
