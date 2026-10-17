import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { cp, mkdtemp, mkdir, readFile, rm } from 'node:fs/promises';
import { Store, compareScans } from '../src/storage.js';
import { Vault } from '../src/vault.js';
import { root } from '../src/detectors.js';
import { makeConfig } from '../src/config.js';
import { effectiveScope } from '../src/domain-scope.js';
import { focusedRetry, resumeFrontier } from '../src/retry.js';
import { runSummary } from '../src/runs.js';
import { startDashboard } from '../src/dashboard.js';
const FIXTURE=path.join(root,'test','fixtures','legacy-2.4');
/** The fixture was written by the 2.4.0-rc.1 code itself (Store, Vault, Scanner). It is always copied first: opening it recovers the interrupted run in place. */
async function copy(){const parent=process.env.EXPOSURE_DATA_DIR||path.join(root,'.cache');await mkdir(parent,{recursive:true});const dir=await mkdtemp(path.join(parent,'legacy-'));await cp(FIXTURE,dir,{recursive:true});return dir;}
test('a 2.4.0-rc.1 data directory opens in 2.5: projects keep exact-origin scope for review, history, reviews, keys and the vault survive, nothing is widened',async()=>{
  const dir=await copy(),meta=JSON.parse(await readFile(path.join(FIXTURE,'FIXTURE.json'),'utf8')),before=JSON.parse(await readFile(path.join(dir,'workspace.json'),'utf8'));
  try{const st=await new Store(dir,true).init();
    assert.equal(st.projects.length,3);for(const p of st.projects){assert.equal(effectiveScope(p.config),'exact-origin','saved 2.4 projects are not widened');assert.equal(p.config.scopeReview?.reason,'legacy-default-exact-origin');assert.equal(p.config.sameRegistrableDomainDiscovery,false,'the downgrade mirror is kept');}
    assert.deepEqual(st.projects.map(p=>p.id).sort(),before.projects.map((p:any)=>p.id).sort());assert.deepEqual(st.projects.map(p=>p.config.urls),before.projects.map((p:any)=>p.config.urls));assert.deepEqual(Object.keys(st.reviews),Object.keys(before.reviews));
    assert.equal(st.history.length,4);const recovered=st.history.find(h=>h.view.stopReason==='application-interrupted');assert.ok(recovered,'the interrupted 2.4 run is recovered as incomplete');assert.equal(recovered!.view.state,'incomplete');
    for(const h of st.history){const s=runSummary({view:h.view,projectId:h.projectId,savedAt:h.savedAt});assert.equal(s.triggerLabel,'Trigger not recorded');assert.equal(s.label,'www.example.com','legacy default names are labeled by host');assert.ok(h.view.findings.every(f=>f.priority?.version==='priority/1'),'old findings are assessed in memory');}
    const ordered=st.history.map(h=>Date.parse(h.view.startedAt||h.savedAt));assert.deepEqual(ordered,[...ordered].sort((a,b)=>a-b),'history is chronological');
    const p1=meta.projects.p1,[a,b]=st.history.filter(h=>h.view.state==='completed');assert.ok(compareScans(a,b),'comparisons work on legacy records');
    st.applyReviews(p1,a.view.findings);const f=a.view.findings[0];assert.match(f.lifecycle!.removalReported!.note,/Legacy 2\.4/);assert.equal(f.lifecycle!.revocation,undefined);
    const suppressed=st.history.flatMap(h=>{st.applyReviews(p1,h.view.findings);return h.view.findings;}).find(f=>f.suppression);assert.ok(suppressed,'the 2.4 suppression still applies');
    assert.equal((await st.key(p1)).length,32,'correlation keys are intact');
    const vault=new Vault(st);await vault.init();await vault.unlock(meta.vaultPassword,false);const values=await vault.get(meta.vaultScan);assert.ok(Object.values(values).some((v:any)=>String(v.value).startsWith('sk_live_LegacyFixture24')),'the encrypted 2.4 evidence decrypts');vault.lock();
    const checkpoint=JSON.parse(await readFile(path.join(dir,'checkpoint.json'),'utf8'));assert.equal(effectiveScope(makeConfig(checkpoint.config)),'exact-origin','a 2.4 checkpoint resumes with the scope that ran');assert.ok(Array.isArray(resumeFrontier(checkpoint.frontier||[],100)));
    const plan=focusedRetry(recovered!.view);assert.equal(plan.sourceScan,recovered!.view.id);
    st.close();
  }finally{await rm(dir,{recursive:true,force:true});}
});
test('the 2.5 dashboard lists the legacy runs with their labels and serves their views without rewriting history files',{timeout:30000},async()=>{
  const dir=await copy();try{const files=['542f2d9b-0d1a-4e6d-a8e8-1b2698bb7c33','7755b7b3-be0a-440f-a069-6cf13ed59dcd','a5f42f89-fa76-4fca-80a1-01ec13f4a596','d817ca8c-3ad3-40d0-9c58-65948f5fef93'];
    const app=await startDashboard({port:0,persistent:true,dataDir:dir,syntheticData:true});const after=await Promise.all(files.map(f=>readFile(path.join(dir,'scans',f+'.json'),'utf8')));
    try{const login=await fetch(app.origin+'/api/login',{method:'POST',headers:{'Content-Type':'application/json',Origin:app.origin,'X-Dashboard-Request':'1'},body:JSON.stringify({token:app.token})});const cookie=login.headers.get('set-cookie')!.split(';')[0];
      const runs=await(await fetch(app.origin+'/api/runs',{headers:{Cookie:cookie}})).json() as any;assert.equal(runs.history.length,4);assert.ok(runs.history.every((r:any)=>r.triggerSource==='unavailable'&&r.label==='www.example.com'));assert.equal(runs.history.filter((r:any)=>r.interrupted).length,1);
      const workspace=await(await fetch(app.origin+'/api/workspace',{headers:{Cookie:cookie}})).json() as any;assert.equal(workspace.projects.length,3);assert.ok(workspace.projects.every((p:any)=>p.config.scopeReview));
      for(const r of runs.history){const v=await(await fetch(app.origin+'/api/scans/'+r.id,{headers:{Cookie:cookie}})).json() as any;assert.equal(v.id,r.id);assert.ok(!JSON.stringify(v).includes('sk_live_LegacyFixture24'));}
      const now=await Promise.all(files.map(f=>readFile(path.join(dir,'scans',f+'.json'),'utf8')));assert.deepEqual(now,after,'listing and reading never rewrite history');
    }finally{await app.close();}
  }finally{await rm(dir,{recursive:true,force:true});}
});
