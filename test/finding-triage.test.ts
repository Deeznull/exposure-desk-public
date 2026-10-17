import test from 'node:test';
import assert from 'node:assert/strict';
import {Evidence} from '../src/evidence.js';
import {Detector} from '../src/detectors.js';
import type {Candidate} from '../src/types.js';
import {classifyFinding} from '../src/finding-triage-rules.js';
test('parallel triage classifies leaks and removes benign observations from findings and full exports',async()=>{
  const e=new Evidence(new Detector('disabled'));e.startTriage(()=>assert.fail('Worker must execute'));
  const add=(category:Candidate['category'],confidence:Candidate['confidence'],value:string,evidence='Unauthenticated HTTP response')=>e.add({category,confidence,value,original:value,index:0,rule:'test-credential',provider:'Test',severity:'high',reasons:[],transformations:[]},value,'https://example.com',[],evidence);
  try{const direct=add('private-credential','high','private-value'),high=add('suspicious','medium','uncertain-value'),low=add('suspicious','low','review-value'),blocked=add('private-credential','high','blocked-value','Locally observed candidate; never transmitted'),local=add('private-credential','high','local-value','Owner-supplied local artifact');
    const benign=add('public-identifier','high','public-value');e.observe('https://example.com/app.js.map','public-source-map','Map is public',[]);
    e.observe('https://example.com/config','published-sensitive-file','Configuration is public',[]);
    await e.triage!.flush();assert.equal(e.findings.get(direct)!.triage!.category,'direct-leak');assert.equal(e.findings.get(high)!.triage!.category,'high-potential-leak');assert.equal(e.findings.get(low)!.triage!.category,'low-potential-leak');assert.equal(e.findings.get(blocked)!.triage!.category,'high-potential-leak');assert.equal(e.findings.get(local)!.triage!.category,'high-potential-leak');assert.equal(e.findings.has(benign),false);assert.equal(e.full()[benign],undefined);assert.throws(()=>e.reveal(benign));assert.equal(e.triage!.view().removedInsignificant,2);
    assert.equal(e.scrub('private-value uncertain-value'),'[redacted] [redacted]');
  }finally{e.clear();}
});
test('later stronger evidence is reclassified and stale worker results cannot delete a credential',async()=>{
  const e=new Evidence(new Detector('disabled'));e.startTriage(()=>assert.fail('Worker must execute'));
  const c:Candidate={value:'same-value',original:'same-value',index:0,rule:'public-client',provider:'Test',category:'public-identifier',confidence:'high',severity:'info',reasons:[],transformations:[]};
  try{const id=e.add(c,c.value,'https://example.com',[],'Unauthenticated HTTP response');e.add({...c,category:'private-credential',rule:'private-credential',severity:'high'},c.value,'https://example.com/config',[],'Unauthenticated HTTP response');await e.triage!.flush();assert.equal(e.findings.get(id)!.triage!.category,'direct-leak');assert.equal(e.triage!.view().removedInsignificant,0);
    const publicId=e.add({...c,value:'public-only',original:'public-only'},'public-only','https://example.com',[],'Public response');await e.triage!.flush();assert.equal(e.findings.has(publicId),false);e.add({...c,value:'public-only',original:'public-only',category:'private-credential',rule:'private-credential'},'public-only','https://example.com',[],'Public response');await e.triage!.flush();assert.equal(e.findings.get(publicId)!.triage!.category,'direct-leak');
  }finally{e.clear();}
});
test('unknown rules, incomplete credentials and database endpoints remain reviewable',()=>{
  assert.equal(classifyFinding({category:'information',rule:'company-rule',confidence:'high',exposures:[]}).category,'low-potential-leak');
  assert.equal(classifyFinding({category:'suspicious',rule:'aws-id',confidence:'high',exposures:['public-response']}).category,'low-potential-leak');
  assert.equal(classifyFinding({category:'suspicious',rule:'structured-config-secret',confidence:'medium',exposures:['public-response']}).category,'low-potential-leak');
  assert.equal(classifyFinding({category:'information',rule:'public-storage-or-database-endpoint',confidence:'high',exposures:['public-response'],observation:{endpoint:'postgres://db.example.com',role:'database-endpoint',extraction:'literal-url',authorization:'untested'}}).category,'low-potential-leak');
});
test('stronger confidence updates an existing private finding and a stopped worker falls back without dropping it',async()=>{
  const e=new Evidence(new Detector('disabled'));let failures=0;e.startTriage(()=>failures++);
  const c:Candidate={value:'private-material',original:'private-material',index:0,rule:'private-credential',provider:'Test',category:'private-credential',confidence:'medium',severity:'high',reasons:[],transformations:[]};
  try{
    const id=e.add(c,c.value,'https://example.com',[],'Public response');await e.triage!.flush();assert.equal(e.findings.get(id)!.triage!.category,'high-potential-leak');
    e.add({...c,confidence:'high'},c.value,'https://example.com/config',[],'Public response');const completion=e.triage!.flush();
    await (e.triage as any).worker.terminate();await completion;
    assert.equal(failures,1);assert.equal(e.findings.get(id)!.confidence,'high');assert.equal(e.findings.get(id)!.triage!.category,'direct-leak');assert.equal(e.triage!.view().pending,0);assert.equal(e.reveal(id).value,c.value);
  }finally{e.clear();}
});
