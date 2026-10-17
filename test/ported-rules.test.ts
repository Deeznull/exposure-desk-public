import test from 'node:test';
import assert from 'node:assert/strict';
import { Detector, rules } from '../src/detectors.js';
import { capability } from '../src/provider-capabilities.js';
import { portedCases } from './provider-fixtures.js';

/** Rules ported from Gitleaks and Nosey Parker (THIRD_PARTY_NOTICES.md). All values are synthetic fixtures; nothing is contacted. */
const RULE:Record<string,string>={
  'planetscale-password':'planetscale-token','doppler-service':'doppler-token','doppler-personal':'doppler-token','grafana-service-account':'grafana-service-account-token',
  'grafana-cloud':'grafana-cloud-token','vault-service':'vault-token','vault-batch':'vault-token','terraform-cloud':'terraform-cloud-token','sourcegraph-legacy':'sourcegraph-token',
  'flyio-org':'flyio-token','flyio-macaroon':'flyio-token','1password-service-account':'1password-service-account-token','newrelic-user-key':'newrelic-api-key',
  'newrelic-insert-key':'newrelic-ingest-key','newrelic-license-key':'newrelic-ingest-key'
};
const PORTED=new Set(portedCases.map(([id])=>RULE[id]||id));
const GENERIC_REMEDIATION=/^Revoke and replace the exposed credential at its issuer/;

test('every ported rule has a positive fixture, and every fixture names a ported rule',()=>{
  const ids=new Set(rules.map(r=>r.id));
  for(const id of PORTED)assert.ok(ids.has(id),'fixture refers to a missing rule: '+id);
  assert.equal(PORTED.size,31);
});

for(const [id,value,provider]of portedCases)test('ported format: '+id,()=>{
  const text=`window.CONFIG={service:"${value}"};`,found=new Detector('disabled').inspectSync(text);
  const hit=found.find(c=>c.value===value&&c.rule===(RULE[id]||id));
  assert.ok(hit,'Planted synthetic credential must be detected by its own rule');
  assert.equal(hit.provider,provider);assert.equal(hit.category,'private-credential');
  assert.equal(text.slice(hit.index,hit.index+hit.original.length),hit.original,'Location must refer to the actual source');
  assert.doesNotMatch(capability(hit.provider,hit.rule).remediation[0],GENERIC_REMEDIATION,'Each ported provider has its own remediation');
  assert.equal(found.filter(c=>c.value===value&&c.category==='private-credential').length,1,'One finding per planted value');
  const continued=new Detector('disabled').inspectSync(`window.CONFIG={service:"${value}Q7"};`);
  assert.ok(!continued.some(c=>c.value===value),'A token that continues past the format is never reported truncated');
});

test('ported rules use bounded repeats only',()=>{
  for(const r of rules.filter(r=>PORTED.has(r.id))){
    const body=r.regex.source.replace(/\\./g,'').replace(/\[[^\]]*\]/g,'C');
    assert.doesNotMatch(body,/[*+]|\{\d+,\}/,r.id+' has an unbounded repeat');
    assert.ok(r.regex.flags.includes('g'),r.id+' must be global');
  }
});

test('ported rules keep public and look-alike values out of private credentials',()=>{
  const d=new Detector('disabled'),fill='Ab9Cx7Dy5Ez3Fh1Gi0Jk8Lm6No4Pq2RsTuVwXyZ'.repeat(3);
  for(const text of [
    `<script src="/app.js" integrity="sha256-${Buffer.from(fill.slice(0,32)).toString('base64')}"></script>`,
    `mapboxgl.accessToken="pk.eyJ1Ijoi${fill.slice(0,60)}.${fill.slice(0,22)}";`,
    `const hawk={init(){}};hawk.init();const pat={a:1};pat.a;`,
    `const ids=["LIN_API_${fill.slice(0,40)}","Pmak-${fill.slice(0,24)}-${fill.slice(0,34)}","ezak${fill.slice(0,54)}","sgp_${fill.slice(0,40)}"];`,
    `const sum="sgp_${'0123456789abcdef'.repeat(4).slice(0,50)}";`
  ])assert.deepEqual(d.inspectSync(text).filter(c=>c.category==='private-credential'&&PORTED.has(c.rule)).map(c=>c.rule),[],text);
});

test('the Gitleaks engine keeps the direct provider for values both detect',async t=>{
  const d=new Detector();await d.init();if(d.version==='unavailable'){t.skip('pinned offline engine not present');return;}
  for(const [id,value,provider]of portedCases){
    const found=(await d.inspect('const key="'+value+'";')).filter(c=>c.value===value);
    assert.ok(found.length>0,id);
    for(const c of found)assert.equal(c.provider,provider,id+' engine finding must keep the direct provider');
  }
});
