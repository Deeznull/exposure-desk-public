import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { readFileSync, existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { root, RULE_VERSION, Detector } from '../src/detectors.js';
import { BUILD } from '../src/build-info.js';
import { Evidence } from '../src/evidence.js';
import { makeConfig } from '../src/config.js';
import { effectiveScope } from '../src/domain-scope.js';
const read=(f:string)=>readFileSync(path.join(root,f),'utf8');
test('version metadata agrees: package, lockfile, build identity and rule version stamped on findings',async()=>{
  const pkg=JSON.parse(read('package.json')),lock=JSON.parse(read('package-lock.json'));assert.equal(lock.version,pkg.version);assert.equal(lock.packages[''].version,pkg.version);assert.equal(BUILD.version,pkg.version);assert.match(BUILD.id,new RegExp('^'+pkg.version.replace(/[.+]/g,'\\$&')+'\\+[a-f0-9]{16}$'));
  assert.equal(RULE_VERSION,'website/2.9.1');const e=new Evidence(new Detector('disabled'));await e.inspect('Stripe("sk_live_'+'Ab9Cx7Dy5Ez3Fh1Gi0Jk8Lm6'+'")','https://www.example.com/app.js',[],'Public response');assert.ok([...e.findings.values()].every(f=>f.assessment?.ruleVersion===RULE_VERSION));e.clear();
  const registry=JSON.parse(read('coverage-registry.json'));assert.equal(registry.websiteRuleVersion,RULE_VERSION);
});
test('every release file exists, documentation links resolve, examples state their scope and the CLI help lists the new options',async()=>{
  const {releaseFiles,excludedFromRelease}=await import(pathToFileURL(path.join(root,'scripts','release-files.mjs')).href);for(const f of releaseFiles)assert.ok(existsSync(path.join(root,f)),'missing release file '+f);
  assert.ok(excludedFromRelease(path.join(root,'scripts','target-recheck.ts'))&&excludedFromRelease(path.join(root,'dist','scripts','target-recheck.js'))&&excludedFromRelease(path.join(root,'benchmarks','2.5','final-unit.log')));assert.ok(!excludedFromRelease(path.join(root,'src','scanner.ts')));
  for(const doc of ['README.md','docs/REFERENCE.md','docs/USER_GUIDE.md','docs/HANDOFF.md','docs/RELEASE_PACKAGE.md','docs/releases/UPGRADE_2.6.md','docs/releases/MIGRATION_2.6.md','docs/releases/CHANGELOG_2.6.md','docs/releases/MIGRATION_2.7.md','docs/releases/CHANGELOG_2.7.md','docs/JSONL.md','docs/releases/MIGRATION_2.8.md','docs/releases/CHANGELOG_2.8.md','docs/releases/MIGRATION_2.9.md','docs/releases/CHANGELOG_2.9.md','docs/releases/CHANGELOG_2.9.1.md','docs/LIVE_KEY_CHECK.md','docs/PROGRAM.md','docs/MASS_SCAN.md','docs/RECON.md','docs/SUBMISSION.md','docs/LINUX.md','docs/history/UPGRADE_2.5.md','docs/history/MIGRATION_2.5.md','docs/history/CHANGELOG_2.5.md','docs/TEST_RESULTS.md','docs/THIRD_PARTY.md','docs/PRIVACY.md','docs/SECURITY.md','docs/ACCEPTABLE_USE.md','docs/CONTRIBUTING.md','docs/DEMO.md'])for(const m of read(doc).matchAll(/\]\(([^)#\s]+)(?:#[^)]*)?\)/g)){const target=m[1];if(/^[a-z]+:/i.test(target))continue;assert.ok(existsSync(path.join(root,path.dirname(doc),decodeURIComponent(target))),`${doc} links to missing ${target}`);}
  for(const f of ['LICENSE','docs/PRIVACY.md','docs/SECURITY.md','docs/ACCEPTABLE_USE.md','docs/THIRD_PARTY.md','docs/THIRD_PARTY_NOTICES.md'])assert.ok(releaseFiles.includes(f),'policy document missing from release: '+f);
  for(const f of releaseFiles)assert.ok(!/(?:^|\/)archive\/|PROGRESS\.md$|^HANDOFF_|^ORCHESTRATOR_HANDOFF/.test(f),'internal work note listed for release: '+f);
  const scopes:Record<string,string>={'examples/config.example.json':'registrable-domain','examples/exhaustive.config.example.json':'registrable-domain','examples/exact-origin.config.example.json':'exact-origin','examples/adaptive.config.example.json':''};
  for(const [file,scope]of Object.entries(scopes)){const j=JSON.parse(read(file)),projects=Array.isArray(j.projects)?j.projects:[j];for(const p of projects){const c=makeConfig(p);if(scope)assert.equal(effectiveScope(c),scope,file);}}
  const help=spawnSync(process.execPath,[path.join(root,'dist','src','cli.js'),'help'],{encoding:'utf8',windowsHide:true}).stdout;for(const option of ['--coverage quick|standard|deep','--traffic low-impact|normal','--scope domain|exact-origin|host-subtree','--fail-on','trigger --project','artifacts --directory'])assert.ok(help.includes(option),'CLI help lists '+option);
});
