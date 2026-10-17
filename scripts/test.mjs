import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { readdirSync } from 'node:fs';
const cwd=fileURLToPath(new URL('../',import.meta.url));
const compile=spawnSync(process.execPath,[path.join(cwd,'scripts/build.mjs')],{stdio:'inherit',cwd,windowsHide:true});if(compile.status!==0)process.exit(compile.status||2);
const browserSuite=['dist/test/completeness-browser.test.js','dist/test/same-domain-browser.test.js','dist/test/browser.test.js','dist/test/stage2-browser.test.js','dist/test/repair-browser.test.js','dist/test/origins-browser.test.js','dist/test/scope-browser.test.js','dist/test/discovery-browser.test.js','dist/test/attribution-browser.test.js','dist/test/runs-browser.test.js','dist/test/privacy-browser.test.js','dist/test/findings-browser.test.js','dist/test/traffic-browser.test.js','dist/test/protected-hosts-browser.test.js','dist/test/profile-ui-browser.test.js','dist/test/ready-options-browser.test.js','dist/test/deployment-paths-browser.test.js','dist/test/host-validation-browser.test.js'],upgradeSuite=['dist/test/upgrade.test.js'],nonbrowser=['dist/test/completeness.test.js','dist/test/same-domain.test.js','dist/test/finding-triage.test.js','dist/test/core.test.js','dist/test/dashboard.test.js','dist/test/upgrade.test.js','dist/test/coverage.test.js','dist/test/providers.test.js','dist/test/detection-quality.test.js','dist/test/ported-rules.test.js','dist/test/reliability.test.js','dist/test/stage2.test.js','dist/test/repair.test.js','dist/test/origin-config.test.js','dist/test/origins.test.js','dist/test/origin-coverage.test.js','dist/test/scope.test.js','dist/test/lifecycle.test.js','dist/test/discovery.test.js','dist/test/attribution.test.js','dist/test/runs.test.js','dist/test/privacy.test.js','dist/test/findings.test.js','dist/test/incidents.test.js','dist/test/egress.test.js','dist/test/legacy.test.js','dist/test/release-metadata.test.js','dist/test/profiles.test.js','dist/test/traffic.test.js','dist/test/profile-limit.test.js','dist/test/protected-hosts.test.js','dist/test/profile-ui.test.js','dist/test/ready-options.test.js','dist/test/websites-at-once.test.js','dist/test/profile-matrix.test.js','dist/test/cli-targets.test.js','dist/test/jsonl.test.js','dist/test/engine-lanes.test.js','dist/test/analysis-memory.test.js','dist/test/host-validation.test.js'];
nonbrowser.push('dist/test/analysis-isolation.test.js');
nonbrowser.push('dist/test/program-rules.test.js');
nonbrowser.push('dist/test/program-file.test.js');
nonbrowser.push('dist/test/program-limiter.test.js');
nonbrowser.push('dist/test/program-import.test.js');
nonbrowser.push('dist/test/program-scan.test.js');
nonbrowser.push('dist/test/submission-markdown.test.js');
nonbrowser.push('dist/test/recon-extract.test.js','dist/test/recon-collector.test.js','dist/test/recon-sourcemap.test.js');
nonbrowser.push('dist/test/detector-scope.test.js');
nonbrowser.push('dist/test/semantic-webpack.test.js');
nonbrowser.push('dist/test/mass-scheduler.test.js','dist/test/mass-resume.test.js','dist/test/mass-block.test.js','dist/test/mass-dedup.test.js','dist/test/mass-budget.test.js','dist/test/mass-regression.test.js','dist/test/mass-recon.test.js');
nonbrowser.push('dist/test/recon-wire.test.js','dist/test/report-submit.test.js','dist/test/recon-dashboard.test.js');
browserSuite.push('dist/test/recon-wire-browser.test.js');
nonbrowser.push('dist/test/platform-linux.test.js');
browserSuite.push('dist/test/submission-ui-browser.test.js');
nonbrowser.push('dist/test/chrome-background.test.js');
browserSuite.push('dist/test/chrome-background-browser.test.js');
browserSuite.push('dist/test/leave-guard-browser.test.js');
nonbrowser.push('dist/test/machine-speed.test.js');
nonbrowser.push('dist/test/mass-scale.test.js');
nonbrowser.push('dist/test/live-check.test.js');
const files=process.argv.includes('--browser')?browserSuite:process.argv.includes('--upgrade')?upgradeSuite:nonbrowser;
// Every test file must be listed in exactly one suite; an unlisted file would otherwise never run.
const listed=[...nonbrowser,...browserSuite,...upgradeSuite].map(f=>path.basename(f).replace(/\.js$/,'.ts')),present=readdirSync(path.join(cwd,'test')).filter(f=>f.endsWith('.test.ts'));
const missing=present.filter(f=>!listed.includes(f)),duplicated=[...nonbrowser,...browserSuite].filter((f,i,a)=>a.indexOf(f)!==i);
if(missing.length||duplicated.length){console.error('Test lists are incomplete: '+[...missing.map(f=>'unlisted '+f),...duplicated.map(f=>'duplicated '+f)].join(', '));process.exit(3);}
// A global per-test timeout guards against hangs; a child killed by a signal (status null) is a failure, never a success.
const result=spawnSync(process.execPath,['--test','--test-isolation=none','--test-concurrency=1','--test-timeout=600000',...files],{stdio:'inherit',cwd,windowsHide:true,env:{...process.env,EXPOSURE_TEST_OUTPUT:process.env.EXPOSURE_TEST_OUTPUT||path.join(cwd,'.cache','test-output')}});process.exitCode=result.status===0?0:(result.status||1);
