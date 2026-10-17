// Smoke test of the Exposure Desk container image (Linux CI): node scripts/docker-smoke.mjs <image>
// Every container runs locked down the way docs/LINUX.md recommends: read-only root filesystem, a private /tmp, no capabilities,
// no privilege escalation, and the data volume as the only writable place. Only loopback fixtures inside the container are scanned.
import {spawnSync} from 'node:child_process';
import {randomUUID} from 'node:crypto';
import assert from 'node:assert/strict';
const image=process.argv[2];if(!image)throw new Error('Usage: node scripts/docker-smoke.mjs <image>');
const delay=ms=>new Promise(r=>setTimeout(r,ms));
function docker(args,{allowFailure=false,timeout=600000}={}){const r=spawnSync('docker',args,{encoding:'utf8',timeout,maxBuffer:64*1024*1024});if(!allowFailure&&r.status!==0)throw new Error(`docker ${args.slice(0,3).join(' ')} failed (${r.status}): ${(r.stderr||r.error?.message||'').slice(-2000)}`);return r;}
const volume='exposure-smoke-'+randomUUID().slice(0,8),names=[];
const locked=['--read-only','--tmpfs','/tmp:rw,nosuid,nodev,size=256m','--cap-drop','ALL','--security-opt','no-new-privileges','-v',volume+':/data'];
const run=(args,options)=>docker(['run','--rm',...locked,...args],options);
const result={};
try{
  // The image's own configuration.
  const [config]=JSON.parse(docker(['image','inspect',image]).stdout),c=config.Config;
  assert.deepEqual(c.Entrypoint,['/usr/bin/tini','--','node','/app/dist/src/cli.js'],'Entrypoint');assert.deepEqual(c.Cmd,['help'],'Default command');
  assert.equal(c.User,'exposure:exposure','The image runs as the exposure user');assert.ok(c.Volumes&&'/data' in c.Volumes,'The image declares the /data volume');
  for(const e of ['EXPOSURE_DATA_DIR=/data','EXPOSURE_NO_OPEN=1','EXPOSURE_BROWSER_NO_SANDBOX=1'])assert.ok(c.Env.includes(e),'Image environment lacks '+e);
  assert.ok(!(c.ExposedPorts&&Object.keys(c.ExposedPorts).length),'The image publishes no port');
  result.imageConfig=true;
  // Not root, and the application files cannot be changed.
  docker(['volume','create',volume]);
  const id=run(['--entrypoint','id',image]).stdout.trim();assert.match(id,/^uid=10001\(exposure\) gid=10001\(exposure\)/,'Runs as uid/gid 10001: '+id);
  const write=run(['--entrypoint','sh',image,'-c','touch /app/probe 2>/dev/null && echo writable || echo read-only; touch /data/probe && echo data-writable; stat -c %a /data']).stdout.trim().split('\n');
  assert.deepEqual(write,['read-only','data-writable','700'],'Application read-only, /data writable and private: '+write.join(' | '));
  result.nonRoot=true;result.readOnlyRoot=true;result.privateData=true;
  // Help through the entrypoint.
  const help=run([image]);assert.match(help.stdout,/Exposure Desk/i,'help output');result.help=true;
  // Doctor with the synthetic runtime scan: build parity, the verified detector and the bundled Chromium launching in the container.
  const doctor=JSON.parse(run([image,'doctor','--runtime']).stdout);
  const check=name=>doctor.checks.find(x=>x.name===name)?.status;
  assert.equal(doctor.parity,'verified','Build parity in the image');assert.equal(check('Offline detector'),'verified','Gitleaks in the image');
  assert.equal(check('Browser sandbox'),'container-isolation','The doctor reports the container sandbox setting');
  assert.equal(doctor.browser.launch,'available','Chromium launches in the container');
  // The runtime scan must inspect the fixture page in the browser and complete. Chrome for Testing's own service connections (sign-in cookie check,
  // GCM check-in) are still denied at the deny-only proxy, but they are informational browser background traffic now, so any open gap fails this check.
  const open=(doctor.browser.limitations||[]).filter(g=>g.incomplete);
  assert.equal(doctor.browser.runtimeScan,'completed','Runtime scan of the synthetic fixture: '+JSON.stringify(open.map(g=>[g.code,g.url||''])));
  result.doctor={parity:doctor.parity,detector:'verified',browserLaunch:doctor.browser.launch,runtimeScan:doctor.browser.runtimeScan,build:doctor.build?.id};
  // The CLI exit codes, masking and full export against the loopback fixture (scripts/cli-smoke.ts).
  const cli=run(['--entrypoint','node','-w','/app',image,'dist/scripts/cli-smoke.js']);assert.equal((cli.stdout.match(/CLI smoke \S+: passed/g)||[]).length,4,'CLI smoke: '+cli.stdout.slice(-1500));result.cliSmoke=true;
  // Dashboard in the default bridge network: it listens on 127.0.0.1 inside the container only, so it answers there and nowhere else.
  const bridge='exposure-smoke-dash-'+randomUUID().slice(0,8);names.push(bridge);
  docker(['run','-d','--name',bridge,...locked,image,'dashboard']);
  let origin;for(let i=0;i<120&&!origin;i++){origin=docker(['logs',bridge],{allowFailure:true}).stdout.match(/Dashboard: (http:\/\/127\.0\.0\.1:\d+)/)?.[1];if(!origin)await delay(500);}
  assert.ok(origin,'Dashboard did not report its address: '+docker(['logs',bridge],{allowFailure:true}).stdout.slice(-1500));
  const inside=docker(['exec',bridge,'node','-e',`fetch(${JSON.stringify(origin+'/health')}).then(r=>r.json()).then(j=>console.log(j.application))`]).stdout.trim();assert.equal(inside,'Exposure Desk','Health inside the container');
  const ip=docker(['inspect','-f','{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}',bridge]).stdout.trim();assert.ok(ip,'Container address');
  const outside=await fetch(`http://${ip}:${new URL(origin).port}/health`,{signal:AbortSignal.timeout(5000)}).then(()=>'reachable',()=>'unreachable');assert.equal(outside,'unreachable','The dashboard must not be reachable on the container network address');
  docker(['stop','-t','20',bridge]);const state=JSON.parse(docker(['inspect',bridge]).stdout)[0].State;assert.equal(state.ExitCode,0,'Dashboard stops cleanly on SIGTERM (exit '+state.ExitCode+')');
  result.dashboard={loopbackOnly:true,healthInside:true,containerAddress:'unreachable',cleanStop:true};
  // The documented way to use the dashboard from the host on Linux: --network host, still 127.0.0.1 only.
  const host='exposure-smoke-host-'+randomUUID().slice(0,8);names.push(host);
  docker(['run','-d','--name',host,'--network','host',...locked,image,'dashboard','--port','4417']);
  let health;for(let i=0;i<120&&!health;i++){health=await fetch('http://127.0.0.1:4417/health',{signal:AbortSignal.timeout(2000)}).then(r=>r.ok?r.json():undefined,()=>undefined);if(!health)await delay(500);}
  assert.equal(health?.application,'Exposure Desk','Dashboard with --network host answers on the host loopback');
  docker(['stop','-t','20',host]);assert.equal(JSON.parse(docker(['inspect',host]).stdout)[0].State.ExitCode,0,'Host-network dashboard stops cleanly');
  result.hostNetworkDashboard=true;
  console.log(JSON.stringify(result));
}finally{
  for(const name of names)docker(['rm','-f',name],{allowFailure:true});
  docker(['volume','rm','-f',volume],{allowFailure:true});
}
