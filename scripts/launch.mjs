import { existsSync } from 'node:fs';
import { mkdir, cp, chmod, readFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { windowsDataPath } from '../dist/src/data-path.js';
let root=fileURLToPath(new URL('../',import.meta.url));
const data=path.resolve(process.env.EXPOSURE_DATA_DIR||(process.platform==='win32'?windowsDataPath(os.homedir(),process.env.LOCALAPPDATA):path.join(process.env.XDG_DATA_HOME||path.join(os.homedir(),'.local/share'),'exposure-desk')));
process.env.EXPOSURE_DATA_DIR=data;process.env.EXPOSURE_TOOLS_DIR=path.join(data,'tools');process.env.PLAYWRIGHT_BROWSERS_PATH=path.join(data,'browser');
if(!existsSync(path.join(root,'node_modules/playwright'))){
  await mkdir(data,{recursive:true,mode:0o700});await chmod(data,0o700);
  const permissionModule=path.join(root,'dist/src/permissions.js');if(!existsSync(permissionModule))throw new Error('Use the compiled source/release package for automatic first-run setup.');
  try{const {restrictWindows}=await import(pathToFileURL(permissionModule));restrictWindows(data,true);}catch{throw new Error('Dependency setup requires operator-only writable application data. Select a directory owned by your account; no ACL bypass is used.');}
  const dest=path.join(data,'application-'+JSON.parse(await readFile(path.join(root,'package.json'),'utf8')).version);await mkdir(dest,{recursive:true,mode:0o700});for(const name of ['BUILD_INFO.json','coverage-registry.json','DETECTOR_COVERAGE.md','package.json','package-lock.json','tsconfig.json','dist','public','rules','scripts','src','test'])if(existsSync(path.join(root,name)))await cp(path.join(root,name),path.join(dest,name),{recursive:true});
  console.log('First run: installing exactly locked dependencies in application data. No Git or administrator access is needed.');
  // The official Node.js layouts: npm sits next to node.exe on Windows and under lib/ next to bin/node on Linux.
  const npm=[path.join(path.dirname(process.execPath),'node_modules/npm/bin/npm-cli.js'),path.join(path.dirname(process.execPath),'..','lib','node_modules','npm','bin','npm-cli.js')].find(f=>existsSync(f))||'';
  const result=npm?spawnSync(process.execPath,[npm,'ci','--ignore-scripts','--cache',path.join(data,'npm-cache'),'--no-audit','--no-fund'],{cwd:dest,stdio:'inherit',windowsHide:true}):spawnSync(process.platform==='win32'?'npm.cmd':'npm',['ci','--ignore-scripts','--cache',path.join(data,'npm-cache'),'--no-audit','--no-fund'],{cwd:dest,stdio:'inherit',windowsHide:true,shell:process.platform==='win32'});
  if(result.status!==0)throw new Error('Locked dependency setup failed. Check network access and writable data.');root=dest;
}
const bundledTool=path.join(root,'tools',process.platform==='win32'?'gitleaks.exe':'gitleaks'),installedTool=path.join(data,'tools',process.platform==='win32'?'gitleaks.exe':'gitleaks');if(existsSync(installedTool))process.env.GITLEAKS_PATH=installedTool;else if(existsSync(bundledTool))process.env.GITLEAKS_PATH=bundledTool;
if(!existsSync(path.join(root,'dist/src/desktop.js'))){const r=spawnSync(process.execPath,[path.join(root,'node_modules/typescript/bin/tsc')],{cwd:root,stdio:'inherit'});if(r.status!==0)throw new Error('Build failed. Use the compiled release package.');}
try{const {launch}=await import(pathToFileURL(path.join(root,'dist/src/desktop.js')));await launch();}catch{console.error('Exposure Desk could not start. Check loopback access, supported Node 24–26, writable application data and antivirus/browser restrictions. No security safeguards were disabled.');process.exitCode=2;}
