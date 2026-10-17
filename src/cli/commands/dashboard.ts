import { startDashboard } from '../../dashboard.js';
import type { Args } from '../args.js';
import type { ScanConfig } from '../../types.js';
export async function dashboard(args:Args,projects:Partial<ScanConfig>[]){
  const app=await startDashboard({port:args.option('port')?Number(args.option('port')):4317,projects,companyRules:args.option('company-rules'),persistent:args.flag('history'),dataDir:args.option('data-dir')});
  console.log(`Dashboard: ${app.origin}\nPer-launch token: ${app.token}\nEnter this token in the local sign-in screen. No token in the URL. Ctrl+C closes sessions.`);
  let closing=false;const close=async()=>{if(closing)return;closing=true;await app.close();};process.on('SIGINT',()=>void close());process.on('SIGTERM',()=>void close());
}
