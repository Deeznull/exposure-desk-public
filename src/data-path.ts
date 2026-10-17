import { existsSync } from 'node:fs';
import path from 'node:path';
export function windowsDataPath(home:string,local?:string,exists:(file:string)=>boolean=existsSync){
  if(local)return path.join(local,'Exposure Desk');
  // Older source launches without LOCALAPPDATA used this dedicated folder.
  // Keep its data in place; permission checks still apply before it is read.
  const legacy=path.join(home,'Exposure Desk');
  return exists(path.join(legacy,'workspace.json'))?legacy:path.join(home,'AppData','Local','Exposure Desk');
}
