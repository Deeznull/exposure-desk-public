/**
 * Source-map parsing and source-name sanitizing for the rebuild. A source name is untrusted text from a public file: it is turned into a
 * relative path that cannot leave the output folder, cannot name a device or a special shell file, and fits Windows path limits.
 */
import { createHash } from 'node:crypto';
import { cleanLabel } from './clean.js';
export interface SourcePath {path:string;notes:string[]}
const RESERVED=/^(?:con|prn|aux|nul|com[0-9\u00b9\u00b2\u00b3]|lpt[0-9\u00b9\u00b2\u00b3]|conin\$|conout\$|clock\$)$/i;
const SPECIAL_DIRS=new Set(['.git','.hg','.svn','.bzr','_darcs','.jj','.vscode','.idea']);
const SPECIAL_FILES=new Set(['desktop.ini','autorun.inf','.directory']);
const SHELL_EXT=/\.(?:lnk|url|scf|library-ms|searchconnector-ms|desktop|appref-ms|website|pif|settingcontent-ms)$/i;
const UNSAFE_CHARS=/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff<>:"|?*]/g;
export const MAX_SEGMENT=100,MAX_PATH=240,MAX_LABEL=4096;
const hash=(s:string,n=12)=>createHash('sha256').update(s).digest('hex').slice(0,n);
/** Shorten one segment to MAX_SEGMENT, keeping a short extension and adding a hash of the full name so shortened names stay distinct. */
function shorten(segment:string){
  if(segment.length<=MAX_SEGMENT)return segment;
  const ext=/\.[A-Za-z0-9]{1,12}$/.exec(segment)?.[0]||'';
  return segment.slice(0,MAX_SEGMENT-ext.length-9)+'~'+hash(segment,8)+ext;
}
function safeSegment(raw:string,last:boolean,notes:Set<string>){
  let s=raw.normalize('NFC').replace(UNSAFE_CHARS,'_');
  if(s!==raw.normalize('NFC'))notes.add('characters-replaced');
  const trimmed=s.replace(/[. ]+$/,'');if(trimmed!==s){notes.add('trailing-dot-or-space');s=trimmed;}
  if(!s){s='_';notes.add('empty-segment');}
  if(RESERVED.test(s.split('.')[0].trimEnd())){s='_'+s;notes.add('reserved-name');}
  if(SPECIAL_DIRS.has(s.toLowerCase())||SPECIAL_FILES.has(s.toLowerCase())){s='_'+s;notes.add('special-name');}
  if(last&&SHELL_EXT.test(s)){s+='.txt';notes.add('shell-extension');}
  const short=shorten(s);if(short!==s)notes.add('segment-shortened');
  return short;
}
/**
 * Relative output path (forward slashes) for a source name, or undefined when nothing usable remains. Query values are dropped and
 * credential-shaped segments redacted first; schemes (`webpack://`, `https://host` keeps the host as the first folder), drive letters,
 * UNC and leading slashes are stripped; `.` and empty segments are dropped; `..` pops a segment and is clamped at the root; reserved
 * device names, VCS/editor folders and shell-processed extensions are neutralized; segments and the whole path are length-capped.
 */
export function sanitizeSourcePath(raw:string):SourcePath|undefined{
  if(typeof raw!=='string'||!raw)return;
  const notes=new Set<string>();
  if(raw.length>MAX_LABEL){notes.add('label-too-long');return {path:'_long/'+hash(raw),notes:[...notes]};}
  if(raw.includes('\u0000'))notes.add('nul');
  // Win32 device and long-path prefixes (`\\?\`, `\\.\`, `\??\`) go first, so their `?` is not read as the start of a query.
  let pre=raw;
  for(let i=0;i<4;i++){const dev=/^[\\/]{1,2}(?:\?\?|[?.])[\\/]/.exec(pre);if(!dev)break;notes.add('device-path');pre=pre.slice(dev[0].length);}
  let s=cleanLabel(pre,MAX_LABEL).replace(/\\/g,'/');
  for(let i=0;i<8;i++){
    const scheme=/^([A-Za-z][A-Za-z0-9+.-]{0,31}):/.exec(s);
    if(scheme){notes.add(scheme[1].length===1?'drive-letter':'scheme');s=s.slice(scheme[0].length);}
    const lead=/^\/+/.exec(s);if(lead){if(!scheme)notes.add('absolute');s=s.slice(lead[0].length);}
    if(!scheme&&!lead)break;
  }
  const stack:string[]=[];const parts=s.split('/');
  for(let i=0;i<parts.length;i++){
    const part=parts[i];
    if(part===''||part==='.')continue;
    if(part==='..'){if(stack.length)stack.pop();else notes.add('parent-clamped');continue;}
    stack.push(safeSegment(part,i===parts.length-1,notes));
  }
  if(!stack.length)return {path:'_unnamed',notes:[...notes,'unnamed']};
  // A trailing `..`/`.` leaves a directory name as the last segment; it is still a file name here, so re-check the shell extension.
  const lastIndex=stack.length-1;if(SHELL_EXT.test(stack[lastIndex])){stack[lastIndex]+='.txt';notes.add('shell-extension');}
  let out=stack.join('/');
  if(out.length>MAX_PATH){notes.add('path-shortened');const base=stack[lastIndex].slice(-80);out='_long/'+hash(out)+'/'+base;}
  return {path:out,notes:[...notes]};
}
/** Parse a source map given as text or an already-parsed object. Text over `maxBytes` characters or that is not a JSON object is refused. */
export function parseSourceMap(input:unknown,maxBytes=64*1024*1024):Record<string,unknown>|undefined{
  if(input&&typeof input==='object'&&!Array.isArray(input))return input as Record<string,unknown>;
  if(typeof input!=='string'||input.length>maxBytes)return;
  try{const v=JSON.parse(input.replace(/^\)\]\}'[^\n]*\n?/,'').replace(/^\ufeff/,''));return v&&typeof v==='object'&&!Array.isArray(v)?v:undefined;}catch{return;}
}
