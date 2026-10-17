import {createHash} from 'node:crypto';
/** Deterministic synthetic minified bundle resembling the observed 1,252,570-byte main bundle: thousands of bare-extension literals and MIME tables as negative discovery controls, then secrets near the end split across safe constant dependencies, plus a late import, a worker URL and a source-map comment past the 1 MiB mark. */
export function syntheticBundle(options:{targetBytes?:number;seed?:string}={}){
  const targetBytes=options.targetBytes??1252570,seed=options.seed??'ExposureDesk/large-bundle/2.5/1';
  const token=(label:string,n=64)=>{let s='';for(let i=0;s.length<n;i++)s+=createHash('sha256').update(seed+label+i).digest('base64url');return s.slice(0,n).replace(/[-_]/g,'A');};
  const value='sk-proj-'+token('split'),tail1=value.slice(8,40),tail2=value.slice(40),mutated='sk-proj-'+token('mutated'),lateChunk='./late-'+createHash('sha256').update(seed).digest('hex').slice(0,8)+'.js';
  // Negative discovery controls per block: a comparison operand, MIME-table keys, a dotted identifier and a bare extension literal stored in a plain variable.
  const blocks:string[]=[];let bytes=0;const block=(i:number)=>`function f${i}(a,b){if(a.endsWith(".json"))return b;const m${i}={".woff":"font/woff",".json":"application/json",".css":"text/css"};return m${i}[a]||"es.array.map"}var v${i}=f${i}("x",${i}),e${i}=".woff";`;
  const tail=`\nconst base="sk-proj-";let more=${JSON.stringify(mutated.slice(8))};function mutate(){more="changed";}const keyB=base+more;const ph1="your_",ph2="api_key_here";const ph=ph1+ph2;const p="sk-proj-";const q=${JSON.stringify(tail1)};const r=${JSON.stringify(tail2)};const apiKey=p+q+r;import(${JSON.stringify(lateChunk)});new Worker(new URL("./tail.js",import.meta.url));\n//# sourceMappingURL=bundle.js.map\n`;
  const prefix='"use strict";',reserved=Buffer.byteLength(prefix)+Buffer.byteLength(tail)+8;
  for(let i=0;;i++){const b=block(i),size=Buffer.byteLength(b);if(bytes+size+reserved>targetBytes)break;blocks.push(b);bytes+=size;}
  let text=prefix+blocks.join('');const pad=targetBytes-Buffer.byteLength(text)-Buffer.byteLength(tail);if(pad>4)text+='/*'+'p'.repeat(pad-4)+'*/';text+=tail;
  return {text,value,mutated,lateChunk,workerUrl:'./tail.js',bytes:Buffer.byteLength(text)};
}
