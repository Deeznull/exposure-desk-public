/** Bounded sniffing uses content and MIME; filename suffixes never decide coverage. */
export function contentDecision(body:Buffer,headers:Record<string,string|string[]>):{binary:boolean;reason?:string}{
  const prefix=body.subarray(0,4096),magic=prefix.subarray(0,12).toString('latin1');
  if(/^(wOF2|wOFF|OTTO|ttcf)/.test(magic)||prefix.subarray(0,4).equals(Buffer.from([0,1,0,0])))return {binary:true,reason:'binary-font'};
  if(/^(GIF8|\x89PNG|\xff\xd8\xff|RIFF|OggS|PK\x03\x04|%PDF-|\x00asm|\x7fELF)/.test(magic))return {binary:true,reason:'binary-unsupported-extractor'};
  const bom=(prefix[0]===255&&prefix[1]===254)||(prefix[0]===254&&prefix[1]===255);
  const type=String(headers['content-type']||'');if(bom)return {binary:false};
  if(/^(?:text\/|application\/(?:[^;]*(?:json|javascript|xml)|x-www-form-urlencoded))/i.test(type))return {binary:false};
  let controls=0;for(const b of prefix)if(b===0||(b<32&&![9,10,13].includes(b)))controls++;
  if(controls>Math.max(2,prefix.length*.01))return {binary:true,reason:'binary-content-sniff'};
  try{new TextDecoder('utf-8',{fatal:true}).decode(prefix,{stream:body.length>prefix.length});return {binary:false};}
  catch{if(/^(?:font|image|audio|video)\/|application\/(?:zip|pdf|wasm|octet-stream)/i.test(type))return {binary:true,reason:'binary-mime-and-content'};return {binary:false};}
}
export function decodeText(body:Buffer,headers:Record<string,string|string[]>,partial=false):string{
  if(contentDecision(body,headers).binary)return '';
  let encoding=/charset\s*=\s*["']?([\w-]+)/i.exec(String(headers['content-type']||''))?.[1]||'utf-8';
  if(body[0]===0xff&&body[1]===0xfe)encoding='utf-16le';else if(body[0]===0xfe&&body[1]===0xff)encoding='utf-16be';
  return new TextDecoder(encoding,{fatal:true}).decode(body,{stream:partial});
}
