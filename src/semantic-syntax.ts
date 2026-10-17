import {parse} from 'acorn';
import {stripTypeScriptTypes} from 'node:module';
/** JSX markup is an unknown value; surrounding constants remain analyzable. */
function maskJsx(text:string){
 const ranges:{start:number;end:number}[]=[];let steps=0,unsafe=false;
 const quoted=(at:number)=>{const quote=text[at++];while(at<text.length){if(++steps>2000000)throw new Error('JSX budget');if(text[at]==='\\'){at+=2;continue;}if(text[at++]===quote)return at;}throw new Error('JSX quote');};
 const braces=(at:number)=>{const start=at;let depth=1;at++;while(at<text.length&&depth){if(++steps>2000000)throw new Error('JSX budget');if(/["'`]/.test(text[at]))at=quoted(at);else if(text[at]==='{'){depth++;at++;}else if(text[at]==='}'){depth--;at++;}else at++;}if(depth)throw new Error('JSX expression');if(/\+\+|--|(?:^|[^=!<>])=(?!=|>)|\bdelete\b/.test(text.slice(start,at)))unsafe=true;return at;};
 const element=(at:number,depth=0):number=>{if(depth>64)throw new Error('JSX depth');const tag=/^<([A-Za-z][\w.:-]*|)(?=[\s/>])/.exec(text.slice(at));if(!tag)throw new Error('JSX start');const name=tag[1];at+=tag[0].length;
  while(at<text.length){if(++steps>2000000)throw new Error('JSX budget');if(/["']/.test(text[at]))at=quoted(at);else if(text[at]==='{')at=braces(at);else if(text.startsWith('/>',at))return at+2;else if(text[at++]==='>')break;}
  while(at<text.length){if(++steps>2000000)throw new Error('JSX budget');if(text.startsWith('</',at)){const end=text.indexOf('>',at);if(end<0||text.slice(at+2,end).trim()!==name)throw new Error('JSX closing tag');return end+1;}if(text[at]==='<')at=element(at,depth+1);else if(text[at]==='{')at=braces(at);else at++;}throw new Error('JSX unclosed');
 };
 // Lexical scanning excludes strings/comments, preserving literal evidence.
 for(let i=0;i<text.length;){if(++steps>2000000)throw new Error('JSX budget');if(/["'`]/.test(text[i])){i=quoted(i);continue;}if(text.startsWith('//',i)){const end=text.indexOf('\n',i+2);i=end<0?text.length:end+1;continue;}if(text.startsWith('/*',i)){const end=text.indexOf('*/',i+2);if(end<0)throw new Error('comment');i=end+2;continue;}if(text[i]==='<'&&/(?:\breturn|=>|[=(:,\[])\s*$/.test(text.slice(Math.max(0,i-80),i))&&/^<(?:[A-Za-z][\w.:-]*|)(?:\s|\/?>)/.test(text.slice(i))){try{const end=element(i);ranges.push({start:i,end});i=end;continue;}catch{}}i++;}
 let masked=text;for(const range of ranges.reverse()){const original=text.slice(range.start,range.end);const filler='!0'+original.slice(2).replace(/[^\r\n]/g,' ');if(filler.length!==original.length)throw new Error('JSX offset');masked=masked.slice(0,range.start)+filler+masked.slice(range.end);}return {masked,hasJsx:ranges.length>0,unsafe};
}
/** Strip syntax only with offset checks. Downloaded code is never executed. */
export function parseStaticSource(text:string,label:string):any{
 try{return parse(text,{ecmaVersion:'latest',sourceType:'module',allowReturnOutsideFunction:true});}catch(error){
  if(!/\.[cm]?tsx?(?:[?#\s]|$)|\.[cm]?jsx(?:[?#\s]|$)/i.test(label)&&!/<[A-Za-z][\w.]*[\s/>]/.test(text))throw error;
 }
 const jsx=maskJsx(text),stripped=stripTypeScriptTypes(jsx.masked,{mode:'strip'});
 if(stripped.length!==text.length||stripped.split('\n').length!==text.split('\n').length)throw new Error('Offset-preserving syntax unavailable');
 const ast:any=parse(stripped,{ecmaVersion:'latest',sourceType:'module',allowReturnOutsideFunction:true});ast.syntax='TypeScript/JSX original offsets';ast.syntaxLimited=jsx.hasJsx;ast.syntaxUnsafe=jsx.unsafe;return ast;
}
