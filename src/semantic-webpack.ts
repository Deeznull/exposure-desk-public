/**
 * Webpack chunk facts for the semantic pass (2.9.1, G5F): a narrow, conservative static scan that lets a module factory read a
 * string/number/boolean CONSTANT exported by another factory of the same downloaded chunk group. Nothing is executed.
 *
 * Soundness rules (every doubt leaves the value unknown):
 * - Only real chunk pushes are recognised: `(self|window|globalThis).webpackChunk*|webpackJsonp* = ... || []).push([[ids], {id: factory}|[factory]])`
 *   at a source's top level, with plain function/arrow factories whose parameters are distinct identifiers (module, exports, require).
 * - A local is constant only when it is declared exactly once, at the factory's top level, and never written anywhere in the factory
 *   (nested functions included, by name, so closure writes count). Destructuring and `for…in/of` targets count as writes.
 * - An export is constant only when it is written exactly once, by a top-level `exports.name = …` statement (or defined once by a
 *   top-level `require.d(exports, {name: () => local})` getter), the exports object never escapes (no other use of the exports or
 *   module parameter, no top-level `this`, no exported-method call on it) and no factory in the group writes, escapes or calls through
 *   that module's exports (`require(id).x = …`, `f(require(id))`, an alias used as anything but a property read).
 * - Any dynamic require (`require(x)`, `require.c`, `require.m`, `require` as a value, factory-level `arguments`, direct `eval`), a write
 *   to a require helper, a reference to the chunk global outside its push, a dynamic member access on `self`/`window`/`globalThis` or one
 *   of those passed around as a value disables resolution for the whole chunk group (closed world over the downloaded group).
 * - Duplicate module ids and ids outside the group are unknown; an importer resolves an export only when the exporter's static
 *   require closure stays inside the group and reaches neither the importer nor the exporter itself (no execution-order cycle).
 * - A factory with a `return` outside nested functions is opaque (later top-level statements may never run).
 * - The semantic worker (semantic-worker.ts) reads only primitive (string/number/boolean) values through factory locals and exports,
 *   so an object handed to unknown code cannot change a value that was reported as constant.
 */
export interface NameFacts {decls:number;top?:any;writes:number;uses:number;safeReads:number;unsafe:number}
export interface WebpackFactory {
 id:string;registry:string;url:string;fn:any;body:any[];module?:string;exports?:string;require?:string;
 /** Exports of this factory are unknown. */
 opaque:boolean;
 /** A factory parameter is redeclared: its require calls cannot be read as requires at its top level. */
 shadowed:boolean;
 names:Map<string,NameFacts>;
 exportWrites:Map<string,number>;
 exportAssigns:Map<string,any>;
 getters:Map<string,(any|undefined)[]>;
 directReads:number;
 aliasCandidates:Map<string,{id:string;start:number;end:number}>;
 edges:Set<string>;
 topDeclarators:Set<any>;topAssigns:Set<any>;topHelperCalls:Set<any>;
 /** Filled by finalize: constant top-level locals and valid require aliases. The scan-only collections above are released after it. */
 constants:Set<string>;aliases:Map<string,{id:string;start:number;end:number}>;
}
export interface WebpackRegistry {name:string;factories:Map<string,WebpackFactory>;order:WebpackFactory[];duplicate:Set<string>;taintedIds:Set<string>;tainted:boolean;allowed:Set<any>}
export interface WebpackScan {registries:WebpackRegistry[];ops:number;outcome:'none'|'completed'|'ceiling'|'deadline'}
const GLOBALS=new Set(['self','window','globalThis']);
const CHUNK=/^webpack(?:Chunk|Jsonp)[\w$]*$/;
const HELPERS=new Set(['d','r','n','e','o','p','g','nmd']);
const FUNCTIONS=new Set(['FunctionDeclaration','FunctionExpression','ArrowFunctionExpression']);
const SKIP=new Set(['start','end','type','loc','range']);
/** Shared empty set that replaces scan-only collections after finalize; nothing writes to a finalized factory. */
const EMPTY_SET=Object.freeze(new Set<any>()) as Set<any>;
export function staticProperty(member:any):string|undefined{if(!member.computed)return member.property.type==='Identifier'?member.property.name:undefined;const p=member.property;return p.type==='Literal'&&(typeof p.value==='string'||typeof p.value==='number')?String(p.value):undefined;}
function chunkMember(n:any):string|undefined{if(n?.type!=='MemberExpression'||n.object.type!=='Identifier'||!GLOBALS.has(n.object.name))return;const p=staticProperty(n);return p&&CHUNK.test(p)?p:undefined;}
function isFactory(fn:any):boolean{if(!fn||!['FunctionExpression','ArrowFunctionExpression'].includes(fn.type)||fn.async||fn.generator||fn.body?.type!=='BlockStatement'||fn.params.length>3)return false;const names=fn.params.map((p:any)=>p.type==='Identifier'?p.name:'');return names.every(Boolean)&&new Set(names).size===names.length;}
/** Recognised chunk pushes at a source's top level. */
function pushes(ast:any){
 const out:{name:string;allowed:any[];entries:{id:string;fn:any}[];valid:boolean}[]=[];
 for(const stmt of ast.body||[]){
  const call=stmt.type==='ExpressionStatement'?stmt.expression:undefined;if(call?.type!=='CallExpression'||call.callee.type!=='MemberExpression'||staticProperty(call.callee)!=='push'||call.callee.computed)continue;
  const target=call.callee.object;let name:string|undefined,allowed:any[]=[];
  if(target.type==='AssignmentExpression'&&target.operator==='='){const left=chunkMember(target.left),r=target.right;if(left&&r.type==='LogicalExpression'&&r.operator==='||'&&chunkMember(r.left)===left&&r.right.type==='ArrayExpression'&&r.right.elements.length===0&&r.left.object.name===target.left.object.name){name=left;allowed=[target.left,r.left];}}
  else if(chunkMember(target)){name=chunkMember(target);allowed=[target];}
  if(!name)continue;
  const arg=call.arguments.length===1?call.arguments[0]:undefined,entries:{id:string;fn:any}[]=[];let valid=!!arg&&arg.type==='ArrayExpression'&&arg.elements.length>=2&&arg.elements.length<=3&&arg.elements[0]?.type==='ArrayExpression'&&arg.elements[0].elements.every((x:any)=>x?.type==='Literal');
  const mods=valid?arg.elements[1]:undefined;
  if(mods?.type==='ObjectExpression'){for(const p of mods.properties){const id=p.type==='Property'&&!p.computed&&p.kind==='init'?(p.key.type==='Identifier'?p.key.name:p.key.type==='Literal'?String(p.key.value):undefined):undefined;if(id===undefined){valid=false;break;}entries.push({id,fn:isFactory(p.value)?p.value:undefined});}}
  else if(mods?.type==='ArrayExpression'){mods.elements.forEach((fn:any,i:number)=>{if(fn)entries.push({id:String(i),fn:isFactory(fn)?fn:undefined});});}
  else valid=false;
  out.push({name,allowed,entries,valid});
 }
 return out;
}
function targets(n:any,out:any[]){if(!n)return;if(n.type==='Identifier'||n.type==='MemberExpression'){out.push(n);return;}if(n.type==='ObjectPattern'){for(const p of n.properties)targets(p.type==='RestElement'?p.argument:p.value,out);return;}if(n.type==='ArrayPattern'){for(const e of n.elements)targets(e,out);return;}if(n.type==='AssignmentPattern'){targets(n.left,out);return;}if(n.type==='RestElement')targets(n.argument,out);}
/** Scans every source of a dependency group. Bounded by `ceiling` operations and `deadline`; any bound reached returns no registries. */
export function scanWebpack(sources:{url:string;ast:any}[],ceiling:number,deadline:number):WebpackScan{
 const registries=new Map<string,WebpackRegistry>(),factoryOf=new Map<any,WebpackFactory>();
 for(const s of sources)for(const p of pushes(s.ast)){
  let reg=registries.get(p.name);if(!reg){reg={name:p.name,factories:new Map(),order:[],duplicate:new Set(),taintedIds:new Set(),tainted:false,allowed:new Set()};registries.set(p.name,reg);}
  for(const a of p.allowed)reg.allowed.add(a);if(!p.valid)reg.tainted=true;
  for(const e of p.entries){if(reg.factories.has(e.id)||reg.duplicate.has(e.id)){reg.duplicate.add(e.id);continue;}if(!e.fn){reg.taintedIds.add(e.id);continue;}const names=e.fn.params.map((x:any)=>x.name);
   const f:WebpackFactory={id:e.id,registry:p.name,url:s.url,fn:e.fn,body:e.fn.body.body,module:names[0],exports:names[1],require:names[2],opaque:false,shadowed:false,names:new Map(),exportWrites:new Map(),exportAssigns:new Map(),getters:new Map(),directReads:0,aliasCandidates:new Map(),edges:new Set(),topDeclarators:new Set(),topAssigns:new Set(),topHelperCalls:new Set(),constants:new Set(),aliases:new Map()};
   reg.factories.set(e.id,f);reg.order.push(f);factoryOf.set(e.fn,f);}
 }
 if(!registries.size)return {registries:[],ops:0,outcome:'none'};
 const all=[...registries.values()],byName=registries;let allTainted=false,ops=0;
 for(const reg of all)for(const id of reg.duplicate){const f=reg.factories.get(id);if(f){reg.factories.delete(id);reg.order.splice(reg.order.indexOf(f),1);}}
 const helper=(callee:any,f:WebpackFactory,names:string[])=>callee?.type==='MemberExpression'&&callee.object.type==='Identifier'&&callee.object.name===f.require&&names.includes(staticProperty(callee)!);
 const requireId=(n:any,f:WebpackFactory|null)=>f&&f.require&&n?.type==='CallExpression'&&n.callee.type==='Identifier'&&n.callee.name===f.require&&n.arguments.length===1&&n.arguments[0].type==='Literal'&&['string','number'].includes(typeof n.arguments[0].value)?String(n.arguments[0].value):undefined;
 const facts=(f:WebpackFactory,name:string)=>{let x=f.names.get(name);if(!x){x={decls:0,writes:0,uses:0,safeReads:0,unsafe:0};f.names.set(name,x);}return x;};
 const taintReg=(f:WebpackFactory)=>{byName.get(f.registry)!.tainted=true;};
 const taintId=(f:WebpackFactory,id:string)=>{byName.get(f.registry)!.taintedIds.add(id);};
 const unsafeContext=(p:any,k:string,patternProps:Set<any>)=>p.type==='AssignmentExpression'&&k==='left'||p.type==='UpdateExpression'||p.type==='UnaryExpression'&&p.operator==='delete'||(p.type==='CallExpression'||p.type==='NewExpression')&&k==='callee'||p.type==='TaggedTemplateExpression'&&k==='tag'||(p.type==='ForInStatement'||p.type==='ForOfStatement')&&k==='left'||p.type==='Property'&&patternProps.has(p)||p.type==='ArrayPattern'||p.type==='AssignmentPattern'&&k==='left'||p.type==='RestElement';
 // Iterative walk with parent, key, factory and "inside a nested non-arrow function" (own `this`/`arguments`).
 for(const s of sources){
  const nodes:any[]=[s.ast],parents:any[]=[null],keys:string[]=[''],facs:(WebpackFactory|null)[]=[null],inFn:boolean[]=[false],inAny:boolean[]=[false],patternProps=new Set<any>();
  while(nodes.length){
   const n=nodes.pop(),p=parents.pop(),k=keys.pop()!,f0=facs.pop()!,fn0=inFn.pop()!,any0=inAny.pop()!;
   if(!n||typeof n!=='object'||typeof n.type!=='string')continue;
   if(++ops>ceiling)return {registries:[],ops,outcome:'ceiling'};if((ops&4095)===0&&Date.now()>deadline)return {registries:[],ops,outcome:'deadline'};
   const isFn=FUNCTIONS.has(n.type),entering=isFn?factoryOf.get(n):undefined,f=entering||f0;let fn=entering?false:fn0;
   if(!entering&&f&&(isFn&&n.type!=='ArrowFunctionExpression'||n.type==='ClassBody'))fn=true;
   // Any nested function (arrows included) owns its `return`; one outside them ends the factory early.
   const any=entering?false:any0||!!f&&(isFn||n.type==='ClassBody');
   if(f&&!any&&n.type==='ReturnStatement')f.opaque=true;
   if(entering){for(const stmt of entering.body){if(stmt.type==='VariableDeclaration')for(const d of stmt.declarations)entering.topDeclarators.add(d);if(stmt.type==='ExpressionStatement'){const list=stmt.expression.type==='SequenceExpression'?stmt.expression.expressions:[stmt.expression];for(const e of list){if(e.type==='AssignmentExpression'&&e.operator==='='&&e.left.type==='MemberExpression'&&e.left.object.type==='Identifier'&&e.left.object.name===entering.exports&&staticProperty(e.left)!==undefined){entering.topAssigns.add(e);entering.exportAssigns.set(staticProperty(e.left)!,e);}if(e.type==='CallExpression'&&helper(e.callee,entering,['d']))entering.topHelperCalls.add(e);}}}
    for(const call of entering.topHelperCalls)defineGetters(entering,call);}
   if(n.type==='ObjectPattern')for(const q of n.properties)patternProps.add(q);
   // Group-wide checks: the chunk global outside its push, dynamic or escaping global objects.
   if(n.type==='MemberExpression'){const prop=staticProperty(n);if(prop&&byName.has(prop)&&!byName.get(prop)!.allowed.has(n))byName.get(prop)!.tainted=true;if(n.object.type==='Identifier'&&GLOBALS.has(n.object.name)&&prop===undefined)allTainted=true;}
   if(n.type==='Literal'&&typeof n.value==='string'&&byName.has(n.value)&&!(p?.type==='MemberExpression'&&k==='property'&&byName.get(n.value)!.allowed.has(p)))byName.get(n.value)!.tainted=true;
   const reference=n.type==='Identifier'&&p&&!(p.type==='MemberExpression'&&k==='property'&&!p.computed)&&!((p.type==='Property'||p.type==='MethodDefinition'||p.type==='PropertyDefinition')&&k==='key'&&!p.computed)&&!(['LabeledStatement','BreakStatement','ContinueStatement'].includes(p.type)&&k==='label')&&p.type!=='MetaProperty'&&!p.type.endsWith('Specifier');
   const declaration=reference&&(p.type==='VariableDeclarator'&&k==='id'||FUNCTIONS.has(p.type)&&(k==='params'||k==='id')||(p.type==='ClassDeclaration'||p.type==='ClassExpression')&&k==='id'||p.type==='CatchClause'&&k==='param');
   const pattern=reference&&!declaration&&(p.type==='Property'&&k==='value'&&patternProps.has(p)||p.type==='ArrayPattern'||p.type==='AssignmentPattern'&&k==='left'||p.type==='RestElement');
   if(reference&&!declaration&&!pattern){if(byName.has(n.name))byName.get(n.name)!.tainted=true;if(GLOBALS.has(n.name)&&!(p.type==='MemberExpression'&&k==='object')&&!(p.type==='UnaryExpression'&&p.operator==='typeof'))allTainted=true;}
   if(n.type==='AssignmentExpression'||n.type==='UpdateExpression'||n.type==='UnaryExpression'&&n.operator==='delete'||(n.type==='ForInStatement'||n.type==='ForOfStatement')&&n.left.type!=='VariableDeclaration'){
    const list:any[]=[];targets(n.type==='AssignmentExpression'||n.type==='ForInStatement'||n.type==='ForOfStatement'?n.left:n.argument,list);
    for(const t of list){
     if(t.type==='Identifier'){if(f){facts(f,t.name).writes++;if(t.name===f.exports||t.name===f.module)f.opaque=true;if(t.name===f.require)taintReg(f);}continue;}
     let first=t;while(first.object.type==='MemberExpression')first=first.object;const base=first.object;
     if(base.type==='Identifier'&&GLOBALS.has(base.name)&&staticProperty(first)===undefined)allTainted=true;
     if(!f)continue;
     if(base.type==='Identifier'){const name=base.name;if(name===f.exports){const prop=staticProperty(first);if(prop===undefined)f.opaque=true;else f.exportWrites.set(prop,(f.exportWrites.get(prop)||0)+(t===first&&f.topAssigns.has(n)?1:2));}else if(name===f.require)taintReg(f);else if(name===f.module)f.opaque=true;else facts(f,name).writes++;}
     else if(base.type==='CallExpression'&&base.callee.type==='Identifier'&&base.callee.name===f.require){const id=requireId(base,f);if(id!==undefined)taintId(f,id);else taintReg(f);}
     else if(base.type==='ThisExpression'&&!fn)f.opaque=true;
    }
   }
   if(f){
    if(reference){const name=n.name;
     if(declaration||pattern){const x=facts(f,name);x.decls++;if(pattern)x.writes++;if(p.type==='VariableDeclarator'&&f.topDeclarators.has(p))x.top=p;if(name===f.module||name===f.exports||name===f.require||name==='arguments'){f.opaque=true;f.shadowed=true;}}
     else if(name==='arguments'){if(!fn)taintReg(f);}
     else if(p.type==='MemberExpression'&&k==='object'){/* classified at the member */}
     else if(name===f.module)f.opaque=true;
     else if(name===f.exports){if(!(p.type==='CallExpression'&&k==='arguments'&&p.arguments[0]===n&&(helper(p.callee,f,['r'])||helper(p.callee,f,['d'])&&f.topHelperCalls.has(p)||p.callee.type==='MemberExpression'&&p.callee.object.type==='Identifier'&&p.callee.object.name==='Object'&&staticProperty(p.callee)==='defineProperty'&&p.arguments[1]?.type==='Literal'&&p.arguments[1].value==='__esModule')))f.opaque=true;}
     else if(name===f.require){if(!(p.type==='CallExpression'&&k==='callee'))taintReg(f);}
     else facts(f,name).uses++;}
    if(n.type==='ThisExpression'&&!fn)f.opaque=true;
    if(n.type==='CallExpression'){
     if(n.callee.type==='Identifier'&&n.callee.name==='eval'){taintReg(f);f.opaque=true;}
     if(helper(n.callee,f,['d'])&&!f.topHelperCalls.has(n))f.opaque=true;
     if(n.callee.type==='Identifier'&&n.callee.name===f.require){const id=requireId(n,f);if(id===undefined)taintReg(f);else{f.edges.add(id);
      if(p?.type==='MemberExpression'&&k==='object'){/* classified at the member */}
      else if(p?.type==='VariableDeclarator'&&k==='init'&&p.id.type==='Identifier'&&f.topDeclarators.has(p))f.aliasCandidates.set(p.id.name,{id,start:p.start,end:p.end});
      else taintId(f,id);}}
    }
    if(n.type==='MemberExpression'){const prop=staticProperty(n),unsafe=unsafeContext(p,k,patternProps),id=requireId(n.object,f);
     if(id!==undefined){if(prop===undefined||unsafe)taintId(f,id);else f.directReads++;}
     else if(n.object.type==='Identifier'){const name=n.object.name;
      if(name===f.require){if(!HELPERS.has(prop!)||(p.type==='AssignmentExpression'&&k==='left'||p.type==='UpdateExpression'||p.type==='UnaryExpression'&&p.operator==='delete'))taintReg(f);}
      else if(name===f.exports){if((p.type==='CallExpression'||p.type==='NewExpression')&&k==='callee'||p.type==='TaggedTemplateExpression')f.opaque=true;}
      else if(name===f.module)f.opaque=true;
      else if(name!=='arguments'){const x=facts(f,name);if(prop===undefined||unsafe)x.unsafe++;else x.safeReads++;}
      else if(!fn)taintReg(f);}
    }
   }
   for(const key in n){if(SKIP.has(key)||entering&&(key==='params'||key==='id'))continue;const v=n[key];if(Array.isArray(v)){for(let i=v.length-1;i>=0;i--)if(v[i]&&typeof v[i]==='object'){nodes.push(v[i]);parents.push(n);keys.push(key);facs.push(f);inFn.push(fn);inAny.push(any);}}else if(v&&typeof v==='object'&&typeof v.type==='string'){nodes.push(v);parents.push(n);keys.push(key);facs.push(f);inFn.push(fn);inAny.push(any);}}
  }
 }
 if(allTainted)for(const reg of all)reg.tainted=true;
 for(const reg of all)for(const f of reg.order){
  if(f.fn.id)facts(f,f.fn.id.name).decls++;
  for(const [name,x] of f.names){if(x.decls===1&&x.top&&x.writes===0&&name!=='arguments'&&name!==f.module&&name!==f.exports&&name!==f.require)f.constants.add(name);}
  for(const [name,a] of f.aliasCandidates){const x=f.names.get(name);if(f.constants.has(name)&&x&&x.uses===0&&x.unsafe===0){f.aliases.set(name,a);f.constants.delete(name);}else taintId(f,a.id);}
  // Scan-only facts are not read after finalize; drop them so a large chunk keeps a small retained footprint.
  f.topDeclarators=EMPTY_SET;f.topAssigns=EMPTY_SET;f.topHelperCalls=EMPTY_SET;f.aliasCandidates=new Map();
 }
 return {registries:all,ops,outcome:'completed'};
}
/** Top-level `require.d(exports, {name: getter})` (webpack 5) or `require.d(exports, "name", getter)` (webpack 4). */
function defineGetters(f:WebpackFactory,call:any){
 const simple=(g:any)=>{if(!g||!['ArrowFunctionExpression','FunctionExpression'].includes(g.type)||g.params.length||g.async||g.generator)return;if(g.body.type!=='BlockStatement')return g.body;const b=g.body.body;return b.length===1&&b[0].type==='ReturnStatement'?b[0].argument||undefined:undefined;};
 const add=(name:string|undefined,g:any)=>{if(name===undefined){f.opaque=true;return;}const list=f.getters.get(name)||[];list.push(simple(g));f.getters.set(name,list);};
 const [target,second,third]=call.arguments;
 if(target?.type!=='Identifier'||target.name!==f.exports){f.opaque=true;return;}
 if(second?.type==='ObjectExpression'&&call.arguments.length===2){for(const q of second.properties){if(q.type!=='Property'||q.computed||q.kind!=='init'){f.opaque=true;return;}add(q.key.type==='Identifier'?q.key.name:q.key.type==='Literal'?String(q.key.value):undefined,q.value);}}
 else if(second?.type==='Literal'&&typeof second.value==='string'&&call.arguments.length===3)add(second.value,third);
 else f.opaque=true;
}
/**
 * Static require closure of `id` (every module it may execute, transitively), or undefined when an id is missing from the
 * registry (another chunk, a duplicate or a non-function entry) or the walk exceeds `limit` modules. `step` is called once
 * per visited module and may stop the walk by returning false (shared evaluation budget).
 */
/** Static require closure of factory `id`, kept inside the downloaded source that defines it: a factory that is missing, duplicated or defined by another source leaves the closure unknown. */
export function requireClosure(reg:WebpackRegistry,id:string,limit:number,step:()=>boolean):Set<string>|undefined{
 const seen=new Set<string>(),queue:string[]=[];const start=reg.factories.get(id);if(!start)return;const url=start.url;for(const e of start.edges)queue.push(e);
 while(queue.length){const next=queue.pop()!;if(seen.has(next))continue;if(!step())return;const f=reg.factories.get(next);if(!f||f.url!==url||reg.duplicate.has(next))return;seen.add(next);if(seen.size>limit)return;for(const e of f.edges)if(!seen.has(e))queue.push(e);}
 return seen;
}
