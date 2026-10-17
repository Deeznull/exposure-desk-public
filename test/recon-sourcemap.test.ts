import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { root } from '../src/detectors.js';
import { synthetic } from '../src/fixture.js';
import { sanitizeSourcePath, parseSourceMap, rebuildSources, SourceRebuilder, DEFAULT_REBUILD_LIMITS, ReconOutputError, type RebuildManifest } from '../src/recon/index.js';
const base=process.env.EXPOSURE_DATA_DIR||path.join(root,'.cache');
async function tempDir(){await mkdir(base,{recursive:true});return mkdtemp(path.join(base,'recon-map-test-'));}
const p=(raw:string)=>sanitizeSourcePath(raw)?.path;
const RESERVED_WIN=/^(?:con|prn|aux|nul|com[0-9\u00b9\u00b2\u00b3]|lpt[0-9\u00b9\u00b2\u00b3]|conin\$|conout\$|clock\$)$/i;
/** Every segment of a sanitized path is safe on Windows, macOS and Linux. */
function assertSafe(rel:string,label=rel){
  assert.ok(rel.length<=240+100,label+': path length');
  assert.ok(!rel.startsWith('/')&&!/^[A-Za-z]:/.test(rel)&&!rel.includes('\\'),label+': relative, forward slashes');
  for(const seg of rel.split('/')){
    assert.ok(seg&&seg!=='.'&&seg!=='..',label+': no dot segments');
    assert.ok(!/[\u0000-\u001f\u007f<>:"|?*]/.test(seg),label+': no forbidden characters in '+JSON.stringify(seg));
    assert.ok(!/[. ]$/.test(seg),label+': no trailing dot or space');
    assert.ok(!RESERVED_WIN.test(seg.split('.')[0].trimEnd()),label+': no device name '+seg);
    assert.ok(seg.length<=100,label+': segment length');
  }
}
async function walk(dir:string,rel=''):Promise<string[]>{
  const out:string[]=[];
  for(const e of await readdir(dir,{withFileTypes:true})){
    const r=rel?rel+'/'+e.name:e.name;
    assert.ok(!e.isSymbolicLink(),'no links in the rebuilt tree: '+r);
    if(e.isDirectory())out.push(...await walk(path.join(dir,e.name),r));else out.push(r);
  }
  return out;
}
/** Every file on disk is in the manifest with a matching sha256, and nothing resolves outside the folder. */
async function verifyTree(dir:string,m:RebuildManifest){
  const real=await realpath(dir);
  const files=(await walk(dir)).filter(f=>f!=='MANIFEST.json').sort();
  assert.deepEqual(files,m.files.map(f=>f.path).sort((a,b)=>a<b?-1:a>b?1:0),'disk matches manifest');
  for(const f of m.files){
    const abs=path.join(dir,...f.path.split('/'));
    const rel=path.relative(real,await realpath(abs));
    assert.ok(rel&&!rel.startsWith('..')&&!path.isAbsolute(rel),'inside the root: '+f.path);
    const data=await readFile(abs);
    assert.equal(createHash('sha256').update(data).digest('hex'),f.sha256,f.path);assert.equal(data.length,f.bytes);
    assertSafe(f.path);
  }
  const onDisk=JSON.parse(await readFile(path.join(dir,'MANIFEST.json'),'utf8'));
  assert.deepEqual(onDisk,JSON.parse(JSON.stringify(m)));
}

test('sanitizeSourcePath normalizes bundler prefixes and keeps ordinary paths readable',()=>{
  assert.equal(p('webpack://shop/./src/index.ts'),'shop/src/index.ts');
  assert.equal(p('webpack:///./src/index.ts'),'src/index.ts');
  assert.equal(p('webpack:///webpack/bootstrap'),'webpack/bootstrap');
  assert.equal(p('webpack://shop/../node_modules/lib/a.js'),'node_modules/lib/a.js');
  assert.equal(p('../../src/app.tsx'),'src/app.tsx');
  assert.equal(p('./src/components/Button.vue'),'src/components/Button.vue');
  assert.equal(p('vite:///src/main.ts'),'src/main.ts');
  assert.equal(p('rollup://pkg/src/x.js'),'pkg/src/x.js');
  assert.equal(p('https://cdn.vendor.example/lib/x.js?v=3#frag'),'cdn.vendor.example/lib/x.js_v','the host becomes a folder; query values are dropped');
  assert.equal(p('src\\win\\path.ts'),'src/win/path.ts');
  assert.equal(p('src//double///slash.ts'),'src/double/slash.ts');
  assert.equal(p('src/ünïcode/naïve.ts'),'src/ünïcode/naïve.ts'.normalize('NFC'));
  assert.equal(sanitizeSourcePath(''),undefined);assert.equal(sanitizeSourcePath(42 as any),undefined);
});
test('sanitizeSourcePath neutralizes traversal, absolute paths, drive letters, UNC, NUL and device names',()=>{
  const cases:[string,string,string?][]=[
    ['../../../../etc/passwd','etc/passwd','parent-clamped'],
    ['src/../../../outside.js','outside.js','parent-clamped'],
    ['/etc/shadow','etc/shadow','absolute'],
    ['C:\\Windows\\System32\\drivers\\etc\\hosts','Windows/System32/drivers/etc/hosts','drive-letter'],
    ['c:/Users/x/a.ts','Users/x/a.ts','drive-letter'],
    ['\\\\server\\share\\a.ts','server/share/a.ts','absolute'],
    ['\\\\?\\C:\\secret\\a.ts','secret/a.ts','device-path'],
    ['\\\\?\\UNC\\server\\share\\a.ts','UNC/server/share/a.ts','device-path'],
    ['\\\\.\\PhysicalDrive0','PhysicalDrive0','device-path'],
    ['\\??\\C:\\x\\CON','x/_CON','reserved-name'],
    ['//?/GLOBALROOT/Device/x','GLOBALROOT/Device/x','device-path'],
    ['src/a?b/../../../x.js','src/a'],
    ['src/a#/../../../x.js','src/a'],
    ['file:///C:/Users/x/a.ts','Users/x/a.ts','scheme'],
    ['webpack://C:/x/../../a.ts','a.ts','drive-letter'],
    ['a\u0000b/../../x.js','x.js','nul'],
    ['src/a\u0000.js','src/a.js','nul'],
    ['src/CON','src/_CON','reserved-name'],
    ['src/con.ts','src/_con.ts','reserved-name'],
    ['NUL.txt','_NUL.txt','reserved-name'],
    ['aux/index.js','_aux/index.js','reserved-name'],
    ['src/COM1.js','src/_COM1.js','reserved-name'],
    ['src/LPT\u00b9.js','src/_LPT\u00b9.js','reserved-name'],
    ['src/conin$','src/_conin$','reserved-name'],
    ['src/nul .js','src/_nul .js','reserved-name'],
    ['src/evil. . .','src/evil','trailing-dot-or-space'],
    ['src/...','src/_','empty-segment'],
    ['src/a:stream.js','src/a_stream.js','characters-replaced'],
    ['src/a<b>|c"*.js','src/a_b__c__.js','characters-replaced'],
    ['src/\u202egnp.js','src/gnp.js'],
    ['.git/hooks/pre-commit','_.git/hooks/pre-commit','special-name'],
    ['src/.GIT/config','src/_.GIT/config','special-name'],
    ['src/desktop.ini','src/_desktop.ini','special-name'],
    ['src/run.lnk','src/run.lnk.txt','shell-extension'],
    ['src/x.url/y/..','src/x.url.txt','shell-extension'],
    ['src/settings.SettingContent-ms','src/settings.SettingContent-ms.txt','shell-extension'],
    ['..','_unnamed','unnamed'],
    ['/','_unnamed','unnamed'],
    ['C:','_unnamed','unnamed'],
  ];
  for(const [raw,want,note] of cases){
    const got=sanitizeSourcePath(raw);
    assert.ok(got,JSON.stringify(raw));
    assert.equal(got!.path,want,JSON.stringify(raw));
    if(note)assert.ok(got!.notes.includes(note),JSON.stringify(raw)+' notes '+got!.notes.join(','));
    assertSafe(got!.path,JSON.stringify(raw));
  }
});
test('sanitizeSourcePath caps segment, path and label lengths with stable distinct hashes',()=>{
  const long='a'.repeat(300)+'.ts',long2='a'.repeat(299)+'b.ts';
  const s1=p('src/'+long)!,s2=p('src/'+long2)!;
  assert.ok(s1.endsWith('.ts')&&s1.split('/')[1].length===100&&s1!==s2&&s1===p('src/'+long));
  const deep=Array.from({length:60},(_,i)=>'dir'+i).join('/')+'/file.ts';
  const d=sanitizeSourcePath(deep)!;assert.ok(d.path.startsWith('_long/')&&d.path.endsWith('/file.ts')&&d.notes.includes('path-shortened'));
  const huge=sanitizeSourcePath('x/'.repeat(5000))!;assert.match(huge.path,/^_long\/[0-9a-f]{12}$/);assert.ok(huge.notes.includes('label-too-long'));
  for(const raw of [long,deep,'x/'.repeat(5000)])assertSafe(p(raw)!);
});
test('sanitizeSourcePath redacts credential-shaped names and never keeps query values',()=>{
  const got=p('webpack:///./src/'+synthetic.stripe+'/config.ts?token='+synthetic.github)!;
  assert.ok(!got.includes(synthetic.stripe)&&!got.includes(synthetic.github),got);
  assert.ok(got.startsWith('src/')&&got.includes('config.ts'),got);
});
test('parseSourceMap accepts objects and JSON text with an XSSI prefix or BOM, and refuses everything else',()=>{
  assert.deepEqual(parseSourceMap(')]}\'\n{"version":3,"sources":[]}'),{version:3,sources:[]});
  assert.deepEqual(parseSourceMap('\ufeff{"version":3}'),{version:3});
  const o={version:3};assert.equal(parseSourceMap(o),o);
  for(const bad of ['[1,2]','null','"x"','{bad json',42,null,undefined,[1]])assert.equal(parseSourceMap(bad as any),undefined,String(bad));
  assert.equal(parseSourceMap('{"version":3}',5),undefined,'over the size cap');
});
test('fixture map rebuilds the original tree, lists the missing source and writes a verifiable manifest',async()=>{
  const dir=await tempDir();
  try{
    const out=path.join(dir,'sources');
    const m=await rebuildSources(out,[{url:'https://shop.example/static/app.js.map?v=42',map:readFileSync(path.join(root,'test','fixtures','recon','app.js.map'),'utf8')}],{protect:false,now:()=>new Date('2026-10-10T00:00:00.000Z')});
    assert.equal(m.schema,'exposure-recon-sources/1');assert.equal(m.generatedAt,'2026-10-10T00:00:00.000Z');
    assert.deepEqual(m.files.map(f=>[f.path,f.source,f.sourceMap]),[
      ['node_modules/tiny-lib/index.js','webpack://shop/../node_modules/tiny-lib/index.js','https://shop.example/static/app.js.map?v'],
      ['shop/src/api/client.ts','webpack://shop/./src/api/client.ts','https://shop.example/static/app.js.map?v'],
      ['shop/src/index.ts','webpack://shop/./src/index.ts','https://shop.example/static/app.js.map?v'],
    ]);
    assert.deepEqual(m.notRecoverable,[{source:'webpack://shop/./src/missing.ts',sourceMap:'https://shop.example/static/app.js.map?v',reason:'no-sources-content'}]);
    assert.equal(await readFile(path.join(out,'shop','src','api','client.ts'),'utf8'),'export const client={get:(p:string)=>fetch(p)};\n');
    assert.deepEqual(m.totals,{maps:1,files:3,bytes:m.files.reduce((n,f)=>n+f.bytes,0),duplicates:0,notRecoverable:1,skipped:0,sourcesOverLimit:0});
    assert.deepEqual(m.limits,{...DEFAULT_REBUILD_LIMITS});
    await verifyTree(out,m);
  }finally{await rm(dir,{recursive:true,force:true});}
});
test('hostile map: traversal, absolute, drive, UNC, NUL, device and link-shaped names all land inside the folder',async()=>{
  const dir=await tempDir();
  try{
    const sources=['../../../../escape.js','/etc/passwd','C:\\Windows\\win.ini','\\\\server\\share\\x.js','\\\\?\\C:\\x.js','a\u0000/../../b.js','CON','src/nul.txt','src/COM9.ts','src/AUX.d.ts','.git/config','src/desktop.ini','src/x.lnk','src/trail. ','src/..\\..\\..\\up.js','webpack:///../../../../../../outside.js','node_modules/../../../../x.js','src/\u202etxt.exe','..','.','file:///etc/hosts','https://evil.example/../../abs.js'];
    const out=path.join(dir,'out');
    const m=await rebuildSources(out,[{url:'https://shop.example/evil.js.map',map:{version:3,sources,sourcesContent:sources.map((s,i)=>'// '+i+'\n')}}],{protect:false});
    assert.equal(m.files.length+m.totals.duplicates,sources.length,'every named source written or identical: '+JSON.stringify(m.skipped));
    assert.equal(m.skipped.length,0);
    await verifyTree(out,m);
    // Nothing escaped next to the output folder.
    assert.deepEqual((await readdir(dir)).sort(),['out']);
    assert.ok(m.files.some(f=>f.path==='escape.js')&&m.files.some(f=>f.path==='_CON')&&m.files.some(f=>f.path==='_.git/config')&&m.files.some(f=>f.path==='src/x.lnk.txt'));
  }finally{await rm(dir,{recursive:true,force:true});}
});
test('collisions: case folding, a file where a folder is needed, MANIFEST.json and identical duplicates across maps',async()=>{
  const dir=await tempDir();
  try{
    const out=path.join(dir,'out');
    const m=await rebuildSources(out,[
      {url:'https://shop.example/a.js.map',map:{version:3,sources:['src/App.ts','src/app.ts','Src/util.ts','lib','lib/inner.ts','MANIFEST.json','manifest.JSON','shared.ts'],sourcesContent:['A','a','u','file','inner','m1','m2','same']}},
      {url:'https://shop.example/b.js.map',map:{version:3,sources:['shared.ts','./shared.ts','shared.ts'],sourcesContent:['same','same','different']}},
    ],{protect:false});
    const paths=m.files.map(f=>f.path);
    assert.deepEqual(paths,['MANIFEST~1.json','lib','lib~1/inner.ts','manifest~2.JSON','shared.ts','shared~1.ts','src/App.ts','src/app~1.ts','src/util.ts']);
    const shared=m.files.find(f=>f.path==='shared.ts')!;
    assert.deepEqual(shared.alsoIn,['https://shop.example/b.js.map']);
    assert.equal(m.totals.duplicates,2);
    assert.equal(JSON.parse(await readFile(path.join(out,'MANIFEST.json'),'utf8')).schema,'exposure-recon-sources/1','the manifest is never overwritten by a source');
    await verifyTree(out,m);
  }finally{await rm(dir,{recursive:true,force:true});}
});
test('sections: embedded maps are rebuilt, URL sections are listed and never fetched, depth and count are capped',async()=>{
  const dir=await tempDir();
  try{
    const nest=(d:number):any=>d===0?{version:3,sources:['deep.ts'],sourcesContent:['deep']}:{version:3,sections:[{offset:{line:0,column:0},map:nest(d-1)}]};
    const out=path.join(dir,'out');
    const r=await SourceRebuilder.create(out,{protect:false,limits:{maxSectionDepth:3,maxSections:6}});
    await r.add('https://shop.example/s.js.map',{version:3,sections:[{offset:{line:0,column:0},map:{version:3,sources:['one.ts'],sourcesContent:['1']}},{offset:{line:5,column:0},url:'part2.js.map'},{offset:{line:9,column:0}}]});
    await r.add('https://shop.example/deep.js.map',nest(5));
    await r.add('https://shop.example/many.js.map',{version:3,sections:Array.from({length:10},(_,i)=>({offset:{line:i,column:0},map:{version:3,sources:['m'+i+'.ts'],sourcesContent:['x'+i]}}))});
    const m=await r.finish();
    assert.deepEqual(m.files.map(f=>f.path),['one.ts']);
    assert.deepEqual(m.notRecoverable,[{source:'https://shop.example/part2.js.map',sourceMap:'https://shop.example/s.js.map',reason:'section-url-not-fetched'}]);
    assert.deepEqual(m.maps.map(x=>[x.sourceMap,x.error,x.sections]),[['https://shop.example/s.js.map','invalid-map',3],['https://shop.example/deep.js.map','section-depth-limit',3],['https://shop.example/many.js.map','section-limit',0]]);
    assert.equal(await r.finish(),m,'finish is idempotent');
    await r.add('https://shop.example/late.js.map',{version:3,sources:['late.ts'],sourcesContent:['x']});
    assert.ok(!(await readdir(out)).includes('late.ts'),'maps added after finish are ignored');
    await verifyTree(out,m);
  }finally{await rm(dir,{recursive:true,force:true});}
});
test('huge counts and sizes are bounded: sources per map, files, bytes per file, total bytes, map size and map count',async()=>{
  const dir=await tempDir();
  try{
    const out=path.join(dir,'out');
    const r=await SourceRebuilder.create(out,{protect:false,limits:{maxSourcesPerMap:50,maxFiles:20,maxFileBytes:1000,maxTotalBytes:5000,maxMapBytes:200000,maxMaps:5,maxListed:10}});
    const n=100000;
    // One map claims 100k sources; only maxSourcesPerMap are read and only maxFiles written.
    const sources=Array.from({length:n},(_,i)=>'gen/f'+i+'.js');
    await r.add('https://shop.example/count.js.map',{version:3,sources,sourcesContent:sources.map(()=>'x')});
    await r.add('https://shop.example/big.js.map',{version:3,sources:['big.js','fits.js','big2.js'],sourcesContent:['y'.repeat(1001),'z'.repeat(1000),'\u00e9'.repeat(600)]});
    await r.add('https://shop.example/huge.js.map','{"version":3,"sources":["h.js"],"sourcesContent":["'+'h'.repeat(250000)+'"]}');
    await r.add('https://shop.example/bad.js.map','not json');
    await r.add('https://shop.example/m5.js.map',{version:3,sources:[],sourcesContent:[]});
    await r.add('https://shop.example/m6.js.map',{version:3,sources:['six.js'],sourcesContent:['6']});
    const m=await r.finish();
    assert.equal(m.totals.files,20);assert.equal(m.files.length,20);
    assert.equal(m.totals.sourcesOverLimit,n-50);
    const count=m.maps.find(x=>x.sourceMap==='https://shop.example/count.js.map')!;
    assert.deepEqual([count.sources,count.written,count.sourcesOverLimit,count.skipped],[n,20,n-50,30]);
    assert.ok(m.skipped.length===10&&m.truncated.skipped&&m.totals.skipped>10,'skipped list capped at maxListed, totals still count');
    assert.deepEqual(m.maps.find(x=>x.sourceMap==='https://shop.example/huge.js.map')!.error,'map-too-large');
    assert.deepEqual(m.maps.find(x=>x.sourceMap==='https://shop.example/bad.js.map')!.error,'invalid-map');
    assert.equal(m.maps.length,5);assert.equal(m.totals.maps,6);assert.ok(m.truncated.maps,'map count capped');
    assert.ok(!m.files.some(f=>f.path==='six.js'));
    assert.ok(m.totals.bytes<=5000);
    await verifyTree(out,m);
    // Byte limits on a fresh rebuilder (the file limit above already stopped the second map).
    const out2=path.join(dir,'out2');
    const m2=await rebuildSources(out2,[{url:'https://shop.example/big.js.map',map:{version:3,sources:['big.js','fits.js','big2.js','a.js','b.js','c.js','d.js','e.js'],sourcesContent:['y'.repeat(1001),'z'.repeat(1000),'\u00e9'.repeat(600),'1'.repeat(1000),'2'.repeat(1000),'3'.repeat(1000),'4'.repeat(1000),'5'.repeat(1000)]}}],{protect:false,limits:{maxFileBytes:1000,maxTotalBytes:5000}});
    assert.deepEqual(m2.skipped.map(s=>[s.source,s.reason]),[['big.js','file-too-large'],['big2.js','file-too-large'],['e.js','total-byte-limit']],'U+00E9 is two bytes: 600 characters exceed 1000 bytes');
    assert.equal(m2.totals.bytes,5000);
    await verifyTree(out2,m2);
  }finally{await rm(dir,{recursive:true,force:true});}
});
test('the output folder must be new or empty, a real folder and never a link; protect makes it owner-only',async()=>{
  const dir=await tempDir();
  try{
    const full=path.join(dir,'full');await mkdir(full);await writeFile(path.join(full,'x'),'x');
    await assert.rejects(SourceRebuilder.create(full,{protect:false}),(e:any)=>e instanceof ReconOutputError&&e.code==='output-not-empty');
    await assert.rejects(SourceRebuilder.create(path.join(full,'x'),{protect:false}),(e:any)=>e instanceof ReconOutputError&&e.code==='output-not-directory');
    const target=await tempDir();
    let linked=false;try{await symlink(target,path.join(dir,'link'),'junction');linked=true;}catch{}
    if(linked){
      await assert.rejects(SourceRebuilder.create(path.join(dir,'link'),{protect:false}),(e:any)=>e instanceof ReconOutputError&&e.code==='unsafe-output');
      assert.deepEqual(await readdir(target),[]);
    }
    await rm(target,{recursive:true,force:true});
    const prot=path.join(dir,'protected');
    const m=await rebuildSources(prot,[{url:'https://shop.example/a.js.map',map:{version:3,sources:['src/a.ts'],sourcesContent:['a']}}]);
    assert.equal(m.files.length,1);
    if(process.platform==='win32'){
      const {spawnSync}=await import('node:child_process');
      const acl=spawnSync('powershell.exe',['-NoProfile','-NonInteractive','-Command','(Get-Acl -LiteralPath $env:T).Access | ForEach-Object { $_.IdentityReference.Value }'],{encoding:'utf8',env:{...process.env,T:path.join(prot,'src','a.ts')},windowsHide:true});
      const ids=acl.stdout.trim().split(/\r?\n/).filter(Boolean);
      assert.equal(new Set(ids).size,1,'one identity (the owner) inherited by rebuilt files: '+ids.join(', '));
    }else assert.equal((await lstat(prot)).mode&0o777,0o700);
  }finally{await rm(dir,{recursive:true,force:true});}
});
test('a link planted inside the tree mid-rebuild is refused, and nothing is written through it',async()=>{
  const dir=await tempDir();
  try{
    const out=path.join(dir,'out');const target=await tempDir();
    const r=await SourceRebuilder.create(out,{protect:false});
    let linked=false;try{await symlink(target,path.join(out,'evil'),'junction');linked=true;}catch{}
    await r.add('https://shop.example/a.js.map',{version:3,sources:['evil/payload.js','ok/fine.js'],sourcesContent:['p','f']});
    const m=await r.finish();
    if(linked){
      assert.deepEqual(m.skipped.map(s=>[s.source,s.reason]),[['evil/payload.js','unsafe-directory']]);
      assert.deepEqual(await readdir(target),[],'nothing written through the link');
    }
    assert.ok(m.files.some(f=>f.path==='ok/fine.js'));
    await rm(target,{recursive:true,force:true});
  }finally{await rm(dir,{recursive:true,force:true});}
});
test('missing, non-string and invalid source entries are listed, never fetched or guessed',async()=>{
  const dir=await tempDir();
  try{
    const m=await rebuildSources(path.join(dir,'out'),[{url:'data:application/json;base64,e30=',map:{version:3,sourceRoot:'https://shop.example/src/',sources:['a.ts','b.ts','c.ts','',7,'webpack:///d.ts'],sourcesContent:['A',null,{x:1}]}}],{protect:false});
    assert.deepEqual(m.files.map(f=>[f.path,f.source,f.sourceMap]),[['shop.example/src/a.ts','https://shop.example/src/a.ts','data:(inline source map)']]);
    assert.deepEqual(m.notRecoverable.map(n=>[n.source,n.reason]),[['https://shop.example/src/b.ts','no-sources-content'],['https://shop.example/src/c.ts','invalid-sources-content'],['webpack:///d.ts','no-sources-content']]);
    assert.deepEqual(m.skipped.map(s=>[s.source,s.reason]),[['sources[3]','invalid-source-name'],['sources[4]','invalid-source-name']]);
  }finally{await rm(dir,{recursive:true,force:true});}
});
