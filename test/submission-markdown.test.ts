import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import path from 'node:path';
import { mkdtemp, mkdir, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { root, Detector } from '../src/detectors.js';
import { Scanner } from '../src/scanner.js';
import { synthetic } from '../src/fixture.js';
import { NOT_ESTABLISHED } from '../src/finding-assessment.js';
import type { Finding, Occurrence } from '../src/types.js';
import { submissionMarkdown, submissionReports, submissionIndex, submissionDocument, submissionInputFromReport, reportableFindings, publicGetUrl, writeSubmission, sensitiveName, mdText, mdCode, mdFence, shellQuote, type SubmissionView } from '../src/submission/index.js';

/** 2.8.0 submission Markdown (w1-report). Synthetic, nonfunctional keys and `.example` hosts only; one loopback fixture for the end-to-end test. */
const KEY=synthetic.openai,KEY_B64=Buffer.from(KEY).toString('base64');
const FID='a'.repeat(64),FID2='b'.repeat(64);
async function temp(prefix:string){const parent=process.env.EXPOSURE_DATA_DIR||path.join(root,'.cache');await mkdir(parent,{recursive:true});return mkdtemp(path.join(parent,prefix));}

function occurrence(over:Partial<Occurrence>={}):Occurrence{
  return {url:'https://shop.example/static/app.js',line:3,column:17,byteOffset:120,coordinates:'generated',byteOffsetEncoding:'utf-8-decoded-text',chain:['https://shop.example/','https://shop.example/static/app.js'],transformations:[],excerpt:'const client={apiKey:"[redacted]"};',evidence:'JavaScript string literal',exposure:'public-response',...over};
}
function finding(over:Partial<Finding>={}):Finding{
  return {id:'1111222233334444',fingerprint:'1111222233334444',category:'private-credential',provider:'OpenAI',rule:'openai-project-key',severity:'critical',confidence:'high',reasons:['Matches the OpenAI project key format'],masked:`[redacted: ${KEY.length} characters]`,validity:'unverified',impact:'Possible paid usage.',remediation:'Revoke and replace.',occurrences:[occurrence()],findingId:FID,
    priority:{level:'urgent',basis:['private credential in a public response','paid AI usage'],version:'priority/1'},impacts:[{kind:'paid-usage',text:'Possible paid API usage billed to the owner.'}],...over};
}
function view(findings:Finding[],over:Partial<SubmissionView>&{url?:string}={}):SubmissionView{
  const {url='https://shop.example/',...rest}=over;
  return {id:'run-'+url.length.toString(16).padStart(4,'0')+'-0000-0000',name:url,findings,config:{urls:[url]} as any,engines:{websiteRules:'website-rules/9',gitleaks:'off',ruleDigest:'d',companyRules:'none'},startedAt:'2026-10-01T10:00:00.000Z',...rest};
}

/** Prose left after removing fenced blocks and code spans, the way CommonMark reads them. Throws if a fence is never closed. */
function prose(md:string):string{
  const out:string[]=[];let fence:string|undefined;
  for(const line of md.split('\n')){
    if(fence){if(new RegExp('^'+fence+'`*\\s*$').test(line))fence=undefined;continue;}
    const open=/^(`{3,})/.exec(line);if(open){fence=open[1];continue;}
    let s='',i=0;
    while(i<line.length){
      if(line[i]==='\\'){s+=line.slice(i,i+2);i+=2;continue;}
      if(line[i]==='`'){let n=0;while(line[i+n]==='`')n++;const tick='`'.repeat(n);let j=i+n,end=-1;
        while(j<line.length){const k=line.indexOf(tick,j);if(k<0)break;if(line[k+n]!=='`'&&line[k-1]!=='`'){end=k;break;}j=k+1;while(line[j]==='`')j++;}
        if(end>=0){s+=' CODE ';i=end+n;continue;}s+=tick;i+=n;continue;}
      s+=line[i];i++;
    }
    out.push(s);
  }
  assert.equal(fence,undefined,'every fenced block is closed');
  return out.join('\n');
}
const OWN_LINK=/^- \[(?:CWE-\d+|OWASP)[^\]]*\]\(https:\/\/(?:cwe\.mitre\.org|cheatsheetseries\.owasp\.org)\/[^)\s]+\)$/;
const HEADINGS=new Set(['## Summary','## Affected URLs and locations','## How it was found','## Steps to reproduce','## Exposed value','## Possible impact (unverified)','## Remediation','## References']);
/** Structural checks that hold for every report: only our headings, no raw HTML, links or images outside code, no controls or bidi characters. */
function assertSafe(md:string,report=true){
  assert.doesNotMatch(md,/[\u0000-\u0008\u000B-\u001F\u007F-\u009F\u061C\u200B-\u200F\u202A-\u202E\u2060-\u2069\uFEFF\u2028\u2029]/,'no controls or invisible characters');
  const text=prose(md),lines=text.split('\n');
  for(const line of lines){
    if(/^ {0,3}#/.test(line))assert.ok(HEADINGS.has(line)||/^# \S/.test(line)&&line===lines.find(l=>/^# /.test(l)),'unexpected heading: '+line);
    if(OWN_LINK.test(line))continue;
    // Index lines link our own hex-named file; the link text and the rest of the line are checked like any prose.
    const own=/^\d+\. \[(.*)\]\(finding-[0-9a-z-]+(?:\.sensitive)?\.md\)( — .*)$/.exec(line),parts=own?[own[1]!,own[2]!]:[line];
    for(const part of parts){
      assert.doesNotMatch(part,/(?<!\\)</,'raw < outside code: '+line);
      assert.doesNotMatch(part,/(?<!\\)[[\]]/,'link or image bracket outside code: '+line);
      assert.doesNotMatch(part,/https?:|www\.|mailto:|@\w/i,'autolink candidate outside code: '+line);
    }
    assert.doesNotMatch(line,/^ {0,3}(?:>|\||=+\s*$|[-*+] \[[ xX]\])/,'unexpected block syntax: '+line);
  }
  if(report){assert.equal((md.match(/Validity not tested\./g)||[]).length,1);assert.match(md,/\nValidity: not tested\. Exposure Desk did not test whether this key is valid/);}
}
/** POSIX single-quote parsing of one shell word; fails on anything a shell would expand. */
function shellWord(s:string):string{
  let out='',i=0;while(i<s.length){if(s[i]==="'"){const j=s.indexOf("'",i+1);assert.ok(j>0,'closed quote');out+=s.slice(i+1,j);i=j+1;}else if(s.startsWith("\\'",i)){out+="'";i+=2;}else assert.fail('unquoted shell text: '+s.slice(i));}
  return out;
}
const curls=(md:string)=>[...md.matchAll(/^curl -sS --compressed -o exposed-resource(?:-\d+)? (.+)$/gm)].map(m=>shellWord(m[1]!));

test('a report has every section, uses only plain GETs for reproduction and never holds the value',()=>{
  const v=view([finding()]),[r,...rest]=submissionMarkdown(v.findings!,v,{generatedAt:'2026-10-02T00:00:00Z'});
  assert.equal(rest.length,0);assert.ok(r);const md=r.markdown;assertSafe(md);
  assert.equal(r.title,'Exposed OpenAI credential in a public JavaScript file on shop.example');
  assert.match(md,/^# Exposed OpenAI credential in a public JavaScript file on `shop\.example`\n/);
  for(const h of HEADINGS)assert.ok(md.includes('\n'+h+'\n'),h);
  assert.match(md,/Generated by Exposure Desk \d+\.\d+\.\d+.* on 2026-10-02/);
  assert.match(md,/\*\*Asset \(target\):\*\* `https:\/\/shop\.example\/`/);
  assert.match(md,/- `https:\/\/shop\.example\/static\/app\.js` — line 3, column 17 \(byte offset 120 of the decoded text\)/);
  assert.match(md,new RegExp('\\*\\*Finding ID:\\*\\* `'+FID+'`'));
  assert.match(md,/\*\*Exposure Desk priority:\*\* urgent \(priority/);assert.match(md,/\*\*Exposure Desk severity:\*\* critical · confidence high/);
  assert.match(md,/\*\*Platform severity:\*\* set it yourself/);
  assert.match(md,/Discovery path: `https:\/\/shop\.example\/` → `https:\/\/shop\.example\/static\/app\.js`/);
  assert.deepEqual(curls(md),['https://shop.example/static/app.js']);
  assert.match(md,/^tail -c \+121 exposed-resource \| head -c 120$/m);
  assert.match(md,/Masked: `\[redacted: \d+ characters\]`/);
  const impact=md.slice(md.indexOf('## Possible impact (unverified)'),md.indexOf('## Remediation'));
  assert.match(impact,/could possibly do the following\. None of it was tested/);assert.match(impact,/\n- Possible metered /);assert.ok(impact.split('\n').filter(l=>l.startsWith('- ')).every(l=>l.startsWith('- Possible ')));assert.ok(impact.includes(NOT_ESTABLISHED));
  const fix=md.slice(md.indexOf('## Remediation'),md.indexOf('## References'));
  assert.match(fix,/Rotate or revoke the credential at OpenAI first/);assert.match(fix,/Remove the value from the public file and from the build/);assert.match(fix,/Check the OpenAI access, usage and billing logs/);
  assert.match(md,/cwe\.mitre\.org\/data\/definitions\/798\.html/);assert.match(md,/Secrets_Management_Cheat_Sheet/);assert.match(md,/rules `website-rules\/9`/);
  assert.ok(!md.includes(KEY));assert.equal(r.sensitive,false);assert.match(r.fileName,/^finding-a{24}\.md$/);
  assert.deepEqual({...r,markdown:undefined,title:undefined},{key:'id:'+FID,fileName:r.fileName,title:undefined,markdown:undefined,findingId:FID,findings:[{runId:v.id,id:'1111222233334444'}],targets:['https://shop.example/'],category:'private-credential',severity:'critical',priority:'urgent',provider:'OpenAI',sensitive:false});
});

test('hostile site content cannot inject links, images, HTML, headings, code fences, controls or shell commands',()=>{
  const evil='[click me](https://evil.example/x) ![pixel](https://evil.example/p.png) <img src=x onerror=alert(1)> <script>alert(1)</script> www.evil.example mailto:a@evil.example *em* _u_ <https://evil.example>';
  const fence='```\n# Injected heading\n```html\n<iframe src="https://evil.example"></iframe>\n';
  const url="https://shop.example/a'$(touch pwned)'`id`;rm -rf ~/x.js?x=<b>1</b>&y=\"q\"#frag-<script>";
  const o=occurrence({url,chain:['https://shop.example/\n## Injected\n'+evil,url,'```'+evil],sourceLabel:'webpack://src/\u202Eevil.js'+fence,evidence:'literal\r\n# Heading\n> quote\n- [ ] task '+evil,transformations:['base64',evil],excerpt:'````\n</code></pre><script>alert(1)</script>\n```\n'+evil,
    originalPosition:{source:'webpack:///'+evil,line:2,column:4,precision:'mapped-segment'}});
  const f=finding({provider:'new'+evil+' (unreviewed provider)',rule:'semantic:'+evil,reasons:[evil,fence,'| a | b |\n|---|---|'],occurrences:[o,occurrence({url:'https://cdn.example/<x>/`b`.js',coordinates:'extracted-source',sourceLabel:evil+'\n```',chain:[evil]})],priority:{level:'high',basis:[evil],version:'priority/1'},credentialSet:{state:'partial',components:[evil],missing:[fence],context:''}});
  const v=view([f],{url:'https://shop.example/?q=<script>',name:evil});
  for(const r of submissionMarkdown([f],v,{maxLocations:5})){
    assertSafe(r.markdown);
    assert.ok(!/[\u202E\r]/.test(r.title)&&!r.title.includes('\n'));
    assert.deepEqual(curls(r.markdown),["https://shop.example/a'$(touch%20pwned)'%60id%60;rm%20-rf%20~/x.js?x=%3Cb%3E1%3C/b%3E&y=%22q%22",'https://cdn.example/%3Cx%3E/%60b%60.js']);
    assertSafe(submissionIndex([r]),false);
  }
  // The helpers on their own.
  assert.equal(mdCode('a``b'),'```a``b```');assert.equal(mdCode('`x`'),'`` `x` ``');assert.equal(mdCode('\u202E\n'),'(empty)');
  assert.equal(mdText('*a* [b](c) <d> 1. www.e.example $x$ a|b'),'\\*a\\* \\[b\\](c) \\<d\\> 1. `www.e.example` \\$x\\$ a\\|b');
  assert.equal(mdText('1. item'),'1\\. item');assert.equal(mdText('- item'),'\\- item');assert.equal(mdText('# h'),'\\# h');assert.equal(mdText('> q'),'\\> q');assert.equal(mdText('= x'),'\\= x');assert.equal(mdText('Plain, readable text (v2).'),'Plain, readable text (v2).');
  assert.equal(mdFence('```\nx','text'),'````text\n```\nx\n````');
  assert.equal(shellWord(shellQuote("a'b $(c) `d`\n;e")),"a'b $(c) `d` ;e");
});

test('masking: values and representations never reach the Markdown, even from raw findings, and reproduction never uses them',()=>{
  // Raw (unredacted) records as a misuse: the secrets record acts as a scrub list, so the value still cannot appear.
  const raw=finding({reasons:['value '+KEY],occurrences:[occurrence({excerpt:'apiKey:"'+KEY+'" b64:'+KEY_B64,url:'https://shop.example/app.js?key='+KEY+'&v=2',chain:['https://shop.example/?k='+encodeURIComponent(KEY)]})]});
  const v=view([raw]),secrets={[raw.id]:{value:KEY,representations:[KEY_B64],locations:[],validity:'unverified'}};
  const reports=submissionMarkdown([raw],v,{secrets});
  for(const text of [reports[0]!.markdown,submissionIndex(reports),submissionDocument(reports),reports[0]!.title])assert.ok(!text.includes(KEY)&&!text.includes(KEY_B64));
  assert.deepEqual(curls(reports[0]!.markdown),['https://shop.example/app.js?v=2']);
  assert.match(reports[0]!.markdown,/A query parameter that held a redacted value was left out/);
  assert.deepEqual(publicGetUrl('https://u:p@shop.example/a.js?token=%5Bredacted%5D&v=1#x'),{url:'https://shop.example/a.js?v=1',droppedQuery:true,valueInUrl:false});
  assert.deepEqual(publicGetUrl('https://shop.example/[redacted]/a.js'),{droppedQuery:false,valueInUrl:true});
  assert.deepEqual(publicGetUrl('javascript:alert(1)'),{droppedQuery:false,valueInUrl:false});
  assert.deepEqual(publicGetUrl('file:///C:/x.js'),{droppedQuery:false,valueInUrl:false});
});

test('reproduction by location kind: value in the path, blocked request, runtime data, assembled value, embedded source, local files',()=>{
  const cases:[Partial<Occurrence>,RegExp,string[]][]=[
    [{url:'https://shop.example/keys/[redacted]/x.js',chain:['https://shop.example/','https://shop.example/keys/[redacted]/x.js']},/address of this resource itself contains the value, so it is not requested[^]*referenced from `https:\/\/shop\.example\/`/,[]],
    [{exposure:'blocked-candidate',url:'https://api.vendor.example/v1?key=[redacted]',coordinates:'runtime-snapshot'},/Exposure Desk blocked that request[^]*Do not send that request yourself/,[]],
    [{exposure:'runtime-memory',coordinates:'runtime-snapshot',url:'https://shop.example/',sourceLabel:'window.__env',line:undefined,column:undefined,byteOffset:undefined},/appears while the page runs \(window\.\\_\\_env\)[^]*developer tools/,[]],
    [{exposure:'static-reconstruction',constituents:[{url:'https://shop.example/a.js',start:1,end:9,line:4,column:2,representation:'[redacted]',label:'part'} as any,{url:'https://shop.example/b.js',start:3,end:20,line:9,column:6,representation:'[redacted]',label:'part'} as any],sink:'fetch header'},/put together from 2 pieces: `https:\/\/shop\.example\/a\.js` line 4, column 2; `https:\/\/shop\.example\/b\.js` line 9, column 6/,['https://shop.example/a.js','https://shop.example/b.js']],
    [{coordinates:'extracted-source',sourceLabel:'webpack://src/config.ts',url:'https://shop.example/app.js.map'},/Look at line 3, column 17 of the embedded source `webpack:\/\/src\/config\.ts` inside this file/,['https://shop.example/app.js.map']],
    [{coordinates:'approximate',transformations:['base64']},/Look at about line 3, column 17 \(byte offset 120 of the decoded text\), after decoding \(base64\)/,['https://shop.example/static/app.js']],
    [{exposure:'local-only',url:'C:/build/app.js'},/not a public exposure/,[]]];
  for(const [over,expect,gets] of cases){
    const [r]=submissionMarkdown([finding({occurrences:[occurrence(over)]})],view([]));
    assert.match(r!.markdown,expect,JSON.stringify(over));assert.deepEqual(curls(r!.markdown),gets,JSON.stringify(over));assertSafe(r!.markdown);
    if(!gets.length||over.coordinates)assert.doesNotMatch(r!.markdown,/tail -c/);
  }
  const [map]=submissionMarkdown([finding({occurrences:[occurrence({url:'https://shop.example/app.js.map'})]})],view([]));assert.match(map!.title,/in a public source map on shop\.example$/);
});

test('reportable findings: credentials only, active suppressions and false positives left out, dismissed never present',()=>{
  const now=Date.parse('2026-10-05T00:00:00Z'),mk=(id:string,over:Partial<Finding>)=>finding({id,fingerprint:id,...over});
  const fs=[mk('01',{}),mk('02',{category:'suspicious'}),mk('03',{category:'public-identifier'}),mk('04',{category:'information'}),mk('05',{suppression:{reason:'accepted',expires:'2026-12-01T00:00:00Z',reviewedAt:'2026-10-01T00:00:00Z'}}),mk('06',{suppression:{reason:'old',expires:'2026-10-01T00:00:00Z',reviewedAt:'2026-09-01T00:00:00Z'}}),mk('07',{feedback:{decision:'false-positive',reason:'test',reviewedAt:'2026-10-01T00:00:00Z'}})];
  const v={...view(fs),dismissedObservations:[mk('08',{})]};
  assert.deepEqual(reportableFindings(v,{now}).map(f=>f.id),['01','02','06']);
  assert.deepEqual(reportableFindings(v,{now,includeSuppressed:true}).map(f=>f.id),['01','02','05','06']);
  assert.deepEqual(reportableFindings(v,{now,categories:['public-identifier','information']}).map(f=>f.id),['03','04']);
  assert.deepEqual(submissionReports([{view:v}]).flatMap(r=>r.findings.map(x=>x.id)).sort(),['01','02','05','06'].filter(id=>reportableFindings(v).some(f=>f.id===id)).sort());
});

test('impact is worded as possible and unverified; unknown providers say so; information findings keep their own text',()=>{
  const withFallback=submissionMarkdown([finding({impacts:undefined})],view([]))[0]!.markdown;
  assert.match(withFallback,/## Possible impact \(unverified\)\n\nIf this is a working OpenAI credential, whoever has it could possibly do the following\. None of it was tested:\n\n- Possible/);
  const unknown=submissionMarkdown([finding({provider:'Acme',rule:'generic-secret',impacts:undefined,category:'suspicious'})],view([]))[0]!;
  assert.match(unknown.markdown,/not mapped, so what it allows is unknown/);assert.match(unknown.title,/^Possible Acme credential exposed in/);
  const info=submissionMarkdown([finding({category:'information',provider:'Website',rule:'source-map',impact:'Readable original source code.',remediation:'Disable production source maps.',impacts:undefined,priority:undefined,occurrences:[occurrence({url:'https://shop.example/app.js.map'})]})],view([]))[0]!;
  assert.match(info.markdown,/Readable original source code\./);assert.match(info.markdown,/Disable production source maps\./);assert.match(info.markdown,/CWE-540/);assert.match(info.markdown,/priority:\*\* not-recorded/);
  for(const r of [unknown,info]){assertSafe(r.markdown);assert.ok(r.markdown.includes(NOT_ESTABLISHED));}
  const caveats=submissionMarkdown([finding({qualifiers:['known-public-example','checksum-mismatch'],environment:'test',credentialSet:{state:'partial',components:['key id'],missing:['secret'],context:''}})],view([]))[0]!.markdown;
  assert.match(caveats,/published documentation example/);assert.match(caveats,/checksum does not match/);assert.match(caveats,/test or sandbox/);assert.match(caveats,/Only part of a credential set was found \(missing: secret\)/);
});

test('grouping: one report per findingId across targets, max severity and priority, per-finding mode on request, stable order',()=>{
  const a=view([finding({severity:'high',priority:{level:'high',basis:['a'],version:'priority/1'}})],{url:'https://shop.example/'});
  const b=view([finding({id:'5555666677778888',fingerprint:'5555666677778888',severity:'critical',occurrences:[occurrence({url:'https://cdn.shop-two.example/main.js',chain:['https://shop-two.example/']})]}),finding({id:'9999',fingerprint:'9999',findingId:FID2,priority:{level:'review',basis:[],version:'priority/1'},severity:'medium'})],{url:'https://shop-two.example/'});
  const grouped=submissionReports([{view:a},{view:b}]);
  assert.equal(grouped.length,2);const [g,other]=grouped;
  assert.equal(g!.findingId,FID);assert.equal(g!.severity,'critical');assert.equal(g!.priority,'urgent');assert.deepEqual(g!.targets,['https://shop.example/','https://shop-two.example/']);
  assert.deepEqual(g!.findings.map(x=>x.id),['1111222233334444','5555666677778888']);
  assert.match(g!.title,/ on 2 assets$/);assert.deepEqual(curls(g!.markdown).sort(),['https://cdn.shop-two.example/main.js','https://shop.example/static/app.js']);
  assert.match(g!.markdown,/· target `https:\/\/shop-two\.example\/`/);assert.match(g!.markdown,/· 2 runs/);
  assert.equal(other!.findingId,FID2);assert.notEqual(g!.fileName,other!.fileName);
  assert.equal(submissionReports([{view:a},{view:b}],{groupBy:'finding'}).length,3);
  // No stable id at all: one report per finding per run, file names still unique and hex-only.
  const anon=submissionReports([{view:view([finding({findingId:undefined}),finding({id:'abcd',fingerprint:'abcd',findingId:undefined})])}]);
  assert.equal(anon.length,2);assert.ok(anon.every(r=>/^finding-[0-9a-z-]+\.md$/.test(r.fileName)&&!r.findingId));assert.equal(new Set(anon.map(r=>r.fileName)).size,2);
  const doc=submissionDocument(grouped);assert.equal(doc.split('\n\n---\n\n').length>=2,true);assert.equal(submissionDocument([]),'# Submission drafts\n\nNo findings were selected for submission.\n');
  const idx=submissionIndex(grouped,{generatedAt:'2026-10-02T00:00:00Z'});assert.match(idx,/^1\. \[Exposed OpenAI credential[^\]]*\]\(finding-a{24}\.md\) — priority urgent · severity critical/m);assert.doesNotMatch(idx,/Sensitive/);
});

test('JSON report input: schema checked, secrets taken only from a sensitive export',()=>{
  const v=view([finding()]),secrets={[finding().id]:{value:KEY,representations:[],locations:[],validity:'unverified'}};
  assert.deepEqual(submissionInputFromReport({schema:'exposure-scan/1',...v,sensitive:true,secrets}).secrets,secrets);
  assert.equal(submissionInputFromReport({schema:'exposure-scan/1',...v,secrets}).secrets,undefined);
  assert.equal(submissionInputFromReport({schema:'exposure-scan/1',...v}).view.id,v.id);
  for(const bad of [null,{},{schema:'exposure-scan/2',...v},{schema:'exposure-scan/1',id:1,name:'x',findings:[]},{schema:'exposure-scan/1',id:'x',name:'x'}])assert.throws(()=>submissionInputFromReport(bad),/schema exposure-scan\/1/);
});

test('disk writer: masked by default; full secrets only in exclusive .sensitive.md files; bundle index never holds values',async()=>{
  const dir=await temp('submission-write-');try{
    const f=finding(),v=view([f,finding({id:'77',fingerprint:'77',findingId:FID2,priority:{level:'review',basis:[],version:'priority/1'}})]),secrets={[f.id]:{value:KEY,representations:[KEY_B64],locations:[],validity:'unverified'}};
    assert.equal(sensitiveName('r.md'),'r.sensitive.md');assert.equal(sensitiveName('r.sensitive.md'),'r.sensitive.md');assert.equal(sensitiveName('r.txt'),'r.txt.sensitive.md');
    // Masked file, secrets present but not asked for.
    const masked=await writeSubmission(path.join(dir,'one.md'),[{view:v,secrets}],{mode:'file'});
    assert.deepEqual(masked.files,[path.join(dir,'one.md')]);assert.equal(masked.sensitive,false);
    const m=await readFile(masked.files[0]!,'utf8');assert.ok(!m.includes(KEY)&&!m.includes(KEY_B64));assert.equal(m.split('\n\n---\n\n').length>=2,true);
    await writeSubmission(path.join(dir,'one.md'),[{view:v}],{mode:'file'});// masked files may be replaced
    // Full secrets: written to the .sensitive.md name, value only in the Exposed value section, excerpts still redacted.
    const full=await writeSubmission(path.join(dir,'one.md'),[{view:v,secrets}],{mode:'file',fullSecrets:true,syntheticFixture:true});
    assert.deepEqual(full.files,[path.join(dir,'one.sensitive.md')]);assert.equal(full.sensitive,true);
    const s=await readFile(full.files[0]!,'utf8');assert.equal(s.split(KEY).length-1,1);assert.ok(!s.includes(KEY_B64));
    assert.ok(s.indexOf(KEY)>s.indexOf('## Exposed value')&&s.indexOf(KEY)<s.indexOf('## Possible impact'));assert.match(s,/\*\*Sensitive: full value\.\*\*/);assert.match(s,/Full value: not available in this record/,'the second finding has no revealed value');
    if(process.platform!=='win32')assert.equal((await stat(full.files[0]!)).mode&0o777,0o600);
    // Never replaces an existing file, and leaves it intact.
    await assert.rejects(writeSubmission(path.join(dir,'one.md'),[{view:v,secrets}],{mode:'file',fullSecrets:true,syntheticFixture:true}),/EEXIST/);
    assert.equal(await readFile(full.files[0]!,'utf8'),s);
    // Full secrets asked for, but the record holds none: stays masked under the ordinary name.
    const none=await writeSubmission(path.join(dir,'none.md'),[{view:v}],{mode:'file',fullSecrets:true,syntheticFixture:true});
    assert.deepEqual(none.files,[path.join(dir,'none.md')]);assert.equal(none.sensitive,false);assert.match(await readFile(none.files[0]!,'utf8'),/Full value: not available in this record/);
    // Bundle: one file per report plus index.md.
    const bundle=await writeSubmission(path.join(dir,'bundle'),[{view:v,secrets}],{mode:'bundle',fullSecrets:true,syntheticFixture:true,generatedAt:'2026-10-02T00:00:00Z'});
    assert.deepEqual((await readdir(path.join(dir,'bundle'))).sort(),['finding-aaaaaaaaaaaaaaaaaaaaaaaa.sensitive.md','finding-bbbbbbbbbbbbbbbbbbbbbbbb.md','index.md']);
    const index=await readFile(bundle.index!,'utf8');assert.ok(!index.includes(KEY));assert.match(index,/\*\*Sensitive:\*\* files ending in `\.sensitive\.md` hold unmasked values/);assert.match(index,/\(finding-a{24}\.sensitive\.md\)/);
    assert.ok((await readFile(path.join(dir,'bundle','finding-aaaaaaaaaaaaaaaaaaaaaaaa.sensitive.md'),'utf8')).includes(KEY));
    assert.ok(!(await readFile(path.join(dir,'bundle','finding-bbbbbbbbbbbbbbbbbbbbbbbb.md'),'utf8')).includes(KEY));
    // A clash removes what this call created and keeps what was there.
    await rm(path.join(dir,'bundle','finding-aaaaaaaaaaaaaaaaaaaaaaaa.sensitive.md'));await writeFile(path.join(dir,'bundle','finding-aaaaaaaaaaaaaaaaaaaaaaaa.sensitive.md'),'kept');
    await assert.rejects(writeSubmission(path.join(dir,'bundle'),[{view:v,secrets}],{mode:'bundle',fullSecrets:true,syntheticFixture:true}),/EEXIST/);
    assert.equal(await readFile(path.join(dir,'bundle','finding-aaaaaaaaaaaaaaaaaaaaaaaa.sensitive.md'),'utf8'),'kept');
    await assert.rejects(writeSubmission(path.join(dir,'x'),[{view:v}],{mode:'zip' as any}),/file or bundle/);
  }finally{await rm(dir,{recursive:true,force:true});}
});

test('disk writer on Windows restricts the sensitive file with the real ACL step before writing it',{skip:process.platform!=='win32'},async()=>{
  const dir=await temp('submission-acl-');try{
    const f=finding(),v=view([f]);
    const r=await writeSubmission(path.join(dir,'acl.md'),[{view:v,secrets:{[f.id]:{value:KEY}}}],{mode:'file',fullSecrets:true});
    assert.deepEqual(r.files,[path.join(dir,'acl.sensitive.md')]);assert.ok((await readFile(r.files[0]!,'utf8')).includes(KEY));
  }finally{await rm(dir,{recursive:true,force:true});}
});

test('end to end on a loopback fixture: the reported line, column and byte offset point at the value in the served file',{timeout:120000},async()=>{
  const app=`// fixture\n/* ünïcode: ok */\nconst client={apiKey:${JSON.stringify(KEY)}};\n`;
  const server=http.createServer((req,res)=>{const p=(req.url||'/').split('?')[0];if(p==='/'){res.setHeader('content-type','text/html');res.end('<!doctype html><title>t</title><script src="/static/app.js"></script>');}else if(p==='/static/app.js'){res.setHeader('content-type','text/javascript');res.end(app);}else{res.statusCode=404;res.end('no');}});
  await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));const origin='http://127.0.0.1:'+(server.address() as any).port,dir=await temp('submission-e2e-');
  try{
    const s=new Scanner({urls:[origin+'/'],developmentFixtureOrigin:origin,requestsPerSecond:20,browser:false,maxRetries:0,timeoutMs:5000,maxDurationMs:60000,semanticAnalysis:false},{detector:new Detector('disabled')});
    const v=await s.run(),found=reportableFindings(v);
    assert.ok(found.length>=1,'the synthetic key is found');
    const reports=submissionMarkdown(found,v),r=reports.find(x=>x.markdown.includes(origin+'/static/app.js'))!;assert.ok(r);assertSafe(r.markdown);
    assert.ok(!JSON.stringify(reports).includes(KEY));assert.deepEqual(curls(r.markdown),[origin+'/static/app.js']);
    const o=found.find(f=>f.occurrences.some(x=>x.url===origin+'/static/app.js'))!.occurrences.find(x=>x.url===origin+'/static/app.js')!;
    const offset=Number(/^tail -c \+(\d+) exposed-resource/m.exec(r.markdown)![1])-1;assert.equal(offset,o.byteOffset);
    assert.ok(Buffer.from(app).subarray(offset).toString().startsWith(KEY),'tail -c +B+1 prints the value (UTF-8 bytes; a non-ASCII comment precedes it)');
    assert.ok(app.split('\n')[o.line!-1]!.slice(o.column!-1).startsWith(KEY),'line and column point at the value');
    // Full secrets from the run's own evidence, written to disk only.
    const written=await writeSubmission(path.join(dir,'e2e.md'),[{view:v,findings:found,secrets:s.evidence.full()}],{mode:'file',fullSecrets:true,syntheticFixture:true});
    assert.match(written.files[0]!,/e2e\.sensitive\.md$/);assert.ok((await readFile(written.files[0]!,'utf8')).includes(KEY));
  }finally{server.close();server.closeAllConnections();await rm(dir,{recursive:true,force:true});}
});
