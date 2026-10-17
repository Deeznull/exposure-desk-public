import test from 'node:test';
import assert from 'node:assert/strict';
import { ProgramScope, RuleError, parseRule, ruleHost, describeRule, MAX_RULE_LENGTH } from '../src/program/rules.js';
/** 2.8 program scope rules (w1-scope): parsing, matching and precedence. Pure: no DNS and no network; names are .example/.test and documentation addresses. */
const scope=(inRules:string[],outRules:string[]=[])=>new ProgramScope({in:inRules,out:outRules});
const allows=(s:ProgramScope,urls:string[])=>urls.map(u=>s.allows(u));

test('rule forms: exact host, wildcard, URL prefix, IP and CIDR parse to canonical rules',()=>{
  assert.deepEqual(parseRule('App.Acme.EXAMPLE.'),{raw:'App.Acme.EXAMPLE.',kind:'host',host:'app.acme.example'});
  assert.deepEqual(parseRule('*.acme.example'),{raw:'*.acme.example',kind:'wildcard',base:'acme.example'});
  assert.deepEqual(parseRule('https://API.acme.test:8443/v1/*'),{raw:'https://API.acme.test:8443/v1/*',kind:'url',host:'api.acme.test',scheme:'https:',port:'8443',path:'/v1/'});
  assert.deepEqual(parseRule('acme.example/app'),{raw:'acme.example/app',kind:'url',host:'acme.example',path:'/app'});
  assert.deepEqual(parseRule('acme.example:8080'),{raw:'acme.example:8080',kind:'url',host:'acme.example',port:'8080'});
  assert.deepEqual(parseRule('*.acme.example/api/'),{raw:'*.acme.example/api/',kind:'url',base:'acme.example',path:'/api/'});
  assert.deepEqual(parseRule('http://acme.example/'),{raw:'http://acme.example/',kind:'url',host:'acme.example',scheme:'http:'});
  assert.deepEqual(parseRule('192.0.2.10'),{raw:'192.0.2.10',kind:'ip',host:'192.0.2.10'});
  assert.equal(parseRule('[2001:DB8::1]').host,'2001:db8:0:0:0:0:0:1');
  assert.equal(parseRule('192.0.2.0/24').kind,'cidr');assert.equal(parseRule('::ffff:192.0.2.0/120').cidr![1],24,'IPv4-mapped CIDR is normalized to IPv4');
  assert.equal(parseRule('bücher.example').host,'xn--bcher-kva.example','international names become punycode');
  assert.equal(ruleHost(parseRule('*.acme.example')),'acme.example');assert.equal(ruleHost(parseRule('192.0.2.0/24')),undefined);
  assert.match(describeRule(parseRule('*.acme.example')),/subdomains of acme\.example only; not acme\.example itself/);
});

test('invalid or too-broad rules are refused with a message naming the rule',()=>{
  const bad:[unknown,RegExp][]=[[42,/must be strings/],['',/empty/],['   ',/empty/],['a b.example',/whitespace/],['acme\u0000.example',/control/],['*',/bare "\*"/],['*.*',/bare/],['*acme.example',/bare/],
    ['ftp://acme.example/',/only http and https/],['https://user:pw@acme.example/',/user information/],['https://acme.example/?q=1',/query strings/],['https://acme.example/#top',/query strings/],['acme.example:0',/invalid port/],['acme.example:70000',/invalid port/],
    ['a.*.acme.example',/only a leading/],['https://acme.example/a*/b',/only a trailing/],['*.com',/public suffix/],['*.co.uk',/public suffix/],['*.github.io',/public suffix/],['10.0.0.0/7',/too broad/],['2001:db8::/31',/too broad/],['192.0.2.0/33',/invalid CIDR/],
    ['Main',/not a valid host name/],['localhost',/not a valid host name/],['-bad.example',/not a valid host name/],['x'.repeat(MAX_RULE_LENGTH+1),/longer than/]];
  for(const [rule,message] of bad)assert.throws(()=>parseRule(rule),(e:unknown)=>e instanceof RuleError&&message.test(e.message),String(rule).slice(0,40));
  // Out-of-scope rules may be broad: excluding more is always safe.
  assert.equal(parseRule('*.com',false).kind,'wildcard');assert.equal(parseRule('10.0.0.0/7',false).kind,'cidr');
});

test('matching: a wildcard covers subdomains but never the apex; an exact host covers any scheme and port; a URL rule limits scheme, port and path',()=>{
  const w=scope(['*.acme.example']);
  assert.deepEqual(allows(w,['https://app.acme.example/','http://a.b.acme.example:8080/x','https://acme.example/','https://evilacme.example/','https://acme.example.test/']),[true,true,false,false,false]);
  const h=scope(['acme.example']);assert.deepEqual(allows(h,['https://acme.example/','http://acme.example:8080/any','https://www.acme.example/','ftp://acme.example/']),[true,true,false,false]);
  const u=scope(['https://api.acme.test/v1/']);
  assert.deepEqual(allows(u,['https://api.acme.test/v1/','https://api.acme.test/v1/users?id=1','https://api.acme.test/v2/','https://api.acme.test/v1','http://api.acme.test/v1/x','https://api.acme.test:8443/v1/x','https://api.acme.test:443/v1/x']),[true,true,false,false,false,false,true]);
  // A path without a trailing slash matches itself and its children, not siblings sharing the prefix.
  const p=scope(['acme.example/app']);assert.deepEqual(allows(p,['https://acme.example/app','http://acme.example/app/x','https://acme.example/application','https://acme.example:9443/app']),[true,true,false,true]);
  const port=scope(['acme.example:8080']);assert.deepEqual(allows(port,['http://acme.example:8080/','https://acme.example:8080/','https://acme.example/']),[true,true,false]);
  const ip=scope(['192.0.2.10','198.51.100.0/24','[2001:db8::1]']);
  assert.deepEqual(allows(ip,['http://192.0.2.10/','https://192.0.2.10:8443/','http://192.0.2.11/','http://198.51.100.200/','http://[2001:db8::1]/','http://[::ffff:198.51.100.7]/','https://ip.acme.example/']),[true,true,false,true,true,true,false],'IP rules match IP-literal URLs only');
  assert.equal(h.allows('not a url'),false);
});

test('precedence: out-of-scope rules always win, at host, wildcard, path and CIDR level; anything unmatched is out of scope',()=>{
  const s=scope(['*.acme.example','acme.example','192.0.2.0/24'],['legacy.acme.example','*.internal.acme.example','https://www.acme.example/admin/','192.0.2.128/25']);
  assert.deepEqual(s.check(new URL('https://app.acme.example/')),{allowed:true,reason:'in-scope',rule:'*.acme.example'});
  assert.deepEqual(s.check(new URL('https://legacy.acme.example/')),{allowed:false,reason:'out-of-scope-rule',rule:'legacy.acme.example'});
  assert.equal(s.check(new URL('https://db.internal.acme.example/')).reason,'out-of-scope-rule');
  assert.equal(s.check(new URL('https://www.acme.example/admin/users')).reason,'out-of-scope-rule');assert.equal(s.check(new URL('https://www.acme.example/admin')).allowed,true,'the /admin/ prefix excludes only its children');
  assert.equal(s.check(new URL('http://192.0.2.200/')).reason,'out-of-scope-rule');assert.equal(s.check(new URL('http://192.0.2.5/')).allowed,true);
  assert.deepEqual(s.check(new URL('https://other.test/')),{allowed:false,reason:'not-in-scope'});
  // Origin level (related origins): a path-limited out rule leaves the origin possible; a whole-origin out rule does not.
  assert.equal(s.originPossible('https://www.acme.example'),true);assert.equal(s.originPossible('https://legacy.acme.example'),false);assert.equal(s.originPossible('https://other.test'),false);
  assert.equal(scope(['https://api.acme.test/v1/']).originPossible('https://api.acme.test'),true);assert.equal(scope(['https://api.acme.test/v1/']).originPossible('http://api.acme.test'),false);
  assert.ok(s.describe().some(l=>l.startsWith('out  legacy.acme.example')));
});

test('a large scope stays fast: indexed by host and wildcard base',()=>{
  const inRules=Array.from({length:5000},(_,i)=>`h${i}.acme.example`).concat(Array.from({length:4000},(_,i)=>`*.w${i}.acme.test`)),s=scope(inRules,['h7.acme.example']);
  const start=performance.now();let hits=0;for(let i=0;i<20000;i++)if(s.allows(`https://x.w${i%4000}.acme.test/p${i}`))hits++;
  assert.equal(hits,20000);assert.equal(s.allows('https://h7.acme.example/'),false);assert.ok(performance.now()-start<5000,'20000 checks well under 5 s');
});
