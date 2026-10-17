import {parse} from 'tldts';
import net from 'node:net';
import {domainToUnicode} from 'node:url';
import {createRequire} from 'node:module';
import {normalizeUrl} from './config.js';
import type {DomainScope,ScanConfig,ScopeView} from './types.js';
import {programScope} from './program/settings.js';
import type {ProgramScope} from './program/rules.js';
export type {DomainScope};
export type ScopeClass='explicit-seed'|'explicit-related'|'in-domain'|'outside';
export type ExclusionReason='third-party'|'exact-origin-mode'|'outside-host-subtree'|'no-public-suffix'|'ip-literal'|'noncanonical-host'|'userinfo'|'non-http'|'program-out-of-scope';
export interface ScopeDecision {class:ScopeClass;origin:string;registrableDomain?:string;seed?:string;root?:string;reason?:ExclusionReason}
export type ScopeSource=ScopeView['source'];
export const DOMAIN_SCOPES:DomainScope[]=['registrable-domain','exact-origin','host-subtree'];
let pslVersion='unknown';try{pslVersion=String(createRequire(import.meta.url)('tldts/package.json').version);}catch{}
/**
 * Shared-hosting and SaaS tenant boundaries that the bundled PSL (tldts 7.4.16) lacks: each customer host directly beneath one of these is its own
 * registrable domain, so domain scope never spans two customers of one provider. `*.` covers one region label. Narrowing only: an entry never
 * widens scope, and a longer suffix the PSL already knows wins. Not exhaustive; the deep-seed warning still recommends host-subtree scope.
 */
export const TENANT_SUFFIXES:readonly string[]=('wpengine.com kinsta.cloud flywheelsites.com flywheelstaging.com wordpress.com wpcomstaging.com myftpupload.com cloudwaysapps.com sg-host.com hostingersite.com 000webhostapp.com '+
  'squarespace.com weebly.com weeblysite.com godaddysites.com mystrikingly.com jimdosite.com jimdofree.com myportfolio.com webnode.page cargo.site bigcartel.com mailchimpsites.com zohosites.com softr.app neocities.org glitch.me tumblr.com ghost.io substack.com '+
  'zendesk.com freshdesk.com freshservice.com myfreshworks.com atlassian.net service-now.com okta.com oktapreview.com onelogin.com sharepoint.com auth0.com us.auth0.com eu.auth0.com au.auth0.com jp.auth0.com uk.auth0.com ca.auth0.com '+
  'force.com lightning.force.com sandbox.lightning.force.com vf.force.com my.salesforce.com sandbox.my.salesforce.com my.site.com sandbox.my.site.com salesforce-sites.com my.salesforce-sites.com hs-sites.com hubspotpagebuilder.com readme.io statuspage.io helpscoutdocs.com teachable.com thinkific.com mykajabi.com '+
  '*.cloudapp.azure.com *.azurecontainerapps.io database.windows.net search.windows.net redis.cache.windows.net vault.azure.net documents.azure.com azurecr.io vo.msecnd.net googleusercontent.com firebaseio.com herokudns.com b-cdn.net kxcdn.com stackpathcdn.com').split(' ');
const tenantSuffixes=new Set(TENANT_SUFFIXES);
export const PSL={library:'tldts' as const,version:pslVersion,tenantSuffixes:TENANT_SUFFIXES.length};
/** The longest supplemental tenant suffix that ends this host (the host itself when it is one), or undefined. */
function tenantSuffix(host:string){const labels=host.split('.');for(let i=0;i<labels.length-1;i++){const s=labels.slice(i).join('.');if(tenantSuffixes.has(s)||tenantSuffixes.has('*.'+labels.slice(i+1).join('.')))return s;}return undefined;}
/** Hostname labels must be nonempty, never `*`, and at most 63 characters; exactly one trailing dot is canonicalized away by normalizeUrl.
 * Lenient on purpose: saved records and discovered URLs are read with it. New input is held to websiteHost. */
export function validHostLabels(hostname:string){return /^\[.*\]$/.test(hostname)||hostname.split('.').every(label=>label.length>0&&label.length<=63&&label!=='*');}
/** A website host as new input accepts it (`--targets` lines, `--url`, `--config`, dashboard saves and scan starts): letters, digits, hyphens and underscores in labels of
 * 1–63 characters (IDN arrives as punycode from the URL parser) with at most one trailing dot, or an IP literal. One rule for the CLI and configurations, so they cannot drift. */
export function websiteHost(hostname:string){return /^\[[0-9a-f:.]+\]$/i.test(hostname)||/^(?:[a-z0-9_-]+\.)*[a-z0-9_-]+\.?$/i.test(hostname)&&validHostLabels(hostname.replace(/\.$/,''));}
/** Include private PSL suffixes and the supplemental tenant boundaries so unrelated tenants of hosted services stay separate. */
export function registrableDomain(raw:string):string|null {
  try {
    const host=new URL(normalizeUrl(raw)).hostname.toLowerCase().replace(/\.$/,'');
    if(!validHostLabels(host))return null;
    const result=parse(host,{allowPrivateDomains:true});
    if(result.isIp||!(result.isIcann||result.isPrivate))return null;
    const tenant=tenantSuffix(host);
    if(tenant&&tenant.length>(result.publicSuffix||'').length)return host===tenant?null:host.split('.').slice(-tenant.split('.').length-1).join('.');
    return result.domain;
  }catch{return null;}
}
export function authorizedSeed(raw:string,seeds:readonly string[]):string|undefined {
  const domain=registrableDomain(raw);
  return domain?seeds.find(seed=>registrableDomain(seed)===domain):undefined;
}
/** Effective mode of any stored config, including pre-2.5 records that only carry the boolean. */
export function effectiveScope(config:Partial<ScanConfig>):DomainScope{return config.domainScope&&DOMAIN_SCOPES.includes(config.domainScope)?config.domainScope:config.sameRegistrableDomainDiscovery?'registrable-domain':'exact-origin';}
/** Where the scope came from, judged on the raw input before defaults are merged. */
export function scopeSource(input:Partial<ScanConfig>):ScopeSource{return input.scopeReview?'legacy-saved-default':input.domainScope!==undefined?'explicit':typeof input.sameRegistrableDomainDiscovery==='boolean'?'legacy-flag':'default';}
/** Websites domain scope may still admit after the start: none in exact-origin mode or when no seed has a registrable domain (IP literals, localhost), otherwise up to maxAutoDiscoveredOrigins. Shared by the scanner and the scan-page preview. */
export const discoveredLimit=(c:Pick<ScanConfig,'domainScope'|'urls'|'maxAutoDiscoveredOrigins'>)=>c.domainScope==='exact-origin'||!c.urls.some(u=>registrableDomain(u))?0:c.maxAutoDiscoveredOrigins??50;
export function unsupportedSeedReason(seed:string):string|undefined{try{const u=new URL(normalizeUrl(seed)),host=u.hostname.replace(/^\[|\]$/g,'');if(net.isIP(host))return 'IP address literal has no registrable domain';if(/^(?:localhost|.*\.(?:localhost|test|invalid|internal|local|example))$/i.test(u.hostname))return 'reserved or special-use name has no public suffix';if(!registrableDomain(seed))return tenantSuffix(host.toLowerCase())===host.toLowerCase()?'shared-hosting tenant suffix has no registrable domain of its own':'suffix is not in the bundled public suffix list';return undefined;}catch{return 'invalid seed';}}
/** The one scope policy. Pure: no DNS and no I/O; matching is on punycode registrable domains, never substrings. */
export class ScopePolicy {
  readonly mode:DomainScope;private seeds=new Map<string,string>();private roots=new Map<string,string>();private seedOrigins=new Set<string>();private related=new Set<string>();private cache=new Map<string,ScopeDecision>();
  /** Program scope (2.8): narrows every decision (never widens it); checked per URL because a URL-prefix rule limits paths. */
  readonly program?:ProgramScope;
  constructor(readonly config:Partial<ScanConfig>&{urls:string[]}){
    this.mode=effectiveScope(config);
    if(config.program)this.program=programScope(config.program);
    for(const seed of config.urls){let origin='';try{origin=new URL(seed).origin;}catch{continue;}this.seedOrigins.add(origin);const domain=registrableDomain(seed);if(!domain)continue;if(!this.seeds.has(domain))this.seeds.set(domain,seed);const root=new URL(normalizeUrl(seed)).hostname.toLowerCase().replace(/^www\./,'');if(!this.roots.has(root))this.roots.set(root,seed);}
    for(const origin of config.relatedOrigins||[])this.related.add(origin);
  }
  get registrableDomains(){return [...this.seeds.keys()];}
  seedFor(domain:string){return this.seeds.get(domain);}
  /** Canonical origin for a raw URL (one trailing dot stripped, lowercase host); undefined when it cannot be canonical. */
  static canonicalOrigin(raw:string){try{return new URL(normalizeUrl(raw)).origin;}catch{return undefined;}}
  classify(raw:string):ScopeDecision{
    let u:URL;try{u=new URL(raw);}catch{return {class:'outside',origin:'',reason:'non-http'};}
    let origin='';try{origin=u.origin;}catch{}
    if(!['http:','https:'].includes(u.protocol))return {class:'outside',origin,reason:'non-http'};
    if(u.username||u.password)return {class:'outside',origin,reason:'userinfo'};
    let canonical:URL;try{canonical=new URL(normalizeUrl(raw));}catch{return {class:'outside',origin,reason:'noncanonical-host'};}
    origin=canonical.origin;
    if(this.program&&!this.program.allows(canonical))return {class:'outside',origin,reason:'program-out-of-scope'};
    const cached=this.cache.get(origin);if(cached)return cached;
    const host=canonical.hostname.toLowerCase(),bare=host.replace(/^\[|\]$/g,'');
    let decision:ScopeDecision;
    if(this.seedOrigins.has(origin))decision={class:'explicit-seed',origin};
    else if(this.related.has(origin))decision={class:'explicit-related',origin};
    else if(net.isIP(bare))decision={class:'outside',origin,reason:'ip-literal'};
    else{
      const domain=registrableDomain(canonical.href);
      if(!domain)decision={class:'outside',origin,reason:'no-public-suffix'};
      else{
        const seed=this.seeds.get(domain);
        if(!seed)decision={class:'outside',origin,registrableDomain:domain,reason:'third-party'};
        else if(this.mode==='exact-origin')decision={class:'outside',origin,registrableDomain:domain,seed,reason:'exact-origin-mode'};
        else if(this.mode==='host-subtree'){const root=[...this.roots.keys()].find(r=>host===r||host.endsWith('.'+r)&&registrableDomain('https://'+r)===domain);decision=root?{class:'in-domain',origin,registrableDomain:domain,seed:this.roots.get(root)!,root}:{class:'outside',origin,registrableDomain:domain,seed,reason:'outside-host-subtree'};}
        else decision={class:'in-domain',origin,registrableDomain:domain,seed};
      }
    }
    if(this.cache.size>=10000)this.cache.clear();this.cache.set(origin,decision);return decision;
  }
  /** Eligibility only: the seed whose domain admits this URL. Admission still requires preflight. */
  eligibleSeed(raw:string){const d=this.classify(raw);return d.class==='in-domain'?d.seed:undefined;}
  inDomain(raw:string){const d=this.classify(raw);return d.class==='in-domain'||d.reason==='exact-origin-mode'||d.reason==='outside-host-subtree';}
  describe(source:ScopeSource='explicit'):ScopeView{
    const max=this.config.maxAutoDiscoveredOrigins??50,groups:ScopeView['groups']=[],unsupportedSeeds:ScopeView['unsupportedSeeds']=[],warnings:string[]=[],otherExplicitOrigins:string[]=[];
    for(const seed of this.config.urls){const reason=unsupportedSeedReason(seed);if(reason){unsupportedSeeds.push({seed,reason});continue;}const domain=registrableDomain(seed)!;let group=groups.find(g=>g.registrableDomain===domain);if(!group){group={registrableDomain:domain,unicode:domainToUnicode(domain),seeds:[],explicitOrigins:[],redundantExplicit:[],subtreeRoots:[],admittedOrigins:[],contactedOrigins:[],notAdmitted:[]};groups.push(group);}if(!group.seeds.includes(seed))group.seeds.push(seed);const host=new URL(seed).hostname.toLowerCase(),root=host.replace(/^www\./,'');if(this.mode==='host-subtree'&&!group.subtreeRoots.includes(root))group.subtreeRoots.push(root);if(this.mode==='registrable-domain'&&root!==domain&&!warnings.some(w=>w.includes(host)))warnings.push(`Seed ${host} is deeper than its registrable domain ${domain}. If ${domain} belongs to a hosting provider that is missing from the bundled public suffix list, domain scope would authorize other tenants; consider host-subtree scope rooted at ${root}.`);}
    // An explicit origin inside a seed's group is redundant when the mode would admit it anyway (it stays authorized either way).
    for(const origin of this.config.relatedOrigins||[]){const domain=registrableDomain(origin),group=domain?groups.find(g=>g.registrableDomain===domain):undefined;if(!group){otherExplicitOrigins.push(origin);continue;}group.explicitOrigins.push(origin);const host=new URL(origin).hostname.toLowerCase();if(this.mode==='registrable-domain'||this.mode==='host-subtree'&&group.subtreeRoots.some(r=>host===r||host.endsWith('.'+r)))group.redundantExplicit.push(origin);}
    const names=groups.map(g=>g.unicode===g.registrableDomain?g.registrableDomain:`${g.unicode} (${g.registrableDomain})`);
    const summary=this.mode==='exact-origin'?`Exact-origin scope: only the entered origins${this.config.relatedOrigins?.length?' and the approved related origins':''} are scanned; discovered subdomains are listed, not scanned.`:this.mode==='host-subtree'?`Host-subtree scope: ${groups.flatMap(g=>g.subtreeRoots).join(', ')||'the entered hosts'} and hosts beneath them (up to ${max} discovered origins; shared limits apply).`:groups.length?`Domain scope: ${names.join(', ')} and all of ${groups.length===1?'its':'their'} subdomains (up to ${max} discovered origins; shared limits apply; third-party origins excluded).`:'Domain scope: no entered seed has a supported registrable domain, so only the entered origins are scanned.';
    const programNote=this.program?` Program scope narrows this to ${this.program.in.length} in-scope rule${this.program.in.length===1?'':'s'}${this.program.out.length?` minus ${this.program.out.length} out-of-scope rule${this.program.out.length===1?'':'s'}`:''}; origins and paths outside it are never contacted.`:'';
    return {mode:this.mode,source,psl:{...PSL},groups,unsupportedSeeds,otherExplicitOrigins,warnings,maxAutoDiscoveredOrigins:max,autoAdmitted:0,summary:summary+programNote,excluded:{thirdPartyOrigins:0,references:0,overflow:0,examples:[]}};
  }
}
