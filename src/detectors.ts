import { spawn } from 'node:child_process';
import {AsyncLocalStorage} from 'node:async_hooks';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { open, rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { parse, parseExpressionAt } from 'acorn';
import type { Candidate, Category, Confidence, Severity, AbortReason, GapCause } from './types.js';
import { abortReason } from './origin-control.js';
import { privateDirectory } from './local-files.js';
import { compileRules } from './rules.js';
import type { RE2 } from 're2-wasm';
import { offlineBinary } from './runtime-paths.js';
import { contextualCredentials, CONTEXT_FOCUS } from './provider-context.js';
import { capabilities } from './capabilities.js';
import { keyMaterial, pemStructure, bip39Words, keyMaterialIssue } from './key-material.js';
import { canonicalProvider } from './provider-capabilities.js';
import { placeholderValue } from './placeholders.js';
import { tokenChecksum } from './token-checksums.js';
import { FifoBudget } from './fifo-budget.js';
import { FairTurns } from './program/limiter.js';
import { AnalysisChild, type AnalysisExit } from './analysis-process.js';
import { analysisTimeFactor, currentTimeFactor, scaleMs } from './machine-speed.js';
const DETECTOR_ENTRY=new URL('./detector-worker.js',import.meta.url);
/** Reference wall-clock analysis limits (a fast computer); each use scales them by the analysis time factor (machine-speed.ts): the isolated large-text inspection, the wait for its process to end,
 * an offline engine run (and gitleaks' own --timeout, in seconds) and the decoded-view enumeration. */
const DIRECT_WORKER_MS=10000,WORKER_CLEANUP_MS=1000,ENGINE_MS=10000,ENGINE_TIMEOUT_S=8,DECODED_ENUMERATION_MS=250;
/** Offline-engine rules whose findings the scan always drops (session, cookie, JWT, flag and generic material is classified by the direct rules instead). */
export const DISCARDED_ENGINE_RULE=/session|cookie|^jwt|feature-flag|feed-token|aws-access-token|twilio-api-key|generic-api-key/;
const enumerationLimit=()=>`Decoded-view count, expanded-size or ${scaleMs(DECODED_ENUMERATION_MS)} ms enumeration budget reached; unseen encoded content remains unknown.`;
const moduleParent = fileURLToPath(new URL('../', import.meta.url));
export const root = path.basename(path.resolve(moduleParent))==='dist'?path.dirname(path.resolve(moduleParent)):moduleParent;
/** Typed interruption of local analysis. The kind comes from the aborted signal, never from exception text; the message stays `cancelled` for existing callers. */
export class AnalysisInterrupted extends Error{constructor(readonly reason:AbortReason|undefined,readonly phase:string){super('cancelled');}}
/** Typed local analysis failure (worker or engine), distinct from an interruption and from a genuine detector exception. */
export class AnalysisFailure extends Error{constructor(readonly code:'direct-worker-timeout'|'worker-failure'|'worker-cleanup-timeout'|'engine-timeout'|'engine-failure'|'engine-output-limit'|'engine-launch-failure',readonly phase:string){super(code);}}
export const ENGINE_VERSION = '8.30.1';
export const RULE_VERSION = 'website/2.9.1';
type Rule = { id: string; provider: string; regex: RegExp | RE2; category: Category; severity: Severity; confidence?: Confidence; group?: number; reason?: string };
export const rules: Rule[] = [
  {id:'resend-key',provider:'Resend',regex:/\bre_[A-Za-z0-9]{20,200}\b/g,category:'private-credential',severity:'high',confidence:'medium',reason:'Bounded Resend API-key prefix heuristic; supported authentication role documented, validity and permissions unverified.'},
  {id:'groq',provider:'Groq',regex:/\bgsk_[A-Za-z0-9_-]{20,200}\b/g,category:'private-credential',severity:'high'},
  {id:'perplexity',provider:'Perplexity',regex:/\bpplx-[A-Za-z0-9_-]{20,200}\b/g,category:'private-credential',severity:'high'},
  {id:'openrouter',provider:'OpenRouter',regex:/\bsk-or-v1-[A-Za-z0-9_-]{20,200}\b/g,category:'private-credential',severity:'high'},
  {id:'digitalocean',provider:'DigitalOcean',regex:/\bdo[pora]_v1_[a-f0-9]{64}\b/g,category:'private-credential',severity:'high'},
  {id:'stripe-org',provider:'Stripe',regex:/\bsk_org_[A-Za-z0-9_]{16,200}\b/g,category:'private-credential',severity:'high'},
  {id:'bedrock-bearer',provider:'AWS Bedrock',regex:/\b(?:ABSK[A-Za-z0-9+/=_-]{20,2048}|bedrock-api-key-[A-Za-z0-9+/=_-]{20,4096})/g,category:'private-credential',severity:'high'},
  {id:'sentry-auth',provider:'Sentry',regex:/\bsntry[su]_[A-Za-z0-9_-]{20,256}\b/g,category:'private-credential',severity:'high'},
  {id:'cloudflare-prefixed',provider:'Cloudflare',regex:/\b(?:cfk_|cfut_|cfat_|cfast_)[A-Za-z0-9_-]{40,64}\b/g,category:'private-credential',severity:'high',confidence:'medium',reason:'Cloudflare scannable credential prefix; checksum and validity are not verified. Scope may be narrow or read-only.'},
  {id:'mailgun-public',provider:'Mailgun',regex:/\bpubkey-[a-f0-9]{32}\b/g,category:'public-identifier',severity:'info'},
  {id:'application-signing-secret',provider:'Application signing',regex:/\b(?:JWT_SECRET|JWT_SIGNING_SECRET|SESSION_SECRET|WEBHOOK_SECRET|SIGNING_SECRET)["']?\s*[:=]\s*["']([A-Za-z0-9_+\/=.!@#$%^&*-]{8,512})["']/gi,group:1,category:'private-credential',severity:'high',confidence:'medium'},
  {id:'openai',provider:'OpenAI',regex:/\b(?:sk-(?:proj-|svcacct-)[A-Za-z0-9_-]{40,200}|sk-[A-Za-z0-9]{48})\b/g,category:'private-credential',severity:'high'},
  {id:'anthropic',provider:'Anthropic',regex:/\bsk-ant-(?:api\d{2}|admin\d{2}|oat\d{2})-[A-Za-z0-9_-]{40,200}\b/g,category:'private-credential',severity:'high'},
  {id:'google-api',provider:'Google / Gemini',regex:/\bAIza[A-Za-z0-9_-]{35}\b/g,category:'suspicious',severity:'medium',reason:'Google API-key format; Firebase use can be public. Restrictions, enabled APIs and billable capabilities are unknown.'},
  {id:'stripe-secret',provider:'Stripe',regex:/\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,150}\b/g,category:'private-credential',severity:'high'},
  {id:'stripe-signing',provider:'Stripe',regex:/\bwhsec_[A-Za-z0-9]{16,150}\b/g,category:'private-credential',severity:'high'},
  {id:'stripe-public',provider:'Stripe',regex:/\bpk_(?:live|test)_[A-Za-z0-9]{16,150}\b/g,category:'public-identifier',severity:'info',reason:'Publishable Stripe key is intended for client applications.'},
  {id:'supabase-secret',provider:'Supabase',regex:/\bsb_secret_[A-Za-z0-9_-]{20,150}\b/g,category:'private-credential',severity:'critical'},
  {id:'supabase-public',provider:'Supabase',regex:/\bsb_publishable_[A-Za-z0-9_-]{20,150}\b/g,category:'public-identifier',severity:'info',reason:'Supabase publishable key is intended for clients; data security depends on grants and RLS.'},
  {id:'github',provider:'GitHub',regex:/\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{50,255})\b/g,category:'private-credential',severity:'high'},
  {id:'gitlab',provider:'GitLab',regex:/\bglpat-[A-Za-z0-9_-]{20,150}\b/g,category:'private-credential',severity:'high'},
  {id:'huggingface',provider:'Hugging Face',regex:/\b(?:hf|api_org)_[A-Za-z0-9]{30,100}\b/g,category:'private-credential',severity:'high'},
  {id:'replicate',provider:'Replicate',regex:/\br8_[A-Za-z0-9]{30,100}\b/g,category:'private-credential',severity:'high'},
  {id:'sendgrid',provider:'SendGrid',regex:/\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g,category:'private-credential',severity:'high'},
  {id:'twilio-api',provider:'Twilio',regex:/\bSK[0-9a-fA-F]{32}\b/g,category:'suspicious',severity:'medium',reason:'Twilio API key SID is a credential component; paired secret was not validated.'},
  {id:'aws-id',provider:'AWS',regex:/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g,category:'suspicious',severity:'medium',reason:'AWS access-key ID is only one component; privileges and paired secret are unverified.'},
  {id:'pgp-private-key',provider:'PGP private key',regex:/-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]{20,20000}?-----END PGP PRIVATE KEY BLOCK-----/g,category:'private-credential',severity:'critical',reason:'Armored PGP private key block; it can sign and decrypt as the key owner. Validity is not tested.'},
  {id:'private-key',provider:'Private signing key',regex:/-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----[\s\S]{20,12000}?-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----/g,category:'private-credential',severity:'critical'},
  {id:'database-password',provider:'Database',regex:/\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|mssql):\/\/[^\s:'"<>/]{0,100}:([^\s@'"<>]{3,300})@[^\s'"<>]+/g,category:'private-credential',severity:'high',group:1},
  {id:'npm-auth',provider:'npm',regex:/(?:_authToken|_auth)\s*[:=]\s*["']?([A-Za-z0-9_+\/=.-]{20,200})/g,category:'private-credential',severity:'high',group:1},
  // Adapted from Nosey Parker rules (github.com/praetorian-inc/noseyparker, crates/noseyparker/data/default/builtin/rules/: dockerhub.yml
  // np.dockerhub.1, firecrawl.yml np.firecrawl.1, google.yml np.google.2 and its ya29 access-token rule, jina.yml np.jina.1, square.yml
  // np.square.2, tavily.yml np.tavily.1; commit 2e6e7f36ce36619852532bbe698d8cb7a26d2da7; Apache-2.0, rules/NOSEYPARKER-LICENSE and
  // rules/NOSEYPARKER-NOTICE). Changes: JavaScript syntax, trailing delimiters as lookaheads, own optional dev-/prod- marker for Tavily.
  {id:'dockerhub-pat',provider:'Docker Hub',regex:/\bdckr_pat_[A-Za-z0-9_-]{27}(?![A-Za-z0-9_-])/g,category:'private-credential',severity:'high'},
  {id:'firecrawl-key',provider:'Firecrawl',regex:/\bfc-[a-f0-9]{32}\b/g,category:'private-credential',severity:'high',confidence:'medium',reason:'Firecrawl API-key format (short prefix and 32 hexadecimal characters), so detection confidence is medium. Validity and credit limits are unverified.'},
  {id:'google-oauth-secret',provider:'Google OAuth',regex:/\bGOCSPX-[A-Za-z0-9_-]{28}(?![A-Za-z0-9_-])/g,category:'private-credential',severity:'high',reason:'Google OAuth client secret format; with the public client ID it lets anyone act as the OAuth application. Validity is unverified.'},
  {id:'google-oauth-access-token',provider:'Google OAuth',regex:/\bya29\.[0-9A-Za-z_-]{20,1024}(?![0-9A-Za-z_-])/g,category:'private-credential',severity:'high',confidence:'medium',reason:'Google OAuth access token format. These usually expire within an hour, so validity, scope and expiry are unverified; its presence shows a user or service token reached public content.'},
  {id:'jina-key',provider:'Jina',regex:/\bjina_[A-Za-z0-9]{60}\b/g,category:'private-credential',severity:'high'},
  {id:'square-oauth-secret',provider:'Square',regex:/\bsq0csp-[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])/gi,category:'private-credential',severity:'high',reason:'Square OAuth application secret format; validity and the application permissions are unverified.'},
  {id:'tavily-key',provider:'Tavily',regex:/\btvly-(?:dev-|prod-)?[A-Za-z0-9]{32}\b/g,category:'private-credential',severity:'high'},
  // Adapted from secretlint (github.com/secretlint/secretlint, packages/@secretlint/secretlint-rule-figma, -tailscale and -vercel, src/index.ts;
  // commit 5b7a74dace5027f3ae327bd9435ac7e20f41b10a; MIT, rules/SECRETLINT-LICENSE). Changes: Vercel split by capability, named groups removed.
  {id:'figma-pat',provider:'Figma',regex:/(?<!\p{L})figd_[A-Za-z0-9_-]{40,200}(?![A-Za-z0-9_-])/gu,category:'private-credential',severity:'high'},
  {id:'tailscale-key',provider:'Tailscale',regex:/(?<!\p{L})tskey-[a-z]{2,20}-[0-9A-Za-z_]{8,40}-[0-9A-Za-z_]{16,60}(?![0-9A-Za-z_])/gu,category:'private-credential',severity:'high',reason:'Tailscale key (auth, API, OAuth client, SCIM or webhook); an auth key can join devices to the tailnet. Validity, expiry and tags are unverified.'},
  {id:'vercel-token',provider:'Vercel',regex:/(?<!\p{L})vc[piar]_[A-Za-z0-9]{20,60}(?![A-Za-z0-9])/gu,category:'private-credential',severity:'high',reason:'Vercel personal, integration or app token format; it can manage deployments and environment variables. Validity and scope are unverified.'},
  {id:'vercel-ai-gateway',provider:'Vercel AI Gateway',regex:/(?<!\p{L})vck_[A-Za-z0-9]{20,60}(?![A-Za-z0-9])/gu,category:'private-credential',severity:'high'},
  // Own formats: Braintree production access token and Cloudinary environment URL (the API secret is the reported value).
  {id:'braintree-access-token',provider:'Braintree',regex:/\baccess_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}\b/g,category:'private-credential',severity:'high'},
  {id:'cloudinary-url',provider:'Cloudinary',regex:/\bcloudinary:\/\/\d{6,20}:([A-Za-z0-9_-]{20,40})@[A-Za-z0-9_-]{1,100}\b/g,category:'private-credential',severity:'high',group:1,reason:'Cloudinary environment URL with API key, API secret and cloud name; the secret can upload, change and delete media. Validity is unverified.'},
  // Passwords in the userinfo of non-web service URLs (same shape as database-password; the user may be empty). http(s) userinfo stays a review signal.
  {id:'ftp-password',provider:'FTP / SFTP',regex:/\b(?:s?ftp|ftps):\/\/[^\s:'"<>/@]{0,100}:([^\s@'"<>/]{3,300})@[^\s'"<>]+/g,category:'private-credential',severity:'high',group:1},
  {id:'mail-server-password',provider:'Mail server',regex:/\b(?:smtps?|imaps?|pop3s?):\/\/[^\s:'"<>/@]{0,100}:([^\s@'"<>/]{3,300})@[^\s'"<>]+/g,category:'private-credential',severity:'high',group:1},
  {id:'message-broker-password',provider:'Message broker',regex:/\b(?:amqps?|mqtts?|nats|stomp):\/\/[^\s:'"<>/@]{0,100}:([^\s@'"<>/]{3,300})@[^\s'"<>]+/g,category:'private-credential',severity:'high',group:1},
  {id:'ldap-password',provider:'LDAP',regex:/\bldaps?:\/\/[^\s:'"<>/@]{0,100}:([^\s@'"<>/]{3,300})@[^\s'"<>]+/g,category:'private-credential',severity:'high',group:1},
  // Adapted from Gitleaks (github.com/gitleaks/gitleaks, config/gitleaks.toml; commit b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b, whose file is identical
  // to the vendored rules/gitleaks-v8.30.1.toml; MIT, rules/GITLEAKS-LICENSE) and Nosey Parker (crates/noseyparker/data/default/builtin/rules/;
  // commit 2e6e7f36ce36619852532bbe698d8cb7a26d2da7; Apache-2.0, rules/NOSEYPARKER-LICENSE and rules/NOSEYPARKER-NOTICE). The upstream rule IDs of
  // each line are listed in THIRD_PARTY_NOTICES.md. Changes: JavaScript syntax, unbounded repeats bounded, trailing delimiters as lookaheads, fixed
  // prefixes case-sensitive, Mapbox keyword context replaced by the fixed token header, Doppler and New Relic variants merged per provider.
  {id:'linear-api-key',provider:'Linear',regex:/\blin_api_[A-Za-z0-9]{40}(?![A-Za-z0-9_-])/g,category:'private-credential',severity:'high'},
  {id:'planetscale-token',provider:'PlanetScale',regex:/\bpscale_(?:tkn|pw|oauth)_[A-Za-z0-9_=.-]{32,64}(?![A-Za-z0-9_=.-])/g,category:'private-credential',severity:'high',reason:'PlanetScale service token, database password or OAuth token format; a password connects to a database branch. Validity and scope are unverified.'},
  {id:'doppler-token',provider:'Doppler',regex:/\bdp\.(?:(?:pt|ct|sa|scim|audit)\.|st\.(?:[a-z0-9_-]{2,35}\.)?)[A-Za-z0-9]{40,44}(?![A-Za-z0-9_-])/g,category:'private-credential',severity:'critical',reason:'Doppler personal, CLI, service, service-account, SCIM or audit token format; service and personal tokens can read the stored secrets of a project. Validity and scope are unverified.'},
  {id:'dynatrace-token',provider:'Dynatrace',regex:/\bdt0[a-z][0-9]{2}\.[A-Za-z0-9]{24}\.[A-Za-z0-9]{64}(?![A-Za-z0-9_-])/g,category:'private-credential',severity:'high'},
  {id:'grafana-service-account-token',provider:'Grafana',regex:/\bglsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}(?![A-Za-z0-9_-])/g,category:'private-credential',severity:'high'},
  {id:'grafana-cloud-token',provider:'Grafana',regex:/\bglc_eyJ[A-Za-z0-9+/]{32,400}={0,2}(?![A-Za-z0-9+/=_-])/g,category:'private-credential',severity:'high'},
  {id:'vault-token',provider:'HashiCorp Vault',regex:/\b(?:hvs\.[A-Za-z0-9_-]{90,130}|hvb\.[A-Za-z0-9_-]{138,300})(?![A-Za-z0-9_-])/g,category:'private-credential',severity:'critical',reason:'HashiCorp Vault service or batch token format; it can read the secrets its policies allow until it expires. Validity, policies and TTL are unverified.'},
  {id:'terraform-cloud-token',provider:'HCP Terraform',regex:/\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_=-]{60,70}(?![A-Za-z0-9_=-])/g,category:'private-credential',severity:'high'},
  {id:'postman-api-key',provider:'Postman',regex:/\bPMAK-[A-Za-z0-9]{24}-[A-Za-z0-9]{34}(?![A-Za-z0-9_-])/g,category:'private-credential',severity:'high'},
  {id:'sourcegraph-token',provider:'Sourcegraph',regex:/\bsgp_(?:[a-fA-F0-9]{16}_|local_)?[a-fA-F0-9]{40}(?![A-Za-z0-9_-])/g,category:'private-credential',severity:'high'},
  {id:'segment-token',provider:'Segment',regex:/\bsgp_[A-Za-z0-9]{64}(?![A-Za-z0-9_-])/g,category:'private-credential',severity:'high',reason:'Segment public API token format (not a write key); it can manage workspace sources, destinations and data. Validity and scope are unverified.'},
  {id:'flyio-token',provider:'Fly.io',regex:/\b(?:fo1_[A-Za-z0-9_-]{43}|fm1[ar]_[A-Za-z0-9+/]{100,4000}={0,3}|fm2_[A-Za-z0-9+/]{100,4000}={0,3})(?![A-Za-z0-9+/=_-])/g,category:'private-credential',severity:'high'},
  {id:'pulumi-token',provider:'Pulumi',regex:/\bpul-[a-f0-9]{40}(?![A-Za-z0-9_-])/g,category:'private-credential',severity:'high'},
  {id:'prefect-token',provider:'Prefect',regex:/\bpnu_[A-Za-z0-9]{36}(?![A-Za-z0-9_-])/g,category:'private-credential',severity:'high'},
  {id:'shippo-token',provider:'Shippo',regex:/\bshippo_(?:live|test)_[a-fA-F0-9]{40}(?![A-Za-z0-9_-])/g,category:'private-credential',severity:'high'},
  {id:'duffel-token',provider:'Duffel',regex:/\bduffel_(?:test|live)_[A-Za-z0-9_=-]{43}(?![A-Za-z0-9_=-])/g,category:'private-credential',severity:'high'},
  {id:'easypost-key',provider:'EasyPost',regex:/\bEZ[AT]K[A-Za-z0-9]{54}(?![A-Za-z0-9_-])/g,category:'private-credential',severity:'high'},
  {id:'atlassian-api-token',provider:'Atlassian',regex:/\bATATT3xFfGF0[A-Za-z0-9_-]{20,200}=[0-9A-F]{8}(?![A-Za-z0-9_-])/g,category:'private-credential',severity:'high',reason:'Atlassian Cloud API token format; with the account email it acts as that user in Jira and Confluence. Validity is unverified.'},
  {id:'artifactory-api-key',provider:'JFrog Artifactory',regex:/\bAKCp[A-Za-z0-9]{69}(?![A-Za-z0-9_-])/g,category:'private-credential',severity:'high'},
  {id:'1password-service-account-token',provider:'1Password',regex:/\bops_eyJ[A-Za-z0-9+/]{250,4000}={0,3}(?![A-Za-z0-9+/=_-])/g,category:'private-credential',severity:'critical',reason:'1Password service account token format; it can read the vaults granted to the service account. Validity and vault access are unverified.'},
  {id:'1password-secret-key',provider:'1Password',regex:/\bA3-[A-Z0-9]{6}-(?:[A-Z0-9]{11}|[A-Z0-9]{6}-[A-Z0-9]{5})-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}(?![A-Za-z0-9_-])/g,category:'private-credential',severity:'medium',reason:'1Password account Secret Key format; it is one of the two unlock factors, so the account password is still needed. Validity is unverified.'},
  {id:'notion-token',provider:'Notion',regex:/\bntn_[0-9]{11}[A-Za-z0-9]{35}(?![A-Za-z0-9_-])/g,category:'private-credential',severity:'high'},
  {id:'harness-token',provider:'Harness',regex:/\b(?:pat|sat)\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9]{24}\.[A-Za-z0-9]{20}(?![A-Za-z0-9_-])/g,category:'private-credential',severity:'high'},
  {id:'readme-api-key',provider:'ReadMe',regex:/\brdme_[a-z0-9]{70}(?![A-Za-z0-9_-])/g,category:'private-credential',severity:'high'},
  {id:'maxmind-license-key',provider:'MaxMind',regex:/\b[A-Za-z0-9]{6}_[A-Za-z0-9]{29}_mmk(?![A-Za-z0-9_-])/g,category:'private-credential',severity:'medium',reason:'MaxMind license key format; it downloads GeoIP databases and spends web-service queries on the account. Validity is unverified.'},
  {id:'openshift-user-token',provider:'OpenShift',regex:/\bsha256~[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])/g,category:'private-credential',severity:'high',reason:'OpenShift OAuth user token format; it acts as that user on the cluster API until it expires. Validity and expiry are unverified.'},
  {id:'newrelic-api-key',provider:'New Relic',regex:/\b(?:NRAK-[A-Za-z0-9]{27}|NRAA-[a-fA-F0-9]{27}|NRRA-[a-fA-F0-9]{42})(?![A-Za-z0-9_-])/g,category:'private-credential',severity:'high'},
  {id:'newrelic-ingest-key',provider:'New Relic',regex:/\b(?:NRII-[A-Za-z0-9_-]{32}|[A-Za-z0-9]{6}[a-fA-F0-9]{30}NRAL)(?![A-Za-z0-9_-])/g,category:'private-credential',severity:'medium',reason:'New Relic insert or license (ingest) key format; it sends data into the account but cannot query it. Validity is unverified.'},
  {id:'stackhawk-key',provider:'StackHawk',regex:/\bhawk\.[A-Za-z0-9_-]{20}\.[A-Za-z0-9_-]{20}(?![A-Za-z0-9_-])/g,category:'private-credential',severity:'high'},
  {id:'adafruit-io-key',provider:'Adafruit IO',regex:/\baio_[A-Za-z0-9]{28}(?![A-Za-z0-9_-])/g,category:'private-credential',severity:'high'},
  {id:'mapbox-secret-token',provider:'Mapbox',regex:/\b[st]k\.eyJ1Ijoi[A-Za-z0-9_-]{20,124}\.[A-Za-z0-9_-]{20,30}(?![A-Za-z0-9_-])/g,category:'private-credential',severity:'high',reason:'Mapbox secret (sk.) or temporary (tk.) access token format; unlike public pk. tokens it can carry write scopes such as uploads, styles and token management. Validity and scopes are unverified.'}
];
export function entropy(s: string): number {
  const counts = new Map<string, number>(); for (const c of s) counts.set(c,(counts.get(c)||0)+1);
  return [...counts.values()].reduce((h,n) => h-(n/s.length)*Math.log2(n/s.length),0);
}
/** Template references, documentation placeholders and masked filler (shared rules in placeholders.ts) never become findings. */
const placeholder=placeholderValue;
export function detectDirect(text: string, extra: Rule[] = []): Candidate[] {
  const found: Candidate[] = [];
  const add = (r: Rule, value: string, index: number, reason?: string) => {
    if (placeholder(value)) return;
    if((!r.group||r.id==='npm-auth')&&r.id!=='private-key'&&/^[A-Za-z0-9_.+/-]+$/.test(value)&&/[A-Za-z0-9_+/-]/.test(text[index+value.length]||'')&&!text.slice(index+value.length).startsWith('-->'))return; // HTML comment terminators delimit values; other token continuations cannot silently truncate.
    found.push({value,original:value,index,rule:r.id,provider:r.provider,category:r.category,severity:r.severity,
      confidence:r.confidence||'high', reasons:[reason||r.reason||'Matches a documented credential format; validity and privileges are unverified.'],transformations:[]});
    // Offline checksum: a match adds structural evidence only; a mismatch keeps the finding but lowers confidence and priority.
    const checksum=tokenChecksum(value),c=found.at(-1)!;
    if(checksum==='valid')c.reasons.push('Offline CRC32 checksum matches the issuer token format; this is structure only, not validity.');
    else if(checksum==='mismatch'){c.confidence='medium';c.qualifiers=['checksum-mismatch'];c.reasons.push('Offline CRC32 checksum does not match the issuer token format, typical of documentation examples and edited copies.');}
  };
  for (const r of [...rules,...extra]) {
    r.regex.lastIndex = 0;
    let m:any,count=0;
    while((m=r.regex.exec(text))&&count++<2000) {
      const value = m[r.group||0]; if (!value) continue;
      add(r,value,m.index!+(r.group?m[0].indexOf(value):0));
      if(['private-key','pgp-private-key'].includes(r.id)&&value.includes('\\n')&&found.at(-1)?.value===value){const c=found.at(-1)!;c.value=value.replace(/\\r\\n|\\n/g,'\n');c.transformations=['Escaped PEM newline decoding'];}
      // PEM structure from the decoded body only: verified, encrypted or truncated (documentation-like). An unverified body never demotes the finding.
      if(r.id==='private-key'&&found.at(-1)?.rule==='private-key'&&found.at(-1)!.index===m.index!+(r.group?m[0].indexOf(value):0)){const c=found.at(-1)!,p=pemStructure(c.value);c.keyStructure=p.structure;if(p.structure==='encrypted')c.qualifiers=['encrypted-material'];}
    }
  }
  // Quoted configuration values can contain punctuation that token-oriented
  // patterns miss. Parse only literal strings, never an executable expression.
  const quoted=/\b([A-Za-z_$][A-Za-z0-9_$.-]{0,120})["']?\s*[:=]\s*("(?:\\.|[^"\\]){8,512}"|'(?:\\.|[^'\\]){8,512}')/g;
  for(const m of text.matchAll(quoted)){
    const name=m[1];if(!/(?:secret|password|passwd|api[_-]?key|access[_-]?token|auth[_-]?token|signing[_-]?key)/i.test(name)||/session|csrf|nonce|public.?key|publishable|anon.?key/i.test(name))continue;
    try{
      const ast=parseExpressionAt(m[2],0,{ecmaVersion:'latest'}) as any;if(ast.type!=='Literal'||typeof ast.value!=='string')continue;const v=ast.value as string;
      if(placeholder(v)||found.some(c=>c.value===v)||/^[a-f0-9-]{36}$/i.test(v)||(entropy(v)<3.2&&!/password|passwd/i.test(name)))continue;
      const provider=/aws|secret.?access.?key/i.test(name)?'AWS':/azure/i.test(name)?'Azure':/twilio/i.test(name)?'Twilio':/oauth|client.?secret/i.test(name)?'OAuth':'Generic';
      const paired=false; // Credential relationships come from structural same-context parsing.
      const candidate:Candidate={value:v,original:m[2],index:m.index!+m[0].indexOf(m[2]),rule:'structured-config-secret',provider,category:paired?'private-credential':'suspicious',severity:paired?'high':'medium',confidence:paired?'high':'medium',reasons:[`Sensitive configuration name (${name}) with a literal value${paired?' and nearby AWS credential component':''}; validity, purpose and privileges unverified.`],transformations:v===m[2].slice(1,-1)?[]:['JavaScript string-escape decoding']};found.push(candidate);
    }catch{}
  }
  const assignment = /\b([A-Za-z_$][A-Za-z0-9_$.-]{0,120})["']?\s*[:=]\s*["']?([A-Za-z0-9_+\/.=@:-]{12,250})/g;
  for (const m of text.matchAll(assignment)) {
    const name=m[1],v=m[2];
    if(text[m.index!+m[0].length]&&/[^\s"',;)}\]&]/.test(text[m.index!+m[0].length]))continue;
    if(!/(?:secret|password|passwd|api[_-]?key|access[_-]?token|auth[_-]?token|signing[_-]?key)/i.test(name))continue;
    if (/session|csrf|nonce|public.?key|publishable|anon.?key/i.test(name) || placeholder(v) || entropy(v)<3.2 || /^(?:[a-f0-9-]{36})$/i.test(v)) continue;
    if (found.some(c=>c.value===v)) continue;
    const provider = /aws/i.test(name)?'AWS':/azure/i.test(name)?'Azure':/twilio/i.test(name)?'Twilio':/oauth|client.?secret/i.test(name)?'OAuth':'Generic';
    const paired = false;
    add({id:'contextual-secret',provider,regex:/x/g,category:paired?'private-credential':'suspicious',severity:paired?'high':'medium',confidence:paired?'high':'medium'},v,m.index!+m[0].lastIndexOf(v),
      `Sensitive variable name (${name}) and entropy ${entropy(v).toFixed(2)}${paired?'; nearby AWS access-key ID forms a credential pair':''}${/NEXT_PUBLIC|VITE_|REACT_APP|NUXT_PUBLIC/i.test(name)?'; frontend environment prefix makes this publicly bundled':''}. No online verification.`);
  }
  for (const m of text.matchAll(/\beyJ[A-Za-z0-9_-]{8,2000}\.[A-Za-z0-9_-]{8,4000}\.[A-Za-z0-9_-]{8,1000}\b/g)) {
    try {
      const payload=JSON.parse(Buffer.from(m[0].split('.')[1],'base64url').toString());
      if (payload.role==='service_role' || payload.role==='anon') add({id:'supabase-legacy-jwt',provider:'Supabase',regex:/x/g,category:payload.role==='anon'?'public-identifier':'private-credential',severity:payload.role==='anon'?'info':'critical'},m[0],m.index!,`JWT payload declares ${payload.role}; signature, issuer and permissions remain unverified.`);
      // Anonymous/user session JWTs are deliberately not treated as shared API credentials.
    } catch { /* Not a parseable JWT. */ }
  }
  return mergeContextual(found,[...contextualCredentials(text),...capabilities(text),...keyMaterial(text)]);
}
/** Strong contextual evidence supersedes generic/provider component classifications at that value. */
function mergeContextual(found:Candidate[],contextual:Candidate[]){
  for(const c of contextual){if(c.category==='private-credential'&&found.some(f=>f.value===c.value&&f.category==='public-identifier'&&['stripe-public','supabase-public','mailgun-public'].includes(f.rule)))continue;const prior=found.findIndex(f=>f.value===c.value&&f.provider===c.provider);if(prior>=0&&c.category==='private-credential')found[prior]={...c,index:found[prior].index,original:found[prior].original,transformations:[...new Set([...found[prior].transformations,...c.transformations])]};else found.push(c);}
  return found.filter((c,i,a)=>a.findIndex(x=>x.value===c.value&&x.index===c.index&&x.category===c.category)===i);
}
/** One whole-document parse of a large script or JSON text (module, then script grammar); null when it is neither. */
function parseDocument(text:string):any{try{return /^\s*\{/.test(text)?parseExpressionAt(text,text.indexOf('{'),{ecmaVersion:'latest'}):parse(text,{ecmaVersion:'latest',sourceType:'module',allowReturnOutsideFunction:true});}catch{try{return parse(text,{ecmaVersion:'latest',sourceType:'script',allowReturnOutsideFunction:true});}catch{return null;}}}
/** Heap (MiB) a large-text worker needs: the text and its windows, plus about 96 bytes per token when it also parses the whole document. Measured with margin on dense synthetic shapes:
 * a worker that runs out of heap can end the whole process, so a parse that does not fit is skipped, never risked. */
export function largeTextHeapMb(text:string,wholeDocument:boolean){
  let tokens=0;if(wholeDocument){let prev=0;for(let i=0;i<text.length;i++){const c=text.charCodeAt(i),k=c<=32?0:(c>=48&&c<=57)||(c>=65&&c<=90)||(c>=97&&c<=122)||c===95||c===36||c>127?1:2;if(k===2||(k===1&&prev!==1))tokens++;prev=k;}}
  return Math.max(64,Math.ceil(48+2*text.length/1048576+96*tokens/1e6));
}
interface Variant { text: string; index: number; original: string; steps: string[] }
const ENCODED_QUOTE=/&(?:quot|apos|#0*3[49]|#[xX]0*2[27]);/;
const NAMED_REFERENCES:Record<string,string>={quot:'"',apos:"'",amp:'&',lt:'<',gt:'>'};
/** Decodes the five XML named references and numeric references; anything else stays as written. */
export function decodeCharacterReferences(s:string):string{
  return s.replace(/&(?:#(\d{1,7})|#[xX]([0-9a-fA-F]{1,6})|(quot|apos|amp|lt|gt));/g,(e,d,h,n)=>{if(n)return NAMED_REFERENCES[n];const c=d?Number(d):parseInt(h,16);return c>0&&c<=0x10ffff&&(c<0xd800||c>0xdfff)?String.fromCodePoint(c):e;});
}
function transformations(text: string,onLimit?:()=>void): Variant[] {
  const out: Variant[] = []; const pending: Variant[]=[{text,index:0,original:text,steps:[]}];
  let expanded=0;const deadline=Date.now()+scaleMs(DECODED_ENUMERATION_MS);const available=()=>{if(Date.now()>deadline||out.length>=128){onLimit?.();return false;}return true;};
  const add=(parent:Variant, value:string, at:number, original:string, step:string)=>{
    if(value===original)return;if(value.length>16384||expanded+value.length>Math.min(text.length*2+8192,131072)||out.length>=128){onLimit?.();return;}
    const v={text:value,index:parent.steps.length?parent.index:at,original:parent.steps.length?parent.original:original,steps:[...parent.steps,step]};
    if (out.some(o=>o.text===v.text&&o.index===v.index)) return;
    expanded+=value.length;out.push(v); if(v.steps.length<3)pending.push(v);
  };
  // Allocate views to likely authentication/configuration expressions before unrelated strings.
  const raw=pending[0];let prioritized=0;
  for(const m of text.matchAll(/(?:\b(?:api[_-]?key|[\w$]*(?:secret|token|password|mnemonic|phrase|private[_-]?key)|seed|wif|xprv|Authorization)\b[^;{}\n]{0,120}[=:]\s*(?:atob\(\s*)?|\batob\(\s*)("(?:\\.|[^"\\]){8,4096}"|'(?:\\.|[^'\\]){8,4096}')/gi)){
    if(++prioritized>64||!available())break;const original=m[1],at=m.index!+m[0].indexOf(original);
    try{const n:any=parseExpressionAt(original,0,{ecmaVersion:'latest'}),s=n.value;if(typeof s!=='string')continue;
      if(s!==original.slice(1,-1))add(raw,s,at,original,'Prioritized configuration string decoding');
      if(/^[A-Za-z0-9+/_-]{24,4096}={0,2}$/.test(s)&&s.length%4!==1){const decoded=Buffer.from(s,/[-_]/.test(s)?'base64url':'base64').toString('utf8');if(/^[\x09\x0a\x0d\x20-\x7e]+$/.test(decoded))add(raw,decoded,at,original,'Prioritized configuration Base64 decoding');}
      if(s.includes('%'))try{add(raw,decodeURIComponent(s),at,original,'Prioritized configuration percent decoding');}catch{}
    }catch{}
  }
  // HTML attribute values holding an encoded quote (for example JSON in data-* attributes): decode the character references once so quoted
  // names and values reach the configuration passes. Plain &amp; links stay with the capability parser and use no decoded view.
  let attributes=0;
  if(ENCODED_QUOTE.test(text))for(const m of text.matchAll(/=\s*(?:"([^"<>]{8,16384})"|'([^'<>]{8,16384})')/g)){
    const value=m[1]??m[2];if(!ENCODED_QUOTE.test(value))continue;if(++attributes>32||!available())break;
    add(raw,decodeCharacterReferences(value),m.index!+m[0].indexOf(value),value,'HTML character-reference decoding');
  }
  // Hex strings that decode entirely to printable text (static data decoding, like Base64). Character-code calls such as String.fromCharCode are runtime territory: browser debugger capture sees them, static analysis never evaluates them.
  let coded=0;
  for(const m of text.matchAll(/\b(?:[0-9a-fA-F]{2}){16,2048}\b/g)){if(++coded>64||!available())break;const v=Buffer.from(m[0],'hex').toString('latin1');if(/^[\x20-\x7e]+$/.test(v)&&/[g-zG-Z]/.test(v))add(raw,v,m.index!,m[0],'Hex decoding');}
  while(pending.length&&available()) {
    const p=pending.shift()!;
    for(const m of p.text.matchAll(/(?:%[0-9a-fA-F]{2}|[A-Za-z0-9_.~+-]){12,4096}/g)) if(m[0].includes('%')) {
      if(!available())break;try{add(p,decodeURIComponent(m[0]),m.index!,m[0],'URL percent decoding');}catch{}
    }
    for(const m of p.text.matchAll(/\b[A-Za-z0-9+/]{24,4096}={0,2}/g)) {
      if(!available())break;
      if(m[0].length%4===1)continue;
      const v=Buffer.from(m[0],'base64').toString('utf8');
      if(/^[\x09\x0a\x0d\x20-\x7e]+$/.test(v))add(p,v,m.index!,m[0],'Base64 decoding');
    }
    for(const m of p.text.matchAll(/\b[A-Za-z0-9_-]{24,4096}\b/g)){if(!available())break;if(/[-_]/.test(m[0])&&m[0].length%4!==1){const v=Buffer.from(m[0],'base64url').toString('utf8');if(/^[\x09\x0a\x0d\x20-\x7e]+$/.test(v))add(p,v,m.index!,m[0],'Base64url decoding');}}
    const literal = /(?:"(?:\\.|[^"\\]){1,4096}"|'(?:\\.|[^'\\]){1,4096}')(?:\s*\+\s*(?:"(?:\\.|[^"\\]){1,4096}"|'(?:\\.|[^'\\]){1,4096}')){0,15}/g;
    for(const m of p.text.matchAll(literal)) {
      if(!available())break;
      if(!m[0].includes('\\')&&!/['"]\s*\+/.test(m[0]))continue;
      try{
        const ast=parseExpressionAt(m[0],0,{ecmaVersion:'latest'});
        const evaluate=(n:any, depth=0):string|undefined=>{
          if(depth>16)return;
          if(n.type==='Literal'&&typeof n.value==='string')return n.value;
          if(n.type==='BinaryExpression'&&n.operator==='+'){const a=evaluate(n.left,depth+1),b=evaluate(n.right,depth+1);if(a!==undefined&&b!==undefined)return a+b;}
        };
        const v=evaluate(ast);if(v!==undefined)add(p,v,m.index!,m[0],/['"]\s*\+/.test(m[0])?'Static string-literal concatenation (no evaluation)':'JavaScript string-escape decoding');
      }catch{}
    }
  }
  return out;
}
/** Added to `Detector.issues` when an engine call fails during a scan. It describes that call, not the detector's setup: a scan reports it through its own failure callback, and a scan that starts later on a shared detector does not inherit it (`setupIssues`). */
export const ENGINE_RUNTIME_ISSUE='Gitleaks execution or report parsing failed.';
export type AnalysisFailureContext={url?:string;attemptId?:number;cause?:GapCause};
/** What one analysis call is cancelled by and reports to: its scan's signal, analysis memory and callbacks. Every inspection method takes one, so scans that share one `Detector` (a mass run) each get only
 * their own cancellation, budget, limits and failures, however their calls interleave. A call that passes no scope uses the detector's own defaults (`signal`/`signalProvider`, `analysisMemory`, `onLimit`,
 * `onFailure`); a call that passes only a `FifoBudget` (the 2.7 form `inspect(text, memory)`) uses that budget with the detector's default signal and callbacks. */
export interface AnalysisScope{
  /** Budget the call's large-text analysis process holds its heap from; the detector's `analysisMemory` when omitted. */
  memory?:FifoBudget;
  /** The call's cancellation, read each time a step starts (for a scan: its current origin turn). An explicit scope never falls back to the detector's signal. */
  signal?:AbortSignal|(()=>AbortSignal|undefined);
  /** A stated inspection limit of this call (for a scan: a `decoded-inspection-limit` gap). */
  onLimit?:(detail:string)=>void;
  /** An offline-engine failure or interruption of this call; `context` names the request (from `measure`) and the typed cause. */
  onFailure?:(code:string,context?:AnalysisFailureContext)=>void;
  /** Mass mode: marks a wait for the process's shared analysis capacity (an engine or large-text lane, analysis memory) that is not available at once, and the time a share of it is held;
   * each returns its end. The scan excludes such waits from its clocks (OriginControl.sharedWait / sharedHold). */
  sharedWait?:()=>()=>void;
  sharedHold?:()=>()=>void;
  /** Mass mode (2.9.1): the target this call queues for, when it must take its turn for the shared engine and large-text lanes in the fair owner queue (`FairTurns`); a scan
   * returns its transport during request preflight screening. Without an owner a call queues first come, first served, as before. */
  turnOwner?:()=>object|undefined;
}
const noMark=()=>()=>{};
/** A resolved scope: read at use, never copied, so a later change to the caller's scope object (or the detector defaults) applies to the next step. `id` keys in-flight sharing and cached-limit replay. */
type Scope={readonly memory:FifoBudget;signal():AbortSignal|undefined;onLimit(detail:string):void;onFailure(code:string,context?:AnalysisFailureContext):void;wait():()=>void;hold():()=>void;turnOwner():object|undefined;readonly id:number};
type CacheEntry={candidates:Candidate[];limits:string[];told:Set<number>};
/** The offline engine's own keyword prefilter, decided without starting the engine. Gitleaks 8.30.1 (`Detect`) lowercases each fragment with Go's `strings.ToLower` and runs a rule only when
 * one of the rule's keywords occurs in it; a rule without keywords always runs. The scan runs it with `--max-decode-depth 0` (nothing is decoded) on stdin, whose fragments are parts of the
 * input, so an input that contains none of the keywords gets no rule run and cannot produce a finding: skipping the engine for it changes no result. Returns that test for the pinned rule file,
 * or undefined (the engine always runs) when the file has anything this reading cannot follow exactly: a rule with a pattern and no keywords, a keyword that is empty, escaped or not ASCII, a
 * multi-line string, or a table other than the rules, their allowlists and the global allowlist (an `[extend]` would add rules this file does not list).
 * `discarded` names the rules whose findings the caller always drops (DISCARDED_ENGINE_RULE): their keywords are left out, since an input with none of the other rules' keywords can only
 * get only those rules run (every other rule's prefilter fails), so its findings, if any, are all dropped and skipping the engine changes no result either. */
export function engineKeywordGate(toml:string,discarded:(id:string)=>boolean=()=>false):((text:string)=>boolean)|undefined{
  type RuleShape={id?:string;keywords?:string[];regex:boolean;path:boolean};let rules:RuleShape[]=[];let rule:RuleShape|undefined;const lines=toml.split(/\r?\n/);
  for(let i=0;i<lines.length;i++){
    const line=lines[i].trim();if(!line||line.startsWith('#'))continue;
    if((line.split("'''").length-1)%2||line.includes('"""'))return undefined;
    if(line.startsWith('[')){if(line==='[[rules]]'){rule={regex:false,path:false};rules.push(rule);}else if(line==='[[rules.allowlists]]'||line==='[rules.allowlist]'){/* a rule's allowlist only removes findings */}else if(line==='[allowlist]')rule=undefined;else return undefined;continue;}
    const key=/^([A-Za-z]+)\s*=/.exec(line)?.[1];if(!rule||!key)continue;
    // Keys of the rule itself come before its first allowlist table; an allowlist has no `regex`, `path` or `keywords` keys of its own (it uses `regexes`, `paths`, `stopwords`).
    if(key==='regex')rule.regex=true;else if(key==='path')rule.path=true;
    else if(key==='id'){const id=/^id\s*=\s*"([\x20-\x7e]+)"\s*(#.*)?$/.exec(line)?.[1];if(rule.id!==undefined||!id||/["\\]/.test(id))return undefined;rule.id=id;}
    else if(key==='keywords'){if(rule.keywords)return undefined;let array=line.slice(line.indexOf('=')+1);while(!array.includes(']')&&i+1<lines.length)array+=lines[++i];
      const body=/^\s*\[([^\]]*)\]\s*(#.*)?$/.exec(array)?.[1];if(body===undefined)return undefined;const items=body.split(',').map(x=>x.trim()).filter(Boolean);
      if(!items.length||items.some(x=>!/^"[\x20-\x7e]+"$/.test(x)||x.slice(1,-1).includes('"')||x.includes('\\')))return undefined;rule.keywords=items.map(x=>x.slice(1,-1).toLowerCase());}
  }
  // Every rule must name itself, so that a discarded rule is known by the same id the engine reports.
  if(!rules.length||rules.some(r=>r.id===undefined))return undefined;rules=rules.filter(r=>!discarded(r.id!));
  // A rule without keywords runs on every fragment: only a path-only rule (no pattern) may have none, and on stdin it has no file path to match.
  if(!rules.length||rules.some(r=>r.regex&&!r.keywords?.length||!r.regex&&!r.path))return undefined;
  const keywords=[...new Set(rules.flatMap(r=>r.keywords??[]))].sort((a,b)=>b.length-a.length||(a<b?-1:1)),pattern=new RegExp(keywords.map(k=>k.replace(/[.*+?^${}()|[\]\\/-]/g,'\\$&')).join('|'));
  // Go lowercases U+0130 to 'i' and U+212A (Kelvin) to 'k', the only characters outside ASCII it lowercases into ASCII; JavaScript gives U+0130 two characters, so it becomes 'i' first.
  return text=>pattern.test(text.replace(/İ/g,'i').toLowerCase());
}
export class Detector {
  engineMs=0;cacheHits=0;private metrics=new AsyncLocalStorage<{engineMs:number;cacheHits:number;engineCalls:number;engineScreened?:number;failures:Set<string>;url?:string;attemptId?:number}>();
  measure<T>(metrics:{engineMs:number;cacheHits:number;engineCalls:number;engineScreened?:number;failures:Set<string>;url?:string;attemptId?:number},task:()=>Promise<T>){return this.metrics.run(metrics,task);}
  /** Engine inputs that contained none of the pinned rules' keywords, so the engine (which would run no rule on them) was not started (`engineKeywordGate`). Set by `init`; a detector that was
   * not initialized starts the engine for every input. */
  engineScreened=0;private keywordGate?:(text:string)=>boolean;
  /** Default callbacks for calls that pass no scope (a detector of its own, tests, the analysis process). A scan passes its own `AnalysisScope` with every call instead. */
  onLimit?:(detail:string)=>void;onFailure?:(code:string,context?:AnalysisFailureContext)=>void;
  private interrupted(phase:string,signal:AbortSignal|undefined){return new AnalysisInterrupted(abortReason(signal),phase);}
  private noteLimit(detail:string,scope:Scope){this.inspectionLimits.add(detail);scope.onLimit(detail);}
  /** Every limit and failure this detector has seen, across all scopes (diagnostics). Each scan states only its own, through its scope. */
  inspectionLimits=new Set<string>();
  inspectionFailures=new Set<string>();
  syntheticFixture=false;
  /** Default cancellation for calls that pass no scope. */
  private explicitSignal?:AbortSignal;signalProvider?:()=>AbortSignal|undefined;
  get signal(){return this.signalProvider?.()||this.explicitSignal;}set signal(value:AbortSignal|undefined){this.explicitSignal=value;}
  private readonly ownScope:Scope=(d=>({get memory(){return d.analysisMemory;},signal:()=>d.signal,onLimit:x=>d.onLimit?.(x),onFailure:(c,x)=>d.onFailure?.(c,x),wait:noMark,hold:noMark,turnOwner:()=>undefined,id:0}))(this);
  private scopes=new WeakMap<object,Scope>();private scopeSequence=0;
  private scope(arg?:FifoBudget|AnalysisScope):Scope{
    if(!arg)return this.ownScope;let s=this.scopes.get(arg);if(s)return s;const d=this,id=++this.scopeSequence;
    if(arg instanceof FifoBudget)s={memory:arg,signal:()=>d.signal,onLimit:x=>d.onLimit?.(x),onFailure:(c,x)=>d.onFailure?.(c,x),wait:noMark,hold:noMark,turnOwner:()=>undefined,id};
    else{const a=arg;s={get memory(){return a.memory??d.analysisMemory;},signal:()=>typeof a.signal==='function'?a.signal():a.signal,onLimit:x=>a.onLimit?.(x),onFailure:(c,x)=>a.onFailure?.(c,x),wait:()=>a.sharedWait?.()??(()=>{}),hold:()=>a.sharedHold?.()??(()=>{}),turnOwner:()=>a.turnOwner?.(),id};}
    this.scopes.set(arg,s);return s;
  }
  /** The cancellation a call with this scope observes now (for a subclass that overrides an inspection method): the scope's own signal, or the detector default when no scope or only a budget is given. */
  signalOf(scope?:FifoBudget|AnalysisScope){return this.scope(scope).signal();}
  /** Engine and large-text lanes (2 each) are first come, first served: back-to-back analysis calls cannot overtake a request preflight that is already waiting. */
  private engineLanes=new FifoBudget(2);private directLanes=new FifoBudget(2);
  /** Fair turns for the lanes (2.9.1): a call whose scope names a turn owner (a mass run's request preflight) first takes its owner's turn, one place per target in a first-in, first-out
   * queue, so one target's many screenings cannot jump ahead of, or starve, the targets waiting with it. Turns are as many as lanes; a call holds its turn until it releases its lane. */
  private engineTurns=new FairTurns(2);private directTurns=new FairTurns(2);
  /** Default analysis memory (MiB) for calls that name none: each large-text analysis process holds its heap limit from the call's budget until the process has ended. A scan passes its own budget with every call
   * (`inspect(text, memory)`), so scans that share one detector never use each other's budget. */
  analysisMemory=new FifoBudget(256);
  /** Large-text heap estimate (MiB); replaceable for tests and measurements. */
  heapEstimate=largeTextHeapMb;wholeDocument=true;private signalIds=new WeakMap<AbortSignal,number>();private signalSequence=0;
  version='unavailable'; ruleDigest=''; companyVersion='none'; issues:string[]=[];
  /** `issues` from setup (`init`) only: what a scan starting now states as detector unavailability. */
  get setupIssues(){return this.issues.filter(issue=>issue!==ENGINE_RUNTIME_ISSUE);}
  private executable:string; private extra:Rule[]=[];private localRules:unknown=[];
  private cache=new Map<string,CacheEntry>();private cacheBytes=0;
  constructor(executable=offlineBinary(),localRules:unknown=[]) {this.executable=executable;this.localRules=localRules;this.extra=compileRules(localRules);}
  async init(companyFile?:string) {
    const ruleBytes=await readFile(path.join(root,'rules/gitleaks-v8.30.1.toml'));
    this.ruleDigest=createHash('sha256').update(ruleBytes).digest('hex');this.keywordGate=engineKeywordGate(ruleBytes.toString('utf8'),id=>DISCARDED_ENGINE_RULE.test(id));
    if(companyFile){
      const raw=await readFile(companyFile,'utf8'),j=JSON.parse(raw);if(!Array.isArray(j.rules)||j.rules.length>30)throw new Error('Invalid company rules');
      this.companyVersion=createHash('sha256').update(raw).digest('hex');
      this.localRules=j.rules;this.extra=compileRules(j.rules);
    }
    try{
      if(!existsSync(this.executable))throw new Error('missing');
      const v=await this.run(['version'],'',this.ownScope);
      if(!v.trim().includes(ENGINE_VERSION))throw new Error('wrong version');
      this.version=ENGINE_VERSION;
    }catch{this.issues.push('Pinned Gitleaks unavailable or wrong version; website-only detection is incomplete.');}
    if(!bip39Words()&&keyMaterialIssue&&!this.issues.includes(keyMaterialIssue))this.issues.push(keyMaterialIssue);
  }
  /** Format rules on one text (windows above 128 KiB, plus the whole-document parse where it applies) in the calling thread; `scope` receives its limits. */
  direct(text:string,scope?:FifoBudget|AnalysisScope){return this.directIn(text,this.scope(scope));}
  private directIn(text:string,s:Scope){const out=this.windowed(text,s);return this.wholeDocumentApplies(text,s)?this.withContext(text,out,s):out;}
  private windowed(text:string,s:Scope){
    if(text.length<=131072)return detectDirect(text,this.extra);
    this.noteLimit('Large text uses 65536-character windows with 16384-character overlap for format inspection; whole-document context analysis covers scripts up to 2 MiB (subtrees naming credentials, providers or signing sinks) and otherwise requires the semantic parser and a complete document.',s);
    const out:Candidate[]=[];for(let start=0;start<text.length;start+=65536){if(s.signal()?.aborted)break;const from=Math.max(0,start-16384),to=Math.min(text.length,start+65536+16384);for(const c of detectDirect(text.slice(from,to),this.extra)){const index=from+c.index;if(index>=start&&index<start+65536)out.push({...c,index});}}
    return out;
  }
  private wholeDocumentApplies(text:string,s:Scope){return text.length>131072&&text.length<=2097152&&this.wholeDocument&&!s.signal()?.aborted;}
  // Window slices lose the enclosing object, scope and call: one bounded parse restores provider context for large bundles (time and heap stay within the analysis process limits).
  private withContext(text:string,out:Candidate[],s:Scope){
    const ast=parseDocument(text);if(!ast)return out;
    try{return mergeContextual(out,contextualCredentials(text,{ast,focus:CONTEXT_FOCUS,nodeLimit:400000}));}catch{this.noteLimit('Whole-document context analysis of a large script stopped early; window results are kept.',s);return out;}
  }
  clear(){this.cache.clear();this.cacheBytes=0;}
  /** Full inspection in the calling thread (the large-text analysis process and small texts). Scan paths use `inspect`, `inspectBounded` or `inspectWindowed`, so a text over 128 KiB never gets an unbounded whole-document parse on the main thread. */
  inspectSync(text:string,scope?:FifoBudget|AnalysisScope):Candidate[]{return this.syncIn(text,this.scope(scope));}
  private syncIn(text:string,s:Scope):Candidate[]{return [...this.directIn(text,s),...this.embedded(text,s)];}
  private embedded(text:string,s:Scope){
    const out:Candidate[]=[];let scripts=0,bytes=0;for(const m of text.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script\s*>/gi)){if(++scripts>100||bytes+m[1].length>131072)break;bytes+=m[1].length;const start=m.index!+m[0].indexOf('>')+1;for(const c of this.directIn(m[1],s))out.push({...c,index:start+c.index,transformations:[...c.transformations,'HTML script extraction without execution']});}
    for(const v of transformations(text,()=>this.noteLimit(enumerationLimit(),s)))for(const c of this.directIn(v.text,s))out.push({...c,index:v.index,original:v.original,transformations:v.steps});
    return out;
  }
  /** `inspectSync` in stages for the analysis process (a detector of its own, default scope): `windows` receives the window, embedded-script and decoded-view results before the whole-document parse runs, so a
   * parse that runs out of memory loses nothing else. The final candidates and limits are in `inspectSync` order. */
  inspectInStages(text:string,windows:(candidates:Candidate[],limits:string[])=>void):{candidates:Candidate[];limits:string[]}{
    const s=this.ownScope,top=this.windowed(text,s),afterTop=[...this.inspectionLimits],rest=this.embedded(text,s),afterRest=[...this.inspectionLimits];
    if(!this.wholeDocumentApplies(text,s))return {candidates:[...top,...rest],limits:afterRest};
    windows([...top,...rest],afterRest);
    const merged=this.withContext(text,top,s),context=[...this.inspectionLimits].filter(l=>!afterRest.includes(l));
    return {candidates:[...merged,...rest],limits:[...afterTop,...context,...afterRest.filter(l=>!afterTop.includes(l))]};
  }
  /** Main-thread inspection for scan paths that stay synchronous (URLs, redaction, browser snapshots and channels, small local checks). A text over 128 KiB gets window inspection only: its whole-document parse
   * runs only in a budgeted analysis process. `covered`: the same text also goes through that budgeted path (`inspect`), so nothing is lost and no limit is stated. `scope` receives the limits. */
  inspectWindowed(text:string,covered=false,scope?:FifoBudget|AnalysisScope):Candidate[]{
    const s=this.scope(scope);if(text.length<=131072)return this.syncIn(text,s);
    const top=this.windowed(text,s);if(!covered&&this.wholeDocumentApplies(text,s))this.noteLimit('Whole-document context analysis of a large text inspected on the main thread (a URL or a redaction check) was skipped; window results are kept.',s);
    return [...top,...this.embedded(text,s)];
  }
  /** Local inspection without the engine, budgeted like `inspect`: a text over 128 KiB is inspected in an analysis process whose heap is held from the scope's memory (the scan's analysis memory). */
  inspectBounded(text:string,scope?:FifoBudget|AnalysisScope):Promise<Candidate[]>{return this.localInspection(text,this.scope(scope));}
  private async fileRun(args:string[],text:string,s:Scope):Promise<string>{
    const signal=s.signal();
    // Sandbox fallback only: stdin/stdout are ephemeral, ACL-restricted files.
    // Nothing is logged; files are removed in finally. Crash leftovers stay in the
    // private tmp folder (privateParent: <data>/tmp, .cache/private for fixtures).
    const dir=await privateDirectory('engine-',this.syntheticFixture);
    try{
      const input=path.join(dir,'stdin'),output=path.join(dir,'stdout');
      const f=await open(input,'wx',0o600);await f.writeFile(text);await f.close();
      const fi=await open(input,'r'),fo=await open(output,'wx',0o600);
      try{
        await new Promise<void>((resolve,reject)=>{
          const env={...process.env};delete env.GITLEAKS_CONFIG;delete env.GITLEAKS_CONFIG_TOML;
          const p=spawn(this.executable,args,{stdio:[fi.fd,fo.fd,'ignore'],windowsHide:true,env});
          const cancel=()=>{p.kill();reject(this.interrupted('engine',signal));};signal?.addEventListener('abort',cancel,{once:true});if(signal?.aborted)cancel();
          const timer=setTimeout(()=>{p.kill();reject(new AnalysisFailure('engine-timeout','engine'));},scaleMs(ENGINE_MS));
          p.on('error',()=>{clearTimeout(timer);signal?.removeEventListener('abort',cancel);reject(new AnalysisFailure('engine-launch-failure','engine'));});
          p.on('close',c=>{clearTimeout(timer);signal?.removeEventListener('abort',cancel);c===0||c===1?resolve():reject(new AnalysisFailure('engine-failure','engine'));});
        });
      }finally{await fi.close();await fo.close();}
      const b=await readFile(output);if(b.length>8*1024*1024)throw new AnalysisFailure('engine-output-limit','engine');return b.toString();
    }finally{await rm(dir,{recursive:true,force:true});}
  }
  private async run(args:string[],text:string,s:Scope=this.ownScope):Promise<string>{
    // A lane that is not free at once is a wait for shared capacity; holding one is the call's own work.
    // A call with a turn owner waits for its owner's fair turn first (a wait for shared capacity too, of the same cause); it holds the turn until it releases the lane.
    const signal=s.signal(),owner=s.turnOwner();let waiting=owner&&!this.engineTurns.free(owner)||!this.engineLanes.available()?s.wait():undefined,turn:(()=>void)|undefined;
    try{
      if(owner){turn=await this.engineTurns.take(owner,signal,()=>this.interrupted('engine-queue',signal));if(!waiting&&!this.engineLanes.available())waiting=s.wait();}
      await this.engineLanes.acquire(1,signal,()=>this.interrupted('engine-queue',signal));
    }catch(e){turn?.();waiting?.();throw e;}
    const held=s.hold();waiting?.();
    if(signal?.aborted){held();this.engineLanes.release();turn?.();throw this.interrupted('engine-queue',signal);}const began=Date.now(),metrics=this.metrics.getStore();if(metrics)metrics.engineCalls++;
    try{
      if(process.env.SCANNER_FILE_ENGINE==='1')return await this.fileRun(args,text,s);
      try{return await this.pipeRun(args,text,s);}catch(e){if((e as any).code==='EPERM')return await this.fileRun(args,text,s);throw e;}
    }finally{const elapsed=Date.now()-began;this.engineMs+=elapsed;if(metrics)metrics.engineMs+=elapsed;this.engineLanes.release();turn?.();held();}
  }
  private pipeRun(args:string[],text:string,s:Scope):Promise<string>{
    const signal=s.signal();
    return new Promise((resolve,reject)=>{
      const env={...process.env};delete env.GITLEAKS_CONFIG;delete env.GITLEAKS_CONFIG_TOML;
      const p=spawn(this.executable,args,{stdio:['pipe','pipe','pipe'],windowsHide:true,env});
      const cancel=()=>{p.kill();reject(this.interrupted('engine',signal));};signal?.addEventListener('abort',cancel,{once:true});if(signal?.aborted)cancel();
      let out='',size=0;const timer=setTimeout(()=>{p.kill();reject(new AnalysisFailure('engine-timeout','engine'));},scaleMs(ENGINE_MS));
      p.stdout.on('data',b=>{size+=b.length;if(size>8*1024*1024){p.kill();reject(new AnalysisFailure('engine-output-limit','engine'));}else out+=b.toString();});
      p.stderr.on('data',()=>{});p.stdin.on('error',()=>{});p.on('error',e=>{clearTimeout(timer);signal?.removeEventListener('abort',cancel);reject(e);});
      p.on('close',code=>{clearTimeout(timer);signal?.removeEventListener('abort',cancel);code===0||code===1?resolve(out):reject(new AnalysisFailure('engine-failure','engine'));});p.stdin.end(text);
    });
  }
  private inFlight=new Map<string,{task:Promise<Candidate[]>;failures:Set<string>}>();
  /** Full inspection (format rules, decoded views, the offline engine), budgeted: a text over 128 KiB runs in an analysis process that holds its heap from the scope's memory.
   * `scope` is the caller's scan: its signal cancels the call, and its callbacks receive this call's limits and failures. A result cached from another scope is returned with that inspection's limits
   * stated to this scope too (once), so every scan states its own limits; calls in flight are shared only within one scope and signal, so a failure always reaches the scan whose call failed. */
  async inspect(text:string,scope?:FifoBudget|AnalysisScope):Promise<Candidate[]>{
    const s=this.scope(scope),signal=s.signal();if(signal?.aborted)throw this.interrupted('queue',signal);
    const cacheKey=createHash('sha256').update(this.version+this.companyVersion).update(text).digest('hex');
    const cached=this.cache.get(cacheKey);if(cached){this.cacheHits++;const m=this.metrics.getStore();if(m)m.cacheHits++;if(!cached.told.has(s.id)){cached.told.add(s.id);for(const limit of cached.limits)this.noteLimit(limit,s);}return cached.candidates;}
    if(signal&&!this.signalIds.has(signal))this.signalIds.set(signal,++this.signalSequence);const flightKey=cacheKey+':'+s.id+':'+(signal?this.signalIds.get(signal):0);
    const pending=this.inFlight.get(flightKey);if(pending){this.cacheHits++;const m=this.metrics.getStore();if(m)m.cacheHits++;const result=await pending.task;for(const failure of pending.failures)m?.failures.add(failure);return result;}const failures=new Set<string>(),task=this.inspectFresh(text,cacheKey,failures,s);this.inFlight.set(flightKey,{task,failures});try{return await task;}finally{this.inFlight.delete(flightKey);}
  }
  private async localInspection(text:string,s:Scope):Promise<Candidate[]>{
    // The wall-clock budgets below and in the engine follow this computer's measured speed. A scan measures it before it starts; a detector used before any scan in this
    // process (or outside one) waits here for that one bounded measurement, so an unmeasured slow computer never gets the reference budgets by default.
    if(currentTimeFactor().source==='default')await analysisTimeFactor();
    if(text.length<=131072)return this.syncIn(text,s);
    const memory=s.memory,signal=s.signal();if(signal?.aborted)throw this.interrupted('direct-queue',signal);
    // Preserve the detector algorithm, but isolate large synchronous scans so a
    // different origin's deadline/cancel callback remains runnable.
    // Waiting for a large-text lane or for analysis memory that is not free at once is a wait for shared capacity; it ends when both are held.
    // A call with a turn owner (request preflight in a mass run) takes its owner's fair turn first and holds it until it releases the lane.
    const owner=s.turnOwner();let waiting=owner&&!this.directTurns.free(owner)||!this.directLanes.available()?s.wait():undefined,held:(()=>void)|undefined,turn:(()=>void)|undefined;
    try{
    if(owner){turn=await this.directTurns.take(owner,signal,()=>this.interrupted('direct-queue',signal));if(!waiting&&!this.directLanes.available())waiting=s.wait();}
    await this.directLanes.acquire(1,signal,()=>this.interrupted('direct-queue',signal));if(signal?.aborted){this.directLanes.release();throw this.interrupted('direct-queue',signal);}
    let heldMb=0,wholeDocument=text.length<=2097152,heapMb=this.heapEstimate(text,wholeDocument);
    if(wholeDocument&&heapMb>memory.capacity){this.noteLimit(`Whole-document context analysis of a large script was skipped: its estimated heap exceeds the analysis memory setting (${memory.capacity} MiB). Window results are kept.`,s);wholeDocument=false;heapMb=this.heapEstimate(text,false);}
    heapMb=Math.min(heapMb,memory.capacity);
    try{if(!waiting&&!memory.available(heapMb))waiting=s.wait();await memory.acquire(heapMb,signal,()=>this.interrupted('direct-queue',signal));heldMb=heapMb;held=s.hold();waiting?.();if(signal?.aborted)throw this.interrupted('direct-queue',signal);
      // The heap stays held from the call's analysis memory until the process has ended, whatever ends it.
      const child=new AnalysisChild('detector',heapMb,DETECTOR_ENTRY);heldMb=0;void child.ended.then(()=>memory.release(heapMb));
      return await new Promise<Candidate[]>((resolve,reject)=>{let done=false,windows:{candidates:Candidate[];limits:string[]}|undefined;
      const finish=(error?:Error,value?:{candidates:Candidate[];limits:string[]})=>{if(done)return;done=true;clearTimeout(timer);signal?.removeEventListener('abort',cancel);child.off('message',onMessage);child.off('end',onEnd);const cleanup=setTimeout(()=>error?reject(error):reject(new AnalysisFailure('worker-cleanup-timeout','direct')),scaleMs(WORKER_CLEANUP_MS));void child.stop().then(()=>{clearTimeout(cleanup);if(error)reject(error);else{for(const limit of value!.limits)this.noteLimit(limit,s);resolve(value!.candidates);}});};
      const cancel=()=>finish(this.interrupted('direct',signal)),timer=setTimeout(()=>finish(new AnalysisFailure('direct-worker-timeout','direct')),scaleMs(DIRECT_WORKER_MS));
      const onMessage=(m:any)=>{if(m?.type==='ready'){if(!child.send({type:'job',id:1,text,rules:this.localRules,wholeDocument,timeFactor:currentTimeFactor().factor}))finish(new AnalysisFailure('worker-failure','direct'));}else if(m?.type==='windows')windows={candidates:m.candidates,limits:m.limits};else if(m?.type==='result')finish(undefined,m);};
      // Out of memory in the whole-document parse: the window results have already arrived and are kept with a stated limit. Any other ending without a result is a failure; running out of memory before the window results is stated too.
      const onEnd=(exit:AnalysisExit)=>{if(exit.outOfMemory&&windows)return finish(undefined,{candidates:windows.candidates,limits:[...windows.limits,`Whole-document context analysis of a large script reached its ${heapMb} MiB heap limit; its analysis process ended without affecting the scan. Window results are kept.`]});
        if(exit.outOfMemory)this.noteLimit(`Large-text inspection reached its ${heapMb} MiB heap limit before its window results were complete; its analysis process ended without affecting the scan and this text stays uninspected.`,s);finish(new AnalysisFailure('worker-failure','direct'));};
      child.on('message',onMessage);child.once('end',onEnd);signal?.addEventListener('abort',cancel,{once:true});if(signal?.aborted)cancel();
    });}finally{if(heldMb)memory.release(heldMb);this.directLanes.release();}
    }finally{turn?.();waiting?.();held?.();}
  }
  private async inspectFresh(text:string,cacheKey:string,sharedFailures:Set<string>,scope:Scope):Promise<Candidate[]>{
    // The limits of this inspection are recorded with its cached result, for other scopes that later reuse it.
    const limits:string[]=[],s:Scope={get memory(){return scope.memory;},signal:()=>scope.signal(),onLimit:detail=>{if(!limits.includes(detail))limits.push(detail);scope.onLimit(detail);},onFailure:(code,context)=>scope.onFailure(code,context),wait:()=>scope.wait(),hold:()=>scope.hold(),turnOwner:()=>scope.turnOwner(),id:scope.id};
    await new Promise<void>(resolve=>setImmediate(resolve));{const signal=s.signal();if(signal?.aborted)throw this.interrupted('pre-check',signal);}
    let engineSucceeded=true;const out=await this.localInspection(text,s);
    if(this.version==='unavailable')return out;
    try{
      const views=transformations(text,()=>this.noteLimit(enumerationLimit(),s)),raw:Variant={text,index:0,original:text,steps:[]};
      const engine=async(input:string,segments:Variant[])=>{
       // The engine's own keyword prefilter decides here: an input with none of the rules' keywords gets no rule run, so the engine is not started for it (engineKeywordGate).
       if(this.keywordGate&&!this.keywordGate(input)){this.engineScreened++;const m=this.metrics.getStore();if(m)m.engineScreened=(m.engineScreened??0)+1;return;}
       const report=JSON.parse(await this.run(['stdin','--no-banner','--no-color','--log-level','error','--ignore-gitleaks-allow','--config',path.join(root,'rules/gitleaks-v8.30.1.toml'),'--report-format','json','--report-path','-','--max-decode-depth','0','--max-archive-depth','0','--timeout',String(Math.ceil(ENGINE_TIMEOUT_S*currentTimeFactor().factor))],input,s));
       for(const f of report||[]){if(typeof f.Secret!=='string'||!f.Secret||placeholder(f.Secret)||out.some(c=>c.value===f.Secret&&(c.category==='public-identifier'||['google-api','aws-id','twilio-api','supabase-legacy-jwt'].includes(c.rule))))continue;
        if(DISCARDED_ENGINE_RULE.test(f.RuleID))continue;
        const classified=this.directIn(f.Secret,s)[0];for(const segment of segments){let at=segment.text.indexOf(f.Secret),count=0;while(at>=0&&count++<2000){const next=segment.text[at+f.Secret.length]||'';if(/^[A-Za-z0-9_-]+$/.test(f.Secret)&&/[A-Za-z0-9_-]/.test(next)&&!segment.text.slice(at+f.Secret.length).startsWith('-->')){at=segment.text.indexOf(f.Secret,at+f.Secret.length);continue;}const index=segment.steps.length?segment.index:at,original=segment.steps.length?segment.original:f.Secret;
          if(!out.some(c=>c.value===f.Secret&&c.index===index&&c.original===original)){const candidate:Candidate=classified?{...classified,index,original,transformations:[...segment.steps,...classified.transformations]}:{value:f.Secret,original,index,rule:`gitleaks:${f.RuleID}`,provider:canonicalProvider(f.RuleID.split('-')[0],'gitleaks:'+f.RuleID),category:'private-credential',severity:'high',confidence:'high',reasons:['Pinned offline Gitleaks rule matched a raw or bounded decoded view; credential validity and privileges unverified.'],transformations:segment.steps};out.push(candidate);}
          at=segment.text.indexOf(f.Secret,at+f.Secret.length);
        }}
       }};
      await engine(text,[raw]);if(views.length)await engine(views.map(v=>v.text).join('\n#'+ '_VIEW_BOUNDARY_'.repeat(32)+'\n'),views);
    }catch(e){engineSucceeded=false;const store=this.metrics.getStore();
      // `engine-cancelled` is assigned only to a typed interruption; a timeout or failure keeps its own code, and the gap carries URL, attempt and cause.
      const failure=e instanceof AnalysisInterrupted?'engine-cancelled':e instanceof AnalysisFailure&&e.code==='engine-timeout'?'engine-rule-timeout':'engine-inspection-failure';sharedFailures.add(failure);s.onFailure(failure,{url:store?.url,attemptId:store?.attemptId,cause:e instanceof AnalysisInterrupted?{kind:e.reason?.kind||'user-cancelled',origin:e.reason?.origin,phase:e.phase,analyzer:'text'}:{kind:e instanceof AnalysisFailure?e.code:'engine-exception',phase:'engine',analyzer:'text'}});store?.failures.add(failure);if(failure!=='engine-cancelled'){this.inspectionFailures.add(failure);if(!this.issues.includes(ENGINE_RUNTIME_ISSUE))this.issues.push(ENGINE_RUNTIME_ISSUE);}}

    {const signal=s.signal();if(signal?.aborted)throw this.interrupted('post-engine',signal);}
    const bytes=out.reduce((n,c)=>n+c.value.length+c.original.length,0)+limits.reduce((n,l)=>n+l.length,0);
    if(this.cache.size>=256||this.cacheBytes+bytes>4*1024*1024){this.cache.clear();this.cacheBytes=0;}
    if(engineSucceeded){this.cache.set(cacheKey,{candidates:out,limits,told:new Set([s.id])});this.cacheBytes+=bytes;}return out;
  }
}
