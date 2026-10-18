export type Category = 'private-credential' | 'public-identifier' | 'suspicious' | 'information';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Confidence = 'high' | 'medium' | 'low';
export interface Candidate {
  value: string; original: string; index: number; rule: string; provider: string;
  category: Category; severity: Severity; confidence: Confidence; reasons: string[];
  transformations: string[];
  environment?:Finding['environment']; credentialSet?:Finding['credentialSet'];
  /** AWS only: the public access-key ID (and session token for temporary keys) that pair with this secret access key. Carried so the live check can SigV4-sign without the secret ever leaving this computer; never shown on the finding or in any report. */
  companions?:{accessKeyId?:string;sessionToken?:string};
  constituents?:import('./semantic.js').Constituent[]; sink?:string;
  exposureKind?:'password-hash'|'sensitive-response'|'private-config'|'debug-output';
  /** Value-derived qualifiers (known public example, encrypted material) and PEM structure from local parsing only. */
  qualifiers?:string[]; keyStructure?:Finding['keyStructure']; environmentSource?:string;
}
export interface Occurrence {
  url: string; line?: number; column?: number; byteOffset?: number; sourceLabel?: string;
  chain: string[]; transformations: string[]; excerpt: string; evidence: string;
  coordinates?: 'generated' | 'extracted-source' | 'runtime-snapshot' | 'approximate' | 'unavailable';
  excerptUnavailableReason?:string;
  byteOffsetEncoding?: 'utf-8-decoded-text';
  originalPosition?: { source: string; line: number; column: number; precision: 'mapped-segment'; approximate?:boolean };
  constituents?:import('./semantic.js').Constituent[]; sink?:string;
  exposure?:'public-response'|'static-reconstruction'|'runtime-memory'|'blocked-candidate'|'local-only';
  /** Per-occurrence environment evidence (aggregated order-independently) and documentation context (lowers priority only). */
  environment?:'production'|'test'|'unknown'; environmentSource?:string; documentation?:boolean;
}
export type ImpactKind='paid-usage'|'cloud-spending'|'payment-asset-access'|'account-takeover'|'signing-encryption'|'data-access';
export type PriorityLevel='urgent'|'high'|'review'|'low'|'none';
/** Result of an explicit, user-initiated live-key check against the key's own provider identity endpoint (2.9). It never changes `validity`, which stays 'unverified'; it is stored only in the mutable per-finding review state, never in the immutable scan file. */
export interface LiveCheckResult {
  result:'live'|'revoked'|'unknown'; checkedAt:string; provider:string;
  endpointHost?:string; status?:number;
  reason?:'no-recipe'|'host-not-allowlisted'|'redirect'|'tls-untrusted'|'timeout'|'network'|'http-error'|'rate-limited'|'unexpected-shape'|'incomplete-credential';
}
/** Owner statements refine priority only; they never establish validity or permissions. */
export interface OwnerRecord {environment?:'production'|'test';restrictions?:'restricted'|'unrestricted'|'unknown';permissionsNote?:string;spendLimitNote?:string;recordedAt:string;source:'owner-statement'}
/** Three independent tracks: what the website currently serves, what the owner reports, and what the latest rescan established. */
export interface FindingLifecycle {
  website?:{state:'observed'|'not-observed'|'uncertain'|'not-rechecked';scanId?:string;at?:string;basis?:string};
  removalReported?:{at:string;note:string};
  revocation?:{state:'owner-confirmed';at:string;note:string;replacement:'replaced'|'not-replaced'|'unknown'};
  rescan?:{scanId:string;at:string;kind:'full'|'focused';comparable:boolean;outcome:'still-observed'|'not-observed'|'uncertain';reasons:string[]};
  firstSeen?:string;lastSeen?:string;scans?:number;
}
export interface Finding {
  id: string; fingerprint: string; category: Category; provider: string; rule: string;
  severity: Severity; confidence: Confidence; reasons: string[]; masked: string;
  validity: 'unverified'; impact: string; remediation: string; occurrences: Occurrence[];
  suppression?: { reason: string; expires: string; reviewedAt: string };
  correlation?: string; findingId?: string; remediationStatus?: 'open' | 'reviewing' | 'removed';
  exposureGroup?: 'paid-ai'|'cloud'|'payments'|'crypto'|'messaging'|'dns'|'deployment'|'signing'|'data'|'other';
  financialPriority?: 'urgent'|'review'|'none'; environment?: 'production'|'test'|'unknown';
  credentialSet?: { state:'complete'|'partial'|'private-material'; components:string[]; missing:string[]; context:string };
  observation?:{endpoint:string;role:'public-image-object'|'storage-endpoint'|'database-endpoint'|'ai-api-endpoint'|'frontend-endpoint';extraction:'literal-url';authorization:'untested'};
  triage?: { category: 'direct-leak'|'high-potential-leak'|'low-potential-leak'|'insignificant'; reason:string };
  exposureKind?:Candidate['exposureKind'];
  assessment?:{ruleVersion:string;exposureConfidence:Confidence;format:string;context:string;completeness:string;channels:string[];validity:'unverified';permissions:'unknown'|'owner-reported'};
  impacts?:{kind:ImpactKind;text:string}[]; qualifiers?:string[]; priority?:{level:PriorityLevel;basis:string[];version:string};
  environmentEvidence?:{production:number;test:number;unknown:number;sources:string[]};
  ownerRecord?:OwnerRecord; lifecycle?:FindingLifecycle;
  assets?:{url:string;deployment:'current'|'previous-only'|'local-only'|'unknown';status?:number;firstSeen?:string;lastSeen?:string}[];
  keyStructure?:'verified'|'unverified'|'encrypted'|'truncated';
  feedback?:{decision:'confirmed'|'false-positive'|'unreviewed';reason:string;reviewedAt:string};
  liveCheck?:LiveCheckResult;
}
export type DomainScope='registrable-domain'|'exact-origin'|'host-subtree';
export type OriginAuthorization = {type:'explicit-seed'|'explicit-related'} | {type:'same-registrable-domain';discoveredFrom:string;seed:string;registrableDomain:string;scope?:DomainScope};
/** Structured interruption cause. Only the kind and an authorized origin are recorded; no exception text. */
export interface AbortReason {kind:'user-cancelled'|'project-deadline'|'origin-deadline'|'work-turn-limit'|'analysis-turn-limit';origin?:string;turn?:'static'|'browser'|'analysis'}
export interface GapCause {kind:string;origin?:string;phase?:string;analyzer?:'headers'|'text'|'semantic'|'discovery'}
export interface Resource {
  origin?:string;
  url: string; status: 'scanned' | 'downloaded' | 'http-error' | 'redirect' | 'skipped' | 'blocked' | 'failed'; code?: number;
  bytes: number; reason?: string; chain: string[]; kind: string;
  textBytes?:number; partial?:boolean; discoveryChains?:string[][];
  analysis?:'pending'|'analyzed'|'skipped'|'failed'|'deferred'; contentType?:string; requestHeaderNames?:string[];
  /** 2.6 Low-impact: the body came from this run's response cache (an identical earlier guarded download); no request was sent. */
  servedFrom?:'run-cache';
  httpDisposition?:'success'|'redirect'|'authentication-challenge'|'http-refusal'|'suspected-bot-challenge'|'not-found'|'server-error'|'other';
  provenance?: { channel:'guarded-route'|'deny-proxy'; attribution:'page'|'frame'|'worker'|'speculative'|'background'|'unknown'; resourceType?:string; source?:string; targetOrigin?:boolean; evidence:string; evidenceSource?:'cdp-observation'|'worker-source'|'header-derived'|'pre-navigation'|'chrome-service-host'|'frame-tree'|'none'; initiator?:string; frameId?:string; phase?:string; connectAuthority?:string; candidates?:string[] };
  attemptId?:number; resourceType?:import('./resource-types.js').ResourceType;
  timings?:{queueMs?:number;rateWaitMs?:number;analyzedAt?:number;preflightMs?:number;dnsMs?:number;connectMs?:number;tlsMs?:number;headersMs?:number;bodyMs?:number;analysisMs?:number;engineMs?:number;totalMs?:number;timeoutPhase?:string;analysisQueueMs?:number;interruption?:string;connectionReused?:boolean};
  analyzers?:Partial<Record<'directText'|'offlineEngine'|'semantic'|'sourceMap'|'debugger', {status:'not-attempted'|'inspected'|'incomplete'|'failed'|'unsupported'|'deferred';reason?:string;reused?:boolean;contentHash?:string;cause?:GapCause}>>;
  sourceMap?:{valid:boolean;reason?:string}; discoveryCount?:number; examples?:string[];
  /** HTML answered a non-navigational request; the body was classified before any browser promotion. */
  fallback?:{type:'spa-fallback'|'login'|'soft-404'|'html-for-asset';sameAs?:string;expected:string};
  contentHash?:string; certainty?:'confirmed'|'contextual'|'heuristic';
}
export interface Gap { code: string; url?: string; detail: string; incomplete: boolean; attemptId?:number; count?:number; examples?:string[]; origin?:string; cause?:GapCause; attribution?:string; targetOrigin?:boolean }
export interface WorkItem { url: string; depth: number; chain: string[]; kind: string; enqueuedAt?:number; notBefore?:number; deferredReason?:string; certainty?:'confirmed'|'contextual'|'heuristic'; context?:string }
export type Coverage='quick'|'standard'|'deep';
export type Traffic='low-impact'|'normal';
export type ProfileKind='profile'|'custom-profile'|'legacy-preset'|'custom';
export interface WebsiteAllocation {pages:number;resources:number;bytes:number;decodedBytes:number;maps:number;browserPages:number;durationMs:number;requestsPerSecond:number;concurrency:number}
/** Pure pre-scan estimate: upper bounds of the allocation and the time its pacing needs, per website and in total (with and without the discovered-website limit). */
export interface ProfileEstimate {
  websites:{explicit:number;discoveredLimit:number};
  perWebsite:{requests:number;connections:number;connectionsMax?:number;bytes:number;browserPages:number;durationMs:number;pacedMs:number};
  total:{websites:number;requests:number;connections:number;connectionsMax?:number;bytes:number;browserPages:number;durationMs:number;pacedMs:number};
  withDiscovered?:ProfileEstimate['total']; expectedMinutes:number; basis:string;
  /** Present when the estimated time is very long (over about 2 hours): says so and names Quick check. Nothing is switched automatically. */
  longRun?:string;
}
/** 2.6 ready options: local resource use for the websites in scope and this computer. `option` is the configuration, `used` what the scan runs with (websites at once never exceed the websites in scope; computer adjustments only lower values). */
export interface ResourceUse {
  websites:number;
  option:{websitesAtOnce:number;browserWebsitesAtOnce:number;analysisMemoryMb:number;analysisWorkers:number};
  used:{websitesAtOnce:number;browserWebsitesAtOnce:number;analysisMemoryMb:number;analysisWorkers:number};
  /** Before the scan: what the option may reach once discovered websites are admitted (domain or host-subtree scope), when that is more than the entered websites use. */
  withDiscovered?:{websites:number;websitesAtOnce:number;browserWebsitesAtOnce:number};
  computer?:{cores:number;freeMemoryMb:number};
  adjustments:{setting:'analysisWorkers'|'browserWebsitesAtOnce'|'analysisMemoryMb';from:number;to:number;reason:string}[];
  summary:string[]; computerNote:string;
}
/** Recorded in every 2.6 scan view: how the settings were chosen, website-count sizing, the start estimate and (Quick) what was not examined. Older records have none and are labeled "legacy preset". */
export interface ProfileView {
  kind:ProfileKind; label:string; coverage?:Coverage; traffic?:Traffic; legacyPreset?:string; equivalent?:{coverage:Coverage;traffic:Traffic;note?:string};
  sizing:{explicitWebsites:number;admittedWebsites:number;discoveredLimit:number;perWebsite:WebsiteAllocation;total:{pages:number;resources:number;bytes:number;decodedBytes:number;maps:number;browserPages:number;projectDurationMs:number;requestsPerSecond:number;concurrency:number};ceilings:Record<string,number>;cappedBy:string[]};
  estimate:ProfileEstimate; examines:string[]; skips:string[]; trafficNote:string;
  completion?:'quick-coverage'|'profile-limited'; notExamined?:{category:string;count:number;examples:string[]}[];
  /** 2.6 owner decision: work skipped only by the traffic option's own stated boundary (Low-impact: one query-string variant per path) is a non-error "Limited by profile" outcome, never a retry candidate. Older records have none. */
  profileLimit?:{rule:'query-variants';count:number;examples:string[];visitedBy:string;note:string};
  /** 2.6 ready options: what the run uses (websites at once, browser websites, analysis memory and workers) and every value lowered for this computer. Older records have none. */
  resourceUse?:ResourceUse; recommended?:boolean;
}
/** Bug-bounty program settings (2.8, from DIR/program.json via --program). Only narrows a scan: scope rules, a program-wide request rate and concurrency shared by every
 * target in one process, safe identification headers and a User-Agent suffix. Validated by makeConfig (src/program/settings.ts); never grants authorization by itself. */
export interface ProgramConfig {
  /** Stable id of the program folder (hash of its resolved path); keys the process-wide program limiter. */
  id:string; name?:string; platform?:string;
  scope:{in:string[];out:string[]};
  requestsPerSecond:number; concurrency:{targets:number;requests:number};
  headers:Record<string,string>; userAgentSuffix?:string;
  /** Explicit analysis memory (MiB, up to 2048); only this setting may exceed the 512 MiB ready-option ceiling. */
  analysisMemoryMb?:number;
  /** Opt-in live key checks (2.9), off unless the program file sets it. `enabled` allows per-finding checks for this program; `checkAll` additionally allows the paced "check all" driver. Absent means no key is ever sent. */
  liveKeyChecks?:{enabled:boolean;checkAll?:boolean};
}
export interface ScanConfig {
  name: string; urls: string[]; relatedOrigins: string[]; privateOrigins: string[];
  /** Scan profile (2.6). Present only when chosen explicitly; omitted means the legacy `preset` (or custom settings) applies unchanged. */
  coverage?:Coverage; traffic?:Traffic; profileCustomized?:boolean;
  /** Profile configurations only: shared caps the owner entered. Website-count sizing never raises a shared cap above its limit. Present (possibly empty) in every profile configuration this build writes, which marks its other shared caps as derived. */
  sharedLimits?:Partial<Record<'maxPages'|'maxResources'|'maxTotalBytes'|'maxDecodedTotalBytes'|'maxMaps'|'browserPages'|'projectMaxDurationMs'|'requestsPerSecond'|'globalConcurrency',number>>;
  autoScaleByWebsiteCount?:boolean;
  sizingMode?:'fixed'|'website-count'|'adaptive';
  originAnalysisMs?:number; semanticSliceMs?:number; maxModuleAnalysisBytes?:number; maxAnalysisBytes?:number; originAnalysisBytes?:number; analysisConcurrency?:number; maxAnalysisMemoryMb?:number;
  browserLazyAssetLimit?:number;
  sensitiveFields?:{path:string;expectation:'private'|'public'}[];
  /** Scope policy. `domainScope` is authoritative; the boolean is a derived mirror kept for older readers and downgrade. */
  domainScope?:DomainScope; sameRegistrableDomainDiscovery?:boolean; maxAutoDiscoveredOrigins?:number;
  /** Set only by the saved-project migration: the project was saved before domain scope became the default and still runs exact-origin. */
  scopeReview?:{reason:'legacy-default-exact-origin';from:string};
  /** Bug-bounty program (2.8). Present only for --program runs with a program.json; every request is also checked against its scope. */
  program?:ProgramConfig;
  developmentFixtureOrigin?: string; browser: boolean; deep: boolean;
  robotsPolicy?:'respect'|'owner-authorized-audit'; browserNavigationUrls?:string[];
  semanticAnalysis?:boolean; debuggerScripts?:boolean; staleAssetCheck?:boolean; staleAssetUrls?:string[];
  readOnlyPostEndpoints: string[]; requestsPerSecond: number; concurrency: number;
  /** Additive per-origin controls; legacy controls retain their project-wide meaning. */
  originConcurrency?:number; originRequestsPerSecond?:number; maxActiveOrigins?:number; globalConcurrency?:number; maxBrowserOrigins?:number;
  originMaxDurationMs?:number; projectMaxDurationMs?:number; originMaxPages?:number; originMaxResources?:number; originMaxTotalBytes?:number; originMaxMaps?:number; originBrowserPages?:number;
  /** Lifecycle controls: static work turn, detached analysis turn, retained backlog for deferred analysis, structured discovery size and the browser baseline idle window. */
  workTurnMs?:number; analysisTurnMs?:number; analysisBacklogBytes?:number; maxDiscoveryBytes?:number; browserBaselineMs?:number;
  /** Request privacy: the language both channels announce, the isolated browser's time zone, and whether static requests carry the product token. */
  browserLocale?:string; browserTimezone?:string; staticUserAgent?:'product'|'none';
  maxDepth: number; maxPages: number; maxResources: number; maxResourceBytes: number;
  maxTotalBytes: number; timeoutMs: number; maxDurationMs: number; queryVariants: number;
  browserPages: number; browserSettleMs: number; maxMaps: number; maxMapSources: number;
  deepPaths: string[]; adjacentMaps: boolean;
  preset: 'quick' | 'standard' | 'thorough' | 'exhaustive' | 'custom'; maxWireResourceBytes: number;
  maxDecodedTotalBytes: number; maxMapDepth: number; maxMapSections: number;
  browserScrollSteps: number; browserScrollDelayMs: number;
  maxRetries?:number;
}
export interface ScopeGroup {registrableDomain:string;unicode:string;seeds:string[];explicitOrigins:string[];redundantExplicit:string[];subtreeRoots:string[];admittedOrigins:string[];contactedOrigins:string[];notAdmitted:{reason:string;count:number;examples:string[]}[]}
export interface ScopeView {
  mode:DomainScope; source:'default'|'explicit'|'legacy-flag'|'legacy-saved-default'; psl:{library:'tldts';version:string;tenantSuffixes?:number};
  groups:ScopeGroup[]; unsupportedSeeds:{seed:string;reason:string}[]; otherExplicitOrigins:string[]; warnings:string[];
  maxAutoDiscoveredOrigins:number; autoAdmitted:number; summary:string;
  excluded:{thirdPartyOrigins:number;references:number;overflow:number;examples:{origin:string;count:number;reason:string;firstSeenIn?:string;kinds:string[];urls:string[]}[]};
  /** Gov-block (2.6): government, military, intelligence and law-enforcement hosts that were referenced and refused without any request (absent in older records). */
  protected?:{hosts:number;references:number;overflow:number;examples:{host:string;count:number;kinds:string[];urls:string[]}[]};
}
/** Per-page browser readiness: local rate-limit queueing, network waiting and blocked or unrouted dependencies are separated; at most one bounded extension. */
export interface PageReadiness {url:string;commitMs?:number;domReadyMs?:number;settleMs?:number;extendedMs?:number;verdict:'ready'|'partial'|'failed';causes:('local-rate-limit'|'network-wait'|'blocked-dependency'|'unrouted-dependency'|'dom-not-ready'|'deadline'|'navigation-failed')[];pendingAtDeadline:{localQueue:number;network:number};blocked:{scope:number;policy:number;unrouted:number;examples:string[]}}
export interface RequestProfile {headerProfile:string;staticUserAgent:string|null;acceptLanguage:string;browserLocale:string;browserTimezone:string;referrer:string;egress:string}
export interface AnalysisView {
  origins:Record<string,{allocationMs:number;maximumMs:number;chargedMs:number;queueWaitMs:number;startupMs:number;workerMs:number;cleanupMs:number;viewInspectionMs:number;jobs:number;reusedVerdicts:number;outcomes:Record<string,number>}>;
  interruptions:Record<string,number>; backlog:{items:number;bytes:number;resumed:number;deferred:number;dropped:number}; note:string;
  /** 2.8: the analysis time factor of this scan (1 on a fast computer; measured, or set with EXPOSURE_ANALYSIS_TIME_FACTOR) and the scaled group slice, group time limit and view-inspection budget. */
  timeFactor?:{factor:number;source:'measured'|'override'|'default';detail:string;speedRatio?:number;cpus?:number;sliceMs:number;groupTimeoutMs:number;viewInspectionMs:number};
}
export interface DiscoveryView {
  rejected:{bareExtension:number;nonUrlContext:number;dottedIdentifier:number;glob:number;examples:string[]}; unresolved:number; observedOnly:number;
  fallbacks:Record<string,number>; reusedDiscoveries:number; syntax:Record<string,number>; sinks:Record<string,number>; windowed:number; referenceLimit:number;
}
/** How a run was started. Recorded from 2.5 on; older records carry no launch and are labeled "trigger not recorded". Request identifiers are never persisted. */
export type RunTrigger='manual'|'queue'|'schedule'|'retry'|'resume'|'rescan'|'demo'|'deployment';
export interface RunLaunch {trigger:RunTrigger;interface?:'dashboard'|'cli';requestedAt:string;queueJobId?:string;previousRunId?:string;relation?:'repeat'|'retry'|'resume'|'rescan';label?:string}
export interface ScanView {
  launch?: RunLaunch;
  schema: 'exposure-scan/1'; id: string; name: string; state: 'ready' | 'running' | 'completed' | 'cancelled' | 'incomplete';
  startedAt?: string; endedAt?: string; elapsedMs: number; config: ScanConfig;
  counts: { resources: number; scanned: number; blocked: number; bytes: number; pending: number; findings: number; deferred?:number };
  accounting?: { networkAttempts:number; blockedEvents:number; uniqueResources:number; repeatedRequests:number; downloadedBytes:number; retainedDecodedBytes:number; textAnalyzedBytes:number; intentionalSkips:number; httpErrors:number; coverageGaps:number; networkFailures?:number;timeouts?:number;failedAttempts?:number;successfulResponses?:number;discoveredUrls?:number;reusedTextInspections?:number;runtimeCaptures?:number;reusedDiscoveries?:number;verifiedMirrors?:number;
    /** 2.6: connections opened and kept-alive reuses (Low-impact only), requests sent again after a kept-alive connection failed before any response, TLS handshakes, browser requests served from the run cache, and requests deliberately not sent (run cache and deduplicated probes). */
    connectionsOpened?:number;connectionsReused?:number;connectionReplays?:number;tlsHandshakes?:number;browserCacheHits?:number;requestsAvoided?:number;
    /** Gov-block (2.6): references to protected (government, military, intelligence, law-enforcement) hosts refused before any request. */
    protectedHostBlocks?:number };
  stopReason?:string; uninspected?:WorkItem[];
  build?:{version:string;id:string;sourceDigest:string};
  acquisitionMode?:'external'|'local-artifacts';
  coverage?:import('./coverage.js').ScanCoverage;
  engines: { websiteRules: string; gitleaks: string; ruleDigest: string; companyRules: string };
  findings: Finding[]; resources: Resource[]; limitations: Gap[];
  findingTriage?:{pending:number;removedInsignificant:number;categories:Record<string,number>};
  dismissedObservations?:Finding[];
  websites?:{mode:string;count:number;analysisMs:number;analysisMsMeaning?:string;importantUninspected:number;limits:import('./adaptive-budget.js').BudgetSnapshot[]};
  retry?:import('./retry.js').RetryPlan;
  stage?: string; browserStatus?: { requested: boolean; launch: boolean; runtimePages: number; isolation: 'unverified' | 'failed' | 'checked'; background?:{count:number;hosts:string[]}; isolationChecks?:Record<string,boolean>; cleanup?:'confirmed'|'deferred'; pages?:PageReadiness[]; popups?:{opened:number;closed:number} };
  discoveryGraph?:{edges:{from:string;to?:string;reference:string;context:string;kind:string;status:string;certainty?:string;sink?:string;method?:string}[];limit:number};
  semantic?:{modules:number;nodes:number;views:number;elapsedMs:number};
  origins?:import('./origin-control.js').OriginSnapshot[];
  scheduler?:{peakBrowserOrigins?:number;classes:Record<string,{pending:number;active:number;oldestQueuedMs:number;blockedReason?:string;deferred?:number}>;timeToFirstJavaScriptMs?:number;timeToFirstBrowserDocumentMs?:number;pageAttempts?:number;dispatches?:{class:import('./resource-types.js').WorkClass;url:string;at:number}[]};
  aggregatedSkips?:{reason:string;count:number;families:number;examples:string[]}[];
  scope?:ScopeView; analysis?:AnalysisView; discovery?:DiscoveryView;
  requestProfile?:RequestProfile; profile?:ProfileView;
}
