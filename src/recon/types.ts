/** Shared types for recon lists (src/recon/collector.ts) and the source-map rebuild (src/recon/rebuild.ts). */
export type HostScope='in-scope'|'out-of-scope'|'third-party';
export interface ScopeVerdict {scope:HostScope;reason?:string}
/** The scope decision function passed in by the caller: given a URL (`https://host/` for bare host literals), how its host relates to the scan scope. */
export type ScopeClassifier=(url:string)=>HostScope|ScopeVerdict;
/** One downloaded or captured resource, as the scanner saw it. Only the `sourcemap` / `x-sourcemap` response headers are read. */
export interface ReconResource {url:string;kind:string;contentType?:string;text:string;headers?:Record<string,unknown>}
export const LIST_NAMES=['urls','endpoints','hosts','parameters','js','sourcemaps','graphql'] as const;
export type ListName=typeof LIST_NAMES[number];
export interface ReconLimits {
  /** Items kept per list; later new items are counted as dropped (`over-limit`). */
  maxItemsPerList:number;
  maxUrlLength:number;
  maxEndpointLength:number;
  /** Parameter and GraphQL operation names. */
  maxNameLength:number;
  maxHostLength:number;
  /** Characters of one resource that are scanned; the rest is ignored and the resource is counted as truncated. */
  maxTextChars:number;
  /** Iterations of one pattern over one resource. */
  maxMatchesPerPattern:number;
}
export const DEFAULT_RECON_LIMITS:Readonly<ReconLimits>=Object.freeze({maxItemsPerList:50000,maxUrlLength:2048,maxEndpointLength:1024,maxNameLength:128,maxHostLength:253,maxTextChars:16*1024*1024,maxMatchesPerPattern:50000});
export interface ReconItem {
  value:string;
  /** Cleaned URL of the first resource the item was seen in. */
  source:string;
  /** hosts only */
  scope?:HostScope;reason?:string;
  /** graphql only */
  type?:'query'|'mutation'|'subscription'|'operation'|'endpoint';name?:string;
}
export interface DroppedCounts {'over-limit':number;'too-long':number;secret:number}
export interface ReconResult {
  schema:'exposure-recon/1';
  generatedAt:string;
  resources:{seen:number;scanned:number;skipped:number;truncated:number;maps:number};
  limits:ReconLimits;
  counts:Record<ListName,number>;
  dropped:Record<ListName,DroppedCounts>;
  /** Path segments replaced by `{redacted}` because they looked like credentials. Query values are always dropped and are not counted. */
  redactions:number;
  /** `sourceMappingURL=data:` maps seen; they are counted, never listed. */
  inlineSourceMaps:number;
  lists:Record<ListName,ReconItem[]>;
}
/** Extra credential screen supplied by the caller (for example the scanner's detector). True means the value must not be listed. */
export type SecretFilter=(value:string)=>boolean;
/** Errors from writing recon output; `code` is stable so the CLI can map it to its own error. */
export class ReconOutputError extends Error {
  constructor(readonly code:'unsafe-output'|'output-not-empty'|'output-not-directory'|'write-failed',message:string){super(message);this.name='ReconOutputError';}
}
