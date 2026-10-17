/** Recon lists and source-map rebuild (core). See docs/RECON.md for formats, caps and the scanner hook. */
export * from './types.js';
export { ReconCollector, scopeFromPolicy, type ReconCollectorOptions, type MapSink, type SourceMapOptions } from './collector.js';
export { writeRecon, RECON_FILES } from './write.js';
export { SourceRebuilder, rebuildSources, DEFAULT_REBUILD_LIMITS, type RebuildLimits, type RebuildManifest, type RebuildOptions, type ManifestFile, type ManifestMap } from './rebuild.js';
export { sanitizeSourcePath, parseSourceMap } from './sourcemap.js';
export { cleanUrl, cleanEndpoint, cleanLabel, secretShaped, containsKnownSecret, REDACTED, EXPR } from './clean.js';
export { reconMode, extractRecon, type ReconMode } from './extract.js';
