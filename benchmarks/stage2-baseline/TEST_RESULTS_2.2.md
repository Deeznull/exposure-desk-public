# Actual verification — 2.2.0-rc.1, 2026-10-06

Build: 2.2.0-rc.1+8399b64166f5075d. Website rules: website/2.2.0. Windows x64; bundled Node 24.18.1, Gitleaks 8.30.1, Playwright 1.63.0 / Chrome 153.0.8010.12. Dependencies remain exact in the lockfile. The 2.1 records are historical, not current verification.

| Check | Measured result |
| --- | --- |
| Build, TypeScript and frontend/launcher/packager syntax | Passed; Diagnostics source/compiled/frontend/test/lock parity verified |
| Source nonbrowser suite | 172 passed, 0 failed, 0 skipped; 187.153 s. Core, dashboard, upgrade, coverage, provider and reliability fixtures |
| Strict actual browser + dashboard UI | 3 passed, 0 failed, 0 skipped; 144.156 s. Pages/API/scroll/storage/config/guarded provenance, forbidden arrivals, deliberate reveal/copy/remask/export and one-click full-pipeline Diagnostics |
| CLI actual child processes | 4 passed: clean exit 0; private evidence exit 1; incomplete exit 2; deliberately full-sensitive export exit 1. Routine outputs masked |
| Native Windows persistence | Passed without synthetic ACL exception: project/correlation/vault save and restart, operator ownership/DACLs and deletion |
| Selected offline provider benchmark | 102/102 detected; zero misses/control false positives/component or original-location errors. Final record: benchmarks/results.json; 102 selected targets, including 98 private, 3 public and 1 suspicious. Per-fixture categories/components/original locations and retained rule/detector IDs; seven negative controls |
| Full-pipeline synthetic scanner | 17/17 found, all execution/isolation assertions passed. Final record: benchmarks/pipeline-results.json and portable-pipeline-results.json; 17 cases in each, actual isolated browser execution required. Deliberate refusals and unknown proxy traffic remain coverage limits even when expected assertions pass |
| HTTP framework integration | Representative Next, Nuxt, Vite, Webpack and Astro chunks fetched, analyzed and planted private values found. Masked per-resource record: benchmarks/framework-results.json |
| Windows package suites | 172 nonbrowser checks passed (193.167 s); 3 actual browser/UI checks passed (148.830 s); zero failures/skips in the final package runs |
| Extracted candidate | All file hashes verified (132 source / 4615 Windows files). Actual .cmd launch with spaces, port conflict, protected storage, existing-instance reuse, demo, masked defaults, reveal, cancellation, shutdown and restart passed. Extracted Diagnostics build parity verified |
| Linux | Native WSL listing returned no distributions; Linux execution unavailable and unverified |

Final archive and extracted-package verification is recorded in artifacts/release-2.2-results.json and SHA256SUMS-2.2.txt. The package remains a candidate because Linux, missing-dependency source bootstrap, default OS browser opening and broader enterprise Windows policy environments remain unverified.

Coverage fixtures verify bounded 401/403/404/5xx body/header detection while retaining HTTP errors; plain 403 is not a login diagnosis. Base href/password-form public scripts and application-before-deployment ordering pass. Tests cover compression/encodings/maps, engine-only encoded UUID, meaningful queries, robots policies, source limits, cancellation, unavailable detector/browser, interrupted redacted ad-hoc history, stale IDs and capability screening before DNS/network. Invalid encoding and detector failures now remain distinct; detector failure does not suppress linked-resource discovery.

Earlier exploratory failures are excluded from final pass counts: the 119-case detector run had one Resend SDK component-set miss; a 171-case full run had one Webpack numeric-table miss; one browser run missed scrolling and another lost the Diagnostics result on refresh. Fixes were exercised with positive assertions, not skipped prerequisites or weakened outbound guards. The final source suite and actual browser/UI suite pass as shown above. Browser dependent tests fail when execution is unavailable.

The request's 22 attempts/20 HTTP errors/664 bytes and target-host proxy observation are user-supplied descriptions, without the associated body/header/initiator/history evidence. Their specific causes cannot be established. The base version's historical target report is not rerun or treated as current verification. A refusal alone does not establish login, bot blocking or missing-header causality. Unknown deny-proxy requests remain denied and unknown; successful routed pages are measured separately.

The exact previously used launch folder could not be established: default registry PID was stale, no dashboard responded and root/build metadata was absent. Current source/dist/frontend and prior portable package were 2.1 and contained both quoted report fields; older 2.0 attachments were not restored. New registrations expose root/build and warn about differing running builds.

Selected synthetic results do not establish universal credential detection, credential validity, permissions, monetary value or whole-site coverage. No capability was redeemed, credential used or website content uploaded.

A staged-package run was interrupted: 171/172 nonbrowser checks passed, with one duration failure during the observed 37,580.864 s run. A UI browser closed unexpectedly (1/2 browser checks passed; cause unknown). A later 2-case browser run exposed a readiness/scroll miss (1/2 passed). Committed-document inspection now preserves available snapshots, records a readiness gap, and waits for routed scripts before scrolling. The new deferred-script fixture and all final 3-case source/package suites pass; failed runs were not counted as passes.
