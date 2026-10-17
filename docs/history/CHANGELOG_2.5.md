# Changelog — 2.5.0-rc.1

Compared with 2.4.0-rc.1 (build `2.4.0-rc.1+5d5acf0f7f18d7e6`). Details: [UPGRADE_2.5.md](UPGRADE_2.5.md). Upgrade notes: [MIGRATION_2.5.md](MIGRATION_2.5.md). Measurements: [TEST_RESULTS.md](../TEST_RESULTS.md).

## Scope (section 1)
- Registrable-domain scope is the default for the UI, presets, CLI and JSON; `exact-origin` and `host-subtree` modes; one scope policy for every channel; punycode/PSL matching with private suffixes; userinfo URLs blocked as credentials; trailing-dot and empty-label hosts normalized or refused.
- Scope fieldset under the website box with a server-computed domain name and one acknowledgement; legacy saved projects keep exact-origin with an adoption banner; aggregated third-party exclusions; `POST /api/scope/preview`; `POST /api/scans` requires `authorized: true`; CLI `--scope`.
- Admission is detached from the discovering origin's turn; the 50-origin cap counts only admitted public origins; admitted roots get priority.

## Runs and counts (section 2)
- `src/runs.ts`: run summaries, separate scope counts, default names from the host, idempotent request IDs, allow-listed `409` errors.
- `GET /api/runs`; current-run card and labeled previous-runs list; triggers and run links (`launch` in views and history); chronological history; disabled start controls; inline repeat confirmation; idempotent queue requests.

## Discovery (section 3)
- Syntax-aware URL extraction with certainty and recorded context; bare extension and non-URL literals rejected with counts; SPA fallback, login and soft-404 classification before browser promotion; content-hash discovery reuse; aggregated summaries.

## Analysis lifecycle (section 4)
- `addModule` reset fixed; outcomes applied to aliases; terminal `deferred`/`partial` states with structured causes; deferred analysis backlog; 4 MiB structured discovery with windowed fallback; semantic worker pool with separated timing; lifecycle invariant check.

## Privacy and attribution (section 5)
- One outbound header policy (profile `v2`): honest static product token, configured language, strict-origin Referer from authorized pages only, no fabricated headers; `browserLocale`, `browserTimezone`, `staticUserAgent` settings; `requestProfile` in views and reports.
- `ws://` CDP connection, allowlisted Chromium environment, SharedWorker and back/forward cache disabled, verified isolation checks, confirmed cleanup with a startup sweep of orphaned profiles, per-page readiness records with one bounded extension, separate request and analysis gates, guarded unload drain, neutral baseline probe paths.
- Cancellation fix: a stop that killed Chromium during page creation could leave a Playwright call pending forever, so the browser session never cleaned up and the run never ended. Every browser-session call now also settles on the stop, and post-stop analysis tasks get one second (gap `browser-cleanup-limit` otherwise).
- CDP network observation and pure deny-proxy classification (page, frame, worker, header-derived, background, unknown); background traffic aggregated; unknown and target events remain gaps.

## Findings and incidents (section 6)
- `src/provider-capabilities.ts`, `src/finding-assessment.ts`, `src/key-material.ts`, `src/triggers.ts`.
- `priority/1` with basis; strictly financial `financialPriority`; separate impact rows; qualifiers; order-independent environment; sandbox hosts as test evidence; canonical Gitleaks providers; `signing` and `data` groups; provider-specific remediation.
- Usage-context detection (signing/encryption calls, request credentials to unmapped hosts, unknown SDK constructors, signing-secret field names), checksum-verified BIP39 seed phrases (vendored wordlist), WIF, BIP32 extended keys, context-gated hex keys, Solana keys, JWK private members, PGP private blocks, PEM structure; published examples dismissed by digest.
- Review merge fixes (feedback/status/suppression), owner records, three lifecycle tracks with focused-rescan comparison, affected assets (current/previous deployment), persisted masked alerts with acknowledgement, file-drop deployment triggers with rate limits, `cli.js trigger`, `--fail-on`, SARIF correlation fingerprints.
- Rules `website/2.5.0`.

## Tests and delivery (section 7)
- New suites: scope, lifecycle, discovery, attribution, runs, privacy, findings, incidents, egress (non-browser); scope, discovery, attribution, runs, privacy, findings (browser); legacy 2.4 data-directory fixture.
- Test harness: fails on unlisted test files, global test timeout, signal exits are failures, test outputs in `.cache/test-output`.
- Frozen before/after evaluation (`scripts/eval-2.5-corpus.mjs`, `scripts/eval-2.5.mjs`), release preflight, parameterized release summary, System32 `tar.exe` packaging, docs frozen before packaging.
