# Milestone 1: fair origins and honest coverage

This milestone changes active source only. Release packaging and archived copies are outside its scope. Results describe supported exposures in inspected public evidence; no credential is used, validated, authenticated with, redeemed, or sent to a remote analysis service.

## Diagnosis and acceptance criteria (set before post-change evaluation)

Baseline build: 2.3.1-rc.1+1b19d40f69120ab9. Source hashes, fixture/settings metadata and raw baseline runs are in benchmarks/milestone1-baseline-source.json and benchmarks/milestone1-baseline/. The working directory is an extracted source tree without Git metadata, so hashes identify the source state.

The previous scheduler rotated resource classes but awaited whole batches, serially fetched robots, and explicitly bootstrapped only the first configured seed. Transport had one rate state, retry pause, deadline and concurrency semaphore for every origin. Browser routed HTTP already used that transport. Coverage counted the same URL in failed and successful totals after recovery. Existing exact scope, pinned DNS/socket checks, TLS, metadata blocking, dashboard denial, method restrictions, credential screening, redaction, guarded browser interception, source maps, semantic worker limits, engine caching and low-value image skipping were present and are retained.

Acceptance: every feasible configured seed gets a bounded early turn before optional traversal; more queued origins than active slots must progress before one flood drains; no origin deadline cancels unrelated work; global/origin rate, request, byte and browser limits remain enforced. Known scripts/config/maps are prioritized over optional pages. Exclusive current states must sum to known inventory, and a recovered retry cannot remain a current failure. Hard budgets take precedence where seed count exceeds configured pages/requests/time; rejected work needs an explicit reason.

The selected benchmark requires 102/102 planted detections with zero private false positives, component errors, location errors or engine issues. The held-out baseline is 16/16 credential targets and zero private false positives on three controls; no decrease is accepted. It is kept unchanged and is not used for tuning detector rules. These benchmarks do not measure multi-origin fairness, request volume, browser concurrency or whole-site recall. New local tests measure those behaviors separately. The matched repair workload measures request/byte/duration/runtime-page differences. Increased traffic is acceptable only within existing shared caps, for measured additional configured inspection; no silent cap increases. There is no broad false-positive rate or universal recall estimate.

## Settings and compatibility

Quick, Standard and Thorough keep all previous numerical preset values and detection settings. Fair scheduling and current coverage semantics intentionally apply to every preset. Saved configs are normalized by makeConfig; new fields are additive in exposure-scan/1, exposure-checkpoint/1 and existing history formats. Historical results without origin data stay historical and are not assigned invented origin accounting. Checkpoint resume still starts a fresh scan and fresh clocks.

| Setting | Supported range | Omitted value / Exhaustive |
| --- | --- | --- |
| originConcurrency | integer 1–8 | legacy concurrency / 3 |
| originRequestsPerSecond | 0.1–20 | legacy requestsPerSecond / 2 |
| maxActiveOrigins | integer 1–8 | 4 / 4 |
| globalConcurrency | integer 1–12 | legacy concurrency / 12 |
| maxBrowserOrigins | integer 1–4 | 2 / 2 |
| originMaxDurationMs | integer 100–3,600,000 | legacy maxDurationMs / 3,600,000 |
| projectMaxDurationMs | integer 100–360,005,000 | legacy maxDurationMs / authorized origins × 3,600,000 + 5,000 |
| originMaxPages | integer 1–500 | maxPages / 80 |
| originMaxResources | integer 1–2,000 | maxResources / 600 |
| originMaxTotalBytes | integer 1,024–524,288,000 | maxTotalBytes / 300 MiB |
| originMaxMaps | integer 0–100 | maxMaps / 80 |
| originBrowserPages | integer 1–50 | browserPages / 15 |

Existing maxPages, maxResources, maxTotalBytes, maxDecodedTotalBytes, maxMaps, browserPages, audit/graph/frontier/module/cache bounds remain shared project caps; origin allowances do not multiply them. requestsPerSecond remains the aggregate HTTP rate cap (Exhaustive 8/s; old presets 2/s). Explicit legacy concurrency, rate and duration supplied to presetConfig retain their values and inherited caps unless the corresponding new setting is explicitly provided. New defaults apply to undefined fields; invalid/null values fail validation.

Exhaustive starts with Thorough's conservative shared limits: 80 pages, 600 request attempts, 24 MiB decoded/wire per resource, 300 MiB total inspection/wire budget, 400 MiB decoded cap, 80 maps, 80 sources/map, 15 browser navigation attempts, 5 bounded scroll steps. Indexed-map depth remains 4 and sections 50. Existing semantic admission remains 100 complete modules, 1 MiB/module, 16 MiB total; discovery graph 4,000 edges, resource audit/known inventory 6,000 rows. These limits are not evidence that a large site will be fully covered. Benchmark evidence does not justify increasing them.

## Admission, clocks and cancellation

An active HTTP origin has at least one currently admitted DNS/socket/response request. Rate waits, retry backoff and whole origin lifetimes hold no HTTP slot. A deterministic round robin chooses eligible origins; when slots are full and another origin is waiting, existing origins drain in-flight requests instead of continually replenishing their slots. Each request still has the configured timeout (at most 30 seconds). HTTP concurrency counts DNS through response completion, including static acquisition, redirects, map-section requests, retry attempts and browser HTTP handled by guarded Node transport. Local detector analysis has its own bounded workers and does not hold a network slot. Deny-only proxy traffic never reaches targets and is not counted as admitted HTTP. Chromium/CDP startup, local snapshots and cleanup are governed by browser/analysis limits, not by HTTP rate promises.

The scanner dispatches continuously as individual work items finish. It rotates seed turns across origins, queues bounded robots prerequisites, and blocks optional traversal until seed turns finish. High-value resources may run while a seed is stalled. Work items have a 30-second turn ceiling, including retry delays and nested map work; unfinished work is deferred with a work-turn-limit reason. This prevents an hour-long Retry-After from occupying the entire scanner window. A browser turn has a separate 120-second ceiling (still bounded by the origin/project deadline) and is one read-only navigation in a fresh guarded session; queued origins precede repeat turns. The separate maxBrowserOrigins bounds simultaneous sessions.

After bootstrap, priorities are JavaScript/source maps/configuration and API JSON; entry documents/discovery and other application resources; optional pages; then low-value resources and finite deployment probes. Origin fairness applies within these choices. A queued optional/low-value item can be displaced when important work reaches the frontier cap; its URL, chain and deferral reason remain in inventory. A hard request/byte cap is never raised or reclaimed by eviction. Image bodies continue to be skipped where supported.

Each origin has one monotonic wall clock starting at its first dispatched scan work, including preflight/admission and subsequent waiting. Waiting before that dispatch is free. The clock does not reset between network, browser, retry, analysis or scheduling turns. An origin with no remaining configured work is finalized early. Later cross-origin discovery can reopen it against the same original start time, including intervening elapsed time; it never receives a fresh budget. At 90%, new optional/low-value work is deferred; configured seeds, discovered important resources, selected runtime captures and important retries remain eligible. At 100%, that origin's AbortSignal cancels child requests, browser work and workers; other origin controllers remain independent. Project cancellation and the shared project deadline cancel every child.

Timers cannot interrupt a synchronous JavaScript instruction. Large direct scans are isolated in at most two workers (192 MiB heap each, 10-second local analysis ceiling); semantic workers remain at most two (128 MiB each, 2.5-second analysis ceiling). Large company-rule inspections use the same isolation. Small synchronous scans and bounded JSON/DOM parsing remain cooperative; the timer runs at the next event-loop opportunity, so no claim of exact real-time millisecond preemption is made. Structured HTML discovery is capped at 1 MiB. Cancellation tests exercise live sockets, browser sessions, semantic and large direct-analysis workers.

Cleanup is separated from productive origin elapsed time. Browser cleanup awaits at most 1.5 seconds for context, 1.5 seconds for browser, 0.5 seconds for proxy, and 1 second for profile removal (4.5 seconds total). Native child termination is requested immediately; workers await termination for at most 1 second and report if it cannot be confirmed. Filesystem deletion may finish later; unfinished removal is a cleanup limitation. No further target work is admitted during cleanup. Recorded cleanup time includes any event-loop overrun after the hard deadline. The configured project ceiling is a safety bound, not a promise of productive duration.

An Exhaustive project can exceed 60 minutes overall: later origins may begin after earlier turns, and each newly admitted origin gets its own clock. The default project ceiling is deliberately a conservative sum of origin ceilings plus cleanup allowance. Fairness, shared caps, rate, number of origins and discovered work determine actual duration; work stops early when the configured frontier is drained. Old presets retain their previous project deadline by default.

## Coverage and completion

coverage.inventory is the bounded known unique URL inventory with discovery chain, one category, one current state and a reason when needed. Category groups and per-origin groups use mutually exclusive states: inspected, reused, pending, unavailable, failed, unsupported and deferred. Inspected/reused require successful complete content and configured analyzer completion; HTTP error text can contain findings while the intended application resource stays unavailable. 304 without a trusted matching body is unavailable. Valid reuse is successful exact-text inspection under the same in-memory detector/rule context, with required other analysis finished. Failed and cancelled inspections are never cached as successful.

A later complete recovery supersedes earlier failures in current state. Attempt rows and legacy downloaded/analyzed/error counters remain historical evidence and may overlap. Browser runtime counts navigations separately from URL inventory. Entry documents, optional pages and important resource categories are separate; highValueLimited does not hide behind an overall percentage. Scope-blocked external dependencies are reported separately and never automatically approved. Pending, unsupported, unavailable, deferred and retry-exhausted important resources make high-value coverage limited. Inventory truncation is an explicit limitation.

Configured checks completed means checks finished for discovered resources within that origin's authorized scope and configured limits. It does not mean every site resource was discovered or inspected. Per-origin completion can be completed while another origin is limited. API/JSON, persisted results, HTML/SARIF exports, CLI summary and dashboard coverage panel use this same projection. Zero findings means only that no supported exposure was detected in inspected coverage.

## Running Exhaustive

GUI: start the current source build with npm run build then npm start. Open the local dashboard URL, sign in with its printed per-launch token, select New scan, enter the authorized website, expand Advanced: saved projects, extra seeds, scope and limits, enter optional extra public seeds and explicitly authorized related origins, choose Exhaustive in Scan preset, review the shared/origin/browser limits, check the authorization box, then Start scan. The Running scan panel's Coverage groups and request scheduling section exposes origin accounting and current states. API clients use the same resolved config shown by the preset controls; no new endpoint or implicit scope is introduced.

CLI, for an authorized URL: node dist/src/cli.js scan --url https://www.example.com/ --preset exhaustive --format json --output reports/exhaustive.json

For multiple origins, create a JSON file with projects containing name, urls and relatedOrigins (only approved origins), then run: node dist/src/cli.js scan --config exhaustive.config.json --preset exhaustive --output reports/exhaustive.json

Do not copy old numerical settings into that file unless retaining their explicit caps is intended. Existing explicit settings override preset defaults. Multiple projects in one file remain separate CLI scans, while multiple urls within one project share this fair scheduler.

## Ordered follow-up roadmap (not implemented here)

1. Conservative static string resolution and wider framework/chunk discovery. Evaluate only expressions whose behavior is established without executing target code, getters, proxies, callbacks or downloaded code.
2. First-class source-map traversal and batched semantic analysis with explicit budgets; retain current safe map support in the meantime.
3. Additional decoded/contextual detection, credential correlation and Gitleaks metadata.
4. Investigate worker/out-of-process frame capture without weakening network policy; do not claim support before containment and resource limits are demonstrated.
5. Broader bounded read-only browser storage inspection. Existing fresh-session snapshot behavior remains, with no new browser interaction capabilities.
6. Investigate selected binary/archive extraction with safety and resource bounds; no archive execution or bulk extraction in this milestone.
7. Broader held-out corpora, false-positive measurement, target-category diagnostics and browser/process memory/load measurements.

See MILESTONE1_RESULTS.md for executed checks, measured comparisons and remaining limitations.
