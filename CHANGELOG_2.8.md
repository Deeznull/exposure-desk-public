# Changelog — 2.8.0

2.8.0 follows 2.7.0 (build `2.7.0+3772c88c496661b5`). It adds opt-in features for bug bounty work: program files with scope rules, target lists that run concurrently, resume after an interruption and stop on blocks, recon lists with a rebuild of public source maps, and submission Markdown. A Linux x64 package and a container image join the Windows package. Upgrade notes: [MIGRATION_2.8.md](MIGRATION_2.8.md). Measurements: [TEST_RESULTS.md](TEST_RESULTS.md). Earlier changes: [CHANGELOG_2.7.md](CHANGELOG_2.7.md). Like every earlier release, 2.8.0 was measured only with local loopback fixtures and synthetic, nonfunctional keys. The release measurements ran on one Windows x64 computer, and the Linux x64 test suites, package and container image ran on GitHub-hosted Ubuntu runners. No real website was scanned.

Rule version `website/2.8.0` (2.7.0 used `website/2.7.0`). The detection rules and patterns are unchanged; only how analysis runs changed (see Analysis). The priority version stays `priority/1`. Unchanged:

- the ready options and their limits, including the 512 MiB analysis memory ceiling
- Low-impact traffic
- the protected-host rule and the authorization rule
- masking
- the dashboard security model

No new option or file can loosen any of them. Every 2.7 command-line flag, configuration file, checkpoint and saved record keeps working. The JSON Lines schema stays `exposure-jsonl/1` and only gains fields. Static requests carry the product token `Mozilla/5.0 (compatible; ExposureDesk/2.8)`, taken from the build version as before.

## Program files and scope rules

- `--program DIR` with a `program.json` (schema `exposure-program/1`, JSON with comments) applies the program's settings, which are:
  - its scope rules
  - its program-wide request rate and concurrency
  - its `X-…` identification headers and a User-Agent suffix, sent only to in-scope URLs

  A folder without `program.json` keeps its 2.7 meaning: it only holds the finding-ID key. See [docs/PROGRAM.md](docs/PROGRAM.md).
- Scope rules can be an exact host, `*.example.com` (subdomains only), a URL prefix, an IP address or a CIDR range. An out-of-scope rule wins over an in-scope one. The program scope only narrows the 2.7 scope:
  - A link or redirect outside it is never requested. It is listed in the report with reason `program-out-of-scope`.
  - A `--targets` line outside it is rejected with reason `out-of-scope`, after the protected-host check, and the rest of the list runs.
- Every run with a program file needs `--authorized` or `"authorized": true`, including a single `--url`. Without either, the run is refused with exit 2 before any request.
- One program-wide limiter covers every scan of the run. The defaults are 5 requests per second, 4 targets at once and 16 requests at once. Its figures are printed after the run and written as `summary.program` in JSON Lines.
- A program file's `analysisMemoryMb` is the only way above the 512 MiB ready-option ceiling (up to 2048 MiB).
- New offline commands: `program init DIR`, `program check DIR` and `program import --platform hackerone-csv|bounty-targets --file FILE [--handle NAME] DIR`. An import:
  - never sets `authorized`
  - refuses and lists protected hosts
  - skips non-web assets and states why
  - never replaces an existing file

## Target lists: concurrency, resume and block detection

- `--concurrency N` runs up to N targets of a `--targets` list at once. The limit is 16 without a program file and 64 with one; a program file's default is 4. Without `--concurrency`, `--state` or a program file, a list still runs one target after another, as in 2.7. See [docs/MASS_SCAN.md](docs/MASS_SCAN.md).
- In mass mode (concurrency above 1, or `--state`), all scans of the run share one detector and one analysis memory budget, granted first come, first served. The run's analysis memory therefore stays within the analysis memory setting however many targets run at once. Each scan keeps its own cancellation, limits and stated failures.
- **Time waiting for shared capacity.** In mass mode a target's time allowances count only its own work. While a website of the target only waits for capacity the targets share (the analysis memory budget, the detector's engine lanes, the parser, or under a program file a request slot that other targets hold), its time allowance and its work turns are paused, and while every open website of the target waits this way, the whole-scan allowance is paused too. Each `target-end` reports the paused time as `sharedWaitMs` and the summary their sum. The target's own request pacing, retry pauses and a program-limit wait right after its own grant are charged as before, and outside mass mode every wait is charged as in 2.7. Without this, at 16 or 64 targets at once most targets used up their per-website allowance while waiting and ended incomplete. See [docs/MASS_SCAN.md](docs/MASS_SCAN.md#time-waiting-for-shared-capacity).
- **Memory gate.** Above concurrency 1 the next target starts only when the scan process's memory leaves room for it. The ceiling is 512 MiB under the ready options; only a program file's `analysisMemoryMb` above 512 raises it, to at most 2048 MiB. `--concurrency` is therefore a maximum, at least one target always runs and a running target is never stopped. The summary reports `effectiveConcurrency` (the most targets that actually ran at once) and `memory` (the gate's figures). See [docs/MASS_SCAN.md](docs/MASS_SCAN.md#memory-gate).
- **One triage worker and one parser.** One finding-triage worker per process and, in mass mode, one parser pool sized by the shared analysis budget serve every target, instead of one of each per target.
- `--state FILE` writes an owner-only run-state file (`exposure-massrun/1`, written atomically). After an interruption:
  - Running the same command again skips the targets that completed and runs the rest.
  - If the target list or the run settings changed, the resume is refused with exit 2 before any request. The compared settings include the contents of a `--config` settings template.
- **Block detection.** Every target of a list, and every program run, is watched. A target is stopped as `blocked` (`incomplete`, exit 2) after any of these in a row:
  - two challenge pages
  - five HTTP 403, 429 or 503 answers
  - three connection resets

  Once at least three targets have finished and a quarter or more of them were blocked, the run starts no further targets (`summary.halted` is `blocked`). Nothing is retried around a block, and the User-Agent, headers, proxy and address never change to get past one.
- **Cross-target de-duplication.** In mass mode, each `finding` event carries `firstSeen`. A finding that another target reported first also carries `duplicateOf`. The summary lists `uniqueFindings` and `sharedFindings`. Each target's report keeps all of its own findings.
- With concurrency above 1, each target's terminal lines are printed together when the target ends. JSON Lines events stream as they happen and carry their `target`.

## Recon lists and source-map rebuild

- `--recon DIR` writes masked recon lists for each target into an owner-only folder:
  - URLs and endpoints
  - hosts, split into in-scope, out-of-scope and third-party
  - parameters, scripts, source maps and GraphQL endpoints
  - `recon.json` with provenance and caps

  Credentials never reach a list. See [docs/RECON.md](docs/RECON.md).
- `--rebuild-sources DIR` rebuilds the website's original source tree from the `sourcesContent` embedded in the source maps the scan retrieved. It requests nothing extra. It writes only into a new or empty, owner-only folder, sanitizes every path, and records every file with its SHA-256 in `MANIFEST.json`. Rebuilt sources are verbatim public code and may contain credentials, so treat them like an unmasked report file.

## Submission Markdown

- `--format md` writes each target's report as masked submission Markdown: an editable report draft for a bug bounty platform. See [docs/SUBMISSION.md](docs/SUBMISSION.md).
- `--submission-bundle DIR` writes one masked draft per finding, grouped by finding ID across targets, plus an `index.md`.
- `report submit REPORT.json [REPORT2.json ...] [--out FILE | --bundle DIR]` renders submission Markdown offline from saved JSON reports.
- `--full-secrets` unmasks values only in files written to disk (`.sensitive.md`). It is refused for `report submit` without `--out` or `--bundle`.
- Hostile page content is escaped in every draft. Drafts are written offline: no request, no platform API and no use of a found key.

## Dashboard

- **Findings** has a **Copy submission Markdown** button on each finding, which copies a masked draft. Without clipboard access, the draft appears in a read-only box, focused and selected. The dashboard never writes unmasked submission files.
- **Findings → Local exports → Recon lists** offers the run's recon lists as downloads. Runs the dashboard stores keep them in `recon/<run id>/` (owner-only), deleted with the run. Runs saved by 2.7 have none, so the block stays hidden for them. The scan view gains the additive field `reconFiles`.

## Linux x64 package, container image and Linux CI

- `Exposure Desk 2.8.0 Linux x64.tar.gz` comes with a `.sha256` file and carries its own runtime pieces:
  - Node.js 24.18.1
  - the Chrome for Testing build Playwright 1.63.0 uses
  - Gitleaks 8.30.1

  Data goes to `$XDG_DATA_HOME/exposure-desk`, or `EXPOSURE_DATA_DIR` (absolute). Chromium keeps its own sandbox. See [docs/LINUX.md](docs/LINUX.md).
- The `Dockerfile` builds a container image with:
  - a pinned base
  - a non-root user
  - data in the `/data` volume
  - support for `--read-only`

  It sets `EXPOSURE_BROWSER_NO_SANDBOX=1`, which has no effect outside Linux, because Docker's default seccomp profile blocks Chromium's sandbox; the container is then the isolation boundary. The dashboard still listens only on `127.0.0.1`.
- `.github/workflows/linux.yml` runs four jobs on GitHub-hosted Ubuntu: the non-browser suite, the browser suite, the package with its smoke test, and the container image with its smoke test. It runs on pull requests into `v3` and `main` and on manual dispatch. Downloads are pinned by checksum (`scripts/linux-distributions.json`), and actions are pinned to full commit hashes.
- `--disable-crashpad-for-testing` is now passed on Windows only; on Linux it crash-loops Chromium 153's network service.

## Analysis

- **One budget per mass run.** A shared detector no longer sends its cancellation, limits or failures to the most recently started scan. Each inspection takes the calling scan's own scope: its analysis memory, cancellation, limit notes and failure notes. A detector used alone behaves as before.
- **Engine keyword gate.** The Gitleaks engine starts only for a text that contains a keyword of at least one engine rule Exposure Desk keeps. This is the engine's own keyword prefilter, applied before the engine starts (and not applied when the rule file cannot be followed exactly), so findings are unchanged; a text that cannot match an engine rule no longer waits for an engine lane (`src/detectors.ts`).
- **Analysis time factor.** Each process measures the computer's speed once, with a short, fixed parse workload in a background thread, combined with the CPUs the process may use.
  - A fast computer gets factor 1 and keeps the 2.7 limits. A slower one gets 1 to 4, in steps of 0.25. `EXPOSURE_ANALYSIS_TIME_FACTOR` sets 1 to 8.
  - The factor scales the wall-clock analysis limits: the per-website analysis allocation, the parser's time slices and limits, the reconstructed-view inspection, and the detector's isolated inspection, engine run, Gitleaks timeout and decoded-view enumeration.
  - Memory limits and a scan's duration limits never scale.
  - Reports show it as `analysis.timeFactor`, and a stated limit names the scaled time. See [docs/LINUX.md](docs/LINUX.md#analysis-time-on-slow-machines).

## Chrome's own service connections

Chrome contacts four hosts by itself after launch: accounts.google.com, android.clients.google.com, update.googleapis.com and www.google.com. When no page, frame or worker requested that host, the connection is still denied at the proxy and listed as a browser background connection. It no longer makes the scan incomplete, so a browser scan that 2.7 ended `incomplete` only because of these connections now completes. A page's own request to one of these hosts, and any other unattributed browser traffic, is handled as in 2.7. `doctor --runtime` follows the same rule.

## Fixes

These were found by the Linux CI runs. Each has a regression test where the cause was in the product.

- **Isolated inspection before the first scan.** A detector used before any scan had measured the time factor used the unmeasured default, so on a slow computer its isolated large-text inspection could run out of time. The detector now waits for the one bounded measurement before its first inspection (`src/detectors.ts`, `test/machine-speed.test.ts`).
- **Queue wait no longer charged.** Time spent waiting for a free parser worker or for analysis memory was charged to the per-website analysis allocation. On a 2-CPU computer this could leave a large script unparsed and miss a key reconstructed from its constants. Only the time spent holding a worker is charged now; the wait is reported separately as `queueWaitMs` (`src/semantic.ts`, `src/scanner.ts`, `test/lifecycle.test.ts`).
- **Time limits at the deadline.** On Linux, Node.js can run a timer up to about 1 ms early. A request whose own timeout fell at the scan's deadline could then end the run as `discovered-frontier-drained` instead of `duration-limit`. A wait that a scan's or website's time limit cuts short now expires that limit itself (`Transport.limitTimer` for the DNS, request and browser session timers; `src/transport.ts`, `src/browser.ts`, `test/repair.test.ts`). See [docs/LINUX.md](docs/LINUX.md#time-limits-and-the-end-of-a-run).
- **Late browser captures.** A script that Chromium parsed after the browser cleanup had started could still be under analysis when the run ended, leaving the run incomplete. The capture window now closes when the cleanup begins, and every capture started is awaited (`src/browser.ts`, `test/completeness-browser.test.ts`).
- **One timer per request.** A request had its own timer and its connection's idle timer, both of the same length. When the event loop ran late, the connection's timer could run first, and a request that was never answered ended as `connection-timeout`. One timer now covers connecting, TLS, sending and the answer. A connect or TLS hang therefore ends as `request-timeout`, with the phase (`connect` or `tls`) in the request's timings; `connection-timeout` stays a known code for older reports (`src/transport.ts`, `test/repair.test.ts`).
- **Scan limit first, one clock reading.** When a scan's and a website's time limits are both reached, the scan's limit is the one that ends the wait, and a website limit timer that runs before the clock reads its limit waits for the time left. Every time-limit check now reads the scan's and the website's clocks at one instant; read a fraction of a millisecond apart, a website's limit could look reached while the scan's was not (`src/transport.ts`, `src/origin-control.ts`, `test/repair.test.ts`).
- **Browser entry document first.** A website's optional pages, baseline, deployment and low-value work now wait while its browser page is starting and until that page's top-level document has been answered or failed. Before, this order held only by timing. Essential work (entry pages, scripts, configuration, source maps, discovery) and other websites never wait (`src/scanner.ts`, `src/browser.ts`).
- **Stopped finding-triage worker.** When the shared triage worker errors or exits, every scan using it sorts its findings in the scan process and reports `finding-triage-worker` once; a scan that starts later gets a new worker (`src/finding-triage.ts`, `test/mass-scale.test.ts`).
- **Page-leave requests.** The browser ran a page's page-leave handlers a second time when the browser context closed, after routing had stopped; on Linux, Chromium sent the beacons and keep-alive requests they started to the deny proxy, which refused them (nothing reached the target). A guard in each document now stops that second run, and the routed page-leave drain covers every frame as well as the page (`src/browser.ts`, `test/privacy-browser.test.ts`). See [docs/LINUX.md](docs/LINUX.md#page-leave-requests).
- **Resume check and help.**
  - The `--state` settings fingerprint now covers the contents of a `--config` settings template.
  - The help says that with `--targets`, `--format md` writes one draft per target. It also says that Markdown drafts are masked unless `--full-secrets` is given, which unmasks only files on disk.
  - The wiring example in docs/RECON.md uses the per-scan detector scope.
- **Tests only.**
  - The dashboard download test paces its downloads around Chromium's limit of 10 downloads a second.
  - The submission test waits for the opened run before opening its findings.
  - A browser assertion carries a masked diagnostic.

## Documentation

- New: [MIGRATION_2.8.md](MIGRATION_2.8.md), [docs/PROGRAM.md](docs/PROGRAM.md), [docs/MASS_SCAN.md](docs/MASS_SCAN.md), [docs/RECON.md](docs/RECON.md), [docs/SUBMISSION.md](docs/SUBMISSION.md) and [docs/LINUX.md](docs/LINUX.md). They ship in both the Windows and the Linux package.
- README has a "Bug bounty quick start", and USER_GUIDE has a "Bug bounty workflow (2.8.0)" section. Both were checked against the code and `--help`.
- [docs/JSONL.md](docs/JSONL.md) adds the `out-of-scope` rejection reason and the fields above, including `target-end.sharedWaitMs` and, in mass mode, `summary.effectiveConcurrency`, `summary.sharedWaitMs` and `summary.memory`.
- [SECURITY.md](SECURITY.md): "There is no bug bounty." now reads "We don't offer paid rewards for reports about Exposure Desk itself." This is a wording change in the documentation only.

## Development and release tooling

These change how the product is built, tested and measured, not the scan options or their results.

- `scripts/package-linux.mjs` builds the Linux x64 package from the shared release file list. `scripts/docker-smoke.mjs` checks the container image, and `scripts/fetch-linux-distributions.mjs` downloads the pinned Linux runtime pieces and checks them against `scripts/linux-distributions.json`. `scripts/packaged-smoke.mjs` and `scripts/packaged-analysis-check.mjs` also cover linux-x64.
- `scripts/mass-scan-measure.mjs` measures mass runs against loopback fixtures only. It records wall time, requests per second, peak memory, the shared analysis budget, each target's final state and stop reason, resume and the block halt (`benchmarks/2.8.0/mass-scan.json`).
- `scripts/release-summary.mjs`:
  - can reuse a previous release's recorded legacy-evaluation side, naming its source
  - reports the mass-scan measurement and the Linux package
  - names the platforms that were exercised
