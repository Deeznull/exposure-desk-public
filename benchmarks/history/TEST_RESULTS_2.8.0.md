# Actual verification — 2.8.0

Build 2.8.0+cc5fecf8cb75f1c7. Windows x64 with the bundled Node 24.18.1, locked dependencies, Gitleaks 8.30.1 and Chrome for Testing 153.0.8010.12 / Playwright 1.63.0. Rules website/2.8.0; structural data checks exposure/1.0. Ready options, limits and traffic: [UPGRADE_2.6.md](UPGRADE_2.6.md); data upgrade: [MIGRATION_2.8.md](MIGRATION_2.8.md); changes: [CHANGELOG_2.8.md](CHANGELOG_2.8.md).

| Final check | Actual result |
| --- | --- |
| Nonbrowser regressions | 654/654 passed, 0 failed or skipped; 1081.1 s |
| Browser and UI regressions | 40/40 passed, 0 failed or skipped; 412.7 s |
| Repeated Chromium cancellation stress | 60/60 passed; 217.6 s |
| CLI child processes | 4 exit/masking checks passed |
| Protected persistence (temporary data directory) | projectRestart, correlationRestart, vaultRestart, operatorPermissions, deletion |
| Selected provider corpus (pinned engine) | 130/130 targets; 0 false positives; 0 component / 0 location errors |
| Full acquisition pipeline | passed; 17/17 fixtures |
| Ready options on local fixtures | 191/191 acceptance checks met over 57 scans (below) |
| Release preflight | passed (earlier release archive hashes, baseline parity, pinned runtime/detector/browser, wordlist and corpus digests) |
| Target lists at scale (loopback fixtures) | 4 runs at 1, 4, 16 and 64 targets at once (64 with a program file), 200 targets each; every target completed; one shared analysis budget of 256 MiB per run, never exceeded; resume after output reader closed and after forced process kill: no finished target scanned again; block fixture: halted after 18 of 200 targets; 0 non-loopback connections (below) |
| Linux x64 on GitHub-hosted Ubuntu runners (workflow run 38245758795, commit eb2f953) | nonbrowser regressions 653/654 passed, 1 skipped; browser and UI regressions 40/40 passed; package job success (builds `Exposure Desk 2.8.0 Linux x64.tar.gz` and runs the packaged smoke on the extracted package); container job success (image build and smoke); artifact SHA-256 `5f515d98ccbb3f37…`, checksum file verified after download |
| Extracted Windows package smoke | 13/13 checks on the extracted Windows x64 ZIP: manifest hashes, launcher path with spaces, port conflict, protected persistence, existing instance, authenticated demo, masked defaults, deliberate reveal, cancel, shutdown, restart, analysis processes (parser and large-text processes started with the bundled `runtime\node.exe`, none running after the scan) and no package process left (`benchmarks/2.8.0/packaged-smoke.json`) |

**Browser suite runs on this build.** Both full runs of the browser suite on build 2.8.0+cc5fecf8cb75f1c7 on this computer passed: the sanity run (w5-fix's final Windows run on commit b941d3c, whose build digest equals this build; reused, not run again: 40/40, 407.5 s) and the final run after the measurements (40/40, 412.7 s; the row above). Record of every run: `benchmarks/2.8.0/browser-attempts.json`.

**Linux CI runs on this build.** Four linux.yml runs on this build digest passed every job. The row above is the release run on the final documentation commit (eb2f953): 653/654 nonbrowser tests (the Windows-only ACL test skipped) and 40/40 browser and UI tests, and its package job built the shipped `Exposure Desk 2.8.0 Linux x64.tar.gz` (265,927,767 bytes, SHA-256 `5f515d98ccbb3f37f6c6dde356a96488c3d8662f9292e378ef810efc146de008`, downloaded and checked against its .sha256 file). The Linux measurement is the two earliest runs: runs 38197793573 and 38199247582 on the w5-fix commit b941d3c, whose build digest equals this build, each passed 653/654 nonbrowser tests (the Windows-only ACL test skipped) and 40/40 browser and UI tests, built the Linux x64 package and passed its packaged smoke test on the runner, and built and smoke-tested the container image. Run 38241561896 on commit 1e6dd0f also passed 653/654 nonbrowser tests (the Windows-only ACL test skipped) and 40/40 browser and UI tests, built the Linux x64 package and passed its packaged smoke test, and built and smoke-tested the container image; its package (SHA-256 `2b804b1b55b87f10fd240059a393e36410a065745db467be9924de228a96c2a9`) is superseded and not shipped, because the delivery note RELEASE_PACKAGE.md was rewritten for 2.8.0 after it. Record: `benchmarks/2.8.0/linux-ci.json`.

## Machine state during the measurements

Sampled while the measurements ran, by a sampler outside the project: CPU load over all logical processors every 5 s (the measurement itself included; "before" is the 10 s idle window ahead of each step), free physical memory every 5 s, and the power source (BatteryStatus.PowerOnline) and battery charge every 60 s and at each step change. A sample belongs to the step whose start and end contain it; two steps that waited for the measurement limiter start when it let them run, so they have no idle window before them. The sanity suites are not listed: they are w5-fix's final Windows runs on the same build digest (reused). The 2.7.0 side of the matrix ran partly under outside load (about 07:42–08:04: CPU at 99 % for minutes, free memory down to 3.2 GB; not part of this project); the 6 rows measured then were run again alone (the next step), and those reruns replace them. The first run of external pair 1 is listed although it was measured again: from about 10:12 an unrelated program kept the CPU at 98–100 % and free memory below 10 GB, and the computer ran on battery for part of it; its results were equal but its times were not used. From then on every step waited for 2 minutes below 50 % CPU with at least 11000 MiB free before it started, and none of them saw CPU at 95 % or more or less than 10000 MiB free. 16 logical processors, 31.3 GiB memory. Not on AC power during every step (see Power). Complete data: `benchmarks/2.8.0/machine-state.json`.

| Step | Duration | Power | CPU load before / median / highest | Least free memory |
| --- | --- | --- | --- | --- |
| Mass scan (loopback fixtures) | 76.8 min | AC (battery at least 100 %) | 6 % / 12 % / 48 % | 9.5 GiB |
| Cancellation stress (20 passes) | 3.6 min | AC (battery at least 100 %) | 6 % / 21 % / 32 % | 11.1 GiB |
| CLI smoke | 0.1 min | AC (battery at least 100 %) | 12 % / 10 % / 10 % | 12.2 GiB |
| Persistence smoke | 0.2 min | AC (battery at least 100 %) | 5 % / 10 % / 14 % | 12.3 GiB |
| Provider corpus benchmark | 0.4 min | AC (battery at least 100 %) | 7 % / 14 % / 17 % | 12.2 GiB |
| Pipeline self-test | 0.2 min | AC (battery at least 100 %) | 6 % / 20 % / 23 % | 11.6 GiB |
| Legacy 2.4 corpora, 2.8.0 | 0.1 min | AC (battery at least 100 %) | 10 % / 10 % / 10 % | 12.2 GiB |
| Dynamic application, 2.8.0 | 0.1 min | AC (battery at least 100 %) | 9 % / 14 % / 14 % | 11.5 GiB |
| Frozen 2.5 corpus, legacy settings (3 repetitions) | 5.6 min | AC (battery at least 100 %) | 8 % / 15 % / 36 % | 10.9 GiB |
| Matrix spot check (6 reused 2.7.0 rows) | 10.2 min | AC (battery at least 100 %) | 8 % / 25 % / 53 % | 10.1 GiB |
| Ready-option matrix, 2.7.0 side (full rerun after spot check) | 60.7 min | AC (battery at least 100 %) | 11 % / 20 % / 100 % | 3.2 GiB |
| Ready-option matrix, 2.7.0 rows measured under outside load, rerun | 16.9 min | AC (battery at least 100 %) | n/a / 13 % / 33 % | 14.7 GiB |
| Ready-option matrix | 64.2 min | AC (battery at least 99 %) | n/a / 10 % / 42 % | 11.0 GiB |
| External corpus pair 1 (2-wide, under outside load; measured again below): 2:standard:low-impact:discovery 3:deep:low-impact:discovery | 31.7 min | AC, battery (battery at least 86 %) | 8 % / 17 % / 100 % | 5.7 GiB |
| Focused bundle mirror check (quiet machine; mirror-check.json) | 2.0 min | AC (battery at least 92 %) | 7 % / 17 % / 36 % | 12.3 GiB |
| External corpus pair 1 (2-wide, quiet machine): 2:standard:low-impact:discovery 3:deep:low-impact:discovery | 30.7 min | AC (battery at least 92 %) | 14 % / 6 % / 45 % | 10.0 GiB |
| External corpus pair 2 (2-wide, quiet machine): 3:deep:low-impact:acquisition 3:deep:normal:acquisition | 28.5 min | AC (battery at least 98 %) | 9 % / 17 % / 37 % | 10.3 GiB |
| External corpus pair 3 (2-wide, quiet machine): 2:standard:low-impact:acquisition 1:quick:low-impact:acquisition | 21.3 min | AC (battery at least 100 %) | 6 % / 7 % / 27 % | 12.6 GiB |
| External corpus pair 4 (2-wide, quiet machine): 1:quick:low-impact:discovery 2:standard:normal:acquisition | 15.7 min | AC (battery at least 100 %) | 11 % / 16 % / 33 % | 11.3 GiB |
| External corpus pair 5 (2-wide, quiet machine): 2:standard:normal:discovery 3:deep:normal:discovery | 11.9 min | AC (battery at least 100 %) | 11 % / 20 % / 54 % | 11.9 GiB |
| External corpus pair 6 (2-wide, quiet machine): 1:quick:normal:discovery 1:quick:normal:acquisition | 4.7 min | AC (battery at least 100 %) | 11 % / 14 % / 27 % | 13.0 GiB |
| Frozen 2.5 corpus G5 memory recheck (5 repetitions) | 1.7 min | AC (battery at least 100 %) | 11 % / 23 % / 27 % | 13.2 GiB |
| Screenshots (regenerated, compared with docs/screenshots) | 1.2 min | AC (battery at least 100 %) | 14 % / 18 % / 27 % | 12.6 GiB |
| Nonbrowser suite (final) | 18.1 min | AC (battery at least 100 %) | 10 % / 13 % / 38 % | 13.1 GiB |
| Browser suite (final) | 6.9 min | AC (battery at least 100 %) | 14 % / 18 % / 34 % | 12.6 GiB |

## Ready options on local fixtures

`scripts/profile-matrix.mjs` (plan §5), 2026-10-12: each of the six ready options as shipped, one scan per child process, on HTTPS loopback fixtures with synthetic, nonfunctional keys and an egress tripwire — a single site (8 keys: inline page, script, source map, split module, .env, configuration file, a depth-3 and a depth-5 page; plus an all-X placeholder decoy), a 1,252,570-byte bundle site (7 keys and a mutated decoy) and 3 or 10 subdomains of one registrable domain (single-site copies). Baseline: the 2.7.0 Windows x64 release ZIP, extracted and run with the same six ready options (rows labelled 2.7.0; "Keeps the 2.7.0 recall" compares each source-build row with the same option and fixture there). The fixture server counts requests, TCP connections, TLS handshakes and wire bytes; browser navigations, coverage and findings come from the scan record; peak RSS is the scan process (Chromium excluded); the analysis heap column lists, for builds that run the parser and the large-text checks in analysis processes, each role's processes × heap limit (the V8 old-space limit, held from the analysis memory setting) and the most heap limit held at once, and for earlier builds the parser worker's V8 heap high-water mark / limit sampled every 25 ms; the analysis-process RSS column is an upper bound on those processes' combined peak RSS (each process's own peak, summed over the processes alive at once), which is not part of the scan process's peak RSS. "In scope" is what each option's stated boundary reaches (Quick: entry documents and their files; Standard: depth 3; Deep: depth 5). Precision counts credential findings that match a planted key. "-small" runs inject a computer with 2 cores and 1 GiB free memory. Complete data: `benchmarks/2.8.0/matrix.json` and `matrix.md`.

| Run | Option | Fixture | State | Time s | Requests | TCP | TLS | Wire MiB | Browser nav | Peak RSS MiB | Analysis heap MiB (worker peak/limit, or processes×limit) | Analysis processes RSS MiB (bound) | Acquisition | Analysis | Recall (in scope) | Precision (credential findings) | Est. conns |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 2.7.0 | quick+normal | single×1 | completed (quick-coverage) | 16.4 | 25 | 25 | 25 | 0.11 | 0 | 165 | parser 1×256; ≤256 at once | 54 | 100% | 100% | 6/8  (6 expected) | 6/6 | — |
| 2.7.0 | quick+low-impact | single×1 | completed (quick-coverage) | 49.7 | 25 | 1 | 1 | 0.02 | 0 | 163 | parser 1×256; ≤256 at once | 54 | 100% | 100% | 6/8  (6 expected) | 6/6 | — |
| 2.7.0 | standard+normal | single×1 | incomplete | 42.6 | 50 | 50 | 50 | 0.22 | 5 | 180 | parser 1×128; ≤128 at once | 58 | 70% | 127% | 7/8  (7 expected) | 7/7 | — |
| 2.7.0 | standard+low-impact | single×1 | incomplete | 80.0 | 40 | 1 | 1 | 0.03 | 3 | 170 | parser 1×128; ≤128 at once | 57 | 65% | 133% | 7/8  (7 expected) | 7/7 | — |
| 2.7.0 | deep+normal | single×1 | incomplete | 81.3 | 61 | 61 | 61 | 0.27 | 10 | 182 | parser 1×256; ≤256 at once | 57 | 73% | 126% | 8/8  (8 expected) | 8/8 | — |
| 2.7.0 | deep+low-impact | single×1 | incomplete | 100.7 | 47 | 3 | 3 | 0.04 | 6 | 171 | parser 1×256; ≤256 at once | 57 | 69% | 131% | 8/8  (8 expected) | 8/8 | — |
| 2.7.0 | quick+normal | bundle×1 | incomplete | 20.3 | 29 | 29 | 29 | 1.32 | 0 | 248 | parser 2×256, detector 1×108; ≤256 at once | 233 | 100% | 100% | 7/7  (7 expected) | 7/7 | — |
| 2.7.0 | quick+low-impact | bundle×1 | incomplete | 59.4 | 29 | 1 | 1 | 1.21 | 0 | 247 | parser 2×256, detector 1×108; ≤256 at once | 233 | 100% | 100% | 7/7  (7 expected) | 7/7 | — |
| 2.7.0 | standard+normal | bundle×1 | incomplete | 29.7 | 41 | 41 | 41 | 2.57 | 1 | 314 | parser 3×128/256, detector 1×108; ≤256 at once | 291 | 66% | 137% | 7/7  (7 expected) | 7/7 | — |
| 2.7.0 | standard+low-impact | bundle×1 | incomplete | 73.4 | 37 | 1 | 1 | 2.42 | 1 | 293 | parser 3×128/256, detector 1×108; ≤256 at once | 289 | 63% | 142% | 7/7  (7 expected) | 7/7 | — |
| 2.7.0 | deep+normal | bundle×1 | incomplete | 26.8 | 41 | 41 | 41 | 2.57 | 1 | 313 | parser 1×256, detector 1×108; ≤364 at once | 394 | 66% | 137% | 7/7  (7 expected) | 7/7 | — |
| 2.7.0 | deep+low-impact | bundle×1 | incomplete | 73.7 | 37 | 1 | 1 | 2.42 | 1 | 291 | parser 1×256, detector 1×108; ≤364 at once | 397 | 63% | 142% | 7/7  (7 expected) | 7/7 | — |
| 2.7.0 | quick+normal | multi×3 | completed (quick-coverage) | 39.3 | 75 | 75 | 75 | 0.33 | 0 | 169 | parser 1×256; ≤256 at once | 58 | 100% | 100% | 18/24  (18 expected) | 18/18 | — |
| 2.7.0 | quick+low-impact | multi×3 | completed (quick-coverage) | 100.5 | 75 | 3 | 3 | 0.05 | 0 | 165 | parser 1×256; ≤256 at once | 55 | 100% | 100% | 18/24  (18 expected) | 18/18 | — |
| 2.7.0 | standard+normal | multi×3 | incomplete | 83.2 | 148 | 148 | 148 | 0.66 | 15 | 204 | parser 2×128; ≤256 at once | 111 | 81% | 115% | 21/24  (21 expected) | 21/21 | — |
| 2.7.0 | standard+low-impact | multi×3 | incomplete | 162.0 | 118 | 5 | 5 | 0.09 | 9 | 175 | parser 2×128; ≤256 at once | 114 | 78% | 119% | 21/24  (21 expected) | 21/21 | — |
| 2.7.0 | deep+normal | multi×3 | incomplete | 130.9 | 183 | 183 | 183 | 0.82 | 30 | 210 | parser 2×256; ≤512 at once | 114 | 82% | 116% | 24/24  (24 expected) | 24/24 | — |
| 2.7.0 | deep+low-impact | multi×3 | incomplete | 198.3 | 141 | 9 | 9 | 0.12 | 18 | 205 | parser 2×256; ≤512 at once | 115 | 80% | 118% | 24/24  (24 expected) | 24/24 | — |
| 2.7.0 | quick+normal | multi×10 | completed (quick-coverage) | 104.7 | 250 | 250 | 250 | 1.13 | 0 | 203 | parser 1×256; ≤256 at once | 57 | 100% | 100% | 60/80  (60 expected) | 60/60 | — |
| 2.7.0 | quick+low-impact | multi×10 | completed (quick-coverage) | 255.2 | 250 | 10 | 10 | 0.17 | 0 | 165 | parser 1×256; ≤256 at once | 57 | 100% | 100% | 60/80  (60 expected) | 60/60 | — |
| 2.7.0 | standard+normal | multi×10 | incomplete | 247.2 | 494 | 494 | 494 | 2.26 | 50 | 281 | parser 2×128; ≤256 at once | 115 | 86% | 111% | 70/80  (70 expected) | 70/70 | — |
| 2.7.0 | standard+low-impact | multi×10 | incomplete | 420.2 | 390 | 18 | 18 | 0.29 | 30 | 212 | parser 2×128; ≤256 at once | 114 | 83% | 113% | 70/80  (70 expected) | 70/70 | — |
| 2.7.0 | deep+normal | multi×10 | incomplete | 298.3 | 529 | 529 | 529 | 2.42 | 50 | 281 | parser 2×256; ≤512 at once | 113 | 87% | 111% | 80/80  (80 expected) | 80/80 | — |
| 2.7.0 | deep+low-impact | multi×10 | incomplete | 567.5 | 450 | 28 | 28 | 0.37 | 50 | 217 | parser 2×256; ≤512 at once | 113 | 87% | 112% | 80/80  (80 expected) | 80/80 | — |
| 2.8 | quick+normal | single×1 | completed (quick-coverage) | 13.1 | 25 | 25 | 25 | 0.11 | 0 | 186 | parser 1×256; ≤256 at once | 56 | 100% | 100% | 6/8  (6 expected) | 6/6 | — |
| 2.8 | quick+low-impact | single×1 | completed (quick-coverage) | 49.1 | 25 | 1 | 1 | 0.02 | 0 | 185 | parser 1×256; ≤256 at once | 56 | 100% | 100% | 6/8  (6 expected) | 6/6 | — |
| 2.8 | standard+normal | single×1 | incomplete | 38.9 | 49 | 49 | 49 | 0.22 | 5 | 201 | parser 1×128; ≤128 at once | 60 | 70% | 127% | 7/8  (7 expected) | 7/7 | — |
| 2.8 | standard+low-impact | single×1 | incomplete | 79.3 | 40 | 1 | 1 | 0.03 | 3 | 188 | parser 1×128; ≤128 at once | 59 | 65% | 133% | 7/8  (7 expected) | 7/7 | — |
| 2.8 | deep+normal | single×1 | incomplete | 78.9 | 61 | 61 | 61 | 0.27 | 10 | 199 | parser 1×256; ≤256 at once | 59 | 73% | 126% | 8/8  (8 expected) | 8/8 | — |
| 2.8 | deep+low-impact | single×1 | incomplete | 100.2 | 47 | 3 | 3 | 0.04 | 6 | 189 | parser 1×256; ≤256 at once | 59 | 69% | 131% | 8/8  (8 expected) | 8/8 | — |
| 2.8 | quick+normal | bundle×1 | incomplete | 15.6 | 29 | 29 | 29 | 1.32 | 0 | 260 | parser 2×256, detector 1×108; ≤256 at once | 233 | 100% | 100% | 7/7  (7 expected) | 7/7 | — |
| 2.8 | quick+low-impact | bundle×1 | incomplete | 57.6 | 29 | 1 | 1 | 1.21 | 0 | 248 | parser 2×256, detector 1×108; ≤256 at once | 234 | 100% | 100% | 7/7  (7 expected) | 7/7 | — |
| 2.8 | standard+normal | bundle×1 | incomplete | 21.3 | 41 | 41 | 41 | 2.57 | 1 | 334 | parser 3×128/256, detector 1×108; ≤256 at once | 291 | 66% | 137% | 7/7  (7 expected) | 7/7 | — |
| 2.8 | standard+low-impact | bundle×1 | incomplete | 73.3 | 37 | 1 | 1 | 2.42 | 1 | 295 | parser 3×128/256, detector 1×108; ≤256 at once | 289 | 63% | 142% | 7/7  (7 expected) | 7/7 | — |
| 2.8 | deep+normal | bundle×1 | incomplete | 23.6 | 41 | 41 | 41 | 2.57 | 1 | 310 | parser 1×256, detector 1×108; ≤364 at once | 397 | 66% | 137% | 7/7  (7 expected) | 7/7 | — |
| 2.8 | deep+low-impact | bundle×1 | incomplete | 73.2 | 37 | 1 | 1 | 2.42 | 1 | 295 | parser 1×256, detector 1×108; ≤364 at once | 397 | 63% | 142% | 7/7  (7 expected) | 7/7 | — |
| 2.8 | quick+normal | multi×3 | completed (quick-coverage) | 14.4 | 75 | 75 | 75 | 0.33 | 0 | 206 | parser 1×256; ≤256 at once | 57 | 100% | 100% | 18/24  (18 expected) | 18/18 | — |
| 2.8 | quick+low-impact | multi×3 | completed (quick-coverage) | 99.9 | 75 | 3 | 3 | 0.05 | 0 | 184 | parser 1×256; ≤256 at once | 58 | 100% | 100% | 18/24  (18 expected) | 18/18 | — |
| 2.8 | standard+normal | multi×3 | incomplete | 46.8 | 147 | 147 | 147 | 0.66 | 15 | 207 | parser 2×128; ≤256 at once | 119 | 81% | 115% | 21/24  (21 expected) | 21/21 | — |
| 2.8 | standard+low-impact | multi×3 | incomplete | 158.6 | 118 | 5 | 5 | 0.09 | 9 | 195 | parser 2×128; ≤256 at once | 117 | 78% | 119% | 21/24  (21 expected) | 21/21 | — |
| 2.8 | deep+normal | multi×3 | incomplete | 107.6 | 183 | 183 | 183 | 0.82 | 30 | 211 | parser 2×256; ≤512 at once | 118 | 82% | 116% | 24/24  (24 expected) | 24/24 | — |
| 2.8 | deep+low-impact | multi×3 | incomplete | 199.1 | 141 | 10 | 10 | 0.12 | 18 | 194 | parser 2×256; ≤512 at once | 117 | 80% | 118% | 24/24  (24 expected) | 24/24 | — |
| 2.8 | quick+normal | multi×10 | completed (quick-coverage) | 31.5 | 250 | 250 | 250 | 1.13 | 0 | 215 | parser 1×256; ≤256 at once | 58 | 100% | 100% | 60/80  (60 expected) | 60/60 | — |
| 2.8 | quick+low-impact | multi×10 | completed (quick-coverage) | 258.5 | 250 | 10 | 10 | 0.17 | 0 | 185 | parser 1×256; ≤256 at once | 57 | 100% | 100% | 60/80  (60 expected) | 60/60 | — |
| 2.8 | standard+normal | multi×10 | incomplete | 168.2 | 490 | 490 | 490 | 2.24 | 50 | 278 | parser 2×128; ≤256 at once | 118 | 86% | 111% | 70/80  (70 expected) | 70/70 | — |
| 2.8 | standard+low-impact | multi×10 | incomplete | 417.3 | 390 | 18 | 18 | 0.29 | 30 | 215 | parser 2×128; ≤256 at once | 116 | 83% | 113% | 70/80  (70 expected) | 70/70 | — |
| 2.8 | deep+normal | multi×10 | incomplete | 223.4 | 529 | 529 | 529 | 2.42 | 50 | 279 | parser 2×256; ≤512 at once | 116 | 87% | 111% | 80/80  (80 expected) | 80/80 | — |
| 2.8 | deep+low-impact | multi×10 | incomplete | 577.7 | 450 | 29 | 29 | 0.37 | 50 | 219 | parser 2×256; ≤512 at once | 117 | 87% | 112% | 80/80  (80 expected) | 80/80 | — |
| 2.8-small | quick+normal | bundle×1 | incomplete | 15.8 | 29 | 29 | 29 | 1.32 | 0 | 256 | parser 2×256, detector 1×108; ≤256 at once | 233 | 100% | 100% | 7/7  (7 expected) | 7/7 | — |
| 2.8-small | quick+low-impact | bundle×1 | incomplete | 57.8 | 29 | 1 | 1 | 1.21 | 0 | 250 | parser 2×256, detector 1×108; ≤256 at once | 234 | 100% | 100% | 7/7  (7 expected) | 7/7 | — |
| 2.8-small | standard+normal | bundle×1 | incomplete | 22.3 | 41 | 41 | 41 | 2.57 | 1 | 311 | parser 2×256, detector 1×108; ≤256 at once | 233 | 66% | 137% | 7/7  (7 expected) | 7/7 | — |
| 2.8-small | standard+low-impact | bundle×1 | incomplete | 73.6 | 37 | 1 | 1 | 2.42 | 1 | 293 | parser 2×256, detector 1×108; ≤256 at once | 234 | 63% | 142% | 7/7  (7 expected) | 7/7 | — |
| 2.8-small | deep+normal | bundle×1 | incomplete | 23.7 | 41 | 41 | 41 | 2.57 | 1 | 310 | parser 2×256, detector 1×108; ≤256 at once | 233 | 66% | 137% | 7/7  (7 expected) | 7/7 | — |
| 2.8-small | deep+low-impact | bundle×1 | incomplete | 73.2 | 37 | 1 | 1 | 2.42 | 1 | 293 | parser 2×256, detector 1×108; ≤256 at once | 233 | 63% | 142% | 7/7  (7 expected) | 7/7 | — |
| 2.8-small | quick+normal | multi×10 | completed (quick-coverage) | 31.3 | 250 | 250 | 250 | 1.13 | 0 | 216 | parser 1×256; ≤256 at once | 58 | 100% | 100% | 60/80  (60 expected) | 60/60 | — |
| 2.8-small | standard+normal | multi×10 | incomplete | 266.5 | 490 | 490 | 490 | 2.25 | 50 | 276 | parser 1×256; ≤256 at once | 61 | 86% | 111% | 70/80  (70 expected) | 70/70 | — |
| 2.8-small | deep+normal | multi×10 | incomplete | 335.8 | 520 | 520 | 520 | 2.38 | 50 | 282 | parser 1×256; ≤256 at once | 59 | 88% | 110% | 80/80  (80 expected) | 80/80 | — |

### Recorded resource use

| Option (websites at once / browser websites / analysis memory / workers) | This computer, 1 website | Small computer, 1 website | This computer, 3 websites | Small computer, 3 websites | This computer, 10 websites | Small computer, 10 websites |
|---|---|---|---|---|---|---|
| quick+normal | 1 / 0 / 256 MiB / 1 | 1 / 0 / 256 MiB / 1 | 3 / 0 / 256 MiB / 1 | 3 / 0 / 256 MiB / 1 | 6 / 0 / 256 MiB / 1 | 6 / 0 / 256 MiB / 1 |
| quick+low-impact | 1 / 0 / 256 MiB / 1 | 1 / 0 / 256 MiB / 1 | 2 / 0 / 256 MiB / 1 | 2 / 0 / 256 MiB / 1 | 2 / 0 / 256 MiB / 1 | 2 / 0 / 256 MiB / 1 |
| standard+normal | 1 / 1 / 256 MiB / 2 | 1 / 1* / 256 MiB / 1* | 3 / 2 / 256 MiB / 2 | 3 / 1* / 256 MiB / 1* | 4 / 2 / 256 MiB / 2 | 4 / 1* / 256 MiB / 1* |
| standard+low-impact | 1 / 1 / 256 MiB / 2 | 1 / 1 / 256 MiB / 1* | 2 / 1 / 256 MiB / 2 | 2 / 1 / 256 MiB / 1* | 2 / 1 / 256 MiB / 2 | 2 / 1 / 256 MiB / 1* |
| deep+normal | 1 / 1 / 512 MiB / 2 | 1 / 1* / 256* MiB / 1* | 3 / 2 / 512 MiB / 2 | 3 / 1* / 256* MiB / 1* | 3 / 2 / 512 MiB / 2 | 3 / 1* / 256* MiB / 1* |
| deep+low-impact | 1 / 1 / 512 MiB / 2 | 1 / 1 / 256* MiB / 1* | 2 / 1 / 512 MiB / 2 | 2 / 1 / 256* MiB / 1* | 2 / 1 / 512 MiB / 2 | 2 / 1 / 256* MiB / 1* |

This computer: 16 logical cores, 15.7 GiB free memory when recorded. Small computer: 2 cores and 1 GiB free memory, injected.

### Acceptance targets

| Target | Met | Not met |
| --- | --- | --- |
| Low-impact fewer connections than Normal, requests no more than Normal's | 4/4 | none |
| Low-impact fewer requests and connections than Normal | 8/8 | none |
| Deep+Low-impact keeps Deep+Normal recall | 4/4 | none |
| Quick reports its limits | 8/8 | none |
| Quick fastest | 8/8 | none |
| Within limits | 33/33 | none |
| Finds its keys at its memory setting | 33/33 | none |
| Keeps the 2.7.0 recall | 24/24 | none |
| Adjustment only lowers | 36/36 | none |
| Settings as recorded | 33/33 | none |

**How the matrix was measured on this build.** The 2.7.0 rows are not reused from the first 2.8.0 measurement (w4-release, build 2.8.0+2bcaef072080ae8e, 2.7.0 side measured 2026-10-11). A same-day spot check of 6 of those rows on 2026-10-12 found 2.7.0 standard+normal/multi×10 at 495 requests and connections against the recorded 494 (`benchmarks/2.8.0/matrix-reuse.json`), so the whole 2.7.0 side was measured again before the 2.8 rows. 6 of the 24 2.7.0 rows ran while something outside the measurement loaded the computer (CPU at 99 %, free memory down to 3.2 GB; cause not identified) and were measured again alone; the alone runs are the ones above (`benchmarks/2.8.0/matrix-prev-disturbed.log`; the same check finds every 2.8 and small-computer row clean). No 2.8 row was more than 15 % slower than its 2.7.0 row, so none needed a further same-day 2.7.0 run. The 2.7.0 rows' keys, requests and connections equal the 2026-10-11 measurement (standard+normal/multi×10 back at 494); deep+low-impact/bundle×1 no longer lists the timing-dependent `browser-settle-deadline` gap.

**2.8 rows against the first 2.8.0 measurement.** Keys, states and memory settings are the same in every row. The differences: The standard+normal and deep+normal bundle×1 rows, on both memory settings, no longer list the `debugger-script-size` gap. Chrome reports the bundle (over 128 KiB) to the browser pass, and that copy counts as a verified mirror only when the static analysis has already analysed the same URL; otherwise the gap is recorded, so the gap depends on which finishes first. A focused check on a quiet computer, each scan alone (`benchmarks/2.8.0/mirror-check.json`), showed the same: 2.8 verified the mirror with no gap in 3 of 3 runs (21.2–24.1 s), 2.7.0 recorded the gap in 2 of 2 (25.2–25.9 s), and every run found 7 of 7 planted keys. In an earlier attempt while another program kept the CPU at 98–100 %, 2.8 recorded the gap as well, so this is timing, not a change in what is checked. The standard+low-impact and deep+low-impact bundle×1 rows no longer list `browser-settle-deadline`, which depends on timing (2.7.0's deep+low-impact bundle row lost it between its two measurements too). Standard+normal/multi×10 made 490 requests and connections (first measurement 495; small-computer setting 490, first measurement 487; 2.7.0 494 and 495 on the same day): how many subresources each page's browser pass loads before its settle deadline varies from run to run. Low-impact standard/multi×10 opened 18 TCP connections (first measurement 17, 2.7.0 18) and deep/multi×10 29 (first measurement 28, 2.7.0 28): a Low-impact connection closes after 4 s idle (`CONNECTION_IDLE_MS`, unchanged since 2.6), so a pause that ends just after that opens one more. Every connection went to the loopback fixture, 0 egress violations.

## External synthetic corpus per ready option (additional measurement)

Not an acceptance target. Corpus `ExposureDesk/detection-corpus/v2`, written by a separate non-Claude AI and reviewed before use (working notes in `archive/notes/HANDOFF_EXTERNAL_CORPUS.md`, not packaged); pinned manifest `ef9187db6d80638d…` and scorer `5e01b10ec2d8e42e…`, re-hashed before use; 20 sites, 27 private values, 402 negative controls. Each site is served from 127.0.0.1 over HTTP and scanned with exact-origin scope and an egress tripwire; the JSON report is scored by the corpus's own scorer. The corpus stays outside the project and is never packaged. Counts describe this corpus only.

| Option | Mode | True / false positives / false negatives | Precision | Recall | Negative-control alerts | Requests | Scan time | Site states |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| quick+low-impact | acquisition | 27 / 3 / 0 | 0.900 | 1 | 3 | 526 | 17.2 min | incomplete 17, completed 3 |
| quick+low-impact | discovery | 24 / 3 / 3 | 0.889 | 0.889 | 3 | 474 | 15.7 min | incomplete 19, completed 1 |
| quick+normal | acquisition | 27 / 3 / 0 | 0.900 | 1 | 3 | 526 | 4.6 min | incomplete 17, completed 3 |
| quick+normal | discovery | 24 / 3 / 3 | 0.889 | 0.889 | 3 | 474 | 4.5 min | incomplete 19, completed 1 |
| standard+low-impact | acquisition | 27 / 3 / 0 | 0.900 | 1 | 3 | 587 | 21.3 min | incomplete 20 |
| standard+low-impact | discovery | 27 / 3 / 0 | 0.900 | 1 | 3 | 921 | 30.6 min | incomplete 20 |
| standard+normal | acquisition | 27 / 3 / 0 | 0.900 | 1 | 3 | 768 | 12.4 min | incomplete 20 |
| standard+normal | discovery | 27 / 3 / 0 | 0.900 | 1 | 3 | 1334 | 11.6 min | incomplete 20 |
| deep+low-impact | acquisition | 27 / 3 / 0 | 0.900 | 1 | 3 | 612 | 28.5 min | incomplete 20 |
| deep+low-impact | discovery | 27 / 3 / 0 | 0.900 | 1 | 3 | 922 | 30.7 min | incomplete 20 |
| deep+normal | acquisition | 27 / 3 / 0 | 0.900 | 1 | 3 | 1067 | 22.7 min | incomplete 20 |
| deep+normal | discovery | 27 / 3 / 0 | 0.900 | 1 | 3 | 1332 | 11.9 min | incomplete 20 |

Every count above, and each site's state, true and false positives, misses, negative-control alerts, classification and acquisition misses, equals the 2.7.0 measurement of the same twelve runs (`benchmarks/2.7.0/external-corpus/`), which equalled 2.6.0-rc.1, and the first 2.8.0 measurement (build 2.8.0+2bcaef072080ae8e). The twelve runs ran two at a time, each pair alone on the computer. The first pair (Standard and Deep audit, Low-impact, from the site root) was measured twice: an unrelated program kept the CPU at 98–100 % during the last minutes of the first run, which had the same results but slower times; the second run is recorded. The gap lists differ from 2.7.0: 2.8.0 records no `unrouted-browser-traffic` gap (160 entries over the 2.7.0 runs), because Chrome's own service connections no longer make a scan incomplete (see CHANGELOG_2.8.md), and 34 of 240 site runs list one timing-dependent gap more or fewer (`browser-page-budget`, `browser-page-http-unavailable`, `debugger-script-size` and `semantic-time-limit`). Requests differed by 1 on 6 site runs and the resource count differed by 1, 2, 3, 6, 7 and 8 on 59 site runs; scan times (run totals) were the same or shorter than on 2.7.0 (up to 4.0 min shorter). 0 egress violations in every run.

## Target lists at scale (mass scan, loopback fixtures)

`scripts/mass-scan-measure.mjs`, 2026-10-12, build 2.8.0+cc5fecf8cb75f1c7, win32 x64, 8-core x86-64 laptop CPU (16 logical processors, 31.3 GiB): the built command line (`exposure-desk scan --targets FILE`) as a user runs it, against 200 synthetic targets on 50 loopback websites (127.0.0.1 to 127.0.0.50, one port); target i is page /t<n> of website i mod 50, so neighbouring targets are different websites. Each page holds its own synthetic, nonfunctional key inline and loads its website's /static/app.js, whose key all targets of that website share (cross-target de-duplication); everything else answers 404. Every run uses quick+normal, `--state`, `--jsonl` and a template that allows exactly the 50 fixture origins; runs at up to 16 targets at once use `--authorized`, the 64 run a program file (authorized, scope = the fixture origins, 50 requests per second, 64 targets and 64 requests at once). An egress tripwire in the scan process refuses and records any socket or DNS lookup outside loopback: 0 recorded. Requests are counted at the fixture; peak RSS is the scan process sampled every 25 ms; the analysis budget is the one memory budget all targets of a run draw from (capacity / highest use / analysis-process heap limits held at once); analysis processes are counted separately from the scan process. Complete data: `benchmarks/2.8.0/mass-scan.json`.

| Run | Targets | At once | Wall time | Requests (per second) | Targets per second | Scan-process peak RSS | Analysis budget: capacity / peak / heap held at once | Analysis processes: started / peak RSS at once | Own keys / shared keys found | Target states |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| c1 | 200 | 1 | 37.9 min | 4400 (1.9) | 0.09 | 185 MiB | 256 / 256 / 256 MiB | 1 / 58 MiB | 200/200 / 50/50 | done 200 (stop reasons: quick-target-set-done 200) |
| c4 | 200 | 4 | 10.3 min | 4400 (7.1) | 0.32 | 297 MiB | 256 / 256 / 256 MiB | 1 / 58 MiB | 200/200 / 50/50 | done 200 (stop reasons: quick-target-set-done 200) |
| c16 | 200 | 16 | 3.9 min | 4400 (18.8) | 0.85 | 363 MiB | 256 / 256 / 256 MiB | 1 / 59 MiB | 200/200 / 50/50 | done 200 (stop reasons: quick-target-set-done 200) |
| program-c64 (program file) | 200 | 64 | 3.4 min | 4400 (21.4) | 0.97 | 319 MiB | 256 / 256 / 256 MiB | 1 / 59 MiB | 200/200 / 50/50 | done 200 (stop reasons: quick-target-set-done 200) |

### Resume after an interrupt

Each run is stopped after 80 of 200 targets have ended (4 at once) and then started again with the same command and `--state` file. "Started again" counts target-start events of the resumed run for targets the state file recorded as done; "pages requested" counts fixture requests for those targets' pages during the resumed run. Analysis processes still alive 5 s after the stop are counted as left behind.

| Interrupt | First run: wall time / targets done in the state file | Resumed run: wall time / skipped | Finished targets started again / their pages requested | All targets accounted for | Own keys found over both runs | Analysis processes left behind |
| --- | --- | --- | --- | --- | --- | --- |
| output reader closed | 4.4 min / 80 | 6.2 min / 80 | 0 / 0 | yes | 200/200 | 0 |
| forced process kill | 4.0 min / 78 | 6.2 min / 78 | 0 / 0 | yes | 200/200 | 0 |

### Block halt

2 of every 5 origins answer every request with HTTP 429 or 403. A run halts when at least 3 targets have finished and at least a quarter of them were blocked; running targets finish and no further target starts. The User-Agent and headers never change and no blocked request is retried.

| Run | Targets | Halted | Scanned / not started | Target states | Requests | User-Agents seen |
| --- | --- | --- | --- | --- | --- | --- |
| block-halt | 200 | blocked | 18 / 182 | blocked 8, done 10, pending 182 | 260 | 1 |

## Legacy settings on the frozen 2.5 corpus (2.7.0 → 2.8.0)

Corpus `scripts/eval-2.5-corpus.mjs`, digest `41f8c2dd214da8bd…`, frozen 2026-10-08T04:15:23.216Z. The 2.5 release corpus, unchanged, run with its own legacy (preset and custom) configurations, none of which names a coverage or traffic level; it checks that such configurations still behave as in the previous release apart from intended detection changes. Each group ran 3× per build in separate child processes with an egress tripwire, alternating builds; the first repetition's measurements are shown and the result is identical across repetitions unless noted in `benchmarks/2.8.0/evaluation.json`. Baseline: 2.7.0+3772c88c496661b5.

| Group · measurement | 2.7.0 | 2.8.0 |
| --- | --- | --- |
| G1 scope · in-domain origins reached, omitted setting | 5/5 | 5/5 |
| G1 scope · in-domain origins reached, explicit domain | 5/5 | 5/5 |
| G1 scope · exact-only opt-out reaches in-domain origins | 0 | 0 |
| G1 scope · third-party/deceptive origins contacted | 0 | 0 |
| G1 scope · private, metadata, mixed-DNS or credential URLs contacted (gate: 0) | 0 | 0 |
| G1 scope · guessed (unreferenced) DNS lookups | 0 | 0 |
| G1 scope · automatic origins with cap 3 | 3 | 3 |
| G1 scope · other github.io tenant contacted | 0 | 0 |
| G2 · requests for bare-extension hints (/.json, /.woff, …) | 0 | 0 |
| G2 · browser pages opened for those hints | 0 | 0 |
| G2 · contextual references fetched (config.json, chunk, worker) | 3/3 | 3/3 |
| G3 · browser navigations to asset hints answered by the SPA shell | 0 | 0 |
| G3 · explicitly requested route navigated | true | true |
| G4 · requests for 12 identical shells, mirrors and base variants | 22 | 22 |
| G4 · findings for the repeated value / occurrences | 1 / 5 | 1 / 5 |
| G5 1,252,570-byte bundle · split key found (engine off / on) | 0/1 / 0/1 | 0/1 / 0/1 |
| G5 · negatives reported (mutated alias, test key, publishable key) | 1 / 1 | 1 / 1 |
| G5 · late import / worker past the first MiB requested | true / true | true / true |
| G5 · non-terminal analyzer states after the run (bundle loaded twice + ?v mirror) | 0 | 0 |
| G6 shortDeadline · non-terminal states / pending inventory rows / state | 0 / 0 / incomplete | 0 / 0 / incomplete |
| G6 cancelAfterDownload · non-terminal states / pending inventory rows / state | 0 / 0 / cancelled | 0 / 0 / cancelled |
| G6 smallSlices · non-terminal states / pending inventory rows / state | 0 / 0 / incomplete | 0 / 0 / incomplete |
| G7 wallets, keys, signing and priority cases · website rules only | 23/23 detected · 0 false positives of 16 negatives · precision 1 · recall 1 | 23/23 detected · 0 false positives of 16 negatives · precision 1 · recall 1 |
| G7 · with the pinned engine | 23/23 detected · 0 false positives of 16 negatives · precision 1 · recall 1 | 23/23 detected · 0 false positives of 16 negatives · precision 1 · recall 1 |
| G7 · expected priority matched | 9/11 | 9/11 |
| G8 · static User-Agent | Mozilla/5.0 (compatible; ExposureDesk/2.7) | Mozilla/5.0 (compatible; ExposureDesk/2.8) |
| G8 · browser language / time zone reported by the page | en-US / UTC | en-US / UTC |
| G8 · headers repeating the page path or query | 0 | 0 |
| G9 · two identical starts 50 ms apart: HTTP statuses / runs created / same run returned | 202, 202 / 1 / true | 202, 202 / 1 / true |

| Group · median wall time per child / peak Node RSS | 2.7.0 | 2.8.0 |
| --- | --- | --- |
| G1 | 1631 ms / 200.9 MiB | 1873 ms / 220.1 MiB |
| G2 | 3742 ms / 196.9 MiB | 4493 ms / 215.5 MiB |
| G3 | 9471 ms / 191.1 MiB | 11624 ms / 221.6 MiB |
| G4 | 2103 ms / 208.2 MiB | 2231 ms / 224.4 MiB |
| G5 | 11374 ms / 417.4 MiB | 7526 ms / 463.9 MiB |
| G6 | 5291 ms / 451.8 MiB | 5020 ms / 453.5 MiB |
| G7 | 18473 ms / 197.9 MiB | 10168 ms / 207.1 MiB |
| G8 | 3827 ms / 200.6 MiB | 4801 ms / 226.1 MiB |
| G9 | 4252 ms / 204.8 MiB | 2955 ms / 218.8 MiB |

2.7.0 legacy-evaluation figures reused from the 2.7.0 release records (owner decision 2026-10-11), not re-measured: the 2.7.0 column is `benchmarks/2.7.0/final-legacy-evaluation.json` and `benchmarks/2.7.0/final-acquisition.json` (build 2.7.0+3772c88c496661b5, measured 2026-10-10, so its elapsed time and peak RSS are not a same-day comparison); the evaluation scripts and their inline corpora are unchanged since that release, and only the 2.8.0 column was measured for this release.

| Legacy 2.4 corpora (unchanged) | 2.7.0 | 2.8.0 |
| --- | --- | --- |
| 48-case detector corpus: credential targets detected / false positives | 13/13 / 0 | 13/13 / 0 |
| Data-exposure targets detected / false positives | 5/5 / 0 | 5/5 / 0 |
| Corpus elapsed / Node peak RSS | 1.916 s / 208.7 MiB | 2.470 s / 208.6 MiB |
| Dynamic application: credential targets / known resources inspected / forbidden arrivals | 5/5 / 9/9 / 0 | 5/5 / 9/9 / 0 |

Limitations: synthetic, nonfunctional values and local fixtures only (loopback servers and a virtual network); every timing and memory figure is from one Windows x64 host (the Linux x64 suites, package and container are pass/fail results from GitHub-hosted Ubuntu runners, without timing claims); single-digit repetitions without statistical controls; Node peak RSS includes worker threads but excludes Chromium, Gitleaks and the analysis child processes (the ready-option table reports the analysis processes separately). Ready-option durations depend on the fixtures' sizes and on this computer; the small-computer rows inject the computer description, they do not run on slower hardware. These counts describe this corpus only and make no general accuracy claim. macOS and ARM were not exercised; Linux x64 only on the CI runners named above. No owner website or production response was contacted or used.
