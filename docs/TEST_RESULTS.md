# Actual verification — 3.0.0

Build 3.0.0+900c631686338160. Windows x64 with the bundled Node 24.18.1, locked dependencies, the pinned offline Gitleaks 8.30.1 and Chrome for Testing 153.0.8010.12 / Playwright 1.63.0. Rules website/3.0.0; structural data checks exposure/1.0. Loopback fixtures and synthetic, nonfunctional keys only; no real website and no real provider endpoint was contacted. The Windows checks ran on the development laptop. GitHub Actions could not run the Linux workflow for this release, so its jobs and the performance matrix ran on a rented Linux server (Ubuntu 24.04); no external host was contacted from it. Changes: [CHANGELOG_3.0.md](releases/CHANGELOG_3.0.md); data upgrade: [MIGRATION_3.0.md](releases/MIGRATION_3.0.md); the earlier run and its laptop performance matrix are the 2.9.1 section below.

| Final check | Actual result |
| --- | --- |
| Nonbrowser regressions | 779/779 passed, 0 failed or skipped; 1261.7 s |
| Browser and UI regressions | 46/46 passed, 0 failed or skipped; 511.6 s |
| Release gate (`release-metadata.test.ts`) | passed: version agreement across package, lock and BUILD_INFO; build-id format; rule version website/3.0.0; registry websiteRuleVersion; release-file existence; documentation links resolve |
| AWS live key check (`live-check.test.ts`) | passed: a complete key signs STS `GetCallerIdentity` with the secret access key absent from every header and from the body, the `Authorization` header carrying `AWS4-HMAC-SHA256 Credential=<access-key-id>/…`; an incomplete credential opens no socket; a revoked 403 does not halt the provider in a check-all run |
| Egress allowlist | the live-check allowlist derived from the recipe table grew by exactly one host, `sts.amazonaws.com`; no request can reach any other host |
| Deployment-path coverage (`profiles.test.ts`) | passed: every coverage probes the larger high-value set; Standard and Deep add the curated set; the Deep audit list stays within the 30-path ceiling (29 paths) |
| No non-loopback connection | none made in any run; the frozen 2.5 corpus and its digests are unchanged; the detector rule catalogue is byte-identical to 2.9.1 |
| Linux x64 on an Ubuntu 24.04 server ([linux-server.json](../benchmarks/3.0.0/linux-server.json); the jobs of `linux.yml`, same build id, bundled Node 24.18.1) | nonbrowser regressions 778/779 passed, 1 skipped (Windows-only); browser and UI regressions 43/46 passed with `EXPOSURE_BROWSER_NO_SANDBOX=1` (the server keeps Ubuntu's unprivileged-user-namespace restriction, so Chromium's own sandbox cannot start). The 3 failures are in the tests: they start their own Chromium without the sandbox switch, and pass 7/7 with a test-only fix kept for the next version. Package `Exposure Desk 3.0.0 Linux x64.tar.gz` built (8094 files, 266295349 bytes, SHA-256 `76a97798cc45f4c9…`), checksum verified, packaged smoke 13/13 from a path with spaces, none left running. Container image built from `docker/Dockerfile` (build id `3.0.0+900c631686338160` inside the image) and its smoke test passed: non-root and read-only, private `/data`, doctor parity and Gitleaks verified, Chromium launched and the runtime scan completed, CLI smoke 4/4, the dashboard reachable only on loopback and stopping cleanly |
| Release packages ([packaged-smoke.json](../benchmarks/3.0.0/packaged-smoke.json), [root-parity.json](../benchmarks/3.0.0/root-parity.json), [source-integrity.json](../benchmarks/3.0.0/source-integrity.json)) | Windows x64 package (5393 files) and Source package (800 files) built from this build. Packaged smoke on the extracted Windows x64 package 13/13: every manifest hash, launcher path with spaces, port conflict, protected persistence, existing instance, authenticated demo, masked defaults, deliberate reveal, cancel, shutdown and restart; the parser and detector analysis processes ran on the bundled runtime and none was left running, and no process from the package remained. The root PACKAGE_MANIFEST.json matches the Windows x64 package (5393 files), and every Source package hash verifies (800 files). SHA-256 of the Windows x64, Source and Linux x64 packages: `artifacts/SHA256SUMS-3.0.0.txt` |

## Ready options on the Linux server

`scripts/profile-matrix.mjs` with the fixtures and checks described in the 2.9.1 section below, run on the Ubuntu 24.04 server on 2026-10-17: build 3.0.0+900c631686338160, the 2.9.1 baseline (2.9.1+94a512df50bb9d43, built there from tag `v2.9.1`), the injected small computer (3.0-small) and the resource rows, all with the same Node v24.18.1, harness 43537d3099028d72 and Chrome for Testing 153.0.8010.12 (`EXPOSURE_BROWSER_NO_SANDBOX=1`). The 2.9.1 rows here are a like-for-like baseline on the same server and are not merged with the laptop rows of the 2.9.1 section. The four phase jobs ran at the same time on a shared server with 2 CPUs free each, so times are noisy and longer than a quiet computer's. Complete data: [linux-server-matrix.md](../benchmarks/3.0.0/linux-server-matrix.md) and `linux-server-matrix.json`; run details and deviations (the matrix runner names case folders by a short digest so Chromium's socket path stays within Linux's 107-character cap; the build id is unchanged): [linux-server.json](../benchmarks/3.0.0/linux-server.json).

| Check | Actual result |
| --- | --- |
| Rows | 58 of 58 current, 0 stale, 0 failed |
| Acceptance checks | 185/191 passed |
| The 6 failed checks | 3.0 and 3.0-small, standard+normal and deep+normal on the bundle fixture: 6/7, the key inside the 1,252,570-byte bundle not reached, with semantic time or budget gaps (`semantic-time-limit`, `semantic-mutation-budget`, `detector-analysis-failure`); for 3.0 this also fails "Keeps the 2.9.1 recall" (6/7 vs 7/7) |
| Cause of the 6 | server load, not a 3.0 change: the 2.9.1 rows of the same run show the same kinds of gaps (and still reached all 7 keys), and the semantic and parser code is unchanged since 2.9.1. Rerun of exactly these cases, one at a time with 2.9.1 interleaved, 3 rounds ([linux-server-bundle-rerun.json](../benchmarks/3.0.0/linux-server-bundle-rerun.json)): 18/18 found 7/7 with no analysis gap — 3.0 6/6, 3.0-small 6/6, 2.9.1 6/6 |
| 3.0 against 2.9.1 on the bundle fixture (rerun) | normal traffic 32–34 s and 53 requests against 26–27 s and 41 requests: the 12 extra requests are the larger deployment-path list; peak RSS 323–337 MiB on both |

The 2.9.1 verification, with the earlier laptop matrix, follows.

# Actual verification — 2.9.1

Build 2.9.1+94a512df50bb9d43. Windows x64 with the bundled Node 24.18.1, locked dependencies, Gitleaks 8.30.1 and Chrome for Testing 153.0.8010.12 / Playwright 1.63.0. Rules website/2.9.1; structural data checks exposure/1.0. Ready options, limits and traffic: [UPGRADE_2.6.md](releases/UPGRADE_2.6.md); data upgrade: [MIGRATION_2.9.md](releases/MIGRATION_2.9.md); changes: [CHANGELOG_2.9.md](releases/CHANGELOG_2.9.md).

| Final check | Actual result |
| --- | --- |
| Nonbrowser regressions | 777/777 passed, 0 failed or skipped; 1442.2 s |
| Browser and UI regressions | 46/46 passed, 0 failed or skipped; 483.4 s |
| Repeated Chromium cancellation stress | 60/60 passed; 298.8 s |
| CLI child processes | 4 exit/masking checks passed |
| Protected persistence (temporary data directory) | projectRestart, correlationRestart, vaultRestart, operatorPermissions, deletion |
| Selected provider corpus (pinned engine) | 167/167 targets; 0 false positives; 0 component / 0 location errors |
| Full acquisition pipeline | passed; 17/17 fixtures |
| Ready options on local fixtures | 167/167 acceptance checks met over 57 scans (below) |
| Release preflight | passed (earlier release archive hashes, baseline parity, pinned runtime/detector/browser, wordlist and corpus digests) |
| Target lists at scale (loopback fixtures) | 7 runs at 1, 4, 16, 64, 1, 4 and 16 targets at once (64 with a program file), 200 targets each; targets that did not complete: 16 of 16 at 1 at once (discovered-frontier-drained 16); 16 of 16 at 4 at once (discovered-frontier-drained 16); 16 of 16 at 16 at once (discovered-frontier-drained 16); one shared analysis budget of 256 MiB per run, never exceeded; 0 non-loopback connections (below) |
| Linux x64 on GitHub-hosted Ubuntu runners (workflow run 38885369937, commit 104e57d) | nonbrowser regressions 776/777 passed, 1 skipped; browser and UI regressions 46/46 passed; package job success (builds `the tar.gz` and runs the packaged smoke on the extracted package); container job success (image build and smoke); package SHA-256 `f278e1ef330817fb…`, attached to the draft GitHub Release v2.9.1, checksum file verified after download |

## Ready options on local fixtures

`scripts/profile-matrix.mjs` (plan §5), 2026-10-16: each of the six ready options as shipped, one scan per child process, on HTTPS loopback fixtures with synthetic, nonfunctional keys and an egress tripwire — a single site (8 keys: inline page, script, source map, split module, .env, configuration file, a depth-3 and a depth-5 page; plus an all-X placeholder decoy), a 1,252,570-byte bundle site (7 keys and a mutated decoy) and 3 or 10 subdomains of one registrable domain (single-site copies). Baseline: the 2.9.0 Windows x64 release ZIP, extracted and run with the same six ready options (rows labelled 2.9.0; "Keeps the 2.9.0 recall" compares each source-build row with the same option and fixture there). The fixture server counts requests, TCP connections, TLS handshakes and wire bytes; browser navigations, coverage and findings come from the scan record; peak RSS is the scan process (Chromium excluded); the analysis heap column lists, for builds that run the parser and the large-text checks in analysis processes, each role's processes × heap limit (the V8 old-space limit, held from the analysis memory setting) and the most heap limit held at once, and for earlier builds the parser worker's V8 heap high-water mark / limit sampled every 25 ms; the analysis-process RSS column is an upper bound on those processes' combined peak RSS (each process's own peak, summed over the processes alive at once), which is not part of the scan process's peak RSS. "In scope" is what each option's stated boundary reaches (Quick: entry documents and their files; Standard: depth 3; Deep: depth 5). Precision counts credential findings that match a planted key. "-small" runs inject a computer with 2 cores and 1 GiB free memory. Complete data: `benchmarks/2.9.1/matrix.json` and `matrix.md`.

| Run | Option | Fixture | State | Time s | Requests | TCP | TLS | Wire MiB | Browser nav | Peak RSS MiB | Analysis heap MiB (worker peak/limit, or processes×limit) | Analysis processes RSS MiB (bound) | Acquisition | Analysis | Recall (in scope) | Precision (credential findings) | Est. conns |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 2.9 | quick+normal | single×1 | completed (quick-coverage) | 13.5 | 25 | 25 | 25 | 0.11 | 0 | 203 | parser 1×256; ≤256 at once | 67 | 100% | 100% | 6/8  (6 expected) | 6/6 | — |
| 2.9 | quick+low-impact | single×1 | completed (quick-coverage) | 49.4 | 25 | 1 | 1 | 0.02 | 0 | 198 | parser 1×256; ≤256 at once | 67 | 100% | 100% | 6/8  (6 expected) | 6/6 | — |
| 2.9 | standard+normal | single×1 | incomplete | 41.9 | 49 | 49 | 49 | 0.22 | 5 | 206 | parser 1×128; ≤128 at once | 70 | 70% | 127% | 7/8  (7 expected) | 7/7 | — |
| 2.9 | standard+low-impact | single×1 | incomplete | 77.4 | 39 | 1 | 1 | 0.03 | 3 | 202 | parser 1×128; ≤128 at once | 70 | 67% | 131% | 7/8  (7 expected) | 7/7 | — |
| 2.9 | deep+normal | single×1 | incomplete | 86.5 | 61 | 61 | 61 | 0.27 | 10 | 206 | parser 1×256; ≤256 at once | 70 | 73% | 126% | 8/8  (8 expected) | 8/8 | — |
| 2.9 | deep+low-impact | single×1 | incomplete | 106.0 | 47 | 4 | 4 | 0.04 | 6 | 203 | parser 1×256; ≤256 at once | 70 | 69% | 131% | 8/8  (8 expected) | 8/8 | — |
| 2.9 | quick+normal | bundle×1 | incomplete | 18.5 | 29 | 29 | 29 | 1.32 | 0 | 270 | parser 2×256, detector 1×108; ≤256 at once | 236 | 100% | 100% | 7/7  (7 expected) | 7/7 | — |
| 2.9 | quick+low-impact | bundle×1 | incomplete | 65.8 | 29 | 2 | 2 | 1.22 | 0 | 255 | parser 2×256, detector 1×108; ≤256 at once | 244 | 100% | 100% | 7/7  (7 expected) | 7/7 | — |
| 2.9 | standard+normal | bundle×1 | incomplete | 24.8 | 41 | 41 | 41 | 2.57 | 1 | 283 | parser 3×128/256, detector 2×108; ≤256 at once | 471 | 67% | 137% | 7/7  (7 expected) | 7/7 | — |
| 2.9 | standard+low-impact | bundle×1 | incomplete | 74.3 | 37 | 1 | 1 | 2.42 | 1 | 304 | parser 3×128/256, detector 1×108; ≤256 at once | 310 | 65% | 142% | 7/7  (7 expected) | 7/7 | — |
| 2.9 | deep+normal | bundle×1 | incomplete | 23.8 | 41 | 41 | 41 | 2.57 | 1 | 284 | parser 1×256, detector 2×108; ≤472 at once | 642 | 66% | 137% | 7/7  (7 expected) | 7/7 | — |
| 2.9 | deep+low-impact | bundle×1 | incomplete | 73.5 | 37 | 1 | 1 | 2.42 | 1 | 305 | parser 1×256, detector 1×108; ≤364 at once | 416 | 63% | 142% | 7/7  (7 expected) | 7/7 | — |
| 2.9 | quick+normal | multi×3 | completed (quick-coverage) | 14.5 | 75 | 75 | 75 | 0.33 | 0 | 207 | parser 1×256; ≤256 at once | 67 | 100% | 100% | 18/24  (18 expected) | 18/18 | — |
| 2.9 | quick+low-impact | multi×3 | completed (quick-coverage) | 100.3 | 75 | 3 | 3 | 0.05 | 0 | 201 | parser 1×256; ≤256 at once | 67 | 100% | 100% | 18/24  (18 expected) | 18/18 | — |
| 2.9 | standard+normal | multi×3 | incomplete | 54.4 | 147 | 147 | 147 | 0.66 | 15 | 222 | parser 2×128; ≤256 at once | 138 | 81% | 115% | 21/24  (21 expected) | 21/21 | — |
| 2.9 | standard+low-impact | multi×3 | incomplete | 180.6 | 117 | 7 | 7 | 0.09 | 9 | 202 | parser 2×128; ≤256 at once | 137 | 78% | 118% | 21/24  (21 expected) | 21/21 | — |
| 2.9 | deep+normal | multi×3 | incomplete | 166.2 | 183 | 183 | 183 | 0.82 | 30 | 222 | parser 2×256; ≤512 at once | 137 | 82% | 116% | 24/24  (24 expected) | 24/24 | — |
| 2.9 | deep+low-impact | multi×3 | incomplete | 207.8 | 141 | 10 | 10 | 0.12 | 18 | 203 | parser 2×256; ≤512 at once | 137 | 80% | 118% | 24/24  (24 expected) | 24/24 | — |
| 2.9 | quick+normal | multi×10 | completed (quick-coverage) | 31.8 | 250 | 250 | 250 | 1.13 | 0 | 221 | parser 1×256; ≤256 at once | 68 | 100% | 100% | 60/80  (60 expected) | 60/60 | — |
| 2.9 | quick+low-impact | multi×10 | completed (quick-coverage) | 263.3 | 250 | 11 | 11 | 0.17 | 0 | 201 | parser 1×256; ≤256 at once | 68 | 100% | 100% | 60/80  (60 expected) | 60/60 | — |
| 2.9 | standard+normal | multi×10 | incomplete | 228.1 | 480 | 480 | 480 | 2.20 | 50 | 292 | parser 2×128; ≤256 at once | 136 | 86% | 111% | 70/80  (70 expected) | 70/70 | — |
| 2.9 | standard+low-impact | multi×10 | incomplete | 429.2 | 390 | 17 | 17 | 0.29 | 30 | 225 | parser 2×128; ≤256 at once | 137 | 83% | 113% | 70/80  (70 expected) | 70/70 | — |
| 2.9 | deep+normal | multi×10 | incomplete | 246.5 | 529 | 529 | 529 | 2.42 | 50 | 294 | parser 1×256; ≤256 at once | 70 | 87% | 111% | 80/80  (80 expected) | 80/80 | — |
| 2.9 | deep+low-impact | multi×10 | incomplete | 592.9 | 450 | 33 | 33 | 0.39 | 50 | 231 | parser 2×256; ≤512 at once | 137 | 87% | 112% | 80/80  (80 expected) | 80/80 | — |
| 2.9-small | quick+normal | bundle×1 | incomplete | 16.3 | 29 | 29 | 29 | 1.32 | 0 | 278 | parser 2×256, detector 1×108; ≤256 at once | 244 | 100% | 100% | 7/7  (7 expected) | 7/7 | — |
| 2.9-small | quick+low-impact | bundle×1 | incomplete | 57.9 | 29 | 1 | 1 | 1.21 | 0 | 280 | parser 2×256, detector 1×108; ≤256 at once | 244 | 100% | 100% | 7/7  (7 expected) | 7/7 | — |
| 2.9-small | standard+normal | bundle×1 | incomplete | 22.2 | 41 | 41 | 41 | 2.57 | 1 | 309 | parser 2×256, detector 1×108; ≤256 at once | 244 | 66% | 137% | 7/7  (7 expected) | 7/7 | — |
| 2.9-small | standard+low-impact | bundle×1 | incomplete | 74.0 | 37 | 1 | 1 | 2.42 | 1 | 273 | parser 2×256, detector 1×108; ≤256 at once | 243 | 63% | 142% | 7/7  (7 expected) | 7/7 | — |
| 2.9-small | deep+normal | bundle×1 | incomplete | 52.5 | 41 | 41 | 41 | 2.57 | 1 | 300 | parser 3×256, detector 2×108; ≤256 at once | 241 | 67% | 137% | 7/7  (7 expected) | 7/7 | — |
| 2.9-small | deep+low-impact | bundle×1 | incomplete | 80.2 | 37 | 1 | 1 | 2.42 | 1 | 359 | parser 2×256, detector 2×108; ≤256 at once | 488 | 65% | 142% | 7/7  (7 expected) | 7/7 | — |
| 2.9-small | quick+normal | multi×10 | completed (quick-coverage) | 40.5 | 250 | 250 | 250 | 1.13 | 0 | 220 | parser 1×256; ≤256 at once | 69 | 100% | 100% | 60/80  (60 expected) | 60/60 | — |
| 2.9-small | standard+normal | multi×10 | incomplete | 305.0 | 486 | 486 | 486 | 2.23 | 50 | 294 | parser 1×256; ≤256 at once | 70 | 86% | 111% | 70/80  (70 expected) | 70/70 | — |
| 2.9-small | deep+normal | multi×10 | incomplete | 454.5 | 520 | 520 | 520 | 2.38 | 50 | 231 | parser 1×256; ≤256 at once | 70 | 88% | 110% | 80/80  (80 expected) | 80/80 | — |
| 2.9.0 | quick+normal | single×1 | completed (quick-coverage) | 13.1 | 25 | 25 | 25 | 0.11 | 0 | 207 | parser 1×256; ≤256 at once | 71 | 100% | 100% | 6/8  (6 expected) | 6/6 | — |
| 2.9.0 | quick+low-impact | single×1 | completed (quick-coverage) | 49.1 | 25 | 1 | 1 | 0.02 | 0 | 201 | parser 1×256; ≤256 at once | 71 | 100% | 100% | 6/8  (6 expected) | 6/6 | — |
| 2.9.0 | standard+normal | single×1 | incomplete | 39.4 | 49 | 49 | 49 | 0.22 | 5 | 209 | parser 1×128; ≤128 at once | 74 | 70% | 127% | 7/8  (7 expected) | 7/7 | — |
| 2.9.0 | standard+low-impact | single×1 | incomplete | 77.3 | 39 | 1 | 1 | 0.03 | 3 | 208 | parser 1×128; ≤128 at once | 73 | 67% | 131% | 7/8  (7 expected) | 7/7 | — |
| 2.9.0 | deep+normal | single×1 | incomplete | 79.7 | 61 | 61 | 61 | 0.27 | 10 | 210 | parser 1×256; ≤256 at once | 73 | 73% | 126% | 8/8  (8 expected) | 8/8 | — |
| 2.9.0 | deep+low-impact | single×1 | incomplete | 101.7 | 47 | 3 | 3 | 0.04 | 6 | 208 | parser 1×256; ≤256 at once | 73 | 69% | 131% | 8/8  (8 expected) | 8/8 | — |
| 2.9.0 | quick+normal | bundle×1 | incomplete | 15.7 | 29 | 29 | 29 | 1.32 | 0 | 281 | parser 2×256, detector 1×108; ≤256 at once | 248 | 100% | 100% | 7/7  (7 expected) | 7/7 | — |
| 2.9.0 | quick+low-impact | bundle×1 | incomplete | 57.7 | 29 | 1 | 1 | 1.21 | 0 | 280 | parser 2×256, detector 1×108; ≤256 at once | 247 | 100% | 100% | 7/7  (7 expected) | 7/7 | — |
| 2.9.0 | standard+normal | bundle×1 | incomplete | 21.4 | 41 | 41 | 41 | 2.57 | 1 | 312 | parser 3×128/256, detector 1×108; ≤256 at once | 319 | 66% | 137% | 7/7  (7 expected) | 7/7 | — |
| 2.9.0 | standard+low-impact | bundle×1 | incomplete | 73.2 | 37 | 1 | 1 | 2.42 | 1 | 306 | parser 3×128/256, detector 1×108; ≤256 at once | 318 | 63% | 142% | 7/7  (7 expected) | 7/7 | — |
| 2.9.0 | deep+normal | bundle×1 | incomplete | 23.9 | 41 | 41 | 41 | 2.57 | 1 | 314 | parser 1×256, detector 1×108; ≤364 at once | 426 | 66% | 137% | 7/7  (7 expected) | 7/7 | — |
| 2.9.0 | deep+low-impact | bundle×1 | incomplete | 73.2 | 37 | 1 | 1 | 2.42 | 1 | 308 | parser 1×256, detector 1×108; ≤364 at once | 423 | 63% | 142% | 7/7  (7 expected) | 7/7 | — |
| 2.9.0 | quick+normal | multi×3 | completed (quick-coverage) | 14.5 | 75 | 75 | 75 | 0.33 | 0 | 210 | parser 1×256; ≤256 at once | 71 | 100% | 100% | 18/24  (18 expected) | 18/18 | — |
| 2.9.0 | quick+low-impact | multi×3 | completed (quick-coverage) | 99.8 | 75 | 3 | 3 | 0.05 | 0 | 199 | parser 1×256; ≤256 at once | 71 | 100% | 100% | 18/24  (18 expected) | 18/18 | — |
| 2.9.0 | standard+normal | multi×3 | incomplete | 49.8 | 147 | 147 | 147 | 0.66 | 15 | 224 | parser 2×128; ≤256 at once | 147 | 81% | 115% | 21/24  (21 expected) | 21/21 | — |
| 2.9.0 | standard+low-impact | multi×3 | incomplete | 156.8 | 117 | 5 | 5 | 0.09 | 9 | 209 | parser 2×128; ≤256 at once | 144 | 78% | 118% | 21/24  (21 expected) | 21/21 | — |
| 2.9.0 | deep+normal | multi×3 | incomplete | 112.9 | 183 | 183 | 183 | 0.82 | 30 | 226 | parser 2×256; ≤512 at once | 146 | 82% | 116% | 24/24  (24 expected) | 24/24 | — |
| 2.9.0 | deep+low-impact | multi×3 | incomplete | 199.1 | 141 | 10 | 10 | 0.12 | 18 | 209 | parser 2×256; ≤512 at once | 144 | 80% | 118% | 24/24  (24 expected) | 24/24 | — |
| 2.9.0 | quick+normal | multi×10 | completed (quick-coverage) | 31.3 | 250 | 250 | 250 | 1.13 | 0 | 226 | parser 1×256; ≤256 at once | 72 | 100% | 100% | 60/80  (60 expected) | 60/60 | — |
| 2.9.0 | quick+low-impact | multi×10 | completed (quick-coverage) | 254.6 | 250 | 10 | 10 | 0.17 | 0 | 205 | parser 1×256; ≤256 at once | 71 | 100% | 100% | 60/80  (60 expected) | 60/60 | — |
| 2.9.0 | standard+normal | multi×10 | incomplete | 163.1 | 490 | 490 | 490 | 2.24 | 50 | 298 | parser 2×128; ≤256 at once | 146 | 86% | 111% | 70/80  (70 expected) | 70/70 | — |
| 2.9.0 | standard+low-impact | multi×10 | incomplete | 418.4 | 390 | 18 | 18 | 0.29 | 30 | 227 | parser 2×128; ≤256 at once | 146 | 83% | 113% | 70/80  (70 expected) | 70/70 | — |
| 2.9.0 | deep+normal | multi×10 | incomplete | 237.8 | 529 | 529 | 529 | 2.42 | 50 | 293 | parser 2×256; ≤512 at once | 146 | 87% | 111% | 80/80  (80 expected) | 80/80 | — |
| 2.9.0 | deep+low-impact | multi×10 | incomplete | 583.4 | 450 | 29 | 29 | 0.37 | 50 | 232 | parser 2×256; ≤512 at once | 144 | 87% | 112% | 80/80  (80 expected) | 80/80 | — |

### Recorded resource use

| Option (websites at once / browser websites / analysis memory / workers) | This computer, 1 website | Small computer, 1 website | This computer, 3 websites | Small computer, 3 websites | This computer, 10 websites | Small computer, 10 websites |
|---|---|---|---|---|---|---|
| quick+normal | 1 / 0 / 256 MiB / 1 | 1 / 0 / 256 MiB / 1 | 3 / 0 / 256 MiB / 1 | 3 / 0 / 256 MiB / 1 | 6 / 0 / 256 MiB / 1 | 6 / 0 / 256 MiB / 1 |
| quick+low-impact | 1 / 0 / 256 MiB / 1 | 1 / 0 / 256 MiB / 1 | 2 / 0 / 256 MiB / 1 | 2 / 0 / 256 MiB / 1 | 2 / 0 / 256 MiB / 1 | 2 / 0 / 256 MiB / 1 |
| standard+normal | 1 / 1 / 256 MiB / 2 | 1 / 1* / 256 MiB / 1* | 3 / 2 / 256 MiB / 2 | 3 / 1* / 256 MiB / 1* | 4 / 2 / 256 MiB / 2 | 4 / 1* / 256 MiB / 1* |
| standard+low-impact | 1 / 1 / 256 MiB / 2 | 1 / 1 / 256 MiB / 1* | 2 / 1 / 256 MiB / 2 | 2 / 1 / 256 MiB / 1* | 2 / 1 / 256 MiB / 2 | 2 / 1 / 256 MiB / 1* |
| deep+normal | 1 / 1 / 512 MiB / 2 | 1 / 1* / 256* MiB / 1* | 3 / 2 / 512 MiB / 2 | 3 / 1* / 256* MiB / 1* | 3 / 2 / 512 MiB / 2 | 3 / 1* / 256* MiB / 1* |
| deep+low-impact | 1 / 1 / 512 MiB / 2 | 1 / 1 / 256* MiB / 1* | 2 / 1 / 512 MiB / 2 | 2 / 1 / 256* MiB / 1* | 2 / 1 / 512 MiB / 2 | 2 / 1 / 256* MiB / 1* |

This computer: 16 logical cores, 10.7 GiB free memory when recorded. Small computer: 2 cores and 1 GiB free memory, injected.

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
| Adjustment only lowers | 36/36 | none |
| Settings as recorded | 33/33 | none |

## External synthetic corpus per ready option (additional measurement)

Not an acceptance target. Corpus `ExposureDesk/detection-corpus/v2`, written by a separate non-Claude AI and reviewed before use (working notes in `archive/notes/HANDOFF_EXTERNAL_CORPUS.md`, not packaged); pinned manifest `ef9187db6d80638d…` and scorer `5e01b10ec2d8e42e…`, re-hashed before use; 20 sites, 27 private values, 402 negative controls. Each site is served from 127.0.0.1 over HTTP and scanned with exact-origin scope and an egress tripwire; the JSON report is scored by the corpus's own scorer. The corpus stays outside the project and is never packaged. Counts describe this corpus only.

| Option | Mode | True / false positives / false negatives | Precision | Recall | Negative-control alerts | Requests | Scan time | Site states |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| quick+low-impact | acquisition | 27 / 3 / 0 | 0.900 | 1 | 3 | 526 | 17.4 min | incomplete 17, completed 3 |
| quick+low-impact | discovery | 24 / 3 / 3 | 0.889 | 0.889 | 3 | 474 | 16.2 min | incomplete 19, completed 1 |
| quick+normal | acquisition | 27 / 3 / 0 | 0.900 | 1 | 3 | 526 | 4.6 min | incomplete 17, completed 3 |
| quick+normal | discovery | 24 / 3 / 3 | 0.889 | 0.889 | 3 | 474 | 4.4 min | incomplete 19, completed 1 |
| standard+low-impact | acquisition | 27 / 3 / 0 | 0.900 | 1 | 3 | 587 | 23.1 min | incomplete 20 |
| standard+low-impact | discovery | 27 / 3 / 0 | 0.900 | 1 | 3 | 921 | 31.3 min | incomplete 20 |
| standard+normal | acquisition | 27 / 3 / 0 | 0.900 | 1 | 3 | 768 | 14.2 min | incomplete 20 |
| standard+normal | discovery | 27 / 3 / 0 | 0.900 | 1 | 3 | 1334 | 11.6 min | incomplete 20 |
| deep+low-impact | acquisition | 27 / 3 / 0 | 0.900 | 1 | 3 | 612 | 30.2 min | incomplete 20 |
| deep+low-impact | discovery | 27 / 3 / 0 | 0.900 | 1 | 3 | 922 | 31.3 min | incomplete 20 |
| deep+normal | acquisition | 27 / 3 / 0 | 0.900 | 1 | 3 | 1067 | 24.6 min | incomplete 20 |
| deep+normal | discovery | 27 / 3 / 0 | 0.900 | 1 | 3 | 1332 | 11.9 min | incomplete 20 |

## Target lists at scale (mass scan, loopback fixtures)

`scripts/mass-scan-measure.mjs`, 2026-10-16, build 2.9.1+94a512df50bb9d43, win32 x64, 8-core x86-64 laptop CPU (16 logical processors, 31.3 GiB): the built command line (`exposure-desk scan --targets FILE`) as a user runs it, against 200 synthetic targets on 50 loopback websites (127.0.0.1 to 127.0.0.50, one port); target i is page /t<n> of website i mod 50, so neighbouring targets are different websites. Each page holds its own synthetic, nonfunctional key inline and loads its website's /static/app.js, whose key all targets of that website share (cross-target de-duplication); everything else answers 404. Every run uses quick+normal, `--state`, `--jsonl` and a template that allows exactly the 50 fixture origins; runs at up to 16 targets at once use `--authorized`, the 64 run a program file (authorized, scope = the fixture origins, 50 requests per second, 64 targets and 64 requests at once). An egress tripwire in the scan process refuses and records any socket or DNS lookup outside loopback: 0 recorded. Requests are counted at the fixture; peak RSS is the scan process sampled every 25 ms; the analysis budget is the one memory budget all targets of a run draw from (capacity / highest use / analysis-process heap limits held at once); analysis processes are counted separately from the scan process. Complete data: `benchmarks/2.9.1/mass-scan.json`.

| Run | Targets | At once | Wall time | Requests (per second) | Targets per second | Scan-process peak RSS | Analysis budget: capacity / peak / heap held at once | Analysis processes: started / peak RSS at once | Own keys / shared keys found | Target states |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| c1 | 200 | 1 | 38.5 min | 4400 (1.9) | 0.09 | 189 MiB | 256 / 256 / 256 MiB | 1 / 60 MiB | 200/200 / 50/50 | done 200 (stop reasons: quick-target-set-done 200) |
| c4 | 200 | 4 | 9.9 min | 4400 (7.4) | 0.34 | 321 MiB | 256 / 256 / 256 MiB | 1 / 72 MiB | 200/200 / 50/50 | done 200 (stop reasons: quick-target-set-done 200) |
| c16 | 200 | 16 | 3.2 min | 4400 (23.3) | 1.06 | 332 MiB | 256 / 256 / 256 MiB | 1 / 73 MiB | 200/200 / 50/50 | done 200 (stop reasons: quick-target-set-done 200) |
| program-c64 (program file) | 200 | 64 | 2.9 min | 4400 (25.6) | 1.16 | 353 MiB | 256 / 256 / 256 MiB | 1 / 73 MiB | 200/200 / 50/50 | done 200 (stop reasons: quick-target-set-done 200) |
| large-c1 (standard+normal) | 16 | 1 | 4.2 min | 448 (1.8) | 0.06 | 360 MiB | 256 / 256 / 256 MiB | 48 / 253 MiB | 16/16 / 16/16 | failed 16 (stop reasons: discovered-frontier-drained 16) |
| large-c4 (standard+normal) | 16 | 4 | 100.4 s | 448 (4.5) | 0.16 | 343 MiB | 256 / 256 / 256 MiB | 48 / 341 MiB | 16/16 / 16/16 | failed 16 (stop reasons: discovered-frontier-drained 16) |
| large-c16 (standard+normal) | 16 | 16 | 59.4 s | 448 (7.5) | 0.27 | 402 MiB | 256 / 256 / 256 MiB | 44 / 340 MiB | 16/16 / 16/16 | failed 16 (stop reasons: discovered-frontier-drained 16) |

"Target states" are the run-state file's: `done` = completed, `failed` = any target that did not complete (here `incomplete`). `origin-deadline-reached` means the target's per-website time allowance (the coverage's duration, for quick 120 s of wall-clock time from the website's first request, not paused while the target waits) ran out before the target finished: all targets of a run share one analysis budget, so with more targets at once each one waits longer between its requests. Keys found before the allowance ran out are reported; a resumed run (`--state`) scans the unfinished targets again. Unfinished targets: large-c1 16 of 16, large-c4 16 of 16, large-c16 16 of 16.

## Legacy settings on the frozen 2.5 corpus (2.9.0 → 2.9.1)

Corpus `scripts/eval-2.5-corpus.mjs`, digest `41f8c2dd214da8bd…`, frozen 2026-10-08T04:15:23.216Z. The 2.5 release corpus, unchanged, run with its own legacy (preset and custom) configurations, none of which names a coverage or traffic level; it checks that such configurations still behave as in the previous release apart from intended detection changes. Each group ran 3× per build in separate child processes with an egress tripwire, alternating builds; the first repetition's measurements are shown and the result is identical across repetitions unless noted in `benchmarks/2.9.1/evaluation.json`. Baseline: 2.9.0+b251a3ea63449d85.

| Group · measurement | 2.9.0 | 2.9.1 |
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
| G5F corrected 1,252,570-byte bundle · split key found (engine off / on) | 0/1 / 0/1 | 1/1 / 1/1 |
| G5F · negatives reported (mutated alias, test key, publishable key) | 1 / 1 | 1 / 1 |
| G6 shortDeadline · non-terminal states / pending inventory rows / state | 0 / 0 / incomplete | 0 / 0 / incomplete |
| G6 cancelAfterDownload · non-terminal states / pending inventory rows / state | 0 / 0 / cancelled | 0 / 0 / cancelled |
| G6 smallSlices · non-terminal states / pending inventory rows / state | 0 / 0 / incomplete | 0 / 0 / incomplete |
| G7 wallets, keys, signing and priority cases · website rules only | 23/23 detected · 0 false positives of 16 negatives · precision 1 · recall 1 | 23/23 detected · 0 false positives of 16 negatives · precision 1 · recall 1 |
| G7 · with the pinned engine | 23/23 detected · 0 false positives of 16 negatives · precision 1 · recall 1 | 23/23 detected · 0 false positives of 16 negatives · precision 1 · recall 1 |
| G7 · expected priority matched | 9/11 | 9/11 |
| G8 · static User-Agent | Mozilla/5.0 (compatible; ExposureDesk/2.9) | Mozilla/5.0 (compatible; ExposureDesk/2.9) |
| G8 · browser language / time zone reported by the page | en-US / UTC | en-US / UTC |
| G8 · headers repeating the page path or query | 0 | 0 |
| G9 · two identical starts 50 ms apart: HTTP statuses / runs created / same run returned | 202, 202 / 1 / true | 202, 202 / 1 / true |

| Group · median wall time per child / peak Node RSS | 2.9.0 | 2.9.1 |
| --- | --- | --- |
| G1 | 1834 ms / 237.3 MiB | 1820 ms / 236.6 MiB |
| G2 | 5096 ms / 242.1 MiB | 5576 ms / 242.2 MiB |
| G3 | 13088 ms / 236.6 MiB | 14664 ms / 235.4 MiB |
| G4 | 2281 ms / 242.1 MiB | 2257 ms / 241.2 MiB |
| G5 | 6561 ms / 402.5 MiB | 6563 ms / 398.7 MiB |
| G5F | 6902 ms / 422.2 MiB | 7652 ms / 421.3 MiB |
| G6 | 4436 ms / 396.4 MiB | 4463 ms / 396.8 MiB |
| G7 | 9554 ms / 225.7 MiB | 9546 ms / 224.2 MiB |
| G8 | 5177 ms / 241.3 MiB | 5446 ms / 241.8 MiB |
| G9 | 2976 ms / 238.0 MiB | 2969 ms / 237.9 MiB |

2.9.0 legacy-evaluation figures reused from the 2.9.0 release records (owner decision 2026-10-11), not re-measured: the 2.9.0 column is `benchmarks/2.9.0/final-legacy-evaluation.json` and `benchmarks/2.9.0/final-acquisition.json` (build 2.9.0+b251a3ea63449d85, measured 2026-10-15, so its elapsed time and peak RSS are not a same-day comparison); the evaluation scripts and their inline corpora are unchanged since that release, and only the 2.9.1 column was measured for this release.

| Legacy 2.4 corpora (unchanged) | 2.9.0 | 2.9.1 |
| --- | --- | --- |
| 48-case detector corpus: credential targets detected / false positives | 13/13 / 0 | 13/13 / 0 |
| Data-exposure targets detected / false positives | 5/5 / 0 | 5/5 / 0 |
| Corpus elapsed / Node peak RSS | 2.541 s / 227.0 MiB | 3.495 s / 227.4 MiB |
| Dynamic application: credential targets / known resources inspected / forbidden arrivals | 5/5 / 9/9 / 0 | 5/5 / 9/9 / 0 |

Limitations: synthetic, nonfunctional values and local fixtures only (loopback servers and a virtual network); every timing and memory figure is from one Windows x64 host (the Linux x64 suites, package and container are pass/fail results from GitHub-hosted Ubuntu runners, without timing claims); single-digit repetitions without statistical controls; Node peak RSS includes worker threads but excludes Chromium, Gitleaks and the analysis child processes (the ready-option table reports the analysis processes separately). Ready-option durations depend on the fixtures' sizes and on this computer; the small-computer rows inject the computer description, they do not run on slower hardware. These counts describe this corpus only and make no general accuracy claim. macOS and ARM were not exercised; Linux x64 only on the CI runners named above. No owner website or production response was contacted or used.

<!-- PREVIOUS_VERIFICATION -->
# Actual verification — 2.9.0

Build 2.9.0+b251a3ea63449d85. Windows x64 with the bundled Node 24.18.1, locked dependencies, Gitleaks 8.30.1 and Chrome for Testing 153.0.8010.12 / Playwright 1.63.0. Rules website/2.9.0; structural data checks exposure/1.0. Ready options, limits and traffic: [UPGRADE_2.6.md](releases/UPGRADE_2.6.md); data upgrade: [MIGRATION_2.9.md](releases/MIGRATION_2.9.md); changes: [CHANGELOG_2.9.md](releases/CHANGELOG_2.9.md).

| Final check | Actual result |
| --- | --- |
| Nonbrowser regressions | 761/761 passed, 0 failed or skipped; 1111.7 s |
| Browser and UI regressions | 46/46 passed, 0 failed or skipped; 467.0 s |
| Repeated Chromium cancellation stress | 60/60 passed; 244.3 s |
| CLI child processes | 4 exit/masking checks passed |
| Protected persistence (temporary data directory) | projectRestart, correlationRestart, vaultRestart, operatorPermissions, deletion |
| Selected provider corpus (pinned engine) | 167/167 targets; 0 false positives; 0 component / 0 location errors |
| Full acquisition pipeline | passed; 17/17 fixtures |
| Ready options on local fixtures | 191/191 acceptance checks met over 57 scans (below) |
| Release preflight | passed (earlier release archive hashes, baseline parity, pinned runtime/detector/browser, wordlist and corpus digests) |
| Target lists at scale (loopback fixtures) | 4 runs of 200 targets at 1, 4, 16 and 64 at once (64 with a program file): every target completed, every key found; 3 runs of 16 large-bundle targets at 1, 4 and 16 at once (Standard): every key found, every target incomplete (discovered-frontier-drained) and exit 2, as in development; scan process at most 390 MiB (2.8.0 code: up to 577 MiB); one shared analysis budget of 256 MiB per run, never exceeded; 0 non-loopback connections (below) |
| Linux x64 on GitHub-hosted Ubuntu runners (workflow run 38684371332, commit a6630b5) | nonbrowser regressions 760/761 passed, 1 skipped; browser and UI regressions 46/46 passed; package job failure: the Linux x64 package was built and passed its checksum and packaged smoke checks on the runner, only the artifact upload failed (repository artifact storage quota full); container job success (image build and smoke) |
| Extracted Windows package smoke | 13/13 checks on the extracted Windows x64 ZIP: manifest hashes, launcher path with spaces, port conflict, protected persistence, existing instance, authenticated demo, masked defaults, deliberate reveal, cancel, shutdown, restart, analysis processes (parser and large-text processes started with the bundled `runtime\node.exe`, none running after the scan) and no package process left (`benchmarks/2.9.0/packaged-smoke.json`) |

**Browser suite runs on this build.** Every run of the browser suite, or of a browser test file alone, on build 2.9.0+b251a3ea63449d85 on this computer: the full sanity run before the measurements passed 44/46 (914.6 s) while an unrelated CPU-bound job outside the project saturated the computer (CPU at or above 95 % for most of the run, free memory down to about 5 GiB); both failures were Chrome not confirming its exit within the 3 s cleanup bound, one in chrome-background-browser.test.js and one in completeness-browser.test.js. Run alone, chrome-background-browser.test.js passed 2/2; completeness-browser.test.js failed 2 of 4 the same way while the outside job still ran, then passed 4/4 twice on a quiet machine. The final full run after the measurements, on a quiet machine, passed 46/46 (467.0 s; the row above). The nonbrowser sanity run under the same load passed 760/761: one mass-mode test in mass-scale.test.js saw its analysis turn deferred at the analysis-turn limit; that file alone then passed 32/32 and the final run passed 761/761 (the row above). Record of every run: `benchmarks/2.9.0/browser-attempts.json`.

**Linux CI runs on this build.** Two runs of linux.yml on GitHub-hosted Ubuntu runners, both with build digest b251a3ea63449d85. The release run 38684371332 on the records commit a6630b5 passed 760/761 nonbrowser tests (the Windows-only ACL test skipped) and 46/46 browser and UI tests and built and smoke-tested the container image; its package job built the Linux x64 package (8048 files, 266,136,232 bytes, sha256 cc1d2e11…3073) and passed `sha256sum --check` and the packaged smoke test (13/13 checks) on the runner. Only the artifact upload failed, because the repository's GitHub Actions artifact storage quota was full, so that job and the run are marked failure and the Linux package is not in `artifacts` (blocked until storage is freed; no artifacts were deleted). The measurement run 38638887840 on the version-freeze commit 3b1628a had the same results (760/761, 46/46, container ok, package built and smoke-tested, upload refused for the same quota). Pass/fail only, no timing or memory figures. Record: `benchmarks/2.9.0/linux-ci.json`.

## Machine state during the measurements

Sampled while the measurements ran, by a sampler outside the project: CPU load over all logical processors every 5 s (the measurement itself included; "before" is the 10 s idle window ahead of each step), free physical memory every 5 s, and the power source (BatteryStatus.PowerOnline) and battery charge every 60 s and at each step change. A sample belongs to the step whose start and end contain it; two steps that ran side by side (the external corpus pairs) share their samples, and steps that waited for the measurement limiter start when it let them run. Every step waited first for 2 minutes below 50 % CPU with at least 11000 MiB free and no outside bot-evaluation process running. An unrelated CPU-bound job outside the project (16 processes, not part of this project and not stopped) still started during three short first-run steps: CLI smoke, the provider corpus benchmark and the frozen 2.5 corpus evaluation saw CPU at 95 % or more and less than 10000 MiB free ("disturbed"). They passed, but they were run again on a quiet machine, alone, and those reruns are the records; the quiet reruns of the legacy and acquisition evaluations were run alongside to confirm their first-run times. The first runs stay listed, marked "first run, superseded by the quiet rerun". The sanity suites before the measurements are not listed (they ran under that outside load; every run is in browser-attempts.json). "disturbed" flags a step that saw CPU at 95 % or more or less than 10000 MiB free. 16 logical processors, 31.3 GiB memory. On AC power during every step. Complete data: `benchmarks/2.9.0/machine-state.json`.

| Step | Duration | Power | CPU load before / median / highest | Least free memory |
| --- | --- | --- | --- | --- |
| Mass scan c16 (loopback fixtures) | 3.5 min | AC (battery at least 99 %) | 27 % / 26 % / 38 % | 11.6 GiB |
| Cancel stress (20 passes) | 4.1 min | AC (battery at least 99 %) | 27 % / 38 % / 59 % | 10.8 GiB |
| CLI smoke (first run, superseded by the quiet rerun) | 0.3 min | AC (battery at least 99 %) | 32 % / 76 % / 100 % | 9.3 GiB |
| Persistence smoke | 0.2 min | AC (battery at least 99 %) | 20 % / 17 % / 18 % | 13.5 GiB |
| Provider corpus benchmark (first run, superseded by the quiet rerun) | 1.3 min | AC (battery at least 99 %) | 18 % / 100 % / 100 % | 7.9 GiB |
| Pipeline self-test | 0.2 min | AC (battery at least 99 %) | 26 % / 34 % / 43 % | 11.9 GiB |
| Legacy evaluation (2.9.0 side) (first run, superseded by the quiet rerun) | 0.1 min | AC (battery at least 99 %) | 38 % / 32 % / 32 % | 12.4 GiB |
| Acquisition evaluation (2.9.0 side) (first run, superseded by the quiet rerun) | 0.1 min | AC (battery at least 99 %) | 32 % / 37 % / 37 % | 11.9 GiB |
| Frozen 2.5 corpus evaluation (2.8.0 and 2.9.0, 3 repeats) (first run, superseded by the quiet rerun) | 11.6 min | AC (battery at least 99 %) | 35 % / 100 % / 100 % | 4.7 GiB |
| Matrix spot check (2.8.0 rows, same day) | 7.8 min | AC (battery at least 99 %) | 4 % / 14 % / 42 % | 12.6 GiB |
| Matrix 2.9.0 side (resources, current, small) | 65.3 min | AC (battery at least 99 %) | 6 % / 9 % / 56 % | 12.5 GiB |
| External corpus 2-standard-low-impact-discovery | 30.6 min | AC (battery at least 99 %) | 12 % / 5 % / 45 % | 11.9 GiB |
| External corpus 3-deep-low-impact-discovery | 30.7 min | AC (battery at least 99 %) | 12 % / 5 % / 45 % | 11.9 GiB |
| External corpus 3-deep-normal-acquisition | 23.2 min | AC (battery at least 99 %) | 7 % / 15 % / 35 % | 12.0 GiB |
| External corpus 3-deep-low-impact-acquisition | 28.8 min | AC (battery at least 99 %) | 7 % / 14 % / 35 % | 12.0 GiB |
| External corpus 1-quick-low-impact-acquisition | 17.2 min | AC (battery at least 99 %) | 1 % / 3 % / 25 % | 12.6 GiB |
| External corpus 2-standard-low-impact-acquisition | 21.5 min | AC (battery at least 99 %) | 1 % / 3 % / 25 % | 12.6 GiB |
| External corpus 2-standard-normal-acquisition | 12.6 min | AC (battery at least 99 %) | 2 % / 13 % / 27 % | 12.6 GiB |
| External corpus 1-quick-low-impact-discovery | 15.6 min | AC (battery at least 99 %) | 2 % / 10 % / 27 % | 12.6 GiB |
| External corpus 2-standard-normal-discovery | 11.6 min | AC (battery at least 99 %) | 6 % / 13 % / 50 % | 11.9 GiB |
| External corpus 3-deep-normal-discovery | 11.9 min | AC (battery at least 99 %) | 6 % / 13 % / 50 % | 11.9 GiB |
| External corpus 1-quick-normal-discovery | 4.5 min | AC (battery at least 99 %) | 2 % / 5 % / 22 % | 13.1 GiB |
| External corpus 1-quick-normal-acquisition | 4.6 min | AC (battery at least 99 %) | 2 % / 5 % / 22 % | 13.1 GiB |
| Mass scan c1, c4, program-c64, large-c1/c4/c16 (loopback fixtures) | 55.7 min | AC (battery at least 98 %) | 3 % / 2 % / 28 % | 13.0 GiB |
| Legacy evaluation (2.9.0 side, quiet rerun) | 0.1 min | AC (battery at least 98 %) | 4 % / 8 % / 8 % | 13.5 GiB |
| Acquisition evaluation (2.9.0 side, quiet rerun) | 0.1 min | AC (battery at least 98 %) | 6 % / 10 % / 25 % | 13.0 GiB |
| Frozen 2.5 corpus evaluation (2.8.0 and 2.9.0, 3 repeats, rerun alone) | 5.6 min | AC (battery at least 98 %) | 18 % / 12 % / 22 % | 12.9 GiB |
| Nonbrowser suite (final) | 18.6 min | AC (battery at least 98 %) | 10 % / 4 % / 31 % | 13.0 GiB |
| Browser suite (final) | 7.8 min | AC (battery at least 98 %) | 1 % / 12 % / 33 % | 12.4 GiB |
| CLI smoke (quiet rerun) | 0.1 min | AC (battery at least 98 %) | 1 % / 11 % / 11 % | 13.3 GiB |
| Provider corpus benchmark (quiet rerun) | 0.5 min | AC (battery at least 98 %) | 12 % / 9 % / 12 % | 13.5 GiB |

## Ready options on local fixtures

`scripts/profile-matrix.mjs` (plan §5), 2026-10-15: each of the six ready options as shipped, one scan per child process, on HTTPS loopback fixtures with synthetic, nonfunctional keys and an egress tripwire — a single site (8 keys: inline page, script, source map, split module, .env, configuration file, a depth-3 and a depth-5 page; plus an all-X placeholder decoy), a 1,252,570-byte bundle site (7 keys and a mutated decoy) and 3 or 10 subdomains of one registrable domain (single-site copies). Baseline: build 2.8.0+cc5fecf8cb75f1c7 with the same six ready options; its 24 rows (labelled 2.8.0) are reused from the 2.8.0 release records (`benchmarks/2.8.0/matrix.json`, measured 2026-10-12 on this computer with the same measurement harness and Node; owner decision 2026-10-11), not re-measured. A same-day spot check ran 6 of them again on the extracted 2.8.0 Windows x64 ZIP: 5 equal to the records in state, keys, connections and memory settings, time within 2.4 % (peak RSS +3.5 % to +10.8 %); the browser row standard+normal on 10 websites gave 70/80 keys as recorded, 489 requests against 490 in one run and 490 with 1 parser process against 2 in a second run, within the same-build variance on record for that row (`benchmarks/2.9.0/matrix-reuse.json`). No 2.9.0 row was more than 15 % slower than its 2.8.0 row, so no 2.8.0 row had to be measured again. "Keeps the 2.8.0 recall" compares each source-build row with the same option and fixture there. The fixture server counts requests, TCP connections, TLS handshakes and wire bytes; browser navigations, coverage and findings come from the scan record; peak RSS is the scan process (Chromium excluded); the analysis heap column lists, for builds that run the parser and the large-text checks in analysis processes, each role's processes × heap limit (the V8 old-space limit, held from the analysis memory setting) and the most heap limit held at once, and for earlier builds the parser worker's V8 heap high-water mark / limit sampled every 25 ms; the analysis-process RSS column is an upper bound on those processes' combined peak RSS (each process's own peak, summed over the processes alive at once), which is not part of the scan process's peak RSS. "In scope" is what each option's stated boundary reaches (Quick: entry documents and their files; Standard: depth 3; Deep: depth 5). Precision counts credential findings that match a planted key. "-small" runs inject a computer with 2 cores and 1 GiB free memory. Complete data: `benchmarks/2.9.0/matrix.json` and `matrix.md`.

| Run | Option | Fixture | State | Time s | Requests | TCP | TLS | Wire MiB | Browser nav | Peak RSS MiB | Analysis heap MiB (worker peak/limit, or processes×limit) | Analysis processes RSS MiB (bound) | Acquisition | Analysis | Recall (in scope) | Precision (credential findings) | Est. conns |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 2.8.0 | quick+normal | single×1 | completed (quick-coverage) | 13.1 | 25 | 25 | 25 | 0.11 | 0 | 186 | parser 1×256; ≤256 at once | 56 | 100% | 100% | 6/8  (6 expected) | 6/6 | — |
| 2.8.0 | quick+low-impact | single×1 | completed (quick-coverage) | 49.1 | 25 | 1 | 1 | 0.02 | 0 | 185 | parser 1×256; ≤256 at once | 56 | 100% | 100% | 6/8  (6 expected) | 6/6 | — |
| 2.8.0 | standard+normal | single×1 | incomplete | 38.9 | 49 | 49 | 49 | 0.22 | 5 | 201 | parser 1×128; ≤128 at once | 60 | 70% | 127% | 7/8  (7 expected) | 7/7 | — |
| 2.8.0 | standard+low-impact | single×1 | incomplete | 79.3 | 40 | 1 | 1 | 0.03 | 3 | 188 | parser 1×128; ≤128 at once | 59 | 65% | 133% | 7/8  (7 expected) | 7/7 | — |
| 2.8.0 | deep+normal | single×1 | incomplete | 78.9 | 61 | 61 | 61 | 0.27 | 10 | 199 | parser 1×256; ≤256 at once | 59 | 73% | 126% | 8/8  (8 expected) | 8/8 | — |
| 2.8.0 | deep+low-impact | single×1 | incomplete | 100.2 | 47 | 3 | 3 | 0.04 | 6 | 189 | parser 1×256; ≤256 at once | 59 | 69% | 131% | 8/8  (8 expected) | 8/8 | — |
| 2.8.0 | quick+normal | bundle×1 | incomplete | 15.6 | 29 | 29 | 29 | 1.32 | 0 | 260 | parser 2×256, detector 1×108; ≤256 at once | 233 | 100% | 100% | 7/7  (7 expected) | 7/7 | — |
| 2.8.0 | quick+low-impact | bundle×1 | incomplete | 57.6 | 29 | 1 | 1 | 1.21 | 0 | 248 | parser 2×256, detector 1×108; ≤256 at once | 234 | 100% | 100% | 7/7  (7 expected) | 7/7 | — |
| 2.8.0 | standard+normal | bundle×1 | incomplete | 21.3 | 41 | 41 | 41 | 2.57 | 1 | 334 | parser 3×128/256, detector 1×108; ≤256 at once | 291 | 66% | 137% | 7/7  (7 expected) | 7/7 | — |
| 2.8.0 | standard+low-impact | bundle×1 | incomplete | 73.3 | 37 | 1 | 1 | 2.42 | 1 | 295 | parser 3×128/256, detector 1×108; ≤256 at once | 289 | 63% | 142% | 7/7  (7 expected) | 7/7 | — |
| 2.8.0 | deep+normal | bundle×1 | incomplete | 23.6 | 41 | 41 | 41 | 2.57 | 1 | 310 | parser 1×256, detector 1×108; ≤364 at once | 397 | 66% | 137% | 7/7  (7 expected) | 7/7 | — |
| 2.8.0 | deep+low-impact | bundle×1 | incomplete | 73.2 | 37 | 1 | 1 | 2.42 | 1 | 295 | parser 1×256, detector 1×108; ≤364 at once | 397 | 63% | 142% | 7/7  (7 expected) | 7/7 | — |
| 2.8.0 | quick+normal | multi×3 | completed (quick-coverage) | 14.4 | 75 | 75 | 75 | 0.33 | 0 | 206 | parser 1×256; ≤256 at once | 57 | 100% | 100% | 18/24  (18 expected) | 18/18 | — |
| 2.8.0 | quick+low-impact | multi×3 | completed (quick-coverage) | 99.9 | 75 | 3 | 3 | 0.05 | 0 | 184 | parser 1×256; ≤256 at once | 58 | 100% | 100% | 18/24  (18 expected) | 18/18 | — |
| 2.8.0 | standard+normal | multi×3 | incomplete | 46.8 | 147 | 147 | 147 | 0.66 | 15 | 207 | parser 2×128; ≤256 at once | 119 | 81% | 115% | 21/24  (21 expected) | 21/21 | — |
| 2.8.0 | standard+low-impact | multi×3 | incomplete | 158.6 | 118 | 5 | 5 | 0.09 | 9 | 195 | parser 2×128; ≤256 at once | 117 | 78% | 119% | 21/24  (21 expected) | 21/21 | — |
| 2.8.0 | deep+normal | multi×3 | incomplete | 107.6 | 183 | 183 | 183 | 0.82 | 30 | 211 | parser 2×256; ≤512 at once | 118 | 82% | 116% | 24/24  (24 expected) | 24/24 | — |
| 2.8.0 | deep+low-impact | multi×3 | incomplete | 199.1 | 141 | 10 | 10 | 0.12 | 18 | 194 | parser 2×256; ≤512 at once | 117 | 80% | 118% | 24/24  (24 expected) | 24/24 | — |
| 2.8.0 | quick+normal | multi×10 | completed (quick-coverage) | 31.5 | 250 | 250 | 250 | 1.13 | 0 | 215 | parser 1×256; ≤256 at once | 58 | 100% | 100% | 60/80  (60 expected) | 60/60 | — |
| 2.8.0 | quick+low-impact | multi×10 | completed (quick-coverage) | 258.5 | 250 | 10 | 10 | 0.17 | 0 | 185 | parser 1×256; ≤256 at once | 57 | 100% | 100% | 60/80  (60 expected) | 60/60 | — |
| 2.8.0 | standard+normal | multi×10 | incomplete | 168.2 | 490 | 490 | 490 | 2.24 | 50 | 278 | parser 2×128; ≤256 at once | 118 | 86% | 111% | 70/80  (70 expected) | 70/70 | — |
| 2.8.0 | standard+low-impact | multi×10 | incomplete | 417.3 | 390 | 18 | 18 | 0.29 | 30 | 215 | parser 2×128; ≤256 at once | 116 | 83% | 113% | 70/80  (70 expected) | 70/70 | — |
| 2.8.0 | deep+normal | multi×10 | incomplete | 223.4 | 529 | 529 | 529 | 2.42 | 50 | 279 | parser 2×256; ≤512 at once | 116 | 87% | 111% | 80/80  (80 expected) | 80/80 | — |
| 2.8.0 | deep+low-impact | multi×10 | incomplete | 577.7 | 450 | 29 | 29 | 0.37 | 50 | 219 | parser 2×256; ≤512 at once | 117 | 87% | 112% | 80/80  (80 expected) | 80/80 | — |
| 2.9 | quick+normal | single×1 | completed (quick-coverage) | 13.1 | 25 | 25 | 25 | 0.11 | 0 | 207 | parser 1×256; ≤256 at once | 71 | 100% | 100% | 6/8  (6 expected) | 6/6 | — |
| 2.9 | quick+low-impact | single×1 | completed (quick-coverage) | 49.1 | 25 | 1 | 1 | 0.02 | 0 | 201 | parser 1×256; ≤256 at once | 71 | 100% | 100% | 6/8  (6 expected) | 6/6 | — |
| 2.9 | standard+normal | single×1 | incomplete | 39.4 | 49 | 49 | 49 | 0.22 | 5 | 209 | parser 1×128; ≤128 at once | 74 | 70% | 127% | 7/8  (7 expected) | 7/7 | — |
| 2.9 | standard+low-impact | single×1 | incomplete | 77.3 | 39 | 1 | 1 | 0.03 | 3 | 208 | parser 1×128; ≤128 at once | 73 | 67% | 131% | 7/8  (7 expected) | 7/7 | — |
| 2.9 | deep+normal | single×1 | incomplete | 79.7 | 61 | 61 | 61 | 0.27 | 10 | 210 | parser 1×256; ≤256 at once | 73 | 73% | 126% | 8/8  (8 expected) | 8/8 | — |
| 2.9 | deep+low-impact | single×1 | incomplete | 101.7 | 47 | 3 | 3 | 0.04 | 6 | 208 | parser 1×256; ≤256 at once | 73 | 69% | 131% | 8/8  (8 expected) | 8/8 | — |
| 2.9 | quick+normal | bundle×1 | incomplete | 15.7 | 29 | 29 | 29 | 1.32 | 0 | 281 | parser 2×256, detector 1×108; ≤256 at once | 248 | 100% | 100% | 7/7  (7 expected) | 7/7 | — |
| 2.9 | quick+low-impact | bundle×1 | incomplete | 57.7 | 29 | 1 | 1 | 1.21 | 0 | 280 | parser 2×256, detector 1×108; ≤256 at once | 247 | 100% | 100% | 7/7  (7 expected) | 7/7 | — |
| 2.9 | standard+normal | bundle×1 | incomplete | 21.4 | 41 | 41 | 41 | 2.57 | 1 | 312 | parser 3×128/256, detector 1×108; ≤256 at once | 319 | 66% | 137% | 7/7  (7 expected) | 7/7 | — |
| 2.9 | standard+low-impact | bundle×1 | incomplete | 73.2 | 37 | 1 | 1 | 2.42 | 1 | 306 | parser 3×128/256, detector 1×108; ≤256 at once | 318 | 63% | 142% | 7/7  (7 expected) | 7/7 | — |
| 2.9 | deep+normal | bundle×1 | incomplete | 23.9 | 41 | 41 | 41 | 2.57 | 1 | 314 | parser 1×256, detector 1×108; ≤364 at once | 426 | 66% | 137% | 7/7  (7 expected) | 7/7 | — |
| 2.9 | deep+low-impact | bundle×1 | incomplete | 73.2 | 37 | 1 | 1 | 2.42 | 1 | 308 | parser 1×256, detector 1×108; ≤364 at once | 423 | 63% | 142% | 7/7  (7 expected) | 7/7 | — |
| 2.9 | quick+normal | multi×3 | completed (quick-coverage) | 14.5 | 75 | 75 | 75 | 0.33 | 0 | 210 | parser 1×256; ≤256 at once | 71 | 100% | 100% | 18/24  (18 expected) | 18/18 | — |
| 2.9 | quick+low-impact | multi×3 | completed (quick-coverage) | 99.8 | 75 | 3 | 3 | 0.05 | 0 | 199 | parser 1×256; ≤256 at once | 71 | 100% | 100% | 18/24  (18 expected) | 18/18 | — |
| 2.9 | standard+normal | multi×3 | incomplete | 49.8 | 147 | 147 | 147 | 0.66 | 15 | 224 | parser 2×128; ≤256 at once | 147 | 81% | 115% | 21/24  (21 expected) | 21/21 | — |
| 2.9 | standard+low-impact | multi×3 | incomplete | 156.8 | 117 | 5 | 5 | 0.09 | 9 | 209 | parser 2×128; ≤256 at once | 144 | 78% | 118% | 21/24  (21 expected) | 21/21 | — |
| 2.9 | deep+normal | multi×3 | incomplete | 112.9 | 183 | 183 | 183 | 0.82 | 30 | 226 | parser 2×256; ≤512 at once | 146 | 82% | 116% | 24/24  (24 expected) | 24/24 | — |
| 2.9 | deep+low-impact | multi×3 | incomplete | 199.1 | 141 | 10 | 10 | 0.12 | 18 | 209 | parser 2×256; ≤512 at once | 144 | 80% | 118% | 24/24  (24 expected) | 24/24 | — |
| 2.9 | quick+normal | multi×10 | completed (quick-coverage) | 31.3 | 250 | 250 | 250 | 1.13 | 0 | 226 | parser 1×256; ≤256 at once | 72 | 100% | 100% | 60/80  (60 expected) | 60/60 | — |
| 2.9 | quick+low-impact | multi×10 | completed (quick-coverage) | 254.6 | 250 | 10 | 10 | 0.17 | 0 | 205 | parser 1×256; ≤256 at once | 71 | 100% | 100% | 60/80  (60 expected) | 60/60 | — |
| 2.9 | standard+normal | multi×10 | incomplete | 163.1 | 490 | 490 | 490 | 2.24 | 50 | 298 | parser 2×128; ≤256 at once | 146 | 86% | 111% | 70/80  (70 expected) | 70/70 | — |
| 2.9 | standard+low-impact | multi×10 | incomplete | 418.4 | 390 | 18 | 18 | 0.29 | 30 | 227 | parser 2×128; ≤256 at once | 146 | 83% | 113% | 70/80  (70 expected) | 70/70 | — |
| 2.9 | deep+normal | multi×10 | incomplete | 237.8 | 529 | 529 | 529 | 2.42 | 50 | 293 | parser 2×256; ≤512 at once | 146 | 87% | 111% | 80/80  (80 expected) | 80/80 | — |
| 2.9 | deep+low-impact | multi×10 | incomplete | 583.4 | 450 | 29 | 29 | 0.37 | 50 | 232 | parser 2×256; ≤512 at once | 144 | 87% | 112% | 80/80  (80 expected) | 80/80 | — |
| 2.9-small | quick+normal | bundle×1 | incomplete | 15.6 | 29 | 29 | 29 | 1.32 | 0 | 283 | parser 2×256, detector 1×108; ≤256 at once | 248 | 100% | 100% | 7/7  (7 expected) | 7/7 | — |
| 2.9-small | quick+low-impact | bundle×1 | incomplete | 57.6 | 29 | 1 | 1 | 1.21 | 0 | 282 | parser 2×256, detector 1×108; ≤256 at once | 249 | 100% | 100% | 7/7  (7 expected) | 7/7 | — |
| 2.9-small | standard+normal | bundle×1 | incomplete | 21.5 | 41 | 41 | 41 | 2.57 | 1 | 319 | parser 2×256, detector 1×108; ≤256 at once | 248 | 66% | 137% | 7/7  (7 expected) | 7/7 | — |
| 2.9-small | standard+low-impact | bundle×1 | incomplete | 73.2 | 37 | 1 | 1 | 2.42 | 1 | 306 | parser 2×256, detector 1×108; ≤256 at once | 248 | 63% | 142% | 7/7  (7 expected) | 7/7 | — |
| 2.9-small | deep+normal | bundle×1 | incomplete | 24.0 | 41 | 41 | 41 | 2.57 | 1 | 324 | parser 2×256, detector 1×108; ≤256 at once | 248 | 66% | 137% | 7/7  (7 expected) | 7/7 | — |
| 2.9-small | deep+low-impact | bundle×1 | incomplete | 73.2 | 37 | 1 | 1 | 2.42 | 1 | 306 | parser 2×256, detector 1×108; ≤256 at once | 248 | 63% | 142% | 7/7  (7 expected) | 7/7 | — |
| 2.9-small | quick+normal | multi×10 | completed (quick-coverage) | 31.4 | 250 | 250 | 250 | 1.13 | 0 | 224 | parser 1×256; ≤256 at once | 72 | 100% | 100% | 60/80  (60 expected) | 60/60 | — |
| 2.9-small | standard+normal | multi×10 | incomplete | 280.0 | 490 | 490 | 490 | 2.24 | 50 | 294 | parser 1×256; ≤256 at once | 74 | 86% | 111% | 70/80  (70 expected) | 70/70 | — |
| 2.9-small | deep+normal | multi×10 | incomplete | 360.6 | 520 | 520 | 520 | 2.38 | 50 | 238 | parser 1×256; ≤256 at once | 73 | 88% | 110% | 80/80  (80 expected) | 80/80 | — |

### Recorded resource use

| Option (websites at once / browser websites / analysis memory / workers) | This computer, 1 website | Small computer, 1 website | This computer, 3 websites | Small computer, 3 websites | This computer, 10 websites | Small computer, 10 websites |
|---|---|---|---|---|---|---|
| quick+normal | 1 / 0 / 256 MiB / 1 | 1 / 0 / 256 MiB / 1 | 3 / 0 / 256 MiB / 1 | 3 / 0 / 256 MiB / 1 | 6 / 0 / 256 MiB / 1 | 6 / 0 / 256 MiB / 1 |
| quick+low-impact | 1 / 0 / 256 MiB / 1 | 1 / 0 / 256 MiB / 1 | 2 / 0 / 256 MiB / 1 | 2 / 0 / 256 MiB / 1 | 2 / 0 / 256 MiB / 1 | 2 / 0 / 256 MiB / 1 |
| standard+normal | 1 / 1 / 256 MiB / 2 | 1 / 1* / 256 MiB / 1* | 3 / 2 / 256 MiB / 2 | 3 / 1* / 256 MiB / 1* | 4 / 2 / 256 MiB / 2 | 4 / 1* / 256 MiB / 1* |
| standard+low-impact | 1 / 1 / 256 MiB / 2 | 1 / 1 / 256 MiB / 1* | 2 / 1 / 256 MiB / 2 | 2 / 1 / 256 MiB / 1* | 2 / 1 / 256 MiB / 2 | 2 / 1 / 256 MiB / 1* |
| deep+normal | 1 / 1 / 512 MiB / 2 | 1 / 1* / 256* MiB / 1* | 3 / 2 / 512 MiB / 2 | 3 / 1* / 256* MiB / 1* | 3 / 2 / 512 MiB / 2 | 3 / 1* / 256* MiB / 1* |
| deep+low-impact | 1 / 1 / 512 MiB / 2 | 1 / 1 / 256* MiB / 1* | 2 / 1 / 512 MiB / 2 | 2 / 1 / 256* MiB / 1* | 2 / 1 / 512 MiB / 2 | 2 / 1 / 256* MiB / 1* |

This computer: 16 logical cores, 14.1 GiB free memory when recorded. Small computer: 2 cores and 1 GiB free memory, injected.

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
| Keeps the 2.8.0 recall | 24/24 | none |
| Adjustment only lowers | 36/36 | none |
| Settings as recorded | 33/33 | none |

## External synthetic corpus per ready option (additional measurement)

Not an acceptance target. Corpus `ExposureDesk/detection-corpus/v2`, written by a separate non-Claude AI and reviewed before use (working notes in `archive/notes/HANDOFF_EXTERNAL_CORPUS.md`, not packaged); pinned manifest `ef9187db6d80638d…` and scorer `5e01b10ec2d8e42e…`, re-hashed before use; 20 sites, 27 private values, 402 negative controls. Each site is served from 127.0.0.1 over HTTP and scanned with exact-origin scope and an egress tripwire; the JSON report is scored by the corpus's own scorer. The corpus stays outside the project and is never packaged. Counts describe this corpus only.

| Option | Mode | True / false positives / false negatives | Precision | Recall | Negative-control alerts | Requests | Scan time | Site states |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| quick+low-impact | acquisition | 27 / 3 / 0 | 0.900 | 1 | 3 | 526 | 17.2 min | incomplete 17, completed 3 |
| quick+low-impact | discovery | 24 / 3 / 3 | 0.889 | 0.889 | 3 | 474 | 15.6 min | incomplete 19, completed 1 |
| quick+normal | acquisition | 27 / 3 / 0 | 0.900 | 1 | 3 | 526 | 4.6 min | incomplete 17, completed 3 |
| quick+normal | discovery | 24 / 3 / 3 | 0.889 | 0.889 | 3 | 474 | 4.4 min | incomplete 19, completed 1 |
| standard+low-impact | acquisition | 27 / 3 / 0 | 0.900 | 1 | 3 | 587 | 21.5 min | incomplete 20 |
| standard+low-impact | discovery | 27 / 3 / 0 | 0.900 | 1 | 3 | 921 | 30.6 min | incomplete 20 |
| standard+normal | acquisition | 27 / 3 / 0 | 0.900 | 1 | 3 | 768 | 12.6 min | incomplete 20 |
| standard+normal | discovery | 27 / 3 / 0 | 0.900 | 1 | 3 | 1334 | 11.6 min | incomplete 20 |
| deep+low-impact | acquisition | 27 / 3 / 0 | 0.900 | 1 | 3 | 612 | 28.8 min | incomplete 20 |
| deep+low-impact | discovery | 27 / 3 / 0 | 0.900 | 1 | 3 | 922 | 30.6 min | incomplete 20 |
| deep+normal | acquisition | 27 / 3 / 0 | 0.900 | 1 | 3 | 1067 | 23.2 min | incomplete 20 |
| deep+normal | discovery | 27 / 3 / 0 | 0.900 | 1 | 3 | 1332 | 11.9 min | incomplete 20 |

## Target lists at scale (mass scan, loopback fixtures)

`scripts/mass-scan-measure.mjs`, 2026-10-15, build 2.9.0+b251a3ea63449d85, win32 x64, 8-core x86-64 laptop CPU (16 logical processors, 31.3 GiB): the built command line (`exposure-desk scan --targets FILE`) as a user runs it, against 200 synthetic targets on 50 loopback websites (127.0.0.1 to 127.0.0.50, one port); target i is page /t<n> of website i mod 50, so neighbouring targets are different websites. Each page holds its own synthetic, nonfunctional key inline and loads its website's /static/app.js, whose key all targets of that website share (cross-target de-duplication); everything else answers 404. Every run uses quick+normal, `--state`, `--jsonl` and a template that allows exactly the 50 fixture origins; runs at up to 16 targets at once use `--authorized`, the 64 run a program file (authorized, scope = the fixture origins, 50 requests per second, 64 targets and 64 requests at once). An egress tripwire in the scan process refuses and records any socket or DNS lookup outside loopback: 0 recorded. Requests are counted at the fixture; peak RSS is the scan process sampled every 25 ms; the analysis budget is the one memory budget all targets of a run draw from (capacity / highest use / analysis-process heap limits held at once); analysis processes are counted separately from the scan process. Complete data: `benchmarks/2.9.0/mass-scan.json`.

| Run | Targets | At once | Wall time | Requests (per second) | Targets per second | Scan-process peak RSS | Analysis budget: capacity / peak / heap held at once | Analysis processes: started / peak RSS at once | Own keys / shared keys found | Target states |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| c1 | 200 | 1 | 37.3 min | 4400 (2) | 0.09 | 204 MiB | 256 / 256 / 256 MiB | 1 / 74 MiB | 200/200 / 50/50 | done 200 (stop reasons: quick-target-set-done 200) |
| c4 | 200 | 4 | 9.9 min | 4400 (7.4) | 0.34 | 309 MiB | 256 / 256 / 256 MiB | 1 / 74 MiB | 200/200 / 50/50 | done 200 (stop reasons: quick-target-set-done 200) |
| c16 | 200 | 16 | 3.5 min | 4400 (21.2) | 0.96 | 329 MiB | 256 / 256 / 256 MiB | 1 / 74 MiB | 200/200 / 50/50 | done 200 (stop reasons: quick-target-set-done 200) |
| program-c64 (program file) | 200 | 64 | 2.9 min | 4400 (25.4) | 1.16 | 357 MiB | 256 / 256 / 256 MiB | 1 / 74 MiB | 200/200 / 50/50 | done 200 (stop reasons: quick-target-set-done 200) |
| large-c1 (standard+normal) | 16 | 1 | 4.0 min | 448 (1.9) | 0.07 | 379 MiB | 256 / 256 / 256 MiB | 48 / 283 MiB | 16/16 / 16/16 | failed 16 (stop reasons: discovered-frontier-drained 16) |
| large-c4 (standard+normal) | 16 | 4 | 66.3 s | 448 (6.8) | 0.24 | 382 MiB | 256 / 256 / 256 MiB | 43 / 375 MiB | 16/16 / 16/16 | failed 16 (stop reasons: discovered-frontier-drained 16) |
| large-c16 (standard+normal) | 16 | 16 | 28.0 s | 448 (16) | 0.57 | 390 MiB | 256 / 256 / 256 MiB | 43 / 371 MiB | 16/16 / 16/16 | failed 16 (stop reasons: discovered-frontier-drained 16) |

"Target states" are the run-state file's: `done` = completed, `failed` = any target that did not complete (here `incomplete`). `origin-deadline-reached` means the target's per-website time allowance (the coverage's duration, for quick 120 s of wall-clock time from the website's first request, not paused while the target waits) ran out before the target finished: all targets of a run share one analysis budget, so with more targets at once each one waits longer between its requests. Keys found before the allowance ran out are reported; a resumed run (`--state`) scans the unfinished targets again. Unfinished targets: large-c1 16 of 16, large-c4 16 of 16, large-c16 16 of 16. The large-bundle runs serve each of 16 targets its own 1.25 MB bundle (8 parse, 8 fail both parses) and scan with Standard + Normal; every target ends incomplete after its discovered pages are done and the run exits 2, as in the development runs, while all 48 findings (33 unique, every per-target and shared key) are reported with 0 unexpected findings. Their scan-process peaks of 379, 382 and 390 MiB stay under the 512 MiB ready-option ceiling; 2.8.0 code peaked at 378, 577 and 557 MiB on the same rows (CHANGELOG_2.9.md, Memory). Against 2.8.0 (`benchmarks/2.8.0/mass-scan.json`): c1 37.3 min (37.9), c4 9.9 min (10.3), c16 3.5 min (3.9), program-c64 2.9 min (3.4) with the longest single wait for a program request slot 3.1 s (23.8 s); peaks 204, 309, 329 and 357 MiB (185, 297, 363 and 319). The resume and block-halt measurements were not repeated for 2.9.0 (the tests cover them; 2.8.0 figures in the 2.8.0 section below).

## Legacy settings on the frozen 2.5 corpus (2.8.0 → 2.9.0)

Corpus `scripts/eval-2.5-corpus.mjs`, digest `41f8c2dd214da8bd…`, frozen 2026-10-08T04:15:23.216Z. The 2.5 release corpus, unchanged, run with its own legacy (preset and custom) configurations, none of which names a coverage or traffic level; it checks that such configurations still behave as in the previous release apart from intended detection changes. Each group ran 3× per build in separate child processes with an egress tripwire, alternating builds; the first repetition's measurements are shown and the result is identical across repetitions unless noted in `benchmarks/2.9.0/evaluation.json`. Baseline: 2.8.0+cc5fecf8cb75f1c7.

| Group · measurement | 2.8.0 | 2.9.0 |
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
| G5F corrected 1,252,570-byte bundle · split key found (engine off / on) | 0/1 / 0/1 | 0/1 / 0/1 |
| G5F · negatives reported (mutated alias, test key, publishable key) | 1 / 1 | 1 / 1 |
| G6 shortDeadline · non-terminal states / pending inventory rows / state | 0 / 0 / incomplete | 0 / 0 / incomplete |
| G6 cancelAfterDownload · non-terminal states / pending inventory rows / state | 0 / 0 / cancelled | 0 / 0 / cancelled |
| G6 smallSlices · non-terminal states / pending inventory rows / state | 0 / 0 / incomplete | 0 / 0 / incomplete |
| G7 wallets, keys, signing and priority cases · website rules only | 23/23 detected · 0 false positives of 16 negatives · precision 1 · recall 1 | 23/23 detected · 0 false positives of 16 negatives · precision 1 · recall 1 |
| G7 · with the pinned engine | 23/23 detected · 0 false positives of 16 negatives · precision 1 · recall 1 | 23/23 detected · 0 false positives of 16 negatives · precision 1 · recall 1 |
| G7 · expected priority matched | 9/11 | 9/11 |
| G8 · static User-Agent | Mozilla/5.0 (compatible; ExposureDesk/2.8) | Mozilla/5.0 (compatible; ExposureDesk/2.9) |
| G8 · browser language / time zone reported by the page | en-US / UTC | en-US / UTC |
| G8 · headers repeating the page path or query | 0 | 0 |
| G9 · two identical starts 50 ms apart: HTTP statuses / runs created / same run returned | 202, 202 / 1 / true | 202, 202 / 1 / true |

| Group · median wall time per child / peak Node RSS | 2.8.0 | 2.9.0 |
| --- | --- | --- |
| G1 | 1598 ms / 238.2 MiB | 1576 ms / 234.4 MiB |
| G2 | 4700 ms / 243.6 MiB | 5151 ms / 231.9 MiB |
| G3 | 12263 ms / 237.9 MiB | 13029 ms / 231.0 MiB |
| G4 | 2193 ms / 242.8 MiB | 2202 ms / 231.6 MiB |
| G5 | 6403 ms / 480.1 MiB | 5930 ms / 401.3 MiB |
| G5F | 6097 ms / 432.1 MiB | 6188 ms / 431.5 MiB |
| G6 | 4551 ms / 472.1 MiB | 4092 ms / 397.7 MiB |
| G7 | 8467 ms / 225.9 MiB | 8542 ms / 230.0 MiB |
| G8 | 4774 ms / 244.1 MiB | 5181 ms / 230.9 MiB |
| G9 | 2867 ms / 240.4 MiB | 2856 ms / 229.3 MiB |

2.8.0 legacy-evaluation figures reused from the 2.8.0 release records (owner decision 2026-10-11), not re-measured: the 2.8.0 column is `benchmarks/2.8.0/final-legacy-evaluation.json` and `benchmarks/2.8.0/final-acquisition.json` (build 2.8.0+cc5fecf8cb75f1c7, measured 2026-10-12, so its elapsed time and peak RSS are not a same-day comparison); the evaluation scripts and their inline corpora are unchanged since that release, and only the 2.9.0 column was measured for this release.

| Legacy 2.4 corpora (unchanged) | 2.8.0 | 2.9.0 |
| --- | --- | --- |
| 48-case detector corpus: credential targets detected / false positives | 13/13 / 0 | 13/13 / 0 |
| Data-exposure targets detected / false positives | 5/5 / 0 | 5/5 / 0 |
| Corpus elapsed / Node peak RSS | 2.470 s / 208.6 MiB | 2.541 s / 227.0 MiB |
| Dynamic application: credential targets / known resources inspected / forbidden arrivals | 5/5 / 9/9 / 0 | 5/5 / 9/9 / 0 |

Limitations: synthetic, nonfunctional values and local fixtures only (loopback servers and a virtual network); every timing and memory figure is from one Windows x64 host (the Linux x64 suites, package and container are pass/fail results from GitHub-hosted Ubuntu runners, without timing claims); single-digit repetitions without statistical controls; Node peak RSS includes worker threads but excludes Chromium, Gitleaks and the analysis child processes (the ready-option table reports the analysis processes separately). Ready-option durations depend on the fixtures' sizes and on this computer; the small-computer rows inject the computer description, they do not run on slower hardware. These counts describe this corpus only and make no general accuracy claim. macOS and ARM were not exercised; Linux x64 only on the CI runners named above. No owner website or production response was contacted or used.
