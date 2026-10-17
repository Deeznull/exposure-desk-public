# Actual verification — 2.6.0-rc.1

Build 2.6.0-rc.1+43dc0e2d6c36202f. Windows x64 with the bundled Node 24.18.1, locked dependencies, Gitleaks 8.30.1 and Chrome for Testing 153.0.8010.12 / Playwright 1.63.0. Rules website/2.6.0; structural data checks exposure/1.0. Ready options, limits and traffic: [UPGRADE_2.6.md](UPGRADE_2.6.md); data upgrade: [MIGRATION_2.6.md](MIGRATION_2.6.md).

| Final check | Actual result |
| --- | --- |
| Nonbrowser regressions | 404/404 passed, 0 failed or skipped; 451.4 s |
| Browser and UI regressions | 33/33 passed, 0 failed or skipped; 497.4 s |
| Repeated Chromium cancellation stress | 60/60 passed; 213.6 s |
| CLI child processes | 4 exit/masking checks passed |
| Protected persistence (temporary data directory) | projectRestart, correlationRestart, vaultRestart, operatorPermissions, deletion |
| Selected provider corpus (pinned engine) | 110/110 targets; 0 false positives; 0 component / 0 location errors |
| Full acquisition pipeline | passed; 17/17 fixtures |
| Ready options on local fixtures | 134/134 acceptance checks met over 45 scans (below) |
| Release preflight | passed (earlier release archive hashes, baseline parity, pinned runtime/detector/browser, wordlist and corpus digests) |

The browser suite on the build before the release-script fix had 32/33 once: `test/repair-browser.test.ts` test 1 is timing-dependent (see HANDOFF.md, known gaps). Its rerun, 5 focused reruns and the suite above on this build passed.

## Ready options on local fixtures

`scripts/profile-matrix.mjs` (plan §5), 2026-10-09: each of the six ready options as shipped, one scan per child process, on HTTPS loopback fixtures with synthetic, nonfunctional keys and an egress tripwire — a single site (8 keys: inline page, script, source map, split module, .env, configuration file, a depth-3 and a depth-5 page; plus an all-X placeholder decoy), a 1,252,570-byte bundle site (7 keys and a mutated decoy) and 3 or 10 subdomains of one registrable domain (single-site copies). Baseline: the 2.5.0-rc.1 Windows x64 release ZIP, extracted and run with its legacy presets (it has no ready options). The fixture server counts requests, TCP connections, TLS handshakes and wire bytes; browser navigations, coverage and findings come from the scan record; peak RSS is the scan process (Chromium excluded); the parser heap is the static-analysis worker's V8 heap high-water mark sampled every 25 ms. "In scope" is what each option's stated boundary reaches (Quick: entry documents and their files; Standard: depth 3; Deep: depth 5). Precision counts credential findings that match a planted key. "-small" runs inject a computer with 2 cores and 1 GiB free memory. Complete data: `benchmarks/2.6/matrix.json` and `matrix.md` (there the 2.5 Quick multi×3 run, added after the first pass, is listed last). Measured on build 2.6.0-rc.1+b6fec2bbb9e6f13b, as was the external corpus below; the release build differs from it only in two release scripts (`scripts/release-summary.mjs`, `scripts/eval-2.5.mjs`), so the scanner, rules, dashboard and tests measured are the released ones.

| Run | Option | Fixture | State | Time s | Requests | TCP | TLS | Wire MiB | Browser nav | Peak RSS MiB | Parser heap MiB (peak/limit per worker) | Acquisition | Analysis | Recall (in scope) | Precision (credential findings) | Est. conns |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 2.5 | 2.5 quick | single×1 | incomplete | 13.4 | 14 | 14 | 14 | 0.06 | 0 | 176 | 12/128 | 88% | 100% | 4/8  | 4/5 decoys 1 | — |
| 2.5 | 2.5 standard | single×1 | incomplete | 41.6 | 30 | 30 | 30 | 0.13 | 5 | 186 | 12/128 | 58% | 146% | 5/8  | 5/6 decoys 1 | — |
| 2.5 | 2.5 thorough | single×1 | incomplete | 94.2 | 59 | 59 | 59 | 0.26 | 10 | 186 | 13/128 | 72% | 127% | 8/8  | 8/9 decoys 1 | — |
| 2.5 | 2.5 quick | bundle×1 | incomplete | 11.8 | 11 | 11 | 11 | 1.24 | 0 | 378 | 109/128+256 | 100% | 100% | 5/7  | 5/5 | — |
| 2.5 | 2.5 standard | bundle×1 | incomplete | 20.2 | 22 | 22 | 22 | 2.49 | 1 | 395 | 109/128+256 | 47% | 181% | 5/7  | 5/5 | — |
| 2.5 | 2.5 thorough | bundle×1 | incomplete | 29.5 | 39 | 39 | 39 | 2.56 | 1 | 394 | 108/128+256 | 65% | 139% | 7/7  | 7/7 | — |
| 2.5 | 2.5 quick | multi×3 | incomplete | 16.6 | 26 | 26 | 26 | 0.12 | 0 | 190 | 12/128 | 67% | 100% | 12/24  | 12/13 decoys 1 | — |
| 2.5 | 2.5 standard | multi×3 | incomplete | 54.9 | 74 | 74 | 74 | 0.33 | 5 | 204 | 17/128 | 68% | 129% | 15/24  | 15/16 decoys 1 | — |
| 2.5 | 2.5 thorough | multi×3 | incomplete | 108.1 | 150 | 150 | 150 | 0.67 | 15 | 223 | 13/128 | 83% | 114% | 24/24  | 24/25 decoys 1 | — |
| 2.5 | 2.5 quick | multi×10 | incomplete | 43.6 | 50 | 50 | 50 | 0.23 | 0 | 175 | 12/128 | 49% | 100% | 32/80  | 32/33 decoys 1 | — |
| 2.5 | 2.5 standard | multi×10 | incomplete | 101.0 | 130 | 130 | 130 | 0.60 | 5 | 198 | 12/128 | 58% | 123% | 40/80  | 40/41 decoys 1 | — |
| 2.5 | 2.5 thorough | multi×10 | incomplete | 468.8 | 411 | 411 | 411 | 1.88 | 15 | 220 | 13/128 | 84% | 112% | 68/80  | 68/69 decoys 1 | — |
| 2.6 | quick+normal | single×1 | completed (quick-coverage) | 16.3 | 25 | 25 | 25 | 0.11 | 0 | 176 | 12/256 | 100% | 100% | 6/8  (6 expected) | 6/7 decoys 1 | — |
| 2.6 | quick+low-impact | single×1 | completed (quick-coverage) | 49.5 | 25 | 1 | 1 | 0.02 | 0 | 176 | 12/256 | 100% | 100% | 6/8  (6 expected) | 6/7 decoys 1 | — |
| 2.6 | standard+normal | single×1 | incomplete | 43.6 | 49 | 49 | 49 | 0.22 | 5 | 193 | 13/128 | 70% | 127% | 7/8  (7 expected) | 7/8 decoys 1 | — |
| 2.6 | standard+low-impact | single×1 | incomplete | 79.7 | 40 | 1 | 1 | 0.03 | 3 | 182 | 13/128 | 65% | 133% | 7/8  (7 expected) | 7/8 decoys 1 | — |
| 2.6 | deep+normal | single×1 | incomplete | 88.1 | 61 | 61 | 61 | 0.27 | 10 | 183 | 12/256 | 73% | 126% | 8/8  (8 expected) | 8/9 decoys 1 | — |
| 2.6 | deep+low-impact | single×1 | incomplete | 101.1 | 47 | 3 | 3 | 0.04 | 6 | 181 | 13/256 | 69% | 131% | 8/8  (8 expected) | 8/9 decoys 1 | — |
| 2.6 | quick+normal | bundle×1 | incomplete | 20.2 | 29 | 29 | 29 | 1.32 | 0 | 387 | 110/256 | 100% | 100% | 7/7  (7 expected) | 7/7 | — |
| 2.6 | quick+low-impact | bundle×1 | incomplete | 59.8 | 29 | 2 | 2 | 1.22 | 0 | 356 | 109/256 | 100% | 100% | 7/7  (7 expected) | 7/7 | — |
| 2.6 | standard+normal | bundle×1 | incomplete | 28.1 | 41 | 41 | 41 | 2.57 | 1 | 405 | 108/128+256 | 66% | 137% | 7/7  (7 expected) | 7/7 | — |
| 2.6 | standard+low-impact | bundle×1 | incomplete | 73.7 | 37 | 1 | 1 | 2.42 | 1 | 371 | 108/128+256 | 65% | 142% | 7/7  (7 expected) | 7/7 | — |
| 2.6 | deep+normal | bundle×1 | incomplete | 29.1 | 41 | 41 | 41 | 2.57 | 1 | 403 | 109/256 | 66% | 137% | 7/7  (7 expected) | 7/7 | — |
| 2.6 | deep+low-impact | bundle×1 | incomplete | 73.8 | 37 | 1 | 1 | 2.42 | 1 | 376 | 108/256 | 63% | 142% | 7/7  (7 expected) | 7/7 | — |
| 2.6 | quick+normal | multi×3 | completed (quick-coverage) | 37.1 | 75 | 75 | 75 | 0.33 | 0 | 181 | 12/256 | 100% | 100% | 18/24  (18 expected) | 18/19 decoys 1 | — |
| 2.6 | quick+low-impact | multi×3 | completed (quick-coverage) | 100.8 | 75 | 3 | 3 | 0.05 | 0 | 176 | 12/256 | 100% | 100% | 18/24  (18 expected) | 18/19 decoys 1 | — |
| 2.6 | standard+normal | multi×3 | incomplete | 91.3 | 148 | 148 | 148 | 0.66 | 15 | 217 | 12/128 | 81% | 116% | 21/24  (21 expected) | 21/22 decoys 1 | — |
| 2.6 | standard+low-impact | multi×3 | incomplete | 161.0 | 118 | 5 | 5 | 0.09 | 9 | 186 | 13/128 | 78% | 119% | 21/24  (21 expected) | 21/22 decoys 1 | — |
| 2.6 | deep+normal | multi×3 | incomplete | 158.0 | 183 | 183 | 183 | 0.82 | 30 | 223 | 12/256 | 82% | 116% | 24/24  (24 expected) | 24/25 decoys 1 | — |
| 2.6 | deep+low-impact | multi×3 | incomplete | 200.3 | 141 | 9 | 9 | 0.12 | 18 | 229 | 13/256 | 80% | 118% | 24/24  (24 expected) | 24/25 decoys 1 | — |
| 2.6 | quick+normal | multi×10 | completed (quick-coverage) | 121.9 | 250 | 250 | 250 | 1.13 | 0 | 215 | 12/256 | 100% | 100% | 60/80  (60 expected) | 60/61 decoys 1 | — |
| 2.6 | quick+low-impact | multi×10 | completed (quick-coverage) | 257.1 | 250 | 10 | 10 | 0.17 | 0 | 176 | 12/256 | 100% | 100% | 60/80  (60 expected) | 60/61 decoys 1 | — |
| 2.6 | standard+normal | multi×10 | incomplete | 309.2 | 484 | 484 | 484 | 2.22 | 50 | 291 | 12/128 | 86% | 111% | 70/80  (70 expected) | 70/71 decoys 1 | — |
| 2.6 | standard+low-impact | multi×10 | incomplete | 420.9 | 390 | 18 | 18 | 0.29 | 30 | 298 | 13/128 | 83% | 113% | 70/80  (70 expected) | 70/71 decoys 1 | — |
| 2.6 | deep+normal | multi×10 | incomplete | 350.5 | 529 | 529 | 529 | 2.42 | 50 | 295 | 12/256 | 87% | 111% | 80/80  (80 expected) | 80/81 decoys 1 | — |
| 2.6 | deep+low-impact | multi×10 | incomplete | 568.3 | 450 | 28 | 28 | 0.37 | 50 | 301 | 13/256 | 87% | 112% | 80/80  (80 expected) | 80/81 decoys 1 | — |
| 2.6-small | quick+normal | bundle×1 | incomplete | 19.6 | 29 | 29 | 29 | 1.32 | 0 | 385 | 109/256 | 100% | 100% | 7/7  (7 expected) | 7/7 | — |
| 2.6-small | quick+low-impact | bundle×1 | incomplete | 59.1 | 29 | 1 | 1 | 1.21 | 0 | 364 | 109/256 | 100% | 100% | 7/7  (7 expected) | 7/7 | — |
| 2.6-small | standard+normal | bundle×1 | incomplete | 27.8 | 41 | 41 | 41 | 2.57 | 1 | 402 | 109/256 | 66% | 137% | 7/7  (7 expected) | 7/7 | — |
| 2.6-small | standard+low-impact | bundle×1 | incomplete | 73.6 | 37 | 1 | 1 | 2.42 | 1 | 375 | 101/256 | 63% | 142% | 7/7  (7 expected) | 7/7 | — |
| 2.6-small | deep+normal | bundle×1 | incomplete | 28.5 | 41 | 41 | 41 | 2.57 | 1 | 403 | 109/256 | 66% | 137% | 7/7  (7 expected) | 7/7 | — |
| 2.6-small | deep+low-impact | bundle×1 | incomplete | 73.7 | 37 | 1 | 1 | 2.42 | 1 | 379 | 109/256 | 63% | 142% | 7/7  (7 expected) | 7/7 | — |
| 2.6-small | quick+normal | multi×10 | completed (quick-coverage) | 111.0 | 250 | 250 | 250 | 1.13 | 0 | 213 | 12/256 | 100% | 100% | 60/80  (60 expected) | 60/61 decoys 1 | — |
| 2.6-small | standard+normal | multi×10 | incomplete | 341.3 | 479 | 479 | 479 | 2.19 | 42 | 290 | 12/256 | 86% | 111% | 70/80  (70 expected) | 70/71 decoys 1 | — |
| 2.6-small | deep+normal | multi×10 | incomplete | 453.2 | 520 | 520 | 520 | 2.38 | 50 | 291 | 12/256 | 88% | 110% | 80/80  (80 expected) | 80/81 decoys 1 | — |

### Recorded resource use

| Option (websites at once / browser websites / analysis memory / workers) | This computer, 1 website | Small computer, 1 website | This computer, 3 websites | Small computer, 3 websites | This computer, 10 websites | Small computer, 10 websites |
|---|---|---|---|---|---|---|
| quick+normal | 1 / 0 / 256 MiB / 1 | 1 / 0 / 256 MiB / 1 | 3 / 0 / 256 MiB / 1 | 3 / 0 / 256 MiB / 1 | 6 / 0 / 256 MiB / 1 | 6 / 0 / 256 MiB / 1 |
| quick+low-impact | 1 / 0 / 256 MiB / 1 | 1 / 0 / 256 MiB / 1 | 2 / 0 / 256 MiB / 1 | 2 / 0 / 256 MiB / 1 | 2 / 0 / 256 MiB / 1 | 2 / 0 / 256 MiB / 1 |
| standard+normal | 1 / 1 / 256 MiB / 2 | 1 / 1* / 256 MiB / 1* | 3 / 2 / 256 MiB / 2 | 3 / 1* / 256 MiB / 1* | 4 / 2 / 256 MiB / 2 | 4 / 1* / 256 MiB / 1* |
| standard+low-impact | 1 / 1 / 256 MiB / 2 | 1 / 1 / 256 MiB / 1* | 2 / 1 / 256 MiB / 2 | 2 / 1 / 256 MiB / 1* | 2 / 1 / 256 MiB / 2 | 2 / 1 / 256 MiB / 1* |
| deep+normal | 1 / 1 / 512 MiB / 2 | 1 / 1* / 256* MiB / 1* | 3 / 2 / 512 MiB / 2 | 3 / 1* / 256* MiB / 1* | 3 / 2 / 512 MiB / 2 | 3 / 1* / 256* MiB / 1* |
| deep+low-impact | 1 / 1 / 512 MiB / 2 | 1 / 1 / 256* MiB / 1* | 2 / 1 / 512 MiB / 2 | 2 / 1 / 256* MiB / 1* | 2 / 1 / 512 MiB / 2 | 2 / 1 / 256* MiB / 1* |

This computer: 16 logical cores, 18.3 GiB free memory when recorded. Small computer: 2 cores and 1 GiB free memory, injected.

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

## External synthetic corpus per ready option (additional measurement)

Not an acceptance target. Corpus `ExposureDesk/detection-corpus/v2`, written by a separate non-Claude AI and reviewed before use (working notes in `archive/notes/HANDOFF_EXTERNAL_CORPUS.md`, not packaged); pinned manifest `ef9187db6d80638d…` and scorer `5e01b10ec2d8e42e…`, re-hashed before use; 20 sites, 27 private values, 402 negative controls. Each site is served from 127.0.0.1 over HTTP and scanned with exact-origin scope and an egress tripwire; the JSON report is scored by the corpus's own scorer. The corpus stays outside the project and is never packaged. Counts describe this corpus only.

| Option | Mode | True / false positives / false negatives | Precision | Recall | Negative-control alerts | Requests | Scan time | Site states |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| quick+low-impact | acquisition | 27 / 3 / 0 | 0.900 | 1 | 3 | 526 | 17.4 min | incomplete 17, completed 3 |
| quick+low-impact | discovery | 24 / 3 / 3 | 0.889 | 0.889 | 3 | 474 | 15.9 min | incomplete 19, completed 1 |
| quick+normal | acquisition | 27 / 3 / 0 | 0.900 | 1 | 3 | 526 | 5.8 min | incomplete 17, completed 3 |
| quick+normal | discovery | 24 / 3 / 3 | 0.889 | 0.889 | 3 | 474 | 5.8 min | incomplete 19, completed 1 |
| standard+low-impact | acquisition | 27 / 3 / 0 | 0.900 | 1 | 3 | 587 | 23.0 min | incomplete 20 |
| standard+low-impact | discovery | 27 / 3 / 0 | 0.900 | 1 | 3 | 921 | 30.8 min | incomplete 20 |
| standard+normal | acquisition | 27 / 3 / 0 | 0.900 | 1 | 3 | 768 | 14.6 min | incomplete 20 |
| standard+normal | discovery | 27 / 3 / 0 | 0.900 | 1 | 3 | 1332 | 13.7 min | incomplete 20 |
| deep+low-impact | acquisition | 27 / 3 / 0 | 0.900 | 1 | 3 | 612 | 30.5 min | incomplete 20 |
| deep+low-impact | discovery | 27 / 3 / 0 | 0.900 | 1 | 3 | 922 | 30.9 min | incomplete 20 |
| deep+normal | acquisition | 27 / 3 / 0 | 0.900 | 1 | 3 | 1067 | 25.3 min | incomplete 20 |
| deep+normal | discovery | 27 / 3 / 0 | 0.900 | 1 | 3 | 1327 | 13.7 min | incomplete 20 |

## Legacy settings on the frozen 2.5 corpus (2.5.0-rc.1 → 2.6.0-rc.1)

Corpus `scripts/eval-2.5-corpus.mjs`, digest `41f8c2dd214da8bd…`, frozen 2026-10-08T04:15:23.216Z. The 2.5 release corpus, unchanged, run with its own legacy (preset and custom) configurations, none of which names a coverage or traffic level; it checks that such configurations still behave as in the previous release apart from intended detection changes. Each group ran 3× per build in separate child processes with an egress tripwire, alternating builds; the first repetition's measurements are shown and the result is identical across repetitions unless noted in `benchmarks/2.6/evaluation.json`. Baseline: 2.5.0-rc.1+97836a16c30888f3.

| Group · measurement | 2.5.0-rc.1 | 2.6.0-rc.1 |
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
| G8 · static User-Agent | Mozilla/5.0 (compatible; ExposureDesk/2.5) | Mozilla/5.0 (compatible; ExposureDesk/2.6) |
| G8 · browser language / time zone reported by the page | en-US / UTC | en-US / UTC |
| G8 · headers repeating the page path or query | 0 | 0 |
| G9 · two identical starts 50 ms apart: HTTP statuses / runs created / same run returned | 202, 202 / 1 / true | 202, 202 / 1 / true |

Differences beyond the table, identical in all 3 repetitions of each build: G5 and G6 take longer and peak memory is higher on the 1,252,570-byte bundle, because 2.6 parses whole scripts up to 2 MiB once for provider context (`website/2.6.0`, see CHANGELOG_2.6.md). G6 cancelAfterDownload cancels 150 ms after the bundle request arrives: 2.5 had finished that bundle's text analysis by then (1 finding), 2.6 had not and reports the bundle as deferred (5 important resources not inspected instead of 4, no finding from it). The lifecycle gates hold in both builds: no non-terminal analyzer state, no pending inventory row, state cancelled.

| Group · median wall time per child / peak Node RSS | 2.5.0-rc.1 | 2.6.0-rc.1 |
| --- | --- | --- |
| G1 | 1210 ms / 200.6 MiB | 1221 ms / 201.2 MiB |
| G2 | 3600 ms / 189.2 MiB | 3910 ms / 191.4 MiB |
| G3 | 10467 ms / 190.5 MiB | 10138 ms / 192.2 MiB |
| G4 | 1955 ms / 193.8 MiB | 1991 ms / 195.7 MiB |
| G5 | 9736 ms / 490.7 MiB | 10788 ms / 676.0 MiB |
| G6 | 3087 ms / 586.2 MiB | 3804 ms / 645.8 MiB |
| G7 | 18838 ms / 181.5 MiB | 18824 ms / 186.3 MiB |
| G8 | 4079 ms / 189.5 MiB | 3908 ms / 190.1 MiB |
| G9 | 4350 ms / 180.2 MiB | 4357 ms / 195.0 MiB |

| Legacy 2.4 corpora (unchanged) | 2.5.0-rc.1 | 2.6.0-rc.1 |
| --- | --- | --- |
| 48-case detector corpus: credential targets detected / false positives | 13/13 / 0 | 13/13 / 0 |
| Data-exposure targets detected / false positives | 5/5 / 0 | 5/5 / 0 |
| Corpus elapsed / Node peak RSS | 1.437 s / 228.0 MiB | 1.426 s / 228.4 MiB |
| Dynamic application: credential targets / known resources inspected / forbidden arrivals | 5/5 / 9/9 / 0 | 5/5 / 9/9 / 0 |

Limitations: synthetic, nonfunctional values and local fixtures only (loopback servers and a virtual network); one Windows x64 host; single-digit repetitions without statistical controls; Node peak RSS includes workers but excludes Chromium and Gitleaks children. Ready-option durations depend on the fixtures' sizes and on this computer; the small-computer rows inject the computer description, they do not run on slower hardware. These counts describe this corpus only and make no general accuracy claim. Linux, macOS and ARM were not exercised. No owner website or production response was contacted or used.
