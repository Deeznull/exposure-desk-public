# P4 measurement matrix (generated 2026-10-15T01:17:46.617Z)

Rows labelled 2.8.0: 2.8.0 matrix figures reused from the 2.8.0 release records (owner decision 2026-10-11), after a same-day spot check of 6 rows on the extracted 2.8.0 Windows ZIP (`matrix-reuse.json`).

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

## Freshness

- 2.9 source build: 2.9.0+b251a3ea63449d85, harness 43537d3099028d72, Node v24.18.1
- 2.8.0 baseline: 2.8.0+cc5fecf8cb75f1c7, harness 43537d3099028d72, Node v24.18.1
- 58 of 58 rows current; 0 stale; 0 failed; 0 measured alongside other cases ("alongside": their times can be longer than a serial run's)

## Resource use (recorded, no network)

| Option (websites at once / browser websites / analysis memory / workers) | This computer, 1 website | Small computer, 1 website | This computer, 3 websites | Small computer, 3 websites | This computer, 10 websites | Small computer, 10 websites |
|---|---|---|---|---|---|---|
| quick+normal | 1 / 0 / 256 MiB / 1 | 1 / 0 / 256 MiB / 1 | 3 / 0 / 256 MiB / 1 | 3 / 0 / 256 MiB / 1 | 6 / 0 / 256 MiB / 1 | 6 / 0 / 256 MiB / 1 |
| quick+low-impact | 1 / 0 / 256 MiB / 1 | 1 / 0 / 256 MiB / 1 | 2 / 0 / 256 MiB / 1 | 2 / 0 / 256 MiB / 1 | 2 / 0 / 256 MiB / 1 | 2 / 0 / 256 MiB / 1 |
| standard+normal | 1 / 1 / 256 MiB / 2 | 1 / 1* / 256 MiB / 1* | 3 / 2 / 256 MiB / 2 | 3 / 1* / 256 MiB / 1* | 4 / 2 / 256 MiB / 2 | 4 / 1* / 256 MiB / 1* |
| standard+low-impact | 1 / 1 / 256 MiB / 2 | 1 / 1 / 256 MiB / 1* | 2 / 1 / 256 MiB / 2 | 2 / 1 / 256 MiB / 1* | 2 / 1 / 256 MiB / 2 | 2 / 1 / 256 MiB / 1* |
| deep+normal | 1 / 1 / 512 MiB / 2 | 1 / 1* / 256* MiB / 1* | 3 / 2 / 512 MiB / 2 | 3 / 1* / 256* MiB / 1* | 3 / 2 / 512 MiB / 2 | 3 / 1* / 256* MiB / 1* |
| deep+low-impact | 1 / 1 / 512 MiB / 2 | 1 / 1 / 256* MiB / 1* | 2 / 1 / 512 MiB / 2 | 2 / 1 / 256* MiB / 1* | 2 / 1 / 512 MiB / 2 | 2 / 1 / 256* MiB / 1* |

This computer: 16 logical cores, 14.1 GiB free memory when recorded. Small computer: 2 cores and 1 GiB free memory, injected.

## Acceptance checks

- PASS Low-impact fewer connections than Normal, requests no more than Normal's — quick singlex1: requests 25 vs 25; TCP 1 vs 25
- PASS Low-impact fewer requests and connections than Normal — standard singlex1: requests 39 vs 49; TCP 1 vs 49
- PASS Low-impact fewer requests and connections than Normal — deep singlex1: requests 47 vs 61; TCP 3 vs 61
- PASS Deep+Low-impact keeps Deep+Normal recall — singlex1: 8/8 vs 8/8
- PASS Low-impact fewer connections than Normal, requests no more than Normal's — quick bundlex1: requests 29 vs 29; TCP 1 vs 29
- PASS Low-impact fewer requests and connections than Normal — standard bundlex1: requests 37 vs 41; TCP 1 vs 41
- PASS Low-impact fewer requests and connections than Normal — deep bundlex1: requests 37 vs 41; TCP 1 vs 41
- PASS Deep+Low-impact keeps Deep+Normal recall — bundlex1: 7/7 vs 7/7
- PASS Low-impact fewer connections than Normal, requests no more than Normal's — quick multix3: requests 75 vs 75; TCP 3 vs 75
- PASS Low-impact fewer requests and connections than Normal — standard multix3: requests 117 vs 147; TCP 5 vs 147
- PASS Low-impact fewer requests and connections than Normal — deep multix3: requests 141 vs 183; TCP 10 vs 183
- PASS Deep+Low-impact keeps Deep+Normal recall — multix3: 24/24 vs 24/24
- PASS Low-impact fewer connections than Normal, requests no more than Normal's — quick multix10: requests 250 vs 250; TCP 10 vs 250
- PASS Low-impact fewer requests and connections than Normal — standard multix10: requests 390 vs 490; TCP 18 vs 490
- PASS Low-impact fewer requests and connections than Normal — deep multix10: requests 450 vs 529; TCP 29 vs 529
- PASS Deep+Low-impact keeps Deep+Normal recall — multix10: 80/80 vs 80/80
- PASS Quick reports its limits — normal singlex1: completed, stage "Completed — quick coverage"; stated limits: http-unavailable, quick-coverage-boundary; not examined: Sitemaps ×1, Linked pages ×5; gaps none
- PASS Quick fastest — normal singlex1: 13.1 s vs Standard 39.4 s, Deep 79.7 s
- PASS Quick reports its limits — low-impact singlex1: completed, stage "Completed — quick coverage"; stated limits: http-unavailable, quick-coverage-boundary; not examined: Sitemaps ×1, Linked pages ×5; gaps none
- PASS Quick fastest — low-impact singlex1: 49.1 s vs Standard 77.3 s, Deep 101.7 s
- PASS Quick reports its limits — normal bundlex1: incomplete, stage "Stopped with coverage limitations"; stated limits: bare-extension-literals, http-unavailable, quick-coverage-boundary; not examined: none listed; gaps decoded-inspection-limit ×1
- PASS Quick fastest — normal bundlex1: 15.7 s vs Standard 21.4 s, Deep 23.9 s
- PASS Quick reports its limits — low-impact bundlex1: incomplete, stage "Stopped with coverage limitations"; stated limits: bare-extension-literals, http-unavailable, quick-coverage-boundary; not examined: none listed; gaps decoded-inspection-limit ×1
- PASS Quick fastest — low-impact bundlex1: 57.7 s vs Standard 73.2 s, Deep 73.2 s
- PASS Quick reports its limits — normal multix3: completed, stage "Completed — quick coverage"; stated limits: http-unavailable, quick-coverage-boundary; not examined: Sitemaps ×3, Linked pages ×15; gaps none
- PASS Quick fastest — normal multix3: 14.5 s vs Standard 49.8 s, Deep 112.9 s
- PASS Quick reports its limits — low-impact multix3: completed, stage "Completed — quick coverage"; stated limits: http-unavailable, quick-coverage-boundary; not examined: Sitemaps ×3, Linked pages ×15; gaps none
- PASS Quick fastest — low-impact multix3: 99.8 s vs Standard 156.8 s, Deep 199.1 s
- PASS Quick reports its limits — normal multix10: completed, stage "Completed — quick coverage"; stated limits: http-unavailable, quick-coverage-boundary; not examined: Sitemaps ×10, Linked pages ×50; gaps none
- PASS Quick fastest — normal multix10: 31.3 s vs Standard 163.1 s, Deep 237.8 s
- PASS Quick reports its limits — low-impact multix10: completed, stage "Completed — quick coverage"; stated limits: http-unavailable, quick-coverage-boundary; not examined: Sitemaps ×10, Linked pages ×50; gaps none
- PASS Quick fastest — low-impact multix10: 254.6 s vs Standard 418.4 s, Deep 583.4 s
- PASS Within limits — 2.9/quick+normal/singlex1: analysis processes parser 1×256 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤71 MiB outside the setting; browser websites 0 ≤ 0; websites in flight 1 ≤ 1 used (option 6); RSS 207 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/quick+normal/singlex1: 6/6 in scope (8 planted); missing: www.example.com:depth3, www.example.com:depth5; memory gaps none
- PASS Keeps the 2.8.0 recall — 2.9/quick+normal/singlex1: 6/8 vs 6/8; scan-process peak RSS 207 vs 186 MiB; 13.1 vs 13.1 s
- PASS Within limits — 2.9/quick+low-impact/singlex1: analysis processes parser 1×256 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤71 MiB outside the setting; browser websites 0 ≤ 0; websites in flight 1 ≤ 1 used (option 2); RSS 201 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/quick+low-impact/singlex1: 6/6 in scope (8 planted); missing: www.example.com:depth3, www.example.com:depth5; memory gaps none
- PASS Keeps the 2.8.0 recall — 2.9/quick+low-impact/singlex1: 6/8 vs 6/8; scan-process peak RSS 201 vs 185 MiB; 49.1 vs 49.1 s
- PASS Within limits — 2.9/standard+normal/singlex1: analysis processes parser 1×128 MiB, at most 128 MiB of heap limits at once of 256 MiB for 2 parser workers; out of memory 0; their RSS ≤74 MiB outside the setting; browser websites 1 ≤ 2; websites in flight 1 ≤ 1 used (option 4); RSS 209 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/standard+normal/singlex1: 7/7 in scope (8 planted); missing: www.example.com:depth5; memory gaps none
- PASS Keeps the 2.8.0 recall — 2.9/standard+normal/singlex1: 7/8 vs 7/8; scan-process peak RSS 209 vs 201 MiB; 39.4 vs 38.9 s
- PASS Within limits — 2.9/standard+low-impact/singlex1: analysis processes parser 1×128 MiB, at most 128 MiB of heap limits at once of 256 MiB for 2 parser workers; out of memory 0; their RSS ≤73 MiB outside the setting; browser websites 1 ≤ 1; websites in flight 1 ≤ 1 used (option 2); RSS 208 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/standard+low-impact/singlex1: 7/7 in scope (8 planted); missing: www.example.com:depth5; memory gaps none
- PASS Keeps the 2.8.0 recall — 2.9/standard+low-impact/singlex1: 7/8 vs 7/8; scan-process peak RSS 208 vs 188 MiB; 77.3 vs 79.3 s
- PASS Within limits — 2.9/deep+normal/singlex1: analysis processes parser 1×256 MiB, at most 256 MiB of heap limits at once of 512 MiB for 2 parser workers; out of memory 0; their RSS ≤73 MiB outside the setting; browser websites 1 ≤ 2; websites in flight 1 ≤ 1 used (option 3); RSS 210 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/deep+normal/singlex1: 8/8 in scope (8 planted); missing: none; memory gaps none
- PASS Keeps the 2.8.0 recall — 2.9/deep+normal/singlex1: 8/8 vs 8/8; scan-process peak RSS 210 vs 199 MiB; 79.7 vs 78.9 s
- PASS Within limits — 2.9/deep+low-impact/singlex1: analysis processes parser 1×256 MiB, at most 256 MiB of heap limits at once of 512 MiB for 2 parser workers; out of memory 0; their RSS ≤73 MiB outside the setting; browser websites 1 ≤ 1; websites in flight 1 ≤ 1 used (option 2); RSS 208 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/deep+low-impact/singlex1: 8/8 in scope (8 planted); missing: none; memory gaps none
- PASS Keeps the 2.8.0 recall — 2.9/deep+low-impact/singlex1: 8/8 vs 8/8; scan-process peak RSS 208 vs 189 MiB; 101.7 vs 100.2 s
- PASS Within limits — 2.9/quick+normal/bundlex1: analysis processes parser 2×256, detector 1×108 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤248 MiB outside the setting; browser websites 0 ≤ 0; websites in flight 1 ≤ 1 used (option 6); RSS 281 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/quick+normal/bundlex1: 7/7 in scope (7 planted); missing: none; memory gaps none
- PASS Keeps the 2.8.0 recall — 2.9/quick+normal/bundlex1: 7/7 vs 7/7; scan-process peak RSS 281 vs 260 MiB; 15.7 vs 15.6 s
- PASS Within limits — 2.9/quick+low-impact/bundlex1: analysis processes parser 2×256, detector 1×108 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤247 MiB outside the setting; browser websites 0 ≤ 0; websites in flight 1 ≤ 1 used (option 2); RSS 280 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/quick+low-impact/bundlex1: 7/7 in scope (7 planted); missing: none; memory gaps none
- PASS Keeps the 2.8.0 recall — 2.9/quick+low-impact/bundlex1: 7/7 vs 7/7; scan-process peak RSS 280 vs 248 MiB; 57.7 vs 57.6 s
- PASS Within limits — 2.9/standard+normal/bundlex1: analysis processes parser 3×128/256, detector 1×108 MiB, at most 256 MiB of heap limits at once of 256 MiB for 2 parser workers; out of memory 0; their RSS ≤319 MiB outside the setting; browser websites 1 ≤ 2; websites in flight 1 ≤ 1 used (option 4); RSS 312 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/standard+normal/bundlex1: 7/7 in scope (7 planted); missing: none; memory gaps none
- PASS Keeps the 2.8.0 recall — 2.9/standard+normal/bundlex1: 7/7 vs 7/7; scan-process peak RSS 312 vs 334 MiB; 21.4 vs 21.3 s
- PASS Within limits — 2.9/standard+low-impact/bundlex1: analysis processes parser 3×128/256, detector 1×108 MiB, at most 256 MiB of heap limits at once of 256 MiB for 2 parser workers; out of memory 0; their RSS ≤318 MiB outside the setting; browser websites 1 ≤ 1; websites in flight 1 ≤ 1 used (option 2); RSS 306 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/standard+low-impact/bundlex1: 7/7 in scope (7 planted); missing: none; memory gaps none
- PASS Keeps the 2.8.0 recall — 2.9/standard+low-impact/bundlex1: 7/7 vs 7/7; scan-process peak RSS 306 vs 295 MiB; 73.2 vs 73.3 s
- PASS Within limits — 2.9/deep+normal/bundlex1: analysis processes parser 1×256, detector 1×108 MiB, at most 364 MiB of heap limits at once of 512 MiB for 2 parser workers; out of memory 0; their RSS ≤426 MiB outside the setting; browser websites 1 ≤ 2; websites in flight 1 ≤ 1 used (option 3); RSS 314 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/deep+normal/bundlex1: 7/7 in scope (7 planted); missing: none; memory gaps none
- PASS Keeps the 2.8.0 recall — 2.9/deep+normal/bundlex1: 7/7 vs 7/7; scan-process peak RSS 314 vs 310 MiB; 23.9 vs 23.6 s
- PASS Within limits — 2.9/deep+low-impact/bundlex1: analysis processes parser 1×256, detector 1×108 MiB, at most 364 MiB of heap limits at once of 512 MiB for 2 parser workers; out of memory 0; their RSS ≤423 MiB outside the setting; browser websites 1 ≤ 1; websites in flight 1 ≤ 1 used (option 2); RSS 308 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/deep+low-impact/bundlex1: 7/7 in scope (7 planted); missing: none; memory gaps none
- PASS Keeps the 2.8.0 recall — 2.9/deep+low-impact/bundlex1: 7/7 vs 7/7; scan-process peak RSS 308 vs 295 MiB; 73.2 vs 73.2 s
- PASS Within limits — 2.9/quick+normal/multix3: analysis processes parser 1×256 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤71 MiB outside the setting; browser websites 0 ≤ 0; websites in flight 1 ≤ 3 used (option 6); RSS 210 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/quick+normal/multix3: 18/18 in scope (24 planted); missing: s1.example.com:depth3, s1.example.com:depth5, s2.example.com:depth3, s2.example.com:depth5, s3.example.com:depth3, s3.example.com:depth5; memory gaps none
- PASS Keeps the 2.8.0 recall — 2.9/quick+normal/multix3: 18/24 vs 18/24; scan-process peak RSS 210 vs 206 MiB; 14.5 vs 14.4 s
- PASS Within limits — 2.9/quick+low-impact/multix3: analysis processes parser 1×256 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤71 MiB outside the setting; browser websites 0 ≤ 0; websites in flight 1 ≤ 2 used (option 2); RSS 199 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/quick+low-impact/multix3: 18/18 in scope (24 planted); missing: s1.example.com:depth3, s1.example.com:depth5, s2.example.com:depth3, s2.example.com:depth5, s3.example.com:depth3, s3.example.com:depth5; memory gaps none
- PASS Keeps the 2.8.0 recall — 2.9/quick+low-impact/multix3: 18/24 vs 18/24; scan-process peak RSS 199 vs 184 MiB; 99.8 vs 99.9 s
- PASS Within limits — 2.9/standard+normal/multix3: analysis processes parser 2×128 MiB, at most 256 MiB of heap limits at once of 256 MiB for 2 parser workers; out of memory 0; their RSS ≤147 MiB outside the setting; browser websites 2 ≤ 2; websites in flight 1 ≤ 3 used (option 4); RSS 224 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/standard+normal/multix3: 21/21 in scope (24 planted); missing: s1.example.com:depth5, s2.example.com:depth5, s3.example.com:depth5; memory gaps none
- PASS Keeps the 2.8.0 recall — 2.9/standard+normal/multix3: 21/24 vs 21/24; scan-process peak RSS 224 vs 207 MiB; 49.8 vs 46.8 s
- PASS Within limits — 2.9/standard+low-impact/multix3: analysis processes parser 2×128 MiB, at most 256 MiB of heap limits at once of 256 MiB for 2 parser workers; out of memory 0; their RSS ≤144 MiB outside the setting; browser websites 1 ≤ 1; websites in flight 1 ≤ 2 used (option 2); RSS 209 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/standard+low-impact/multix3: 21/21 in scope (24 planted); missing: s1.example.com:depth5, s2.example.com:depth5, s3.example.com:depth5; memory gaps none
- PASS Keeps the 2.8.0 recall — 2.9/standard+low-impact/multix3: 21/24 vs 21/24; scan-process peak RSS 209 vs 195 MiB; 156.8 vs 158.6 s
- PASS Within limits — 2.9/deep+normal/multix3: analysis processes parser 2×256 MiB, at most 512 MiB of heap limits at once of 512 MiB for 2 parser workers; out of memory 0; their RSS ≤146 MiB outside the setting; browser websites 2 ≤ 2; websites in flight 1 ≤ 3 used (option 3); RSS 226 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/deep+normal/multix3: 24/24 in scope (24 planted); missing: none; memory gaps none
- PASS Keeps the 2.8.0 recall — 2.9/deep+normal/multix3: 24/24 vs 24/24; scan-process peak RSS 226 vs 211 MiB; 112.9 vs 107.6 s
- PASS Within limits — 2.9/deep+low-impact/multix3: analysis processes parser 2×256 MiB, at most 512 MiB of heap limits at once of 512 MiB for 2 parser workers; out of memory 0; their RSS ≤144 MiB outside the setting; browser websites 1 ≤ 1; websites in flight 1 ≤ 2 used (option 2); RSS 209 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/deep+low-impact/multix3: 24/24 in scope (24 planted); missing: none; memory gaps none
- PASS Keeps the 2.8.0 recall — 2.9/deep+low-impact/multix3: 24/24 vs 24/24; scan-process peak RSS 209 vs 194 MiB; 199.1 vs 199.1 s
- PASS Within limits — 2.9/quick+normal/multix10: analysis processes parser 1×256 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤72 MiB outside the setting; browser websites 0 ≤ 0; websites in flight 1 ≤ 6 used (option 6); RSS 226 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/quick+normal/multix10: 60/60 in scope (80 planted); missing: s1.example.com:depth3, s1.example.com:depth5, s2.example.com:depth3, s2.example.com:depth5, s3.example.com:depth3, s3.example.com:depth5, s4.example.com:depth3, s4.example.com:depth5, s5.example.com:depth3, s5.example.com:depth5, s6.example.com:depth3, s6.example.com:depth5, s7.example.com:depth3, s7.example.com:depth5, s8.example.com:depth3, s8.example.com:depth5, s9.example.com:depth3, s9.example.com:depth5, s10.example.com:depth3, s10.example.com:depth5; memory gaps none
- PASS Keeps the 2.8.0 recall — 2.9/quick+normal/multix10: 60/80 vs 60/80; scan-process peak RSS 226 vs 215 MiB; 31.3 vs 31.5 s
- PASS Within limits — 2.9/quick+low-impact/multix10: analysis processes parser 1×256 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤71 MiB outside the setting; browser websites 0 ≤ 0; websites in flight 1 ≤ 2 used (option 2); RSS 205 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/quick+low-impact/multix10: 60/60 in scope (80 planted); missing: s1.example.com:depth3, s1.example.com:depth5, s2.example.com:depth3, s2.example.com:depth5, s3.example.com:depth3, s3.example.com:depth5, s4.example.com:depth3, s4.example.com:depth5, s5.example.com:depth3, s5.example.com:depth5, s6.example.com:depth3, s6.example.com:depth5, s7.example.com:depth3, s7.example.com:depth5, s8.example.com:depth3, s8.example.com:depth5, s9.example.com:depth3, s9.example.com:depth5, s10.example.com:depth3, s10.example.com:depth5; memory gaps none
- PASS Keeps the 2.8.0 recall — 2.9/quick+low-impact/multix10: 60/80 vs 60/80; scan-process peak RSS 205 vs 185 MiB; 254.6 vs 258.5 s
- PASS Within limits — 2.9/standard+normal/multix10: analysis processes parser 2×128 MiB, at most 256 MiB of heap limits at once of 256 MiB for 2 parser workers; out of memory 0; their RSS ≤146 MiB outside the setting; browser websites 2 ≤ 2; websites in flight 1 ≤ 4 used (option 4); RSS 298 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/standard+normal/multix10: 70/70 in scope (80 planted); missing: s1.example.com:depth5, s2.example.com:depth5, s3.example.com:depth5, s4.example.com:depth5, s5.example.com:depth5, s6.example.com:depth5, s7.example.com:depth5, s8.example.com:depth5, s9.example.com:depth5, s10.example.com:depth5; memory gaps none
- PASS Keeps the 2.8.0 recall — 2.9/standard+normal/multix10: 70/80 vs 70/80; scan-process peak RSS 298 vs 278 MiB; 163.1 vs 168.2 s
- PASS Within limits — 2.9/standard+low-impact/multix10: analysis processes parser 2×128 MiB, at most 256 MiB of heap limits at once of 256 MiB for 2 parser workers; out of memory 0; their RSS ≤146 MiB outside the setting; browser websites 1 ≤ 1; websites in flight 1 ≤ 2 used (option 2); RSS 227 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/standard+low-impact/multix10: 70/70 in scope (80 planted); missing: s1.example.com:depth5, s2.example.com:depth5, s3.example.com:depth5, s4.example.com:depth5, s5.example.com:depth5, s6.example.com:depth5, s7.example.com:depth5, s8.example.com:depth5, s9.example.com:depth5, s10.example.com:depth5; memory gaps none
- PASS Keeps the 2.8.0 recall — 2.9/standard+low-impact/multix10: 70/80 vs 70/80; scan-process peak RSS 227 vs 215 MiB; 418.4 vs 417.3 s
- PASS Within limits — 2.9/deep+normal/multix10: analysis processes parser 2×256 MiB, at most 512 MiB of heap limits at once of 512 MiB for 2 parser workers; out of memory 0; their RSS ≤146 MiB outside the setting; browser websites 2 ≤ 2; websites in flight 1 ≤ 3 used (option 3); RSS 293 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/deep+normal/multix10: 80/80 in scope (80 planted); missing: none; memory gaps none
- PASS Keeps the 2.8.0 recall — 2.9/deep+normal/multix10: 80/80 vs 80/80; scan-process peak RSS 293 vs 279 MiB; 237.8 vs 223.4 s
- PASS Within limits — 2.9/deep+low-impact/multix10: analysis processes parser 2×256 MiB, at most 512 MiB of heap limits at once of 512 MiB for 2 parser workers; out of memory 0; their RSS ≤144 MiB outside the setting; browser websites 1 ≤ 1; websites in flight 1 ≤ 2 used (option 2); RSS 232 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/deep+low-impact/multix10: 80/80 in scope (80 planted); missing: none; memory gaps none
- PASS Keeps the 2.8.0 recall — 2.9/deep+low-impact/multix10: 80/80 vs 80/80; scan-process peak RSS 232 vs 219 MiB; 583.4 vs 577.7 s
- PASS Within limits — 2.9-small/quick+normal/bundlex1: analysis processes parser 2×256, detector 1×108 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤248 MiB outside the setting; browser websites 0 ≤ 0; websites in flight 1 ≤ 1 used (option 6); RSS 283 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9-small/quick+normal/bundlex1: 7/7 in scope (7 planted); missing: none; memory gaps none
- PASS Within limits — 2.9-small/quick+low-impact/bundlex1: analysis processes parser 2×256, detector 1×108 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤249 MiB outside the setting; browser websites 0 ≤ 0; websites in flight 1 ≤ 1 used (option 2); RSS 282 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9-small/quick+low-impact/bundlex1: 7/7 in scope (7 planted); missing: none; memory gaps none
- PASS Within limits — 2.9-small/standard+normal/bundlex1: analysis processes parser 2×256, detector 1×108 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤248 MiB outside the setting; browser websites 1 ≤ 2; websites in flight 1 ≤ 1 used (option 4); RSS 319 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9-small/standard+normal/bundlex1: 7/7 in scope (7 planted); missing: none; memory gaps none
- PASS Within limits — 2.9-small/standard+low-impact/bundlex1: analysis processes parser 2×256, detector 1×108 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤248 MiB outside the setting; browser websites 1 ≤ 1; websites in flight 1 ≤ 1 used (option 2); RSS 306 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9-small/standard+low-impact/bundlex1: 7/7 in scope (7 planted); missing: none; memory gaps none
- PASS Within limits — 2.9-small/deep+normal/bundlex1: analysis processes parser 2×256, detector 1×108 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤248 MiB outside the setting; browser websites 1 ≤ 2; websites in flight 1 ≤ 1 used (option 3); RSS 324 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9-small/deep+normal/bundlex1: 7/7 in scope (7 planted); missing: none; memory gaps none
- PASS Within limits — 2.9-small/deep+low-impact/bundlex1: analysis processes parser 2×256, detector 1×108 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤248 MiB outside the setting; browser websites 1 ≤ 1; websites in flight 1 ≤ 1 used (option 2); RSS 306 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9-small/deep+low-impact/bundlex1: 7/7 in scope (7 planted); missing: none; memory gaps none
- PASS Within limits — 2.9-small/quick+normal/multix10: analysis processes parser 1×256 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤72 MiB outside the setting; browser websites 0 ≤ 0; websites in flight 1 ≤ 6 used (option 6); RSS 224 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9-small/quick+normal/multix10: 60/60 in scope (80 planted); missing: s1.example.com:depth3, s1.example.com:depth5, s2.example.com:depth3, s2.example.com:depth5, s3.example.com:depth3, s3.example.com:depth5, s4.example.com:depth3, s4.example.com:depth5, s5.example.com:depth3, s5.example.com:depth5, s6.example.com:depth3, s6.example.com:depth5, s7.example.com:depth3, s7.example.com:depth5, s8.example.com:depth3, s8.example.com:depth5, s9.example.com:depth3, s9.example.com:depth5, s10.example.com:depth3, s10.example.com:depth5; memory gaps none
- PASS Within limits — 2.9-small/standard+normal/multix10: analysis processes parser 1×256 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤74 MiB outside the setting; browser websites 1 ≤ 2; websites in flight 1 ≤ 4 used (option 4); RSS 294 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9-small/standard+normal/multix10: 70/70 in scope (80 planted); missing: s1.example.com:depth5, s2.example.com:depth5, s3.example.com:depth5, s4.example.com:depth5, s5.example.com:depth5, s6.example.com:depth5, s7.example.com:depth5, s8.example.com:depth5, s9.example.com:depth5, s10.example.com:depth5; memory gaps none
- PASS Within limits — 2.9-small/deep+normal/multix10: analysis processes parser 1×256 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤73 MiB outside the setting; browser websites 1 ≤ 2; websites in flight 1 ≤ 3 used (option 3); RSS 238 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9-small/deep+normal/multix10: 80/80 in scope (80 planted); missing: none; memory gaps none
- PASS Adjustment only lowers — quick+normal 1 websites, this computer: none
- PASS Adjustment only lowers — quick+low-impact 1 websites, this computer: none
- PASS Adjustment only lowers — standard+normal 1 websites, this computer: none
- PASS Adjustment only lowers — standard+low-impact 1 websites, this computer: none
- PASS Adjustment only lowers — deep+normal 1 websites, this computer: none
- PASS Adjustment only lowers — deep+low-impact 1 websites, this computer: none
- PASS Adjustment only lowers — quick+normal 1 websites, small (2 cores, 1 GiB free): none
- PASS Adjustment only lowers — quick+low-impact 1 websites, small (2 cores, 1 GiB free): none
- PASS Adjustment only lowers — standard+normal 1 websites, small (2 cores, 1 GiB free): analysisWorkers 2→1; browserWebsitesAtOnce 2→1
- PASS Adjustment only lowers — standard+low-impact 1 websites, small (2 cores, 1 GiB free): analysisWorkers 2→1
- PASS Adjustment only lowers — deep+normal 1 websites, small (2 cores, 1 GiB free): analysisWorkers 2→1; browserWebsitesAtOnce 2→1; analysisMemoryMb 512→256
- PASS Adjustment only lowers — deep+low-impact 1 websites, small (2 cores, 1 GiB free): analysisWorkers 2→1; analysisMemoryMb 512→256
- PASS Adjustment only lowers — quick+normal 3 websites, this computer: none
- PASS Adjustment only lowers — quick+low-impact 3 websites, this computer: none
- PASS Adjustment only lowers — standard+normal 3 websites, this computer: none
- PASS Adjustment only lowers — standard+low-impact 3 websites, this computer: none
- PASS Adjustment only lowers — deep+normal 3 websites, this computer: none
- PASS Adjustment only lowers — deep+low-impact 3 websites, this computer: none
- PASS Adjustment only lowers — quick+normal 3 websites, small (2 cores, 1 GiB free): none
- PASS Adjustment only lowers — quick+low-impact 3 websites, small (2 cores, 1 GiB free): none
- PASS Adjustment only lowers — standard+normal 3 websites, small (2 cores, 1 GiB free): analysisWorkers 2→1; browserWebsitesAtOnce 2→1
- PASS Adjustment only lowers — standard+low-impact 3 websites, small (2 cores, 1 GiB free): analysisWorkers 2→1
- PASS Adjustment only lowers — deep+normal 3 websites, small (2 cores, 1 GiB free): analysisWorkers 2→1; browserWebsitesAtOnce 2→1; analysisMemoryMb 512→256
- PASS Adjustment only lowers — deep+low-impact 3 websites, small (2 cores, 1 GiB free): analysisWorkers 2→1; analysisMemoryMb 512→256
- PASS Adjustment only lowers — quick+normal 10 websites, this computer: none
- PASS Adjustment only lowers — quick+low-impact 10 websites, this computer: none
- PASS Adjustment only lowers — standard+normal 10 websites, this computer: none
- PASS Adjustment only lowers — standard+low-impact 10 websites, this computer: none
- PASS Adjustment only lowers — deep+normal 10 websites, this computer: none
- PASS Adjustment only lowers — deep+low-impact 10 websites, this computer: none
- PASS Adjustment only lowers — quick+normal 10 websites, small (2 cores, 1 GiB free): none
- PASS Adjustment only lowers — quick+low-impact 10 websites, small (2 cores, 1 GiB free): none
- PASS Adjustment only lowers — standard+normal 10 websites, small (2 cores, 1 GiB free): analysisWorkers 2→1; browserWebsitesAtOnce 2→1
- PASS Adjustment only lowers — standard+low-impact 10 websites, small (2 cores, 1 GiB free): analysisWorkers 2→1
- PASS Adjustment only lowers — deep+normal 10 websites, small (2 cores, 1 GiB free): analysisWorkers 2→1; browserWebsitesAtOnce 2→1; analysisMemoryMb 512→256
- PASS Adjustment only lowers — deep+low-impact 10 websites, small (2 cores, 1 GiB free): analysisWorkers 2→1; analysisMemoryMb 512→256
- PASS Settings as recorded — 2.9/quick+normal/singlex1: same as the resources phase
- PASS Settings as recorded — 2.9/quick+low-impact/singlex1: same as the resources phase
- PASS Settings as recorded — 2.9/standard+normal/singlex1: same as the resources phase
- PASS Settings as recorded — 2.9/standard+low-impact/singlex1: same as the resources phase
- PASS Settings as recorded — 2.9/deep+normal/singlex1: same as the resources phase
- PASS Settings as recorded — 2.9/deep+low-impact/singlex1: same as the resources phase
- PASS Settings as recorded — 2.9/quick+normal/bundlex1: same as the resources phase
- PASS Settings as recorded — 2.9/quick+low-impact/bundlex1: same as the resources phase
- PASS Settings as recorded — 2.9/standard+normal/bundlex1: same as the resources phase
- PASS Settings as recorded — 2.9/standard+low-impact/bundlex1: same as the resources phase
- PASS Settings as recorded — 2.9/deep+normal/bundlex1: same as the resources phase
- PASS Settings as recorded — 2.9/deep+low-impact/bundlex1: same as the resources phase
- PASS Settings as recorded — 2.9/quick+normal/multix3: same as the resources phase
- PASS Settings as recorded — 2.9/quick+low-impact/multix3: same as the resources phase
- PASS Settings as recorded — 2.9/standard+normal/multix3: same as the resources phase
- PASS Settings as recorded — 2.9/standard+low-impact/multix3: same as the resources phase
- PASS Settings as recorded — 2.9/deep+normal/multix3: same as the resources phase
- PASS Settings as recorded — 2.9/deep+low-impact/multix3: same as the resources phase
- PASS Settings as recorded — 2.9/quick+normal/multix10: same as the resources phase
- PASS Settings as recorded — 2.9/quick+low-impact/multix10: same as the resources phase
- PASS Settings as recorded — 2.9/standard+normal/multix10: same as the resources phase
- PASS Settings as recorded — 2.9/standard+low-impact/multix10: same as the resources phase
- PASS Settings as recorded — 2.9/deep+normal/multix10: same as the resources phase
- PASS Settings as recorded — 2.9/deep+low-impact/multix10: same as the resources phase
- PASS Settings as recorded — 2.9-small/quick+normal/bundlex1: same as the resources phase
- PASS Settings as recorded — 2.9-small/quick+low-impact/bundlex1: same as the resources phase
- PASS Settings as recorded — 2.9-small/standard+normal/bundlex1: same as the resources phase
- PASS Settings as recorded — 2.9-small/standard+low-impact/bundlex1: same as the resources phase
- PASS Settings as recorded — 2.9-small/deep+normal/bundlex1: same as the resources phase
- PASS Settings as recorded — 2.9-small/deep+low-impact/bundlex1: same as the resources phase
- PASS Settings as recorded — 2.9-small/quick+normal/multix10: same as the resources phase
- PASS Settings as recorded — 2.9-small/standard+normal/multix10: same as the resources phase
- PASS Settings as recorded — 2.9-small/deep+normal/multix10: same as the resources phase
