# P4 measurement matrix (generated 2026-10-16T08:38:53.763Z)

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

## Freshness

- 2.9 source build: 2.9.1+94a512df50bb9d43, harness 43537d3099028d72, Node v24.18.1
- baseline rows not checked: run report with --baseline <extracted release folder>
- 34 of 58 rows current; 0 stale; 0 failed; 0 measured alongside other cases ("alongside": their times can be longer than a serial run's)

## Resource use (recorded, no network)

| Option (websites at once / browser websites / analysis memory / workers) | This computer, 1 website | Small computer, 1 website | This computer, 3 websites | Small computer, 3 websites | This computer, 10 websites | Small computer, 10 websites |
|---|---|---|---|---|---|---|
| quick+normal | 1 / 0 / 256 MiB / 1 | 1 / 0 / 256 MiB / 1 | 3 / 0 / 256 MiB / 1 | 3 / 0 / 256 MiB / 1 | 6 / 0 / 256 MiB / 1 | 6 / 0 / 256 MiB / 1 |
| quick+low-impact | 1 / 0 / 256 MiB / 1 | 1 / 0 / 256 MiB / 1 | 2 / 0 / 256 MiB / 1 | 2 / 0 / 256 MiB / 1 | 2 / 0 / 256 MiB / 1 | 2 / 0 / 256 MiB / 1 |
| standard+normal | 1 / 1 / 256 MiB / 2 | 1 / 1* / 256 MiB / 1* | 3 / 2 / 256 MiB / 2 | 3 / 1* / 256 MiB / 1* | 4 / 2 / 256 MiB / 2 | 4 / 1* / 256 MiB / 1* |
| standard+low-impact | 1 / 1 / 256 MiB / 2 | 1 / 1 / 256 MiB / 1* | 2 / 1 / 256 MiB / 2 | 2 / 1 / 256 MiB / 1* | 2 / 1 / 256 MiB / 2 | 2 / 1 / 256 MiB / 1* |
| deep+normal | 1 / 1 / 512 MiB / 2 | 1 / 1* / 256* MiB / 1* | 3 / 2 / 512 MiB / 2 | 3 / 1* / 256* MiB / 1* | 3 / 2 / 512 MiB / 2 | 3 / 1* / 256* MiB / 1* |
| deep+low-impact | 1 / 1 / 512 MiB / 2 | 1 / 1 / 256* MiB / 1* | 2 / 1 / 512 MiB / 2 | 2 / 1 / 256* MiB / 1* | 2 / 1 / 512 MiB / 2 | 2 / 1 / 256* MiB / 1* |

This computer: 16 logical cores, 10.7 GiB free memory when recorded. Small computer: 2 cores and 1 GiB free memory, injected.

## Acceptance checks

- PASS Low-impact fewer connections than Normal, requests no more than Normal's — quick singlex1: requests 25 vs 25; TCP 1 vs 25
- PASS Low-impact fewer requests and connections than Normal — standard singlex1: requests 39 vs 49; TCP 1 vs 49
- PASS Low-impact fewer requests and connections than Normal — deep singlex1: requests 47 vs 61; TCP 4 vs 61
- PASS Deep+Low-impact keeps Deep+Normal recall — singlex1: 8/8 vs 8/8
- PASS Low-impact fewer connections than Normal, requests no more than Normal's — quick bundlex1: requests 29 vs 29; TCP 2 vs 29
- PASS Low-impact fewer requests and connections than Normal — standard bundlex1: requests 37 vs 41; TCP 1 vs 41
- PASS Low-impact fewer requests and connections than Normal — deep bundlex1: requests 37 vs 41; TCP 1 vs 41
- PASS Deep+Low-impact keeps Deep+Normal recall — bundlex1: 7/7 vs 7/7
- PASS Low-impact fewer connections than Normal, requests no more than Normal's — quick multix3: requests 75 vs 75; TCP 3 vs 75
- PASS Low-impact fewer requests and connections than Normal — standard multix3: requests 117 vs 147; TCP 7 vs 147
- PASS Low-impact fewer requests and connections than Normal — deep multix3: requests 141 vs 183; TCP 10 vs 183
- PASS Deep+Low-impact keeps Deep+Normal recall — multix3: 24/24 vs 24/24
- PASS Low-impact fewer connections than Normal, requests no more than Normal's — quick multix10: requests 250 vs 250; TCP 11 vs 250
- PASS Low-impact fewer requests and connections than Normal — standard multix10: requests 390 vs 480; TCP 17 vs 480
- PASS Low-impact fewer requests and connections than Normal — deep multix10: requests 450 vs 529; TCP 33 vs 529
- PASS Deep+Low-impact keeps Deep+Normal recall — multix10: 80/80 vs 80/80
- PASS Quick reports its limits — normal singlex1: completed, stage "Completed — quick coverage"; stated limits: http-unavailable, quick-coverage-boundary; not examined: Sitemaps ×1, Linked pages ×5; gaps none
- PASS Quick fastest — normal singlex1: 13.5 s vs Standard 41.9 s, Deep 86.5 s
- PASS Quick reports its limits — low-impact singlex1: completed, stage "Completed — quick coverage"; stated limits: http-unavailable, quick-coverage-boundary; not examined: Sitemaps ×1, Linked pages ×5; gaps none
- PASS Quick fastest — low-impact singlex1: 49.4 s vs Standard 77.4 s, Deep 106.0 s
- PASS Quick reports its limits — normal bundlex1: incomplete, stage "Stopped with coverage limitations"; stated limits: bare-extension-literals, http-unavailable, quick-coverage-boundary; not examined: none listed; gaps decoded-inspection-limit ×1
- PASS Quick fastest — normal bundlex1: 18.5 s vs Standard 24.8 s, Deep 23.8 s
- PASS Quick reports its limits — low-impact bundlex1: incomplete, stage "Stopped with coverage limitations"; stated limits: bare-extension-literals, http-unavailable, quick-coverage-boundary; not examined: none listed; gaps decoded-inspection-limit ×1
- PASS Quick fastest — low-impact bundlex1: 65.8 s vs Standard 74.3 s, Deep 73.5 s
- PASS Quick reports its limits — normal multix3: completed, stage "Completed — quick coverage"; stated limits: http-unavailable, quick-coverage-boundary; not examined: Sitemaps ×3, Linked pages ×15; gaps none
- PASS Quick fastest — normal multix3: 14.5 s vs Standard 54.4 s, Deep 166.2 s
- PASS Quick reports its limits — low-impact multix3: completed, stage "Completed — quick coverage"; stated limits: http-unavailable, quick-coverage-boundary; not examined: Sitemaps ×3, Linked pages ×15; gaps none
- PASS Quick fastest — low-impact multix3: 100.3 s vs Standard 180.6 s, Deep 207.8 s
- PASS Quick reports its limits — normal multix10: completed, stage "Completed — quick coverage"; stated limits: http-unavailable, quick-coverage-boundary; not examined: Sitemaps ×10, Linked pages ×50; gaps none
- PASS Quick fastest — normal multix10: 31.8 s vs Standard 228.1 s, Deep 246.5 s
- PASS Quick reports its limits — low-impact multix10: completed, stage "Completed — quick coverage"; stated limits: http-unavailable, quick-coverage-boundary; not examined: Sitemaps ×10, Linked pages ×50; gaps none
- PASS Quick fastest — low-impact multix10: 263.3 s vs Standard 429.2 s, Deep 592.9 s
- PASS Within limits — 2.9/quick+normal/singlex1: analysis processes parser 1×256 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤67 MiB outside the setting; browser websites 0 ≤ 0; websites in flight 1 ≤ 1 used (option 6); RSS 203 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/quick+normal/singlex1: 6/6 in scope (8 planted); missing: www.example.com:depth3, www.example.com:depth5; memory gaps none
- PASS Within limits — 2.9/quick+low-impact/singlex1: analysis processes parser 1×256 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤67 MiB outside the setting; browser websites 0 ≤ 0; websites in flight 1 ≤ 1 used (option 2); RSS 198 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/quick+low-impact/singlex1: 6/6 in scope (8 planted); missing: www.example.com:depth3, www.example.com:depth5; memory gaps none
- PASS Within limits — 2.9/standard+normal/singlex1: analysis processes parser 1×128 MiB, at most 128 MiB of heap limits at once of 256 MiB for 2 parser workers; out of memory 0; their RSS ≤70 MiB outside the setting; browser websites 1 ≤ 2; websites in flight 1 ≤ 1 used (option 4); RSS 206 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/standard+normal/singlex1: 7/7 in scope (8 planted); missing: www.example.com:depth5; memory gaps none
- PASS Within limits — 2.9/standard+low-impact/singlex1: analysis processes parser 1×128 MiB, at most 128 MiB of heap limits at once of 256 MiB for 2 parser workers; out of memory 0; their RSS ≤70 MiB outside the setting; browser websites 1 ≤ 1; websites in flight 1 ≤ 1 used (option 2); RSS 202 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/standard+low-impact/singlex1: 7/7 in scope (8 planted); missing: www.example.com:depth5; memory gaps none
- PASS Within limits — 2.9/deep+normal/singlex1: analysis processes parser 1×256 MiB, at most 256 MiB of heap limits at once of 512 MiB for 2 parser workers; out of memory 0; their RSS ≤70 MiB outside the setting; browser websites 1 ≤ 2; websites in flight 1 ≤ 1 used (option 3); RSS 206 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/deep+normal/singlex1: 8/8 in scope (8 planted); missing: none; memory gaps none
- PASS Within limits — 2.9/deep+low-impact/singlex1: analysis processes parser 1×256 MiB, at most 256 MiB of heap limits at once of 512 MiB for 2 parser workers; out of memory 0; their RSS ≤70 MiB outside the setting; browser websites 1 ≤ 1; websites in flight 1 ≤ 1 used (option 2); RSS 203 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/deep+low-impact/singlex1: 8/8 in scope (8 planted); missing: none; memory gaps none
- PASS Within limits — 2.9/quick+normal/bundlex1: analysis processes parser 2×256, detector 1×108 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤236 MiB outside the setting; browser websites 0 ≤ 0; websites in flight 1 ≤ 1 used (option 6); RSS 270 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/quick+normal/bundlex1: 7/7 in scope (7 planted); missing: none; memory gaps none
- PASS Within limits — 2.9/quick+low-impact/bundlex1: analysis processes parser 2×256, detector 1×108 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤244 MiB outside the setting; browser websites 0 ≤ 0; websites in flight 1 ≤ 1 used (option 2); RSS 255 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/quick+low-impact/bundlex1: 7/7 in scope (7 planted); missing: none; memory gaps none
- PASS Within limits — 2.9/standard+normal/bundlex1: analysis processes parser 3×128/256, detector 2×108 MiB, at most 256 MiB of heap limits at once of 256 MiB for 2 parser workers; out of memory 0; their RSS ≤471 MiB outside the setting; browser websites 1 ≤ 2; websites in flight 1 ≤ 1 used (option 4); RSS 283 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/standard+normal/bundlex1: 7/7 in scope (7 planted); missing: none; memory gaps none
- PASS Within limits — 2.9/standard+low-impact/bundlex1: analysis processes parser 3×128/256, detector 1×108 MiB, at most 256 MiB of heap limits at once of 256 MiB for 2 parser workers; out of memory 0; their RSS ≤310 MiB outside the setting; browser websites 1 ≤ 1; websites in flight 1 ≤ 1 used (option 2); RSS 304 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/standard+low-impact/bundlex1: 7/7 in scope (7 planted); missing: none; memory gaps none
- PASS Within limits — 2.9/deep+normal/bundlex1: analysis processes parser 1×256, detector 2×108 MiB, at most 472 MiB of heap limits at once of 512 MiB for 2 parser workers; out of memory 0; their RSS ≤642 MiB outside the setting; browser websites 1 ≤ 2; websites in flight 1 ≤ 1 used (option 3); RSS 284 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/deep+normal/bundlex1: 7/7 in scope (7 planted); missing: none; memory gaps none
- PASS Within limits — 2.9/deep+low-impact/bundlex1: analysis processes parser 1×256, detector 1×108 MiB, at most 364 MiB of heap limits at once of 512 MiB for 2 parser workers; out of memory 0; their RSS ≤416 MiB outside the setting; browser websites 1 ≤ 1; websites in flight 1 ≤ 1 used (option 2); RSS 305 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/deep+low-impact/bundlex1: 7/7 in scope (7 planted); missing: none; memory gaps none
- PASS Within limits — 2.9/quick+normal/multix3: analysis processes parser 1×256 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤67 MiB outside the setting; browser websites 0 ≤ 0; websites in flight 1 ≤ 3 used (option 6); RSS 207 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/quick+normal/multix3: 18/18 in scope (24 planted); missing: s1.example.com:depth3, s1.example.com:depth5, s2.example.com:depth3, s2.example.com:depth5, s3.example.com:depth3, s3.example.com:depth5; memory gaps none
- PASS Within limits — 2.9/quick+low-impact/multix3: analysis processes parser 1×256 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤67 MiB outside the setting; browser websites 0 ≤ 0; websites in flight 1 ≤ 2 used (option 2); RSS 201 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/quick+low-impact/multix3: 18/18 in scope (24 planted); missing: s1.example.com:depth3, s1.example.com:depth5, s2.example.com:depth3, s2.example.com:depth5, s3.example.com:depth3, s3.example.com:depth5; memory gaps none
- PASS Within limits — 2.9/standard+normal/multix3: analysis processes parser 2×128 MiB, at most 256 MiB of heap limits at once of 256 MiB for 2 parser workers; out of memory 0; their RSS ≤138 MiB outside the setting; browser websites 2 ≤ 2; websites in flight 1 ≤ 3 used (option 4); RSS 222 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/standard+normal/multix3: 21/21 in scope (24 planted); missing: s1.example.com:depth5, s2.example.com:depth5, s3.example.com:depth5; memory gaps none
- PASS Within limits — 2.9/standard+low-impact/multix3: analysis processes parser 2×128 MiB, at most 256 MiB of heap limits at once of 256 MiB for 2 parser workers; out of memory 0; their RSS ≤137 MiB outside the setting; browser websites 1 ≤ 1; websites in flight 1 ≤ 2 used (option 2); RSS 202 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/standard+low-impact/multix3: 21/21 in scope (24 planted); missing: s1.example.com:depth5, s2.example.com:depth5, s3.example.com:depth5; memory gaps none
- PASS Within limits — 2.9/deep+normal/multix3: analysis processes parser 2×256 MiB, at most 512 MiB of heap limits at once of 512 MiB for 2 parser workers; out of memory 0; their RSS ≤137 MiB outside the setting; browser websites 2 ≤ 2; websites in flight 1 ≤ 3 used (option 3); RSS 222 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/deep+normal/multix3: 24/24 in scope (24 planted); missing: none; memory gaps none
- PASS Within limits — 2.9/deep+low-impact/multix3: analysis processes parser 2×256 MiB, at most 512 MiB of heap limits at once of 512 MiB for 2 parser workers; out of memory 0; their RSS ≤137 MiB outside the setting; browser websites 1 ≤ 1; websites in flight 1 ≤ 2 used (option 2); RSS 203 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/deep+low-impact/multix3: 24/24 in scope (24 planted); missing: none; memory gaps none
- PASS Within limits — 2.9/quick+normal/multix10: analysis processes parser 1×256 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤68 MiB outside the setting; browser websites 0 ≤ 0; websites in flight 1 ≤ 6 used (option 6); RSS 221 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/quick+normal/multix10: 60/60 in scope (80 planted); missing: s1.example.com:depth3, s1.example.com:depth5, s2.example.com:depth3, s2.example.com:depth5, s3.example.com:depth3, s3.example.com:depth5, s4.example.com:depth3, s4.example.com:depth5, s5.example.com:depth3, s5.example.com:depth5, s6.example.com:depth3, s6.example.com:depth5, s7.example.com:depth3, s7.example.com:depth5, s8.example.com:depth3, s8.example.com:depth5, s9.example.com:depth3, s9.example.com:depth5, s10.example.com:depth3, s10.example.com:depth5; memory gaps none
- PASS Within limits — 2.9/quick+low-impact/multix10: analysis processes parser 1×256 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤68 MiB outside the setting; browser websites 0 ≤ 0; websites in flight 1 ≤ 2 used (option 2); RSS 201 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/quick+low-impact/multix10: 60/60 in scope (80 planted); missing: s1.example.com:depth3, s1.example.com:depth5, s2.example.com:depth3, s2.example.com:depth5, s3.example.com:depth3, s3.example.com:depth5, s4.example.com:depth3, s4.example.com:depth5, s5.example.com:depth3, s5.example.com:depth5, s6.example.com:depth3, s6.example.com:depth5, s7.example.com:depth3, s7.example.com:depth5, s8.example.com:depth3, s8.example.com:depth5, s9.example.com:depth3, s9.example.com:depth5, s10.example.com:depth3, s10.example.com:depth5; memory gaps none
- PASS Within limits — 2.9/standard+normal/multix10: analysis processes parser 2×128 MiB, at most 256 MiB of heap limits at once of 256 MiB for 2 parser workers; out of memory 0; their RSS ≤136 MiB outside the setting; browser websites 2 ≤ 2; websites in flight 1 ≤ 4 used (option 4); RSS 292 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/standard+normal/multix10: 70/70 in scope (80 planted); missing: s1.example.com:depth5, s2.example.com:depth5, s3.example.com:depth5, s4.example.com:depth5, s5.example.com:depth5, s6.example.com:depth5, s7.example.com:depth5, s8.example.com:depth5, s9.example.com:depth5, s10.example.com:depth5; memory gaps none
- PASS Within limits — 2.9/standard+low-impact/multix10: analysis processes parser 2×128 MiB, at most 256 MiB of heap limits at once of 256 MiB for 2 parser workers; out of memory 0; their RSS ≤137 MiB outside the setting; browser websites 1 ≤ 1; websites in flight 1 ≤ 2 used (option 2); RSS 225 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/standard+low-impact/multix10: 70/70 in scope (80 planted); missing: s1.example.com:depth5, s2.example.com:depth5, s3.example.com:depth5, s4.example.com:depth5, s5.example.com:depth5, s6.example.com:depth5, s7.example.com:depth5, s8.example.com:depth5, s9.example.com:depth5, s10.example.com:depth5; memory gaps none
- PASS Within limits — 2.9/deep+normal/multix10: analysis processes parser 1×256 MiB, at most 256 MiB of heap limits at once of 512 MiB for 2 parser workers; out of memory 0; their RSS ≤70 MiB outside the setting; browser websites 2 ≤ 2; websites in flight 1 ≤ 3 used (option 3); RSS 294 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/deep+normal/multix10: 80/80 in scope (80 planted); missing: none; memory gaps none
- PASS Within limits — 2.9/deep+low-impact/multix10: analysis processes parser 2×256 MiB, at most 512 MiB of heap limits at once of 512 MiB for 2 parser workers; out of memory 0; their RSS ≤137 MiB outside the setting; browser websites 1 ≤ 1; websites in flight 1 ≤ 2 used (option 2); RSS 231 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9/deep+low-impact/multix10: 80/80 in scope (80 planted); missing: none; memory gaps none
- PASS Within limits — 2.9-small/quick+normal/bundlex1: analysis processes parser 2×256, detector 1×108 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤244 MiB outside the setting; browser websites 0 ≤ 0; websites in flight 1 ≤ 1 used (option 6); RSS 278 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9-small/quick+normal/bundlex1: 7/7 in scope (7 planted); missing: none; memory gaps none
- PASS Within limits — 2.9-small/quick+low-impact/bundlex1: analysis processes parser 2×256, detector 1×108 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤244 MiB outside the setting; browser websites 0 ≤ 0; websites in flight 1 ≤ 1 used (option 2); RSS 280 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9-small/quick+low-impact/bundlex1: 7/7 in scope (7 planted); missing: none; memory gaps none
- PASS Within limits — 2.9-small/standard+normal/bundlex1: analysis processes parser 2×256, detector 1×108 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤244 MiB outside the setting; browser websites 1 ≤ 2; websites in flight 1 ≤ 1 used (option 4); RSS 309 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9-small/standard+normal/bundlex1: 7/7 in scope (7 planted); missing: none; memory gaps none
- PASS Within limits — 2.9-small/standard+low-impact/bundlex1: analysis processes parser 2×256, detector 1×108 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤243 MiB outside the setting; browser websites 1 ≤ 1; websites in flight 1 ≤ 1 used (option 2); RSS 273 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9-small/standard+low-impact/bundlex1: 7/7 in scope (7 planted); missing: none; memory gaps none
- PASS Within limits — 2.9-small/deep+normal/bundlex1: analysis processes parser 3×256, detector 2×108 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤241 MiB outside the setting; browser websites 1 ≤ 2; websites in flight 1 ≤ 1 used (option 3); RSS 300 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9-small/deep+normal/bundlex1: 7/7 in scope (7 planted); missing: none; memory gaps none
- PASS Within limits — 2.9-small/deep+low-impact/bundlex1: analysis processes parser 2×256, detector 2×108 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤488 MiB outside the setting; browser websites 1 ≤ 1; websites in flight 1 ≤ 1 used (option 2); RSS 359 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9-small/deep+low-impact/bundlex1: 7/7 in scope (7 planted); missing: none; memory gaps none
- PASS Within limits — 2.9-small/quick+normal/multix10: analysis processes parser 1×256 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤69 MiB outside the setting; browser websites 0 ≤ 0; websites in flight 1 ≤ 6 used (option 6); RSS 220 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9-small/quick+normal/multix10: 60/60 in scope (80 planted); missing: s1.example.com:depth3, s1.example.com:depth5, s2.example.com:depth3, s2.example.com:depth5, s3.example.com:depth3, s3.example.com:depth5, s4.example.com:depth3, s4.example.com:depth5, s5.example.com:depth3, s5.example.com:depth5, s6.example.com:depth3, s6.example.com:depth5, s7.example.com:depth3, s7.example.com:depth5, s8.example.com:depth3, s8.example.com:depth5, s9.example.com:depth3, s9.example.com:depth5, s10.example.com:depth3, s10.example.com:depth5; memory gaps none
- PASS Within limits — 2.9-small/standard+normal/multix10: analysis processes parser 1×256 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤70 MiB outside the setting; browser websites 1 ≤ 2; websites in flight 1 ≤ 4 used (option 4); RSS 294 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.9-small/standard+normal/multix10: 70/70 in scope (80 planted); missing: s1.example.com:depth5, s2.example.com:depth5, s3.example.com:depth5, s4.example.com:depth5, s5.example.com:depth5, s6.example.com:depth5, s7.example.com:depth5, s8.example.com:depth5, s9.example.com:depth5, s10.example.com:depth5; memory gaps none
- PASS Within limits — 2.9-small/deep+normal/multix10: analysis processes parser 1×256 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤70 MiB outside the setting; browser websites 1 ≤ 2; websites in flight 1 ≤ 3 used (option 3); RSS 231 MiB; egress violations 0
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
