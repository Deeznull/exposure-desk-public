# P4 measurement matrix (generated 2026-10-12T07:46:49.663Z)

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

## Freshness

- 2.8 source build: 2.8.0+cc5fecf8cb75f1c7, harness 43537d3099028d72, Node v24.18.1
- 2.7.0 baseline: 2.7.0+3772c88c496661b5, harness 43537d3099028d72, Node v24.18.1
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

This computer: 16 logical cores, 15.7 GiB free memory when recorded. Small computer: 2 cores and 1 GiB free memory, injected.

## Acceptance checks

- PASS Low-impact fewer connections than Normal, requests no more than Normal's — quick singlex1: requests 25 vs 25; TCP 1 vs 25
- PASS Low-impact fewer requests and connections than Normal — standard singlex1: requests 40 vs 49; TCP 1 vs 49
- PASS Low-impact fewer requests and connections than Normal — deep singlex1: requests 47 vs 61; TCP 3 vs 61
- PASS Deep+Low-impact keeps Deep+Normal recall — singlex1: 8/8 vs 8/8
- PASS Low-impact fewer connections than Normal, requests no more than Normal's — quick bundlex1: requests 29 vs 29; TCP 1 vs 29
- PASS Low-impact fewer requests and connections than Normal — standard bundlex1: requests 37 vs 41; TCP 1 vs 41
- PASS Low-impact fewer requests and connections than Normal — deep bundlex1: requests 37 vs 41; TCP 1 vs 41
- PASS Deep+Low-impact keeps Deep+Normal recall — bundlex1: 7/7 vs 7/7
- PASS Low-impact fewer connections than Normal, requests no more than Normal's — quick multix3: requests 75 vs 75; TCP 3 vs 75
- PASS Low-impact fewer requests and connections than Normal — standard multix3: requests 118 vs 147; TCP 5 vs 147
- PASS Low-impact fewer requests and connections than Normal — deep multix3: requests 141 vs 183; TCP 10 vs 183
- PASS Deep+Low-impact keeps Deep+Normal recall — multix3: 24/24 vs 24/24
- PASS Low-impact fewer connections than Normal, requests no more than Normal's — quick multix10: requests 250 vs 250; TCP 10 vs 250
- PASS Low-impact fewer requests and connections than Normal — standard multix10: requests 390 vs 490; TCP 18 vs 490
- PASS Low-impact fewer requests and connections than Normal — deep multix10: requests 450 vs 529; TCP 29 vs 529
- PASS Deep+Low-impact keeps Deep+Normal recall — multix10: 80/80 vs 80/80
- PASS Quick reports its limits — normal singlex1: completed, stage "Completed — quick coverage"; stated limits: http-unavailable, quick-coverage-boundary; not examined: Sitemaps ×1, Linked pages ×5; gaps none
- PASS Quick fastest — normal singlex1: 13.1 s vs Standard 38.9 s, Deep 78.9 s
- PASS Quick reports its limits — low-impact singlex1: completed, stage "Completed — quick coverage"; stated limits: http-unavailable, quick-coverage-boundary; not examined: Sitemaps ×1, Linked pages ×5; gaps none
- PASS Quick fastest — low-impact singlex1: 49.1 s vs Standard 79.3 s, Deep 100.2 s
- PASS Quick reports its limits — normal bundlex1: incomplete, stage "Stopped with coverage limitations"; stated limits: bare-extension-literals, http-unavailable, quick-coverage-boundary; not examined: none listed; gaps decoded-inspection-limit ×1
- PASS Quick fastest — normal bundlex1: 15.6 s vs Standard 21.3 s, Deep 23.6 s
- PASS Quick reports its limits — low-impact bundlex1: incomplete, stage "Stopped with coverage limitations"; stated limits: bare-extension-literals, http-unavailable, quick-coverage-boundary; not examined: none listed; gaps decoded-inspection-limit ×1
- PASS Quick fastest — low-impact bundlex1: 57.6 s vs Standard 73.3 s, Deep 73.2 s
- PASS Quick reports its limits — normal multix3: completed, stage "Completed — quick coverage"; stated limits: http-unavailable, quick-coverage-boundary; not examined: Sitemaps ×3, Linked pages ×15; gaps none
- PASS Quick fastest — normal multix3: 14.4 s vs Standard 46.8 s, Deep 107.6 s
- PASS Quick reports its limits — low-impact multix3: completed, stage "Completed — quick coverage"; stated limits: http-unavailable, quick-coverage-boundary; not examined: Sitemaps ×3, Linked pages ×15; gaps none
- PASS Quick fastest — low-impact multix3: 99.9 s vs Standard 158.6 s, Deep 199.1 s
- PASS Quick reports its limits — normal multix10: completed, stage "Completed — quick coverage"; stated limits: http-unavailable, quick-coverage-boundary; not examined: Sitemaps ×10, Linked pages ×50; gaps none
- PASS Quick fastest — normal multix10: 31.5 s vs Standard 168.2 s, Deep 223.4 s
- PASS Quick reports its limits — low-impact multix10: completed, stage "Completed — quick coverage"; stated limits: http-unavailable, quick-coverage-boundary; not examined: Sitemaps ×10, Linked pages ×50; gaps none
- PASS Quick fastest — low-impact multix10: 258.5 s vs Standard 417.3 s, Deep 577.7 s
- PASS Within limits — 2.8/quick+normal/singlex1: analysis processes parser 1×256 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤56 MiB outside the setting; browser websites 0 ≤ 0; websites in flight 1 ≤ 1 used (option 6); RSS 186 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.8/quick+normal/singlex1: 6/6 in scope (8 planted); missing: www.example.com:depth3, www.example.com:depth5; memory gaps none
- PASS Keeps the 2.7.0 recall — 2.8/quick+normal/singlex1: 6/8 vs 6/8; scan-process peak RSS 186 vs 165 MiB; 13.1 vs 16.4 s
- PASS Within limits — 2.8/quick+low-impact/singlex1: analysis processes parser 1×256 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤56 MiB outside the setting; browser websites 0 ≤ 0; websites in flight 1 ≤ 1 used (option 2); RSS 185 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.8/quick+low-impact/singlex1: 6/6 in scope (8 planted); missing: www.example.com:depth3, www.example.com:depth5; memory gaps none
- PASS Keeps the 2.7.0 recall — 2.8/quick+low-impact/singlex1: 6/8 vs 6/8; scan-process peak RSS 185 vs 163 MiB; 49.1 vs 49.7 s
- PASS Within limits — 2.8/standard+normal/singlex1: analysis processes parser 1×128 MiB, at most 128 MiB of heap limits at once of 256 MiB for 2 parser workers; out of memory 0; their RSS ≤60 MiB outside the setting; browser websites 1 ≤ 2; websites in flight 1 ≤ 1 used (option 4); RSS 201 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.8/standard+normal/singlex1: 7/7 in scope (8 planted); missing: www.example.com:depth5; memory gaps none
- PASS Keeps the 2.7.0 recall — 2.8/standard+normal/singlex1: 7/8 vs 7/8; scan-process peak RSS 201 vs 180 MiB; 38.9 vs 42.6 s
- PASS Within limits — 2.8/standard+low-impact/singlex1: analysis processes parser 1×128 MiB, at most 128 MiB of heap limits at once of 256 MiB for 2 parser workers; out of memory 0; their RSS ≤59 MiB outside the setting; browser websites 1 ≤ 1; websites in flight 1 ≤ 1 used (option 2); RSS 188 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.8/standard+low-impact/singlex1: 7/7 in scope (8 planted); missing: www.example.com:depth5; memory gaps none
- PASS Keeps the 2.7.0 recall — 2.8/standard+low-impact/singlex1: 7/8 vs 7/8; scan-process peak RSS 188 vs 170 MiB; 79.3 vs 80.0 s
- PASS Within limits — 2.8/deep+normal/singlex1: analysis processes parser 1×256 MiB, at most 256 MiB of heap limits at once of 512 MiB for 2 parser workers; out of memory 0; their RSS ≤59 MiB outside the setting; browser websites 1 ≤ 2; websites in flight 1 ≤ 1 used (option 3); RSS 199 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.8/deep+normal/singlex1: 8/8 in scope (8 planted); missing: none; memory gaps none
- PASS Keeps the 2.7.0 recall — 2.8/deep+normal/singlex1: 8/8 vs 8/8; scan-process peak RSS 199 vs 182 MiB; 78.9 vs 81.3 s
- PASS Within limits — 2.8/deep+low-impact/singlex1: analysis processes parser 1×256 MiB, at most 256 MiB of heap limits at once of 512 MiB for 2 parser workers; out of memory 0; their RSS ≤59 MiB outside the setting; browser websites 1 ≤ 1; websites in flight 1 ≤ 1 used (option 2); RSS 189 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.8/deep+low-impact/singlex1: 8/8 in scope (8 planted); missing: none; memory gaps none
- PASS Keeps the 2.7.0 recall — 2.8/deep+low-impact/singlex1: 8/8 vs 8/8; scan-process peak RSS 189 vs 171 MiB; 100.2 vs 100.7 s
- PASS Within limits — 2.8/quick+normal/bundlex1: analysis processes parser 2×256, detector 1×108 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤233 MiB outside the setting; browser websites 0 ≤ 0; websites in flight 1 ≤ 1 used (option 6); RSS 260 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.8/quick+normal/bundlex1: 7/7 in scope (7 planted); missing: none; memory gaps none
- PASS Keeps the 2.7.0 recall — 2.8/quick+normal/bundlex1: 7/7 vs 7/7; scan-process peak RSS 260 vs 248 MiB; 15.6 vs 20.3 s
- PASS Within limits — 2.8/quick+low-impact/bundlex1: analysis processes parser 2×256, detector 1×108 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤234 MiB outside the setting; browser websites 0 ≤ 0; websites in flight 1 ≤ 1 used (option 2); RSS 248 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.8/quick+low-impact/bundlex1: 7/7 in scope (7 planted); missing: none; memory gaps none
- PASS Keeps the 2.7.0 recall — 2.8/quick+low-impact/bundlex1: 7/7 vs 7/7; scan-process peak RSS 248 vs 247 MiB; 57.6 vs 59.4 s
- PASS Within limits — 2.8/standard+normal/bundlex1: analysis processes parser 3×128/256, detector 1×108 MiB, at most 256 MiB of heap limits at once of 256 MiB for 2 parser workers; out of memory 0; their RSS ≤291 MiB outside the setting; browser websites 1 ≤ 2; websites in flight 1 ≤ 1 used (option 4); RSS 334 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.8/standard+normal/bundlex1: 7/7 in scope (7 planted); missing: none; memory gaps none
- PASS Keeps the 2.7.0 recall — 2.8/standard+normal/bundlex1: 7/7 vs 7/7; scan-process peak RSS 334 vs 314 MiB; 21.3 vs 29.7 s
- PASS Within limits — 2.8/standard+low-impact/bundlex1: analysis processes parser 3×128/256, detector 1×108 MiB, at most 256 MiB of heap limits at once of 256 MiB for 2 parser workers; out of memory 0; their RSS ≤289 MiB outside the setting; browser websites 1 ≤ 1; websites in flight 1 ≤ 1 used (option 2); RSS 295 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.8/standard+low-impact/bundlex1: 7/7 in scope (7 planted); missing: none; memory gaps none
- PASS Keeps the 2.7.0 recall — 2.8/standard+low-impact/bundlex1: 7/7 vs 7/7; scan-process peak RSS 295 vs 293 MiB; 73.3 vs 73.4 s
- PASS Within limits — 2.8/deep+normal/bundlex1: analysis processes parser 1×256, detector 1×108 MiB, at most 364 MiB of heap limits at once of 512 MiB for 2 parser workers; out of memory 0; their RSS ≤397 MiB outside the setting; browser websites 1 ≤ 2; websites in flight 1 ≤ 1 used (option 3); RSS 310 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.8/deep+normal/bundlex1: 7/7 in scope (7 planted); missing: none; memory gaps none
- PASS Keeps the 2.7.0 recall — 2.8/deep+normal/bundlex1: 7/7 vs 7/7; scan-process peak RSS 310 vs 313 MiB; 23.6 vs 26.8 s
- PASS Within limits — 2.8/deep+low-impact/bundlex1: analysis processes parser 1×256, detector 1×108 MiB, at most 364 MiB of heap limits at once of 512 MiB for 2 parser workers; out of memory 0; their RSS ≤397 MiB outside the setting; browser websites 1 ≤ 1; websites in flight 1 ≤ 1 used (option 2); RSS 295 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.8/deep+low-impact/bundlex1: 7/7 in scope (7 planted); missing: none; memory gaps none
- PASS Keeps the 2.7.0 recall — 2.8/deep+low-impact/bundlex1: 7/7 vs 7/7; scan-process peak RSS 295 vs 291 MiB; 73.2 vs 73.7 s
- PASS Within limits — 2.8/quick+normal/multix3: analysis processes parser 1×256 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤57 MiB outside the setting; browser websites 0 ≤ 0; websites in flight 1 ≤ 3 used (option 6); RSS 206 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.8/quick+normal/multix3: 18/18 in scope (24 planted); missing: s1.example.com:depth3, s1.example.com:depth5, s2.example.com:depth3, s2.example.com:depth5, s3.example.com:depth3, s3.example.com:depth5; memory gaps none
- PASS Keeps the 2.7.0 recall — 2.8/quick+normal/multix3: 18/24 vs 18/24; scan-process peak RSS 206 vs 169 MiB; 14.4 vs 39.3 s
- PASS Within limits — 2.8/quick+low-impact/multix3: analysis processes parser 1×256 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤58 MiB outside the setting; browser websites 0 ≤ 0; websites in flight 1 ≤ 2 used (option 2); RSS 184 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.8/quick+low-impact/multix3: 18/18 in scope (24 planted); missing: s1.example.com:depth3, s1.example.com:depth5, s2.example.com:depth3, s2.example.com:depth5, s3.example.com:depth3, s3.example.com:depth5; memory gaps none
- PASS Keeps the 2.7.0 recall — 2.8/quick+low-impact/multix3: 18/24 vs 18/24; scan-process peak RSS 184 vs 165 MiB; 99.9 vs 100.5 s
- PASS Within limits — 2.8/standard+normal/multix3: analysis processes parser 2×128 MiB, at most 256 MiB of heap limits at once of 256 MiB for 2 parser workers; out of memory 0; their RSS ≤119 MiB outside the setting; browser websites 2 ≤ 2; websites in flight 1 ≤ 3 used (option 4); RSS 207 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.8/standard+normal/multix3: 21/21 in scope (24 planted); missing: s1.example.com:depth5, s2.example.com:depth5, s3.example.com:depth5; memory gaps none
- PASS Keeps the 2.7.0 recall — 2.8/standard+normal/multix3: 21/24 vs 21/24; scan-process peak RSS 207 vs 204 MiB; 46.8 vs 83.2 s
- PASS Within limits — 2.8/standard+low-impact/multix3: analysis processes parser 2×128 MiB, at most 256 MiB of heap limits at once of 256 MiB for 2 parser workers; out of memory 0; their RSS ≤117 MiB outside the setting; browser websites 1 ≤ 1; websites in flight 1 ≤ 2 used (option 2); RSS 195 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.8/standard+low-impact/multix3: 21/21 in scope (24 planted); missing: s1.example.com:depth5, s2.example.com:depth5, s3.example.com:depth5; memory gaps none
- PASS Keeps the 2.7.0 recall — 2.8/standard+low-impact/multix3: 21/24 vs 21/24; scan-process peak RSS 195 vs 175 MiB; 158.6 vs 162.0 s
- PASS Within limits — 2.8/deep+normal/multix3: analysis processes parser 2×256 MiB, at most 512 MiB of heap limits at once of 512 MiB for 2 parser workers; out of memory 0; their RSS ≤118 MiB outside the setting; browser websites 2 ≤ 2; websites in flight 1 ≤ 3 used (option 3); RSS 211 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.8/deep+normal/multix3: 24/24 in scope (24 planted); missing: none; memory gaps none
- PASS Keeps the 2.7.0 recall — 2.8/deep+normal/multix3: 24/24 vs 24/24; scan-process peak RSS 211 vs 210 MiB; 107.6 vs 130.9 s
- PASS Within limits — 2.8/deep+low-impact/multix3: analysis processes parser 2×256 MiB, at most 512 MiB of heap limits at once of 512 MiB for 2 parser workers; out of memory 0; their RSS ≤117 MiB outside the setting; browser websites 1 ≤ 1; websites in flight 1 ≤ 2 used (option 2); RSS 194 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.8/deep+low-impact/multix3: 24/24 in scope (24 planted); missing: none; memory gaps none
- PASS Keeps the 2.7.0 recall — 2.8/deep+low-impact/multix3: 24/24 vs 24/24; scan-process peak RSS 194 vs 205 MiB; 199.1 vs 198.3 s
- PASS Within limits — 2.8/quick+normal/multix10: analysis processes parser 1×256 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤58 MiB outside the setting; browser websites 0 ≤ 0; websites in flight 1 ≤ 6 used (option 6); RSS 215 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.8/quick+normal/multix10: 60/60 in scope (80 planted); missing: s1.example.com:depth3, s1.example.com:depth5, s2.example.com:depth3, s2.example.com:depth5, s3.example.com:depth3, s3.example.com:depth5, s4.example.com:depth3, s4.example.com:depth5, s5.example.com:depth3, s5.example.com:depth5, s6.example.com:depth3, s6.example.com:depth5, s7.example.com:depth3, s7.example.com:depth5, s8.example.com:depth3, s8.example.com:depth5, s9.example.com:depth3, s9.example.com:depth5, s10.example.com:depth3, s10.example.com:depth5; memory gaps none
- PASS Keeps the 2.7.0 recall — 2.8/quick+normal/multix10: 60/80 vs 60/80; scan-process peak RSS 215 vs 203 MiB; 31.5 vs 104.7 s
- PASS Within limits — 2.8/quick+low-impact/multix10: analysis processes parser 1×256 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤57 MiB outside the setting; browser websites 0 ≤ 0; websites in flight 1 ≤ 2 used (option 2); RSS 185 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.8/quick+low-impact/multix10: 60/60 in scope (80 planted); missing: s1.example.com:depth3, s1.example.com:depth5, s2.example.com:depth3, s2.example.com:depth5, s3.example.com:depth3, s3.example.com:depth5, s4.example.com:depth3, s4.example.com:depth5, s5.example.com:depth3, s5.example.com:depth5, s6.example.com:depth3, s6.example.com:depth5, s7.example.com:depth3, s7.example.com:depth5, s8.example.com:depth3, s8.example.com:depth5, s9.example.com:depth3, s9.example.com:depth5, s10.example.com:depth3, s10.example.com:depth5; memory gaps none
- PASS Keeps the 2.7.0 recall — 2.8/quick+low-impact/multix10: 60/80 vs 60/80; scan-process peak RSS 185 vs 165 MiB; 258.5 vs 255.2 s
- PASS Within limits — 2.8/standard+normal/multix10: analysis processes parser 2×128 MiB, at most 256 MiB of heap limits at once of 256 MiB for 2 parser workers; out of memory 0; their RSS ≤118 MiB outside the setting; browser websites 2 ≤ 2; websites in flight 1 ≤ 4 used (option 4); RSS 278 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.8/standard+normal/multix10: 70/70 in scope (80 planted); missing: s1.example.com:depth5, s2.example.com:depth5, s3.example.com:depth5, s4.example.com:depth5, s5.example.com:depth5, s6.example.com:depth5, s7.example.com:depth5, s8.example.com:depth5, s9.example.com:depth5, s10.example.com:depth5; memory gaps none
- PASS Keeps the 2.7.0 recall — 2.8/standard+normal/multix10: 70/80 vs 70/80; scan-process peak RSS 278 vs 281 MiB; 168.2 vs 247.2 s
- PASS Within limits — 2.8/standard+low-impact/multix10: analysis processes parser 2×128 MiB, at most 256 MiB of heap limits at once of 256 MiB for 2 parser workers; out of memory 0; their RSS ≤116 MiB outside the setting; browser websites 1 ≤ 1; websites in flight 1 ≤ 2 used (option 2); RSS 215 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.8/standard+low-impact/multix10: 70/70 in scope (80 planted); missing: s1.example.com:depth5, s2.example.com:depth5, s3.example.com:depth5, s4.example.com:depth5, s5.example.com:depth5, s6.example.com:depth5, s7.example.com:depth5, s8.example.com:depth5, s9.example.com:depth5, s10.example.com:depth5; memory gaps none
- PASS Keeps the 2.7.0 recall — 2.8/standard+low-impact/multix10: 70/80 vs 70/80; scan-process peak RSS 215 vs 212 MiB; 417.3 vs 420.2 s
- PASS Within limits — 2.8/deep+normal/multix10: analysis processes parser 2×256 MiB, at most 512 MiB of heap limits at once of 512 MiB for 2 parser workers; out of memory 0; their RSS ≤116 MiB outside the setting; browser websites 2 ≤ 2; websites in flight 1 ≤ 3 used (option 3); RSS 279 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.8/deep+normal/multix10: 80/80 in scope (80 planted); missing: none; memory gaps none
- PASS Keeps the 2.7.0 recall — 2.8/deep+normal/multix10: 80/80 vs 80/80; scan-process peak RSS 279 vs 281 MiB; 223.4 vs 298.3 s
- PASS Within limits — 2.8/deep+low-impact/multix10: analysis processes parser 2×256 MiB, at most 512 MiB of heap limits at once of 512 MiB for 2 parser workers; out of memory 0; their RSS ≤117 MiB outside the setting; browser websites 1 ≤ 1; websites in flight 1 ≤ 2 used (option 2); RSS 219 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.8/deep+low-impact/multix10: 80/80 in scope (80 planted); missing: none; memory gaps none
- PASS Keeps the 2.7.0 recall — 2.8/deep+low-impact/multix10: 80/80 vs 80/80; scan-process peak RSS 219 vs 217 MiB; 577.7 vs 567.5 s
- PASS Within limits — 2.8-small/quick+normal/bundlex1: analysis processes parser 2×256, detector 1×108 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤233 MiB outside the setting; browser websites 0 ≤ 0; websites in flight 1 ≤ 1 used (option 6); RSS 256 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.8-small/quick+normal/bundlex1: 7/7 in scope (7 planted); missing: none; memory gaps none
- PASS Within limits — 2.8-small/quick+low-impact/bundlex1: analysis processes parser 2×256, detector 1×108 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤234 MiB outside the setting; browser websites 0 ≤ 0; websites in flight 1 ≤ 1 used (option 2); RSS 250 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.8-small/quick+low-impact/bundlex1: 7/7 in scope (7 planted); missing: none; memory gaps none
- PASS Within limits — 2.8-small/standard+normal/bundlex1: analysis processes parser 2×256, detector 1×108 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤233 MiB outside the setting; browser websites 1 ≤ 2; websites in flight 1 ≤ 1 used (option 4); RSS 311 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.8-small/standard+normal/bundlex1: 7/7 in scope (7 planted); missing: none; memory gaps none
- PASS Within limits — 2.8-small/standard+low-impact/bundlex1: analysis processes parser 2×256, detector 1×108 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤234 MiB outside the setting; browser websites 1 ≤ 1; websites in flight 1 ≤ 1 used (option 2); RSS 293 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.8-small/standard+low-impact/bundlex1: 7/7 in scope (7 planted); missing: none; memory gaps none
- PASS Within limits — 2.8-small/deep+normal/bundlex1: analysis processes parser 2×256, detector 1×108 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤233 MiB outside the setting; browser websites 1 ≤ 2; websites in flight 1 ≤ 1 used (option 3); RSS 310 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.8-small/deep+normal/bundlex1: 7/7 in scope (7 planted); missing: none; memory gaps none
- PASS Within limits — 2.8-small/deep+low-impact/bundlex1: analysis processes parser 2×256, detector 1×108 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤233 MiB outside the setting; browser websites 1 ≤ 1; websites in flight 1 ≤ 1 used (option 2); RSS 293 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.8-small/deep+low-impact/bundlex1: 7/7 in scope (7 planted); missing: none; memory gaps none
- PASS Within limits — 2.8-small/quick+normal/multix10: analysis processes parser 1×256 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤58 MiB outside the setting; browser websites 0 ≤ 0; websites in flight 1 ≤ 6 used (option 6); RSS 216 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.8-small/quick+normal/multix10: 60/60 in scope (80 planted); missing: s1.example.com:depth3, s1.example.com:depth5, s2.example.com:depth3, s2.example.com:depth5, s3.example.com:depth3, s3.example.com:depth5, s4.example.com:depth3, s4.example.com:depth5, s5.example.com:depth3, s5.example.com:depth5, s6.example.com:depth3, s6.example.com:depth5, s7.example.com:depth3, s7.example.com:depth5, s8.example.com:depth3, s8.example.com:depth5, s9.example.com:depth3, s9.example.com:depth5, s10.example.com:depth3, s10.example.com:depth5; memory gaps none
- PASS Within limits — 2.8-small/standard+normal/multix10: analysis processes parser 1×256 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤61 MiB outside the setting; browser websites 1 ≤ 2; websites in flight 1 ≤ 4 used (option 4); RSS 276 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.8-small/standard+normal/multix10: 70/70 in scope (80 planted); missing: s1.example.com:depth5, s2.example.com:depth5, s3.example.com:depth5, s4.example.com:depth5, s5.example.com:depth5, s6.example.com:depth5, s7.example.com:depth5, s8.example.com:depth5, s9.example.com:depth5, s10.example.com:depth5; memory gaps none
- PASS Within limits — 2.8-small/deep+normal/multix10: analysis processes parser 1×256 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤59 MiB outside the setting; browser websites 1 ≤ 2; websites in flight 1 ≤ 3 used (option 3); RSS 282 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 2.8-small/deep+normal/multix10: 80/80 in scope (80 planted); missing: none; memory gaps none
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
- PASS Settings as recorded — 2.8/quick+normal/singlex1: same as the resources phase
- PASS Settings as recorded — 2.8/quick+low-impact/singlex1: same as the resources phase
- PASS Settings as recorded — 2.8/standard+normal/singlex1: same as the resources phase
- PASS Settings as recorded — 2.8/standard+low-impact/singlex1: same as the resources phase
- PASS Settings as recorded — 2.8/deep+normal/singlex1: same as the resources phase
- PASS Settings as recorded — 2.8/deep+low-impact/singlex1: same as the resources phase
- PASS Settings as recorded — 2.8/quick+normal/bundlex1: same as the resources phase
- PASS Settings as recorded — 2.8/quick+low-impact/bundlex1: same as the resources phase
- PASS Settings as recorded — 2.8/standard+normal/bundlex1: same as the resources phase
- PASS Settings as recorded — 2.8/standard+low-impact/bundlex1: same as the resources phase
- PASS Settings as recorded — 2.8/deep+normal/bundlex1: same as the resources phase
- PASS Settings as recorded — 2.8/deep+low-impact/bundlex1: same as the resources phase
- PASS Settings as recorded — 2.8/quick+normal/multix3: same as the resources phase
- PASS Settings as recorded — 2.8/quick+low-impact/multix3: same as the resources phase
- PASS Settings as recorded — 2.8/standard+normal/multix3: same as the resources phase
- PASS Settings as recorded — 2.8/standard+low-impact/multix3: same as the resources phase
- PASS Settings as recorded — 2.8/deep+normal/multix3: same as the resources phase
- PASS Settings as recorded — 2.8/deep+low-impact/multix3: same as the resources phase
- PASS Settings as recorded — 2.8/quick+normal/multix10: same as the resources phase
- PASS Settings as recorded — 2.8/quick+low-impact/multix10: same as the resources phase
- PASS Settings as recorded — 2.8/standard+normal/multix10: same as the resources phase
- PASS Settings as recorded — 2.8/standard+low-impact/multix10: same as the resources phase
- PASS Settings as recorded — 2.8/deep+normal/multix10: same as the resources phase
- PASS Settings as recorded — 2.8/deep+low-impact/multix10: same as the resources phase
- PASS Settings as recorded — 2.8-small/quick+normal/bundlex1: same as the resources phase
- PASS Settings as recorded — 2.8-small/quick+low-impact/bundlex1: same as the resources phase
- PASS Settings as recorded — 2.8-small/standard+normal/bundlex1: same as the resources phase
- PASS Settings as recorded — 2.8-small/standard+low-impact/bundlex1: same as the resources phase
- PASS Settings as recorded — 2.8-small/deep+normal/bundlex1: same as the resources phase
- PASS Settings as recorded — 2.8-small/deep+low-impact/bundlex1: same as the resources phase
- PASS Settings as recorded — 2.8-small/quick+normal/multix10: same as the resources phase
- PASS Settings as recorded — 2.8-small/standard+normal/multix10: same as the resources phase
- PASS Settings as recorded — 2.8-small/deep+normal/multix10: same as the resources phase
