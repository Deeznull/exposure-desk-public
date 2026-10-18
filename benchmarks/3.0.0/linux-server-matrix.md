# P4 measurement matrix (generated 2026-10-17T19:28:06.464Z)

| Run | Option | Fixture | State | Time s | Requests | TCP | TLS | Wire MiB | Browser nav | Peak RSS MiB | Analysis heap MiB (worker peak/limit, or processes×limit) | Analysis processes RSS MiB (bound) | Acquisition | Analysis | Recall (in scope) | Precision (credential findings) | Est. conns |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 2.9.1 | quick+normal | single×1 | completed (quick-coverage) | 16.4 | 25 | 25 | 25 | 0.11 | 0 | 242 | parser 1×256; ≤256 at once | 54 | 100% | 100% | 6/8  (6 expected) | 6/6 | — |
| 2.9.1 | quick+low-impact | single×1 | completed (quick-coverage) | 52.8 | 25 | 1 | 1 | 0.02 | 0 | 233 | parser 1×256; ≤256 at once | 54 | 100% | 100% | 6/8  (6 expected) | 6/6 | — |
| 2.9.1 | standard+normal | single×1 | incomplete | 54.1 | 49 | 49 | 49 | 0.22 | 5 | 258 | parser 1×128; ≤128 at once | 63 | 65% | 127% | 7/8  (7 expected) | 7/7 | — |
| 2.9.1 | standard+low-impact | single×1 | incomplete | 81.4 | 39 | 1 | 1 | 0.03 | 3 | 256 | parser 1×128; ≤128 at once | 64 | 63% | 131% | 7/8  (7 expected) | 7/7 | — |
| 2.9.1 | deep+normal | single×1 | incomplete | 105.2 | 61 | 61 | 61 | 0.27 | 10 | 326 | parser 1×256; ≤256 at once | 66 | 64% | 126% | 8/8  (8 expected) | 8/8 | — |
| 2.9.1 | deep+low-impact | single×1 | incomplete | 107.8 | 47 | 4 | 4 | 0.04 | 6 | 243 | parser 1×256; ≤256 at once | 64 | 63% | 131% | 8/8  (8 expected) | 8/8 | — |
| 2.9.1 | quick+normal | bundle×1 | incomplete | 22.4 | 29 | 29 | 29 | 1.32 | 0 | 309 | parser 2×256, detector 1×108; ≤256 at once | 246 | 100% | 100% | 7/7  (7 expected) | 7/7 | — |
| 2.9.1 | quick+low-impact | bundle×1 | incomplete | 65.5 | 29 | 2 | 2 | 1.22 | 0 | 310 | parser 2×256, detector 1×108; ≤256 at once | 245 | 100% | 100% | 7/7  (7 expected) | 7/7 | — |
| 2.9.1 | standard+normal | bundle×1 | incomplete | 33.0 | 41 | 41 | 41 | 2.57 | 1 | 341 | parser 4×128/256, detector 2×108; ≤256 at once | 351 | 65% | 137% | 7/7  (7 expected) | 7/7 | — |
| 2.9.1 | standard+low-impact | bundle×1 | incomplete | 79.0 | 37 | 1 | 1 | 2.42 | 1 | 341 | parser 5×128/256, detector 2×108; ≤256 at once | 488 | 62% | 142% | 7/7  (7 expected) | 7/7 | — |
| 2.9.1 | deep+normal | bundle×1 | incomplete | 27.1 | 41 | 41 | 41 | 2.57 | 1 | 365 | parser 1×256, detector 2×108; ≤472 at once | 770 | 65% | 137% | 7/7  (7 expected) | 7/7 | — |
| 2.9.1 | deep+low-impact | bundle×1 | incomplete | 78.3 | 37 | 1 | 1 | 2.42 | 1 | 406 | parser 1×256, detector 2×108; ≤472 at once | 766 | 62% | 142% | 7/7  (7 expected) | 7/7 | — |
| 2.9.1 | quick+normal | multi×3 | completed (quick-coverage) | 22.3 | 75 | 75 | 75 | 0.33 | 0 | 257 | parser 1×256; ≤256 at once | 54 | 100% | 100% | 18/24  (18 expected) | 18/18 | — |
| 2.9.1 | quick+low-impact | multi×3 | completed (quick-coverage) | 105.4 | 75 | 3 | 3 | 0.05 | 0 | 240 | parser 1×256; ≤256 at once | 54 | 100% | 100% | 18/24  (18 expected) | 18/18 | — |
| 2.9.1 | standard+normal | multi×3 | incomplete | 74.6 | 144 | 144 | 144 | 0.64 | 15 | 335 | parser 2×128; ≤256 at once | 122 | 74% | 115% | 21/24  (21 expected) | 21/21 | — |
| 2.9.1 | standard+low-impact | multi×3 | incomplete | 211.9 | 117 | 14 | 14 | 0.12 | 9 | 247 | parser 2×128; ≤256 at once | 119 | 76% | 114% | 21/24  (21 expected) | 21/21 | — |
| 2.9.1 | deep+normal | multi×3 | incomplete | 166.2 | 183 | 183 | 183 | 0.82 | 30 | 270 | parser 2×256; ≤512 at once | 120 | 72% | 116% | 24/24  (24 expected) | 24/24 | — |
| 2.9.1 | deep+low-impact | multi×3 | incomplete | 260.4 | 141 | 17 | 17 | 0.15 | 18 | 245 | parser 2×256; ≤512 at once | 121 | 72% | 118% | 24/24  (24 expected) | 24/24 | — |
| 2.9.1 | quick+normal | multi×10 | incomplete | 96.0 | 250 | 250 | 250 | 1.13 | 0 | 325 | parser 1×256; ≤256 at once | 56 | 100% | 100% | 60/80  (60 expected) | 60/60 | — |
| 2.9.1 | quick+low-impact | multi×10 | completed (quick-coverage) | 278.3 | 250 | 12 | 12 | 0.18 | 0 | 234 | parser 1×256; ≤256 at once | 55 | 100% | 100% | 60/80  (60 expected) | 60/60 | — |
| 2.9.1 | standard+normal | multi×10 | incomplete | 201.3 | 485 | 485 | 485 | 2.22 | 50 | 354 | parser 2×128; ≤256 at once | 122 | 78% | 111% | 70/80  (70 expected) | 70/70 | — |
| 2.9.1 | standard+low-impact | multi×10 | incomplete | 445.1 | 390 | 20 | 20 | 0.30 | 30 | 271 | parser 2×128; ≤256 at once | 123 | 78% | 113% | 70/80  (70 expected) | 70/70 | — |
| 2.9.1 | deep+normal | multi×10 | incomplete | 271.0 | 529 | 529 | 529 | 2.42 | 50 | 317 | parser 2×256; ≤512 at once | 124 | 80% | 111% | 80/80  (80 expected) | 80/80 | — |
| 2.9.1 | deep+low-impact | multi×10 | incomplete | 664.4 | 450 | 38 | 38 | 0.41 | 50 | 265 | parser 2×256; ≤512 at once | 122 | 78% | 112% | 80/80  (80 expected) | 80/80 | — |
| 3.0 | quick+normal | single×1 | completed (quick-coverage) | 18.6 | 28 | 28 | 28 | 0.12 | 0 | 248 | parser 1×256; ≤256 at once | 54 | 100% | 100% | 6/8  (6 expected) | 6/6 | — |
| 3.0 | quick+low-impact | single×1 | completed (quick-coverage) | 58.5 | 28 | 1 | 1 | 0.02 | 0 | 233 | parser 1×256; ≤256 at once | 54 | 100% | 100% | 6/8  (6 expected) | 6/6 | — |
| 3.0 | standard+normal | single×1 | incomplete | 58.6 | 61 | 61 | 61 | 0.27 | 5 | 253 | parser 1×128; ≤128 at once | 65 | 70% | 121% | 7/8  (7 expected) | 7/7 | — |
| 3.0 | standard+low-impact | single×1 | incomplete | 109.4 | 52 | 1 | 1 | 0.03 | 3 | 243 | parser 1×128; ≤128 at once | 65 | 69% | 125% | 7/8  (7 expected) | 7/7 | — |
| 3.0 | deep+normal | single×1 | incomplete | 114.8 | 73 | 73 | 73 | 0.32 | 10 | 320 | parser 1×256; ≤256 at once | 67 | 68% | 122% | 8/8  (8 expected) | 8/8 | — |
| 3.0 | deep+low-impact | single×1 | incomplete | 133.1 | 59 | 4 | 4 | 0.05 | 6 | 254 | parser 1×256; ≤256 at once | 65 | 68% | 124% | 8/8  (8 expected) | 8/8 | — |
| 3.0 | quick+normal | bundle×1 | incomplete | 26.3 | 32 | 32 | 32 | 1.34 | 0 | 311 | parser 2×256, detector 1×108; ≤256 at once | 243 | 100% | 100% | 7/7  (7 expected) | 7/7 | — |
| 3.0 | quick+low-impact | bundle×1 | incomplete | 70.3 | 32 | 2 | 2 | 1.22 | 0 | 311 | parser 2×256, detector 1×108; ≤256 at once | 242 | 100% | 100% | 7/7  (7 expected) | 7/7 | — |
| 3.0 | standard+normal | bundle×1 | incomplete | 39.6 | 53 | 53 | 53 | 2.63 | 1 | 343 | parser 4×128/256, detector 2×108; ≤256 at once | 490 | 71% | 128% | 6/7  (7 expected) | 6/6 | — |
| 3.0 | standard+low-impact | bundle×1 | incomplete | 103.5 | 49 | 1 | 1 | 2.42 | 1 | 394 | parser 3×128/256, detector 2×108; ≤256 at once | 490 | 70% | 130% | 7/7  (7 expected) | 7/7 | — |
| 3.0 | deep+normal | bundle×1 | incomplete | 38.4 | 53 | 53 | 53 | 2.63 | 1 | 340 | parser 2×256, detector 2×108; ≤472 at once | 732 | 71% | 128% | 6/7  (7 expected) | 6/6 | — |
| 3.0 | deep+low-impact | bundle×1 | incomplete | 100.9 | 49 | 1 | 1 | 2.42 | 1 | 356 | parser 1×256, detector 2×108; ≤364 at once | 532 | 69% | 130% | 7/7  (7 expected) | 7/7 | — |
| 3.0 | quick+normal | multi×3 | completed (quick-coverage) | 21.6 | 84 | 84 | 84 | 0.37 | 0 | 250 | parser 1×256; ≤256 at once | 54 | 100% | 100% | 18/24  (18 expected) | 18/18 | — |
| 3.0 | quick+low-impact | multi×3 | completed (quick-coverage) | 143.3 | 84 | 3 | 3 | 0.05 | 0 | 242 | parser 1×256; ≤256 at once | 54 | 100% | 100% | 18/24  (18 expected) | 18/18 | — |
| 3.0 | standard+normal | multi×3 | incomplete | 127.9 | 180 | 180 | 180 | 0.80 | 15 | 336 | parser 2×128; ≤256 at once | 120 | 79% | 112% | 21/24  (21 expected) | 21/21 | — |
| 3.0 | standard+low-impact | multi×3 | incomplete | 228.3 | 153 | 8 | 8 | 0.11 | 9 | 324 | parser 2×128; ≤256 at once | 121 | 79% | 113% | 21/24  (21 expected) | 21/21 | — |
| 3.0 | deep+normal | multi×3 | incomplete | 222.3 | 219 | 219 | 219 | 0.98 | 30 | 301 | parser 2×256; ≤512 at once | 119 | 76% | 112% | 24/24  (24 expected) | 24/24 | — |
| 3.0 | deep+low-impact | multi×3 | incomplete | 298.6 | 177 | 14 | 14 | 0.15 | 18 | 245 | parser 2×256; ≤512 at once | 122 | 77% | 114% | 24/24  (24 expected) | 24/24 | — |
| 3.0 | quick+normal | multi×10 | completed (quick-coverage) | 51.1 | 280 | 280 | 280 | 1.27 | 0 | 326 | parser 1×256; ≤256 at once | 56 | 100% | 100% | 60/80  (60 expected) | 60/60 | — |
| 3.0 | quick+low-impact | multi×10 | completed (quick-coverage) | 299.8 | 280 | 10 | 10 | 0.18 | 0 | 240 | parser 1×256; ≤256 at once | 55 | 100% | 100% | 60/80  (60 expected) | 60/60 | — |
| 3.0 | standard+normal | multi×10 | incomplete | 252.1 | 606 | 606 | 606 | 2.77 | 50 | 328 | parser 2×128; ≤256 at once | 126 | 82% | 108% | 70/80  (70 expected) | 70/70 | — |
| 3.0 | standard+low-impact | multi×10 | incomplete | 568.8 | 510 | 20 | 20 | 0.35 | 30 | 305 | parser 2×128; ≤256 at once | 123 | 82% | 110% | 70/80  (70 expected) | 70/70 | — |
| 3.0 | deep+normal | multi×10 | incomplete | 329.7 | 649 | 649 | 649 | 2.96 | 50 | 340 | parser 2×256; ≤512 at once | 122 | 83% | 109% | 80/80  (80 expected) | 80/80 | — |
| 3.0 | deep+low-impact | multi×10 | incomplete | 843.7 | 576 | 54 | 54 | 0.53 | 50 | 261 | parser 2×256; ≤512 at once | 122 | 81% | 111% | 80/80  (80 expected) | 80/80 | — |
| 3.0-small | quick+normal | bundle×1 | incomplete | 22.6 | 32 | 32 | 32 | 1.34 | 0 | 309 | parser 2×256, detector 1×108; ≤256 at once | 243 | 100% | 100% | 7/7  (7 expected) | 7/7 | — |
| 3.0-small | quick+low-impact | bundle×1 | incomplete | 72.9 | 32 | 2 | 2 | 1.22 | 0 | 310 | parser 2×256, detector 1×108; ≤256 at once | 244 | 100% | 100% | 7/7  (7 expected) | 7/7 | — |
| 3.0-small | standard+normal | bundle×1 | incomplete | 42.0 | 53 | 53 | 53 | 2.63 | 1 | 319 | parser 3×256, detector 2×108; ≤256 at once | 243 | 71% | 128% | 6/7  (7 expected) | 6/6 | — |
| 3.0-small | standard+low-impact | bundle×1 | incomplete | 101.7 | 49 | 1 | 1 | 2.42 | 1 | 326 | parser 2×256, detector 2×108; ≤256 at once | 358 | 69% | 130% | 7/7  (7 expected) | 7/7 | — |
| 3.0-small | deep+normal | bundle×1 | incomplete | 42.5 | 53 | 53 | 53 | 2.63 | 1 | 334 | parser 4×256, detector 2×108; ≤256 at once | 246 | 71% | 128% | 6/7  (7 expected) | 6/6 | — |
| 3.0-small | deep+low-impact | bundle×1 | incomplete | 103.0 | 49 | 1 | 1 | 2.42 | 1 | 368 | parser 2×256, detector 1×108; ≤256 at once | 251 | 69% | 130% | 7/7  (7 expected) | 7/7 | — |
| 3.0-small | quick+normal | multi×10 | completed (quick-coverage) | 52.2 | 280 | 280 | 280 | 1.27 | 0 | 322 | parser 1×256; ≤256 at once | 56 | 100% | 100% | 60/80  (60 expected) | 60/60 | — |
| 3.0-small | standard+normal | multi×10 | incomplete | 428.3 | 587 | 587 | 587 | 2.68 | 40 | 310 | parser 1×256; ≤256 at once | 68 | 83% | 109% | 70/80  (70 expected) | 70/70 | — |
| 3.0-small | deep+normal | multi×10 | incomplete | 607.9 | 640 | 640 | 640 | 2.92 | 50 | 306 | parser 1×256; ≤256 at once | 68 | 84% | 108% | 80/80  (80 expected) | 80/80 | — |

## Freshness

- 3.0 source build: 3.0.0+900c631686338160, harness 43537d3099028d72, Node v24.18.1
- 2.9.1 baseline: 2.9.1+94a512df50bb9d43, harness 43537d3099028d72, Node v24.18.1
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

This computer: 7 logical cores, 8.6 GiB free memory when recorded. Small computer: 2 cores and 1 GiB free memory, injected.

## Acceptance checks

- PASS Low-impact fewer connections than Normal, requests no more than Normal's — quick singlex1: requests 28 vs 28; TCP 1 vs 28
- PASS Low-impact fewer requests and connections than Normal — standard singlex1: requests 52 vs 61; TCP 1 vs 61
- PASS Low-impact fewer requests and connections than Normal — deep singlex1: requests 59 vs 73; TCP 4 vs 73
- PASS Deep+Low-impact keeps Deep+Normal recall — singlex1: 8/8 vs 8/8
- PASS Low-impact fewer connections than Normal, requests no more than Normal's — quick bundlex1: requests 32 vs 32; TCP 2 vs 32
- PASS Low-impact fewer requests and connections than Normal — standard bundlex1: requests 49 vs 53; TCP 1 vs 53
- PASS Low-impact fewer requests and connections than Normal — deep bundlex1: requests 49 vs 53; TCP 1 vs 53
- PASS Deep+Low-impact keeps Deep+Normal recall — bundlex1: 7/7 vs 6/7
- PASS Low-impact fewer connections than Normal, requests no more than Normal's — quick multix3: requests 84 vs 84; TCP 3 vs 84
- PASS Low-impact fewer requests and connections than Normal — standard multix3: requests 153 vs 180; TCP 8 vs 180
- PASS Low-impact fewer requests and connections than Normal — deep multix3: requests 177 vs 219; TCP 14 vs 219
- PASS Deep+Low-impact keeps Deep+Normal recall — multix3: 24/24 vs 24/24
- PASS Low-impact fewer connections than Normal, requests no more than Normal's — quick multix10: requests 280 vs 280; TCP 10 vs 280
- PASS Low-impact fewer requests and connections than Normal — standard multix10: requests 510 vs 606; TCP 20 vs 606
- PASS Low-impact fewer requests and connections than Normal — deep multix10: requests 576 vs 649; TCP 54 vs 649
- PASS Deep+Low-impact keeps Deep+Normal recall — multix10: 80/80 vs 80/80
- PASS Quick reports its limits — normal singlex1: completed, stage "Completed — quick coverage"; stated limits: http-unavailable, quick-coverage-boundary; not examined: Sitemaps ×1, Linked pages ×5; gaps none
- PASS Quick fastest — normal singlex1: 18.6 s vs Standard 58.6 s, Deep 114.8 s
- PASS Quick reports its limits — low-impact singlex1: completed, stage "Completed — quick coverage"; stated limits: http-unavailable, quick-coverage-boundary; not examined: Sitemaps ×1, Linked pages ×5; gaps none
- PASS Quick fastest — low-impact singlex1: 58.5 s vs Standard 109.4 s, Deep 133.1 s
- PASS Quick reports its limits — normal bundlex1: incomplete, stage "Stopped with coverage limitations"; stated limits: bare-extension-literals, http-unavailable, quick-coverage-boundary; not examined: none listed; gaps decoded-inspection-limit ×1
- PASS Quick fastest — normal bundlex1: 26.3 s vs Standard 39.6 s, Deep 38.4 s
- PASS Quick reports its limits — low-impact bundlex1: incomplete, stage "Stopped with coverage limitations"; stated limits: bare-extension-literals, http-unavailable, quick-coverage-boundary; not examined: none listed; gaps decoded-inspection-limit ×1
- PASS Quick fastest — low-impact bundlex1: 70.3 s vs Standard 103.5 s, Deep 100.9 s
- PASS Quick reports its limits — normal multix3: completed, stage "Completed — quick coverage"; stated limits: http-unavailable, quick-coverage-boundary; not examined: Sitemaps ×3, Linked pages ×15; gaps none
- PASS Quick fastest — normal multix3: 21.6 s vs Standard 127.9 s, Deep 222.3 s
- PASS Quick reports its limits — low-impact multix3: completed, stage "Completed — quick coverage"; stated limits: http-unavailable, quick-coverage-boundary; not examined: Sitemaps ×3, Linked pages ×15; gaps decoded-inspection-limit ×1
- PASS Quick fastest — low-impact multix3: 143.3 s vs Standard 228.3 s, Deep 298.6 s
- PASS Quick reports its limits — normal multix10: completed, stage "Completed — quick coverage"; stated limits: http-unavailable, quick-coverage-boundary; not examined: Sitemaps ×10, Linked pages ×50; gaps none
- PASS Quick fastest — normal multix10: 51.1 s vs Standard 252.1 s, Deep 329.7 s
- PASS Quick reports its limits — low-impact multix10: completed, stage "Completed — quick coverage"; stated limits: http-unavailable, quick-coverage-boundary; not examined: Sitemaps ×10, Linked pages ×50; gaps none
- PASS Quick fastest — low-impact multix10: 299.8 s vs Standard 568.8 s, Deep 843.7 s
- PASS Within limits — 3.0/quick+normal/singlex1: analysis processes parser 1×256 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤54 MiB outside the setting; browser websites 0 ≤ 0; websites in flight 1 ≤ 1 used (option 6); RSS 248 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 3.0/quick+normal/singlex1: 6/6 in scope (8 planted); missing: www.example.com:depth3, www.example.com:depth5; memory gaps none
- PASS Keeps the 2.9.1 recall — 3.0/quick+normal/singlex1: 6/8 vs 6/8; scan-process peak RSS 248 vs 242 MiB; 18.6 vs 16.4 s
- PASS Within limits — 3.0/quick+low-impact/singlex1: analysis processes parser 1×256 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤54 MiB outside the setting; browser websites 0 ≤ 0; websites in flight 1 ≤ 1 used (option 2); RSS 233 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 3.0/quick+low-impact/singlex1: 6/6 in scope (8 planted); missing: www.example.com:depth3, www.example.com:depth5; memory gaps none
- PASS Keeps the 2.9.1 recall — 3.0/quick+low-impact/singlex1: 6/8 vs 6/8; scan-process peak RSS 233 vs 233 MiB; 58.5 vs 52.8 s
- PASS Within limits — 3.0/standard+normal/singlex1: analysis processes parser 1×128 MiB, at most 128 MiB of heap limits at once of 256 MiB for 2 parser workers; out of memory 0; their RSS ≤65 MiB outside the setting; browser websites 1 ≤ 2; websites in flight 1 ≤ 1 used (option 4); RSS 253 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 3.0/standard+normal/singlex1: 7/7 in scope (8 planted); missing: www.example.com:depth5; memory gaps none
- PASS Keeps the 2.9.1 recall — 3.0/standard+normal/singlex1: 7/8 vs 7/8; scan-process peak RSS 253 vs 258 MiB; 58.6 vs 54.1 s
- PASS Within limits — 3.0/standard+low-impact/singlex1: analysis processes parser 1×128 MiB, at most 128 MiB of heap limits at once of 256 MiB for 2 parser workers; out of memory 0; their RSS ≤65 MiB outside the setting; browser websites 1 ≤ 1; websites in flight 1 ≤ 1 used (option 2); RSS 243 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 3.0/standard+low-impact/singlex1: 7/7 in scope (8 planted); missing: www.example.com:depth5; memory gaps none
- PASS Keeps the 2.9.1 recall — 3.0/standard+low-impact/singlex1: 7/8 vs 7/8; scan-process peak RSS 243 vs 256 MiB; 109.4 vs 81.4 s
- PASS Within limits — 3.0/deep+normal/singlex1: analysis processes parser 1×256 MiB, at most 256 MiB of heap limits at once of 512 MiB for 2 parser workers; out of memory 0; their RSS ≤67 MiB outside the setting; browser websites 1 ≤ 2; websites in flight 1 ≤ 1 used (option 3); RSS 320 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 3.0/deep+normal/singlex1: 8/8 in scope (8 planted); missing: none; memory gaps none
- PASS Keeps the 2.9.1 recall — 3.0/deep+normal/singlex1: 8/8 vs 8/8; scan-process peak RSS 320 vs 326 MiB; 114.8 vs 105.2 s
- PASS Within limits — 3.0/deep+low-impact/singlex1: analysis processes parser 1×256 MiB, at most 256 MiB of heap limits at once of 512 MiB for 2 parser workers; out of memory 0; their RSS ≤65 MiB outside the setting; browser websites 1 ≤ 1; websites in flight 1 ≤ 1 used (option 2); RSS 254 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 3.0/deep+low-impact/singlex1: 8/8 in scope (8 planted); missing: none; memory gaps none
- PASS Keeps the 2.9.1 recall — 3.0/deep+low-impact/singlex1: 8/8 vs 8/8; scan-process peak RSS 254 vs 243 MiB; 133.1 vs 107.8 s
- PASS Within limits — 3.0/quick+normal/bundlex1: analysis processes parser 2×256, detector 1×108 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤243 MiB outside the setting; browser websites 0 ≤ 0; websites in flight 1 ≤ 1 used (option 6); RSS 311 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 3.0/quick+normal/bundlex1: 7/7 in scope (7 planted); missing: none; memory gaps none
- PASS Keeps the 2.9.1 recall — 3.0/quick+normal/bundlex1: 7/7 vs 7/7; scan-process peak RSS 311 vs 309 MiB; 26.3 vs 22.4 s
- PASS Within limits — 3.0/quick+low-impact/bundlex1: analysis processes parser 2×256, detector 1×108 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤242 MiB outside the setting; browser websites 0 ≤ 0; websites in flight 1 ≤ 1 used (option 2); RSS 311 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 3.0/quick+low-impact/bundlex1: 7/7 in scope (7 planted); missing: none; memory gaps none
- PASS Keeps the 2.9.1 recall — 3.0/quick+low-impact/bundlex1: 7/7 vs 7/7; scan-process peak RSS 311 vs 310 MiB; 70.3 vs 65.5 s
- PASS Within limits — 3.0/standard+normal/bundlex1: analysis processes parser 4×128/256, detector 2×108 MiB, at most 256 MiB of heap limits at once of 256 MiB for 2 parser workers; out of memory 0; their RSS ≤490 MiB outside the setting; browser websites 1 ≤ 2; websites in flight 1 ≤ 1 used (option 4); RSS 343 MiB; egress violations 0
- FAIL Finds its keys at its memory setting — 3.0/standard+normal/bundlex1: 6/7 in scope (7 planted); missing: bundle.example.com:bundle; memory gaps none
- FAIL Keeps the 2.9.1 recall — 3.0/standard+normal/bundlex1: 6/7 vs 7/7; scan-process peak RSS 343 vs 341 MiB; 39.6 vs 33.0 s
- PASS Within limits — 3.0/standard+low-impact/bundlex1: analysis processes parser 3×128/256, detector 2×108 MiB, at most 256 MiB of heap limits at once of 256 MiB for 2 parser workers; out of memory 0; their RSS ≤490 MiB outside the setting; browser websites 1 ≤ 1; websites in flight 1 ≤ 1 used (option 2); RSS 394 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 3.0/standard+low-impact/bundlex1: 7/7 in scope (7 planted); missing: none; memory gaps none
- PASS Keeps the 2.9.1 recall — 3.0/standard+low-impact/bundlex1: 7/7 vs 7/7; scan-process peak RSS 394 vs 341 MiB; 103.5 vs 79.0 s
- PASS Within limits — 3.0/deep+normal/bundlex1: analysis processes parser 2×256, detector 2×108 MiB, at most 472 MiB of heap limits at once of 512 MiB for 2 parser workers; out of memory 0; their RSS ≤732 MiB outside the setting; browser websites 1 ≤ 2; websites in flight 1 ≤ 1 used (option 3); RSS 340 MiB; egress violations 0
- FAIL Finds its keys at its memory setting — 3.0/deep+normal/bundlex1: 6/7 in scope (7 planted); missing: bundle.example.com:bundle; memory gaps none
- FAIL Keeps the 2.9.1 recall — 3.0/deep+normal/bundlex1: 6/7 vs 7/7; scan-process peak RSS 340 vs 365 MiB; 38.4 vs 27.1 s
- PASS Within limits — 3.0/deep+low-impact/bundlex1: analysis processes parser 1×256, detector 2×108 MiB, at most 364 MiB of heap limits at once of 512 MiB for 2 parser workers; out of memory 0; their RSS ≤532 MiB outside the setting; browser websites 1 ≤ 1; websites in flight 1 ≤ 1 used (option 2); RSS 356 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 3.0/deep+low-impact/bundlex1: 7/7 in scope (7 planted); missing: none; memory gaps none
- PASS Keeps the 2.9.1 recall — 3.0/deep+low-impact/bundlex1: 7/7 vs 7/7; scan-process peak RSS 356 vs 406 MiB; 100.9 vs 78.3 s
- PASS Within limits — 3.0/quick+normal/multix3: analysis processes parser 1×256 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤54 MiB outside the setting; browser websites 0 ≤ 0; websites in flight 1 ≤ 3 used (option 6); RSS 250 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 3.0/quick+normal/multix3: 18/18 in scope (24 planted); missing: s1.example.com:depth3, s1.example.com:depth5, s2.example.com:depth3, s2.example.com:depth5, s3.example.com:depth3, s3.example.com:depth5; memory gaps none
- PASS Keeps the 2.9.1 recall — 3.0/quick+normal/multix3: 18/24 vs 18/24; scan-process peak RSS 250 vs 257 MiB; 21.6 vs 22.3 s
- PASS Within limits — 3.0/quick+low-impact/multix3: analysis processes parser 1×256 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤54 MiB outside the setting; browser websites 0 ≤ 0; websites in flight 1 ≤ 2 used (option 2); RSS 242 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 3.0/quick+low-impact/multix3: 18/18 in scope (24 planted); missing: s1.example.com:depth3, s1.example.com:depth5, s2.example.com:depth3, s2.example.com:depth5, s3.example.com:depth3, s3.example.com:depth5; memory gaps none
- PASS Keeps the 2.9.1 recall — 3.0/quick+low-impact/multix3: 18/24 vs 18/24; scan-process peak RSS 242 vs 240 MiB; 143.3 vs 105.4 s
- PASS Within limits — 3.0/standard+normal/multix3: analysis processes parser 2×128 MiB, at most 256 MiB of heap limits at once of 256 MiB for 2 parser workers; out of memory 0; their RSS ≤120 MiB outside the setting; browser websites 2 ≤ 2; websites in flight 1 ≤ 3 used (option 4); RSS 336 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 3.0/standard+normal/multix3: 21/21 in scope (24 planted); missing: s1.example.com:depth5, s2.example.com:depth5, s3.example.com:depth5; memory gaps none
- PASS Keeps the 2.9.1 recall — 3.0/standard+normal/multix3: 21/24 vs 21/24; scan-process peak RSS 336 vs 335 MiB; 127.9 vs 74.6 s
- PASS Within limits — 3.0/standard+low-impact/multix3: analysis processes parser 2×128 MiB, at most 256 MiB of heap limits at once of 256 MiB for 2 parser workers; out of memory 0; their RSS ≤121 MiB outside the setting; browser websites 1 ≤ 1; websites in flight 1 ≤ 2 used (option 2); RSS 324 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 3.0/standard+low-impact/multix3: 21/21 in scope (24 planted); missing: s1.example.com:depth5, s2.example.com:depth5, s3.example.com:depth5; memory gaps none
- PASS Keeps the 2.9.1 recall — 3.0/standard+low-impact/multix3: 21/24 vs 21/24; scan-process peak RSS 324 vs 247 MiB; 228.3 vs 211.9 s
- PASS Within limits — 3.0/deep+normal/multix3: analysis processes parser 2×256 MiB, at most 512 MiB of heap limits at once of 512 MiB for 2 parser workers; out of memory 0; their RSS ≤119 MiB outside the setting; browser websites 2 ≤ 2; websites in flight 1 ≤ 3 used (option 3); RSS 301 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 3.0/deep+normal/multix3: 24/24 in scope (24 planted); missing: none; memory gaps none
- PASS Keeps the 2.9.1 recall — 3.0/deep+normal/multix3: 24/24 vs 24/24; scan-process peak RSS 301 vs 270 MiB; 222.3 vs 166.2 s
- PASS Within limits — 3.0/deep+low-impact/multix3: analysis processes parser 2×256 MiB, at most 512 MiB of heap limits at once of 512 MiB for 2 parser workers; out of memory 0; their RSS ≤122 MiB outside the setting; browser websites 1 ≤ 1; websites in flight 1 ≤ 2 used (option 2); RSS 245 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 3.0/deep+low-impact/multix3: 24/24 in scope (24 planted); missing: none; memory gaps none
- PASS Keeps the 2.9.1 recall — 3.0/deep+low-impact/multix3: 24/24 vs 24/24; scan-process peak RSS 245 vs 245 MiB; 298.6 vs 260.4 s
- PASS Within limits — 3.0/quick+normal/multix10: analysis processes parser 1×256 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤56 MiB outside the setting; browser websites 0 ≤ 0; websites in flight 1 ≤ 6 used (option 6); RSS 326 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 3.0/quick+normal/multix10: 60/60 in scope (80 planted); missing: s1.example.com:depth3, s1.example.com:depth5, s2.example.com:depth3, s2.example.com:depth5, s3.example.com:depth3, s3.example.com:depth5, s4.example.com:depth3, s4.example.com:depth5, s5.example.com:depth3, s5.example.com:depth5, s6.example.com:depth3, s6.example.com:depth5, s7.example.com:depth3, s7.example.com:depth5, s8.example.com:depth3, s8.example.com:depth5, s9.example.com:depth3, s9.example.com:depth5, s10.example.com:depth3, s10.example.com:depth5; memory gaps none
- PASS Keeps the 2.9.1 recall — 3.0/quick+normal/multix10: 60/80 vs 60/80; scan-process peak RSS 326 vs 325 MiB; 51.1 vs 96.0 s
- PASS Within limits — 3.0/quick+low-impact/multix10: analysis processes parser 1×256 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤55 MiB outside the setting; browser websites 0 ≤ 0; websites in flight 1 ≤ 2 used (option 2); RSS 240 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 3.0/quick+low-impact/multix10: 60/60 in scope (80 planted); missing: s1.example.com:depth3, s1.example.com:depth5, s2.example.com:depth3, s2.example.com:depth5, s3.example.com:depth3, s3.example.com:depth5, s4.example.com:depth3, s4.example.com:depth5, s5.example.com:depth3, s5.example.com:depth5, s6.example.com:depth3, s6.example.com:depth5, s7.example.com:depth3, s7.example.com:depth5, s8.example.com:depth3, s8.example.com:depth5, s9.example.com:depth3, s9.example.com:depth5, s10.example.com:depth3, s10.example.com:depth5; memory gaps none
- PASS Keeps the 2.9.1 recall — 3.0/quick+low-impact/multix10: 60/80 vs 60/80; scan-process peak RSS 240 vs 234 MiB; 299.8 vs 278.3 s
- PASS Within limits — 3.0/standard+normal/multix10: analysis processes parser 2×128 MiB, at most 256 MiB of heap limits at once of 256 MiB for 2 parser workers; out of memory 0; their RSS ≤126 MiB outside the setting; browser websites 2 ≤ 2; websites in flight 1 ≤ 4 used (option 4); RSS 328 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 3.0/standard+normal/multix10: 70/70 in scope (80 planted); missing: s1.example.com:depth5, s2.example.com:depth5, s3.example.com:depth5, s4.example.com:depth5, s5.example.com:depth5, s6.example.com:depth5, s7.example.com:depth5, s8.example.com:depth5, s9.example.com:depth5, s10.example.com:depth5; memory gaps none
- PASS Keeps the 2.9.1 recall — 3.0/standard+normal/multix10: 70/80 vs 70/80; scan-process peak RSS 328 vs 354 MiB; 252.1 vs 201.3 s
- PASS Within limits — 3.0/standard+low-impact/multix10: analysis processes parser 2×128 MiB, at most 256 MiB of heap limits at once of 256 MiB for 2 parser workers; out of memory 0; their RSS ≤123 MiB outside the setting; browser websites 1 ≤ 1; websites in flight 1 ≤ 2 used (option 2); RSS 305 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 3.0/standard+low-impact/multix10: 70/70 in scope (80 planted); missing: s1.example.com:depth5, s2.example.com:depth5, s3.example.com:depth5, s4.example.com:depth5, s5.example.com:depth5, s6.example.com:depth5, s7.example.com:depth5, s8.example.com:depth5, s9.example.com:depth5, s10.example.com:depth5; memory gaps none
- PASS Keeps the 2.9.1 recall — 3.0/standard+low-impact/multix10: 70/80 vs 70/80; scan-process peak RSS 305 vs 271 MiB; 568.8 vs 445.1 s
- PASS Within limits — 3.0/deep+normal/multix10: analysis processes parser 2×256 MiB, at most 512 MiB of heap limits at once of 512 MiB for 2 parser workers; out of memory 0; their RSS ≤122 MiB outside the setting; browser websites 2 ≤ 2; websites in flight 1 ≤ 3 used (option 3); RSS 340 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 3.0/deep+normal/multix10: 80/80 in scope (80 planted); missing: none; memory gaps none
- PASS Keeps the 2.9.1 recall — 3.0/deep+normal/multix10: 80/80 vs 80/80; scan-process peak RSS 340 vs 317 MiB; 329.7 vs 271.0 s
- PASS Within limits — 3.0/deep+low-impact/multix10: analysis processes parser 2×256 MiB, at most 512 MiB of heap limits at once of 512 MiB for 2 parser workers; out of memory 0; their RSS ≤122 MiB outside the setting; browser websites 1 ≤ 1; websites in flight 1 ≤ 2 used (option 2); RSS 261 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 3.0/deep+low-impact/multix10: 80/80 in scope (80 planted); missing: none; memory gaps none
- PASS Keeps the 2.9.1 recall — 3.0/deep+low-impact/multix10: 80/80 vs 80/80; scan-process peak RSS 261 vs 265 MiB; 843.7 vs 664.4 s
- PASS Within limits — 3.0-small/quick+normal/bundlex1: analysis processes parser 2×256, detector 1×108 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤243 MiB outside the setting; browser websites 0 ≤ 0; websites in flight 1 ≤ 1 used (option 6); RSS 309 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 3.0-small/quick+normal/bundlex1: 7/7 in scope (7 planted); missing: none; memory gaps none
- PASS Within limits — 3.0-small/quick+low-impact/bundlex1: analysis processes parser 2×256, detector 1×108 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤244 MiB outside the setting; browser websites 0 ≤ 0; websites in flight 1 ≤ 1 used (option 2); RSS 310 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 3.0-small/quick+low-impact/bundlex1: 7/7 in scope (7 planted); missing: none; memory gaps none
- PASS Within limits — 3.0-small/standard+normal/bundlex1: analysis processes parser 3×256, detector 2×108 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤243 MiB outside the setting; browser websites 1 ≤ 2; websites in flight 1 ≤ 1 used (option 4); RSS 319 MiB; egress violations 0
- FAIL Finds its keys at its memory setting — 3.0-small/standard+normal/bundlex1: 6/7 in scope (7 planted); missing: bundle.example.com:bundle; memory gaps none
- PASS Within limits — 3.0-small/standard+low-impact/bundlex1: analysis processes parser 2×256, detector 2×108 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤358 MiB outside the setting; browser websites 1 ≤ 1; websites in flight 1 ≤ 1 used (option 2); RSS 326 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 3.0-small/standard+low-impact/bundlex1: 7/7 in scope (7 planted); missing: none; memory gaps none
- PASS Within limits — 3.0-small/deep+normal/bundlex1: analysis processes parser 4×256, detector 2×108 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤246 MiB outside the setting; browser websites 1 ≤ 2; websites in flight 1 ≤ 1 used (option 3); RSS 334 MiB; egress violations 0
- FAIL Finds its keys at its memory setting — 3.0-small/deep+normal/bundlex1: 6/7 in scope (7 planted); missing: bundle.example.com:bundle; memory gaps none
- PASS Within limits — 3.0-small/deep+low-impact/bundlex1: analysis processes parser 2×256, detector 1×108 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤251 MiB outside the setting; browser websites 1 ≤ 1; websites in flight 1 ≤ 1 used (option 2); RSS 368 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 3.0-small/deep+low-impact/bundlex1: 7/7 in scope (7 planted); missing: none; memory gaps none
- PASS Within limits — 3.0-small/quick+normal/multix10: analysis processes parser 1×256 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤56 MiB outside the setting; browser websites 0 ≤ 0; websites in flight 1 ≤ 6 used (option 6); RSS 322 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 3.0-small/quick+normal/multix10: 60/60 in scope (80 planted); missing: s1.example.com:depth3, s1.example.com:depth5, s2.example.com:depth3, s2.example.com:depth5, s3.example.com:depth3, s3.example.com:depth5, s4.example.com:depth3, s4.example.com:depth5, s5.example.com:depth3, s5.example.com:depth5, s6.example.com:depth3, s6.example.com:depth5, s7.example.com:depth3, s7.example.com:depth5, s8.example.com:depth3, s8.example.com:depth5, s9.example.com:depth3, s9.example.com:depth5, s10.example.com:depth3, s10.example.com:depth5; memory gaps none
- PASS Within limits — 3.0-small/standard+normal/multix10: analysis processes parser 1×256 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤68 MiB outside the setting; browser websites 1 ≤ 2; websites in flight 1 ≤ 4 used (option 4); RSS 310 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 3.0-small/standard+normal/multix10: 70/70 in scope (80 planted); missing: s1.example.com:depth5, s2.example.com:depth5, s3.example.com:depth5, s4.example.com:depth5, s5.example.com:depth5, s6.example.com:depth5, s7.example.com:depth5, s8.example.com:depth5, s9.example.com:depth5, s10.example.com:depth5; memory gaps none
- PASS Within limits — 3.0-small/deep+normal/multix10: analysis processes parser 1×256 MiB, at most 256 MiB of heap limits at once of 256 MiB for 1 parser worker; out of memory 0; their RSS ≤68 MiB outside the setting; browser websites 1 ≤ 2; websites in flight 1 ≤ 3 used (option 3); RSS 306 MiB; egress violations 0
- PASS Finds its keys at its memory setting — 3.0-small/deep+normal/multix10: 80/80 in scope (80 planted); missing: none; memory gaps none
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
- PASS Settings as recorded — 3.0/quick+normal/singlex1: same as the resources phase
- PASS Settings as recorded — 3.0/quick+low-impact/singlex1: same as the resources phase
- PASS Settings as recorded — 3.0/standard+normal/singlex1: same as the resources phase
- PASS Settings as recorded — 3.0/standard+low-impact/singlex1: same as the resources phase
- PASS Settings as recorded — 3.0/deep+normal/singlex1: same as the resources phase
- PASS Settings as recorded — 3.0/deep+low-impact/singlex1: same as the resources phase
- PASS Settings as recorded — 3.0/quick+normal/bundlex1: same as the resources phase
- PASS Settings as recorded — 3.0/quick+low-impact/bundlex1: same as the resources phase
- PASS Settings as recorded — 3.0/standard+normal/bundlex1: same as the resources phase
- PASS Settings as recorded — 3.0/standard+low-impact/bundlex1: same as the resources phase
- PASS Settings as recorded — 3.0/deep+normal/bundlex1: same as the resources phase
- PASS Settings as recorded — 3.0/deep+low-impact/bundlex1: same as the resources phase
- PASS Settings as recorded — 3.0/quick+normal/multix3: same as the resources phase
- PASS Settings as recorded — 3.0/quick+low-impact/multix3: same as the resources phase
- PASS Settings as recorded — 3.0/standard+normal/multix3: same as the resources phase
- PASS Settings as recorded — 3.0/standard+low-impact/multix3: same as the resources phase
- PASS Settings as recorded — 3.0/deep+normal/multix3: same as the resources phase
- PASS Settings as recorded — 3.0/deep+low-impact/multix3: same as the resources phase
- PASS Settings as recorded — 3.0/quick+normal/multix10: same as the resources phase
- PASS Settings as recorded — 3.0/quick+low-impact/multix10: same as the resources phase
- PASS Settings as recorded — 3.0/standard+normal/multix10: same as the resources phase
- PASS Settings as recorded — 3.0/standard+low-impact/multix10: same as the resources phase
- PASS Settings as recorded — 3.0/deep+normal/multix10: same as the resources phase
- PASS Settings as recorded — 3.0/deep+low-impact/multix10: same as the resources phase
- PASS Settings as recorded — 3.0-small/quick+normal/bundlex1: same as the resources phase
- PASS Settings as recorded — 3.0-small/quick+low-impact/bundlex1: same as the resources phase
- PASS Settings as recorded — 3.0-small/standard+normal/bundlex1: same as the resources phase
- PASS Settings as recorded — 3.0-small/standard+low-impact/bundlex1: same as the resources phase
- PASS Settings as recorded — 3.0-small/deep+normal/bundlex1: same as the resources phase
- PASS Settings as recorded — 3.0-small/deep+low-impact/bundlex1: same as the resources phase
- PASS Settings as recorded — 3.0-small/quick+normal/multix10: same as the resources phase
- PASS Settings as recorded — 3.0-small/standard+normal/multix10: same as the resources phase
- PASS Settings as recorded — 3.0-small/deep+normal/multix10: same as the resources phase
