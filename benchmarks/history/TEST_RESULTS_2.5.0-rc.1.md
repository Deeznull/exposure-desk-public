# Actual verification — 2.5.0-rc.1

Build 2.5.0-rc.1+97836a16c30888f3. Windows x64 with the bundled Node 24.18.1, locked dependencies, Gitleaks 8.30.1 and Chrome for Testing 153.0.8010.12 / Playwright 1.63.0. Rules website/2.5.0; structural data checks exposure/1.0. Controls and limits: [UPGRADE_2.5.md](docs/history/UPGRADE_2.5.md); data upgrade: [MIGRATION_2.5.md](docs/history/MIGRATION_2.5.md).

| Final check | Actual result |
| --- | --- |
| Nonbrowser regressions | 333/333 passed, 0 failed or skipped; 180.0 s |
| Browser and UI regressions | 22/22 passed, 0 failed or skipped; 220.5 s |
| Repeated Chromium cancellation stress | 60/60 passed; 198.5 s |
| CLI child processes | 4 exit/masking checks passed |
| Protected persistence (temporary data directory) | projectRestart, correlationRestart, vaultRestart, operatorPermissions, deletion |
| Selected provider corpus (pinned engine) | 110/110 targets; 0 false positives; 0 component / 0 location errors |
| Full acquisition pipeline | passed; 17/17 fixtures |
| Release preflight | passed (2.4 archive hashes, baseline parity, pinned runtime/detector/browser, wordlist and corpus digests) |

## Before/after on the frozen 2.5 corpus

Corpus `scripts/eval-2.5-corpus.mjs`, digest `41f8c2dd214da8bd…`, frozen 2026-10-08T04:15:23.216Z. Frozen on 2026-10-08 after Chat 1 had implemented sections 1, 3, 4 and the attribution part of 5, and Chat 2 sections 2 and the rest of 5, but before any section 6 (findings, wallet and key detection, priority) change. Groups G1-G4, G6, G8 and G9 were therefore written with knowledge of the implemented behaviour; G5 and G7 detection fixtures precede the code they measure. Synthetic values only. Each group ran 3× per build in separate child processes with an egress tripwire, alternating builds; the first repetition's measurements are shown and the result is identical across repetitions unless noted in `benchmarks/2.5/evaluation.json`. Baseline: 2.4.0-rc.1+5d5acf0f7f18d7e6.

| Group · measurement | 2.4.0-rc.1 | 2.5.0-rc.1 |
| --- | --- | --- |
| G1 scope · in-domain origins reached, omitted setting | 0/5 | 5/5 (intended default change) |
| G1 scope · in-domain origins reached, explicit domain | 5/5 | 5/5 |
| G1 scope · exact-only opt-out reaches in-domain origins | 0 | 0 |
| G1 scope · third-party/deceptive origins contacted | 0 | 0 |
| G1 scope · private, metadata, mixed-DNS or credential URLs contacted (gate: 0) | 0 | 0 |
| G1 scope · guessed (unreferenced) DNS lookups | 0 | 0 |
| G1 scope · automatic origins with cap 3 | 3 | 3 |
| G1 scope · other github.io tenant contacted | 0 | 0 |
| G2 · requests for bare-extension hints (/.json, /.woff, …) | 4 | 0 |
| G2 · browser pages opened for those hints | 3 | 0 |
| G2 · contextual references fetched (config.json, chunk, worker) | 3/3 | 3/3 |
| G3 · browser navigations to asset hints answered by the SPA shell | 2 | 0 |
| G3 · explicitly requested route navigated | true | true |
| G4 · requests for 12 identical shells, mirrors and base variants | 22 | 22 |
| G4 · findings for the repeated value / occurrences | 1 / 5 | 1 / 5 |
| G5 1,252,570-byte bundle · split key found (engine off / on) | 0/1 / 0/1 | 0/1 / 0/1 |
| G5 · negatives reported (mutated alias, test key, publishable key) | 1 / 1 | 1 / 1 |
| G5 · late import / worker past the first MiB requested | false / false | true / true |
| G5 · non-terminal analyzer states after the run (bundle loaded twice + ?v mirror) | 0 | 0 |
| G6 shortDeadline · non-terminal states / pending inventory rows / state | 0 / 0 / incomplete | 0 / 0 / incomplete |
| G6 cancelAfterDownload · non-terminal states / pending inventory rows / state | 0 / 0 / cancelled | 0 / 0 / cancelled |
| G6 smallSlices · non-terminal states / pending inventory rows / state | 0 / 0 / incomplete | 0 / 0 / incomplete |
| G7 wallets, keys, signing and priority cases · website rules only | 8/23 detected · 0 false positives of 16 negatives · precision 1 · recall 0.348 | 23/23 detected · 0 false positives of 16 negatives · precision 1 · recall 1 |
| G7 · with the pinned engine | 9/23 detected · 0 false positives of 16 negatives · precision 1 · recall 0.391 | 23/23 detected · 0 false positives of 16 negatives · precision 1 · recall 1 |
| G7 · expected priority matched | n/a (no priority in this build) | 9/11 |
| G8 · static User-Agent | none sent | Mozilla/5.0 (compatible; ExposureDesk/2.5) |
| G8 · browser language / time zone reported by the page | en-GB / Europe/Amsterdam | en-US / UTC |
| G8 · headers repeating the page path or query | 3 | 0 |
| G9 · two identical starts 50 ms apart: HTTP statuses / runs created / same run returned | 202, 400 / 1 / false | 202, 202 / 1 / true |

Notes (added by hand after generation; raw values are in `benchmarks/2.5/evaluation.json`):
- **G5 does not measure split-key reconstruction.** The frozen G5 bundle has a JavaScript syntax error about 175 bytes before its end (in the lazy-chunk table), which was found only after the freeze. Both builds therefore report `semantic-parser-failure` and 0/1. The corpus was left unchanged to keep the freeze valid. Reconstruction from a valid bundle of the same size is covered by the regular regression test "a 1,252,570-byte synthetic bundle is discovered past the 1 MiB mark, reconstructed from constants near the end…" (lifecycle suite, passed in 1.6 s on 2.5.0-rc.1). G5 still shows the discovery change: 2.5 requests the late import and the worker past the first MiB, and 2.4 does not.
- **G5 negatives:** one of the G5 negative values is reported by both builds. The harness counts it but does not record which one.
- **G7 priority 9/11:** the two misses are the AWS documentation example and the BIP-39 "abandon … about" test vector. The corpus expected them at low priority; 2.5 instead moves published example values to the masked dismissed audit, so they have no priority to compare.
- **Memory:** peak Node RSS is higher on the large-bundle groups (G5 +67 MiB, G6 +150 MiB). The cause was not broken down further.

| Group · median wall time per child / peak Node RSS | 2.4.0-rc.1 | 2.5.0-rc.1 |
| --- | --- | --- |
| G1 | 830 ms / 194.3 MiB | 1194 ms / 200.9 MiB |
| G2 | 10188 ms / 191.8 MiB | 3490 ms / 189.9 MiB |
| G3 | 10851 ms / 190.7 MiB | 10008 ms / 190.4 MiB |
| G4 | 1862 ms / 183.7 MiB | 1946 ms / 190.2 MiB |
| G5 | 9610 ms / 436.9 MiB | 8375 ms / 503.8 MiB |
| G6 | 4667 ms / 437.0 MiB | 3094 ms / 586.5 MiB |
| G7 | 15487 ms / 170.4 MiB | 16159 ms / 181.5 MiB |
| G8 | 2503 ms / 182.0 MiB | 3942 ms / 188.8 MiB |
| G9 | 3902 ms / 171.9 MiB | 3947 ms / 184.5 MiB |

| Legacy 2.4 corpora (unchanged) | 2.4.0-rc.1 | 2.5.0-rc.1 |
| --- | --- | --- |
| 48-case detector corpus: credential targets detected / false positives | 13/13 / 0 | 13/13 / 0 |
| Data-exposure targets detected / false positives | 5/5 / 0 | 5/5 / 0 |
| Corpus elapsed / Node peak RSS | 1.371 s / 207.8 MiB | 1.402 s / 229.8 MiB |
| Dynamic application: credential targets / known resources inspected / forbidden arrivals | 5/5 / 9/9 / 0 | 5/5 / 9/9 / 0 |

Limitations: synthetic, nonfunctional values and local fixtures only (loopback servers and a virtual network); one Windows x64 host; single-digit repetitions without statistical controls; Node peak RSS includes workers but excludes Chromium and Gitleaks children. These counts describe this corpus only and make no general accuracy claim. Linux, macOS and ARM were not exercised. No owner website or production response was contacted or used.
