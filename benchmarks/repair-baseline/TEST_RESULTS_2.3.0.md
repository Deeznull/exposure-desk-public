# Actual verification — 2.3.0-rc.1, 2026-10-06

Build: 2.3.0-rc.1+5fd9435d84e583c6. Source digest: 5fd9435d84e583c60e6c96b8727db9dca5b70ecc2a7eb83eace453768b202052. Windows x64, bundled Node 24.18.1, Gitleaks 8.30.1, Playwright 1.63.0 / Chromium 153.0.8010.12, Acorn 8.19.0, RE2-WASM 1.0.2, TypeScript 7.0.2. Exact dependencies retained in the lockfile. Current final package suite records are benchmarks/stage2-verification.json. Prior 2.2 records and archives remain preserved in benchmarks/stage2-baseline and artifacts.

| Actual check | Result |
| --- | --- |
| Preserved baseline source / compiled / freshly launched health | 2.2.0-rc.1+8399b64166f5075d matched; no newer build or responding registered instance found |
| Baseline reruns | 172 nonbrowser and 3 actual browser/UI passed; 102 selected targets and 17 pipeline fixtures passed |
| Final Windows candidate nonbrowser | 192 passed, zero failed/skipped; 215.911 s |
| Final actual browser/UI | 4 passed, zero failed/skipped; 176.266 s |
| Pinned-engine selected benchmark | 102/102 targets; 98 private, 3 public identifiers, 1 suspicious; 7 negative controls, zero private false positives/component/location errors |
| Independent held-out corpus | 19 fixtures: 16 credential targets found, zero misses; 3 negative controls, zero private false positives |
| Full pipeline | 17/17 found; actual engine/browser, fresh storage, getter avoidance, scope and forbidden-arrival checks passed; 61.071 s |
| Actual CLI child processes | 4 passed: clean, private, incomplete and deliberate full-value local export exits; 21.395 s |
| Native Windows protected persistence | Save/restart/vault/correlation/ownership assertions passed; 13.633 s |
| Build identity | Source-input and compiled-file hashes plus fresh dashboard health verified as 2.3.0-rc.1+5fd9435d84e583c6 |
| ZIP extraction / launcher | See artifacts/release-2.3-results.json and packaged-extraction.json for the final archive integrity and extracted launcher results |

The same corrected held-out corpus digest 41b7636e922326aa05c70731a8cd1c408e6a4e44472d0af278503baca370dec8 ran against the preserved actual 2.2 package and this candidate. Credential detection increased from 9/16 to 16/16; false positives remained zero on 3 controls. Newly detected cases: alias-chain, template-array, late-decoding, sas-fragment, module-split, debugger-only, stale-exact-url. Existing large-tail, boundary, source-map, decoded-engine and blocked-request detections were retained, not counted as new gains. Per-provider and per-acquisition outcomes, misses and category-separated selected benchmark results are in benchmarks/stage2-comparison.json. Information observations are excluded from credential recall.

Held-out elapsed time: 35.356 s before, 45.154 s after (27.7% increase). Peak Node RSS: 176472 KiB before, 196780 KiB after; this includes worker threads but excludes Gitleaks and Chromium children. The original selected benchmark increased from 44.842 to 82.912 s. Additional reconstruction/debugger work costs time; these are measured fixture runs, not throughput guarantees. Large-resource tests inspect a 4 MiB tail and a boundary-spanning credential with Unicode byte offsets. Worker cancellation completes under its 2 s assertion and forced parser lifetime produces a distinct time-limit gap. Download truncation, parser failures, disabled channels, provenance limits, transformation/expansion limits, 304 without trusted body and engine failures stay visible independently of HTTP download success.

| Capability | Independent proof / expected limitation |
| --- | --- |
| Import maps, extensionless modules, manifests, module graph | Server module-split fixture and semantic-disabled ablation; unresolved bare imports remain unknown |
| Alias/template/array/property/destructuring/import/export/encodings | Held-out aliases/template plus separate namespace/default/re-export and decoding tests; unknown calls, mutations and shadowed builtins are negative controls |
| SDK/context and cross-resource credentials | Complete values reconstructed only through supported constants/imports; opaque contextual provider and actual engine-only split tests |
| Source maps | Secret only in map, never bundle; map-disabled ablation; mapped locations labelled approximate |
| Generated debugger code | Complete credential absent from every ordinary downloadable response; generated eval source only; debugger-disabled and browser-disabled ablations |
| Blocked outgoing requests | Browser-built URL contains complete key only in memory; request remains blocked; report says blocked candidate, with forbidden arrivals asserted |
| Late application JSON and stale assets | Actual isolated browser response and exact prior URL fixture; stale-disabled ablation; current scope controls rerun |
| Large / late decoded values | 4 MiB tail, overlapping boundary and 300 harmless strings before configuration; parser failures preserve raw detections |
| Capability/config exposure | Format-accurate standalone Azure SAS and Azure AccountKey pair plus existing signed URLs/webhooks/connections; no capability link followed |
| Precision / safe evidence | Public key, clean and unknown-expression negatives; report injection, redaction, reveal/full export, API-key scope and 304/truncation tests |
| Bounded tracing | More than 64 constituents or 32 transformation labels stays unknown with an explicit provenance-budget gap, never shortened silently |
| Local owner artifacts | Explicit separate CLI, no transport, local-only occurrences; reconstructed engine-only local module splits unsupported |

Held-out seed: ExposureDesk/stage2/heldout/20261006/73. Fixtures use deterministic, nonfunctional format-accurate values. Browser-only/source-map invariants and analyzer ablations prevent duplicate-source paths from creating false confidence. Self-test assertions are separate from the fixture scan's deliberate incomplete coverage. 41 advertised provider families map to executable selected fixtures and 45 attempted primary references; registry rows show exact lexical bounds, context/engine modes and unsupported cases. No match establishes validity, usable privilege, balance or monetary value.

Windows x64 is the verified host. Linux/ARM, source bootstrap without installed dependencies, default OS browser opening and broader enterprise Windows policies remain untested. Separate-process debugger frame/worker targets, import-map scopes/prefix mappings, arbitrary runtime functions/obfuscation, JSX/TypeScript semantic parsing, full browser-object traversal and online credential validation are unsupported. See MIGRATION_2.3.md for exact budgets and actionable gaps. No real target or third-party service was contacted by the acceptance fixtures. Raw secret-bearing captured source stays memory-only; protected full values still require deliberate owner actions.

Earlier exploratory runs are retained separately and are not counted as final passes. A final provenance-limit repair was followed by a complete rerun on this build. Synthetic acceptance is not an overall real-world accuracy percentage. A value no longer observed does not establish credential revocation.
