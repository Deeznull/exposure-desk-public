# Actual verification — 2.3.1-rc.1

Build 2.3.1-rc.1+1b19d40f69120ab9. Source digest 1b19d40f69120ab990e89655815cd8f2a16c2dbd31046b4f4b63c84239a9bdf0. Windows x64, bundled Node 24.18.1, Gitleaks 8.30.1, Playwright 1.63.0 / Chromium 153.0.8010.12, Acorn 8.19.0, RE2-WASM 1.0.2 and TypeScript 7.0.2. Dependencies remain locked; provider format rules remain website/2.3.0.

The real repair baseline was the newer completed 2.3.0-rc.1+5fd9435d84e583c6. Source, compiled files and freshly launched health matched before production edits. Prior archives and protected operator data were preserved. Original 2.2 claims were verified during the completed second-stage upgrade: 172 nonbrowser / 3 browser tests, 102 selected targets and 17 pipeline fixtures. These counts describe selected tests, not universal detection. Baseline receipts and prior results are in benchmarks/repair-baseline and benchmarks/stage2-baseline.

| Actual final check | Result |
| --- | --- |
| Nonbrowser regressions | 211 passed, zero failed/skipped; 227.560 s |
| Actual browser / UI regressions | 7 passed, zero failed/skipped; 204.463 s |
| Pinned-engine selected benchmark | 102/102 targets; 98 private, 3 public identifiers, 1 suspicious; 7 negative controls; zero private false positives, component or location errors |
| Independent retained held-out corpus | 19 fixtures: 16/16 credential targets; 0 misses; 3 controls, 0 private false positives |
| Full acquisition pipeline | 17/17; 48.215 s |
| Actual CLI child processes | 4 passed; clean/private/incomplete/full-value export exits; 28.038 s |
| Native Windows protected persistence | Save/restart/vault/correlation/ownership checks passed; 12.706 s |
| Source / compiled / fresh launched build | Verified as 2.3.1-rc.1+1b19d40f69120ab9 |
| Final extracted ZIP / CMD launcher | Separate actual integrity, launcher, restart, CLI, pipeline and browser results in artifacts/packaged-extraction-2.3.1.json and release-2.3.1-results.json |

Final source runs and durations: benchmarks/repair-verification.json and repair-*.log. The unchanged selected provider fixture hash, category counts, misses and historical/current benchmark timing are compared separately in benchmarks/repair-selected-comparison.json. Prior exploratory failures remain outside the final pass counts. The final browser workload has a 65 s scan deadline because real native-engine work is measured; network attempts retain a 1 s timeout. The matched scheduling benchmark uses the same 12 s scan deadline and unavailable offline engine on both versions to isolate scheduling. Those timing results are not interchangeable.

| Same generated local workload | Preserved 2.3.0 | Repair |
| --- | --- | --- |
| Stalled listings / application scripts | 0/18 scripts inspected, 0 runtime pages | 18/18 scripts inspected, 1 runtime page |
| Starvation fixture elapsed | 12.592 s | 7.752 s |
| Failed attempts / timeout notes | 22 / 44 | 4 / 4 |
| Repeated query warnings | 457 | 0; 460 renditions summarized as 115 distinct source families |
| Small reconstructed config after vendor pressure | false | true; unfinished vendor analysis stays explicitly incomplete |
| Node/worker high-water RSS, matched workload | 156952 KiB | 305344 KiB |

The higher Node peak (94.5%) is a measured memory regression from processing more scripts/semantic work. RSS includes workers but excludes Chromium/Gitleaks child processes; aggregate child memory was not measured. Do not infer whole-system memory from this number. The independent native-engine/browser fixture also records its elapsed time, first static/browser document times, request counts, reuse and capture counts in repair-browser.log and repair-browser-workload.json.

Matched fixture seed: ExposureDesk/scan-repair/20261006/921. Three route workloads contain 261 stalled listings, 18 scripts, 460 renditions of 115 source images and eight map candidates; a separate pressure workload has three semantic documents. Browser-only material is constructed from character codes and absent as a complete credential from ordinary downloaded source; browser-disabled ablation proves the intended path. Map-only material is absent from its bundle. The native test uses actual pinned Gitleaks. Timeout outcome/phase tests deliberately create 18 attempts and assert exactly 18 failed outcomes and 18 cause notes. No remote response bodies were available, so these are workload shapes rather than full site replays.

| Repair capability | Executable proof |
| --- | --- |
| Fair/early scheduling and failure containment | Static scripts and browser dispatch precede optional listings; failed page attempts consume page cap; weighted class order, shared FIFO/concurrency and deadline assertions |
| Timings and bounded retry | DNS/headers timeout phases, cancellation, zero/one retry bounds, delta and HTTP-date Retry-After beyond deadline without early transmission |
| Honest counters | Sitemap separate; eight map bodies inspected, one valid map, five 404s and seven invalid/uninspected map candidates; HTTP errors distinct from network failures |
| Image grouping | 460 URLs / 115 families; distinct sources preserved; SVG/config/unknown/signed query controls and URL credential evidence |
| Exact endpoint evidence | Actual S3 image URL, excerpt and Unicode offset; public object role and owner action; missing metadata positions omit SARIF regions; legacy empty evidence is not assigned fake coordinates |
| Semantic/debugger efficiency | Large vendor budget cannot suppress supported small reconstruction; unfinished mutation aliases remain unknown; identical source occurrence replay; captured source/hash/analyzer state; proven helper exclusion |
| Offline reuse | Concurrent actual native inspection shares work; shared failures mark every waiter incomplete and never become cached success |
| Browser delivery and recovery | Guarded network/completeness/decode checks before delivery; offline analysis drained separately; runtime snapshot has immediate direct findings; cancellation releases isolated traffic and shuts down proxy/profile |
| Focused retry and scope | Authenticated POST plan/execute, exact approved URLs, successful static exclusions, no implicit new origin or capability redemption; focused coverage remains incomplete |
| Actual dashboard | Visible failure/timeout counts, grouped limitations, reviewable retry preview, endpoint copy/evidence, deliberate secret reveal/remask, redacted JSON/HTML/SARIF and no page errors |

Retained independent held-out seed: ExposureDesk/stage2/heldout/20261006/73; digest 41b7636e922326aa05c70731a8cd1c408e6a4e44472d0af278503baca370dec8. Per-provider and acquisition outcomes and missed case IDs are in benchmarks/repair-retained-heldout.json. The historical 2.2→2.3 comparison increased credential recall from 9/16 to 16/16, with zero private false positives on three controls; this repair retains 16/16. New matched HTTP/browser/semantic gains are separately measured, and map detection remains present. Information observations are excluded from credential recall. Existing literal/decoded engine-only, chunk-boundary/4 MiB tail, public-key/clean decoys, generated-script ablations, map ablations, stale exact URL, scope escape, forbidden arrival, report injection, redaction, 304-without-body, dependency failure and self-test checks remain. Self-test assertions stay separate from intentionally incomplete fixture coverage.

Windows x64 is the execution-verified host. Linux/ARM, source bootstrap without installed dependencies, default OS browser opening and broader enterprise Windows policies remain untested. Separate-process debugger frame/worker targets, import-map scope/prefix mappings, arbitrary runtime obfuscation, JSX/TypeScript semantic parsing, full object traversal and credential validation are unsupported. Download/decode/parser/transform/time limits and unsupported channels remain independent gaps. Full captured secret-bearing code stays memory-only; deliberate full-value reveal/copy/local exports and protected vault remain available. No real target or third-party service was contacted by acceptance scans; no capability link redeemed. A match proves neither credential validity, privilege, balance, monetary value nor revocation.

## Same registrable domain discovery and finding triage — 2026-10-07

Final active build: 2.3.1-rc.1+ce20a8f049185883. Added locked tldts 7.4.16 with private PSL suffix rules. Source and compiled output have been rebuilt.

- Nonbrowser suite during implementation: 241 passed, zero failed/skipped (verification-same-domain-suite.log).
- Supplemental scope/coverage/retry regressions: 51 passed, zero failed/skipped (verification-same-domain-targeted.log).
- Final feature checks under bundled Node 24.18.1: 17 passed, zero failed/skipped (verification-same-domain-final.log). Covers domain traps, multi-label suffixes, IDN, tenant boundaries, duplicate/concurrent admission, ports/schemes, 50-origin cap and deferred examples, recursive/source-map/RSC/runtime discovery, provenance, network protections, stronger finding evidence and worker fallback.
- Focused actual Chromium checks: 3 passed, zero failed/skipped (verification-same-domain-browser-final.log): automatic scope with private DNS/credential/redirect traps, finding review UI, and isolation of one origin deadline.
- The preceding combined Chromium run passed the Exhaustive GUI control, full pipeline diagnostics, outbound isolation, runtime/worker collection, browser fairness, cancellation and debugger ablation checks. One deadline test timed out and an old UI assertion expected a now-deleted insignificant image reference. The UI assertion was updated to exercise a retained sensitive endpoint; both checks passed in the focused rerun. A clean single combined browser run is not claimed.

Sandbox loopback connections produced EACCES; actual network/browser fixture checks were run with local loopback and IPC access. No target security guards were disabled. Tests use synthetic local fixtures or a mocked public resolver, never live credential validation. Previously exported history is preserved; concurrent triage applies to new scans. Existing release archives were not repackaged.
