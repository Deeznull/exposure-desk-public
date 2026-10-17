# Actual verification — 2.4.0-rc.1

Build 2.4.0-rc.1+5d5acf0f7f18d7e6. Rebuilt with supplied Node 24.18.1, locked dependencies, Gitleaks 8.30.1 and Chromium 153.0.8010.12. Provider rules website/2.4.0; structural checks exposure/1.0. See [UPGRADE_2.4.md](UPGRADE_2.4.md) for controls and remaining limits.

| Final check | Actual result |
| --- | --- |
| Nonbrowser regressions | 263/263 passed; 172.458 s |
| Repeated Chromium cancellation stress | 20/20 passed; 48.325 s; same final debugger implementation |
| Browser and UI regressions | 14/14 passed; 188.331 s |
| Native selected provider regression corpus | 102/102; 7 negative controls; 0 private false positives; 0 component / 0 location errors |
| Full native acquisition pipeline | passed; 17 fixtures |
| Actual CLI child processes | 4/4 clean, policy, incomplete and full-export exit/masking checks |
| Native Windows protected persistence | Restart, correlation, vault, operator-only ACL and deletion checks passed |
| Extracted Windows ZIP / CMD launcher | All file hashes, path with spaces, port conflict, existing instance, authenticated demo, masking/reveal, cancel, shutdown and restart passed |

The original active build was 2.3.1-rc.1+6543b980ccdd8f3a; its source/compiled baseline ZIP was preserved before edits. Its original nonbrowser suite had 246/247 passes and one deadline-attribution failure, now fixed. Earlier exploratory failures are excluded from final pass counts.

| Same frozen local corpus | Baseline | Upgrade |
| --- | --- | --- |
| Credential targets detected | 10/13 | 13/13 |
| Credential false positives / classification errors | 0 / 0 | 0 / 0 |
| Data-exposure targets detected | 0/5 | 5/5 |
| Data-exposure false positives | 0 | 0 |
| Detector/semantic corpus elapsed | 1.123 s | 2.044 s |
| Detector/semantic Node/worker peak RSS | 198.1 MiB | 204.0 MiB |
| Dynamic credential targets detected | 2/5 | 5/5 |
| Known dynamic resources inspected | 8/9 | 9/9 |
| Dynamic fixture elapsed | 3.147 s | 4.158 s |
| Dynamic Node/worker peak RSS | 223.8 MiB | 217.4 MiB |
| Forbidden requests reaching fixture | 0 | 0 |

The 48-case detector corpus has 13 credential targets, five data targets and 30 negative controls. Credential precision is 13/(13+0) and recall is 13/13 on this corpus only. Baseline precision is 10/(10+0), recall 10/13. Four credential providers have one to seven targets each; detailed provider/framework/channel counts and missed case IDs are retained in benchmarks/upgrade-results.json. Website data checks have five examples. These counts do not establish general accuracy.

The separate matched dynamic application has five targets across shared constants, virtual TypeScript/JSX maps, generated worker/frame code and an approved fragment route. Baseline already captured the frame target; it missed the map, worker and approved route. Settings, bodies, seed, installed runtime and Chromium match. Both runs deliberately disable the native detector to isolate changed acquisition/static/browser channels; the selected-provider and pipeline regressions above exercise the real pinned native engine separately.

Evaluation seeds and corpus digests are frozen in the compact JSON. Evaluation templates remain together in the evaluation split; independent regression seeds exercise implementation boundaries. Only synthetic, nonfunctional values were used; no owner production bodies were supplied. Timings are single local runs without statistical controls. Node RSS includes workers but excludes Chromium/Gitleaks children; whole-system memory was not measured. Memory and timing changes are shown directly, with no speed or universal accuracy claim.

Worker/frame integration asserts no unauthorized, credential-bearing, private-address, destructive-method or unrelated redirect reaches the fixture, alongside existing browser boundary tests. Approved navigation turns precede incidental routes, queued lazy work keeps existing request/concurrency/retry controls, feedback survives restart and undo, and default JSON/HTML/SARIF remain masked. Parser/heap/time/download limits remain visible as gaps. Windows x64 is verified; other platforms and policies remain unverified. Previous release ZIPs, reports and application data are preserved. Temporary extracted verification copies and large new logs are removed only after this compact record is saved.
