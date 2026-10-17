# Changelog — 2.9.1

2.9.1 is a patch release that follows 2.9.0 (build `2.9.0+b251a3ea63449d85`). It follows webpack's cross-module constant exports in the semantic pass, gives the screening of requests in a mass run fair turns, makes `invalid-url` refusals informational, reports memory for mass runs at concurrency 1, and delivers the Linux package as an asset of a draft GitHub Release. Measurements: [TEST_RESULTS.md](TEST_RESULTS.md). Earlier changes: [CHANGELOG_2.9.md](CHANGELOG_2.9.md). Like every earlier release, 2.9.1 was measured only with local loopback fixtures and synthetic, nonfunctional keys. No real website and no real provider endpoint was contacted.

Rule version `website/2.9.1` (2.9.0 used `website/2.9.0`), because the semantic pass can now find a key whose parts are split across webpack modules, so a scan of the same bundle can report a finding 2.9.0 did not. No format rule was added, removed or changed. The priority version stays `priority/1`. Unchanged:

- the ready options and their limits, including the 512 MiB analysis memory ceiling
- Low-impact traffic
- the protected-host rule and the authorization rule
- the live key check (off unless a program file turns it on, one read-only request per key)
- masking
- the dashboard security model

No new option or file can loosen any of them. There is no MIGRATION_2.9.1.md because nothing needs migrating: 2.9.1 reuses the 2.9.0 data directory in place, and every 2.9.0 command-line flag, configuration file, program file, checkpoint and saved record keeps working (see [MIGRATION_2.9.md](MIGRATION_2.9.md) for coming from 2.8). The JSON Lines schema stays `exposure-jsonl/1` and only gains fields. Static requests still carry the product token `Mozilla/5.0 (compatible; ExposureDesk/2.9)`.

## Webpack cross-module constants (G5F)

- The semantic pass now reads webpack chunk pushes as module factories. Inside a factory it resolves the factory's own constants and the primitive exports of other factories in the same downloaded file: `exports.x =` written once at the top level, `require.d` getters (webpack 4 and 5), re-export getter chains, direct `require(id).x` reads, require aliases and string concatenation across them.
- Anything it cannot follow soundly stays unknown: factories that return at the top level, let `exports` or `module` escape, use a dynamic `require` or the module cache, duplicate or modified ids, cycles, values from another file, non-primitive values and reads before the value is assigned.
- Only values that crossed a module boundary are new findings, so a constant inside one factory is reported exactly as in 2.9.0.
- The work runs under the existing semantic operation ceiling and time slice. When either bound is reached the scan states the gap `semantic-webpack-budget` instead of silently stopping.
- The benchmark's G5F group (the frozen G5 bundle with its syntax error corrected) now finds its split key. The frozen 2.5 corpus and its digests are unchanged.

## Mass scan

- **Fair screening turns.** In a mass run, the screening of a request before it is sent now takes fair turns for the shared detector, the way program-wide request slots do since 2.9.0. Each target has one place in a first-in, first-out queue however many of its requests wait, so a target with many requests ready can neither jump ahead of the waiting targets nor starve them. The detector's two lanes still serve two screenings at once. The time spent waiting for a turn is part of `sharedWaitByCause.preflightMs`, and the four causes still add up to `sharedWaitMs` exactly. Scans of one target at a time are unchanged.
- **Memory at concurrency 1.** A mass run at concurrency 1 (`--targets` with `--state`) now samples memory and its `summary` carries `memory`, so its peak can be compared with the other rows. `admissionWaits` stays 0 there. A plain `--targets` run at concurrency 1 **without** `--state` is not a mass run and still has the 2.7 summary shape without `memory`; this is unchanged and stays open.

## Completeness

- **`invalid-url` is informational.** A discovered URL whose host is not a valid website host is still refused before any DNS lookup, still listed with the reason `invalid-url` and still sent as the same JSON Lines event, but it no longer makes a scan incomplete or lowers its coverage assessment. `target-end.gaps` lists it as `{code, count, informational: true}`; readers that ignore entries with `informational` get the 2.9.0 meaning. A page the scan was already fetching that redirects to such a host stays a gap, like a redirect out of scope. Runs saved by 2.9.0 keep the state they were saved with. See [docs/JSONL.md](docs/JSONL.md) and [USER_GUIDE.md](USER_GUIDE.md).

## Fixes

- **Opening a run keeps your page.** If you move to another dashboard page while a run is loading, the dashboard no longer switches to that run afterwards. This was also the cause of an intermittent failure of the dashboard completeness test.

## Linux package

- linux.yml no longer stores the Linux package as an Actions artifact by default (2.9.0's upload failed on the full artifact storage quota). A manual run with a release tag attaches the package and its `.sha256` to a **draft** GitHub Release of the private repository after `sha256sum --check` and the packaged smoke test pass. The workflow never publishes the release and never deletes releases, assets or artifacts. `scripts/linux-release-assets.mjs` checks a downloaded package against its `.sha256` and the version and gives both files back their package names. See [RELEASE_PACKAGE.md](RELEASE_PACKAGE.md) and [docs/LINUX.md](docs/LINUX.md).

## Development and tests

- Browser tests whose subject is not the browser's own exit tolerate an unconfirmed Chromium exit (`browser-process-exit`, `browser-cleanup`) on a local run and log it; they stay strict on CI and with `EXPOSURE_STRICT_BROWSER_EXIT=1`. The product's exit bounds and their gaps are unchanged.
- The mass-scale analysis-turn test releases its held lanes only after the analysis is seen waiting, and the dashboard test closes its browser outside the test's time limit.

## Release measurements

Measured on build `2.9.1+94a512df50bb9d43` on one Windows x64 computer with loopback fixtures only; details are in [TEST_RESULTS.md](TEST_RESULTS.md) and `benchmarks/2.9.1/`. Every timing and memory figure below is from Windows; the Linux x64 runs on GitHub-hosted Ubuntu runners give pass/fail results only.

- Ready-option matrix: 167/167 checks passed over 57 scans, and every source-build row keeps the 2.9.0 recall. The 2.9.0 side was not reused from records; it was measured for this release on the extracted 2.9.0 Windows x64 release ZIP, run with the same six ready options.
- External synthetic corpus (the external `detection-corpus/v2`: 20 sites, 27 private values, 402 negative controls; 12 runs, the six ready options in acquisition and discovery; not an acceptance target): precision 0.900 in every run; recall 1 in acquisition (27/27) and 0.889 in discovery (24/27); the same 3 negative-control alerts in every run and no other false positive.
- Target lists at scale: every Normal row completed 200/200 targets with every key found — 1 at once (the new concurrency-1 row) in 38.5 min at 189 MiB, 16 at once in 3.2 min, 64 at once with a program file in 2.9 min. The large-bundle rows found all 16 keys and ended incomplete (discovered-frontier-drained, as in development) at 343–402 MiB, 1 at once at 360 MiB. Each run drew on one shared 256 MiB analysis budget, never exceeded, and made 0 non-loopback connections.
- Regression suites: 777/777 non-browser and 46/46 browser and UI tests on Windows (final runs on a quiet machine; logs in `benchmarks/2.9.1/`); 60/60 cancellation stress; 167/167 provider-corpus targets with 0 false positives and 0 component / 0 location errors; the frozen 2.5 corpus runs without errors, results equal to 2.9.0 except the corrected G5F bundle, whose split key is now found with the detection engine off as well as on (0/1 → 1/1) and no new negatives, and the legacy 2.4 corpora 13/13 and 5/5 with 0 false positives, equal to 2.9.0. On GitHub-hosted Linux x64 runners, the manual `linux.yml` run with `release_tag=v2.9.1` (run 38885369937) passed 776/777 non-browser tests (one Windows-only test skipped) and 46/46 browser and UI tests, built and smoke-tested the container image, and built the Linux x64 package, checked it with `sha256sum --check` and the packaged smoke test (13/13) and attached it to the draft GitHub Release `v2.9.1`; the run and the package SHA-256 are in `benchmarks/2.9.1/linux-ci.json`.
