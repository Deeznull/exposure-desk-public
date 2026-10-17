# Changelog — 2.7.0

2.7.0 follows 2.6.0 (build `2.6.0+8b02299c3915954b`). It adds opt-in command-line options for target lists, JSON Lines output and stable finding IDs, moves large-text analysis into separate processes, and checks the host of every new website address. Upgrade notes: [MIGRATION_2.7.md](MIGRATION_2.7.md). JSON Lines format: [docs/JSONL.md](docs/JSONL.md). Measurements: [TEST_RESULTS.md](TEST_RESULTS.md). Earlier changes: [CHANGELOG_2.6.md](CHANGELOG_2.6.md). Like every earlier release, 2.7.0 was measured only with local loopback fixtures and synthetic, nonfunctional keys on one Windows x64 computer; no real website was scanned.

Rule version `website/2.7.0` (2.6.0 used `website/2.6.1`); the detection rules and patterns are unchanged, and only where large texts are analysed changed (see Reliability). The priority version stays `priority/1`. The ready options and their limits, Low-impact traffic, the protected-host rule and the dashboard security model are unchanged. Every 2.6 command-line flag, configuration file and saved record keeps working; saved records of earlier versions load unchanged and are never rewritten.

## Scan page and dashboard

- Scan page: each scope choice drew its radio button stretched across a full line above its text, so it was unclear which choice was selected. Each choice is now a card with the radio beside its title, and the selected choice is highlighted like the ready options (`public/index.html`, `public/style.css`, `test/browser.test.ts`).
- Starting or queueing a scan that saves full evidence while the vault is locked or not yet created was refused with the generic "Request rejected" text. It now says to unlock or create the vault in Settings, or to untick saving full evidence (409 `vault-locked`; `src/desk.ts`, `test/profile-ui.test.ts`).
- Static requests carry the product token `Mozilla/5.0 (compatible; ExposureDesk/2.7)` (taken from the build version, as before); the scan page's network note shows the same text.

## Command line

Every 2.6 flag, configuration and saved record keeps working. Details in [docs/JSONL.md](docs/JSONL.md).

- The CLI is split into `src/cli/**` (one module per command, flag and output-format registries); `dist/src/cli.js` stays the entry point.
- `scan --targets FILE|-` reads hosts, URLs and httpx lines (plain or `-json`) from a file or standard input; comments, blank lines and a BOM are skipped, targets are normalized and deduplicated, and each rejected line is listed with its reason; the protected-host rule runs on every line before any request (no override).
- `--authorized` is required when more than one target is accepted; a single target, `--url` and multi-URL configurations work as in 2.6.
- `--jsonl` streams the events `run-start`, `target-start`, `finding`, `target-end` and `summary` (schema `exposure-jsonl/1`, always masked) on standard output; `--silent` keeps only results.
- `--program DIR` keeps a key in `DIR/.key` (owner-only file) so `findingId` stays the same across targets and runs; `findingId` appears in the JSON, SARIF (`properties.findingId`) and HTML reports, JSON Lines, the terminal `Finding` lines and the dashboard API.
- `--help`/`-h` print help (2.6 printed "Scanner failed"); `--format` and `--fail-on` values are checked before any request.
- A closed `--jsonl` reader (for example `| head -1`) stops the run like Ctrl+C (exit 2, no stack trace) instead of crashing with EPIPE.
- Fix: the terminal Scope line printed an entered seed URL unmasked (a key in a target URL's query reached the terminal); the Run and Scope lines are now masked like every other output.
- Tests: `test/cli-targets.test.ts`, `test/jsonl.test.ts` (nonbrowser suite).

## Website addresses

- Changed: a website address in new input must use a valid host (letters, digits, hyphens, underscores; international names are converted; or an IP address). `--url`, `--config`, `--targets` templates, `--resume`, `trigger` and dashboard saves, previews and scan starts refuse anything else before any request (CLI exit 2, one line starting `Refused:`; dashboard error `invalid-url`).
- Changed: saved projects from earlier versions with such a host still load unchanged and show a warning. Their scans, queue entries, routines and deployment triggers are refused until the address is corrected and saved. A retry or resume of a saved run or checkpoint whose saved addresses hold such a host is refused at scan start, before any request.
- Tests: `test/host-validation.test.ts` (nonbrowser suite) and `test/host-validation-browser.test.ts` (browser suite).

## Reliability

- The detector's engine lanes and large-text lanes are a first-come, first-served queue (`src/fifo-budget.ts`) instead of polling; this removes the cause of the timing-dependent `repair-browser` failure seen in the 2.6.0 verification (12 of 12 repeated runs passed; `test/engine-lanes.test.ts`).
- The parser and the engine's large-text checks run in their own processes (`src/analysis-process.ts`). One that reaches its heap limit now ends alone, and the scan continues and states the limit; before, it could sometimes end the whole scan.
- The large-text checks count against the analysis memory setting together with the parser, so the heap limits held at once never exceed the setting (before: setting + 192 MiB); the large-text heap is sized to the text; a whole-document parse that cannot fit is skipped with a stated limit (`test/analysis-memory.test.ts`).
- A text over 128 KiB checked in the scan process itself (browser snapshots, supplied bodies) gets window checks only, never an unbounded whole-document parse.
- Fix: a detector shared by two scans charges each scan's own analysis-memory budget.
- Memory: scan-process peak 248-318 MiB, down from 385-431 MiB, on the local 1.25 MB bundle fixture. Each analysis process adds about 40-56 MiB of its own runtime outside the setting. Durations, recall (7/7) and precision (7/7) are unchanged.

## Development and release tooling

These change how measurements are made, not the scan options or their results.

- `scripts/profile-matrix.mjs`:
  - repeats only cases that failed or were measured with a different build, measurement harness or Node version
  - can run cases in parallel (`--jobs N|auto`, at most 4 for `auto`, guarded by free memory)
  - adds `status`, `--only` and `--rerun`
  - stops a hung case with everything it started (`--timeout-min`)
  - keeps replaced rows in `results-history.jsonl`
  - reports row freshness and whether each scan used the recorded settings
  - one case at a time stays the default and the source of release numbers; covered by `test/profile-matrix.test.ts` (nonbrowser suite)
  - 2.7.0: labels rows with the measured build's version, can run the six ready options on a previous release (`prev` phase, with `--baseline`), and reports the analysis processes' heap limits and peak memory separately from the scan process
- `scripts/packaged-smoke.mjs` checks that a packaged scan starts its analysis processes with the bundled runtime and leaves none running.
- `scripts/release-summary.mjs` takes the upgrade guide, matrix baseline text and result folders from the release being summarised instead of fixed 2.6 names, and reports the power source, CPU load and free memory sampled while each measurement ran (an optional `machine-state.json`) beside the timings.
- `scripts/package-portable.mjs` copies the bundled runtime, modules and browser as files even when the project folder links to them.
