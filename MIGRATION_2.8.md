# Migrating to 2.8.0

2.8.0 reads data written by 2.7 in place, and nothing breaks. Every 2.7 command-line flag, JSON configuration file, checkpoint and saved record keeps working, and the JSON Lines schema stays `exposure-jsonl/1` with additive fields only. The bug bounty features (program files, concurrent and resumable target lists, recon lists, submission Markdown) are opt-in. A Linux x64 package and a container image join the Windows package. Four behaviours change without a new option: block detection on target lists, Chrome's own service connections, analysis time on slow computers and the code of a connect or TLS hang. All four are described below.

## Before you switch

1. Stop every running Exposure Desk instance (Settings → Stop Exposure Desk, or close the launch window).
2. Back up the whole data directory shown in Settings while the app is stopped: `%LOCALAPPDATA%\Exposure Desk` on Windows and `$XDG_DATA_HOME/exposure-desk` (`~/.local/share/exposure-desk`) on Linux by default. Keep `keys`, `scans`, `vault` and `workspace.json` together. Back up every `--program` folder too: its `.key` keeps finding IDs stable. Exposure Desk does not make this backup for you.
3. Extract the 2.8.0 package into its own folder and start it as before: **Start Exposure Desk.cmd** on Windows, `Start Exposure Desk.sh` on Linux ([docs/LINUX.md](docs/LINUX.md)). It reuses the same data directory.

## What keeps working

- Every 2.7 flag, with the same meaning: `--url`, `--config`, `--targets`, `--authorized`, `--jsonl`, `--silent`, `--program`, `--preset`, `--coverage`, `--traffic`, `--scope`, `--browser`, `--deep`, `--sizing`, `--format`, `--output`, `--full-secrets`, `--checkpoint`, `--resume`, `--company-rules` and `--fail-on`, and the `dashboard`, `launch`, `trigger`, `artifacts`, `cleanup` and `doctor` commands.
- A target list still runs one target after another in one process, with one report per target, unless you add `--concurrency N`, `--state FILE` or a program file.
- `--program DIR` on a folder **without** `program.json` keeps its 2.7 meaning: it only holds the finding-ID key in `DIR/.key`. Finding IDs are computed as in 2.7, so the same key and value keep the same ID.
- Authorization works as in 2.7 for runs without a program file: `--authorized` is needed when more than one target is accepted, and `--url` and `--config` do not need it.
- JSON Lines: every 2.7 event and field keeps its meaning and order. A reader that ignores unknown fields needs no change.
- Exit codes keep their meaning: 0 completed with no unsuppressed private credential, 1 completed with a policy finding, 2 failed, cancelled, incomplete or refused.
- Ready options and their ceilings are unchanged, including the 512 MiB analysis memory limit. Only a program file's `analysisMemoryMb` can go above it, up to 2048 MiB.
- The protected-host rule and local-only data are unchanged, and no new option or file can loosen them or the authorization rule; a program file only makes authorization stricter. Masking is unchanged too. Masked by default everywhere: `--full-secrets` unmasks values only in report files written to disk; the terminal, JSON Lines and recon lists always stay masked.

## New command-line options

All of them are opt-in. `node dist/src/cli.js help` lists them, and the [README quick start](docs/REFERENCE.md#bug-bounty-quick-start) shows them together.

- `--concurrency N` runs up to N targets of a list at once. The default is 1, or, with a program file and two or more accepted targets, the file's `concurrency.targets` (default 4). Without a program file N can be at most 16; with one, at most 64. A value that is not a whole number, is below 1 or is over the limit exits 2 before any request. See [docs/MASS_SCAN.md](docs/MASS_SCAN.md).
- `--state FILE` keeps a run-state file so an interrupted target list resumes (see [Resume](#resume-and-the-run-state-file)). It needs `--targets`.
- `--recon DIR` writes masked recon lists; `--rebuild-sources DIR` rebuilds the website's public source from its published source maps into a new or empty, owner-only folder. See [docs/RECON.md](docs/RECON.md).
- `--format md` writes each target's report as masked submission Markdown, and `--submission-bundle DIR` writes one masked draft per finding plus an `index.md`. See [docs/SUBMISSION.md](docs/SUBMISSION.md).
- `report submit REPORT.json [REPORT2.json ...] [--out FILE | --bundle DIR] [--full-secrets]` renders submission Markdown offline from saved JSON reports. `--full-secrets` is refused without `--out` or `--bundle`.
- `program init DIR`, `program check DIR` and `program import --platform hackerone-csv|bounty-targets --file FILE [--handle NAME] DIR` write and check `DIR/program.json`, offline. See [docs/PROGRAM.md](docs/PROGRAM.md).

## Program files

A `program.json` in the `--program` folder (schema `exposure-program/1`) is new in 2.8. When it exists, `--program DIR` also applies the program's scope rules, its program-wide request rate and concurrency, and its `X-…` identification headers and User-Agent suffix, which are sent only to in-scope URLs.

- **Authorization on every run.** With a program file, every run needs `--authorized` or `"authorized": true` in the file, also for a single `--url`. Without either, the scan is refused with exit 2 before any request.
- **Out-of-scope lines.** A `--targets` line outside the program scope is rejected with the new reason `out-of-scope`, after the protected-host check, and the rest of the list runs.
- **Never wider.** The program scope only narrows the 2.7 scope rules. A link or redirect outside it is never requested and is listed in the report with reason `program-out-of-scope`.

## Behaviour changes you may notice

- **Block detection on target lists.** In 2.7 each target of a list ran until its own limits, however the website answered. Now every target of a `--targets` list, and every run with a program file, is watched for blocks. Two bot or challenge interstitials in a row, five HTTP 403, 429 or 503 responses in a row, or three connection resets in a row stop that target as **blocked**: `incomplete`, stop reason `blocked`, exit 2, and a `blocked` object on its `target-end` JSON Lines event. A target that 2.7 kept scanning while it was refused can therefore end earlier, with exit 2. Nothing is retried around a block. A single `--url` or `--config` scan without a program file keeps the 2.7 behaviour. See [docs/MASS_SCAN.md](docs/MASS_SCAN.md#block-detection-no-evasion).
- **Chrome's own service connections.** Chrome contacts four hosts by itself after launch: accounts.google.com, android.clients.google.com, update.googleapis.com and www.google.com. When no page, frame or worker requested that host, the connection is still denied at the proxy and listed in the report as a browser background connection, but it no longer makes the scan incomplete. A browser scan that 2.7 ended `incomplete` (exit 2) only because of these connections now ends `completed` and exits 0 or 1. A page's own request to one of these hosts, and any other unattributed browser traffic, is handled as in 2.7. The runtime self-check (`doctor --runtime`) follows the same rule.
- **Analysis time on slow computers.** Analysis time budgets now scale with the computer's measured speed (see [Analysis time factor](#analysis-time-factor)). On a fast computer nothing changes. On a slow one, a scan can spend more time analysing large scripts and finish analysis that 2.7 cut short. Memory budgets and the scan's duration limits are unchanged.
- **Connect and TLS hangs.** A request now has one timer that covers connecting, TLS, sending and the answer. A connection or TLS handshake that hangs ends as `request-timeout`, with the phase (`connect` or `tls`) in the request's timings; 2.7 could list such a request, or a request that was never answered, as `connection-timeout`. `connection-timeout` stays a known code for older reports. See [docs/LINUX.md](docs/LINUX.md#time-limits-and-the-end-of-a-run).
- **Help.** The `scan` usage line and the help text list the new options, and the target-list paragraph says that targets run one after another "by default".

## JSON Lines additions

The schema stays `exposure-jsonl/1`. Every addition is a new field or a new value; nothing is renamed or removed. The full reference is [docs/JSONL.md](docs/JSONL.md).

- **In every mode.** `target-end.recon` and `summary.recon`, `summary.rebuild` and `summary.submissionBundle` are always present, `null` when the option was not used. `run-start.format` can be `md`, and `target-end.report` then names a `.md` file.
- **With a program file.** `summary.program` carries the program limiter's figures: `{requestsPerSecond, concurrency, active, peakActive, granted, waits, waitMs, maxWaitMs}`. A rejected line can have the reason `out-of-scope`.
- **For a blocked target.** `target-end.blocked` is `{kind, reason, status?}`, where `kind` is `challenge`, `status` or `reset`.
- **In mass mode only** (concurrency above 1, or `--state`): `finding.firstSeen` and `finding.duplicateOf`, and on `summary` the fields `concurrency`, `statuses`, `halted`, `uniqueFindings`, `sharedFindings`, `skipped` and `state`, plus `effectiveConcurrency` and `sharedWaitMs` (and `memory` when concurrency is above 1); each `target-end` carries `sharedWaitMs`. `summary.notStarted` also counts targets not started after a block halt, and `scanned + notStarted + skipped` equals `targets`.

Outside mass mode a list writes the 2.7 events and summary keys plus the fields listed under "In every mode", and those under "With a program file" and "For a blocked target" when they apply.

## Resume and the run-state file

- `--state FILE` writes a run-state file (schema `exposure-massrun/1`) with each target's position, status, report path, finding count, exit code and stop reason. It is owner-only and written atomically.
- After an interruption, run the same command again. Targets that completed are skipped (counted in `summary.skipped`); every other target, including a blocked, incomplete or cancelled one, runs again. With `--jsonl`, append to the earlier output with `>>`.
- If the target list or the run settings changed, the resume is refused with exit 2, a line containing `resume refused`, and `Nothing was requested.` [docs/MASS_SCAN.md](docs/MASS_SCAN.md#resume---state-file) lists which settings are compared.
- `--state` is separate from the 2.7 per-scan `--checkpoint FILE` and `--resume FILE`, which keep working for single scans. `--targets` still cannot be combined with `--resume`.

## Analysis time factor

- Exposure Desk measures the computer once per process with a short, fixed parse workload in a background thread, combined with the CPUs the process may use. A fast computer gets factor 1; a slower one gets a factor from 1 to 4 in steps of 0.25.
- The factor scales the analysis time budgets only: the per-website analysis allocation, the parser's time slices and limits, the reconstructed-view inspection budget and the detector's isolated-inspection limits.
- `EXPOSURE_ANALYSIS_TIME_FACTOR` sets the factor yourself. Values from 1 to 8 are used; larger values become 8 and smaller ones 1. Anything that is not a positive number is ignored, and the scan notes it.
- Reports and the dashboard's analysis summary show it as `analysis.timeFactor`: `{factor, source, detail, speedRatio?, cpus?, sliceMs, groupTimeoutMs, viewInspectionMs}`, where `source` is `measured`, `override` or `default`.

Details: [docs/LINUX.md](docs/LINUX.md#analysis-time-on-slow-machines).

## Linux and the container image

- **Linux x64 package.** `Exposure Desk <version> Linux x64.tar.gz`, with a `.sha256` file to check it, carries its own Node.js runtime, so Node.js no longer has to be installed. A source copy still runs with Node.js 24–26 from `PATH`. The data folder is the same as in 2.7: `$XDG_DATA_HOME/exposure-desk`, or `EXPOSURE_DATA_DIR`, which must be an absolute path.
- **Chromium sandbox.** Chromium keeps its own sandbox on Linux. A host that blocks unprivileged user namespaces (Ubuntu 23.10 and later, through AppArmor) reports the browser launch as blocked; the fixes are the host administrator's decision.
- **Container image.** Built from a checkout of this repository with `docker build --tag exposure-desk .`. It runs as a non-root user with its data in the `/data` volume, works with `--read-only`, and sets `EXPOSURE_BROWSER_NO_SANDBOX=1` because Docker's default seccomp profile blocks Chromium's sandbox; the container is then the isolation boundary. That variable has no effect outside Linux. The dashboard listens only on `127.0.0.1`; use `--network host` on a Linux host.

All of it is described in [docs/LINUX.md](docs/LINUX.md).

## New in the dashboard

- **Copy submission Markdown.** Each finding on **Findings** has a **Copy submission Markdown** button that copies a masked draft. Without clipboard access, the draft appears in a read-only box to select and copy. The dashboard never writes unmasked submission files.
- **Recon lists.** Runs the dashboard stores keep their recon lists, and **Findings → Local exports → Recon lists** offers them as downloads. Runs saved by 2.7 have none, so the block stays hidden for them.

## Data written by 2.8.0

- The workspace stays `exposure-workspace/3`, history `exposure-history/2`, checkpoints `exposure-checkpoint/1` and reports `exposure-scan/1`. New fields are additive: reports carry `analysis.timeFactor`, and a checkpoint of a program run keeps the program settings so that resuming it still enforces them.
- The data directory gains a `recon` folder. Each run the dashboard stores gets `recon/<run id>/` (owner-only), deleted with the run.
- `--state FILE` writes an owner-only `exposure-massrun/1` file.
- `program init` and `program import` write `DIR/program.json` with owner-only permissions and never replace an existing file.
- `--recon DIR` and `--rebuild-sources DIR` folders are owner-only. Rebuilt sources are verbatim public code and may contain credentials; treat them like an unmasked report file. `--submission-bundle DIR` drafts are masked unless `--full-secrets` is given, which writes `.sensitive.md` files.
- Going back to 2.7 with data written by 2.8.0 was not tested; restore the backup instead.
