# Mass scan (`scan --targets` at scale)

Added in 2.8.0. A **mass scan** runs a list of targets with a bounded number in flight at once, shares one analysis budget and one request limiter across the whole run, can resume an interrupted run from a state file, stops a target that is being blocked without ever evading, and collapses the same exposure found on several targets into one summary entry.

In the examples, `exposure-desk` stands for `node dist/src/cli.js` (in the Windows package, `runtime\node.exe dist\src\cli.js`); there is no separate `exposure-desk` command. Mass scan uses only the machine-readable [`--jsonl`](JSONL.md) stream and the readable terminal lines; it adds **no** network behaviour of its own beyond scheduling.

## When mass mode is on

Mass mode is on when more than one target runs at once, or when a state file is kept:

- `--concurrency N` with `N` above 1 and at least two accepted targets;
- `--state FILE` is given (even at concurrency 1);
- a program file (`program.json` in the `--program DIR` folder) and at least two accepted targets: the file's `concurrency.targets` (default **4**) becomes the concurrency unless you pass `--concurrency 1` or the file sets it to 1.

The concurrency never exceeds the number of accepted targets, so a single target is never a mass run unless `--state` is given. A `--program` folder that only holds the correlation key (no `program.json`) does not change the concurrency.

Outside mass mode a target list runs **strictly sequentially, as in 2.7**: one target after another, the 2.7 summary keys and none of the mass fields on any event. The 2.8 output fields that exist in every mode are additive: `target-end.recon`, `summary.recon`, `summary.rebuild` and `summary.submissionBundle` (`null` when unused), plus `summary.program` and `target-end.blocked` when they apply. Shared budgets, buffered output, resume, the program-wide halt and dedup apply to mass mode only. [Block detection](#block-detection-no-evasion) runs for every target of a list and for every run with a program file. The hard safety rules below apply to every run.

## Hard rules (unchanged, no override)

- **Authorization.** More than one accepted target, and every run with a program file, needs `--authorized` (or `"authorized": true` in the program). Without it the command exits 2 before any request. A single target, `--url` and a `--config` file with several websites need no `--authorized`, exactly as in 2.6.
- **Protected hosts.** A government, military, intelligence or law-enforcement host is refused on every target line and on every request, before scope rules and with no override. In a list it becomes a `protected-host` rejected line; the remaining targets still run.
- **No evasion.** Block handling only stops and backs off. The run never changes the User-Agent, headers, proxy or IP, and never retries around a block.
- **Found keys never leave.** Masked by default everywhere: `--full-secrets` unmasks values only in report files written to disk; the terminal, JSON Lines and recon lists always stay masked. Only loopback fixtures and synthetic keys are ever used in testing; no real website is contacted.

## Concurrency (`--concurrency N`)

How many targets run at once:

- **Without `--concurrency`:** 1 when there is no program file, or the file's `concurrency.targets` (default **4**) with one.
- **Never more than the accepted targets:** the value is lowered to the number of accepted targets.
- **With `--concurrency N`:** `N` targets at once. `N` must be a whole number of 1 or more.
- **Above 16** needs a program file (`--program DIR` with a `program.json`) whose rate and concurrency you accepted; without one, at most 16 run at once.
- **Above 64** is always refused (64 is the program maximum too).

A missing, non-numeric, zero or over-limit value **refuses the whole command**: exit 2, nothing on standard output, one line on standard error ending `Nothing was requested.`, and no request is ever made. The scheduler fills up to `N` lanes and never exceeds `N` targets in flight, however fast targets finish.

```
# 8 lanes under a program file you accepted
exposure-desk scan --targets hosts.txt --authorized --program ./example-program --concurrency 8 --jsonl --silent > run.jsonl
# up to 16 lanes without a program
exposure-desk scan --targets hosts.txt --authorized --concurrency 12
```

## One budget, one detector, one limiter

A mass run builds its shared resources once and gives every target the same ones, so cost does **not** grow with `N`:

- **One analysis-memory budget.** A single FIFO budget sized to the computer's analysis-memory cap — **≤512 MiB under the ready options**, and up to 2048 MiB only when a program sets `analysisMemoryMb` explicitly. It is shared by every concurrent target, never multiplied by the number of lanes.
- **One Detector.** The detector (and its rule set) is built once and shared, so rule memory is paid once. Its gitleaks engine is started only for a text that contains a keyword of at least one engine rule Exposure Desk keeps. That is the engine's own keyword prefilter, applied before the engine starts, so the findings are the same; a text that cannot match an engine rule no longer waits for an engine lane.
- **One finding-triage worker and one parser.** One background worker sorts the findings of every target (not one per target), and in mass mode one parser pool, sized by the shared analysis budget, serves every target. If that worker stops, every scan using it sorts its findings in the scan process instead and reports this (`finding-triage-worker`).
- **One request limiter.** Under a program file, a single rate-and-concurrency limiter bounds requests across **all** targets at once (the program's `rate.requestsPerSecond` and `concurrency.requests`), not per target. The run prints the shared limiter's totals at the end, and `summary.program` carries the limiter's figures (`requestsPerSecond`, `concurrency`, `active`, `peakActive`, `granted`, `waits`, `waitMs`, `maxWaitMs`). Since 2.9 the slots are shared in turn: the targets that wait for the limiter queue first in, first out, one place per target, and only the target whose turn it is is woken (by the limiter's one timer at the next rate slot, or by a finished request), so a target that just got a slot cannot take the next ones while other targets wait. Before 2.9 the target that had just got a slot usually got the next one too, and the other targets waited until its requests ran out. A program file adds `summary.program` outside mass mode too.

## Time waiting for shared capacity

In mass mode a target's time allowances count only the time it spends on its own work. While a website of the target only waits for capacity it shares with the other targets (the shared analysis-memory budget, the shared detector's engine lanes or the shared parser, also while a request is screened before it is sent, and under a program file a program-wide request slot that other targets hold), that website's time allowance is paused; while every open website of the target is paused this way, the whole-scan allowance is paused too. The analysis turn limit and the work turn limit (30 s for one piece of work, 120 s for one browser page) likewise count only the target's own time, so a turn is not cut while its website only waits. Time spent on requests and on the website's own politeness is charged as before: its own request pacing and concurrency, retry backoff and `Retry-After` pauses, and a program-limit wait right after the target's own grant (the program's pace applied to this target). A wait for an inspection another website of the same target already started is charged too. A target therefore no longer runs out of its allowance (`origin-deadline-reached`), defers its last work (`discovered-frontier-drained`) or has a turn cut (`work-turn-limit`) just because other targets were using the shared analysis or the program's request slots.

The paused time is reported, not hidden: each `target-end` carries `sharedWaitMs` (the time this target's allowance was paused) and the `summary` carries the sum. Since 2.9 both also carry `sharedWaitByCause` `{analysisMs, parserMs, preflightMs, programSlotMs}`, the same time split by what was waited for: the detector's lanes and analysis memory, a parser worker, the screening of a request before it is sent, or a program-wide request slot that other targets hold. The parts add up to `sharedWaitMs` exactly; overlapping waits share the time by their number. A large `programSlotMs` means the program's request rate or concurrency is what holds the targets back; a large `analysisMs` or `parserMs` means the shared analysis is. Outside mass mode (one target at a time, without `--state`) nothing changes: every wait is charged as in 2.7.

Since 2.9.1 the screening of a request before it is sent takes fair turns for the shared detector, as the program's request slots do since 2.9.0: each target has one place in a first-in, first-out queue however many of its requests wait to be screened, takes one turn and joins the back again, so a target with many requests ready can neither jump ahead of the targets already waiting nor starve them. The detector's two lanes still serve two screenings at once, so the throughput is the same; the time a target waits for its turn is part of `preflightMs`. One target at a time, nothing changes.

## Memory gate

Above concurrency 1, a mass run starts the next target only when the scan process's memory leaves room for it. The run samples the process's resident memory, keeps a per-target estimate (the memory above the start-up level spread over the most targets that ran at once in the last 30 seconds; it rises at once with a higher reading and falls slowly), and holds the next target back while the projected memory with one more target would exceed the ceiling minus a margin of one eighth of the ceiling (at least 32 MiB). The ceiling is **512 MiB** under the ready options; only a program's explicit `analysisMemoryMb` raises it, up to **2048 MiB**. At least one target always runs, so a list always progresses.

`--concurrency` (or the program's `concurrency.targets`) is therefore a maximum: the run lowers the targets running at once by itself when memory is short and goes back up when it frees. The `summary` reports what happened: `effectiveConcurrency` is the most targets that actually ran at once, and `memory` carries the gate's figures (`ceilingMb`, `marginMb`, `startRssMb`, `peakRssMb`, `perTargetMb`, `admissionWaits`). The gate decides when targets start; it never stops a running target. Since 2.9.1 a mass run at concurrency 1 (a `--targets` run with `--state`) samples memory the same way and its `summary` carries `memory` too, so its peak can be compared with the other rows; with one target at a time there is no further target to admit, so `admissionWaits` stays 0 and nothing is held back.

Large scripts get one more safeguard (2.9). Structured discovery parses each script in the scan process, and the syntax tree of a large bundle holds much more memory than its text for under a second (about 60 to 200 MiB for a 1.25 MB bundle), then is garbage. Several targets parsing large bundles in turn used to leave that garbage to be collected later, by which time the process had grown past the ceiling, and the gate cannot see a spike that short. In a mass run the scan process now counts the scripts of 64 KiB or more that it parsed and, once they add up to 512 KiB since the last collection, runs one full memory collection. Every script is still parsed in full, with the same budgets and the same findings. `memory` in the `summary` reports how often this happened (`parseCollections`) and the time it took (`parseCollectMs`).

## Measured on one computer (2.9.0)

`scripts/mass-scan-measure.mjs` on one Windows computer (16 logical cores), 200 synthetic targets on 50 loopback origins, Quick check + Normal traffic, `--state`, one measurement at a time, on build 2.9.0+b251a3ea63449d85. 2.8.0 figures in brackets.

| At once | Time | Requests per second | Scan process peak | Shared wait (sum over targets) |
|---|---|---|---|---|
| 1 | 2238 s (2272 s) | 2.0 (1.9) | 204 MiB (185 MiB) | 0 s |
| 4 | 592 s (618 s) | 7.4 (7.1) | 309 MiB (297 MiB) | 30 s, all preflight |
| 16 | 207 s (234 s) | 21.2 (18.8) | 329 MiB (363 MiB) | 222 s, 221 s of it preflight |
| 64 with a program file (50 requests per second) | 173 s (206 s) | 25.4 (21.4) | 357 MiB (319 MiB) | 7650 s, 7514 s of it program request slots |

Every run completed all 200 targets with 4400 requests, found every per-target and shared key (200 and 50), kept the one 256 MiB analysis budget, had 0 out-of-memory analysis processes and made 0 non-loopback connections. With the program file, the program's request limiter still sets the pace on this fixture: it granted the 4400 requests at about 25 per second against its nominal 50, 4298 of them after a wait, but since 2.9.0 in arrival order, so the longest single wait fell from 24 s in 2.8.0 to 3.1 s; the memory gate held a target start 32 times (2.8.0: 30). `summary.sharedWaitMs` is a sum over targets, not wall time, and `sharedWaitByCause` shows where it went: preflight screening at 4 and 16 at once, the program's request slots at 64. The resume and block-halt measurements were not repeated for 2.9.0 (the tests cover them); the 2.8.0 figures are in `benchmarks/2.8.0/mass-scan.json`. Figures: `benchmarks/2.9.0/mass-scan.json`.

Large bundles (same computer, build 2.9.0+b251a3ea63449d85): 16 targets, each serving its own 1.25 MB bundle (half of them parse, half fail both parses), Standard check + Normal traffic, `--state`. Before the parse collection (2.8.0 code), 4 at once peaked at 577 MiB and 16 at once at 557 MiB, over the 512 MiB ceiling of the ready options (1 at once: 378 MiB). On 2.9.0: 1 at once 240 s, 379 MiB; 4 at once 66 s, 382 MiB; 16 at once 28 s, 390 MiB, with 16 collections taking 180 and 182 ms in all. Every run found the same 48 findings (33 unique, every per-target and shared key), kept the one 256 MiB analysis budget and made 0 non-loopback connections; every target ends incomplete (stop reason `discovered-frontier-drained`) at every concurrency, as in development, so these runs exit 2. Run it with `node scripts/mass-scan-measure.mjs --only large-c1,large-c4,large-c16`.

## Terminal output

- **At concurrency 1**, readable lines stream live and in order, exactly as in 2.7, and the 5-second progress line is shown.
- **Above concurrency 1**, each target's readable `info`/result lines are **buffered and flushed as one block when that target ends**, so interleaving targets do not scramble the human output; the 5-second progress line is suppressed.
- **With `--jsonl`**, events are written live as they happen, so `target-start`, `finding` and `target-end` from different targets **interleave**. Every event carries a `target` number — key on it, never on adjacency. `run-start` is always first and `summary` always last.

## Resume (`--state FILE`)

`--state FILE` keeps a run-state file so an interrupted or re-invoked target list resumes without redoing finished work. It requires `--targets` (it has nothing to resume for `--url` or a single `--config`).

- **Schema `exposure-massrun/1`.** One JSON file recording, per target, its index, status, report path, finding count, exit code and stop reason.
- **Owner-only and atomic.** Written to a temporary file and renamed into place, mode `0600` (owner-only ACL on Windows); the temporary file is never left behind.
- **Skip done, re-run the rest.** On a second run the done targets are skipped (counted in `summary.skipped`), no `target-start` is emitted for them, and they make no request. Only the targets that did not finish run again.
- **Refuses a changed run.** If the target list or the run settings differ from the saved state, the resume is **refused**: exit 2 and one line on standard error containing `resume refused`, naming a `different target list` or `different run settings`, and ending `Nothing was requested.`. The state file is not rewritten. Because the check runs just after `run-start`, under `--jsonl` standard output carries only the `run-start` line and no request is made.
- **What counts as the run settings.** The ready-option and scan flags (`--coverage`, `--traffic`, `--scope`, `--preset`, `--sizing`, `--browser`, `--deep`), `--format`, `--fail-on`, `--full-secrets`, the program file's settings, `--company-rules`, the `--recon` folder and the contents of a `--config` settings template. `--concurrency`, `--output`, `--jsonl`, `--silent`, `--rebuild-sources` and `--submission-bundle` are not compared, so you can change the concurrency on a resume.

```
# First run; interrupt any time with Ctrl+C
exposure-desk scan --targets hosts.txt --authorized --state run.state --jsonl --silent > run.jsonl
# Re-run the same command: finished targets are skipped, the rest resume
exposure-desk scan --targets hosts.txt --authorized --state run.state --jsonl --silent >> run.jsonl
```

The state layer is proven at 1,000 targets; see `test/mass-resume.test.ts`.

## Recon, rebuild and submission output

`--recon DIR`, `--rebuild-sources DIR`, `--format md` and `--submission-bundle DIR` work the same in a mass run as in a sequential one (see [docs/RECON.md](RECON.md) and [docs/SUBMISSION.md](SUBMISSION.md)). Under concurrency:

- **Per target, when it ends.** Each target writes its recon lists to `DIR/<n>-<host>` and its report or Markdown draft as soon as it finishes; `target-end.recon` and `target-end.report` carry the paths. The recon collector is built per scan even though a mass run shares one detector, and its secret filter uses that scan's own analysis budget.
- **Once, after the last target.** The merged top-level recon set (beside the per-target folders), the rebuilt-sources manifest and the submission bundle are written after the last target, on completion, a block halt and Ctrl+C alike. The merged set and the bundle are in target-list order, whatever order the targets finished in. All targets feed one shared rebuilt-source tree; its writes are serialized, so concurrent targets never interleave a file.

On a `--state` resume:

- **The recon folder is part of the run settings.** A resume with a different `--recon DIR` (or with/without `--recon`) is refused like any other settings change. Each finished target's recon folder is recorded in the state file, and its `recon.json` is read back so the merged top-level set again covers every target, not just the ones this run scanned. A missing or unreadable `recon.json` is left out of the merge.
- **`--rebuild-sources` needs a new or empty folder on every run**, a resume included, and it covers only the targets this run scans (a finished target is not requested again, so its source maps are not re-read). It is not part of the run settings.
- **`--submission-bundle` is assembled at the end and is not part of the run settings.** With `--format json`, the targets an earlier run finished are added from their JSON reports, so the bundle covers the whole list. With another format there is no JSON report to read, so those targets are left out and one line on standard error says how many; run `exposure-desk report submit` on JSON reports to build a complete bundle. With `--full-secrets` the bundle's `.sensitive.md` files are never overwritten, so give a resumed run a new bundle folder.

## Block detection (no evasion)

A target that repeatedly refuses, rate-limits, serves a bot/CAPTCHA interstitial or resets the connection is recorded as **blocked**. The response is only to stop that target and move on. There is **no** User-Agent, header, proxy or IP change, and **no** retry around a block. Before any streak trips, the transport already honours `Retry-After` and backs off exponentially (capped) on its own.

Consecutive-signal thresholds (a normal response clears the streak; once blocked, a target stays blocked):

| Signal | Trips after |
|---|---|
| Bot/challenge interstitial (`cf-mitigated`, challenge platform, CAPTCHA, "verify you are human", "checking your browser") | **2** in a row |
| Plain HTTP 403 / 429 / 503 | **5** in a row |
| Connection reset / network failure (in scope) | **3** in a row |

A blocked target ends `status: "incomplete"`, `stopReason: "blocked"`, exit 2, and its `target-end` carries `blocked: {kind, reason, status?}` where `kind` is `challenge`, `status` or `reset`. This applies to every target of a list and to every run with a program file, in or out of mass mode; only the program-wide halt below needs mass mode. A single `--url` or `--config` scan without a program file keeps the 2.7 behaviour (no block detection).

**Program-wide halt.** When at least **3** targets have finished and at least **a quarter** of the finished targets were blocked, the run stops starting new targets; the targets already running finish normally. The `summary` then reports `halted: "blocked"`, the not-started targets are counted in `notStarted` (`scanned + notStarted + skipped === targets`, where `skipped` counts the finished targets a `--state` resume skipped), and the exit code is 2. This keeps a run from hammering an origin that is clearly refusing it.

## Cross-target de-duplication

The same exposure found on several targets is one line in the run summary, not many:

- Each `finding` event gains `firstSeen` (the lowest target number that id has been seen on) and, for a later target, `duplicateOf` (that earlier target).
- `summary.sharedFindings` lists each id seen on more than one target once, with its sorted `targets`; `summary.uniqueFindings` is the count of distinct ids.
- Per-target **report files keep their own findings in full** — dedup only collapses the run summary, never the reports.

Finding ids are stable so duplicates can be recognised: without `--program` the correlation key is random per run (ids match across the targets of one run, not between runs); with `--program DIR` the key is stored under the program directory, so the same exposure keeps its id across runs. See [Finding ids](JSONL.md#finding-ids).

## Ctrl+C and a closed reader

- **Ctrl+C / SIGTERM:** running targets are cancelled, no new target starts, `summary` reports `interrupted: true` with the not-started count, and the exit code is 2.
- **Closed reader** (for example `--jsonl | head -1`): the run stops the same way; later events, including `summary`, may not be written, so a reader should treat a missing `summary` as an unfinished run.

## Machine-readable fields

Every field mass mode adds is **additive** and the JSON Lines schema stays `exposure-jsonl/1`. The full list — the `finding` dedup fields, the `target-end` `sharedWaitMs`, `sharedWaitByCause` and `blocked` object and the `summary` extras (`concurrency`, `statuses`, `halted`, `uniqueFindings`, `sharedFindings`, `skipped`, `state`, `effectiveConcurrency`, `sharedWaitMs`, `sharedWaitByCause`, `memory`) — is in [docs/JSONL.md → Mass scan fields](JSONL.md#mass-scan-fields). The recon, rebuild and submission fields (`target-end.recon`, `summary.recon`, `rebuild`, `submissionBundle`) are the same in every mode.

## Examples

```
# Resumable, concurrent, program-governed sweep, machine output to a file
exposure-desk scan --targets hosts.txt --authorized --program ./example-program \
  --concurrency 8 --state run.state --jsonl --silent > run.jsonl

# Pipe from httpx, 12 lanes, no program (<=16 allowed), readable output
httpx -silent -l hosts.txt | exposure-desk scan --targets - --authorized --concurrency 12

# Resume after an interruption (same command re-run)
exposure-desk scan --targets hosts.txt --authorized --program ./example-program \
  --concurrency 8 --state run.state --jsonl --silent >> run.jsonl
```
