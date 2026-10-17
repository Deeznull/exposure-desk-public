# JSON Lines output (`scan --jsonl`)

Schema: **`exposure-jsonl/1`**. Added in 2.7.0.

`exposure-desk scan --jsonl` writes one JSON object per line to standard output. It is meant for scripts and pipelines, for example `jq`, a notify step or a results database. Every line is complete when it arrives: each event is written with a single write and ends with `\n`, so a reader can process lines as they come. In the examples, `exposure-desk` stands for `node dist/src/cli.js` (in the Windows package, `runtime\node.exe dist\src\cli.js`); there is no separate `exposure-desk` command.

```
exposure-desk scan --targets hosts.txt --authorized --program ./example-program --jsonl --silent > run.jsonl
httpx -silent -l hosts.txt | exposure-desk scan --targets - --authorized --jsonl
```

## Streams

| Stream | With `--jsonl` | Without `--jsonl` |
|---|---|---|
| standard output | events only, one per line | readable plan, progress and result lines |
| standard error | readable plan, progress and result lines; rejected target lines; refusals and errors | rejected target lines; refusals and errors |

`--silent` drops the plan and progress lines (Target, Run, Profile, Uses, Long scan, Scope, Scope counts, the 5-second progress line and the per-website detail). Results stay: the state line, one `Finding …` line per finding, and the coverage notes. With `--jsonl --silent`, standard error carries only rejected target lines, refusals and errors.

## Masking

JSON Lines and terminal output are **always masked**:

- A found value appears only as `masked`, for example `[redacted: 72 characters]`.
- URLs and names come from the redacted scan view. A key pasted into a target URL, such as `?api_key=…`, is masked in every event and line.
- A rejected target line is echoed without its user info, query and fragment, and is cut to 200 characters.

Values are masked by default everywhere. `--full-secrets` keeps its 2.x meaning: it unmasks values **only in report files written to disk** (sensitive local exports with restricted permissions, including a `--format md` draft and a `--submission-bundle`). It never changes the events, the terminal or the recon lists. Found keys never leave the computer automatically.

## Common fields

Every line has:

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | Always `exposure-jsonl/1`. A reader should refuse any other value it does not know. |
| `event` | string | `run-start`, `target-start`, `finding`, `target-end` or `summary`. |
| `at` | string | ISO 8601 time the line was written. |

Additive fields may appear in later versions of the same schema. A change that removes or redefines a field gets a new schema name.

## Event order

```
run-start
  target-start  finding*  target-end      (once per accepted target, in list order)
summary
```

Outside mass mode, targets run one after another in one process, and a `finding` always belongs to the `target-start` right before it.

**Mass scan** (`--concurrency N` above 1, any `--state` run, or a list of two or more targets under a program file; see [When mass mode is on](MASS_SCAN.md#when-mass-mode-is-on)) runs several targets at once, so their `target-start`, `finding` and `target-end` lines **interleave** on standard output. The per-target ordering still holds — a target's `finding` events come between its own `target-start` and `target-end` — but lines from different targets mix. Always key on the `target` number, never on adjacency. `run-start` is still first and `summary` still last. In mass mode the readable (non-`--jsonl`) output buffers each target's lines and prints them as one block when that target ends, and the 5-second progress line is suppressed. See [docs/MASS_SCAN.md](MASS_SCAN.md).

### `run-start`

| Field | Type | Meaning |
|---|---|---|
| `version` | string | Exposure Desk version, for example `2.8.0`. |
| `mode` | string | `targets` (`--targets`), `config` (`--config`), `url` (`--url`) or `resume` (`--resume`). |
| `targets` | number | Accepted targets (or configuration entries) that will run. |
| `rejected` | array | Rejected target lines: `{line, input, reason}`. Always empty outside `--targets`. |
| `authorized` | boolean | `--authorized` was given. |
| `program` | boolean | `--program DIR` was given (finding ids are stable across runs). |
| `format` | string | Report file format: `json`, `html`, `sarif` or `md` (a submission-Markdown draft, 2.8). |
| `failOn` | string | `private-credential`, `urgent` or `never`. |

### `target-start`

| Field | Type | Meaning |
|---|---|---|
| `target` | number | 1-based position among the accepted targets. |
| `url` | string | The first entered URL (masked). |
| `urls` | string[] | Every entered URL of this target (masked). |
| `runId` | string | Local run id of this target's scan. |
| `name` | string | Scan name. With `--targets` it is the target's host. |

### `finding`

| Field | Type | Meaning |
|---|---|---|
| `target` | number | The target it was found on. |
| `findingId` | string | Stable id, 64 hex characters (see [Finding ids](#finding-ids)). |
| `category` | string | `private-credential`, `public-identifier`, `suspicious` or `information`. |
| `severity` | string | `critical`, `high`, `medium`, `low` or `info`. |
| `confidence` | string | `high`, `medium` or `low`. |
| `priority` | string or null | Priority level, for example `urgent`. |
| `provider` | string | Provider name, for example `OpenAI`. |
| `rule` | string | Detection rule id. |
| `exposureKind` | string | Only on structural exposure findings (unintended fields in public content). |
| `masked` | string | The masked value, never the value itself. |
| `validity` | string | `unverified`. Exposure Desk never tests a found key against its provider. |
| `suppressed` | boolean | An unexpired suppression applies. |
| `occurrences` | number | Places the value was seen. |
| `locations` | array | Up to 20 of them: `{url, line?, column?}` (masked). |

### `target-end`

| Field | Type | Meaning |
|---|---|---|
| `target`, `url`, `runId` | | As in `target-start`. |
| `status` | string | `completed`, `incomplete` or `cancelled`. |
| `stopReason` | string | Why the scan stopped, for example `quick-target-set-done`, `discovered-frontier-drained`, `request-count-limit`, `origin-deadline-reached`, `cancelled`. |
| `assessment` | string or null | Coverage assessment, for example `configured-checks-completed`. |
| `completion` | string or null | Profile completion, for example `quick-coverage` or `profile-limited`. |
| `findings` | number | Findings on this target (the `finding` events before it). |
| `coverageNotes` | number | Coverage notes recorded in the report. |
| `gaps` | array | Incomplete coverage by code, most frequent first, at most 50: `{code, count}`. Since 2.9.1 it also lists informational refusals that do not make the target incomplete (today only `invalid-url`, a discovered URL whose host is not a valid website host) as `{code, count, informational: true}`. Empty when nothing was left incomplete and nothing informational was refused. Readers that only count entries without `informational` get the 2.9.0 meaning. |
| `exit` | number | This target's exit code (see [Exit codes](#exit-codes)). |
| `report` | string | Absolute path of the report file written for this target. The extension follows `--format` (`json`, `html`, `sarif`, or `md` for a submission-Markdown draft). |
| `recon` | string or null | Absolute path of this target's recon folder when `--recon DIR` was given (a `N-host` subfolder for a multi-target run), otherwise `null`. |

Each target still writes its report file, to `--output FILE` or by default `reports/scan-<runId>.<ext>`. With more than one target a `-N` suffix numbers the files, for example `run-1.json`, `run-2.json` for `--output run.json`.

`recon` is only ever a folder path; recon lists are never printed on standard output or embedded in the stream. The lists themselves are masked by construction — found secret values never appear in them.

### `summary`

| Field | Type | Meaning |
|---|---|---|
| `targets` | number | Accepted targets. |
| `scanned` | number | Targets whose scan ran to an end, including a cancelled one. |
| `notStarted` | number | Targets never started because of Ctrl+C or, in mass mode, a block halt. |
| `rejected` | number | Rejected target lines. |
| `findings` | number | Findings over all targets. |
| `states` | object | Count per status, for example `{"completed": 2}`. |
| `interrupted` | boolean | Ctrl+C or SIGTERM was received (a closed reader stops the run too, but then `summary` is not written). |
| `exit` | number | The process exit code. |
| `recon` | string or null | Absolute path of the top-level recon set when `--recon DIR` was given; for a multi-target run this is the merged set beside the per-target subfolders. `null` when `--recon` was not used. |
| `rebuild` | string or null | Absolute path of the rebuilt-sources folder when `--rebuild-sources DIR` was given (one shared source tree across all targets), otherwise `null`. The rebuilt tree is owner-only and is never printed; it legitimately contains public source, so it is written to disk only. |
| `submissionBundle` | string or null | Absolute path of the submission-Markdown bundle folder when `--submission-bundle DIR` was given, otherwise `null`. |
| `program` | object | Present only when a program file (`program.json` in the `--program` folder) applies, in every mode: the shared program limiter's figures `{requestsPerSecond, concurrency, active, peakActive, granted, waits, waitMs, maxWaitMs}`. `granted` counts requests let through, `waits` and `waitMs` how often and how long requests waited for the program limit, `peakActive` the most in flight at once. See [docs/PROGRAM.md](PROGRAM.md#program-wide-limits). |

`recon`, `rebuild`, `submissionBundle` and `program` are 2.8 additions to the same schema.

## Target lists (`--targets FILE|-`)

One target per line, read from a file or from standard input (`-`):

- a host name: `app.example.com` (scanned as `https://app.example.com/`)
- a URL: `http://app.example.com:8080/login`
- an httpx-style line: its first URL token is used, for example `https://app.example.com [200] [Title]`
- an `httpx -json` line: its `url` field (or `input`, or `host`)

Blank lines and lines starting with `#` are skipped. URLs are normalized, and a repeated target is rejected as a duplicate. A UTF-8 byte order mark is ignored. Lists are limited to 16 MiB and 100,000 targets.

Each rejected line is printed to standard error as `Rejected line N: input (reason)`, in every mode, including `--silent`. It is also listed in `run-start`. Rejected lines do not change the exit code, and the remaining targets still run.

| Reason | Meaning |
|---|---|
| `protected-host` | A government, military, intelligence or law-enforcement website. Checked on every line before anything else, with no override. |
| `invalid-url` | Not a host name, URL or httpx line. |
| `unsupported-scheme` | Not `http` or `https`. |
| `credentials-in-url` | The URL carries a user name or password. |
| `line-too-long` | Longer than 4096 characters. |
| `duplicate` | The same normalized target appeared earlier. |
| `target-limit` | Beyond 100,000 accepted targets. |
| `out-of-scope` | Outside the scope of the program file (`program.json` in the `--program` folder, 2.8). Checked after the protected-host rule; see [PROGRAM.md](PROGRAM.md#how-a-program-run-enforces-the-scope). |

**More than one accepted target needs `--authorized`.** It is your statement that you are authorized to test every listed target, for example because each one is in the scope of a program you accepted. Without it the command exits 2 before any request.

A single target, `--url`, and a `--config` file with several websites work as in 2.6 and need no `--authorized`.

With `--targets`, `--config FILE` is a settings template. Its own `urls` and `name` are replaced by each target. `--targets` cannot be combined with `--url` or `--resume`.

## Mass scan fields

A **mass scan** runs more than one target at once or keeps a run-state file. It is on when the concurrency is above 1 (`--concurrency N`, or a program file's `concurrency.targets`, with at least two accepted targets) or when `--state FILE` is given; [docs/MASS_SCAN.md → When mass mode is on](MASS_SCAN.md#when-mass-mode-is-on) has the exact rule. All of the fields below are **additive**: the schema stays `exposure-jsonl/1`, and a reader that ignores them sees the 2.7 fields unchanged. A target list outside mass mode runs sequentially and carries **none** of the mass-only fields. See [docs/MASS_SCAN.md](MASS_SCAN.md) for behaviour; this section only lists the extra JSONL fields.

**`finding`** gains, in mass mode only:

| Field | Type | Meaning |
|---|---|---|
| `firstSeen` | number | The lowest target number this `findingId` has been seen on so far in the run. On the first sighting it equals the finding's own `target`. |
| `duplicateOf` | number | Present only when an **earlier** target already reported this `findingId`: the target it was first seen on (`firstSeen`). Absent on the first sighting. |

Each target's report file still lists its own findings in full; dedup only collapses the run `summary`.

**`target-end`** gains, in mass mode only:

| Field | Type | Meaning |
|---|---|---|
| `sharedWaitMs` | number | Milliseconds this target's scan time allowance was paused because the target only waited for capacity it shares with the other targets (the shared analysis-memory budget, the shared detector's lanes, the shared parser, or a program-wide request slot that other targets hold), rounded. That time is not charged to the per-website or per-target allowance or to a work turn. Per-host politeness waits and a program-limit wait right after the target's own grant are charged as before. See [docs/MASS_SCAN.md → Time waiting for shared capacity](MASS_SCAN.md#time-waiting-for-shared-capacity). |
| `sharedWaitByCause` | object | 2.9. `sharedWaitMs` split by what the target waited for: `{analysisMs, parserMs, preflightMs, programSlotMs}`, whole milliseconds that always add up to `sharedWaitMs` exactly. `analysisMs`: the shared detector's engine or large-text lanes and the analysis memory they need. `parserMs`: a worker of the shared parser and the analysis memory its heap needs. `preflightMs`: the detector screening of a request before it is sent (its lanes and memory, and since 2.9.1 the target's fair turn for them). `programSlotMs`: a program-wide request slot that other targets hold. While several waits overlap, the paused time is shared between their causes by the number of waits (an analysis turn that waits counts as one, split by the causes of its own waits); the target's split is the average over its paused websites. Present exactly when `sharedWaitMs` is. |

**`target-end`** also gains, when the target was stopped by a block (any mode):

| Field | Type | Meaning |
|---|---|---|
| `blocked` | object | `{kind, reason, status?}`. `kind` is `challenge` (a bot/CAPTCHA interstitial), `status` (repeated 403/429/503) or `reset` (repeated connection resets). `reason` is a short human string; `status` is the HTTP status when there was one. A blocked target has `status: "incomplete"` and `stopReason: "blocked"`, and its `exit` is 2. |

**`summary`** gains, in mass mode only:

| Field | Type | Meaning |
|---|---|---|
| `concurrency` | number | Targets allowed to run at once (1 for a `--state` run with no `--concurrency`). |
| `statuses` | object | Count per end state across targets, for example `{"done": 7, "blocked": 1}`. `done` counts targets that finished a scan; `blocked` counts blocked ones. |
| `halted` | string or null | `"blocked"` when the program-wide block halt stopped starting new targets; otherwise `null`. |
| `uniqueFindings` | number | Distinct `findingId` values across every target. |
| `sharedFindings` | array | Each `findingId` seen on more than one target, once: `{findingId, firstSeen, targets[]}` with `targets` sorted ascending. Ordered by first sighting. |
| `skipped` | number | Targets skipped on a `--state` resume because they were already done. |
| `state` | string | Present only with `--state`: the absolute path of the run-state file. |
| `effectiveConcurrency` | number | The most targets that actually ran at once. It is at most `concurrency`, and lower when the memory gate held targets back (or when fewer targets remained). |
| `sharedWaitMs` | number | The sum of every scanned target's `target-end.sharedWaitMs`. |
| `sharedWaitByCause` | object | 2.9. The sum of every scanned target's `target-end.sharedWaitByCause`, per cause (`{analysisMs, parserMs, preflightMs, programSlotMs}`); the parts add up to `sharedWaitMs`. |
| `memory` | object | Present in every mass run (since 2.9.1 also at `concurrency` 1 with `--state`; before, only above 1): the memory gate's figures `{ceilingMb, marginMb, startRssMb, peakRssMb, perTargetMb, admissionWaits, parseCollections, parseCollectMs}`. `ceilingMb` is the process memory ceiling (512 MiB, or a program's explicit `analysisMemoryMb` up to 2048), `peakRssMb` the highest sampled resident memory of the scan process, `perTargetMb` the last per-target estimate and `admissionWaits` how many times the gate held the next target back. `parseCollections` (2.9) is how many full memory collections ran after large in-process script parses and `parseCollectMs` their total time. See [docs/MASS_SCAN.md → Memory gate](MASS_SCAN.md#memory-gate). |

When the run halts on blocks, the targets never started are counted in the existing `notStarted` field, and `scanned + notStarted + skipped === targets`.

**Recon, rebuild and submission output** (`target-end.recon`, `target-end.report` for `--format md`, and `summary.recon`, `rebuild`, `submissionBundle`) are the same fields in every mode, not mass-only. Under concurrency each target's recon folder and report (or Markdown draft) are written when that target ends; the merged top-level recon set, the rebuilt-sources manifest and the submission bundle are written once, after the last target, in target-list order whatever order the targets finished in. On a `--state` resume the targets the earlier run finished are not rescanned, so they emit no `target-end`; their recon lists still join the merged set and, for a `--format json` run, their findings still join the bundle. See [docs/MASS_SCAN.md → Recon, rebuild and submission output](MASS_SCAN.md#recon-rebuild-and-submission-output).

## Finding ids

`findingId` is a keyed HMAC-SHA-256 of the finding's identity: the found value, plus its kind for a structural exposure finding. The value itself cannot be recovered from it. The same value found on two targets gets the same id.

- **Without `--program`**, the key is random for each run: ids match across the targets of one run but not between runs.
- **With `--program DIR`**, the key is read from `DIR/.key`, which is created on first use: 32 random bytes, restricted to the current user (owner-only Windows ACL, or mode 0600 elsewhere). The same exposure then keeps its id across targets and across runs, so new findings can be told from known ones. A `.key` that is not a regular 32-byte file stops the run with exit 2 before any request. Keep the directory private: anyone with the key can test whether a guessed value matches an id.

`findingId` is also in the JSON report (`findings[].findingId`, equal to `correlation`). In SARIF it is the `exposureDesk/correlation/v2` partial fingerprint, and it appears on the terminal `Finding …` line.

## Exit codes

Unchanged from 2.6. The process exit code is the highest per-target exit code:

| Code | Meaning |
|---|---|
| `0` | Every target completed and none triggered `--fail-on`. |
| `1` | Every target completed and at least one triggered `--fail-on`. |
| `2` | A target ended `incomplete` (including a blocked target) or `cancelled`, a target was not started because of Ctrl+C, a closed reader or a block halt, the command was refused (missing `--authorized`, protected host, no accepted target, invalid flag, file or program file, a refused `--state` resume), or the scanner failed. |

`--fail-on` decides what gives exit 1:

- `private-credential` (default): an unsuppressed private-credential finding.
- `urgent`: an unsuppressed finding with urgent priority.
- `never`: never; the exit code only reports coverage.

## Refusals, failures and Ctrl+C

- **Refusals:** a refused command prints one line to standard error, writes **no events**, requests nothing and exits 2. Refusals include a missing `--authorized`, a protected host in a `--config` file, no accepted target, conflicting flags, an invalid value (such as a bad `--concurrency`), an unreadable list, an invalid program key or an invalid program file. One exception writes a single event: a `--state` resume whose target list or settings changed is refused just after `run-start`, so standard output then holds only the `run-start` line (see [docs/MASS_SCAN.md](MASS_SCAN.md#resume---state-file)).
- **Failures:** if a target's configuration cannot be used after the run started, the command prints an error and exits 2. The stream then ends **without a `summary`** line, so a reader should treat a missing `summary` as a failed run.
- **Ctrl+C or SIGTERM:** the running target is cancelled. Its `target-end` reports `status: "cancelled"`, and no further target starts. `summary` then reports `interrupted: true` and the number of targets not started, and the exit code is 2.
- **Reader closed:** when the program reading standard output goes away (for example `| head -1`), the run stops the same way as Ctrl+C. Later events, including `summary`, are not written; one readable line on standard error (not with `--silent`) says so, no raw error is printed, and the exit code is 2 if a target was cancelled or not started.

## Example

```json
{"schema":"exposure-jsonl/1","event":"run-start","at":"2026-10-10T09:00:00.000Z","version":"2.8.0","mode":"targets","targets":2,"rejected":[{"line":1,"input":"intranet.example.mil","reason":"protected-host"}],"authorized":true,"program":true,"format":"json","failOn":"private-credential"}
{"schema":"exposure-jsonl/1","event":"target-start","at":"2026-10-10T09:00:00.100Z","target":1,"url":"https://app.example.com/","urls":["https://app.example.com/"],"runId":"…","name":"app.example.com"}
{"schema":"exposure-jsonl/1","event":"finding","at":"2026-10-10T09:00:20.000Z","target":1,"findingId":"647ab138…","category":"private-credential","severity":"high","confidence":"high","priority":"urgent","provider":"OpenAI","rule":"openai","masked":"[redacted: 72 characters]","validity":"unverified","suppressed":false,"occurrences":2,"locations":[{"url":"https://app.example.com/app.js","line":1,"column":23}]}
{"schema":"exposure-jsonl/1","event":"target-end","at":"2026-10-10T09:00:21.000Z","target":1,"url":"https://app.example.com/","runId":"…","status":"completed","stopReason":"quick-target-set-done","assessment":"configured-checks-completed","completion":"quick-coverage","findings":1,"coverageNotes":1,"gaps":[],"exit":1,"report":"C:\\work\\run-1.json","recon":"C:\\work\\recon\\1-app.example.com"}
{"schema":"exposure-jsonl/1","event":"summary","at":"2026-10-10T09:01:00.000Z","targets":2,"scanned":2,"notStarted":0,"rejected":1,"findings":1,"states":{"completed":2},"interrupted":false,"exit":1,"recon":"C:\\work\\recon","rebuild":null,"submissionBundle":null}
```
