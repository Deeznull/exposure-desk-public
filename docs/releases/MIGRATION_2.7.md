# Migrating to 2.7.0

2.7.0 reads data written by 2.6 in place. Every 2.6 command-line flag, JSON configuration file, checkpoint and saved record keeps working, and new fields are additive. The new command-line options (target lists, JSON Lines, finding IDs) are opt-in. A few command-line behaviours changed, website addresses are checked more strictly, and script analysis runs in separate processes; all three are described below.

## Before you switch

1. Stop every running Exposure Desk instance (Settings → Stop Exposure Desk, or close the launch window).
2. Back up the whole data directory shown in Settings (`%LOCALAPPDATA%\Exposure Desk` by default) while the app is stopped. Keep `keys`, `scans`, `vault` and `workspace.json` together. Exposure Desk does not make this backup for you.
3. Extract the 2.7.0 Windows x64 ZIP into its own folder and start it with **Start Exposure Desk.cmd**. It reuses the same data directory.

## What keeps working

- Every 2.6 flag, with the same meaning: `--url`, `--config`, `--preset`, `--coverage`, `--traffic`, `--scope`, `--browser`, `--deep`, `--sizing`, `--format`, `--output`, `--full-secrets`, `--checkpoint`, `--resume`, `--company-rules` and `--fail-on`, and the `dashboard`, `launch`, `trigger`, `artifacts`, `cleanup` and `doctor` commands.
- Object, array and `{projects:[...]}` configuration files, ready options, legacy presets and custom settings run as they did in 2.6. Nothing is re-mapped.
- `--url` and a `--config` file with several websites do not need `--authorized`. It is needed only when more than one `--targets` entry is accepted.
- `node dist/src/cli.js` stays the command-line entry point. Exit codes keep their meaning: 0 completed with no unsuppressed private credential, 1 completed with a policy finding, 2 failed, cancelled, incomplete or refused.
- When one command scans several websites, report files still get `-1`, `-2` … added to their names.
- Saved projects, routines, queue jobs, deployment triggers, history, checkpoints and the vault are read unchanged. The one exception is a website address whose host no website can have (see [Website addresses](#website-addresses)): it still loads, but it is refused when a scan starts.

## New command-line options

- `scan --targets FILE` (or `--targets -` for standard input) scans a list of targets, one per line: host names, URLs or httpx-style lines. Targets run one after another in one process, each with its own report. `--targets` cannot be combined with `--url` or `--resume`; with `--targets`, `--config FILE` is used as a settings template whose `urls` are replaced by each target.
- Every line is checked against the protected-host rule before any request, with no override. Rejected lines (protected, invalid or duplicate) are listed on standard error with their reason, and the other lines continue. No accepted line exits 2.
- `--authorized` states that you own or are authorized to test every listed target. Without it, more than one accepted target exits 2 before any request.
- `--jsonl` writes one JSON object per event to standard output and moves the readable lines to standard error. The events are described in [docs/JSONL.md](../JSONL.md).
- `--silent` prints no plan or progress lines, only results.
- `--program DIR` keeps a finding-ID key in `DIR/.key`, so a finding keeps the same ID across runs that use the same folder.

The [command-line reference in the README](../REFERENCE.md#target-lists-json-lines-and-finding-ids-270) has an example.

## Behaviour changes you may notice

- **Help.** `--help` or `-h` anywhere on the command line prints the help text and runs nothing. In 2.6, `cli.js --help` on its own failed with "Scanner failed", `-h` was not recognized, and `artifacts`, `launch`, `trigger` and `doctor` ignored `--help` and ran the command.
- **Checked before any request.** An unknown `--format` or `--fail-on` value now stops the command with exit 2 before anything is requested. In 2.6 an unknown `--format` stopped it after the scan, without a report, and an unknown `--fail-on` after the report was written. The message is the same generic one as before.
- **Finding lines.** The terminal prints one masked `Finding <id> · …` line per finding (priority, severity, category, provider and rule, masked value, first location). Scripts that read the terminal output of 2.6 will see these extra lines; use the report file or `--jsonl` for machine-readable results.
- **Finding IDs in reports.** Command-line reports now include each finding's ID: in JSON as `findings[].correlation` and `findings[].findingId` (the same value), in SARIF as the `exposureDesk/correlation/v2` partial fingerprint and `properties.findingId`, and in HTML as a "Finding ID" line. Without `--program` the IDs are new for each run; if a SARIF consumer matches results between runs by partial fingerprint, use `--program`. Dashboard scans of saved projects already had `correlation`; their findings now also carry it as `findingId`.
- **Masked plan lines.** The Run and Scope lines printed before a scan now pass through the same masking as the rest of the terminal output, so a key placed in a scan name or a seed URL is no longer printed in full.
- **Ctrl+C.** Ctrl+C (or a termination signal) stops the running website and starts no further one, and the command exits 2. In 2.6, a `--config` file with several websites continued with the next website after Ctrl+C.
- **Closed reader.** With `--jsonl`, if the program reading standard output closes it (for example `| head -1`), the run stops as with Ctrl+C, prints one line on standard error (not with `--silent`) instead of a raw error, and exits 2 if a target was cancelled or not started.

## Website addresses

2.7.0 checks the host of every website address. A valid host is made of labels of 1 to 63 letters, digits, hyphens and underscores (international names are converted automatically), with at most one trailing dot, or it is an IP address such as `127.0.0.1` or `[::1]`; `localhost` is also accepted. 2.6 accepted some addresses that no website can have, such as `shop{old}.example.com` or `a,b.example.net`; their scans then failed when the name was looked up.

- **New input is checked strictly.** `--url`, every website in a `--config` file, a `--targets` settings template, a `--resume` checkpoint, `dashboard --config`, `trigger` (a saved project or an `--assets` list), and dashboard saves, previews, scan starts, resumes, queue entries, routines and deployment triggers refuse such an address before any request. The checked fields are the website addresses, related, private and development-fixture origins, read-only POST endpoints, browser navigation URLs and stale-asset URLs.
  - The command line exits 2 and prints one line: `Refused: "<host>" is not a valid website host. A host uses letters, digits, hyphens and underscores (international names are converted automatically) or is an IP address. Nothing was requested.` `trigger` prints it after `Trigger not written:`.
  - The dashboard shows the same message (error code `invalid-url`).
  - `--targets` lines are rejected with the reason `invalid-url`, as in 2.6, and the other lines continue.
- **Saved records load leniently.** Projects, routines, queue entries, deployment triggers, history and checkpoints saved by earlier versions load unchanged and are never rewritten.
  - A saved project whose address has such a host shows "Cannot scan: … is not a valid website host (saved by an earlier version)". In the project list its name ends with "(cannot scan: invalid host)", and it stays selectable so you can edit it. At startup the dashboard adds one note with the number of such projects.
  - Until you correct the address and save it, its scans, queue entries, routines and deployment triggers are refused. A routine that comes due is skipped and left as saved. Saving the same address again is refused.
  - After the corrected save, an overdue routine waits for its next time instead of running at once.
- **Refused at scan start.** Every scan start checks its addresses again, before any request: a manual start, the queue, a routine, a deployment trigger, and a retry, rescan or resume of a saved run.
  - A retry or resume of a saved run or checkpoint is refused as a whole if any of its saved addresses has such a host, including its browser navigation and stale-asset URLs. Start a new scan with corrected addresses instead.
- **Unchanged.** The protected-host rule is checked first and keeps its own message. Addresses found during a scan (links, redirects, source maps) are handled as in 2.6.

## Analysis processes and memory

- **Separate processes.** The parser and the engine's checks of texts over 128 KiB now run in their own child processes. Each is started with the same Node runtime as Exposure Desk; in the Windows package that is the bundled `runtime\node.exe`. While a scan analyses scripts, Task Manager shows these extra `node.exe` processes. They end when the scan ends, when it is cancelled, or when Exposure Desk stops.
- **Memory setting.** The analysis memory setting (at most 512 MiB) now holds the heap limits of the parser and the large-text checks together. In 2.6 the large-text checks could use up to 192 MiB on top of it. Saved settings keep their values, and there is nothing to change.
- **Outside the setting.** Each analysis process also has its own runtime memory, which is not part of the setting: about 40 MiB for a parser process and 56 MiB for a large-text process, measured while idle. The scan process, the isolated browser and the engine process are not part of it either. Expect total memory use while scripts are analysed to be higher than the setting by that much per running analysis process.
- **Heap limit.** An analysis process that reaches its heap limit ends alone. The scan continues and states the limit; in 2.6 this could sometimes end the whole scan.
- **Window checks only.** A text over 128 KiB that is checked in the scan process itself (browser snapshots, supplied bodies) gets window checks only, never a whole-document parse.

## Data written by 2.7.0

- The workspace stays `exposure-workspace/3`, history `exposure-history/2`, checkpoints `exposure-checkpoint/1` and reports `exposure-scan/1`. `findingId` is an additive field.
- With `--targets` and several targets, `--checkpoint FILE` writes one checkpoint per target, with `-1`, `-2` … added to the name.
- `--program DIR` creates `DIR/.key` (32 random bytes, restricted to your user account) on first use. Anyone with that file can link finding IDs to values they already know, so keep it private. Without `--program` nothing is written for finding IDs.
- Going back was not tested; restore the backup instead.
