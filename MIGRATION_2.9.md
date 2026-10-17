# Migrating to 2.9.0

2.9.0 reads data written by 2.8 in place, and nothing breaks. Every 2.8 command-line flag, JSON configuration file, program file, checkpoint, run-state file and saved record keeps working, and the JSON Lines schema stays `exposure-jsonl/1` with additive fields only. The one new feature, the live key check, is off unless a program file turns it on. The behaviour changes you may notice are listed below. The full list of changes is in [CHANGELOG_2.9.md](CHANGELOG_2.9.md).

## Before you switch

1. Stop every running Exposure Desk instance (Settings → Stop Exposure Desk, or close the launch window).
2. Back up the whole data directory shown in Settings while the app is stopped: `%LOCALAPPDATA%\Exposure Desk` on Windows and `$XDG_DATA_HOME/exposure-desk` (`~/.local/share/exposure-desk`) on Linux by default. Keep `keys`, `scans`, `vault` and `workspace.json` together. Back up every `--program` folder too: its `.key` keeps finding IDs stable. Exposure Desk does not make this backup for you.
3. Extract the 2.9.0 package into its own folder and start it as before: **Start Exposure Desk.cmd** on Windows, `Start Exposure Desk.sh` on Linux ([docs/LINUX.md](docs/LINUX.md)). It reuses the same data directory.

## What keeps working

- Every 2.8 flag and command, with the same meaning, including `--targets`, `--concurrency`, `--state`, `--program`, `--recon`, `--rebuild-sources` and `--submission-bundle`.
- Program files without a `liveKeyChecks` block load and behave exactly as in 2.8.
- Finding IDs are computed as in 2.8, so the same key and value keep the same ID.
- Exit codes keep their meaning: 0 completed with no unsuppressed private credential, 1 completed with a policy finding, 2 failed, cancelled, incomplete or refused.
- Ready options and their ceilings are unchanged, including the 512 MiB analysis memory limit. Low-impact traffic, masking, the authorization rule and the dashboard security model are unchanged. No new option or file can loosen them.

## Live key check (opt-in)

A person can ask whether one found key still works. Nothing changes until a program file contains:

```json
"liveKeyChecks": { "enabled": true }
```

Then **Check if live** appears on a finding and `check-key FINDING-ID --program DIR --authorized` is accepted. `"checkAll": true` is a separate permission for **Check all** and `--all`. No scan, mass scan or ready option ever checks a key. Only the key leaves the computer, in the one header its provider documents, in one read-only identity request. The result (**live**, **revoked** or **unknown**) is stored with the finding, and the finding's `validity` stays `unverified`. Many programs forbid testing found credentials; turn this on only where the program permits it. See [docs/LIVE_KEY_CHECK.md](docs/LIVE_KEY_CHECK.md).

## Behaviour changes you may notice

- **New findings from 31 new rules.** Rule version `website/2.9.0` adds format rules for 28 providers that had no rule of their own. A rescan can report keys of these providers that 2.8 did not. No existing finding changes its provider, rule or category. See [DETECTOR_COVERAGE.md](DETECTOR_COVERAGE.md).
- **Discovered URLs with an invalid host are refused.** A link, script, source map, redirect target or browser subrequest whose host is not a valid website host is refused before any DNS lookup and recorded as `invalid-url`. Entered addresses were already checked this way.
- **Two more protected hosts.** `politie.be` and `policia.pt`, with their subdomains, are refused like every other protected host. There is still no override.
- **Popups are not loaded.** In a browser scan, a popup's in-scope page URL is added to the scan like a link; any other popup request is recorded as blocked with reason `browser-popup`.
- **Page-leave handlers.** A document that leaves without a network request (a removed frame, `about:blank`, `javascript:` or `srcdoc`) no longer runs its page-leave handlers, so anything only they would have revealed is not seen. Requests a page starts after its inspection has ended are aborted.
- **Lower memory in mass runs with large bundles.** After large in-process parses the scan process runs a full memory collection. The findings are the same.
- **Fairer program-wide request turns.** With a program file, targets now take program-wide request turns in arrival order, so no target waits much longer than the others for its first request.

## JSON Lines additions

All additive; a reader that ignores unknown fields needs no change. See [docs/JSONL.md](docs/JSONL.md).

- `target-end.sharedWaitByCause` and `summary.sharedWaitByCause`: `{analysisMs, parserMs, preflightMs, programSlotMs}`, which always add up to `sharedWaitMs`. `sharedWaitMs` itself is unchanged.
- `summary.memory` gains `parseCollections` and `parseCollectMs`.
- `browserStatus.popups` counts the popups opened and closed.

## Data written by 2.9.0

- The workspace stays `exposure-workspace/3`, history `exposure-history/2`, checkpoints `exposure-checkpoint/1`, reports `exposure-scan/1` and run-state files `exposure-massrun/1`. New fields are additive: a finding's saved review gains `liveCheck` once a key has been checked.
- Going back to 2.8 with data written by 2.9.0 was not tested; restore the backup instead.
