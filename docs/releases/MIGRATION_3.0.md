# Migrating to 3.0.0

3.0.0 reads data written by 2.9 in place, and nothing breaks. Every 2.9 command-line flag, JSON configuration file, program file, checkpoint, run-state file and saved record keeps working, and the JSON Lines schema stays `exposure-jsonl/1` with additive fields only. The live key check stays off unless a program file turns it on. The behaviour changes you may notice are listed below. The full list of changes is in [CHANGELOG_3.0.md](CHANGELOG_3.0.md).

## Before you switch

1. Stop every running Exposure Desk instance (Settings → Stop Exposure Desk, or close the launch window).
2. Back up the whole data directory shown in Settings while the app is stopped: `%LOCALAPPDATA%\Exposure Desk` on Windows and `$XDG_DATA_HOME/exposure-desk` (`~/.local/share/exposure-desk`) on Linux by default. Keep `keys`, `scans`, `vault` and `workspace.json` together. Back up every `--program` folder too: its `.key` keeps finding IDs stable. Exposure Desk does not make this backup for you.
3. Extract the 3.0.0 package into its own folder and start it as before: **Start Exposure Desk.cmd** on Windows, `Start Exposure Desk.sh` on Linux ([docs/LINUX.md](../LINUX.md)). It reuses the same data directory.

## What keeps working

- Every 2.9 flag and command, with the same meaning, including `--coverage`, `--traffic`, `--scope`, `--targets`, `--concurrency`, `--state`, `--program`, `--recon`, `--rebuild-sources` and `--submission-bundle`.
- Program files without a `liveKeyChecks` block load and behave exactly as in 2.9.
- A project's own `deepPaths` list is used as given; the expanded deployment-path set applies only to the Coverage × Traffic profiles.
- Finding IDs are computed as in 2.9, so the same key and value keep the same ID.
- Exit codes keep their meaning: 0 completed with no unsuppressed private credential, 1 completed with a policy finding, 2 failed, cancelled, incomplete or refused.
- Ready options and their ceilings are unchanged, including the 512 MiB analysis memory limit. Low-impact traffic, masking, the authorization rule, the protected-host rule and the dashboard security model are unchanged. No new option or file can loosen them.

## AWS live key check (opt-in, like every provider)

The live key check is unchanged in doctrine and still off unless a program file sets `"liveKeyChecks": { "enabled": true }`. 3.0.0 only adds AWS to the providers it can check:

- An AWS key is checked against STS `GetCallerIdentity`, read-only. The **secret access key never leaves your computer**: it only signs the request locally (AWS SigV4). Only the public access-key ID, the signature and — for a temporary `ASIA…` key — the session token are sent. See [LIVE_KEY_CHECK.md](../LIVE_KEY_CHECK.md).
- A secret found without its paired access-key ID, or an `ASIA…` key without a session token, returns **unknown** (`incomplete-credential`) and sends nothing.
- The egress allowlist gains exactly one host, `sts.amazonaws.com`, derived from the recipe. No other host becomes reachable.

## Behaviour changes you may notice

- **More deployment paths are probed.** Every coverage now probes a larger high-value deployment-path set (`/.git/config`, `/wp-config.php.bak`, `/.aws/credentials`, `/.env.dev`, `/.env.prod` in addition to the earlier list), and Standard and Deep probe a fuller curated set as well. A rescan can therefore report an exposed file that an earlier scan did not reach. Each path is still confirmed by content before analysis, and the curated list stays within the fixed 30-path limit.
- **A revoked AWS key no longer halts the provider in Check all.** A 403 that the recipe reads as a revocation is now a conclusive per-key verdict, so a check-all run continues to the provider's other keys instead of halting AWS. Genuine rate-limits and opaque refusals still halt the provider for the rest of the run, as before.

## JSON Lines additions

All additive; a reader that ignores unknown fields needs no change. See [docs/JSONL.md](../JSONL.md). The schema stays `exposure-jsonl/1`.

## Data written by 3.0.0

- The workspace stays `exposure-workspace/3`, history `exposure-history/2`, checkpoints `exposure-checkpoint/1`, reports `exposure-scan/1` and run-state files `exposure-massrun/1`. A finding's saved review still gains `liveCheck` once a key has been checked; an AWS verdict is stored the same way.
- Going back to 2.9 with data written by 3.0.0 was not tested; restore the backup instead.
