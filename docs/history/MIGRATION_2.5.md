# Migrating to 2.5.0-rc.1

2.5 reads data written by 2.1–2.4.0-rc.1 in place. Nothing is migrated destructively: history files and checkpoints are never rewritten to a new meaning, and old records are labeled instead of guessed.

## Before you switch

1. Stop every running Exposure Desk instance (Settings → Stop Exposure Desk, or close the launch window).
2. Back up the whole data directory shown in Settings (`%LOCALAPPDATA%\Exposure Desk` by default) while the app is stopped. Keep `keys`, `scans`, `vault` and `workspace.json` together: correlation keys and encrypted evidence only work as a set. Exposure Desk does not make this backup for you.
3. Extract the 2.5 Windows x64 ZIP into its own folder and start it with **Start Exposure Desk.cmd**. It reuses the same data directory.

## Saved projects and scope

- Projects saved before 2.5 stored `sameRegistrableDomainDiscovery: false` as the old default. Because that value is ambiguous, they keep scanning **only their exact origins** and are marked `scopeReview: legacy-default-exact-origin`. Their cards show **Use domain scope for <domain>**. Adopting it requires the acknowledgement again and saving the project; until then, subdomains inside the domain are listed in the scan's scope summary but not scanned.
- A project saved with `sameRegistrableDomainDiscovery: true` runs domain scope.
- New projects, presets, CLI `--url` scans and JSON files without a scope key use domain scope. To keep exact-origin behavior explicitly, set `"domainScope": "exact-origin"` (see [exact-origin.config.example.json](../../exact-origin.config.example.json)) or keep an explicit `"sameRegistrableDomainDiscovery": false`; setting both keys to disagreeing values is an error.
- The workspace schema is `exposure-workspace/3`. The boolean `sameRegistrableDomainDiscovery` is still written as a mirror so a downgrade to 2.4 keeps honouring the scope.

## History, runs and comparisons

- Runs recorded before 2.5 show **Trigger not recorded** (focused retries and the synthetic demo are recognized and marked "(inferred)"), "contacted: not recorded" when the record has no per-origin data, and "unknown build" when no build was recorded. Their scope, analysis and discovery summaries read "not recorded by build …".
- History is listed by start time instead of file name.
- Retry, rescan and resume from an old record reproduce the scope and settings that actually ran; they never adopt the new default silently.
- Comparisons between builds become "uncertain" when the effective scope, rules, build, analysis lifecycle or outgoing request headers differ (2.4 static requests sent no User-Agent or Accept-Language).
- An old analyzer state `pending` in a finished 2.4 record means "never finished"; it is labeled legacy and not re-interpreted.

## Reviews and lifecycle

- Review records now merge field by field: feedback keeps the review status, a status change keeps an active suppression, and suppression is cleared only by Remove suppression or by confirming/undoing feedback. Reviews are applied when history is read; history files are no longer rewritten for each review.
- A 2.4 review status **removed** is shown as an unqualified removal report ("Legacy 2.4 removed status: whether the value was removed from the website or revoked was not recorded"). It is never treated as a revocation. Record an owner-confirmed revocation explicitly if that is what happened.
- The `open | reviewing | removed` field is still derived for older readers. After a downgrade to 2.4, removal reports and revocation records made in 2.5 are not shown (2.4 ignores the new fields).
- Saved views from older builds are re-assessed in memory with `priority/1` when loaded; their files are unchanged.

## Request headers

Static requests now send `User-Agent: Mozilla/5.0 (compatible; ExposureDesk/2.5)` and `Accept-Language: en-US,en;q=0.9` (the configured `browserLocale`). Browser requests use the configured `browserLocale` and `browserTimezone` (default `UTC`) instead of this computer's settings, and Referer is cut to the origin. If a site you own blocks the product token, allowlist it or set `"staticUserAgent": "none"` for the project (the 2.4 behavior). These keys are additive; older projects receive the defaults.

## New data written by 2.5

- `workspace.json`: `alerts` (up to 200, masked), `projects[].deploymentTrigger`, `projects[].schedule.lastRunId`, and new review fields (`owner`, `removalReported`, `revocation`, `rescan`, `website`, `firstSeen`, `lastSeen`, `scans`). 2.4 ignores them.
- `scans/*.json`: views gain `launch`, `requestProfile`, `scope`, `analysis`, `discovery`, per-finding `priority`, `impacts`, `qualifiers`, `assets` and `keyStructure`. Schemas stay `exposure-history/2`, `exposure-scan/1` and `exposure-checkpoint/1`.
- `triggers/`: deployment trigger request files written by `cli.js trigger` and deleted once processed.
- `tmp/browser-*/.exposure-desk-profile.json`: a marker naming the owning process, so a later start can remove profiles left by a crash.

## Known 2.4 package drift

The 2.4.0-rc.1 ZIPs in `artifacts/` were created before the final README, HANDOFF and RELEASE_PACKAGE edits; those three files inside both 2.4 ZIPs differ from the 2.4 root copies, and the root `PACKAGE_MANIFEST.json` of 2.4 matched a re-staged package that was not re-zipped. The 2.4 ZIPs are kept unchanged as the baseline of record (their hashes are re-verified in `artifacts/final-parity-2.5.json`). The 2.5 release freezes documentation before packaging and verifies root/ZIP parity.
