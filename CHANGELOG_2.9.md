# Changelog — 2.9.0

2.9.0 follows 2.8.0 (build `2.8.0+cc5fecf8cb75f1c7`). It adds an opt-in live key check for a single finding, 31 detection rules ported from Gitleaks and Nosey Parker, host validation for every discovered URL, and fixes to the page-leave guard, mass-scan memory and the analysis memory of unparseable bundles. Upgrade notes: [MIGRATION_2.9.md](MIGRATION_2.9.md). Measurements: [TEST_RESULTS.md](TEST_RESULTS.md). Earlier changes: [CHANGELOG_2.8.md](CHANGELOG_2.8.md). Like every earlier release, 2.9.0 was measured only with local loopback fixtures and synthetic, nonfunctional keys. The live key check was tested only against loopback mock providers. No real website and no real provider endpoint was contacted.

Rule version `website/2.9.0` (2.8.0 used `website/2.8.0`), because of the new detection rules below. The priority version stays `priority/1`. Unchanged:

- the ready options and their limits, including the 512 MiB analysis memory ceiling
- Low-impact traffic
- the protected-host rule and the authorization rule
- masking
- the dashboard security model

No new option or file can loosen any of them. Every 2.8 command-line flag, configuration file, program file, checkpoint and saved record keeps working. The JSON Lines schema stays `exposure-jsonl/1` and only gains fields. Static requests carry the product token `Mozilla/5.0 (compatible; ExposureDesk/2.9)`, taken from the build version as before.

## Live key check (opt-in, off by default)

- A person can ask whether **one** found key still works. Exposure Desk makes one read-only identity request to that key's own provider and records **live**, **revoked** or **unknown** next to the finding. The finding's `validity` stays `unverified`. See [docs/LIVE_KEY_CHECK.md](docs/LIVE_KEY_CHECK.md).
- It is off unless a program file sets `"liveKeyChecks": { "enabled": true }`. **Check all** is a separate permission (`"checkAll": true`). Without the block, nothing changes.
- It is never automatic: no scan, mass scan or ready option ever checks a key. A check starts only from **Check if live** on a finding (after a confirmation that names the host) or from `check-key FINDING-ID --program DIR --authorized`.
- Only the key leaves the computer, in the one header the provider documents. No URL, path, context or other finding is sent. Redirects are not followed.
- Providers with a recipe: GitHub, GitLab, OpenAI, Anthropic, Stripe, SendGrid and Slack. A finding of any other rule is not checked and reads **unknown** (`no-recipe`), with no request made.
- **Check all** runs one key at a time, paced per provider, and stops a provider at its first rate limit or refusal. It can be cancelled.
- The request goes through the same address guards a scan uses: the protected-host block (before DNS, no override), the refusal of private, internal and cloud-metadata addresses, DNS pinning with a socket-address check, and a certificate host re-check. The User-Agent is the honest product token.
- PRIVACY.md, README.md and ACCEPTABLE_USE.md now say that a found credential is never sent to its provider automatically, only on an explicit per-key check.

## Detection rules

- 31 rules for 28 providers, ported from Gitleaks (MIT) and Nosey Parker (Apache-2.0). Only providers that had no rule of their own were added, so no existing finding changes its provider, rule or category. Upstream quantifiers were bounded. See [DETECTOR_COVERAGE.md](DETECTOR_COVERAGE.md) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md), which now ships in both packages.
- Left out: public browser keys (New Relic browser keys, Mapbox `pk`), rules that need context, rules for short or collision-prone prefixes, and entropy or generic rules.
- An old-vs-new comparison over 529 inputs (the external corpus files and the frozen 2.5 corpus strings) found no difference in existing results. The benchmark finds 167 of 167 with no false positives.

## Host validation for discovered URLs

- URLs found during a scan (links, scripts, source maps, redirect targets, browser subrequests) whose host is not a valid website host are now refused before any DNS lookup and recorded as `invalid-url`. Before, only URLs a person entered were checked this strictly. The protected-host check still comes first.

## Protected hosts

- `politie.be` (Belgian police) and `policia.pt` (Portuguese police portal) join the built-in list, with their subdomains. The list only grows; there is still no override.

## Page-leave guard

- **Documents replaced with `document.open`.** The guard is put back at once after `open`, `write` and `writeln`, so a page cannot remove it by rewriting its document.
- **Removed and detached frames.** A real page leave never runs the page's own page-leave handlers, so a removed frame cannot send their requests unrouted.
- **Pages a document leaves itself.** Before a navigation that the page starts, the guard runs the leaving documents' handlers once, while routing still applies, and the navigation waits briefly (at most 400 ms) for their requests.
- **Popups.** Popups are never loaded. A popup's in-scope page URL is added to the scan like a link, under the scan's scope, protected-host and request rules; any other popup request is recorded as blocked with reason `browser-popup`. `browserStatus.popups` counts the popups opened and closed.
- **Late work.** Requests and WebSockets that a page starts after its inspection has ended are aborted and never sent.
- Trade-off: the page-leave handlers of a document that leaves without a network request (a removed frame, `about:blank`, `javascript:` or `srcdoc`) no longer run, so anything only they would have revealed is not seen.

## Memory

- **Unparseable large bundles (O1).** A text of 64 KiB or more that fails both the module and the script parse is remembered by content hash, so the same bundle is not parsed again. On the G5 benchmark bundle, which has a syntax error, the peak fell from 467–520 MiB to 394–396 MiB (G6: 460–463 to 390–393 MiB), with identical results.
- **Mass runs with large bundles.** After in-process script parses of 64 KiB or more add up to 512 KiB, the scan process runs one full memory collection, so the parse garbage of several targets no longer piles up. The parses, budgets and findings are the same. `summary.memory` gains `parseCollections` and `parseCollectMs`. 16 targets, each with its own 1.25 MB bundle:

  | At once | 2.8.0 peak | 2.9.0 peak |
  |---|---|---|
  | 1 | 378 MiB | 377 MiB |
  | 4 | 577 MiB | 356 MiB |
  | 16 | 557 MiB | 415 MiB |

  The normal 200-target fixture is unchanged (no collection runs there).
- **Correction to 2.8.0.** CHANGELOG_2.8 and docs/MASS_SCAN.md said the memory gate keeps a mass run's scan process under the 512 MiB ceiling. That held for the normal fixture but not for targets with large bundles: the gate estimates an average cost per target, and the memory of one large parse is a short spike it cannot see. With 16 such targets 2.8.0 peaked at 557–577 MiB (other runs: up to 728 MiB). 2.9.0 fixes this as above, and docs/MASS_SCAN.md now describes both mechanisms.

## Mass scan: shared-capacity waits

- **Fair program-wide request turns (O2).** With a program file, the program-wide request limiter now hands out its turns in arrival order across targets, so a busy target can no longer keep taking turns ahead of targets still waiting for their first request. In the probe run, the longest wait any target had for its first request fell from 9528 ms to 2205 ms. Budgets, request counts and findings are the same.
- **Where the shared wait goes (O3).** `target-end`, the mass `summary` and the origin snapshots gain `sharedWaitByCause`: `{analysisMs, parserMs, preflightMs, programSlotMs}`, the time spent waiting for the shared analysis budget, the parser, the preflight and the program-wide request slots. The four always add up exactly to `sharedWaitMs`, which is unchanged. See [docs/JSONL.md](docs/JSONL.md) and [docs/MASS_SCAN.md](docs/MASS_SCAN.md).

## Fixes

- **Starting a scan keeps your page.** If you move to another dashboard page while a scan start is pending, the dashboard no longer switches to Running scan; the message says where to find the run.

## Development, CI and release tooling

- Linux CI runs on `ubuntu-24.04` instead of `ubuntu-latest`. THIRD_PARTY.md lists the Linux package and container components.
- The benchmark has a G5F group: the frozen G5 bundle with its syntax error corrected, so its parse can be measured. The frozen 2.5 corpus and its digests are unchanged. The split key in G5F is still not found: following webpack's cross-module constant exports is not part of 2.9.0.
- `scripts/mass-scan-measure.mjs` has large-bundle rows (`large-c1`, `large-c4`, `large-c16`, `--large-targets`, `--only`).

## Release measurements

Measured on build `2.9.0+b251a3ea63449d85` on one Windows x64 computer with loopback fixtures only; details and the 2.8.0 comparison are in [TEST_RESULTS.md](TEST_RESULTS.md) and `benchmarks/2.9.0/`.

- Ready-option matrix: 191/191 checks passed; the 2.8.0 side is reused from the 2.8.0 release records after a same-day spot check.
- External synthetic corpus (20 sites; 12 runs: the six ready options from the site root and with every expected file seeded): every count and each site's findings, misses and false positives equal to 2.8.0.
- Target lists at scale: every normal row completed 200/200 targets with every key found; 16 at once took 207 s (2.8.0: 234 s), 64 at once with a program file 173 s (206 s) with the longest single program-slot wait down from 24 s to 3.1 s. The large-bundle rows stayed at 379–390 MiB (2.8.0 code: up to 577 MiB).
- Regression suites: 761/761 non-browser and 46/46 browser and UI tests on Windows (final runs on a quiet machine; every run is listed in `benchmarks/2.9.0/browser-attempts.json`) and 760/761 (one Windows-only test skipped) and 46/46 on GitHub-hosted Linux x64 runners; 60/60 cancellation stress; 167/167 provider-corpus targets with 0 false positives; the frozen 2.5 corpus 60/60 runs without errors, results equal to 2.8.0.
