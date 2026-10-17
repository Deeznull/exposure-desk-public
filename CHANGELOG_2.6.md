# Changelog — 2.6.0

2.6.0 is the final 2.6 release. It contains everything in 2.6.0-rc.1 (listed below) plus the detection-quality update and the fixes made after it. Details: [UPGRADE_2.6.md](UPGRADE_2.6.md). Upgrade notes: [MIGRATION_2.6.md](MIGRATION_2.6.md). Measurements: [TEST_RESULTS.md](TEST_RESULTS.md). Later changes: [CHANGELOG_2.7.md](CHANGELOG_2.7.md). Like every earlier release, 2.6.0 was measured only with local loopback fixtures and synthetic, nonfunctional keys on one Windows x64 computer; no real website was scanned.

## 2.6.0

Compared with 2.6.0-rc.1 (build `2.6.0-rc.1+43dc0e2d6c36202f`). Rule version `website/2.6.1` (2.6.0-rc.1 used `website/2.6.0`); the priority version stays `priority/1`. The ready options and their limits, Low-impact traffic, the protected-host rule and the dashboard security model are unchanged. Saved records of earlier versions load unchanged and are never rewritten.

### Detection-quality update
- Compared with Gitleaks, Nosey Parker, secretlint, TruffleHog (ideas only), Titus and others; details, decisions and measurements in archive/notes/HANDOFF_GITHUB_COMPARE.md (local working notes, not packaged).
- `src/placeholders.ts`: one template and placeholder filter (adapted from the Gitleaks 8.30.1 allowlist, MIT) used by direct rules, structured passes and provider context.
- `src/detectors.ts`: 17 rules — Docker Hub, Firecrawl, Google OAuth secret and access token, Jina, Square OAuth secret, Tavily (adapted from Nosey Parker, Apache-2.0), Figma, Tailscale, Vercel, Vercel AI Gateway (adapted from secretlint, MIT), Braintree access token, Cloudinary URL, and FTP/SFTP, mail, message-broker and LDAP URL passwords; database URLs accept an empty user name; one bounded HTML character-reference view for attribute JSON.
- `src/capabilities.ts`: Discord webhook and Zapier catch-hook URLs. `src/provider-capabilities.ts`: impact and remediation text for each new provider.
- `src/token-checksums.ts`: offline CRC32 check for GitHub `ghp_`/`gho_`/`ghu_`/`ghs_` tokens; a mismatch adds the `checksum-mismatch` qualifier and caps priority at review (`src/evidence.ts`, `src/finding-assessment.ts`, `src/finding-triage-rules.ts`, `public/app.js`).
- `src/reports.ts`: SARIF rules with help, tags (CWE-798/CWE-200), `security-severity`, `precision`; active suppressions exported.
- Tests: `test/detection-quality.test.ts` (new) and new synthetic cases in `test/provider-fixtures.ts`; DETECTOR_COVERAGE.md rows and coverage-registry.json regenerated. Licences: `rules/NOSEYPARKER-LICENSE`, `rules/NOSEYPARKER-NOTICE`, `rules/SECRETLINT-LICENSE`.

### Fixes
- Offline build-folder gate (`artifacts`): a file that is not valid UTF-8 (binary or another encoding) is skipped without inspecting its contents and recorded as the gap `local-artifact-undecodable`, instead of aborting the whole local scan (`src/artifact-scan.ts`, `test/stage2.test.ts`).
- `cleanup` also removes browser profile folders left behind by interrupted scans; profiles of running scans are kept (`src/cli.ts`, `test/privacy.test.ts`).
- The self-test fixture's synthetic GitHub token carries a valid checksum, so the new offline checksum check does not lower its priority (`src/fixture.ts`).
- The scan page's description of the User-Agent named `ExposureDesk/2.5`; it now matches the header that is actually sent (`ExposureDesk/2.6`).

### Delivery
- The Windows x64 and Source packages include `LICENSE`, `PRIVACY.md`, `SECURITY.md`, `ACCEPTABLE_USE.md`, `THIRD_PARTY.md`, `DEMO.md` and `docs/screenshots/`.
- `scripts/screenshots.mjs` (dashboard screenshots from synthetic local data on 127.0.0.1) and `scripts/demo.ts` (a synthetic demo project); see [DEMO.md](DEMO.md).
- Release records use the full version from 2.6.0 on: `artifacts/SHA256SUMS-2.6.0.txt`, `artifacts/release-2.6.0-results.json`, `artifacts/final-parity-2.6.0.json` and `benchmarks/2.6.0/`. The records of 2.6.0-rc.1 and earlier keep their names (`SHA256SUMS-2.6.txt`, `benchmarks/2.6/`, …) and were not rewritten; `artifacts/ARCHIVE_INDEX.json` marks 2.6.0-rc.1 as superseded.
- The ready-option matrix and the external synthetic corpus were measured for 2.6.0-rc.1 and are reported for 2.6.0 as carried over (labelled as such in TEST_RESULTS.md); every other suite was re-run on the 2.6.0 build.

## 2.6.0-rc.1

Compared with 2.5.0-rc.1 (build `2.5.0-rc.1+97836a16c30888f3`).

### Ready options (P1, P3, P3b)
- `src/profiles.ts`: three coverages (Quick check, Standard, Deep audit) × two traffic levels (Normal, Low-impact) with per-website allocations, local resource settings (analysis memory, workers, websites and browser websites at once), hard ceilings, honest examines/skips lists, labels and the descriptive legacy mapping. `resolveProfile` in `src/config.ts` fills every profile key; legacy presets and custom numbers resolve exactly as in 2.5.
- Standard + Normal is Recommended and the default for the scan page, new projects and a CLI scan without a preset, option, configuration file, checkpoint or sizing flag.
- Quick check: entry documents, up to 40 first-party scripts per website, maps, manifests and deployment paths; stop reason `quick-target-set-done`, stage "Completed — quick coverage", gap `quick-coverage-boundary`, `profile.notExamined`. Every profile probes `/wp-config.php.bak` and `/.git/config`.
- Shared caps and the estimate grow with the website count; long-scan notice above about 2 hours; `estimateScan`/`profilePreview` and `POST /api/profile/preview`; CLI `Uses:` and `Long scan:` lines.
- `src/computer.ts`: cores and free memory at scan start, lower-only adjustment, `profile.resourceUse` in records and reports.
- Analysis memory is one allowance across all parser workers (per-worker share, an oversized group gets the whole allowance alone); Quick uses 256 MiB.
- Scan page: six option cards in one radio group, read-only "What this option uses" panel, no number fields; legacy and custom banners with a one-click switch and Restore; `POST /api/projects/profile`; profile tags on run rows; "Scan profile" report section; saved ready options follow the current tables (`followReadyOption`).
- CLI `--coverage`, `--traffic`; conflicting preset and coverage refused (exit 2); `--sizing fixed` with an option refused.

### Low-impact traffic (P2)
- 0.5 requests/s and 1 at once per website, at most 2 websites and 1 browser website at once, no retries, one query variant per path (Limited by profile, owner decision 2026-10-09), no adjacent source-map guessing (`enforceLowImpact`, `LOW_IMPACT_LIMITS`).
- One kept-alive connection per website keyed by protocol, host, port, pinned IP and TLS name; DNS rechecked before every request and cache hit; one replay of a stale connection.
- 64 MiB run cache (RFC 9111; 200/404/410; never with cookies or credentials); `servedFrom: run-cache`.
- Connection accounting: connections opened and reused, replays, TLS handshakes, browser cache hits, requests avoided; `connectionsMax` in the estimate.

### Protected hosts (gov-block)
- `src/protected-hosts.ts`: reviewed list and `protectedHost()` with no override; seeds refused in `makeConfig` (CLI exit 2, API 400 `protected-host`); `Transport.preflight`, `addresses()`, `openPinned` (including TLS certificate names), scanner admission and the browser route refuse follow-on requests; block kind `protected-host` in accounting and reports; saved records load unchanged and never run.

### External review and corpus (2026-10-08)
- F-01/D-4: browser cookies keyed to the initiating document, `Domain=` stripped, `cookieStore` disabled, UI claim corrected.
- F-02: changed text at a module alias becomes one bounded variant (`#variant-<sha8>`).
- F-03: 80 curated tenant suffixes in `src/domain-scope.ts` (narrowing only).
- D-2/D-3: README scope sentence and storage schemas.
- Detection (`website/2.6.0`): whole-document parse up to 2 MiB, plain-text configuration groups, hex decoding, URL- and identifier-named values no longer reported as secrets.

### Fixes found during 2.6 work
- HTML report escapes stored numbers; `authorizedAt` is no longer refreshed by a profile switch; reports include the computer's cores and free memory.
- Websites at once (found by the P4 matrix): a ready option used to start every website together, so each website's time allowance ran while it waited for shared analysis and a Low-impact website's requests drifted past the 4-second idle close. Now a website that has not started waits while the websites at once still have work; its time allowance starts with its own first request, and Low-impact keeps one connection per website. The scan record's scheduler view names the reason ("Website waits for a free website slot"). 2.5 configurations keep their round-robin over every website (`src/scanner.ts`, `src/scheduler.ts`, `test/websites-at-once.test.ts`).
- Deployment paths while the browser is busy (found by the P4 matrix): a website probed its deployment paths only after its browser pages. On a small computer (one browser website at once) a website could wait for the browser slot until its soft deadline, so Standard + Normal for 10 websites missed `/.env` and `/config.json` of four websites. Now a ready-option website whose browser turn waits for a slot other websites hold probes its deployment paths meanwhile; with a free browser the order stays browser pages, then deployment paths, and 2.5 configurations keep that order always (`src/scanner.ts`, `test/deployment-paths-browser.test.ts`).

### Tests and delivery (P4)
- New suites: profiles, profile-limit, traffic, protected-hosts, profile-ui, ready-options, websites-at-once (nonbrowser); traffic, protected-hosts, profile-ui, ready-options, deployment-paths (browser); additions to privacy, lifecycle and same-domain; a loopback TLS fixture (its random certificate serial is always minimal DER: before the P4 fix about 1 in 240 generated certificates was refused by OpenSSL, which failed one matrix case).
- `scripts/profile-matrix.mjs` and `scripts/profile-matrix-case.mjs`: the ready-option measurement matrix (six options × single, bundle and multi-subdomain fixtures × 1, 3 and 10 websites, a small-computer injection and the 2.5 release as baseline).
- `scripts/external-corpus.mjs` runs a ready option as shipped (`--coverage`, `--traffic`).
- Release preflight and release summary generalized to every earlier release (all `SHA256SUMS-*.txt` re-verified, baseline parity against the current release candidate, archive index carried forward).
- Configuration examples use ready options; the 2.5 examples are kept as test fixtures in `test/fixtures/legacy-2.5/`.
