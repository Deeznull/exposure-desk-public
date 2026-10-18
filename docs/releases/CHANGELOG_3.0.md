# Changelog — 3.0.0

3.0.0 completes the opt-in live key check with AWS and broadens the deployment-path coverage every scan probes. The live key check can now confirm an AWS access key against STS `GetCallerIdentity` without ever sending the secret access key, and the high-value deployment-path list every coverage probes is larger, with a fuller curated set for Standard and Deep. Measurements: [TEST_RESULTS.md](../TEST_RESULTS.md). Earlier changes: [CHANGELOG_2.9.1.md](CHANGELOG_2.9.1.md). Like every earlier release, 3.0.0 was measured only with local loopback fixtures and synthetic, nonfunctional keys. No real website and no real provider endpoint was contacted.

Rule version `website/3.0.0` (2.9.1 used `website/2.9.1`). No format rule was added, removed or changed: the detector's rule catalogue is identical to 2.9.1, and a scan of the same content reports the same findings. The version moves because the live key check gained a provider and the probed deployment-path list grew — both change what a check or scan reaches, not what the detector recognises. The priority version stays `priority/1`. Unchanged:

- the detector rule catalogue and the pinned offline Gitleaks 8.30.1 engine and its digest
- the ready options and their limits, including the 512 MiB analysis memory ceiling
- Low-impact traffic
- the protected-host rule, the private/internal/cloud-metadata refusal, DNS pinning and the authorization rule
- the live key check doctrine: off unless a program file turns it on, never part of a scan, one read-only request per key, the key never printed and the verdict stored apart from the finding, whose `validity` stays `unverified`
- masking and the dashboard security model

No new option or file can loosen any of them. Migration notes: [MIGRATION_3.0.md](MIGRATION_3.0.md). 3.0.0 reuses the 2.9 data directory in place, and every 2.9 command-line flag, configuration file, program file, checkpoint and saved record keeps working. The JSON Lines schema stays `exposure-jsonl/1` and only gains fields. Static requests carry the product token `Mozilla/5.0 (compatible; ExposureDesk/3.0)`, taken from the build version as before.

## AWS live key check

- **STS `GetCallerIdentity`, read-only.** An AWS key found with its public access-key ID can now be checked against `https://sts.amazonaws.com/` with the documented read-only `GetCallerIdentity` action (`POST /`, body `Action=GetCallerIdentity&Version=2011-06-15`). A 200 is **live**, a 403 such as `InvalidClientTokenId` is **revoked**, and a throttle or any other response stays **unknown** with a reason code. The recipe covers the `provider-context:aws`, `provider-context:awsbedrock` and `provider-context:awsroute53` rules.
- **The secret access key never leaves the machine.** AWS authenticates with Signature Version 4, so the secret is used only to derive a short-lived signing key locally (HMAC-SHA256 over date, region and service). The request carries the public access-key ID, the signature, the request date and — for a temporary `ASIA…` key — the session token (`x-amz-security-token`). The secret itself is never transmitted, logged or printed. This is stronger than the bearer-style recipes, where the token itself is the only thing sent.
- **Companions travel with the key.** For the check to sign, the saved evidence carries the access-key ID paired with each AWS secret, and the session token for temporary keys. A secret found without its access-key ID, or an `ASIA…` key found without a session token, is **unknown** (`incomplete-credential`) and **no request is sent** — nothing can be signed, so nothing leaves the machine.
- **The egress allowlist grew by exactly one host.** The allowlist is derived from the recipe table, so adding the AWS recipe added `sts.amazonaws.com` and nothing else. No request can still be made to any other host.
- **A revoked AWS key no longer halts the provider in Check all.** In a check-all run, a provider is halted on the first genuine rate-limit or opaque refusal (HTTP 429, a 403 that is not a recognised revocation, or a connection refusal). A 403 that the recipe reads as **revoked** — the normal answer for a dead AWS key — is a conclusive per-key verdict, not a block, so the run continues to the provider's other keys. Other providers were never affected by one provider's responses.

See [LIVE_KEY_CHECK.md](../LIVE_KEY_CHECK.md).

## Deployment-path coverage

- **A larger high-value set, probed by every coverage.** Every coverage (Quick, Standard, Deep) now probes a high-value deployment-path set that adds `/.git/config`, `/wp-config.php.bak`, `/.aws/credentials`, `/.env.dev` and `/.env.prod` to the base list. Each is confirmed by content before analysis, exactly as before.
- **A fuller curated set for Standard and Deep.** Standard and Deep additionally probe the common deploy-stage and framework variants `/.env.development`, `/.env.staging`, `/.env.test`, `/config.yml`, `/config.yaml`, `/appsettings.json`, `/credentials.json`, `/secrets.json` and `/.git-credentials`. Quick keeps only the high-value set, so it stays quick.
- **Within the existing ceiling.** The curated list a Deep audit probes stays within the fixed 30-path limit (29 paths), each a literal path matching the same validation as before (no traversal, no wildcards). Legacy presets and any project with its own `deepPaths` are unchanged; the expansion applies to the Coverage × Traffic profiles only.

See [DETECTOR_COVERAGE.md](../DETECTOR_COVERAGE.md) and [USER_GUIDE.md](../USER_GUIDE.md).

## Release measurements

Measured on build `3.0.0+900c631686338160` with loopback fixtures only: the Windows checks on one Windows x64 laptop and, because GitHub Actions could not run for this release, the jobs of `linux.yml` and the ready-option matrix on one rented Ubuntu 24.04 server. No external host was contacted from either. Details are in [TEST_RESULTS.md](../TEST_RESULTS.md) and `benchmarks/3.0.0/`.

- Regression suites: `779` non-browser tests pass, including the version-metadata and release-file gates (`release-metadata.test.ts`), the live-key-check egress suite (`live-check.test.ts`, with the new AWS SigV4 tests) and the profile deep-path suite (`profiles.test.ts`). All `46` browser and UI tests pass.
- Live key check: the AWS tests prove a complete key signs `GetCallerIdentity` with the secret absent from every header and from the body, the `Authorization` header carrying `AWS4-HMAC-SHA256 Credential=<access-key-id>/…`, and that an incomplete credential opens no socket; and that a revoked 403 from AWS does not halt the provider in a run.
- No non-loopback connection was made in any run. The frozen 2.5 corpus and its digests are unchanged, and the detector rule catalogue is byte-identical to 2.9.1.
- Linux x64 on the server: `778/779` non-browser tests pass (1 Windows-only skip) and `43/46` browser and UI tests (the 3 failures are a test-harness gap: those tests start their own Chromium without the sandbox switch the server needs, and pass with a test-only fix kept for the next version). The Linux x64 package (8094 files) passes its checksum and the packaged smoke test 13/13, and the container image builds from `docker/Dockerfile` and passes its smoke test. See [linux-server.json](../../benchmarks/3.0.0/linux-server.json).
- Ready options on the server: 58/58 matrix rows and 185/191 acceptance checks against a 2.9.1 baseline built on the same server. The 6 failed checks (3.0 on the bundle fixture, with semantic time or budget gaps from server load that the 2.9.1 rows of the same run also show) found all 7 keys with no analysis gap in every rerun, one case at a time with 2.9.1 interleaved (3.0 6/6, 3.0-small 6/6, 2.9.1 6/6). The larger deployment-path list adds 12 requests on the bundle fixture.
- Packages: the Windows x64 package passes the packaged smoke test 13/13 (launcher path with spaces, port conflict, persistence, masking, cancel, shutdown and restart, analysis processes on the bundled runtime, none left running); the root manifest matches the Windows x64 package and the Source package's hashes verify. Checksums are in `artifacts/SHA256SUMS-3.0.0.txt`.
