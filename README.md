<div align="center">

# Exposure Desk

**Find the API keys and secrets your own website is leaking before someone else does.**

A local, privacy-first scanner that looks at your site the way an anonymous visitor would.

![version 2.9.1](https://img.shields.io/badge/version-2.9.1-0f5f5c)
![Windows x64 | Linux x64](https://img.shields.io/badge/platform-Windows%20x64%20%7C%20Linux%20x64-555)
![Node 24](https://img.shields.io/badge/node-24-555)
![licence: all rights reserved](https://img.shields.io/badge/licence-all%20rights%20reserved-a33)

</div>

![Findings view: grouped by provider with priority, masked value and reveal controls](docs/screenshots/3-findings.png)

## Why

Keys end up in public places all the time: a Stripe secret in a JavaScript bundle, a database URL in a forgotten `.env`, an OpenAI key in a source map, a signing secret in page data. Exposure Desk crawls a website **you own or are authorized to test**, finds that material, tells you where it came from and how urgent it is, and explains how to fix it. Everything runs on your machine.

## Features

- 🔎 **Deep discovery.** HTML, scripts and lazy chunks, source maps (with embedded sources), JSON and config files, framework manifests, well-known deployment paths, and pages rendered in an isolated browser.
- 🧠 **Wide detection.** 88 detection families with test evidence: AI, cloud, payment, messaging, DNS and deployment providers, wallet seed phrases, private keys, signing secrets and passwords in connection URLs. A pinned, offline Gitleaks engine adds its rule catalogue. Placeholders such as `${VAR}` are filtered out. See [DETECTOR_COVERAGE.md](DETECTOR_COVERAGE.md).
- 🎯 **Findings you can act on.** Exact location (traced back through source maps), confidence, priority with its reason, possible impact, and provider-specific remediation steps.
- 🖥️ **Dashboard and CLI.** A local web dashboard, plus a CLI with JSON, HTML, SARIF and submission-Markdown output and CI-friendly exit codes.
- 🐞 **Bug bounty workflow.** Program files with scope rules, resumable target lists, masked recon lists and submission drafts. See the [bug bounty quick start](docs/REFERENCE.md#bug-bounty-quick-start).
- 📊 **Honest coverage.** Every scan says what it could not inspect. "No findings" is never presented as proof that a site is clean.

## Safe by design

| | |
| --- | --- |
| **Local only** | No account, cloud service, telemetry or upload. Scans and findings stay in a protected data folder on your computer. |
| **Never uses found keys** | Scans never send a discovered credential anywhere. An opt-in, one-at-a-time [live key check](docs/LIVE_KEY_CHECK.md) is off by default. |
| **Masked by default** | Secrets are redacted in history, exports and the UI until you deliberately reveal one. |
| **Polite traffic** | An honest User-Agent, per-site rate limits and a Low-impact mode. No spoofing, no proxy rotation, no evasion. |
| **Guarded transport** | One scope policy for every request: DNS pinning, private and cloud-metadata addresses blocked, redirects rechecked. |
| **Protected hosts** | Government, military, intelligence, law-enforcement and judiciary sites are refused. There is no override. |

## Quick start

> **Permission required.** This repository is published for viewing only. Running, building or copying Exposure Desk needs prior written permission from the author (see [LICENSE](LICENSE)). The steps below are for people who have it, and for contributors testing a change under [CONTRIBUTING.md](CONTRIBUTING.md).

**From source** (Node.js 24):

```sh
npm ci
npm run build
npm run launch
```

The launcher opens the dashboard in your browser. Paste the launch token from the terminal, open **New scan**, keep **Standard + Normal (Recommended)**, confirm that you are authorized, and start. The isolated browser and the Gitleaks engine are installed from **Settings**.

**Command line:**

```sh
node dist/src/cli.js scan --url https://www.example.com/ --output reports/site.json
node dist/src/cli.js scan --url https://www.example.com/ --coverage quick --traffic low-impact --format sarif --output reports/site.sarif
node dist/src/cli.js artifacts --directory build   # offline check of a build folder before you deploy
```

Exit code `0` means no unsuppressed private credentials were found, `1` means some were, and `2` means the scan failed, was refused or was incomplete.

Windows x64 and Linux x64 packages and a container image are described in [RELEASE_PACKAGE.md](RELEASE_PACKAGE.md) and [docs/LINUX.md](docs/LINUX.md).

## Screenshots

All screenshots show a synthetic demo shop served by the built-in fixture on `127.0.0.1`. No real website was scanned.

| | |
| --- | --- |
| ![Start a scan](docs/screenshots/1-new-scan.png) | ![A running scan](docs/screenshots/2-running.png) |
| **Start a scan:** six ready options with an estimate before anything is sent. | **Running scan:** live counters and coverage. |
| ![HTML report](docs/screenshots/4-report.png) | ![A government site is refused](docs/screenshots/5-protected-refused.png) |
| **Report:** a masked export by default. | **Protected hosts:** refused before any DNS lookup. |

## Documentation

- [User guide](USER_GUIDE.md): dashboard, scan options, findings, CLI and the bug bounty workflow
- [Overview and reference](docs/REFERENCE.md): every feature, measured results, limitations and the technical reference
- [Program files](docs/PROGRAM.md) · [Target lists](docs/MASS_SCAN.md) · [Recon](docs/RECON.md) · [Submissions](docs/SUBMISSION.md) · [JSON Lines](docs/JSONL.md) · [Linux](docs/LINUX.md)
- [Changelog 2.9.1](CHANGELOG_2.9.1.md) · [Test results](TEST_RESULTS.md) · [Demo script](DEMO.md)

## Status

Version 2.9.1. Verified with local test fixtures and synthetic, non-functional keys on Windows x64 and on GitHub-hosted Ubuntu runners. It has not yet been benchmarked on real websites, and macOS and ARM are not supported. See [limitations](docs/REFERENCE.md#limitations).

## Responsible use

Exposure Desk is for websites **you own or are explicitly authorized to assess**. Scanning systems without permission may be illegal where you or the website are. You are solely responsible for how you use it. Read [ACCEPTABLE_USE.md](ACCEPTABLE_USE.md) before your first scan.

If you find a secret on someone else's site through an authorized program, report it to the owner. Do not use it. To report a vulnerability in Exposure Desk itself, see [SECURITY.md](SECURITY.md). What the program stores and sends is described in [PRIVACY.md](PRIVACY.md).

## Contributing

Contributions are welcome: bug fixes, new detection families, docs and tests. Read [CONTRIBUTING.md](CONTRIBUTING.md) first. Contributions are accepted under section 6 of the [LICENSE](LICENSE).

## Licence

**All rights reserved.** Exposure Desk is proprietary, not open source. The code is public so it can be read. It may not be used, run, copied, modified, redistributed or used to train AI models without the author's prior written permission. The only exceptions are viewing and forking on GitHub as GitHub's Terms require, running a local copy to report a vulnerability under [SECURITY.md](SECURITY.md), and running a local copy to prepare a contribution under [CONTRIBUTING.md](CONTRIBUTING.md). See [LICENSE](LICENSE). The software comes **as is, without any warranty**.

Third-party components keep their own licences. They are listed in [THIRD_PARTY.md](THIRD_PARTY.md) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

Product and company names (for example GitHub, Stripe, OpenAI or AWS) are trademarks of their owners. They are used only to describe which credential formats are detected. Exposure Desk is not affiliated with, endorsed by or sponsored by any of them.
