<div align="center">

# Exposure Desk

**Find the API keys and secrets a website is leaking before someone else does.**

A local, privacy-first scanner for site owners and bug bounty hunters. It looks at a site the way an anonymous visitor would.

![version 2.9.1](https://img.shields.io/badge/version-2.9.1-0f5f5c)
![Windows x64 | Linux x64](https://img.shields.io/badge/platform-Windows%20x64%20%7C%20Linux%20x64-555)
![Node 24](https://img.shields.io/badge/node-24-555)
![licence: all rights reserved](https://img.shields.io/badge/licence-all%20rights%20reserved-a33)

</div>

<p align="center"><img src="docs/screenshots/3-findings.png" width="560" alt="Findings view: grouped by provider with priority, masked value and reveal controls"></p>

## Who it's for

- **Site owners and developers:** catch a leaked key before an attacker does, and check a build folder offline before you deploy.
- **Bug bounty hunters:** load a program's scope, work through a target list politely and turn a finding into a submission draft, without ever using the key.

## Features

- 🔎 **Deep discovery.** HTML, scripts and lazy chunks, source maps (with embedded sources), JSON and config files, framework manifests, well-known deployment paths, and pages rendered in an isolated browser.
- 🧠 **Wide detection.** 88 detection families with test evidence: AI, cloud, payment, messaging, DNS and deployment providers, wallet seed phrases, private keys, signing secrets and passwords in connection URLs. A pinned, offline Gitleaks engine adds its rule catalogue. Placeholders such as `${VAR}` are filtered out. See [DETECTOR_COVERAGE.md](docs/DETECTOR_COVERAGE.md).
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

## Requirements and capacity

### What you need

| | |
| --- | --- |
| **System** | Windows x64 or Linux x64. A source build needs Node.js 24. |
| **Disk space** | About **650 MB** for the full Windows package: isolated browser 432 MB, bundled Node.js runtime 101 MB, dependencies 61 MB, Gitleaks engine 22 MB. A source checkout needs about 70 MB of dependencies; the browser and Gitleaks are optional downloads from **Settings**. Keep about **1 GB** free. |
| **Saved scans** | A few hundred KB per scan on the test sites; bigger sites with more findings take more. History keeps the newest 100 scans and nothing older than 90 days by default (changeable in **Settings**). |
| **Memory** | About **2 GB of free RAM** is comfortable. The scan process stays under 512 MiB and analysis uses 256 or 512 MiB; the isolated browser comes on top. With under 4 cores or about 2 GiB free memory, the scan lowers its own workers automatically. |

### How many websites at once, and how long

Each ready option fixes how many websites run at once and how long each one may take. Further websites wait for a free slot.

| Option | Websites at once | Of those in the browser | Pace per website | Time limit per website |
| --- | --- | --- | --- | --- |
| Quick check + Normal | 6 | none | about 2 requests/s | 2 min |
| Quick check + Low-impact | 2 | none | about 0.5 requests/s | 8 min |
| **Standard + Normal (Recommended)** | 4 | 2 | about 2 requests/s | 5 min |
| Standard + Low-impact | 2 | 1 | about 0.5 requests/s | 20 min |
| Deep audit + Normal | 3 | 2 | about 2 requests/s | 60 min |
| Deep audit + Low-impact | 2 | 1 | about 0.5 requests/s | 60 min |

**Measured times for one small website** (local test site, one Windows laptop):

| | Quick check | Standard | Deep audit |
| --- | --- | --- | --- |
| Normal | 14 s | 42 s | 87 s |
| Low-impact | 49 s | 77 s | 106 s |

Real websites take longer the more pages and scripts they have and the slower they answer; the time limit above caps each website. Before a scan starts, the dashboard shows how many websites will run at once and an estimate of the total time.

**Target lists from the command line** (`--targets`): `--concurrency N` runs up to **16** targets at once, or up to **64** with a program file. There is no fixed limit on the length of the list, and `--state` resumes an interrupted run. Measured with 200 Quick check targets on local test sites:

| Targets at once | 1 | 4 | 16 | 64 (program file) |
| --- | --- | --- | --- | --- |
| Total time for 200 targets | 37 min | 10 min | 3.5 min | 2.9 min |
| Peak memory of the scan process | 204 MiB | 309 MiB | 329 MiB | 357 MiB |

All these timings come from one computer and local test sites. Full figures are in [TEST_RESULTS.md](docs/TEST_RESULTS.md) and [REFERENCE.md](docs/REFERENCE.md#ready-scan-options).

## Quick start

> **Permission required.** This repository is published for viewing only. Running, building or copying Exposure Desk needs prior written permission from the author (see [LICENSE](LICENSE)). The steps below are for people who have it, and for contributors testing a change under [CONTRIBUTING.md](docs/CONTRIBUTING.md).

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

Windows x64 and Linux x64 packages and a container image are described in [RELEASE_PACKAGE.md](docs/RELEASE_PACKAGE.md) and [docs/LINUX.md](docs/LINUX.md).

## Screenshots

All screenshots show a synthetic demo shop served by the built-in fixture on `127.0.0.1`. No real website was scanned.

| | |
| --- | --- |
| ![Start a scan](docs/screenshots/1-new-scan.png) | ![A running scan](docs/screenshots/2-running.png) |
| **Start a scan:** six ready options with an estimate before anything is sent. | **Running scan:** live counters and coverage. |
| ![HTML report](docs/screenshots/4-report.png) | ![A government site is refused](docs/screenshots/5-protected-refused.png) |
| **Report:** a masked export by default. | **Protected hosts:** refused before any DNS lookup. |

## Repository layout

| Folder | Contents |
| --- | --- |
| [`src/`](src) | Scanner, detectors, dashboard server and CLI |
| [`public/`](public) | Dashboard front end |
| [`rules/`](rules) | Pinned detection rules and their licences |
| [`test/`](test) | Tests and the local fixture sites they scan |
| [`scripts/`](scripts) | Build, packaging, launch and benchmark scripts |
| [`docs/`](docs) | Guides, policies and third-party notices; release notes in [`docs/releases/`](docs/releases) |
| [`examples/`](examples) | Example scan configurations |
| [`benchmarks/`](benchmarks) · [`reports/`](reports) | Measured results per release · sample reports from the fixture |

## Documentation

- [User guide](docs/USER_GUIDE.md): dashboard, scan options, findings, CLI and the bug bounty workflow
- [Overview and reference](docs/REFERENCE.md): every feature, measured results, limitations and the technical reference
- [Program files](docs/PROGRAM.md) · [Target lists](docs/MASS_SCAN.md) · [Recon](docs/RECON.md) · [Submissions](docs/SUBMISSION.md) · [JSON Lines](docs/JSONL.md) · [Linux](docs/LINUX.md)
- [Changelog 2.9.1](docs/releases/CHANGELOG_2.9.1.md) · [Test results](docs/TEST_RESULTS.md) · [Demo script](docs/DEMO.md)

## Status

Version 2.9.1. Verified with local test fixtures and synthetic, non-functional keys on Windows x64 and on GitHub-hosted Ubuntu runners. It has not yet been benchmarked on real websites, and macOS and ARM are not supported. See [limitations](docs/REFERENCE.md#limitations).

## Responsible use

Exposure Desk is for websites **you own or are explicitly authorized to assess**, such as assets listed in scope by a bug bounty program. Follow the program's rules: stay in scope, respect its rate limits and its rules on automated scanning, and never use a key you find. Scanning systems without permission may be illegal where you or the website are. You are solely responsible for how you use it. Read [ACCEPTABLE_USE.md](docs/ACCEPTABLE_USE.md) before your first scan.

If you find a secret on someone else's site through an authorized program, report it to the owner. Do not use it. To report a vulnerability in Exposure Desk itself, see [SECURITY.md](docs/SECURITY.md). What the program stores and sends is described in [PRIVACY.md](docs/PRIVACY.md).

## Contributing

Contributions are welcome: bug fixes, new detection families, docs and tests. Read [CONTRIBUTING.md](docs/CONTRIBUTING.md) first. Contributions are accepted under section 6 of the [LICENSE](LICENSE).

## Licence

**All rights reserved.** Exposure Desk is proprietary, not open source. The code is public so it can be read. It may not be used, run, copied, modified, redistributed or used to train AI models without the author's prior written permission. The only exceptions are viewing and forking on GitHub as GitHub's Terms require, running a local copy to report a vulnerability under [SECURITY.md](docs/SECURITY.md), and running a local copy to prepare a contribution under [CONTRIBUTING.md](docs/CONTRIBUTING.md). See [LICENSE](LICENSE). The software comes **as is, without any warranty**.

Third-party components keep their own licences. They are listed in [THIRD_PARTY.md](docs/THIRD_PARTY.md) and [THIRD_PARTY_NOTICES.md](docs/THIRD_PARTY_NOTICES.md).

Product and company names (for example GitHub, Stripe, OpenAI or AWS) are trademarks of their owners. They are used only to describe which credential formats are detected. Exposure Desk is not affiliated with, endorsed by or sponsored by any of them.
