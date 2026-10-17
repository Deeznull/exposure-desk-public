<div align="center">

# Exposure Desk

Finds API keys and other secrets that a website exposes to the public.<br>
Runs on your own computer. For site owners and bug bounty hunters.

![version 2.9.1](https://img.shields.io/badge/version-2.9.1-0f5f5c)
![Windows x64 | Linux x64](https://img.shields.io/badge/platform-Windows%20x64%20%7C%20Linux%20x64-555)
![Node 24](https://img.shields.io/badge/node-24-555)
![licence: all rights reserved](https://img.shields.io/badge/licence-all%20rights%20reserved-a33)

</div>

## Screenshots

Taken on the built-in demo shop (`127.0.0.1`) with fake keys.

<p align="center"><img src="docs/screenshots/3-findings.png" width="560" alt="Findings grouped by provider, with priority and masked values"></p>

| | | |
| --- | --- | --- |
| ![New scan](docs/screenshots/1-new-scan.png) | ![Running scan](docs/screenshots/2-running.png) | ![HTML report](docs/screenshots/4-report.png) |
| New scan | Running scan | HTML report |

## How a scan works

1. Enter one or more website addresses. On the command line you can also pass a file with a list of targets.
2. Pick how much to check and how fast:
   - **Quick check:** the start page, its scripts and source maps, and a few known files.
   - **Standard** (default): follows links 3 levels deep and opens a few pages in a built-in browser.
   - **Deep audit:** 5 levels deep, more browser pages, more files.
   - **Normal** traffic sends about 2 requests per second per website. **Low-impact** sends about 0.5 over one connection.
3. Exposure Desk downloads what any visitor could see: HTML, JavaScript, source maps, JSON and config files, and common deployment paths.
4. Every file is checked with 88 built-in detectors and the Gitleaks rule set.
5. Each finding shows the provider, where it was found (traced back through source maps), its priority and how to fix it. Values are masked until you reveal them.
6. Export the results as JSON, HTML or SARIF.

Scans never use a key they find. You can also check a local build folder before you deploy it, without sending any requests.

## Scan times

Measured on one Windows laptop against small local test sites:

| Websites | Quick check | Standard | Deep audit |
| --- | --- | --- | --- |
| 1 | 14 s | 42 s | 1.5 min |
| 10 | 32 s | 4 min | 4 min |
| 1, Low-impact | 49 s | 1.3 min | 1.8 min |
| 10, Low-impact | 4.4 min | 7 min | 10 min |

| Option | Websites at once | Time limit per website |
| --- | --- | --- |
| Quick check | 6 (Low-impact: 2) | 2 min (Low-impact: 8 min) |
| Standard | 4 (Low-impact: 2) | 5 min (Low-impact: 20 min) |
| Deep audit | 3 (Low-impact: 2) | 60 min |

Bigger sites take longer, up to the time limit per website. Extra websites wait for a free slot. Before a scan starts, the dashboard shows an estimate.

## Mass scan

Scan a list of websites from the command line. Put one host name or URL per line in a file (httpx output works too):

```sh
node dist/src/cli.js scan --targets hosts.txt --authorized --concurrency 16 --coverage quick --state run.state
```

- `--concurrency` sets how many websites run at once: up to 16, or up to 64 with a bug bounty [program file](docs/PROGRAM.md). Without it, websites run one at a time (4 at a time with a program file).
- There is no limit on the length of the list.
- `--state` saves progress. Run the same command again after a stop and it skips the websites that are done.
- Each website gets its own report in `reports/`. A key found on several websites is listed once in the summary.
- A website that keeps blocking the scan (for example with 403, 429 or a CAPTCHA page) is stopped, and the run moves on.
- `--authorized` is required for a list. It confirms you may test every website in it.

Measured times (one Windows laptop, local test sites):

| Websites | Option | 1 at once | 4 at once | 16 at once | 64 at once |
| --- | --- | --- | --- | --- | --- |
| 200 | Quick check | 38.5 min | 9.9 min | 3.2 min | 2.9 min |
| 16, each with a 1.25 MB script | Standard | 4.2 min | 1.7 min | 1 min | — |

At 16 or more at once, Quick check gets through about 1 website per second, so 1,000 small websites take roughly 16 minutes. Real websites are bigger and slower than the test sites, so expect longer.

## Requirements

- Windows x64 or Linux x64. Building from source needs Node.js 24.
- About 650 MB of disk space with the built-in browser and Gitleaks, or about 70 MB without them. Each saved scan takes a few hundred KB.
- About 2 GB of free RAM. A scan uses up to about 750 MB, plus the browser.

## Install and run

Running Exposure Desk needs the author's written permission (see [LICENSE](LICENSE)).

```sh
npm ci
npm run build
npm run launch
```

This opens the dashboard in your browser. Paste the token shown in the terminal, then open **New scan**. Install the built-in browser and Gitleaks from **Settings**.

Windows and Linux packages and a container image: see [RELEASE_PACKAGE.md](docs/RELEASE_PACKAGE.md) and [LINUX.md](docs/LINUX.md).

## Command line

```sh
node dist/src/cli.js scan --url https://www.example.com/ --output reports/site.json
node dist/src/cli.js scan --url https://www.example.com/ --coverage quick --traffic low-impact --format sarif --output reports/site.sarif
node dist/src/cli.js artifacts --directory build
```

Exit code `0` means no secrets were found, `1` means some were, and `2` means the scan failed or did not finish.

## Docs

[User guide](docs/USER_GUIDE.md) · [Reference](docs/REFERENCE.md) · [Bug bounty quick start](docs/REFERENCE.md#bug-bounty-quick-start) · [Mass scan](docs/MASS_SCAN.md) · [Program files](docs/PROGRAM.md) · [Detectors](docs/DETECTOR_COVERAGE.md) · [Test results](docs/TEST_RESULTS.md) · [Changelog](docs/releases/CHANGELOG_2.9.1.md)

## Allowed use

Only scan websites you own or are allowed to test, such as assets in a bug bounty program's scope. Read [ACCEPTABLE_USE.md](docs/ACCEPTABLE_USE.md). To report a bug in Exposure Desk itself, see [SECURITY.md](docs/SECURITY.md).

## Contributing

Pull requests are welcome. See [CONTRIBUTING.md](docs/CONTRIBUTING.md).

## Licence

All rights reserved. The code is public to read, but using, copying or redistributing it needs the author's written permission. See [LICENSE](LICENSE). Third-party components keep their own licences ([THIRD_PARTY.md](docs/THIRD_PARTY.md)). Product names such as Stripe or AWS belong to their owners and only describe which key formats are detected.
