# Contributing to Exposure Desk

Thank you for helping. Bug fixes, new detection families, better remediation text, documentation and tests are all welcome.

## Before you start

- **Security problems in Exposure Desk itself** go through [SECURITY.md](SECURITY.md), never a public issue or pull request.
- For anything bigger than a small fix, open an issue first so we can agree on the approach.
- Exposure Desk stays a defensive tool for sites the user owns or is authorized to test. Changes that add stealth, evasion, proxy rotation, spoofed User-Agents, CAPTCHA bypass or a way around the protected-host refusal will not be accepted.

## What the licence lets you do

Exposure Desk is not open source (see [LICENSE](LICENSE)). Section 3 lets you build, run and modify a local copy **only to prepare, test and submit a contribution** to this repository. That covers running the test suite and the built-in fixtures on your own machine. It does not cover scanning real websites, publishing a modified version or using the code elsewhere.

By opening a pull request or issue you agree to section 6 of the licence. In short:

- You keep the copyright in your contribution and give the author a permanent, royalty-free licence to use, change and relicense it, including under a future open-source or commercial licence.
- You confirm the work is yours to give (with your employer's permission if they have rights in it).
- You are not paid for it, and the author may change or decline it.

## Development setup

You need Node.js 24 on Windows x64 or Linux x64.

```sh
npm ci
npm run build
npm run check   # type check
npm test        # unit and integration tests on local fixtures
```

`npm run setup:gitleaks` installs the pinned Gitleaks engine that part of the suite uses, and `npm run setup:browser` installs the isolated browser for `npm run test:browser`.

## Rules for test data

- **Never commit a real secret**, not even a revoked one. Use synthetic, non-functional values that only match the format.
- If a synthetic value still looks real enough for GitHub push protection to block it, build it from parts in the test (for example `'sk-proj-'+'...'`) and say so in a comment.
- Tests must only talk to the loopback fixtures in `test/` and `src/fixture.ts`. No real domains, IP addresses or third-party services, except reserved names such as `example.com`, `*.test` and `*.invalid`.
- Keep personal data out: no real names, emails, local paths or machine details in code, tests, logs or benchmark records.

## New detection families

Each new provider or credential format needs:

1. the pattern, with a placeholder filter so values such as `${VAR}` or `your-key-here` are ignored;
2. positive and negative test evidence with synthetic values;
3. a priority, an impact line and provider-specific remediation steps;
4. an entry in [DETECTOR_COVERAGE.md](DETECTOR_COVERAGE.md).

Patterns adapted from another project must keep that project's licence notice and be listed in [THIRD_PARTY.md](THIRD_PARTY.md). Copy only from projects whose licence allows it.

## Pull requests

- Keep each pull request to one change, with a clear description of what and why.
- `npm run check` and `npm test` pass locally. The Linux workflow runs on every pull request; first-time contributors wait for a maintainer to approve the run.
- Update the user-facing docs when behaviour changes.
- Match the surrounding code style. There is no separate formatter.

This is a small project maintained on a best-effort basis, so reviews can take a while.
