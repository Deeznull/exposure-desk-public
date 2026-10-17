# Security policy

Exposure Desk handles secrets found on websites, so problems in the tool itself matter. Thank you for reporting them privately.

## Reporting a vulnerability

- **Contact:** use GitHub's private vulnerability reporting: open the repository's **Security** tab and click **Report a vulnerability**. Do not open a public issue for a security problem.
- **Response:** this is a small project maintained on a best-effort basis. We aim to acknowledge a report within 7 days and to share a first assessment within 30 days.
- **What to include:** the Exposure Desk version and build id (the `version` and `id` fields of `BUILD_INFO.json` in the installation folder; the dashboard also shows the build on each scan), the operating system, exact steps to reproduce, and what you expected instead.
- **Do not include real secrets.** If a report needs a secret-looking value, use a synthetic one or at most a short masked prefix. Never send a live credential, a full-value (sensitive) export or a vault file.
- Please give us reasonable time to fix the issue before you disclose it publicly: 90 days from your report, or earlier once a fix is released.
- **Good-faith research.** Section 3 of [LICENSE](LICENSE) lets you build and run a local copy of Exposure Desk only to find and privately report vulnerabilities in it. Research that stays within that permission and follows this policy is welcome, and we will not pursue legal action over it. This covers only Exposure Desk itself, not any website, service or system of anyone else.

We don't offer paid rewards for reports about Exposure Desk itself.

## Supported versions

| Version | Supported |
| --- | --- |
| 2.9.1 | Yes: current release |
| 2.9.0 | No: superseded by 2.9.1 (saved data loads unchanged) |
| 2.8.0 | No: superseded by 2.9.0 (saved data loads unchanged; see [MIGRATION_2.9.md](MIGRATION_2.9.md)) |
| 2.7.0 | No: superseded by 2.8.0 (saved data loads unchanged; see [MIGRATION_2.8.md](MIGRATION_2.8.md)) |
| 2.6.0 | No: superseded by 2.7.0 (saved data loads unchanged; see [MIGRATION_2.7.md](MIGRATION_2.7.md)) |
| 2.6.0-rc.1 | No: superseded by 2.6.0 |
| 2.5.0-rc.1 and older | No: upgrade to 2.9.1 (saved data loads tolerantly; see [MIGRATION_2.6.md](MIGRATION_2.6.md), [MIGRATION_2.7.md](MIGRATION_2.7.md), [MIGRATION_2.8.md](MIGRATION_2.8.md) and [MIGRATION_2.9.md](MIGRATION_2.9.md)) |

Security fixes are made on the newest release only.

## Scope

In scope: the Exposure Desk application as shipped in the release packages, that is the dashboard, the CLI, the scanner and its transport and browser guards, the vault, reports and exports, the launch scripts and the packaging. Examples of issues we want to hear about:

- reaching the dashboard from another machine or another local user, or bypassing the launch token, CSRF protection, the Content Security Policy or the Host/Origin checks;
- a scan sending any request outside the scope the user entered, or to a private, cloud-metadata or protected (government, military, intelligence or law-enforcement) host;
- a found secret being sent anywhere, written unmasked to history, logs, checkpoints or a default export, or shown without the deliberate reveal action;
- weaknesses in the vault encryption or in the per-project HMAC correlation key;
- local artifact mode reading files outside the directory the user supplied (for example through links or junctions).

Out of scope:

- vulnerabilities in third-party components themselves (Node.js, Chrome for Testing, Playwright, Gitleaks, npm packages): please report them upstream, unless the way Exposure Desk uses the component causes the problem;
- secrets or weaknesses on websites you scanned with Exposure Desk: report those to that website's owner;
- detection gaps (a secret format that is not found): these are welcome as ordinary feedback, see [DETECTOR_COVERAGE.md](DETECTOR_COVERAGE.md);
- attacks that already require full control of the user's account or machine.

The security model is described in [README.md](docs/REFERENCE.md#security-model). How data is stored and what leaves the computer is in [PRIVACY.md](PRIVACY.md); permitted use is in [ACCEPTABLE_USE.md](ACCEPTABLE_USE.md).
