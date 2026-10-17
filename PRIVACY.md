# Privacy

Exposure Desk is a local program. It has no account, no cloud service, no telemetry, no analytics, no crash reporting, no update check, no remote AI model and no report upload. Nobody, including the publisher, receives your scans, findings or settings. This page explains what the program stores on your computer, where it stores it, and which network connections it makes.

Exposure Desk is published by its author on GitHub ([Deeznull](https://github.com/Deeznull)). This page covers only the program. The repository does not collect personal data; GitHub's own privacy statement applies to anything you post on GitHub, such as issues.

## Where data is stored

All saved data lives in one data folder that only your user account can open (permissions 0700; on Windows an access-control list limited to your account).

| System | Default data folder |
| --- | --- |
| Windows | `%LOCALAPPDATA%\Exposure Desk`; if `LOCALAPPDATA` is not set, `AppData\Local\Exposure Desk` in your home folder (an older `Exposure Desk` folder directly in your home folder that already holds data keeps being used) |
| Linux (untested) | `$XDG_DATA_HOME/exposure-desk`, normally `~/.local/share/exposure-desk` |
| macOS | not supported yet; the code would use the Linux location |

Set the `EXPOSURE_DATA_DIR` environment variable to an absolute path before launch to use another folder you own. The dashboard shows the folder in **Settings**.

## What is stored

| Item | Contents |
| --- | --- |
| `workspace.json` | Projects (website addresses and scan settings), finding reviews and notes, settings, custom rules and their versions, and alerts. Alerts show masked values only. |
| `scans/` | One file per scan in your history. Secret values are replaced by `[redacted: N characters]` before the file is written. A history entry still contains the scanned addresses, the request and coverage records, and short text excerpts (about 100 characters on each side of a finding) with the secret removed. |
| `keys/` | A random 32-byte key per project, used to recognise the same secret across scans (an HMAC fingerprint) without storing the value. |
| `vault/` | Only if you create the vault. Full secret values that you deliberately save there (see below). |
| `tmp/` | Temporary browser profiles and detector files while a scan runs. |
| `tools/`, `browser/` | The Gitleaks detector and the Chromium browser, if you install them from **Settings**. The Windows package ships both inside the program folder instead. |
| `triggers/` | Queued deployment-trigger requests created with the CLI `trigger` command; they expire after 24 hours. |
| `instance.json` | While the dashboard runs: its process id, local address, build and the per-launch sign-in token. It is deleted when the dashboard shuts down normally. |
| `company-rules.json`, `diagnostic-results.json` | Imported company rules and the result of the last self-test from **Settings**, if you use those features. |
| `application-<version>/`, `npm-cache/` | Only for the source package on first launch: the locked npm dependencies (see "Network connections"). |

The program writes no log files. The console window shows the build, the dashboard address, the sign-in token and, for CLI scans, the run id, scope and origins.

## Secret values

- **Masked by default.** Findings, history, alerts, default exports and reports show a secret as `[redacted: N characters]` or a short masked prefix. A deliberate **Reveal** in the dashboard shows one value and masks it again after 30 seconds.
- **Not validated during a scan.** No scan ever sends a found credential to its provider; while scanning, any request that would carry a credential is refused before any DNS lookup, and findings are marked "validity not established". Exposure Desk can check whether one found key is still accepted by its own provider only when a person explicitly starts a per-finding live key check — off by default, enabled per program, one key at a time, header-only, to that provider's official read-only identity endpoint. It never signs in, never writes and never triggers paid usage, and the verdict does not change "validity not established". Many programs forbid using found credentials at all; read the program rules first. See [docs/LIVE_KEY_CHECK.md](docs/LIVE_KEY_CHECK.md).
- **Vault (optional).** The vault stores full values only after you unlock it and confirm each save. Values are encrypted with AES-256-GCM. The key is derived from your vault password (12 to 1024 characters) with scrypt (N = 131072, r = 8, p = 1). The password is not stored anywhere and **cannot be recovered**: if you forget it, the vault contents are lost. The vault locks itself after 5 minutes of inactivity by default (adjustable from 1 to 60 minutes).
- **Full-value exports.** A `.sensitive` export is created only after an explicit confirmation in the dashboard, or with `--full-secrets` on the CLI. It is a **plain, unencrypted** file that contains the real secrets. It is created as a new file (never overwriting one), readable only by your account. Store it like a password file and delete it when you no longer need it.

## Retention and deletion

- History keeps the newest 100 scans and nothing older than 90 days by default. You can change this in **Settings** (1 to 3650 days, 1 to 1000 scans). Limits are applied when the program starts, after every saved scan and when you change the setting.
- In the dashboard you can delete a single scan, a whole project, or the vault (each after a confirmation).
- Each scan's browser profile and detector files are deleted when the scan ends. Profiles left behind by a crash are removed on the next start (or by `cli cleanup`) once their process has gone or they are older than 24 hours.
- Deleting is an ordinary file deletion, not a secure wipe. To remove everything, stop Exposure Desk and delete the data folder; the program never makes copies elsewhere. Exports you saved yourself (for example in Downloads) are yours to delete.

## Network connections

**During a scan** Exposure Desk sends requests only to the website addresses you entered and to hosts inside the scope you chose. It identifies itself with an honest product user agent, respects per-website rate limits and ignores system proxy settings. Host names are resolved with your operating system's resolver. Private, internal and cloud-metadata addresses are refused, including when a public name resolves to one. Government, military, intelligence and law-enforcement hosts are refused before any DNS lookup, with no override.

**The scanning browser** (Chromium) cannot resolve or reach any host by itself: every request goes through Exposure Desk's own guarded network layer, which applies the same scope and blocks. Background networking, component updates, sync, crash reporting, translation, phishing-detection lookups, extensions, service workers and downloads are disabled or blocked for the scan profile.

**Other connections, all started by you:**

| When | Destination | Why |
| --- | --- | --- |
| Source package, first launch only | the npm registry | installs the locked dependencies from `package-lock.json` (not needed for the Windows package, which includes them) |
| Source launcher on Windows, only if no compatible Node.js is installed | nodejs.org | downloads the official Node.js 24.18.1 archive and checks its SHA-256 |
| **Settings → install the detector** | github.com (Gitleaks releases) | downloads Gitleaks 8.30.1 and checks its SHA-256 |
| **Settings → install the browser** | Playwright's browser download servers | downloads Chromium with Playwright's official installer |

Gitleaks runs as a local process with a pinned configuration and reads the scanned text from its standard input; Exposure Desk does not send anything to it over the network. Report formats such as SARIF contain public schema addresses as plain text; opening a report does not contact them.

## The local dashboard

The dashboard listens on `127.0.0.1` only and cannot be reached from other computers. Signing in needs the per-launch token shown in the launch window; sessions use an HttpOnly, SameSite=Strict cookie, every change needs a CSRF token, and requests with an unexpected Host, Origin or cross-site fetch are refused. The Content Security Policy allows only the program's own scripts. One unauthenticated address, `/health`, returns the application name, the launch instance nonce and the build so the launcher can find a running instance; it returns no scan data.

## Questions

Questions about this page: open an issue in the repository (do not include secrets or scan results). Security problems in Exposure Desk itself: see [SECURITY.md](SECURITY.md). Permitted use: see [ACCEPTABLE_USE.md](ACCEPTABLE_USE.md).
