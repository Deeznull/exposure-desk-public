# Exposure Desk user guide (2.9.1)

Exposure Desk checks websites you own or are authorized to assess for secrets they expose to anonymous visitors. Everything runs on this computer: scans never send found keys to their providers (only the opt-in [live key check](#live-key-check-290) does, for one finding a person chooses), and findings, history and the optional vault stay in the local data folder. For an overview, the safety model and measured results, see [README.md](README.md).

## Start here

1. **Start the app.** Extract the Windows x64 ZIP and double-click **Start Exposure Desk.cmd**. Keep the launch window open. The dashboard opens in your default browser; paste the token from the launch window into **Launch token** and click **Open workspace**. On Linux or in a container, see [Linux and Docker](#linux-and-docker).
2. **Check this computer.** Open **Settings** and click **Run full-pipeline self-test**. It uses local synthetic fixtures only and shows every expected case. Settings also names any missing prerequisite or storage problem, with a repair action.
3. **Start a scan.** Open **New scan**, enter the website, keep **Standard + Normal (Recommended)**, keep the default scope (*This domain and its subdomains*), confirm that you own the website or are authorized to assess it, and click **Start scan**.
4. **Watch it run.** **Running scan** shows progress, what each website can see, anything lowered for this computer and, at the end, whether coverage is complete.
5. **Act on findings.** **Findings** are sorted by priority. Open each one for its location, evidence and remediation steps, rotate or revoke the key with its provider, remove it from the website, then record the result and scan again.

Contents of this guide:

- [Hard rule: protected hosts](#hard-rule-protected-hosts): websites Exposure Desk never contacts.
- [Ready scan options in 2.6](#ready-scan-options-in-26): the six options, automatic adjustment, ceilings and older projects.
- [Command line: target lists and JSON Lines (2.7.0)](#command-line-target-lists-and-json-lines-270): scanning a list of targets, `--authorized`, JSON Lines and finding IDs.
- [Bug bounty workflow (2.8.0)](#bug-bounty-workflow-280): program files and scope rules, mass scan and resume, recon lists, submission Markdown, recon downloads in the dashboard, Linux and Docker, and analysis time on slow machines.
- [Live key check (2.9.0)](#live-key-check-290): the opt-in check of one found key, off by default.
- [Detection-quality update in 2.6.0](#detection-quality-update-in-260): what 2.6.0 detects differently from 2.6.0-rc.1.
- [Scope, findings, alerts and triggers (2.5)](#new-controls-in-25).
- [Allocations, feedback and suppressions (2.4)](#controls-added-in-24) and [evidence paths (2.3)](#current-23-controls).
- [Basic workflow](#basic-workflow), [reliability and retries](#reliability-repair-in-231), [Exhaustive coverage](#exhaustive-and-origin-coverage) and [automatic domain discovery](#automatic-domain-discovery-and-finding-assessment).

# Hard rule: protected hosts

Exposure Desk never scans government, military, intelligence or security-service, law-enforcement, judiciary or intergovernmental-organization websites. **Nothing can turn this off.** There is no configuration key, CLI flag, environment variable, saved-project field, preset, profile or dashboard control for it.

**What is blocked.** A host is protected when it is, or is a subdomain of, an entry in the built-in reviewed list:

- **Top-level domains:** .gov, .mil, .int (treaty organizations such as UN agencies, NATO and Interpol), .va, .cern and .政务.
- **Country zones:** national, state, provincial and local government, military, police, court and parliament zones, such as:
  - gov.uk, police.uk, mod.uk, gouv.fr, gob.mx, gov.br, jus.br, gv.at, go.jp, lg.jp, govt.nz, gc.ca, gov.au, gov.in and nic.in;
  - state.<state>.us, and city, county, town and village names under a US state (for example ci.<city>.<state>.us);
  - Japanese prefecture and municipal names (pref.<prefecture>.jp, city.<city>.<prefecture>.jp).
- **Well-known bodies on ordinary domains**, grouped by country and organization. Examples: europa.eu, un.org and other UN, financial and treaty organizations, canada.ca, bund.de, admin.ch and the Swiss cantons, kremlin.ru, and presidencies, governments, parliaments, courts, police and intelligence services, armed forces, election bodies and central banks.
- **Safety net:** any gov, govt, gouv, gob, gub, mil or 政府 zone that the bundled public-suffix data lists directly under a country domain.

Names are compared after normalization: letter case, Unicode or punycode spelling, trailing dots, port and user name make no difference. A name that merely contains "gov" or "mil" is not blocked, for example gov.example.com, mygov-shop.com or mil.example.org. Ordinary names under shared suffixes such as co.uk or go.it (Gorizia) are not blocked either.

**What happens.**

- **Protected website or seed:** the whole scan is refused with "Exposure Desk never scans government, military, intelligence or law-enforcement websites: <host>". The CLI exits with code 2, and the dashboard shows the message. This also covers extra seeds, related or private origins, browser navigation URLs, read-only POST endpoints, stale-asset URLs, imported configuration files, checkpoints and deployment-trigger assets.
- **Saved projects, queued scans, schedules and deployment triggers:** if one names a protected host, it shows **Never runs** with the reason and is never queued, scheduled or triggered. Its stored record is left exactly as it was. Edit the project to remove the host, or delete it.
- **During a scan:** links, redirects, assets, images, sitemaps, source maps, WebSockets and browser requests to a protected host are skipped before any DNS lookup or connection. The report lists them as "refused (never scanned)" with a count. Like out-of-scope origins, they do not make the scan incomplete.
- **Discovered URL with an invalid host:** a link, script, source map, redirect target or browser subrequest whose host is not a valid website host is refused before any DNS lookup and listed with the reason `invalid-url`. Since 2.9.1 this is informational: it is still shown in the report and the resource audit, but it does not make the scan incomplete or lower its coverage assessment. A page the scan was already fetching that redirects to such a host still stays a gap, like a redirect out of scope. Runs saved by 2.9.0 keep the incomplete state they were saved with.

**Known limits.**

- **The list is not exhaustive.** A public body on an ordinary domain that is not listed (for example a small agency on a .com, .org or national domain) is not recognized. The list grows only in code, through a reviewed update.
- **Bare IP addresses are not matched.** The rule recognizes names, not who owns an address.
- **No DNS-alias inspection.** A hostname that is a CNAME alias of a government service is not recognized by its name, because the scanner looks up addresses only. Over HTTPS, a server whose certificate names a protected host gets no request: the connection is closed right after the TLS handshake, before any request is sent. A plain-HTTP alias is not caught. The normal scope rules still limit a scan to the domains you entered.

# Ready scan options in 2.6

1. **New scan → Scan option**: pick one of six cards. Click a card, or use the arrow keys in the group; Tab moves on to the next control. Each card names the option, says in one line what it is for, and shows its own numbers.
   - **Standard + Normal** carries the **Recommended** mark and is selected for every new scan and project.
   - Coverage decides where the scan looks; Traffic decides how gently the websites are asked.

   | Option | Examines | Traffic per website | Websites at once | Browser websites at once | Analysis memory | Analysis workers | Download cap / website | Time allowance / website |
   | --- | --- | --- | --- | --- | --- | --- | --- | --- |
   | Quick check + Normal | Entry documents, their first-party scripts and source maps, build and web app manifests, robots.txt and high-value deployment paths. No browser and no crawl. | About 2 requests/s | 6 | none | 256 MiB | 1 | 40 MiB | 2 min |
   | Quick check + Low-impact | Same as Quick check + Normal | About 0.5 requests/s, one kept-alive connection | 2 | none | 256 MiB | 1 | 40 MiB | 8 min |
   | **Standard + Normal (Recommended)** | Static discovery to depth 3, deployment paths and a few isolated-browser pages | About 2 requests/s | 4 | 2 | 256 MiB | 2 | 120 MiB | 5 min |
   | Standard + Low-impact | Same as Standard + Normal, with fewer browser pages and no adjacent source-map guessing or extra query-string variants | About 0.5 requests/s, one kept-alive connection | 2 | 1 | 256 MiB | 2 | 120 MiB | 20 min |
   | Deep audit + Normal | Full static discovery (depth 5), browser routes with debugger capture, adjacent source maps, query variants and adaptive allocations | About 2 requests/s | 3 | 2 | 512 MiB | 2 | 300 MiB | 60 min |
   | Deep audit + Low-impact | Same as Deep audit + Normal, with fewer browser pages and no adjacent source-map guessing or extra query-string variants | About 0.5 requests/s, one kept-alive connection | 2 | 1 | 512 MiB | 2 | 300 MiB | 60 min |

   - Quick check ends as "completed — quick coverage"; that never means the site has no secrets.
   - Low-impact takes longer. It does not hide the scan: websites still see every request, this computer's IP address and the honest User-Agent.
   - **Limited by profile.** Low-impact visits one query-string variant per path (for example `/list?page=1` but not `/list?page=2`). That is the option's stated boundary, not an error. A Standard or Deep Low-impact scan whose only unvisited work is those variants ends as **completed** and is labelled "Limited by profile" in the run row, the report, the traffic and coverage lines, and CLI/JSON output. The label says how many variants were skipped and that the same coverage with Normal traffic visits them (up to 3 per path). No retry is offered for them. The skipped variants stay in the run data (and in a saved checkpoint), so a later Normal scan can use them.
   - A scan that is limited by profile **and** has a real gap (an error, a timeout, a cancellation, or a budget or variant limit that Normal traffic would also hit) stays **incomplete**, keeps "Retry important gaps" for the real gap, and also says "Also limited by profile". Runs saved before 2.6 keep the status they were saved with.
2. **The estimate line and What this option uses** (right column) update as you type the websites. Neither can be edited. To change the numbers, choose another option.
   - The estimate line reads, for example, "Standard + Normal (Recommended) · 10 websites · up to … requests · about … min at this pacing · 4 websites at once, adjusted for 10 websites".
   - The panel lists websites at once, browser websites at once, analysis memory and workers, requests per website and in total, the download cap, the time allowance, pages, browser pages, retries and discovered websites.
3. **Automatic adjustment is always on.** It only ever lowers values, never raises them, and never switches the option.
   - **Websites at once** never exceed the websites in scope. With domain or host-subtree scope, the panel adds "up to N once discovered websites are admitted". Further websites wait for a free slot, and a website's time allowance starts with its own first request.
   - **Shared caps and the time estimate** grow with the number of websites, within the hard ceilings.
   - **This computer:** at scan start Exposure Desk reads the logical cores and free memory.
     - Under 4 cores or about 2 GiB free memory, the scan uses 1 analysis worker and 1 browser website.
     - Analysis memory stays within a quarter of the free memory, and never below 64 MiB per worker.
     - Each lowered value appears as "(lowered from … for this computer)" in the panel, in the Running scan view and in the report under "Lowered for this computer". It is also kept in the scan record.
   - **Long scans:** if the estimate is over about 2 hours, a notice names the time and suggests Quick check. Nothing switches automatically.
4. **Ceilings that nothing can exceed:**
   - **512 MiB** analysis memory, for the parser workers and the engine's large-text workers together. Each runs in its own process: one that reaches its heap limit ends alone, and the scan continues with a stated limit. A large dependency group gets the whole ceiling and runs alone; other analysis waits for memory rather than going over.
   - 8 websites at once and 4 browser websites at once.
   - 12 requests at once and 20 requests/s.

   JSON specifications, CLI `--config` files, saved projects and scan starts with higher values are refused before any request. Low-impact never goes above its own limits: 0.5 requests/s and 1 request at once per website, 2 websites and 1 browser website at once, no retries, and one query variant.
5. **Projects from older versions** keep their stored numbers until you switch. They show as **Legacy preset: X**, as **Custom (from an older version)**, or, for a profile with its own numbers, as **Custom (based on …)**.
   - The card and the scan page show a banner with the closest ready option.
   - **Switch to …** switches the project with one click. Scope, seeds, routes, privacy settings, the authorization record and earlier runs stay unchanged.
   - **Choose another option…** opens the project on the scan page with the closest option focused.
   - On the scan page, **Restore …** undoes a switch until you reload the form.
   - History is never rewritten.
6. **Advanced** keeps the saved project and project name, extra seeds, related and private origins, the robots policy, browser navigation URLs (at most 10), read-only POST endpoints, sensitive-field expectations, stale asset URLs (and **Revisit exact assets from this project's last three scans**, on by default for Deep audit), request privacy (announced language, browser time zone, static User-Agent) and **Upload scan specifications (JSON, for power users)**. It has no rate, concurrency, page, byte, duration or preset fields: the ready option sets those.
   - A file with `coverage` and `traffic` and no numbers of its own loads as that option. The bundled examples `config.example.json`, `exact-origin.config.example.json` and `exhaustive.config.example.json` name ready options this way.
   - A file with its own numbers (for example `maxPages` or `sizingMode`, as in `adaptive.config.example.json`) loads as custom settings and is checked against the ceilings above.
7. **CLI:** `node dist/src/cli.js help` prints the same table.
   - A scan with no `--preset`, `--coverage`, `--traffic`, `--config` or checkpoint uses Standard + Normal (2.5 ran the legacy Thorough preset; `--preset thorough` keeps it).
   - The 2.5 flag `--sizing` keeps the 2.5 default.
   - Before scanning, the CLI prints a **Profile** line and a **Uses** line ("4 websites at once, adjusted for 10 websites · 2 with the isolated browser at once · 256 MiB analysis memory · 2 analysis workers. This computer: …").
   - A very long estimate adds a **Long scan** line.

# Command line: target lists and JSON Lines (2.7.0)

These options are for the command line only. The full reference, with an example, is in [README.md](docs/REFERENCE.md#target-lists-json-lines-and-finding-ids-270), and the event format is in [docs/JSONL.md](docs/JSONL.md).

1. **A list of targets.** `node dist/src/cli.js scan --targets hosts.txt` reads one host name, URL or httpx-style line per line; `--targets -` reads the list from standard input. Blank lines and `#` comments are skipped. By default targets are scanned one after another, each with its own report; since 2.8, `--concurrency N` runs several at once and `--state FILE` lets an interrupted list resume (see [Mass scan and resume](#mass-scan-and-resume)).
2. **Rejected lines.** Every line is checked against the [protected-host rule](#hard-rule-protected-hosts) before any request, with no override. A protected, invalid or duplicate line, or (with a program file) a line outside the program scope, is listed on standard error with its reason and the other lines continue. If no line is accepted, the command exits 2.
3. **Authorization.** If more than one target is accepted, add `--authorized`: it states that you own or are authorized to test every listed target. Without it the command exits 2 and nothing is requested. A single target, `--url` and `--config` do not need it, unless a program file applies: then every run needs `--authorized` or `"authorized": true` in the file (see [Program files and scope rules](#program-files-and-scope-rules)).
4. **Output.** Each finding prints a masked `Finding <id> · …` line. `--silent` keeps only results. `--jsonl` writes one JSON object per event to standard output, for another program to read, and moves the readable lines to standard error. Terminal and JSON Lines output are always masked.
5. **Finding IDs.** Each finding has a `findingId` that does not reveal the value; it is in the terminal line, the JSON, SARIF and HTML reports and the JSON Lines events. Without `--program` the IDs change with each run. `--program DIR` keeps a key in `DIR/.key` so the same value keeps the same ID across runs; keep that folder private.
6. **Stopping.** Ctrl+C stops the running target and starts no further target; the exit code is then 2.

# Bug bounty workflow (2.8.0)

These features are for researchers who test the assets of a bug bounty or disclosure program from the command line. The [README quick start](docs/REFERENCE.md#bug-bounty-quick-start) shows one complete run; each part below says what to do and links to the full reference. In the commands, `exposure-desk` stands for `node dist/src/cli.js` (`runtime/bin/node dist/src/cli.js` in the Linux package, `runtime\node.exe dist\src\cli.js` in the Windows package).

The hard rules apply unchanged. No program file, flag or setting can scan a [protected host](#hard-rule-protected-hosts), widen your authorization, send a found key anywhere or hide the scan. Masked by default everywhere: `--full-secrets` unmasks values only in report files written to disk; the terminal, JSON Lines and recon lists always stay masked.

## Program files and scope rules

1. **Create the file.** `exposure-desk program init DIR` writes a commented `DIR/program.json` template. `exposure-desk program import --platform hackerone-csv|bounty-targets --file FILE [--handle NAME] DIR` builds it from a scope file you downloaded yourself; nothing is fetched. Neither replaces an existing `program.json`, and the import never sets `"authorized": true`.
2. **Fill in the scope.** `scope.in` lists what you may test (at least one rule) and `scope.out` what you may not; out-of-scope rules always win. A rule is an exact host (`app.example.com`), a wildcard for subdomains (`*.example.com`, which does not include `example.com` itself), a URL prefix (`https://api.example.com/v1/`), an IP address or a CIDR block. Too-broad in-scope rules (such as `*.com`) and in-scope protected hosts are refused.
3. **Set the pace and identification.** `rate.requestsPerSecond` (default 5) and `concurrency.requests` (default 16) apply to the whole run, all targets together. `headers` takes up to 8 `X-…` identification headers the program asks for, sent only to in-scope URLs, and `userAgentSuffix` is appended to the honest User-Agent, never a replacement.
4. **Check it.** `exposure-desk program check DIR` validates the file and prints the effective scope, one rule per line. Every error is a refusal with exit 2, before any request.
5. **Scan with it.** `scan --program DIR` applies the scope, the pace and the headers. Target lines outside the scope are rejected as `out-of-scope`; links and redirects outside it are never requested and are listed in the report as excluded. With a program file, every run needs `--authorized` or `"authorized": true` in the file. A folder without `program.json` keeps the 2.7 meaning: it only holds the finding-ID key.

Full reference: [docs/PROGRAM.md](docs/PROGRAM.md).

## Mass scan and resume

1. **Several targets at once.** `--concurrency N` runs up to N targets of a `--targets` list at once: at most 16 without a program file, at most 64 with one. With a program file and two or more targets, its `concurrency.targets` (default 4) is the default; `--concurrency 1` keeps one at a time. All targets share one analysis budget and, with a program file, one request limiter. Measured on one Windows computer with 200 Quick check targets: 2272 s one at a time, 618 s at 4, 234 s at 16 and 206 s at 64 with a program file; every target completed at each setting, and the scan process stayed under 512 MiB (363 MiB at most). Above 1 at once a memory gate holds back the next target while the scan process is short of memory, so `--concurrency` is a maximum. With a program file, the program's request rate sets the pace. Run again with the same `--state` to finish targets that did not complete.
2. **Resume.** `--state FILE` records each target's progress in an owner-only run-state file. After an interruption, run the same command again: targets that completed are skipped and the others run again. If the target list or the run settings changed, the run is refused before any request. `--state` needs `--targets`.
3. **Blocks.** A target that keeps answering with bot challenges, 403, 429 or 503 responses, or connection resets is stopped as blocked (incomplete, exit 2). Nothing is retried around a block, and nothing about the requests changes. In a mass run, once at least 3 targets have finished and at least a quarter of them were blocked, no further target is started.
4. **The same exposure on several targets.** In a mass run, a finding already reported on an earlier target carries `duplicateOf` in JSON Lines, and the summary lists unique and shared findings. Each target's report still lists its own findings in full.

Full reference: [docs/MASS_SCAN.md](docs/MASS_SCAN.md); the event fields are in [docs/JSONL.md](docs/JSONL.md).

## Recon lists and source rebuild

1. **Recon lists.** `scan --recon DIR` writes what each scan saw as plain-text lists (URLs, endpoints, hosts split by scope, parameters, scripts, source maps and GraphQL operations) plus `recon.json`. With `--targets`, each target gets a `DIR/<n>-<host>` folder and `DIR` holds the merged set. Recon makes no extra requests, and the lists never contain a found value, even with `--full-secrets`.
2. **Source rebuild.** `scan --rebuild-sources DIR` rebuilds the website's own public source files from its published source maps into a new or empty, owner-only folder. These files are verbatim public code and may contain credentials: treat the folder like an unmasked report file and do not share it.

Full reference: [docs/RECON.md](docs/RECON.md).

## Submission Markdown

1. **During a scan.** `--format md` writes each target's report as one masked submission Markdown file. `--submission-bundle DIR` also writes one masked draft per finding, grouped by finding ID across targets, plus an `index.md`, at the end of the run.
2. **From saved reports.** `exposure-desk report submit REPORT.json [REPORT2.json ...]` renders drafts offline from saved JSON reports. Without `--out FILE` or `--bundle DIR`, the masked Markdown is printed.
3. **Full values.** `--full-secrets` writes unmasked values only into files: a scan's report files, or `report submit` with `--out` or `--bundle` (and only when the input report is a full-secret export). It is refused when the Markdown would be printed.
4. **In the dashboard.** On **Findings**, each finding has a **Copy submission Markdown** button. It copies a masked draft for that finding. If the browser does not allow clipboard access, the draft appears in a read-only box labelled "Submission Markdown (masked)": select it and copy it. The dashboard never writes unmasked submission files.

Review every draft before you submit it, and follow the program's rules for proof and disclosure. Full reference: [docs/SUBMISSION.md](docs/SUBMISSION.md).

## Recon downloads in the dashboard

Runs that the dashboard stores keep their recon lists in the data folder (`recon/<run id>/`). On **Findings**, the **Local exports** panel then shows a **Recon lists** block with one download link per list for the selected run. The block is hidden when the run has no recon lists, for example a run saved by an earlier version. The lists are masked, and deleting the run in the app deletes them too. Command-line runs write their lists to `--recon DIR` instead. Details: [docs/RECON.md](docs/RECON.md#dashboard).

## Linux and Docker

1. **Linux x64 package.** Check the archive with `sha256sum --check` and its `.sha256` file, unpack it with `tar -xzf`, and start the dashboard with `Start Exposure Desk.sh` in the unpacked folder. The package carries its own Node.js; the command line is `runtime/bin/node dist/src/cli.js`. Data goes to `$XDG_DATA_HOME/exposure-desk` (`~/.local/share/exposure-desk` by default); `EXPOSURE_DATA_DIR` chooses another folder and must be an absolute path.
2. **Browser sandbox.** Chromium keeps its own sandbox, which needs unprivileged user namespaces. Some hosts block them (Ubuntu 23.10 and later, through AppArmor), and browser checks then report the browser launch as blocked. The two fixes are the host administrator's decision; [docs/LINUX.md](docs/LINUX.md#chromium-libraries-and-sandbox) describes them.
3. **Container image.** Build it from a checkout of this repository with `docker build --tag exposure-desk .` and run it read-only, without capabilities and with a named volume for its data, as shown in [docs/LINUX.md](docs/LINUX.md#container-image). Any command can follow the image name; the working directory and all writable state are the `/data` volume. The image runs as a non-root user and turns Chromium's own sandbox off (`EXPOSURE_BROWSER_NO_SANDBOX=1`), because Docker's default seccomp profile blocks it; the container is then the isolation boundary.
4. **Dashboard in a container.** The dashboard listens only on `127.0.0.1`, inside the container as well. On a Linux host, run the image with `--network host` and the `dashboard` command; publishing a port does not make it reachable. See [docs/LINUX.md](docs/LINUX.md#dashboard-in-a-container).

## Analysis time on slow machines

A large script takes longer to analyse on a slow computer, such as a small VPS or a 2-vCPU CI runner. Exposure Desk measures the computer once per process and gives analysis more time to match: a fast computer gets a time factor of 1, a slower one a factor from 1 to 4. Only analysis time scales; memory budgets and the scan's duration limits never change. The factor and the resulting budgets appear in the dashboard's analysis summary and in the report (`analysis.timeFactor`).

To set the factor yourself, for example on a CI runner whose speed varies, set the environment variable `EXPOSURE_ANALYSIS_TIME_FACTOR` (values from 1 to 8; anything that is not a positive number is ignored and noted in the scan). Details: [docs/LINUX.md](docs/LINUX.md#analysis-time-on-slow-machines).

# Live key check (2.9.0)

Off by default. A program file that contains `"liveKeyChecks": { "enabled": true }` lets a person ask whether **one** found key still works: open the finding in **Advanced** and click **Check if live** (the confirmation names the host that will be contacted), or run `check-key FINDING-ID --program DIR --authorized`. Exposure Desk makes one read-only identity request to that key's own provider (GitHub, GitLab, OpenAI, Anthropic, Stripe, SendGrid or Slack) and records **live**, **revoked** or **unknown** next to the finding; a key of any other provider reads **unknown** without a request. The finding's `validity` stays `unverified`. **Check all** (`--all`) needs the separate `"checkAll": true` and runs one key at a time, paced per provider. No scan, mass scan or ready option ever checks a key, and only the key itself leaves the computer, in the one header its provider documents. Many programs forbid testing found credentials: turn this on only where the program permits it. Details: [docs/LIVE_KEY_CHECK.md](docs/LIVE_KEY_CHECK.md).

# Detection-quality update in 2.6.0

This update is part of 2.6.0 (rule version `website/2.6.1`; 2.6.0-rc.1 used `website/2.6.0`). What changes for you:

- **Fewer placeholder findings.** Values that are templates or placeholders — `${DB_PASSWORD}`, `${{ secrets.API_KEY }}`, `{{ password }}`, `%PASSWORD%`, `<your-api-key>`, `your_key_here`, `changeme`, masked `sk_live_****` or `xxxx` values, or one repeated character — are not reported, also inside database URLs and configuration objects. A default such as `${DB_PASSWORD:-s3cret}` is still examined, because the default is a real value.
- **More providers.** Docker Hub, Figma, Tailscale, Vercel (including AI Gateway keys), Firecrawl, Jina, Tavily, Google OAuth client secrets and access tokens, Square OAuth secrets, Braintree access tokens and Cloudinary URLs are recognized by their published prefixes, and each has its own remediation text. Firecrawl keys and Google access tokens are medium confidence because their shapes are short or short-lived.
- **Passwords in service URLs.** `sftp://`, `ftp(s)://`, `smtp(s)://`, `imap(s)://`, `pop3(s)://`, `amqp(s)://`, `mqtt(s)://`, `nats://`, `stomp://` and `ldap(s)://` addresses with a password are reported like database URLs, and `redis://:password@host` (no user name) is now recognized.
- **Webhook URLs.** Discord webhook URLs are private capabilities. Zapier catch-hook URLs are reported as possible credentials at review priority, because some hooks are meant to be public.
- **HTML attributes.** JSON written with `&quot;` (or `&#34;`, `&#x22;`) inside an attribute such as `data-config` is decoded once and checked; the finding points to the original place in the page.
- **GitHub checksum.** GitHub tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`) end in a checksum. When it does not match, the finding stays visible with the qualifier "token checksum does not match the issuer format" and review priority — typical of documentation examples and edited copies. A matching checksum shows the token is well formed, not that it works.
- **SARIF.** `--format sarif` now describes each rule with its providers, category, remediation help, a CWE tag, `security-severity` and `precision`, which code-scanning dashboards use for sorting. Findings with an active suppression carry it as an accepted external suppression; expired suppressions are left out.

Nothing is sent to a provider to check whether a value works; live validation remains an owner decision. Rows, limits and references: DETECTOR_COVERAGE.md.

# New controls in 2.5

1. **New scan → Scope** (under the website box): *This domain and its subdomains* is the default. The domain name shown is computed locally from the public suffix list. Confirm the single acknowledgement that names the domain. Choose *Only the exact addresses entered* to keep the 2.4 behavior, or *This host and hosts beneath it* for a hosting provider. Saved 2.4 projects keep exact-origin scope; use **Use domain scope for <domain>** on the project card to adopt it.
2. **Running scan** shows the **Current run** and **Previous runs** with start time, state, `#run-id`, trigger and links such as "repeat of #…". The count line separates entered seeds, domain groups, authorized origins and contacted origins; budgets still apply per origin. **Scan again** reloads a finished run's settings and links the new run as a repeat. Start buttons stay disabled while a run is active.
3. Leave **Project name** blank to name it after the website host. **Advanced** adds the announced language, browser time zone and static User-Agent choice; **What the websites can see** explains requests, headers and the egress address.
4. **Findings** sort by priority. Each finding shows its priority and why, financial priority, separate possible impacts (never established), qualifiers (test environment, missing secret or identifier, documentation context, published example, encrypted key, previous deployment only), affected assets and the three lifecycle tracks. Use **Report removed**, **Record owner-confirmed revocation** (with replacement state), **Rescan affected resources** or **Full rescan**. A comparable full scan that inspects every affected URL is required before "Removed from website: yes". **Owner record** stores your environment and restriction statements; it is not verified and only refines priority.
5. **Projects → Alerts** lists masked alerts (new urgent or high findings, reappeared values, values published after revocation, previous deployments still serving a value, incomplete scheduled or deployment runs, rejected triggers). Acknowledge them individually or all at once.
6. **Settings → Local schedules and deployment triggers**: enable a deployment trigger per project, then let a build step run `runtime\node.exe dist\src\cli.js trigger --project <id> --label "release 42" [--assets manifest.json --base https://www.example.com/]` on this computer. The request runs while Exposure Desk is open, replays only exact asset URLs inside the scope, never saves evidence, and is limited per day and per interval. For CI before deployment use `cli.js artifacts --directory <build>` (no requests).

See docs/history/UPGRADE_2.5.md for exact behavior and limits.

# Controls added in 2.4

Adaptive allocations per website are part of **Deep audit**; since 2.6 the scan page has no sizing control. JSON specifications and the CLI (`--sizing fixed|website-count|adaptive`) can still set `sizingMode`, which loads as custom settings. View allocations/reasons and important pending assets in Running scan. Findings includes a masked dismissal audit; saved projects support confirmed/false-positive feedback and reversible expiry-based suppression. Sensitive-field expectations use exact private/public JSON dot paths. See docs/history/UPGRADE_2.4.md for examples and precise limits.

# Current 2.3 controls

External anonymous mode remains the default. Since 2.6 the ready option decides constant reconstruction, browser inspection and debugger capture (Standard and Deep audit use isolated-browser pages with debugger capture of generated scripts; Quick check uses no browser); there are no separate toggles on the scan page. Stale-history replay is on by default only for Deep audit (**Revisit exact assets from this project's last three scans** in Advanced). Use exact stale URLs from an authorized deployment manifest or the last three project scans. Every request still passes the current scope and transport policy.

Open a finding's evidence path to distinguish public response, static reconstruction, runtime memory, blocked candidate and local-only evidence. Incomplete coverage explains disabled/unsupported channels and exhausted budgets. Remediation priorities reflect supported potential impact and confidence; credential activity and privileges are untested. Explicit reveal/copy/full local export and vault behavior are unchanged. Optional owner-build scanning uses the separate artifacts CLI; local-only findings never imply public reachability.

Read docs/history/MIGRATION_2.3.md for exact operational limits and TEST_RESULTS.md for measured verification. The remainder documents the retained original controls.

---

# Basic workflow

(Originally the 2.2 guide; updated for 2.6.)

1. Extract the Windows x64 ZIP and double-click **Start Exposure Desk.cmd**. Keep the launch window open. Enter its token in the local dashboard. Settings shows specific prerequisite/storage problems and repair actions.
2. Settings → **Run full-pipeline self-test** exercises local synthetic HTML/scripts/JSON/headers/maps/error/encoded/browser fixtures and shows every expected case. Refresh checks for its result. Missing detector or actual browser execution fails. **Run synthetic demo** remains a separate small example.
3. Open **New scan**, paste a website or hostname, confirm you own it or have authorization, and click **Start scan**. A hostname becomes HTTPS. **Standard + Normal (Recommended)** and all supported detectors are enabled; choose another ready option card if needed. **Advanced** contains saved projects, optional extra public seed URLs, exact related origins and the other controls listed in [Ready scan options](#ready-scan-options-in-26), item 6. Add related origins only within your authorization. Since 2.5 the Scope fieldset decides whether discovered subdomains of the entered domain are included (default) or only listed.

Sizing to the number of websites is automatic since 2.6 (see automatic adjustment above); the former **Adjust shared scan limits to website count** checkbox is gone. Older projects and JSON files that set `autoScaleByWebsiteCount` keep that setting and load as custom settings.

Use **Upload scan specifications (JSON, for power users)** to load a scan config object, `{ "config": { ... } }`, or a `{ "projects": [ ... ] }` file containing exactly one project. A partial object keeps the current website and other form values; an object with `coverage` and `traffic` only selects that ready option, and an object with its own numbers (for example `{ "maxPages": 60, "originMaxPages": 30, "autoScaleByWebsiteCount": true }`) loads as custom settings within the ceilings. An uploaded `urls` array replaces the current seed URLs. The app validates the merged configuration locally, shows it for review, and requires authorization before starting or saving. Uploading does not change an existing saved project automatically.
4. Follow **Running scan**. Counters separate downloaded/decoded/analyzed content, skips, errors and limitations. A drained discovered frontier does not mean every possible resource exists in that frontier. Cancel/checkpoint/resume retain the existing bounded workflow; resume starts fresh budgets/profile and re-fetches safe public seeds.
5. Review **Financial priority and critical exposure** and the priority-sorted findings list (2.5). Expand evidence for provider, source location, transformations, discovery chains, component completeness, confidence, environment, priority, impact and remediation. Potential impact is conditional; validity and permissions are never checked.
6. Reveal/Copy full value are deliberate authenticated actions. Re-mask/navigation/timeout remove revealed DOM values. Default exports/history/checkpoints stay redacted. Full-secret export is explicit and local. Protect that file and clear clipboard contents after use.
7. All scans retain masked progress/history when protected storage is available. Recovered interruptions are incomplete and can be reviewed/exported or resumed with fresh requests. Save an authorized project for persistent correlation, queue/comparison/suppression/scheduling. Independent unsaved scans cannot establish absence. Schedules run only while the app is open. No longer observed does not establish revocation. Affected-resource rescan never uses a credential.
8. Full values normally remain in memory. Create/unlock the optional encrypted vault and deliberately save evidence to retain them across restart. The password and key are not stored in plaintext. Forgotten passwords and values absent from redacted history cannot be recovered.
9. Company rules/preview remain local in Settings. Review diagnostics before installing/repairing a missing source-package dependency. The portable Windows package contains pinned dependencies; source setup may download official software.
10. Stop in Settings or Ctrl+C before deleting/moving application data. Use in-app deletion for scans/projects/vault. Back up the complete data directory displayed in Settings before migration, retaining correlation keys and encrypted vault files together. Do not change permissions on unrelated folders.

Zero findings, access barriers or incomplete scans do not establish that a website is secure. Browser traffic with no trustworthy initiator stays unknown and blocked, and it makes the scan incomplete. The one exception is Chrome's own service connections: a Google account cookie check, the GCM device check-in, a component update check and an AI Mode eligibility check, which Chrome retries for up to about 30 s after launch. When a connection goes to one of these four hosts (accounts.google.com, android.clients.google.com, update.googleapis.com, www.google.com) and no page, frame or worker requested that host, it is still denied at the proxy and listed in the report as a browser background connection, but it does not make the scan incomplete. A page's own request to one of these hosts, and any other hostname, is accounted as before. Chrome launch and runtime page counts do not certify isolation; the separate strict suite verifies it against the synthetic fixture.

2.9.1 is the current release (a patch release of 2.9.0), verified with local fixtures and synthetic keys only (no real website was scanned for its measurements). See [TEST_RESULTS.md](TEST_RESULTS.md) and [DETECTOR_COVERAGE.md](DETECTOR_COVERAGE.md) for verified checks and remaining platform/format limitations. Windows x64 was measured on one computer. The Linux x64 package is built and smoke-tested on GitHub-hosted Ubuntu runners, where both test suites also pass, and is delivered as an asset of a draft GitHub Release of the private repository; other Linux distributions are unverified, and macOS and ARM are not supported yet.


## Reliability repair in 2.3.1

Start with the Recommended option. Since 2.6, rate, concurrency, page, resource, byte, browser and duration values come from the ready option and are no longer form fields; they can still be set in an uploaded JSON specification or CLI `--config` file (loaded as custom settings, within the ceilings), and maxRetries can be set to 0 or 1 there. Low-impact traffic makes no retries. Failed page attempts now consume the page cap. Selected public links and explicit browser routes receive an early bounded browser turn. No control is clicked or submitted.

Read the first-screen diagnosis before interpreting zero findings. Network failures/timeouts, HTTP errors, policy events and intentional skips are separate. Expand coverage groups for pending/active/deferred classes, age and first-inspection times; expand limitation groups for examples. Phase timings show local waits, not a proven remote cause. A map candidate is successful only after valid map analysis.

After an incomplete scan, Retry important gaps previews exact URLs, successful static exclusions and fresh browser routes under the same approved origins. Include optional failed pages only when useful; then start the reviewed plan with fresh budgets. Focused results cannot prove project-wide absence.

Information findings offer Copy endpoint and View source evidence. A public image/bucket/AI/admin reference does not prove access or unrestricted use. Credential findings retain Reveal full value, Copy full value, Re-mask and deliberate protected local exports. Metadata-only source coordinates are unavailable.


## Exhaustive and origin coverage

Since 2.6 the scan page has no preset selector. **Deep audit + Normal** is the closest ready option to the former Exhaustive preset; `exhaustive.config.example.json` loads as Deep audit + Normal. The legacy Exhaustive preset itself still runs from the CLI (`--preset exhaustive`), from a saved project that uses it (shown as **Legacy preset: Exhaustive**) or from an uploaded JSON specification. Review explicitly authorized roots/related origins, confirm authorization, then start the scan. Each origin receives bounded fair turns and up to 60 minutes from first dispatch; shared project budgets remain in force. At 90% optional traversal stops. Project duration may exceed 60 minutes. Coverage groups and request scheduling shows per-origin accounting, separate important/optional limitations, and exclusive resource states. No findings is limited to inspected supported coverage. See [MILESTONE1.md](docs/history/MILESTONE1.md) for exact limits, CLI commands, compatibility and cleanup semantics.

## Automatic domain discovery and finding assessment

(2.4 text, updated.) Since 2.5 the Scope fieldset under the website box replaces the former Advanced checkbox, and domain scope is the default; `domainScope: "exact-origin"` or an explicit `sameRegistrableDomainDiscovery: false` opts out. `maxAutoDiscoveredOrigins` is 50 by default; the limit can be lowered to 0–50. Domains are compared with the maintained Public Suffix List, including private hosting suffixes. Schemes and ports remain separate origins and receive ordinary origin budgets. Only explicit seed URLs anchor domain authorization; manually approved unrelated origins do not expand it.

Discovery is recursive across supported HTML, scripts/imports, CSS, manifests, maps, hydration/RSC, runtime configuration, and guarded browser responses. WebSocket channels remain disabled; their corresponding HTTP(S) origin may be discovered after screening the complete URL. DNS, socket pinning, TLS, credential screening, redirects, private/metadata blocking and browser isolation apply. Automatic scope never inherits private-origin exceptions. Shared resource and project deadlines still apply, so adding origins can leave some coverage incomplete.

Running scan lists each automatic origin, its explicit seed and the resource that discovered it. JSON, HTML and SARIF reports retain that authorization. Reaching the origin limit produces an `auto-origin-limit` coverage gap with counts and examples, plus deferred URLs where available. Automatic origins stay in scan provenance and do not become manually approved project origins.

An offline worker assesses findings concurrently with acquisition. **Direct leak** means high-confidence private material observed in public content or anonymous runtime evidence; credential validity and permissions are unverified. **High potential leak** retains private or credible possible credentials requiring review. **Low potential leak** retains weaker/incomplete credentials and potentially sensitive configuration/debug evidence. Known benign public identifiers and endpoint/source-map observations are classified insignificant and deleted from findings and full-value exports. A masked dismissal audit remains available in the findings view; removed raw values cannot be recovered from that audit. Resource coverage remains visible. Unknown company rules remain reviewable, and stronger later evidence is reclassified. Running scan shows assessment counts, pending work and the number of removed observations.
