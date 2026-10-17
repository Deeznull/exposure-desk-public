# Exposure Desk 2.6 upgrade

Version 2.6 (released as 2.6.0 after the release candidate 2.6.0-rc.1) replaces the many per-scan numbers with six ready scan options, adds a gentler traffic level, sizes every scan for the computer it runs on, never contacts government, military or law-enforcement websites, and fixes the browser-cookie and alias findings of an external review. Measured results are in [TEST_RESULTS.md](../TEST_RESULTS.md); upgrade steps for saved settings are in [MIGRATION_2.6.md](MIGRATION_2.6.md); the change list is in [CHANGELOG_2.6.md](CHANGELOG_2.6.md). 2.6.0 also adds the detection-quality update described there and in the [user guide](../USER_GUIDE.md#detection-quality-update-in-260); the ready options and their limits are the same as in 2.6.0-rc.1.

## 1. Six ready options

A scan option is a **Coverage** (what is examined) combined with a **Traffic** level (how gently the websites are asked). Each option sets every number, including how much of this computer the scan may use. **Standard + Normal is Recommended.** It is the default for the scan page, a new project and a CLI scan that names no `--preset`, `--coverage`, `--traffic`, `--config`, checkpoint or `--sizing`.

| Option | Examines | Traffic per website | Websites at once | Browser websites at once | Analysis memory | Analysis workers | Pages / requests / download cap per website | Time allowance per website |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Quick check + Normal | Entry documents, their first-party scripts and source maps, build and web app manifests, robots.txt and high-value deployment paths. No browser and no crawl. | About 2 requests/s | 6 | none | 256 MiB | 1 | 8 / 100 / 40 MiB | 2 min |
| Quick check + Low-impact | Same | About 0.5 requests/s, one kept-alive connection | 2 | none | 256 MiB | 1 | 8 / 100 / 40 MiB | 8 min |
| **Standard + Normal (Recommended)** | Static discovery to depth 3, deployment paths and up to 5 isolated-browser pages | About 2 requests/s | 4 | 2 | 256 MiB | 2 | 30 / 200 / 120 MiB | 5 min |
| Standard + Low-impact | Same, with up to 3 browser pages, no adjacent source-map guessing and one query variant per path | About 0.5 requests/s, one kept-alive connection | 2 | 1 | 256 MiB | 2 | 30 / 200 / 120 MiB | 20 min |
| Deep audit + Normal | Full static discovery (depth 5), up to 15 browser pages with debugger capture, adjacent source maps, query variants and adaptive allocations | About 2 requests/s (3 at once) | 3 | 2 | 512 MiB | 2 | 80 / 600 / 300 MiB | 60 min |
| Deep audit + Low-impact | Same, with up to 6 browser pages, no adjacent source-map guessing and one query variant per path | About 0.5 requests/s, one kept-alive connection | 2 | 1 | 512 MiB | 2 | 80 / 600 / 300 MiB | 60 min |

- **Quick check** looks only at entry documents and what they load directly: up to 40 first-party scripts per website (entry-document bundles first), their source maps, manifests, robots.txt and deployment paths. It skips linked pages, sitemaps, query variants, adjacent source-map guessing, stylesheets and fonts. It ends as **Completed — quick coverage**, and the report lists what was not examined (`profile.notExamined`). That never means the site has no secrets.
- Every coverage probes the same high-value deployment paths, including two new ones, `/wp-config.php.bak` and `/.git/config`; each is confirmed by content before analysis. Legacy presets keep the 2.5 list.
- Analysis memory is shared by the parser workers: each worker gets the option's memory divided by the worker count. A dependency group too large for one share gets the whole allowance and runs alone. Quick uses 256 MiB, not 128 MiB: at 128 MiB a 1.25 MB bundle exceeded the parser limit and its split key was missed.
- The scan page has no number fields. The read-only **What this option uses** panel lists every number; choosing another option is the way to change them. Power users can still upload a JSON specification (New scan → Advanced).
- CLI: `--coverage quick|standard|deep` and `--traffic normal|low-impact`. API: `POST /api/scans` accepts top-level `coverage` and `traffic`; `POST /api/profile/preview` returns the numbers and the estimate for a planned scan.

## 2. Low-impact traffic

Low-impact asks each website more gently. It does not hide the scan: websites still see every request, this computer's IP address and the honest User-Agent. There is no spoofing, evasion timing, proxy rotation or rate-limit bypass.

- Per website: about 0.5 requests/s, 1 request at once, no retries. At most 2 websites and 1 browser website at once. No adjacent source-map guessing.
- **One query variant per path** (for example `/list?page=1` but not `/list?page=2`). That is the option's stated boundary, shown as **Limited by profile**, not as a gap. A scan that is limited by profile and also has a real gap (an error, a timeout, a cancellation, or a budget or variant limit that Normal traffic would also hit) is reported as incomplete. Owner decision, 2026-10-09.
- **One kept-alive connection per website** (Low-impact only). A connection is reused only for the same protocol, host, port, pinned IP address and TLS name; DNS is rechecked before every request, and a stale connection is replayed once. Idle connections close after 4 s.
- **Run cache** (Low-impact only, 64 MiB, at most 16 MiB per entry): a response that HTTP caching rules (RFC 9111) allow to be reused — status 200, 404 or 410, never one with cookies or credentials — answers a repeated request inside the same run. Reports show `servedFrom: run-cache`. There are no conditional requests and no TLS session resumption.
- Normal traffic and legacy settings are unchanged from 2.5: one connection per request, no cache, about 2 requests/s and 2 at once per website (Deep 3), one retry.
- Reports count connections opened and reused, replays, TLS handshakes, browser cache hits and requests avoided. The estimate includes a maximum connection count.
- The time allowance grows ×4 for Low-impact, capped at 60 minutes per website (8, 20 and 60 minutes).

## 3. Sizing for the websites and the computer

Automatic adjustment is always on and only ever lowers values. The scan page says it in plain words, for example "4 websites at once, adjusted for 10 websites", and the scan record and report keep every lowered value (`profile.resourceUse`).

- **Websites at once** never exceed the websites in scope. With domain or host-subtree scope, the panel also says how many could run at once after discovered websites are admitted. Further websites wait for a free slot, and a website's time allowance starts with its own first request.
- **Shared caps** (pages, requests, bytes and total time) grow with the number of websites, within the hard ceilings. The time estimate grows with them; analysis time is not included.
- **Long scans:** an estimate over about 2 hours is named on the scan page and in the CLI (`Long scan:`), with Quick check suggested. Nothing switches automatically. The CLI also prints `Uses:` with the numbers.
- **This computer:** at scan start Exposure Desk reads the logical cores and free memory. Under 4 cores or under 2 GiB free memory a scan uses 1 analysis worker and 1 browser website. Analysis memory stays within a quarter of the free memory and never below 64 MiB per worker. On a measured small computer (2 cores, 1 GiB free) this lowered workers 2 → 1, browser websites 2 → 1 and Deep's memory 512 → 256 MiB.
- Legacy presets and custom settings without a coverage run exactly as entered, without computer adjustment (as in 2.5).

## 4. Hard ceilings

- Analysis memory never exceeds **512 MiB**, counted for all parser workers together.
- Per scan, however many websites: 500 pages, 2,000 requests, 500 MiB downloaded and 500 MiB decoded, 100 source maps, 50 browser pages, 20 requests/s, 12 requests at once, 8 websites and 4 browser websites at once.
- Per website: 60 minutes.
- A JSON configuration file, a CLI `--config` file, a saved project, a scan start or a preview with a higher value is refused before any request. Only Low-impact clamps its own limits instead of refusing.

## 5. Protected hosts (no override)

Exposure Desk never sends any request to a government, military, intelligence or security-service, law-enforcement, judiciary or intergovernmental-organization website. No configuration key, CLI flag, environment variable, saved-project field, preset, option or dashboard control can disable or narrow it.

- The list (`src/protected-hosts.ts`) has the top-level domains .gov, .mil, .int, .va, .cern and .政务, government and public-sector zones per country, well-known bodies on ordinary domains, and a public-suffix safety net.
- A seed on the list refuses the whole scan: CLI exit 2, API `400` with code `protected-host`. Saved records that name such a host load unchanged, show the reason and never run.
- Follow-on requests (links, redirects, assets, source maps, WebSockets, browser navigations and subrequests, retries) are refused before DNS, before a socket and, for HTTPS aliases, when the server certificate names a protected host. Each refusal is recorded as `protected-host`, counts like out-of-scope and is shown in reports.
- Known limits: unlisted bodies on ordinary domains, bare IP addresses and CNAME aliases are not detected. HTTPS aliases are caught only through the server certificate, after the handshake.

## 6. External review fixes

A separate, non-Claude review of 2.5.0-rc.1 was checked finding by finding before anything was changed (working notes in `archive/notes/HANDOFF_EXTERNAL_REVIEW.md`, kept in the project folder and not packaged).

- **Browser cookies stay with their host (F-01, D-4).** A cookie belongs to the document that started the request; `Domain=` attributes are stripped, so a cookie set by `owner.example.com` is never sent to `assets.example.com`. `cookieStore` is disabled. The New scan text now describes this correctly. Browsers do not separate cookies by port, so two origins on one host with different ports can still share a cookie the page set itself.
- **Changed text at a module alias (F-02):** an alias URL stands for its canonical module's exact text. Different text at an alias becomes one bounded variant (`#variant-<sha8>`) that is analyzed; a third different text is recorded as an incomplete gap. Nothing is reused or dropped silently.
- **Tenant suffixes (F-03):** a curated, narrowing-only list of 80 shared-hosting and SaaS tenant suffixes missing from the public suffix list (for example WP Engine, Kinsta, Squarespace, Zendesk, Okta, Firebase) makes each tenant its own registrable domain, so `foo.wpengine.com` no longer admits `other.wpengine.com`. A bare suffix is refused as a seed. Providers on neither list remain an open owner decision.
- **Docs (D-2, D-3):** the README says the website box and the Scope choice are on the first screen (extra seeds, related origins and technical settings are in Advanced) and names both storage schemas, `exposure-workspace/3` and `exposure-history/2`. D-1 was stale and rejected.

## 7. Detection

Rules are `website/2.6.0` in 2.6.0-rc.1 and `website/2.6.1` in 2.6.0, which adds the detection-quality update (placeholder filter, 17 rules, offline GitHub token checksum; see [CHANGELOG_2.6.md](CHANGELOG_2.6.md)). The whole document is parsed up to 2 MiB with a focused context. Plain-text configuration groups are recognized: PHP `define()`, debug-page tables, environment lines, WordPress, Laravel and Rails signing keys and database passwords. Hex-encoded values are decoded. `*_uri`, `*_url` and `*_endpoint` values are not treated as secrets, and `*key_id` values are identifiers. On the external synthetic corpus (20 sites, 27 private values, 402 negative controls; legacy Thorough preset, every expected file given as a seed so that detection is measured apart from discovery) results went from 19 true / 3 false positives / 8 misses in 2.5 to 27 / 3 / 0.

Each ready option as shipped, on the same corpus served from 127.0.0.1 (extra measurement, `benchmarks/2.6/external-corpus/`; synthetic and local, no claim about real websites):

| Ready option | From the site root: found / false positives / missed | Every expected file as a seed | Time from the root |
|---|---|---|---|
| Quick check + Normal | 24 / 3 / 3 | 27 / 3 / 0 | 6 min |
| Quick check + Low-impact | 24 / 3 / 3 | 27 / 3 / 0 | 16 min |
| Standard audit + Normal (Recommended) | 27 / 3 / 0 | 27 / 3 / 0 | 14 min |
| Standard audit + Low-impact | 27 / 3 / 0 | 27 / 3 / 0 | 31 min |
| Deep audit + Normal | 27 / 3 / 0 | 27 / 3 / 0 | 14 min |
| Deep audit + Low-impact | 27 / 3 / 0 | 27 / 3 / 0 | 31 min |

- Quick check's 3 misses from the root are two values returned only by a JSON API the page script calls and one in an older deployment bundle listed in a manifest. Quick check renders no pages, so those resources are not examined, and the run says so.
- Low-impact found exactly what Normal found with fewer requests (Standard audit from the root: 921 against 1,332) and took 2–3 times as long.
- The 3 false positives are the same in every run and are policy, not detector misses: two Stripe test-mode keys and one OpenAI documentation example. The corpus treats them as non-private; Exposure Desk reports them with a test-environment label or lower priority. Without them precision is 27/27.
- No run contacted anything outside the corpus server, and no output file holds a corpus value. The selected provider corpus, the acquisition pipeline and the 2.4 corpora are unchanged.

## 8. Remaining limits

- Fixture measurements only. They make no claim about accuracy or speed on real websites. Linux, macOS and ARM were not exercised.
- An all-`X` placeholder that looks like an OpenAI project key is still reported as a credential, in 2.5 and 2.6 alike.
- The estimate does not include analysis time; its connection count is an upper bound.
- Analysis runs inside the fetch slots, as in 2.5: each fetched resource is checked by the secret-scanning engine in its own process (about 0.6 s on this computer). On the fixtures a whole scan therefore fetched about 1–1.6 resources per second for 1, 3 and 10 websites, well below the Normal request rates. The Normal options are bounded by analysis time, not by their traffic limits; Low-impact is bounded by its own pacing.
- With 6 Quick check websites at once sharing that analysis rate, Quick check + Normal for 10 fixture websites is close to its per-website soft deadline. In one matrix run it deferred 2 of 250 requests (3 on the small computer) and was reported as incomplete; in the final run it completed all 250 on both computers. Quick check + Low-impact, with its ×4 time allowance, completed them every time.
- Quick check + Low-impact sends about the same requests as Quick check + Normal (25 against 25 for one fixture website), over one connection per website instead of one per request: Quick check has no query variants or adjacent source-map guesses for Low-impact to leave out. Standard and Deep audit + Low-impact send fewer requests than their Normal options.
- Low-impact keeps one connection per website while requests follow each other, but an idle connection closes after 4 s, so a website reconnects after a pause longer than that (analysis of a large file, a browser turn of another website, a wait for the browser slot). On the fixtures (final run) Deep audit + Low-impact opened 9 connections for 3 websites and 28 for 10 (Normal: one per request, 183 and 529); every reconnect followed a pause of 4 s or more, mostly around browser turns.
- The 512 MiB ceiling is the analysis memory of the parser workers. The secret-scanning engine checks each text over 128 KiB in a separate worker of up to 192 MiB (at most 2 at once, as in 2.5), outside that ceiling. Whole-process peak memory on the fixtures reached 405 MiB in the final run and 533 MiB in an earlier run on the small computer (Standard + Normal, one bundle website inspected twice at once by the static and browser passes); it is reported as measured, not capped.
- A redirect to a protected host leaves that part of a run incomplete.
- Retries and rescans of a ready-option run are labelled Custom. Seeds that are IP addresses or `localhost` show 0 discovered websites.
- No TLS session resumption and no conditional requests. The protected-host list is reviewed only in code; the owner should review it.
- Open items carried over are listed in [HANDOFF.md](../HANDOFF.md).
