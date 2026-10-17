# Demo script (2–3 minutes)

A short walkthrough for a recording or a live call. It uses only the synthetic demo shop that ships with Exposure Desk and runs on your own computer (`127.0.0.1`): no real website is contacted, and every secret-looking value is a non-functional test vector. The screenshots in the [README](../README.md#screenshots) were taken from this exact setup.

## Before you record (not part of the 2–3 minutes)

1. Open a terminal in the Exposure Desk folder and start the demo:
   - Windows package: `runtime\node.exe dist\scripts\demo.js`
   - Source package: `npm run build`, then `npm run demo` (install the browser and detector from **Settings** first, or set `SCANNER_CHROMIUM_PATH` and `GITLEAKS_PATH`).
2. The terminal prints the dashboard address (normally `http://127.0.0.1:4317`) and a per-launch token. The demo dashboard saves nothing: no history, no vault, no data folder changes.
3. Open the address in a browser, paste the token and click **Open workspace**.
4. Do one practice scan so you know the timing (a Standard scan of the demo shop takes about one to two minutes), then restart the demo for a clean recording.
5. Close other windows and notifications. Do not show the token on screen.

## The script

**0:00 – The problem (15 s).** "Websites leak keys by accident: an API key in a JavaScript bundle, a token in a source map, a `.env` file left on the server. Automated scanners look for exactly these. Exposure Desk lets a website owner find them first, on their own computer."

**0:15 – Start a scan (30 s).** Click **New scan**. Open **Advanced**, choose the saved project **Synthetic demo shop (local fixture)** and close Advanced again.
- Point at the six ready options: "No settings to tune. Pick one option; **Standard + Normal** is recommended."
- Point at **Before you start**: "Before anything is sent, it shows the scope and an upper bound for requests, data and time."
- Tick **I own this domain or am authorized to assess it** and click **Start scan**. "It only scans what you own or are authorized to test."

**0:45 – While it runs (30 s).** On **Running scan**: "Every request goes through one guarded network layer: only the authorized website, DNS checked, private addresses blocked, an honest user agent and per-website rate limits. A fresh, isolated browser looks at the pages the way a visitor would." Point at the live counters and the coverage notice: "It is honest about coverage. No findings never means proven safe."

**1:15 – Findings (45 s).** When the state shows *completed* or *incomplete*, click **Findings**.
- "Findings are grouped by provider and prioritized: what the key could do, how sure we are, where it was found."
- Point at `[redacted: N characters]`: "Values are masked by default. History, alerts and normal exports never store the secret."
- "It never tries a key. No login, no provider call, no paid usage. Validity is marked unverified." Open **Evidence, possible impact and remediation** on the first finding to show the location and the fix steps. Do not click **Reveal full value** on camera.

**2:00 – Report (20 s).** Choose **HTML** under the report format and click **Export redacted**, then open the downloaded file. "The report is redacted too: what was scanned, what the website could see, and what was found."

**2:20 – The hard rule (20 s).** Back on **New scan**, open **Advanced**, choose **New / unsaved website** and close Advanced. Enter `https://portal.agency-example.gov/` (a fictional address), tick the authorization box and click **Start scan**. "Government, military, intelligence and law-enforcement websites are refused before a single DNS lookup. There is no setting to turn that off."

**2:40 – Close (15 s).** "Everything stays on this computer: no account, no cloud, no telemetry. Exposure Desk finds exposed secrets on your own websites, or in bug bounty scope, before someone else does."

Stop the demo with **Ctrl+C** in the terminal.

## Notes for the presenter

- If a viewer asks about real websites: the measured results in the [README](REFERENCE.md#measured-results) come from local fixtures and synthetic data. Test on a website you own before quoting numbers for real sites.
- The second saved project, **Synthetic fixture · all modes**, turns on every discovery mode with explicit numbers and takes longer; it is meant for testing, not for a short demo.
- To refresh the screenshots after a change, run `scripts/screenshots.mjs` (see the comment at the top of the file).
