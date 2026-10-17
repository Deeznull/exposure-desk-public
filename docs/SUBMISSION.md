# Submission Markdown

Exposure Desk 2.8.0 can turn findings into bug-bounty report drafts: one plain, editable Markdown report per finding, or one per stable finding ID when the same exposure shows up on several targets. The drafts are built offline from a saved or finished scan. Exposure Desk calls no platform API, sends nothing anywhere, and never uses a found value.

This page describes the report format, the library API and the command-line and dashboard entry points that call it ([Using submission Markdown from the CLI](#using-submission-markdown-from-the-cli), [Dashboard](#dashboard)).

## What a report contains

Every report has the same sections, in this order:

1. **Title.** For example `Exposed OpenAI credential in a public JavaScript file on shop.example`. The resource type comes from the file (JavaScript file, source map, JSON file, page, runtime data).
2. **Draft note.** The Exposure Desk version and generation date, and a reminder to check and edit the draft before submitting.
3. **Validity not tested.** A bold line near the top and a closing line at the end. Every report carries both.
4. **Summary.**
   - asset (the scan target or targets)
   - number of affected locations
   - finding ID
   - provider, category and rule
   - Exposure Desk priority with its basis
   - Exposure Desk severity and confidence
   - a line telling you to set the platform severity yourself under the program's rules
   - the scan date and run
   - then a one-paragraph summary and any caveats, such as a documentation example, a checksum mismatch, a test environment, a partial credential set, or local files only
5. **Affected URLs and locations.** Each URL with its line, column and byte offset. It notes the embedded source name for source maps and the original source position when a source map mapped it. A grouped report lists every target, and long lists stop at 20 entries.
6. **How it was found.** The discovery path in plain words (page → script → source map …), the evidence label, the decoding steps, and why the rule flagged it.
7. **Steps to reproduce.** Only plain, unauthenticated `curl` GETs of public resources, followed by the position to look at. For generated code with a byte offset, the report adds a command that prints the text at that offset:

   ```sh
   curl -sS --compressed -o exposed-resource 'https://shop.example/static/app.js'
   tail -c +121 exposed-resource | head -c 120
   ```

   `tail -c +N` counts bytes from 1, so it starts at byte offset `N-1` of the decoded (UTF-8) text. `--compressed` makes curl decode the body the way the scanner read it. The steps never contain the value, and in particular never a request that sends it:
   - **Fragments and user info:** dropped from the URL.
   - **Redacted query parameters:** a parameter that held a redacted value is left out, with a note.
   - **Value in the path or host:** there is no request. The report points to the page that references the resource instead.
   - **Requests Exposure Desk blocked** (the page would have sent the value): there is no request, only developer-tools steps, with "do not send that request yourself".
   - **Runtime data:** steps to open the page in a private window and look in the developer tools.
   - **Values assembled from several pieces:** a GET for each file, plus the line and column of each piece.
   - **Embedded sources in source maps:** the position inside the named embedded source.
   - **Owner-supplied local files:** a statement that this is not a public exposure.

   Up to 3 locations get full steps (the `maxLocations` option allows 1 to 20). The rest are listed under the affected URLs.
8. **Exposed value.** The masked form, e.g. `[redacted: 164 characters]`, plus the key structure and credential-set state. The full value appears only in a disk file written with full secrets (see Masking).
9. **Possible impact (unverified).** The impact texts for the finding (from `src/finding-assessment.ts` and `src/provider-capabilities.ts`). Each one starts with "Possible", is introduced with "None of it was tested", and is followed by the standard "Not established: validity, permissions, restrictions, balances and any loss." An unmapped provider is reported as unknown impact.
10. **Remediation.**
    - Rotate or revoke at the provider first.
    - Add the provider-specific steps.
    - Remove the value from the public file and from the build, redeploy, and delete stale bundles and source maps.
    - Check the provider's access, usage and billing logs.
11. **References.**
    - For credentials: CWE-798, CWE-200 and the OWASP Secrets Management Cheat Sheet.
    - For information findings: CWE-200 and CWE-540.
    - Then the Exposure Desk version, finding ID, rule and rules version.

Reports are bullet lists and paragraphs. They contain no tables, so they paste cleanly into HackerOne, Bugcrowd, Intigriti and similar Markdown editors. The title field (`report.title`) is plain text, not Markdown.

## Which findings are included

`reportableFindings(view)` selects the findings a hunter would normally report:

- **Category:** private credentials and possible credentials (`private-credential`, `suspicious`). Other categories can be chosen with `categories`.
- **Suppressed:** findings under an active (unexpired) suppression are left out, unless `includeSuppressed` is set.
- **False positives:** findings marked false positive are left out.
- **Dismissed:** dismissed observations are never included.

You can also pass any list of findings yourself.

## Grouping

By default, findings with the same `findingId` are merged into one report, across scans and targets. Older records without a `findingId` fall back to `correlation`. A merged report:

- uses the highest priority and severity in the group
- lists every target and location
- titles the asset as "N assets" when several hosts are involved

With `groupBy: 'finding'`, every finding of every scan gets its own report. Findings without any stable ID always get their own report.

## Masking

Values are masked by default everywhere.

- **The renderer is always masked.** `submissionMarkdown`, `submissionReports`, `submissionIndex` and `submissionDocument` never print a value. Excerpts and URLs come from the redacted scan view. Revealed values, when you supply them, are used only as a scrub list: any occurrence of a value or one of its encoded representations is replaced with `[redacted]` before the text is returned.
- **Only the disk writer unmasks.** `writeSubmission(…, {fullSecrets: true})` is the only way to get an unmasked value, and the value appears only in the "Exposed value" section. Excerpts, URLs and steps stay masked even then. Unmasked files:
  - are named `*.sensitive.md`, so `report.md` becomes `report.sensitive.md`
  - are created exclusively, so an existing file is never replaced (the write fails with `EEXIST`)
  - are restricted to the current user before any content is written: a Windows ACL through the same helper as other sensitive exports, mode 0600 elsewhere
  - are removed again if a later step fails
- **When the record holds no value**, for example a JSON report without secrets, the full-secret write says "Full value: not available in this record" and keeps the ordinary file name.
- **Terminal output and JSON Lines** never go through the writer and stay masked.

## Escaping hostile content

A scanned website controls much of what ends up in a report: URLs, provider names built from page code, source labels, discovery paths, excerpts, evidence labels and reasons. All of it is treated as hostile:

- **Inline code spans.** URLs, hosts, file and source names, rules and IDs. The backtick delimiter is always longer than any backtick run inside, so the content cannot close the span. Code span content is literal: no links, images, HTML or emphasis.
- **Fenced blocks.** Excerpts. The fence is longer than any backtick run inside, and the info string is fixed (`text` or `sh`).
- **Escaped prose.** Other text (reasons, labels, provider names) is flattened to one line. CommonMark and GFM inline syntax (`\ ` * _ [ ] < > ! & | ~ # $`) is backslash-escaped, along with a leading list, quote or heading marker. Anything a renderer could turn into a link (a scheme, `www.`, an e-mail address, a bare domain) is shown as a code span.
- **Removed characters.** Control characters, bidirectional overrides and isolates, zero-width characters, the BOM, and line and paragraph separators are removed everywhere. Newlines are kept only inside fenced blocks.
- **Shell arguments.** URLs in `curl` lines are parsed with the WHATWG URL parser, limited to `http:` and `https:`, and passed as one POSIX single-quoted word. Embedded `'` is closed, escaped and reopened, so `$(…)`, backticks and `;` are never run.
- **Bundle file names.** Built only from the hex finding ID (`finding-<24 hex>.md`), never from site content.

`test/submission-markdown.test.ts` checks this with hostile fixtures: links, images, raw HTML, scripts, autolinks, code fences, headings, block quotes, task lists, tables, bidi overrides, CR/LF injection and shell metacharacters.

## Library API

All of it is exported from `src/submission/index.ts` (`dist/src/submission/index.js`).

```ts
// Masked renderers (pure, synchronous, no I/O)
submissionMarkdown(findings: Finding[], view: SubmissionView, options?: SubmissionOptions & {secrets?: SecretRecord}): SubmissionReport[]
submissionReports(scans: SubmissionScan[], options?: SubmissionOptions): SubmissionReport[]   // cross-target grouping
submissionIndex(reports: SubmissionReport[], options?: {generatedAt?: string | Date}): string   // index.md
submissionDocument(reports: SubmissionReport[]): string                                       // all reports in one file
reportableFindings(view, {categories?, includeSuppressed?, now?}): Finding[]
submissionInputFromReport(json: unknown): SubmissionScan    // a parsed `scan --format json` report (schema exposure-scan/1)

// Disk writer, the only unmask path
writeSubmission(target: string, scans: SubmissionScan[], options: WriteSubmissionOptions): Promise<WrittenSubmission>

interface SubmissionScan { view: SubmissionView; findings?: Finding[]; secrets?: SecretRecord }
interface SubmissionOptions { groupBy?: 'findingId' | 'finding'; generatedAt?: string | Date; maxLocations?: number }
interface WriteSubmissionOptions extends SubmissionOptions { mode: 'file' | 'bundle'; fullSecrets?: boolean; syntheticFixture?: boolean }
interface WrittenSubmission { mode; files: string[]; index?: string; reports: SubmissionReport[]; sensitive: boolean }
interface SubmissionReport { key; fileName; title; markdown; findingId?; findings: {runId, id}[]; targets: string[];
  category; severity; priority; provider; sensitive }
```

- `view` is the redacted scan view: `scanner.view()`, a dashboard run's view, or a parsed JSON report.
- `secrets` is the record `Evidence.full()` returns (`{[finding.id]: {value, representations, locations, validity}}`). It is the same shape as the dashboard vault entry and as the `secrets` field of a sensitive JSON export.
- In `file` mode, `target` is the Markdown file. In `bundle` mode, it is a directory that gets one file per report plus `index.md`. The index holds titles, priorities, severities, providers, targets and short IDs, never a value.

Example (masked, one target):

```ts
import { submissionMarkdown, reportableFindings } from './submission/index.js';
const view = scanner.view();
for (const report of submissionMarkdown(reportableFindings(view), view)) console.log(report.markdown);
```

Example (bundle with full values, written to disk only):

```ts
import { writeSubmission } from './submission/index.js';
await writeSubmission('reports/shop', [{ view: scanner.view(), secrets: scanner.evidence.full() }], { mode: 'bundle', fullSecrets: true });
// → reports/shop/finding-<id>.sensitive.md …, reports/shop/index.md
```

## Using submission Markdown from the CLI

Two entry points, both offline:

**During a scan.** `scan --format md` writes the report as submission Markdown instead of JSON/HTML/SARIF (to `--output FILE` or the default
`reports/scan-<runId>.md`); the draft is masked. `scan --submission-bundle DIR` additionally writes a bundle folder (one file per report plus
`index.md`) covering every target of the run, written once at the end of the run. The bundle path is reported on the `summary` JSON Lines
event (`submissionBundle`). Both are masked unless `--full-secrets` is set, and `--full-secrets` only ever writes unmasked values to a file,
never to standard output.

**From saved reports.** `report submit REPORT.json [REPORT2.json ...] [--out FILE | --bundle DIR] [--full-secrets]` renders drafts from one
or more saved JSON scan reports (`schema exposure-scan/1`), grouping findings with the same `findingId` across the reports into one draft.

- With neither `--out` nor `--bundle`, the masked Markdown document is written to standard output.
- `--out FILE` writes one Markdown file; `--bundle DIR` writes a bundle folder. The two are mutually exclusive.
- `--full-secrets` includes unmasked values and is **refused** (exit 2, nothing written) without `--out`/`--bundle`, because standard output
  must never hold an unmasked value. An unmasked value is only present when the input report is a sensitive full-secret export carrying a
  `secrets` field; otherwise the output stays masked even with the flag.
- A file that is not JSON, or not an Exposure Desk scan report, exits 2 with the offending path named.

## Dashboard

For a live or retained run, `POST /api/scans/<id>/submission` with `{ "findingId": "<id>" }` returns `{ markdown, title, fileName }` for that
one finding. The Markdown is built server-side from the redacted view (no values are passed in) and re-masked before it is sent, so the
response never carries a full value. The action sits behind the same host/origin/session/CSRF checks as every other `POST /api/scans/<id>/…`
action; an unknown `findingId` is a 400. The dashboard never writes unmasked submission files — full values stay with the `report submit`
and `scan --full-secrets` file paths above.

## Limits

- The drafts describe what Exposure Desk observed. They do not establish that a key works, what it can access, or that any loss happened. Check each draft, follow the program's rules (some programs ask you not to include full secrets, or to submit them through a specific field), and set the platform severity yourself.
- The `tail -c` offset matches the file as served when the response is UTF-8 text. It may not match for other character sets. The line and column are always given as well.
- A report can only be as complete as its record. Older saved runs without a `findingId`, priority or impact list still render, with "not recorded" or the provider fallback in place of the missing fields.
