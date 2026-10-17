# Program files (`program.json`)

Schema: **`exposure-program/1`**. Added in 2.8.0.

A program file describes one bug bounty or disclosure program: what is in scope, what is out of scope, how fast Exposure Desk may send requests across the whole run, and which identification headers the program asks researchers to send. It lives in the folder you already pass with `--program DIR` (the folder that holds the program's correlation key since 2.7). In the examples, `exposure-desk` stands for `node dist/src/cli.js` (in the Windows package, `runtime\node.exe dist\src\cli.js`).

```
exposure-desk program init ./example-program
exposure-desk program check ./example-program
exposure-desk scan --targets hosts.txt --authorized --program ./example-program --jsonl
```

Between `init` and `check`, fill in `scope.in` (the template leaves it empty, so `check` refuses it until you do) and read the program's policy before you set `"authorized": true` or pass `--authorized`.

A folder **without** `program.json` keeps the 2.7 meaning: `--program DIR` only selects the correlation key, and nothing else changes.

## What a program file can and cannot do

- It can only **narrow** what a scan contacts. Every 2.7 scope rule (entered origins, domain scope, related origins, the protected-host block) still applies first; the program scope is an extra filter on top.
- It never overrides a hard rule. Government, military, intelligence and law-enforcement websites are never scanned, whatever the file says. Found keys never leave the computer, data stays local, and there is no evasion: the User-Agent stays honest, and there is no fingerprint faking and no IP or proxy rotation.
- `"authorized": true` counts as `--authorized` for in-scope targets. It is your statement that the program's policy authorizes testing these assets. It never widens the scope.
- When `program.json` exists, a scan needs authorization: `"authorized": true` in the file or `--authorized` on the command line. Without either, the scan is refused with exit 2 before any request.
- Every error (unknown field, bad value, invalid rule, protected host, unreadable file) is a refusal with exit 2 **before any request**.

## Fields

The file is JSON with `//` and `/* */` comments allowed (a UTF-8 byte-order mark is fine). It may be at most 4 MiB. Unknown fields are refused at every level, so a typo can never be silently ignored.

| Field | Type | Default | Meaning |
|---|---|---|---|
| `schema` | string | required | Must be `"exposure-program/1"`. |
| `name` | string | none | The program name, for your records and the run's info line (up to 100 characters). |
| `platform` | string | none | Where the program runs, for example `hackerone` (up to 40 characters). |
| `authorized` | boolean | `false` | `true` counts as `--authorized` for in-scope targets. |
| `scope.in` | array of rules | required, at least one | In-scope rules. Anything not matched by an in rule is out of scope. |
| `scope.out` | array of rules | `[]` | Out-of-scope rules. They always win over in rules. |
| `rate.requestsPerSecond` | number | `5` | Requests per second across the whole program run, all targets and both engines together. From 0.1 to 50. |
| `concurrency.targets` | whole number | `4` | Targets at once (1 to 64) when this program scans a target list of two or more targets. It is the default for `--concurrency`; an explicit `--concurrency N` wins. It is a maximum: fewer targets run at once while the scan process's memory is short (see [MASS_SCAN.md → Memory gate](MASS_SCAN.md#memory-gate)). See [MASS_SCAN.md](MASS_SCAN.md). |
| `concurrency.requests` | whole number | `16` | Requests in flight at once across the whole run (1 to 64). |
| `headers` | object | `{}` | Identification headers the program asks for, such as `X-Bug-Bounty`. Up to 8 headers. |
| `userAgentSuffix` | string | none | Text appended to the User-Agent, such as your platform username (up to 128 characters). |
| `analysisMemoryMb` | whole number | none | Analysis memory for this program's runs, 64 to 2048 MiB. This is the only way to go above the 512 MiB ready-option limit. It is still lowered automatically when the computer has less free memory. Above 512 MiB it also raises the scan process's memory ceiling for a target list run several at once (512 MiB otherwise, at most 2048 MiB; see [MASS_SCAN.md → Memory gate](MASS_SCAN.md#memory-gate)). |

There are 10,000 rules at most across `in` and `out`.

### Headers

Program headers identify you to the program. They are never a way to change routing or to authenticate:

- The names must be `X-…` identification headers with a plain name (letters, digits and `-`, up to 64 characters). Values are printable ASCII on one line, up to 256 characters.
- Client-address, routing, method-override and cloud headers are refused, for example `X-Forwarded-For`, `X-Real-IP`, `X-Original-URL`, `X-HTTP-Method-Override`, `X-Amz-…` and `X-Goog-…`.
- Names that look like credentials (`token`, `auth`, `key`, `secret`, `session`, `cookie` and similar) are refused. `Authorization`, `Cookie` and `User-Agent` are never set by a program.
- A value that looks like a credential is refused, and the value is not shown in the error.

Headers go on **static and browser requests**, and **only toward URLs inside the program scope**. They are added after the 2.7 outbound header policy, so a page can never override them, and they are never sent to an origin outside the scope.

### User-Agent suffix

`userAgentSuffix` is **appended**, never a replacement: `ExposureDesk/… researcher-1` for static requests, and Chromium's own User-Agent plus the suffix for browser requests. It must not contain browser product tokens such as `Mozilla/`, `Chrome/` or `Safari/`, so it cannot be used to look like a different client. It needs the product User-Agent, so `staticUserAgent: "none"` together with a suffix is refused as conflicting settings.

## Scope rules

Each rule is one string. The forms are:

| Rule | Matches |
|---|---|
| `app.example.com` | That exact host, with any scheme and any port. |
| `*.example.com` | Subdomains of `example.com` at any depth, **not** `example.com` itself. Add `example.com` as its own rule to include the apex. |
| `https://api.example.com/v1/` | URLs with that scheme, host and port (the default port for the scheme when none is given) whose path starts with `/v1/`. A wildcard host also works: `https://*.example.com/`. |
| `192.0.2.10`, `[2001:db8::1]` | URLs that name that IP address. |
| `192.0.2.0/24`, `2001:db8::/48` | URLs that name an address in that block. |

- Out-of-scope rules always win, at host, wildcard, path and address level.
- IP and CIDR rules match URLs that name the address. They do not match host names that resolve into the block; DNS answers are checked separately by the 2.7 network rules.
- An in-scope wildcard over a public suffix (`*.com`, `*.co.uk`, `*.github.io`) is refused as too broad. So are in-scope CIDR blocks wider than `/8` (IPv4) or `/32` (IPv6). Out-of-scope rules may be broad.
- An in-scope rule that names a protected host (government, military, intelligence or law-enforcement) is refused. An out-of-scope rule may name one.
- Host names are compared lowercase in punycode form; a trailing dot is ignored.

`exposure-desk program check DIR` prints the effective scope, one rule per line, with what each rule covers.

## How a program run enforces the scope

- **Seeds.** A configured seed URL outside the program scope refuses the scan before any request: `Refused: URL is outside the program scope in FILE (see: exposure-desk program check DIR). Nothing was requested.` A related origin outside the scope is refused the same way.
- **Target lists.** With `--targets`, a line outside the program scope is rejected like any other bad line, with reason `out-of-scope` (after the protected-host check), and the rest of the list runs. Rejections appear on standard error and in the `run-start` JSON Lines event.
- **Every request.** Each request, including redirects, scripts, source maps, fixed paths such as `robots.txt`, and browser subresources, is checked against the program scope before it is sent. The protected-host block runs first. A URL outside the scope is **never contacted**; it is recorded in the report under the excluded scope examples with reason `program-out-of-scope`, and the scope gap names it.
- A URL outside a URL-prefix rule on an otherwise authorized origin does not take an inventory slot. A redirect that leaves the scope leaves its target uninspected, so the run can honestly report itself as incomplete.

## Program-wide limits

All transports of one program in one process share a single limiter:

- `rate.requestsPerSecond` spaces request starts across every target and both engines (static and browser).
- `concurrency.requests` caps the requests in flight across the run.
- The limiter is an extra gate after the 2.7 per-origin and global limits; it never raises them.

The run's info line shows the limits, and the summary shows how often requests waited:

```
Program: Example program · 3 in-scope and 1 out-of-scope rules · up to 5 requests per second and 16 at once across the run · authorized in program.json
...
Program limit: 412 requests, 37 waited for the program limit (5210 ms in total), at most 16 at once.
```

The JSON Lines `summary` event carries the same numbers under `program`. When a target list runs several targets at once, a request that waits only because other targets hold the program's request slots does not use up its own target's time allowance (a wait right after the target's own grant does); see [MASS_SCAN.md → Time waiting for shared capacity](MASS_SCAN.md#time-waiting-for-shared-capacity).

## Commands

All program commands are offline. They read and write local files only and never send a request.

### `program init DIR`

Writes a commented template to `DIR/program.json`, with `"authorized": false` and an empty `scope.in` that you must fill in. It refuses to replace an existing file.

### `program check DIR`

Validates `DIR/program.json` and prints the effective settings and scope. Exit 0 when the file is valid, exit 2 with the reason otherwise.

### `program import --platform hackerone-csv|bounty-targets --file FILE [--handle NAME] DIR`

Builds `DIR/program.json` from a scope file you downloaded yourself:

- **`hackerone-csv`**: the CSV a HackerOne program page exports from its scope table. It needs the `identifier` and `asset_type` columns. `eligible_for_submission` set to false puts the asset out of scope.
- **`bounty-targets`**: a file from the public bounty-targets-data project, such as `hackerone_data.json`, `bugcrowd_data.json`, `intigriti_data.json`, `yeswehack_data.json` or `federacy_data.json`. When the file lists more than one program, choose one with `--handle`. It matches the handle, id, name, slug or the last segment of the program URL, ignoring case. An ambiguous handle is refused.

Mapping:

- Website, URL, wildcard, domain and API assets become scope rules. IP address and CIDR assets become IP and CIDR rules. An asset with several identifiers (a description and a URL, for example) uses the first one that forms a valid rule.
- Out-of-scope and ineligible assets go to `scope.out`.
- Mobile apps, source code, hardware, executables, other non-web assets and descriptions that are not a valid rule are **skipped**. Each is listed with its reason on standard error and as a comment in the file.
- A protected host (government, military, intelligence or law-enforcement) is **refused**. It is listed on standard error and as a comment and never becomes an in-scope rule.
- The import **never** sets `"authorized": true`. Read the program's policy, then set it yourself.
- The written file is validated before it is written, is created with owner-only permissions where the system supports them, and never replaces an existing `program.json`. Text from the imported file only appears inside comments, flattened to one line.

The file is read with a 256 MiB limit. Nothing is fetched: download the scope file yourself and pass its path.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success (`init`, `check`, `import`), or a scan finished with no finding at or above `--fail-on`. |
| 1 | A scan finished with a finding at or above `--fail-on`. |
| 2 | A usage error, an invalid program file, a refusal (authorization, scope, protected host) or an incomplete scan. |
