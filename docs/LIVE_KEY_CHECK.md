# Live key check (opt-in)

A **live key check** answers one question about a single finding: *does this key still work?* It makes one read-only "who am I" request to that key's own provider and records the result — **live**, **revoked** or **unknown** — as evidence on the finding.

It is **off by default** and does nothing unless a person turns it on for a program and then explicitly checks a key. A scan never performs it.

## What it never does

- **No scan ever checks a key.** Checking happens only when a person clicks **Check if live** on a finding, or runs the `check-key` command. It is never automatic, never part of a scan, never runs after a scan, and is never offered in mass scan or the ready options.
- **Only the key leaves your computer.** The request carries the key in the one header the provider documents and nothing else from the scan — no URL, no file path, no context, no other finding. The key is never put in a URL, path or query string.
- **Read-only.** Each recipe targets a provider's official identity or metadata endpoint. The check never signs in, never writes, never creates or deletes anything and never triggers paid usage.
- **It does not change the finding's validity.** A finding's `validity` stays `unverified` whatever the check returns. The live-check result is stored separately, alongside the finding.
- **The protected-host block still applies.** If a recipe host were ever a government, military, intelligence or law-enforcement host it would be refused before any DNS lookup, with no override. The same address guards a scan uses (protected host, private/internal/cloud-metadata refusal, DNS pinning, no redirects) run on this path too.
- **The honest product User-Agent is sent.** No spoofing, no evasion.

## How to enable it

Add a `liveKeyChecks` block to the program file (`program.json`):

```json
{
  "id": "0123456789abcdef",
  "scope": { "in": ["example.com"], "out": [] },
  "liveKeyChecks": { "enabled": true }
}
```

- `enabled: true` turns on the **per-finding** check (the **Check if live** button and the `check-key` command).
- `checkAll: true` is a **separate** permission that additionally allows **Check all** / `--all`. With only `enabled: true`, check-all stays off. Leaving `liveKeyChecks` out entirely keeps everything off.

Both sub-keys are validated strictly: unknown fields or wrong types are rejected, and program files without a `liveKeyChecks` block keep loading unchanged.

Many bug-bounty programs forbid using or testing found credentials at all. Enabling this is your declaration that the program you are working under permits an active check. Confirm that before you turn it on.

## Checking one key

Dashboard: open a finding in **Advanced**, click **Check if live**, and confirm the dialog (it names the exact host that will be contacted). The result appears on the finding; until then it reads **not checked**.

Command line:

```
exposure-desk check-key FINDING-ID --program ./program.json --authorized
```

- `--authorized` is required; it is your confirmation that you are permitted to run the check.
- The key value is read from the unlocked vault (`EXPOSURE_VAULT_PASSWORD`) and is never printed. A finding whose value was redacted and is not in the vault cannot be checked.
- `--run SCAN-ID` selects a finding from a specific scan; `--data-dir DIR` points at a non-default data folder.

## Check all (only when `checkAll` is set)

When the program sets `checkAll: true`, the dashboard shows a **Check all** panel and the command accepts `--all`. The run is deliberately slow and cautious:

- one key at a time, never in parallel;
- paced per provider (about one request per second to a given provider);
- progress is shown and the run can be cancelled;
- the **first** rate-limit or refusal from a provider (HTTP 429, 403, or a connection refusal) **halts that provider** for the rest of the run; other providers continue.

## What the verdicts mean

| Verdict | Meaning |
| --- | --- |
| **live** | The provider accepted the key on its identity endpoint (HTTP 200, or for Slack `ok: true`). The key still works. |
| **revoked** | The provider rejected the key with a status the recipe recognises as "this credential is not valid" (for example 401, or for Slack a known auth error such as `token_revoked`). |
| **unknown** | Anything else: no recipe for this provider, a rate-limit, a network or TLS error, an unexpected response shape, or a refused address. Nothing conclusive — the result is recorded with a short reason code. |

The mapping is deliberately conservative: only a documented success means **live**, only a documented rejection means **revoked**, and everything ambiguous stays **unknown**.

**`revoked` is not global revocation.** It means the key failed this one provider's check now; it does not mean anyone revoked it, and it is not a substitute for the real fix. The correct action for any found secret is still to have its owner rotate or revoke it.

## Supported providers

Each provider has one hand-written recipe pointing at that provider's own documented read-only endpoint. Lookup is by exact detector rule id and **fails closed**: a finding whose rule matches no recipe sends nothing and returns **unknown** (`no-recipe`).

| Provider | Endpoint contacted | How the key is sent |
| --- | --- | --- |
| GitHub | `GET https://api.github.com/user` | `Authorization: Bearer` |
| GitLab | `GET https://gitlab.com/api/v4/user` | `PRIVATE-TOKEN` header |
| OpenAI | `GET https://api.openai.com/v1/models` | `Authorization: Bearer` |
| Anthropic | `GET https://api.anthropic.com/v1/models` | `x-api-key` header |
| Stripe | `GET https://api.stripe.com/v1/balance` | HTTP Basic |
| SendGrid | `GET https://api.sendgrid.com/v3/scopes` | `Authorization: Bearer` |
| Slack | `POST https://slack.com/api/auth.test` | `Authorization: Bearer` |

These hosts are the complete egress allowlist for the check: no request can be made to any other host. The endpoints are read-only identity/metadata calls taken from each provider's official API documentation.

## Where the result is stored

The verdict is saved locally with the finding (result, time checked, provider, endpoint host, and a short status/reason code) and shown masked in the dashboard and reports. It never leaves your computer, and it never alters the finding's `validity`, which remains `unverified`.

See also [PRIVACY.md](PRIVACY.md), [ACCEPTABLE_USE.md](ACCEPTABLE_USE.md) and [docs/PROGRAM.md](PROGRAM.md).
