# Recon lists and source-map rebuild

`src/recon/` turns what a scan already downloaded or captured into plain recon lists, and can rebuild the original source tree from
public source maps. It never makes a request of its own: everything comes from resources the scanner fed it, and sources that are not
embedded in a map are listed as not recoverable instead of being fetched.

The scanner, CLI and dashboard are wired to this module. The command flags and the exact hooks are documented under
[Using recon from the CLI](#using-recon-from-the-cli) and [Scanner, CLI and dashboard hooks](#scanner-cli-and-dashboard-hooks) at the end
of this page.

## Recon lists

`ReconCollector.add({url, kind, contentType, text, headers})` is called once per resource. `result()` returns sorted (by UTF-16 code
unit), de-duplicated lists. `writeRecon(dir, result)` writes them.

| File | One line per | Notes |
| --- | --- | --- |
| `urls.txt` | absolute URL (`http`, `https`, `ws`, `wss`) | resolved against the resource URL; fragment and user info removed; query reduced to names (`/login?next`) |
| `endpoints.txt` | path or API route | from JS strings, `fetch`/`axios`/`$.ajax`/`XMLHttpRequest.open`/`navigator.sendBeacon`/`new WebSocket`/`EventSource`, route tables (`path:`, `<Route path>`), HTML forms and links, robots rules; template expressions become `{EXPR}` (`/api/v2/products/{EXPR}/reviews`); route parameters stay (`/orders/:id`) |
| `hosts.txt` | host name | every host is classified; see below |
| `hosts-in-scope.txt`, `hosts-out-of-scope.txt`, `hosts-third-party.txt` | host name | `hosts.txt` split by scope |
| `parameters.txt` | query or body parameter name | from URLs, `URLSearchParams`/`FormData` calls, request body objects, form fields; never a value |
| `js.txt` | script URL | query removed |
| `sourcemaps.txt` | source-map URL | from `sourceMappingURL` comments, `SourceMap`/`X-SourceMap` headers, `.map` resources and maps passed to `addSourceMap`; query removed; inline `data:` maps are only counted |
| `graphql.txt` | `query Name`, `mutation Name`, `subscription Name`, `operation Name`, `endpoint /path` | operations from GraphQL documents and `operationName`; endpoints from paths containing `graphql`, `graphiql` or `gql` |
| `recon.json` | everything above with provenance | see below |

An empty list gives an empty file. Lines never contain line breaks or control characters.

### Host scope

The caller passes a scope decision function: `(url) => 'in-scope' | 'out-of-scope' | 'third-party' | {scope, reason}`. It is called once
per origin (`https://host:port/`; `ws`/`wss` are classified as `http`/`https`). `scopeFromPolicy(new ScopePolicy(config))` adapts the
scanner's scope policy:

| Policy result | Recon scope | Reason |
| --- | --- | --- |
| `protectedHost()` (government/military block) | out-of-scope | `protected-host` (always wins) |
| explicit seed, explicit related origin, in-domain | in-scope | the class (`explicit-seed`, `explicit-related`, `in-domain`) |
| outside, `third-party` | third-party | `third-party` |
| outside, any other reason | out-of-scope | the policy reason (`exact-origin-mode`, `outside-host-subtree`, `ip-literal`, `no-public-suffix`, ...) |

A classifier that throws gives `out-of-scope` / `classifier-error`. A host seen on several origins keeps its most permissive verdict
(in-scope, then third-party, then out-of-scope). Hosts of URLs and resources are always listed. Bare host-name strings in scripts
(`"api.shop.example"`) are listed only when they belong to the scanned site (in scope, or `exact-origin-mode` / `outside-host-subtree`),
so `e.target`-style property chains and unrelated domains do not flood the list. The path of an absolute URL in a request call
(`fetch("https://api.shop.example/v2/orders")`) is added to `endpoints` only when its host is in scope.

### recon.json

```json
{
  "schema": "exposure-recon/1",
  "generatedAt": "2026-10-10T00:00:00.000Z",
  "resources": {"seen": 12, "scanned": 10, "skipped": 0, "truncated": 0, "maps": 2},
  "limits": {"maxItemsPerList": 50000, "...": "..."},
  "counts": {"urls": 31, "endpoints": 24, "hosts": 10, "parameters": 22, "js": 2, "sourcemaps": 2, "graphql": 4},
  "dropped": {"urls": {"over-limit": 0, "too-long": 0, "secret": 0}, "...": {}},
  "redactions": 0,
  "inlineSourceMaps": 0,
  "lists": {
    "endpoints": [{"value": "/api/v2/orders", "source": "https://shop.example/static/app.js?v"}],
    "hosts": [{"value": "cdn.vendor.example", "source": "https://shop.example/", "scope": "third-party", "reason": "third-party"}],
    "graphql": [{"value": "query GetProduct", "source": "https://shop.example/static/app.js?v", "type": "query", "name": "GetProduct"}]
  }
}
```

`source` is the first resource the item was seen in, cleaned the same way as a URL (query names only). `resources.seen` counts every
`add()`, including script-inline and embedded sources; `skipped` counts images, fonts, media and binaries; `truncated` counts resources
longer than `maxTextChars`; `maps` counts source-map resources.

### Credentials never reach a list

* Query and fragment values are always dropped; only names are kept (`?token=abc` becomes `?token`). Matrix parameters (`;jsessionid=...`)
  keep their name only. User info in URLs is removed.
* A path segment that looks like a credential is replaced with `{redacted}`: known key formats (cloud, payment, source-hosting, chat,
  AI-provider and messaging tokens, JWTs, private-key headers, `password=`/`secret=`/`sig=` pairs), whole-segment hex keys of 32+
  characters (lower-case 40-hex commit IDs stay), and random-looking mixed-case tokens of 24+ characters. Slack and Discord webhook paths
  always have their token segment redacted. `redactions` counts the replacements.
* Every finished item is checked once more against the known formats (raw and percent-decoded). A match is dropped and counted in
  `dropped.<list>.secret`, never written. An optional `secretFilter` (for example the scanner's detector) adds a second screen; if it
  throws, the item is dropped (fail closed). A provenance label that matches is written as `{redacted}`.
* `writeRecon` re-checks every line before writing, so even a hand-built result cannot put a known credential shape or a line break in a
  file.

### Caps

| Limit | Default | When reached |
| --- | --- | --- |
| `maxItemsPerList` | 50,000 | later new items are counted in `dropped.<list>.over-limit` |
| `maxUrlLength` | 2,048 characters | URL dropped, `too-long` |
| `maxEndpointLength` | 1,024 characters | endpoint dropped, `too-long` |
| `maxNameLength` | 128 characters | parameter or GraphQL name dropped, `too-long` |
| `maxHostLength` | 253 characters | host dropped, `too-long` |
| `maxTextChars` | 16 MiB of text per resource | the rest is not scanned; `resources.truncated` |
| `maxMatchesPerPattern` | 50,000 per pattern per resource | further matches of that pattern are ignored |

Every pattern is bounded and linear-time (no nested quantifiers on overlapping classes): the test suite's hostile inputs (about a
dozen 0.5-2 MB repetition bombs, each scanned as both script and HTML) finish in roughly a second together.

### Output folder

`writeRecon(dir, result)` creates the folder when missing, refuses a symbolic link or junction (`unsafe-output`) and a non-folder
(`output-not-directory`), and restricts it to the current user (Windows: owner-only inherited ACL through the project's
`restrictWindows`; elsewhere `0700`, files `0600`). Each file is written to a new temporary file and renamed, so a rerun replaces the
recon files atomically and leaves other files in the folder alone.

## Source-map rebuild

`SourceRebuilder.create(dir)` prepares a new or empty folder (refusing links, non-folders and non-empty folders), restricted to the
current user. `add(mapUrl, map)` takes the map text or parsed object; calls are serialized and never throw. `finish()` writes
`MANIFEST.json` and returns it; later `add()` calls are ignored. `rebuildSources(dir, [{url, map}])` does all three.

Only `sourcesContent` embedded in the map is written. A source with `null` or missing content is listed under `notRecoverable` with
`no-sources-content`; a non-string entry with `invalid-sources-content`; an index-map section that points to a `url` with
`section-url-not-fetched`. Nothing is ever fetched: the module performs no network I/O at all.

### Path sanitizing

Each source name (after `sourceRoot` is applied to relative names) becomes a relative path that cannot leave the output folder:

* Win32 device prefixes (`\\?\`, `\\.\`, `\??\`), schemes (`webpack://`, `vite://`, `file://`, `https://` — the host of an `http(s)` URL
  becomes the first folder), drive letters, UNC prefixes and leading slashes are removed. Backslashes are folder separators.
* Query values are dropped (`?v=3` becomes `_v`), credential-shaped segments become `{redacted}`, control, bidi and zero-width
  characters are removed.
* `.` and empty segments are dropped; `..` removes the previous segment and is clamped at the root (`webpack://shop/../lib/a.js` is
  `lib/a.js`; `../../../../etc/passwd` is `etc/passwd`).
* `< > : " | ? *` become `_`; trailing dots and spaces are trimmed.
* Windows device names (`CON`, `PRN`, `AUX`, `NUL`, `COM0-9`, `LPT0-9`, superscript-digit variants, `CONIN$`, `CONOUT$`, `CLOCK$`), with
  or without an extension, get a `_` prefix. So do VCS and editor folders (`.git`, `.hg`, `.svn`, `.bzr`, `_darcs`, `.jj`, `.vscode`,
  `.idea`) and `desktop.ini`, `autorun.inf`, `.directory`.
* Files with shell-processed extensions (`.lnk`, `.url`, `.scf`, `.library-ms`, `.searchconnector-ms`, `.desktop`, `.appref-ms`,
  `.website`, `.pif`, `.settingcontent-ms`) get `.txt` appended.
* Segments are capped at 100 characters and paths at 240 (shortened names keep a hash, so they stay distinct). A name longer than 4,096
  characters becomes `_long/<hash>`. A name with nothing left becomes `_unnamed`.

Folders are created one level at a time; each level must be a real folder (not a link or junction) whose real path is the expected path
inside the output folder, otherwise the file is skipped as `unsafe-directory`. Files are created with exclusive create, so an existing
file or link is never overwritten.

### Collisions

All maps write into one tree. Paths are compared case-insensitively (NFC, lower case), so the result is the same on every file system:
a folder keeps its first spelling (`Src/b.ts` lands in `src/`), a second file with the same name and different content gets `~1`, `~2`
(`app~1.ts`), and a folder whose name is already a file gets `~n`. `MANIFEST.json` at the root is reserved. Identical content at the
same path is written once; other maps that carried it are listed in `alsoIn` (up to 100) and counted as `duplicates`.

### Caps

| Limit | Default | When reached |
| --- | --- | --- |
| `maxFiles` | 10,000 | further sources skipped, `file-limit` |
| `maxTotalBytes` | 256 MiB | further sources skipped, `total-byte-limit` |
| `maxFileBytes` | 32 MiB (UTF-8) | that source skipped, `file-too-large` |
| `maxSourcesPerMap` | 50,000 | the rest counted in `sourcesOverLimit` |
| `maxSectionDepth` | 4 | map error `section-depth-limit` |
| `maxSections` | 1,000 across all maps | map error `section-limit` |
| `maxMapBytes` | 64 MiB of map text | map error `map-too-large` |
| `maxMaps` | 1,000 | further maps counted in `totals.maps` only, `truncated.maps` |
| `maxListed` | 10,000 entries in `notRecoverable` and in `skipped` | totals still count all; `truncated.*` |

### MANIFEST.json

```json
{
  "schema": "exposure-recon-sources/1",
  "generatedAt": "2026-10-10T00:00:00.000Z",
  "note": "Rebuilt only from sourcesContent embedded in public source maps. ...",
  "files": [
    {"path": "shop/src/index.ts", "sha256": "…", "bytes": 92, "sourceMap": "https://shop.example/static/app.js.map?v", "source": "webpack://shop/./src/index.ts"}
  ],
  "notRecoverable": [{"source": "webpack://shop/./src/missing.ts", "sourceMap": "https://shop.example/static/app.js.map?v", "reason": "no-sources-content"}],
  "skipped": [{"source": "big.js", "sourceMap": "…", "reason": "file-too-large", "path": "big.js"}],
  "maps": [{"sourceMap": "…", "sources": 4, "written": 3, "duplicates": 0, "notRecoverable": 1, "skipped": 0, "sourcesOverLimit": 0, "sections": 0}],
  "totals": {"maps": 1, "files": 3, "bytes": 210, "duplicates": 0, "notRecoverable": 1, "skipped": 0, "sourcesOverLimit": 0},
  "truncated": {"notRecoverable": false, "skipped": false, "maps": false},
  "limits": {"maxFiles": 10000, "...": "..."}
}
```

`path` is relative to the output folder with `/` separators, and `sha256` is over the bytes written. `sourceMap` is the cleaned map URL;
an inline map is `data:(inline source map)`, or `inline:<resource URL>` when the caller passes `{inline: true}`. A map's `error` is one
of `invalid-map`, `map-too-large`, `section-depth-limit`, `section-limit`.

### Safety notes

* Rebuilt files are the site's public source **verbatim**. They may contain credentials. The recon lists are credential-free; the rebuilt
  tree is not. That is why the folder is owner-only; treat it like an unmasked report file.
* Nothing is executed or fetched. Rebuilt files are plain data; shell-processed extensions are neutralized so a double-click cannot run a
  shortcut.

## Using recon from the CLI

Recon is produced by the `scan` command from a normal scan; it makes no extra requests.

* `--recon DIR` writes the recon lists for the scan into `DIR`. For a single target the lists sit directly in `DIR`; with `--targets`
  each target gets a `N-host` subfolder (for example `1-app.example.com`) and `DIR` also holds a **merged** top-level set that unions the
  per-target lists (a host keeps its most permissive scope). The folder is made owner-only. The recon paths are reported on the
  `target-end` (`recon`) and `summary` (`recon`) JSON Lines events, never on standard output.
* `--rebuild-sources DIR` rebuilds the original source tree from the public source maps the scan saw. `DIR` must be new or empty, or the
  command exits 2 with a one-line usage error. One shared tree is built across all targets. The rebuilt tree legitimately contains public
  source (which may include values), so it is owner-only and is only ever written to disk — never printed, and never on JSON Lines beyond
  its folder path (`summary.rebuild`). A one-line notice names the folder when the rebuild is requested. `--rebuild-sources` works with or
  without `--recon`; without `--recon` the collector still runs but no lists are written.
* On a loopback development fixture (every seed URL's origin equals `--config`'s `developmentFixtureOrigin`) the recon and rebuild folders
  skip the owner-only ACL step, mirroring the dashboard store and the submission output, so tests on `127.0.0.1` do not require elevation.
* A mass run (`--concurrency N`, `--state FILE`) writes the same folders; on a `--state` resume the targets an earlier run finished keep their
  recon folders and join the merged set again, while `--rebuild-sources` needs a new or empty folder and covers only the targets that run
  scans. See [docs/MASS_SCAN.md](MASS_SCAN.md#recon-rebuild-and-submission-output).

## Dashboard

When the dashboard runs with a persistent store, every stored run keeps its recon lists under `<data-dir>/recon/<runId>/` (written on
finish, with the default caps, owner-only unless the store is synthetic). `GET /api/scans/<id>/recon/<file>` downloads one list as an
attachment. The route is GET-only, sits behind the same host/origin/`Sec-Fetch-Site`/session checks as every other `/api` route, and the
file name must be one of the fixed `RECON_FILES` names, so no path can be traversed. The lists are masked by construction. `store.deleteScan`
removes `recon/<id>` with the rest of the run.

## Scanner, CLI and dashboard hooks

The core takes no scanner dependency. The wiring (`src/scanner.ts`, the CLI and `src/dashboard.ts`) is:

1. **Construct** in `Scanner.init()` when recon output is requested (`new Scanner(config, { recon: { limits?, rebuilder? } })`; the desk
   passes `recon: {}` whenever a store exists, and the CLI passes a rebuilder when `--rebuild-sources` is set):
   ```ts
   import { ReconCollector, scopeFromPolicy } from './recon/index.js';
   import { programScope } from './program/settings.js';
   const base = scopeFromPolicy(this.transport.scope);
   // A program narrows the host lists: a host the transport would call in-scope but the program does not allow is listed
   // out-of-scope with reason 'program-out-of-scope'. Without a program, the transport scope is used unchanged.
   const prog = this.config.program ? programScope(this.config.program) : undefined;
   const classify = prog ? (url: string) => {
     const d = base(url), scope = typeof d === 'string' ? d : d.scope;
     return scope === 'in-scope' && !prog.allows(url) ? { scope: 'out-of-scope' as const, reason: 'program-out-of-scope' } : d;
   } : base;
   this.recon = new ReconCollector({ classify, rebuilder: this.reconRequest.rebuilder,
     secretFilter: v => { try { return this.detector.inspectWindowed(v, false, this.analysis).length > 0; } catch { return true; } } /* fail-closed: a throw is treated as a secret; per-scan detector scope (w1-budget) */ });
   ```
2. **Feed resources**: first statement of `Scanner.discover(text, url, depth, chain, kind, headers, ...)`, before the source-map dispatch:
   ```ts
   this.recon?.add({ url, kind, contentType: String(headers['content-type'] || ''), text, headers });
   ```
3. **Feed parsed maps**: in `Scanner.map()`, right after
   `this.evidence.observe(url, 'public-source-map', ...)` (the point reached only by a schema-valid flat map, including each section
   child and each inline map):
   ```ts
   await this.recon?.addSourceMap(url, j, { inline: chain[chain.length - 1] === 'inline source map' });
   ```
   `inlineMap()` passes the embedding resource's URL and appends `'inline source map'` to the chain; the flag keeps that URL out of
   `sourcemaps.txt` and labels the manifest entry `inline:<url>`. Section children arrive as `url#section-...`; the fragment is removed
   from labels.
4. **Finish** at the end of the scan (also on an aborted scan, so partial results are kept):
   ```ts
   await writeRecon(reconDir, this.recon.result());
   const manifest = await rebuilder?.finish();
   ```
5. **Errors**: `SourceRebuilder.create` and `writeRecon` throw `ReconOutputError` with `code` `unsafe-output`, `output-not-empty`,
   `output-not-directory` or `write-failed`; map these to the CLI's usage error. Nothing else in the module throws.
