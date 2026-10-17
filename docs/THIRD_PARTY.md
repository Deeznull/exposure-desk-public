# Dependency provenance

Versions are exact in package.json and transitive versions/integrity hashes are locked in package-lock.json. Native Gitleaks installation uses its official release checksum. Chromium installation is paired with the pinned Playwright version, using Playwright's official installer.

Exposure Desk 2.0 adds:

- re2-wasm 1.0.2: Apache-2.0, [official project](https://github.com/google/re2-wasm). WASM RE2 provides bounded-time matching for declarative company rules; incompatible syntax is rejected. Its package includes LICENSE and third-party notices.
- @jridgewell/trace-mapping 0.3.31 and locked resolve-uri/sourcemap-codec: MIT, [official monorepo](https://github.com/jridgewell/sourcemaps/tree/main/packages/trace-mapping); individual npm packages include licenses.
- Portable Node.js 24.18.1: MIT and bundled third-party notices in runtime/LICENSE, [official distribution](https://nodejs.org/dist/v24.18.1/). The ZIP SHA-256 is verified against the official HTTPS SHASUMS256.txt; GPG signature verification is not claimed.
- Dedicated Chrome for Testing 153.0.8010.12: Chromium and third-party notices remain in the browser distribution. [Official Chrome for Testing](https://googlechromelabs.github.io/chrome-for-testing/). The candidate records the SHA-256 of the official HTTPS archive locally; no publisher-provided signature/checksum for that archive was available. A recorded local hash is not publisher signature verification.

The portable candidate retains each included npm dependency's license, Node's notices, Gitleaks LICENSE, and all browser distribution files. Ordinary Windows storage and launch have been exercised; broader platform/policy checks remain release-candidate limits.

- Gitleaks 8.30.1: MIT, [official repository](https://github.com/gitleaks/gitleaks), vendored rule license in `rules/GITLEAKS-LICENSE`. Updates require explicit version/integrity and compatibility review.
- Playwright 1.63.0: Apache-2.0, [official repository](https://github.com/microsoft/playwright). Browsers have their own upstream notices in the downloaded distribution.
- Acorn 8.19.0: MIT, [official repository](https://github.com/acornjs/acorn).
- ipaddr.js 2.5.0: MIT, [official repository](https://github.com/whitequark/ipaddr.js).
- Cheerio 1.2.0: MIT, [official repository](https://github.com/cheeriojs/cheerio).
- TypeScript and Node types: development/build tooling; the npm distribution includes each dependency's license.

Installation accesses package/release/browser distribution servers. Target analysis never submits scanned content to those servers. No LLM, telemetry, hosted scanner or paid service is a runtime dependency.

Exposure Desk 2.2 keeps these exact dependencies and native distributions. The offline Gitleaks 8.30.1 catalogue is pinned; upstream describes feature completeness and security-patch maintenance, not continuous provider-rule expansion. See coverage-registry.json for digest/provenance and the selected fixtures actually exercised.

- tldts 7.4.16 and tldts-core 7.4.16: MIT, [official project](https://github.com/remusao/tldts). Bundled maintained Public Suffix List rules, including private suffixes, determine registrable-domain scope locally. Exact versions and integrity are locked; update the dependency to refresh the PSL. No runtime PSL download occurs.

Exposure Desk 2.5 adds one vendored data file and no new npm dependency:

- BIP39 English wordlist (`rules/bip39-english.txt`, 2,048 words): MIT, copyright 2013-2016 Pavol Rusnak, from [trezor/python-mnemonic](https://github.com/trezor/python-mnemonic) tag v0.21 (`src/mnemonic/wordlist/english.txt`); license text in `rules/BIP39-WORDLIST-LICENSE`. The file is byte-identical to the canonical BIP-0039 English list; its SHA-256 `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda` is pinned in code and checked on first use (a missing or altered file disables only seed-phrase checks and is reported as a coverage issue). It was downloaded once with the owner's approval on 2026-10-08 and is never fetched at runtime.
- `rules/known-public-examples.json` contains only SHA-256 digests of values published in vendor documentation (for example the AWS documentation access key pair) and reference test vectors (BIP39 vectors, the Hardhat/Anvil development mnemonic and account key). No plaintext is stored; it was written for Exposure Desk.

The detection-quality update released in 2.6.0 (see archive/notes/HANDOFF_GITHUB_COMPARE.md, local working notes that are not packaged) adapts a few detection rules and adds no npm dependency. Every adapted piece carries a header comment naming the source repository, path, commit and licence; each line was reviewed and rewritten to the project style (no network calls, no evaluation, no other behaviour), and no test data or secret value was copied:

- Nosey Parker (Apache-2.0, Copyright 2022 Praetorian Security, Inc), [praetorian-inc/noseyparker](https://github.com/praetorian-inc/noseyparker) commit `2e6e7f36ce36619852532bbe698d8cb7a26d2da7`, `crates/noseyparker/data/default/builtin/rules/`: regular expressions for the Docker Hub, Firecrawl, Google OAuth client secret and access token, Jina, Square OAuth secret and Tavily rules in `src/detectors.ts`. Licence in `rules/NOSEYPARKER-LICENSE`, notice in `rules/NOSEYPARKER-NOTICE`.
- secretlint (MIT, Copyright (c) 2020 azu), [secretlint/secretlint](https://github.com/secretlint/secretlint) commit `5b7a74dace5027f3ae327bd9435ac7e20f41b10a`, `packages/@secretlint/secretlint-rule-figma`, `-tailscale` and `-vercel` (`src/index.ts`): regular expressions for the Figma, Tailscale, Vercel and Vercel AI Gateway rules in `src/detectors.ts`. Licence in `rules/SECRETLINT-LICENSE`.
- Gitleaks 8.30.1 (MIT, already vendored above), `config/gitleaks.toml` global `[allowlist]` regexes at tag v8.30.1 (commit `83d9cd684c87d95d656c1458ef04895a7f1cbd8e`): adapted into the template and placeholder recognition in `src/placeholders.ts`. Licence in `rules/GITLEAKS-LICENSE`.
- Design only, no code copied: the GitHub token CRC32 checksum in `src/token-checksums.ts` follows GitHub's published token-format description and was cross-checked against the independent implementations in [google/osv-scalibr](https://github.com/google/osv-scalibr) (Veles, Apache-2.0) and [mongodb/kingfisher](https://github.com/mongodb/kingfisher) (Apache-2.0). [praetorian-inc/titus](https://github.com/praetorian-inc/titus) (Apache-2.0) informed the comparison only.

The next rule version ports 31 further provider rules (Linear to Mapbox) from Gitleaks (MIT, commit `b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b`, `config/gitleaks.toml`, identical to the vendored v8.30.1 file) and Nosey Parker (Apache-2.0, commit `2e6e7f36ce36619852532bbe698d8cb7a26d2da7`). The source rule IDs, copyright notices and changes for each are listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). No new dependency was added.

No code, regular expression or wordlist was copied from TruffleHog (AGPL-3.0), SecretFinder (GPL-3.0) or secrets-patterns-db (mixed CC-BY-SA/AGPL); Katana, jsluice and Betterleaks informed design only.

## Licence audit for 2.6.0 (2026-10-09)

Exposure Desk's own code, documentation and rules written for it are proprietary ([LICENSE](../LICENSE), all rights reserved). Everything below keeps its own licence. The audit read the `license` field and the licence files of every installed package and the notices shipped with the runtimes; it is a technical inventory, not legal advice.

| Component (shipped in) | Licences found | Copyleft? |
| --- | --- | --- |
| npm packages in `node_modules/` (Windows package; the source package installs the same locked versions): 37 packages, including the build tools TypeScript 7.0.2 and @types/node | 21 MIT, 10 BSD-2-Clause, 5 Apache-2.0, 1 ISC | None |
| npm and corepack bundled with Node.js in `runtime/node_modules/` (Windows package): 145 packages | 72 ISC, 44 MIT, 11 BlueOak-1.0.0, 9 Apache-2.0, 5 BSD-2-Clause, 1 BSD-3-Clause, 1 Artistic-2.0 (npm itself), 1 CC-BY-3.0 (SPDX exception list data), 1 CC0-1.0 | None |
| Node.js 24.18.1 (`runtime/`, Windows package) | MIT, with the notices of its bundled components in `runtime/LICENSE` (OpenSSL Apache-2.0, ICU Unicode licence and others) | No. The only GPL text in `runtime/LICENSE` covers build macros of ICU4C under the Autoconf exception, not code in `node.exe` |
| Chrome for Testing 153.0.8010.12 (`browser/`, Windows package) | Google-branded test build of Chromium. Its `ABOUT` file states Google's copyright and points to `chrome://credits` (open-source components) and `chrome://terms` | Weak copyleft inside the browser only: Chromium's credits include components under licences such as LGPL-2.1 (for example FFmpeg) and MPL, shipped unmodified as part of the browser |
| Gitleaks 8.30.1 (`tools/gitleaks.exe`, Windows package) | MIT (`tools/LICENSE`) | None known; the Go modules compiled into the binary were not audited separately |
| Vendored rule and data files in `rules/` | Gitleaks rules MIT, Nosey Parker Apache-2.0 (licence and NOTICE), secretlint MIT, BIP39 wordlist MIT; `known-public-examples.json` and `company.example.json` written for Exposure Desk | None |
| Adapted regular expressions in `src/detectors.ts` and `src/placeholders.ts` | Apache-2.0 (Nosey Parker) and MIT (secretlint, Gitleaks), each with a header comment naming source, commit and licence | None. Nothing was copied from TruffleHog (AGPL-3.0), SecretFinder (GPL-3.0) or secrets-patterns-db (CC-BY-SA/AGPL) |
| npm packages in `node_modules/` (Linux x64 package) | The same 37 locked packages and licences as the Windows package (21 MIT, 10 BSD-2-Clause, 5 Apache-2.0, 1 ISC), counted in the shipped 2.8.0 Linux tar | None |
| npm and corepack bundled with Node.js in `runtime/lib/node_modules/` (Linux x64 package): 145 packages | The same mix as the Windows package (72 ISC, 44 MIT, 11 BlueOak-1.0.0, 9 Apache-2.0, 5 BSD-2-Clause, 1 BSD-3-Clause, 1 Artistic-2.0, 1 CC-BY-3.0, 1 CC0-1.0) | None |
| Node.js 24.18.1 for Linux x64 (`runtime/`, Linux package and container image) | MIT, with the notices of its bundled components in `runtime/LICENSE`; official nodejs.org archive, checksum-verified against SHASUMS256.txt (`scripts/linux-distributions.json`) | No, as for the Windows build |
| Chrome for Testing 153.0.8010.12 for Linux x64 (`browser/chrome-linux64/`, Linux package and container image) | As for the Windows build: Google's `ABOUT` file, `chrome://credits` and `chrome://terms` | Weak copyleft inside the browser only, as for the Windows build |
| Gitleaks 8.30.1 for Linux x64 (`tools/gitleaks`, Linux package and container image) | MIT (`tools/LICENSE`); official release archive, checksum-verified against the release checksums | None known; Go modules not audited separately |
| Container base image `node:24.18.1-bookworm-slim` (pinned by digest) and the Debian 12 packages added in the image (Chromium's system libraries from Playwright's `install-deps chromium` list, and tini) | Debian packages under their own licences, including GPL and LGPL system packages (for example glibc and bash); tini MIT | Yes, for some unmodified Debian system packages in the image. Not audited package by package |

The Linux package and container rows were added for 2.9.0 (2026-10-13), checked against the shipped 2.8.0 Linux tar and the Dockerfile.

Redistribution notes:

- **Chrome for Testing redistribution.** The Windows package ships Google's Chrome for Testing binaries. Their open-source components are covered by the credits, but the Chrome-branded build also refers to Google's terms. Before selling or widely distributing the Windows package, review whether those terms allow redistribution, or change the package to install the browser on first run with Playwright's official installer (the source package already installs it from **Settings**).
- **Apache-2.0 notices.** Playwright, playwright-core, TypeScript and Nosey Parker ship NOTICE files; keep them in every distribution (the packages already include them).
- **boolbase 1.0.0** (ISC, a Cheerio dependency) ships no separate licence file; its licence is declared in its `package.json`.
- **Gitleaks binary.** If a full dependency inventory is needed (for example for a customer audit), list the Go modules of the Gitleaks 8.30.1 release separately.
- **Container image.** The image contains unmodified Debian packages, some under GPL or LGPL. Before publishing the image (for example on a public registry), keep the Debian copyright files in the image (they are under `/usr/share/doc`) and be ready to point to the matching Debian source packages. A package-by-package list can be produced with `dpkg-query` inside the image.
- **Chrome for Testing on Linux.** The redistribution point above applies to the Linux package and the container image too.
