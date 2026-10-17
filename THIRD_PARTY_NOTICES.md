# Third-party notices for ported detection rules

The provider rules listed here (in `src/detectors.ts`, after `ldap-password`) are regular expressions ported as reviewed data from two permissively licensed secret scanners. Only the rule files were read, as text; no code from either project was run, copied or linked. Every pattern was rewritten by hand into JavaScript, and the changes are listed below. The licences and notices are vendored in `rules/`. For other third-party components and the earlier ports, see THIRD_PARTY.md.

## Sources

### Gitleaks

- Repository: <https://github.com/gitleaks/gitleaks>
- Commit: `b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b`
- File: `config/gitleaks.toml`. At this commit it is byte-identical to the vendored `rules/gitleaks-v8.30.1.toml` from tag v8.30.1 (commit `83d9cd684c87d95d656c1458ef04895a7f1cbd8e`), the file that the pinned offline engine already uses.
- Licence: MIT. The full text is in `rules/GITLEAKS-LICENSE`.
- Copyright notice: `Copyright (c) 2019 Zachary Rice`

### Nosey Parker

- Repository: <https://github.com/praetorian-inc/noseyparker>
- Commit: `2e6e7f36ce36619852532bbe698d8cb7a26d2da7`
- Files: `crates/noseyparker/data/default/builtin/rules/`, specifically `adafruit.yml`, `atlassian.yml`, `doppler.yml`, `dynatrace.yml`, `grafana.yml`, `hashicorp.yml`, `mapbox.yml`, `newrelic.yml`, `postman.yml`, `segment.yml`, `sourcegraph.yml` and `stackhawk.yml`.
- Licence: Apache License 2.0. The full text is in `rules/NOSEYPARKER-LICENSE`.
- NOTICE file: kept verbatim in `rules/NOSEYPARKER-NOTICE`. It begins `Copyright 2022 Praetorian Security, Inc <https://praetorian.com>.`

## Rules and their sources

| Exposure Desk rule | Provider | Gitleaks rule IDs | Nosey Parker rule IDs |
| --- | --- | --- | --- |
| `linear-api-key` | Linear | `linear-api-key` | |
| `planetscale-token` | PlanetScale | `planetscale-api-token`, `planetscale-password`, `planetscale-oauth-token` | |
| `doppler-token` | Doppler | `doppler-api-token` | `np.doppler.1` to `np.doppler.6` |
| `dynatrace-token` | Dynatrace | `dynatrace-api-token` | `np.dynatrace.1` |
| `grafana-service-account-token` | Grafana | `grafana-service-account-token` | `np.grafana.3` |
| `grafana-cloud-token` | Grafana | `grafana-cloud-api-token` | `np.grafana.2` |
| `vault-token` | HashiCorp Vault | `vault-service-token`, `vault-batch-token` | `np.hashicorp.4`, `np.hashicorp.5` |
| `terraform-cloud-token` | HCP Terraform | `hashicorp-tf-api-token` | |
| `postman-api-key` | Postman | `postman-api-token` | `np.postman.1` |
| `sourcegraph-token` | Sourcegraph | `sourcegraph-access-token` | `np.sourcegraph.1` |
| `segment-token` | Segment | | `np.segment.1` |
| `flyio-token` | Fly.io | `flyio-access-token` | |
| `pulumi-token` | Pulumi | `pulumi-api-token` | |
| `prefect-token` | Prefect | `prefect-api-token` | |
| `shippo-token` | Shippo | `shippo-api-token` | |
| `duffel-token` | Duffel | `duffel-api-token` | |
| `easypost-key` | EasyPost | `easypost-api-token`, `easypost-test-api-token` | |
| `atlassian-api-token` | Atlassian | `atlassian-api-token` | `np.atlassian.1` |
| `artifactory-api-key` | JFrog Artifactory | `artifactory-api-key` | |
| `1password-service-account-token` | 1Password | `1password-service-account-token` | |
| `1password-secret-key` | 1Password | `1password-secret-key` | |
| `notion-token` | Notion | `notion-api-token` | |
| `harness-token` | Harness | `harness-api-key` | |
| `readme-api-key` | ReadMe | `readme-api-token` | |
| `maxmind-license-key` | MaxMind | `maxmind-license-key` | |
| `openshift-user-token` | OpenShift | `openshift-user-token` | |
| `newrelic-api-key` | New Relic | `new-relic-user-api-key` | `np.newrelic.1`, `np.newrelic.3`, `np.newrelic.4` |
| `newrelic-ingest-key` | New Relic | `new-relic-insert-key` | `np.newrelic.5`, `np.newrelic.7` |
| `stackhawk-key` | StackHawk | | `np.stackhawk.1` |
| `adafruit-io-key` | Adafruit IO | `adafruit-api-key` | `np.adafruit.1` |
| `mapbox-secret-token` | Mapbox | `mapbox-api-token` | `np.mapbox.2`, `np.mapbox.3` |

## Changes from the upstream patterns

- Converted from Go RE2 and Rust regex syntax to JavaScript regular expressions with the `g` flag.
- Every repeat is bounded. Upstream `+` and `*` became explicit upper limits, for example `{100,4000}` for Fly.io macaroons and `{250,4000}` for 1Password service account tokens.
- Upstream trailing delimiter groups, such as Gitleaks' `(?:[\x60'"\s;]|\\[nr]|$)`, became negative lookaheads. A token that continues past the format is therefore never reported truncated.
- Case-insensitive `(?i)` prefixes became case-sensitive fixed prefixes. Upstream keyword-and-assignment context (Gitleaks `[\w.-]{0,50}?(?:…)` prefixes) was removed where a fixed prefix exists. For Mapbox, the keyword context was replaced by the fixed `sk.eyJ1Ijoi` / `tk.eyJ1Ijoi` token header, and public `pk.` tokens are not ported.
- Variants were merged into one rule per provider format: Doppler token kinds, New Relic user/REST keys and New Relic insert/license keys, PlanetScale tokens, Vault service/batch tokens and Fly.io token kinds.
- Not ported: entropy thresholds, keyword lists and allowlists. The existing Exposure Desk placeholder and context checks apply instead.
- Also not ported: public identifiers (New Relic `NRJS-` browser keys, Mapbox `pk.` tokens), context-only rules without a fixed prefix, and formats that collide with ordinary identifiers.

Nosey Parker's example strings and Gitleaks' generated test values were not copied. The test fixtures in `test/provider-fixtures.ts` are synthetic and nonfunctional.
