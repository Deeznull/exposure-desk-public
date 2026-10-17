# Provider evidence review — 2026-10-06

Pinned executable: Gitleaks 8.30.1 and supplied catalogue digest e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf. Exact dependencies retained: Acorn 8.19.0, Playwright 1.63.0, RE2-WASM 1.0.2. Authentication documentation does not guarantee all lexical formats; the registry records actual regex patterns, context rules and selected executable fixtures per family.

Primary sources reviewed for this stage:

- [Gitleaks pinned source and release](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1), [maintained upstream](https://github.com/gitleaks/gitleaks). The executable pin is preserved; no unreviewed detector update.
- [Stripe authentication](https://docs.stripe.com/api/authentication), [Stripe keys](https://docs.stripe.com/keys): client publishable material remains separate from secret/restricted credentials.
- [Azure service SAS](https://learn.microsoft.com/en-us/rest/api/storageservices/create-service-sas), [storage connection strings](https://learn.microsoft.com/en-us/azure/storage/common/storage-configure-connection-string): signature-bearing local tokens and AccountName/AccountKey pairs; no use of permissions or expiration as verified claims.
- [Anthropic gateway configuration](https://docs.anthropic.com/en/docs/claude-code/llm-gateway): endpoint and Authorization/API-key construction are separate evidence. Gateway references alone do not establish unauthorized workloads.

Every advertised family remains tied to executable selected-fixture results in coverage-registry.json and benchmarks/results.json. Families with opaque credentials rely on explicit same-object/provider/sink context. No arbitrary cross-resource component pairing is introduced. Cross-module correlation occurs only through supported imports and a reconstructed configuration object. Partial components remain review items. Public identifiers and ordinary anonymous sessions remain separate. Format-specific, contextual and engine-dependent modes are listed independently; generic suspicion is not provider attribution.

All 45 primary references associated with the 41 advertised family rows were opened during this stage; the attempted-reference inventory is benchmarks/provider-primary-review.json. Actual selected-fixture execution populates the registry, including engine-only rule IDs. Authentication roles were reviewed separately from bounded lexical heuristics. The current Gemini documentation distinguishes standard and authorization keys; a bare AIza match continues to report restrictions and capabilities as unknown.

Unverified formats, lengths outside bounded patterns, prefixes not supported by executable rules, arbitrary encodings/obfuscation and unreviewed provider changes remain unsupported. Synthetic success says nothing about active privileges, balances or real-world recall.
