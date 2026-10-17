# Exposure Desk 2.3.0-rc.1

Second-stage candidate extends 2.2 without replacing transport, scope, vault, history, reveal/copy/full export, schedules or self-test. Adds a redacted resource discovery graph, import maps and extensionless modules, application JSON links, local API-description observations and exact stale-asset replay. Operations from API descriptions are never automatically executed.

Adds isolated Acorn constant propagation across already downloaded modules. Supports constant aliases, string concatenation, templates, array joins, static object properties/destructuring, named/default/namespace imports and named/default exports, supported explicit constant encodings. Unknown expressions remain unknown. Constituents, steps and static request/SDK sinks remain reviewable. No downloaded code is executed by the analyzer.

Isolated Chromium can capture generated loaded script source through CDP. Captured source is runtime evidence; reported source URLs do not prove public reachability. Separate process frame/worker debugger targets are unsupported and visible. Guarded request inspection still precedes dispatch; blocked candidate traffic is distinguished from public responses and reconstructed values. Settling follows activity under an explicit deadline.

Large retained text receives bounded window inspection with exact offsets; likely configuration decodings precede unrelated strings. Truncated downloads, decoding limits, parser failures, unavailable channels and missing 304 bodies remain coverage gaps. Adds contextual standalone Azure SAS, Azure storage and database connection-string checks, plus frontend proxy/admin reference observations with untested impact.

Existing provider and safety regressions are retained. A separate fixed held-out corpus and acquisition ablations measure gains. See TEST_RESULTS.md for measured candidate results and remaining host/format limitations.
