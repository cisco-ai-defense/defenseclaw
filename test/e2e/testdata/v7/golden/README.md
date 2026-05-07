# v7 Golden Event Fixtures

This directory holds frozen JSON envelopes used by `TestGoldenEvents`
(`test/e2e/v7_golden_events_test.go`). The flat files at the top of
this directory are the **connector-agnostic baseline** — they were
written before connector parameterization and remain in place so the
existing test suite continues to compare against them with no path
changes.

## Per-connector subdirectories

The four subdirectories — `openclaw/`, `zeptoclaw/`, `claudecode/`,
`codex/` — hold the **per-connector overrides** introduced by Plan
E3.4 (PR #194 single rollup). The contract is:

| Path | Used by | Notes |
|------|---------|-------|
| `<event>.golden.json`           | Existing connector-agnostic tests          | Baseline; current tests do not look in subdirectories. |
| `openclaw/<event>.golden.json`  | Future per-connector tests, OpenClaw cell  | Bit-for-bit copy of the baseline (back-compat). |
| `zeptoclaw/<event>.golden.json` | Future per-connector tests, ZeptoClaw cell | Identical envelope today (no per-connector field surface yet); diverges when tests start seeding `agent_id="zeptoclaw"`. |
| `claudecode/<event>.golden.json`| Future per-connector tests, ClaudeCode cell| Same as above. |
| `codex/<event>.golden.json`     | Future per-connector tests, Codex cell     | Same as above. |

## Why the subdirs exist if the goldens are identical today

The test harness does not currently seed a connector-specific
`agent_id` into emitted events (the harness uses a constant
`e2eAgentID = "e2e-agent"`). Per-connector goldens therefore look
identical to the connector-agnostic baseline today. The four
subdirectories are pre-positioned so that when a future test wraps
`TestGoldenEvents` in a `t.Run(connector, ...)` loop and seeds the
matching `agent_id`, the per-connector golden path resolves under
`testdata/v7/golden/<connector>/` and the diff lands in only that
file — no fan-out churn across the repo, no clobbering of the
baseline.

## Updating

When a test starts emitting per-connector envelopes, run:

```sh
go test ./test/e2e -run TestGoldenEvents -update
```

with the matching `goldenPath()` helper variant in
`v7_test_helpers.go`. The connector-agnostic baseline at the top of
this directory should not be regenerated unless the envelope schema
itself changes — that's what the presence-check guards in
`stripVolatileGatewayJSON` are for.
