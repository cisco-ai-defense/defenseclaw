# End-to-end CI

This is a contributor reference for the full-stack test implementation. Product
setup and verification instructions belong in the
[published documentation](https://cisco-ai-defense.github.io/defenseclaw/docs/get-started/quickstart/).

The executable contract is [`.github/workflows/e2e.yml`](../.github/workflows/e2e.yml).
At present that workflow is scheduled daily at `07:00 UTC`; its conditions also
define behavior for manual and same-repository pull-request events if those
triggers are enabled in the workflow.

## Jobs and runner contract

| Job | Runner | Purpose |
| --- | --- | --- |
| `core` | `[self-hosted, Linux, ARM64, e2e]` | Deterministic full-stack scanner, enforcement, policy, health, and observability coverage |
| `full-live` | `[self-hosted, Linux, ARM64, e2e]` | Runs after `core` and adds live agent, guardrail, plugin-lifecycle, and recovery paths |
| `connector-matrix` | `ubuntu-latest` | Exercises OpenClaw, ZeptoClaw, Claude Code, and Codex connector contracts |
| `e2e-required` | `ubuntu-latest` | Aggregates required results for non-scheduled events |

`core` and `full-live` mutate the same persistent host state, including
`~/.defenseclaw`, `~/.openclaw`, Docker resources, and user services. The
dependency between them is intentional: do not make them concurrent on the
same runner.

The self-hosted runner must provide the toolchains declared by the repository
(`go.mod`, `pyproject.toml`, and `package.json`), Docker with Compose, and an
existing OpenClaw installation. The workflow does not bootstrap those host
dependencies. It uses repository secrets named in the workflow; do not copy
their values into documentation, logs, or fixtures.

## Execution flow

Both full-stack jobs:

1. clean prior DefenseClaw and test-scoped state;
2. start the local Splunk stack and an isolated HEC assertion sink;
3. run `make plugin install` so the gateway embeds the built OpenClaw
   extension;
4. initialize and validate a config-v8 test deployment;
5. run Python, Go, TypeScript, Rego, and
   [`scripts/test-e2e-full-stack.sh`](../scripts/test-e2e-full-stack.sh)
   coverage; and
6. run
   [`test/e2e/observability_assertions.sh`](../test/e2e/observability_assertions.sh)
   before unconditional cleanup.

The `core` profile disables required live-agent and live-guardrail paths.
`full-live` enables the required live agent, scanner, and guardrail paths while
leaving selected optional integrations non-fatal. The exact flags in the
workflow are authoritative.

## Source map

- [`.github/workflows/e2e.yml`](../.github/workflows/e2e.yml): orchestration,
  runner labels, secrets, timeouts, and required-result policy.
- [`scripts/test-e2e-full-stack.sh`](../scripts/test-e2e-full-stack.sh):
  profile-aware full-stack assertions and teardown.
- [`test/e2e/`](../test/e2e/): Go connector lifecycle tests and observability
  helpers.
- [`scripts/runner-cleanup.sh`](../scripts/runner-cleanup.sh): bounded reclaim
  of persistent-runner resources.
- [`bundles/splunk_local_bridge/`](../bundles/splunk_local_bridge/): local
  Splunk test stack used by the full-stack jobs.

For focused local test targets, see [Testing](TESTING.md).
