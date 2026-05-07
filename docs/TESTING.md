# Testing

DefenseClaw has Python, Go, TypeScript, Rego, docs, and end-to-end test surfaces. Use the smallest focused target while developing, then run the broader gates before opening a PR.

## Common Targets

| Command | Scope |
|---------|-------|
| `make test` | Python CLI unit tests plus focused Go gateway/TUI/test packages |
| `make cli-test` | Python `unittest` suite under `cli/tests/` |
| `make cli-test-cov` | Python pytest coverage report |
| `make gateway-test` | Race-enabled Go tests for gateway, TUI, and `test/` |
| `make tui-test` | Race-enabled TUI package tests |
| `make go-test-cov` | Race-enabled Go coverage across all packages |
| `make ts-test` | OpenClaw plugin Vitest suite |
| `make rego-test` | OPA tests for `policies/rego/` |
| `make check` | Audit action, error code, schema, and provider coverage parity gates |
| `make lint` | Ruff, Go formatting/linting, and Python compile check |

## Focused Tests

```bash
# One Python test module
make test-file FILE=test_cmd_plugin

# One Go package or test
go test ./internal/gateway -run TestProviderCoverageCorpus -count=1

# One TypeScript plugin test
cd extensions/defenseclaw
npx --prefer-offline --no-install vitest run src/__tests__/provider-coverage.test.ts

# Rego policy tests
opa test policies/rego/ -v
```

## End-to-End Tests

E2E scripts live under `scripts/` and are documented in [E2E.md](E2E.md). They cover local CLI flows, sandbox behavior, tool blocking, proxy behavior, and platform-specific setups.

Run E2E tests only when the required local services, credentials, and platform assumptions are available.

## CI Workflows

| Workflow | Purpose |
|----------|---------|
| `.github/workflows/ci.yml` | Go lint/test, Python test, TypeScript test, Rego test, and parity checks |
| `.github/workflows/e2e.yml` | Self-hosted end-to-end suites and scheduled validation |
| `.github/workflows/release.yaml` | Tagged release artifacts |

## Before a PR

```bash
make lint
make test
make ts-test
make rego-test
make check
```

---

## Parity Gates (v7 Consistency)

DefenseClaw enforces cross-language parity via automated checks:

```bash
# Run all parity checks
make check

# Individual checks
make check-audit-actions      # Python audit action parity with Go
make check-error-codes        # Error code parity with Go
make check-schemas            # JSON schema validation
make check-provider-coverage  # Provider detection corpus (Go + TS)
```

### V7 Golden Tests

E2E tests under `test/e2e/` validate observability contract compliance:

| Test | Purpose |
|------|---------|
| `v7_golden_events_test.go` | Schema validation against golden fixtures |
| `v7_golden_per_connector_layout_test.go` | Connector-specific event layouts |
| `v7_observability_test.go` | Full observability tier conformance |
| `v7_observability_connector_matrix_test.go` | Cross-connector observability matrix |
| `v7_migration_test.go` | v5→v7 migration path validation |
| `v7_provenance_test.go` | Provenance field stamping |
| `v7_contract_doc_test.go` | Contract doc lists match Go source |

### Provider Coverage Corpus

A shared test corpus (`test/testdata/llm-endpoints.json`) validates that both Go (provider detection) and TypeScript (shape classification) produce consistent results for all supported LLM endpoints.

```bash
make check-provider-coverage
```

### Connector Lifecycle Matrix

`test/e2e/connector_lifecycle_matrix_test.go` exercises setup → disable → uninstall round-trips across all 4 connectors (OpenClaw, Claude Code, Codex, ZeptoClaw).
