# Testing

DefenseClaw has Python, Go, TypeScript, Rego, docs, and end-to-end test surfaces. Use the smallest focused target while developing, then run the broader gates before opening a PR.

## Common Targets

| Command | Scope |
|---------|-------|
| `make test` | Python CLI unit tests plus focused Go gateway/test packages |
| `make cli-test` | Python `pytest` suite under `cli/tests/` |
| `make cli-test-cov` | Python pytest coverage report |
| `make gateway-test` | Race-enabled Go tests for gateway and `test/` |
| `make security-suite-test` | Deterministic security + PII coverage suite (regex + stubbed judge); see [SECURITY-TEST-SUITE.md](SECURITY-TEST-SUITE.md) |
| `make security-suite-eval` | Live LLM-judge scoring of the security + PII corpus (needs `DEFENSECLAW_LLM_KEY`) |
| `make go-test-cov` | Race-enabled Go coverage across all packages |
| `make ts-test` | OpenClaw plugin Vitest suite |
| `make rego-test` | OPA tests for `policies/rego/` |
| `make check` | v7 parity, observability-v8, dashboard, provider, model-catalog, and guardrail-catalog gates |
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

E2E orchestration lives in `.github/workflows/e2e.yml`,
`scripts/test-e2e-full-stack.sh`, and `test/e2e/`. Its runner and profile
contract is documented in [E2E.md](E2E.md).

Run E2E tests only when the required local services, credentials, and platform assumptions are available.

## Install and Upgrade Tests

`scripts/test-install-lifecycle.sh` (macOS and Linux) and
`scripts/test-install-lifecycle.ps1` (Windows) run the real installers against
a release-shaped asset directory. Every lane uses its own throwaway `HOME` and
a free gateway port, so the machine's own install is never touched.

```bash
# Assets for the host platform, built from the working tree.
scripts/build-release-assets.sh 1.0.1 /tmp/dc-1.0.1
scripts/build-release-assets.sh 1.0.0 /tmp/dc-1.0.0

scripts/test-install-lifecycle.sh --assets /tmp/dc-1.0.1 --previous-assets /tmp/dc-1.0.0 \
  --lanes "fresh upgrade-previous upgrade-0.8.10 handoff drills"
```

| Lane | What it proves |
| --- | --- |
| `fresh` | A piped install (as the one-liner runs it), then a same-version repair that changes nothing |
| `upgrade-previous` | Upgrade from `--previous-assets`, `defenseclaw rollback`, roll forward, and keeping rolled-back data |
| `upgrade-0.X.Y` | Upgrade from a published 0.x release, then rollback and roll forward. `upgrade-0.8.4` imports a pre-v8 configuration and needs `cosign` on `PATH` |
| `handoff` | 0.8.8-0.8.10 `defenseclaw upgrade` running `defenseclaw-upgrade.sh` with the frozen arguments |
| `drills` | A gateway that never becomes healthy, a migration that fails halfway, a configuration from a newer release, a CLI broken at import, an install killed mid-swap, and a stale `gateway.pid` |
| `macos-app` | The app bundle is swapped with the runtime and restored by rollback (macOS only) |

When `cosign` is installed and the assets carry `checksums.txt.bundle`, the
`fresh` lane also checks that the installer verified the release signature.
The PowerShell script takes `-Assets`, `-PreviousAssets` and `-Lanes`. Its
lanes are `fresh`, `setup-import` (replacing a synthetic 0.8.x Setup install),
`files-in-use`, `failure-drill`, `policy` (the `DisableSelfUpdate` refusal;
needs an elevated shell), and `upgrade-previous` and `shim`, which need
`-PreviousAssets`.

## CI Workflows

Ordinary PRs stay fast, while the release dispatch tests the final signed
assets on every platform before publishing them. See the
[Release Runbook](RELEASE_RUNBOOK.md) for how to cut a release.

| Workflow | Purpose |
|----------|---------|
| `.github/workflows/ci.yml` | Language, parity and lint checks on every PR, plus `install-smoke`: the install lifecycle lanes on Linux and Windows against assets built from the PR |
| `.github/workflows/telemetry-registry.yml` | Exhaustive telemetry-registry mutation, provenance, and failure-atomicity suites for telemetry-sensitive PRs, nightly, and manual dispatch |
| `.github/workflows/e2e.yml` | Self-hosted end-to-end suites and scheduled validation |
| `.github/workflows/release.yaml` | One manual build, sign, install-gate and publish pipeline for a reviewed `main` commit |

Ordinary PR and main CI always run `make telemetry-check`, which compiles the
real registry and rejects stale generated runtime or Go outputs. The two
exhaustive telemetry mutation suites are excluded from the regular Python
shards and run only when their registry, compiler, renderer, schema, generated
output, test, or dependency inputs change. They also run nightly and through
manual dispatch. This keeps the common CI path fast without weakening the
exhaustive gate for changes that can affect telemetry generation.

## Before a PR

```bash
make lint
make test
make ts-test
make rego-test
make check
```

For a change to the installers, migrations or gateway startup, also run the
install lifecycle lanes above.
