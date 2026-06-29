# Testing

DefenseClaw has Python, Go, TypeScript, Rego, docs, and end-to-end test surfaces. Use the smallest focused target while developing, then run the broader gates before opening a PR.

## Common Targets

| Command | Scope |
|---------|-------|
| `make test` | Python CLI unit tests plus focused Go gateway/test packages |
| `make cli-test` | Python `unittest` suite under `cli/tests/` |
| `make cli-test-cov` | Python pytest coverage report |
| `make gateway-test` | Race-enabled Go tests for gateway and `test/` |
| `make security-suite-test` | Deterministic security + PII coverage suite (regex + stubbed judge); see [SECURITY-TEST-SUITE.md](SECURITY-TEST-SUITE.md) |
| `make security-suite-eval` | Live LLM-judge scoring of the security + PII corpus (needs `DEFENSECLAW_LLM_KEY`) |
| `make go-test-cov` | Race-enabled Go coverage across all packages |
| `make ts-test` | OpenClaw plugin Vitest suite |
| `make rego-test` | OPA tests for `policies/rego/` |
| `make check` | Audit action, error code, schema, and provider coverage parity gates |
| `make lint` | Ruff, Go formatting/linting, and Python compile check |
| `make upgrade-smoke` | Build/serve candidate artifacts and run a real old-version upgrade in a throwaway HOME |
| `make upgrade-smoke-matrix` | Run the release upgrade smoke against all supported historical baselines |

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

## Release Upgrade Smoke

Before cutting a release, run the upgrade smoke on at least macOS and Linux. It builds or consumes candidate release artifacts, installs an older DefenseClaw in a temporary `HOME`, redirects that old `defenseclaw upgrade` command to a localhost release server, and verifies:

- the upgrade exits successfully
- every `required_cli_migrations` entry from `upgrade-manifest.json` is recorded in `.migration_state.json`
- CLI and gateway versions match the candidate version
- known regression markers such as `Traceback`, `AttributeError`, missing required migrations, and component drift are absent
- the Textual metric tile refresh path works in the installed environment
- signed candidates run the default upgrade path; `--allow-unverified` is only added automatically for unsigned local smoke artifacts

```bash
# Current platform, building candidate artifacts from the working tree.
make upgrade-smoke ARGS="--from-version 0.7.2"

# Full supported historical matrix.
make upgrade-smoke-matrix

# Reuse an existing release-style dist directory, such as in release CI.
make upgrade-smoke-matrix ARGS="--release-dir dist --baseline-mode seed"

# Custom subset, useful while debugging one old branch of the upgrade path.
scripts/test-upgrade-release.sh --from-versions "0.7.2,0.6.6,0.5.0,0.4.0"
```

For a Linux host without the repo's Go toolchain, prepare candidate artifacts on a machine that can cross-build, copy the printed release root to Linux, then run the same smoke there:

```bash
scripts/test-upgrade-release.sh --prepare-only --platform linux/arm64 --keep-workdir
scp -r /tmp/defenseclaw-upgrade-smoke.xxxxxx/candidate-release openclaw-vineeth:/tmp/
ssh openclaw-vineeth 'scripts/test-upgrade-release.sh --release-root /tmp/candidate-release --from-versions "0.8.1,0.8.0,0.7.2,0.7.1,0.6.6,0.6.5,0.6.4,0.6.3,0.6.2,0.6.1,0.6.0,0.5.0,0.4.0" --baseline-mode seed'
```

The default matrix covers every published 0.4.0+ baseline that has both a Python wheel, platform gateway archives, and an upgrade command: `0.8.1`, `0.8.0`, `0.7.2`, `0.7.1`, `0.6.6`, `0.6.5`, `0.6.4`, `0.6.3`, `0.6.2`, `0.6.1`, `0.6.0`, `0.5.0`, and `0.4.0`. Baselines newer than the candidate target are skipped automatically so local CI does not accidentally test downgrades before a release workflow stamps the next version. Release `0.7.0` has no downloadable release assets, and `0.2.0` predates the upgrade command, so they are not live-upgradeable by this harness.

The release workflow also runs `make upgrade-smoke-matrix ARGS="--release-dir dist --baseline-mode seed"` after artifacts/checksums are finalized and before `gh release create`, so a broken upgrade path aborts before assets are published.

## CI Workflows

| Workflow | Purpose |
|----------|---------|
| `.github/workflows/ci.yml` | Go lint/test, Python test, TypeScript test, Rego test, upgrade smoke, and parity checks |
| `.github/workflows/e2e.yml` | Self-hosted end-to-end suites and scheduled validation |
| `.github/workflows/release.yaml` | Tagged release artifacts |

## Before a PR

```bash
make lint
make test
make ts-test
make rego-test
make check
make upgrade-smoke-matrix
```
