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
| `make upgrade-smoke` | Build an unsigned schema-2 candidate and prove an old controller refuses it before mutation |
| `make upgrade-smoke-matrix` | Run that unsigned-candidate refusal contract across all supported historical baselines |
| `make upgrade-signed-protocol-matrix` | Run the full resolver success/refusal policy against an already signed candidate (release gate only) |

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

Schema-2 releases deliberately cannot be installed from an unsigned working-tree
candidate. A generic PR job cannot mint the
`release.yaml@refs/heads/main` Fulcio identity, and the test harness must not
replace that identity or fake a successful `cosign` check. The ordinary local
smoke therefore installs authenticated historical releases in a temporary
`HOME` and verifies both explicit-target and latest-mode attempts:

- refuse the schema-2 candidate before service stop, backup, or mutation
- leave CLI, gateway, config, OpenClaw state, permissions, and PID state unchanged
- emit the historical controller's expected forward-compatibility failure
- ship the exact reviewed POSIX resolver and signed PowerShell refusal asset bound by the candidate checksums

The protected release workflow separately signs the sealed candidate and then
runs the full manifest-derived resolver matrix. That signed gate verifies
successful bridge activation, fresh-controller handoff, required migrations,
exact CLI/gateway versions, health, receipts, and rollback behavior before
publish.

```bash
# Current platform, proving one old controller refuses the unsigned candidate.
make upgrade-smoke ARGS="--from-version 0.7.2"

# Full supported historical refusal matrix used by generic PR CI.
make upgrade-smoke-matrix

# Full positive protocol matrix. This requires the sealed, release-workflow-
# signed candidate; it must not be pointed at unsigned local artifacts.
make upgrade-signed-protocol-matrix \
  ARGS="--release-dir release-candidate/dist --baseline-mode seed"

# Legacy schema-1 positive harness, retained only for old release fixtures.
make upgrade-legacy-smoke-matrix \
  ARGS="--target-version 0.8.3 --release-root /path/to/published-release-root --baseline-mode seed"
```

For a Linux host without the repo's Go toolchain, prepare candidate artifacts on a machine that can cross-build, copy the printed release root to Linux, then run the same smoke there:

```bash
scripts/test-upgrade-release.sh --prepare-only --platform linux/arm64 --keep-workdir
scp -r /tmp/defenseclaw-upgrade-smoke.xxxxxx/candidate-release openclaw-vineeth:/tmp/
ssh openclaw-vineeth 'scripts/test-upgrade-protocol-release.sh --release-root /tmp/candidate-release --from-versions "0.8.4,0.8.3,0.8.2,0.8.1,0.8.0,0.7.2,0.7.1,0.6.6,0.6.5,0.6.4,0.6.3,0.6.2,0.6.1,0.6.0,0.5.0,0.4.0" --baseline-mode seed'
```

The default matrix covers the required schema-v7 bridge plus every supported 0.4.0+ historical source: `0.8.4`, `0.8.3`, `0.8.2`, `0.8.1`, `0.8.0`, `0.7.2`, `0.7.1`, `0.6.6`, `0.6.5`, `0.6.4`, `0.6.3`, `0.6.2`, `0.6.1`, `0.6.0`, `0.5.0`, and `0.4.0`. Its single source is `release/upgrade-baselines.json`; the Make target and smoke-contract tests must match that reviewed data exactly. Release `0.7.0` has no downloadable release assets, and `0.2.0` predates the upgrade command, so neither is eligible for automatic staging. The `0.8.4` entry deliberately makes the `0.8.5` gate fail until that bridge has actually been published with its complete signed POSIX asset set. Targets before `0.8.5` retain schema-v7 checks. A hard-cut manifest (`min_upgrade_protocol >= 2`) must prove pre-mutation refusal for incapable baselines, a verified `0.8.4` bridge handoff for every listed older POSIX source, and full v7-to-v8 observability, private-secret, rollback, local-bundle, SQLite, and fresh-process health checks from the bridge.

The release workflow seals one candidate, then runs `scripts/test-upgrade-protocol-release.sh` once per reviewed Linux baseline plus the native macOS and live-continuity gates before publishing those exact bytes. Windows runtime publication and upgrade jobs remain disabled; release validation instead proves that no Windows gateway, rollback, or SBOM binary is emitted and that the signed PowerShell resolver refuses before mutation. A broken refusal, bridge handoff, migration, rollback, health, or history path therefore aborts before any release asset is published.

### 0.8.4 bridge rollout order

Publish `0.8.4` as the latest release before cutting `0.8.5`. Confirm GitHub
reports the release immutable,
let the bridge soak, and retain evidence that the sealed `0.8.4` candidate
upgraded successfully from every version in
`release/upgrade-baselines.json` on the required native platforms. Only after
that proof is green should the hard-cut candidate be cut.
The later hard-cut baseline policy must include published `0.8.4`; do not treat
an uncut branch artifact as the bridge.

## CI Workflows

| Workflow | Purpose |
|----------|---------|
| `.github/workflows/ci.yml` | Go lint/test, Python test, TypeScript test, Rego test, unsigned schema-2 refusal contract, and parity checks |
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
