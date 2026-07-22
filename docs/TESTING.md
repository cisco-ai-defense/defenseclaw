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
| `make upgrade-developer-activation` | In a throwaway `HOME`, directly activate an unsigned exact-SHA candidate and prove target migration/runtime health without claiming resolver provenance |
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

The protected signing workflow creates the sealed candidate. Nightly/manual
certification then runs the manifest-derived behavior-class matrix. A final
release reuses that exact golden candidate, or runs the same full certification
when no recent matching receipt exists. The signed gates verify successful
bridge activation, fresh-controller handoff, required migrations, exact
CLI/gateway versions, health, receipts, and rollback behavior before publish.

```bash
# Current platform, proving one old controller refuses the unsigned candidate.
make upgrade-smoke ARGS="--from-version 0.7.2"

# Optional developer diagnostic across the complete reviewed historical floor.
# Ordinary PR CI uses a smaller path-sensitive behavior-class selection.
make upgrade-smoke-matrix ARGS="--target-version X.Y.Z"

# Fast positive target-owned migration/health check for an unsigned local
# candidate. This never calls or weakens the production upgrade resolver.
make upgrade-developer-activation ARGS="--release-root /path/to/candidate-root --target-version 0.8.5 --from-version 0.8.4 --baseline-mode seed"

# Full positive protocol matrix. This requires the sealed, release-workflow-
# signed candidate; it must not be pointed at unsigned local artifacts.
make upgrade-signed-protocol-matrix \
  ARGS="--target-version X.Y.Z --release-dir release-candidate/dist --baseline-mode seed"

# Legacy schema-1 positive harness, retained only for old release fixtures.
make upgrade-legacy-smoke-matrix \
  ARGS="--target-version 0.8.3 --release-root /path/to/published-release-root --baseline-mode seed"
```

For a Linux host without the repo's Go toolchain, prepare candidate artifacts
on a machine that can cross-build and copy the printed release root plus the
reviewed test scripts to Linux. Run target activation and production refusal as
separate claims:

```bash
scripts/test-upgrade-release.sh --prepare-only --platform linux/arm64 --keep-workdir
scp -r /tmp/defenseclaw-upgrade-smoke.xxxxxx/candidate-release openclaw-vineeth:/tmp/
ssh openclaw-vineeth 'scripts/test-developer-target-activation.sh --release-root /tmp/candidate-release --target-version 0.8.6 --from-version 0.8.5 --baseline-mode seed'
ssh openclaw-vineeth 'scripts/test-upgrade-protocol-release.sh --release-root /tmp/candidate-release --target-version 0.8.6 --from-version 0.8.4 --baseline-mode seed --refusal-contract-only'
```

For routine candidates newer than the reviewed support list, the default matrix covers the required schema-v7 bridge plus every supported 0.4.0+ historical source: `0.8.4`, `0.8.3`, `0.8.2`, `0.8.1`, `0.8.0`, `0.7.2`, `0.7.1`, `0.6.6`, `0.6.5`, `0.6.4`, `0.6.3`, `0.6.2`, `0.6.1`, `0.6.0`, `0.5.0`, and `0.4.0`.
That reviewed floor lives in `release/upgrade-baselines.json`;
the Make target and smoke-contract tests must match it exactly. At execution
time the resolver authenticates and prepends every newer immutable stable
release older than the exact `--target-version`, and candidate certification
seals that effective snapshot with its signed checksums and upgrade manifest.
This tests newly published sources such as config-v8 `0.8.5` without baking
unpublished assets into the reviewed floor. Legacy fixture candidates exclude
reviewed sources that are not older than the candidate and fail clearly when no
supported predecessor remains. Dynamic matrix targets require the candidate
argument because the checked-in development version is not release selection;
set `UPGRADE_SMOKE_FROM` only for an intentional developer subset. Release
`0.7.0` has no downloadable assets, and `0.2.0` predates the upgrade command,
so neither is eligible for automatic staging. Targets before `0.8.5` retain
schema-v7 checks. A hard-cut manifest (`min_upgrade_protocol >= 2`) must prove
pre-mutation refusal for incapable baselines, a verified `0.8.4` bridge handoff
for every listed older POSIX source, and full v7-to-v8 observability,
private-secret, rollback, local-bundle, SQLite, and fresh-process health checks
from the bridge.

The effective baseline resolver adds published 0.8.5 dynamically as config
version 8. The harness then seeds canonical v8 config, migration
cursor, and baseline-owned bundle state; it requires later targets to preserve
config/environment bytes, avoid replaying the one-time v8 activation, refresh
managed bundle bytes, and retain operator files. Unknown future config families
fail closed until their fixture and verifier are reviewed.

Nightly/manual certification seals one candidate, then runs
`scripts/test-upgrade-protocol-release.sh` for the selected behavior-class
Linux/macOS baselines plus native fresh-install and live-continuity gates.
The final release reuses those exact certified bytes, or invokes that complete
certification workflow on a cache miss. Legacy raw Windows runtime archives
remain omitted, while exactly one `DefenseClawSetup-x64.exe` and its custody
sidecars are promoted from the same sealed candidate. Complete Authenticode
credentials require signing plus real Codex and Claude certification; absent,
partial, or invalid credential sets abort instead of producing a release Setup.
A broken refusal, bridge handoff, migration, rollback, installer lifecycle,
health, or history path aborts before publication.

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

The release gates are layered so ordinary PRs stay fast and publication reuses
recently certified bytes. See [Release Validation Strategy](RELEASE_VALIDATION.md)
for the behavior-class selector, certification receipt, cache-miss fallback,
and exact operator commands.

| Workflow | Purpose |
|----------|---------|
| `.github/workflows/ci.yml` | Fast deterministic release regressions on every PR; a five-class unsigned success/refusal matrix only for release-sensitive PRs; and an exact-SHA medium upgrade canary on every main merge, alongside the normal language/parity checks |
| `.github/workflows/telemetry-registry.yml` | Exhaustive telemetry-registry mutation, provenance, and failure-atomicity suites for telemetry-sensitive PRs, nightly, and manual dispatch |
| `.github/workflows/e2e.yml` | Self-hosted end-to-end suites and scheduled validation |
| `.github/workflows/release.yaml` | Nightly/manual certification and promotion of exact certified release bytes |
| `.github/workflows/pre-release-certification.yml` | Reusable expensive signed historical, rollback, native, and live-continuity gates |

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

For a release-sensitive change, run `make upgrade-smoke` locally and use
`make upgrade-developer-activation` with an unsigned candidate root when the
target migration/runtime changed. Neither test claims a signed bridge handoff.
The signed live historical, rollback, and Docker matrix is deliberately owned
by nightly/manual pre-release certification rather than ordinary PR validation.
