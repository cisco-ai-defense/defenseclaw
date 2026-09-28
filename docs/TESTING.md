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
a free gateway port, so the machine's own install is never touched. (The
Windows `upgrade-0.X.Y` lanes are the exception noted below.)

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
`-PreviousAssets`. `upgrade-0.X.Y` (0.8.0-0.8.3) needs `-CodexExe`, a Codex CLI
`codex.exe`: 0.x sets up the codex connector, and DefenseClaw on Windows runs
Codex only from where its installer puts it. Unless Codex is already
installed there, the lane copies it into the real profile's
`%LOCALAPPDATA%\Programs\OpenAI\Codex\bin` and removes it afterwards.

## Enterprise Install Lanes

The standalone managed-enterprise packages have their own install lanes.
They install and remove system services, so run them only on a disposable
host (a CI runner, a container or a throwaway VM), as root or from an
elevated shell.

| Script | What it does |
| --- | --- |
| `scripts/test-enterprise-unix-install.sh` | Installs a `.deb`, `.rpm` or macOS `.pkg` and applies a config that enables Claude Code and Codex, whose machine policy must be owned and locked. Checks that a second `ensure` is a no-op, and runs `verify`, `status` and the MDM `detect.sh`. Then uninstalls, checks that no service or machine-policy entry is left and that the config is kept, and purges |
| `scripts/test-enterprise-linux-container.sh` | Runs the Linux lane in a container that boots systemd (`--image`), for a distribution other than the host's |
| `scripts/test-enterprise-windows-install.ps1` | Runs the hash-pinned unsigned `DefenseClawSetup-Enterprise-Standalone-x64.exe` through `/ensure`, a no-op `/ensure`, `verify`, `status`, `detect.ps1`, the installed CLI's own `ensure` and `/uninstall`. Checks the four services, the HKLM marker, the Add/Remove Programs entry, and that the Codex requirements and the Claude Code managed-settings fragment name the DefenseClaw hook after `/ensure` and are gone after `/uninstall` |
| `scripts/check_enterprise_lifecycle_result.py` | Checks one saved lifecycle result against what the step must produce. Every lane uses it. A step fails on any error and on any warning it does not allow (`--allow-warning`); `--complete` also requires `coverage_complete` and `security_complete` |

Build the packages the lanes install:

- **Linux deb, rpm and payload tarball:** `make packaging-linux-enterprise`
  runs a GoReleaser snapshot of the release config into `dist/`. It needs
  GoReleaser v2; `ci.yml` and `release.yaml` pin v2.15.4, so install the
  same version (`go install github.com/goreleaser/goreleaser/v2@v2.15.4`).
  `GORELEASER_CURRENT_TAG` sets the version: `v9.9.9` builds
  `9.9.9-SNAPSHOT-<commit>`. To test an upgrade, build the second package
  with a higher tag.
- **macOS pkg:** `make packaging-macos-enterprise VERSION=<version>` runs
  `scripts/build-macos-enterprise-pkg.sh` on a Mac with Go and the Xcode
  command line tools, and writes
  `dist/defenseclaw-enterprise-<version>-darwin-arm64.pkg`. The Makefile's
  default `VERSION` is an old release number, so always pass `VERSION`:
  the package refuses to install over a newer deployment, so a build for an
  upgrade test needs a version above the installed one. See
  [packaging/macos/PACKAGING.md](../packaging/macos/PACKAGING.md).

```bash
# Unsigned deb and rpm from the release config, then the rpm lane on RHEL 9.
GORELEASER_CURRENT_TAG=v9.9.9 make packaging-linux-enterprise
v=$(python3 -c 'import json; print(json.load(open("dist/metadata.json"))["version"])')
scripts/test-enterprise-linux-container.sh \
  --image registry.access.redhat.com/ubi9/ubi-init \
  --package "dist/defenseclaw-enterprise-$v-linux-amd64.rpm" --version "$v"

# Unsigned macOS pkg (on a Mac), then the pkg lane on a disposable Mac.
make packaging-macos-enterprise VERSION=9.9.9
sudo bash scripts/test-enterprise-unix-install.sh \
  --package dist/defenseclaw-enterprise-9.9.9-darwin-arm64.pkg --version 9.9.9
```

On every pull request, `ci.yml` runs the deb lane on the Ubuntu 24.04
runner, the rpm lane in RHEL 9 and RHEL 8 UBI containers, the pkg lane on
`macos-latest` and the Windows lane on `windows-latest`. Each lane uploads
its lifecycle results as an artifact.

Standalone Windows enrolls a user for a connector only when it finds the
connector's CLI in that user's profile, and the Windows runner has neither
Claude Code nor Codex. The Windows lane therefore writes the npm package
manifests listed in `testdata/enterprise_install_lane/windows-agents.json`
into the runner account's profile, removes them at the end, and refuses a host
where they already exist. Windows reports `security_complete` false until an
administrator records the live Claude Code policy proof
(`Repair -AttestClaudeEffectivePolicy`, see
[WINDOWS-ENTERPRISE-CERTIFICATION.md](WINDOWS-ENTERPRISE-CERTIFICATION.md)),
so the Windows lane requires `coverage_complete` and requires
`security_complete` to stay false.

## CI Workflows

Ordinary PRs stay fast, while the release dispatch tests the final signed
assets on every platform before publishing them. See the
[Release Runbook](RELEASE_RUNBOOK.md) for how to cut a release.

| Workflow | Purpose |
|----------|---------|
| `.github/workflows/ci.yml` | Language, parity and lint checks on every PR, plus `install-smoke`: the install lifecycle lanes on Linux and Windows against assets built from the PR, and the enterprise install lanes (deb, rpm, macOS pkg and Windows services) |
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
