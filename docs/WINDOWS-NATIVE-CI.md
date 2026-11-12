# Native Windows CI

`Windows Native CI` is DefenseClaw's deterministic Windows x64 merge gate. It
runs on pull requests and pushes to `main` without WSL or provider
credentials. Only the connector contract uses Git Bash, to run the shared
`contract-smoke.sh`.

Repository merge rules should require the aggregate check name
`Windows Native Required`. The aggregate fails when a required Windows job
fails, is cancelled, or is skipped.

The merge gate covers:

- native Go tests, including current-user Windows DACL regressions, exact
  CMD/PowerShell quote and executable identity, destination-bound curl
  metadata/body/file projection, and typed Windows sensitive-path
  block/advisory/quiet outcomes, followed by `go vet` and gateway/hook builds;
- the ordinary Python suite plus focused native Windows telemetry-registry
  updater and headless TUI checks on pull requests; main and
  manual/release-candidate runs retain both exhaustive telemetry-registry
  modules and the complete TUI suite;
- PowerShell parsing of every script and module, the standalone
  managed-enterprise lifecycle smokes (`packaging/windows/tests`), the
  `install.ps1` bootstrap and offline contract tests
  (`cli/tests/test_install_ps1.py`), and the harness self-test (timeout,
  redaction and process-tree cleanup contracts);
- the connector contract on a per-user install: `contract-assets` builds this
  tree's release-shaped Windows assets (`scripts/build-release-assets.sh ...
  windows/amd64`), and each `connector-contract` cell (codex, claudecode, amp,
  copilot, cursor, devin, hermes, antigravity, opencode) installs them with
  `install.ps1 -Local` into a throwaway profile and runs
  `scripts/live-connector-e2e/run-windows-install.ps1`: observe setup and the
  Windows checks of what it wrote (exact hook commands, the Cursor and
  Copilot PowerShell adapters, the Amp and OpenCode plugins, the Doctor row),
  `contract-smoke.sh`'s golden allow and block payloads through the installed
  hook with the gateway evidence, the observability v8 records, and teardown
  restoring the vendor config byte for byte. No vendor agent is installed, so
  a green cell is not connector certification.
  `cli/tests/test_windows_connector_contract.py` pins the matrix to the
  Windows connectors;
- the install lifecycle on the same assets (`install-lifecycle`): install,
  version, status, doctor, the TUI at 80x24, a repair re-run, and a full
  uninstall that leaves no files, processes, Run value or Path entry; then the
  `fresh` and `files-in-use` lanes of `scripts/test-install-lifecycle.ps1`.

Failure diagnostics are bounded, secret-redacted, retained for five
days, and followed by unconditional process, listener, and temporary-state
cleanup.

## Relationship to Release

A merge to `main` is the review-and-CI boundary. The Release workflow trusts
that boundary and does not poll or replay `Windows Native CI`.

The secret-bearing real-client cells in `Connector Live E2E` are a separate,
manual regression layer, not a release dependency or fork-pull-request merge
gate. They run on Linux and macOS only; the workflow has no Windows cells.

One manual Release dispatch (`.github/workflows/release.yaml`) builds the
publishable Windows assets from the reviewed `main` commit selected by that
dispatch:

1. the Windows gateway, hook and ACP guard binaries from GoReleaser, which
   `install.ps1` installs for a user;
2. the standalone managed-enterprise Setup,
   `enterprise-windows/DefenseClawSetup-Enterprise-Standalone-x64.exe`, with its
   payload manifest. It is Authenticode-signed when a code-signing certificate
   is configured; otherwise it ships hash-pinned (flavor
   `standalone-unsigned`).

The release's `Install and upgrade (windows-latest)` gate then runs
`scripts/test-install-lifecycle.ps1` against the candidate assets (fresh
install, Setup import, files in use, a failure drill, policy, and an upgrade
from the previous release when one exists) before publication.

The release never publishes `DefenseClawSetup-x64.exe`; see
[RELEASE_RUNBOOK.md](RELEASE_RUNBOOK.md) for the names 0.8.x clients rely on
not existing.
