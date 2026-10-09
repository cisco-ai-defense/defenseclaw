# Native Windows CI

`Windows Native CI` is DefenseClaw's deterministic Windows x64 merge gate. It
runs on pull requests and pushes to `main` without WSL, MSYS, Git Bash, or
provider credentials.

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
- PowerShell parsing, timeout, redaction, and process-tree cleanup contracts;
- a release-shaped Windows amd64 gateway archive and Python wheel;
- a disposable-user fresh installation;
- the public `install.ps1` authentication and native handoff path under a
  token-bound disposable Windows profile;
- installed CLI, gateway lifecycle, doctor, scanner, and dependency checks;
- live-gateway Doctor custody checks for the audit database and HMAC-bound
  device identity, proving the detached gateway and watchdog do not pin the
  protected data directory;
- Setup build and native install/repair/uninstall acceptance, including the
  staged connector selection, repair, custody, and exact-restoration paths;
- deterministic packaged connector contract tests for Codex, Claude Code,
  Amp, Copilot, Cursor, Devin, Hermes, Antigravity, and OpenCode. OpenCode's
  contract imports the installed JavaScript bridge, proves
  `tool.execute.before` permits on normal return and blocks on a thrown error,
  and treats `tool.execute.after` as observation only. Devin's cell stages the
  digest-pinned official `3000.4.25` Windows archive solely to retain the
  product's exact fixed-path, Authenticode-signer, and version admission; it
  does not log in, run an interactive client session, or claim live-client
  evidence; and
- the Amp cell covers setup, observe/action
  allow/block behavior, audit correlation, gateway-generated connector
  telemetry, bounded timeout handling, teardown, and cleanup. It additionally
  proves all five documented plugin callbacks, the Task/subagent boundary, a
  private managed plugin, self-heal, and tamper-recovery behavior.

These deterministic packaged cells do not certify authenticated official-client
behavior. Secret-bearing real-client evidence remains a separate manual layer.

The packaged test artifact is built once and reused by the disposable lifecycle
jobs. The public-bootstrap shard's child launch uses sandbox-relative arguments to stay
deterministically below `CreateProcessWithLogonW`'s 1,024-character command-line
limit even when the parent state root is deeply nested. Failure diagnostics are
bounded, secret-redacted, retained for five days, and followed by unconditional
process, listener, account/profile, and temporary-state cleanup.

## Relationship to Release

A merge to `main` is the review-and-CI boundary. The Release workflow trusts
that boundary and does not poll or replay `Windows Native CI`.

The secret-bearing real-client cells in `Connector Live E2E` are a separate,
manual regression layer, not a release dependency or fork-pull-request merge
gate. Its native Windows matrix covers Codex, Claude Code, and Amp. The Amp cell
uses `AMP_API_KEY`, runs the official CLI through its native TypeScript plugin,
and requires lifecycle, tool allow/block, audit, and gateway-generated
connector telemetry evidence. It does not claim that Amp exports native OTLP.

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
