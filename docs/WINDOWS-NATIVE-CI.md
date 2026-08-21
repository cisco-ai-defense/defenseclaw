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
- the Python suite and headless TUI checks;
- PowerShell parsing, timeout, redaction, and process-tree cleanup contracts;
- a release-shaped Windows amd64 gateway archive and Python wheel;
- a disposable-user fresh installation;
- the public `install.ps1` authentication and native handoff path under a
  token-bound disposable Windows profile;
- installed CLI, gateway lifecycle, doctor, scanner, and dependency checks;
- live-gateway Doctor custody checks for the audit database and HMAC-bound
  device identity, proving the detached gateway and watchdog do not pin the
  protected data directory;
- Setup build and native install/repair/uninstall acceptance; and
- required PowerShell contract cells for Codex, Claude Code, and Amp covering
  setup; exact action-mode blocks; detection-only shadow or advisory outcomes;
  quiet controls; request, action, and audit correlation; gateway-generated
  connector telemetry; bounded timeout handling; teardown; and cleanup. Amp
  additionally proves all five documented plugin callbacks, the Task/subagent
  boundary, a private managed plugin, self-heal, and tamper-recovery behavior.

The packaged test artifact is built once and reused by the disposable lifecycle
jobs. The public-bootstrap shard uses the authenticated `0.8.7` release—the
first published native Setup—as its compatibility fixture. Its child launch
uses sandbox-relative arguments to stay
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

One manual Release dispatch builds the publishable Windows amd64 and arm64
gateway binaries plus the x64 `DefenseClawSetup-x64.exe` from the reviewed
`main` commit selected by that dispatch. The same run:

1. requires either the expected Authenticode signature and timestamp or an
   explicit unverified provenance record with exact `NotSigned` state;
2. exercises `install.ps1` and the exact Setup candidate as a standard user;
3. verifies installed versions and payload ownership; and
4. seals the tested Windows assets with the Linux and macOS candidate before
   publication.

Version `0.8.7`, the first release with native Windows Setup, was validated as
a fresh x64 install and made no Windows upgrade claim. Published releases
`0.8.7` through `0.8.10` carry explicit unverified provenance with the outer
Setup and DefenseClaw executables recorded as `NotSigned`; their bytes are
authenticated by the release checksum/provenance chain, not Authenticode. The
release gate also verifies and seals both Windows gateway architectures before
publication.
