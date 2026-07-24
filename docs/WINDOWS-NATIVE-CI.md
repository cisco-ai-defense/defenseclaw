# Native Windows CI

`Windows Native CI` is DefenseClaw's deterministic Windows x64 merge gate. It
runs on pull requests and pushes to `main` without WSL, MSYS, Git Bash, or
provider credentials.

Repository merge rules should require the aggregate check name
`Windows Native Required`. The aggregate fails when a required Windows job
fails, is cancelled, or is skipped.

The merge gate covers:

- native Go tests, `go vet`, and gateway/hook builds;
- the Python suite and headless TUI checks;
- PowerShell parsing, timeout, redaction, and process-tree cleanup contracts;
- a release-shaped Windows amd64 gateway archive and Python wheel;
- a disposable-user fresh installation;
- the public `install.ps1` authentication and native handoff path under a
  token-bound disposable Windows profile;
- installed CLI, gateway lifecycle, doctor, scanner, and dependency checks;
- Setup build and native install/repair/uninstall acceptance; and
- deterministic Codex and Claude Code connector contract tests.

The packaged test artifact is built once and reused by the disposable lifecycle
jobs. The public-bootstrap shard uses the authenticated `0.8.7` release as its
compatibility fixture; before that release exists, it replays the immutable
sealed candidate from the failed release run that exposed the fake-profile
harness defect. Its child launch uses sandbox-relative arguments to stay
deterministically below `CreateProcessWithLogonW`'s 1,024-character command-line
limit even when the parent state root is deeply nested. Failure diagnostics are
bounded, secret-redacted, retained for five days, and followed by unconditional
process, listener, account/profile, and temporary-state cleanup.

## Relationship to Release

A merge to `main` is the review-and-CI boundary. The Release workflow trusts
that boundary and does not poll or replay `Windows Native CI`.

One manual Release dispatch builds the publishable Windows amd64 and arm64
gateway binaries plus the x64 `DefenseClawSetup-x64.exe` from the reviewed
`main` commit selected by that dispatch. The same run:

1. requires the expected Cisco Authenticode signature and RFC 3161 timestamp;
2. exercises `install.ps1` and the exact Setup candidate as a standard user;
3. re-verifies the exact Setup bytes in the release-owned real-client
   certification job, including the PE/CMS signature, Windows trust result,
   signer identity, timestamp token, and SHA-256;
4. verifies installed versions, connector traffic, and payload ownership; and
5. seals the tested Windows assets with the Linux and macOS candidate before
   publication.

The certification job emits a schema-2
`DefenseClawSetup-x64.exe.certification.json` record. Candidate assembly checks
that its Setup digest, provenance digest, signer, RFC 3161 timestamp evidence,
and source artifact custody all match the exact tested release inputs.
`publish-release` depends directly on `assemble-release-candidate` and
`release-smoke`, and indirectly on `windows-real-client-certification` through
the sealed candidate chain.

This first native Windows release is validated as a fresh x64 install. The
release gate also verifies and seals both Windows gateway architectures before
publication.
