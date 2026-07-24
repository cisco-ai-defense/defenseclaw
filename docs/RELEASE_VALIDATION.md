# Release Validation Strategy

DefenseClaw uses one manually dispatched workflow to build, validate, and
publish a release from a reviewed `main` commit. A merge to `main` is the
review-and-CI boundary. Release trusts that boundary and validates the
publishable artifacts.

## One-dispatch contract

Run the `Release` workflow from `main` with:

- a required bare `X.Y.Z` version; and
- `immutable_releases_confirmed=true` after checking the repository setting.

The workflow rejects a non-`main` dispatch, a commit that is not reachable from
reviewed `main`, an invalid version, and an existing tag or release namespace.
It stamps the requested version into an isolated checkout; a version-bump
commit is not required. A later merge to `main` does not invalidate the
already-selected reviewed commit while its release is running.

```bash
gh workflow run release.yaml --ref main \
  -f version=0.8.7 \
  -f immutable_releases_confirmed=true
```

Do not create or push the tag and do not run `gh release create` manually. The
workflow owns the tag and release namespace until it publishes the tested
candidate.

## Required release gates

One run builds one candidate and must pass all of these gates before
publication:

| Platform | Built assets | Validation |
|---|---|---|
| Linux | amd64 and arm64 gateway archives plus the shared CLI/plugin assets | Install the exact sealed candidate with `install.sh`; upgrade the latest authenticated older release, the `0.8.5` hard-cut boundary, the `0.8.4` bridge boundary, and representative `0.7.x`, `0.6.x`, and `0.5.x` releases; require the candidate CLI and gateway to be healthy |
| macOS | Intel and Apple Silicon gateway archives, shared CLI/plugin assets, and the unified macOS app | Install the exact sealed candidate with `install.sh`; run the same six authenticated upgrade paths; with a complete Apple credential set, require Developer ID signing and notarization; with no Apple credentials, require ad-hoc signing and explicit `-unverified` artifact names |
| Windows | amd64 and arm64 gateway binaries, shared CLI assets, and the x64 `DefenseClawSetup-x64.exe` | Exercise the exact x64 candidate through `install.ps1` and native Setup; verify the installed CLI/gateway versions; with both Windows credentials, require Cisco Authenticode; with neither, require explicit unverified provenance and exact `NotSigned` state |

This is the complete release acceptance scope. The first native Windows release
has no older native Windows baseline, so Windows acceptance is intentionally
fresh-install only.

The POSIX upgrade sources are resolved from authenticated published release
metadata: the latest supported version older than the target, the `0.8.5`
hard-cut boundary, the `0.8.4` bridge boundary, and the newest available
`0.7.x`, `0.6.x`, and `0.5.x` versions. Linux and macOS use the same six
resolved baselines so the result is easy to understand and reproduce.

Platform signing credentials are optional as complete groups. For macOS, all
five Developer ID and notary values produce signed, notarized artifacts with
the normal names. If all five are absent, the same release continues with
ad-hoc-signed DMG and ZIP assets whose names end in `-unverified`. A partially
configured Apple credential group fails before packaging; the workflow never
silently downgrades a requested signed build.
For Windows, the certificate and password are also one complete group. Both
produce Cisco Authenticode-signed Setup and payload executables. If both are
absent, the same release continues with an explicitly unverified Setup whose
exact bytes remain authenticated by the release Sigstore checksum manifest and
schema-1 provenance. A partial Windows credential group fails before packaging.

For every pre-`0.8.4` source, the success gate must prove the staged route
through the immutable published `0.8.4` bridge, followed by the fresh-controller
handoff into the `0.8.5+` update mechanism. Candidate assembly authenticates and
binds the exact `0.8.4` bridge release. The harness rejects a run that bypasses
the bridge, omits the forward handoff, loses either rollback snapshot, or fails
final target health. The explicit `0.8.4` and `0.8.5` lanes prove both sides of
the boundary. The `0.8.4` lane deliberately starts with a drifted but importable
dependency graph and must transactionally rebuild the authenticated bridge
under its historical constraints before the `0.8.5` handoff. The other five
lanes resolve their published dependency graphs, and the latest-source lane
separately proves the current direct updater path.

## Candidate custody and publication

The workflow builds the runtime artifacts once, uses those exact bytes to build
the platform installers, seals a single checksummed candidate, and validates
that candidate. Validation jobs do not rebuild from the source checkout.

Only after every required gate succeeds does the workflow create the tag and
immutable GitHub release. It publishes the selected Linux, macOS, and Windows
assets from the sealed candidate and verifies the remote asset bytes. A failed
gate leaves no release to promote and requires a new dispatch after the problem
is fixed.

## What belongs before merge

Pull-request and `main` workflows remain responsible for broad unit,
integration, lint, and platform regression coverage. Repository merge rules
should require their aggregate checks. Release assumes anything merged into
`main` has passed that review boundary and limits itself to proving that the
actual artifacts install, the supported POSIX upgrade works, platform signing
status is represented honestly, and the tested bytes are the bytes published.
