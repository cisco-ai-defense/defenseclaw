# Release Validation Strategy

DefenseClaw uses one manually dispatched workflow to build, validate, and
publish a release from a reviewed `main` commit. A merge to `main` is the
review-and-CI boundary. Release trusts that boundary and validates the
publishable artifacts.

For the operator procedure, workflow request validation, post-publication
verification, and failure handling, follow the canonical
[DefenseClaw Release Runbook](RELEASE_RUNBOOK.md). This document defines the
release gates; the runbook defines how to operate them.

## One-dispatch contract

Run the `Release` workflow from `main` with only:

- `operation=release`; and
- a required bare `X.Y.Z` version.

A manual dispatch from `main` is release authorization: anything merged there
has already crossed the source-certification boundary. GitHub automatically
freezes the event's exact `github.sha`, so operators do not copy a commit SHA
or attest to repository settings. The first workflow job validates the release
namespace, version progression, and authenticated upgrade baseline matrix.

The workflow rejects a non-`main` dispatch, a commit that is not reachable from
reviewed `main`, an invalid version, and any conflicting or partially populated
tag/release namespace. `operation=release` never rebuilds a release that already
exists, even when its tag points to the selected commit. The only resumable
namespace is an exact same-commit tag with no release object, which can be left
before immutable publication begins. Once an immutable `0.8.8+` release exists,
use `operation=repair-channel` to repair only the authenticated stable pointer.
The workflow stamps the requested version into an isolated checkout; a
version-bump commit is not required. A later merge to `main` does not
invalidate the `github.sha` already selected for the running release.

```bash
gh workflow run release.yaml \
  --repo cisco-ai-defense/defenseclaw \
  --ref main \
  -f operation=release \
  -f version=0.8.8
```

Do not create or push the tag and do not run `gh release create` manually. The
workflow owns the tag and release namespace until it publishes the tested
candidate.

## Required release gates

One run builds one candidate and must pass all of these gates before
publication:

| Platform | Built assets | Validation |
|---|---|---|
| Linux | amd64 and arm64 gateway archives plus the shared CLI/plugin assets | Install the exact sealed candidate with `install.sh`; upgrade every authenticated historical lane selected for the target, including the latest older release, fixed migration boundaries, and representative `0.7.x`, `0.6.x`, and `0.5.x` releases; require the candidate CLI and gateway to be healthy |
| macOS | Intel and Apple Silicon gateway archives, shared CLI/plugin assets, and the unified macOS app | Install the exact sealed candidate with `install.sh`; run the same target-specific authenticated upgrade paths; with a complete Apple credential set, require Developer ID signing and notarization; with no Apple credentials, require ad-hoc signing and explicit `-unverified` artifact names |
| Windows | amd64 and arm64 gateway binaries, shared CLI assets, and the x64 `DefenseClawSetup-x64.exe` | Exercise the exact x64 candidate through `install.ps1` and native Setup; verify the installed CLI/gateway versions; with both Windows credentials, require Cisco Authenticode; with neither, require explicit unverified provenance and exact `NotSigned` state |

This is the complete release acceptance scope. Windows acceptance is
explicitly fresh-install-only. Every target must pass the exact native Setup
and `install.ps1` lifecycle, but no historical Windows baseline is inferred or
required. This gate is not evidence of a native Windows upgrade path.

The POSIX upgrade sources are resolved from authenticated published release
metadata: the latest supported version older than the target, the exact
`0.8.6` field-recovery anchor, the `0.8.5` hard-cut boundary, the `0.8.4`
bridge boundary, and the newest available `0.7.x`, `0.6.x`, and `0.5.x`
versions. For targets newer than `0.8.7`, Linux and macOS use the same seven
resolved baselines so the result is easy to understand and reproduce. A target
of `0.8.7` has six distinct lanes because its latest-older selection and exact
`0.8.6` field-recovery anchor resolve to the same release.

For a target newer than `0.8.7`, those seven lanes are: latest older (`0.8.7`
for a `0.8.8` target), exact `0.8.6` with the clean missing-cursor field
fixture, exact `0.8.5`, exact `0.8.4`, newest `0.7.x` (`0.7.2` today), newest
`0.6.x` (`0.6.6` today), and newest `0.5.x` (`0.5.0` today). Fixed anchors and
family selectors are mandatory; baseline resolution fails instead of silently
omitting an unavailable lane.

Field-recovery acceptance additionally installs and runs first setup through
the authenticated published `0.8.6` and `0.8.7` controllers without
manufacturing a cursor. The candidate resolver must authenticate the installed
source bytes and recover both real cursorless field states on Linux and macOS
while running with the immutable rescue bootstrap’s minimal
`/usr/bin:/bin:/usr/sbin:/sbin` tool path. This keeps the seven-lane matrix
compact while retaining the exact `0.8.7` regression after it stops being the
latest-older lane.

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
Because GitHub Actions normalizes permissions when it uploads a directory, the
sealed candidate crosses job boundaries only inside the deterministic
mode-preserving transport produced and safely restored by
`scripts/release_candidate.py`. Every consumer verifies the restored seal and
reviewed installer modes before using the bytes.

The Cosign version split is intentional: native Windows and release-candidate
jobs use `2.6.2`, matching the legacy JSON bundle framing and verifier embedded
in the native Windows candidate; signed stable-channel and public rescue paths
use `2.6.3`. The latter is pinned by the reviewed production SHA-256 for each
supported Linux/macOS architecture; offline tests compare those shipped pins
and workflow versions instead of adding a flaky network probe. Each job still
installs the exact requested Cosign version before it can sign or verify
anything. Do not align these pins without migrating and retesting both bundle
contracts.

Only after every required gate succeeds does the workflow create the tag and
immutable GitHub release. It publishes the selected Linux, macOS, and Windows
assets from the sealed candidate and verifies the remote asset bytes. A failed
gate leaves no release to promote and requires a new dispatch after the problem
is fixed.

Starting with `0.8.8`, the sealed candidate also contains the external
`defenseclaw-rescue.sh` bootstrap. After proving the immutable remote release,
the separate post-release job signs a strict stable-channel document and
fast-forwards the dedicated `release-channel` branch. The channel may point to
a newer immutable resolver; no workflow replaces assets on an existing tag. If
that job fails, the immutable publication job remains green and the prior stable
pointer stays in place. Inspect the failed step before retrying: a channel API
or signing failure after a successful remote-custody proof can be retried only
as that failed post-release job from the same run, or with a new
`operation=repair-channel` dispatch. Never redispatch `operation=release` for
the published tag. A failed asset-digest or custody proof means the published
assets have not been shown to match the tested bytes and must be investigated
rather than treated as a valid release. See
[Authenticated release channel and rescue bootstrap](RELEASE_CHANNEL.md) for
the field-level trust and recovery contract.

## What belongs before merge

Pull-request and `main` workflows remain responsible for broad unit,
integration, lint, and platform regression coverage. Repository merge rules
should require their aggregate checks. Release assumes anything merged into
`main` has passed that review boundary and limits itself to proving that the
actual artifacts install, the supported POSIX upgrade works, platform signing
status is represented honestly, and the tested bytes are the bytes published.
