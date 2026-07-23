# Release Validation Strategy

DefenseClaw treats publication as promotion of already certified bytes. The
final Release workflow is not intended to discover upgrade, rollback,
observability, Docker, or provenance defects for the first time.

## Validation Layers

| Layer | Trigger | Required scope | Candidate custody |
|---|---|---|---|
| Pull request | Every PR, with a path-filtered selective upgrade job for release-sensitive changes | Fast deterministic release regressions; risky PRs add current stable, previous stable, the `0.8.4` bridge boundary, an explicit direct-skip refusal, and the oldest-supported smoke/refusal | Unsigned PR candidate; direct target activation plus production pre-mutation refusal, never release certification |
| Main smoke | Every merge to `main` | Medium candidate smoke for the exact merged SHA and at least one representative published target-activation canary | Exact merged SHA; no publication or provenance claim |
| Pre-release certification | Nightly schedule or manual dispatch for a selected ref and candidate version | Signed candidate; behavior-class historical matrix; live migration and rollback/recovery; Docker/local observability continuity; native platform checks; bounded-retry provenance verification | One signed candidate artifact plus one certification receipt |
| Release | Manual version input on protected `main` | First verify a recent receipt for the exact SHA, workflow version, candidate version, platform set, behavior-class baselines, artifact ID/digest, and run identity; only then wait for successful main CI, native Windows CI, and macOS app CI for that SHA and publish those same bytes | Reuse certified bytes without rebuilding |

The manual workflow defaults to `operation=certify`. For
`operation=release`, exact receipt lookup and verification finish before the
workflow begins its potentially three-hour wait for that SHA's main CI, native
Windows CI, and macOS app CI. All three workflows execute independently and
are checked under one absolute deadline with bounded API requests. The window
covers the native Windows package and acceptance critical path plus normal
runner setup and queueing. After all three workflows succeed, Release refetches
`main` and aborts if another commit has superseded the selected SHA; the
operator must then promote the new reviewed tip instead.

The standalone macOS app workflow builds the complete ad-hoc DMG on affected
pull requests, every exact `main` SHA, and manual requests. Its stable
`macOS App Required` aggregate must pass before Release starts publishable
packaging. The protected Release workflow remains the only path that builds
the conditionally notarized macOS assets. Release-wrapper changes also trigger
this workflow, which executes their nounset contracts with macOS system Bash
before certification can consume them.

If a matching certification receipt is missing, failed, stale, or does not
cover the exact release inputs, `operation=release` fails before candidate
construction or platform packaging. Run the explicit `operation=certify` path
for that exact commit and version, wait for it to succeed, and then retry
promotion. Release must never publish after only a reduced smoke and must never
silently accept a receipt for another commit, version, workflow revision,
platform set, baseline selection, or candidate digest.

## Behavior-Class Baselines

`release/upgrade-baselines.json` remains the reviewed historical floor of
supported sources. The effective-policy resolver also admits newer stable
versions from the live GitHub Releases API after authenticating their immutable
release assets. This matters immediately after publication and does not require
a hand-edited version pin.
`release/certification-policy.json` selects representatives by behavior instead
of taking an arbitrary number of versions:

- latest published stable before the candidate;
- previous published stable;
- the `0.8.4` protocol-2 bridge boundary when the v8 hard cut applies;
- the newest pre-bridge source, including a direct-target pre-mutation refusal;
- the oldest supported baseline;
- both sides of each config-schema transition;
- both sides of the signed-historical-artifact boundary; and
- explicitly reviewed protocol/installer boundaries.

Duplicate versions are collapsed while all of their behavior classes remain in
the selection metadata. PR cases that resolve to the same version, mode, and
expected result also execute once with all covered classes attached; a success
and refusal for the same version remain separate cases. Routine newly published
stables enter dynamically.
Expanding the historical support floor or moving a protocol, installer, schema,
or artifact-authentication boundary still requires a reviewed policy change.

Full certification authenticates each selected historical wheel and gateway,
then exercises its controller and state through the signed release-owned
resolver on Linux and macOS. Representative latest-stable and pre-bridge Linux
cases also start the authenticated source gateway and require version-bound
health before the resolver handoff. Full certification does not reinstall an
old wheel by resolving
its transitive dependencies against today's mutable package index. That would
model a fresh historical install—not an existing endpoint—and can become
unsatisfiable after publication without any change to the candidate or upgrade
path. The required bridge case is the narrow exception: it resolves the
bridge's published dependencies so target-only dependency promotion and the
hard-cut probe are exercised realistically on both Linux and macOS. The
release-sensitive PR and main gates separately install the resolver's
hash-pinned historical scanner/LiteLLM compatibility pair into clean `0.8.4`
and `0.8.5` environments and require every installed package's metadata to be
consistent. Resolution of the remaining transitives is capped at the immutable
`0.8.5` publication timestamp, so later package uploads cannot silently change
the bootstrap graph. Those historical constraints and the cutoff are kept out
of the final candidate controller environment. The current-stable main canary
also resolves the published stable's dependencies. All other historical cases
use the candidate-compatible runtime and validate the actual controller,
migration, refusal, rollback, and health behavior.

For nightly/manual certification, `scripts/resolve_upgrade_baselines.py`
materializes `effective-upgrade-baselines.json`. It starts from the reviewed
historical floor, then admits a newer live stable only after GitHub reports an
immutable release and the resolver authenticates its signed checksums,
release-owned manifest, runtime config identity, and platform capability. The
same snapshot must be passed as `--baselines effective-upgrade-baselines.json`
to selection, metadata creation, and metadata verification. It is also sealed
with the candidate. This lets a just-published stable become the next release's
`latest_stable` without a workflow-authored policy commit, while preventing an
unreviewed or unauthenticated release from entering the matrix.

The published `0.8.4` bridge is POSIX-only. Full certification currently lists
the live hosted-runner targets (`linux-amd64` and `darwin-arm64`) plus the special
`windows-resolver-refusal` target. That target proves the signed PowerShell
resolver refuses safely; it does not claim a Windows gateway, rollback binary,
SBOM binary, or bridge path. Cross-built Linux ARM64 and Darwin AMD64 artifacts
remain covered by candidate integrity/provenance checks, but the receipt does
not claim native execution on a runner that was not used.

## Workflow Integration CLI

In the Actions UI, always run the `Release` workflow itself from `main`.
Choose `certify` for a manual full certification; `candidate_ref` may name an
exact reviewed commit reachable from `main`, and an omitted version is resolved
from the live stable state. Choose `release` to publish, provide the version,
and confirm immutable releases; publishing is restricted to the current
`main` tip. The exact commit's `CI` push workflow must complete successfully;
the same is true for `Windows Native CI` and `macOS App`. A release dispatched
while any of those runs is queued, starting, or running waits for it in bounded
preflight. A failed run stops publication, and a run that does not appear or
finish within the bound can be retried after CI passes. A missing or rejected
certification stops promotion before candidate construction; run `certify`
successfully for the exact commit and version before retrying `release`.

All scheduled and manual certification/publication runs share one repository-wide
promotion lock. A later dispatch waits instead of racing another candidate, so
its stable-version and tag preflight runs only after the earlier operation finishes.

Resolve a nightly/main candidate from the live GitHub Releases response. A
manual request wins; without one, the helper selects the greater of the source
default and the next patch after the latest published stable:

```bash
gh api --paginate --slurp \
  repos/cisco-ai-defense/defenseclaw/releases > releases.json
python3 scripts/release_certification.py resolve-version \
  --source-version "$SOURCE_VERSION" \
  --published-releases releases.json \
  --github-output "$GITHUB_OUTPUT"
```

`--requested "$VERSION"` may be added for a manual dispatch. Select the reduced
PR matrix or full behavior-class matrix using those outputs:

```bash
GITHUB_TOKEN="$GH_TOKEN" python3 scripts/resolve_upgrade_baselines.py \
  --target-version "$CANDIDATE_VERSION" \
  --output effective-upgrade-baselines.json

python3 scripts/release_certification.py select-baselines \
  --baselines effective-upgrade-baselines.json \
  --scope pr \
  --candidate-version "$CANDIDATE_VERSION" \
  --latest-stable "$LATEST_STABLE" \
  --format matrix \
  --github-output "$GITHUB_OUTPUT"

python3 scripts/release_certification.py select-baselines \
  --baselines effective-upgrade-baselines.json \
  --scope full \
  --candidate-version "$CANDIDATE_VERSION" \
  --latest-stable "$LATEST_STABLE" \
  --format document \
  --output selection.json \
  --github-output "$GITHUB_OUTPUT"
```

Only after every selected case, live continuity gate, rollback/recovery gate,
and provenance check passes, record the signed artifact. Every selected
baseline must be repeated in the same order so a partially executed matrix
cannot claim full certification:

```bash
mapfile -t TESTED_BASELINES < <(
  python3 -c 'import json; print(*(item["version"] for item in json.load(open("selection.json"))["baselines"]), sep="\n")'
)
TESTED_ARGS=()
for baseline in "${TESTED_BASELINES[@]}"; do
  TESTED_ARGS+=(--tested-baseline "$baseline")
done

python3 scripts/release_certification.py write-metadata \
  --baselines effective-upgrade-baselines.json \
  --scope full \
  --candidate-version "$CANDIDATE_VERSION" \
  --latest-stable "$LATEST_STABLE" \
  --repository "$GITHUB_REPOSITORY" \
  --commit "$GITHUB_SHA" \
  --candidate-root release-candidate \
  "${TESTED_ARGS[@]}" \
  --artifact-id "$SIGNED_CANDIDATE_ARTIFACT_ID" \
  --artifact-name "$SIGNED_CANDIDATE_ARTIFACT_NAME" \
  --artifact-digest "$SIGNED_CANDIDATE_ARTIFACT_DIGEST" \
  --run-id "$GITHUB_RUN_ID" \
  --run-attempt "$GITHUB_RUN_ATTEMPT" \
  --workflow-file .github/workflows/pre-release-certification.yml \
  --output release-certification.json
```

The metadata command consumes the selector output; operators and workflows do
not maintain a second baseline list.

At publication, verify the downloaded receipt before acquiring or publishing
the certified candidate:

```bash
python3 scripts/release_certification.py verify-metadata \
  --baselines effective-upgrade-baselines.json \
  --scope full \
  --candidate-version "$RELEASE_VERSION" \
  --latest-stable "$LATEST_STABLE" \
  --repository "$GITHUB_REPOSITORY" \
  --commit "$GITHUB_SHA" \
  --candidate-root release-candidate \
  --workflow-file .github/workflows/pre-release-certification.yml \
  --metadata release-certification.json \
  --github-output "$GITHUB_OUTPUT"
```

The verifier emits the immutable candidate artifact ID and SHA-256 digest, the
certifying run ID/attempt, validity interval, and tested baselines. A nonzero
exit means “run full certification,” never “skip validation.” The certification
window is intentionally bounded by the reviewed policy (currently 72 hours).
The workflow version is not a manually bumped release number: it is an
automatic SHA-256 over the helper and all baseline/selection policies. The
receipt separately binds the exact certification workflow file. Changing code,
workflow, policy, behavior selection, or candidate bytes invalidates old
receipts.

## Path-Sensitive PR Scope

The selective PR matrix should run when a PR changes release workflows,
installers or upgrade resolvers, migrations/config schemas, runtime packaging,
release policies, observability continuity tooling, or the certification helper
and its tests. Documentation-only and unrelated application changes retain the
fast deterministic release regressions without paying for live historical
upgrades.

Tests must enforce both directions of this boundary: ordinary PR and Release
must not contain the full signed live matrix, while nightly/manual
certification must retain signed candidates, rollback/recovery, live
observability continuity, behavior-class baselines, and provenance checks.

Unsigned PR and main success cases use
`scripts/test-developer-target-activation.sh`. It authenticates the published
baseline, creates a private throwaway `HOME`, checksum-binds the exact-SHA
candidate, installs it directly, and proves target-owned migration, required
migration cursors, exact CLI and gateway versions, fresh-process health, and
SQLite integrity. For pre-v8 sources it additionally proves config/secret
conversion and recovery digests. For an authenticated config-v8 source it
instead requires byte-exact config/environment continuity and proves that the
one-time v7-to-v8 activation is not replayed. Fixture selection is keyed by the
authenticated source config family and fails closed for a future unreviewed
family; it is never inferred only from the target version. It intentionally
does not call the production updater and cannot claim signed provenance, the
`0.8.4` controller handoff, production receipts, rollback/recovery, or
Docker/local-observability continuity. The separate unsigned refusal case
continues to prove that the production path fails before mutation. All omitted
positive guarantees remain mandatory in nightly/manual signed certification.

Signed certification seeds native-v8 continuity from the authenticated
baseline wheel's own managed observability bundle and ownership manifest, then
requires the target to replace managed bytes while preserving operator-owned
files. This keeps the dynamic `0.8.5 -> 0.8.6` canary representative after
0.8.5 becomes the current stable release.
