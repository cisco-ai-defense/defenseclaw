# Release Validation Strategy

DefenseClaw treats publication as promotion of already certified bytes. The
final Release workflow is not intended to discover upgrade, rollback,
observability, Docker, or provenance defects for the first time.

## Validation Layers

| Layer | Trigger | Required scope | Candidate custody |
|---|---|---|---|
| Pull request | Every PR, with a path-filtered selective upgrade job for release-sensitive changes | Fast deterministic release regressions; risky PRs add current stable, previous stable, the `0.8.4` bridge boundary, an explicit direct-skip refusal, and the oldest-supported smoke/refusal | Unsigned PR candidate; success is not release certification |
| Main smoke | Every merge to `main` | Medium candidate smoke for the exact merged SHA and at least one representative published upgrade canary | Exact merged SHA; no publication |
| Pre-release certification | Nightly schedule or manual dispatch for a selected ref and candidate version | Signed candidate; behavior-class historical matrix; live migration and rollback/recovery; Docker/local observability continuity; native platform checks; bounded-retry provenance verification | One signed candidate artifact plus one certification receipt |
| Release | Manual version input on protected `main` | Verify a recent receipt for the exact SHA, workflow version, candidate version, platform set, behavior-class baselines, artifact ID/digest, and run identity; then publish those same bytes | Reuse certified bytes without rebuilding |

If a matching certification receipt is missing, failed, stale, or does not
cover the exact release inputs, Release must invoke the full certification path
and wait for it. It must never publish after only a reduced smoke and must never
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
the selection metadata. Routine newly published stables enter dynamically.
Expanding the historical support floor or moving a protocol, installer, schema,
or artifact-authentication boundary still requires a reviewed policy change.

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
`main` tip. A missing or rejected certification automatically selects the full
certification path before publication.

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
