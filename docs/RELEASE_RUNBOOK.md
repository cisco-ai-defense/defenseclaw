# DefenseClaw Release Runbook

This is the canonical operator procedure for a DefenseClaw release and for
repairing its authenticated stable channel. The repository is the policy
authority: when this runbook, an external note, or a personal automation
disagrees, stop and use the checked-in workflow, scripts, policies, and
documentation.

Read this runbook together with:

- [Release validation strategy](RELEASE_VALIDATION.md), which defines the
  artifact gates and historical upgrade matrix;
- [Authenticated release channel](RELEASE_CHANNEL.md), which defines stable
  discovery and rescue trust; and
- [Windows rescue](WINDOWS_RESCUE.md), which defines native Windows recovery.

## Release model

A reviewed merge to `main` is source certification. The release workflow does
not recertify all repository CI. It builds one candidate from that reviewed
commit and proves only the release outcomes: Linux, macOS, and Windows
artifacts exist; fresh installers work; supported macOS/Linux upgrades work;
platform signing status is honest; and the tested bytes are the published
bytes.

There are two intentionally different kinds of release state:

- **Immutable tagged releases.** A version tag, resolver, installer, app,
  binary, manifest, checksum, and proof are never replaced after publication.
- **A mutable, signed stable channel.** The `release-channel` branch may
  fast-forward to a signed document that selects a newer immutable release.
  Clients authenticate that document and the target resolver digest before
  running anything.

The updater is therefore repairable without making an old updater mutable. A
future patch release can publish a fixed immutable resolver and advance the
signed channel to it. Nothing rewrites assets attached to an older tag.

## One-time repository controls

An administrator must establish these controls before the first production
dispatch. Recheck them after any repository, organization, or GitHub App
policy change.

### Immutable releases and protected environment

1. Enable GitHub Immutable Releases for the repository.
2. Keep the `release` environment protected and limit its secrets and
   approvals to the release workflow.
3. Configure Apple and Windows signing secrets only as complete groups. See
   [Unsigned platform builds](#unsigned-platform-builds) for the supported
   no-credential mode.
4. Keep the required PR and `main` checks in branch policy. Merge remains the
   source-certification boundary.

### Protect the stable channel

The live ruleset must match
[`release/release-channel-ruleset-policy.json`](../release/release-channel-ruleset-policy.json):

| Setting | Required value |
| --- | --- |
| Source | Organization `cisco-ai-defense` |
| Repository include | Exactly `defenseclaw`; protected repositories enabled |
| Target | Branch |
| Include | Exactly `refs/heads/release-channel` |
| Exclude | Empty |
| Enforcement | Active |
| Restrictions | `creation`, `update`, `deletion`, `non_fast_forward` |
| Publisher bypass | GitHub Actions `Integration` actor `15368`, mode `always` |

Create this as an organization ruleset. GitHub does not accept its own Actions
integration as a bypass actor on a repository-sourced ruleset. The configuring
operator therefore needs organization-ruleset authority; this is one-time
administrative setup, not a release credential. Track the initial live setup
in [#620](https://github.com/cisco-ai-defense/defenseclaw/issues/620); no
production dispatch is ready until that issue's audit succeeds.

Do not add a human publisher bypass. Avoid an overlapping rule that prevents
the reviewed GitHub Actions publisher from creating or fast-forwarding the
branch. The release workflow's keyless Sigstore identity authenticates channel
content; the ruleset limits who can publish and preserves the Git audit trail.

After creating or changing the organization ruleset, authenticate `gh` with
organization-ruleset administration authority and run:

```bash
python3 scripts/release-preflight.py ruleset-admin-audit
```

That one-time audit requires the sole exact publisher bypass. GitHub hides
bypass actors from routine release operators and the workflow's restricted
token, so every operator preflight and first workflow job validate the exact
visible source, repository/ref targets, restrictions, and aggregate effective
rules instead. The later channel push is the live proof that the Actions
publisher retains bypass. A missing, broad, disabled, duplicated, overlapping,
or observably incomplete ruleset stops the release before an expensive build.
Bypass-only drift is detectable by the administrator audit or the final channel
push, so rerun the administrator audit after every ruleset change.

## Cut a release

### 1. Prepare reviewed `main`

Merge every release change and wait for the required `main` checks. Do not make
a version-bump commit; the workflow input stamps an isolated build checkout.

From a macOS or Linux checkout, update a clean local `main`. Baseline-policy
persistence deliberately requires POSIX `O_NOFOLLOW` descriptor custody; the
hosted workflow still builds and validates the Windows deliverables.

```bash
git switch main
git pull --ff-only origin main
git status --porcelain
gh auth status
```

`git status --porcelain` must print nothing. Choose a bare canonical version,
without a `v` prefix. The examples below use `0.8.8`; replace it with the
intended version.

```bash
RELEASE_VERSION=0.8.8
```

Confirm in GitHub Settings that Immutable Releases is still enabled. Do not
infer this from an older run.

### 2. Run the non-mutating operator preflight

```bash
python3 scripts/release-preflight.py operator \
  --operation release \
  --version "$RELEASE_VERSION" \
  --immutable-releases-confirmed true
```

The preflight does not dispatch or publish anything. It fails closed unless:

- local `main` is clean and exactly equals fetched `origin/main`;
- GitHub CLI authentication works;
- the stable-channel ruleset matches the checked-in policy;
- the tag/release namespace is safe and the version progresses forward; and
- every authenticated POSIX baseline can be resolved.

Read the complete plan. Record the workflow commit, target commit, ruleset ID,
and selected macOS/Linux upgrade baselines with the release evidence. For a
target newer than `0.8.7`, there must be seven distinct lanes: latest older,
exact `0.8.6`, exact `0.8.5`, exact `0.8.4`, and the newest authenticated
`0.7.x`, `0.6.x`, and `0.5.x` releases. `0.8.7` is the one six-lane exception
because latest older and `0.8.6` are the same release.

Do not dispatch if the plan is surprising. Fix the repository policy or
release state and rerun preflight instead of overriding it.

### 3. Dispatch exactly once

Use the command printed by the successful preflight. Its release form is:

```bash
# Replace this quoted placeholder with the exact workflow_commit from preflight.
RELEASE_COMMIT="replace-with-exact-40-character-workflow-commit"

gh workflow run release.yaml \
  --repo cisco-ai-defense/defenseclaw \
  --ref main \
  -f operation=release \
  -f version="$RELEASE_VERSION" \
  -f expected_commit="$RELEASE_COMMIT" \
  -f immutable_releases_confirmed=true
```

The expected commit makes the dispatch fail if `main` advances between preflight
and dispatch. After dispatch, the event remains intentionally bound to that
exact SHA. Rerun preflight instead of changing the field. Do not create or push
the tag first. Do not run `gh release create`. The workflow owns the version
namespace until the tested candidate is published.

### 4. Monitor the exact run

Find the run created by that dispatch, record its ID and URL, then watch that
ID:

```bash
gh run list --workflow release.yaml --event workflow_dispatch --limit 10
gh run watch <run-id> --exit-status
gh run view <run-id> --log-failed
```

The expected release path is:

1. validate the request, live channel rules, credentials, namespace, and
   authenticated baselines;
2. build the runtime once and build the macOS app and native Windows Setup;
3. seal one checksummed candidate;
4. run fresh-install and target-specific upgrade gates against those exact
   candidate bytes;
5. create the tag and immutable GitHub release, then prove remote custody; and
6. sign and fast-forward the stable channel in the separate post-release job.

GitHub Actions directory artifacts normalize POSIX file modes. The workflow
therefore crosses every candidate job boundary as one deterministic
`release-candidate.tar`, safely extracts it without following archive links or
paths, and then reruns sealed-candidate verification, including the reviewed
`install.sh` executable mode. Do not upload the candidate directory directly,
extract the tar with a generic command, or weaken the mode check.

The run is complete only when the required release jobs and
`Advance authenticated stable channel` are green. The immutable release may
already exist when only the final channel job is red; handle that case with
the [failure decision tree](#failure-decision-tree), not another release
dispatch.

## Required evidence before declaring success

### Workflow gates

Confirm that the exact run shows:

- Linux and macOS fresh install through `install.sh`;
- every baseline printed by operator preflight upgraded on both Linux and
  macOS, including the `0.8.4` bridge and `0.8.5` forward handoff for
  pre-`0.8.4` sources;
- native Windows x64 fresh install through `install.ps1` and
  `DefenseClawSetup-x64.exe`;
- exact CLI and gateway version plus healthy gateway checks;
- sealed-candidate verification before publication; and
- immutable remote asset custody before stable-channel advancement.

Windows is explicitly fresh-install-only through `0.8.8`. Preflight blocks a
later release until [#619](https://github.com/cisco-ai-defense/defenseclaw/issues/619)
adds a native upgrade lane from an authenticated published Windows Setup.
Do not discard Windows baselines or invent an unauthenticated historical lane.

### Public release and asset inventory

Inspect the release object and its asset names:

```bash
gh release view "$RELEASE_VERSION" \
  --repo cisco-ai-defense/defenseclaw \
  --json tagName,isDraft,isPrerelease,isImmutable,targetCommitish,url,assets

gh release view "$RELEASE_VERSION" \
  --repo cisco-ai-defense/defenseclaw \
  --json assets \
  --jq '.assets[].name' | sort
```

Require the exact version, a non-draft/non-prerelease immutable release, and
the expected complete families:

- Linux, macOS, and Windows amd64/arm64 gateway artifacts and their SBOMs;
- the CLI wheel and plugin release assets;
- the macOS app DMG and ZIP, either notarized names or explicit
  `-unverified` names;
- `DefenseClawSetup-x64.exe` plus its digest, provenance, and SBOM;
- `install.sh`, `install.ps1`, `defenseclaw-upgrade.sh`,
  `defenseclaw-upgrade.ps1`, `defenseclaw-rescue.sh`, and
  `defenseclaw-rescue.ps1`;
- the upgrade manifest, release provenance, and source map; and
- `checksums.txt`, `checksums.txt.pem`, `checksums.txt.sig`, and
  `checksums.txt.bundle`.

On a clean Linux verification host, download every public asset, authenticate
the checksum manifest, and check every payload digest:

```bash
VERIFY_DIR="$(mktemp -d "${TMPDIR:-/tmp}/defenseclaw-release.XXXXXX")"
gh release download "$RELEASE_VERSION" \
  --repo cisco-ai-defense/defenseclaw \
  --dir "$VERIFY_DIR"

python3 scripts/verify-sigstore-blob.py \
  --certificate "$VERIFY_DIR/checksums.txt.pem" \
  --signature "$VERIFY_DIR/checksums.txt.sig" \
  --certificate-identity \
    "https://github.com/cisco-ai-defense/defenseclaw/.github/workflows/release.yaml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "$VERIFY_DIR/checksums.txt"

(cd "$VERIFY_DIR" && sha256sum --check checksums.txt)
```

Do not treat the GitHub page, TLS, or a `releases/latest` redirect as artifact
authentication.

### Public install and upgrade smoke

Use disposable, clean hosts; never make a production machine the release test
bed. The pre-publication candidate gates remain the authoritative full matrix,
and the custody proof binds those tested bytes to the public release.

On both Linux and macOS, authenticate the downloaded release directory as
above, then exercise the published POSIX installer:

```bash
bash "$VERIFY_DIR/install.sh" \
  --local "$VERIFY_DIR" \
  --yes \
  --connector none
defenseclaw --version
defenseclaw status
```

On a disposable native Windows x64 host, use a trusted checkout of the
reviewed release commit with the exact Cosign `2.6.3` verifier installed on
`PATH`. Download the public proof and installer, authenticate `checksums.txt`
under the release workflow identity, bind the saved `install.ps1` to that
signed manifest, and only then execute the verified script:

```powershell
$ReleaseVersion = "0.8.8" # Replace with the intended release.
$VerifyDir = Join-Path ([IO.Path]::GetTempPath()) (
  "defenseclaw-release-" + [guid]::NewGuid().ToString("N")
)
[IO.Directory]::CreateDirectory($VerifyDir) | Out-Null
foreach ($Asset in @(
  "checksums.txt",
  "checksums.txt.pem",
  "checksums.txt.sig",
  "install.ps1",
  "DefenseClawSetup-x64.exe"
)) {
  gh release download $ReleaseVersion `
    --repo cisco-ai-defense/defenseclaw `
    --dir $VerifyDir `
    --pattern $Asset
  if ($LASTEXITCODE -ne 0) { throw "Could not download $Asset" }
}

python scripts/verify-sigstore-blob.py `
  --certificate (Join-Path $VerifyDir "checksums.txt.pem") `
  --signature (Join-Path $VerifyDir "checksums.txt.sig") `
  --certificate-identity `
    "https://github.com/cisco-ai-defense/defenseclaw/.github/workflows/release.yaml@refs/heads/main" `
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" `
  (Join-Path $VerifyDir "checksums.txt")
if ($LASTEXITCODE -ne 0) { throw "Release checksum proof did not authenticate" }

$Installer = Join-Path $VerifyDir "install.ps1"
$InstallerLines = @(
  Get-Content -LiteralPath (Join-Path $VerifyDir "checksums.txt") |
    Where-Object { $_ -cmatch "^[0-9a-f]{64}  install\.ps1$" }
)
if ($InstallerLines.Count -ne 1) {
  throw "Signed checksums do not contain exactly one install.ps1 entry"
}
$ExpectedInstallerSha256 = $InstallerLines[0].Substring(0, 64)
$ActualInstallerSha256 = (
  Get-FileHash -LiteralPath $Installer -Algorithm SHA256
).Hash.ToLowerInvariant()
if ($ActualInstallerSha256 -cne $ExpectedInstallerSha256) {
  throw "Downloaded install.ps1 does not match signed checksums"
}

& $Installer -Version $ReleaseVersion -Connector none -Yes
if ($LASTEXITCODE -ne 0) { throw "Authenticated install.ps1 failed" }
defenseclaw --version
defenseclaw status
Get-AuthenticodeSignature (
  Join-Path $VerifyDir "DefenseClawSetup-x64.exe"
)
```

The installed CLI and gateway must report the target version and the gateway
must be healthy. For notarized macOS output, also require:

```bash
hdiutil verify "DefenseClawMac-${RELEASE_VERSION}-macos-arm64.dmg"
xcrun stapler validate "DefenseClawMac-${RELEASE_VERSION}-macos-arm64.dmg"
spctl --assess --verbose=4 --type open \
  "DefenseClawMac-${RELEASE_VERSION}-macos-arm64.dmg"
```

Finally, snapshot disposable Linux and macOS installations on the previous
stable release and exercise signed-channel discovery:

```bash
defenseclaw upgrade --yes
defenseclaw --version
defenseclaw status
```

Require the target version and healthy gateway. If the release changes
migrations, bridge selection, or recovery, also repeat the relevant public
smoke from the affected historical fixture. Regardless, the pre-publication
run must already show every authenticated `0.8.6`, `0.8.5`, `0.8.4`,
`0.7.x`, `0.6.x`, and `0.5.x` lane selected by preflight.

### Stable channel

Require the channel job to report successful read-back verification. Record
the `release-channel` commit:

```bash
gh api \
  repos/cisco-ai-defense/defenseclaw/git/ref/heads/release-channel \
  --jq '.object.sha'
```

The public `defenseclaw upgrade --yes` smoke above is the end-to-end
authentication check: discovery must accept the signed channel, fetch the
immutable target resolver, and finish at the target release.

## Unsigned platform builds

Missing platform credentials do not block an otherwise valid release:

- With none of the five Apple Developer ID/notary values, the workflow
  ad-hoc-signs the macOS app and publishes only DMG/ZIP names ending in
  `-unverified`.
- With neither Windows certificate value, the workflow publishes Setup with
  explicit unverified provenance and requires Authenticode `NotSigned`.
- Linux and the release checksum manifest continue through their normal
  keyless Sigstore custody path.

Those bytes are still immutable and authenticated by the signed release
manifest, but they are not platform-trusted. Release notes and operator
evidence must preserve that distinction. A partially configured Apple group
or Windows pair is an error and stops the run; the workflow never silently
downgrades a requested signed build.

## Repair only the stable channel

Use `repair-channel` only when the immutable release is already correct and
the separate channel job cannot be rerun successfully. The target must be the
newest immutable stable release. Repair never builds, edits, uploads, or
replaces a tagged asset.

From clean, current `main`, set the published target and run:

```bash
RELEASE_VERSION=0.8.8

python3 scripts/release-preflight.py operator \
  --operation repair-channel \
  --version "$RELEASE_VERSION"
```

Inspect the resolved tag commit, ruleset, and latest-immutable proof. Then use
the command printed by preflight:

```bash
# Replace this quoted placeholder with the exact workflow_commit from preflight.
RELEASE_COMMIT="replace-with-exact-40-character-workflow-commit"

gh workflow run release.yaml \
  --repo cisco-ai-defense/defenseclaw \
  --ref main \
  -f operation=repair-channel \
  -f version="$RELEASE_VERSION" \
  -f expected_commit="$RELEASE_COMMIT"
```

Watch the exact run ID. The repair job re-authenticates the published checksum
proof, provenance, source tree, and GitHub asset digests. It then signs a new
channel document and publishes a non-forced fast-forward child. An invalid old
tip remains in history; same-version rebinding and rollback remain forbidden.
Repeat the stable-channel and disposable signed-discovery checks after repair.

## Failure decision tree

| Observed state | Action |
| --- | --- |
| A build, installer, or upgrade gate failed and no release exists | Fix the cause, merge it to `main`, rerun operator preflight, and dispatch the still-unused version from the new reviewed commit. A transient failure may use GitHub's **Re-run failed jobs** while its candidate artifacts remain available. |
| Only an exact same-commit tag exists and no release exists | Let the workflow's namespace reconciliation decide whether the original run or a same-commit redispatch can resume. Do not delete, move, or recreate the tag manually. |
| Publication returned an ambiguous API error | Inspect the workflow reconciliation and remote namespace. Never retry `gh release create` manually. Escalate any state that is neither absent nor the exact immutable candidate. |
| The immutable release is green, but `Advance authenticated stable channel` failed | Prefer **Re-run failed jobs** on the original run. If that is unavailable or the channel tip needs authenticated repair, run the repair preflight and dispatch `operation=repair-channel` for the newest immutable release. |
| Asset digest, Sigstore, provenance, or remote-custody proof failed | Stop. Investigate the immutable release and evidence. Do not advance or repair the channel merely to hide a custody failure. |
| A field defect exists in an immutable installer or resolver | Fix it on `main`, publish a new patch version, and advance the signed channel to that new immutable resolver. Never replace the old tagged asset. |
| Installed CLI discovery is broken | Obtain a rescue bootstrap from an authenticated `0.8.8+` tagged release, verify the saved bytes, and use the external rescue path in `RELEASE_CHANNEL.md`; never pipe an unauthenticated response into a shell. |
| The proposed repair target is older than the newest immutable stable release | Stop. Channel rollback is forbidden; ship a newer fixed patch instead. |

## Never do these

- Never dispatch from a PR branch, dirty worktree, stale `main`, or a commit
  that does not exactly match `origin/main`.
- Never manually create, push, move, or delete a release tag.
- Never manually create a GitHub release or upload, edit, or replace an asset
  attached to an existing tag.
- Never rerun `operation=release` for an already published version.
- Never edit, delete, or force-push `release-channel`; only the reviewed
  workflow may publish a signed fast-forward update.
- Never point the stable channel at a mutable, older, draft, prerelease, or
  unauthenticated target.
- Never remove an upgrade lane, bridge, installer gate, checksum, or custody
  check to make a release finish.
- Never use `--allow-unverified`, an unsigned raw branch script, or an
  unauthenticated `releases/latest` response to rescue an installation.
- Never call an explicitly `-unverified` or `NotSigned` platform artifact
  notarized or Authenticode-signed.

## Release record

Retain these facts with the release:

- target version, workflow run ID/URL, workflow commit, and target commit;
- successful operator-preflight output and live channel ruleset ID;
- the exact authenticated Linux/macOS baseline list;
- macOS and Windows verification status;
- immutable release URL and complete public asset inventory;
- signed checksum verification and digest-check results;
- Linux, macOS, and Windows install smoke results;
- Linux and macOS signed-channel upgrade smoke results; and
- stable-channel commit plus any rerun or repair evidence.

Do not declare the rollout complete while any required item is missing or
ambiguous.
