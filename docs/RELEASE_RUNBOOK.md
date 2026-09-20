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

## Persistent repository controls

These are repository settings, not fields that an operator must attest to for
each release.

### Immutable releases and scoped secrets

1. Enable GitHub Immutable Releases for the repository.
2. Scope `release` environment secrets to the release workflow. A per-release
   environment approval is optional, not part of the dispatch contract.
3. Configure Apple and Windows signing secrets only as complete groups. See
   [Unsigned platform builds](#unsigned-platform-builds) for the supported
   no-credential mode.
4. Keep the required PR and `main` checks in branch policy. Merge remains the
   source-certification boundary.

GitHub verifies the immutable release after publication, so there is no
per-release confirmation checkbox. You do not need to create a ruleset to cut
a release. A ruleset on `release-channel` is optional repository hardening,
not a release prerequisite or part of client trust.
This relies on protected `main`, required checks, and the reviewed release
workflow and signing identity remaining protected from administrator-level
bypass; a channel ruleset alone cannot defend against an administrator who can
rewrite those publishing authorities.

With those authorities intact, someone limited to editing the channel can
delete the pointer or replay an older valid signed pointer, affecting
availability or freshness. They still cannot make clients accept an unsigned
channel document, altered resolver, or altered release payload: Sigstore
authenticates the channel and its digests bind the immutable versioned assets.

## Cut a release

### 1. Dispatch from reviewed `main`

Merge every release change and wait for the required `main` checks. Anything
merged into `main` is source-certified. Do not make a version-bump commit; the
workflow input stamps an isolated build checkout.

In GitHub, open **Actions → Release → Run workflow**, select **main**, choose
`operation=release`, and enter a bare canonical version without a `v` prefix.
The examples below use `0.8.8`; replace it with the intended version.

```bash
RELEASE_VERSION=0.8.8
```

```bash
gh workflow run release.yaml \
  --repo cisco-ai-defense/defenseclaw \
  --ref main \
  -f operation=release \
  -f version="$RELEASE_VERSION"
```

Clicking **Run workflow** (or running the command above) is the release
authorization. GitHub automatically freezes the dispatch's exact `github.sha`,
so the run stays on that reviewed `main` commit even if another merge lands
later. Operators do not copy a commit SHA or attest to repository settings.

The first job validates the version, selected commit, tag/release namespace,
version progression, and authenticated POSIX upgrade baselines before the
expensive build begins. For a target newer than `0.8.7`, it must select seven
distinct lanes: latest older, exact `0.8.6`, exact `0.8.5`, exact `0.8.4`, and
the newest authenticated `0.7.x`, `0.6.x`, and `0.5.x` releases. `0.8.7` is
the one six-lane exception because latest older and `0.8.6` are the same
release.

Do not create or push the tag first. Do not run `gh release create`. The
workflow owns the version namespace until the tested candidate is published.

### 2. Monitor the exact run

Find the run created by that dispatch, record its ID and URL, then watch that
ID:

```bash
gh run list --workflow release.yaml --event workflow_dispatch --limit 10
gh run watch <run-id> --exit-status
gh run view <run-id> --log-failed
```

The expected release path is:

1. validate the request, credentials, namespace, and authenticated baselines;
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
- every baseline selected by workflow request validation upgraded on both
  Linux and macOS, including the `0.8.4` bridge and `0.8.5` forward handoff
  for pre-`0.8.4` sources;
- exact public `0.8.1` upgraded through the full `0.8.4` and `0.8.5` bridge
  route on both Linux and macOS as a companion case in the selected `0.8.5`
  lane;
- exact published `0.8.6` and `0.8.7` install-plus-first-run field states with
  an absent migration cursor recovered through the candidate resolver on both
  Linux and macOS under the immutable rescue bootstrap’s clean tool path;
- every candidate resolver success case ran without a runner-installed `uv`
  on `PATH`, proving the authenticated private bootstrap and handoffs;
- the native `macos-15-intel` fresh-install and authenticated-upgrade lanes
  both verified the exact sealed candidate, then refused before dependency,
  network, artifact, or state effects;
- native Windows x64 fresh install through `install.ps1` and
  `DefenseClawSetup-x64.exe`;
- exact CLI and gateway version plus healthy gateway checks;
- sealed-candidate verification before publication; and
- immutable remote asset custody before stable-channel advancement.

Windows acceptance is explicitly fresh-install-only. Every release still
builds and exercises the exact native Setup and `install.ps1` candidate, but
the release matrix does not claim or require a historical native Windows
upgrade path. Do not invent an unauthenticated historical lane.

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

- Linux amd64/arm64, macOS arm64, and Windows amd64/arm64 gateway artifacts
  and their SBOMs; Intel macOS is outside the supported release contract;
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

Protocol-2 policy still carries the legacy Darwin/amd64 slot for authenticated
schema compatibility. It is not a supported macOS asset: release install,
upgrade, rescue, package, build-validation, and certification paths must all
refuse Intel macOS before using it.

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
$ExpectUnsignedSetup = $true # Set false when the release job reports signed.
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

$Setup = Join-Path $VerifyDir "DefenseClawSetup-x64.exe"
$SetupLines = @(
  Get-Content -LiteralPath (Join-Path $VerifyDir "checksums.txt") |
    Where-Object { $_ -cmatch "^[0-9a-f]{64}  DefenseClawSetup-x64\.exe$" }
)
if ($SetupLines.Count -ne 1) {
  throw "Signed checksums do not contain exactly one DefenseClawSetup-x64.exe entry"
}
$ExpectedSetupSha256 = $SetupLines[0].Substring(0, 64)
$ActualSetupSha256 = (
  Get-FileHash -LiteralPath $Setup -Algorithm SHA256
).Hash.ToLowerInvariant()
if ($ActualSetupSha256 -cne $ExpectedSetupSha256) {
  throw "Downloaded DefenseClawSetup-x64.exe does not match signed checksums"
}

$SetupSignature = Get-AuthenticodeSignature $Setup
$ExpectedSignatureStatus = if ($ExpectUnsignedSetup) { "NotSigned" } else { "Valid" }
if ($SetupSignature.Status.ToString() -cne $ExpectedSignatureStatus) {
  throw "Setup signature status was $($SetupSignature.Status), expected $ExpectedSignatureStatus"
}
if (-not $ExpectUnsignedSetup) {
  $SetupPublisher = if ($null -ne $SetupSignature.SignerCertificate) {
    $SetupSignature.SignerCertificate.GetNameInfo(
      [Security.Cryptography.X509Certificates.X509NameType]::SimpleName,
      $false
    )
  } else {
    ""
  }
  if ($SetupPublisher -cne "Cisco Systems, Inc.") {
    throw "Setup publisher was '$SetupPublisher', expected 'Cisco Systems, Inc.'"
  }
}

& $Installer -Version $ReleaseVersion -Connector none -Yes
if ($LASTEXITCODE -ne 0) { throw "Authenticated install.ps1 failed" }
defenseclaw --version
defenseclaw status
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
`0.7.x`, `0.6.x`, and `0.5.x` lane selected by the workflow.

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

In GitHub, open **Actions → Release → Run workflow**, select **main**, choose
`operation=repair-channel`, and enter the published target:

```bash
RELEASE_VERSION=0.8.8

gh workflow run release.yaml \
  --repo cisco-ai-defense/defenseclaw \
  --ref main \
  -f operation=repair-channel \
  -f version="$RELEASE_VERSION"
```

As with a normal release, GitHub binds the dispatch to its own `github.sha`;
no human-supplied commit or confirmation is required. Watch the exact run ID.
The repair job re-authenticates the newest immutable target, published checksum
proof, provenance, source tree, and GitHub asset digests. It then signs a new
channel document and publishes a non-forced fast-forward child. An invalid old
tip remains in history; same-version rebinding and rollback remain forbidden.
Repeat the stable-channel and disposable signed-discovery checks after repair.

## Failure decision tree

| Observed state | Action |
| --- | --- |
| A build, installer, or upgrade gate failed and no release exists | Fix the cause, merge it to `main`, and dispatch the still-unused version from the new reviewed commit. A transient failure may use GitHub's **Re-run failed jobs** while its candidate artifacts remain available. |
| Only an exact same-commit tag exists and no release exists | Let the workflow's namespace reconciliation decide whether the original run or a same-commit redispatch can resume. Do not delete, move, or recreate the tag manually. |
| Publication returned an ambiguous API error | Inspect the workflow reconciliation and remote namespace. Never retry `gh release create` manually. Escalate any state that is neither absent nor the exact immutable candidate. |
| The immutable release is green, but `Advance authenticated stable channel` failed | Prefer **Re-run failed jobs** on the original run. If that is unavailable or the channel tip needs authenticated repair, dispatch `operation=repair-channel` for the newest immutable release. |
| Asset digest, Sigstore, provenance, or remote-custody proof failed | Stop. Investigate the immutable release and evidence. Do not advance or repair the channel merely to hide a custody failure. |
| A field defect exists in an immutable installer or resolver | Fix it on `main`, publish a new patch version, and advance the signed channel to that new immutable resolver. Never replace the old tagged asset. |
| Installed CLI discovery is broken | Obtain a rescue bootstrap from an authenticated `0.8.8+` tagged release, verify the saved bytes, and use the external rescue path in `RELEASE_CHANNEL.md`; never pipe an unauthenticated response into a shell. |
| The proposed repair target is older than the newest immutable stable release | Stop. Channel rollback is forbidden; ship a newer fixed patch instead. |

## Never do these

- Never dispatch the release workflow from a branch other than `main`.
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
- the exact authenticated Linux/macOS baseline list selected by the workflow;
- macOS and Windows verification status;
- immutable release URL and complete public asset inventory;
- signed checksum verification and digest-check results;
- Linux, macOS, and Windows install smoke results;
- Linux and macOS signed-channel upgrade smoke results; and
- stable-channel commit plus any rerun or repair evidence.

Do not declare the rollout complete while any required item is missing or
ambiguous.
