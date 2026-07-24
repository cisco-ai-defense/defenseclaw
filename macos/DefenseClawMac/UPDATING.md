<!--
Copyright 2026 Cisco Systems, Inc. and its affiliates

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

SPDX-License-Identifier: Apache-2.0
-->

# Updating the imported macOS app

Use this procedure to refresh `macos/DefenseClawMac` from the standalone [`keitheobrien/defenseclaw_mac`](https://github.com/keitheobrien/defenseclaw_mac) repository without losing the monorepo's release, identity, or licensing integration.

## 1. Prepare the update

Start from an updated `main` and create a feature branch. Confirm the current pin and online freshness state:

```bash
python3 scripts/check-macos-upstream.py --offline
python3 scripts/check-macos-upstream.py
```

Prepare the latest stable update with:

```bash
scripts/update-macos-app.sh
```

Pass an explicit stable release tag to reproduce or select an update:

```bash
scripts/update-macos-app.sh v1.2.0
```

The updater performs a three-way merge using the commit in [upstream.lock.toml](upstream.lock.toml) as the base, the checked-in Cisco app as `ours`, and the requested stable upstream release as `theirs`. This preserves Cisco integration while surfacing real conflicts for review. It updates the lock and this provenance record, reapplies license headers, and runs the macOS checks. If a conflict occurs, the script leaves the merge under `build/macos-upstream-sync-<tag>` and does not modify the checked-in app.

Review upstream changes since the old locked SHA before accepting the generated diff.

Only sync these maintained paths:

```text
DefenseClawMac.xcodeproj/
DefenseClawMac/
Tests/
script/build_and_run.sh
script/test_connector_onboarding.sh
tools/
images/
.gitignore
```

Do not import upstream Git metadata, `.codex`, personal signing identities, a duplicate `LICENSE`, or design/planning documents that the monorepo supersedes. Port relevant changes from the standalone DMG script into `scripts/build-macos-app-release.sh`; do not restore its hard-coded team, keychain profile, or download-from-an-already-published-release assumptions.

## 2. Preserve Cisco integration points

After syncing, review and restore these intentional differences:

- Bundle identifier: `com.cisco.defenseclaw.macos`.
- No personal Apple development team or signing identity in the project file.
- App `MARKETING_VERSION` matches the repository `VERSION`.
- `UpdateChecker` reads releases from `cisco-ai-defense/defenseclaw`, selects only verified `DefenseClawMac-*-macos-arm64.zip` assets, and never offers `-unverified` artifacts through in-app self-update.
- Before extraction, `UpdateChecker` rejects empty or malformed ZIP manifests, absolute and traversal paths, link entries, multiple app bundles, and content outside one top-level `.app` bundle.
- `RuntimeInstaller` continues to understand `Contents/Resources/RuntimePayload`.
- Release packaging remains in `scripts/build-macos-app-release.sh` and `.github/workflows/release.yaml`, producing a runtime-bearing DMG and app-only self-update zip.

Search for stale personal/repository settings:

```bash
rg -n 'keitheobrien|9R236BB67S|com\.keitheobrien|Developer ID Application' macos/DefenseClawMac
```

Any retained upstream attribution belongs in [UPSTREAM.md](UPSTREAM.md), not in runtime identifiers.

## 3. Apply and verify license headers

The updater changes [UPSTREAM.md](UPSTREAM.md) and [upstream.lock.toml](upstream.lock.toml) together. Confirm the stable tag resolves to the recorded immutable commit, then run:

```bash
python3 scripts/macos_license_headers.py --fix
python3 scripts/macos_license_headers.py
```

The fixer adds the full Cisco Apache-2.0 header to commentable imported files. PNG assets and asset-catalog `Contents.json` manifests are covered by [ASSET_LICENSES.md](ASSET_LICENSES.md). The check fails on any new file type until its licensing policy is made explicit.

## 4. Build and test

Run from the repository root:

```bash
make check-version-sync
make macos-app-test
make extensions
make dist-cli
make macos-app-release
make macos-app-release-verify
```

Mount the resulting DMG and confirm it contains `DefenseClawMac.app`, an `/Applications` symlink, the matching gateway and wheel under `Contents/Resources/RuntimePayload`, and `payload-manifest.json`. Confirm the zip contains the app without `RuntimePayload`, preserving the independent runtime update track. Local development builds may produce clearly named `-unverified` artifacts, but the in-app self-updater ignores those assets.

Confirm the app-only ZIP contains exactly one top-level `.app` bundle and no absolute paths, `..` components, symlinks, hardlinks, or unrelated top-level files. The updater performs this validation before `ditto` extraction, then requires bundle identity/version checks, code-signature validation, and Gatekeeper assessment before installation.

The first-run runtime installer pins its fallback `uv` download by version and SHA-256 in `RuntimeInstaller.swift`. When updating that pin, use an immutable `astral-sh/uv` release, copy the Apple Silicon archive digest from the release asset, and verify the archive locally before changing both constants together.

Production releases require all five release-environment secrets
(`MACOS_DEVELOPER_ID_P12_BASE64`, `MACOS_DEVELOPER_ID_P12_PASSWORD`,
`MACOS_NOTARY_KEY_BASE64`, `MACOS_NOTARY_KEY_ID`, and
`MACOS_NOTARY_ISSUER_ID`) and publish only verified macOS app-update assets.
Missing, partial, or invalid credentials stop the workflow before publication.
Local development builds may omit all five and produce ad-hoc-signed
`-unverified` assets, which the in-app self-updater rejects.

## 5. Review before merging

- Inspect the complete upstream diff, especially process execution, update URLs, token handling, filesystem writes, and embedded payload installation.
- Confirm no credentials, signing certificates, developer-team IDs, generated build products, or local user paths were imported.
- Confirm every GitHub Action is pinned to an immutable commit SHA.
- Confirm the release job downloads both the DMG and zip before regenerating `checksums.txt` and publishing the atomic GitHub release.
- Confirm `test_update_checker_verification.sh` and `test_update_checker_safety.sh` pass, covering verified-only asset selection and pre-extraction archive rejection.
- Confirm `python3 scripts/check-macos-upstream.py` succeeds online. The release preflight fails before signing if the pin is stale.
- Confirm the scheduled `macOS Upstream Freshness` workflow is enabled. It opens one update issue when the latest stable standalone release advances.
- Record exact commands and observed results in the pull request test plan.
