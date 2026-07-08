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

Start from an updated `main` and create a feature branch. Clone or fetch the upstream repository outside this working tree, record the exact commit SHA, and review its changes since the SHA in [UPSTREAM.md](UPSTREAM.md).

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
- `UpdateChecker` reads releases from `cisco-ai-defense/defenseclaw` and only selects `DefenseClawMac-*-macos-arm64*.zip` assets.
- `RuntimeInstaller` continues to understand `Contents/Resources/RuntimePayload`.
- Release packaging remains in `scripts/build-macos-app-release.sh` and `.github/workflows/release.yaml`, producing a runtime-bearing DMG and app-only self-update zip.

Search for stale personal/repository settings:

```bash
rg -n 'keitheobrien|9R236BB67S|com\.keitheobrien|Developer ID Application' macos/DefenseClawMac
```

Any retained upstream attribution belongs in [UPSTREAM.md](UPSTREAM.md), not in runtime identifiers.

## 3. Apply and verify license headers

Update [UPSTREAM.md](UPSTREAM.md) with the new SHA, title, and import date, then run:

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
```

Mount the resulting DMG and confirm it contains `DefenseClawMac.app`, an `/Applications` symlink, the matching gateway and wheel under `Contents/Resources/RuntimePayload`, and `payload-manifest.json`. Confirm the zip contains the app without `RuntimePayload`, preserving the independent runtime update track. Verify both artifact names contain `-unverified` unless Developer ID signing and notarization were deliberately configured.

## 5. Review before merging

- Inspect the complete upstream diff, especially process execution, update URLs, token handling, filesystem writes, and embedded payload installation.
- Confirm no credentials, signing certificates, developer-team IDs, generated build products, or local user paths were imported.
- Confirm every GitHub Action is pinned to an immutable commit SHA.
- Confirm the release job downloads both the DMG and zip before regenerating `checksums.txt` and publishing the atomic GitHub release.
- Record exact commands and observed results in the pull request test plan.
