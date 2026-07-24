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

# Upstream provenance

The macOS app was imported from [`keitheobrien/defenseclaw_mac`](https://github.com/keitheobrien/defenseclaw_mac) at:

- Stable release: `v1.1.7`
- Commit: `f8a79fe0ce86facd81205b7d6ff8a480c8e5a3b4`
- Commit title: `Release DefenseClawMac 1.1.7`
- Imported: 2026-07-21

The import includes the Xcode project, Swift sources, tests, developer build/test scripts, icon-generation tool, asset catalog, and README images. It intentionally excludes the upstream repository's Git metadata, `.codex` configuration, personal signing identities, duplicate license file, and standalone release wrapper. The upstream `scripts/build_unified_dmg.sh` behavior is adapted into the monorepo's `scripts/build-macos-app-release.sh` so the unified DMG is built from the same unpublished commit as the backend release rather than downloading an already-published runtime.

Cisco integration changes after import include the Cisco bundle identifier, unified release source, synchronized DefenseClaw version, ad-hoc-by-default signing, the runtime-bearing DMG plus app-only update zip, monorepo CI/release workflows, and Cisco Apache-2.0 headers.

The same immutable release and commit are recorded in [upstream.lock.toml](upstream.lock.toml). The weekly freshness workflow reports a newer stable release, and the DefenseClaw release preflight refuses to sign stale source.

Update this file and the lock whenever the imported app is refreshed. Follow [UPDATING.md](UPDATING.md); do not copy the standalone repository wholesale.
