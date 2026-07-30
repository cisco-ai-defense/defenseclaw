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

- Stable release: `v1.1.10`
- Commit: `e168726fab31c6b37f3c07e4cb8871d292313e2c`
- Commit title: `Merge pull request #6 from keitheobrien/kobrien/fix-menu-alert-acknowledgement`
- Imported: 2026-07-28

The import includes the Xcode project, Swift sources, tests, developer build/test scripts, icon-generation tool, asset catalog, and README images. It intentionally excludes the upstream repository's Git metadata, `.codex` configuration, personal signing identities, duplicate license file, and standalone release wrapper. The upstream `scripts/build_unified_dmg.sh` behavior is adapted into the monorepo's `scripts/build-macos-app-release.sh` so the unified DMG is built from the same unpublished commit as the backend release rather than downloading an already-published runtime.

Cisco integration changes after import include the Cisco bundle identifier, unified release source, synchronized DefenseClaw version, ad-hoc-by-default signing, the runtime-bearing DMG plus app-only update zip, monorepo CI/release workflows, and Cisco Apache-2.0 headers.

The same immutable release and commit are recorded in
[upstream.lock.toml](upstream.lock.toml). The weekly freshness workflow reports
a newer stable release. Release preflight validates the checked-in lock
offline; it deliberately does not query the upstream repository or prove that
the pin is the latest release.

Update this file and the lock whenever the imported app is refreshed. Follow [UPDATING.md](UPDATING.md); do not copy the standalone repository wholesale.
