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

- Stable release: `v1.1.25`
- Commit: `22e1aeb38cc37546976ab98a725d1c8194d3f523`
- Commit title: `Merge pull request #27 from keitheobrien/kobrien/gateway-auto-start`
- Imported: 2026-09-26

The import includes the Xcode project, Swift sources, the gateway administrator helper and its build script, tests, developer build/test scripts, icon-generation tool, asset catalog, and README images. It intentionally excludes the upstream repository's Git metadata, `.codex` configuration, personal signing identities, duplicate license file, and standalone release wrapper. The upstream `scripts/build_unified_dmg.sh` behavior is adapted into the monorepo's `scripts/build-macos-app-release.sh`, which builds the DMG and zip from the same unpublished commit as the backend release; the runtime is installed by that release's `install.sh` rather than embedded in the app.

Cisco integration changes after import include the Cisco bundle identifier, unified release source, synchronized DefenseClaw version, ad-hoc-by-default signing, install and update through the release's `install.sh`, an administrator helper that trusts its own signing team instead of a pinned personal team, monorepo CI/release workflows, and Cisco Apache-2.0 headers.

The same immutable release and commit are recorded in
[upstream.lock.toml](upstream.lock.toml). The weekly freshness workflow reports
a newer stable release. Release preflight validates the checked-in lock
offline; it deliberately does not query the upstream repository or prove that
the pin is the latest release.

Update this file and the lock whenever the imported app is refreshed. Follow [UPDATING.md](UPDATING.md); do not copy the standalone repository wholesale.
