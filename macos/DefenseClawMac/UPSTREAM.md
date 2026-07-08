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

- Commit: `9fcd1f18ce67da70d54d7c41dc5c86e7f0b89362`
- Commit title: `Release DefenseClawMac 1.1.4`
- Imported: 2026-07-08

The import includes the Xcode project, Swift sources, tests, developer build/test scripts, icon-generation tool, asset catalog, and README images. It intentionally excludes the upstream repository's Git metadata, `.codex` configuration, standalone release automation, duplicate license file, and superseded unified-installer plan.

Cisco integration changes after import include the Cisco bundle identifier, unified release source, synchronized DefenseClaw version, ad-hoc-by-default signing, embedded backend payload, monorepo CI/release workflows, and Cisco Apache-2.0 headers.

Update this file whenever the imported app is refreshed. Follow [UPDATING.md](UPDATING.md); do not copy the standalone repository wholesale.
