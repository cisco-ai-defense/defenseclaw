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

# DefenseClaw for macOS

Native SwiftUI companion app for [Cisco DefenseClaw](https://github.com/cisco-ai-defense/defenseclaw). The app provides a menu-bar status view, native dashboards and setup flows, and one-click install and update through the release's `install.sh`.

![Overview dashboard](images/overview.png)

## Release package

The DefenseClaw release workflow publishes two Apple Silicon artifacts containing the same app:

- `DefenseClawMac-<version>-macos-arm64.dmg` — the drag-to-Applications installer. Mount it, drag `DefenseClawMac.app` to `/Applications`, launch it, then select **Install DefenseClaw Runtime** on first run.
- `DefenseClawMac-<version>-macos-arm64.zip` — the app with `DefenseClawMac.app` at the archive root. The release's `install.sh` unpacks it with `ditto -xk` when it updates the app.

The app does not embed the runtime. **Install DefenseClaw Runtime** (first run) installs the release matching the app's version, and **Update** installs the latest release. Both download that release's `install.sh` and `checksums.txt`, verify the script's SHA-256, and run `install.sh --yes` with `DEFENSECLAW_APP_PATH` set to the running app. The installer installs or upgrades the CLI and gateway, replaces the app bundle, and rolls back automatically if a step fails; output streams to the Activity panel, and the app restarts into the new bundle when it changed. Configuration, tokens, and the audit database are preserved.

The production GitHub release workflow Developer ID signs and notarizes the app
when all Apple credentials are available. If all five are absent, it publishes
ad-hoc-signed artifacts under the same names and reports them as unverified. A
partial credential group, or any invalid configured credential, stops the
release instead of silently falling back.

### Optional production Apple verification

Add these secrets to the GitHub `release` environment:

- `MACOS_DEVELOPER_ID_P12_BASE64`: base64-encoded Developer ID Application certificate and private key (`.p12`).
- `MACOS_DEVELOPER_ID_P12_PASSWORD`: password for that `.p12`.
- `MACOS_SIGNING_IDENTITY`: optional explicit `Developer ID Application: ...` identity; the script discovers it from the imported certificate when omitted.
- `MACOS_NOTARY_KEY_BASE64`: base64-encoded App Store Connect API private key (`.p8`).
- `MACOS_NOTARY_KEY_ID`: App Store Connect API key ID.
- `MACOS_NOTARY_ISSUER_ID`: App Store Connect issuer ID.

All five signing/notary values produce notarized release assets. Production,
local, and pull-request builds may omit all five to produce ad-hoc-signed,
unverified assets; partial credentials fail in every mode. Certificates are
imported into a temporary keychain, sensitive temporary files are removed on
exit, and the original user keychain search list is restored.

## Requirements

- Apple Silicon Mac (`arm64`)
- macOS 14 or newer
- Network access to GitHub and, while `install.sh` runs, PyPI/uv/Python distribution endpoints
- Xcode 16 or newer to build from source

## Build and test

From the DefenseClaw repository root:

```bash
make macos-app-test
make macos-app-build
```

To reproduce the release package locally:

```bash
make macos-app-release
```

The target writes the DMG and zip to `dist/`. Local invocations without Apple
credentials produce ad-hoc, unverified artifacts under the release names. The
production workflow signs and notarizes when the complete credential set is
available.

## Runtime connections

The app connects only to the local DefenseClaw installation:

| Source | Path / address |
|---|---|
| Gateway REST API | `http://127.0.0.1:<gateway.api_port>` (default 18970) |
| Audit DB (read-only) | `~/.defenseclaw/audit.db` |
| Event stream | `~/.defenseclaw/gateway.jsonl` |
| Logs | `~/.defenseclaw/gateway.log`, `~/.defenseclaw/watchdog.log` |
| Configuration | `~/.defenseclaw/config.yaml`, `~/.defenseclaw/.env` |
| Actions | `defenseclaw`, `defenseclaw-gateway` |

Read-only state is loaded from local files or the gateway. State-changing operations run through the DefenseClaw CLI and appear in the Activity panel. Secrets are sent over hidden standard input rather than command-line arguments.

## Maintaining the imported app

The source was imported from the standalone macOS repository. See [UPSTREAM.md](UPSTREAM.md) for provenance and [UPDATING.md](UPDATING.md) for the exact refresh, licensing, build, and review procedure.

All source is licensed under the repository's Apache License 2.0. See [LICENSE](../../LICENSE), [NOTICE](../../NOTICE), and [ASSET_LICENSES.md](ASSET_LICENSES.md).
