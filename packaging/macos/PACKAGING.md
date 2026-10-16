# macOS gateway bundle packaging

This file documents the source layout and build contract for the standalone
macOS gateway bundle, and how to build the standalone enterprise installer
package ([Standalone enterprise package](#standalone-enterprise-package)). Installation and upgrade instructions belong in the
[published installation guide](https://cisco-ai-defense.github.io/defenseclaw/docs/get-started/install/).
The short README shipped inside each bundle is generated from
[`scripts/write-macos-bundle-readme.sh`](../../scripts/write-macos-bundle-readme.sh).

## Build entry points

- `make packaging-macos-test` runs the side-effect-free shell tests in
  [`packaging/macos/tests/`](tests/).
- `make packaging-macos-bundle` invokes
  [`scripts/build-macos-bundle.sh`](../../scripts/build-macos-bundle.sh).
- `BUNDLE_GOARCH` is fixed to `arm64`. Intel (`amd64`) and universal macOS
  bundles are unsupported and the builder refuses them before producing files.
- Release builds provide the managed cloud-auth overlay and its pinned module
  version through `CMID_OVERLAY` and `CMID_VERSION`. Omitting that overlay is
  suitable only for local packaging tests; the resulting binary fails closed
  when configured for `managed_enterprise`.

The bundle name is
`defenseclaw-macos-${VERSION}-darwin-${BUNDLE_GOARCH}`. The build creates that
directory plus a `.tar.gz` archive and a sibling `.sha256` file under `dist/`.

## Managed agent-version discovery

The managed hook enumerator renders each connector's discovered version into
the hook-guardian target manifest. Codex discovery prefers the current
`ChatGPT.app` bundle, then the legacy standalone `Codex.app` bundle, in both
`/Applications` and the target user's `~/Applications`. It then checks
OpenAI's standalone `~/.codex/packages/standalone/current` selection,
Homebrew, and user/system package-manager metadata (including NVM and Bun)
before the bounded `PATH` fallback. Claude Code applies the same NVM/Bun
coverage in addition to its native installer and Desktop/extension layouts.

Bundle metadata is preferred when available. When a known application bundle
only exposes an executable version probe, the enumerator runs `--version` as
the target console user through `/usr/bin/sudo`, with bounded output and a
bounded wall-clock duration. It never executes an app-bundled Codex binary as
root. A missing, failed, or malformed bundle probe does not stop discovery:
the enumerator continues through the remaining bundle executables and
lower-priority sources, including package metadata and the bounded `PATH`
fallback. When every applicable source fails to yield a supported version, the
target remains unversioned. Under Secure Client the guardian installs the
reviewed best-effort contract with fail-open delivery until later discovery
resolves a known compatible contract; every other profile keeps the
fail-closed contract gate, which refuses an unverified target in action mode.

Reconciliation repeats discovery on every render, so an in-place agent upgrade
updates `agent_version` without reinstalling DefenseClaw.

## Bundle contents

The build script assembles:

- the gateway executable as `defenseclaw`;
- [`install.sh`](install.sh) and [`uninstall.sh`](uninstall.sh);
- `lib/installer_lib.sh`, `lib/render-targets.sh`, and
  `lib/scrub_agent_configs.py`;
- the gateway, hook-guardian, and hook-enumerator LaunchDaemon property lists
  from [`packaging/launchd/`](../launchd/); and
- a versioned `README.md` generated for the assembled artifact.

`install.sh` installs the bundle-local `defenseclaw` executable as
`defenseclaw-gateway` in the managed runtime tree. It is a fresh-install
surface and deliberately refuses an existing managed or legacy deployment;
upgrade behavior is owned by the release upgrade protocol.

## Source ownership

| Concern | Source |
| --- | --- |
| Bundle assembly and architecture selection | [`scripts/build-macos-bundle.sh`](../../scripts/build-macos-bundle.sh) |
| Generated bundle README | [`scripts/write-macos-bundle-readme.sh`](../../scripts/write-macos-bundle-readme.sh) |
| Install and fresh-host safety contract | [`packaging/macos/install.sh`](install.sh) |
| Uninstall and purge behavior | [`packaging/macos/uninstall.sh`](uninstall.sh) |
| Pure installer helpers | [`packaging/macos/lib/installer_lib.sh`](lib/installer_lib.sh) |
| Agent-config cleanup | [`packaging/macos/lib/scrub_agent_configs.py`](lib/scrub_agent_configs.py) |
| Installer tests | [`packaging/macos/tests/`](tests/) |

## Standalone enterprise package

The standalone managed-enterprise installer package is a separate build
from the gateway bundle above. It installs `defenseclaw-gateway`,
`defenseclaw-hook`, `defenseclaw-sensor-helper` and, when built,
`defenseclaw-acp` under `/opt/cisco/defenseclaw/bin`, and its postinstall
runs `defenseclaw-gateway enterprise macos ensure --from-package`.

```bash
make packaging-macos-enterprise VERSION=1.2.3
# dist/defenseclaw-enterprise-1.2.3-darwin-arm64.pkg
```

- The target runs
  [`scripts/build-macos-enterprise-pkg.sh`](../../scripts/build-macos-enterprise-pkg.sh)
  `--version "$(VERSION)" --dist-dir "$(DIST_DIR)"`. It runs on macOS only
  and needs Go and the Xcode command line tools (`pkgbuild`,
  `productbuild`). It cross-builds the darwin/arm64 binaries itself; pass
  `--payload DIR` to the script to package prebuilt ones instead.
- Always pass `VERSION`. The Makefile default is an old release number,
  and the package's preinstall refuses to install over a deployment with a
  higher version (unless an administrator created the root-owned
  `/opt/cisco/defenseclaw/lifecycle/allow-downgrade` marker), so a build for
  an upgrade test needs a version above the installed one.
- The package is unsigned unless `MACOS_APP_SIGN_IDENTITY` (Developer ID
  Application, codesigns the binaries with the hardened runtime) and
  `MACOS_INSTALLER_SIGN_IDENTITY` (Developer ID Installer, signs the product
  archive) are set; `MACOS_SIGN_KEYCHAIN` names the keychain holding them.
  Notarize a signed package separately.
- `scripts/test-enterprise-unix-install.sh` installs, converges, verifies
  and removes the package on a disposable Mac; see
  [docs/TESTING.md](../../docs/TESTING.md#enterprise-install-lanes).

The native SwiftUI app has a separate release pipeline under
[`macos/DefenseClawMac/`](../../macos/DefenseClawMac/) and is not produced by
`make packaging-macos-bundle`.
