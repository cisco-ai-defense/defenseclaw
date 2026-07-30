# macOS gateway bundle packaging

This file documents the source layout and build contract for the standalone
macOS gateway bundle. Installation and upgrade instructions belong in the
[published installation guide](https://cisco-ai-defense.github.io/defenseclaw/docs/get-started/install/).
The short README shipped inside each bundle is generated from
[`scripts/write-macos-bundle-readme.sh`](../../scripts/write-macos-bundle-readme.sh).

## Build entry points

- `make packaging-macos-test` runs the side-effect-free shell tests in
  [`packaging/macos/tests/`](tests/).
- `make packaging-macos-bundle` invokes
  [`scripts/build-macos-bundle.sh`](../../scripts/build-macos-bundle.sh).
- `BUNDLE_GOARCH` accepts `universal` (the default), `amd64`, or `arm64`.
  Universal builds require macOS and `lipo`.
- Release builds provide the managed cloud-auth overlay and its pinned module
  version through `CMID_OVERLAY` and `CMID_VERSION`. Omitting that overlay is
  suitable only for local packaging tests; the resulting binary fails closed
  when configured for `managed_enterprise`.

The bundle name is
`defenseclaw-macos-${VERSION}-darwin-${BUNDLE_GOARCH}`. The build creates that
directory plus a `.tar.gz` archive and a sibling `.sha256` file under `dist/`.

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

The native SwiftUI app has a separate release pipeline under
[`macos/DefenseClawMac/`](../../macos/DefenseClawMac/) and is not produced by
`make packaging-macos-bundle`.
