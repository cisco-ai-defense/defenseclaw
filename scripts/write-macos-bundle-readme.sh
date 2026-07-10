#!/usr/bin/env bash
# Emit the README that ships inside the macOS installer bundle.
# Args: OUT_PATH VERSION GOOS GOARCH
set -euo pipefail

OUT="${1:?missing OUT_PATH}"
VERSION="${2:?missing VERSION}"
GOOS="${3:?missing GOOS}"
GOARCH="${4:?missing GOARCH}"

cat > "${OUT}" <<EOF
# DefenseClaw macOS bundle ${VERSION} (${GOOS}/${GOARCH})

Self-contained installer for a managed_enterprise DefenseClaw
deployment on macOS. No repository checkout, Go toolchain, or Homebrew
formula is required at install time — everything the installer needs
ships in this folder.

## Contents

| Path                            | Purpose                                             |
| ------------------------------- | --------------------------------------------------- |
| \`defenseclaw-gateway\`           | Prebuilt gateway binary (installed root:wheel 0755) |
| \`install.sh\`                    | Orchestrator: config, LaunchDaemon, per-user hooks  |
| \`uninstall.sh\`                  | Bootout daemon + scrub agent hook configs           |
| \`com.cisco.secureclient.defenseclaw.plist\` | LaunchDaemon plist                                  |
| \`lib/installer_lib.sh\`          | Pure helpers (sourced by install.sh)                |
| \`lib/scrub_agent_configs.py\`    | Agent hook config scrubber (stdlib Python)          |

## Install

\`\`\`
sudo ./install.sh --mode action --connector cursor,claudecode
\`\`\`

Full flag reference: \`./install.sh --help\`.

The installer resolves the gateway binary and plist by looking next to
\`install.sh\` first, so the bundle works verbatim from wherever you
place it.

### Custom plist overrides

Two paths are supported for the LaunchDaemon plist source:

- **Bundle default** (\`com.cisco.secureclient.defenseclaw.plist\` next to
  \`install.sh\`) — used automatically. The bundled plist inherits the
  extracting user's uid when you unpack the tarball; that's fine
  because its content came from this signed bundle.
- **Explicit override** via \`--plist <path>\` or the
  \`DEFENSECLAW_PLIST_SRC\` environment variable — treated as an
  untrusted operator input and required to be **root-owned** (\`chown
  root:wheel <path>\`) before install.sh will accept it.

Both paths refuse any source that is group- or world-writable (mode
must not include \`0022\`). Fix with:

\`\`\`
sudo chmod 0644 <path-to-plist>
\`\`\`

## Uninstall

Preserve config + audit DB (reversible reinstall):

\`\`\`
sudo ./uninstall.sh
\`\`\`

Full wipe (system files, runtime state, and DefenseClaw entries in the
user's native agent configs — non-DefenseClaw entries preserved):

\`\`\`
sudo ./uninstall.sh --purge -y
\`\`\`

## Requirements

- macOS with \`launchctl\` and \`/usr/bin/python3\` (stdlib only).
- Root privileges (\`sudo\`).
- Target user's home directory must not be group/other-writable
  (installer will refuse with an exact \`chmod\` fix).

Everything else — Codex / Claude Code / Cursor version detection, hook
config pre-creation, guardian invocation, tamper repair — is handled by
the scripts.
EOF
