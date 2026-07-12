# DefenseClaw macOS 0.8.0 — Install & Uninstall

**Artifact:** `defenseclaw-macos-0.8.0-darwin-universal.tar.gz` (fat binary — `x86_64` + `arm64`; produced by `make packaging-macos-bundle` with the default `BUNDLE_GOARCH=universal`. Single-arch tarballs `-darwin-arm64` / `-darwin-amd64` are available via `make packaging-macos-bundle BUNDLE_GOARCH=arm64` etc.)
**SHA-256:** see accompanying `defenseclaw-macos-0.8.0-darwin-universal.tar.gz.sha256`
**Target:** macOS (Intel or Apple Silicon), `launchctl` + `/usr/bin/python3` present, root privileges.

## 1. Verify + unpack

```sh
shasum -a 256 -c defenseclaw-macos-0.8.0-darwin-universal.tar.gz.sha256
tar -xzf defenseclaw-macos-0.8.0-darwin-universal.tar.gz
cd defenseclaw-macos-0.8.0-darwin-universal
```

The bundle is self-contained — no Go toolchain, no Homebrew, no repo checkout. `install.sh` resolves the gateway binary and plist next to itself.

## 2. Install

Standard install (observe mode, Codex connector only):

```sh
sudo ./install.sh
```

Typical enterprise install (action mode, Cursor + Claude Code hooks):

```sh
sudo ./install.sh --mode action --connector cursor,claudecode
```

Common flags:

| Flag | Default | Purpose |
| --- | --- | --- |
| `--mode {observe\|action}` | `observe` | Guardrail + asset_policy mode |
| `--connector LIST` | `codex` | Comma-separated: `codex`, `claudecode`, `cursor` |
| `--port PORT` | `18970` | Loopback API port |
| `--user USER` | `$SUDO_USER` | Target user for per-user hook wiring |
| `--skip-connector` | — | Gateway only; skip user-space hook wiring |
| `--skip-launchd` | — | Install files without bootstrapping the daemon |

Full reference: `./install.sh --help`.

The installer writes strict `config_version: 8` with local history under
`observability.local` and `observability.defaults.redaction_profile: sensitive`.
The retired global `--disable-redaction` switch is not accepted. To change the
posture, edit the administrator-owned v8 source with a global, bucket, or
destination profile, run `defenseclaw config validate` and
`defenseclaw observability plan`, then restart the daemon.

`install.sh` is fresh-install-only. It refuses current managed paths, legacy
managed paths, per-user DefenseClaw state, or loaded DefenseClaw launchd jobs
before building, stopping, or writing anything. Existing deployments must use
the release-owned staged upgrade path. If a managed-enterprise staged upgrader
is not published for the target release, remain on the current version and
contact the deployment owner; uninstalling or overwriting state is not a safe
upgrade procedure.

**Pre-flight requirement:** the target user's home must not be group/other-writable. If it is, `install.sh` refuses with the exact `chmod` fix in its error output.

### Custom plist source

`install.sh` picks the LaunchDaemon plist from the first path that exists in this order:

1. `--plist <path>` flag or `DEFENSECLAW_PLIST_SRC` env var (**explicit override**)
2. `com.cisco.secureclient.defenseclaw.plist` next to `install.sh` (**bundle default**)
3. `packaging/launchd/com.cisco.secureclient.defenseclaw.plist` under a repo checkout (**dev-tree default**)

The plist source is validated before it is copied to `/Library/LaunchDaemons/`:

| Source | Owner requirement | Mode requirement |
| --- | --- | --- |
| `--plist` / `DEFENSECLAW_PLIST_SRC` (override) | `root:*` | `!(mode & 0022)` |
| Bundle default / repo default | any (extraction uid is fine) | `!(mode & 0022)` |

The override tier is strict because the installer treats `--plist` as untrusted operator input; the bundle default is relaxed because the plist next to `install.sh` inherits the extracting user's uid when you `tar -xzf` the tarball but its content came from this signed bundle. Group- or world-writable sources are refused on either tier; `stat`-failure aborts with `cannot stat plist source ...`.

Fix a rejection with:

```sh
sudo chown root:wheel <path-to-plist>   # only needed for --plist / DEFENSECLAW_PLIST_SRC
sudo chmod 0644 <path-to-plist>          # required for either tier
```

## 3. Uninstall

Full wipe (system files, runtime state, any legacy service-user records, and DefenseClaw entries in per-user agent configs — non-DefenseClaw entries preserved):

```sh
sudo ./uninstall.sh --purge -y
```

Reversible alternative (preserves config + audit DB so a reinstall keeps history):

```sh
sudo ./uninstall.sh
```

Purge flags:

| Flag | Purpose |
| --- | --- |
| `--purge` | Delete `/opt/cisco/secureclient/defenseclaw/` (runtime + config + audit DB), `/Library/Logs/Cisco/SecureClient/DefenseClaw/`, `~/.defenseclaw/`, legacy service-user dscl records from pre-root installs, and scrub `~/.codex/config.toml`, `~/.claude/settings.json`, `~/.cursor/hooks.json` |
| `--keep-agent-configs` | With `--purge`, skip the agent-config scrub. Only safe if reinstalling immediately — otherwise dangling hook refs will fail-close every agent tool call. |
| `--user USER` | Per-user cleanup target (default `$SUDO_USER`) |
| `-y, --yes` | Skip purge confirmation prompt |

Full reference: `./uninstall.sh --help`.

## 4. Verification after install

```sh
sudo launchctl print system/com.cisco.secureclient.defenseclaw | head
curl -sS http://127.0.0.1:18970/healthz
```

## 5. Permissions the binary requests

### macOS OS-level permissions

- **No TCC prompts.** The gateway does not touch Full Disk Access, Accessibility, Camera/Mic, Screen Recording, Contacts, Location, or any other TCC-gated service.
- **No firewall prompts.** The gateway listens only on `127.0.0.1:18970` (loopback). Non-loopback bind addresses are rejected in config. macOS does not surface an Application Firewall prompt for loopback-only listeners.
- **No inbound connections from outside the host.**

### Code signing

- The shipped binary is **adhoc-signed** (`Signature=adhoc`, no `TeamIdentifier`, no entitlements).
- Consequences for distribution:
  - Downloading the tarball onto another Mac will trigger **Gatekeeper quarantine** (`com.apple.quarantine` xattr). Either strip it (`xattr -d com.apple.quarantine defenseclaw-gateway`) or sign + notarize before shipping.
  - For MDM/enterprise deployment, sign with a Developer ID cert and notarize — LaunchDaemon load may succeed, but user-facing invocation can be blocked otherwise.

### Root-level actions during install

Requires `sudo`. The installer:

- Creates directories under the managed install tree (all `root:wheel`):
  - `/opt/cisco/secureclient/defenseclaw/bin/` — `0755` (gateway binary)
  - `/opt/cisco/secureclient/defenseclaw/etc/` — `0755` (config.yaml)
  - `/opt/cisco/secureclient/defenseclaw/runtime/` — `0750` (audit DB, tokens, device key)
  - `/opt/cisco/secureclient/defenseclaw/hook-guardian-state/` — `0750` (authorization records)
  - `/Library/Logs/Cisco/SecureClient/DefenseClaw/` — `0750`
- Writes `/Library/LaunchDaemons/com.cisco.secureclient.defenseclaw.plist` (`root:wheel 0644`) and `launchctl bootstrap`s it.
- Writes `/opt/cisco/secureclient/defenseclaw/etc/config.yaml` as `root:wheel 0640`.
- Does NOT create a dedicated service user. The gateway daemon runs as root (uid 0) because the managed cloud auth provider requires root to read and re-perm its credential store on disk.
- Wires per-user hook configs in the target user's `~/.codex/config.toml`, `~/.claude/settings.json`, and/or `~/.cursor/hooks.json` depending on `--connector`.
- Refuses legacy pre-managed-layout install locations (`/Library/DefenseClaw/`, `/Library/Application Support/DefenseClaw/`, `/Library/Logs/DefenseClaw/`, `/Library/LaunchDaemons/com.defenseclaw.gateway.plist`, and `/Library/LaunchDaemons/com.defenseclaw.hook-guardian.plist`) and the corresponding `com.defenseclaw.gateway` / `com.defenseclaw.hook-guardian` launchd jobs before mutation. Existing deployments must use the release-owned staged upgrader; the fresh installer does not sweep or cut over legacy state.

### Runtime privileges

The daemon runs as **root** (uid 0). The plist deliberately omits `UserName` / `GroupName` so launchd defaults to root; the managed cloud auth provider requires root to read and re-perm its on-disk credential store. No dedicated service user is created. Every install-time chown of a DefenseClaw-owned path uses `root:wheel`.

Do not turn a pre-root deployment into an upgrade by running
`uninstall.sh --purge` and reinstalling: that discards the rollback and state
migration contract. Use the release-owned staged upgrader. Purge is reserved
for an intentional decommission and removes the legacy service uid/gid.
