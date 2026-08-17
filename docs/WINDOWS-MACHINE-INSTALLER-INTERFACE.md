# Windows machine installer interface

This is the contract a deployment system programs against when it drives the
machine-level DefenseClaw deployment from `defenseclaw.exe`. The certification
runbook in `WINDOWS-ENTERPRISE-CERTIFICATION.md` covers what a correct
deployment looks like; this document covers how to call it.

## Commands

Every machine-level action is a subcommand of `defenseclaw.exe enterprise
windows`, and every one of them requires an elevated caller except `status`.

| Command | Purpose |
| --- | --- |
| `install` | Create the protected tree, register both services, and start them. |
| `upgrade` | Replace artifacts and re-register in one transaction. |
| `repair` | Reapply ACL, service, environment, and recovery invariants. |
| `reconcile` | Restart the guardian and wait for a fresh reconcile pass. |
| `verify` | Check files, DACLs, service policy, mode pin, and readiness. |
| `status` | Report SCM process state separately from application readiness. |
| `uninstall` | Remove services and binaries, keeping managed state unless `--purge`. |

Add `--json` to any of them for machine-readable output.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | The requested action completed. |
| 1603 | The requested action failed. The deployment is unchanged or rolled back, and the failure text on stderr names the cause. |

1603 is the standard fatal-install result, so a deployment system that already
understands MSI results needs no translation layer.

Two codes are deliberately absent. 3010 never appears, because it means
installed and awaiting a reboot, and no failure here has earned that reading;
if a future action does require a reboot it will be added as an explicit
success code. 1602 never appears, because these commands are non-interactive
and nothing can be cancelled.

## The executable carries its own scripts

The lifecycle is implemented in PowerShell, and an installed Windows
`defenseclaw.exe` carries both script files inside the binary. This lets the
installed CLI service an existing deployment without loose sidecar scripts.
It does not make that CLI a first-install package: initial installation also
requires the gateway, hook, CLI source, protected configuration, and target
manifest. `DefenseClawSetup-Enterprise-x64.exe` is the self-contained delivery
artifact that carries those release sources and invokes this lifecycle.

Resolution order for the entry script:

1. The `--installer` flag.
2. The `DEFENSECLAW_WINDOWS_ENTERPRISE_INSTALLER` environment variable.
3. `install-enterprise.ps1` in the `libexec` directory beside the executable,
   which is what an installed tree uses.
4. The embedded copy.

An installer named by the flag or the variable is used exactly as given. If it
is missing or fails the trust check, the command fails rather than quietly
falling back to the embedded copy.

## Requirements

Windows PowerShell 5.1 at its fixed System32 location runs the scripts. The
executable does not use PowerShell 7 and does not read the caller's
environment, profile, or working directory.

## Managed-enterprise build

The public `DefenseClawSetup-x64.exe` is the non-elevating per-user product. It
must never be relabeled as the enterprise installer. The separate
`DefenseClawSetup-Enterprise-x64.exe` requests administrator elevation, embeds
the three machine-lifecycle executables plus the enterprise PowerShell pair,
and delegates every mutation to the transaction documented above. Its gateway
links the private CMID provider so it can authenticate to AI Defense; that
requires a `-tags cmid` build with the private cloudreg overlay and a pinned
`github.com/cisco-aispg/ai-common/cmid` pseudo-version.

The build is split so the Windows tester never needs SSH access to the
private `cisco-aispg/ai-common` repo:

### macOS (or Linux) — prep the managed gateway zip

`packaging/scripts/build-managed-windows-bundle.sh` clones `cisco-aispg/ai-common` at
`--ref` (default `develop`), computes the Go pseudo-version for that ref,
snapshots the OSS cloudreg stub + `go.mod` + `go.sum`, applies the private
overlay, runs `go get` to pin the ai-common/cmid module, and cross-builds
`defenseclaw.exe` + `defenseclaw-hook.exe` with `GOOS=windows GOARCH=amd64
-tags cmid`. The two binaries get VERSIONINFO + icon stamped via the
cross-platform `internal/tools/windowsresources` tool (Go, works on any host
that can produce Windows PEs). The result is packaged into the goreleaser-
shaped `defenseclaw_<version>_windows_amd64.zip` alongside a
`gateway-source-commit.txt` recording the defenseclaw HEAD used. The
snapshot is restored on exit — whether the build succeeded or failed — so
the OSS working tree stays clean.

```
packaging/scripts/build-managed-windows-bundle.sh \
    --ref develop \
    --version 0.9.0-rc1 \
    --dist-dir ./dist
```

Or via Make:

```
make packaging-managed-windows-bundle VERSION=0.9.0-rc1
```

Requires: `git`, `go`, and either SSH access to
`git@github.com-aispg:cisco-aispg/ai-common.git` or an HTTPS-token path.

### Windows — consume the pre-staged zip

Copy `defenseclaw_<version>_windows_amd64.zip` and
`gateway-source-commit.txt` into one directory, sync the DefenseClaw working
tree to the commit listed in the sidecar, and run the separate enterprise
builder:

```powershell
$expected = (Get-Content .\dist\gateway-source-commit.txt -Raw).Trim()
git checkout $expected

.\scripts\build-windows-enterprise-installer.ps1 `
    -DistRoot .\dist `
    -OutRoot .\dist\windows-enterprise-installer `
    -StateRoot .\dist\windows-enterprise-installer-state `
    -Version 0.9.0-rc1
```

The enterprise builder always cross-checks local `git HEAD` against the
sidecar and has no bypass. The commit is repeated in the embedded manifest and
external provenance record.

Or via Make on the Windows box:

```
make packaging-windows-managed-bundle VERSION=0.9.0-rc1
```

The Windows box does not need access to `cisco-aispg/ai-common`. Everything
CMID-specific already happened on the macOS side; the Windows flow only
consumes the gateway zip and produces the setup.exe.

The result is `DefenseClawSetup-Enterprise-x64.exe` plus its `.sha256` and
`.provenance.json` files. `cmd/defenseclaw-enterprise-setup` accepts only the
`managed-enterprise` payload flavor. For disposable certification, add
`-SkipSigning`; that artifact then requires the existing exact run-scoped
`--allow-unsigned` lifecycle contract and cannot target production roots.

## AVC env_config.json contract

Cisco Secure Client's AVC packaging pipeline can drop a small overlay
file at a canonical path *after* DefenseClaw is installed — for example,
when a region change moves a tenant from the US inspect endpoint to EU.
The gateway sidecar's `ConfigManager` watches that path via fsnotify
and re-reads `cisco_ai_defense_endpoint` on every change, so no
DefenseClaw restart is needed for a region flip.

- **Path:** `C:\ProgramData\Cisco\Cisco Secure Client\DefenseClaw\env_config.json`
  (see [`internal/config/env_config_windows.go`](../internal/config/env_config_windows.go) — `ResolveDefaultEnvConfigPath`).
  Mirrors the macOS `/opt/cisco/secureclient/defenseclaw/env_config.json`
  convention: the file and DefenseClaw's managed state share the canonical
  Secure Client per-machine data root.

- **Owner / ACL:** the parent directory and the file itself must be
  administrator-owned with **no** non-admin write ACEs. The gateway
  service SID needs Read on the file (grantable via inheritance from
  the parent directory). This matches every other DefenseClaw managed
  artifact — [`internal/managed/trust_windows.go`](../internal/managed/trust_windows.go)
  refuses to load a file whose ancestor chain is world- or user-
  writable.

- **Contents:** JSON with one meaningful key,
  `cisco_ai_defense_endpoint`, whose value is an HTTPS bare origin
  (no path, no query, no fragment, no userinfo). Both the shell
  installer's `_valid_aid_endpoint_url()` and the Go loader enforce
  the same URL shape; a value that fails either check is rejected
  as an overlay, and the previously-active endpoint is retained
  with a health error surfaced on `defenseclaw status`.

  ```json
  {
    "cisco_ai_defense_endpoint": "https://eu.api.inspect.aidefense.security.cisco.com"
  }
  ```

- **Ownership boundary:** DefenseClaw's Windows installer does **not**
  create this directory or write the file — that is AVC's job, mirroring
  macOS where AVC (not `install-enterprise.sh`) authors env_config.json.
  On a freshly installed Windows managed box before AVC has landed the
  file, the gateway treats the missing overlay as "no override" and
  falls through to `cisco_ai_defense.endpoint` from `config.yaml`.

- **Runtime trust check:** at every `ConfigManager` reload the gateway
  re-validates the file (owner, no reparse point, ancestor chain admin-
  owned) via `managed.ValidateTrustedFilePath` before parsing. A file
  that fails the check is rejected as if it were malformed — the current
  in-memory endpoint is kept and an error is logged. When the DefenseClaw
  gateway is not running elevated (dev boxes, unit tests, opensource
  local runs), the trust check is skipped and only the parse-shape
  validation runs; `DEFENSECLAW_ENV_CONFIG_SKIP_TRUST=1` forces the
  skip regardless of elevation for tests that need it.
