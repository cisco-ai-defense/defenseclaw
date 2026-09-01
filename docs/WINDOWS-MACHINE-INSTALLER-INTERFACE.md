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
| `install` | Create the protected tree, register all four SCM services, and start them. |
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
requires the CMID broker, trusted provider library, gateway, hook, CLI source,
protected configuration, and target manifest.
`DefenseClawSetup-Enterprise-x64.exe` is the self-contained delivery artifact
that carries the DefenseClaw release sources and invokes this lifecycle; the
provider library remains in its independently trusted Cisco Secure Client
installation.

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
`DefenseClawSetup-Enterprise-x64.exe` requests administrator elevation and
embeds six signed inner files: the credential broker, gateway, native hook,
enterprise CLI, installer script, and PowerShell module. It delegates every
mutation to the transaction documented above. The gateway and isolated broker
use the private CMID overlay and a pinned
`github.com/cisco-aispg/ai-common/cmid` pseudo-version to authenticate to AI
Defense.

The former native-Windows builder was removed. The current release flow is an
AVC signing handoff: DefenseClaw creates an unsigned, offline-buildable kit on
macOS or Linux; AVC signs the inner payload, assembles the outer Setup in its
pipeline, then signs and finalizes the outer artifact.

### DefenseClaw — prepare the AVC build kit

From the exact release commit, on a host with access to
`cisco-aispg/ai-common`, run:

```bash
make packaging-windows-avc-buildkit VERSION=0.9.0-rc1
```

This invokes `packaging/scripts/build-managed-windows-bundle.sh`, applies the
private CMID overlay in a restorable snapshot, cross-builds and stamps
`defenseclaw.exe`, `defenseclaw-gateway.exe`, `defenseclaw-hook.exe`, and
`defenseclaw-cmid-broker.exe`, and writes:

```text
dist/windows-enterprise-buildkit-0.9.0-rc1/
```

The kit contains the six unsigned files under `payload/`, the trimmed vendored
Go source needed to build the outer Setup offline, one root-level assembler,
both shell families' reproducibility/signature/finalize helpers,
`payload-metadata.json`, and the generated `README-AVC.md`. The bundler also
emits the legacy gateway ZIP and source-commit sidecar for compatibility; those
are not the input to the signed Setup flow.

Requires `git`, `go`, and `zip`, plus either SSH access to
`git@github.com-aispg:cisco-aispg/ai-common.git` or an approved HTTPS-token
path. The script restores the OSS cloudreg stub and `go.mod`/`go.sum` on every
exit and refuses to overwrite a pre-existing repository `vendor` path.

### AVC — sign inner, assemble, sign outer, finalize

Follow [Windows AVC packaging handoff](WINDOWS-AVC-PACKAGING-HANDOFF.md). The
ordering is part of the artifact contract:

1. Sign every expected file under `payload/` and verify the Cisco signer.
2. Export the commit-derived `SOURCE_DATE_EPOCH`, then run the shipped
   `assemble.sh` or `assemble.ps1`. The assembler validates the exact payload
   inventory and signatures, emits the embedded manifest, and builds
   `out/DefenseClawSetup-Enterprise-x64.exe` from vendored source.
3. Sign the outer Setup EXE.
4. Run the shipped `finalize.sh`/`finalize.ps1`, or equivalent AVC logic, to
   write the signed EXE's `.sha256` and populate `setup_sha256` and
   `setup_size` in provenance.

AVC returns the signed `DefenseClawSetup-Enterprise-x64.exe`, its `.sha256`,
and `.provenance.json`. The runtime accepts only an exact
`managed-enterprise` payload with the six-file manifest.

### Local unsigned developer build

For disposable certification only:

```bash
make packaging-windows-enterprise-installer VERSION=0.9.0-rc1
```

This emits the build kit and runs the assembler locally with
`--allow-unsigned`, producing a runnable artifact below
`dist/windows-enterprise-buildkit-0.9.0-rc1-unsigned/out/`. It is stamped
`managed-enterprise-unsigned`, requires the exact run-scoped
`--allow-unsigned` lifecycle contract, and cannot target production names or
roots. It must not enter a release channel.

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
