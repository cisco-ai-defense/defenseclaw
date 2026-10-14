# Windows machine installer interface

This is the contract a deployment system programs against when it drives the
machine-level DefenseClaw deployment from `defenseclaw.exe`. The certification
runbook in `WINDOWS-ENTERPRISE-CERTIFICATION.md` covers what a correct
deployment looks like; this document covers how to call it.

The interface serves two enterprise profiles. The **Secure Client** profile
(`--profile secure_client`) is the Cisco Secure Client deployment. The
**standalone** profile (`--profile standalone`) is deployable by any MDM and
has no Secure Client dependency. Unless a statement names a profile, it applies
to both.

## Commands

Every machine-level action is a subcommand of `defenseclaw.exe enterprise
windows`, and every one of them requires an elevated caller except `status`.

| Command | Purpose |
| --- | --- |
| `install` | Create the protected tree, register every SCM service of the profile (five for Secure Client, four for standalone), and start them. |
| `upgrade` | Replace artifacts and re-register in one transaction. |
| `repair` | Reapply ACL, service, environment, and recovery invariants. |
| `reconcile` | Restart the guardian and wait for a fresh reconcile pass. |
| `verify` | Check files, DACLs, service policy, mode pin, and readiness. |
| `status` | Report SCM process state separately from application readiness. |
| `uninstall` | Remove services and binaries, keeping managed state unless `--purge`. |
| `ensure` | Standalone only. Install when nothing is installed, upgrade an older deployment or reapply drifted binaries or config, repair a pending transaction or a failed `verify`, and otherwise do nothing. It refuses a downgrade (`downgrade_refused`). The Secure Client profile refuses `ensure`. |

Add `--json` to any of them for machine-readable output. With `--json`, the
standalone profile prints the lifecycle result document described by
`packaging/mdm/contract/lifecycle-result.schema.json` (schema version 2); the
Secure Client profile prints its installer status document.

### Profile selection and standalone flags

`--profile secure_client|standalone` selects the profile. Without it, the
lifecycle uses `enterprise.profile` from the supplied `--config`, then the
profile of the installed deployment, then the profile of a previously
uninstalled deployment, then `secure_client`. A `--profile` that conflicts with
the config's `enterprise.profile` is refused, and a request for the other
profile while a deployment is installed is refused with `profile_conflict`.

These flags apply only to the standalone profile. The Secure Client profile
refuses them, and the standalone profile refuses `--broker-binary`:

| Flag | Meaning |
| --- | --- |
| `--trust-mode authenticode\|hash_pinned` | How the payload is trusted. The default is `authenticode`. |
| `--payload-manifest <path>` | Required with `hash_pinned`: the administrator-owned JSON of payload SHA-256 digests. Refused with `authenticode`. |
| `--allowed-signer <sha256>` | Repeatable. The SHA-256 thumbprint of an accepted Authenticode signer certificate. |
| `--product-version <version>` | The version recorded for the deployment. The default is the CLI's own version. |

`ensure` fills each unset `--gateway-binary`, `--acp-binary`, `--hook-binary`,
`--sensor-helper-binary` and `--cli-binary` from the installer script's own
directory, which is how the standalone Setup and an extracted MDM package lay
out the payload. Installing or upgrading through `ensure` needs the gateway,
ACP, hook and sensor-helper sources; the CLI source is optional. A first
install also needs `--config` (or `--mode`/`--connector` together with
`--manifest`); without `--manifest`, `ensure` builds the first guardian
manifest from `--config`.

## Exit codes

| Code | Profile | Meaning |
| --- | --- | --- |
| 0 | Both | The requested action completed. For standalone `ensure`, this includes a run with nothing to change (`noop: true`). |
| 1603 | Both | The requested action failed. The deployment is unchanged or rolled back, and the failure text on stderr names the cause. The Secure Client profile also reports invalid arguments this way. |
| 1618 | Standalone | Another lifecycle run holds the lifecycle lock (`lifecycle_busy`). Retry later. |
| 1639 | Standalone | Invalid arguments (`invalid_arguments`), for example a first `ensure` without `--config`. Retrying does not help. A config that does not load or validate fails with 1603. |
| 3010 | Standalone | Reserved for success that needs a reboot. No action returns it in this release. |

These are the standard MSI results, so a deployment system that already
understands them needs no translation layer. The exit codes and the MDM
wrapper's `mdm_*` error codes are listed in
`packaging/mdm/contract/exit-codes.md`. The lifecycle's own codes
(`lifecycle_busy`, `invalid_arguments`, `downgrade_refused`,
`profile_conflict`, and the PowerShell 7 refusals) are the ones named on this
page.

1602 never appears, because these commands are non-interactive and nothing can
be cancelled. The Secure Client profile never returns 3010.

## The executable carries its own scripts

The lifecycle is implemented in PowerShell, and an installed Windows
`defenseclaw.exe` carries both script files inside the binary. This lets the
installed CLI service an existing deployment without loose sidecar scripts.
It does not make that CLI a first-install package. In the Secure Client
profile, initial installation also requires the CMID broker, trusted provider
library, gateway, ACP, hook and sensor-helper sources, the protected
configuration, and the target manifest; the CLI source is optional. In the standalone profile it requires the gateway, ACP, hook and
sensor-helper sources, the protected configuration, and a target manifest,
which `ensure` builds itself from the configuration. There is no broker or
provider library.

Each profile has a self-contained delivery artifact that carries the
DefenseClaw release sources and invokes this lifecycle:

- `DefenseClawSetup-Enterprise-x64.exe` for Secure Client. The provider library
  remains in its independently trusted Cisco Secure Client installation.
- `DefenseClawSetup-Enterprise-Standalone-x64.exe` for the standalone profile
  (see `WINDOWS-ENTERPRISE-SETUP.md`).

Resolution order for the entry script:

1. The `--installer` flag.
2. The `DEFENSECLAW_WINDOWS_ENTERPRISE_INSTALLER` environment variable.
3. `install-enterprise.ps1` in the `libexec` directory that sits beside the
   executable's `bin` directory, which is what an installed tree uses.
4. `install-enterprise.ps1` in the executable's own directory, which is how
   an extracted payload or the Setup's staging directory lays it out.
5. The embedded copy, only when steps 3 and 4 find no file.

An installer named by the flag or the variable is used exactly as given. If it
is missing or fails the trust check, the command fails rather than quietly
falling back to the embedded copy. A script found in step 3 or 4 that fails
the trust check also fails the command.

## Requirements

Secure Client profile: Windows PowerShell 5.1 at its fixed System32 location
runs the scripts. The executable does not use PowerShell 7 for this profile and
does not read the caller's environment, profile, or working directory.

Standalone profile: the lifecycle runs only in PowerShell 7. The CLI selects
the newest stable (not preview or release-candidate) x64 PowerShell 7 that the
MSI registered under
`HKLM\SOFTWARE\Microsoft\PowerShellCore\InstalledVersions`, requires it under
the trusted Program Files directory, and requires a valid Microsoft
Authenticode signature on `pwsh.exe`. It never consults `PATH`. The installer
script then refuses to run unless it is a 64-bit process in FullLanguage mode
on native Windows x64. Each refusal carries a stable code:
`powershell7_required`, `powershell7_untrusted`, `powershell_32bit_host`,
`powershell_constrained_language` or `unsupported_architecture`.

## Managed-enterprise build

This section covers the Secure Client Setup. The standalone Setup is not part
of the AVC handoff; its build and signing channels are in
[Windows enterprise Setup](WINDOWS-ENTERPRISE-SETUP.md#standalone-setup).

The retired per-user `DefenseClawSetup-x64.exe` (per-user installs now use
`install.ps1`) must never be relabeled as the enterprise installer. The
separate `DefenseClawSetup-Enterprise-x64.exe` embeds eight signed inner files:
the credential broker, gateway, native hook, ACP mediator, sensor helper,
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
make packaging-windows-avc-buildkit VERSION=X.Y.Z
```

This invokes `packaging/scripts/build-managed-windows-bundle.sh`, applies the
private CMID overlay in a restorable snapshot, cross-builds and stamps
`defenseclaw-gateway.exe`, `defenseclaw-hook.exe`, `defenseclaw-acp.exe`,
`defenseclaw-sensor-helper.exe` and `defenseclaw-cmid-broker.exe`, copies the
gateway image as `defenseclaw.exe`, and writes:

```text
dist/windows-enterprise-buildkit-X.Y.Z/
```

The kit contains the eight unsigned files under `payload/`, the trimmed vendored
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
`managed-enterprise` payload with the eight-file manifest.

### Local unsigned developer build

For disposable certification only:

```bash
make packaging-windows-enterprise-installer VERSION=X.Y.Z
```

This emits the build kit and runs the assembler locally with
`--allow-unsigned`, producing a runnable artifact below
`dist/windows-enterprise-buildkit-X.Y.Z-unsigned/out/`. It is stamped
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
  refuses to load a file that is itself world- or user-writable. Since
  AIFW-34262 a world- or user-writable **ancestor** of that file logs a
  `managed_trust_ancestor_advisory` warning and the load continues: the
  Cisco Secure Client tree above the managed roots is AVC's to ACL, and a
  transient grant there must not fail a load or an install. That downgrade
  is scoped to the Cisco-owned roots (`%ProgramData%\Cisco`,
  `%ProgramFiles%\Cisco`, `%ProgramFiles(x86)%\Cisco`, and always
  `C:\ProgramData\Cisco` — `managed.PlatformInstallerOwnedRoots`); an
  ancestor outside them keeps its verdicts fatal, since nobody else has a
  claim on those permissions. Ancestors are always evaluated with the
  narrower replacement mask so stock `BUILTIN\Users` create-child grants on
  `C:\` and `C:\ProgramData` still pass. Pin
  `DEFENSECLAW_MANAGED_TRUST_STRICT_ANCESTORS=1` to make the in-root
  ancestor verdicts fatal again.

  If AVC does not merely add an ACE but replaces the canonical DACL that
  DefenseClaw stamps on its own state root, the installer repairs it
  rather than failing: the stamp is retried, and the post-hardening
  assertion re-stamps the canonical descriptor once and re-reads the path
  before judging it. Both steps log the `managed_acl_self_heal` marker —
  worth alerting on, since a host that emits it repeatedly has AVC and
  DefenseClaw contending for the same DACL. What survives that repair is
  still fatal if it means DefenseClaw itself lacks the rights it needs
  (missing SYSTEM/Administrators/gateway rights); foreign *additional*
  access remains advisory.

- **Contents:** JSON with one meaningful key,
  `cisco_ai_defense_endpoint`, whose value is an HTTPS bare origin
  (no path, no query, no fragment, no userinfo). Both the macOS
  installer's `resolve_aid_endpoint()`
  (`packaging/macos/lib/installer_lib.sh`) and the Go loader enforce
  the same URL shape; a value that fails either check is rejected
  as an overlay, and the previously-active endpoint is retained
  with a health error surfaced on `defenseclaw status`.

  ```json
  {
    "cisco_ai_defense_endpoint": "https://eu.api.inspect.aidefense.security.cisco.com"
  }
  ```

- **Ownership boundary:** DefenseClaw's Windows installer does **not**
  write this file — that is AVC's job, mirroring
  macOS where AVC (not `install-enterprise.sh`) authors env_config.json.
  On a freshly installed Windows managed box before AVC has landed the
  file, the gateway treats the missing overlay as "no override" and
  falls through to `cisco_ai_defense.endpoint` from `config.yaml`.

- **Runtime trust check:** at every `ConfigManager` reload the gateway
  re-validates the file (owner, no reparse point, and the ancestor chain
  as an advisory) via `managed.ValidateTrustedFilePath` before parsing. A file
  that fails the check is rejected as if it were malformed — the current
  in-memory endpoint is kept and an error is logged. The trust check
  always runs, including under the gateway's non-elevated virtual
  service account. `DEFENSECLAW_ENV_CONFIG_SKIP_TRUST=1` is honored only
  inside Go test binaries, for parser fixtures.
