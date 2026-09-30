# Windows enterprise Setup

`DefenseClawSetup-Enterprise-x64.exe` is the single-file Windows enterprise
delivery artifact for Cisco Secure Client and endpoint-management testing. It
is unrelated to the retired per-user `DefenseClawSetup-x64.exe` (per-user
Windows installs now use `install.ps1`). This page describes the Secure Client
flavor; for the standalone profile deployed by Intune or another MDM, see the
docs-site [Windows standalone deployment](https://cisco-ai-defense.github.io/defenseclaw/docs/enterprise/windows/)
page. That profile has its own Setup,
`DefenseClawSetup-Enterprise-Standalone-x64.exe`, summarized under
[Standalone Setup](#standalone-setup) at the end of this page.

## Contents and behavior

The executable embeds exact, SHA-256-bound copies of:

- `defenseclaw-cmid-broker.exe`;
- `defenseclaw-gateway.exe`;
- `defenseclaw-hook.exe`;
- `defenseclaw-acp.exe`;
- `defenseclaw-sensor-helper.exe`;
- `defenseclaw.exe`, the installed enterprise lifecycle CLI;
- `install-enterprise.ps1`;
- `DefenseClawEnterprise.psm1`.

That is eight files (`requiredPayloadFiles` in
`cmd/defenseclaw-enterprise-setup/main.go`). The credential broker isolates
the gateway's access to Secure Client's cloud machine identity (CMID)
provider, which the gateway uses to authenticate to AI Defense. The provider
library itself stays in the trusted Secure Client installation.

It must run with an elevated administrator token and exits 1603 without one. At runtime it resolves
ProgramData from protected 64-bit HKLM registration, creates a random staging
directory writable only by SYSTEM and Administrators, verifies every embedded
digest after writing, and invokes `defenseclaw enterprise windows` in a bounded
job with a strict environment allowlist. The existing enterprise transaction
remains responsible for the services, Secure Client paths, ACLs, rollback,
readiness, repair, and cleanup.

Production roots are fixed to:

```text
%ProgramFiles%\Cisco\Cisco Secure Client\DefenseClaw
%ProgramData%\Cisco\Cisco Secure Client\DefenseClaw
```

## Build

AVC is the Cisco Secure Client signing and packaging pipeline. It signs the
release files and assembles the signed Setup; DefenseClaw hands it a kit.

For a signed release, create the AVC-facing build kit on macOS or Linux from
the exact release commit. The build machine must be able to read
`cisco-aispg/ai-common`:

```bash
make packaging-windows-avc-buildkit VERSION=X.Y.Z
```

The primary output is:

```text
dist/windows-enterprise-buildkit-X.Y.Z/
```

DefenseClaw does not produce a signed enterprise Setup locally. Hand the kit to
AVC using [Windows AVC packaging handoff](WINDOWS-AVC-PACKAGING-HANDOFF.md).
The required order is:

1. AVC signs the eight inner payload files.
2. AVC runs the kit's `assemble.sh` or `assemble.ps1` to build the outer Setup.
3. AVC signs `out/DefenseClawSetup-Enterprise-x64.exe`.
4. AVC runs `finalize.sh` or `finalize.ps1` (or performs the equivalent) to
   hash the signed outer EXE and update provenance.

Final release outputs returned by AVC:

```text
out\DefenseClawSetup-Enterprise-x64.exe
out\DefenseClawSetup-Enterprise-x64.exe.sha256
out\DefenseClawSetup-Enterprise-x64.exe.provenance.json
```

For a local disposable-test artifact only, use the explicitly unsigned target:

```bash
make packaging-windows-enterprise-installer VERSION=X.Y.Z
```

That produces
`dist/windows-enterprise-buildkit-X.Y.Z-unsigned/out/DefenseClawSetup-Enterprise-x64.exe`.
It is stamped as unsigned and the runtime accepts it only with the exact
run-scoped `--allow-unsigned` certification contract. Never publish or deploy
that output to production roots.

The **Windows Enterprise Setup** GitHub Actions workflow is intentionally a
public, fork-safe contract check. It runs the installer tests and vetting,
cross-compiles the Windows bootstrap shell, parses the PowerShell assembly
boundary, and validates the managed-bundle shell script. It does not fetch
`cisco-aispg/ai-common`, receive private-repository credentials, assemble a
CMID-enabled payload, or publish a certification artifact.

The real CMID-enabled gateway and signed enterprise Setup must be produced
through the protected release/AVC process above. A personal access token must
not be placed in pull-request CI as a substitute for that release boundary.

## Invocation

The Setup supports these lifecycle actions:

```text
/install /upgrade /repair /reconcile /status /verify /uninstall
```

The standalone Setup also accepts `/ensure` (see
[Standalone Setup](#standalone-setup)). This Setup refuses `/ensure` and
`ALLOWEDSIGNERS=` and exits `1603`.

For example, a signed production installation uses administrator-approved
config and target files and an explicit application-control attestation:

```powershell
.\DefenseClawSetup-Enterprise-x64.exe /install `
  CONFIG="C:\ProgramData\Cisco\Cisco Secure Client\DefenseClaw-Staging\config.yaml" `
  MANIFEST="C:\ProgramData\Cisco\Cisco Secure Client\DefenseClaw-Staging\targets.yaml" `
  ATTESTAGENTAPPLICATIONCONTROL=1 `
  JSON=1
```

The lifecycle fixes the five production services (`DefenseClawGateway`,
`DefenseClawCMIDBroker`, `DefenseClawSensorHelper`, `DefenseClawHookGuardian`,
and `DefenseClawHookEnumerator`) and Secure Client roots; the caller cannot redirect
them. Unsigned artifacts additionally require the existing exact
`DefenseClaw-Cert` roots, paired run-scoped service names, and
`.codex-defenseclaw-cert-<run-id>` home. Use the official Windows enterprise
certification harness to create and clean that scope rather than approximating
it on a non-disposable endpoint.

Success exits `0`. Any incomplete or rolled-back lifecycle exits `1603`.

## Standalone Setup

`DefenseClawSetup-Enterprise-Standalone-x64.exe` is the Setup for the
standalone profile, which any MDM can deploy without Cisco Secure Client. Each
release publishes it with
`DefenseClawSetup-Enterprise-Standalone-x64.payload-manifest.json`, the
SHA-256 digest of every embedded file. To deploy it, see the docs-site
[Windows](https://cisco-ai-defense.github.io/defenseclaw/docs/enterprise/windows/)
and [Install with an MDM](https://cisco-ai-defense.github.io/defenseclaw/docs/enterprise/mdm/)
pages.

It differs from the Secure Client Setup in these ways:

| | Secure Client Setup | Standalone Setup |
| --- | --- | --- |
| Embedded files | Eight (`requiredPayloadFiles`) | Seven: the same set without `defenseclaw-cmid-broker.exe` (`standalonePayloadFiles`) |
| Services | Five, including `DefenseClawCMIDBroker` | Four: `DefenseClawGateway`, `DefenseClawSensorHelper`, `DefenseClawHookGuardian`, `DefenseClawHookEnumerator` |
| Roots | `%ProgramFiles%\Cisco\Cisco Secure Client\DefenseClaw` and `%ProgramData%\Cisco\Cisco Secure Client\DefenseClaw` | `%ProgramFiles%\Cisco\DefenseClaw` and `%ProgramData%\Cisco\DefenseClaw` |
| Lifecycle engine | Windows PowerShell 5.1 | PowerShell 7 x64 (see `WINDOWS-MACHINE-INSTALLER-INTERFACE.md`) |
| Actions | The seven above | The seven above plus `/ensure` |
| Exit codes | `0`, `1603` | `0`, `1603`, `1618`, `1639`; `3010` is reserved and never returned |

### Invocation

Setup takes one action and `NAME=value` properties. Property names are not
case-sensitive and dashes in them are ignored. `/quiet` and `/norestart` are
accepted and do nothing, because Setup never prompts and never asks for a
reboot.

| Property | Meaning |
| --- | --- |
| `CONFIG=` | The administrator-approved `config.yaml`. Required for the first install. |
| `MANIFEST=` | A guardian `targets.yaml`. Required with `/install`. Optional with `/ensure`, which builds the first manifest from the config. |
| `ALLOWEDSIGNERS=` | Comma-separated SHA-256 thumbprints of accepted Authenticode signer certificates. Meaningful only for a signed Setup. |
| `JSON=1` | Print the lifecycle result document. |
| `NOSTART=1` | Install, upgrade, repair or ensure without starting the services. |
| `PURGE=1` | With `/uninstall`, also remove managed state. |
| `TIMEOUTSECONDS=` | The lifecycle time limit, from 60 to 7200 seconds. The default is 1800. |

`CONFIG=` and `MANIFEST=` must be absolute local drive paths to regular,
non-link files whose folder chain only administrators and SYSTEM can write.
Setup refuses relative, padded, UNC and environment-expanded (`%...%`) paths,
and files a standard user could change. The MDM wrapper
`packaging/mdm/windows/Invoke-DefenseClawEnterprise.ps1` creates such a
folder for you.

```powershell
# $Stage is a folder that only Administrators and SYSTEM can write.
.\DefenseClawSetup-Enterprise-Standalone-x64.exe /ensure `
  CONFIG="$Stage\config.yaml" `
  JSON=1
```

`/ensure` installs, upgrades or repairs as needed and does nothing when the
device is compliant. The first `/ensure` without `CONFIG=` exits `1639`.
Setup's own checks run before the lifecycle: a malformed command line (an
unknown property, a missing, relative, padded or environment-expanded
`CONFIG=` or `MANIFEST=` path, `/install` without `CONFIG=` and `MANIFEST=`,
or `TIMEOUTSECONDS` out of range) exits `1639`; an unelevated token and a
`CONFIG=` or `MANIFEST=` file that is a link or can be changed by a
non-administrator exit `1603`. The lifecycle it runs adds `1603`, `1618` and
`1639`. The Secure Client Setup returns only `0` and `1603`.

### Payload trust

The Setup trusts its payload through one of two channels, fixed when it is
built:

- **Hash-pinned** (flavor `standalone-unsigned`). The inner files are not
  signed. Setup writes `payload-trust.json` from its own embedded manifest and
  runs the lifecycle with `--trust-mode hash_pinned`. Administrators never
  supply that file. The trust root is the Setup file itself, so pin its
  SHA-256 in your MDM.
- **Authenticode** (flavor `standalone`). Every inner file is signed, and the
  lifecycle requires a valid signature on each one. Pass `ALLOWEDSIGNERS=` to
  accept only your signer.

### Build

`packaging/windows/standalone/build-setup.sh` builds the standalone Setup on
macOS or Linux. It is separate from the Secure Client AVC kit and never reads
or changes it. It writes the Setup, its `.sha256` and `payload-manifest.json`
to `dist/windows-standalone-<version>/` unless `--out-dir` names another
directory.

| Command | Result |
| --- | --- |
| `build-setup.sh --version <version>` | Builds the seven inner files and embeds them unsigned (hash-pinned). |
| `build-setup.sh --version <version> --sign-command <cmd>` | Builds the inner files, runs `<cmd> <file>` to sign each one in place, embeds them, and signs the outer Setup with the same command. |
| `build-setup.sh --version <version> --payload-dir <dir>` | Embeds seven files that were already signed. The directory must hold exactly those seven files. |

With `--payload-dir`, sign the outer Setup afterwards with the same
certificate, then compute its SHA-256 again: the script hashes the Setup
before you sign it. `packaging/mdm/signing/authenticode-sign.sh` is a signing
command for `--sign-command`; the release workflow uses it when a
code-signing certificate is configured and otherwise ships the hash-pinned
flavor.

There is no AVC handoff kit for the standalone Setup. The AVC flow in
[Windows AVC packaging handoff](WINDOWS-AVC-PACKAGING-HANDOFF.md) builds only
`DefenseClawSetup-Enterprise-x64.exe`.
