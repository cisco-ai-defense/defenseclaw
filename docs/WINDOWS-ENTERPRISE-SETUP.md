# Windows enterprise Setup

`DefenseClawSetup-Enterprise-x64.exe` is the single-file Windows enterprise
delivery artifact for Cisco Secure Client and endpoint-management testing. It
is not the existing per-user `DefenseClawSetup-x64.exe`.

## Contents and behavior

The executable embeds exact, SHA-256-bound copies of:

- `defenseclaw-gateway.exe`;
- `defenseclaw-hook.exe`;
- `defenseclaw.exe`, the installed enterprise lifecycle CLI;
- `install-enterprise.ps1`;
- `DefenseClawEnterprise.psm1`.

Its Windows manifest requests administrator elevation. At runtime it resolves
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

First prepare the CMID-enabled Windows gateway ZIP on a machine that can read
`cisco-aispg/ai-common`:

```bash
make packaging-managed-windows-bundle VERSION=0.8.6
```

Copy the resulting gateway ZIP and `gateway-source-commit.txt` into `dist` on
a native Windows x64 checkout at that exact commit. In PowerShell 7, build the
enterprise Setup:

```powershell
.\scripts\build-windows-enterprise-installer.ps1 `
  -DistRoot .\dist `
  -OutRoot .\dist\windows-enterprise-installer `
  -StateRoot .\dist\windows-enterprise-installer-state `
  -Version 0.8.6 `
  -SkipSigning
```

`-SkipSigning` is only for disposable certification. A production build omits
it and supplies the Cisco signing certificate through
`WINDOWS_SIGNING_CERT_BASE64`, `WINDOWS_SIGNING_CERT_PASSWORD`, and an HTTPS
`WINDOWS_SIGNING_TIMESTAMP_URL`.

Outputs:

```text
dist\windows-enterprise-installer\DefenseClawSetup-Enterprise-x64.exe
dist\windows-enterprise-installer\DefenseClawSetup-Enterprise-x64.exe.sha256
dist\windows-enterprise-installer\DefenseClawSetup-Enterprise-x64.exe.provenance.json
```

The **Windows Enterprise Setup** GitHub Actions workflow is intentionally a
public, fork-safe contract check. It runs the installer tests and vetting,
cross-compiles the Windows bootstrap shell, parses the PowerShell assembly
boundary, and validates the managed-bundle shell script. It does not fetch
`cisco-aispg/ai-common`, receive private-repository credentials, assemble a
CMID-enabled payload, or publish a certification artifact.

The real CMID-enabled gateway and enterprise Setup must be produced through
the protected release/AVC process using the build steps above. A personal
access token must not be placed in pull-request CI as a substitute for that
release boundary.

## Invocation

The Setup supports these lifecycle actions:

```text
/install /upgrade /repair /reconcile /status /verify /uninstall
```

For example, a signed production installation uses administrator-approved
config and target files and an explicit application-control attestation:

```powershell
.\DefenseClawSetup-Enterprise-x64.exe /install `
  CONFIG="C:\ProgramData\Cisco\Cisco Secure Client\DefenseClaw-Staging\config.yaml" `
  MANIFEST="C:\ProgramData\Cisco\Cisco Secure Client\DefenseClaw-Staging\targets.yaml" `
  ATTESTAGENTAPPLICATIONCONTROL=1 `
  JSON=1
```

The lifecycle fixes the production service names and Secure Client roots; the
caller cannot redirect them. Unsigned artifacts additionally require the
existing exact `DefenseClaw-Cert` roots, paired run-scoped service names, and
`.codex-defenseclaw-cert-<run-id>` home. Use the official Windows enterprise
certification harness to create and clean that scope rather than approximating
it on a non-disposable endpoint.

Success exits `0`. Any incomplete or rolled-back lifecycle exits `1603`.
