# Windows enterprise Setup

`DefenseClawSetup-Enterprise-x64.exe` is the single-file Windows enterprise
delivery artifact for Cisco Secure Client and endpoint-management testing. It
is not the existing per-user `DefenseClawSetup-x64.exe`.

## Contents and behavior

The executable embeds exact, SHA-256-bound copies of:

- `defenseclaw-cmid-broker.exe`;
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

For a signed release, create the AVC-facing build kit on macOS or Linux from
the exact release commit. The build machine must be able to read
`cisco-aispg/ai-common`:

```bash
make packaging-windows-avc-buildkit VERSION=0.9.0-rc1
```

The primary output is:

```text
dist/windows-enterprise-buildkit-0.9.0-rc1/
```

DefenseClaw does not produce a signed enterprise Setup locally. Hand the kit to
AVC using [Windows AVC packaging handoff](WINDOWS-AVC-PACKAGING-HANDOFF.md).
The required order is:

1. AVC signs the six inner payload files.
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
make packaging-windows-enterprise-installer VERSION=0.9.0-rc1
```

That produces
`dist/windows-enterprise-buildkit-0.9.0-rc1-unsigned/out/DefenseClawSetup-Enterprise-x64.exe`.
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

For example, a signed production installation uses administrator-approved
config and target files and an explicit application-control attestation:

```powershell
.\DefenseClawSetup-Enterprise-x64.exe /install `
  CONFIG="C:\ProgramData\Cisco\Cisco Secure Client\DefenseClaw-Staging\config.yaml" `
  MANIFEST="C:\ProgramData\Cisco\Cisco Secure Client\DefenseClaw-Staging\targets.yaml" `
  ATTESTAGENTAPPLICATIONCONTROL=1 `
  JSON=1
```

The lifecycle fixes the four production services (`DefenseClawGateway`,
`DefenseClawCMIDBroker`, `DefenseClawHookGuardian`, and
`DefenseClawHookEnumerator`) and Secure Client roots; the caller cannot redirect
them. Unsigned artifacts additionally require the existing exact
`DefenseClaw-Cert` roots, paired run-scoped service names, and
`.codex-defenseclaw-cert-<run-id>` home. Use the official Windows enterprise
certification harness to create and clean that scope rather than approximating
it on a non-disposable endpoint.

Success exits `0`. Any incomplete or rolled-back lifecycle exits `1603`.
