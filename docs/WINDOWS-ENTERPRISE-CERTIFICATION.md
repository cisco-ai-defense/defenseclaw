# Windows enterprise service certification

This runbook certifies Windows `managed_enterprise` parity with the Linux
systemd and macOS LaunchDaemon deployments. It is intentionally separate from
the ordinary native Windows per-user installer certification: normal mode must
keep its existing startup/watchdog and hook self-heal behavior, while the
enterprise service boundary is administrator opt-in.

Run the host-mutating procedure only on a disposable Windows endpoint or
ephemeral CI runner with an independent administrator recovery channel. Do not
run it on a production workstation.

## Acceptance boundary

The deployed endpoint passes only when all of these statements have direct
evidence:

| Surface | Required result |
| --- | --- |
| Enterprise opt-in | A build containing enterprise support makes no machine-level change until an authorized invocation activates it. Interactive administrators run `DefenseClawSetup-Enterprise-x64.exe /install` or `defenseclaw enterprise windows install`; both authenticate through the signed CLI. Direct execution of `packaging/windows/install-enterprise.ps1` is supported only from a protected LocalSystem endpoint-management context (the script has no `deployment_mode` parameter; `deployment_mode: managed_enterprise` is set inside the protected `-Config` file the invocation supplies). |
| Normal-mode repair/no-op | Empty/default and every non-managed deployment mode retain the existing gateway application-protection repair and hook self-heal owner. Without the protected installer-owned service-name marker, Windows process startup does not even call the SCM-host detector or service executor. Before installation, the candidate reports enterprise enforcement disabled without creating a service, data root, or machine policy. A separate disposable normal-mode setup then replaces its user hook registration and must auto-heal the exact bytes while every enterprise-protected machine artifact remains unchanged. |
| Managed-root provenance | Default install, state, staging, and work roots come from Windows known folders. Poisoned process `ProgramFiles` or `ProgramData` variables cannot redirect them and no poisoned path is created. |
| Trusted release input | The installer, module, gateway, hook, CLI, config, manifest, and required separately version-stamped upgrade binaries are copied byte-stably into an administrator/System-only staging tree before full lifecycle execution. `-AllowUnsigned` is accepted before module import only for `Install`/`Upgrade`/`Repair` with the exact same-id certification service names, roots, and required certification CODEX_HOME scope marker; production defaults and near misses fail closed. It does not weaken source-path trust. |
| Drive-namespace integrity | Every enterprise source, managed root, certification home, and target profile uses an exact mount-manager drive root on fixed NTFS. Effective-drive, global-drive, and volume-GUID DOS-device targets are single, well-formed, and identical. A medium user raw `DefineDosDevice` alias that still reports `Fixed`/`NTFS` is rejected by the CLI, bootstrap, module, Codex machine-policy path, and target-profile path before mutation. |
| Service control | The gateway runs as `NT SERVICE\<gateway-name>`, the guardian runs as LocalSystem, both start automatically, and a standard user cannot stop, disable, reconfigure, delete, or obtain `PROCESS_TERMINATE` access to either service. Direct `taskkill` fails and both PIDs remain unchanged. |
| Process/token object isolation | A standard user may obtain query-limited process access, but cannot terminate, suspend, inject into, create threads in, duplicate handles from, change quota/information/DACL/owner on, or obtain all-access to either service process. It also cannot obtain any duplicate/impersonate/assign-primary/adjust/DACL/owner token handle. Both original PIDs remain responsive after every probe. |
| Actual service tokens | A read-only C#/PInvoke probe records each live PID's TokenUser, integrity, privileges, groups, and restricted SIDs. The gateway is the exact virtual service SID with a restricted system-integrity token and only ChangeNotify. The LocalSystem guardian has exactly Tcb/Impersonate/ChangeNotify/Backup/Restore; Backup and Restore must be present-but-disabled at idle and enabled only on the dedicated bounded DACL-repair thread. TakeOwnership is never retained. |
| Recovery semantics | Each service has only restart actions at 5s/15s/60s, with the final 60s action repeated indefinitely and no terminal NONE. Controlled unexpected failures 1-4 replace the PID every time. Servicing persists intent, disables and stops both services, and completes a fresh 65-second queued-restart drain before guardian-first activation. `-NoStart` remains disabled/stopped until a complete public `Repair`; raw SCM start is rejected as an activation path. |
| Shared Codex prerequisite | Explicit enterprise lifecycle securely creates missing `C:\ProgramData\OpenAI\Codex` parents with System/Administrators full control and Users read/traverse. Status and normal mode do not create them; unsafe preexisting owners/DACLs/reparse points fail without takeover; rollback removes only transaction-created empty directories; preexisting legitimate directories survive failure and purge. |
| Codex machine policy | `%ProgramData%\OpenAI\Codex\requirements.toml` contains exactly ten managed hook groups and points only to the protected installed hook. Its protected enrollment state, ownership record, and ACL preimage are non-user-writable and guardian-repaired after deletion, event removal, or DACL drift. Managed enterprise never reads, writes, or patches `<profile>\.codex`. |
| Codex policy serialization | `%ProgramData%\OpenAI\Codex\.defenseclaw-managed-hooks.lock` is Administrators-owned, protected, no-reparse, and single-link. Acquisition is bounded. The retired predictable Global mutex name is ignored even when a user pre-creates it; a user-held read lock may deny availability only until the bounded failure and later reconcile. |
| Agent application control | Protected schema-v2 evidence attests approved signed clients and Claude effective policy. Approved clients start; explicitly supplied official old Codex/Claude and custom unsigned lookalikes are blocked. |
| Codex effective enforcement | The protected machine requirements point approved Codex directly to the shared `defenseclaw-hook.exe`; certification invokes the real client and requires managed hook contact or a blocked operation. |
| Claude effective enforcement | The real approved Claude client must exercise the installed machine policy against a local no-auth Messages stub. Hostile user and project `disableAllHooks` settings cannot yield a green result unless a managed hook is observed or the client operation is blocked. A protected `90-defenseclaw.json` file alone is not acceptance evidence. |
| Hook server identity | Scoped-token authentication is necessary but not sufficient. The connected loopback server PID must equal the exact live SCM gateway PID. A standard-user fake listener on the exact API port, including a gateway-restart bind race, cannot obtain an authenticated request or return a trusted allow verdict. |
| SID enrollment | Every protected interactive SID is explicitly enrolled. The installed managed hook returns non-zero with a causal enrollment diagnostic for an unregistered non-admin SID and does not create or change that user's DefenseClaw state. |
| Administrator assets | A standard user cannot replace the gateway/hook binaries, edit config or manifest, forge the authorization ledger, or change deployment metadata/service environment. |
| Credential isolation | A protected user cannot read or write service-side connector-scoped credentials. Per-user hook credentials remain scoped to the declared connector route. |
| Permanent protection | A standard user cannot invoke enterprise uninstall or remove the manifest/ledger. A declared hook deletion is repaired by the guardian. |
| Target-owned read bounds | Managed token, sidecar, contract, snapshot, helper, and artifact reads use stable no-reparse/single-link handles with format-specific ceilings. Digests stream in constant memory. A sparse grow-after-check race fails closed without exhausting the guardian. Managed helpers are always rewritten from the exact embed; unmanaged newer-helper preservation and normal auto-heal behavior remain unchanged. |
| Drift repair | Deleted or modified native config, hook scripts, generated helpers, per-user tokens, and contract metadata return to their verified canonical bytes. A deleted canonical data directory and a previously authorized target-owned root junction are replaced without changing the junction target. Target/SYSTEM/Administrators/OWNER RIGHTS deny-ACE obstructions become truthfully unhealthy and are repaired to the canonical target-owned DACL without changing file bytes. Every managed regular file has one hard-link name; a previously authorized multi-link leaf is quarantined and recreated under its managed name without changing the outside name's bytes, owner, or DACL. A previously authorized target-owned oversized regular obstruction is likewise quarantined and replaced with the canonical bounded leaf. Settled files stop changing. |
| Fail-closed paths | Unsafe DACLs, foreign owners, foreign-owned reparse points, and paths outside the declared user home or managed roots fail without following, removing, or changing an outside target. |
| CLI truth | Windows lifecycle `install`, `upgrade`, `repair`, `reconcile`, `status`, `verify`, and `uninstall` emit parseable JSON when requested and exit non-zero on failure. Guardian `status` and `verify` remain read-only and truthful for partial or unhealthy target state. |
| Servicing truth | A missing-source preflight failure and a real post-snapshot managed-config activation failure both return non-zero. The latter must restore binary/config/manifest/metadata hashes, the full SCM contract, Running state, and guardian readiness exactly. A successful byte-changing upgrade must then use the newly installed v2 public CLI for an immediate healthy `verify`, revalidate the full SCM contract, and match the protected config and manifest source hashes exactly. |
| Removal | Only an administrator can remove services. Codex requirements/enrollment and Claude managed-policy wiring are removed and verified before binary retirement, using protected ownership/preimage records; shared vendor parents and unrelated administrator settings are preserved. A fresh Codex/Claude process has no DefenseClaw reference after teardown. Default removal must preserve exact real audit, gateway/guardian log, guardian-state, and authorization-ledger bytes, publish an inactive deployment tombstone, convert the retained StateRoot and critical subdirectories to administrator-only protected DACLs, and deny an actual medium-token process write and DELETE handles while both services are absent. Already-running clients must be closed or restarted because they may have cached the retired absolute Program Files hook command; enterprise purge does not promise a retained no-op launcher. `-Purge` removes only exact DefenseClaw-owned roots after explicit authorization. |

The in-process regression matrix lives in
`internal/gateway/enterprise_mode_matrix_test.go`. It is platform-neutral and
must run in the normal Go suite.

### Windows mutation authority

An elevated administrator owns deployment lifecycle and may run Windows
lifecycle actions plus read-only guardian `status` and `verify`. Generic Codex
or other user-footprint mutation is different: `install`, `reconcile`, and
`watch` must run inside the installed LocalSystem guardian. That process must
obtain the active WTS token for the manifest's exact SID, impersonate the user
while touching that profile, and revert before updating the administrator
ledger. There is no LocalSystem path-string-write fallback.

The harness therefore triggers `enterprise windows reconcile` (equivalent to
installer `-Action Reconcile`) and waits on guardian state. It never invokes a
generic user-footprint reconcile or uninstall as a successful mutation from
the elevated harness process; one direct reconcile is attempted only to prove
that the LocalSystem boundary rejects it. The separate Claude Code
machine-policy path is allowed from
an elevated administrator because that policy is a machine-owned object, not a
generic user-owned footprint.

Managed target-owned leaves and directories use a protected DACL with exactly
four allow principals: OWNER RIGHTS receives `READ_CONTROL`; the exact target
SID receives generic read/write/execute/delete (plus child delete on
directories); LocalSystem and Administrators receive generic all. A file has
four direct ACEs. A directory has seven ACEs because the target, LocalSystem,
and Administrators entries are each split into one direct ACE and one
object/container-inherit, inherit-only ACE; OWNER RIGHTS remains direct-only.
The OWNER RIGHTS entry removes the owner's implicit ability to rewrite the
DACL while preserving read-control visibility. The guardian never
canonicalizes the profile root.

Legacy files or a race may still present a target-owned object whose DACL
denies the target, LocalSystem, Administrators, or OWNER RIGHTS. The guardian
repairs only an already-authorized exact target-owned object. On one locked
dedicated OS thread it enables only `SeBackupPrivilege` and
`SeRestorePrivilege`, opens the profile-relative object without following a
reparse point, rechecks exact owner/type/bounds on handles, writes only the
canonical DACL, reverts impersonation, disables the privileges, and discards
the thread if reversion fails. It does not request
`SeTakeOwnershipPrivilege`, take over a foreign-owned object, follow a
junction, invoke connector callbacks in the privileged window, or repair an
unapproved first-install obstruction.

Every managed regular-file handle must report `NumberOfLinks == 1`. First
enrollment may canonicalize an ordinary, exact-target-owned ACL under the
target token, but it must not recreate a missing required native config or
repair a multi-link obstruction. Once the target is present in the protected
authorization ledger, the guardian may move the managed name into its one
bounded `.defenseclaw-quarantine` sibling, create and verify a new single-link
managed file, and purge only that profile-side quarantine. It must not write,
retarget, take ownership of, or change the DACL on another hard-link name.

## Prerequisites

- Disposable Windows 11 or supported Windows Server x64 host with NTFS.
- 64-bit PowerShell 7 and an elevated administrator shell.
- The fixed in-box
  `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`. The harness
  resolves it below the Windows known folder, starts it with `-NoProfile`, a
  protected `System32`/known-folder environment allowlist, and an
  atomic 128-bit-random child of Windows Temp whose owner and protected DACL
  grant access only to LocalSystem and Administrators. The shared writable
  Windows Temp parent is never used directly, and the child must be absent
  after every CLI lifecycle call. This prevents inherited
  `COR_*`/`CORECLR_*`/`COMPlus_*`/`DOTNET_*`, `__COMPAT_LAYER`, and PowerShell
  preference variables from reaching bootstrap. Outside the harness, start
  this fixed engine from a clean endpoint-management process: a script cannot
  undo loader injection that acted before the script began.
- Use the signed `defenseclaw enterprise windows ...` CLI for interactive
  administrator lifecycle operations. Direct `install-enterprise.ps1`
  execution is supported only from a trusted LocalSystem or
  endpoint-management startup context whose loader environment was protected
  before PowerShell started. Its internal protected bootstrap directory
  contains helper compilation; it does not convert an already-influenced
  interactive PowerShell process into a trusted bootstrap context.
- Exactly one matching interactive user in WTS `Active` state. Keep that
  desktop logged on, close DefenseClaw and any process that writes
  `.defenseclaw`, and do not launch a new Codex process during the temporary
  machine-environment certification window. Already-running desktop processes
  are not modified. Close and restart Codex and Claude when validating
  post-uninstall de-enrollment; a process that cached an enterprise hook
  command before teardown is outside the fresh-process removal proof.
- Secondary Logon service available so the harness can create a real
  medium-integrity local non-admin process for hostile control probes.
- A gateway, native hook, and optional CLI from the same approved build.
- A separately version-stamped second build when upgrade byte replacement and
  activation must be certified.
- No existing services, scheduled tasks, or local users whose names start with
  the harness-only prefixes `DefenseClawCert` or `DCEH`.
- `C:\ProgramData\OpenAI` and `C:\ProgramData\OpenAI\Codex` initially absent.
  This clean disposable-host prerequisite lets one run prove secure creation,
  rollback of only transaction-created empty directories, later treatment as
  preexisting shared state, and exact removal of the harness-owned fixture.
- Enough time for a full run plus cleanup. Do not interrupt the endpoint while
  service or profile cleanup is in progress.

The harness never targets an existing machine-level DefenseClaw installation.
Every run generates a new ten-character identifier and confines machine
mutations to:

- `DefenseClawCertGateway_<id>` and `DefenseClawCertGuardian_<id>`;
- one `DCEH<id-prefix>` local non-admin denial user;
- short-lived, Administrators-owned `DefenseClawCert_<id>_*` scheduled tasks
  with an exact protected three-ACE DACL; `RunEx` binds them to the exact
  resolved user SID and WTS session at limited run level;
- short-lived `\\.\pipe\DefenseClawCert.<id>.<nonce>` capture channels owned
  by Administrators, with bounded target-SID data access and exact Task
  Scheduler `RunEx` `EnginePID` binding;
- `C:\Program Files\Cisco\Cisco Secure Client\DefenseClaw-Cert\<id>`;
- `C:\ProgramData\Cisco\Cisco Secure Client\DefenseClaw-Cert\<id>`;
- `C:\ProgramData\Cisco\Cisco Secure Client\DefenseClaw-Cert-Staging\<id>`;
- `C:\ProgramData\Cisco\Cisco Secure Client\DefenseClaw-Cert-Work\<id>`.
- the exact direct child
  `<active-WTS-profile>\.codex-defenseclaw-cert-<id>`.

The run also temporarily creates the canonical shared prerequisites
`C:\ProgramData\OpenAI` and `C:\ProgramData\OpenAI\Codex`. It proves that
production uninstall/purge preserves them, then removes them only after both
certification services are absent, both directories retain the exact expected
protected inventory, `Codex` is empty, and `OpenAI` contains no other entry.
Any unexpected content, reparse point, ACL drift, or lingering service makes
cleanup fail rather than widening deletion.

Those roots are resolved from `Environment.SpecialFolder.ProgramFiles` and
`Environment.SpecialFolder.CommonApplicationData`, not process environment
variables. The automated contract test poisons both `ProgramFiles` and
`ProgramData`, runs installer `Status` and the harness plan, requires the
known-folder paths above, and proves that neither poison path was created.

Codex requires the canonical `<profile>\.defenseclaw` runtime, so the harness
does not invent a test-only runtime mapping. It snapshots that complete runtime
tree into protected staging, including file hashes, attributes, timestamps,
owner, and DACL, and requires exact restoration.

The potentially large live `<profile>\.codex` tree is never enumerated,
snapshotted, or mutated. No machine or service `CODEX_HOME` value is created.
Instead, after the normal-mode no-op gate, the active medium user creates an
initially absent, target-owned direct child named
`.codex-defenseclaw-cert-<id>` on the same fixed NTFS profile volume. The
harness rejects a preexisting path, a different basename or parent, a reparse
point anywhere in the path, a non-fixed/non-NTFS volume, or the wrong owner.
It then:

1. runs the candidate gateway's read-only `connector verify` against hostile
   `USERPROFILE` config and hooks decoys to prove the built Codex resolver
   honors the explicit `CODEX_HOME`, comparing complete before/after
   inventories to prove no writes;
2. snapshots the machine and coordinator `CODEX_HOME` absence/value/type only
   to prove they remain unchanged;
3. invokes the installer with `-NoStart`, then requires both unique
   certification services to be disabled, have PID 0, and omit `CODEX_HOME`
   from their service environments. It then activates only through a complete
   public `Repair` without `-NoStart`; raw `Start-Service` is an invalid
   activation path. Every unsigned certification lifecycle, including the full
   and `-ClaudeOnly` profiles, passes the exact
   `-CertificationCodexHome` scope marker; only `-ClaudeOnly` also passes the
   distinct `-CoreHardeningCertification` flag;
4. requires the guardian to publish only the protected machine
   `requirements.toml` as Codex hook configuration and to place per-SID
   DefenseClaw runtime below exact `<profile>\.defenseclaw`, without consulting
   either live `.codex` or the alternate child;
5. passes the alternate `CODEX_HOME` only to the disposable actual Codex child
   process used for end-to-end policy evidence; and
6. verifies machine, coordinator, and both services still omit the override,
   then removes the absent-baseline certification child.

The switch is certification-only. It is an exact unsigned-scope marker for
every `-AllowUnsigned` `Install`, `Upgrade`, or `Repair`, including both the
full and `-ClaudeOnly` profiles. It never becomes a machine or service
environment value; only the disposable actual-Codex child may receive it as
`CODEX_HOME`. Production service names reject it, signed production lifecycle
calls omit it, and every service environment omits `CODEX_HOME`.
`-CoreHardeningCertification` is a separate explicit mode: it requires that
same unsigned scope, rejects a Codex-enabled manifest and all production
attestations, and is used only by the `-ClaudeOnly` core profile.

The active user's password is never requested or serialized. The elevated
coordinator uses Task Scheduler's interactive-token logon and `RunLevel
Limited`, then verifies that the task token has the exact manifest SID,
medium integrity, and no enabled Administrators group. An account that belongs
to Administrators is acceptable only when the tested interactive token is UAC
filtered and satisfies those effective-token checks.

Cleanup revalidates every service name, task name, user name, and root before
deletion. The default production names and roots do not match those guards.

## Read-only plan

First run the plan path from a non-elevated shell. It reads the supplied files
and prints JSON, but creates no user, service, directory, or policy:

```powershell
.\scripts\test-windows-enterprise-hardening.ps1 `
  -GatewayBinary .\defenseclaw-gateway.exe `
  -HookBinary .\defenseclaw-hook.exe `
  -CLIBinary .\defenseclaw.exe `
  -NormalModeCLILauncher C:\cert\python-cli\defenseclaw.exe `
  -NormalModeCLIWheel C:\cert\defenseclaw-0.8.0-py3-none-any.whl `
  -CodexBinary C:\cert\codex-0.144.3.exe `
  -ClaudeBinary C:\cert\claude-2.1.207.exe `
  -RejectedCodexBinary C:\cert\codex-0.130.0.exe `
  -RejectedClaudeBinary C:\cert\claude-2.1.151.exe
```

Review the exact names and paths. Confirm they all contain the generated run
identifier and use only the certification roots above. The automated
poisoned-environment test performs this same plan after replacing
`ProgramFiles` and `ProgramData` and requires the plan to remain under Windows
known folders without creating either poison path.

## Full disposable-host run

From an elevated 64-bit PowerShell 7 window:

```powershell
.\scripts\test-windows-enterprise-hardening.ps1 `
  -GatewayBinary .\defenseclaw-gateway.exe `
  -HookBinary .\defenseclaw-hook.exe `
  -CLIBinary .\defenseclaw.exe `
  -NormalModeCLILauncher C:\cert\python-cli\defenseclaw.exe `
  -NormalModeCLIWheel C:\cert\defenseclaw-0.8.0-py3-none-any.whl `
  -CodexBinary C:\cert\codex-0.144.3.exe `
  -ClaudeBinary C:\cert\claude-2.1.207.exe `
  -RejectedCodexBinary C:\cert\codex-0.130.0.exe `
  -RejectedClaudeBinary C:\cert\claude-2.1.151.exe `
  -AllowUnsigned `
  -AttestAgentApplicationControl `
  -Execute `
  -DisposableHost
```

If more than one WTS-active desktop exists, pin the intended one without
supplying credentials:

```powershell
.\scripts\test-windows-enterprise-hardening.ps1 `
  -GatewayBinary .\defenseclaw-gateway.exe `
  -HookBinary .\defenseclaw-hook.exe `
  -CLIBinary .\defenseclaw.exe `
  -NormalModeCLILauncher C:\cert\python-cli\defenseclaw.exe `
  -NormalModeCLIWheel C:\cert\defenseclaw-0.8.0-py3-none-any.whl `
  -CodexBinary C:\cert\codex-0.144.3.exe `
  -ClaudeBinary C:\cert\claude-2.1.207.exe `
  -RejectedCodexBinary C:\cert\codex-0.130.0.exe `
  -RejectedClaudeBinary C:\cert\claude-2.1.151.exe `
  -ProtectedUserSID 'S-1-5-21-...' `
  -AllowUnsigned `
  -AttestAgentApplicationControl `
  -Execute `
  -DisposableHost
```

`-AllowUnsigned` exists only for developer-built fixture binaries. The
bootstrap accepts it before importing an unsigned adjacent module only for
`Install`, `Upgrade`, or `Repair`, with the exact case-sensitive
`DefenseClawCertGateway_<id>` /
`DefenseClawCertGuardian_<same-id>` names, exact run-id leaf under both
dedicated `DefenseClaw-Cert` roots, and the required exact
`.codex-defenseclaw-cert-<same-id>` basename. Only `-ClaudeOnly` adds
`-CoreHardeningCertification`; the full unsigned profile omits the core flag
and supplies its separately validated attestation inputs. The harness passes
these certification-only flags only for those three mutating actions. Its
positive contract and negative production,
mismatched-id, case-near-miss, nested-root, and CODEX_HOME-near-miss
assertions run before install. Before any installer action, the
harness byte-copies the installer, adjacent module, gateway, hook, required
CLI, and required three-binary upgrade set into the administrator/System-only
staging root, then proves source and staged hashes match. The adjacent module is validated
before import across its complete fixed-NTFS/reparse/owner/DACL/signature path
chain. Installer child commands receive a strict environment allowlist, a
`System32` working directory, and only a newly created protected
System/Administrators temporary child rather than the shared Windows Temp
root. Omit the switch for signed release
artifacts. The public installer continues to reject unsigned production
binaries by default, and `-AllowUnsigned` never bypasses source trust.

`-AttestAgentApplicationControl` means endpoint application-control rules allow
only approved agent clients and enforce at least Claude 2.1.152. The harness
invokes the approved Codex executable directly with the ordinary
`codex exec ...` argument shape and requires managed-hook contact or a blocked
operation.

The full harness is deliberately two-phase. Initial `Install` may report
`core_hardening_complete=true`, but it must report
`claude_effective_policy_verified=false` and `security_complete=false`.
The harness then runs the real approved Claude client with hostile user and
project precedence. Only after that succeeds does it run `Repair` with
`-AttestClaudeEffectivePolicy`; the protected schema-v2 evidence binds that
proof to the current manifest hash. Only that second transaction may make
aggregate `security_complete=true`.

The public signed CLI maps one-to-one to those installer parameters. For the
first transaction, use `defenseclaw enterprise windows install` with
`--gateway-binary`, `--hook-binary`, `--cli-binary`, `--config`, `--manifest`,
and the normal signed release inputs. Add
`--attest-agent-application-control` only when WDAC or AppLocker has been
independently deployed and tested. After the independent live Claude proof,
use `defenseclaw enterprise windows repair` with the same protected release
inputs, repeat that optional application-control attestation if used, and add
`--attest-claude-effective-policy`. Then require both
`enterprise windows status --json` and `enterprise windows verify --json` to
report the manifest-bound effective-policy field and aggregate security true.
The CLI delegates to the same protected PowerShell transaction; it does not
weaken elevation, signature, source-path, or action restrictions.
Certification drives the clean first transaction through the protected staged
base CLI with `--no-start`, proves both services remain disabled with PID zero,
and then uses the installed public `repair` command for guardian-first
activation; it does not substitute a direct installer call for public
`install`.

For a CLI-replacing `enterprise windows upgrade`, execute the **new release's
protected staged CLI** outside the installed `bin` directory and supply that
same file through `--cli-binary`. Windows cannot safely replace the currently
mapped installed image synchronously. The installed CLI therefore rejects its
own byte replacement before mutation; it remains valid for a gateway/hook-only
upgrade when `--cli-binary` is omitted. Certification invokes the staged
release CLI and binds the installed gateway, hook, and CLI hashes exactly to all
three staged upgrade hashes.

The certification harness also creates a real per-logon raw DOS-device drive
alias under the medium test token, pointing at a local NTFS subdirectory. It
first proves that the alias appears fixed and NTFS and is not enumerated by
`subst.exe`, then requires the public bootstrap and module to reject aliased
installer, install-root, state-root, and certification-home paths in both
Windows PowerShell 5.1 and PowerShell 7. The exact alias is removed and all
trees are re-snapshotted before lifecycle testing continues.

For a useful implementation-only run before optional WDAC/AppLocker policy is
available, omit `-AttestAgentApplicationControl`; the full profile can still
exercise both connectors through the shared `defenseclaw-hook.exe`. Add
`-ClaudeOnly -AllowUnsigned` only for the intentionally Claude-only core
profile. That profile still executes the real hostile-precedence Claude test
and the Windows service, ACL, denial, repair, revocation, and cleanup suite, but
it truthfully
retains `claude_effective_policy_verified=false`,
`security_complete=false`, and `production_certified=false`. Its live result is
certification evidence only; it cannot be promoted or reused as a production
attestation.

To certify a real byte-changing upgrade, add the separately version-stamped
second build:

```powershell
.\scripts\test-windows-enterprise-hardening.ps1 `
  -GatewayBinary .\v1\defenseclaw-gateway.exe `
  -HookBinary .\v1\defenseclaw-hook.exe `
  -CLIBinary .\v1\defenseclaw.exe `
  -NormalModeCLILauncher C:\cert\python-cli\defenseclaw.exe `
  -NormalModeCLIWheel C:\cert\defenseclaw-0.8.0-py3-none-any.whl `
  -CodexBinary C:\cert\codex-0.144.3.exe `
  -ClaudeBinary C:\cert\claude-2.1.207.exe `
  -RejectedCodexBinary C:\cert\codex-0.130.0.exe `
  -RejectedClaudeBinary C:\cert\claude-2.1.151.exe `
  -UpgradeGatewayBinary .\v2\defenseclaw-gateway.exe `
  -UpgradeHookBinary .\v2\defenseclaw-hook.exe `
  -UpgradeCLIBinary .\v2\defenseclaw.exe `
  -AllowUnsigned `
  -AttestAgentApplicationControl `
  -Execute `
  -DisposableHost
```

Full execution refuses to start without all three second-build artifacts. The
harness requires each staged upgrade hash to differ from its corresponding
installed preimage and requires the resulting gateway, hook, and CLI hashes to
match the staged values exactly. Immediately after that byte change, the
harness invokes public `verify` through the newly installed v2 CLI, requires
healthy gateway and guardian readiness, revalidates the complete service
contract, and matches the installed config and manifest to their protected
source hashes. It also proves that an invalid upgrade returns non-zero,
preserves the installed hashes, leaves both services running, and keeps
guardian verification healthy. It runs two negative servicing paths: a
missing hook source that must fail before transaction creation, and a protected,
syntactically valid managed config with a non-loopback bind that must fail only
after the installer snapshot/staging boundary. The second case requires exact
rollback of every deployment hash, SCM configuration/recovery/SDDL/environment
field, Running state, installer verification, and guardian verification.

### Normal-mode non-regression

The enterprise implementation is dormant unless the effective deployment mode
is `managed_enterprise`. The harness proves that twice:

1. Before installation, normal-mode status creates no service, machine policy,
   data root, or user-tree change.
2. After enterprise installation, a separate temporary non-admin profile runs
   ordinary `defenseclaw init` and `setup codex` with
   `DEFENSECLAW_DEPLOYMENT_MODE=unmanaged_byod`. The test records the generated
   Codex hook registration, replaces it, and waits for the existing
   normal-mode guardian to restore the exact bytes. It then tears down only
   that disposable normal-mode fixture and compares every enterprise-protected
   machine artifact byte, owner, and DACL to the pre-test snapshot.

Enterprise opt-in therefore adds no normal-mode machine behavior, but it also
does not disable the hook auto-heal users already have. The allocation-safe
exact-file comparison is result-equivalent in normal mode: it still rewrites
only non-matching bytes. Managed-only stable readers, exact embedded-helper
canonicalization, and authorized quarantine repair are not selected by
ordinary setup.

### Managed hook and machine-policy repair

The harness deliberately stops the guardian as an administrator for one
deterministic test window. It then damages user-owned artifacts through the
already-active medium interactive token: the connector-scoped token and
connector sidecar are deleted, while shared hook configuration and contract
metadata are modified. It requires every tamper action to succeed and both
`status --json` and
`verify --json` to report `ok: false` with non-zero exit status. After the
administrator restarts the guardian, every baseline digest must return within
the configured timeout and remain unchanged for the settle interval.

Codex hook registration is machine policy, never the user's
`<profile>\.codex\config.toml`. The harness separately removes one of the ten
managed hook groups from
`%ProgramData%\OpenAI\Codex\requirements.toml`, deletes the requirements file,
weakens its DACL, and deletes
`.defenseclaw-managed-hooks.state`. Each case must make the hidden
`enterprise windows codex-requirements verify --json` command and guardian
verification unhealthy. Restart must restore the exact canonical bytes, owner,
DACL, ten-event set, ownership record, and ACL preimage.

It also proves the Windows DACL recovery boundary. First, the exact active
medium user attempts to add full-control deny ACEs for its SID, LocalSystem,
Administrators, and OWNER RIGHTS (`S-1-3-4`) to the managed Codex config; every
attempt must be denied and leave bytes/security exact. The coordinator then
stops the guardian and injects each same deny class into a target-owned
managed config, config lock, hook/runtime leaf, or contract lock to simulate a
legacy or preexisting self-deny obstruction. Both read-only status and verify
must return non-zero/unhealthy. Restart must restore the exact prior bytes,
target owner, and protected canonical DACL within the bounded repair window.
The live guardian token is inspected again after recovery: Backup and Restore
must be disabled at idle.

The harness also exercises allocation and check/use races against every
target-owned managed input. With the guardian stopped, the active target
replaces its token, sidecar, contract lock, generated helper, and digest input
with sparse regular files above their format-specific ceilings, and separately
grows each leaf after the initial check. Read-only status and verify must fail
closed within their bounded timeout; the guardian PID must remain stable and
its working set must not materially increase. After restart, every previously
authorized oversized leaf must be quarantined and recreated at its exact
canonical bytes, and the bounded profile-side quarantine must be absent. A
synthetic helper carrying a newer marker such as `v99` must be overwritten by
the exact embedded managed helper. The equivalent unmanaged fixture must still
preserve a newer helper, proving that normal-mode compatibility was not
changed.

In another stopped-guardian window, that same exact medium target creates an
outside hard-link name for the already-authorized managed Codex config.
`status --json` and `verify --json` must be non-zero/unhealthy while both names
resolve to the original file identity with link count two. After restart, the
managed config must have a different identity and link count one; the outside
identity must remain the original with link count one and byte-for-byte,
owner, and DACL equality. The bounded profile-side quarantine must be absent.

Two additional stopped-guardian windows exercise whole-root recovery through
that same exact medium token. The active target first deletes its canonical
`.defenseclaw` directory, then in a separate case replaces it with a
target-owned junction to an administrator-protected outside sentinel. Because
the target was already present in the protected authorization ledger, restart
must rebuild a real canonical directory in both cases. The outside tree's
bytes, attributes, timestamps, owner, and DACL must remain identical. A
separate administrator-owned canonical junction fixture must instead fail
closed and remain untouched until the harness restores the original tree.

The separate `DCEH...` account exercises the complete SCM denial surface.
`stop`, `pause`, user control 128, `config`, recovery-policy change, `sdset`,
and `delete` must return `ERROR_ACCESS_DENIED`; query may succeed. It also
requires `OpenProcess` with terminate, suspend/resume, VM operation/write,
create-thread, duplicate-handle, set-quota/information, WRITE_DAC, WRITE_OWNER,
injection-combination, and all-access masks to fail with Win32 access denied.
It opens a query-limited handle only to prove that `OpenProcessToken` denies
TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_ASSIGN_PRIMARY,
TOKEN_ADJUST_PRIVILEGES, TOKEN_ADJUST_GROUPS, TOKEN_ADJUST_DEFAULT, WRITE_DAC,
WRITE_OWNER, and their combined mutation mask. It requires `taskkill /PID /F`
to fail for both exact service PIDs, and opens every
binary/config/manifest/ledger/token for write and DELETE access without changing
it; each protected handle request must be denied. The harness then requires
both services to retain their original PIDs and remain Running with byte-identical `qc`,
`qfailure`, SDDL, environment, image paths, deployment hashes, authorization
ledger, and user-hook artifacts. Installer `Verify` and guardian verification
must also prove both services remained responsive. Its unregister attempt is accepted as a
denial only when diagnostics identify the authorization/elevation/LocalSystem
boundary, not merely an unsupported connector.

That account also reads/traverses the shared `OpenAI\Codex` parents, proving
the intended user-facing visibility, while direct child creation, directory
DELETE handles, and ACL changes must be denied and the complete parent
inventory must remain exact.

The same temporary account is intentionally absent from the protected
enrollment state. Invoking the installed hook with
`hook --connector codex --enterprise-managed` must return non-zero with an
unregistered-SID/enrollment diagnostic. It must not discover or reuse the
protected user's credential, and that account's `.defenseclaw` tree must be
byte/security-exact before and after.

### Loopback listener spoof and restart race

The gateway port is not authenticated by address alone. The harness stops the
gateway, starts a standard-user listener on the exact configured API port, and
programs it to return a valid allow document. A managed hook invocation must
deny or fail closed, and the fake listener must record zero authenticated
requests. While the fake listener still owns the port, the harness starts the
gateway to exercise the SCM restart/bind race and repeats the hook call. It
again requires a nonzero hook result and zero authenticated fake requests.
Only after the fake listener releases the port may the SCM gateway start and
guardian readiness return.

The decisive identity is the connected peer PID. It must equal the exact
current PID of the configured SCM gateway service. A stale PID, stopped
service, different listener PID, or PID change during connect is not accepted,
even when the listener knows the JSON shape of an allow response.

### Real agent and application-control evidence

The process-creation matrix runs under the exact protected medium user. The
approved signed Codex 0.144.3 and approved signed Claude 2.1.207 binaries must
start. Mandatory caller-supplied official signed Codex below 0.133.0, official
signed Claude below 2.1.152, and custom unsigned lookalikes must be rejected by
application control at process creation. Both floors are the minimums of the
current hook contracts in `cli/defenseclaw/inventory/hook_contracts.json`; the
harness reads them from there, so a published contract change moves the
required fixtures without a harness edit. A rejected fixture must be an
official signed release below its floor, otherwise its denial proves only that
application control rejects unsigned binaries. The harness never downloads
these artifacts; evidence identifies their exact paths, versions, signers, and
SHA-256 digests.

The real approved Claude binary runs against a loopback no-auth Anthropic
Messages stub with disposable user and project settings that set
`disableAllHooks: true`. A protected Program Files drop-in by itself is not a
pass. The run must create new `claudecode` managed-hook audit evidence or the
client operation must be blocked.

Because the Program Files policy is global while any managed Claude target is
enabled, the harness also invokes the installed hook from a different,
unregistered standard-user SID. That user must fail closed with a causal
enrollment diagnostic before credential lookup and must create neither
per-user managed runtime nor an authenticated audit event. Global machine
policy must never turn an unregistered account into an implicitly authorized
target.

The real approved Codex binary runs against a loopback no-auth Responses stub.
The harness tests a hostile alternate user hook, a deleted alternate user
config, and a hostile `PATH`/`COMSPEC` shell directory. For every run, pass
requires new managed hook contact or a blocked Codex operation. In particular,
the known stock Codex 0.144.3 result—fake shell blocked, fake marker absent,
provider reached, exit code zero, and no managed hook audit—is an intentional
failure. AppLocker/WDAC shell blocking alone must never be reported as
enterprise enforcement.

### Surgical uninstall

Uninstall first revokes every enrolled target and removes only
DefenseClaw-owned connector wiring. Codex removal uses the protected ownership
record and ACL preimage to remove or restore exact
`requirements.toml`/enrollment state. Claude removal uses its protected policy
state to remove the DefenseClaw drop-in only when the current bytes still
match the owned postimage. A concurrent administrator edit, another drop-in,
an unrelated registry value, or a shared vendor parent is preserved or causes
a truthful refusal; it is never overwritten by a broad cleanup.

The harness must prove this ordering before the Program Files tree is renamed
or removed: all Codex and Claude machine policy is absent, the protected
teardown verifier reports zero surviving DefenseClaw-owned command references,
and a fresh process observes no DefenseClaw hook. Existing client processes
must be closed or restarted during endpoint decommissioning. They may retain a
cached absolute command and report hook-launch failure once the enterprise
binary is retired; neither certification nor purge claims a cached enterprise
no-op. That guarantee remains specific to the ordinary per-user stable
launcher and its disabled tombstone.

When uninstall is invoked through the installed CLI, Windows can rename the
canonical install tree while the CLI image is still mapped, but cannot delete
the mapped executable or a file held without delete sharing. The transaction
therefore removes Users read/execute access after policy teardown, publishes an
authenticated prepared receipt, atomically renames the exact protected tree to
a 128-bit-random sibling on the same volume, and returns
`self_uninstall_cleanup_pending=true`. A fixed-System32 detached finalizer
revalidates the caller identity, receipt, hashes, no-reparse/single-link tree,
tombstone, absent services, and absent canonical root. It retries bounded
sharing violations with the lifecycle lock released between attempts, removes
only the authenticated allowlisted tree, and deletes its protected receipt and
helper last. It starts the fixed System32 engine with native `CreateProcessW`,
`bInheritHandles=false`, no standard-handle startup fields, and a clean Unicode
environment so it cannot retain a CLI output-capture pipe while waiting for the
CLI to exit. Writable temp, cache, and home variables point to a
receipt-bound, Administrators/System-only lifecycle child, and PowerShell's
module-analysis cache points to `NUL`; that environment root is validated and
removed before the helper and receipt. The harness keeps an approved hook
handle open without delete sharing through the immediate policy and receipt
checks, proves the installed CLI returns valid JSON while the helper is still
pending, then releases the handle and requires bounded finalizer completion
with no sibling, environment-root, helper, or receipt leak.

`-Purge` may delete only the exact run-owned DefenseClaw Program Files and
ProgramData roots. It does not recursively delete
`C:\ProgramData\OpenAI`, `C:\ProgramData\OpenAI\Codex`,
`C:\Program Files\ClaudeCode`, or `managed-settings.d`. The certification
fixture removes an initially absent shared parent only after verifying it is
empty, unchanged, non-reparse, and contains no non-certification content.

Separately, the elevated coordinator opens each live service process with
`PROCESS_QUERY_LIMITED_INFORMATION`, opens its token with `TOKEN_QUERY`, and
records native TokenUser, mandatory integrity label, TokenPrivileges,
TokenGroups, TokenRestrictedSids, and `IsTokenRestricted`. It compares the
actual token—not only the SCM registry—to this exact contract:

| Service | Token contract |
| --- | --- |
| Gateway | TokenUser equals the resolved `NT SERVICE\<generated-gateway>` SID; integrity is System (`S-1-16-16384`); the service SID is a non-deny-only token group; the token is restricted and includes the service SID, World (`S-1-1-0`), write-restricted (`S-1-5-33`), and exactly one service-logon SID; its only privilege is `SeChangeNotifyPrivilege`. |
| Guardian | TokenUser is LocalSystem (`S-1-5-18`); integrity is System; its service SID is a non-deny-only group; the token has no restricting SID list; its privileges are exactly `SeTcbPrivilege`, `SeImpersonatePrivilege`, `SeChangeNotifyPrivilege`, `SeBackupPrivilege`, and `SeRestorePrivilege`. Backup and Restore are present-but-disabled in the idle process token and are enabled only on the locked, short-lived repair thread. |

Either token retaining Debug, TakeOwnership, AssignPrimaryToken, or
CreateToken privilege is an explicit failure. Backup/Restore on the gateway,
absence of either on the guardian, or either privilege enabled on the idle
guardian process token is also an explicit failure. The full group and
privilege attributes are retained as structured evidence.

The elevated recovery sequence decodes the exact 44-byte `FailureActions`
registry contract instead of relying on localized `sc.exe qfailure` text. It
requires three `SC_ACTION_RESTART` entries at 5000, 15000, and 60000
milliseconds, a reset period of 86400 seconds, and
`FailureActionsOnNonCrashFailures=1`. Per SCM semantics, the final action is
reused after the action-array index is exhausted. The harness then verifies
each service's CIM image/PID points to the protected gateway executable,
forcibly terminates that exact PID four times, records old/new PID and elapsed
restart time for 5s/15s/60s/60s, validates the live tokens again, and proves
deployment hashes plus the SCM contract did not drift.

Finally, it sends an ordinary `Stop-Service` request to each service and
observes Stopped/PID 0 continuously for 70 seconds—past the last recovery
delay—before explicitly starting it. A service that restarts during this
maintenance window fails certification.

## Independent manual inspection

Do not rely only on the harness's pass line. While a run is paused for
inspection, or in a separately provisioned fixture, record:

```powershell
Get-CimInstance Win32_Service |
  Where-Object Name -like 'DefenseClawCert*' |
  Select-Object Name, State, StartMode, StartName, PathName

sc.exe sdshow DefenseClawCertGateway_<id>
sc.exe sdshow DefenseClawCertGuardian_<id>
sc.exe qfailure DefenseClawCertGateway_<id>

Get-Acl 'C:\Program Files\Cisco\Cisco Secure Client\DefenseClaw-Cert\<id>\bin\defenseclaw-gateway.exe' |
  Format-List Owner, Sddl
Get-Acl 'C:\ProgramData\Cisco\Cisco Secure Client\DefenseClaw-Cert\<id>\etc\config.yaml' |
  Format-List Owner, Sddl
Get-Acl 'C:\ProgramData\Cisco\Cisco Secure Client\DefenseClaw-Cert\<id>\hook-guardian\targets.yaml' |
  Format-List Owner, Sddl
Get-Acl 'C:\ProgramData\Cisco\Cisco Secure Client\DefenseClaw-Cert\<id>\hook-guardian-state\protected_targets.json' |
  Format-List Owner, Sddl
```

The service image paths must be absolute and remain under the unique install
root. The gateway identity must be its exact virtual account. The guardian
identity must be LocalSystem. The service registry environment must pin
`managed_enterprise`, installed config/home/authorization paths, and the
correct service role. No protected-user, `BUILTIN\Users`, `Everyone`, or
`Authenticated Users` allow ACE may grant write-like rights to managed assets;
service tokens must also deny read.

Both service Environment values must omit `CODEX_HOME`, including in
certification scope. They must independently pin approved-client application
control and Claude policy evidence. The removed legacy trusted-shell pin is
not accepted. `sc.exe qprivs` and the live token
record must show the guardian's exact
Tcb/Impersonate/ChangeNotify/Backup/Restore set, with no TakeOwnership; the
evidence must show Backup/Restore disabled again after DACL recovery.

Inspect the service logs and require:

- one initial reconcile with every enabled target successful;
- one bounded deleted-root repair and one bounded previously authorized
  target-owned junction repair, with the outside inventory unchanged;
- one explicit refusal of a foreign-owned canonical junction, again with the
  outside inventory unchanged;
- a non-zero/unhealthy observation while the guardian is deliberately stopped
  and user artifacts are damaged;
- one bounded repair after restart;
- four bounded deny-ACE repairs covering target SID, LocalSystem,
  Administrators, and OWNER RIGHTS, with exact bytes/owner/DACL restored;
- one bounded managed-hard-link repair with a new one-link managed identity,
  unchanged outside bytes/owner/DACL, and no surviving quarantine;
- one unregistered-SID managed invocation rejected before credential use;
- two fake-listener denials (gateway stopped and SCM restart race), with zero
  authenticated requests reaching the standard-user listener;
- exact Codex machine-policy event/deletion/DACL/state repairs;
- real Claude effective-precedence evidence and real Codex hostile-shell
  evidence, including the intentional stock-0.144.3 rejection when applicable;
- no repeating reconcile loop after canonical files settle;
- no token value in logs, JSON, or error text.

## Evidence and cleanup

The default evidence directory is:

```text
artifacts\windows-enterprise-certification\<id>\
```

`windows-enterprise-certification.json` contains source hashes, exact fixture
names/roots, every check outcome, observed recovery time, and cleanup status.
Elevated and service-process stdout/stderr lives under its `logs` directory.
Active-user probe output is never accepted from a user-writable file: it is
captured in memory across the administrator-owned named pipe only after the
client PID equals the one Task Scheduler engine PID and its SID, executable,
active session, and random nonce all match. Treat the evidence as sensitive
operational data even though token contents must never be logged.
The harness registers current service/per-user token values only in memory,
scans work/evidence logs for raw occurrences, redacts any occurrence, and fails
the run if one is found. Result and failure text are also secret-redacted before
JSON serialization.
The protected user-tree byte backups are not copied into evidence and are
deleted with the staging root after exact restoration.

The run is not accepted if:

- any required result is `failed` or unexpectedly `skipped`;
- the final status is `passed_with_cleanup_errors`;
- the temporary local user/profile, scheduled task, service, Program Files root,
  ProgramData root, or staging root remains;
- the active user's `.defenseclaw` inventory differs from its pre-test
  snapshot;
- the absent-baseline certification CODEX_HOME remains, its native paths enter
  live `.codex`, or evidence says live `.codex` was enumerated, snapshotted, or
  mutated;
- the machine or coordinator `CODEX_HOME` absence/value/type changed at all, or
  either service received a `CODEX_HOME` environment entry;
- a DefenseClaw-owned Codex requirements/enrollment leaf or Claude managed
  policy leaf remains after uninstall, or an unrelated shared vendor
  parent/setting changed;
- source hashes or logs cannot be tied to the tested build.

Check cleanup independently:

```powershell
Get-Service 'DefenseClawCert*' -ErrorAction SilentlyContinue
Get-ScheduledTask -TaskName 'DefenseClawCert_*' -ErrorAction SilentlyContinue
Get-LocalUser | Where-Object Name -like 'DCEH*'
Get-CimInstance Win32_UserProfile |
  Where-Object LocalPath -match '\\Users\\DCEH[a-f0-9]{8}$'
Get-ChildItem 'C:\Program Files\Cisco\Cisco Secure Client\DefenseClaw-Cert' -Force -ErrorAction SilentlyContinue
Get-ChildItem 'C:\ProgramData\Cisco\Cisco Secure Client\DefenseClaw-Cert' -Force -ErrorAction SilentlyContinue
Get-ChildItem 'C:\ProgramData\Cisco\Cisco Secure Client\DefenseClaw-Cert-Staging' -Force -ErrorAction SilentlyContinue
Get-ChildItem 'C:\ProgramData\Cisco\Cisco Secure Client\DefenseClaw-Cert-Work' -Force -ErrorAction SilentlyContinue
```

If cleanup fails, preserve the evidence, use the exact identifiers recorded in
the JSON, and remove the fixture through an administrator recovery channel.
Never broaden cleanup to a wildcarded production root.
