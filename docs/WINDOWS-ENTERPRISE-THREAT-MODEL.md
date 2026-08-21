# Windows managed-enterprise threat model

## Target identity and review scope

- Repository: `defenseclaw`
- Baseline commit: `439a01b54632f9a1a13478fda13562693ec2a36f`
- Review target: the working-tree implementation of native Windows
  managed-enterprise services, lifecycle commands, protected state, per-user
  hook reconciliation, and its certification harness
- Primary paths:
  - `cmd/defenseclaw`
  - `internal/cli`
  - `internal/config`
  - `internal/enterprisehooks`
  - `internal/gateway`
  - `internal/managed`
  - `packaging/windows`
  - `scripts/test-windows-enterprise-hardening.ps1`
- Security boundary: a supported Windows endpoint on a local fixed NTFS volume

This model covers the uncommitted implementation as a coherent review target.
The final certification record must identify the exact tree hash or patch
digest that was built and tested.

## Security objectives

The Windows deployment must provide the same security properties as the Linux
and macOS managed-enterprise deployments, expressed in Windows-native terms:

1. A standard local user cannot stop, pause, reconfigure, delete, or replace
   the DefenseClaw gateway or hook-guardian services.
2. A standard local user cannot change the protected executable, managed
   configuration, mode pin, target manifest, service definition, or guardian
   authorization ledger.
3. The gateway has only the filesystem and token privileges required for its
   runtime. It cannot modify the guardian manifest or authorization ledger and
   cannot write arbitrary interactive-user profiles.
4. Only the LocalSystem guardian may authorize per-user hook repair. Content,
   rename, quarantine, and deletion operations run with an active,
   non-elevated token whose user SID exactly matches the administrator-pinned
   manifest SID. The only process-token exception is a DACL-only recovery path
   for an already target-owned object whose self-denying ACL prevents the
   target token from repairing it.
5. Deleted or modified hook artifacts are detected and reconciled. A periodic
   reconcile is the backstop for missed filesystem events.
6. Readiness is fail-safe: service process state, guardian reconcile state,
   protected authorization, target counts, freshness, and per-connector
   coverage are distinct checks. Partial success is never reported as healthy.
7. Connector-scoped credentials cannot authorize management APIs or another
   connector's routes.
8. Enterprise enforcement is opt-in. When the effective deployment mode is
   not `managed_enterprise`, existing per-user setup and auto-heal behavior is
   unchanged and no machine service is created implicitly.
9. Every enabled Windows agent is constrained to an approved, signed minimum
   client version and a protected managed-hook configuration.
10. A hook verdict is accepted only from the exact live SCM gateway process.
    A same-user listener that wins the configured loopback port cannot return a
    forged allow verdict.
11. Enrollment is explicit per interactive SID. An unregistered SID gets no
    shared credential and its managed hook invocation fails closed with a
    stable enrollment diagnostic.
12. Enterprise uninstall removes only DefenseClaw-owned machine policy and
    restores captured preimages. Shared OpenAI/Codex and Claude Code policy
    parents, unrelated settings, and settings owned by another administrator
    are never recursively deleted or overwritten.
13. Every managed read of target-owned tokens, runtime sidecars, contract
    metadata, snapshots, and generated artifacts is allocation-bounded and
    identity-stable. A sparse-file size race, reparse replacement, or hard-link
    alias fails closed instead of exhausting the guardian or blessing raced
    bytes. Windows targets require an explicit certified agent version and
    never fall back to the target-owned discovery cache.

## System and trust boundaries

```text
Administrator / endpoint management
  |
  | signed or administrator-staged artifacts and policy
  v
Windows enterprise lifecycle transaction
  |-- Program Files: gateway, hook, CLI, installer, module
  |-- ProgramData: config, target manifest, runtime, logs, metadata
  |-- ProgramData\OpenAI\Codex: managed requirements + ownership state
  |-- Program Files\ClaudeCode: owned managed-settings drop-in + state
  |-- SCM: gateway service + guardian service
  |
  +--> Gateway service
  |      identity: NT SERVICE\<gateway>, restricted service SID
  |      reads: protected config and guardian authorization
  |      writes: runtime tokens/state and its own log only
  |
  +--> Hook guardian service
         identity: LocalSystem with an explicit privilege allow-list
                   Tcb, Impersonate, ChangeNotify, Backup, Restore
         reads: protected config and manifest
         writes: protected authorization and guardian log
         |
         +--> exact active-session, non-elevated target token
                writes/verifies that SID's declared user-home footprint
         |
         `--> dedicated short-lived privilege thread
                DACL-only, no-follow handle walk for target-owned objects;
                never rewrites the profile root and never takes ownership

Interactive standard user / agent process
  |-- may read installed public executables
  |-- may edit or delete files the user owns
  |-- may call loopback hook endpoints with a connector-scoped token
  |      only when the connected peer PID is the live SCM gateway PID
  `-- has query-only SCM access
```

The administrator and LocalSystem are trusted deployment authorities. A
compromised or malicious administrator is outside this model. The gateway is
not an administrator authority even though it is a machine service.

## Assets

| Asset | Required property |
|---|---|
| Gateway and hook executables | Administrator-owned, non-reparse, no untrusted writer, recorded integrity |
| Installer and module | Trusted before elevated execution; protected after installation |
| Managed `config.yaml` | Administrator-controlled, mode pinned, no runtime downgrade |
| Guardian target manifest | Administrator-controlled explicit user home and SID allow-list |
| SCM service objects and registry configuration | Standard users have query-only access; image, account, privileges, environment, start, recovery, and SDDL are verified |
| Guardian authorization ledger | LocalSystem/Administrators write; exact gateway service SID read-only |
| Gateway runtime and scoped tokens | Administrators/LocalSystem and exact gateway service SID only; no standard-user read |
| Per-user hook footprint | Confined to the manifest SID's canonical profile; exact protected OWNER RIGHTS DACL; regular files have one NTFS link; repairable after target-user tamper |
| Codex machine requirements | Exact `%ProgramData%\OpenAI\Codex\requirements.toml`, ten managed hook groups, protected ownership/ACL preimage records, and guardian-repaired enrollment state |
| Claude Code managed policy | DefenseClaw-owned protected drop-in and ownership state; effective precedence verified with the real approved Claude client |
| Agent application-control attestation | Protected schema-v2 evidence for approved-client rules and Claude effective-policy verification |
| Gateway and guardian logs | Separate ACL domains so the less-trusted gateway cannot alter guardian evidence |

## Threat actors and assumptions

### In scope

- A local standard user, including a member of the local Administrators group
  running with a split, medium-integrity token.
- A user-controlled AI-agent process.
- A compromised gateway process running as the restricted virtual service
  account.
- Accidental drift, deletion, failed upgrades, service crashes, missed watcher
  events, malformed manifests, and partial target failures.
- User-controlled reparse points, path replacement, ACL changes, PATH and
  inherited environment poisoning, stale authorization records, and named
  object squatting.
- A standard-user process binding the configured gateway port before or while
  the SCM gateway restarts and returning a syntactically valid allow response.
- Officially signed but unsupported old clients, unsigned lookalike clients,
  and an approved client whose hook-launch failure is nonblocking.

### Trusted or outside scope

- A fully elevated administrator, LocalSystem, kernel compromise, malicious
  endpoint-management authority, or malicious signer.
- Physical attacks and offline disk modification without BitLocker or an
  equivalent platform control.
- Prevention of all local resource-exhaustion attacks.
- Forcing a client outside the approved application-control allow-list to honor
  a vendor hook mechanism. Such a client is blocked, not certified.

## Primary data flows

### Installation, upgrade, and repair

1. An elevated lifecycle command resolves trusted Windows known folders and
   trusted system executables without relying on user-controlled `PATH`,
   `SystemRoot`, `ProgramFiles`, or `ProgramData` values.
2. It validates source type, reparse state, ownership, DACL, signature where
   applicable, and content hash.
3. It acquires an administrator-only lifecycle lock.
4. It persists a servicing intent, disables and stops both SCM services, and
   holds that state through a fresh bounded drain of any already queued SCM
   failure restart before mutating protected files or service definitions.
5. It snapshots the owned deployment, stages same-volume replacements, applies
   protected DACLs, creates or repairs the SCM services, and pins service
   environment values.
6. It verifies exact static postconditions while both services remain
   disabled. Activation makes only the guardian demand-startable, requires a
   fresh successful reconcile while the gateway remains disabled, starts and
   verifies the gateway, then restores automatic start last. An interrupted
   activation re-enters a fresh disable/stop/drain cycle.
7. `-NoStart` deliberately commits a disabled, stopped deployment. Only a
   complete later `Repair` without `-NoStart` may activate it; raw service
   starts are not an activation API. Failure rolls back and returns non-zero.

### Guardian reconcile

1. The LocalSystem guardian validates the protected config, manifest, runtime,
   and explicit Windows target fields.
2. It resolves an active WTS session and queries its user token.
3. It rejects a SID mismatch, service identity, full/elevated token,
   high-integrity token, UIAccess token, or missing active session.
4. A bounded callback runs on a dedicated locked OS thread under the exact
   target token. User paths are revalidated immediately before use. Regular
   files with multiple NTFS links are rejected and, only for a previously
   authorized target, the in-profile link is quarantined without following or
   modifying its other link.
5. Reads of target-owned leaves pin the opened identity, reject reparse and
   multi-link handles, enforce format-specific byte ceilings, and require
   stable content. Artifact digests stream through bounded readers rather than
   allocating from attacker-controlled file metadata.
6. Only the declared user's canonical connector footprint is written.
   Machine-wide Claude Code policy is handled separately under LocalSystem in
   an administrator-controlled directory.
7. If the target owner has installed a DACL that denies its own token, a
   separate locked LocalSystem thread enables only Backup and Restore for a
   no-follow, handle-relative walk from the verified profile anchor. Every
   component must still be owned by the target SID. The operation changes only
   the final DACL, never ownership or the profile-root DACL, and the thread
   reverts before it can return to the runtime.
8. The guardian verifies content, ownership, the exact canonical DACL, link
   count, hook contract, and scoped token equality before recording success.
9. It publishes service-writable diagnostic state and a separately protected
   authorization ledger. Removed or disabled targets are revoked from the
   ledger.

### Hook request

1. A user-owned hook reads only its connector-scoped token.
2. The request goes to a loopback-only endpoint and names its connector scope.
3. Before sending a request, the managed hook resolves the exact running
   gateway PID from SCM and verifies that the connected loopback peer PID is
   that same process. A missing, stopped, changed, or mismatched PID is a
   fail-closed result.
4. Constant-time token comparison authorizes only that connector's hook or
   notification route.
5. Management, status, configuration, policy, scan, and cross-connector routes
   reject the scoped credential.
6. A managed invocation from a SID absent from protected enrollment state
   fails before it can use another user's token or contact an unauthenticated
   listener.

## Threat analysis and required controls

| ID | Threat / attack path | Required control | Required evidence |
|---|---|---|---|
| W-01 | Standard user calls SCM stop, pause, user-control, config, failure, SDDL, or delete | Protected service DACL with only query/interrogate rights for `BU`; protected service registry configuration | Exact non-admin `sc.exe` probes return access denied and services remain unchanged/running |
| W-02 | User replaces an executable, script, config, manifest, metadata, or ledger | Fixed local NTFS roots; no reparse points; trusted owner and ancestor chain; protected DACLs; content hashes/signatures | Write/delete/rename/ACL probes fail; verify catches byte or ACL drift |
| W-03 | Elevated CLI executes a user-planted PowerShell or installer/module, or gives elevated PowerShell a shared user-writable temp/cache/home root | Resolve the system PowerShell by OS API; ignore `PATH` and poisoned known-folder environment variables; trust-check installer and adjacent module before execution; atomically create a 128-bit-random child under Windows Temp with a protected System/Administrators-only owner/DACL and pin `TEMP`, `TMP`, `LOCALAPPDATA`, `APPDATA`, `USERPROFILE`, `HOME`, `HOMEDRIVE`, and `HOMEPATH` to that exact one-shot child | Poisoned `PATH`, `SystemRoot`, known-folder env, working directory, installer, module, shared-temp-parent, protected-temp-child, PowerShell module-cache location, and cleanup tests |
| W-04 | User downgrades enterprise mode through user config or environment | SCM-owned environment pins `managed_enterprise`; protected config must agree; runtime PATCH cannot change it | Config conflict and untrusted-config tests; service registry DACL test |
| W-05 | Compromised gateway edits policy or authorization | Restricted virtual service SID; separate runtime/log ACLs; config and authorization read-only; guardian log and manifest inaccessible | Effective-token/privilege and ACL matrix; gateway-write attempts fail |
| W-06 | LocalSystem follows a user junction or path race and writes outside the profile | Explicit SID/home binding; reject reparse chains; every user mutation under target impersonation; revalidate immediately before mutation; no LocalSystem fallback | Outside sentinel remains unchanged across junction, owner, and swap tests |
| W-07 | Guardian accepts an elevated administrator session token and creates a UAC bypass | Exact SID plus `TokenElevation`, elevation type, integrity level, and UIAccess checks | Unit tests and active medium-token certification |
| W-08 | Failed `RevertToSelf` leaks an impersonated thread into the Go scheduler | Dedicated locked OS thread; unlock only after successful revert; terminate/discard the thread or fail-stop on revert failure | Injected revert-failure test |
| W-09 | User deletes or edits a hook, token, helper, contract, or native config | Filesystem watcher plus one-minute periodic reconcile; target-token repair; content and ACL verification | Deterministic stop/tamper/unhealthy/start/restore test with measured recovery |
| W-10 | User blocks repair with an owned junction or wrong-type path object | Previously authorized targets may remove or quarantine only the exact owned obstruction while impersonated; never follow it; first install and foreign owners fail closed | Root junction/file obstruction tests; outside sentinel unchanged |
| W-11 | Predictable named mutex is pre-created and held by a standard user, or a reader holds the real transaction lock indefinitely | Codex policy transactions use the protected, no-reparse, single-link `%ProgramData%\OpenAI\Codex\.defenseclaw-managed-hooks.lock` with bounded `LockFileEx`; the retired predictable Global mutex is never opened. Lifecycle uses its independently protected file lock | Pre-create the exact retired Global name with both hostile and permissive DACLs and require zero influence. Hold the real file lock from a standard-user read handle, require bounded fail-closed verification with unchanged policy, release it, and require immediate recovery |
| W-12 | One successful target hides another target's failure | Strict schema, exact counts, no duplicates/trailing fields, `ok=false` on any failure, all configured connectors covered | Partial-failure status, verify, and gateway-health tests |
| W-13 | Old successful authorization remains valid after removal, guardian death, or hang | Current-manifest merge semantics revoke removed/disabled rows; authorization has bounded age and future-skew checks | Revocation and stale/future ledger tests |
| W-14 | Service token is read by a standard user or crosses connector scope | Exact gateway service SID gets runtime Modify; users get no token access; per-user token is connector-scoped | ACL denial plus route-scope matrix |
| W-15 | Upgrade failure leaves new binaries with old state or reports success | Serialized transaction, owned-deployment identity, rollback, exact postcondition verification, non-zero structured error | Injected failed-upgrade test and before/after equality |
| W-16 | Higher-precedence Claude policy disables hooks or a lower user/project `disableAllHooks` source produces a false green | Enforce and validate the documented server-managed > HKLM/MDM > Program Files > HKCU precedence; do not treat a local `90-defenseclaw.json` as sufficient evidence | Real approved Claude 2.1.207 invocation against a local no-auth Messages stub with hostile user and project `disableAllHooks`; require managed hook contact or a blocked client operation |
| W-17 | Normal installations silently change after adding enterprise support | All new enforcement branches require effective `managed_enterprise`; lifecycle install is explicit; the Windows process entry point returns before even consulting SCM service detection unless the protected installer-owned service-name marker is present; existing unmanaged hook self-heal remains active | Entrypoint seam proves the SCM detector and service executor are never called without the marker; full mode matrix, pre-install no-machine-mutation proof, and a disposable normal-mode hook deletion/replacement followed by exact live auto-heal |
| W-18 | Target owner uses implicit `WRITE_DAC`, an OWNER RIGHTS ACE, or `WRITE_OWNER` to make a permissive/irreparable managed object | Exact protected canonical DACL: files have four direct ACEs; directories have direct OWNER RIGHTS plus direct and OI/CI/inherit-only target, System, and Administrators ACEs (seven total). OWNER RIGHTS gets only `READ_CONTROL`; target gets required read/write/execute/delete rights but no `WRITE_DAC`/`WRITE_OWNER`; System and Administrators get full control. LocalSystem recovery is DACL-only and requires exact owner | Exact ACE mask/inheritance tests for both object types, self-deny recovery, ordinary write/atomic-replace compatibility, owner/DACL tamper repair |
| W-19 | Target replaces a regular footprint file with an NTFS hard link to a file outside its profile | Require a handle-observed link count of exactly one before accepting a regular file; quarantine only the in-profile link under the target token; rollback uses no-follow/atomic replacement | Outside-sentinel hard-link repair and forced-rollback tests |
| W-20 | Standard user terminates, suspends, injects into, changes security on, or duplicates a dangerous handle from either service process | Service/process token and object DACLs; restricted gateway service SID; no standard-user process or token mutation handles | Explicit OpenProcess, OpenThread, process-DACL/owner, token-duplicate/impersonate/adjust, taskkill, and PID-continuity probes |
| W-21 | Service exits once recovery actions are exhausted, or a planned stop races automatic recovery | Three restart delays with the final action repeated indefinitely; unexpected command exits terminate the host as a base SCM failure; accepted Stop/Shutdown is graceful and returns cleanly | Four consecutive forced terminations for each service plus a clean stop held beyond the longest recovery delay |
| W-22 | User-controlled loader environment, shared temp/cache/home content, PowerShell function, module, or preloaded helper type hijacks elevated lifecycle code | Fixed System32 PowerShell, strict environment/working directory, one unique protected directory for every writable temp/cache/home variable, pre-import module trust, module-qualified built-ins, randomized retained native-helper type | Poisoned loader/environment/module/function/type smokes, PowerShell ModuleAnalysisCache containment, and protected one-shot-directory ACL/use probes in Windows PowerShell 5.1 and PowerShell 7 |
| W-23 | Authorization remains green with an extra removed/disabled target | Healthy status and verify require exact target-set equality, strict schema/counts, no duplicates, same reconcile identity, and freshness | Extra/stale/removed target tests for status, verify, and gateway readiness |
| W-24 | A caller uses `-AllowUnsigned` with production names/roots, a near-miss certification scope, a non-install action, or implicit core-only semantics to import or deploy untrusted code | Before module import, accept unsigned artifacts only for `Install`/`Upgrade`/`Repair` with exact case-sensitive same-id certification service names, exact same-id Program Files/ProgramData certification roots, and a required same-id certification CODEX_HOME basename. Select core-only behavior through a separate explicit flag that requires the same scope, rejects production attestations and Codex targets, and is bound into transaction recovery; retain all fixed-NTFS, no-reparse, owner, and DACL source checks | Bootstrap, module, public-CLI, recovery, and live-harness matrix tests: full unsigned uses home/no-core, Claude-only uses home/core, signed production and read-only use neither; negative production, mismatched-id, case-near-miss, nested-root, CODEX_HOME-near-miss, and flag-combination assertions |
| W-25 | A standard-user fake listener wins the exact API port and returns a valid allow response while the gateway is stopped or restarting | Bind hook trust to both the connector token and the connected server PID; the PID must equal the exact current SCM gateway PID, not merely any process listening on loopback | Stop/crash the gateway, bind the exact port as a non-admin, return valid allow JSON, and race service restart; the hook must deny/fail closed and the fake listener must observe zero authenticated requests |
| W-26 | Codex managed-hook configuration is removed, redirected, or bypassed | Protect the machine requirements and enrollment state with administrator-owned ACLs, verify the exact ten-event policy, and require end-to-end managed-hook contact or a blocked operation in certification | Invoke the approved Codex client against a bounded local provider and require SessionStart/UserPromptSubmit audit evidence or a causal block |
| W-27 | An old officially signed or custom unsigned agent avoids a newer managed-hook contract | When an enterprise opts into application control, allow only approved signed clients at or above the minimum versions. **The source of truth is `cli/defenseclaw/inventory/hook_contracts.json` for the tested build** — the certification harness reads the floors from there, and any contract update automatically retunes the check without a threat-model edit. As of this document snapshot, the floors are Codex 0.133.0 and Claude 2.1.152 (fixture values, not authoritative — consult the contract) | In the optional application-control profile, approved clients start and explicitly supplied old signed Codex/Claude and custom unsigned lookalikes fail process creation with an application-control denial |
| W-28 | An unregistered interactive SID invokes the installed managed hook or reuses another target's state | Exact SID membership in protected connector enrollment state is checked before token use; absence is fail-closed and diagnostic | Run the installed managed hook under a temporary non-admin SID absent from the manifest; require non-zero, causal enrollment text, and byte/security-exact user trees |
| W-29 | A user removes or weakens Codex machine requirements/enrollment state | Administrator-owned protected DACLs, private ownership/ACL-preimage records, hidden read-only verify, and guardian reconciliation of the exact ten-event canonical document | Standard-user write/delete/DACL attempts fail; administrator-injected deletion, DACL drift, event removal, and state removal are unhealthy until exact auto-heal |
| W-30 | Uninstall removes a shared vendor tree, another administrator's setting, or a value that changed after install | Record exact ownership and preimages; remove/restore only a current value still equal to the DefenseClaw-owned postimage; preserve shared parents and unrelated content | Install over absent and preexisting shared parents, mutate unrelated values, uninstall and purge, then compare preserved parents/preimages and require only owned Codex/Claude wiring to be absent |
| W-31 | A certification-only `CODEX_HOME` leaks into the machine environment or either service and changes production behavior | Treat `-CertificationCodexHome` only as an exact unsigned-scope marker and pass it solely to a disposable actual-Codex child; machine, coordinator, gateway, and guardian environments omit `CODEX_HOME` | Before/after machine-environment snapshot, service registry environment inspection, hostile `USERPROFILE` decoys, and exact cleanup of the alternate child without enumerating or mutating live `.codex` |
| W-32 | A disabled, removed, or deleted-account SID remains enrolled in native machine policy and can keep invoking the hook | Reconcile authorization and native connector state to exact enabled-manifest equality. Remove the final owned Claude policy/state transactionally, retain any per-user runtime only as inert data, and reject the stale SID before credential use | Disable the only Claude row (and repeat with an unavailable account/profile), reconcile, require exact zero Claude authorization and absent owned machine policy/state, then invoke as the former SID and require a causal non-enrollment failure with no audit event |
| W-33 | Valid application-control evidence is reused as proof that Claude's managed hooks are effective | Keep client process control and effective Claude policy as independent fields and transactions. Structural files, hashes, owners, and DACLs cannot set the effective-policy field | Preserve byte-exact application-control evidence while deleting the Claude policy and require effective-policy health to fail independently; run the real client with hostile precedence before accepting a separate manifest-bound Claude attestation |
| W-34 | Install, a core-only test, or stale evidence claims production security before a live Claude run against the current manifest | Initial install always leaves Claude effective-policy and aggregate security incomplete. Only production `Repair -AttestClaudeEffectivePolicy` after the live hostile-precedence proof may persist schema-v2, manifest-hash-bound evidence; core certification forbids persistence | Assert phase-one Install/Status/Verify remain incomplete, run the real Claude proof, perform the attested Repair, then require aggregate completion. Change the manifest or use `-ClaudeOnly` and require the claim to be absent/incomplete |
| W-35 | Target races a validated token, sidecar, contract, helper, or hook artifact into a huge sparse file, reparse point, hard link, or changing same-name object while the guardian reads it | Managed-only stable handle readers with no-reparse/single-link validation and format-specific byte ceilings; constant-memory double-pass artifact hashing; managed helpers always overwrite exact embedded bytes; authorized oversized regular obstructions are quarantined and recreated under the target token | One-TiB sparse exact-compare test; managed token/sidecar/contract/digest bounded-read tests; managed-versus-unmanaged helper test; authorized oversized-obstruction auto-heal with quarantine cleanup |
| W-36 | A planned stop or interrupted activation races an `SC_ACTION_RESTART` that SCM already queued, reviving the gateway without a fresh guardian or against a partially replaced deployment | Durable servicing intent; both services disabled before stop; fresh monotonic 65-second drain while disabled; durable activation phase that invalidates old quiescence timestamps; guardian demand start plus a newly published reconcile before gateway demand start; readiness before automatic start; every recovery path reasserts disabled/stopped and begins a new drain | Executable latent-restart model plus crash injection before and after every activation transition in Windows PowerShell 5.1 and PowerShell 7; no gateway becomes startable before fresh guardian evidence |
| W-37 | A crash after committed uninstall or during purge removes the metadata needed to authenticate a retry, or generic dispatcher initialization recreates a deleted Program Files tree | Authenticate and route uninstall/purge recovery before generic layout creation; keep a protected tombstone/purge receipt outside the recursively deleted root until deletion succeeds; remove authentication metadata last; make committed uninstall and partial purge retries idempotent; never initialize the install tree on a tombstone path | Crash injection at each teardown, tombstone, and purge phase; retry with the install root absent and with partially deleted state; exact proof that services/policy stay removed, shared vendor parents survive, and no managed root is recreated |
| W-38 | Installed-CLI self-uninstall leaves a mapped executable, lets a user race/lock the observable retired tree, loses its only cleanup attempt to a sharing violation, or deadlocks because its detached helper inherits the CLI's captured output pipe | Remove all owned machine command references first; strip Users RX before same-volume atomic retirement; bind a protected prepared/committed receipt to exact caller creation time, file identity, hashes, tombstone, roots, and service absence; use native `CreateProcessW` with no inherited or standard handles, a fixed System32 engine, and a protected receipt-bound temp/cache/home environment; authenticate every survivor and retry bounded sharing violations while releasing the lifecycle lock between attempts; delete the isolated environment, helper, and receipt last. Require already-running clients to reload instead of retaining an enterprise launcher outside the purged root | Transaction crash injection before/after rename and receipt commit; standard-user directory-notification/locker race; captured-parent probe proves the helper remains alive after CLI pipe EOF; hold the installed hook without delete sharing through immediate post-uninstall checks, require canonical root/services/policy already absent, release it, and require exact bounded retirement with no sibling/environment/helper/receipt leak; fresh-client no-policy proof |
| W-39 | A medium-integrity user creates an unused raw `DefineDosDevice` alias to a trusted local subdirectory. The alias reports `Fixed` and `NTFS`, is absent from `subst.exe`, and redirects an elevated installer source, managed root, certification home, or impersonated profile mutation | Require exact drive-letter syntax, fixed NTFS, a volume GUID from `GetVolumeNameForVolumeMountPointW`, exact root membership in a bounded `GetVolumePathNamesForVolumeNameW` list, and one identical well-formed `QueryDosDeviceW` target for the effective drive, `Global\<drive>`, and volume GUID. Reject volume-folder mounts and every reparse ancestor. Revalidate after transaction locks and adjacent to source import/copy, managed-root mutation, certification-home use, and WTS-profile mutation | Under a real medium token, create a raw unused drive alias to a local NTFS directory; prove legacy `DriveInfo`/filesystem/`subst.exe` predicates would accept it; require Go trust validators and both Windows PowerShell 5.1 and 7 bootstrap/module paths to reject aliased installer, install root, state root, and certification home without creating artifacts. Require the ordinary mounted system drive to pass and remove the alias exactly |
| W-40 | The tested medium user or another same-user process forges certification stdout, stderr, or a completion marker in a handoff directory, or rewrites the short-lived scheduled task, and causes the elevated coordinator to record a false pass | Never trust user-writable result files. Give the scheduled task an exact Administrators-owned protected DACL with only System/Administrators full control and target-SID read/execute. Start it with `IRegisteredTask.RunEx` using the exact resolved WTS session and user SID, then capture bounded output over an administrator-owned named pipe whose DACL grants only System/Administrators full control and the exact target SID data access. Require `GetNamedPipeClientProcessId` to equal the returned `IRunningTask.EnginePID`, then bind the receipt to the random nonce, exact SID, PID, approved PowerShell image, and active WTS session before sending an acknowledgement | Execute the real exact-session/exact-SID scheduled-task and pipe handshake in 64-bit PowerShell 7; keep Windows PowerShell 5.1 coverage on the fixed production bootstrap/module boundary; re-read and validate the task owner plus exact three-ACE DACL before start; static contract rejects file-backed completion/output; every active-user fixture binds its ready PID to the exact `RunEx` task instance, and every high-stakes result records PID binding and `user_writable_files_trusted=false` |

## Security invariants

- `managed_enterprise` is both configuration and authority. Merely setting a
  user environment variable cannot make a user-owned config trusted.
- Service `Running` is not readiness.
- A runtime status file is not authorization.
- A previously successful target is retained during a transient failure only
  if the same target remains enabled in the current protected manifest.
- No target SID means no Windows enterprise user mutation.
- No safe active token means retry later; it never means write as LocalSystem.
- No path-string validation is treated as durable across a user-controlled
  mutation. The write is constrained by the target user's effective token.
- Reparse points are never followed for privileged writes.
- Regular managed files must have exactly one NTFS link. A hard link is not
  treated as a safe regular file merely because it is not a reparse point.
- Predictable Global mutex objects are not part of Codex policy serialization.
  The protected machine lock is validated by handle and contention has a hard
  deadline; a standard user can deny availability temporarily but cannot make
  a partial policy transaction appear healthy.
- The guardian never canonicalizes the profile-root DACL. The profile root is
  an identity and no-follow traversal anchor, not DefenseClaw-owned state.
- No LocalSystem recovery path changes ownership or enables
  `SeTakeOwnershipPrivilege`.
- A standard user may temporarily alter user-owned hook files. The guarantee is
  bounded detection and repair, not an impossible zero-time tamper window.
- An SCM `SC_ACTION_RESTART` already queued for a failed service is not treated
  as canceled by a later stop. Servicing and recovery remain disabled for a
  complete fresh drain interval before any service becomes startable.
- `-NoStart` is a staged-disabled state, not permission to call SCM directly.
  Activation is a complete lifecycle transaction with a fresh guardian gate.
- Target-owned managed reads are bounded independently of a prior metadata
  check. Managed helper downgrade preservation is disabled so an attacker
  cannot pin arbitrary bytes with a synthetic newer schema marker. The
  historical downgrade rule remains unchanged outside managed enterprise.
- Non-managed modes retain the existing auto-heal owner and behavior.
- Loopback is transport locality, not server identity. Managed hooks require
  both scoped authentication and an exact SCM-gateway peer-PID match.
- Application-control attestation is an optional posture signal, independent
  of managed-hook installation and reconciliation. Its absence does not make
  an otherwise healthy Codex target incomplete.
- Application control, structural Claude policy health, and live Claude
  effective-policy evidence are three distinct facts. Initial install cannot
  infer the third from either of the first two.
- A core-only certification run may prove `core_hardening_complete`, but it
  cannot persist production Claude evidence or claim `security_complete`.
- Supported Codex clients use the protected machine policy to invoke the shared
  `defenseclaw-hook.exe`. An enterprise may additionally use application
  control to restrict which client versions or binaries can start.
- Machine and service environments never carry `CODEX_HOME`; the disposable
  certification home is process-local to the actual Codex child.
- Uninstall is surgical. It removes DefenseClaw-owned leaves or restores
  recorded preimages and preserves shared vendor parents and unrelated policy.
- A committed uninstall or partial purge remains self-authenticating and
  retryable after either managed root is absent. Retry must not recreate the
  Program Files tree or depend on metadata already selected for deletion.
- Installed-CLI uninstall removes every machine command reference before
  retiring the executable tree. Its protected finalizer tolerates a bounded
  sharing violation and retains authenticated retry evidence until the exact
  retired tree is gone; it never leaves a broadly authorized retirement
  sibling. Already-running enterprise clients must reload after teardown.
- `-AllowUnsigned` is not a production compatibility mode. It cannot cross the
  exact disposable certification name/root grammar and is never forwarded to
  non-install lifecycle actions.
- The certification home is an unsigned-scope marker, not an implicit
  privilege or completeness mode. Core-only certification requires a distinct
  transaction-bound flag and cannot be combined with Codex enrollment or
  production attestations.

## Residual risks and deployment dependencies

1. A user can continuously race repairs to files that the user necessarily
   owns. The guardian provides bounded eventual recovery and truthful health,
   not simultaneous immutability. Endpoint policy can remove this gap where a
   vendor supports machine-managed hooks.
2. A target without an active, safe WTS token cannot be repaired. The guardian
   records failure and retries rather than writing the profile as LocalSystem.
3. Application control and vendor MDM/GPO policy are optional defense-in-depth
   controls, not features DefenseClaw can synthesize. Their absence does not
   block managed-hook readiness, but leaves the user-owned hook race described
   above as a residual risk. If an enterprise claims these controls, it must
   certify them independently.
4. Local port squatting cannot forge an allow verdict because the connected
   peer PID must be the exact SCM gateway PID, but it can still deny
   availability. Target-owned file reads and comparisons are bounded, and an
   authorized oversized runtime leaf is quarantined for repair, but disk-full,
   handle exhaustion, continuously generated new data, and broader endpoint
   resource starvation remain availability residuals. SCM recovery, monitoring,
   and endpoint resource controls reduce but do not eliminate them.
5. A target can deny access to or replace its entire OS profile root, or create
   a wrong-owner obstruction that the target token cannot safely remove.
   DefenseClaw deliberately fails health rather than taking ownership or
   rewriting broad Windows/OneDrive/enterprise profile ACLs. Endpoint profile
   policy and monitoring must treat this broader self-denial as an endpoint
   availability event.
6. A removed target may retain an old connector-scoped hook credential until
   that connector token is rotated and remaining enabled targets are
   reconciled. The credential cannot authorize management or another
   connector's route, but decommission procedures must rotate it rather than
   relying only on manifest removal.
7. Static policy inspection cannot prove effective client behavior. Fleet
   acceptance must include real approved Codex and Claude invocations against
   the deployed policy stack and require managed hook contact or a blocked
   operation. Stock Codex 0.144.3 currently fails this requirement.
8. An elevated administrator can disable or replace the deployment. Restrict
   local-administrator membership and audit lifecycle activity.
9. Authenticode establishes publisher integrity, not rollout intent. Enterprise
   software distribution should pin approved versions and hashes.
10. A client process can cache the enterprise Program Files hook command before
    an administrator decommissions DefenseClaw. Because purge intentionally
    removes that binary, the old process may report a hook-launch failure.
    Decommission procedures must close or restart Codex and Claude; only a
    fresh-process no-policy result is certified. Ordinary per-user mode keeps
    its separate stable-launcher tombstone behavior.

## Certification gate

Release acceptance requires all of the following against the same built
artifacts:

- focused and repository-wide automated tests;
- PowerShell 5.1 and PowerShell 7 parser and execution tests;
- an elevated install/upgrade/repair/status/verify/uninstall lifecycle;
- exact standard-user SCM, registry, filesystem, token, and CLI denial probes;
- active medium-user hook deletion/modification and measured auto-heal;
- a disposable non-managed-mode hook tamper followed by exact legacy
  auto-heal, with no enterprise service or machine-policy mutation;
- junction/path-escape/foreign-owner/unsafe-DACL negative tests;
- target-owner self-denial, exact OWNER RIGHTS DACL, and outside-sentinel
  hard-link tests;
- unsigned-bootstrap positive certification scope plus production-default and
  near-miss rejection tests;
- stale, partial, duplicate, malformed, and removed-target authorization tests;
- exact disabled/removed-account native-policy de-enrollment followed by a
  stale-SID runtime-inert denial;
- hostile and permissive pre-created predictable lock objects, plus protected
  file-lock tamper and bounded acquisition behavior;
- injected failed-upgrade rollback with before/after equality;
- latent queued-restart and activation-phase crash injection proving a fresh
  disabled/stopped drain and guardian-first recovery on every retry;
- committed-uninstall and partial-purge crash injection proving authenticated,
  idempotent retry without recreating the install tree;
- installed-CLI purge while a standard user holds the approved hook without
  delete sharing, proving immediate canonical-root/service/policy removal,
  valid CLI JSON/pipe EOF while the no-handle-inheritance helper remains
  pending, protected retry evidence, bounded post-release finalization, and no
  retired sibling/environment/helper/receipt leak;
- four forced crashes per service, a clean-stop non-recovery interval, and
  standard-user service-process/token handle denial probes;
- an exact-port fake-allow listener plus service restart race proving zero
  authenticated requests and fail-closed hook behavior;
- explicit unregistered-SID managed-hook denial;
- machine Codex policy tamper/ACL/state auto-heal and surgical Codex/Claude
  uninstall/preimage restoration;
- application-control process-creation tests for approved, old signed, and
  custom unsigned clients;
- real Claude 2.1.207 user/project precedence runs and a real Codex hostile
  shell run; Codex passes only with managed hook contact or a blocked
  operation, never merely because the fake shell executable was blocked;
- a phase-one incomplete Install followed by a manifest-bound
  `Repair -AttestClaudeEffectivePolicy` only after the live Claude proof;
- evidence inspection and proof that disposable services, users, roots, and
  user-profile fixtures were restored or removed;
- authenticated, PID-bound active-user result capture with no trusted
  user-writable completion or output files;
- a final security scan of the resulting implementation.

Any skipped destructive probe, unsupported PowerShell runtime, failed cleanup,
or unexplained test failure leaves certification incomplete.
