# Windows managed-enterprise threat model

This is the Windows part of the [enterprise threat model](ENTERPRISE-THREAT-MODEL.md).
The cross-platform document defines the two enterprise profiles, the trust
zones Z0–Z5 and the boundary table; this document carries the Windows threat
rows `W-01`…

## Review scope

- Repository: `defenseclaw`
- Review target: the native Windows managed-enterprise services, lifecycle
  commands, protected state, per-user hook reconciliation, vendor machine
  policy, and the certification harness, in both enterprise profiles:
  - `secure_client` — installed by Cisco Secure Client; in production and
    unchanged by the standalone work;
  - `standalone` — installed by any MDM or an administrator, without Secure
    Client.
- A certification record must name the exact tree hash it built and tested.
  This document does not pin a commit.
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

Rows `W-01`…`W-42` describe controls shared by both profiles unless a row
names one. Rows `W-43` and later cover the standalone profile.

## Security objectives

The Windows deployment must provide the same security properties as the Linux
and macOS managed-enterprise deployments, expressed in Windows-native terms:

1. A standard local user cannot stop, pause, reconfigure, delete, or replace
   any production SCM service. The Secure Client profile has five:
   `DefenseClawGateway`, `DefenseClawCMIDBroker`, `DefenseClawSensorHelper`,
   `DefenseClawHookGuardian`, and `DefenseClawHookEnumerator`. The standalone
   profile has the same services without `DefenseClawCMIDBroker`.
2. A standard local user cannot change the protected executable, managed
   configuration, mode pin, target manifest, service definition, or guardian
   authorization ledger.
3. The gateway has only the filesystem and token privileges required for its
   runtime. It cannot modify the guardian manifest or authorization ledger and
   cannot write arbitrary interactive-user profiles.
4. Enrollment authority and hook mutation are separated. The LocalSystem
   enumerator maintains the protected target manifest from eligible profiles
   and the protected connector policy. The LocalSystem guardian repairs only
   enabled rows in the authenticated manifest. Content, rename, quarantine,
   and deletion operations run with an active token whose user SID exactly
   matches the manifest SID. The only process-token exception is a DACL-only
   recovery path for an already target-owned object whose self-denying ACL
   prevents the target token from repairing it.
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
10. A `defenseclaw-hook.exe` verdict is accepted only from the exact live SCM
    gateway process. A same-user listener that wins the configured loopback
    port cannot return a forged allow verdict to it. The Amp plugin and the
    per-user OpenCode plugin call the gateway themselves (W-55) and send
    neither the credential nor the payload until the listener proves it can
    derive the user's credential (W-25); that proof is a separate request
    and does not cover a listener that replaces the gateway before the
    hook request (residual 5).
11. Enrollment is automatic for an eligible interactive profile and connector
    when the enumerator discovers a supported CLI/version. Existing manifest
    rows retain their protected `enabled`, `deferred`, and version state. A SID
    that is not yet present in protected enrollment state gets no shared
    credential and its managed hook invocation fails closed with a stable
    enrollment diagnostic.
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
14. Secure Client profile: the restricted gateway cannot load or call the
    machine credential provider directly. Only `DefenseClawCMIDBroker` may
    access the pinned provider, and its bounded local IPC contract
    authenticates the exact live gateway service identity and
    cryptographically binds each response to its request.
15. Standalone profile: no Secure Client component is loaded or trusted. The
    gateway runs the local policy engine and reads the optional Cisco AI
    Defense API key only from a protected credential; a missing or failing
    key leaves the local verdict in force.
16. Standalone profile: a normal user cannot disable DefenseClaw's hooks
    through vendor settings. Codex always runs with its vendor
    managed-hooks-only lock. The Claude Code drop-in sets
    `allowManagedHooksOnly` under the default `managed_hooks_only: enforce`,
    so user and project Claude Code hooks do not run; with `preserve` the
    foreign-hook guard covers Claude Code instead. Connectors without a
    vendor lock are covered by the foreign-hook guard.

## System and trust boundaries

### Zones

| Zone | Secure Client profile | Standalone profile |
| --- | --- | --- |
| Z0 Trusted platform and administrator | SCM, LSA, Administrators, Secure Client running `DefenseClawSetup-Enterprise-x64.exe` elevated | SCM, LSA, Administrators, the MDM agent as SYSTEM (for example the Intune Management Extension) running `DefenseClawSetup-Enterprise-Standalone-x64.exe /ensure` or `defenseclaw.exe enterprise windows ensure` |
| Z1 Privileged DefenseClaw services | `DefenseClawCMIDBroker` (LocalSystem, `SeChangeNotifyPrivilege` only); `DefenseClawSensorHelper` (LocalSystem, `SeChangeNotifyPrivilege` only); `DefenseClawHookGuardian` and `DefenseClawHookEnumerator` (LocalSystem, explicit privilege list) | Same without the broker |
| Z2 Restricted gateway | `NT SERVICE\DefenseClawGateway`, restricted service SID | Same |
| Z3 Administrator-owned state | `C:\Program Files\Cisco\Cisco Secure Client\DefenseClaw`, `C:\ProgramData\Cisco\Cisco Secure Client\DefenseClaw`, `%ProgramData%\OpenAI\Codex`, `C:\Program Files\ClaudeCode`, `%ProgramData%\Cursor` | `C:\Program Files\Cisco\DefenseClaw`, `C:\ProgramData\Cisco\DefenseClaw` (including `secrets\`), the same vendor machine-policy roots plus `%ProgramData%\GitHub\Copilot\policy.d` |
| Z4 User session (untrusted) | The AI agent, `defenseclaw-hook.exe` running as the user, per-user registrations and scoped tokens | Same, plus the foreign-hook guard in the hook |
| Z5 External | Cisco AI Defense through the Secure Client Cloud Management identity; managed telemetry | Cisco AI Defense with an API key (optional), judge, telemetry, the MDM cloud |

```mermaid
flowchart TB
  subgraph Z0["Z0 · Trusted platform and administrator"]
    MDM["Secure Client or MDM agent<br/>SYSTEM"]
    LC["Setup /ensure · enterprise windows"]
    MDM --> LC
  end
  subgraph Z1["Z1 · Privileged services (LocalSystem)"]
    BRK["DefenseClawCMIDBroker<br/>Secure Client only"]
    SNS["DefenseClawSensorHelper"]
    GRD["DefenseClawHookGuardian"]
    ENM["DefenseClawHookEnumerator"]
  end
  subgraph Z2["Z2 · Restricted gateway"]
    GW["DefenseClawGateway<br/>NT SERVICE virtual account"]
  end
  subgraph Z3["Z3 · Administrator-owned state"]
    CFG["ProgramData config · policies · secrets"]
    LED["targets.yaml · authorization ledger"]
    VP["Codex · Claude · Cursor · Copilot machine policy"]
  end
  subgraph Z4["Z4 · Interactive user (medium integrity)"]
    AG["AI agent"]
    HK["defenseclaw-hook.exe"]
    UF["Profile hook files · scoped token"]
  end
  LC -->|"SCM · protected DACLs"| Z1
  ENM -->|"ProfileList → eligible rows"| LED
  GRD -->|"impersonated target token"| UF
  GRD -->|"owned entries"| VP
  GRD -->|"authorize"| LED
  AG -->|"loads"| VP
  AG --> HK
  HK -->|"peer PID = SCM gateway PID"| GW
  GW -->|"read-only"| CFG
  BRK -->|"HMAC named pipe"| GW
  SNS -->|"fixed IPC"| GW
```

### Service detail (Secure Client profile)

The standalone profile has the same tree without `DefenseClawCMIDBroker`;
its gateway does not depend on a broker and never loads a credential
provider.

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
  |-- SCM: DefenseClawGateway
  |        DefenseClawCMIDBroker (Secure Client profile only)
  |        DefenseClawSensorHelper
  |        DefenseClawHookGuardian
  |        DefenseClawHookEnumerator
  |
  +--> DefenseClawSensorHelper
  |      identity: LocalSystem; only ChangeNotify retained
  |      exposes: fixed, fieldless acquisition requests to the gateway
  |      the gateway has an SCM dependency on it
  |
  +--> DefenseClawCMIDBroker
  |      identity: LocalSystem; only ChangeNotify retained
  |      reads: protected broker key and pinned credential provider
  |      exposes: protected local named pipe to the exact live gateway SID/PID
  |      writes: broker log only
  |
  +--> DefenseClawGateway
  |      identity: NT SERVICE\DefenseClawGateway, restricted service SID
  |      depends on: DefenseClawSensorHelper; DefenseClawCMIDBroker
  |                  (Secure Client profile)
  |      reads: protected config and guardian authorization
  |      writes: runtime tokens/state and gateway log only
  |
  +--> DefenseClawHookGuardian
  |      identity: LocalSystem with an explicit privilege allow-list
  |                Tcb, Impersonate, ChangeNotify, Backup, Restore
  |      reads: protected config and enumerator-maintained manifest
  |      writes: protected authorization and guardian log
  |      |
  |      +--> exact active-session target token
  |      |      writes/verifies that SID's declared user-home footprint
  |      |
  |      `--> dedicated short-lived privilege thread
  |             DACL-only, no-follow handle walk for target-owned objects;
  |             never rewrites the profile root and never takes ownership
  |
  `--> DefenseClawHookEnumerator
         identity: LocalSystem with the guardian privilege allow-list
         reads: protected config, HKLM ProfileList, existing manifest
         writes: protected target manifest and shared guardian/enumerator log
         grants: gateway Read+Execute on a fixed set of inventory dotdirs
                 for manifest-enrolled profiles, not on whole profiles

Interactive standard user / agent process
  |-- may read installed public executables
  |-- may edit or delete files the user owns
  |-- may call loopback hook endpoints with its own credential (standalone:
  |      bound to the user's SID; Secure Client: connector-scoped, residual 18)
  |      only when the connected peer PID is the live SCM gateway PID, or,
  |      for the standalone OpenCode and Amp plugins, after the listener
  |      proves it can derive that credential
  `-- has query-only SCM access
```

The administrator and LocalSystem are trusted deployment authorities. A
compromised or malicious administrator is outside this model. The gateway is
not an administrator authority even though it is a machine service. The broker
(Secure Client profile) has a deliberately narrow provider/IPC role; the
sensor helper answers only fixed acquisition requests; the enumerator is the
continuing enrollment authority; and the guardian is the per-user repair
authority.

## Assets

| Asset | Required property |
|---|---|
| Broker (Secure Client), sensor helper, gateway, guardian/enumerator host, and hook executables | Administrator-owned, non-reparse, no untrusted writer, recorded integrity |
| Installer and module | Trusted before elevated execution; protected after installation |
| Managed `config.yaml` | Administrator-controlled, mode pinned, no runtime downgrade |
| Protected target manifest | Enumerator-maintained enrollment state; authenticated administrator/System ancestry and exact file DACL; bounded regular-file/link/schema checks; atomic replacement; connector eligibility comes from protected config |
| SCM service objects and registry configuration | Every exact production service of the profile is administrator-owned; standard users have query-only access; image, account, dependencies, privileges, environment, start, recovery, and SDDL are verified |
| Broker authentication key, pipe, and provider binding (Secure Client) | Exact broker/gateway/pipe identity tuple; gateway read-only key access; LocalSystem and exact gateway SID only on the local pipe; pinned trusted provider library |
| Guardian authorization ledger | LocalSystem/Administrators write; exact gateway service SID read-only |
| Gateway runtime and scoped tokens | Administrators/LocalSystem and exact gateway service SID only; no standard-user read |
| Per-user hook footprint | Confined to the manifest SID's canonical profile; exact protected OWNER RIGHTS DACL; regular files have one NTFS link; repairable after target-user tamper |
| Inventory-directory grants | Exact gateway service SID receives inheritable Read+Execute/Traverse only on the fixed inventory-dotdir set beneath unique manifest homes; existing non-null DACLs are merged, missing directories are retried, and per-directory failures are logged |
| Codex machine requirements | Exact `%ProgramData%\OpenAI\Codex\requirements.toml`, ten managed hook groups, protected ownership/ACL preimage records, and guardian-repaired enrollment state |
| Claude Code managed policy | DefenseClaw-owned protected drop-in and ownership state; effective precedence verified with the real approved Claude client |
| Agent application-control attestation | Protected schema-v2 evidence for approved-client rules and Claude effective-policy verification |
| Standalone AI Defense credential | `C:\ProgramData\Cisco\DefenseClaw\secrets\<name>`; exact DACL: SYSTEM and Administrators full control, the gateway service SID read, nobody else |
| Standalone registration | `HKLM\SOFTWARE\Cisco\DefenseClaw\Enterprise` marker, the Add/Remove Programs entry, the `DefenseClaw Enterprise` event source and `%WINDIR%\Logs\DefenseClaw\enterprise-lifecycle.log`; advisory only, never an authority |
| Broker, gateway, and guardian/enumerator logs | Separate ACL domains keep the less-trusted gateway from altering LocalSystem guardian/enumerator evidence; the enumerator shares the guardian log rail |

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
4. It persists a servicing intent, disables and stops every managed SCM
   service of the profile, and holds that state through a fresh bounded drain of any already
   queued SCM failure restart before mutating protected files or service
   definitions.
5. It snapshots the owned deployment, stages same-volume replacements, applies
   protected DACLs, creates or repairs `DefenseClawGateway`,
   `DefenseClawSensorHelper`, `DefenseClawHookGuardian`,
   `DefenseClawHookEnumerator` and, in the Secure Client profile,
   `DefenseClawCMIDBroker`, and pins each service's image, identity,
   dependencies, privileges, environment (including the
   `DEFENSECLAW_DEPLOYMENT_MODE` and, for standalone,
   `DEFENSECLAW_ENTERPRISE_PROFILE` pins), recovery policy, and DACL.
6. It verifies exact static postconditions while every service remains
   disabled. Activation demand-starts the broker first (Secure Client
   profile), then the guardian and a fresh successful reconcile while the
   gateway remains disabled. It next starts the gateway (SCM starts the
   sensor helper first as a dependency) and then the enumerator, proves full
   readiness, and only then promotes every service to automatic start. An
   interrupted activation re-enters a fresh disable/stop/drain cycle.
7. `-NoStart` deliberately commits a disabled, stopped deployment. Only a
   complete later `Repair` without `-NoStart` may activate it; raw service
   starts are not an activation API. Failure rolls back and returns non-zero.

### Credential request (Secure Client profile)

1. `DefenseClawGateway` selects the broker only when the protected service
   environment supplies the complete broker service, gateway service, local
   pipe, and authentication-key tuple. Partial configuration fails closed and
   cannot fall back to in-process provider loading.
2. `DefenseClawCMIDBroker` verifies that it is the exact active LocalSystem SCM
   process for its configured service and that the pinned provider path remains
   trusted. Its service token retains only `SeChangeNotifyPrivilege`.
3. The pipe DACL grants LocalSystem full access and the exact gateway service
   SID read/write. For each connection, the broker also impersonates the pipe
   client to verify that SID and matches the pipe-client PID to the currently
   running gateway PID reported by SCM.
4. Requests and responses use bounded strict messages, one-use nonces, bounded
   operation time, and a protected 32-byte key. The gateway accepts a response
   only when its nonce and HMAC match the request.

### Standalone credential and inspection

1. The standalone gateway resolves the Cisco AI Defense API key named by
   `enterprise.inspection.ai_defense.credential` only from
   `C:\ProgramData\Cisco\DefenseClaw\secrets\<name>`, after the trusted-path
   check and an exact reader-DACL check (SYSTEM and Administrators full
   control, the gateway service SID read-only, no other ACE). The value is a
   bounded single line and is never logged.
2. An inline `cisco_ai_defense.api_key` in the managed config is rejected,
   and `api_key_env` is ignored, so a user environment cannot supply a key.
3. With no key, an untrusted key file, or while AI Defense is unreachable,
   the local engine's verdict stands. `enterprise windows status` reports
   `inspection.local` as `active`. It reports `inspection.ai_defense` as
   `disabled` when `enterprise.inspection.ai_defense.enabled` is false, and
   otherwise as `unavailable:gateway_not_ready` until the gateway is ready and
   `ok` after that. The status does not prove that the key is present or
   valid.

### Enumerator enrollment and inventory access

1. `DefenseClawHookEnumerator` loads the protected `managed_enterprise` config,
   walks HKLM ProfileList, and filters to valid interactive user SIDs with
   absolute existing profile directories and reparse-free profile ancestry.
   The Secure Client profile accepts local and domain `S-1-5-21-...` SIDs; the
   standalone profile also accepts Microsoft Entra ID `S-1-12-1-...` SIDs
   through one interactive-user predicate. Well-known/service SIDs,
   bare-domain SIDs, duplicate stale rows,
   invalid homes, and explicitly excluded SIDs are dropped.
2. Connector families come from protected guardrail config and are reduced to
   the Windows managed-hook set. For a previously known `(SID, connector)` row,
   the enumerator preserves the protected `enabled`, `deferred`, and
   `agent_version` state. A new row is enabled automatically only when the
   profile has a discoverable supported CLI/version; otherwise it is omitted
   and the reason is logged.
3. Before publication, the enumerator authenticates the committed manifest's
   ancestry, exact administrator-file descriptor, regular-file/link identity,
   and schema. It stages the new manifest under the same contract and replaces
   it atomically only when bytes change. Trust drift fails closed and leaves the
   committed generation untouched.
4. After publication, the enumerator resolves the exact gateway service SID and
   considers only the fixed inventory-dotdir catalog beneath each unique
   manifest home. For each existing directory with a non-null DACL, it merges
   one inheritable gateway Read+Execute/Traverse ACE. It does not grant access
   to the whole profile or rewrite the profile-root DACL.
5. Missing inventory directories are skipped and retried next cycle. A
   per-directory DACL error is categorized and logged without blocking other
   targets, so enrollment can succeed while inventory coverage is incomplete;
   operators must monitor these warnings.

### Guardian reconcile

1. The LocalSystem guardian validates the protected config, manifest, runtime,
   and explicit Windows target fields.
2. It resolves an active WTS session and queries its user token.
3. It rejects a SID mismatch, service identity, or missing active session.
   Full-integrity / elevated / high-integrity / UIAccess tokens are
   permitted with an advisory ("elevated target relaxation" — see
   below); enrollment proceeds and the reconcile loop's tamper-recovery
   provides best-effort protection.
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

1. A user-owned hook reads only its own credential. In the standalone profile
   the guardian derives it for that user's SID from a per-machine key the
   user never sees; in the Secure Client profile it is connector-scoped.
2. The request goes to a loopback-only endpoint and names its connector scope.
3. Before sending a request, the managed hook resolves the exact running
   gateway PID from SCM and verifies that the connected loopback peer PID is
   that same process. A missing, stopped, changed, or mismatched PID is a
   fail-closed result. The standalone hook applies the same check, and before
   the call it also runs the foreign-hook guard (W-50). The standalone
   OpenCode and Amp plugins call the gateway from the agent's own runtime and
   cannot compare PIDs. Before each request they send only the credential's
   SHA-256 and a fresh nonce to `/api/v1/hook-listener-proof` and require an
   HMAC over the nonce keyed by their credential, which only the gateway can
   derive. Any other answer is handled like an unreachable gateway (managed
   plugins fail closed), and neither the credential nor the payload is sent.
   The proof and the request are separate loopback requests, and nothing
   binds the request to the connection that passed the proof. A holder that
   takes the port between them receives that request's credential and
   payload, and the plugin accepts its verdict. That needs the gateway to
   release the port in that interval (an administrator or upgrade restart)
   and the request to open a new connection instead of reusing the pooled
   one (residual 5).
4. Constant-time token comparison authorizes only that connector's hook or
   notification route. In the standalone profile the gateway accepts only a
   credential bound to a SID the authorization ledger protects, attributes
   the request to that SID, and refuses (403) identity headers that name
   another user; connector-wide credentials are not accepted.
5. Management, status, configuration, policy, scan, and cross-connector routes
   reject the scoped credential.
6. A managed invocation from a SID absent from protected enrollment state
   fails before it can use another user's token or contact an unauthenticated
   listener.

## Threat analysis and required controls

| ID | Threat / attack path | Required control | Required evidence |
|---|---|---|---|
| W-01 | Standard user calls SCM stop, pause, user-control, config, failure, SDDL, or delete | Protected service DACL with only query/interrogate rights for `BU`; protected service registry configuration on every exact production service of the profile | Exact non-admin `sc.exe` probes return access denied for `DefenseClawGateway`, `DefenseClawSensorHelper`, `DefenseClawHookGuardian`, `DefenseClawHookEnumerator` and, in the Secure Client profile, `DefenseClawCMIDBroker`, which remain unchanged/running |
| W-02 | User replaces an executable, script, config, manifest, metadata, or ledger | Fixed local NTFS roots; no reparse points; trusted owner and ancestor chain; protected DACLs; content hashes/signatures | Write/delete/rename/ACL probes fail; verify catches byte or ACL drift |
| W-03 | Elevated CLI executes a user-planted PowerShell or installer/module, or gives elevated PowerShell a shared user-writable temp/cache/home root | Resolve the system PowerShell by OS API; ignore `PATH` and poisoned known-folder environment variables; trust-check installer and adjacent module before execution; atomically create a 128-bit-random child under Windows Temp with a protected System/Administrators-only owner/DACL and pin `TEMP`, `TMP`, `LOCALAPPDATA`, `APPDATA`, `USERPROFILE`, `HOME`, `HOMEDRIVE`, and `HOMEPATH` to that exact one-shot child | Poisoned `PATH`, `SystemRoot`, known-folder env, working directory, installer, module, shared-temp-parent, protected-temp-child, PowerShell module-cache location, and cleanup tests |
| W-04 | User downgrades enterprise mode through user config or environment | SCM-owned environment pins `managed_enterprise`; protected config must agree; runtime PATCH cannot change it | Config conflict and untrusted-config tests; service registry DACL test |
| W-05 | Compromised gateway edits policy or authorization | Restricted virtual service SID; separate runtime/log ACLs; config and authorization read-only; guardian log and manifest inaccessible | Effective-token/privilege and ACL matrix; gateway-write attempts fail |
| W-06 | LocalSystem follows a user junction or path race and writes outside the profile | Explicit SID/home binding; reject reparse chains; every user mutation under target impersonation; revalidate immediately before mutation; no LocalSystem fallback | Outside sentinel remains unchanged across junction, owner, and swap tests |
| W-07 | Guardian binds the wrong session identity, or silently treats an elevated target as equivalent to the ordinary medium-integrity posture | Exact SID/session binding plus explicit elevation, integrity, and UIAccess classification; elevated targets proceed only under the documented administrator trust assumption with a rate-limited advisory | Unit tests, active medium-token certification, and an elevated-target run that records the advisory without changing SID/home binding |
| W-08 | Failed `RevertToSelf` leaks an impersonated thread into the Go scheduler | Dedicated locked OS thread; unlock only after successful revert; terminate/discard the thread or fail-stop on revert failure | Injected revert-failure test |
| W-09 | User deletes or edits a hook, token, helper, contract, or native config | Filesystem watcher plus one-minute periodic reconcile; target-token repair; content and ACL verification | Deterministic stop/tamper/unhealthy/start/restore test with measured recovery |
| W-10 | User blocks repair with an owned junction or wrong-type path object | Previously authorized targets may remove or quarantine only the exact owned obstruction while impersonated; never follow it; first install and foreign owners fail closed | Root junction/file obstruction tests; outside sentinel unchanged |
| W-11 | Predictable named mutex is pre-created and held by a standard user, or a reader holds the real transaction lock indefinitely | Codex policy transactions use the protected, no-reparse, single-link `%ProgramData%\OpenAI\Codex\.defenseclaw-managed-hooks.lock` with bounded `LockFileEx`; the retired predictable Global mutex is never opened. Lifecycle uses its independently protected file lock | Pre-create the exact retired Global name with both hostile and permissive DACLs and require zero influence. Hold the real file lock from a standard-user read handle, require bounded fail-closed verification with unchanged policy, release it, and require immediate recovery |
| W-12 | One successful target hides another target's failure | Strict schema, exact counts, no duplicates/trailing fields, `ok=false` on any failure, all configured connectors covered | Partial-failure status, verify, and gateway-health tests |
| W-13 | Old successful authorization remains valid after disablement, manifest change, guardian death, or hang | Guardian state is reconciled to the exact current protected manifest; disabled or absent rows are revoked and authorization has bounded age/future-skew checks. The enumerator preserves an existing disabled row; deleting an otherwise eligible row is not a durable exclusion because automatic discovery may publish it again | Disabled-row preservation, manifest-generation revocation, and stale/future ledger tests |
| W-14 | Service token is read by a standard user, crosses connector scope, or is used by one user to post events attributed to another | Exact gateway service SID gets runtime Modify; users get no token access; per-user token is connector-scoped, and in the standalone profile bound to the user's SID (the gateway attributes the request to that SID and refuses conflicting identity headers). The Secure Client profile does not bind the token to a SID, so cross-user attribution remains open there (residual 18) | ACL denial plus route-scope matrix; `internal/gateway/user_scoped_credentials_test.go` |
| W-15 | Upgrade failure leaves new binaries with old state or reports success | Serialized transaction, owned-deployment identity, rollback, exact postcondition verification, non-zero structured error | Injected failed-upgrade test and before/after equality |
| W-16 | Higher-precedence Claude policy disables hooks or a lower user/project `disableAllHooks` source produces a false green | Enforce and validate the documented server-managed > HKLM/MDM > Program Files > HKCU precedence; do not treat a local `90-defenseclaw.json` as sufficient evidence | Real approved Claude 2.1.207 invocation against a local no-auth Messages stub with hostile user and project `disableAllHooks`; require managed hook contact or a blocked client operation |
| W-17 | Normal installations silently change after adding enterprise support | All new enforcement branches require effective `managed_enterprise`; lifecycle install is explicit; the Windows process entry point returns before even consulting SCM service detection unless the protected installer-owned service-name marker is present; existing unmanaged hook self-heal remains active | Entrypoint seam proves the SCM detector and service executor are never called without the marker; full mode matrix, pre-install no-machine-mutation proof, and a disposable normal-mode hook deletion/replacement followed by exact live auto-heal |
| W-18 | Target owner uses implicit `WRITE_DAC`, an OWNER RIGHTS ACE, or `WRITE_OWNER` to make a permissive/irreparable managed object | Exact protected canonical DACL: files have four direct ACEs; directories have direct OWNER RIGHTS plus direct and OI/CI/inherit-only target, System, and Administrators ACEs (seven total). OWNER RIGHTS gets only `READ_CONTROL`; target gets required read/write/execute/delete rights but no `WRITE_DAC`/`WRITE_OWNER`; System and Administrators get full control. LocalSystem recovery is DACL-only and requires exact owner | Exact ACE mask/inheritance tests for both object types, self-deny recovery, ordinary write/atomic-replace compatibility, owner/DACL tamper repair |
| W-19 | Target replaces a regular footprint file with an NTFS hard link to a file outside its profile | Require a handle-observed link count of exactly one before accepting a regular file; quarantine only the in-profile link under the target token; rollback uses no-follow/atomic replacement | Outside-sentinel hard-link repair and forced-rollback tests |
| W-20 | Standard user terminates, suspends, injects into, changes security on, or duplicates a dangerous handle from any managed service process | Service/process token and object DACLs; restricted gateway service SID; no standard-user process or token mutation handles | Explicit OpenProcess, OpenThread, process-DACL/owner, token-duplicate/impersonate/adjust, taskkill, and PID-continuity probes for every service process of the profile |
| W-21 | A managed service exits once recovery actions are exhausted, or a planned stop races automatic recovery | Every managed service uses three restart delays with the final action repeated indefinitely; unexpected command exits terminate the host as a base SCM failure; accepted Stop/Shutdown is graceful and returns cleanly | Four consecutive forced terminations for each service plus a clean stop held beyond the longest recovery delay |
| W-22 | User-controlled loader environment, shared temp/cache/home content, PowerShell function, module, or preloaded helper type hijacks elevated lifecycle code | Fixed System32 PowerShell, strict environment/working directory, one unique protected directory for every writable temp/cache/home variable, pre-import module trust, module-qualified built-ins, randomized retained native-helper type | Poisoned loader/environment/module/function/type smokes, PowerShell ModuleAnalysisCache containment, and protected one-shot-directory ACL/use probes in Windows PowerShell 5.1 and PowerShell 7 |
| W-23 | Authorization remains green with an extra removed/disabled target | Healthy status and verify require exact target-set equality, strict schema/counts, no duplicates, same reconcile identity, and freshness | Extra/stale/removed target tests for status, verify, and gateway readiness |
| W-24 | A caller uses `-AllowUnsigned` with production names/roots, a near-miss certification scope, an action outside the lifecycle, or implicit core-only semantics to import or deploy untrusted code | Before module import, accept unsigned artifacts only for the seven lifecycle actions (`Install`, `Upgrade`, `Repair`, `Reconcile`, `Status`, `Verify`, `Uninstall`) and only with exact case-sensitive same-id certification service names, exact same-id Program Files/ProgramData certification roots, and a required same-id certification CODEX_HOME basename. Select core-only behavior through a separate explicit flag that is valid only for `Install`/`Upgrade`/`Repair`, requires the same scope, rejects production attestations and Codex targets, and is bound into transaction recovery; retain all fixed-NTFS, no-reparse, owner, and DACL source checks. The standalone profile's hash-pinned trust (W-45) is a separate production mode, not an extension of this switch | Bootstrap, module, public-CLI, recovery, and live-harness matrix tests: full unsigned uses home/no-core, Claude-only uses home/core, signed production and read-only use neither; negative production, mismatched-id, case-near-miss, nested-root, CODEX_HOME-near-miss, and flag-combination assertions |
| W-25 | A standard-user fake listener wins the exact API port and returns a valid allow response while the gateway is stopped or restarting | For `defenseclaw-hook.exe`, bind hook trust to both the user's credential and the connected server PID; the PID must equal the exact current SCM gateway PID, not merely any process listening on loopback. The standalone Amp plugin and the per-user OpenCode plugin, which cannot read the PID, require the listener proof before sending the credential or payload; the proof is not bound to the request that follows (residual 5). The Codex and Claude Code OTLP exporters verify nothing (residual 5) | Stop/crash the gateway, bind the exact port as a non-admin, return valid allow JSON, and race service restart; the hook must deny/fail closed and the fake listener must observe zero authenticated requests; `internal/gateway/connector/plugin_listener_proof_test.go` for the plugins |
| W-26 | Codex managed-hook configuration is removed, redirected, or bypassed | Protect the machine requirements and enrollment state with administrator-owned ACLs, verify the exact ten-event policy, and require end-to-end managed-hook contact or a blocked operation in certification | Invoke the approved Codex client against a bounded local provider and require SessionStart/UserPromptSubmit audit evidence or a causal block |
| W-27 | An old officially signed or custom unsigned agent avoids a newer managed-hook contract | When an enterprise opts into application control, allow only approved signed clients at or above the minimum versions. The hook-contract floors are the source of truth: `cli/defenseclaw/inventory/hook_contracts.json` (mirrored in `internal/gateway/connector/hook_contract.go`) currently starts Codex at 0.124.0, Claude Code at 2.1.154, Cursor at 2.4.0 and Copilot at 1.0.18. The Secure Client installer's own minimums in `internal/enterprisehooks/install_windows.go` (Codex 0.131.0, Claude Code 2.1.152, Cursor 1.7.0) differ from the contract table; the standalone profile takes its floors from the contract table. Certification records the floors of the tested build rather than this document | In the optional application-control profile, approved clients start and explicitly supplied old signed Codex/Claude and custom unsigned lookalikes fail process creation with an application-control denial |
| W-28 | An unregistered interactive SID invokes the installed managed hook or reuses another target's state | Exact SID membership in protected connector enrollment state is checked before token use; absence is fail-closed and diagnostic | Run the installed managed hook under a temporary non-admin SID absent from the manifest; require non-zero, causal enrollment text, and byte/security-exact user trees |
| W-29 | A user removes or weakens Codex machine requirements/enrollment state | Administrator-owned protected DACLs, private ownership/ACL-preimage records, hidden read-only verify, and guardian reconciliation of the exact ten-event canonical document | Standard-user write/delete/DACL attempts fail; administrator-injected deletion, DACL drift, event removal, and state removal are unhealthy until exact auto-heal |
| W-30 | Uninstall removes a shared vendor tree, another administrator's setting, or a value that changed after install | Record exact ownership and preimages; remove/restore only a current value still equal to the DefenseClaw-owned postimage; preserve shared parents and unrelated content | Install over absent and preexisting shared parents, mutate unrelated values, uninstall and purge, then compare preserved parents/preimages and require only owned Codex/Claude wiring to be absent |
| W-31 | A certification-only `CODEX_HOME` leaks into the machine environment or a managed service and changes production behavior | Treat `-CertificationCodexHome` only as an exact unsigned-scope marker and pass it solely to a disposable actual-Codex child; machine, coordinator, and every managed-service environment omit `CODEX_HOME` | Before/after machine-environment snapshot, every service registry environment inspection, hostile `USERPROFILE` decoys, and exact cleanup of the alternate child without enumerating or mutating live `.codex` |
| W-32 | A disabled, removed, or deleted-account SID remains enrolled in native machine policy and can keep invoking the hook | Reconcile authorization and native connector state to exact enabled-manifest equality. Remove the final owned Claude policy/state transactionally, retain any per-user runtime only as inert data, and reject the stale SID before credential use | Disable the only Claude row (and repeat with an unavailable account/profile), reconcile, require exact zero Claude authorization and absent owned machine policy/state, then invoke as the former SID and require a causal non-enrollment failure with no audit event |
| W-33 | Valid application-control evidence is reused as proof that Claude's managed hooks are effective | Keep client process control and effective Claude policy as independent fields and transactions. Structural files, hashes, owners, and DACLs cannot set the effective-policy field | Preserve byte-exact application-control evidence while deleting the Claude policy and require effective-policy health to fail independently; run the real client with hostile precedence before accepting a separate manifest-bound Claude attestation |
| W-34 | Install, a core-only test, or stale evidence claims production security before a live Claude run against the current manifest | Initial install always leaves Claude effective-policy and aggregate security incomplete. Only production `Repair -AttestClaudeEffectivePolicy` after the live hostile-precedence proof may persist schema-v2, manifest-hash-bound evidence; core certification forbids persistence | Assert phase-one Install/Status/Verify remain incomplete, run the real Claude proof, perform the attested Repair, then require aggregate completion. Change the manifest or use `-ClaudeOnly` and require the claim to be absent/incomplete |
| W-35 | Target races a validated token, sidecar, contract, helper, or hook artifact into a huge sparse file, reparse point, hard link, or changing same-name object while the guardian reads it | Managed-only stable handle readers with no-reparse/single-link validation and format-specific byte ceilings; constant-memory double-pass artifact hashing; managed helpers always overwrite exact embedded bytes; authorized oversized regular obstructions are quarantined and recreated under the target token | One-TiB sparse exact-compare test; managed token/sidecar/contract/digest bounded-read tests; managed-versus-unmanaged helper test; authorized oversized-obstruction auto-heal with quarantine cleanup |
| W-36 | A planned stop or interrupted activation races an `SC_ACTION_RESTART` that SCM already queued, reviving a service against a partially replaced deployment or the gateway without fresh guardian evidence | Durable servicing intent; every managed service disabled before stop; fresh monotonic 65-second drain while disabled; durable activation phase that invalidates old quiescence timestamps; demand-start order broker (Secure Client profile), guardian/fresh reconcile, gateway (with its sensor-helper dependency), enumerator; readiness before every service becomes automatic; every recovery path reasserts disabled/stopped and begins a new drain | Executable latent-restart model plus crash injection before and after every activation transition in Windows PowerShell 5.1 and PowerShell 7; no managed service escapes the transaction and no gateway becomes startable before fresh guardian evidence |
| W-37 | A crash after committed uninstall or during purge removes the metadata needed to authenticate a retry, or generic dispatcher initialization recreates a deleted Program Files tree | Authenticate and route uninstall/purge recovery before generic layout creation; keep a protected tombstone/purge receipt outside the recursively deleted root until deletion succeeds; remove authentication metadata last; make committed uninstall and partial purge retries idempotent; never initialize the install tree on a tombstone path | Crash injection at each teardown, tombstone, and purge phase; retry with the install root absent and with partially deleted state; exact proof that services/policy stay removed, shared vendor parents survive, and no managed root is recreated |
| W-38 | Installed-CLI self-uninstall leaves a mapped executable, lets a user race/lock the observable retired tree, loses its only cleanup attempt to a sharing violation, or deadlocks because its detached helper inherits the CLI's captured output pipe | Remove all owned machine command references first; strip Users RX before same-volume atomic retirement; bind a protected prepared/committed receipt to exact caller creation time, file identity, hashes, tombstone, roots, and service absence; use native `CreateProcessW` with no inherited or standard handles, a fixed System32 engine, and a protected receipt-bound temp/cache/home environment; authenticate every survivor and retry bounded sharing violations while releasing the lifecycle lock between attempts; delete the isolated environment, helper, and receipt last. Require already-running clients to reload instead of retaining an enterprise launcher outside the purged root | Transaction crash injection before/after rename and receipt commit; standard-user directory-notification/locker race; captured-parent probe proves the helper remains alive after CLI pipe EOF; hold the installed hook without delete sharing through immediate post-uninstall checks, require canonical root/services/policy already absent, release it, and require exact bounded retirement with no sibling/environment/helper/receipt leak; fresh-client no-policy proof |
| W-39 | A medium-integrity user creates an unused raw `DefineDosDevice` alias to a trusted local subdirectory. The alias reports `Fixed` and `NTFS`, is absent from `subst.exe`, and redirects an elevated installer source, managed root, certification home, or impersonated profile mutation | Require exact drive-letter syntax, fixed NTFS, a volume GUID from `GetVolumeNameForVolumeMountPointW`, exact root membership in a bounded `GetVolumePathNamesForVolumeNameW` list, and one identical well-formed `QueryDosDeviceW` target for the effective drive, `Global\<drive>`, and volume GUID. Reject volume-folder mounts and every reparse ancestor. Revalidate after transaction locks and adjacent to source import/copy, managed-root mutation, certification-home use, and WTS-profile mutation | Under a real medium token, create a raw unused drive alias to a local NTFS directory; prove legacy `DriveInfo`/filesystem/`subst.exe` predicates would accept it; require Go trust validators and both Windows PowerShell 5.1 and 7 bootstrap/module paths to reject aliased installer, install root, state root, and certification home without creating artifacts. Require the ordinary mounted system drive to pass and remove the alias exactly |
| W-40 | The tested medium user or another same-user process forges certification stdout, stderr, or a completion marker in a handoff directory, or rewrites the short-lived scheduled task, and causes the elevated coordinator to record a false pass | Never trust user-writable result files. Give the scheduled task an exact Administrators-owned protected DACL with only System/Administrators full control and target-SID read/execute. Start it with `IRegisteredTask.RunEx` using the exact resolved WTS session and user SID, then capture bounded output over an administrator-owned named pipe whose DACL grants only System/Administrators full control and the exact target SID data access. Require `GetNamedPipeClientProcessId` to equal the returned `IRunningTask.EnginePID`, then bind the receipt to the random nonce, exact SID, PID, approved PowerShell image, and active WTS session before sending an acknowledgement | Execute the real exact-session/exact-SID scheduled-task and pipe handshake in 64-bit PowerShell 7; keep Windows PowerShell 5.1 coverage on the fixed production bootstrap/module boundary; re-read and validate the task owner plus exact three-ACE DACL before start; static contract rejects file-backed completion/output; every active-user fixture binds its ready PID to the exact `RunEx` task instance, and every high-stakes result records PID binding and `user_writable_files_trusted=false` |
| W-41 | A standard user or same-machine process calls the LocalSystem credential provider, impersonates the gateway, replays a broker response, or tricks the restricted gateway into accepting a fake broker | Exact broker/gateway/pipe identity tuple; protected key with gateway read-only access; pipe DACL limited to LocalSystem and the exact gateway SID; pipe-client SID impersonation plus live SCM gateway-PID match; bounded strict protocol, nonce replay rejection, request-bound response HMAC, and all-or-none protected gateway configuration | Unauthorized pipe-open and wrong-SID/PID probes, broker/gateway scope-mismatch tests, key ACL/read-denial checks, replay/tamper/oversize tests, provider-path trust validation, and incomplete-configuration fail-closed tests |
| W-42 | Automatic enumeration enrolls an ineligible identity, overwrites operator state, corrupts the manifest, or broadens gateway read access across a user profile | ProfileList SID/home/reparse filters; protected-config connector allow-set; supported CLI/version gate for new rows; preservation of existing `enabled`/`deferred`/version state; authenticated bounded manifest and atomic byte-change publication; fixed inventory-dotdir catalog; exact gateway Read+Execute/Traverse ACE merged only into existing non-null directory DACLs; per-path failures logged | Eligible/ineligible profile fixtures, new-row auto-enrollment and no-CLI skip tests, disabled-row preservation, manifest trust/race/atomicity tests, repeated idempotent DACL passes, null/missing-directory handling, and proof that no ACE is added to the profile root or unrelated directories |
| W-43 | A user or a partial configuration switches the enterprise profile, or a standalone config is applied to Secure Client services (or the reverse) | `DEFENSECLAW_ENTERPRISE_PROFILE` in the protected service environment and `enterprise.profile` in the managed config must agree; a Secure Client config may set only `enterprise.profile`; hot reload refuses a profile change (`enterprise_profile_change`); the lifecycle refuses to install one profile while the other is present (`profile_conflict`) | `internal/managed/profile_test.go`, `internal/config/enterprise_test.go`, the config-manager reload test, and the lifecycle profile-resolution tests in `internal/cli/windows_enterprise_standalone_test.go` |
| W-44 | The standalone lifecycle launches a user-writable or lookalike PowerShell, or .NET and PowerShell loader variables hijack the elevated engine | Resolve the newest stable PowerShell 7 only from `HKLM\SOFTWARE\Microsoft\PowerShellCore\InstalledVersions`, require it as a strict descendant of the trusted Program Files root with an administrator-only ancestor chain and a valid Microsoft Authenticode signature on `pwsh.exe`, never consult `PATH` or App Paths, and start it with the protected environment allowlist (loader variables such as `DOTNET_*`, `CORECLR_*`, `COMPlus_*` and `PSModulePath` do not pass). A missing or untrusted engine fails with `powershell7_required` or `powershell7_untrusted`. The Secure Client profile keeps its Windows PowerShell 5.1 launch path | Version-parse, trusted-root, signer, and environment tests in `internal/cli/windows_enterprise_standalone_test.go`; a host run with PowerShell 7 absent and with a user-owned `pwsh.exe` earlier on `PATH` |
| W-45 | An unsigned standalone payload is swapped between staging and execution, or an arbitrary signed binary is accepted as DefenseClaw | Trust comes from the lifecycle invocation, and the config can only narrow it: `--trust-mode hash_pinned` admits an unsigned installer, module and payload only when every leaf matches an administrator-owned SHA-256 manifest (`--payload-manifest`), verified by the CLI before PowerShell starts and recorded for later verification; `--trust-mode authenticode` (the CLI default) requires a valid signature and, when `--allowed-signer` thumbprints are given, one of them, so a customer can re-sign the payload with its own certificate. Setup writes `payload-trust.json` from its embedded manifest and takes signers from `ALLOWEDSIGNERS=`; the MDM wrapper passes `-TrustMode` (default `HashPinned`) and `-AllowedSigners`. `enterprise.trust.mode: authenticode` in the applied config (the supplied one, or the installed one for a mutation without `--config`) refuses a hash-pinned run and any mutation over a deployment recorded as hash-pinned with `1639`; `hash_pinned` or an unset mode admits both; `enterprise.trust.allowed_signers` pins signers like `--allowed-signer`, and a conflicting pair is refused. The marker's `TrustMode` records the deployment's own trust mode | Payload-manifest parse and mismatch tests; a tampered-leaf run that must fail before any service changes |
| W-46 | Concurrent, retried or repeated MDM runs corrupt the deployment or report a false failure | One protected lifecycle lock; contention returns `1618` so Intune retries; invalid arguments return `1639`; `ensure` installs, upgrades or repairs only when needed and is a true no-op (no service drain) when nothing changed; uninstall on a clean host succeeds as a no-op | Exit-code mapping and no-op tests in `internal/cli/windows_enterprise_standalone_test.go`; two concurrent `ensure` runs on a host |
| W-47 | A detection artifact is forged or deleted to hide or fake a deployment | The marker key `HKLM\SOFTWARE\Cisco\DefenseClaw\Enterprise` and the Add/Remove Programs entry are written only after a successful mutation and removed only after a successful uninstall; a failed run leaves them unchanged. Every elevated run, successful or not, writes a `DefenseClaw Enterprise` event and appends to `%WINDIR%\Logs\DefenseClaw\enterprise-lifecycle.log`. HKLM and the log directory are administrator-write only (log SDDL grants users read). They are advisory: enforcement, readiness and `verify` never read them | Registration write/remove tests; a user write attempt on the marker key and log directory must be denied; deleting the marker must not change `verify` |
| W-48 | A user reads or replaces the standalone AI Defense key, or supplies one through config or the environment | Exact reader DACL on `secrets\<name>` (SYSTEM and Administrators full control, gateway service SID read-only, no other ACE) checked by the gateway before reading; bounded single-line value; inline `cisco_ai_defense.api_key` rejected; `api_key_env` cleared; no logging | `internal/managed/credentials_test.go`, `internal/gateway/standalone_inspection_test.go`; a standard-user read attempt must be denied |
| W-49 | A user disables Codex or Claude Code hooks through user or project settings, profiles or `-c` overrides | Codex: `%ProgramData%\OpenAI\Codex\requirements.toml` always carries `allow_managed_hooks_only = true` and `[features] hooks = true`; an administrator value of `false` for either fails the transaction instead of being overridden, and `managed_hooks_only` is not read. Claude Code: the drop-in `C:\Program Files\ClaudeCode\managed-settings.d\90-defenseclaw.json` carries DefenseClaw's hooks and, under the default `managed_hooks_only: enforce`, `allowManagedHooksOnly: true`. Claude Code runs managed hooks even when user or project settings set `disableAllHooks`, and with the lock it runs no user or project hooks; `managed_hooks_only: preserve` for `claudecode` leaves the lock out and turns the foreign-hook guard on for Claude Code | `internal/gateway/connector/codex_machine_requirements_test.go`, `internal/gateway/connector/claudecode_policy_test.go`; a live Codex and Claude Code tool call in the user's own session, read with `audit export` from an elevated prompt (`enterprise policy verify --live` is refused on a managed Windows host) |
| W-50 | A user or project hook for a connector without a vendor lock (Cursor, Copilot, Devin, OpenCode, Amp, and Claude Code with `managed_hooks_only: preserve`) rewrites a tool call after DefenseClaw inspected it | Foreign-hook guard: the guardian removes non-DefenseClaw entries from user-level vendor config (with a backup and an audit event per removal), including `%APPDATA%` locations, redirects the hook recorded and the folders the user's persistent environment (`HKEY_USERS\<SID>\Environment`, while the hive is loaded) names; `defenseclaw-hook.exe` denies tool calls while an unapproved rewriting hook is present in user or project files (walking up to the repository root, or the drive root when there is none) and names the file and the allowlist (`enterprise.machine_policy.connectors.<connector>.allowed_hooks`); the Amp plugin and the per-user OpenCode plugin ask `defenseclaw-hook.exe` for the same decision at load and before each tool call; a session that started with an unapproved hook present stays denied until the agent restarts, for at most 7 days, with the record kept by the gateway per verified SID, and its stop and session-end events get the neutral allow; `foreign_hooks: remove`, `report` or `allow` per connector | `internal/enterprisepolicy/guard_test.go`, `internal/enterprisepolicy/guard_session_test.go`, `internal/gateway/foreign_hook_session_test.go`, `internal/cli/enterprise_hooks_foreign_env_windows_test.go`; hook-runtime guard tests; a live run with a project-level rewriting hook for each connector |
| W-51 | A higher-precedence Claude Code source (HKLM `SOFTWARE\Policies\ClaudeCode`, server-managed settings) silently shadows DefenseClaw's drop-in in the standalone profile | The guardian refuses to publish the drop-in while `HKLM\SOFTWARE\Policies\ClaudeCode\Settings` is non-empty, in both profiles, so the Claude Code target fails instead of reporting coverage it does not have; `higher_precedence_sources` and `managedSourcesBehavior` are not consulted on Windows. `enterprise policy export --connector claudecode --format claude-hklm-json` renders DefenseClaw's hooks for an administrator who delivers Claude Code policy through that source. Server-managed settings cannot be seen locally (residual 17) | `internal/enterprisehooks/managed_policy_windows.go` (`windowsClaudeHigherPolicyCheck`); a host run with an HKLM policy present and absent |
| W-52 | A per-user DefenseClaw install on a managed host takes port 18970 or `%USERPROFILE%\.defenseclaw`, or runs its own hooks next to the managed ones | Per-user `install.ps1`, `defenseclaw upgrade` and `defenseclaw rollback` refuse while the marker key exists, and the per-user gateway refuses while the administrator-owned marker key or a trusted standalone deployment record (or the running standalone `DefenseClawGateway` service) confirms a standalone deployment (`winpath.InspectEnterpriseDeployment`); a record or folder a standard user planted counts as neither. These refusals prevent accidental conflicts; W-25 is the control against a hostile listener. The lifecycle does not detect, migrate or remove a per-user install that already exists; `enterprise.coexistence.per_user_install` is accepted and validated but has no effect in this release, so administrators remove existing per-user copies themselves. A per-user listener on the port cannot forge an allow (W-25) but can deny availability (residual 5) | `internal/cli/managed_host_guard_test.go`, `cli/tests/test_upgrade_shim.py`; refusal tests for each per-user entry point |
| W-53 | The per-user updater replaces managed binaries or a user re-enables self-update | The standalone marker key carries `DisableSelfUpdate=1` unless `enterprise.coexistence.disable_self_update: false`. The lifecycle also sets `HKLM\SOFTWARE\Policies\Cisco\DefenseClaw\DisableSelfUpdate=1`, which the per-user installers honor (the update notice stays off on every managed host whatever the value), but only when that value is absent; it records ownership in the marker (`OwnsSelfUpdatePolicy`) and removes the policy value on uninstall or re-enable only while it owns it and the value is still `1`, so an administrator's Group Policy value is never changed. Both keys are administrator-write only | `internal/cli/windows_enterprise_registration.go`; registration tests; `install.ps1` refusal with the value present |
| W-54 | The lifecycle runs in a 32-bit host, under x64 emulation on ARM64, or in Constrained Language Mode and silently misbehaves | Setup is an x64 build and refuses any other architecture; the installer refuses a 32-bit process (`powershell_32bit_host`), a non-x64 OS including ARM64 (`unsupported_architecture`) and Constrained Language Mode (`powershell_constrained_language`, naming the signer to allow); the MDM wrapper makes the same checks before it starts | `cmd/defenseclaw-enterprise-setup/platform_windows.go`, `packaging/windows/install-enterprise.ps1`, `packaging/mdm/windows/Invoke-DefenseClawEnterprise.ps1`; guard tests and a SysWOW64 Windows PowerShell launch of the Intune remediation script |
| W-55 | A connector outside the certified Windows set is enrolled with an unverified hook route, or an unsupported one appears protected | Each Windows connector is added to the certified registry one at a time with its version floor, teardown and foreign-hook guard. Codex, Claude Code and Cursor use machine policy; Copilot uses its `policy.d` machine policy plus a per-user DefenseClaw runtime; Antigravity, Devin and Hermes use an impersonated per-user registration that runs `defenseclaw-hook.exe --enterprise-managed`; OpenCode uses machine policy (`%ProgramData%\opencode` loads the managed plugin, which runs `defenseclaw-hook.exe`) plus a per-user DefenseClaw runtime, and falls back to an in-agent plugin in the user's profile while the managed plugin is not in force; Amp uses an in-agent plugin in the user's profile that calls the gateway after the listener proof (W-25). OpenHands, Omnigent, OpenClaw and ZeptoClaw are refused on Windows with a clear reason, and Kiro is refused by the guardian because it is managed through `enterprise acp` | `internal/enterprisehooks/peruser_managed.go`, `internal/enterprisepolicy/types.go`; per-connector certification runs |
| W-56 | Under the default ProgramData ACL a standard user creates `C:\ProgramData\Cisco`, a standalone root beneath it, or the other profile's `install\deployment.json`, to block the first install or make a lifecycle refuse or switch profile | A deployment record counts only when the file and every ancestor are owned by SYSTEM, Administrators or TrustedInstaller with no non-admin write or replace rights (Go profile resolution, `enterprise secret`, and the module's cross-profile check); a planted record is ignored with an `untrusted_deployment_record` warning. An uninstall tombstone never selects a profile. The per-user gateway guard keys on the administrator-owned marker key, not the ProgramData record. The lifecycle never adopts a user-owned standalone root: Install renames it aside in place (`<name>.untrusted-<time>-<id>`, reported in `quarantined_paths`) without opening or following it, and refuses when it holds administrator-owned content or, for the shared `C:\ProgramData\Cisco`, anything but DefenseClaw roots and content the user account that owns the directory created (so a folder that user made there moves with it); every other action fails with `root_squatted`. Residual: a user who keeps a handle open on the tree or re-creates it during the rename keeps Install failing with `root_squatted` (1603) until they sign out or an administrator removes it; a user-owned `C:\ProgramData\Cisco` that holds content another principal owns (for example another product's service account, an administrator, or a different user) is not moved, so Install keeps failing with `root_squatted` until an administrator corrects or removes it | `internal/cli/windows_enterprise_record_trust_test.go`, `packaging/windows/tests/enterprise-profile-deployment-record-smoke.ps1`, `packaging/windows/tests/enterprise-standalone-root-squat-smoke.ps1` |
| W-57 | A user has an agent only as a desktop app or editor extension (Claude Desktop, the Claude Code or Codex VS Code extension, the Codex app, the Antigravity IDE) and is never enrolled, so machine-policy hook calls are refused and per-user connectors get no hooks | Not in this release: enrollment discovers agents only through their CLI installs ([R25](ENTERPRISE-THREAT-MODEL.md#residual-risks), [#912](https://github.com/cisco-ai-defense/defenseclaw/issues/912)) | Tracked in #912 |
| W-58 | A Copilot agent chat in VS Code's Local harness runs without DefenseClaw policy or audit | Not in this release: Local never reads Copilot `policy.d`, and DefenseClaw has no VS Code hook route ([R26](ENTERPRISE-THREAT-MODEL.md#residual-risks), [#913](https://github.com/cisco-ai-defense/defenseclaw/issues/913)) | Tracked in #913 |
| W-59 | An agent session runs inside the user's WSL 2 distribution (Claude Desktop WSL sessions, the Codex app or VS Code extension in WSL), outside Windows machine policy and endpoint sensors | Partly covered by `enterprise.machine_policy.windows_wsl`: the Claude Desktop `disableWslSessions` gate, the Codex extension setting repair, `wslInheritsWindowsSettings` detection and a `wsl` row in `enterprise policy verify`; `platform: disable` (`AllowWSL=0`) closes it ([R27](ENTERPRISE-THREAT-MODEL.md#residual-risks), [#914](https://github.com/cisco-ai-defense/defenseclaw/issues/914)) | CLIs inside the distribution, Remote - WSL windows and the Codex app's agent environment stay open |
| W-60 | Devin Desktop (Devin Local under `devin acp`, or Cascade in builds before 3.9.19) runs without DefenseClaw hooks for a user without the `devin` CLI | Reported, not enrolled: a Desktop-only user gets an `unprotected-agents.json` record ([R28](ENTERPRISE-THREAT-MODEL.md#residual-risks), [#915](https://github.com/cisco-ai-defense/defenseclaw/issues/915)) | Tracked in #915 |
| W-61 | The Kiro IDE, or a Kiro that starts hook commands through `powershell -Command`, proceeds past a DefenseClaw block. The guardian does not enroll Kiro on Windows; per-user Kiro hooks return a block as exit 2 through `cmd.exe` or a direct launch, and PowerShell reports it as 1 | The encoded PowerShell hook command (`internal/gateway/connector/kiro.go`); the Kiro IDE and the hook shell are tracked ([R29](ENTERPRISE-THREAT-MODEL.md#residual-risks), [#916](https://github.com/cisco-ai-defense/defenseclaw/issues/916)) | `TestKiroWindowsHookCommandsBlockThroughTheShell`; live check of Kiro's hook shell |

## Security invariants

- `managed_enterprise` is both configuration and authority. Merely setting a
  user environment variable cannot make a user-owned config trusted.
- Production service identity is the exact service tuple of the profile:
  `DefenseClawGateway` evaluates traffic, `DefenseClawSensorHelper` answers
  fixed acquisition requests, `DefenseClawHookGuardian` reconciles enabled
  manifest rows, `DefenseClawHookEnumerator` maintains eligible enrollment and
  inventory access, and in the Secure Client profile `DefenseClawCMIDBroker`
  isolates provider access. The standalone profile never creates the broker.
- The enterprise profile is pinned in the service environment and must agree
  with the managed config. Nothing a user controls can change it.
- In the standalone profile, registration artifacts (marker key, Add/Remove
  Programs entry, event log, lifecycle log) are for detection and support
  only. They never grant or prove protection.
- Service `Running` is not readiness.
- A runtime status file is not authorization.
- The protected target manifest is dynamic enrollment state, not a permanent
  administrator-authored SID allow-list. A new eligible `(SID, connector)` row
  may be enabled automatically on the next enumerator cycle; an invocation
  remains fail-closed until that row reaches protected authorization state.
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
- Local named-pipe transport is not credential-provider authority. The broker
  requires the exact gateway pipe-client SID and live SCM PID, and the gateway
  requires a nonce-bound authenticated response from the protected broker key.
- On each enumerator grant pass, inventory access is added only for the exact
  gateway service SID and only at the fixed inventory-dotdir names for homes
  represented in that manifest generation. It is an inheritable
  Read+Execute/Traverse grant merged into an existing non-null DACL, never a
  whole-profile or profile-root rewrite.
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
2. **Elevated target relaxation.** An earlier revision of the guardian
   fail-closed any target session whose active WTS token was elevated,
   full-integrity, or UIAccess. That refusal denied per-user inspection
   to every user in the local Administrators group — including all users
   of the built-in Administrator account (RID `-500`), users on hosts
   with UAC disabled, and members of the Administrators group on a
   host whose token-filter policy has been turned off. In real
   deployments these are common configurations, so the strict refusal
   traded "no inspection for admin sessions" for "no inspection for
   any admin-group user at all." The current guardian permits enrollment
   of elevated targets and emits a rate-limited stderr advisory
   (`[hook-guardian] WARN: target SID … active-session token is
   <reason>; per-user hook enrollment proceeds best-effort …`) so
   operators can see which sessions run at full integrity. Trust
   assumption unchanged: a fully-elevated user can uninstall
   DefenseClaw entirely or edit its files directly, so the previous
   hook-level refusal never actually defended against a determined
   admin attacker — it only refused to try. Guardian tamper-recovery
   (filesystem watching plus a one-minute reconcile interval) still restores DefenseClaw-owned
   artifacts within one reconcile cycle after accidental or malicious
   drift; the residual gap is the bounded window between tamper and
   next reconcile tick, during which an elevated target can bypass its
   own hooks. That gap was always present for uninstall / kill-service
   attack shapes; the relaxation extends it to per-file tampering.
   Endpoint policy (WDAC / AppLocker / SmartScreen) remains the
   authoritative defense against a determined elevated attacker.
3. A target without an active, safe WTS token cannot be repaired. The guardian
   records failure and retries rather than writing the profile as LocalSystem.
   The activating install-time `-Mode` / `-Connector` shorthand therefore
   seeds enabled rows only for eligible `WTSActive` profile SIDs.

   Post-install, the SCM hook-enumerator runs on a 5-minute interval and
   auto-authorizes newly-discovered `(SID, Connector)` rows whose per-user
   profile contains a supported CLI OR whose connector has a supported
   machine-scoped install shared across all users (parity with macOS
   `render-targets.sh`; see
   `internal/enterprisehooks/agent_version_windows.go` for the per-connector
   probe). Managed-enterprise deployments are administrator-controlled at
   the *connector-policy* layer, not through a permanent per-device SID
   allow-list. Eligible profiles otherwise auto-enroll, while an existing
   disabled manifest row remains disabled across enumerator cycles. Three
   residual sub-risks follow from this posture:

   a. **Local-admin user creation → auto-enrollment.** A local admin
      who can create an interactive user (`S-1-5-21-…`) on the target
      machine and give it a discoverable supported CLI, or rely on an
      eligible machine-scoped connector installation, causes that user to be
      enrolled on the next enumerator tick. macOS's `launchd`-driven
      `render-targets.sh` operates under
      the same posture; this is the accepted cost of parity. The exact
      SID membership check (row W-28 above) still fail-closes on an
      unregistered SID between enumerator ticks, and the guardian
      authorization ledger records every enrollment for audit.

   b. **Unprivileged self-enrollment via user-writable `package.json`,
      or admin-driven all-user enrollment via a machine-scoped install.**
      The per-connector version probe reads a `version` field from
      package metadata under paths inside the user's own profile
      (`AppData\Roaming\npm\node_modules\@…\package.json`,
      `AppData\Local\Programs\cursor\resources\app\package.json`) OR
      — for connectors that ship a machine-scoped installer — from a
      fixed shared path such as
      `C:\Program Files\Cursor\resources\app\package.json` (Cursor's
      MSI installer). Any interactive user can create the per-user
      files with a plausible `version` string and cause the enumerator
      to auto-authorize their `(SID, Connector)` on the next tick,
      *without actually installing a supported CLI*. A machine-scoped
      install of a supported connector (admin-only to write) causes
      that `(SID, Connector)` row to auto-authorize for *every*
      enumerated profile on the box, because the shared version is
      by construction the same for every user. This is deliberately
      accepted because enrollment confers no privilege to the target —
      it only means that user's own agent invocations become subject to
      DefenseClaw inspection. A user who self-enrolls opts themselves
      *into* monitoring, which is a security-neutral (or
      defense-positive) outcome; there is no path from "user drops a
      fake `package.json`" to "attacker gains inspection authority
      over another user's traffic." Endpoint policy remains
      authoritative for what shell / CLI activity is actually visible
      to DefenseClaw once the row exists.

   c. **`Install -NoStart` planned-enrollment.** `Install -NoStart`
      keeps the complete planned all-user enrollment because it makes
      no immediate readiness claim. An explicit manifest that enables
      a disconnected target remains authoritative and fails readiness
      until the exact SID has an active token.
4. Application control and vendor MDM/GPO policy are optional defense-in-depth
   controls, not features DefenseClaw can synthesize. Their absence does not
   block managed-hook readiness, but leaves the user-owned hook race described
   above as a residual risk. If an enterprise claims these controls, it must
   certify them independently.
5. Local port squatting cannot forge an allow verdict for
   `defenseclaw-hook.exe`, because the connected peer PID must be the exact
   SCM gateway PID, but it can still deny availability. The Amp plugin and
   the per-user OpenCode plugin require the listener proof instead; it is a
   separate request, so a user who takes the port between the proof and the
   hook request (the gateway must release it then, in an administrator or
   upgrade restart, and the request must open a new connection) receives
   that request's per-user credential and tool payload, and the plugin
   accepts that user's verdict. A request-bound proof would close it. The
   Codex and Claude Code OTLP exporters verify neither: while a user holds
   the port, that user receives their telemetry,
   which can include prompt text, and the sending user's per-SID telemetry
   credential, and can replay the credential once the gateway is back to
   post telemetry attributed to that user for that connector until the user
   leaves enrollment. The credentials do not rotate; a telemetry credential
   never authenticates hook, inspect or management routes or another
   connector ([R7](ENTERPRISE-THREAT-MODEL.md#residual-risks)). Target-owned
   file reads and comparisons are bounded, and an authorized oversized
   runtime leaf is quarantined for repair, but disk-full,
   handle exhaustion, continuously generated new data, and broader endpoint
   resource starvation remain availability residuals. SCM recovery, monitoring,
   and endpoint resource controls reduce but do not eliminate them.
6. A target can deny access to or replace its entire OS profile root, or create
   a wrong-owner obstruction that the target token cannot safely remove.
   DefenseClaw deliberately fails health rather than taking ownership or
   rewriting broad Windows/OneDrive/enterprise profile ACLs. Endpoint profile
   policy and monitoring must treat this broader self-denial as an endpoint
   availability event.
7. In the Secure Client profile a removed target may retain an old
   connector-scoped hook credential until that connector token is rotated and
   remaining enabled targets are reconciled. The credential cannot authorize
   management or another connector's route, but decommission procedures must
   rotate it rather than relying only on manifest removal. In the standalone
   profile each credential is bound to one SID and stops authenticating when
   the guardian's ledger drops that target.
8. Static policy inspection cannot prove effective client behavior. Fleet
   acceptance must include real approved Codex and Claude invocations against
   the deployed policy stack and require managed hook contact or a blocked
   operation. Stock Codex 0.144.3 currently fails this requirement.
9. An elevated administrator can disable or replace the deployment. Restrict
   local-administrator membership and audit lifecycle activity.
10. Authenticode establishes publisher integrity, not rollout intent. Enterprise
   software distribution should pin approved versions and hashes.
11. A client process can cache the enterprise Program Files hook command before
    an administrator decommissions DefenseClaw. Because purge intentionally
    removes that binary, the old process may report a hook-launch failure.
    Decommission procedures must close or restart Codex and Claude; only a
    fresh-process no-policy result is certified. Ordinary per-user mode keeps
    its separate stable-launcher tombstone behavior.
12. The inventory ACE is bounded by a fixed top-level dotdir catalog, but it is
    inheritable across each selected directory rather than limited to the
    individual signature files the scanner currently reads. A per-directory
    failure also does not fail the enrollment cycle, and the grant is not a
    manifest authorization record. Operators must monitor inventory-DACL
    warnings and include these profile ACEs in de-enrollment/decommission ACL
    review when the gateway service identity should no longer retain access.
13. Standalone hash-pinned payloads are unsigned. They satisfy DefenseClaw's
    own trust check but not a WDAC or AppLocker policy that requires a
    publisher signature. Use Authenticode-signed builds or re-sign the payload
    with the organization's certificate and pin its thumbprint at install
    time: `--allowed-signer` on `defenseclaw.exe enterprise windows`,
    `ALLOWEDSIGNERS=` on Setup, `-AllowedSigners` on the MDM wrapper, or
    `enterprise.trust.allowed_signers` in the config. A deployment installed
    hash-pinned stays hash-pinned until it is removed with `uninstall --purge`
    and reinstalled from a signed Setup.
14. The foreign-hook guard only recognizes the hook and plugin locations each
    vendor documents. A connector release that adds a new location, or a
    plugin that acts outside tool calls, is outside the guard until the
    location list is updated. The guard can also block a developer's
    legitimate project hook; administrators approve those by hash in
    `enterprise.machine_policy.connectors.<connector>.allowed_hooks` or relax the connector to
    `report`.
15. Standalone agent discovery covers the per-user package locations,
    nvm-windows, fnm, Volta, pnpm, yarn, the in-profile `.npmrc` prefix, the
    native installers and machine-scope WinGet packages. An agent found there
    that cannot be enrolled is reported by status and verify
    (`hook_contract_unverified`, `agent_unprotected`); an agent CLI installed
    anywhere else in a profile is not found and not reported. A user controls
    the version their own install reports: while signed in they can move
    their rows between verified hook contracts, and an upgrade to an
    unverified version keeps the row at its last verified version, reported
    as `hook_contract_unverified`. An enrolled Claude Code row never moves to
    an older contract, since the shared Claude Code policy is rendered from
    the oldest enrolled one; the downgrade is reported as
    `agent_unprotected`. A user enrolled for the first time with an older
    Claude Code still sets that contract for every user.
16. `include_groups` and `exclude_groups` decide a signed-out user from the
    group SIDs cached at their last sign-in, so a membership change applies
    at the next sign-in. A directory user with no cached membership (not
    signed in since installation) is pending: existing rows are kept, none
    are added, nothing is revoked. Well-known groups other than Everyone are
    decided from tokens only, so they leave such a user pending too. A group
    name that never resolved excludes no one in `exclude_groups` and leaves
    users no other entry admits pending in `include_groups`; a signed-in
    pending user's installed agents are reported. Entra ID groups are matched
    by SID only.
17. The cross-platform vendor residuals in the
    [enterprise threat model](ENTERPRISE-THREAT-MODEL.md#residual-risks)
    (Claude Code `--bare`, Amp plugin order, OpenCode plugin order, Hermes and
    Copilot fail-open behavior, higher-precedence cloud policy) apply to
    Windows unchanged.
18. In the Secure Client profile hook and telemetry credentials are
    connector-scoped: every user of a connector holds the same credential,
    and the gateway attributes the request from its SID header. One user can
    therefore post hook, inspection and telemetry events attributed to
    another user of the same connector (W-14). The credential still cannot
    reach management routes or another connector. The standalone profile
    binds each credential to one SID; applying that to Secure Client is a
    tracked follow-up, and until then Secure Client per-user attribution is
    advisory ([R12](ENTERPRISE-THREAT-MODEL.md#residual-risks)).
19. Retired (the number is kept for references). The standalone Claude Code
    drop-in on Windows sets `allowManagedHooksOnly` under the default
    `managed_hooks_only: enforce`, so user and project Claude Code hooks no
    longer run beside DefenseClaw's hooks
    ([R16](ENTERPRISE-THREAT-MODEL.md#residual-risks)).
20. Per-user connectors (Antigravity, Devin, Hermes, Amp, and OpenCode on the
    per-user route) register DefenseClaw only in the user's default config.
    A user who starts the agent with another config root (`APPDATA`,
    `XDG_CONFIG_HOME`, `HOME`, `OPENCODE_CONFIG_DIR`, a non-default Hermes
    profile) runs it without DefenseClaw's registration; nothing fails
    closed ([R1](ENTERPRISE-THREAT-MODEL.md#residual-risks)). An uninstall
    that does not run as LocalSystem, or finds users signed out, leaves their
    DefenseClaw registrations; they are inert, and the result lists them
    (`user_registrations_pending`).
21. When the guardian takes back a vendor policy path a standard user
    created under `%ProgramData%`, a process that user started earlier and
    that still holds a handle with `WRITE_DAC` on the object keeps that
    handle until the process closes it. Ending that user's processes (for
    example by signing the user out) closes it.
22. `defenseclaw-hook.exe` runs as the user, who can end or suspend it or
    starve it until the agent's hook timeout. Agents that block only on an
    explicit deny then run the call, with no DefenseClaw audit row for it
    ([R18](ENTERPRISE-THREAT-MODEL.md#residual-risks)). Claude Code and
    Codex treat a hook that exits without code 2 or times out as
    non-blocking, so both run the call after the user kills or stops their
    own hook.
23. The managed OpenCode plugin
    (`C:\Program Files\Cisco\DefenseClaw\share\opencode\defenseclaw.js`)
    grants `BUILTIN\Users` `FILE_WRITE_ATTRIBUTES` besides read and execute,
    because OpenCode's Bun runtime opens every module with that right and
    cannot load the plugin without it. With it a standard account can change
    the plugin's attributes, including setting a reparse point that leaves the
    plugin unreadable. OpenCode skips a plugin it cannot load and runs without
    DefenseClaw for every account; it does not fail closed. The guardian
    restores the plugin on its next pass (about a minute), and
    `enterprise policy verify` reports it untrusted until then. Tracked in
    issue #930.

## Certification gate

Release acceptance requires all of the following against the same built
artifacts:

- focused and repository-wide automated tests;
- PowerShell 5.1 and PowerShell 7 parser and execution tests;
- an elevated install/upgrade/repair/status/verify/uninstall lifecycle;
- exact configuration, identity, dependency, privilege, environment, DACL,
  recovery, and readiness checks for `DefenseClawGateway`,
  `DefenseClawSensorHelper`, `DefenseClawHookGuardian`,
  `DefenseClawHookEnumerator` and, in the Secure Client profile,
  `DefenseClawCMIDBroker`;
- activation-order proof that the broker (Secure Client profile) starts before
  the guardian, the guardian publishes fresh manifest-bound authorization
  before the gateway, the enumerator starts only after the gateway, and every
  service becomes automatic only after full readiness;
- for the standalone profile: the same lifecycle on PowerShell 7 only, with no
  broker service, a hash-pinned and an Authenticode payload, the `ensure`
  no-op and busy (`1618`) paths, registration and event-log output, and the
  W-43…W-55 probes;
- broker IPC tests covering exact gateway SID/live PID authentication,
  protected-key ACLs, identity-tuple mismatch, replay/tamper/oversize rejection,
  provider-path trust, and incomplete-configuration fail-closed behavior;
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
- eligible-profile automatic-enrollment, unsupported/no-CLI omission,
  existing-disabled-row preservation, profile/SID/reparse filtering, and
  byte-identical manifest no-write tests;
- inventory-DACL tests proving the exact gateway SID receives only the fixed
  dotdir Read+Execute/Traverse grants, existing non-null DACLs are preserved,
  missing/null/failing directories are logged or skipped as specified, repeat
  passes are idempotent, and no profile-root or unrelated-directory ACE appears;
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
- four forced crashes for each managed service of the profile, a clean-stop
  non-recovery interval, and standard-user service-process/token handle denial
  probes;
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
