# Spec 007 — Windows managed_enterprise gateway runs as LocalSystem

Run the DefenseClaw gateway service as `LocalSystem` instead of the
restricted virtual service account `NT SERVICE\<GatewayServiceName>`.
This removes the gateway's dependency on `SeServiceLogonRight`, so install
no longer needs a local rights grant or a Group Policy change. The
guardian, enumerator, sensor helper and CMID broker already run as
`LocalSystem`; after this change every DefenseClaw Windows service does.

This is an early-phase limitation on the Windows threat model and is
documented as such.

## Why

On a customer endpoint (Windows 11 26100, release 26.8.4 at `739ccc3ca`)
install failed with SCM event 7041 and exit code 1603. The gateway's
virtual account had no `SeServiceLogonRight`. A local grant unblocked the
install, but a domain GPO that defines "Log on as a service" replaces the
local list on the next refresh, and the gateway then fails at its next
start. The only durable fix was for IT to add the gateway's exact SID to
that GPO.

`LocalSystem` has the service logon right by design, and Group Policy
cannot remove it. Moving the gateway removes the failure mode and the GPO
prerequisite.

## Current state

- Gateway: `$gatewayAccount = "NT SERVICE\$GatewayServiceName"`, used as
  `obj=` on `sc create` and `sc config`
  (`packaging/windows/DefenseClawEnterprise.psm1:5396`, `:5478`, `:5490`).
- Broker, guardian and enumerator: `obj=LocalSystem` (same file, six call
  sites).
- The virtual service SID (`Get-DefenseClawServiceSID -ServiceName
  $GatewayServiceName`) is also used in about 14 places to stamp ACLs on
  config, runtime, log, manifest and IPC paths.
- The gateway service is configured with service SID type `restricted`
  (`-ExpectedSidType 3`) and a required-privileges list of only
  `SeChangeNotifyPrivilege`. Both apply to any logon account.

## How the gateway stays contained under LocalSystem

Service SID type `restricted` makes the gateway's token write-restricted,
whatever account it logs on as. A write needs both the normal access check
and a second check against the restricting SIDs: the gateway service SID,
Everyone and WRITE_RESTRICTED. Only the runtime and log ACLs grant the
service SID write, so the set of paths the gateway can write is the same as
before. The required-privileges list strips every LocalSystem privilege
except `SeChangeNotifyPrivilege`.

What changes is reads and identity: reads are checked against LocalSystem,
and the token user is `S-1-5-18` instead of the service SID. The service SID
is still in the token as an enabled group, which is how code recognizes the
gateway.

Ownership stays as it was. A LocalSystem token's default owner is SYSTEM,
which is not a restricting SID, so files the gateway created would be
SYSTEM-owned and its write-restricted token could not use the owner's
implicit `WRITE_DAC` to secure them: Setup failed with exit 1603 because the
gateway could not harden its new audit database ("reopen existing database
file for ACL hardening: Access is denied"). SCM gives the service SID
`SE_GROUP_OWNER`, so the service host sets it as the token's default owner
before the gateway creates its first file
(`managed.AdoptWindowsGatewayServiceFileOwner`) and fails to start if it
cannot. Files the gateway writes are owned by the service SID, as under the
virtual account; no ACL grants anything new. The audit, judge-body and JSONL
owner checks recognize the gateway by its service SID
(`managed.WindowsCurrentProcessOwnerSID`), not by the token user.

## Scanner path boundary

`managed.RequireWindowsGatewayPathOutsideUserProfiles(path)` applies only to
the LocalSystem gateway process carrying the enabled gateway service SID. It
resolves existing path components, including junctions and short names, and
checks both the supplied and final paths against every ProfileList
`ProfileImagePath` and the system drive's Users directory. If a path is
inside a user profile, the gateway refuses that read or scan with:

> the managed gateway runs as LocalSystem and does not read inside user profiles; scan the folder as the signed-in user (defenseclaw ... from the user session) or move it outside the profile

The gateway continues scanning readable paths outside profiles, including
managed roots, ProgramData, Program Files and ordinary project folders. The
watcher skips only profile roots and reports a degraded detail when it skips
one. This preserves the former virtual-account boundary around other users'
profiles.

Scanner children inherit the gateway's write-restricted LocalSystem token,
which keeps only `SeChangeNotifyPrivilege`. The gateway has neither
`SeAssignPrimaryTokenPrivilege` nor `SeIncreaseQuotaPrivilege` and cannot
start a child as another user. For paths outside profiles, reads are now
checked as LocalSystem. A caller-supplied outside path readable only by
administrators is therefore readable by the gateway; this extends the W-05
early-phase limitation.

## Change

1. **Service identity.** Set the gateway's `obj=` to `LocalSystem` on both
   the `create` and `config` paths, matching the other services. `sc
   config` on upgrade moves an existing installation to `LocalSystem`. Keep
   SID type `restricted` and the single required privilege.
2. **ACLs.** Keep the virtual-SID ACEs. They are what the write-restricted
   token is checked against, so they remain the gateway's write boundary.
3. **Service environment.** `DEFENSECLAW_WINDOWS_SERVICE_ACCOUNT` keeps the
   value `NT SERVICE\<GatewayServiceName>`. It names the gateway's service
   SID for ACLs and trust checks, not its logon account. Keeping it means
   files the old gateway wrote, owned by that SID, stay trusted after
   migration. Its descriptions in `internal/managed/managed.go` and the
   env-var registry say so.
4. **No logon-right code.** The installer does not grant or check
   `SeServiceLogonRight`. If PR #1127 lands first, remove its grant for the
   gateway as part of this change.
5. **Go-side identity checks.** Checks that recognize the gateway process
   by "token user == service SID" also accept "token user is LocalSystem and
   the service SID is an enabled, non-deny-only group"
   (`managed.WindowsTokenRunsAsService`). This covers the redaction
   correlation key store and the CMID broker's pipe-client check. The
   broker's check of the gateway's SCM account accepts `LocalSystem` and the
   old virtual account. The W-25 gateway-PID binding is unchanged.
6. **LocalSystem admin gates exclude the gateway.** Three checks treat any
   LocalSystem token as administrator authority: hook lifecycle preflight,
   hook mutation preflight, and Codex machine-policy writes. They now refuse
   when the current process is the gateway service
   (`managed.WindowsCurrentProcessIsGatewayService`). None of them is
   reached by the gateway's runtime today, and the write-restricted token
   would block the writes anyway, so this keeps the rule explicit in code.

## Existing installs on the virtual account

Endpoints already running a release where the gateway is
`NT SERVICE\<GatewayServiceName>` must move to the new build without
manual steps. Each lifecycle action of the new build must work against
such an install:

| Action (new build) | Required result |
|---|---|
| `Uninstall` | Stops and removes every service, including the virtual-account gateway, and removes DefenseClaw state as today. Succeeds without any prior upgrade. |
| `Uninstall` with purge | Same, and also removes the virtual-SID ACEs from every path DefenseClaw owns, as the current purge does. |
| `Install` on a host with existing deployment metadata (reconcile Install) | Reconfigures the gateway to `LocalSystem`, keeps config, manifest and enrolled targets, and starts the gateway. No refusal for "existing deployment". |
| `Upgrade` and `Repair` | Same as reconcile Install. |
| `Install` after an `Uninstall` | Clean install as `LocalSystem`. |

Rules that make this work:

1. **Ownership checks accept both accounts.** Any check that decides
   whether the existing gateway service belongs to this deployment
   (owned-service, exact-scope-service and image-path checks) accepts
   `NT SERVICE\<GatewayServiceName>` or `LocalSystem` as the account. It
   must never treat the old account as a foreign service and refuse.
2. **Teardown does not depend on the account.** Stop, delete and
   dependency removal work the same for either account.
3. **Rollback restores the previous account.** If an `Upgrade` fails
   after the gateway was reconfigured, the transaction rollback restores
   the previous service configuration, including `obj=`, so the restored
   old binaries run under the identity they expect. The transaction
   snapshot records the gateway's service account so rollback has it.
4. **Old journals recover.** A transaction or teardown journal written
   by the previous build (no recorded account) is recovered by the new
   build. A missing account in an old journal is read as the virtual
   account.
5. **Leftover logon-right grants are left alone.** A local
   `SeServiceLogonRight` grant an admin added for the virtual SID or for
   `NT SERVICE\ALL SERVICES` is not owned by DefenseClaw and is not
   removed. The setup guide tells admins they may remove it.

Uninstalling a migrated (`LocalSystem`) install with the *previous*
build is out of scope.

## Threat model changes (early-phase limitation)

| ID | Before | After |
|---|---|---|
| W-05 | A compromised gateway cannot edit policy or authorization. It also cannot read the guardian log or manifest. | Still cannot write them: the write-restricted token needs a service-SID ACE, and only runtime and log paths have one. **Limitation:** it can now read config, authorization, guardian log and manifest, because reads are checked against LocalSystem. |

W-14, W-18, W-20 and W-25 hold as written. The runtime `Modify` ACE is
still on the service SID. The gateway token is still restricted by that SID.
Standard users still cannot open a LocalSystem process for mutation. The
W-25 PID binding is account-independent.

One further difference: the gateway's network identity is now the computer
account. This matters only if the outbound path authenticates to a proxy
with Windows credentials. The gateway calls AI Defense with no proxy today.

## Out of scope

These are reported from the same customer case but are not fixed by this
spec:

- **TLS inspection root CA.** `LocalSystem` reads the same
  `LocalMachine\Root` store as the virtual account. Sites that inspect TLS
  must exempt the AI Defense host or deploy the inspection root to the
  machine store. Documented as a prerequisite.
- **Signed-out, previously protected user blocks repair/upgrade.** Tracked
  by branch `fix/windows-enumerator-deferred-default` (PR #1124).
- **Codex Store/MSIX desktop app not detected**
  (`agent_version_windows.go:123`). Separate detection change.
- macOS and Linux.

## Tests

### Acceptance condition: CI stays green

Every CI check that passes on the release branch before this change must
pass on the PR before merge, across every workflow (CI, Windows Native CI,
macOS, Telemetry Registry, Connector Live E2E, Windows
deterministic-build, Docs).

- If the change breaks an existing test, fix it in the same PR. Do not
  defer it to a follow-up.
- A test that asserts the gateway's old logon identity
  (`NT SERVICE\<GatewayServiceName>` as its SCM account, or the virtual
  service SID as its process TokenUser) is updated to `LocalSystem` /
  `S-1-5-18`, keeping the rest of the assertion.
- Tests of `DEFENSECLAW_WINDOWS_SERVICE_ACCOUNT` stay unchanged. Its value
  is still `NT SERVICE\<GatewayServiceName>` because it pins the service
  SID, not the logon account.
- A test that breaks for any other reason is fixed in the product code
  if the change caused a real regression, or in the test if the test
  encoded the old identity indirectly.
- No test is deleted, skipped, or loosened to make the change pass.
- Tests of ACLs that still carry the virtual-SID entries stay unchanged,
  because those entries are kept.
- The PR lists every edited test with a one-line reason.
- Before merge, compare CI on the release branch tip with CI on the PR
  branch. Any check that passes on the tip and fails on the PR blocks
  merge.

### Update

- `cli/tests/test_windows_enterprise_service_contract.py`: assert the
  gateway's `obj=` is `LocalSystem` on both `create` and `config`, that the
  virtual account is no longer used as the gateway's expected account, and
  that SID type `restricted` and the single required privilege are kept.
  `DEFENSECLAW_WINDOWS_SERVICE_ACCOUNT` still names the service SID.
- `scripts/test-windows-enterprise-hardening.ps1` live token probe: the
  gateway's TokenUser is `S-1-5-18` at System integrity, its service SID is
  a non-deny-only group, and it is still a restricted token with the service
  SID, Everyone and WRITE_RESTRICTED as restricting SIDs.

### Add

- Contract test: no `SeServiceLogonRight` grant or assertion for the
  gateway SID in the module, the installer or the Go lifecycle code.
- Migration tests, each starting from a gateway registered as
  `NT SERVICE\<GatewayServiceName>` with deployment metadata, config,
  manifest and enrolled targets in place:
  - `Upgrade`, `Repair` and reconcile `Install` reconfigure the gateway
    to `LocalSystem`, keep config, manifest and targets, and the gateway
    starts and reports Ready.
  - `Uninstall` and `Uninstall` with purge succeed and leave no
    DefenseClaw service, state or virtual-SID ACE behind.
  - `Install` after that `Uninstall` succeeds as `LocalSystem`.
  - A failed `Upgrade` after reconfiguration rolls back to
    `NT SERVICE\<GatewayServiceName>` with the old binaries, and the
    gateway starts.
  - A transaction journal written by the previous build is recovered.
  - Ownership checks do not refuse the old account as a foreign service.
- `scripts/test-windows-enterprise-hardening.ps1`: confirm that a standard
  user still cannot stop, reconfigure, delete, open for write, or inject
  into the gateway process with the gateway as `LocalSystem`.
- `scripts/test-windows-enterprise-hardening.ps1`: on a host whose
  "Log on as a service" list excludes virtual accounts, install and start
  succeed.

## Documentation

- `docs/WINDOWS-ENTERPRISE-SETUP.md`: state that every DefenseClaw service
  runs as `LocalSystem`, that no "Log on as a service" grant or GPO change
  is needed, and that TLS-inspecting networks must trust the inspection
  root in `LocalMachine\Root` or exempt the AI Defense host. Add an
  upgrade note: existing installs move to `LocalSystem` on `Upgrade`,
  `Repair` or reinstall with no manual step, and any "Log on as a
  service" grant an admin added for the old gateway account can be
  removed afterwards.
- `docs/WINDOWS-ENTERPRISE-THREAT-MODEL.md`: update W-05, W-14 and W-20 as
  in the table above, and mark the change as an early-phase limitation.
- Remove or correct any statement elsewhere in the docs that the gateway
  runs as a virtual service account or needs `SeServiceLogonRight`.

## Open decision for the owner

May scanner and MCP-scan child processes ever keep the gateway's LocalSystem
token, or must a broker scan as the enrolled user? Current scanner children
inherit the gateway's write-restricted LocalSystem token for paths outside
profiles. A project folder inside a profile receives the refusal above,
including MCP scan requests. The issue 1164 follow-up needs a brokered
user-session scan that binds the enrolled user and profile and revalidates
the path before launching a scanner child.
