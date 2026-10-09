# Linux managed-enterprise threat model

This is the Linux part of the [enterprise threat model](ENTERPRISE-THREAT-MODEL.md),
which defines the enterprise profiles, the trust zones Z0–Z5 and the
cross-platform boundary table. Linux supports only the `standalone` profile;
the loader rejects `secure_client` on Linux.

Rows are numbered `L-01`…. Where a row mirrors a Windows row, the Windows ID
is given in the second column so reviewers can compare the two platforms.

## Review scope

- Repository: `defenseclaw`; a certification record names the exact tree hash.
- Primary paths:
  - `internal/enterpriseunix/` (lifecycle transaction)
  - `internal/cli/enterprise_unix*.go` (`defenseclaw-gateway enterprise linux …`, `enterprise secret …`)
  - `packaging/systemd/` (units, sockets, path unit, timer, sysusers)
  - `packaging/linux/` (`.deb` / `.rpm` maintainer scripts)
  - `internal/gateway/api_uds_unix.go`, `internal/gateway/managed_hook_peer.go`,
    `internal/gateway/user_scoped_credentials.go`
  - `internal/gateway/connector/hookexec/managed_standalone_transport.go`,
    `internal/gateway/connector/user_scoped_token.go`
  - `internal/peercred/`, `internal/systemd/`
  - `internal/unixidentity/`, `internal/enterprisehooks/enumerator_unix.go`,
    `internal/cli/enterprise_hooks_worker_*.go`
  - `internal/enterprisepolicy/`
  - `internal/managed/credentials_unix.go`, `internal/managed/runtime_descriptor.go`
- Supported hosts: systemd 239 or later as PID 1. Containers and WSL without
  systemd are refused (`systemd is not the running init system`).
- Unit hardening by systemd version. systemd ignores a unit directive it does
  not know (it logs `Unknown lvalue` when it loads the unit), so on an older
  supported systemd the units below run without these directives. RHEL 8
  (systemd 239) ignores every one of them; systemd 250 or later applies them
  all.

  | Directive | Needs systemd | Units that set it |
  | --- | --- | --- |
  | `ProtectHostname=true` | 242 | gateway, hook guardian, guardian reconcile, hook enumerator, sensor helper |
  | `ProtectKernelLogs=true` | 244 | the same five units |
  | `ProtectClock=true` | 245 | the same five units |
  | `ProtectProc=invisible` | 247 | gateway, hook guardian, guardian reconcile |
  | `ProcSubset=pid` | 247 | gateway |
  | `TriggerLimitIntervalSec=`, `TriggerLimitBurst=` in `[Path]` | 250 | `defenseclaw-enterprise-apply.path` (its trigger rate limit) |

  How the AI Defense key reaches the gateway also depends on the version:
  `LoadCredential=` needs systemd 247 ([Secrets](#secrets), L-20). A
  `systemd-analyze verify` run over these units in the `ubi8-init` image the
  rpm-el8 CI lane uses (systemd 239-82.el8_10) reported only the directives
  above; the rest (`ProtectSystem=strict`, `ProtectHome`, `PrivateDevices`,
  `PrivateTmp`, `RestrictNamespaces`, `RestrictSUIDSGID`,
  the syscall filters and the capability sets)
  load there.

## Security objectives

1. A standard user cannot stop, disable, mask, reconfigure or replace any
   DefenseClaw unit, binary, config, policy, secret, manifest, ledger or
   runtime descriptor.
2. The gateway runs as the `defenseclaw` system user with an empty capability
   set inside a systemd sandbox, and can write only its state, runtime, hook
   socket and log directories.
3. `defenseclaw-hook` sends no request byte until the kernel proves the
   listener is root (PID 1 holding an activated socket) or the gateway's
   service uid. DefenseClaw's in-agent plugins (OpenCode, Amp) and the
   OmniGent and Codex notify bridges use the same socket and check; there is
   no TCP fallback. The agents' own telemetry exporters do not verify the
   listener (residual 3).
4. The gateway authorizes each hook caller by kernel uid against the
   guardian's root-owned authorization ledger.
5. The root guardian never reads, writes, removes or changes permissions
   inside a user home itself; a per-user worker does it with that user's uid
   and gid.
6. Directory-backed users (LDAP, SSSD, AD, NIS, systemd-userdb) are enrolled
   when their uid is at least `UID_MIN` from `/etc/login.defs` (1000 when
   unset; `enrollment.uid_min` overrides it) and not above
   `enrollment.uid_max` when that is set (login.defs `UID_MAX` bounds only
   local accounts), and their shell is not a nologin shell, or when they are
   listed in `enrollment.include_users`; a directory outage never revokes
   anyone.
7. Vendor machine policy is merged, never replaced; administrator entries
   survive install, repair and uninstall byte for byte.
8. A normal user cannot disable DefenseClaw's hooks through vendor settings,
   and a foreign hook cannot rewrite a tool call DefenseClaw inspected for a
   connector with a vendor lock or the foreign-hook guard, within the bounds
   of enterprise residuals R3, R4, R13 and R14. Antigravity, OpenHands and
   OmniGent have neither, and the guard covers Hermes shell hooks with the
   gaps listed in R24.
9. Every lifecycle action is a transaction that commits fully or rolls back.
10. Only the root sensor helper talks to a Tetragon API, only over a Unix
    socket that root owns and root serves, and only the `defenseclaw-*`
    policies it recorded itself are ever changed or deleted. Kernel
    enforcement starts only when the administrator approves the exact control
    set, is limited to enrolled command-line agents' own process trees, and
    is removed by every uninstall, rollback and downgrade path. The events of
    the customer's own Tetragon policies are read, never managed: no call names
    a policy the helper did not record loading, and only typed, bounded fields
    of events below an AI agent cross the broker.

## Zones on Linux

| Zone | What runs or lives there | Identity | Protected by |
| --- | --- | --- | --- |
| Z0 | systemd (PID 1), root, `apt`/`dnf`, `defenseclaw-gateway enterprise linux` run by an MDM script or an administrator | root | Trusted by assumption |
| Z1 | `defenseclaw-hook-guardian.service` | root; `CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_KILL CAP_SETGID CAP_SETUID`; `AmbientCapabilities=CAP_SETGID CAP_SETUID` (systemd 255 otherwise drops `CAP_SETUID`); `NoNewPrivileges=true` | Root-owned unit; `ProtectSystem=strict`; writes only homes (through the worker), `/var/lib/defenseclaw` (hook tokens and the per-user credential key) and the guardian state |
| Z1 | `defenseclaw-hook-enumerator.service` | root; `CAP_CHOWN CAP_DAC_READ_SEARCH CAP_KILL CAP_SETGID CAP_SETUID`, the last two also ambient; `ProtectHome=read-only` | Writes only `/etc/defenseclaw/hook-guardian` and `refused-surfaces.json` (root:defenseclaw 0640) in `/var/lib/defenseclaw-hook-guardian` |
| Z1 | Per-user `enterprise hooks apply-target` worker | the target user's uid and primary gid | New session, parent-death signal, non-dumpable, rlimits, timeout, minimal environment |
| Z1 | `defenseclaw-sensor-helper.service` | root with acquisition capabilities (`CAP_SYS_ADMIN`, `CAP_NET_RAW`, `CAP_NET_ADMIN`, `CAP_DAC_READ_SEARCH`, `CAP_SYS_PTRACE`, `CAP_CHOWN`, `CAP_FOWNER`) | Own `RuntimeDirectory=defenseclaw-sensor` and `StateDirectory=defenseclaw-sensor` (`0700`); fixed fieldless request protocol; homes from the manifest. Ordered after `tetragon.service`. When the computer runs Tetragon it is the only client of that root-equivalent API (L-42), limited to the calls each `enterprise.tetragon.mode` allows |
| Z2 | `defenseclaw-gateway.service` (`Type=notify`, watchdog) | `defenseclaw:defenseclaw`, `CapabilityBoundingSet=` (empty) | `ProtectSystem=strict`, `ProtectHome=true`, `PrivateDevices`, `PrivateTmp`, `ProtectProc=invisible` (systemd 247 or later; see [Review scope](#review-scope)), `@system-service` syscall filter, `RestrictNamespaces` (no `MemoryDenyWriteExecute`: the sonic JSON library maps executable memory on x86_64); read-only `/etc/defenseclaw`, `/opt/defenseclaw` and the ledger |
| Z2 endpoints | `defenseclaw-gateway-api.socket` (`127.0.0.1:18970`) and `defenseclaw-gateway-hook.socket` (`/run/defenseclaw-hook/hook.sock`) | bound by PID 1 | Held across gateway restarts. `/run/defenseclaw-hook` is created `0755 defenseclaw:defenseclaw` by systemd-tmpfiles at boot (`packaging/systemd/defenseclaw.conf`) and by the lifecycle; only root and the service account can create entries in it. The socket is `0666 defenseclaw:defenseclaw` (`SocketUser`, `SocketGroup`, `SocketMode`) so every local user can connect; the gateway authorizes each caller by kernel uid (L-08) |
| Z3 | `/opt/defenseclaw` (binaries), `/etc/defenseclaw` (config, `policies/`, `secrets/`, `hook-guardian/targets.yaml`, `managed-runtime.json`, `machine-policy.json`), `/var/lib/defenseclaw-hook-guardian` (ledger), `/var/lib/defenseclaw-enterprise` (lifecycle), `/etc/{codex,claude-code,cursor,github-copilot,opencode}` | root | Administrator-only write; secrets root-only with systemd 247 or later, otherwise `root:defenseclaw 0640` |
| Z4 | The AI agent and `/opt/defenseclaw/bin/defenseclaw-hook` running as the user; the user's vendor config | the user | Peer verification, guardian repair, foreign-hook guard |

Supporting units: `defenseclaw-enterprise-apply.path` watches the config,
secrets and policies and runs `ensure`; `defenseclaw-enterprise-verify.timer`
runs `verify` daily; `defenseclaw.sysusers` creates the service account. The
racing oneshot guardian timer and the template unit from earlier layouts are
removed.

## Data flows

### Install, upgrade, ensure, uninstall

1. An administrator, package script or MDM runs
   `defenseclaw-gateway enterprise linux <action>` as root. Paths come from
   `managed.StandaloneLayoutFor("linux")`; the environment is not consulted.
2. The lifecycle takes the lock in `/var/lib/defenseclaw-enterprise`, rolls
   back any interrupted transaction, records an intent, snapshots every file
   it will touch, and stages replacements in the destination directory.
3. It stops the services, applies files, owners and modes, reloads systemd,
   and starts the sensor helper, the gateway (waiting for `READY=1` and
   `/health` on the hook socket), the guardian (waiting for a fresh ledger) and the enumerator.
4. It verifies every file, mode, unit property and readiness check, then
   commits the deployment record or restores the snapshot and the previously
   running services. `ensure` is a no-op when nothing changed. Exit codes are
   `0`, `1` (rolled back), `2` (invalid arguments) and `75` (lock busy).
5. On SELinux hosts the lifecycle runs `restorecon -R` on `/opt/defenseclaw`
   and `/etc/defenseclaw` and reports a warning if relabeling fails.

### Secrets

`defenseclaw-gateway enterprise secret set --name <name> --from-stdin` stores
a value in `/etc/defenseclaw/secrets/<name>`. With systemd 247 or later the
file is `root:root 0600` and reaches the gateway only through
`LoadCredential=` under `/run/credentials/`; with older systemd it is
`root:defenseclaw 0640`. The gateway reads it through
`managed.ResolveServiceCredential`, which requires the credentials directory
under `/run/credentials/` or a root-owned, single-link file with no other
access. Status shows presence, modification time and a digest prefix only.

### Hook request

1. The agent runs `/opt/defenseclaw/bin/defenseclaw-hook hook --connector <c>
   --enterprise-managed` as the user.
2. The hook reads the gateway address, hook socket and gateway service uid
   only from the root-owned runtime descriptor
   (`/etc/defenseclaw/managed-runtime.json`). Inherited gateway tokens and
   addresses cannot loosen it.
3. It connects to `/run/defenseclaw-hook/hook.sock`, checks the socket
   directory is owned by root or the service account and writable by no one
   else, and requires the peer's `SO_PEERCRED` uid to be 0 or the service uid.
   Only then does it send the request. There is no TCP fallback: a
   descriptor that names no socket fails closed
   (`enterprise_managed_hook_socket_missing`). Per-user shell hooks, in-agent
   plugins, the OmniGent bridge and the Codex notify bridge use the same
   socket, and the guardian refuses to render them without it.
4. The gateway reads the caller's uid from the socket and checks the
   authorization ledger (L-08).
5. The remaining TCP consumers (the Codex, Claude Code, OpenHands and
   OmniGent telemetry exporters) present credentials bound to
   the user's uid. The guardian derives them from a per-machine key kept in
   the gateway's data directory (`hooks/.user-scoped-token.key`) and renders
   them into the user's own hook directory and agent configuration. The
   gateway accepts them only while the ledger protects that uid, attributes
   the request to it, and refuses identity headers that name another user
   (L-08). The exporters are third-party code and do not verify the
   listener (residual 3).

### Enrollment and repair

1. The enumerator lists candidates from NSS (`getent passwd` through the
   root-owned binary, so LDAP, SSSD, AD, NIS and systemd-userdb accounts are
   visible to the `CGO_ENABLED=0` build), logged-in sessions, home owners and
   `enrollment.include_users`, then applies uid, shell, group, home-root and
   exclusion filters. The uid range starts at `UID_MIN` from
   `/etc/login.defs` (1000 when unset); `UID_MAX` (60000 when unset) bounds
   only local accounts in `/etc/passwd`, and directory accounts have no upper
   bound unless `enrollment.uid_max` is set (residual 10); accounts with a nologin shell
   (`/usr/sbin/nologin`, `/sbin/nologin`, `/usr/bin/nologin`, `/bin/false`
   and the like) are skipped; `enrollment.include_users` bypasses both
   checks, `include_groups` does not; uid 0 and `nobody` are never targets.
2. Agent versions are discovered by the per-user worker as that user, never
   as root.
3. The manifest is published atomically. Existing `enabled`, `deferred` and
   version state is kept; a row is revoked only after three consecutive
   definitive not-found answers (`UnixRevokeAfterMisses`), about 15 minutes at
   the 5-minute cycle; a changed uid or home inode is a new identity.
4. The guardian spawns one worker per target. The worker installs or repairs
   the registration, removes foreign hooks, and reports back; the guardian
   mints tokens, writes the ledger and watches files.

## Threat analysis

| ID | Windows | Threat | Control | Evidence |
| --- | --- | --- | --- | --- |
| L-01 | W-01 | A user stops, disables, masks, edits or deletes a unit | Units live in root-owned systemd directories; `systemctl` mutations need root or polkit authorization that standard users lack; `Restart=always`, `StartLimitIntervalSec=0` | `systemctl stop/disable/mask` as each test user; unit files unchanged |
| L-02 | W-02 | A user replaces a binary, config, policy, secret, manifest, ledger or descriptor | Root ownership of every file and ancestor; the loader rejects untrusted config and policy inputs; the descriptor parser is strict and bounded | Write, rename, symlink-swap attempts; `verify` detects drift |
| L-03 | W-04 | A user downgrades `managed_enterprise` or the profile through config or environment | `DEFENSECLAW_DEPLOYMENT_MODE` and `DEFENSECLAW_ENTERPRISE_PROFILE` pinned in the gateway, guardian, enumerator and sensor-helper units; config must agree; reload refuses a profile change | `internal/config/enterprise_test.go`, `internal/managed/profile_test.go` |
| L-04 | W-05 | A compromised gateway edits policy or the ledger | `ReadOnlyPaths=/etc/defenseclaw /opt/defenseclaw -/var/lib/defenseclaw-hook-guardian`; empty capabilities; `ProtectHome=true` | `systemctl show` properties; write attempts from the service identity |
| L-05 | W-25 | A user binds `127.0.0.1:18970` or the hook socket during a restart and returns an allow | PID 1 binds both sockets before any user process and holds them across restarts; hooks and plugins use only the hook socket and verify its `SO_PEERCRED` uid before writing; there is no TCP fallback | `internal/gateway/connector/hookexec/managed_standalone_transport_test.go`, `internal/cli/hook_trusted_state_unix_test.go`, `internal/systemd/systemd_test.go`; a squat-and-restart race on a host |
| L-06 | — | A user pre-creates `/run/defenseclaw-hook/hook.sock` or its directory | The directory is created at boot by systemd-tmpfiles as `0755 defenseclaw:defenseclaw` (and by the lifecycle), before `sockets.target`, so no other user can create entries in it. The gateway's own account owning it is acceptable: that account already serves the socket, and the directory is not writable by anyone else. The gateway's own bind (without activation) refuses a directory that is not owned by root or the service account or is writable by others, and replaces only a stale socket it owns; the hook applies the same directory check before it connects | `packaging/systemd/defenseclaw.conf`, `internal/enterpriseunix/layout.go`, `internal/gateway/api_uds_unix_test.go`, `internal/gateway/connector/hookexec/managed_standalone_transport_test.go` |
| L-07 | W-14 | A user reads another user's hook token or the service's runtime state | `StateDirectoryMode=0700`, `RuntimeDirectoryMode=0750`, `UMask=0077`; tokens under each user's home with owner-only modes; each user's tokens are bound to that user's uid, and the key they derive from stays in the service's data directory | Cross-user read attempts |
| L-08 | W-28 | An unenrolled uid uses a per-user connector's hook route, or one user's credential posts events attributed to another | Hook socket authorization: per-user connectors require a ledger row for that uid and connector; machine-policy connectors inspect every user unless `enrollment.unenrolled_users: deny`; uid 0 follows `enrollment.root`; `exempt_users` are inspected and logged. TCP: only per-user credentials authenticate a connector route or OTLP source, only while the ledger protects that uid; the event is attributed to that uid and a request whose identity headers name anyone else is refused; connector-wide credentials are not accepted | `internal/gateway/managed_hook_peer_test.go`, `internal/gateway/user_scoped_credentials_test.go` |
| L-09 | W-06 | The root guardian follows a user-planted symlink or races a check-then-act inside a home | The root guardian refuses in-process home access in the standalone profile; the per-user worker operates with the user's own kernel permissions, so a race gains nothing the user did not already have | `internal/enterprisehooks/standalone_unix_test.go`, worker tests |
| L-10 | W-08 | A credential drop leaks into other goroutines | No `Seteuid` in the guardian process; the worker is a separate process started with the target credentials (`SysProcAttr.Credential`) | Worker tests |
| L-11 | — | A home under a world-writable ancestor (for example `/tmp`) is swapped by another user | Refused with a reason before any mutation | `internal/enterprisehooks/home_unix.go` tests |
| L-12 | — | An NFS `root_squash`, autofs, ecryptfs-locked or homed home breaks repair or is treated as deleted | The worker reads as the user; an unavailable home is `deferred`, not failed or revoked | `pendingErrno` tests |
| L-13 | W-42 | A directory outage or uid reuse revokes or mis-enrolls users | NSS lookups; only a definitive not-found counts; three consecutive misses before revocation; uid and home-inode identity | `internal/unixidentity/identity_test.go`, `internal/enterprisehooks/enumerator_unix_test.go` |
| L-14 | W-09 | A user deletes or edits a per-user registration | File watching plus a one-minute reconcile repairs through the worker | Tamper-and-measure runs per connector |
| L-15 | W-26, W-49 | A user disables Codex or Claude Code hooks (`[features] hooks = false`, `-c`, `disableAllHooks`, `CODEX_HOME`, `CLAUDE_CONFIG_DIR`) | Machine policy in `/etc/codex/requirements.toml` (with `allow_managed_hooks_only` and a mandatory `[features] hooks = true` pin) and `/etc/claude-code/managed-settings.d/90-defenseclaw.json` (with `allowManagedHooksOnly`), both under the default `managed_hooks_only: enforce` | `internal/enterprisepolicy/codex_test.go`, `claude_test.go`; `sudo DEFENSECLAW_CONFIG=/etc/defenseclaw/config.yaml /opt/defenseclaw/bin/defenseclaw-gateway enterprise policy verify --live --user <user> --connector <codex or claudecode> --agent-binary <absolute path>` |
| L-16 | W-50 | A user or project hook rewrites a tool call (Cursor, Copilot, Devin, OpenCode, Amp, and Hermes shell hooks in `~/.hermes/config.yaml` and in the managed-scope `config.yaml` that `HERMES_MANAGED_DIR` names, checked by the per-user `hermes-hook.sh` through `defenseclaw-hook`; R24 lists the Hermes gaps) | Foreign-hook guard: guardian removal from user config through the worker, hook-time project check, allowlist by hash | `internal/enterprisepolicy/guard_test.go`, `internal/enterprisepolicy/guard_hermes_test.go`, `internal/gateway/connector/hermes_foreign_guard_test.go` |
| L-17 | W-30 | Uninstall deletes an administrator's vendor policy | Ownership records and preimages; remove only DefenseClaw-owned entries; restore preimages | Install over existing admin policy; uninstall; byte compare |
| L-18 | W-15 | A failed upgrade leaves mixed state | Transaction snapshot, rollback and crash recovery on the next run | `internal/enterpriseunix/lifecycle_test.go` failure injection |
| L-19 | W-46 | Concurrent MDM runs collide | Lifecycle lock; exit `75` while busy | Lifecycle tests |
| L-20 | W-48 | A user reads the AI Defense key | `LoadCredential=` with a root-only file (systemd 247 or later), else `root:defenseclaw 0640`; the reader rejects any other owner, mode or link count | `internal/managed/credentials_test.go`, `internal/enterpriseunix/lifecycle_test.go` |
| L-21 | W-52 | A per-user install competes with the managed deployment | `scripts/install.sh`, `scripts/defenseclaw-upgrade.sh`, `defenseclaw upgrade` and the per-user gateway refuse while `/etc/defenseclaw/managed-runtime.json` exists; `--adopt-existing` backs up and takes over an older unmanaged layout | `cli/tests/test_upgrade_shim.py`, `internal/cli/managed_host_guard_test.go` |
| L-22 | W-13 | A removed user or connector stays authorized | The ledger is rebuilt from the current manifest; removed or disabled rows are revoked | Enumerator and guardian tests |
| L-23 | — | SELinux, fapolicyd or AppArmor silently blocks a service | Relabel after install; lifecycle warnings | Host certification record |
| L-24 | W-21 | The gateway hangs without exiting | `WatchdogSec=60s` with `Type=notify`; systemd restarts it | SIGSTOP drill |
| L-25 | W-27 | An old, copied or self-built agent client (for example Codex built from source, or an older Codex or Claude Code under `~/.local`) ignores `/etc/codex/requirements.toml` or the managed-settings drop-in | Out of DefenseClaw's reach from user space: the hook-contract floors are in `cli/defenseclaw/inventory/hook_contracts.json`, and fapolicyd (or another application-control tool) allowing only approved client binaries at or above the floors closes it (enterprise R15). Claude Code releases that do not read `/etc/claude-code/managed-settings.d` (for example 1.0.128 and 2.0.77) ignore both DefenseClaw drop-ins, including the version floor, run with no DefenseClaw hook and no audit row, and are not reported by `status` or `verify` ([#920](https://github.com/cisco-ai-defense/defenseclaw/issues/920)). GitHub Copilot CLI 1.0.15, below its 1.0.18 floor, installed with `npm install --prefix` and run with `--no-auto-update`, does not load `/etc/github-copilot/policy.d` either. Per-user connectors below their contract minimum are the same class: OpenHands 1.11.0 (the minimum is 1.12.0), started with `uvx --from openhands==1.11.0 openhands`, starts without loading `~/.openhands/hooks.json`, and nothing refuses it or reports it, because it runs from the uv cache, where discovery does not look | Application-control profile on a host; an old client started from a user's home |
| L-26 | — | A standard user creates a private user and mount namespace and starts an agent with its own view of the machine policy, runtime descriptor or hook socket directory | `enterprise linux verify` warns (`unprivileged_user_namespaces`) unless the kernel refuses unprivileged user namespaces; the host sysctl closes it (residual 11, enterprise R20) | `internal/enterpriseunix/userns_test.go` |
| L-27 | W-57 | A user has an agent only as a desktop app or editor extension and is never enrolled | Not in this release: machine-policy hook calls are inspected under the default contract or refused (`unenrolled_users`), and per-user connectors get no hooks ([R25](ENTERPRISE-THREAT-MODEL.md#residual-risks), [#912](https://github.com/cisco-ai-defense/defenseclaw/issues/912)) | Tracked in #912 |
| L-28 | W-58 | A Copilot agent chat in VS Code's Local harness runs without DefenseClaw policy or audit | Partly covered: `ChatHooks` and `ChatEditorPreferCopilotHarness` through `/etc/vscode/policy.json` send new editor chats to the SDK harness. A per-user Local hook file governs a Local chat. Under `managed_hooks_only: enforce`, a per-user plugin is also placed, and `allowManagedHooksOnly` is set in `/etc/github-copilot/managed-settings.json` once every enrolled user has the plugin and every VS Code found is 1.139.x ([R26](ENTERPRISE-THREAT-MODEL.md#residual-risks), [#913](https://github.com/cisco-ai-defense/defenseclaw/issues/913)) | Tracked in #913 |
| L-29 | W-59 | The standalone profile is installed inside a WSL 2 distribution, where the Windows user is root | Not a supported deployment: the user controls the distribution. The lifecycle refuses a new install inside WSL and warns on an existing one (`wsl_distribution`) ([R27](ENTERPRISE-THREAT-MODEL.md#residual-risks), [#914](https://github.com/cisco-ai-defense/defenseclaw/issues/914)) | Govern WSL from the Windows side |
| L-30 | W-60 | Devin Desktop runs without DefenseClaw hooks for a user without the `devin` CLI | Enrolled at the bundled Devin CLI version when it is 3000.4.25 or later and not known broken, otherwise reported in `unprotected-agents.json`; Cascade is refused through the machine-level Cascade hooks file ([R28](ENTERPRISE-THREAT-MODEL.md#residual-risks), [#915](https://github.com/cisco-ai-defense/defenseclaw/issues/915)) | Tracked in #915 |
| L-31 | W-61 | The Kiro IDE's reading of the global `~/.kiro/hooks` file is not live-verified | Partly covered: the IDE is discovered from its `product.json`, an IDE-only user is enrolled, and an IDE before 1.0.182 is reported as `kiro_ide_below_global_hooks_floor` ([R29](ENTERPRISE-THREAT-MODEL.md#residual-risks), [#916](https://github.com/cisco-ai-defense/defenseclaw/issues/916)) | Tracked in #916 |
| L-32 | — | A user kills, stops or starves their own `defenseclaw-hook` (or `openhands-hook.sh`, `hermes-hook.sh`) while an agent waits for it | Not closable from user space: the hook is a user process. Claude Code, Codex, OpenHands, Devin and Hermes then run the call with no DefenseClaw decision before it runs (Hermes' later `post_tool_call` hook can still record it); Copilot, OpenCode, Amp and Antigravity stay closed (residual 12, enterprise R5 and R18). Application control or EDR process protection closes it | Kill and stop drill on the user's hook processes |
| L-33 | — | A project's `.openhands/hooks.json` replaces the user-level registration, so none of DefenseClaw's OpenHands hooks run in that project | Not closable by DefenseClaw: OpenHands uses the first `hooks.json` it finds, the project's before the user's, so any project file (a cloned repository can carry one) removes every DefenseClaw hook; the guardian does not restore or remove project files, the foreign-hook guard does not cover OpenHands, and policy verify does not look for it ([R30](ENTERPRISE-THREAT-MODEL.md#residual-risks)) | A project `.openhands/hooks.json` drill |
| L-34 | — | A user starts a per-user agent with another config root or a mode that skips user configuration (Amp or Devin with `XDG_CONFIG_HOME` or `HOME`, `devin --config <file>`, Antigravity or OpenHands with `HOME`, Hermes with `--safe-mode` or `HERMES_HOME`), so DefenseClaw's registration is never loaded | Not closable by DefenseClaw: the guardian repairs only the default location and cannot see a process's environment or command line, so the session is not inspected, logged or repaired, and status and verify keep the user's target ready (residual 7, enterprise R1). Application control over how users launch these agents closes it | Alternate config root and launch flag drill per connector |
| L-35 | — | A user, or an API caller, changes policy through a local config writer (`defenseclaw config set`, `skill`/`mcp`/`plugin`/`tool` `block` or `allow`, `guardrail block-at`, `policy activate`, `setup`, the TUI config editor, `POST /enforce/block`, `POST /enforce/allow`) | One config writer under `config.yaml.lock` refuses every actor except `lifecycle` and `migration` on a managed standalone host, also for root: the CLI exits `3` with "This device is managed", the gateway answers `403` `managed_device`, nothing is written and the attempt is audited (`outcome=refused reason=managed_device`). `/etc/defenseclaw/config.yaml` is root-owned in addition, so a standard user cannot write it at all | `internal/config/configwrite/configwrite_test.go`, `cli/tests/test_config_writer.py`, `internal/gateway/enforce_config_test.go`; enterprise B15 |
| L-36 | — | `config.yaml`, a unit file, a machine-policy entry or a hook script is edited in place | A standard user has no write access. An administrator's edit of `config.yaml` is validated by the apply trigger's `ensure --reason path` and recorded as the next config generation (`config.generation.json`, actor `lifecycle`), or reverted to `/var/lib/defenseclaw-enterprise/committed-config.yaml` with the edit kept as `rejected-config.yaml` (`config_rejected` in `status`, `verify` fails). Derived files are regenerated from the config and never read back; `verify` fails on drift | `internal/enterpriseunix/committed_config_test.go`, `internal/enterpriseunix/lifecycle_test.go`; enterprise B16 |
| L-37 | — | A user environment variable or `.env` entry weakens a check (`DEFENSECLAW_ALLOW_PRIVATE_UPSTREAMS`, `DEFENSECLAW_TOOL_INSPECT_FAIL_OPEN`, and the other security opt-outs) | The registry's `managed` setting: `ignore` variables read as unset from the environment and from `.env` on a managed standalone host; `DEFENSECLAW_FAIL_MODE`, `DEFENSECLAW_STRICT_AVAILABILITY` and `DEFENSECLAW_HOOK_MAX_BODY` are `tighten_only`. Doctor names the ignored variables, never their values | `internal/envvars/registry_test.go`, `cli/tests/test_envvars.py`; enterprise B17 |
| L-38 | — | `DEFENSECLAW_DEPLOYMENT_MODE` or `DEFENSECLAW_ENTERPRISE_PROFILE` is forged so the host looks unmanaged | The managed test reads `deployment_mode` and `enterprise.profile` from `config.yaml` as well as the environment, so the environment can only add managed status. Both variables are `ignore` on a managed host, the gateway, guardian, enumerator and sensor-helper units pin the profile, and a `.env` file cannot set it | `internal/config/validate_candidate.go`, `cli/defenseclaw/config_writer.py`; enterprise B18 |
| L-39 | — | Operator block or allow entries are placed in the `actions` table of `audit.db` | Ignored: the gateway decides from `asset_policy` in the config. A managed `ensure` that migrates a version 8 config counts them and warns `local_enforcement_entries_ignored`; it neither imports nor deletes them | `internal/enforce/policy.go`, `internal/config/migrate_v9.go`; enterprise B19 |
| L-40 | — | A release is fetched from a redirected source (`update.source`, `DEFENSECLAW_REPO`) and installed | The release identity is compiled into `install.sh` and `defenseclaw upgrade`; the source only changes where bytes come from. A mirror needs cosign 2.0 or later and the unchanged signed `checksums.txt`; only the official source falls back to `checksums.txt` alone. On a managed host `defenseclaw upgrade` and `rollback` refuse and `DEFENSECLAW_REPO` is ignored | `cli/tests/test_upgrade_shim.py`; enterprise B20 |
| L-41 | — | The gateway enforces an older policy than the config on disk | A change that does not build keeps the previous policy generation and shows as `policy.last_reload_error` on `/health`; `status --json` and `verify --json` report `policy.applied` (the digest the config computes to against the one the gateway reports), and `ensure` warns `policy_not_applied`. The last applied digest is in `policy-state.json` | `internal/enterpriseunix/policystate_test.go`; enterprise B21 |
| L-42 | — | A local account, or an endpoint it controls, uses Tetragon's API: a TCP listener lets any account load or remove kernel policies, and a forged socket or info file could point the helper at an attacker | The helper reads `/var/run/tetragon/tetragon-info.json` only when root owns it and nobody else can write it, dials only `unix://` addresses, and connects only when the socket file and its directory belong to root, are not world-writable, and `SO_PEERCRED` of the connection is uid 0 and the pid the info file names. A TCP `server_address` is never dialed: the helper stays on `cn_proc` and `fanotify`, `observe` and `enforce` are refused, and status and `doctor` warn `tetragon_tcp_api`. The helper's calls are limited per mode: `off` and `consume` read only (and delete names it recorded itself), `observe` and `enforce` may also add, configure and delete `defenseclaw-*` policies | `internal/sensor/tetragon` and `internal/sensor/kernelpolicy` tests with a fake Tetragon server (missing socket, TCP address, wrong owner, wrong peer, call allow-list per mode); live rows TG-04 and TG-14 |
| L-43 | — | A compromised gateway or user asks the helper to load, widen or remove kernel policy | The request protocol stays fieldless and gains one read-only operation, `kernel_status`. Desired state comes only from root-owned inputs: the helper's drop-in (rendered by the lifecycle from the config `ensure` accepted), the control set compiled into the binary, `targets.yaml` and the process table. The helper never reads `config.yaml`, and the gateway sends no policy | `internal/sensor/acquire` request field-count test; `internal/enterpriseunix` render tests |
| L-44 | — | A kernel control denies the wrong process or user: an empty filter list widens a rule, a look-alike process is treated as an agent, or an IDE terminal is locked out | A policy linter refuses any deny selector whose binary, pid, user or namespace list is empty (upstream ignores an empty binary list, which would leave a path-only rule). Controls apply only below an enrolled command-line agent, resolved to its real install file or live pid, as that uid, in the host process namespace. Processes recognized only by name or arguments, IDE-hosted agents and other users are observe-only. Only `Post`, `NoPost` and `Override -EPERM` are allowed; there are no program denies, no `Sigkill`, no socket or address rules, and no hook-runtime, provider-credential or repository paths. A control is enforced only with a matching `enforce_ack`, for a connector in `action` mode, and for a user who finished a measured burn-in | `internal/sensor/kernelpolicy` lint tests and golden renders; live rows TG-15 to TG-26 |
| L-45 | — | An administrator's stop is undone by a helper or Tetragon restart, or a human's change is overwritten | `enterprise linux tetragon pause` writes a root-owned record that survives restarts of the helper and of Tetragon (`--until-reboot` is kept in `/run`), is checked before every policy change, and moves the controls to monitor within seconds. A policy moved to monitor or deleted with `tetra` is recorded as an operator override and never re-promoted until the intent (`enforce_ack` or the mode) changes. A control set that changes with a release makes the old ack stale | `internal/sensor/kernelpolicy` reconciler tests; live rows TG-29 to TG-31 |
| L-46 | — | DefenseClaw's policies stay loaded in Tetragon after uninstall, purge, rollback, downgrade or a stopped helper, enforcing with nobody reconciling | Every exit path deletes the names the helper recorded, using the helper that loaded them, before binaries or state are removed: `uninstall`, `purge`, a transaction rollback, and the package's pre-removal script. `verify` fails with `kernel_policy_orphaned` for a recorded name that is still loaded while the mode is `off` or `consume` or the helper is not running. Enforcement is refused when Tetragon runs with `keep-sensors-on-exit`, because its programs would outlive it | `internal/enterpriseunix` lifecycle and `packaging/linux` tests; live rows TG-33 to TG-37 |
| L-47 | — | Command lines read from Tetragon carry secrets or a turn's content to the gateway or an exporter | The helper applies the shared command-line redaction before a line leaves it, withholds the arguments of Codex's notify program, asks Tetragon for no environment variables, capabilities, namespaces or pod data, and never forwards raw Tetragon events. The hook's own short-lived helper processes are summarized; any other child, and any process that does not match the exact rendered hook command, is forwarded in full | `internal/redaction` tests; `internal/sensor` self-filter tests; live row TG-08 |
| L-48 | — | The helper changes or deletes a policy of the customer's while it reads that policy's events, or those events carry content to the gateway or an exporter that the customer did not expect | Ownership is by record: a policy is DefenseClaw's only if this helper recorded loading it, whatever its name, and a customer policy named like a DefenseClaw one is treated as the customer's and warned about (`tetragon_foreign_defenseclaw_name`). The reading adds no request and no RPC: the per-mode call allowlist of L-42 is unchanged, and a fake Tetragon serving customer policies (one named `defenseclaw-controls-deadbeef`, one from `tetragon.tp.d`) sees no add, delete or configure call naming them through every mode, a mode change, the cleanup, uninstall and rollback. Only typed fields of kprobe and LSM events cross the broker (policy name, hook type, function, action, policy mode, outcome, one file or binary path or socket peer, tags, message and the process facts every event carries, with the command line redacted). String and byte arguments, integers, credentials, stack traces, return values, ancestors and the raw event are never forwarded; a test feeds a string argument carrying a marker and asserts it never crosses. Volume is bounded in the helper (repeats folded within 60 seconds, 20 events a second per policy, 200 a second per host, the overflow counted and warned as `tetragon_customer_events_capped`). The gateway exports a record only for an event below an AI agent's process lineage; the rest are counted per policy. The target is a content-class field, so each destination's redaction profile decides whether it leaves the computer, and `enterprise.tetragon.customer_events: off` forwards nothing. The events are not scored | `internal/sensor/tetragon` mapper fixtures and the never-mutate pin; `internal/sensor` host-plane lineage-gate tests; manual onboarding rows OB-05 to OB-07 |

## Invariants

- The Linux profile is always `standalone`.
- PID 1 owns the gateway's listening sockets; the gateway only inherits them.
- The gateway has no capabilities and cannot write outside its own
  directories.
- The root guardian does not touch user homes itself.
- A hook trusts only uid 0 or the service uid read from the root-owned
  descriptor.
- A lookup error is "unknown", never "deleted".

## Residual risks

1. Per-user registrations are user-owned. A user can remove them until the
   next repair (seconds with the watcher, at most one reconcile interval
   otherwise). Machine-policy connectors do not have this window.
2. A runtime descriptor without `hook_socket` (hand-edited, or left by a
   broken install) makes every managed hook fail closed and every per-user
   target fail repair; the lifecycle always writes it.
3. A user can hold the TCP port while an administrator has stopped the
   gateway's socket unit (socket activation keeps it bound otherwise). Hooks
   and plugins use the socket and are unaffected. The Codex, Claude Code,
   OpenHands and OmniGent telemetry exporters do not verify the
   listener, so while the port is held their telemetry, which can include
   prompt text, goes to the holder together with the sending user's
   per-user telemetry credential. The holder can replay a captured
   credential once the gateway is back to post telemetry attributed to that
   user for that connector until the user leaves enrollment; the credentials
   do not rotate. A telemetry credential never authenticates hook, inspect
   or management routes or another connector
   ([R7](ENTERPRISE-THREAT-MODEL.md#residual-risks)).
4. The sensor helper and guardian run as root with capabilities. A compromise
   of either collapses into the trusted-administrator assumption.
5. The vendor residuals in the
   [enterprise threat model](ENTERPRISE-THREAT-MODEL.md#residual-risks) apply.
6. Confined SELinux users (`user_u`) and fapolicyd rules may block the hook
   binary or agent CLIs; the lifecycle reports but does not rewrite host
   policy.
7. Amp loads plugins only from the per-user config directory, which follows
   `XDG_CONFIG_HOME`. A user who starts Amp with `XDG_CONFIG_HOME` pointing
   at another directory runs it without the DefenseClaw plugin. The guardian cannot see a per-process environment,
   no DefenseClaw hook runs that could detect it, and Amp has no machine
   plugin path (R3). The same holds for every per-user connector started
   with another config root or a mode that skips user configuration (R1):
   Amp with `HOME`, Devin with `XDG_CONFIG_HOME` or `devin --config <file>`
   naming a copy without hooks, Antigravity with `HOME`, Hermes with
   `--safe-mode` or `HERMES_HOME`, and OpenHands with `HOME` run tool calls
   with no DefenseClaw audit row, and the guardian never repairs such a
   session.
   `status` and `verify` keep reporting the user's target ready, because
   the registration in the default location is intact (L-34). Hermes
   `--ignore-user-config` on its own keeps DefenseClaw's hooks, and
   `DEFENSECLAW_*` overrides do not remove them. The machine-policy
   connectors are not affected. Closing it needs application control over how users launch
   these agents (for example allowing the agent binary to run only from an
   administrator-owned launcher that resets these variables and refuses
   these flags), or a vendor machine setting that pins the config directory.
8. Agent versions without a verified DefenseClaw hook contract get no
   DefenseClaw hooks (the guardian refuses hooks it cannot parse). Status
   and verify report them as `hook_contract_unverified` with
   `security_complete: false`; the administrator pins a verified version or
   upgrades DefenseClaw. An enrolled user who upgrades to such a version
   keeps a row at the last verified one, so the guardian keeps repairing
   those hooks, and the new version is reported the same way; an upgrade to
   another verified version is re-rendered.
9. Agent discovery covers the per-user install locations, the Node version
   managers (nvm, fnm, Volta, asdf, mise), pnpm and yarn global directories,
   the `~/.npmrc` prefix, the machine prefixes and `agent_prefixes`. An agent
   found there that cannot be enrolled is reported as `agent_unprotected`.
   An agent CLI a user installs or copies anywhere else in their home (a
   custom `NVM_DIR`, `XDG_DATA_HOME` or `PNPM_HOME`, a command-line
   `--prefix`, an arbitrary directory) is not found: it is neither enrolled
   nor reported, and a per-user connector run from there has no DefenseClaw
   hooks. Closing it needs application control over where users run agents
   from. A user who has never been enrolled and whose home is untrusted
   (for example group-writable) is not enrolled; the agents found for them
   by a discovery that runs nothing in that home are reported as
   `agent_unprotected` until the home is fixed.
10. Local accounts whose uid is above login.defs `UID_MAX`, and accounts with
    a nologin shell, are not enrolled unless they are listed in
    `enrollment.include_users` (directory accounts above `UID_MAX` are
    enrolled unless `enrollment.uid_max` caps them). Per-user connectors are
    not installed for such users, and their per-user hook calls fail closed;
    machine-policy connectors treat them as unenrolled users, which are
    inspected unless `enrollment.unenrolled_users` is `deny`.
11. Where standard users can create a private user and mount namespace, an
    agent started inside one can be given its own view of
    `/etc/codex/requirements.toml`, the other machine-policy files, the
    runtime descriptor and `/run/defenseclaw-hook`, outside the
    administrator's enforcement. `enterprise linux verify` warns with
    `unprivileged_user_namespaces` unless `user.max_user_namespaces=0`,
    `kernel.unprivileged_userns_clone=0`, or both
    `kernel.apparmor_restrict_unprivileged_userns=1` and
    `kernel.apparmor_restrict_unprivileged_unconfined=1` (the Ubuntu 24.04
    default leaves the second at `0`). DefenseClaw cannot close this from
    user space; the host sysctl can (R20). Both settings also restrict the
    agents' bubblewrap command sandboxes: `user.max_user_namespaces=0` stops
    Codex's and Claude Code's sandboxes, and on stock Ubuntu 24.04 the
    AppArmor userns restriction already stops Codex's bundled bubblewrap
    (`bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted`), so
    its shell calls fail until the user runs without its sandbox.
12. `defenseclaw-hook` and the per-user hook scripts run as the user, who
    can terminate, suspend or starve them; agents that block only on an
    explicit deny then run the call, with no DefenseClaw decision or audit
    row before it runs (R18, L-32). With the user's own hook processes
    killed or stopped, Claude Code and Codex run the tool call (a killed hook
    is a non-2 exit; a stopped one times out after 30 s), and so do OpenHands
    (`Exit Code: -9`), Devin and Hermes for a killed hook. For Hermes no
    `pre_tool_call` row reaches the gateway, while its later `post_tool_call`
    and model hooks do, so the audit shows the call only after it ran (R5).
    Copilot, OpenCode, Amp and Antigravity stay closed. Closing it needs
    the vendor to treat a failed or timed-out hook as a deny, or
    application control or EDR that stops users from signalling the hook.
13. The root sensor helper reaches Tetragon's API, which lets its caller load
    kernel programs. Only the helper connects, over a verified Unix socket, but
    a compromise of the helper is also a kernel-policy compromise. It is
    inside the trusted-administrator assumption of residual 4. A Tetragon that
    serves its API on TCP is a host risk whatever DefenseClaw does; `doctor` and
    status warn (L-42).
14. The kernel controls are narrow by design (L-44). They deny in-place write
    opens of shell profiles and user autostart entries, and opens of SSH
    private keys by name, for the descendants of an enrolled command-line
    agent. They do not stop replacing a file by rename or removing it; a
    second name for the same file created beforehand (a link); a library-based
    SSH tool (libssh2, paramiko) in the agent's tree, which is denied like any
    other reader and shows in the burn-in first; a process that is not below an
    enrolled agent root (an IDE terminal, a look-alike by name, another
    user); agent configuration files, which are observed only; program
    execution; or any destination. Hook rules and the observe policy keep the
    record for these.
15. Kernel enforcement fails open. While Tetragon is stopped nothing is denied;
    after a restart the policies are loaded again within one reconcile pass
    (about a minute); while the helper is stopped loaded policies keep the
    scope they had. Enforcing policies anchor only native agent binaries,
    never a process ID: a pid freed and reused by another process of the same
    user inside the host namespace can briefly fall under a monitor-mode pid
    anchor until the next pass, where it can only count as a would-block hit
    (and reset that user's burn-in), never deny. Two coverage limits follow: a
    script-hosted agent (such as an npm install run by `node`) is monitored,
    never denied (`kernel_pid_anchor_monitor_only`), and one controls policy
    denies for one user per computer, the lowest uid of the users who
    finished burn-in and have a native agent install, while the other users
    stay in monitor
    (`kernel_binary_anchor_scope_limited`).
16. The arguments of Codex's notify program carry the turn's content. The
    helper withholds them from its stream, but any other
    process accounting on the computer (Tetragon's own export file, which is
    root `0600` and the customer's, or `auditd`) records them.
17. The events of the customer's own Tetragon policies carry a target (a file
    or binary path, or a socket peer) and a policy message for events below an
    AI agent. The helper forwards no other argument type, but a path can
    itself be sensitive. The target is a content-class field: each destination's
    redaction profile decides whether it leaves the computer, and
    `enterprise.tetragon.customer_events: off` stops the forwarding while
    keeping the counts (L-48).
