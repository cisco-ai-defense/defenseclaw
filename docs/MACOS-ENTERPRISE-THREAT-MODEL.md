# macOS managed-enterprise threat model

This is the macOS part of the [enterprise threat model](ENTERPRISE-THREAT-MODEL.md),
which defines the enterprise profiles, the trust zones Z0–Z5 and the
cross-platform boundary table.

macOS runs either profile:

- `secure_client` (the default when no profile is set) is installed by Cisco
  Secure Client through `packaging/macos/install.sh`, runs its gateway,
  guardian and enumerator as root under `com.cisco.secureclient.defenseclaw.*`
  in `/opt/cisco/secureclient/defenseclaw`, and is in production. The
  standalone work does not change its scripts, plists or behavior.
- `standalone` is installed by any MDM or an administrator through
  `defenseclaw-gateway enterprise macos …` or the standalone `.pkg`.

The rows below cover the standalone profile. They are numbered `M-01`…; the
second column names the matching Windows row.

## Review scope

- Primary paths:
  - `internal/enterpriseunix/` (lifecycle, shared with Linux; `launchd` platform)
  - `internal/cli/enterprise_unix*.go` (`defenseclaw-gateway enterprise macos …`)
  - `packaging/launchd-standalone/` (LaunchDaemons `com.cisco.defenseclaw.*`)
  - `scripts/build-macos-enterprise-pkg.sh` (standalone `.pkg`)
  - `internal/gateway/api_uds_unix.go`, `internal/gateway/managed_hook_peer.go`
  - `internal/gateway/connector/hookexec/managed_standalone_transport.go`
  - `internal/peercred/peercred_darwin.go`
  - `internal/unixidentity/platform_darwin.go`, `internal/cli/enterprise_hooks_worker_darwin.go`
  - `internal/enterprisepolicy/` (`*_darwin.go` sources)
- Out of scope: the Secure Client packaging under `packaging/macos/` and
  `packaging/launchd/`.

## Security objectives

1. A standard user cannot unload, edit or replace any DefenseClaw
   LaunchDaemon, binary, config, policy, secret, manifest, ledger or runtime
   descriptor.
2. The gateway runs as the hidden `_defenseclaw` user and can write only its
   runtime state and its log directory.
3. `defenseclaw-hook` sends no request byte until `LOCAL_PEERCRED` proves the
   hook socket's listener is root or `_defenseclaw`. DefenseClaw's in-agent
   plugins (OpenCode, Amp) and the Codex notify bridge use the same socket
   and check; there is no TCP fallback. The agents' own telemetry exporters
   do not verify the listener (residual 6).
4. The gateway authorizes every hook caller by kernel uid against the root
   guardian's ledger.
5. The root guardian never touches a user home itself; a per-user worker does
   it as that user.
6. Vendor machine policy is merged, never replaced.
7. A normal user cannot disable DefenseClaw's hooks through vendor settings,
   and a foreign hook cannot rewrite a tool call DefenseClaw inspected for a
   connector with a vendor lock or the foreign-hook guard, within the bounds
   of enterprise residuals R3, R4, R13 and R14. Antigravity, OpenHands and
   OmniGent have neither, and the guard covers Hermes shell hooks with the
   gaps listed in R24.

## Zones on macOS (standalone)

| Zone | What runs or lives there | Identity | Protected by |
| --- | --- | --- | --- |
| Z0 | launchd, root, the MDM agent, the `.pkg` postinstall, `defenseclaw-gateway enterprise macos` | root | Trusted by assumption |
| Z1 | `com.cisco.defenseclaw.hook-guardian` (watch, one-minute reconcile) | root | Root-owned plist in `/Library/LaunchDaemons`; `KeepAlive` |
| Z1 | `com.cisco.defenseclaw.hook-enumerator` (five-minute cycle) | root | Same |
| Z1 | Per-user `enterprise hooks apply-target` worker | the target's uid and primary gid | New session; the guardian's timeout kills its process group; cross-user task ports are denied by the OS |
| Z1 | `com.cisco.defenseclaw.sensor-helper` | root | Fixed request protocol; homes from the manifest |
| Z0 | `com.cisco.defenseclaw.apply` (`WatchPaths` on config, secrets, policies → `ensure`), `com.cisco.defenseclaw.verify` (daily); they run the lifecycle | root | Root-owned plists |
| Z2 | `com.cisco.defenseclaw.gateway` | `_defenseclaw` (`UserName`/`GroupName`), `Umask` 077 | Read-only config, policy and ledger; writes `/opt/cisco/defenseclaw/runtime` and `/Library/Logs/Cisco/DefenseClaw/gateway` |
| Z2 endpoints | `127.0.0.1:18970` and `/opt/cisco/defenseclaw/run/hook.sock`, bound by the gateway | `_defenseclaw` | The lifecycle creates `/opt/cisco/defenseclaw/run` for `_defenseclaw` inside the root-owned install tree; it survives reboot and no other user can create a file there |
| Z3 | `/opt/cisco/defenseclaw/{bin,etc,etc/policies,etc/secrets,etc/hook-guardian,lifecycle,hook-guardian-state}` (the `run/` socket directory belongs to `_defenseclaw`), `/Library/Application Support/{ClaudeCode,Cursor,opencode}`, `/etc/codex`, `/etc/github-copilot/policy.d` | root (secrets `root:_defenseclaw 0640`) | Administrator-only write |
| Z4 | The AI agent and `/opt/cisco/defenseclaw/bin/defenseclaw-hook` as the user | the user | Peer verification, repair, foreign-hook guard |

launchd hands sockets to a daemon only through `launch_activate_socket(3)`,
which needs cgo; release builds are `CGO_ENABLED=0`, so the macOS gateway
binds its own listeners. The protected socket directory, not socket
activation, is what prevents squatting on the hook socket. The hook socket
does not use `/var/run`: macOS clears it at boot and `_defenseclaw` cannot write it. The
lifecycle creates `/opt/cisco/defenseclaw/run` (`0755`, owned by
`_defenseclaw`); no boot-time prepare daemon is needed.

## Data flows

### Install and lifecycle

1. The MDM installs the standalone `.pkg` (or stages a payload) and runs
   `defenseclaw-gateway enterprise macos ensure` as root. The postinstall
   calls the same lifecycle.
2. The lifecycle creates the hidden `_defenseclaw` user and group with
   `dscl` if needed, lays out `/opt/cisco/defenseclaw` from
   `managed.StandaloneLayoutFor("darwin")`, writes the LaunchDaemons, and
   runs the same locked, snapshotted, verified transaction as on Linux. It
   refuses when a Secure Client deployment is present.
3. Exit codes are `0`, `1`, `2` and `75`.

### Hook request

1. The agent runs the admin-owned hook as the user.
2. The hook reads the socket path and the `_defenseclaw` uid from the
   root-owned descriptor `/opt/cisco/defenseclaw/etc/managed-runtime.json`.
3. It resolves the socket directory through platform symlinks, requires it
   to be owned by root or the service account and writable by no one else,
   connects to `/opt/cisco/defenseclaw/run/hook.sock`, and requires the
   `LOCAL_PEERCRED` uid to be 0 or the service uid before sending.
4. There is no TCP fallback. A descriptor that names no hook socket fails
   closed (`enterprise_managed_hook_socket_missing`), and the guardian
   renders per-user hooks and in-agent plugins only for the socket.
5. Consumers that still use the TCP API (Codex, Claude Code and OpenHands
   telemetry) authenticate with credentials bound to the user's
   uid (see L-08); the gateway attributes their events to that uid.

### Enrollment

Accounts resolve through `os/user`, which on macOS goes through libSystem
and Open Directory, so directory-bound and mobile accounts resolve; `dscl .
-list /Users` lists local accounts. Directory accounts are found through
logged-in sessions, home owners under `/Users` and
`enrollment.include_users`. Candidates need a uid of 501 or more
(`enrollment.uid_min` raises the floor) and a login shell, unless they are
listed in `enrollment.include_users`. As on Linux, a lookup error is never a
deletion, and a row is revoked only after three consecutive definitive
not-found answers.

## Threat analysis

| ID | Windows | Threat | Control | Evidence |
| --- | --- | --- | --- | --- |
| M-01 | W-01 | A user unloads, disables or edits a LaunchDaemon (`launchctl bootout`, `disable`, plist edit) | System-domain daemons require root; plists are `root:wheel 0644`; `KeepAlive` restarts a killed daemon | `launchctl` attempts as each test user |
| M-02 | W-02 | A user replaces a binary, config, policy, secret, manifest, ledger or descriptor | Root ownership of every file and ancestor under `/opt/cisco/defenseclaw`; trusted-path checks on read | Write and swap attempts; `verify` |
| M-03 | W-04 | A user downgrades the mode or profile | Mode and profile pinned in the `EnvironmentVariables` of the gateway, guardian, enumerator and sensor-helper plists; config must agree | Config and profile tests |
| M-04 | W-05 | A compromised gateway edits policy or the ledger | `_defenseclaw` has no write access to `etc/`, `hook-guardian-state/` or `bin/` | File-mode verification |
| M-05 | W-25 | A user wins the gateway's endpoint during a restart | Hooks, in-agent plugins and the Codex notify bridge use only the socket, in a directory no other user can write, and verify the peer uid before sending; the gateway serves the socket even while another process holds the TCP port. The TCP telemetry exporters do not verify the listener (residual 6) | `managed_standalone_transport_test.go`, `api_uds_unix_test.go`, `api_run_hook_socket_unix_test.go`; squat-and-restart race on a host |
| M-06 | — | A user pre-creates the socket or its directory, or the directory disappears at boot | The directory is `/opt/cisco/defenseclaw/run`, created by the lifecycle for `_defenseclaw` inside the root-owned install tree, so it persists across reboot and no other user can create entries; the gateway refuses a directory with any other owner or a group/other write bit and replaces only a stale socket it owns | `internal/gateway/api_uds_unix_test.go`; reboot test on a host |
| M-07 | W-28 | An unenrolled uid uses a per-user connector's hook, or one user's TCP credential posts events attributed to another | Hook-socket authorization against the ledger; per-user TCP credentials bound to the uid (as L-08). A telemetry credential an exporter sent to a process holding the port stays usable by that process (residual 6) | `managed_hook_peer_test.go`, `user_scoped_credentials_test.go` |
| M-08 | W-06 | Root follows a user symlink inside a home | The root guardian refuses in-process home access; the worker acts as the user | Worker and standalone tests |
| M-09 | — | TCC blocks the worker from reading the agent's configuration | Agent configs live in dotdirs in the home, which TCC does not protect. For sites that relocate them into TCC-protected folders, a PPPC profile can grant Full Disk Access to `/opt/cisco/defenseclaw/bin/defenseclaw-gateway`, the binary that runs the guardian (`enterprise hooks watch`) and its per-user worker. This has not yet been checked on a real host | Host run with each connector |
| M-10 | W-26, W-49 | A user disables Codex or Claude Code hooks | `/etc/codex/requirements.toml` with `allow_managed_hooks_only` and `[features] hooks = true`; `/Library/Application Support/ClaudeCode/managed-settings.d/90-defenseclaw.json` with `allowManagedHooksOnly` (default `managed_hooks_only: enforce`) | Machine-policy tests; `sudo DEFENSECLAW_CONFIG=/opt/cisco/defenseclaw/etc/config.yaml /opt/cisco/defenseclaw/bin/defenseclaw-gateway enterprise policy verify --live --user <user> --connector <codex or claudecode> --agent-binary <absolute path>` |
| M-11 | W-51 | A higher-precedence source shadows DefenseClaw's policy: the Codex MDM preference `com.openai.codex` `requirements_toml_base64` outranks `/etc/codex`, and Claude Code managed preferences outrank the file drop-in | Detect the preference and accept it when it carries DefenseClaw's hooks (or, for Claude Code 2.1.242 or later, sets `managedSourcesBehavior: merge`); `enterprise policy export` produces the plist block the MDM should carry (`--format plist` for both connectors). For Codex and Claude Code alike, `higher_precedence_sources: fail` (default) records a conflict and reports the connector as not covered, and `warn` only reports it. On this code the policy commands read the config named by `DEFENSECLAW_CONFIG`, so run them with `DEFENSECLAW_CONFIG=/opt/cisco/defenseclaw/etc/config.yaml` | `codex_sources_darwin.go`, `claude_sources_darwin.go`, `codex.go`, `claude.go` tests |
| M-12 | W-50 | A user or project hook rewrites a tool call (Cursor, Copilot, Devin, OpenCode, Amp, and Hermes shell hooks in `~/.hermes/config.yaml` and in the managed-scope `config.yaml` that `HERMES_MANAGED_DIR` names, checked by the per-user `hermes-hook.sh` through `defenseclaw-hook`; R24 lists the Hermes gaps) | Foreign-hook guard | `guard_test.go`, `guard_hermes_test.go`, `hermes_foreign_guard_test.go` |
| M-13 | W-48 | A user reads the AI Defense key | `root:_defenseclaw 0640` in a `0750` directory; the reader requires root ownership, a single link and no access for others | Credential tests |
| M-14 | W-52 | A per-user install competes with the managed deployment | `scripts/install.sh`, `defenseclaw upgrade` and the per-user gateway refuse while the descriptor exists | Refusal tests |
| M-15 | W-15 | A failed upgrade leaves mixed state | Transaction snapshot and rollback | Lifecycle tests |
| M-16 | — | The standalone and Secure Client profiles are installed together | The standalone lifecycle refuses when a Secure Client deployment is present | `secureClientPresent` tests |
| M-17 | W-27 | An old, copied or self-built agent client ignores `/etc/codex/requirements.toml` or the Claude Code managed-settings drop-in | Out of DefenseClaw's reach from user space: the hook-contract floors are in `cli/defenseclaw/inventory/hook_contracts.json`, and Santa (or another application-control tool) allowing only approved client binaries at or above the floors closes it (enterprise R15). Claude Code 2.0.0, installed by a standard user under their home, does not read `/Library/Application Support/ClaudeCode/managed-settings.d`, so it ignores both DefenseClaw drop-ins, including the version floor, runs with no DefenseClaw hook, and is not reported by `status` or `verify` ([#920](https://github.com/cisco-ai-defense/defenseclaw/issues/920)). Per-user connectors below their contract minimum are the same class: OpenHands 1.11.0 (the minimum is 1.12.0), started by a standard user with `uvx --from openhands==1.11.0 openhands`, does not load `~/.openhands/hooks.json`, so its tool calls run with no DefenseClaw decision or audit row; nothing refuses it, discovery does not look in the uv cache it runs from, and `status` and `verify`, which check only the enrolled OpenHands and its default hook file, keep reporting the user's target ready | Application-control profile on a host; an old client started from a user's home |
| M-18 | W-57 | A user has an agent only as a desktop app or editor extension and is never enrolled | Not in this release: machine-policy hook calls are inspected under the default contract or refused (`unenrolled_users`), and per-user connectors get no hooks ([R25](ENTERPRISE-THREAT-MODEL.md#residual-risks), [#912](https://github.com/cisco-ai-defense/defenseclaw/issues/912)) | Tracked in #912 |
| M-19 | W-58 | A Copilot agent chat in VS Code's Local harness runs without DefenseClaw policy or audit | Partly covered: `ChatHooks` and `ChatEditorPreferCopilotHarness` through an MDM profile (DefenseClaw reports the values but does not write them) send new editor chats to the SDK harness; a Local chat is governed only by a hand-bound `--hook-surface vscode-local` hook ([R26](ENTERPRISE-THREAT-MODEL.md#residual-risks), [#913](https://github.com/cisco-ai-defense/defenseclaw/issues/913)) | Tracked in #913 |
| M-20 | W-60 | Devin Desktop runs without DefenseClaw hooks for a user without the `devin` CLI | Enrolled at the bundled Devin CLI version when it is at a pinned contract version, otherwise reported in `unprotected-agents.json`; Cascade is refused through the machine-level Cascade hooks file ([R28](ENTERPRISE-THREAT-MODEL.md#residual-risks), [#915](https://github.com/cisco-ai-defense/defenseclaw/issues/915)) | Tracked in #915 |
| M-21 | W-61 | The Kiro IDE's reading of the global `~/.kiro/hooks` file is not live-verified | Partly covered: the IDE is discovered from its `product.json`, an IDE-only user is enrolled, and an IDE before 1.0.182 is reported as `kiro_ide_below_global_hooks_floor` ([R29](ENTERPRISE-THREAT-MODEL.md#residual-risks), [#916](https://github.com/cisco-ai-defense/defenseclaw/issues/916)) | Tracked in #916 |
| M-22 | — | A user kills, stops or starves their own `defenseclaw-hook` (or a per-user hook script) while an agent waits for it | Not closable from user space: the hook is a user process. Claude Code, Codex, OpenHands (killed, or stalled until its 60 s timeout, leaving only its own confirmation prompt, which the user answers) and Hermes (killed) then run the call with no DefenseClaw decision or audit row; Copilot stays closed unless every one of its hooks is stopped, and OpenCode and Amp stay closed (residual 8, enterprise R5 and R18). Application control or EDR process protection closes it | Kill and stop drill on the user's hook processes |
| M-23 | — | A project's `.openhands/hooks.json` replaces the user-level registration, so none of DefenseClaw's OpenHands hooks run in that project | Not closable by DefenseClaw: OpenHands uses the first `hooks.json` it finds, the project's before the user's, so any project file (a cloned repository can carry one) removes every DefenseClaw hook; the guardian does not restore or remove project files, the foreign-hook guard does not cover OpenHands, and policy verify does not look for it ([R30](ENTERPRISE-THREAT-MODEL.md#residual-risks)) | A project `.openhands/hooks.json` drill |
| M-24 | — | A standard user kickstarts the on-demand `apply` or `verify` LaunchDaemon | Accepted: the jobs run fixed, idempotent root work from root-owned inputs; the lifecycle lock serializes them with administrator runs (residual 9) | `launchctl kickstart` as a standard user |
| M-25 | — | A standard user hard-links root-owned DefenseClaw files into their home | Accepted: a link keeps the file's owner and mode, and the files DefenseClaw refuses with more than one link are in directories standard users cannot search (residual 10) | Hard-link attempts as a standard user; `verify` and `repair` |
| M-26 | — | A user starts a per-user agent with another config root or a mode that skips user configuration (Amp with `XDG_CONFIG_HOME`, Hermes with `--safe-mode` or `HERMES_HOME`), so DefenseClaw's registration is never loaded | Not closable by DefenseClaw: the guardian repairs only the default location and cannot see a process's environment or command line, so the session is not inspected, logged or repaired, and status and verify keep the user's target ready (residual 1, enterprise R1). Application control over how users launch these agents closes it | Alternate config root and launch flag drill per connector |

## Residual risks

1. Per-user registrations are user-owned and repaired within one reconcile
   interval, as on the other platforms, and a per-user agent started with
   another config root or a mode that skips user configuration never loads
   them ([R1](ENTERPRISE-THREAT-MODEL.md#residual-risks), M-26): Amp with
   `XDG_CONFIG_HOME` naming a directory without DefenseClaw's plugin, Hermes
   with `--safe-mode`, and Hermes with `HERMES_HOME` naming a copy of
   `config.yaml` without the `hooks` block run tool calls with no DefenseClaw
   decision or audit row. The guardian cannot see a
   per-process environment or command line, so it never repairs such a
   session, and `status` and `verify` keep reporting the user's target
   ready. `DEFENSECLAW_*` overrides do not remove the hooks. Amp has no
   machine plugin path (R3) and Hermes has no DefenseClaw machine policy;
   closing it needs application control over how users launch these
   agents, for example allowing the agent binary to run only from an
   administrator-owned launcher that resets these variables and refuses
   these flags.
2. Without socket activation, a hook that runs while the gateway restarts
   fails closed rather than queuing.
3. The Codex and Claude Code MDM preference layers can override local files;
   they belong to whoever manages those preferences.
4. Unsigned (hash-pinned) builds do not satisfy Gatekeeper or notarization
   requirements; sign with a Developer ID and notarize, or re-sign.
5. The vendor residuals in the
   [enterprise threat model](ENTERPRISE-THREAT-MODEL.md#residual-risks) apply.
6. The gateway binds `127.0.0.1:18970` itself (launchd socket activation
   needs `launch_activate_socket(3)`, which the cgo-free release build does
   not call), so during every gateway restart a local user can bind the
   port. Hooks and plugins use the hook socket and are
   unaffected. `status`, `verify` and `repair` read the gateway's health
   over the hook socket, never from the port, and name the process that
   holds the port. The Codex, Claude Code, OpenHands and OmniGent
   telemetry exporters do not verify the listener: the holder receives
   their telemetry, which can include prompt text, and the sending user's
   per-user telemetry credential, and can replay that credential once the
   gateway is back to post telemetry attributed to that user for that
   connector until the user leaves enrollment. The credentials do not
   rotate, and a telemetry credential never authenticates hook, inspect or
   management routes or another connector
   ([R7](ENTERPRISE-THREAT-MODEL.md#residual-risks)).
7. An old, copied or self-built agent client can ignore machine policy
   (M-17); only application control closes it. This includes Claude Code
   releases that do not read `managed-settings.d` (for example 2.0.0), which
   ignore DefenseClaw's hooks and version floor alike ([#920](https://github.com/cisco-ai-defense/defenseclaw/issues/920)),
   and per-user connectors below their contract minimum: OpenHands 1.11.0,
   started with `uvx --from openhands==1.11.0 openhands`, loads no
   DefenseClaw hooks and is neither refused nor reported.
8. `defenseclaw-hook` and the per-user hook scripts run as the user, who can
   terminate, suspend or starve them; agents that block only on an explicit
   deny then run the call, with no DefenseClaw audit row for it
   ([R18](ENTERPRISE-THREAT-MODEL.md#residual-risks), M-22). With the
   user's own hook processes killed or stopped, Claude Code and Codex run
   the tool call (a killed hook is a non-2 exit; a stopped one times out
   after 30 s), OpenHands does for a killed hook (`Exit Code: -9`) and for
   one that stalls until its 60 s timeout, once the user answers Yes at
   OpenHands' own confirmation prompt, and Hermes does for a killed
   `pre_tool_call` hook (R5); Copilot stays closed unless every one of its
   hooks is stopped, and OpenCode and Amp stay closed. Closing it needs the vendor
   to treat a failed or timed-out hook as a deny, or application control or
   EDR that stops users from signalling the hook.
9. A standard user can start the root on-demand LaunchDaemons
   `com.cisco.defenseclaw.apply` (runs `enterprise macos ensure`) and
   `com.cisco.defenseclaw.verify` with
   `launchctl kickstart -k system/<label>`; launchd accepts it (exit 0),
   while the same request for a running daemon is refused. Both jobs do fixed, idempotent work from
   root-owned inputs, so the effect is extra root lifecycle runs (an
   `ensure` that reports `noop`), growth of `lifecycle.log`, and lock
   contention: an administrator's own run or the daily `verify` that
   starts meanwhile waits for the lock or exits `75`, and a `verify` that
   exits `75` reports `lifecycle_busy` in `verify.log` instead of its
   checks. It cannot change the configuration or the deployment. launchd
   has no per-job permission for `kickstart`; watch `lifecycle.log` for
   runs nobody requested.
10. macOS has no `protected_hardlinks` setting, so a standard user can
    hard-link any root-owned DefenseClaw file that sits in a directory they
    can search (the binaries, `etc/config.yaml`, `etc/managed-runtime.json`,
    `etc/machine-policy.json`, the LaunchDaemon plists, the logs and the
    vendor machine-policy files) into their own home. The link does not change the file's
    owner or mode, so the user can read or write no more than before, and
    `verify` and `repair` still pass. The user keeps the old inodes after an
    upgrade or log rotation replaces the files, so a file the user could
    read stays readable in its old version. No file a standard user can
    link is subject to a single-link check: the files DefenseClaw refuses
    with more than one link (the AI Defense key (M-13), the enumerator's
    eligible-accounts record, the gateway's private files) sit in
    directories standard users cannot search. A single-link check added for
    any other file needs the same placement, or any user could make it
    fail.
