# Enterprise managed mode (`managed_enterprise`)

In this file, "standalone" means `managed_enterprise` with `enterprise.profile: standalone`. The Secure Client profile must stay byte-identical (§9). Every standalone-only branch is gated on one of these: `standaloneProfileProcess()`, `windowsEnterpriseStandaloneProcess()`, `cfg.StandaloneEnterprise()`, or `Test-DefenseClawStandaloneProfile` in PowerShell.

## 0. Decide five things first

1. **Route per OS.** `internal/enterprisepolicy/types.go` `RouteFor(connector, goos)` returns one of:
   - `machine_policy`: a vendor machine source that standard users can't write.
   - `per_user`: the guardian registers DefenseClaw in each enrolled user's own config and repairs it.
   - `acp`: the `defenseclaw-gateway enterprise acp` mediator.
   - `unsupported`.

   The `default:` arm is `unsupported`. A connector missing from the switch is silently unmanaged.
2. **Runtime kind.** One of:
   - the admin-owned binary, `defenseclaw-hook hook --connector X --enterprise-managed [--event E]`;
   - a per-user script, `~/.defenseclaw/hooks/X-hook.sh`;
   - an in-agent plugin.

   The foreign-hook guard runs only inside the admin binary, or through `hook --foreign-hook-check`.
3. **Rewrite protection.** Pick one:
   - a vendor lock (`lockConnectors`: codex, claudecode);
   - the foreign-hook guard (`guardConnectors` / `unixGuardConnectors`);
   - none, documented as a threat-model residual (R24: Antigravity, OpenHands, OmniGent).
4. **Version gating.**
   - Windows standalone requires a versioned contract with status `HookCompatibilityKnown`.
   - A not-gated contract (Kiro) needs `standaloneNotGatedAgentFloors` on Unix, and the Windows guardian can't enroll it.
5. **Windows posture.** One of:
   - machine policy;
   - a per-user hook binary;
   - a per-user plugin;
   - refused, with a reason;
   - ACP.

## 1. Route, policy summary and guard eligibility (`internal/enterprisepolicy`)

| # | File : symbol | What to do |
|---|---|---|
| 1 | `types.go` `RouteFor` | Add a `case` with a per-OS return. Today: codex/claudecode/cursor/copilot → machine_policy; devin/antigravity/hermes/opencode/amp → per_user; openhands/omnigent → per_user on Unix, unsupported on Windows; kiro → per_user on Unix, acp on Windows; openclaw/zeptoclaw → unsupported. `Options.Route` can move OpenCode onto machine policy. |
| 2 | `types.go` connector consts, the `targets` map, the `Target` interface | Only for a vendor machine source. `Target` has `Name`, `Paths`, `Reconcile`, `Verify`, `RemoveOwned`, `Export`. Merge only: never re-marshal an admin document, record ownership plus the preimage, and restore on removal. Model it on `copilot.go` or `opencode.go`. Shared paths go in `paths.go` (`DefenseClawDropInName = "90-defenseclaw.json"`). |
| 3 | `api.go` `reconcileOne` / `VerifyAll` | Add a route detail line if users need to know where the hook lives (see `kiroRouteDetail`). |
| 4 | `publicpolicy.go` `guardConnectors`, `unixGuardConnectors`, `lockConnectors`, `GuardApplies`, `publicRoute` | Put the connector in exactly one set. `publicRoute` must report `per_user` while DefenseClaw's own per-user registration is what the agent loads; otherwise the guard treats it as foreign and denies every call (OpenCode, `a80101f1`). |
| 5 | `presence.go` `MachinePolicyPresent`, `MachinePolicyMayRemain` | Machine-policy targets only. The runtime uses these to tell a live registration from a stale one after uninstall. |
| 6 | `windows_owned.go` `windowsGoOwnedTargets` | Only if the Go guardian writes this vendor file on Windows (Copilot and OpenCode). Codex, Claude and Cursor Windows policy stays in lifecycle and Secure Client code. Never add a second writer. |
| 7 | `live.go` `VerifyLive` | Optional; codex and claudecode only today. |
| 8 | `internal/enterpriseunix/layout.go` `machinePolicyDirs`, `MachinePolicyConnectors` | Linux and macOS vendor directories for a machine-policy target. They must match `Target.Paths`. |
| 9 | `internal/config/enterprise.go` | Usually nothing, because `PolicyFor` and the schema's `connectors` `additionalProperties` are generic. A connector-only knob follows `version_floor`: a const, validation that refuses the key for other connectors, and a `$defs` entry in `schemas/config/v8/defenseclaw-config.schema.json`. |

## 2. Foreign-hook guard (guarded connectors only)

| File : symbol | What to do |
|---|---|
| `guard.go` `connectorSources` | Add a `case` listing every user and project file the agent loads hooks from. Read env redirects through `req.getenv` (`COPILOT_HOME`, `CODEX_HOME`, `XDG_CONFIG_HOME`, ...). `guard_env.go` `ObservedEnvRedirect` and the Windows persistent-environment reader (`internal/cli/enterprise_hooks_foreign_env_windows.go`) then pick the redirects up. Use `sourceOptions{reportOnly:true}` for files another program owns (Devin's `~/.claude.json`). Cursor, Copilot and Devin also load Claude-format files (`claudeFormat()`). |
| `guard.go` format consts, `scanFile` / `scan`, `cleanup.go` `cleanUserSources` | Reuse a format if you can: `grouped`, `hooks-object`, `flat`, `flat-dir`, `codex-toml`, `plugin-dir`, `plugin-list`, `claude-plugins` or `hermes-yaml`. A new format needs a scanner and a cleanup case; `guard_hermes.go` shows the full set. |
| `guard.go` `ownedCommand`, `ownedExecArgs`, `ownedHandlerKeys` | The owned forms are `'<bin>' hook --connector X --enterprise-managed [--event 'E']` and the Windows exec form with 4 or 6 args. Any extra handler key makes a handler foreign. Connectors that bind `--event` (Antigravity, Copilot) depend on the 6-arg form. |
| `guard.go` `ownedPluginPath` | Plugin connectors only. It exempts exactly `~/.config/<agent>/plugins/defenseclaw.*` on the per-user route. |
| `internal/gateway/connector/managed_policy_exports.go` `PerUserOwnedHookCommands` | Per-user script registrations count as owned only if the connector is in `NewDefaultRegistry` and implements `HookScriptOwner`. |
| `internal/cli/hook_foreign_guard.go` `standaloneForeignHookGuardBinary` | Add the connector if its per-user runtime must call the admin binary (plugins, or a script that asks `--foreign-hook-check`). The value travels through `InstallOptions.ForeignHookGuardBinary`, then the worker JSON, then `SetupOpts`. |
| `hook_foreign_guard.go` `foreignHookGuardedEvent` | Restrict guarded events when some events can't block (OpenCode guards only `tool.execute.before`). |
| Session state: `hook_foreign_guard.go` `hookForeignGuardSessionStart`, `hookForeignGuardSessionKeys`, `captureHookPayloadFacts`; `internal/enterprisepolicy/guard_session.go` | Add the session-start event (matched lowercased), the session-ID key and the cwd keys. The snapshot is keyed by session ID and agent process, and kept per verified uid or SID for 7 days (`sessionRecordTTL`). |
| `internal/gateway/connector/hookexec/hookexec.go` `foreignHookStopEvent` | Add the exact-case stop and session-end events, or a guarded session loops on stop hooks. |

The guard's block reason starts with `hookexec.ForeignHookBlockedReasonPrefix` and names the file, its digest and `enterprise.machine_policy.connectors.<name>.allowed_hooks`.

## 3. Unix guardian, enumerator and per-user worker

**Enrollment gate** (`internal/enterprisehooks/enumerator_unix.go` `EffectiveUnixHookConnectors`). The connector must be:
- enabled in `guardrail.connectors`;
- in the registry (`newConnectorRegistryWithPlugins`);
- not a proxy (`!connector.IsProxyConnector`);
- the owner of its runtime (`connector.OwnsManagedHookRuntime`);
- supported on the host OS (`connector.ConnectorSupportedOnHostOS`).

Machine-policy connectors named in the runtime descriptor (`descriptor.MachinePolicyConnectors`) get per-user rows only with `enrollment.unenrolled_users: deny`.

**Version probe** (`agent_version_unix.go` `unixAgentProbes`). Fields:
- `npmPackages`;
- `versionDirs` (home-relative);
- `binaries` (the first name is the install evidence);
- `stateEnv` (a scratch dir for agents that lock state, such as `HERMES_HOME`);
- `uvTool` (for Python CLIs too slow to exec).

For macOS app bundles, add the binary to `unixAgentAppBundleBinaries`. `--version` runs only in the worker, as the user, and only on paths that pass `unixDiscoveryCandidateTrusted`. An installed CLI with no readable version is reported as unprotected (`UnixAgentUnversionedReasonPrefix`), not skipped.

**First install needs the vendor hook file.** Choose one:
- implement `HookConfigBootstrap`;
- add a case to `bootstrap.go` `defaultHookConfigStubForConnector`, gated on `standaloneProfileProcess()` (the OpenHands and Antigravity pattern);
- if DefenseClaw owns the whole file (`defenseclaw.json`) in a folder the agent never creates, add the connector to `standalone_peruser_repair.go` `standaloneOwnedHookConfigConnectors` (Kiro, Copilot).

**Protected executable binding.** `connector.ProtectedSetupSelectionConnector` feeds `managed_selection_unix.go` `selectManagedAgentExecutable`.

**Not-gated floor.** `agent_floor_standalone.go` `standaloneNotGatedAgentFloors`. It is consumed by:
- `installer.go` `validateHookContract`, which gates new enrollments only; rows with an existing lock keep being repaired;
- `standaloneAcceptsAgentVersionChange`;
- `enumerator_unix.go` `unixKnownRowVersionRefused`, so a known row never follows a downgrade below the floor.

**Worker protocol.** A new `SetupOpts` or `InstallOptions` field must also be added to:
- `internal/cli/enterprise_hooks_worker_unix.go` `enterpriseHookWorkerOptions`, plus its two mapping sites;
- the verify path, `enterprise_hooks_standalone_verify_unix.go`.

Otherwise the worker renders without it.

**Invariants.**
- The root guardian never touches a home in process.
- Unix hooks and plugins use only the peer-authorized hook socket; there is no TCP fallback.
- Standalone `Verify` must fail when a rendered artifact is older than a required feature (the guard line, the Hermes guard), so the guardian re-renders after an upgrade.

## 4. Windows standalone

There is no single source of truth on Windows. Update **every** list below; drift here is the main risk. All of them are gated on `windowsEnterpriseStandaloneProcess()`.

1. **`internal/enterprisehooks/peruser_managed.go`:**
   - `windowsStandalonePerUserConnectors`: `true` for a hook-binary runtime (protected runtime generation plus per-SID enrollment), `false` for plugin-only (Amp).
   - `windowsStandaloneInAgentPluginConnector`: plugin install marker and listener proof.
   - `windowsStandaloneRuntimeOnlyConnectors`: vendor machine policy carries the hook, so the per-user row writes only the runtime (Copilot).
   - `windowsEnterpriseRefusedConnectors`: the admin-facing refusal text.
   - `WindowsStandalonePerUserConnectorNames()`: a sorted literal list used by teardown, cleanup and tests.
   - `isWindowsStandalonePerUserBuiltin`: a concrete-type check (`IsBuiltinHookOnlyConnector` / `IsBuiltinAMPConnector`), because a plugin can claim a built-in name.
2. **Certified registries.** `peruser_managed_windows.go` `RegisterWindowsStandalonePerUserConnectors` feeds `internal/cli/enterprise_hooks.go` `newWindowsEnterpriseCertifiedConnectorRegistry` and `install_windows.go` `newWindowsEnterpriseConnectorRegistry`. `certifyWindowsEnterpriseConnector` falls through to `certifyWindowsStandalonePerUserConnector`.
3. **`install_windows.go` dispatch.** `platformInstall` and `verifyWindowsManagedResult` are generic, or runtime-only through `install_windows_runtime_only.go` `windowsStandaloneRuntimeOnlyInstall` / `windowsRuntimeOnlyPolicyPath`. `windowsEnterpriseHookFailMode` forces `closed`.
4. **Hard-coded runtime and selector lists:**
   - `managed_runtime_windows.go` `ResolveWindowsManagedHookRuntime`;
   - the selector switch in `managed_runtime_generation_windows.go`;
   - `parseWindowsManagedRuntimeBundleLeaf`;
   - `internal/cli/hook_trusted_state_windows.go` `windowsStandalonePerUserHookConnector`.
5. **Version discovery.** Windows never executes the agent. Reads are static, bounded, and refuse reparse points (`winpath.RejectReparseChain`). Sources:
   - `agent_version_peruser_windows.go` `windowsStandalonePerUserAgentVersionCandidatePaths` (npm package map);
   - `discoverWindowsStandalonePerUserAgentVersion` (native installers: Devin `_versions`, the Hermes `install-stamp.json`, the Antigravity log tail);
   - `agent_version_managers_windows.go` `windowsStandaloneNPMPackages`, a second npm map that must match the first;
   - `enumerator_standalone_windows.go` `windowsWinGetPackageIDs`;
   - the order is in `standaloneWindowsAgentVersionExplain`.

   Don't edit the claudecode, codex or cursor cases of `agent_version_windows.go` `windowsAgentVersionCandidatePaths`; Secure Client shares them.
6. **Admission.** `peruser_admission_windows.go` `windowsStandaloneRowAdmission` requires `HookCompatibilityKnown` plus the floor. A protected executable image goes in `windowsStandaloneManagedExecutableRelative` / `windowsStandalonePerUserManagedExecutable`.
7. **Floors.** `agent_floor_standalone_windows.go` `windowsEnterpriseStandalonePlatformAgentMinimums`, raised to the lowest contract minimum (`windowsEnterpriseStandaloneAgentMinimum`).
8. **Machine-policy row classification.** `enumerator_windows.go` `windowsStandaloneMachinePolicyConnector`. Exempt users keep these rows, and an unregistered SID fails closed.
9. **Lifecycle module.** In `packaging/windows/DefenseClawEnterprise.psm1`, inside `if (Test-DefenseClawStandaloneProfile)`, add the name to the `$teardownConnectors += @(...)` standalone line only, never to the Secure Client line above it. Say in the PR that the psm1 changed, so maintainers run the Secure Client invariance check (§9).
10. **Revocation and cleanup.** `internal/cli/enterprise_hooks_standalone_policy_windows.go` and `windows_managed_hooks_teardown_peruser.go` follow `IsWindowsStandalonePerUserConnector` automatically. User writes happen only under the target user's token, and only while the user has an active session.
11. **Shared machine-wide bodies.** Render them from the oldest enrolled contract, never from one row's user-controlled version. Follow `claude_machine_contract.go` `WindowsStandaloneClaudeMachinePolicyContract` (`8d896821`).

**Plugins on Windows** need token custody designed in:
- the scoped-token sidecar is published under the target user's token (`3be05555`, `462e7b10`);
- the DACL is `windowsManagedPluginSDDLFormat` (`peruser_private_plugin_windows.go`);
- the install marker is in `plugin_install_marker_windows.go`.

Without these, the plugin fails closed with "hook credential is unavailable".

## 5. ACP route

- `internal/acp/catalog.go` `BuiltinCatalog` needs an agent entry (`ConnectorID`, command, args).
- `internal/cli/enterprise_acp.go` `resolveEnterpriseACPEnrollment` validates it through `acp.LookupAgent` and the central `cfg.ACP` policy.
- If Windows uses ACP, return `RouteACP` from `RouteFor`, and add a refusal reason to `windowsEnterpriseRefusedConnectors` that names `enterprise acp`, as Kiro's does. No test checks the wording.
- `internal/inventory/acp_registry.json` must match its `cli/` copy byte for byte, and `acp_certifications.json` must use the same `protocol_release` (`check_acp_inventory_instances` in `scripts/check_schemas.py`).

## 6. Version floors: which mechanism

| Mechanism | Where | When |
|---|---|---|
| Vendor-enforced floor drop-in | `internal/enterprisepolicy/claude_floor.go` (`00-defenseclaw-version-floor.json`, `ClaudeVersionFloor()`); `EnterpriseConnectorPolicy.VersionFloor` accepted only for claudecode | Only when the vendor has a managed "refuse to start below X" key. Use a separate drop-in so the hook drop-in bytes don't change. Write it only while no admin source sets the key. Record ownership plus a postimage hash, and save the record before the file. |
| Not-gated standalone floor | `agent_floor_standalone.go` | Connectors without versioned contracts (Kiro). Gates new enrollments only. |
| Windows platform minimum | `agent_floor_standalone_windows.go` | Minimums above the contract. |
| Secure Client floors | `install_windows.go` `requireWindowsEnterpriseManagedAgentVersion`; psm1 `Get-DefenseClawClaudeMinimumClientVersion` | **Don't touch.** Pinned by `TestWindowsEnterpriseManagedAgentVersionMinimums` (`internal/enterprisehooks/install_windows_test.go`) and `test_secure_client_claude_floor_is_unchanged` (`cli/tests/test_windows_enterprise_standalone_contract.py`). |

## 7. How the existing connectors differ

| Connector | Linux/macOS | Windows | Rewrite protection | Discovery | Notes |
|---|---|---|---|---|---|
| codex | machine policy (`/etc/codex/requirements.toml`), admin binary | machine policy (lifecycle) | lock, `features.hooks=true` | npm + `--version`; Windows npm/bun/yarn, managers, WinGet | Secure Client floor |
| claudecode | machine policy (`managed-settings.d/90-defenseclaw.json`) | machine policy, hooks only | lock on Unix | npm + versionDirs; Windows native + WinGet | floor drop-in; shared contract = oldest enrolled |
| cursor | machine policy (`/etc/cursor/hooks.json`) | machine policy | guard | versionDirs; Windows app `package.json` | |
| copilot | machine policy (`policy.d/90-defenseclaw.json`) | Go-owned machine policy + runtime-only per-user row | guard | npm `@github/copilot` | owned `~/.copilot/hooks/defenseclaw.json`; command hook timeouts fail open |
| opencode | managed plugin, or a per-user plugin fallback | same; runtime-only while machine policy is in force | guard (`--foreign-hook-check`; `tool.execute.before` only) | npm; Windows WinGet or npm image | trusted artifact required |
| amp | per user, plugin `~/.config/amp/plugins/defenseclaw.ts` | per user, plugin only, listener proof | guard via `--foreign-hook-check` | npm `@ampcode/cli` (Windows also `@sourcegraph/amp`) | no machine plugin path |
| devin | per user; standalone Unix runs the admin binary | per user, admin binary | guard | binary; Windows `_versions` | reads `~/.claude.json` report-only; `~/.config/devin` on macOS |
| hermes | per user; `hermes-hook.sh` asks `--foreign-hook-check` | per user, admin binary | guard on Unix only | binary + `stateEnv` `HERMES_HOME`; Windows install stamp | `hermes-yaml`; `HERMES_MANAGED_DIR` |
| antigravity | per user, `--event` binding | per user, admin binary | none (R24) | `agy` / `antigravity`; Windows log tail | stub `~/.gemini/config/hooks.json` |
| openhands, omnigent | per user | refused | none (R24, R30) | `uvTool` | stub `~/.openhands/hooks.json` |
| kiro | per user: `~/.kiro/hooks/defenseclaw.json` + the CLI 2.x agent | ACP | none | `kiro-cli`, macOS app bundle | not-gated floor; pre-run failure exits 2 |
| openclaw, zeptoclaw | unsupported (proxy) | refused | — | — | |

## 8. Conventions

- **Naming.** Owned files are named `defenseclaw.*`. Drop-ins are `90-defenseclaw.json` and `00-defenseclaw-version-floor.json`.
- **Contract pinning.**
  - Standalone follows an agent upgrade only to a `Known` contract, or to a version at or above the not-gated floor.
  - Anything else is reported as `hook_contract_unverified` (`unprotected_agents.go`, `internal/enterpriseunix/contracts.go`).
  - Standalone Windows verify fails when the rendered version differs from the enrolled one (`requireWindowsStandaloneAgentVersionUnchanged`), which triggers a repair.
- **Fail modes.**
  - Managed hooks always fail closed.
  - Stop and session-end events get the neutral allow.
- **Exit codes.**
  - `hook --foreign-hook-check` always exits 0 with JSON. Callers must treat anything other than `{"deny":false}` as a block.
  - `enterprise policy verify` and `enterprise hooks reconcile` exit non-zero when incomplete or when any target fails.
  - Windows Setup returns 1618 for a concurrent run and 1639 for a trust-mode mismatch.
- **CHANGELOG.** Standalone-only changes don't get a CHANGELOG line. Add one only when per-user or Secure Client installs are affected.

## 9. Secure Client: must not change

- The Windows certified set stays codex, claudecode and cursor. `RegisterWindowsStandalonePerUserConnectors` stays pin-gated (`TestRegisterWindowsStandalonePerUserConnectorsRequiresStandalonePin`).
- `enumerator_windows.go` `windowsHookConnectors` stays those three.
- `install_windows.go` `requireWindowsEnterpriseManagedAgentVersion` floors stay as they are.
- In `packaging/windows/install-enterprise.ps1`, don't change `$script:DefenseClawSupportedConnectors`, `$script:DefenseClawWindowsManagedEnterpriseSupportedConnectors`, `ConvertTo-DefenseClawConnectorList`, `Resolve-DefenseClawConnectorMetadataVersion` or the `param()` block. Also leave the psm1 Secure Client helpers and `internal/cli/hook_foreign_guard_host*.go` alone.
- The macOS allow-list in `packaging/macos/lib/installer_lib.sh` (`amp|codex|claudecode|cursor|opencode`) stays as is.
- `internal/gateway/connector/hook_only.go` `secureClientPluginAssets` stays as is.
- **Check:** the Secure Client invariance check is run by maintainers outside the repo; there are no Secure Client golden fixtures or golden tests in the tree. If a change touches `packaging/windows`, `packaging/macos` or a Secure Client code path, say so in the PR so a maintainer runs that check before it is marked ready. The in-repo pins that remain are:
  - `TestSecureClientPluginTemplatesArePinned` (the Secure Client plugin templates and renders);
  - `TestRegisterWindowsStandalonePerUserConnectorsRequiresStandalonePin` (per-user connectors join the certified registry only with the standalone pin);
  - the floor tests in §6.

## 10. Docs and threat model

- **Docs:**
  - `docs-site/content/docs/enterprise/machine-policy.mdx`: the routes table, the paths table and the who-writes table.
  - `foreign-hook-guard.mdx`, `concepts.mdx`, `threat-model.mdx`, `troubleshooting.mdx`, `enrollment.mdx`, `windows.mdx`, `rollout.mdx`.
  - `docs-site/content/docs/connectors/<id>.mdx`: the `## Enterprise deployments` section.
- **`docs/ENTERPRISE-THREAT-MODEL.md`:**
  - B11: writers per OS.
  - B12: the lock-or-guard sentence.
  - R1: per-user connectors are advisory; list the config-redirect variables.
  - R15: a client below the floor skips hooks.
  - R18: kill and stall behavior.
  - R19: discovery coverage.
  - R24: no lock and no guard.
  - R25: desktop-app surfaces.
  - A new `Rnn` for vendor quirks (for example R30, OpenHands file precedence).
- **Per-OS threat models:**
  - `docs/LINUX-ENTERPRISE-THREAT-MODEL.md` L-16 and `docs/MACOS-ENTERPRISE-THREAT-MODEL.md` M-12: the guard list.
  - `docs/WINDOWS-ENTERPRISE-THREAT-MODEL.md`:
    - W-50: the guard list.
    - W-55: the certified set and each connector's route, floor, teardown and guard.
    - The deferred app-surface rows.
- **Live certification** for each OS you claim, done interactively in the agent's own UI:
  - a harmless call is allowed, and the audit attributes it to the right account;
  - a marker rule (an `expression:` rule over command facts) blocks, with a visible message;
  - approving and denying a permission prompt both work;
  - turning hooks off through the vendor's own settings is detected;
  - config-redirect environment variables are covered;
  - a copy of the agent below the floor is refused;
  - the stop and kill behavior matches what the docs say.

## 11. Mistakes from this branch's history

| Mistake | Commit | Lesson |
|---|---|---|
| Kiro commands rendered a flag that the hook binary lacked; it exited 1 and Kiro went ahead | `cb96bc5d` | Every rendered argument must exist in `internal/cli/hook.go`. Test the rendered command end to end. |
| The Windows `& '<exe>'` form lost exit 2 | `cd6b6f2c` | Use the encoded bridge and test it through `cmd.exe /d /s /c`. |
| The Kiro floor refused repairs of rows below it; every self-update counted as drift | `cd6b6f2c`, `cb96bc5d` | A floor gates new enrollments only. Not-gated connectors need `standaloneAcceptsAgentVersionChange`. |
| Unix Devin ran the per-user script, so the guard never ran | `0f728f8b` | Guarded connectors run the admin binary. Keep the old script recognized for upgrade and teardown. |
| Hermes: a user hook placed after DefenseClaw's rewrote tool input | `358158aa`, `c304cfa4` | Research the vendor's hook ordering. Add a guard, and make Verify fail for artifacts rendered before the guard existed. |
| OpenHands PascalCase events weren't inspected | `bb78ad66` | Use exact wire casing, and test with real payloads. |
| Antigravity and Copilot payloads have no event name | `c33fdb01`, `c08d0e94` | Guard ownership must accept the `--event` suffix, and the guard uses `opts.Event` before the payload's event. |
| Amp `async_shell_command` made no command facts | `d01406ee` | Register every shell tool name, or command-fact certification passes falsely. |
| The OpenHands and Antigravity hook files didn't exist, so repair failed; the `~/.kiro/hooks` parent was missing | `a266d801`, `bb78ad66` | Add a standalone bootstrap stub or `standaloneOwnedHookConfigConnectors`. |
| The OpenCode summary said machine policy; the guard denied DefenseClaw's own plugin; reclassifying it dropped the listener proof | `a80101f1` | The route must track what the agent actually loads. Re-check every behavior a classification flag drives. |
| Plugins failed closed with "hook credential is unavailable" | `3be05555`, `462e7b10` | Design plugin token custody on Windows. |
| One user's version claim switched the shared Claude policy contract | `8d896821` | Render machine-wide bodies from the oldest enrolled contract. |
| **Open:** `parseWindowsManagedRuntimeBundleLeaf` omits `opencode`, though OpenCode is a hook-binary connector there | — | Grep every hard-coded Windows list when you add a connector. |

## 12. Tests

**`internal/enterprisepolicy`:**
- `api_test.go` `TestKiroRouteFollowsItsEnrollment` (route per GOOS).
- `api_test.go` `TestPublishVerifyRemoveAll` (routes map and summary `Guard`).
- `guard_test.go`: `TestPublicPolicyGuardFlags`, `TestGuardHonorsPerUserOwnedCommandsOnlyOnPerUserRoute`, and a source-coverage test like `TestGuardCoversOpenCodeConfigLocations`.
- `TestCleanupRemovesUserForeignHooksAndBacksUp`.
- A `guard_<name>_test.go` for a new format.

**`internal/cli`:**
- `hook_foreign_guard_test.go`: `TestStandaloneForeignHookGuardBinaryOnlyForStandalonePlugins`, `TestForeignHookGuardDenialUsesVendorBlockResponse`.
- `hook_foreign_guard_session_test.go` `TestForeignHookGuardBlocksTheSessionOnlyForAHookPresentAtStart` (its "each agent's session id" rows).
- `enterprise_hooks_user_cleanup_test.go` (connector list).
- `TestHookPreRunFailureUsesTheConnectorsBlockingExit`, if exit codes are special.

**`hookexec`:** `session_stop_test.go` `TestManagedSessionStopEventsAllowWhileOtherEventsStayBlocked`.

**`internal/enterprisehooks` on Unix:**
- `standalone_peruser_repair_unix_test.go` `TestStandaloneVerifyFollowsModeSwitchesInOneHome` (fresh install and mode switches for every per-user connector).
- `agent_version_unix_test.go`, `enumerator_unix_test.go`, `unprotected_agents_unix_test.go`.
- Floor tests in `installer_kiro_unix_test.go`.
- Guard tests in `hermes_foreign_guard_unix_test.go` and `installer_foreign_guard_test.go`.

**`internal/enterprisehooks` on Windows:**
- `peruser_managed_test.go` `TestWindowsStandalonePerUserBuiltinRejectsImpostors`.
- `peruser_managed_windows_test.go`: `TestRegisterWindowsStandalonePerUserConnectorsRequiresStandalonePin`, `TestWindowsStandalonePerUserConnectorMappings` (a hand-kept managed-runtime name list) and `TestDiscoverWindowsStandalonePerUserAgentVersions`.
- `enumerator_standalone_admission_windows_test.go` (row admission and the platform minimum) and `peruser_admission_windows_test.go`.
- `managed_runtime_generation_windows_test.go`.

No test covers the runtime kind or the refusal reason of each connector; check those maps by hand.

**Python:** `cli/tests/test_windows_enterprise_standalone_contract.py` if the psm1 changes.

Windows `_test.go` files compile only with `GOOS=windows`. The quick check is `GOOS=windows go vet ./internal/enterprisehooks/... ./internal/enterprisepolicy/... ./internal/cli/...`.
