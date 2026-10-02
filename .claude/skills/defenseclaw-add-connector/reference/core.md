# Core: identity, contract, hook runtime, lifecycle

Paths are repo-relative. Unless noted, Go files are under `internal/gateway/connector/`. Find symbols with `git grep -n '<symbol>'`.

## 1. Identity

**ID rules.** Use lowercase `[a-z0-9]+` with no separators. That is the only form every validator accepts:

- `validNativeHookConnector` (`helpers.go`) accepts `[a-z0-9-]`.
- `hookAPITokenScopeRE` (`hook_api_token.go`) is `^[a-z0-9][a-z0-9_-]*$`.
- The shell helper `defenseclaw_shared_runtime_connector` (`hooks/_hardening.sh`) accepts `[a-z0-9_-]`.
- `hookSidecarFailModeKey` (`internal/cli/hook.go`) upper-cases the ID and **strips** `-` and `_` to build `DEFENSECLAW_FAIL_MODE_<ID>`.
- The enterprise config key must match `^[a-z][a-z0-9_-]{0,63}$`.
- Metric labels must pass `observability.IsStableToken`; anything else becomes `unknown`.

**Derived names.**

| Name | Pattern | Exceptions |
|---|---|---|
| Hook route | `/api/v1/<id>/hook` | claudecode uses `/api/v1/claude-code/hook`; codex adds `/api/v1/codex/notify` (`NotifyEndpoint`) |
| Script | `hooks/<id>-hook.sh` | `claude-code-hook.sh` |
| `spec.hookName` / `X-DefenseClaw-Client` | `<id>-hook` / `<id>-hook/1.0` | |
| Scoped token | `hooks/.hook-<id>.token` (`HookTokenFilePath`) | |
| Backups | `<data_dir>/connector_backups/<id>/` | |
| Contract lock | `hook_contract_lock.json` → `connectors.<id>` | |
| Setup subcommand | `defenseclaw setup <id>` | `setup claude-code` |
| Contract ID | `<id>-hooks-vN` | `amp-plugin-v1`, `omnigent-custom-policy-v1` |

**Aliases.** The canonical normalizer is `normalizeConnectorName` (`hook_contract.go`). It maps `claude`, `claude-code` and `claude_code` to `claudecode`, and `open-hands` and `open_hands` to `openhands`. Copies of it, which have drifted, live in:

- **Go:**
  - `normalizeConnectorKey` (`internal/config/config.go`, no bare `claude`)
  - `internal/gateway/application_protection.go`
  - `normalizeConnectorTelemetrySource` (`internal/gateway/otel_ingest.go`). This one is a closed allowlist: it also maps `agy` to `antigravity`, and anything missing becomes `unknown`.
  - `normalizeConnector` (`internal/useridentity/email.go`)
  - `normalizeConnector` (`cmd/defenseclaw-setup/main.go`)
- **Python:**
  - `normalize_connector` (`cli/defenseclaw/connector_contracts.py`)
  - `normalize` (`cli/defenseclaw/connector_paths.py`; empty input means `openclaw`)
  - `cli/defenseclaw/bootstrap.py`
  - `cli/defenseclaw/commands/cmd_init.py`
  - `cli/defenseclaw/config.py`
  - `cli/defenseclaw/inventory/agent_discovery.py`
  - `cli/defenseclaw/tui/registry.py`

Add an alias to all of them or to none. Prefer none.

**Retired or renamed IDs.**

- Go package `internal/legacyconnector`: `RetiredDesktopID`, `Replacement`, `IsRetired`.
- `connector.RetiredConnector` (`retired.go`): a teardown-only connector whose Setup refuses.
- `internal/gateway/legacy_connector_migration.go`.
- `Registry.NotShipped` (`unshipped.go`).
- Python `cli/defenseclaw/legacy_connector.py`: `RETIRED`, `BACKUP_MARKERS`, `CONNECTOR_MAP_BLOCKS`, `TOP_LEVEL_CONNECTOR_MAPS`, `CONNECTOR_NAME_LISTS`, `ASSET_POLICY_RULE_LISTS`.
- The tripwire test `cli/tests/test_retired_connector_names.py`.

Never register a hook factory for a retired ID; `TestHookRegister_HasBuiltinFactories` asserts that.

## 2. Go type and registration

1. **Connector type.** Create `internal/gateway/connector/<id>.go`, or add a constructor to `hook_only.go`. It must implement `Connector` (`connector.go`): `Name`, `Description`, `ToolInspectionMode`, `SubprocessPolicy`, `Setup`, `Teardown`, `Authenticate`, `Route`, `SetCredentials`, `VerifyClean`. `Description()` is shown in inventory. `ToolInspectionMode` and `SubprocessPolicy` must be values in the v8 enums, or they are exported as empty.
2. **Optional interfaces** (all in `connector.go`). Implement the ones that apply:

| Interface | What it drives |
|---|---|
| `HookEndpoint` | route registration and scoped-token auth. `api.go` finds the connector by `HookAPIPath()`. |
| `NotifyEndpoint` | a second, notify-only route |
| `HookCapabilityProvider` + `HookProfileProvider` | both are required together (`TestHookProfileMatrix_AllCapabilityProvidersHaveProfile`) |
| `ConnectorCapabilityProvider` | MCP, skills, rules, plugins, agents, CodeGuard, telemetry and ACP surfaces. Feeds `ResolvedConnectorLocations` and the lock. |
| `HookScriptOwner` or `HookConfigReferenceOwner` | makes `OwnsManagedHookRuntime` true. Without one, `HookConfigPathsForConnector` returns nil, so doctor, the guardian and enterprise enumeration don't see the connector. |
| `HookRuntimeArtifactProvider` | plugin files (OpenCode, Amp, OmniGent) |
| `ManagedPluginArtifactOwner` | plugin files that the watcher must treat as lifecycle-owned |
| `ScopedHookTokenRequirement` | the connector needs a scoped hook token |
| `AgentPathProvider` | patched, generated and backup files (the setup footprint) |
| `EnvRequirementsProvider` | environment the agent needs |
| `ComponentScanner` | watcher targets. Without it, the watcher falls back to the `claw.go` switches (see assets.md). |
| `StopScanner` | stop scanning |
| `ProviderProbe` | provider probing |
| `HookConfigBootstrap` | a stub for an absent vendor config on fresh installs |
| `ManagedHookPolicyProvider` | the vendor admin policy tier |
| `AllowedHostsProvider` | allowed hosts |
| `CorrelationSpecProvider` | correlation (see §3.4) |

3. **Registry.** Add the connector to `newBuiltinConnectors()` (`registry.go`). `IsKnownBuiltinConnector` and `NewDefaultRegistry` derive from it.
4. **Platform support.** Add an entry to `windowsConnectorSupport` (`platform_support.go`) with a status (`PlatformSupported`, `PlatformPreview`, `PlatformNotCertified` or `PlatformUnsupported`) and an operator-facing reason.
   - A missing entry means `PlatformNotCertified` on Windows. The connector is then hidden from `Registry.Available()` and from Windows inventory, and `CheckPlatformSupport` refuses it.
   - For a proxy connector, also add it to `proxyConnectors`.
   - The Python mirror is `cli/defenseclaw/platform_support.py` `WINDOWS_CONNECTOR_SUPPORT`, pinned by regex in `cli/tests/test_platform_support.py`.
5. **Docs row.** Add a row to `docs-site/data/capability-matrix.json`. `TestDocsCapabilityMatrixMatchesConnectors` iterates `newBuiltinConnectors()` (see docs-tests-ci.md).

## 3. Hook contract and lifecycle

### 3.1 Go contract

Add `builtinHookContracts["<id>"]` (`hook_contract.go`) with at least one `HookContract`:

- `ContractID`: `<id>-hooks-vN`.
- The version window: `ExactAgentVersions`, and/or `MinAgentVersion` (inclusive) and `MaxAgentVersion` (exclusive). Use exact lists for vendors that break often (cursor, devin, opencode).
- **Exactly one** `DefaultForUnversioned`.
- `HookScriptVersion`: must equal the script's `# defenseclaw-managed-hook vN` on line 2, the plugin's `// defenseclaw-managed-plugin vN` on line 1, or the policy bridge's `# defenseclaw-managed-policy vN` on line 1 (OmniGent). `parseHookSchemaVersion` reads only the first 512 bytes. A Windows adapter carries its own marker, which can differ from the contract's (`cursor-hook.ps1` is v9 while `cursor-hook.sh` and the contract are v8).
- `HookConfigPathTemplates`: `~/`, `<workspace>/` or absolute paths.
- `ResponseFieldName`: `hook_output` by default; `claude_code_output` / `codex_output` for those two; **empty** for connectors that read the top-level `action` (amp, omnigent). `TestHookContractsCoverHookEndpoints` enforces this.
- `Events`: the vendor's exact spelling.
- `AIDSurfaces`: declarative only. `HookProfileAIDSurfaceEnabled` has no runtime caller.
- `Capabilities`: `HookCapability{CanBlock, CanAskNative, AskEvents, BlockEvents, SupportsFailClosed, Scope}`. `ApplyHookContract` **replaces** the profile's capability with this value, keeping only `ConfigPath` and `Scope`, so BlockEvents and AskEvents belong here.
- `SupportsTraceparent`, `NativeOTLP`, `ToolCallLifecycle`, optional `ContentEnvelopeKey`, and `Notes` (cite the vendor docs and versions). No contract sets `ContentEnvelopeKey` today, Hermes included (`TestContentEnvelopeKeyDeclarations` pins every contract to empty), so setting one means changing that test.

**Resolution** happens in `resolveHookContractForOS`:

| Situation | Status |
|---|---|
| Connector on the not-gated lists (`proxyConnectorsWithoutHookGate`, `catalogedOnlyConnectorsWithoutHookGate`) | `not-gated` |
| No contracts | `unknown` |
| Empty agent version | `unversioned` (uses the default contract) |
| Unparsable version | `unknown` |
| Otherwise | the first matching contract, `known` |

Details:
- `exactAgentVersionMatch` accepts one or two version fields. A second field is allowed only after `agent` or `cursor-agent`.
- A `SetupOpts.HookContractID` pin that doesn't match gives `unknown` (`resolveHookContractForOptions`).
- Action mode refuses `unknown` and `unversioned` unless overridden (`HookContractNeedsActionOverride`).
- `ApplyHookContract` must be the **last** call in every `HookProfile()`.

**Per-OS pins** are hand-coded `if` blocks in `hookContractsForOS`. Examples:
- Devin is pinned to exact builds per OS.
- OpenHands has native OTLP only on darwin, and a Windows contract with a 0.0.0 minimum and no OTLP.

Mirror every pin in the JSON `platform_overrides`.

**Standalone-only floors** live outside the contract: `standaloneNotGatedAgentFloors` in `internal/enterprisehooks/agent_floor_standalone.go` (see enterprise.md).

### 3.2 JSON manifest

Add `connectors.<id>` to `cli/defenseclaw/inventory/hook_contracts.json` (`schema_version` 2).

- **Connector fields:** `kind` (`hook`, `proxy`, `acp-with-native-hook-defense-in-depth`), `compatibility_gate` (`hook-contract` or `not-gated`), `version_probe` (for example `copilot --version`), `contracts[]`.
- **Contract fields:** `contract_id`, `agent_version{exact,min_inclusive,max_exclusive}`, `default_for_unversioned`, `hook_script_version`, `hook_script`, `hook_config_path_templates`, `response_field`, `events`, `aid_surfaces`, `supports_traceparent`, `native_otlp` (plus `native_otlp_auth`, `_signals` and `_endpoint_template`), `content_envelope_key`, `tool_call_lifecycle`, `capabilities{can_block,can_ask_native,ask_events,block_events,supports_fail_closed,scope}`, `platform_overrides{darwin,linux,windows}`, `notes`.
- **Loader:** `connector_contracts._load_contracts_from_manifest`. It rejects unknown platforms and more than one default per platform. Override keys are listed in `_PLATFORM_OVERRIDE_FIELDS`.
- **Parity:** `TestHookContractsManifestMatchesRuntime` (`hook_contract_test.go`) compares Go and JSON on darwin, linux and windows. `cli/tests/test_connector_contracts.py::test_manifest_covers_every_connector` requires an entry for every connector in `KNOWN_CONNECTORS` plus the ACP-only connectors.
- **Packaging:** the file ships through `pyproject.toml` package-data.
- **Validated versions:** `cli/defenseclaw/inventory/validated_versions.json` has one row per connector with `os.{linux,macos,windows}`. It is alert-only and edited by a person after a green live run; don't fill it speculatively. Its `version_probe` must equal the manifest's.

### 3.3 Tool-call lifecycle

Add `<id>ToolCallLifecycle()` to `tool_call_lifecycle.go` (copy a sibling such as `copilotToolCallLifecycle`). `ValidateToolCallLifecycleContract` checks it:

- every event is in `Events`;
- one route per event;
- pre-proposal events are structured-action;
- outcome events are result-content;
- discard and terminal events are audit-only;
- `paired-outcomes` requires `paired-id`;
- the https sources and limitations are non-empty.

**Important:** when the lifecycle `Version != 0` and the event does not route exactly as structured-action, the generic fallback is disabled, so the tool call is never inspected (guardrails.md §2).

### 3.4 Correlation

- Add a `CorrelationProfile<Id>V1` constant and a case in `CorrelationSpecForConnector` (`correlation.go`). The case uses `makeSpec(profile, contractID, surfaces, ...)` with `reported(...)` bindings and `complete(...)` missing-reason declarations. `makeSpec` matches the contract ID exactly; a mismatch falls back to `ExplicitCanonicalCorrelationSpec`, which quietly loses session keys.
- Add entries to `nativeTelemetryForConnector`, `mirrorIdentityTargets` and `declaredCorrelationAliases` where they apply.
- In `correlation_provenance.go`, add a `correlationContractSources` entry: a URI plus an immutable revision (a 40-hex commit or `sha256:`). Optional fixtures go in `testdata/` with a sha256. Add a `correlationFieldEvidence` entry if the connector has native IDs.
- `correlationLifecycleForContract` compares event names exactly, case included.

### 3.5 HookProfile callbacks

`HookProfile` (`connector.go`) fields:

- `Decode`: needed whenever stdin is not the flat generic shape.
- `ToolArgsAuthoritative`.
- `DecodeToolArgs`.
- `MapVerdict`.
- `Respond`.
- `SupportedEvents`.

For hook-only connectors, add a case to `hookOnlyProfileRespond` (`hook_only_profile.go`) and to the name switch in `hookOnlyConnector.HookProfile` (`hook_only.go`). Decode may not set identity; identity comes only from the correlation spec.

## 4. Hook templates

- **Embedding and rendering.** Templates live in `internal/gateway/connector/hooks/` and are embedded with `//go:embed all:hooks` (`subprocess.go`; the `all:` prefix is what embeds `_hardening.sh`). They are rendered by `renderTemplate` (`text/template`) with `templateData`: `APIAddr`, `APIToken`, `TokenFile`, `ScopedToken`, `FailMode`, `Managed`, `ConnectorName`, `HookSocketTransportSH`, `ForeignHookGuardSH`, and the JS fields `TokenFileJS`, `HookSocketJS`, `InstallMarkerJS`, `ServiceUID`, `ForeignHookGuardJS`, `ListenerProofJS`. PowerShell adapters use `HookBinaryPS`, `HookTimeoutMS`, `CursorHookTimeoutMS` and `CopilotHookTimeoutMS`.
- **Registration.** Add `connectorHookScripts["<id>"]` (`subprocess.go`). Windows-only adapters are added in `HookScriptNames` (`hook_only.go`).

**Shell skeleton.** Copy `hooks/openhands-hook.sh` or `hooks/copilot-hook.sh` and keep this order:

1. Line 2 is `# defenseclaw-managed-hook vN`. Helpers are never downgraded.
2. Resolve `HOOK_DIR` through symlinks (depth 40; exit 2 on failure).
3. `{{if .Managed}}` pins `DEFENSECLAW_HOME` from the script location. Otherwise honor `.disabled` and exit 0.
4. Source `_hardening.sh`, then call `defenseclaw_harden_resources` and the env hardening.
5. `FAIL_MODE="${DEFENSECLAW_FAIL_MODE:-{{.FailMode}}}"`.
6. Call `defenseclaw_handle_missing_token`, then `defenseclaw_read_stdin_capped` (1 MiB).
7. Read the scoped token.
8. Define `fail_unreachable` and `fail_response`.
9. Insert `{{.HookSocketTransportSH}}`.
10. Send the auth, trace and identity headers. `X-DefenseClaw-User-Id` and `-User-Name` are required; `hook_user_identity_test.go` globs `hooks/*-hook.sh`.
11. `curl --connect-timeout 2 --max-time 10 [--unix-socket]`.
12. Map the result to connector-native stdout and exit code.

**Plugins.**
- Line 1 is `// defenseclaw-managed-plugin vN`, the ownership marker (`managedPluginOwnershipMarker`).
- Secure Client renders pinned copies (`secureClientPluginAssets`), and `TestSecureClientPluginTemplatesArePinned` pins them. Never edit `*-secure-client.*` when changing `opencode-plugin.js` or `amp-plugin.ts`.
- Any bridge template edit also needs the plugin-scanner digest bump (assets.md §2, step 11).
- The managed machine-policy OpenCode plugin is `internal/enterprisepolicy/opencode_managed_plugin.js`. It runs `defenseclaw-hook hook --connector opencode --enterprise-managed --event E`.
- In-agent plugins must also send the identity headers. They are a hand-kept list in `TestPluginTransportsReportIdentityToo`.

**PowerShell adapters.**
- `hooks/cursor-hook.ps1` turns pipeline objects into UTF-8 JSON and uses the hidden `--input-file`.
- `hooks/copilot-hook.ps1` uses a `ProcessStartInfo` byte stream and fails open.
- Other code checks literal lines of these adapters: the Cursor runtime check in `hook_only.go`, `cli/defenseclaw/cursor_contract.py`, the Copilot adapter check in `cli/defenseclaw/doctor_hooks.py`, `scripts/windows-native-ci.ps1` and `scripts/live-connector-e2e/run-windows.ps1`. A new adapter needs the same kind of check, and an edit to an existing one must update all of them.

## 5. Native hook runner (`hookexec`)

This is the Windows path, the enterprise-managed path, and the standalone Unix path.

**Entry.**
- `cmd/defenseclaw-hook/main.go` accepts only `hook` and `notify` (anything else exits 2), plus `--version-json`. It passes through the Windows tombstone checks (`NativeHookRuntimeNoop`, `NativeConnectorHookNoop`) and then `cli.Execute`.
- The hidden `hook` command (`internal/cli/hook.go`) has these flags:
  - `--connector` (required), `--event`, `--api-addr`, `--fail-mode`;
  - hidden: `--hook-contract`, `--hook-surface`, `--input-file` (Cursor on Windows only), `--enterprise-managed`, `--foreign-hook-check`.
- `buildHookOptionsForRuntime` then calls `hookexec.Run`.

**Registration.**
- Add `specs["<id>"]` (`hookexec/spec.go`) with `connector`, `hookName`, `errLabel`, `subject`, `endpoint`, `outputField`, `style` and, where it applies, `failOpenOnly`.
- `TestSupportedConnectorsSorted` pins the sorted list.

**`Run` order** (`hookexec.go`):
1. Look up `specFor`. An unknown connector exits 2.
2. A managed runtime failure fails closed.
3. Check home and `.disabled`. This is a no-op normally and fails closed when managed.
4. Read stdin, capped.
5. Bind the event:
   - codex requires the event and contract to match stdin;
   - antigravity requires the event and fails **open** if it is missing;
   - copilot requires a reviewed event (`validCopilotEvent`).
6. Budget the request (`hookRequestTimeout`): 10 s by default, 29 s for copilot and antigravity, per event for claudecode, 2 s for codex SessionEnd. The budget must stay below the timeout Setup registers in the vendor's hook config, with about a second to spare. Otherwise the vendor kills the hook before it can print the fail-mode response.
7. Choose the transport: the Unix socket for standalone, a verified-peer TCP client for Windows managed, the default otherwise.
8. Resolve the token: `.hook-<id>.token` beats the environment, which beats the legacy `.token`.
9. Call `doRequest`, then `spec.decide`.

**Per-connector branches** to review in `hookexec.go`:

| Symbol | Purpose |
|---|---|
| `validAntigravityEvent`, `validCopilotEvent` | event validation |
| `hookRequestTimeout` | request budget |
| `foreignHookStopEvent` | stop and session-end events. **Required.** It is exact-case, and `managedStandaloneStopEvent` reuses it. |
| `failForeignHookBlocked` | native deny body |
| `emitHookResult` | event-native fallback |
| `hookDialects` | `--hook-surface` values |

**Styles and exits** (`spec.go`; `blockExit=2`):

| Style | Behavior |
|---|---|
| `styleClaudeCode` | print the output; a block with no output prints the reason on stderr and exits 2 |
| `styleCodex` | block only on control events of the bound contract (`emitCodexBlock`) |
| `styleHookEcho` | print `hook_output` and exit 0 (Cursor synthesizes event-native JSON) |
| `styleHookEchoDecision` | print, then exit 2 if the decision is deny or block |
| `styleHookDecisionStderr` | Kiro: no stdout; a deny prints the reason on stderr and exits 2 |
| `styleActionStderr` | Amp: a block prints the reason on stderr and exits 2 |
| `stylePluginBridge` | print the whole compacted response as one JSON line |

Claude, Codex and Amp treat a missing or invalid `action` as a response failure. The other styles treat it as allow.

## 6. Windows commands

`defenseclaw-hook.exe` is built with `-H=windowsgui` (`.goreleaser.yaml`, `Makefile`). A PowerShell call operator therefore doesn't wait for it and loses the exit code. Most connectors use the encoded bridge, `windowsNativePowerShellHookCommandForBoundEvent` (`helpers.go`, `windowsAwaitedHookStatements`: `[System.Diagnostics.Process]::Start`, `WaitForExit()`, `exit $hookProcess.ExitCode`). Don't use `Start-Process -Wait -PassThru`: Windows PowerShell 5.1 opens the process again by ID, so a hook that exits at once comes back as 1.

Add a branch to `hookInvocationCommandFor` (`helpers.go`). The default fall-through is Claude Code's `& '<exe>' hook --connector <id>`, which is wrong for almost every other host.

| Connector | Unix command | Windows command |
|---|---|---|
| claudecode | script | `& '<exe>' hook --connector claudecode` (Claude Code evaluates with PowerShell) |
| codex | script; machine policy: `hook --connector codex --enterprise-managed --event E --hook-contract C` | encoded bridge |
| antigravity | `<script> <Event>` (the event as extra argv) | encoded bridge with `--event` (agy tokenizes the command itself) |
| copilot | `<script> --event <e>` | `copilot-hook.ps1 -Event '<e>'` (`windowsCopilotPowerShellAdapterCommand`) |
| cursor | script | `& '<cursor-hook.ps1>'` |
| hermes | script | `"C:/.../defenseclaw-hook.exe" hook --connector hermes` (shlex with shell=False; forward slashes) |
| devin | script; Unix standalone: `'<admin defenseclaw-hook>' hook --connector devin --enterprise-managed` | bash-quoted exe with forward slashes. Devin runs hooks through bash, so never use `-EncodedCommand`. |
| kiro | script (`--hook-surface v3` on the `.kiro/hooks` config) | encoded bridge (cmd.exe rejects `&`) |
| openhands | script | unsupported (WSL) |

Also:
- Update `ownedHookCommandNeedlesFor` (`hook_config_paths.go`) if commands differ per event (copilot, antigravity).
- Add the connector to `managedNativeHookRuntimeConnector` (`subprocess.go`) only for a Windows machine-policy runtime.
- Add it to `protectedSetupSelectionConnectorForOS` (`connector_state.go`) if setup pins the agent executable.

## 7. Setup, teardown, verify

**Callers.**
- The per-user CLI, `internal/cli/connector_cmd.go`: `connector reconcile|teardown|verify|list-backups`. `verify` runs `VerifyClean`, a residue check.
- Gateway boot (`sidecar.go`), a connector switch (`proxy.go`), self-heal (`hook_config_guard.go`).
- The standalone guardian (`internal/enterprisehooks/installer.go`) and the Windows guardian (`install_windows.go`).

**Setup order** (see `hookOnlyConnector.Setup`):
1. Platform and admission checks.
2. `WriteHookScriptsForConnectorObjectWithOpts`.
3. `captureManagedFileBackup` (`managed_backup.go`), **before** any edit.
4. Patch only DefenseClaw-owned entries.
5. `updateManagedFileBackupPostHash`.
6. Optionally re-read and verify, as Cursor does.

Setup must be idempotent. Use a lock file wherever setup can run concurrently (Hermes uses `.hermes-lifecycle.lock`).

**Teardown.**
- Remove entries by exact owned command strings (`removeJSONHookReferences`). Include **every** legacy rendered command, for example `legacyAntigravityWindowsHookCommand` and the legacy Devin, Copilot and Kiro call-operator forms.
- Restore the pristine file when it is unchanged.
- Write `writeDisabledHookTombstone` for hosts that cache hook paths. Cursor removes its files instead.
- Call `ClearHookContractLockEntry`.
- Combine errors with `errors.Join`.

**Presence and drift.**
- `OwnedHooksPresent` (`hook_config_paths.go`).
- `HookContractLockEntry` (`connector_state.go`) records the version, executable and sha, the contract, script digests, locations, fail mode and `RegistrationPosture`.
- The drift checks are `HookContractLockDrifted`, `HookTransportDrifted` and `HookCredentialDrifted`.

**`SetupOpts` fields to honor** (`connector.go`):
- `DataDir`, `APIAddr`, `HookAPIToken` / `HookAPITokenScoped`, `WorkspaceDir`, `ConfigHome`
- `ManagedEnterprise`
- `ManagedHookSocket` / `ManagedServiceUID` (Unix standalone socket)
- `ForeignHookGuardBinary`, `ManagedInstallMarker`, `ManagedListenerProof`, `HookExecutable`
- `ManagedTargetSID`: the Windows guardian must never launch the user's agent
- `AgentVersion` / `AgentExecutable`, `HookContractID`, `GuardrailMode`, `HookFailMode`

A new `SetupOpts` field must also be carried through the Unix worker protocol (enterprise.md §3).

## 8. Fail modes and exit codes

**Fail mode.**
- `resolveHookFailMode` (`subprocess.go`) decides it. Cursor is closed in action mode and open in observe mode. Otherwise the order is `HookFailMode`, then the codex/claudecode enforcement flags, then `defaultHookFailMode="closed"`.
- It is persisted in the sidecar `hooks/.hookcfg` as `DEFENSECLAW_FAIL_MODE_<ID>`.
- In the runner, `normalizeFailMode` treats an empty value as **open**, while rendered templates default to closed. The CLI fills the value from the flag, then the per-connector sidecar key, then the sidecar global. `DEFENSECLAW_FAIL_MODE` is honored only when the runtime is untrusted or the value tightens to closed.
- `StrictAvailability` forces transport failures closed.
- `failOpenOnly` connectors (copilot, hermes) never fail closed, except managed Copilot (`managedCopilotFailClosed`).
- Standalone stop and session-end events always get the neutral allow (`allowManagedStandaloneStop`).
- Enterprise-managed hooks always fail closed. Their lock and status must say so (Devin, `b4aaedb3`).

**Exit codes.**
- The `hook` command's pre-run failures (cobra usage errors) exit 1. `hookFailureExitCode` (`internal/cli/hook.go`) makes Kiro exit 2 when fail-closed, because Kiro ignores status 1. Add your connector there if its vendor also ignores status 1.
- `connector verify` exits 0 when clean, 1 on residue, 2 for an unknown connector.
- Vendors differ on what blocks: exit 2 blocks for Claude, Devin, Kiro and Amp; JSON decides for Codex, Cursor, Copilot and Antigravity.

## 9. Do and don't

- **Do** copy the closest sibling's constructor, contract, lifecycle, correlation case, spec, script and tests, then change them. Diff against the sibling at the end.
- **Do** capture real vendor stdin for every event (per OS if it differs) and turn it into decode tests before writing `Decode`.
- **Do** keep the old rendered command forms as teardown identities when you change a command.
- **Don't** rely on a generic default: `hookInvocationCommandFor`, `hookOnlyProfileRespond`, `specs`, `hookRequestTimeout` and `foreignHookStopEvent` all have defaults that are wrong for a new vendor.
- **Don't** append positional arguments to `defenseclaw-hook hook`, and don't render a flag that the hook command doesn't define.
- **Don't** set `DefaultForUnversioned` on more than one contract per OS.
- **Don't** edit the Secure Client templates or the codex command-hook hash pins (`connector_test.go`, mirrored in `cli/tests/test_cmd_doctor_windows_hooks.py`) as part of adding a connector.

## 10. Mistakes from this branch's history

| Symptom | Cause | Fix |
|---|---|---|
| OpenHands PreToolUse never routed or enforced | The SDK writes PascalCase `event_type`; the contract uses snake_case; `TerminalAction` carried extra keys | `bb78ad66`: `openHandsStdinEventNames`, `openHandsProfileDecode`, `openHandsTerminalCommandArgs` |
| Kiro hook exited 1 and Kiro went ahead; every event exited 2 | The rendered `--hook-surface v3` flag didn't exist; there was no Kiro spec in `hookexec` | `cb96bc5d`: `hookDialects`, a Kiro spec, the pre-run exit-2 rule |
| Kiro block lost on Windows | The call operator lost exit 2; cmd.exe reported "& was unexpected" | `cd6b6f2c`: encoded bridge; the old command kept as a teardown identity |
| Unix standalone Devin skipped the foreign-hook guard | It ran the user-writable `devin-hook.sh` | `0f728f8b`: run the admin `defenseclaw-hook ... --enterprise-managed`; `b4aaedb3`: fail mode shows closed everywhere |
| Devin config not loaded on macOS | The config root belongs in `~/.config/devin`, not `~/Library` | `devinConfigRootFor`; under LocalSystem, resolve the target user's `%APPDATA%` (`8d896821`) |
| Antigravity event missing | stdin has no event name | The event is bound as argv (Unix) or `--event` (Windows) and sent as `X-DefenseClaw-Antigravity-Event`; the gateway rejects a missing value. Only tokenizer-safe arguments go in `hooks.json`. |
| Amp background commands allowed | `async_shell_command` wasn't treated as a shell tool | `d01406ee` (guardrails.md) |
| Hermes: a later user hook rewrote tool input | Vendor hook ordering and merge rules | `358158aa`: guard; Hermes blocks only through JSON, so `failOpenOnly` |
| OpenCode template change broke the Secure Client render | A shared template was edited | `b4aaedb3`: keep the Secure Client render byte-identical; bump the scanner fingerprint |

## 11. Tests

**Hard-coded lists in tests** (edit these by hand):
- `TestHookContractsCoverHookEndpoints` (`hook_contract_test.go`)
- `TestSupportedConnectorsSorted` and `TestNativeConnectorEndpointMatrix` (`hookexec/hookexec_test.go`)
- `TestForeignHookBlockNamesTheFileInEveryConnectorsResponse`
- `TestHookRegister_HasBuiltinFactories` (`internal/gateway/hook_register_test.go`)
- `TestHookProfile_HasDispatchCallbacks` (`hook_profile_dispatch_test.go`)
- The name lists in `platform_support_test.go` (`TestWindowsConnectorSupportTaxonomy`)
- `r.Len() != 14`-style registry counts (`connector_test.go`; `correlation_test.go` `want 14`). Bump them.

**Hand-kept tables that don't fail when the connector is missing**, but should cover it:
- `TestPlatformHookContractsPreservePR655Bands` (`hook_contract_test.go`): every contract band per OS (ID, min, max, default, script version, event count).
- `TestLLMTrafficModeForConnector` (`llm_traffic_mode_test.go`).

**Tests that iterate** and pick the connector up on their own:
- `TestHookContractsManifestMatchesRuntime`
- `TestHookProfileMatrix_AllCapabilityProvidersHaveProfile`
- `TestDocsCapabilityMatrixMatchesConnectors`
- `TestCorrelationContractSourcesAndFixturesAreImmutable`
- `TestConnectorRegistry_ScopeAndHookHandlerInSync`

**Per-connector tests** (extend a table where one exists; copy these examples otherwise):

| What | Example to copy |
|---|---|
| Decoding real vendor payloads | `openhands_event_decode_test.go`, `antigravity_hook_profile_test.go` |
| Decision goldens and the fail matrix | `TestDecisionGolden`, `TestResponseFailure`, `TestUnreachable`, `TestMissingToken`, `TestOversizedPayload` (`hookexec`) |
| Shell script exits under bash | `TestOpenHandsHookScript_BlockExitsTwo`, `cursor_hook_failopen_test.go` |
| Setup, teardown and VerifyClean round trip, including an absent config | `hook_teardown_absent_config_test.go` (its Copilot leftover row) |
| Windows shell behavior | `kiro_windows_shell_test.go`, `cursor_hook_adapter_windows_test.go` |
| CLI flag and exit | `internal/cli/hook_kiro_test.go` |
| Stop events | `hookexec/session_stop_test.go` |

Helpers are in `internal/gateway/connector/connectortest/connectortest.go`.

## 12. Known gaps (check before relying on them)

- Nothing checks that `HookScriptVersion` and the JSON `hook_script_version` match the embedded marker. They match by convention today:

  | Connector | Marker |
  |---|---|
  | openhands | v6 |
  | antigravity | v8 |
  | cursor | v8 |
  | copilot | v7 |
  | devin | v7 |
  | claudecode | v7 |
  | codex | v6 |
  | hermes | v6 |
  | opencode | v7 |
  | amp | v2 |
  | omnigent | v1 (`# defenseclaw-managed-policy v1`) |
  | kiro | v1 (not gated, so no contract to compare) |

- **Hard-coded marker literals.** Some code checks a rendered file for its exact marker string, so bumping a template marker breaks it without a compile error:
  - `hook_only.go` (Cursor runtime: `v8` on Unix, `v9` for the Windows adapter) and `cli/defenseclaw/cursor_contract.py`;
  - `amp.go` and `cli/defenseclaw/fail_mode.py` (`// defenseclaw-managed-plugin v2`);
  - `hook_config_paths.go` (OpenCode, `// defenseclaw-managed-plugin v7`);
  - `cli/defenseclaw/doctor_hooks.py` (the Copilot adapter, `v7`);
  - `scripts/windows-native-ci.ps1` and `scripts/live-connector-e2e/run-windows.ps1`.

  Find them all with `git grep -n 'defenseclaw-managed-' -- ':!internal/gateway/connector/hooks'`.

- The Go parity test doesn't compare the JSON `native_otlp_auth`, `_signals` and `_endpoint_template` overrides. Only Python validates them.
- The alias normalizers and connector name lists are duplicated across layers (§1). A future registry-driven parity test would remove most of this checklist.
