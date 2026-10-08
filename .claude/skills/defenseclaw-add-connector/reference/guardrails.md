# Guardrails: from vendor payload to verdict and back

This layer turns a connector's hook, plugin, proxy or ACP payload into a guardrail verdict, then renders that verdict in the vendor's format. Paths are repo-relative. Gateway files are under `internal/gateway/`.

## 1. Pipeline, in execution order

| # | File : symbol | What it does for a connector |
|---|---|---|
| 1 | `hook_register.go` `init()` | `registerHookHandler(name, handleUnifiedConnectorHook(name))`. **Add the connector to this name list.** |
| 1b | `api.go` `connectorHookHandlerByName` and the legacy route list | Fallback route list used when there is no registry. It is duplicated, so keep it in sync. |
| 2 | `unified_hook_dispatch.go` `handleUnifiedConnectorHook`, `hookProfileForConnector` | Gets the profile from the registry through `HookProfileProvider`. Uses the contract ID from the lock, or `ResolveHookContract(name, agentVersion)`. |
| 3 | `agent_hook.go` `handleAgentHook` | Enforces the body limit (413) and JSON decode (400). Checks trusted event headers: `X-DefenseClaw-Antigravity-Event`, `X-DefenseClaw-Copilot-Event`, and Codex `X-DefenseClaw-Hook-Event`/`-Contract` (409 on mismatch). A registered event outside `profile.SupportedEvents` gives 400. Also handles the Kiro surface (`kiroHookSurfaceFromHeaders`), correlation, `withAuthenticatedToolResource`, tool-chain capture and the judge session reset. |
| 4 | `agent_hook.go` `normalizeAgentHookRequestWithCorrelationEvent`, `normalizeAgentHookRequestWithRawProfileEvent` | Generic field extraction (§3), then `ContentEnvelope`, then `profile.Decode`, then `profile.DecodeToolArgs`. Decode may **not** set identity. |
| 5 | `hook_profile_runtime.go` `hookProfileRuntimes` | Only `codex` and `claudecode` have typed evaluators. Every other connector goes to `evaluateAgentHook`. Add an entry only for a bespoke evaluator. |
| 6 | `agent_hook.go` `evaluateAgentHook` | Routes by event class (prompt, result, structured tool call). Builds `trustedActionRequest`. Merges asset policy, maps the verdict, renders the response. |
| 7 | `inspect.go` `inspectTrustedToolPolicyCtx` | Order: managed AID-only short-circuit, MCP-server runtime block, static block/allow (`@connector/tool` first), `dispatchTrustedAction`, CodeGuard on write tools, the AID lane, the judge lane. |
| 8 | `trusted_action_dispatch.go` `dispatchTrustedAction` | `actionfacts.Analyze`, then semantic CEL owners from `snapshotRulePackGeneration(connector)`, or `dispatchTrustedFallback` when facts are not authoritative. It returns nil when `ManagedEnterpriseActive()`. |
| 9 | `trusted_action_proof.go` `applyTrustedActionProofBoundary` | Same-rule proof gate. An unproven finding becomes detection-only. |
| 10 | `decision.go` `guardrailRuntimeActionForFindings`, `guardrailRuntimeActionForConnector` | Maps the severity of **enforceable** findings to block, confirm or alert, using the per-connector profile (strict, default or permissive) and HILT. |
| 11 | `agent_hook.go` `mapHookActionForProfile`, or `profile.MapVerdict` | Observe mode gives allow plus `would_block`. Block becomes allow plus `would_block` unless the event is in `CanBlock && BlockEvents`. Confirm becomes alert unless the event is in `CanAskNative && AskEvents`. |
| 12 | `agent_hook.go` `agentHookResponseForProfile`, `profile.Respond`, `renderAgentHookResponseForProfile` | Canonical fields (`action`, `raw_action`, `severity`, `mode`, `would_block`, `reason`, `findings`, `additional_context`, `evaluation_id`, `rule_ids`) plus the vendor object under `ResponseFieldName`. |
| 13 | `connector/hookexec/spec.go` `specs`, the shell script or the plugin | Turns the response into vendor stdout and an exit code. |
| 14 | `agent_hook_chain.go` `applyAgentHookToolChains` | Stateful chain enforcement. Runs only when `profile.ExperimentalToolLifecycleEligible()`, the event routes as structured-action, state-transition or paired result, and `SemanticEventID` and `ConnectorInstanceID` are set. Disabled in managed enterprise. |

**How other kinds enter the pipeline:**
- **Proxy connectors** (openclaw, zeptoclaw): `proxy.go` parses model `tool_calls` and calls `dispatchTrustedAction`. A parse error blocks (fail closed).
- **OpenClaw event router** (`router.go`): observational only.
- **ACP** (`acp.go` `handleACPEvaluate`): calls `inspectMessageContent` with `ruleContentScopeUntrusted`. It inspects **text only**, with no ActionFacts or proof. `DeniedMethods` blocks per profile.
- **Shared endpoints and PATH shims:** `/api/v1/inspect/{tool,request,response,tool-response}` go to `inspectToolPolicyCtx`. Shims are enforceable only with the exact `{"argv":[...]}` envelope (`parseTrustedShimArgv`).

## 2. Event vocabulary: two matching rules

- **Exact string** (`containsExact`):
  - `ToolCallLifecycleContract.RouteForEvent`;
  - the lifecycle pre-proposal, terminal and discard sets;
  - `hookTargetTypeForEvent` (`hook_findings_emit.go`);
  - `foreignHookStopEvent`;
  - `correlationLifecycleForContract`.
- **Canonical** (`canonicalEvent`: lowercase, strip `_ - .`):
  - `eventIn` (BlockEvents, AskEvents, SupportedEvents);
  - `isGenericToolInspectionEvent`, `isPromptLikeEvent`, `isResultLikeEvent`;
  - `isToolJudgeIntentEvent`, `isToolJudgeSessionBoundaryEvent`;
  - `runtimeAssetCanEnforce` (`asset_policy_runtime.go`).

What to register:
1. **Contract.** `Events`, `Capabilities` (BlockEvents, AskEvents), `ResponseFieldName`, `ContentEnvelope` and `ToolCallLifecycle` in `builtinHookContracts` (core.md §3).
2. **Lifecycle routing.** If the lifecycle `Version != 0` and the pre-tool event does not route **exactly** as structured-action, the generic fallback is off and the call is **never inspected** (`structuredToolEvent` in `evaluateAgentHook`). That is how the OpenHands PascalCase bug happened. A connector with no lifecycle (Kiro) uses the canonical `isGenericToolInspectionEvent` fallback.
3. **Classifier switches.** If the pre-tool, prompt, result, turn-start or session-boundary names are new spellings, add them to the classifier switches in `agent_hook.go`. `runtimeAssetCanEnforce` reuses `isGenericToolInspectionEvent`, so a missing name also turns MCP and skill asset blocks into would-block.
4. **Missing event name.** If stdin lacks the event name, bind it at Setup and forward it in a trusted header (Antigravity, Copilot), or map it in Decode (`openHandsStdinEventNames`).

## 3. Payload decode (`HookProfile`)

Generic keys:

| Field | Keys read, in order |
|---|---|
| Event | `hook_event_name hookEventName event_type eventType event_name eventName agent_action_name` |
| Tool | `tool_name toolName command_name name`, then `tool_info.{mcp_tool_name,tool_name,command_name}`. If only `tool_info.command_line` is present, the tool is `shell`. |
| Args | `tool_input toolInput tool_args toolArgs args arguments`, then `tool_info`, otherwise **the whole payload** |
| Content | `prompt user_prompt userPrompt message initial_prompt ...`, then `tool_info.*`, then `tool_response/tool_result/result/error` |

Overrides:
- **`Decode`** may set the event, CWD, tool name, args, content, direction and payload.
- **`ToolArgsAuthoritative=true`** makes an empty result count as `ToolArgsProjectionUncertain` (the parser-uncertainty metric) instead of using the generic guess.
- **`DecodeToolArgs(raw)`** has final authority over args. Antigravity's `antigravityToolArgsFromRawPayload` rejects duplicate keys and alias collisions.
- **`ContentEnvelope`** opens exactly one declared sub-object and reads exactly the one field it declares for the event. There is no recursive scan and no shared key list. Only Hermes declares one: its payload puts the prompt, tool result and model response under `extra` (GAP-0898; a contract that called the payload flat left every Hermes prompt unscanned). `TestContentEnvelopeDeclarations` pins that.

Examples:
- `openHandsProfileDecode` / `openHandsTerminalCommandArgs` (`connector/hook_only.go`)
- `copilotProfileDecode`: `toolArgs` arrives as a JSON **string**
- `cursorProfileDecode`: event-specific result keys
- `devinProfileDecode` (`connector/devin.go`)
- `antigravityProfileDecode` (`connector/antigravity_hook_profile.go`)

## 4. Tool normalization into ActionFacts

**ActionFacts uses closed schemas.** `extractJSONObject` in `internal/actionfacts/input.go` marks any unknown key as `StatusPartial` / `IssueUnknownOperandGrammar`. Such facts are not authoritative: CEL owners don't run authoritatively, proofs fail, and findings are detection-only.

**Shell tool names are spread across tables that must agree.** The Amp fix `d01406ee` had to touch three of them.

| Table | File : symbol | Purpose |
|---|---|---|
| Raw dialect | `internal/actionfacts/dialect.go` `genericRawExecutionTool` / `chooseRawCommandDialect` | grammar (POSIX, PowerShell, CMD) |
| Args execution | `internal/actionfacts/analyze.go` `argsExecutionTool` | whether command args become command facts |
| Exact shell schema | `internal/actionfacts/input.go` `exactShellExecutionTool` (`bash`, `powershell`), `usesClosedShellExecutionArgumentSchema` (`shell` + metadata keys), `extractExactShellExecutionArgs` | requires `command`; allows only `cwd/workdir/description/timeout/run_in_background/dangerouslyDisableSandbox` |
| Bash fallback | `trusted_action_dispatch.go` `trustedBashExecutionTool`, `trustedCommandFieldName` | fallback lanes |
| Windows | `windows_command.go` `windowsCommandText` | Windows command findings |
| Server-side alias | `agent_hook.go` `agentHookTrustedActionTool` | Windows: opencode `bash` and copilot `powershell` become `shell`. All OSes: kiro `execute_bash` becomes `shell`. The recorded tool label is unchanged. |
| Arg projection | `antigravity_action_args.go` `agentHookTrustedActionArgs` | drops the reviewed Antigravity `run_command` metadata keys when their types match; other shapes pass through unchanged |
| Confidence | `rules.go` `knownExecTools` | regex confidence only |
| Terminal MCP | `asset_policy_runtime.go` `isTerminalTool` | only `bash shell terminal run_command exec` |
| Proxy capability | `internal/guardrail/capability.go` `ClassifyToolName` | proxy correlator only |

Other tables:
- **File, web and network tool semantics:** `lookupToolArgumentSemantics` (`analyze.go`), plus the closed coding-agent schemas `usesClosedCodingAgentArgumentSchema` / `extractClosedCodingAgentArgs` (`input.go`).
- **Accepted keys:** `canonicalInputFieldName` (`input.go`) accepts only these: `command cmd script commandline...`, `argv`, `cwd workdir...`, `path file_path...`, `url uri endpoint`, `body data payload content headers`, and nested `input parameters request`.
- **CodeGuard trigger:** `isWriteToolName` (`inspect.go`). A write tool not in this list skips CodeGuard.
- **Limits** (`internal/actionfacts/limits.go`): args 256 KiB, command 64 KiB, JSON depth 16, 512 members. Exceeding any gives `StatusLimitExceeded`, which is never authoritative.

## 5. Minimum a connector must map so rules can match and block

1. **Pre-tool event.** It routes as structured-action in the lifecycle (exact spelling), or is in `isGenericToolInspectionEvent` when there is no lifecycle. It is in `BlockEvents`, and in `AskEvents` if the vendor has a native ask.
2. **Shell tool.** Use a shared shell name, or alias it in `agentHookTrustedActionTool` (preferred over payload hints). A new name goes into every table in §4.
3. **Shell args.** Exactly `{"command": "..."}` plus only the allowed metadata keys. Project vendor metadata away in `Decode`/`DecodeToolArgs` (OpenHands `TerminalAction`) or `agentHookTrustedActionArgs` (Antigravity). Never drop unknown keys generically.
4. **File tools.** Use names from `lookupToolArgumentSemantics` and keys from `canonicalInputFieldName`. Write tools also go in `isWriteToolName`.
5. **MCP tools.** They carry `mcp_server_name`, or use the `mcp__srv__tool` / `mcp:srv:tool` form (assets.md §2, step 9).
6. **CWD.** Decode it (`cwd`, `working_dir`, ...). `sanitizeHookCWD` sanitizes it. `ActiveHome` comes from `trustedActiveHome`.
7. **Identity.** Add a correlation spec for the contract (core.md §3.4). Without it, the tool-chain and judge features lose their session keys.

The symptom of a missed step is a finding with CRITICAL severity, `raw_action=allow` and a parser-uncertainty metric, instead of a block.

## 6. Proof gating

- Four proof kinds authorize enforcement (`trusted_action_proof.go`): ActionFacts semantic (facts authoritative, enforcement-eligible, projection complete, evaluation complete, matched), subgraph, exact CodeGuard, and exact fallback. A proof counts only for its own rule ID.
- Raw or custom regex, parser shadow, partial or invalid facts, and a proof for another rule all stay detection-only.
- `guardrailRuntimeActionForFindings` looks only at enforceable findings. Alert-only owners never produce more than alert.
- **Prompts and results** (`inspectMessageContent`): confirm needs `Direction=="outbound"`. Hook prompts use `"prompt"`, so rule findings on prompts give block or alert, never confirm. AID and judge verdicts can still escalate to confirm through `mergeWithLaneVerdict`.
- **Capability gate:** `enforcementCapable` in the generic path is `CanBlock && eventIn(event, BlockEvents)`. When it is false, every trusted-action finding is detection-only. `KiroBlockEventsForSurface` is an example of narrowing it per request.

## 7. Verdict mapping and vendor rendering

- **`MapVerdict`:** `hookOnlyProfileMapVerdict` (`connector/hook_only_profile.go`) is the default. Special cases:
  - Hermes `pre_verify` gives `continue`;
  - OpenCode with an ambiguous MCP identity blocks (`openCodeProfileMapVerdict`);
  - Codex demotes confirm to alert;
  - Claude has its own mapper.
- **`Respond`:** add a `case "<id>"` to `hookOnlyProfileRespond`. A custom field name must match both `hookOutputFieldName` (`agent_hook.go`) and the contract's `ResponseFieldName`.
- **Legacy responder:** `hookOutputFor` (`agent_hook.go`) runs only when `profile.Respond == nil`. Keep it in parity or leave it alone. It has drifted for OpenHands `additionalContext`.
- **Block reason:** `resolveHookBlockReasonForConfig` (`guardrail.connectors.<id>.block_message` or the global value) changes only the agent-visible text. `genericHookAdditionalContext` keeps the prefix "a <SEV> <connector> hook finding"; telemetry greps for it.
- **Fallback:** when there is no vendor output, `rawAction==confirm`, there is no native ask, and the connector is not hermes, openhands or devin, the response is `{"systemMessage": additional}`.

| Connector | Block | Native ask | Transport |
|---|---|---|---|
| claudecode | `claude_code_output` deny, or exit 2 with no output | `permissionDecision=ask` on PreToolUse | `styleClaudeCode` |
| codex | `codex_output` `{"decision":"block"}` | none; demoted to alert + `systemMessage` | `styleCodex` |
| cursor | `permission=deny` (+ `user_message`/`agent_message`); `beforeSubmitPrompt`: `continue:false` | `permission=ask` on `beforeShellExecution`/`beforeMCPExecution` only | `styleHookEcho` |
| copilot | preToolUse `permissionDecision=deny`; permissionRequest `behavior=deny`; stop `decision=block` | `permissionDecision=ask` on preToolUse | `styleHookEcho`, `failOpenOnly` |
| devin | `{"decision":"block"}` + exit 2 | none | `styleHookEchoDecision` |
| hermes | `{"decision":"block"}` on `pre_tool_call` only | none | `styleHookEcho`, `failOpenOnly` |
| openhands | `{"decision":"deny"}` + exit 2 | none | `styleHookEchoDecision` |
| antigravity | PreToolUse `{"decision":"deny"}`; stdout decides, not the exit code | `{"decision":"ask"}` on PreToolUse | `styleHookEcho` |
| kiro | exit 2 + stderr; no stdout (stdout is appended to the agent context) | none | `styleHookDecisionStderr` |
| opencode | `hook_output.decision=deny`; the plugin throws | none | plugin / `stylePluginBridge` |
| amp | top-level `action=block`; the plugin rejects | plugin `ctx.ui.confirm` | `styleActionStderr` |
| omnigent | top-level action gives DENY | ASK on UserPromptSubmit/PreToolUse/BeforeModel | Python policy |

## 8. Config and policy knobs (keyed by the lowercase connector name)

- **`internal/config/config.go`:**
  - `PerConnectorGuardrailConfig{Mode, HILT, HookFailMode, BlockMessage, RulePackDir, Enabled}`;
  - `ConnectorHookConfig(name)`;
  - `JudgeConfig.HookConnectorEnabled(name)` (`hook_connectors` is `*` or a name).
- **Mode resolution:** `agentHookEnabled` / `agentHookMode` (`agent_hook.go`). `action` and `enforce` mean action; anything else means observe.
- **Per-connector rule packs:** `ApplyConnectorRulePackOverrides` / `snapshotRulePackGeneration` (`rules.go`), keyed by `canonicalConnectorRulePackKey`. The name in `ToolInspectRequest.Connector` must match the config key exactly.
- **Rule schema:** `RuleDefYAML` (`internal/guardrail/rulepack.go`). Most rules use `f.commands` / `f.paths`, so mapping the shell tool correctly is enough for the shipped command rules to match.
- **Managed enterprise:** `managedAIDOnly()` (`inspect.go`) makes Cisco AI Defense the only decision-maker, and a nil AID result fails open. `hookAIDInspect` is gated only by the global `CiscoAIDefense.HookSurfaceEnabled()`.
- **Judge:** `runHookJudge` runs only when the connector is in `guardrail.judge.hook_connectors` and the strategy is `judge_first` or `regex_judge`.

## 9. Per-OS differences

- **Shell aliases:** opencode `bash` and copilot `powershell` become `shell` only on Windows, so `chooseRawCommandDialect` can choose PowerShell or CMD. Kiro `execute_bash` becomes `shell` everywhere.
- **Windows command findings:** `windows_command.go` and `appendTrustedWindowsPathFactFindings`.
- **Standalone or service-account gateway:** `trustedActiveHome` uses the hook-socket peer's home or a per-user TCP credential. Otherwise it uses `/nonexistent-home`, so suffix rules such as `.aws/credentials` still match.
- **Payload shapes:** Copilot `toolArgs` is a JSON string. Check each OS's payload shape; Windows builds sometimes differ.

## 10. Do and don't

- **Do** write a normalization regression test from the live payload that asserts **authoritative facts and a block**, and that other shapes are left unchanged (`antigravity_action_args_test.go`, `agent_hook_openhands_event_test.go`, `agent_hook_windows_shell_contract_test.go`).
- **Do** add the connector's row to `TestHandleAgentHook_FullChain_PerConnector` (`agent_hook_e2e_test.go`) with the native event, tool and args shape, `expectAction=block`, and the right output field.
- **Don't** fix a missing shell name with a payload hint or a generic key drop. Alias the tool server-side or project exactly the reviewed keys.
- **Don't** assume a CRITICAL finding means a block. Check `raw_action` and `would_block`.
- **Don't** put BlockEvents or AskEvents only in the connector's own `HookCapabilities()`. `ApplyHookContract` overwrites them from the contract.

## 11. Mistakes from this branch's history

| Symptom | Root cause | Fix |
|---|---|---|
| OpenHands PreToolUse never inspected | PascalCase stdin event vs exact snake_case routing; `TerminalAction` extra keys made facts partial | `bb78ad66`; `TestHandleAgentHook_OpenHandsSDKStdinPreToolUseIsInspected` |
| Antigravity `run_command` never had complete facts | Metadata keys (`WaitMsBeforeAsync`, `SafeToAutoRun`, `Blocking`, `toolAction`, `toolSummary`) were unknown operands | `8d896821`: `agentHookTrustedActionArgs`; `TestAgentHookTrustedActionArgsGivesLiveAntigravityCommandsCompleteFacts` |
| Kiro CRITICAL finding with `raw_action=allow` | `execute_bash` wasn't a shell name | `f05a9d3c`: alias in `agentHookTrustedActionTool` |
| Kiro prompt blocking disabled for everyone | Surface inferred from the version | Per-request `KiroBlockEventsForSurface` |
| Amp background commands allowed | `async_shell_command` missing from the shell tables | `d01406ee`: dialect.go, `trustedBashExecutionTool`, `windowsCommandText`; e2e row `amp-async-shell` |
| Copilot not enforced on Windows | `powershell` label; `toolArgs` string | `77d215a8`: alias plus the `copilotProfileDecode` string branch |
| Cursor result shadowed by a decoy `result` key | Generic content fallback | Cursor-specific authoritative-empty branch in the normalizer |

## 12. Known gaps (verify before building on them)

1. **Cursor `beforeShellExecution` gets no authoritative facts.** Its body has no `tool_name`, so it normalizes to tool `tool` with the whole payload as args. `preToolUse` with `Shell` and `tool_input` is authoritative.
2. **Amp Bash arg key.** If Amp's Bash `input` uses `cmd`, `extractExactShellExecutionArgs` rejects it because it requires `command`. Check the live payload.
3. **`hookTargetTypeForEvent` matches exact PascalCase only.** Other spellings emit `target_type=inspect`.
4. **`isTerminalTool` is narrow.** It lacks `run_terminal_cmd`, `execute_command`, `async_shell_command`, `execute_bash` and `powershell`.
5. **`AIDSurfaces` is declarative.** Nothing gates the AID lane on it.
6. **The generic path omits `ActiveAgentFiles`** (Claude only) and `DowngradeReadOnlyDataArgs` (Codex observe only).

## 13. Tests

**Gateway:**
- `TestHandleAgentHook_FullChain_PerConnector`: registry completeness fails without the row.
- `TestConnectorRegistry_ScopeAndHookHandlerInSync`, `TestHookRegister_HasBuiltinFactories`.
- `agent_hook_test.go`: `TestHookOutputFor_AllConnectors_AllActions`, `TestRuntimeAssetCanEnforce_HookOnlyEvents`, `TestToolJudgeIntentEventsCoverConnectorTurnStarts`, `TestAgentHookMode_HonorsPerConnectorOverride`, `TestAgentHookEnabled_PerConnectorDisableShortCircuits`.
- `decision_test.go`: per-connector posture and HILT.
- `TestHandleAgentHook_FullChain_PanicFailsOpen`.

**Connector:**
- `TestHookContractsCoverHookEndpoints`, `TestHookContractsManifestMatchesRuntime`, `TestApplyHookContractPinsProfileCapabilities`, `TestToolCallLifecycleRuntimeHelpers`.
- `hook_profile_dispatch_test.go`: Respond parity, MapVerdict, Decode shapes.
- `TestBuiltinCorrelationProfilesAreVersionedAndValid`.
- `hookexec`: `TestDecisionGolden`, `TestForeignHookBlockNamesTheFileInEveryConnectorsResponse`.

**e2e and actionfacts:**
- `test/e2e/testdata/v7/golden/<id>/verdict-blocked.golden.json` with `TestGoldenPerConnectorLayout`.
- `internal/actionfacts` dialect and input tests for any new tool name or closed schema.

**Docs:** `docs-site/content/docs/policies/cel/tool-call-state.mdx`, which has an outcome and identity matrix and a tool-surface matrix.
