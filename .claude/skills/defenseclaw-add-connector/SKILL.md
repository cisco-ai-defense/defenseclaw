---
name: defenseclaw-add-connector
description: Use when adding or changing a DefenseClaw connector for a new AI agent (a vendor command hook, in-agent plugin, policy bridge, LLM proxy or ACP route). Covers the hook contract and native hook runner, guardrails, enterprise managed mode, skills/MCP/plugins, discovery, observability, CLI setup, TUI, installers, docs, tests and CI. Gives the architecture, a route decision tree, the ordered end-to-end checklist, per-layer references with the mistakes this codebase has already made, and a worked example (GitHub Copilot CLI).
---

# Add or change a DefenseClaw connector

A connector is how DefenseClaw governs one AI agent. The agent calls DefenseClaw through a vendor hook, plugin, proxy or ACP stream. The gateway turns each event into a guardrail verdict and sends the verdict back in the agent's native format. The same connector name also drives setup, teardown, inventory, discovery, telemetry, the enterprise guardian, the TUI and the docs.

A connector ID ends up in hundreds of places: the retired-connector fold in `e508ba54` touched 247 files, and the Amp connector (`cf576356`) touched 241. Most of those places are closed lists with a silent default, such as OpenClaw paths, `"unknown"` telemetry, a generic proxy message or "not certified on Windows". A missed entry usually fails without an error, which is why this skill exists.

Verified against `fix/enterprise-hardening` at `fc9e12a2`. The references name files and symbols, not line numbers. Find each one with `git grep -n '<symbol>'`. Source code and tests are authoritative; if this skill disagrees with them, trust the code and update the skill.

The commit SHAs cited here come from that branch's history. If the branch reached `main` as a squash merge, `git show <sha>` fails in a fresh clone. Find the change instead with `git log -S '<symbol>'` on a symbol the same entry names, or in the pull request's commit list.

## Architecture

```
                         AI agent (CLI, IDE or desktop app)
                                        |
     +-------------------+--------------+------------------+------------------+
     | command hook      | in-agent plugin| policy bridge    | LLM proxy        | ACP (stdio)
     | (most connectors) | (opencode, amp)| (omnigent)       | (openclaw,       | (kiro; zed
     |                   |                |                  |  zeptoclaw)      |  via catalog)
     v                   v                v                  v                  v
 hooks/<id>-hook.sh  hooks/<id>-plugin.*  hooks/omnigent-    proxy.go           internal/acp
 or defenseclaw-hook rendered into the    policy.py          /c/<name>/...      enterprise acp
 hook --connector id agent's plugin dir                      (model tool_calls) (text only)
        \__________________ POST /api/v1/<id>/hook __________/                   |
                    (scoped hook token, trace and identity headers)              |
                                   |                                             |
  gateway  hook_register.go -> handleUnifiedConnectorHook -> handleAgentHook     |
           normalize (generic keys, then HookProfile.Decode / DecodeToolArgs)    |
           evaluateAgentHook -> inspectTrustedToolPolicyCtx                      |
             (actionfacts + CEL rule packs, CodeGuard, Cisco AI Defense, judge)  |
           mapHookActionForProfile / MapVerdict -> Respond ------------------- verdict
                                   |
  response {action, raw_action, severity, would_block, ..., <ResponseFieldName>: vendor body}
                                   |
  hook runner (hookexec spec, shell script or plugin) -> vendor stdout + exit code

  Side channels keyed by the same ID: audit + OTel, inventory (skills/MCP/plugins),
  AI discovery, doctor/status, hook_contract_lock.json, enterprise guardian.
```

Lifecycle ownership:

```
defenseclaw setup <x>   (Python)                      defenseclaw-gateway   (Go)
  contract + platform check (hook_contracts.json)
  writes config.yaml + <data_dir>/picked_connector
  restarts the gateway  ----------------------------> Connector.Setup(SetupOpts)
                                                        render hooks/*, back up and patch the
                                                        vendor config, seal hook_contract_lock.json
  waits for the lock   <----------------------------
defenseclaw uninstall   ----------------------------> connector teardown | verify --connector <x>

enterprise standalone guardian (root / LocalSystem)
  enterprisepolicy.RouteFor(connector, goos):
    machine_policy  Target writes the vendor's admin-only machine file
    per_user        a worker running as each enrolled user calls Connector.Setup(ManagedEnterprise)
    acp             `defenseclaw-gateway enterprise acp` mediates the agent
    unsupported
```

## Choose the integration kind

| Kind | Existing examples | Go type | Artifact | Native runner style | Contract gate |
|---|---|---|---|---|---|
| Command hook, shell script on Unix, native exe on Windows or managed | cursor, copilot, devin, hermes, openhands, antigravity | `hookOnlyConnector` (`hook_only.go`; Devin's constructor is in `devin.go`) | `hooks/<id>-hook.sh` plus a vendor config patch | `styleHookEcho` / `styleHookEchoDecision` | versioned |
| Command hook with rich vendor config and machine policy | claudecode, codex | own type (`ClaudeCodeConnector`, `CodexConnector`) | script + settings/TOML patch | `styleClaudeCode` / `styleCodex` | versioned |
| Command hook + ACP | kiro | `KiroConnector` | `.kiro/hooks/*.json` + CLI agent file | `styleHookDecisionStderr` | not gated |
| In-agent plugin | opencode (JS), amp (TS) | `hookOnlyConnector{pluginArtifact:true}`; Amp embeds it in `AMPConnector` | `hooks/opencode-plugin.js`, `hooks/amp-plugin.ts` | `stylePluginBridge` (managed OpenCode), `styleActionStderr` (amp) | versioned |
| In-process policy bridge | omnigent | `OmnigentConnector` | `hooks/omnigent-policy.py` | none | versioned |
| LLM proxy | openclaw, zeptoclaw | own types | proxy routes | none | not gated |

## Decision tree

```
1. Does the agent run an external command for each lifecycle event (a hooks config)?
   yes -> command hook.
     a. Does it have rich settings plus a vendor machine-policy file (like Claude/Codex)?
        yes -> dedicated connector type. no -> a hookOnlyConnector constructor.
     b. Is the event name missing from stdin?      -> bind it at Setup: `--event` (copilot)
                                                      or an extra argv (antigravity on Unix).
     c. How does the vendor read the result?       -> pick the decisionStyle:
        stdout JSON decides (HookEcho) | exit 2 + JSON (HookEchoDecision) |
        exit 2 + stderr, stdout goes to the context (HookDecisionStderr) | exit 2 + reason (ClaudeCode).
     d. Does the vendor lack an exit-status or fail-closed contract, so a failed or
        timed-out hook always counts as allow?                  -> failOpenOnly (copilot, hermes).
2. No command hooks, but it loads code plugins from a directory?  -> in-agent plugin (opencode/amp).
3. It exposes an in-process policy API?                        -> policy bridge (omnigent).
4. It speaks ACP over stdio?                                   -> internal/acp catalog entry (kiro, zed),
                                                                  optionally plus native hooks.
5. Only its LLM traffic can be intercepted?                    -> proxy connector (openclaw pattern).

Per OS:
   Windows: does the host run hooks through PowerShell, cmd.exe, bash, or an exec argv?
            -> a branch in hookInvocationCommandFor. WSL-only -> PlatformUnsupported with a reason.
   macOS:   is it an app bundle? -> macos_bundle_binaries / unixAgentAppBundleBinaries.
Enterprise (per OS):
   vendor machine-wide hook source that standard users can't write?  -> machine_policy Target
   otherwise per_user; can users rewrite or add hooks?  -> foreign-hook guard (connectorSources),
                                                           or a documented threat-model residual.
   no way to deliver hooks on that OS?                   -> acp or unsupported, with a refusal reason.
```

## Rules that prevent the known bugs

1. **ID:** use lowercase `[a-z0-9]+` with no separators. `DEFENSECLAW_FAIL_MODE_<ID>` strips `-` and `_`, so `open-hands` and `openhands` would collide.
2. **Closed lists:** give the connector an explicit arm in every closed list, even when the answer is "none" (`return nil`, `[]`, `unsupportedSurface(...)`). Default arms fall back to OpenClaw paths, `"unknown"`, a proxy message or "not certified".
3. **Contract parity:** the Go contract (`builtinHookContracts`) and `cli/defenseclaw/inventory/hook_contracts.json` must agree on darwin, linux and windows. `HookScriptVersion` must equal the script's `# defenseclaw-managed-hook vN` marker (the plugin's `// defenseclaw-managed-plugin vN`, the policy bridge's `# defenseclaw-managed-policy vN`). No test checks that they match, so check it yourself. Verify and doctor code also hard-codes some markers as literals, so grep for `defenseclaw-managed-` whenever you bump one ([core.md §12](reference/core.md#12-known-gaps-check-before-relying-on-them)).
4. **Event casing:** use the vendor's exact wire casing. Lifecycle routing, `foreignHookStopEvent` and `correlationLifecycleForContract` match exactly. OpenHands sent PascalCase `event_type` while the contract said snake_case, so PreToolUse was never inspected (`bb78ad66`).
5. **Shell tools:** map every shell or exec tool name in all the shell tables, and project vendor metadata keys away so ActionFacts stays authoritative. If you don't, the result is a CRITICAL finding with `raw_action=allow`, not a block (Amp `async_shell_command` `d01406ee`, Kiro `execute_bash`, Antigravity `run_command` metadata).
6. **Rendered arguments:** every argument in a rendered hook command must exist on the `defenseclaw-hook hook` command (`internal/cli/hook.go`). Kiro's `--hook-surface v3` was a usage error, exit 1, and Kiro went ahead (`cb96bc5d`). Never append positional arguments to the native runner; it is `cobra.NoArgs`.
7. **Windows exit codes:** `defenseclaw-hook.exe` is a GUI-subsystem binary, so `& '<exe>'` does not wait and loses exit 2. Use the encoded `Start-Process -Wait` bridge or a `.ps1` adapter, and test through the host's real shell (`cmd.exe /d /s /c`, PowerShell or bash) (`cd6b6f2c`).
8. **Stop events:** put the vendor's stop and session-end events in `foreignHookStopEvent`. Otherwise a fail-closed standalone session loops on the stop hook.
9. **Teardown:** teardown must recognize every command form ever rendered (legacy Windows forms, script versus admin binary). Keep old forms as teardown identities.
10. **Enterprise guard:** a guarded connector must run the admin-owned `defenseclaw-hook ... --enterprise-managed` (or call `--foreign-hook-check`), never a user-writable script (Devin, `0f728f8b`).
11. **Secure Client:** the Secure Client profile must stay byte-identical. Never edit `*-secure-client.*` templates, `secureClientPluginAssets`, the three-connector Windows certified set, or the macOS allow-list.
12. **Hygiene:** don't hand-edit generated `openwiki/` pages. Don't spell retired connector names; `cli/tests/test_retired_connector_names.py` scans every tracked file. Keep host names, accounts and local paths out of the repository.

## End-to-end order

Work in this order. Each step links to the reference section with the file- and symbol-level detail. [reference/checklist.md](reference/checklist.md) is the copyable version, with one line per touch point and the test that verifies it.

0. **Research the vendor** before you write any code. Record, with doc URLs and a pinned revision:
   - the hook events and their exact casing;
   - stdin shapes for every event, captured from a real run;
   - how the agent reads the result (stdout, exit code, stderr);
   - hook ordering and merge rules when several sources register hooks;
   - config paths per OS and the environment variables that redirect them;
   - the version command;
   - where MCP servers, skills, plugins, rules and agents live;
   - native OTel;
   - any machine-policy source;
   - shell and exec tool names and their argument keys.

   These become the contract `Notes`, the correlation provenance and the tests.
1. **Identity and the Go type.** Pick the ID, aliases and derived names. Implement `Connector` and the optional interfaces. Register it in `newBuiltinConnectors` and add a `windowsConnectorSupport` row. See [core.md §1–2](reference/core.md#1-identity).
2. **Hook contract.** Add the Go contract, the JSON manifest entry, the tool-call lifecycle, the correlation spec, and the per-OS pins. See [core.md §3](reference/core.md#3-hook-contract-and-lifecycle).
3. **Runtime artifact.** Add the script, plugin or adapter template; `connectorHookScripts`; the `hookexec` spec and dialect branches; the Windows command; and the owned-command needles. See [core.md §4–6](reference/core.md#4-hook-templates).
4. **Setup, teardown and verify.** Cover backups, idempotence, tombstones, the contract lock and fail mode. See [core.md §7](reference/core.md#7-setup-teardown-verify).
5. **Gateway and guardrails.** Add the route; Decode and DecodeToolArgs; event classifiers; shell-tool normalization; the MCP and skill identity; verdict mapping and the response. See [guardrails.md](reference/guardrails.md).
6. **Assets.** Add capabilities and `ComponentTargets`; the Go `claw.go` resolvers; managed MCP inventory; Python `connector_paths.py`; the AIBOM; plugin manifests; self-exemption for bridges. See [assets.md](reference/assets.md).
7. **Discovery and observability.** Add AI signatures (Go and Python copies byte-identical); agent discovery specs; endpoint inventory; schema enums; telemetry normalizers; correlation; native OTLP; audit identity; health and status names; dashboards. See [discovery-observability.md](reference/discovery-observability.md).
8. **CLI, TUI and installers.** Add setup tables and branches; onboarding; doctor, status and fail mode; uninstall and migration; TUI pickers and labels; the Go CLI; env vars; `install.sh`, `install.ps1` and the Windows native Setup lists; the macOS app's connector lists. See [cli-tui.md](reference/cli-tui.md).
9. **Enterprise managed mode.** Add the route per OS; the machine-policy target or per-user enrollment; the guard; the version probe and floor; every hard-coded Windows per-user list; ACP; threat-model rows. See [enterprise.md](reference/enterprise.md).
10. **Docs.** Add the connector page; `meta.json`; the index and compatibility rows; the capability matrix; the icon; the pages that list every connector; enterprise docs; CHANGELOG. See [docs-tests-ci.md §1–3](reference/docs-tests-ci.md#1-docs).
11. **Tests and CI.** Update the hard-coded lists in tests; the registry-driven parity tests; per-connector tests; the e2e matrix row and golden; the live E2E harness; CI matrices and the tests that pin them. See [docs-tests-ci.md §4–6](reference/docs-tests-ci.md#4-tests).
12. **Validate** with the narrowest commands that prove the change ([docs-tests-ci.md §7](reference/docs-tests-ci.md#7-validation-commands)). Then certify live on each OS you claim, and only then add a `validated_versions.json` row.

## Find every list: the sibling grep

No single registry drives everything. The reliable way to find every touch point is to pick the existing connector closest to yours, list every place it appears, and decide for each hit whether your connector belongs there:

```bash
# closest sibling: copilot (per-event command hook + machine policy), devin (per-user hook),
# amp/opencode (plugin), kiro (ACP + hooks), omnigent (policy bridge), openclaw (proxy)
git grep -n -i -w '<sibling>' -- ':!openwiki' ':!docs/research' ':!CHANGELOG.md' | wc -l
git grep -l -i -w '<sibling>' -- ':!openwiki' | awk -F/ '{print $1"/"$2}' | sort | uniq -c | sort -rn
# then, per directory, review each hit
git grep -n -i -w '<sibling>' -- internal/enterprisehooks
```

Also grep for lists that hold several connectors but not your sibling, for example `git grep -n '"hermes", *"opencode"'`. The worked example, [reference/worked-example.md](reference/worked-example.md), is this search already done for Copilot.

## Reference files

| File | Covers |
|---|---|
| [reference/core.md](reference/core.md) | identity, Go interfaces, registry, hook contract, lifecycle, correlation, templates, `hookexec`, Windows commands, setup/teardown/verify, fail modes, exit codes |
| [reference/guardrails.md](reference/guardrails.md) | request pipeline, payload decode, event classes, ActionFacts shell tables, proof gating, verdict mapping, vendor block/ask rendering |
| [reference/enterprise.md](reference/enterprise.md) | routes, machine-policy targets, foreign-hook guard, Unix guardian and worker, Windows standalone lists, floors, ACP, Secure Client invariants, threat model |
| [reference/assets.md](reference/assets.md) | skills, MCP servers, plugins, rules and agents: capabilities, watcher, config resolvers, inventory, AIBOM, bridge self-exemption |
| [reference/discovery-observability.md](reference/discovery-observability.md) | AI signatures, agent discovery, endpoint inventory, schemas, telemetry normalizers, correlation, native OTLP, audit, health, dashboards |
| [reference/cli-tui.md](reference/cli-tui.md) | Python setup, onboarding, doctor, status, fail mode, uninstall, migration, TUI, Go CLI, env vars, installers, Windows native Setup |
| [reference/docs-tests-ci.md](reference/docs-tests-ci.md) | docs pages and data, hard-coded test lists, registry-driven parity tests, e2e matrix, live E2E harness, CI workflows, validation commands |
| [reference/worked-example.md](reference/worked-example.md) | GitHub Copilot CLI traced through every layer, file by file in order |
| [reference/checklist.md](reference/checklist.md) | copyable checklist, one line per touch point, with the verifying test or command |

## Study these commits

- `cf576356`: Amp added as a policy plugin, end to end.
- `f29b76ec`: OmniGent policy connector.
- `f05a9d3c`: ACP guard with Kiro and Zed.
- `e508ba54` (the port of #903): a connector folded into another. It shows every place a connector ID lives, including the config-migration maps.

The fix commits named in each reference show the mistakes to avoid.

Run `git show --stat <sha>` to see a commit's footprint. The first three are on `main`; the others may need the `git log -S` search described at the top.
