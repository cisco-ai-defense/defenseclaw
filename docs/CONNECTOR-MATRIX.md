# DefenseClaw — Connector Matrix

This page is the canonical, version-controlled reference for which features
are wired across each connector and, importantly, which gaps are **by
design** versus which are still pending implementation.

For the historical change log of how each row got to its current state, see
[`PR141-MATRIX-UPDATE.md`](PR141-MATRIX-UPDATE.md).

---

## At a glance

| Feature                     | OpenClaw | ZeptoClaw | Claude Code | Codex | Hermes | Cursor | Windsurf | Gemini CLI | Copilot CLI | OpenHands |
| --------------------------- | -------- | --------- | ----------- | ----- | ------ | ------ | -------- | ---------- | ----------- | --------- |
| LLM traffic interception    | OK       | OK        | OK          | OK    | n/a    | n/a    | n/a      | n/a        | n/a         | n/a       |
| Proxy-side response scan    | OK       | OK        | OK          | OK    | n/a    | n/a    | n/a      | n/a        | n/a         | n/a       |
| Hook telemetry              | OK       | n/a*      | OK          | OK    | OK     | OK     | OK       | OK         | OK          | OK        |
| Hook `mode=action` blocking | OK       | n/a*      | OK          | partial | partial | partial | partial | partial    | partial     | partial   |
| Native human approval       | brokered | n/a       | PreToolUse  | no    | no     | event-specific | no | no | PreToolUse | no        |
| Subprocess enforcement      | OK       | OK        | OK          | OK    | no     | no     | no       | no         | no          | no        |
| Skill scan / list / enable  | OK       | OK        | OK          | OK    | skills | skills/rules | no skills | skills | skills/rules | skills |
| Watcher (skills + plugins)  | OK       | OK        | OK          | OK    | skills/plugins | skills | discovery | skills/extensions | skills | skills |
| Native OTLP ingest          | OK       | n/a       | OK          | OK    | hook-only | hook-only | hook-only | OK | env-opt-in | hook-only |

`*` = "not applicable" because the host agent has no schema slot for
external-script hook invocation. See **By-design connector limitations**
below for the architectural reason and how the security guarantee is
preserved without it.

The Hermes, Cursor, Windsurf, Gemini CLI, Copilot CLI, and OpenHands connectors do not
redirect LLM traffic through the proxy in v1. They are still first-class
connectors with explicit hook, MCP, skill/rule/plugin/agent, CodeGuard, and
telemetry capability rows where the vendor has documented local surfaces.

## Versioned Hook Contracts

The machine-readable compatibility source lives at
[`cli/defenseclaw/inventory/hook_contracts.json`](../cli/defenseclaw/inventory/hook_contracts.json).
DefenseClaw setup refreshes `agent_discovery.json`, checks the installed
connector version against this manifest, and refuses unsupported hook
contracts in `mode=action` unless
`DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT=1` is set for exploratory testing.

After the gateway completes connector setup it writes
`<data_dir>/hook_contract_lock.json`. That lock records the current
installed connector version, normalized version, selected contract ID, hook
script version, script digests, and DefenseClaw build version so a later
doctor run can detect drift.

Setup allows unsupported or unverified hook connector versions in observe mode
with a warning. Action mode fails closed unless
`DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT=1` is set for exploratory testing.

| Connector | Current compatibility gate | Supported connector versions | Hook contract / script | AID surfaces |
| --------- | -------------------------- | ---------------------------- | ---------------------- | ------------ |
| OpenClaw | proxy, not hook-gated | not gated by hook contract | n/a | proxy request/response surfaces |
| ZeptoClaw | proxy, not hook-gated | not gated by hook contract | n/a | proxy request/response surfaces |
| Codex | hook contract | `>=0.124.0` | `codex-hooks-v1` / `v6` | prompt, tool_call, tool_result |
| Claude Code | hook contract | `>=2.1.144` | `claudecode-hooks-v1` / `v6` | prompt, tool_call, tool_result, event_content |
| Hermes | hook contract | `>=0.11.0` | `hermes-hooks-v1` / `v6` | tool_call |
| Cursor | hook contract | `>=1.7.0` | `cursor-hooks-v1` / `v6` | prompt, tool_call, tool_result |
| Windsurf | hook contract | `>=1.12.41` | `windsurf-hooks-v1` / `v6` | prompt, tool_call, tool_result |
| Gemini CLI | hook contract | `>=0.26.0` | `geminicli-hooks-v1` / `v6` | prompt, tool_call, tool_result |
| Copilot CLI | hook contract | `>=1.0.18` | `copilot-hooks-v1` / `v6` | prompt, tool_call, tool_result |
| OpenHands | hook contract | unversioned / documented hooks; tested with `OpenHands CLI 1.16.0` | `openhands-hooks-v1` / `v6` | prompt, tool_call, tool_result, event_content |

No hook contract currently has a `max_exclusive` ceiling. We only add an upper
bound when an upstream release publishes a breaking hook change; otherwise,
future connector versions remain reproducible through the lock file and drift
checks instead of being blocked by a guessed major-version cap.

Version floors are evidence-backed from upstream release notes or current
vendor docs: Codex `0.124.0` is the stable-hooks release, Gemini CLI `0.26.0`
enabled hooks by default, Cursor `1.7.0` introduced beta hooks, Hermes
`0.11.0` added shell hooks for `pre_tool_call`, Windsurf `1.12.41` added user
prompt hooks to the Cascade pre-hook set, and Copilot CLI `1.0.18` is the first
release containing every event in the current DefenseClaw Copilot contract.
OpenHands uses the current documented `.openhands/hooks.json` contract, has
been validated with `OpenHands CLI 1.16.0`, and is accepted as unversioned
until upstream publishes a hook-version floor. DefenseClaw installs OpenHands
globally through `~/.openhands/hooks.json` by default and uses repo-local
`.openhands/hooks.json` only when a workspace is pinned.
Claude Code is pinned to the current documented hook surface captured at
`2.1.144`; older Claude Code versions exposed smaller event sets.

## Hook Capability Matrix

| Connector | can_block | can_ask_native | ask_events | block_events | supports_fail_closed | scope | config_path |
| --------- | --------- | -------------- | ---------- | ------------ | -------------------- | ----- | ----------- |
| Hermes | yes | no | none | `pre_tool_call` | no | user | `~/.hermes/config.yaml` |
| Cursor | yes | yes | `beforeShellExecution`, `beforeMCPExecution` | documented pre-action hooks | yes | user | `~/.cursor/hooks.json` |
| Windsurf | yes | no | none | `pre_user_prompt`, `pre_read_code`, `pre_write_code`, `pre_run_command`, `pre_mcp_tool_use` | no | user | `~/.codeium/windsurf/hooks.json` |
| Gemini CLI | yes | no | none | `BeforeAgent`, `BeforeModel`, `BeforeTool`, `AfterTool`, `AfterAgent` | yes | user | `~/.gemini/settings.json` |
| Copilot CLI | yes | yes | `preToolUse` / `PreToolUse` | `PreToolUse`, `PermissionRequest`, stop/failure hooks | no | user,workspace | `~/.copilot/hooks/defenseclaw.json` or `<workspace>/.github/hooks/defenseclaw.json` |
| OpenHands | yes | no | none | `pre_tool_use`, `user_prompt_submit`, `stop` | yes | user,workspace | `~/.openhands/hooks.json` or `<workspace>/.openhands/hooks.json` |

`confirm` verdicts are rendered as native ask only when the event is listed in
`ask_events`. Unsupported `confirm` decisions are downgraded explicitly while
preserving `raw_action: "confirm"` in the hook response.

## Local Surface Matrix

| Connector | MCP | Skills | Rules | Plugins / extensions | Agents | CodeGuard native assets |
| --------- | --- | ------ | ----- | -------------------- | ------ | ----------------------- |
| Hermes | `~/.hermes/config.yaml` | `~/.hermes/skills` | unsupported | `~/.hermes/plugins` (`.hermes/plugins` discovery only) | unsupported | opt-in skill |
| Cursor | `.cursor/mcp.json`, `~/.cursor/mcp.json` | `.cursor/skills`, `.agents/skills`, user equivalents | `.cursor/rules`, `AGENTS.md` | unsupported | unsupported | opt-in skill or rule |
| Windsurf | existing documented/user MCP paths only | unsupported | existing documented/user rules paths only | unsupported | unsupported | opt-in rule only when a rules path exists |
| Gemini CLI | `~/.gemini/settings.json` | `.gemini/skills`, `.agents/skills` | represented through skills/agents | `.gemini/extensions`, `~/.gemini/extensions` | `.gemini/agents`, `~/.gemini/agents` | opt-in skill |
| Copilot CLI | `~/.copilot/mcp-config.json`, optional workspace `.github/mcp.json`, `.mcp.json` | `~/.copilot/skills`, optional workspace `.github/skills`, `.agents/skills` | optional workspace `.github/instructions` | CLI marketplace/plugin flow | `~/.copilot/agents`, optional workspace `.github/agents` | opt-in skill or rule |
| OpenHands | `~/.openhands/mcp.json` | `~/.agents/skills`, `~/.openhands/skills/installed`, `~/.openhands/cache/skills/public-skills/skills` (`~/.openhands/skills`, `~/.openhands/microagents` discovery only; workspace equivalents with `--workspace`) | `AGENTS.md` discovery only when workspace-pinned | unsupported | unsupported | opt-in skill |

CodeGuard native assets are never installed by CLI startup, `init`, sandbox
setup, or sidecar setup. Operators must run `defenseclaw codeguard install`
explicitly. Existing valid CodeGuard assets are skipped, and existing
non-CodeGuard paths require `--replace`.

## Telemetry Matrix

| Connector | Native telemetry | DefenseClaw auth | Hook telemetry |
| --------- | ---------------- | ---------------- | -------------- |
| Codex | native OTLP HTTP from config.toml | header token | notify/hook telemetry |
| Claude Code | native OTLP env in settings.json | header token | hook telemetry |
| Gemini CLI | native logs/metrics/traces in settings.json | loopback path token | hook telemetry |
| Copilot CLI | native traces/metrics via documented env vars | header token | hook telemetry |
| OpenHands | no documented native OTLP | header token | hook telemetry |
| Hermes / Cursor / Windsurf | no documented native OTLP | n/a | hook-generated logs, spans, counters |

---

## By-design connector limitations (WONTFIX, architectural)

Plan PR #194 / matrix §"Out of scope". Each item below is **not a bug** —
it is a property of the host agent's design. We do not own those binaries,
so we cannot fix the limitation directly. Instead, the proxy provides the
same security guarantee from a different surface, and the on-disk
artefacts we ship today are forward-compatible: the moment the upstream
agent grows external-script hook support, our setup is wired and the
fix is purely on the agent side.

### 1. ZeptoClaw `before_tool` hook wiring is by design

- Source: [`internal/gateway/connector/zeptoclaw.go`](../internal/gateway/connector/zeptoclaw.go)
  near the `ZeptoClawConnector` doc comment.
- Why: ZeptoClaw's `HooksConfig.before_tool` is a **notification list**
  (in-process callback signal), shaped as `[]HookRule{Match, Action}` —
  structured objects, not script paths. There is no schema slot to say
  "run `/path/to/inspect-tool.sh` before this tool fires", and adding
  one is upstream's call.
- What replaces it: The proxy enforces the policy on the LLM response
  stream **before** the tool list reaches the agent. `ToolModeBoth` on
  the connector wires this. The proxy is the policy enforcement point;
  the agent never sees a disallowed `tool_calls` entry.
- What we still ship: Hook scripts under `DataDir/hooks` for subprocess
  enforcement (shim PATH) and as forward-compat artefacts in case
  ZeptoClaw ever grows external-script hooks.
- What we do NOT do: Patch `before_tool` to point at a script. That
  would silently no-op or, worse, write a malformed `HookRule` and
  break the user's config.

### 2. Codex hook invocation is by design

- Source: [`internal/gateway/connector/codex.go`](../internal/gateway/connector/codex.go)
  near `buildCodexHooksTable`.
- Why: Today's `codex` binary does **not** honor a settings-based hook
  invocation pipeline. There is no codex code path that reads a
  `[hooks]` table out of `config.toml` and shells out to `command` on
  the matching event. The schema slot exists in the TOML grammar but
  no handler is wired in the codex runtime.
- What we ship: We still write the `[hooks]` block as a
  forward-compatibility placeholder. The script lands on disk; the
  table is well-formed per the published TOML schema. The day codex
  grows hook support, no DefenseClaw change is needed.
- What replaces it: Path-based interception. The proxy admits Codex via
  the `/c/codex/...` route prefix (`codex.HookAPIPath()`), which forces
  every tool call through `GuardrailProxy.Route` + response-scan.
  `ToolModeBoth` on the connector ensures pre-call telemetry is captured
  from the LLM response side, where the proxy still has the unstreamed
  `tool_calls` array to inspect.

---

## Implementation pointers

If you came here because something looks "missing" for ZeptoClaw or
Codex pre-tool gating, the answer is almost always one of:

- "It's enforced at the proxy, not the agent — read `Route()`."
- "It's a forward-compat artefact — we don't expect the agent to read it."
- "The schema doesn't support what you're trying to do."

Before adding code that "fixes" either case, re-read the
**By-design connector limitations** section above and check whether the
proxy already covers the scenario via `ToolModeBoth` and response-scan.

---

## See also

- [`PR141-MATRIX-UPDATE.md`](PR141-MATRIX-UPDATE.md) — change history for
  every row, including which commit shipped each piece.
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — overview of the proxy → connector
  → agent flow.
- Plan: `pr194_single_rollup` Phase C3.
