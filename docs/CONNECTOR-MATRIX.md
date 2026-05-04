# DefenseClaw — Connector Matrix

This page is the canonical, version-controlled reference for which features
are wired across each connector and, importantly, which gaps are **by
design** versus which are still pending implementation.

For the historical change log of how each row got to its current state, see
[`PR141-MATRIX-UPDATE.md`](PR141-MATRIX-UPDATE.md).

---

## At a glance

| Feature                     | OpenClaw | ZeptoClaw | Claude Code | Codex | Hermes | Cursor | Windsurf | Gemini CLI | Copilot CLI |
| --------------------------- | -------- | --------- | ----------- | ----- | ------ | ------ | -------- | ---------- | ----------- |
| LLM traffic interception    | OK       | OK        | OK          | OK    | n/a    | n/a    | n/a      | n/a        | n/a         |
| Proxy-side response scan    | OK       | OK        | OK          | OK    | n/a    | n/a    | n/a      | n/a        | n/a         |
| Hook telemetry              | OK       | n/a*      | OK          | OK    | OK     | OK     | OK       | OK         | OK          |
| Hook `mode=action` blocking | OK       | n/a*      | OK          | partial | partial | partial | partial | partial    | partial     |
| Native human approval       | brokered | n/a       | PreToolUse  | no    | no     | event-specific | no | no | PreToolUse |
| Subprocess enforcement      | OK       | OK        | OK          | OK    | no     | no     | no       | no         | no          |
| Skill scan / list / enable  | OK       | OK        | OK          | OK    | no     | no     | no       | no         | no          |
| Watcher (skills + plugins)  | OK       | OK        | OK          | OK    | no     | no     | no       | no         | no          |

`*` = "not applicable" because the host agent has no schema slot for
external-script hook invocation. See **By-design connector limitations**
below for the architectural reason and how the security guarantee is
preserved without it.

The Hermes, Cursor, Windsurf, Gemini CLI, and Copilot CLI connectors are
hook-only in v1. They install vendor-native hook config and send hook payloads
to DefenseClaw, but they do not redirect LLM traffic through the proxy.

## Hook Capability Matrix

| Connector | can_block | can_ask_native | ask_events | block_events | supports_fail_closed | scope | config_path |
| --------- | --------- | -------------- | ---------- | ------------ | -------------------- | ----- | ----------- |
| Hermes | yes | no | none | `pre_tool_call` | no | user | `~/.hermes/config.yaml` |
| Cursor | yes | yes | `beforeShellExecution`, `beforeMCPExecution` | documented pre-action hooks | yes | user | `~/.cursor/hooks.json` |
| Windsurf | yes | no | none | `pre_user_prompt`, `pre_read_code`, `pre_write_code`, `pre_run_command`, `pre_mcp_tool_use` | no | user | `~/.codeium/windsurf/hooks.json` |
| Gemini CLI | yes | no | none | `BeforeAgent`, `BeforeModel`, `BeforeTool`, `AfterTool`, `AfterAgent` | yes | user | `~/.gemini/settings.json` |
| Copilot CLI | yes | yes | `preToolUse` / `PreToolUse` | `PreToolUse`, `PermissionRequest`, stop/failure hooks | no | workspace | `<workspace>/.github/hooks/defenseclaw.json` |

`confirm` verdicts are rendered as native ask only when the event is listed in
`ask_events`. Unsupported `confirm` decisions are downgraded explicitly while
preserving `raw_action: "confirm"` in the hook response.

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
