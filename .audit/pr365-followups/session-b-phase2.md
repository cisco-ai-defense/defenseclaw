# Session B Phase 2: Antigravity Go MCP and Capabilities

Branch/worktree: `codex/pr365-antigravity-go-capabilities-phase2` in `../defenseclaw-pr365-antigravity-go-capabilities-phase2`.

## Changed Files

- `internal/config/claw.go`
  - Added Antigravity-native MCP reads from `~/.gemini/config/mcp_config.json`.
  - Added pinned-workspace MCP reads from `<workspace>/.agents/mcp_config.json`.
  - Added `serverUrl` read support, `url` compatibility, local `cwd`, and documented optional remote metadata fields.
  - Added Antigravity AgentSkills and plugin discovery path dispatch without OpenClaw fallback.
- `internal/config/claw_test.go`
  - Covered Antigravity `serverUrl`, `url`, local command/args/env/cwd, optional remote metadata, global plus workspace merge, missing/malformed config safety, pinned-workspace requirement, and no OpenClaw fallback.
  - Updated skill/plugin path tests for Antigravity-owned paths.
- `internal/gateway/connector/hook_only.go`
  - Marked Antigravity MCP supported with Antigravity-owned read/write paths.
  - Marked AgentSkills folder form read/write and CLI direct markdown skills discovery-only.
  - Marked rules, plugins, and plugin-contained agents discovery-only with current rationale.
  - Kept hook installation global-only at `~/.gemini/config/hooks.json`.
- `internal/gateway/connector/hook_only_test.go`
  - Updated the hook-only capability matrix for Antigravity MCP and plugin discovery.
  - Added exact Antigravity capability path assertions for MCP, hooks, skills, rules, plugins, and plugin-contained agents.
- `.audit/pr365-followups/session-b-phase2.md`
  - This audit note.

## Tests Run

- `make sync-openclaw-extension`
  - Passed; reported placeholder OpenClaw extension embed because `dist/` is missing.
- `go test ./internal/config ./internal/gateway/connector`
  - Passed.

## Unresolved Questions

- `ConnectorCapabilities` has no first-class Workflows surface, so Antigravity workflows remain unsupported by omission in Go metadata. A future schema addition would be needed to advertise workflow discovery explicitly.
- Native Project CodeGuard install remains disabled for Antigravity because the current Go installer only implements Codex skill and Claude Code plugin install flows.
- Existing MCP merge de-duplication keeps the first server entry for duplicate names. This preserves current Go behavior; if the Python contract requires workspace duplicate-name overrides, the shared de-duplication helper should be revisited separately.

## Risks

- The Go MCP read model now carries Antigravity's documented optional remote metadata, but it still does not preserve arbitrary unknown JSON fields.
- Hook setup behavior intentionally remains global-only; workspace and plugin hook discovery metadata is represented by rationale/tests, not by a separate hook-surface write/read path type.
