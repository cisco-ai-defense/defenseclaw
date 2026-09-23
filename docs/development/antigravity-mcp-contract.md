# Antigravity MCP and Customization Contract

> **Status: implementation research contract.** Antigravity is implemented
> under `internal/gateway/connector/`; use the
> [published Antigravity guide](https://cisco-ai-defense.github.io/defenseclaw/docs/connectors/antigravity/)
> and current connector tests for supported behavior. This contract records the
> official-source decisions and native Windows eligibility refreshed below.

Scope: Google's Antigravity (`agy`) connector. This pins native Windows eligibility, hook enforcement, file paths, and JSON shapes DefenseClaw relies on.

Research refreshed: 2026-07-31.

## Official Sources

- [Antigravity MCP](https://antigravity.google/docs/mcp)
- [Antigravity Hooks](https://antigravity.google/docs/hooks)
- [Antigravity Skills](https://antigravity.google/docs/skills)
- [Antigravity Rules and Workflows](https://antigravity.google/docs/rules-workflows)
- [Antigravity Plugins](https://antigravity.google/docs/plugins)
- [Antigravity CLI Plugins and Skills](https://antigravity.google/docs/cli-plugins)
- [Antigravity Agents command](https://antigravity.google/docs/cli/commands/agents)
- [Antigravity Subagents](https://antigravity.google/docs/subagents)
- [Antigravity CLI Migration](https://antigravity.google/docs/gcli-migration)
- [Antigravity Changelog](https://antigravity.google/changelog)
- [Antigravity CLI install](https://antigravity.google/docs/cli/install)
- [Antigravity downloads](https://antigravity.google/download)
- [Antigravity CLI releases](https://github.com/google-antigravity/antigravity-cli/releases)
- [Google I/O 2026 feature deep dive](https://antigravity.google/blog/google-io-2026-feature-deep-dive)

## Native Windows Research Gate

| Evidence | Official result |
| --- | --- |
| Current release | Antigravity 2.0 v2.4.3; the accepted protected harness pins official CLI v1.1.10. This is availability metadata, not DefenseClaw validation. |
| Native support | The install page says the CLI runs natively on Windows, macOS, and Linux. The download page publishes Windows x64 and ARM64 clients with Windows 10 64-bit minimum. DefenseClaw's x64 implementation awaits integrated certification. |
| Install | PowerShell: `irm https://antigravity.google/cli/install.ps1 \| iex`; CMD installer is also published. The official PowerShell installer selects `windows_amd64` or `windows_arm64`, verifies the manifest-provided SHA-512, installs `%LOCALAPPDATA%\agy\bin\agy.exe`, and invokes the native executable. DefenseClaw discovery accepts only the token-bound Known Folder form of that canonical path, applies its trusted ACL boundary, and checks a stable no-follow SHA-512 across the version probe. No vendor signer pin or certification is claimed. |
| Authentication | Windows Credential Manager stores secure token profiles; browser authentication is the fallback. No API-key-based headless authentication is documented. |
| Config | Global hooks: `~/.gemini/config/hooks.json`; workspace hooks: `<workspace>/.agents/hooks.json`. |
| Process contract | Command handlers receive JSON on stdin and return JSON on stdout. `timeout` defaults to 30 seconds. `PreToolUse` runs before execution and its synchronous stdout decision can deny the tool. |
| Exit behavior | The official hook documentation does not define non-zero process exit status as an enforcement mechanism. DefenseClaw does not claim it. |

The five official inputs share `conversationId`, `workspacePaths`,
`transcriptPath`, and `artifactDirectoryPath`. `PreToolUse` adds
`toolCall{name,args}` and `stepIdx`; `PostToolUse` adds `stepIdx` and optional
`error`; Pre/PostInvocation add `invocationNum` and `initialNumSteps`; Stop adds
`executionNum`, `terminationReason`, `error`, and `fullyIdle`.

The output contracts are event-specific:

- `PreToolUse`: required `decision` (`allow`, `deny`, `ask`, or `force_ask`),
  with optional `reason` and `permissionOverrides`.
- `PostToolUse`: `{}`.
- Pre/PostInvocation: optional `injectSteps`; PostInvocation may also return
  `terminationBehavior`.
- Stop: required `decision`; `continue` re-enters the loop and any other value
  permits stopping.

`PreToolUse` and `PostToolUse` use matcher groups with nested `hooks`.
PreInvocation, PostInvocation, and Stop use direct handler lists; matchers are
ignored for those events. Reusing Claude Code response fields is not valid.

## Contract Decisions

| Surface | Global path | Workspace path | Plugin-contained path | DefenseClaw behavior |
| --- | --- | --- | --- | --- |
| Hooks | `~/.gemini/config/hooks.json` | `<workspace>/.agents/hooks.json` | `<plugin>/hooks.json` | Read/write global hook only. Discover workspace/plugin hooks but do not write them. |
| MCP | `~/.gemini/config/mcp_config.json` | `<workspace>/.agents/mcp_config.json` | `<plugin>/mcp_config.json` | Read/write global and workspace MCP configs. Discover plugin MCP configs. |
| Skills | `~/.gemini/config/skills/<skill>/SKILL.md`; CLI also documents `~/.gemini/antigravity-cli/skills/` | `<workspace>/.agents/skills/<skill>/SKILL.md`; legacy `.agent/skills` remains readable | `<plugin>/skills/<skill>/SKILL.md` | Read/write AgentSkills folder form; discover CLI direct-`.md` skill files until shape conflict is resolved. |
| Rules | `~/.gemini/GEMINI.md`; migration/changelog also mention `AGENTS.md` as context | `<workspace>/.agents/rules/`; legacy `<workspace>/.agent/rules/` remains readable | `<plugin>/rules/*.md` | Bounded no-follow discovery/scan only. Do not write rules. |
| Workflows | UI supports global workflows but no path is documented | UI supports workspace workflows but no path is documented | Not documented | Unsupported for write; discovery only if a documented path appears later. |
| Agents | `~/.gemini/config/agents/<agent>.md` or `<agent>/agent.md` | `<workspace>/.agents/agents/<agent>.md` or `<agent>/agent.md` | `<plugin>/agents/` | Global, workspace, and plugin-contained agents are discovery-only; DefenseClaw does not install or modify them. |
| Plugins | `~/.gemini/config/plugins/<plugin>/`; CLI stages installed plugins under `~/.gemini/antigravity-cli/plugins/<plugin>/` | `<workspace>/.agents/plugins/<plugin>/` or `<workspace>/_agents/plugins/<plugin>/` | N/A | Install/list/scan/remove at the documented global or workspace path. Discover the CLI staging path. Runtime disable remains policy/advisory state. |

Notes:

- The CLI plugins page mentions `~/.gemini/antigravity-cli/mcp_config.json`, but the IDE MCP docs, CLI migration docs, and the local `agy 1.0.5` install point to `~/.gemini/config/mcp_config.json`. DefenseClaw should write `~/.gemini/config/mcp_config.json` and treat `~/.gemini/antigravity-cli/mcp_config.json` as discovery-only until Google resolves the conflict.
- Official hook docs document both global and workspace discovery. DefenseClaw writes only the global hook file and reports a duplicate if its managed hook is also present in the workspace file.

## MCP Schema

MCP files are JSON documents with one top-level `mcpServers` object.

### Local stdio example

```json
{
  "mcpServers": {
    "defenseclaw-local": {
      "command": "/opt/defenseclaw/bin/defenseclaw",
      "args": ["mcp", "serve"],
      "env": {
        "AGY_PROFILE": "default"
      },
      "cwd": "/workspace/project",
      "disabled": false,
      "disabledTools": ["unsafe_tool"]
    }
  }
}
```

Local schema contract:

- `command`: required string for stdio transport.
- `args`: optional string array.
- `env`: optional object/map of environment variable names to string values.
- `cwd`: optional working directory string.
- `disabled`: optional boolean.
- `disabledTools`: optional string array.

### Remote HTTP example

```json
{
  "mcpServers": {
    "defenseclaw-remote": {
      "serverUrl": "https://mcp.example.com/mcp/",
      "headers": {
        "Authorization": "Bearer ${AGY_MCP_TOKEN}"
      },
      "disabled": false
    }
  }
}
```

Remote schema contract:

- `serverUrl`: canonical DefenseClaw write field for remote MCP.
- `url`: accepted by the Antigravity 2.0.13 changelog as an alias, but not canonical for DefenseClaw writes.
- `httpUrl`: legacy migration input only; do not write it.
- Optional remote fields include `headers`, `authProviderType`, and `oauth`.

DefenseClaw should read both `serverUrl` and `url`, preserve unknown fields, and write `serverUrl` for new or migrated remote entries.

## Implemented Decisions

- DefenseClaw writes Antigravity hooks only to `~/.gemini/config/hooks.json`. Google documents no `ANTIGRAVITY_CONFIG_DIR` or `GEMINI_CONFIG_DIR` override. Older DefenseClaw-only custom bindings remain internal custody solely for exact restoration and migration to the official path. Workspace and plugin hook files are discovery-only so agy's multi-file merge cannot duplicate DefenseClaw hook firings.
- All five documented events are registered with their exact mixed schema and an event-bound command. Only synchronous `PreToolUse` stdout `{"decision":"deny"}` is claimed as hard blocking; non-zero exit status is not.
- MCP read/write support uses `~/.gemini/config/mcp_config.json` and `<workspace>/.agents/mcp_config.json`; plugin MCP configs are discovery-only. DefenseClaw writes `serverUrl` for remote entries, reads `url` for compatibility, preserves unknown fields, and does not log secret-bearing `env` or `headers` values.
- AgentSkills folder form is read/write at `~/.gemini/config/skills/<skill>/SKILL.md` and `<workspace>/.agents/skills/<skill>/SKILL.md`. CLI direct markdown skills under `~/.gemini/antigravity-cli/skills/` remain discovery-only because they use a different shape.
- Global `GEMINI.md`, current `.agents/rules`, legacy `.agent/rules`, and plugin `rules/*.md` are bounded no-follow discovery/scan only. Workflows and global, workspace, or plugin-contained agents remain discovery-only as listed in the contract table. DefenseClaw installs and removes Antigravity plugins at Google's documented manual global/workspace paths; the CLI staging path remains discovery-only, and runtime disable remains policy/advisory state rather than invoking `agy plugin disable`.
- CLI v1.1.10 is current vendor availability metadata. The hook compatibility floor remains `>=1.1.8`; no undocumented behavior or certification is inferred from the version delta. Ordinary native-Windows setup is supported while validated version, timestamp, run URL, authentication, HITL, and live evidence remain empty or unverified and `live` remains `false`.
- Enterprise/managed, Team, ProgramData, cloud-dashboard, MDM, and organization-policy surfaces are outside this connector contract and remain unverified.
