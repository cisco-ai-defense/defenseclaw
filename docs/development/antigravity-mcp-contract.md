# Antigravity MCP and Customization Contract

Scope: PR #365 follow-up contract for Google's Antigravity (`agy`) connector. This pins the file paths and JSON shapes DefenseClaw should rely on before implementation.

Research date: 2026-06-16. Local cross-check: `agy --version` returned `1.0.5`; the local install exposes `agy plugin ...` commands and has `~/.gemini/config/mcp_config.json` plus `~/.gemini/config/hooks.json`. No local Antigravity plugins were installed.

## Official Sources

- [Antigravity MCP](https://antigravity.google/docs/mcp)
- [Antigravity Hooks](https://antigravity.google/docs/hooks)
- [Antigravity Skills](https://antigravity.google/docs/skills)
- [Antigravity Rules and Workflows](https://antigravity.google/docs/rules-workflows)
- [Antigravity Plugins](https://antigravity.google/docs/plugins)
- [Antigravity CLI Plugins and Skills](https://antigravity.google/docs/cli-plugins)
- [Antigravity CLI Migration](https://antigravity.google/docs/gcli-migration)
- [Antigravity Changelog](https://antigravity.google/changelog)

## Contract Decisions

| Surface | Global path | Workspace path | Plugin-contained path | DefenseClaw behavior |
| --- | --- | --- | --- | --- |
| Hooks | `~/.gemini/config/hooks.json` | `<workspace>/.agents/hooks.json` | `<plugin>/hooks.json` | Read/write global hook only. Discover workspace/plugin hooks but do not write them. |
| MCP | `~/.gemini/config/mcp_config.json` | `<workspace>/.agents/mcp_config.json` | `<plugin>/mcp_config.json` | Read/write global and workspace MCP configs. Discover plugin MCP configs. |
| Skills | `~/.gemini/config/skills/<skill>/SKILL.md`; CLI also documents `~/.gemini/antigravity-cli/skills/` | `<workspace>/.agents/skills/<skill>/SKILL.md`; legacy `.agent/skills` remains readable | `<plugin>/skills/<skill>/SKILL.md` | Read/write AgentSkills folder form; discover CLI direct-`.md` skill files until shape conflict is resolved. |
| Rules | `~/.gemini/GEMINI.md`; migration/changelog also mention `AGENTS.md` as context | `<workspace>/.agents/rules/` | `<plugin>/rules/*.md` | Discovery-only. Do not write rules until activation metadata/file naming is documented. |
| Workflows | UI supports global workflows but no path is documented | UI supports workspace workflows but no path is documented | Not documented | Unsupported for write; discovery only if a documented path appears later. |
| Agents | No standalone path documented | No standalone path documented | CLI plugins may include `<plugin>/agents/` | Unsupported standalone; plugin-contained agents are discovery-only. |
| Plugins | `~/.gemini/config/plugins/<plugin>/`; CLI stages installed plugins under `~/.gemini/antigravity-cli/plugins/<plugin>/` | `<workspace>/.agents/plugins/<plugin>/` or `<workspace>/_agents/plugins/<plugin>/` | N/A | Install/list/scan/remove at the documented global or workspace path. Discover the CLI staging path. Runtime disable remains policy/advisory state. |

Notes:

- The CLI plugins page mentions `~/.gemini/antigravity-cli/mcp_config.json`, but the IDE MCP docs, CLI migration docs, and the local `agy 1.0.5` install point to `~/.gemini/config/mcp_config.json`. DefenseClaw should write `~/.gemini/config/mcp_config.json` and treat `~/.gemini/antigravity-cli/mcp_config.json` as discovery-only until Google resolves the conflict.
- Official hook docs do not specify precedence or deduplication. Current PR evidence says Antigravity merges global and workspace hook files, causing duplicate firing if DefenseClaw writes both. Therefore write only the global hook file and record workspace hook files as discovered state.

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

## Implemented PR #365 Decisions

- DefenseClaw writes Antigravity hooks only to `~/.gemini/config/hooks.json`. Workspace and plugin hook files are discovery-only so agy's multi-file merge cannot duplicate DefenseClaw hook firings.
- `PreToolUse` remains the only empirically verified ask/block event in agy v1.0.x. Other lifecycle events are registered according to the Antigravity 2.0 contract and handled when upstream starts emitting them.
- MCP read/write support uses `~/.gemini/config/mcp_config.json` and `<workspace>/.agents/mcp_config.json`; plugin MCP configs are discovery-only. DefenseClaw writes `serverUrl` for remote entries, reads `url` for compatibility, preserves unknown fields, and does not log secret-bearing `env` or `headers` values.
- AgentSkills folder form is read/write at `~/.gemini/config/skills/<skill>/SKILL.md` and `<workspace>/.agents/skills/<skill>/SKILL.md`. CLI direct markdown skills under `~/.gemini/antigravity-cli/skills/` remain discovery-only because they use a different shape.
- Rules, workflows, and plugin-contained agents remain discovery/scan only as listed in the contract table. DefenseClaw installs and removes Antigravity plugins at Google's documented manual plugin paths; runtime disable remains policy/advisory state rather than invoking `agy plugin disable`.
