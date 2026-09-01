# Devin native connector evidence

Research date: **2026-08-20**. Supported contract: **Devin CLI 3000.4.25** on
Windows, macOS, and Linux. This is source-reviewed contract evidence, not an
authenticated live-client certification record.

## Accepted native boundary

- Connector ID: `devin`. Retired predecessor identifiers are not public
  aliases or install choices. Installer migration code may use an old ID only
  to restore an existing managed hook file before configuring Devin.
- Windows executable: `%LOCALAPPDATA%\devin\cli\bin\devin.exe`, exact version
  `3000.4.25`, regular non-reparse path, valid Authenticode chain, signer
  `Exafunction, Inc.`.
- User hooks: `%APPDATA%\devin\config.json` on Windows and
  `~/.config/devin/config.json` on macOS/Linux, nested under `hooks`.
- Project hooks: `.devin/hooks.v1.json`, where the hook map is the whole JSONC
  document. DefenseClaw does not claim or modify Devin's Claude-compatibility
  hook locations.
- Events: `PreToolUse`, `PostToolUse`, `PermissionRequest`,
  `UserPromptSubmit`, `Stop`, `PostCompaction`, `SessionStart`, `SessionEnd`.
- Command hooks receive JSON on stdin. Top-level `decision` and `reason` carry
  allow/block results. `hookSpecificOutput` is event-tagged; DefenseClaw emits
  `additionalContext` only for `UserPromptSubmit`, `SessionStart`, and
  `PostToolUse`. Exit `2` blocks; every other hook error fails open.
- Correlation uses `session_id` and per-turn `prompt_id`. Devin publishes no
  stable per-tool invocation ID, so paired tool state is detection-only.
- MCP inventory covers `mcp_config.json`. Skills are read from the documented
  `.agents` and `.devin` surfaces; explicit DefenseClaw installs use the native
  project `.devin/skills` or user config `skills` root. Custom subagent files
  under the user config root and project `.devin/agents` or `.agents/agents`
  are discovered read-only. Rules are discovered locally. Plugins are closed
  beta and are not advertised as a generally available connector capability.

## Explicit limitations

Restricted Mode disables hooks and agents. DefenseClaw does not claim native
OTLP, a proxy/model transport, ACP, cloud Devin execution, plugin support,
sandboxing, or egress enforcement for this connector.

## Primary sources

- [Hooks overview](https://docs.devin.ai/cli/extensibility/hooks/overview)
- [Lifecycle hooks](https://docs.devin.ai/cli/extensibility/hooks/lifecycle-hooks)
- [Configuration](https://docs.devin.ai/cli/extensibility/configuration)
- [MCP configuration](https://docs.devin.ai/cli/extensibility/mcp/configuration)
- [Rules and AGENTS.md](https://docs.devin.ai/cli/extensibility/rules)
- [Skills](https://docs.devin.ai/cli/extensibility/skills/overview)
- [Plugins](https://docs.devin.ai/cli/extensibility/plugins/overview)
- [Stable changelog](https://docs.devin.ai/cli/changelog/stable)

The reviewed hook overview snapshot is recorded by
`devin-hooks-doc-d420df73` with SHA-256
`d420df730773a54829f863a05874da48b1fbeb9213f9b5147d65f1acbe3a7ca9`.
