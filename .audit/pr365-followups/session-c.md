# Session C: Antigravity Contract Findings

Branch/worktree: `codex/pr365-antigravity-contract` in `../defenseclaw-pr365-antigravity-contract`.

No implementation files were changed. This session created only:

- `docs/development/antigravity-mcp-contract.md`
- `.audit/pr365-followups/session-c.md`

## Findings

- Official Antigravity docs now document MCP, hooks, skills, rules/workflows, and plugins as file-backed customization surfaces.
- Canonical MCP path for PR #365 should be `~/.gemini/config/mcp_config.json`; workspace MCP is `<workspace>/.agents/mcp_config.json`.
- Remote MCP should be written with `serverUrl`. The 2.0.13 changelog says `url` is now accepted, but CLI docs and migration docs still identify `serverUrl` as the modern/canonical field.
- Local MCP uses `command`, optional `args`, optional `env` object, and optional `cwd`.
- Hooks use `hooks.json` in `~/.gemini/config/` or `.agents/`. DefenseClaw should write global hooks only because current PR evidence says global+workspace hook files duplicate-fire when both are present.
- Skills are officially documented in two shapes: AgentSkills folders with `SKILL.md`, and CLI direct markdown skill files. The contract recommends write support for the folder form and discovery-only handling for direct `.md` skill files.
- Rules are markdown-backed, but activation metadata/file naming is not documented enough for safe DefenseClaw writes.
- Workflows are markdown-backed in the UI, but no filesystem path/schema is documented.
- Plugins require `plugin.json`; `name` is optional and defaults to the folder name. Plugin-contained `mcp_config.json`, `hooks.json`, `skills/`, `rules/`, and CLI `agents/` are documented, but this PR should keep plugins discovery/scan-only unless maintainers approve install/disable semantics.

## Sources

- Antigravity MCP: https://antigravity.google/docs/mcp
- Antigravity Hooks: https://antigravity.google/docs/hooks
- Antigravity Skills: https://antigravity.google/docs/skills
- Antigravity Rules and Workflows: https://antigravity.google/docs/rules-workflows
- Antigravity Plugins: https://antigravity.google/docs/plugins
- Antigravity CLI Plugins and Skills: https://antigravity.google/docs/cli-plugins
- Antigravity CLI Migration: https://antigravity.google/docs/gcli-migration
- Antigravity Changelog: https://antigravity.google/changelog
- Local `agy --version`: `1.0.5`

## Unresolved Maintainer Questions

1. Should Antigravity skill writes be workspace-only for PR #365, even though global skills are documented?
2. Should DefenseClaw ever write CLI direct markdown skills, or only AgentSkills folder-form skills?
3. Should Antigravity plugin install/disable be implemented later through `agy plugin`, or remain discovery-only permanently?
4. Should the duplicate-fire hook behavior be treated as permanently contracted, or re-smoked against a newer `agy` before release?
