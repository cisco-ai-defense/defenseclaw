# Cursor native macOS connector evidence

Evidence date: 2026-07-30

This record distinguishes upstream availability, local observation, and
DefenseClaw validation. A latest upstream release is not a support
certification.

## Version findings

| Classification | Surface | Evidence | DefenseClaw conclusion |
| --- | --- | --- | --- |
| CURRENT | Cursor Agent CLI | The official installer at `https://cursor.com/install` resolved the macOS arm64 artifact release `2026.07.23-e383d2b`. The downloaded binary returned that exact value from `agent --version`; help uses `agent` as the primary command. The installer creates `~/.local/bin/agent` and retains `~/.local/bin/cursor-agent` as a compatibility alias. | Discovery probes the primary command, compatibility alias, and official fixed locations. This passive version/help check is not authenticated live validation. |
| CURRENT upstream | Cursor Desktop | `https://cursor.com/download` labeled Desktop `3.13` as Latest and published macOS arm64, x64, and universal downloads. | The Desktop release scheme is separate from Agent CLI. Desktop availability does not certify Agent CLI or DefenseClaw. |
| OUTDATED local | Cursor Desktop | The locally installed `/Applications/Cursor.app` reported `3.12.10`; the current upstream page reported `3.13`. The local app was accepted by Gatekeeper and signed by Team ID `VDXQ22DGB9`. | Useful host evidence only; it is neither current nor a durable green connector run. |
| CURRENT | Hook contract | Current official hook documentation still exposes the 21 events in DefenseClaw's v8 inventory, schema version 1, `failClosed`, and `cursor_version`. | The existing minimum gate `>=1.7.0`, open upper bound, 21-event inventory, user `~/.cursor/hooks.json`, fail-open default, ask/event semantics, and `NativeOTLP=false` remain evidence-backed. |
| OUTDATED | Capability claims before this change | DefenseClaw described plugins as OpenClaw-only, custom subagents as unsupported, and omitted `CLAUDE.md` plus deprecated `.cursorrules` discovery. | Current Cursor plugins, subagents, and instruction compatibility paths are now inventoried. Plugins and subagents remain discovery-only. |
| OUTDATED | macOS support claim before this change | The generic non-Windows fallback labeled Cursor supported even though no macOS validation record existed. | macOS is now `preview`, still selectable, with the missing certification stated explicitly. |
| UNCERTIFIED | DefenseClaw macOS validation | `validated_versions.json` has empty macOS `last_validated_version`, `last_validated_at`, and `run_url`. No authenticated live Cursor invocation was completed from a packaged DefenseClaw build on this PR head. | These fields remain empty. Downloading the latest CLI and running `--version`/`--help` does not populate them. |

Primary sources:

- Cursor downloads: <https://cursor.com/download>
- Cursor Agent CLI installation: <https://cursor.com/docs/cli/installation>
- Cursor hooks: <https://cursor.com/docs/hooks>
- Cursor rules and instructions: <https://cursor.com/docs/context/rules>
- Cursor skills and compatibility locations: <https://cursor.com/docs/skills#where-skills-live>
- Cursor subagents and compatibility locations: <https://cursor.com/docs/subagents#file-locations>
- Cursor nested AGENTS.md support: <https://cursor.com/docs/rules#nested-agentsmd-support>
- Cursor custom commands: <https://docs.cursor.com/en/agent/chat/commands>
- Cursor plugins: <https://cursor.com/docs/plugins>
- Cursor 2.4 (skills and custom subagents): <https://cursor.com/changelog/2-4>
- Cursor 2.5 (plugins): <https://cursor.com/changelog/2-5>

## Twelve acceptance surfaces

| Surface | macOS evidence and resulting behavior |
| --- | --- |
| 1. Registry, discovery, version, platform | Cursor remains registered and selectable. Agent CLI discovery probes PATH `agent` then `cursor-agent`; the official user-writable `~/.local/bin/{agent,cursor-agent}` locations are considered only when explicit trusted-binary enforcement is enabled. Desktop application presence/version is read separately from `/Applications/Cursor.app` or `~/Applications/Cursor.app` `Info.plist` metadata and is never executed as the Agent CLI. Agent and Desktop evidence cannot select each other's hook contract. macOS is preview. |
| 2. CLI, help, aliases | The dedicated `defenseclaw setup cursor` alias and shared guardrail options remain intact. Official Agent CLI help confirmed `agent` as the current primary command and `cursor-agent` as installer compatibility. |
| 3. TUI, setup, status, repair | The shared connector roster, setup wizard, status surfaces, and repair path continue to include preview connectors. Operators receive the macOS preview reason rather than a certified-support claim. |
| 4. Full Setup lifecycle and exact restoration | Setup uses user-scoped `~/.cursor/hooks.json`, managed backups, atomic patching, and the v8 shell adapter. Teardown restores the exact backup when unchanged; after external edits it removes only DefenseClaw-owned entries and managed assets. Project `.cursor/hooks.json`, cloud/team, enterprise/MDM, and plugin-provided hooks are outside the v1 managed Setup scope and are not modified. |
| 5. Hook contract | Schema 1, all 21 official events, 30-second command timeout, fail-open default, explicit fail-closed option, blocking and ask semantics, and fire-and-forget lifecycle behavior remain pinned in JSON and Go mirrors. `subagentStart` is blockable; its allow/deny-only response means a confirm verdict is conservatively downgraded to deny. |
| 6. Native process and provenance | Cursor spawns the managed shell adapter directly on macOS. Doctor requires a regular, non-symlink, current-user-owned, executable, non-group/world-writable v8 adapter; full transport markers; and an exact Setup-recorded SHA-256 digest. Passive binary discovery can require trusted paths; user-writable official Agent locations are not silently elevated to trusted provenance. |
| 7. Gateway, auth, lifecycle | The adapter calls the loopback hook endpoint with the connector-scoped sidecar token. Existing gateway identity, listener, token-drift, start/restart, and teardown behavior is shared with other native hook connectors. There is no Cursor proxy path. |
| 8. Doctor, tamper, repair | Doctor validates schema, exact event coverage, one consistent command, timeouts, runtime existence, fail mode, structural transport markers, filesystem provenance, and the Setup-recorded runtime digest. With the gateway live it executes the exact configured adapter and requires both valid allow JSON and an advancing Cursor request counter. Drift directs operators to rerun Setup. |
| 9. Native OTEL, audit, correlation | Cursor has no documented native OTLP exporter, so `NativeOTLP=false` remains correct. DefenseClaw hook processing emits its own logs, metrics, traces, audit records, and session/turn/tool correlation. |
| 10. MCP, skills, rules, instructions, agents, plugins, extensions | MCP: user/workspace supported. Skills inventory covers `.cursor/skills`, `.agents/skills`, `.claude/skills`, and `.codex/skills`; Setup writes only the explicit `.cursor/skills` target. Rules/instructions inventory covers workspace-root `.cursor/rules`, `AGENTS.md`, `CLAUDE.md`, and deprecated `.cursorrules`; nested `AGENTS.md` is officially supported by Cursor but recursive traversal is an explicit DefenseClaw v1 limit. Subagent inventory covers `.cursor/agents`, `.claude/agents`, and `.codex/agents` at user/workspace scope and is discovery-only. Cursor has no separate documented microagents category. Local plugins are discovery-only; marketplace/team and plugin-provided components are not expanded. Custom `.cursor/commands` have no DefenseClaw v1 category. Editor extensions are N/A because they are a separate VS Code-compatible surface and are not managed. |
| 11. Docs, matrix, limits | Connector docs and the capability matrix state macOS preview, Desktop/Agent version separation, discovery-only surfaces, no proxy, no native OTLP, and the certification limit. |
| 12. Deterministic, packaged, live, manual evidence | Deterministic Go/Python lifecycle and contract tests plus macOS Layer A workflow coverage exist. The manual live workflow includes Cursor on macOS and validates hook firing before the authenticated driver run. Packaged and authenticated official-client evidence is still blocked on a durable green run with Cursor credentials, so no validation version is recorded. |

## Remaining certification blocker

Run the manual macOS Cursor cell from a packaged DefenseClaw artifact with a
valid `CURSOR_API_KEY`, retain its artifacts and run URL, and verify a real
Agent CLI turn fires the installed hook contract through the authenticated
gateway. Only that durable green evidence can populate the macOS validation
record.
