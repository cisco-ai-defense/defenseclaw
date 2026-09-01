# OpenCode v1.18.10-v1.18.19 native connector evidence

Reviewed 2026-08-21 against the official OpenCode `v1.18.19` tag, with the
connector's bounded compatibility floor at `v1.18.10`.

Primary sources:

- [OpenCode v1.18.19 release](https://github.com/anomalyco/opencode/releases/tag/v1.18.19)
- [Plugin type contract](https://github.com/anomalyco/opencode/blob/v1.18.19/packages/plugin/src/index.ts)
- [Runtime plugin dispatcher](https://github.com/anomalyco/opencode/blob/v1.18.19/packages/opencode/src/plugin/index.ts)
- [Configuration loader and component discovery](https://github.com/anomalyco/opencode/blob/v1.18.19/packages/opencode/src/config/config.ts)
- [Configuration path resolution](https://github.com/anomalyco/opencode/blob/v1.18.19/packages/opencode/src/config/paths.ts)
- [Instruction resolution](https://github.com/anomalyco/opencode/blob/v1.18.19/packages/opencode/src/session/instruction.ts)
- [Skill discovery](https://github.com/anomalyco/opencode/blob/v1.18.19/packages/opencode/src/skill/index.ts)
- [Tool registry](https://github.com/anomalyco/opencode/blob/v1.18.19/packages/opencode/src/tool/registry.ts)
- [Official plugin documentation](https://opencode.ai/docs/plugins/)

## Reviewed contract

OpenCode loads global and project JS/TS plugins and awaits
`tool.execute.before`; a thrown error is the connector's native block
boundary. `tool.execute.after` is post-execution telemetry only. DefenseClaw
bridge v7 uses that awaited contract and does not insert a model proxy or
claim a resumable native confirmation surface. The validated compatibility
range is `>=1.18.10,<1.18.20`, with `1.18.19` the current pin.

The reviewed source accepts singular and plural component directories:
`agent`/`agents`, `command`/`commands`, `plugin`/`plugins`, `skill`/`skills`,
and `tool`/`tools`. Config also supplies a `plugin` package list, `agent` and
`command` maps, and local `instructions`. Global/project `AGENTS.md` uses a
`CLAUDE.md` fallback. Skills additionally include project and user
`.claude/skills` and `.agents/skills`. The legacy config `tools` object is a
permission map, not a custom-tool declaration.

## DefenseClaw disposition

| Surface | Disposition |
| --- | --- |
| Enforcement | Managed dependency-free `defenseclaw.js`; awaited pre-tool throw; bridge v7 |
| Version | `>=1.18.10,<1.18.20`; current pin `1.18.19` |
| Platforms | Same local discovery contract on native Windows, macOS, and Linux |
| Project scope | Explicit workspace only; upward walk stops at the nearest regular `.git` file or `.git` directory |
| Skills | Native read roots; installs target project `.opencode/skills` or user/custom config `skills` |
| Plugins | Direct JS/TS and config package specs are discovery/policy assets; no third-party install claim |
| Agents, instructions, tools, commands | Bounded, local, no-follow discovery; no remote or enterprise claim |
| Managed bridge | Exact managed global `plugins/defenseclaw.js` remains lifecycle configuration and is excluded from ordinary inventory, scanning, and blocking |
| Enterprise/remote | Typed unverified or excluded; never fetched by offline inventory and never inferred from local results |
| Certification | Source and deterministic test evidence do not fabricate a live-client certification record |

This evidence record does not extend custody to operator-authored OpenCode
configuration or plugins. DefenseClaw owns only its exact managed bridge and
its receipt/repair/teardown state.
