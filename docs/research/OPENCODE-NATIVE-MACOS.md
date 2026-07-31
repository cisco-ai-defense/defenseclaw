# OpenCode native macOS boundary

Reviewed 2026-07-30 against the official OpenCode `v1.18.10` tag and the
`@opencode-ai/plugin` `1.18.10` type package.

Primary sources:

- [OpenCode v1.18.10 release](https://github.com/anomalyco/opencode/releases/tag/v1.18.10)
- [Compatible-floor v1.16.2 plugin contract](https://github.com/anomalyco/opencode/blob/v1.16.2/packages/plugin/src/index.ts)
- [Official plugin documentation](https://opencode.ai/docs/plugins/)
- [Plugin type contract at v1.18.10](https://github.com/anomalyco/opencode/blob/v1.18.10/packages/plugin/src/index.ts)
- [Runtime plugin dispatcher at v1.18.10](https://github.com/anomalyco/opencode/blob/v1.18.10/packages/opencode/src/plugin/index.ts)
- [Configuration loader at v1.18.10](https://github.com/anomalyco/opencode/blob/v1.18.10/packages/opencode/src/config/config.ts)
- [Experimental native OTLP implementation at v1.18.10](https://github.com/anomalyco/opencode/blob/v1.18.10/packages/opencode/src/observability/otlp.ts)

The release publishes native `opencode-darwin-arm64.zip` and
`opencode-darwin-x64.zip` assets. Local plugins are loaded from the documented
global and project plugin directories. The runtime also accepts singular
`plugin`, `agent`, `tool`, and `command` directory aliases, while the public
documentation primarily shows the plural forms. `tool.execute.before` is
awaited, so a thrown error is the enforcement boundary. `tool.execute.after`
receives tool arguments on the input and `{title, output, metadata}` on the
output. Generic `event` delivery is fire-and-forget in the tagged runtime and
is observe-only. The type package declares `permission.ask`, but the tagged
runtime does not dispatch it; `permission.asked` and `permission.replied` are
bus events and cannot implement a native DefenseClaw ask verdict.

## Status

| Classification | Result |
| --- | --- |
| OUTDATED | Earlier records omitted generic event variants and application/config/command/agent/plugin discovery paths, treated config `tools` permissions as tool declarations, and said OpenCode had no native OTLP implementation. |
| CURRENT | The macOS/Linux registry accepts `>=1.16.2, <1.18.11` and installs the 35-event v7 bridge. Version 1.18.10 is the latest source-reviewed candidate. Windows deliberately preserves the unbounded/default nine-event v6 bridge. The bridge uses the official awaited pre-tool throw contract, exact connector bearer authentication, fail-closed transport behavior, official post-tool arguments/results, observe-only post/event telemetry, managed backup, tamper repair, restart guidance, and hash-gated exact restore. |
| UNCERTIFIED | No durable green latest-version macOS run is retained. `last_validated_version`, timestamp, and run URL therefore remain empty. |

## Acceptance-surface disposition

| Surface | Disposition |
| --- | --- |
| Registry, discovery, version, platform | macOS/Linux `>=1.16.2, <1.18.11`, v7 and 35 events; 1.18.10 source-reviewed; Windows remains unbounded/default on v6 with nine events; Darwin assets confirmed; explicit empty macOS certification record |
| CLI, help, aliases | Existing `setup opencode` alias retained; source review does not create a certification pin |
| TUI, setup, status, repair | Existing generic connector flows retained; macOS target generation now includes OpenCode |
| Setup lifecycle and custody | Whole-file `defenseclaw.js`, owner-only credentials, exclusive guardian custody, digest verification, idempotent upgrade/repair, rollback on failed Setup, and hash-gated exact restore on teardown/uninstall/purge; drift is preserved |
| Plugin and policy contract | v7 recognizes 35 reviewed events; awaited `tool.execute.before` is the only blocking lane; after/event delivery is observe-only; `permission.ask` not claimed |
| Native process and provenance | Official native Darwin release; root installer reads package metadata and never executes a user binary |
| Gateway, auth, lifecycle | Connector-specific route accepts only the scoped bridge bearer (not loopback bypass or master key), with explicit fail mode and session/tool correlation |
| Doctor, tamper, repair, restart | Plugin marker is directly verified; missing/drifted bridge is repairable; restart remains required because OpenCode loads plugins at startup |
| OTEL, audit, correlation | DefenseClaw-certified telemetry is hook-derived logs/metrics/traces with IDs and no traceparent. Upstream 1.18.10 has experimental native OTLP logs/traces, but this connector neither configures nor takes custody of that feature, and it has no native metrics claim. |
| MCP, skills, rules/instructions, plugins, agents | MCP config and skills are governed. Upward project/global JSON/JSONC, `instructions`, `AGENTS.md`/`CLAUDE.md`, direct JS/TS plugins, plugin packages, singular/plural tool/command/agent roots, and config `agent` maps are discovery-only. OpenCode `tools` config is permission policy, not a tool declaration. |
| Assets | N/A: OpenCode documents no independent asset category beyond the listed config/plugin/skill/tool/command/agent surfaces |
| Evidence | Go connector/guardian, Python inventory, macOS packaging, and imported-plugin bridge tests are deterministic; packaged/live/manual latest-version macOS evidence is still pending |

Direct chat/provider interception is N/A. `shell.env`, message transforms,
tool-definition mutation, and typed `permission.ask` are not dispatched or
used as DefenseClaw enforcement boundaries at the reviewed tag. The connector
does not claim an asset category independent of config, rules/instructions,
skills, plugins, MCP, tools/commands, or agents/microagents.
