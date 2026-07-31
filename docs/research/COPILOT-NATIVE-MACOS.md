# GitHub Copilot CLI native macOS connector evidence

Status: **not certified**. Static and deterministic coverage targets Copilot
CLI 1.0.77. No authenticated latest-version macOS run was available, so
`validated_versions.json` remains unchanged.

## Outdatedness decision

Primary-source recheck on 2026-07-30:

| Item | Decision | Comparison with latest official macOS release |
|---|---:|---|
| Upstream macOS release | CURRENT | GitHub's latest release is 1.0.77, with official arm64 and x64 Darwin artifacts. |
| DefenseClaw version bounds | CURRENT | On Windows/macOS/Linux, v1 is `[1.0.18, 1.0.76)` and v2 is `[1.0.76, unbounded)`, so latest resolves to v2 without claiming validation. |
| macOS `last_validated_version` | UNCERTIFIED | Empty by design because no authenticated green 1.0.77 macOS live run exists. |
| Hook inventory | CURRENT | v2 contains all 14 currently documented events, including `userPromptTransformed`. |
| Discovery paths/probe | CURRENT | `copilot version`; `$COPILOT_HOME/settings.json`, legacy `config.json`, MCP and hooks; current repository settings, hook, MCP, and cross-tool settings paths. |
| Capability/native OTel | CURRENT / LIMITED | Upstream documents traces and metrics; native logs are not documented. macOS models the exporter as `native_otlp=true`, but DefenseClaw does not auto-configure or certify it; Windows remains false. Cleartext HTTP gateway wiring remains blocked. |

`CURRENT` means aligned with the latest official surface, not certified
support. Only a reviewed green live cell may change `UNCERTIFIED`.

Classifications: **I** implemented, **L** limited, **N/A** not applicable,
**B** blocked.

| Acceptance surface | Class | Evidence and resulting behavior |
|---|---:|---|
| Registry, discovery, version, platform | I | `copilot version` resolves 1.0.77. Trusted discovery canonicalizes the executable, rejects unsafe ownership/modes and symlink escape, rejects quarantine, and requires GitHub team `VEKTX9H2N7` for native Mach-O artifacts. |
| CLI, help, aliases | I | Official `version`, `plugin`, `skill`, `mcp`, and `help monitoring` surfaces were probed. The binary rejects the documented-looking `plugin list --json`; inventory therefore uses passive installed-plugin discovery. |
| TUI, setup, status, repair | I | Existing connector registry/setup/status flows remain shared. Setup chooses the versioned hook contract and managed-file lifecycle; Doctor consumes the pinned lock. |
| Setup lifecycle and restoration | I | Setup captures the original hook file, atomically patches owned entries, restores the exact original when unchanged, preserves foreign edits, and leaves a disabled tombstone for cached hook invocations. |
| Hook contract and responses | I | Current contract registers all 14 official events. `userPromptTransformed` is observe-only and returns `{}`; DefenseClaw never writes `modifiedTransformedPrompt`. Event-specific deny/ask/stop/context responses remain explicit. |
| Native process and provenance | I | Official arm64 artifact digest, Mach-O format, strict code signature, Developer ID team, hardened runtime, mode, and quarantine state are recorded in the durable evidence JSON. |
| Gateway, auth, lifecycle | L | Command hooks use the existing scoped hook credential and loopback gateway lifecycle. Copilot login tokens remain in GitHub's supported environment variables or macOS Keychain and are never copied into DefenseClaw state. |
| Doctor, tamper, repair | I/L | Doctor validates the pinned v1/v2 contract, exact event set, one owned handler per event, command-field isolation, timeout, registration symlink state, and executable target mode/type. Native Mach-O provenance is checked before passive execution. Authenticated runtime repair remains a live-test requirement. |
| Official native OTel, audit, correlation | L/B | Upstream traces and metrics document conversation, turn, interaction, and tool-call IDs. Native logs are N/A. macOS records the upstream exporter capability as `native_otlp=true`, but DefenseClaw does not auto-configure or certify it; Windows remains false. Copilot 1.0.76 disables cleartext `http://` OTLP export, so the current HTTP loopback gateway is not auto-wired. Hook audit remains implemented. |
| Extensions: MCP, skills, plugins, instructions, agents, hooks | I/L | MCP, skills, personal extensions, agents, instructions, hooks, and the two-level installed-plugin layout have documented user/workspace paths and honor `COPILOT_HOME`. macOS MDM settings and policy-hook paths are discovery-only. Plugin-provided extensions and LSP are inventoried through plugin provenance; DefenseClaw mutation of plugin state is intentionally not implemented. Separate “rules” and microagents are N/A beyond instruction and custom-agent files. |
| Docs, matrices, limits | I | Connector docs and this acceptance map state current event count, native signal limits, transport block, and certification state. |
| Deterministic, packaged, live, manual evidence | I/B | Contract/unit tests, the durable static probe, and `scripts/live-connector-e2e/verify-copilot-macos-release.sh` are packaged. The live driver consumes the requested-version input. An authenticated latest-version macOS lifecycle run is blocked by unavailable credentials; certification is not stamped. |

Official sources:

- [Install GitHub Copilot CLI](https://docs.github.com/en/copilot/how-tos/copilot-cli/set-up-copilot-cli/install-copilot-cli)
- [Copilot CLI hooks reference](https://docs.github.com/en/copilot/reference/hooks-reference)
- [Copilot CLI command reference and monitoring](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-command-reference)
- [Copilot CLI configuration directories](https://docs.github.com/en/enterprise-cloud@latest/copilot/reference/copilot-cli-reference/cli-config-dir-reference)
- [Copilot CLI plugin reference](https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-plugin-reference)
- [Copilot CLI 1.0.77 release](https://github.com/github/copilot-cli/releases/tag/v1.0.77)
