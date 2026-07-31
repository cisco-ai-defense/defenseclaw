# Native macOS Antigravity Acceptance

Status date: 2026-07-31
Scope: Google Antigravity CLI (`agy`) on native macOS only. Gemini CLI,
proxy connectors, and other connector implementations are out of scope.

## Release and certification status

| Classification | Result |
| --- | --- |
| **OUTDATED** | The previous macOS platform claim said `supported` even though no macOS `last_validated_version` record existed. POSIX Doctor checked only for a script-name substring, passive discovery could execute an arbitrary `agy` found first on `PATH`, the `agy` product alias was not normalized, and extension discovery omitted documented rules and standalone agents. |
| **CURRENT** | Google's official stable channel identifies Antigravity CLI `1.1.9`, released 2026-07-31. DefenseClaw recognizes macOS versions `>=1.1.8, <1.1.10` after reviewing the official 1.1.9 arm64 and x64 artifacts. The five-event `antigravity-hooks-v2` contract, global hook path, native macOS installer location, MCP schema, skills, plugins, rules, agents, and authentication boundary remain compatible. |
| **UNCERTIFIED** | macOS remains `preview`. `validated_versions.json` intentionally has an empty macOS `last_validated_version`, timestamp, and run URL. The persistent authenticated macOS connector-lab workflow is a source-build regression harness, not current-head packaged certification evidence, so no certification stamp was added. |

Primary sources:

- [Official macOS arm64 installer manifest](https://antigravity-cli-auto-updater-974169037036.us-central1.run.app/manifests/darwin_arm64.json)
- [Installation and authentication](https://antigravity.google/docs/cli/install)
- [CLI 1.1.9 release](https://github.com/google-antigravity/antigravity-cli/releases/tag/1.1.9)
- [Changelog](https://antigravity.google/changelog)
- [Hooks](https://antigravity.google/docs/hooks)
- [MCP](https://antigravity.google/docs/mcp)
- [Skills](https://antigravity.google/docs/skills)
- [Plugins](https://antigravity.google/docs/plugins)
- [CLI plugins and skills](https://antigravity.google/docs/cli/plugins)
- [CLI custom agents](https://antigravity.google/docs/cli/commands/agents)
- [Gemini CLI migration](https://antigravity.google/docs/cli/gcli-migration)

## CLI 1.1.9 artifact review

| Evidence | Result |
| --- | --- |
| Official GitHub macOS arm64 asset | SHA-256 `bbc42c75f6e603fd35a70f353f2963e74bb4ea261f89e4256f5f60a78f95bb84`; `agy --version` reports `1.1.9`. |
| Official GitHub macOS x64 asset | SHA-256 `8daa903f5135072b3921dbac90f449cb8a778102b03853e8691146665cad06bd`. |
| Stable updater manifests | Both Darwin architectures resolve to `1.1.9`; their published SHA-512 values are `4bb5c759cec7e5aa7738f9d5259bb29bc8899fb616a0979be5b192ddade9f143d493ede30dcc1475298ef4060c013bf75a992adc041be8955762b2c5a3061f1b` (arm64) and `2e61abdf7d627e6ad24bfefeed8bb35a00a538adc00398106270e635015f78969327f776791053d2cb6b92912824912fa2eaf65ac9224fafcd3d0aad7ebd8e8d` (x64). |
| Native provenance | Both 1.1.9 archives contain one regular Mach-O executable named `antigravity`; both binaries use hardened runtime and carry Google team identifier `EQHXZ8M8AV`, matching reviewed 1.1.8 provenance. |
| Contract comparison | The five events, every documented payload/response field, and hooks/MCP/skills/plugins/rules/agents paths are present in both 1.1.9 architectures and match 1.1.8. The only help-surface addition is `--disable-slash-commands` for print-mode skill expansion. |
| Hook behavior changes | The release bounds repeated `Stop` continuations and corrects `PostToolUse` so it fires only for tool steps and honors matchers. These are compatible fixes; no event, registration shape, payload, response, or enforcement claim changes. |
| MCP, skills, and permissions | Interactive MCP startup now loads servers in the background, while headless and one-shot runs still wait for their toolset. Print mode now expands slash commands and skills. Conversation-scoped permission persistence and the broader system temp-directory grant remain vendor runtime behavior. None changes DefenseClaw's MCP schema, inventory paths, custody, telemetry, or policy boundary. |
| Support decision | Raise the reviewed macOS/non-Windows ceiling from `<1.1.9` to `<1.1.10`. Keep macOS `preview`, leave certification fields blank, and keep the Windows open ceiling and certification state unchanged. |

## Twelve-surface review

| # | Acceptance surface | macOS result |
| --- | --- | --- |
| 1 | Registry, discovery, version, platform | Implemented. `agy --version`; official `~/.local/bin/agy`; mandatory trusted-path admission before a passive Antigravity probe; reviewed macOS gate `>=1.1.8, <1.1.10`; macOS is available as `preview`, not certified. |
| 2 | CLI, help, aliases | Implemented. `setup antigravity` remains canonical and `setup agy`/`init --connector agy` normalize to Antigravity, never Gemini CLI. |
| 3 | TUI, setup, status, repair | Implemented. Antigravity remains visible with a preview marker. Setup/status use the Antigravity connector identity. Doctor reports exact contract drift and points to scoped setup repair. |
| 4 | Narrow Setup custody and restoration | Implemented. Setup writes only five `defenseclaw-antigravity-*` keys in global `~/.gemini/config/hooks.json`. Exact pre-Setup bytes and mode are restored if unchanged; after operator drift, only DefenseClaw-owned keys are removed. `ANTIGRAVITY_CONFIG_DIR` is a DefenseClaw-internal, validated lifecycle binding for the selected profile, not a claimed upstream Antigravity override; Setup rejects unsafe path ancestry, overrides ambient state for the child operation, and restores it afterward. |
| 5 | Hook contract | Current through 1.1.9. Exactly `PreInvocation`, `PreToolUse`, `PostToolUse`, `PostInvocation`, and `Stop`; direct lists for invocation/stop and matcher groups for tool events. Only `PreToolUse` claims deny/ask. Version 1.1.9 fixes `PostToolUse` matcher application and bounds repeated `Stop` continuations without widening DefenseClaw's enforcement claims. |
| 6 | Native process and provenance | Implemented. Native `agy` invokes the managed POSIX hook script synchronously. Passive discovery executes version probes only from trusted prefixes. No Gemini CLI or proxy executable is substituted. |
| 7 | Gateway, auth, lifecycle | Implemented. Connector-scoped token, Antigravity route, setup/teardown, loopback gateway, event-bound trusted header, and event-specific fail-open outputs are distinct from Gemini CLI. |
| 8 | Doctor, tamper, repair | Implemented. macOS Doctor passively validates all keys, shapes, timeouts, runtime path, and event bindings without executing config text; duplicate workspace registration is warned. |
| 9 | OTEL, audit, correlation | Implemented with limits. Telemetry is hook-derived logs/metrics/traces with connector identity and W3C context; Antigravity has no documented native OTLP exporter. Correlation uses `conversationId`, event-specific step/invocation fields, and never relabels `stepIdx` as a turn. |
| 10 | MCP, skills, plugins, rules, instructions, agents, assets | Implemented to documented boundaries. MCP and AgentSkills folder form are read/write; direct-markdown CLI skills are discovery-only; plugins install to the CLI staging root while shared/manual roots remain scanned; rules/instructions, standalone `agent.md` definitions, and plugin agents are discovery-only. Skill scripts/resources/assets are carried inside the skill directory. Runtime subagent processes are not managed. |
| 11 | Docs, matrix, limits | Updated. macOS preview and uncertified state, current release, five-event limits, shared-home custody, native-OTLP absence, and explicit N/A categories are recorded. |
| 12 | Deterministic, packaged, live, manual evidence | Deterministic contract/custody tests and a packaged contract matrix exist. The persistent macOS upgrade harness verifies official manifest SHA-512 artifacts while reusing Keychain auth and restoring exact config state, but it builds `main` source and does not retain the complete immutable package/manifest/custody record required for certification. Latest-version authenticated packaged evidence remains pending. |

## Explicit N/A categories

- Native model-traffic proxy, TLS interception, firewall ownership, and
  DefenseClaw-managed network sandbox: **N/A** (hook-only connector).
- Native Antigravity OTLP exporter: **N/A** (not documented).
- Gemini CLI settings, hooks, telemetry, credentials, process lifecycle, and
  migration ownership: **N/A** (separate connector despite shared
  `~/.gemini` ancestry).
- Workspace/plugin hook writes: **N/A** for DefenseClaw Setup; these are
  discovery-only to prevent duplicate hook execution.
- Standalone custom-agent writes: **N/A** for DefenseClaw management. Google
  documents global and workspace `agent.md` paths, which DefenseClaw discovers;
  Antigravity owns activation and runtime subagent/microagent processes.
- Workflow writes: **N/A** until Google documents a stable workflow file path.

## Evidence required to certify

Promoting macOS from preview requires one durable run from a reviewed,
immutable candidate corresponding to the current PR head
using the official latest stable macOS binary and a genuine authenticated
Keychain session. The evidence must retain the resolved version and manifest
digest, packaged DefenseClaw identity, all live probe results, setup config
hashes, audit/correlation artifacts, exact restoration proof, and immutable run
URL. A maintainer may then review that evidence and update
`last_validated_version`; the workflow must not update it automatically.
The existing main-branch source-build connector radar does not meet this bar.
