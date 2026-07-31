# Native macOS Claude Code connector acceptance

Last audit: **2026-07-30**

Scope: Claude Code on native macOS 13 or later, on Apple Silicon (`arm64`) or
Intel (`x86_64`). This ledger uses the same twelve surfaces and cell vocabulary
as `NATIVE-WINDOWS-CONNECTOR-ACCEPTANCE.md`.

- **I — Implemented:** present in the final tree with deterministic coverage or
  a concrete validation definition.
- **L — Officially limited:** DefenseClaw stops at an upstream host boundary.
- **N/A:** the surface does not apply and is not emulated.
- **B — Blocked:** authentic external evidence is not present in this tree.

## Evidence decision

The current official upstream release observed through the Anthropic GitHub
release feed and native download service is **Claude Code 2.1.220** (published
2026-07-25). Latest upstream and validated support are separate facts.

### Outdatedness decision

| Compared surface | Decision | Evidence and consequence |
| --- | --- | --- |
| Latest official macOS release | **CURRENT — 2.1.220** | Both `releases/latest` and `downloads.claude.ai/claude-code-releases/latest` resolved to 2.1.220 on 2026-07-30. |
| Audit-host executable | **OUTDATED — 2.1.217** | The installed native client is three patch releases behind 2.1.220. It is useful local provenance evidence only. |
| DefenseClaw minimum | **CURRENT — `>=2.1.154`** | The shared registry floor remains 2.1.154. A checksum-verified official 2.1.152 `darwin-arm64` artifact supplied older event-inventory evidence, but does not lower the supported floor. SHA-256 `43cb9361f7bc48c39214d5f125003b8de0ebde5cd6a1173e6b74fcdd10966d46` matches Anthropic's manifest. |
| Shared DefenseClaw maximum | **OUTDATED — open** | The PR #655 cross-platform contract remains open to preserve its Windows behavior, but that mechanical match is not macOS certification after 2.1.219 added `DirectoryAdded`. |
| macOS certification ceiling | **CURRENT — `<2.1.219`** | macOS protected selection and Go provenance reject 2.1.219+ before connector mutation because `DirectoryAdded` has no published hook schema. |
| macOS `last_validated_version` | **UNCERTIFIED — empty** | There is no reviewed green packaged, authenticated, latest-version macOS run. Neither the 2.1.152 artifact inspection nor the local 2.1.217 probe may populate this cell. |
| Event inventory | **OUTDATED / UNCERTIFIED** | The existing 28 owned events remain current against the published hook reference, plus explicit exclusions for `Setup` and `WorktreeCreate`. Upstream 2.1.219 adds `DirectoryAdded`, so the latest full event inventory is incomplete until Anthropic publishes its schema; response and enforcement semantics remain uncertified. |
| Native discovery path | **CURRENT / LIMITED** | Official troubleshooting documents `~/.local/bin/claude` as a symlink into `~/.local/share/claude/versions/`; Setup resolves the launcher and also enumerates canonical version files when `~/.local/bin` is absent from `PATH`. Homebrew is not claimed: commonly group-writable Homebrew ancestry fails the connector's stricter mutation boundary. |
| Capability claims | **CURRENT / LIMITED** | The official table still has fourteen block-capable events, native ask remains only `PreToolUse`, `MessageDisplay` is observational, and completed post-tool effects cannot be undone. Official logs/metrics and beta traces are supported; detailed hook spans require additional flags and upstream allowlisting and are not claimed. |

The prior claim that the open shared version range established current macOS
support was outdated. PR #655's shared Windows behavior remains unchanged,
while the macOS provenance gate ends before 2.1.219. Current/latest Claude Code
remains unsupported on macOS until `DirectoryAdded` has a published contract.
The local executable is also outdated, and latest-version certification is absent.

The macOS host used for this audit has **2.1.217**, installed by Anthropic's
native installer as an `arm64` Mach-O. Its code signature reports:

- identifier `com.anthropic.claude-code`;
- Developer ID `Anthropic PBC (Q6L2SF6YDW)`;
- team identifier `Q6L2SF6YDW`;
- hardened runtime enabled.

That local observation is provenance evidence for the implementation, not a
green latest-version live certification run. The macOS status is therefore
**preview**, and
`cli/defenseclaw/inventory/validated_versions.json` intentionally retains an
empty macOS `last_validated_version`.

Official sources:

- Install, system requirements, update channels:
  https://code.claude.com/docs/en/setup
- Native package/platform troubleshooting:
  https://code.claude.com/docs/en/troubleshoot-install
- Settings, macOS MDM and managed-file precedence:
  https://code.claude.com/docs/en/settings
- Hooks:
  https://code.claude.com/docs/en/hooks
- OpenTelemetry:
  https://code.claude.com/docs/en/monitoring-usage
- MCP:
  https://code.claude.com/docs/en/mcp
- Skills and compatibility commands:
  https://code.claude.com/docs/en/slash-commands
- Plugins:
  https://code.claude.com/docs/en/plugins-reference
- Agents/subagents:
  https://code.claude.com/docs/en/sub-agents
- Instructions and auto memory:
  https://code.claude.com/docs/en/memory
- Release:
  https://github.com/anthropics/claude-code/releases/tag/v2.1.220

## Twelve-surface matrix

| # | Surface | Cell | Final-tree behavior and boundary |
| --- | --- | --- | --- |
| 1 | Registry / discovery / version / platform | **I/B** | Go and Python explicitly classify `claudecode` as macOS preview. The shared floor is `>=2.1.154`, while macOS protected selection rejects `>=2.1.219` pending `DirectoryAdded`; the official native installer layout is discovered through its canonical signed Mach-O. Latest green live evidence is blocked. |
| 2 | CLI / help / aliases | **I** | `setup claude-code`, `claude-code`, `claudecode`, and `claude` normalization retain the existing hook-only setup behavior and options. |
| 3 | TUI / setup / status / repair | **I/B** | macOS pickers label Claude Code preview; Setup records protected executable evidence; status and Doctor use the shared contract lock; the repair command is `defenseclaw setup claude-code --yes --restart`. Hosted interactive repair evidence is blocked. |
| 4 | macOS Setup lifecycle / exact restoration | **I** | `CLAUDE_CONFIG_DIR` or `~/.claude` is resolved once. Setup owns marked hook entries and exact native-OTel keys in `settings.json`, uses hash-checked backup/CAS state, reconciles repeated setup, and teardown restores pristine bytes when identity matches or removes only owned values after drift. Scoped credentials are revoked only after clean verification. |
| 5 | Hook / policy contract | **I/L/B** | The versioned contract owns 28 of the 30 events in the current hook reference through 2.1.218. `Setup` and `WorktreeCreate` are intentional exclusions. Releases from 2.1.219 are rejected as unknown because `DirectoryAdded` has no published schema. Native ask is limited to `PreToolUse`; `TaskCreated`, `TaskCompleted`, and `TeammateIdle` block through exit 2 with feedback, while post-result decisions cannot undo effects. |
| 6 | Native process / provenance | **I/B** | Setup resolves the native-installer symlink, rejects symlink execution authority, unsafe permissions, non-Mach-O images, wrong architecture, active quarantine, invalid signatures, wrong identifier/team/Developer ID, and unstable files. Before mutation, Go rebinds the exact receipt path, raw version, and SHA-256; the resulting contract lock seals the same identity. Latest signed/notarized packaged evidence is blocked; DefenseClaw does not claim Apple notarization from `codesign` alone. |
| 7 | Gateway / auth / lifecycle | **I** | Hook and OTLP paths use connector-scoped credentials, loopback routing, rotation/revocation, startup reconciliation, tombstone-safe teardown, and no LLM proxy. Claude Code continues to talk directly to its configured provider. |
| 8 | Doctor / tamper / repair | **I** | Doctor checks hook shape, managed-policy conflicts, contract/version, config paths, signed Mach-O provenance, canonical path, sealed digest, and the current verified launcher target. Native auto-update drift produces a repair-required failure without executing the registered hook. |
| 9 | Native OTEL / audit / correlation | **I/L/B** | Hooks emit attributed v8 audit events. macOS configures official OTLP logs, metrics, and enhanced-telemetry beta traces through Claude-scoped headers/endpoints; Windows retains logs+metrics and traces disabled. Deterministic probes cover logs and metrics only, so native trace reception remains blocked on live evidence and is kept distinct from hook-derived audit. |
| 10 | Official extension inventory | **L/N/A/B** | See the explicit inventory below. Direct user/project sources are partially inventoried; Claude's runtime plugin/cache graph and several component-provided surfaces are documented blockers rather than claimed implementation. |
| 11 | Docs / matrices / limits | **I** | This ledger and the Claude Code connector page record platform state, paths, trust checks, hook limits, telemetry signals, extension surfaces, and evidence blockers. |
| 12 | Deterministic / packaged / live / manual evidence | **I/B** | Deterministic Python/Go tests cover platform parity, signed-Mach-O admission, protected selection/lock, hook/OTLP contracts, lifecycle restoration, and Doctor drift. The live workflow installs the checksum-verified official native artifact and defines authenticated allow/block, OTLP, teardown, and result artifacts. Latest 2.1.220 correctly stops at the unknown-contract gate; no genuine latest-version packaged + authenticated result is recorded. |

## Official extension-surface inventory

| Surface | Cell | Sources DefenseClaw inventories | Limits |
| --- | --- | --- | --- |
| MCP | **I/L/B** | Top-level user state in `~/.claude.json`; explicitly pinned project `.mcp.json`; hook events retain MCP tool identity. | Project-local registrations nested in Claude's user state and server-managed/cloud connector state are not decoded by this inventory. |
| Skills | **L/B** | Direct `~/.claude/skills/*/SKILL.md` and pinned project `.claude/skills/*/SKILL.md` roots. | Plugin-provided and additional-directory skills are not decoded from Claude's runtime plugin graph. |
| Compatibility commands | **L/B** | The official `.claude/commands/*.md` compatibility surface is documented. | It is not a distinct DefenseClaw inventory category and plugin-provided commands are not decoded. |
| Plugins / marketplaces | **L/B** | Direct filesystem plugin roots can be scanned when supplied. | Claude's installed-plugin/cache/marketplace state and `claude plugin list/details` are not decoded; component skills, commands, agents, hooks, MCP, LSP, monitors, themes, output styles, and workflows are therefore not claimed. |
| Agents / subagents | **L/B** | Direct user and explicitly pinned project agent files are inventoried; hooks correlate `SubagentStart`/`SubagentStop`. | Plugin, additional-directory, CLI-injected, and subagent persistent-memory sources are not decoded. |
| Microagents | **N/A** | None. | Claude Code has no separate official microagent extension category; subagents are covered above. |
| Instructions / rules | **L/B** | `CLAUDE.md`, `.claude/CLAUDE.md`, `CLAUDE.local.md`, `.claude/rules`, managed `/Library/Application Support/ClaudeCode/CLAUDE.md`, and `InstructionsLoaded` are scanner/attribution sources. | They are not separate inventory categories, and scanning does not make instructions authoritative policy. |
| Auto memory | **L/B** | Main-agent project memory below `~/.claude/projects/<project>/memory/` is a read-only inventory surface. | Subagent persistent-memory roots are not inventoried; Claude owns all writes and load limits. |
| Hook handler types | **I/L** | DefenseClaw owns command handlers for its 28-event contract. | Official prompt, agent, HTTP, and `mcp_tool` handler types are host/plugin surfaces and are not rewritten into DefenseClaw command handlers. |
| Model proxy / sandbox / firewall / egress | **N/A** | None. | The connector is hook-only plus OTLP. DefenseClaw does not intercept Claude provider traffic or claim native sandbox/firewall parity. |

## Validation gates

Deterministic:

```text
uv run pytest -q cli/tests/test_platform_support.py cli/tests/test_agent_selection.py
uv run pytest -q cli/tests/test_cmd_setup_codex_claudecode_alias.py
uv run pytest -q cli/tests/test_cmd_doctor_connector.py
go test ./internal/gateway/connector -run 'ClaudeCode|Claude|PlatformSupport|NativeOTLP'
```

Defined hosted gates:

- `.github/workflows/connector-live-e2e.yml` Layer A on `macos-latest` for
  `claudecode`;
- the manual/live macOS cell installing
  `@anthropic-ai/claude-code@latest`, authenticating with an operator secret,
  proving allow/block and OTLP, and uploading the JSONL result;
- packaged Setup/upgrade/uninstall plus manual interactive HITL and
  Gatekeeper/notarization review.

The final two gates remain **B** until artifacts from the current PR head and
the latest official Claude Code version are durably recorded and reviewed.
