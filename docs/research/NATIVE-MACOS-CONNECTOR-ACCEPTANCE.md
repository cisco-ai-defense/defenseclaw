# Native macOS connector integration acceptance

Last integration audit: **2026-07-31**

This is the consolidated acceptance ledger for the native-macOS connector
refresh. It covers Claude Code, Codex CLI, GitHub Copilot CLI, Cursor, Devin
Desktop (the stable `windsurf` connector ID), OpenCode, Hermes, OpenHands,
OmniGent, and Antigravity. Gemini CLI, OpenClaw, ZeptoClaw, Amp, and proxy
connectors are intentionally outside this audit; their existing behavior must
remain unchanged.

This ledger records implementation coverage, official limits, and missing
release evidence. It is not certification evidence. Source review, a local
binary, deterministic tests, skipped jobs, and `continue-on-error` workflows
cannot populate `last_validated_version` or promote a connector.

Cell vocabulary:

- **I — Implemented:** the final tree has the surface and a deterministic check
  or concrete validation definition.
- **L — Officially limited:** the implementation stops at a documented vendor
  or host boundary.
- **N/A:** the vendor has no applicable surface and DefenseClaw does not invent
  one.
- **B — Blocked:** the implementation or validation definition exists, but
  authentic external evidence is unavailable.

## Version and status decision

`CURRENT` means the implemented contract was reconciled to the named current
upstream surface. It does not mean certified.

| Connector | Version decision | macOS platform status | Certification decision |
| --- | --- | --- | --- |
| Claude Code | **LIMITED:** shared floor `>=2.1.154`; macOS protected admission also requires `<2.1.219`, while Windows keeps the open ceiling and latest 2.1.220 adds undocumented `DirectoryAdded` | `preview` | **UNCERTIFIED:** current/latest macOS is unsupported and no packaged, authenticated latest-client run exists |
| Codex CLI | **CURRENT:** v1-v4 gates; latest reviewed 0.146.0 resolves v4 | `preview` | **UNCERTIFIED:** no packaged, authenticated 0.146.0 run |
| Copilot CLI | **CURRENT:** latest 1.0.77; Windows/macOS/Linux v1 `[1.0.18,1.0.76)` and v2 `>=1.0.76` | available, not certified | **UNCERTIFIED:** no authenticated 1.0.77 run |
| Cursor | **CURRENT:** hook floor `>=1.7.0`; desktop and Agent versions remain distinct | `preview` | **UNCERTIFIED:** no durable packaged, signed-in client run |
| Devin Desktop / Windsurf | **CURRENT:** renamed product 3.6.22 remains compatible with `>=1.12.41` | `preview` | **UNCERTIFIED:** no genuine interactive 3.6.22 run |
| OpenCode | **CURRENT:** macOS/Linux `>=1.16.2,<1.18.11`, v7/35 events; Windows unbounded/default, v6/9 events; latest 1.18.10 source-reviewed | available, not certified | **UNCERTIFIED:** no durable latest-version run |
| Hermes | **CURRENT:** 0.19.1 / release tag `v2026.7.30`; macOS/Linux `>=0.19.0,<0.20.0`, Windows `>=0.19.0` unbounded | `preview` | **UNCERTIFIED:** no packaged genuine-client run |
| OpenHands | **CURRENT / LIMITED:** CLI 1.16.0 remains latest and macOS/Linux stays `>=1.12.0`; standalone SDK 1.39.1 preserves the six-event hook and trace-only exporter boundaries; Windows zero-floor override is native-OTLP-off and setup-unsupported | available, not certified | **UNCERTIFIED:** no genuine latest-version run |
| OmniGent | **CURRENT:** 0.7.0 custom-policy API | historical `supported` default | **UNCERTIFIED:** no durable packaged/live record |
| Antigravity | **CURRENT:** macOS `>=1.1.8, <1.1.10`; official 1.1.9 arm64/x64 artifacts reviewed with the unchanged five-event v2 contract | `preview` | **UNCERTIFIED:** no packaged authenticated client record |

All ten macOS entries in
[`validated_versions.json`](../../cli/defenseclaw/inventory/validated_versions.json)
retain empty version, timestamp, and run-URL fields.

## Cross-surface acceptance matrix

The numbered columns are the same twelve surfaces used by the native-Windows
acceptance ledger.

| Connector | 1 Registry/discovery/version/platform | 2 CLI/help/aliases | 3 TUI/setup/status/repair | 4 macOS Setup lifecycle | 5 Hook/policy contract | 6 Native process/provenance |
| --- | --- | --- | --- | --- | --- | --- |
| Claude Code | **I/L/B** — mirrored preview, signed native layouts, `claude --version`, macOS-only `<2.1.219` ceiling; latest 2.1.220 is rejected | **I** — `claude-code` and `claudecode` converge | **I/B** — preview and repair guidance; live repair pending | **I** — fixed home, CAS backup, repeat/upgrade/rollback/uninstall, drift-preserving exact restore | **I/L/B** — 28 owned events through 2.1.218; ask only `PreToolUse`; two lifecycle mutations excluded; 2.1.219+ `DirectoryAdded` schema blocked | **I** — canonical regular Mach-O, protected ancestry, pinned Anthropic signature/team, architecture and quarantine checks |
| Codex CLI | **I/B** — mirrored preview, official npm/standalone layouts, four gates | **I** — `codex` lifecycle parity | **I/B** — preview, contract/effective-policy status, repair; live proof pending | **I** — fixed `CODEX_HOME`, fresh/reconcile/upgrade/rollback/uninstall and exact restore | **I/L** — current 11-event v4 plus historical gates; no native ask | **I** — selected path/version/SHA-256 lock, canonical Mach-O, OpenAI signature/team, owner/ancestry and quarantine checks |
| Copilot CLI | **I** — `copilot version`, canonical trusted Darwin binary, shared v1/v2 version gates | **I** — setup/status/verify/repair/teardown and documented command surfaces | **I/B** — shared flows implemented; authenticated repair evidence pending | **I** — user/workspace hook custody, atomic backup, repair, cached-hook tombstone, exact restore | **I/L** — v2 has 14 events and v1 has 13 on all platforms; ask only pre-tool; transform is observe/mutation-only where v2 applies | **I** — official artifact digest plus Mach-O, Developer ID, hardened-runtime, mode and quarantine evidence |
| Cursor | **I/B** — preview; Desktop bundle plus `agent`/`cursor-agent` discovery and distinct versions | **I** — stable `cursor` alias and lifecycle parity | **I/B** — preview, passive status/Doctor/repair; signed-in live pending | **I** — fixed home/workspace custody, reconcile, rollback, deferred cleanup and exact restore | **I/L** — 21 events; block six gates, ask only shell/MCP, lifecycle limits retained | **I/B** — canonical bundle/Agent discovery and code-signing checks; genuine official-client run pending |
| Devin Desktop / Windsurf | **I/B** — preview; canonical Devin and legacy Windsurf bundle metadata, no GUI execution | **I** — stable `windsurf` ID, current product label | **I/B** — preview and repair; interactive reload/Restricted Mode proof pending | **I** — fixed `.codeium/windsurf` home, foreign-entry preservation, repair and exact restore | **I/L** — 12 exact events; exit 2 blocks five pre-hooks; async post hooks and Restricted Mode limit enforcement | **I/B** — canonical system bundle/plist identity only; signed genuine app unavailable |
| OpenCode | **I/B** — macOS/Linux `>=1.16.2,<1.18.11`, v7/35 events; Windows remains unbounded v6/9; 1.18.10 source-reviewed native Darwin artifacts | **I** — `opencode` alias and lifecycle parity | **I/B** — shared setup/status/repair plus restart requirement; live pending | **I** — whole managed plugin custody, digest repair, upgrade/uninstall and exact restore | **I/L** — awaited `tool.execute.before` throws to block; after/event observe only; no ask | **N/A/I** — in-process JavaScript plugin has no hook subprocess; trusted native executable discovery remains enforced |
| Hermes | **I/B** — mirrored preview, `hermes --version`, `HERMES_HOME`, macOS/Linux `>=0.19.0,<0.20.0`; Windows unbounded above | **I** — lifecycle aliases and forced-open wording | **I/B** — preview, requested/effective fail posture, repair; live pending | **I** — fixed config home, YAML backup, reconcile, deferred cleanup and byte-exact restore | **I/L** — all 23 events; block only pre-tool, context/verify separately bounded, every failure opens | **I** — exact quoted absolute POSIX executable, `shlex.split`/`shell=False`; no shell or PATH fallback |
| OpenHands | **I/B** — official Python 3.12 CLI, macOS/Linux `>=1.12.0`, 1.16.0 source review, global/workspace precedence; Windows setup unsupported | **I** — `openhands` lifecycle parity | **I/B** — supported macOS setup and shadow/tamper repair; live pending | **I** — selected global/workspace file, atomic custody, tombstone, foreign-edit preservation and exact restore | **I/L** — six snake-case events; exit 2/deny blocks three; no ask | **I/L** — trusted Python CLI path/version; no invented native binary signature claim |
| OmniGent | **I/B** — 0.7.0 `uv tool`/Homebrew/writable-environment discovery | **I** — `omnigent` and `omni` discovery with lifecycle parity | **I/B** — policy status/repair and explicit environment limits; live pending | **I** — config/module/`.pth` custody, environment binding, reconcile/rollback/uninstall/exact restore | **I/L** — six awaited policy phases; ASK only three pre-action phases | **N/A/I** — in-process Python policy has no hook subprocess; owning interpreter/environment is validated |
| Antigravity | **I/B** — mirrored preview, `agy` alias, reviewed macOS `>=1.1.8, <1.1.10` gate and native install discovery | **I** — `antigravity`/`agy` lifecycle parity | **I/B** — preview, status/Doctor/repair; authenticated app proof pending | **I** — narrow global hooks-file ownership, reconcile, rollback/uninstall and exact restore | **I/L** — five exact events through 1.1.9; deny/ask only synchronous `PreToolUse`; exit status is not enforcement | **I/L** — direct POSIX command with trusted event binding; no ownership of Gemini CLI state or compatibility shell |

| Connector | 7 Gateway/auth/lifecycle | 8 Doctor/tamper/provenance | 9 Native OTEL vs hook audit/correlation/fail mode | 10 Inventories and MCP writers | 11 Docs/capability matrices | 12 Deterministic/packaged/live/manual evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Claude Code | **I** — connector-scoped hook/OTLP tokens, rotation and teardown | **I/B** — settings, lock, signature, managed-policy and exact-restore checks; hosted tamper run pending | **I/L** — native logs/metrics/traces on macOS plus hook v8; event-specific fail behavior and documented correlation only | **I/L** — settings, MCP, skills, plugins/commands, instructions and agents; vendor-owned state excluded | **I** — connector page, capability data and focused acceptance record | **I/B** — deterministic and workflow definitions exist; packaged authenticated latest-client evidence blocked |
| Codex CLI | **I** — scoped hook/notify/OTLP auth, rotation/revocation | **I/B** — lock/digest/signature/quarantine/effective policy and repair; hosted run pending | **I/L** — official logs/metrics/traces plus hook/notify v8; no native ask or invented provider IDs | **I/L** — config, MCP, skills, rules/instructions and agents where documented | **I** — connector page, matrix and focused acceptance record | **I/B** — deterministic gates exist; packaged authenticated 0.146.0 evidence blocked |
| Copilot CLI | **I/L** — scoped hook auth; GitHub credentials remain Keychain/vendor-env owned | **I/B** — managed-file, binary and contract checks; authenticated repair pending | **I/L/B** — hook audit implemented; upstream traces/metrics are modeled on macOS but not auto-configured or certified; Windows `native_otlp=false`; cleartext HTTP exporter blocked | **I/L** — hooks, MCP, skills, installed plugins, instructions and agents; plugin state read-only, separate rules N/A | **I** — connector page and focused macOS record | **I/B** — static/deterministic evidence exists; entitlement-backed latest live run blocked |
| Cursor | **I** — scoped sidecar token, route/status/rotation/revocation | **I/B** — adapter/config/version/provenance drift and repair; live proof pending | **I/L** — hook-derived v8 and W3C propagation; native OTLP N/A; vendor `failClosed` only where documented | **I/L** — MCP, skills, rules/instructions and agents; workspace overlays only when pinned | **I** — connector page and capability matrix retain limits | **I/B** — deterministic definitions exist; packaged signed-in block visibility pending |
| Devin Desktop / Windsurf | **I** — scoped token remains outside vendor JSON; route and teardown | **I/B** — bundle/config/event/script/lock checks; GUI reload/Restricted Mode pending | **I/L** — hook-derived v8; no native OTLP; async attribution best effort and non-exit-2 failures open | **I/L** — MCP writer; skills, preferred/legacy rules, AGENTS.md, workflows/memories discovery; plugins/subagents N/A | **I** — rename, stable ID, limits and matrix updated | **I/B** — deterministic packaging driver exists; interactive 3.6.22 record blocked |
| OpenCode | **I** — protected plugin token, route, rotation/revocation | **I/B** — plugin digest/version/restart drift and repair; live pending | **I/L** — gateway-derived telemetry and `native_otlp=false`; upstream experimental OTLP is not configured or certified; no traceparent; closed mode authoritative only in awaited before-hook | **I/L** — MCP writer; skills/instructions/plugins/agents discovery; no independent assets; broad plugin mutation excluded | **I** — connector page, matrix and focused record | **I/B** — deterministic and pinned live definitions exist; reviewed latest run blocked |
| Hermes | **I/L** — scoped token/route/teardown; auth and transport failures remain open | **I/B** — YAML, auto-accept, exact argv, ownership, lock/version checks; live pending | **I/L** — hook-derived v8 only, native OTLP N/A; effective fail mode always open | **I/L** — config and canonical MCP writer, local/external skills, read-only plugins; rules/agents/microagents N/A | **I** — connector page, matrix and focused record | **I/B** — deterministic and official-client job definitions exist; durable green run blocked |
| OpenHands | **I** — scoped hook token, global/workspace route and teardown | **I/B** — shadowing, schema/digest/version/auth and repair; genuine run pending | **I/L/B** — macOS/Linux `native_otlp=true` records the trace-only process-env exporter from the stale 1.21.0 review; Setup does not persist it and no stable cross-rail ID is documented; SDK 1.39.1 re-review is pending and Windows keeps native OTLP off | **I/L** — MCP writer, skills, agents/microagents and AGENTS.md discovery; persistent CLI plugins N/A | **I** — current/outdated/uncertified boundaries and matrix updated | **I/B** — deterministic macOS tests/driver exist; genuine 1.16.0 run blocked |
| OmniGent | **I** — scoped awaited policy gateway calls, module lifecycle and revocation | **I/B** — config/module/`.pth`/environment drift and repair; live pending | **I/L** — optional native logs/metrics/traces require launch env; policy-derived v8/W3C; no proxy judge lane | **I/L/N/A** — config/policy/module plus embedded skills/MCP in bounded `~/.omnigent/agents/**/*.yaml` are discovery-only; no guessed standalone plugin/agent roots | **I** — connector page and capability matrix state process/sandbox limits | **I/B** — deterministic and advisory live definitions exist; packaged genuine-client evidence blocked |
| Antigravity | **I** — distinct scoped route/token, rotation/revocation | **I/B** — five-event shape, shared-home narrow ownership, digests/version and repair; live pending | **I/L** — hook-derived v8 only, native OTLP N/A; nonzero exit is not fail-closed | **I/L** — narrow config plus MCP, skills, plugins and rules/instructions; Gemini CLI ownership excluded | **I** — connector page, capability matrix and focused record | **I/B** — deterministic definitions and 1.1.9 artifact review exist; authenticated packaged 1.1.9 record blocked |

## Hook, telemetry, and inventory reconciliation

The machine-readable hook inventory is
[`hook_contracts.json`](../../cli/defenseclaw/inventory/hook_contracts.json);
the Go mirror is
[`hook_contract.go`](../../internal/gateway/connector/hook_contract.go).
Current recognized contracts are: Codex v4 **11** events, Claude Code **28**
owned events, Copilot v2 **14** (v1 retains **13** before 1.0.76), Cursor
**21**, Windsurf **12**, macOS/Linux OpenCode v7 **35** (Windows
preserves v6 **9**), Hermes **23**, OpenHands **6**, OmniGent **6** policy
phases, and Antigravity **5**. Historical and platform-specific version gates
remain separate and are never silently promoted.

Native telemetry is a separate capability from gateway-derived telemetry:

- Codex exports official logs, metrics, and traces.
- Claude Code exports official logs and metrics on supported hosts; enhanced
  beta traces are enabled only on macOS and remain disabled on Windows.
- Copilot documents official traces and metrics. macOS models that
  exporter capability but DefenseClaw does not auto-configure or certify it;
  Windows keeps native OTLP off and cleartext HTTP cannot reach the loopback
  listener.
- The previous OpenHands SDK 1.21.0 review found trace-only native OTLP through
  process environment, and the macOS/Linux registry marks that exporter
  capability true. Setup does not persist the launch environment, Windows
  keeps it false, and no stable cross-rail attribute was documented. SDK
  1.39.1 is newer, so the hook schema and native-OTLP evidence are pending
  re-review; no new events, ceilings, or identifiers are inferred.
- OmniGent can emit native logs, metrics, and traces only when its launch
  environment enables telemetry.
- OpenCode 1.18.10 has experimental native OTLP logs/traces, but DefenseClaw
  neither configures nor certifies that upstream surface.
- Hermes 0.19.1 has optional upstream OTLP for content-free gateway health,
  diagnostics, and cron signals; DefenseClaw does not treat it as policy
  telemetry or take custody of its configuration.
- Cursor, Windsurf, and Antigravity have no documented native OTLP surface.
  Their authenticated hook events still produce connector-attributed
  DefenseClaw audit and downstream telemetry.

Every managed gateway lane uses a connector-scoped credential and route.
Vendor login credentials remain vendor-owned. Teardown rotates or revokes
DefenseClaw credentials only after owned-state verification, and an already
running client receives a safe tombstone rather than a stale executable or
credential.

Inventory paths are explicit and bounded. Writers exist only for documented
MCP/config or installable skill/agent surfaces. Rules, instructions, plugins,
agents, microagents, memories, workflows, and external roots are classified
read/write, discovery-only, or N/A per connector; the implementation does not
traverse arbitrary homes/workspaces or infer one connector's assets from
another.

## CodeGuard and release gate

The integration preserves canonical-path and symlink confinement, rejects
unsafe ownership/modes and traversal, uses structured argv or in-process APIs
instead of shell interpolation, parses only bounded JSON/YAML/TOML with safe
loaders, uses SHA-256 for custody, validates loopback/scoped outbound
destinations, and never copies vendor secrets. Where a connector claims signed
native-binary provenance, macOS admission requires its documented Mach-O,
codesign/team, architecture, ownership, and quarantine evidence;
Python/in-process connectors do not receive invented codesign claims.

Promotion requires a reviewed durable run of the packaged DefenseClaw artifact
and genuine current client. The run must cover fresh setup, repair, upgrade,
rollback, uninstall, deferred cleanup, exact restoration, visible allow/block
and applicable ask behavior, tamper/Doctor results, scoped-auth teardown, and
correlated audit/telemetry. Until then the status and empty macOS validation
stamps above are authoritative.
