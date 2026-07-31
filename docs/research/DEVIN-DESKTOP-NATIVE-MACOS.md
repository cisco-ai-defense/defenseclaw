# Devin Desktop (Windsurf) native macOS research gate

Checked 2026-07-30 against primary vendor sources. DefenseClaw keeps the
stable registry ID `windsurf`; user-facing text uses **Devin Desktop
(Windsurf)** where the legacy path or ID still matters.

## Source and release result

| Status | Result |
| --- | --- |
| **OUTDATED** | The old product-only name “Windsurf”; treating MCP and rules as discovery-only; claiming no Cascade skills surface; probing the GUI with `--version`; describing macOS as certified merely because generic Unix setup works. |
| **CURRENT** | Latest stable **Devin Desktop 3.6.22**, released **2026-07-29**. The download page states Devin Desktop is the new name for Windsurf and preserves IDE settings. Cascade retains `~/.codeium/windsurf/hooks.json` and the same 12 documented hook events. DefenseClaw's open-ended `>=1.12.41` contract therefore resolves 3.6.22 without changing the stable ID. |
| **UNCERTIFIED** | macOS remains preview. No Devin Desktop app is installed on this worker, and there is no durable packaged, signed-in, interactive 3.6.22 run proving visible allow/block behavior, repair, upgrade, exact uninstall restoration, and persisted evidence. `last_validated_version` remains empty. |

Primary sources:

- [Devin Desktop changelog](https://docs.devin.ai/desktop/changelog) — 3.6.22
  on 2026-07-29; 3.6.21 documents Restricted Mode disabling hooks.
- [Devin download](https://devin.ai/download) — native Apple Silicon and Intel
  downloads; Devin Desktop is the new name for Windsurf.
- [Cascade hooks](https://docs.devin.ai/desktop/cascade/hooks) — macOS/user/
  workspace paths, JSON stdin, `command` via `bash -c`, twelve events, exit 2,
  async response hooks, and Restricted Mode limitation.
- [Cascade MCP](https://docs.devin.ai/desktop/cascade/mcp) — documented
  `~/.codeium/windsurf/mcp_config.json`.
- [Cascade skills](https://docs.devin.ai/desktop/cascade/skills) — workspace,
  global, cross-agent, and macOS enterprise skill roots.
- [Memories and rules](https://docs.devin.ai/desktop/cascade/memories) —
  `.devin/rules`, legacy `.windsurf/rules`, global rules, and memories.
- [AGENTS.md](https://docs.devin.ai/desktop/cascade/agents-md) — recursive
  directory-scoped instruction discovery.
- [Workflows](https://docs.devin.ai/desktop/cascade/workflows) — workspace,
  global, built-in, and macOS enterprise workflow paths.

## Twelve acceptance surfaces

| # | Surface | macOS result |
| --- | --- | --- |
| 1 | Registry/discovery/version/platform | **Implemented/preview.** ID stays `windsurf`; canonical `/Applications/Devin.app` and legacy `/Applications/Windsurf.app` bundle metadata are read without launching the GUI. Version floor remains `1.12.41`; 3.6.22 is compatible, not certified. |
| 2 | CLI/help/aliases | **Implemented.** `setup windsurf` remains stable; presentation names Devin Desktop (Windsurf). |
| 3 | TUI/setup/status/repair | **Implemented.** Preview reason is shared by Go/Python; existing status and Doctor paths consume the same connector lock and capability data. |
| 4 | macOS Setup lifecycle/exact restoration | **Partial.** Unit coverage proves merge, repair, teardown, and byte-exact restoration; a genuine signed-in 3.6.22 upgrade/rollback/uninstall/Restricted Mode matrix is blocked. |
| 5 | Hook contract | **Current.** Exactly 12 events. Five pre-hooks may block only with exit 2; other nonzero exits open; post hooks cannot block; response hooks are async; Restricted Mode disables hooks. |
| 6 | Native process/provenance | **Implemented/limited.** Passive discovery executes neither the GUI nor PATH aliases. It requires bundle ID `com.exafunction.windsurf`, Team ID `83Z2LHX6XW`, a valid code signature, and Gatekeeper acceptance. This is installed-artifact provenance, not live certification. |
| 7 | Gateway/auth/lifecycle | **Implemented.** Connector-scoped token stays outside vendor JSON; on macOS the Windsurf route rejects missing, invalid, cross-scope, and master credentials once its scoped token exists. Rotation/revocation, teardown, and hook tombstone behavior remain shared with the audited hook runtime. |
| 8 | Doctor/tamper/repair | **Partial.** Deterministic tests cover config, marker/digest, token, contract lock, repair, and restoration; genuine GUI auto-reload, upgrade, rollback, and Restricted Mode remain blocked. |
| 9 | OTEL/audit/correlation | **Implemented/limited.** Hook-derived v8 telemetry maps `trajectory_id` to session and `execution_id` to turn with W3C propagation. **N/A:** Cascade has no documented native OTLP exporter. Async attribution remains best effort. |
| 10 | MCP/skills/rules/instructions/plugins/agents/assets | **Partial with explicit boundaries.** MCP, workspace/user skills, root-level rules/instructions, and macOS enterprise read roots are covered. Nested/git-parent traversal, workflows, and the broader memories directory are documented but not inventoried. **N/A:** Devin Local plugins and custom subagents are separate from Cascade. |
| 11 | Docs/matrix/limits | **Updated.** Rename, stable ID, paths, five blocking events, failure semantics, async hooks, Restricted Mode, no proxy/sandbox/egress, and empty certification are explicit. |
| 12 | Deterministic/packaged/live/manual evidence | **Partial/blocked.** Contract smoke and focused tests exist, but no Windsurf lifecycle driver, signed-in app run, hosted macOS workflow, or durable 3.6.22 manual record exists. |

## Release gate

Do not populate `last_validated_version` until a durable run records the genuine
stable app version, application identity, packaged DefenseClaw artifact,
fresh/upgrade/repair/uninstall lifecycle, all five visible blocking gates,
non-blocking post behavior, Restricted Mode behavior, audit/correlation rows,
and exact pre-install restoration.
