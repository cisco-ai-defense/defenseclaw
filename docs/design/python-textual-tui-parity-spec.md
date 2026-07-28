# Python Textual TUI Full-Parity Development Spec

## Status

Draft for implementation planning.

> [!NOTE]
> This planning snapshot predates the observability-v8 hard cut. References below
> to implicit `gateway.jsonl` reads or a global redaction toggle describe the v7
> baseline being replaced; they are not current runtime requirements. The shipped
> Python TUI reads canonical v8 SQLite event history and effective destination
> policy. JSONL exists only when an explicit destination selects it. See
> [`docs/OBSERVABILITY.md`](../OBSERVABILITY.md) for the current contract.

## Summary

Replace the current Go Bubble Tea TUI with a Python Textual TUI while preserving the operational contract of the existing UI. The goal is not merely a visual refresh. The required outcome is behavior parity, materially better mouse support through widget-level click handling, and a polished futuristic operator-console interface that improves scanability, feedback, and day-to-day UX.

In this document, "full parity" means the Python TUI can replace the Go TUI for all documented operator workflows without losing keyboard workflows, mouse workflows, command routing, audit parity, setup behavior, or test coverage. It does not mean byte-for-byte ANSI output identity. Textual renders through a different layout engine, so visual acceptance is defined by functional layout, stable information hierarchy, theme consistency, polished widget states, and snapshot coverage.

## Current System Inventory

The current TUI lives in `internal/tui/` and is launched by the Go gateway binary. The Python CLI currently hands off to that binary:

- `defenseclaw tui`: `cli/defenseclaw/commands/cmd_tui.py` resolves `defenseclaw-gateway` and execs `defenseclaw-gateway tui`.
- `defenseclaw` with no subcommand on a TTY: `cli/defenseclaw/main.py::_try_launch_tui()` performs the same handoff.
- Direct gateway launch: `defenseclaw-gateway tui`.

Current size and surface:

- 49 production Go files in `internal/tui/`.
- About 30,427 production LOC.
- 62 Go test files.
- About 14,938 TUI test LOC.
- 14 panels/screens in the root model: Overview, Alerts, Skills, MCPs, Plugins, Inventory, Policy, Logs, Audit, Activity, Tools, AI Discovery, Registries, Setup.
- 224 command registry entries in `internal/tui/command.go`.

Important existing contracts:

- Mutations route through the Python CLI whenever possible. The TUI shells out to `defenseclaw ...` or `defenseclaw-gateway ...`, streams output to Activity, and observes resulting audit/config/health changes.
- Read paths are mixed: Python CLI JSON subprocesses, Go audit store reads, gateway HTTP endpoints, and local files such as `doctor_cache.json`, `gateway.jsonl`, `audit.db`, `config.yaml`, `.env`, and registry indexes.
- The Go TUI implements mouse handling through root dispatch and panel-specific coordinate mapping. This is the reliability problem the Textual rewrite must fix.

## Framework Decision

Use Textual, not Rich-only.

Rich stays useful for rendering tables and text fragments, but Rich does not provide a full application model, focus management, screens, modal screens, widget events, or test pilot APIs. Textual provides those primitives and is the correct fit for a multi-panel operator console.

Framework assumptions:

- Add `textual>=8.2,<9.0` to the Python dependencies unless implementation-time testing identifies a blocker. `textual` 8.2.5 was the latest PyPI release observed during this spec pass, uploaded April 30, 2026.
- Continue using `rich>=13.0` already present in the project.
- Use Textual widgets and events as first choice:
  - `DataTable` for list/table panels that need row selection and row click handling.
  - `TabbedContent` or `Tabs` plus `ContentSwitcher` for top-level and sub-panel navigation.
  - `Input`, `Select`, `Switch`, `Checkbox`, `OptionList`, `TextArea`, and `Button` for forms.
  - Textual command palette APIs for fuzzy command discovery.
  - `RichLog` or `Log` for command output and gateway log tailing.
  - `LoadingIndicator` and widget `loading` states for async work.
  - `ModalScreen` for previews, confirmations, action menus, uninstall/reset, redaction/notification toggles, and config diffs.
- Use Textual `Click` / row-selected events for mouse behavior. Raw terminal coordinates are allowed only for narrow escape hatches that cannot be represented as widgets, and each such exception requires a test and a comment explaining why.
- Use Textual `border: round` for primary app chrome and modal surfaces unless a target terminal cannot render Unicode rounded corners cleanly. The fallback must be `solid`, not ASCII, except in explicit low-compatibility mode.

Reference docs used for framework assumptions:

- Textual `DataTable`: https://textual.textualize.io/widgets/data_table/
- Textual `TabbedContent`: https://textual.textualize.io/widgets/tabbed_content/
- Textual `Click` event: https://textual.textualize.io/events/click/
- Textual border styles, including `round`: https://textual.textualize.io/css_types/border/
- Textual `LoadingIndicator`: https://textual.textualize.io/widgets/loading_indicator/
- Textual command palette: https://textual.textualize.io/guide/command_palette/
- Textual testing / `Pilot`: https://textual.textualize.io/guide/testing/
- Textual PyPI: https://pypi.org/project/textual/

## Non-Goals

- Do not rewrite the Go gateway, policy engine, watcher, firewall, audit sinks, or connector runtime.
- Do not change the on-disk config format.
- Do not bypass Python CLI mutation paths for convenience.
- Do not introduce a second, incompatible setup workflow.
- Do not remove `defenseclaw-gateway` as a runtime binary. Only the full-screen TUI moves to Python.
- Do not attempt exact ANSI render parity with Lip Gloss. Textual has different layout and styling semantics.

## Parity Definition

The rewrite is complete only when all gates below pass.

No feature is optional. Incremental delivery may hide unfinished Python panels behind `--backend textual` while development is in progress, but the default launch path cannot flip from Go to Python until every current top-level panel, sub-tab, sub-mode, modal, filter, command action, and documented keyboard/mouse path has a Python equivalent.

Functional parity:

- Every documented panel exists and is reachable through the same stable keyboard shortcuts.
- Every current sub-tab/sub-view inside each panel exists. A panel is not considered ported if only its first/default view works.
- Every current top-level keybinding either works the same way or has a documented compatibility reason.
- Shortcut precedence must match the Go TUI: active modal/form/detail/filter/terminal states consume keys before global shortcuts, panel-owned number keys override global panel switching, and `Ctrl+C` is the only unconditional global quit.
- Every current command palette entry exists with equivalent command argv, masking behavior, category, argument hint, and interactivity behavior.
- Every TUI mutation still routes through the same CLI/gateway command family and produces the same audit trail as the Go TUI.
- Every read-only panel displays the same classes of data from the same authoritative source.
- Existing first-run behavior is preserved, including the pre-TUI `defenseclaw init` prompt and embedded Setup fallback semantics.
- Existing connector gating is preserved, including hiding Plugins for non-OpenClaw connectors.

Mouse parity-plus:

- Every clickable item in the Go TUI remains clickable in the Python TUI.
- Click targets are implemented as widgets or table rows, not hand-maintained coordinate ranges.
- Resize must not invalidate click behavior.
- A row click and keyboard `Enter` on the same row must call the same handler.
- Each modal button must have both a click test and a keyboard test.
- Each panel with mouse affordances must have at least one Textual `Pilot.click()` regression test.

Visual parity:

- The top-level information architecture must match the Go TUI: header/navigation, active panel body, command input or command affordance, hints/footer, status strip.
- The panel order and shortcuts must remain stable.
- Content must remain usable at 80x24, 120x40, and a wide terminal such as 180x50.
- Text must not overlap or truncate critical fields without an explicit ellipsis/truncation rule.
- Color/state semantics must match the current theme: pass/running/clean, warn, error/high, disabled, muted, active selection.

Source-of-truth behavior discovered in the Go audit:

- `q` is not a global quit. It is delegated to the active panel/overlay and is often a local close/no-op. Preserve this to avoid accidental full-TUI exits.
- `Ctrl+C` quits globally except where command execution cancellation or an interactive child process explicitly owns it.
- The command line and palette do not shell arbitrary commands. They resolve registered aliases by longest prefix, split the tail into argv without a shell, mask secrets, classify risk, and show a confirmation preview for anything non-read-only.
- Activity supports `!` to rerun the most recent command.
- Alerts support copying the selected alert detail to the clipboard with `y`.
- Overview quick actions are: `s` Scan all, `d` Doctor, `i` Inventory, `g` Guardrail, `m` Mode, `p` Policy, `l` Logs, `R` Redaction, `N` Notify, `u` Upgrade, `X` Uninstall, `?` Help.
- Overview must distinguish intentionally disabled/standalone gateway mode from broken gateway mode, surface connector drift/no-traffic notices, silent bypass counts, stale doctor cache state, and missing required API keys.
- Policy supports external `$EDITOR` handoff for Rego files, rule files, and suppressions YAML; the terminal must suspend/resume cleanly and reload policy data afterward.
- Logs surface a `RAW` redaction-disabled badge and provide a `J` shortcut on Verdicts for SQLite-backed judge response review.
- Skills and MCPs use `R` as a deep link into Registries, focused on the selected registry-backed entry when possible.
- The MCP add/update form has seven fields in order: Name, Command, Args, URL, Transport, Env vars, Skip scan. Name is required; at least one of Command or URL is required; Env vars are comma-separated `KEY=VAL` pairs emitted as repeated `--env`; truthy Skip scan emits `--skip-scan`.
- Setup has restart-queue controls: `G` starts the queued gateway restart, `C` clears the queue, `S` opens config diff/save, and `R` reverts config from disk.
- First-run embedded setup is a small field list, not a generic Setup redirect. It collects Connector, Profile, Scanner Mode, LLM Judge, Start Gateway, and Verify, then runs `defenseclaw init --non-interactive --yes --json-summary ...`.
- TUI filter changes and refresh duration currently emit telemetry and must not silently disappear.

Test parity:

- Port or replace every high-value Go TUI test with a Python equivalent.
- Keep the Go tests during the transition until the Python TUI is the default and parity gates pass.
- Add Python tests for click behavior that the Go TUI currently struggles with.
- Add command registry parity tests against the live Click command tree and gateway help output.

Compatibility parity:

- `defenseclaw tui` launches the Python Textual TUI.
- `defenseclaw` on a TTY with no subcommand launches the Python Textual TUI.
- Non-TTY invocations still fall back to Click CLI behavior.
- `defenseclaw-gateway tui` remains supported for at least one compatibility release by execing `defenseclaw tui` when available, or by printing a clear deprecation message with an actionable command.

## Mandatory UI Parity Inventory

This is the minimum required UI inventory. If implementation discovers another Go TUI state, tab, modal, filter, action, or shortcut not listed here, the spec must be updated and the missing surface must be ported before the Python TUI can become the default.

### Top-Level Panels

The Python TUI must preserve all current top-level panels and shortcuts:

| Shortcut | Panel | Required Python status |
|---|---|---|
| `1` | Overview | Full parity |
| `2` | Alerts | Full parity |
| `3` | Skills | Full parity |
| `4` | MCPs | Full parity |
| `5` | Plugins | Full parity, including OpenClaw-only gating |
| `6` | Inventory | Full parity, including every sub-tab |
| `7` | Policy | Full parity, including every sub-tab and overlay |
| `8` | Logs | Full parity, including every source tab and chip filter |
| `9` | Audit | Full parity |
| no digit | Activity | Full parity, reachable through existing navigation/palette paths |
| `T` | Tools | Full parity |
| `V` | AI Discovery | Full parity |
| `R` | Registries | Full parity, including every sub-tab |
| `0` | Setup | Full parity, including wizard mode, config mode, list editors, and every config section |

### Required Sub-Tabs, Sub-Modes, And Filters

Overview:

- Dashboard home.
- Service health / gateway / watchdog / guardrail / connector status.
- Doctor cache summary, stale/recovered/failure states.
- Credential/key status.
- Discovered AI agents box.
- Recent activity/notices.
- Quick actions.
- Connector mode picker path.
- Redaction, notifications, and uninstall/reset entry points where currently reachable.

Alerts:

- Alert list.
- Inline/detail view.
- Text filter.
- Severity quick filters: All, Critical, High, Medium, Low.
- Multi-select state.
- Select all filtered, clear filtered, acknowledge, dismiss.
- Bulk action keys: `space` selects the current alert and advances, `a` selects all filtered alerts, `A` or `X` deselects all, `x` acknowledges selected alerts, `c` clears filtered alerts, and `C` clears all alerts.
- Scan parent rows expand/collapse on `Enter`; normal alert/finding rows open/close detail on `Enter`.
- Scan block/finding enrichment.
- Request/trace/run/session identifiers in details where present.

Skills:

- List view.
- Text filter.
- Detail view.
- Registry attribution badge.
- Connector/source banner.
- Action menu paths: scan, allow, block, unblock, disable, enable, quarantine, restore, info/install where currently available.
- Registry cross-link to Registries Entries filtered/focused on the selected skill.

MCPs:

- List view.
- Text filter.
- Detail view.
- Registry attribution badge.
- Connector/source banner.
- Action menu paths: scan, allow, block, unblock, set, unset, info where currently available.
- Full MCP set/unset form.
- Registry cross-link to Registries Entries filtered/focused on the selected MCP.

Plugins:

- List view.
- Text filter if active in current Go behavior.
- Detail view.
- OpenClaw-only panel gating and non-OpenClaw explanatory notice.
- Action menu paths: scan, allow, block, disable, enable, install, quarantine, remove, restore, info.

Inventory:

- Sub-tabs: Summary, Skills, Plugins, MCPs, Agents, Models, Memory.
- Load scope/category chips: skills, plugins, mcp, agents, tools, models, memory.
- Fast-scan preset toggle.
- Scope values map to `defenseclaw aibom scan --json --only skills,plugins,mcp` style argv. The flag and comma-separated value are separate argv entries, and the CSV contains no spaces.
- The Go parity key for scope is `o`, toggling the fast preset of skills, plugins, and MCPs. Individual category chips may be clickable as an additive Textual improvement, but they must not replace the existing all/fast behavior.
- Summary source/config/policy counts.
- Skills table and details.
- Skills filters: All, Eligible, Warning, Blocked.
- Plugins table and details.
- Plugins filters: All, Loaded, Disabled, Blocked.
- MCPs table and details.
- Agents table and details.
- Models table and details.
- Memory table and details.
- Policy verdict badges and scan finding counts.

Policy:

- Sub-tabs: Policies, Rule Packs, Judge Prompts, Suppressions, OPA / Rego.
- Policies list.
- Active policy indicator.
- Policy YAML detail overlay.
- Policy create form.
- Policy actions: list, show, create, activate, delete, validate, edit actions/scanner/guardrail/firewall.
- Rule pack list.
- Rule list within the active pack.
- Rule-pack rule detail overlay.
- Judge prompt list and YAML viewer.
- Suppressions sections and delete behavior.
- OPA/Rego file list and source viewer.
- Toggle test files in OPA/Rego.
- Validate, test, reload paths.
- External editor launch behavior.
- Outer sub-tab navigation supports `]` and `[` everywhere; `Tab`/right and `Shift+Tab`/left also switch outer sub-tabs except inside Suppressions, where Tab cycles inner Suppressions sections.
- Policies tab keys: `r` reloads the local list, `l` runs `defenseclaw policy list`, `s`/`Enter` opens YAML detail, `a` activates, `d` deletes, `v` validates, and `n`/`+` opens create form.
- Rule Packs tab keys: `Enter` activates a different pack and runs `policy reload`, or drills into rules when the selected pack is already active; rule detail supports `e` to edit the backing YAML file.
- Suppressions tab keys: `Tab`/`Shift+Tab` cycle Pre-Judge Strips, Finding Suppressions, Tool Suppressions; `d` deletes the selected suppression and writes `suppressions.yaml`; `Enter`/`e` opens `$EDITOR` on `suppressions.yaml`.
- OPA/Rego keys: `t` toggles test files, `v` validates, `r` reloads, `T` runs `defenseclaw policy test` in-panel with a 30-second timeout, and `E` opens `$EDITOR` on the selected Rego file.
- `$EDITOR` falls back to `vi`, releases the terminal while open, then reloads Rego or full policy data after exit.

Logs:

- Source tabs: Gateway, Verdicts, OTEL, Watchdog.
- Live tail.
- Pause/resume.
- Search.
- Source switching with `left`/`h` and `right`/`l`.
- Cursor movement pins the view paused; `g` jumps to the start and pauses, while `G` jumps to newest and resumes live tailing.
- Per-source cursor/scroll preservation.
- Generic filter presets: All, No Noise, Important, Errors, Warnings+, Scan, Drift, Guardrail.
- Filter hotkeys: `f` cycles presets, `1`-`8` select presets directly, `e` toggles Errors, and `w` toggles Warnings+.
- Verdict action chips: All actions, Block, Alert, Confirm, Allow.
- Verdict event-type chips: All events, Verdict, Judge, Lifecycle, Error, Diagnostic, Scan, Scan finding, Activity.
- Verdict severity chips: All severities, Critical, High, High+, Medium, Low, Info.
- Verdict chip hotkeys: `a` cycles action, `t` cycles event type, and `s` cycles severity only on the Verdicts tab.
- Structured detail modal for Verdicts and OTEL rows.
- Gateway and Watchdog rows open a raw-line detail modal on `Enter`.
- `R` opens the redaction modal and `N` opens the notifications modal from Logs when search is not active.
- Redaction indicator.
- Empty/error states for every source.

Audit:

- Audit event list.
- Text filter.
- Detail modal.
- Export action.
- Exact export behavior: `e` writes `defenseclaw-audit-export.json`, records an Activity entry, and shows success/failure toast feedback.
- Empty and no-match states.

Activity:

- Sub-tabs: Commands, Mutations.
- Command history.
- Running command terminal mode.
- Output streaming.
- Exit code/duration/cancelled metadata.
- Command cancellation.
- Mutation list from gateway activity JSONL.
- Structured mutation diff expand/collapse.

Tools:

- Tool block/allow list.
- Global and scoped source status.
- Allow, block, unblock actions.
- Empty state and palette guidance.

AI Discovery:

- Full deduplicated AI usage table.
- Filter/search.
- Detail drill-down with per-signal evidence.
- Offline/loading/disabled/empty states.
- Refresh/scan path.
- Confidence score/band rendering.
- Grouping and sorting equivalent to the Go panel and CLI output:
  - Dedup key is state, product, vendor, ecosystem, component name, and version.
  - Category and detector are deliberately not in the dedup key; they are aggregated into list cells.
  - Sort order is state weight `new`, `changed`, `active`, `seen`, `gone`, then descending count, then product name.
  - Search matches every rendered column plus every underlying category and detector, so truncated `+N` cells never hide matches.
  - Header always shows active count and files scanned, and shows new/changed/gone only when non-zero.
  - Detail view snapshots the selected row and shows up to 50 per-signal evidence rows with a pointer to `defenseclaw agent usage --detail --json` for the full list.

Registries:

- Sub-tabs: Sources, Entries, Approved.
- Source list from config.
- Source index summaries from registry cache.
- Entries union table from every source index.
- Approved entries table.
- Source sync.
- Sync all enabled.
- Approve.
- Reject.
- Delete/remove source from the Sources tab only.
- Focus entry from Skills/MCPs.
- Source IDs used for index reads must reject `/`, `\`, and `.` before opening `~/.defenseclaw/registries/<id>/index.json`.
- Entry rows must show Source, Name, Type, Status, Severity, A/R approval/rejection marker, and Location chosen from URL, Command, then Source URL.
- Source/entry empty and error states.

Setup:

- Modes: Wizards and Config.
- Readiness checks.
- Credential/key snapshot.
- Restart queue.
- Wizard form mode.
- Wizard output terminal mode.
- Secret reveal toggle for wizard forms.
- Audit Sinks list editor.
- Webhooks list editor.
- Config diff preview.
- Config save path.
- Config field editing, choice cycling, bool toggles, password masking.
- Section wrapping when the tab row exceeds terminal width.

Setup wizards:

- Connector Setup.
- Credentials.
- LLM.
- Local OTel.
- Token Rotation.
- Custom Providers.
- Skill Scanner.
- MCP Scanner.
- Gateway.
- Guardrail.
- Splunk.
- Observability.
- Webhooks.
- Sandbox.
- Registries.

Setup config sections:

- General.
- Agent.
- Privacy.
- Notifications.
- Claw.
- Agent Hooks.
- Connector Hooks.
- Gateway.
- Guardrail.
- Scanners.
- Asset Policy.
- AI Discovery.
- Gateway Watcher.
- Gateway Watchdog.
- Audit Sinks.
- Webhooks.
- OTel.
- Skill Actions.
- MCP Actions.
- Plugin Actions.
- Watch.
- OpenShell.
- Inspect LLM (legacy — read-only).
- Cisco AI Defense.
- Firewall.

Setup config field catalog:

- The section list above is not sufficient by itself. The Python TUI must port every editable/read-only `configField` key from Go `SetupPanel.loadSections()` and every write path from `applyConfigField()`.
- Preserve field kind semantics:
  - `header` rows are read-only.
  - `bool` rows toggle.
  - `choice` rows cycle/select only declared options.
  - `int` rows validate integer input.
  - `password` rows mask by default and support explicit reveal.
  - CSV/list fields round-trip through the same comma-splitting behavior as Go.
- Preserve high-risk setup surfaces called out by Go tests:
  - Notifications master/category/source/throttle fields.
  - Unified `llm.*` editable block and legacy Inspect LLM read-only/deprecation surface.
  - Guardrail hook fail mode, HILT, per-direction detection strategies, LLM override, judge override, judge category toggles, retain-judge-bodies.
  - Scanners full surface for skill scanner, MCP scanner, plugin scanner, and CodeGuard.
  - AI Discovery mode/interval/source/privacy/emission fields.
  - Gateway extra fields, watcher, watchdog, and watch settings.
  - OTel per-signal and batch settings.
  - OpenShell tristates: blank, true, false.
  - Cisco AI Defense editable fields, with API key rendered as password.
  - Firewall section is read-only where the Go section is read-only.
- Every interactive field must have a concise hint, and every section must have a summary, matching the Go `setup_hints_test.go` contract.

Setup list editors:

- Audit Sinks editor:
  - List.
  - Add/open Observability wizard.
  - Enable.
  - Disable.
  - Remove.
  - Test.
  - Migrate legacy Splunk.
  - Refresh.
  - Resume after command completion.
- Webhooks editor:
  - List.
  - Add/open Webhooks wizard.
  - Enable.
  - Disable.
  - Remove.
  - Test.
  - Show.
  - Refresh.
  - Resume after command completion.

Global overlays/modals:

- Help.
- Detail modal.
- Command palette.
- Command preview.
- Action menu.
- Config diff.
- Mode picker.
- Redaction toggle.
- Notifications toggle.
- Uninstall/reset confirmation.
- MCP set form.
- Setup wizard form.
- Setup wizard output terminal.
- Audit Sinks editor.
- Webhooks editor.
- First-run Setup fallback.

Exact overlay behavior discovered in the Go implementation:

- First-run fallback fields and defaults:
  - Connector defaults to `codex`; choices are `codex`, `claudecode`, `zeptoclaw`, `openclaw`, `hermes`, `cursor`, `windsurf`, `geminicli`, `copilot`.
  - Profile defaults to `observe`; choices are `observe`, `action`.
  - Scanner Mode defaults to `local`; choices are `local`, `remote`, `both`.
  - LLM Judge defaults off, Start Gateway defaults off, Verify defaults on.
  - `Ctrl+R` dispatches `defenseclaw init --non-interactive --yes --json-summary --connector <connector> --profile <profile> --scanner-mode <mode> --with-judge|--no-judge --start-gateway|--no-start-gateway --verify|--no-verify`.
- Mode picker choices and hotkeys:
  - `o` OpenClaw: fetch interceptor plus before-tool-call plugin, full guardrail.
  - `z` ZeptoClaw: api_base redirect plus proxy response scan, full guardrail.
  - `k` Claude Code: PreToolUse hooks, native OTel, CodeGuard plugin.
  - `c` Codex: hook scripts, native OTel, notify, CodeGuard skill.
  - `h` Hermes, `u` Cursor, `w` Windsurf, `g` Gemini CLI, `p` Copilot.
  - The active connector is preselected; pressing a hotkey selects the row and confirms. Re-running the active connector setup is valid because it refreshes hooks/config/runtime files.
  - Confirmation runs `defenseclaw setup <alias> --yes`, with `claudecode` mapped to `claude-code`.
  - The preview copy must preserve the Go semantics: proxy-backed connectors pin `claw.mode` and `guardrail.connector`, hook-driven connectors wire hooks/native telemetry/CodeGuard, and backups/preservation of non-DefenseClaw hooks/settings are explicitly mentioned.
- Redaction toggle:
  - Desired action is `off` when currently redacted, `on` when currently RAW.
  - Disabling redaction must warn that RAW content goes to SQLite audit DB, Splunk HEC, OTel log exporters, webhooks, `gateway.log`, and the Logs panel.
  - Re-enabling redaction must say existing already-emitted rows/events remain as written.
  - Confirmation dispatches `defenseclaw setup redaction <on|off> --yes`.
- Notifications toggle:
  - Desired action is `off` when currently enabled, `on` when currently disabled.
  - Turning on surfaces hook/guardrail/asset-policy blocks, observe-mode would-blocks, and HITL approval prompts.
  - Clicking a notification does not approve anything.
  - Turning off stops the toaster only; audit DB, Splunk, OTel, and webhooks remain unaffected.
  - Confirmation dispatches `defenseclaw setup notifications <on|off> --yes`.
- Uninstall modal:
  - Defaults to preview-only dry run.
  - Choices are `p` Preview plan -> `defenseclaw uninstall --dry-run`, `u` Uninstall keep data -> `defenseclaw uninstall --yes`, and `a` Uninstall and wipe data -> `defenseclaw uninstall --all --yes`.
  - Destructive rows pass `--yes` because this modal is the confirmation step.

## Proposed Package Layout

Add a Python package rooted at `cli/defenseclaw/tui/`:

```text
cli/defenseclaw/tui/
  __init__.py
  app.py                    # DefenseClawTUI(Textual App)
  bootstrap.py              # config/store/env/first-run loading
  registry.py               # CmdEntry, command matching, parity helpers
  executor.py               # async subprocess + PTY command execution
  command_line.py           # raw defenseclaw/defenseclaw-gateway command parser
  models.py                 # DTOs shared by panels
  theme.py                  # state colors, CSS constants, rich styles
  paths.py                  # doctor/config/audit/log/registry path helpers
  services/
    config_service.py
    audit_service.py
    gateway_client.py
    cli_json.py
    registry_cache.py
    log_tail.py
    doctor_cache.py
    credentials.py
    hint_engine.py
  widgets/
    chrome.py               # header, nav, status strip, footer hints
    tables.py               # common DataTable wrappers
    action_menu.py
    command_palette.py
    command_input.py
    hint_bar.py
    detail.py
    forms.py
    toasts.py
    badges.py
  screens/
    main.py
    help.py
    command_preview.py
    confirm.py
    config_diff.py
    set_mcp.py
    mode_picker.py
    redaction.py
    notifications.py
    uninstall.py
  panels/
    overview.py
    alerts.py
    skills.py
    mcps.py
    plugins.py
    inventory.py
    policy.py
    logs.py
    audit.py
    activity.py
    tools.py
    ai_discovery.py
    registries.py
    setup.py
  tests/
    ...
```

Keep code boundaries explicit:

- `panels/` owns rendering, selection state, and panel-specific UI handlers.
- `services/` owns IO and data parsing.
- `executor.py` owns subprocess lifecycle, masking, cancellation, and PTY behavior.
- `registry.py` owns the TUI-to-CLI command map.
- `app.py` owns top-level routing, refresh timers, global keybindings, and cross-panel propagation.

## Launch And Packaging Plan

Phase 1 introduces the Python TUI behind a feature flag:

- Add `defenseclaw tui --backend textual|go`.
- Add env override `DEFENSECLAW_TUI_BACKEND=textual|go`.
- Default stays `go` until all full-parity gates in this spec pass.

Phase 2 flips the default:

- `defenseclaw tui` defaults to Textual.
- `defenseclaw tui --backend go` remains available.
- `defenseclaw-gateway tui` tries to exec `defenseclaw tui --backend textual`.
- Docs mark Go TUI as compatibility backend.

Phase 3 removes the Go TUI command path:

- Remove `--backend go` after one compatibility release.
- Remove Bubble Tea/Lip Gloss/Bubbles dependencies only after no other Go package imports them.
- Keep gateway binary for non-TUI runtime commands.

`pyproject.toml` changes:

- Add `textual>=8.2,<9.0`.
- Consider `pytest-asyncio` if Textual tests require it and current pytest setup does not cover async test execution.
- Do not add broad optional extras for the default path; the TUI is now part of the main CLI experience.

## Bootstrap Contract

`cli/defenseclaw/tui/bootstrap.py` must mirror the current Go `runTUIPre` and `runTUI` behavior.

Startup sequence:

1. Load default `.env` from `config.DefaultDataPath()` equivalent.
2. Try to load config via `defenseclaw.config.load()`.
3. If config load fails:
   - Do not crash immediately.
   - Preserve the first-run decision flow.
   - If stdin/stdout are TTYs and `--skip-first-run-prompt` is false, ask whether to run `defenseclaw init`.
   - If accepted, exec/run `defenseclaw init`, reload config/store, then launch normal TUI.
   - If declined, launch normal TUI without embedded first-run overlay.
   - If unavailable/non-TTY/unparseable, launch Setup/first-run fallback.
4. If config loads:
   - Apply privacy/redaction config.
   - Open audit store using existing Python `Store`.
   - Initialize logger only if needed for activity writes.
   - Load config-specific `.env` if `data_dir` differs.
5. Construct `DefenseClawTUI` with `Deps(config, store, first_run, version)`.

Embedded first-run fallback:

- When the app starts in first-run mode, render the field list from the Go `FirstRunPanel` rather than jumping directly to the full Setup panel.
- Field order, defaults, and options must match the Go panel exactly:
  - Connector: default `codex`; choices `codex`, `claudecode`, `zeptoclaw`, `openclaw`, `hermes`, `cursor`, `windsurf`, `geminicli`, `copilot`.
  - Profile: default `observe`; choices `observe`, `action`.
  - Scanner Mode: default `local`; choices `local`, `remote`, `both`.
  - LLM Judge: bool, default off.
  - Start Gateway: bool, default off.
  - Verify: bool, default on.
- Navigation is Up/Down or `k`/`j`; choice changes are Left/Right or `h`/`l`; Space/Enter toggles or advances; `Ctrl+R` applies.
- Apply must dispatch the canonical Python backend: `defenseclaw init --non-interactive --yes --json-summary` plus the selected connector/profile/scanner and the appropriate judge/start-gateway/verify flags.

Acceptance tests:

- Missing config + TTY + accept runs `defenseclaw init`, reloads, does not show embedded first-run.
- Missing config + TTY + decline starts app without embedded first-run.
- Missing config + non-TTY does not launch full-screen TUI.
- Bad config reports recoverable error and still allows recovery commands where the current CLI allows them.

## Application Chrome

Top-level layout:

- Header: product/version and panel tabs.
- Body: active panel.
- Command affordance: persistent command input/drawer, matching `:` for direct command entry and `Ctrl+K` for fuzzy command discovery.
- Hints: panel-aware hint engine with keyboard hints, mouse affordance hints, and next-best-action suggestions.
- Status strip: gateway, watchdog, guardrail mode, alert count, command running spinner, version, stale refresh indicator.
- Status strip parity details:
  - Gateway segment includes state dot and truncated last error when non-running.
  - Watchdog segment includes state dot and truncated last error when non-running.
  - Guardrail segment shows disabled/off when config guardrail is disabled, otherwise `Guardrail.<mode>`.
  - Alert segment is red/high when alert count is non-zero and green/clean at zero.
  - Running command segment shows spinner plus `running`.
  - Stale segment appears when refresh age exceeds the current stale threshold.
  - Unfocused/background state is shown when Textual exposes focus state.
  - Version remains visible at the end.

Keyboard bindings:

- `1` through `9`: Overview through Audit.
- `0`: Setup.
- `T`: Tools.
- `V`: AI Discovery.
- `R`: Registries.
- `Tab` / `Shift+Tab`: next/previous visible panel.
- `:`: direct command input for registry aliases and raw `defenseclaw ...` commands.
- `Ctrl+K`: fuzzy command palette.
- `Ctrl+P`: optional Textual command palette binding if it does not conflict with existing shortcuts.
- `/`: active panel filter.
- `?`: help.
- `r`: manual refresh.
- `Ctrl+C`: global quit, except when Activity terminal mode or an interactive child process owns it for cancellation.
- `q`: local panel/overlay close or no-op. It must not quit the whole TUI globally.
- `Esc`: close modal/filter/input where applicable.

Shortcut precedence:

- Top-level key routing order must be: help/modal/preview/diff/action menu/detail, redaction/notification/uninstall overlays, first-run, command input, command palette, active filter, Activity terminal mode, panel-exclusive states, panel-owned numeric shortcuts, then global navigation.
- Panel-owned digit shortcuts must override global panel switching:
  - Alerts: `1`-`5` severity filters.
  - Inventory: `1`-`4` category filters where applicable.
  - Activity: `1`/`2` Commands/Mutations tabs.
  - Logs: `1`-`8` filter presets.
  - Registries: `1`-`3` tabs.
- Panel-exclusive states include policy overlays, item detail panes, MCP set form, Setup forms/wizard output/editors, AI Discovery detail, Activity terminal mode, and modal screens.

Panel visibility:

- Plugins remains hidden when active connector is not OpenClaw.
- Hidden panels are skipped by tab cycling.
- Numeric shortcut for hidden Plugins is a no-op or shows the existing OpenClaw-only notice when reached through a stale path.

Mouse behavior:

- Panel tabs are click targets using Textual tab widgets.
- Status strip is not a mutation surface unless explicitly implemented.
- All action rows, table rows, modal buttons, and form controls are widget click targets.

Hint engine behavior:

- `services/hint_engine.py` computes contextual hints from the active panel, focused widget, selected row, gateway state, running commands, stale data, and available actions.
- `widgets/hint_bar.py` renders the highest-priority hints in a compact rounded strip. It must never block command input, modals, or table focus.
- Preserve the current Go hint inputs: gateway running, guardrail enabled/mode, critical alerts, unscanned skills, total alerts, command running, command count, logs paused, new lines since pause, active filter, and audit count.
- Hints are ranked by usefulness:
  - critical system hints: gateway offline, guardrail disabled, stale doctor cache, failed command
  - selected-object actions: acknowledge alert, scan skill, approve registry entry, test webhook
  - navigation/filter hints: open details, filter, refresh, command palette
  - onboarding hints: first-run setup, missing credentials, empty registry
- Preserve current priority order where it exists:
  - Overview: gateway offline, guardrail disabled, critical alerts, unscanned skills, then rotating tips.
  - Alerts: empty/no-alerts, critical alerts, active filter, then normal key hints.
  - Logs: paused state with new-line count before streaming hints.
  - Audit: empty state, active filter, then normal history hints.
  - Activity: running command, empty history, then command count/rerun hint.
- Preserve current panel hint coverage for Overview, Alerts, Skills, MCPs, Plugins, Inventory, Logs, Audit, Activity, Tools, and AI Discovery. Add Registries and Setup hints rather than leaving them on the generic fallback.
- Hints must be actionable when possible. A hint can expose a keybinding, a click target, or a command palette entry.
- Hints must be quiet when the user is typing, confirming a destructive action, or reading command output.
- Hints must be testable with fixed state fixtures so the same context always produces the same top hints.

Help overlay:

- Preserve the global help inventory at minimum: Navigation, Lists, Skills/MCPs, Alerts, Logs, Policy Panel, and Overview Quick Actions.
- The Textual help can become panel-aware and hide irrelevant shortcuts, but it must not remove the global keymap summary available in the Go overlay.
- Help closes on any key in the current Go behavior; if Textual uses a close button as well, keyboard close must still work.

## Command Registry

Port `internal/tui/command.go::BuildRegistry()` to `cli/defenseclaw/tui/registry.py`.

Model:

```python
@dataclass(frozen=True)
class CmdEntry:
    tui_name: str
    cli_binary: Literal["defenseclaw", "defenseclaw-gateway"]
    cli_args: tuple[str, ...]
    description: str
    category: str
    needs_arg: bool = False
    arg_hint: str = ""
```

Required behavior:

- Longest-prefix matching, matching current `MatchCommand`.
- Shell-tail splitting with support for quoting and escapes, matching current `splitCommandTail`.
- Binary resolution equivalent to Go `resolveSiblingBin`.
- `defenseclaw` commands must reuse the same Python environment that launched the TUI when possible.
- Gateway commands must resolve `defenseclaw-gateway` via existing Python gateway resolver.
- Secret masking must match or improve `CommandIntent` masking.

Command registry source of truth:

- Preferred: move command entries to a generated or manually maintained Python registry and make the Go registry compare against it during transition.
- Acceptable transition: duplicate entries in Python and add a strict parity test comparing Python registry output to a serialized Go registry output generated by `go test` helper or a small Go command.
- Final state: Python registry is authoritative.
- As an implementation artifact, generate `cli/defenseclaw/tui/tests/fixtures/go_command_registry.json` during the transition. It must include `tui_name`, `cli_binary`, `cli_args`, `description`, `category`, `needs_arg`, and `arg_hint` for all current Go entries, and Python tests must fail on missing, added, or changed entries unless the spec is updated.

Tests:

- Every Python registry command that targets `defenseclaw` exists in the live Click tree.
- Every flag passed by the registry exists for that command.
- Gateway registry commands are checked by invoking `defenseclaw-gateway <group> --help` or equivalent.
- Matching behavior covers aliases, longest-prefix collisions, extra args, unterminated quotes, escaped spaces, and empty input.
- Registry tests must assert no `tui_name` starts with `defenseclaw ` or `defenseclaw-gateway `. The binary prefix is a direct-command-input convenience, not part of the alias namespace.
- Command risk tests must cover the same classes as Go: `read-only`, `setup`, `mutation`, `restart`, `destructive`, and `secret`.
- Secret masking must cover separated values (`--token VALUE`) and inline values (`--token=VALUE`) for `--value`, `--token`, `--api-key`, `--hec-token`, `--access-token`, `--secret`, and `--password`.

## In-TUI Command Line

The Python TUI must support typing actual DefenseClaw commands inside the TUI, not only selecting curated actions from the command palette.

Entry points:

- `:` opens a command input drawer.
- The command input accepts:
  - TUI registry aliases, preserving Go TUI behavior.
  - Raw `defenseclaw ...` commands.
  - Raw `defenseclaw-gateway ...` commands for gateway subcommands that already exist in the Go registry or are explicitly allowed.
  - Optional shorthand without the binary, such as `doctor`, `skill scan ...`, or `scan skill ...`, only when it resolves unambiguously to `defenseclaw`.
- `Ctrl+K` opens fuzzy command discovery and can prefill the direct command input.
- Command history is searchable with Up/Down or a history picker.

Parsing and safety:

- Parse command text with `shlex.split`, never through a shell.
- Do not support arbitrary host commands. Inputs must resolve to `defenseclaw` or `defenseclaw-gateway`.
- If input starts with `defenseclaw` or `defenseclaw-gateway`, strip the binary for alias matching only after validating that the remaining command exists in the registry or in an explicit allowlist backed by Click/gateway help tests.
- Reject shell operators such as `|`, `>`, `<`, `&&`, `;`, command substitution, and environment-prefix execution.
- Reject environment-prefixed commands such as `FOO=bar defenseclaw doctor`; environment should come from the loaded TUI process/config environment, not user input.
- Preserve quoting for command display, but execute only structured argv.
- Use the same secret masking rules as registry commands.
- Mutating, destructive, or config-writing commands must open command preview/confirmation before execution unless the current CLI semantics already require an interactive confirmation.
- A raw command that is unknown should return inline validation feedback and suggested close matches, not silently fail in Activity.

Execution feedback:

- On submit, the command drawer shows an immediate running state, then Activity receives the full transcript.
- The status strip shows the masked command, elapsed time, and spinner while running.
- Success must be shown with green state styling, exit code, duration, and a short completion toast.
- Failure must be shown with red state styling, exit code, duration, stderr summary, and suggested next action when one is known.
- Cancelled commands must use a distinct neutral/warning state, not success or failure.
- If a command changes data shown in the active panel, the affected panel refreshes and briefly highlights updated rows or changed summary metrics.

Autocomplete and hints:

- While typing, the input provides completions from the Click command tree, gateway command help, registry aliases, recent commands, and panel-relevant actions.
- The hint engine should surface safe examples for the active panel, such as `defenseclaw doctor`, `defenseclaw skill scan <name>`, or `defenseclaw audit export ...`.
- Argument placeholders must come from registry `arg_hint`, Click metadata, or curated panel hints; do not invent flags that are not validated by tests.

## Command Execution And Activity

`executor.py` must replace `CommandExecutor`.

Capabilities:

- Run non-interactive commands asynchronously with stdout/stderr merged.
- Stream output line by line into Activity.
- Run interactive commands in a PTY so prompts appear immediately.
- Forward user-entered lines to the child PTY when Activity is in interactive terminal mode.
- Cancel running commands with interrupt semantics.
- Prevent concurrent command execution unless explicitly designed later.
- Emit start/output/done events to the app.
- Capture:
  - display command with secrets masked
  - raw argv for execution only
  - start time
  - finish time
  - duration
  - exit code
  - cancelled flag
  - origin/category
  - risk class
  - masked argv
  - config reloaded flag
  - restart completed flag
  - doctor cache refreshed flag
  - suggested next action

Implementation notes:

- Use `asyncio.create_subprocess_exec` for piped commands.
- Use Python `pty` plus async/thread reader for interactive commands on POSIX.
- Preserve environment variables loaded from config `.env`.
- Do not pass commands through a shell.
- Avoid buffering pitfalls by using PTY for interactive commands and unbuffered env where needed.

Activity panel:

- Commands tab shows command history, output, exit state, duration, and cancellation.
- Terminal mode shows latest command output, supports scroll, and uses `Esc`/`q` to return to history.
- `!` reruns the most recent command when it resolves through the registry or direct command parser.
- Mutations tab reads gateway activity from `gateway.jsonl`.
- Mutations tab supports expanding structured diffs for gateway activity rows.
- Command result cards show origin, category, risk, elapsed time while running, masked argv, config reload, restart completion, doctor cache refresh, and suggested next action when present.
- On command completion:
  - Refresh panels impacted by command category.
  - Refresh Inventory, Plugins, Skills, and MCPs when their cached lists are loaded and the command could have changed them.
  - Reload doctor cache after doctor commands.
  - Reload config after setup/settings/keys/init commands.
  - Reload credential snapshot after keys commands.
  - Refresh AI usage after AI discovery commands.
  - Clear restart queue after a successful restart command.
  - Log operator activity through the same audit path as today.

## Data Services

Use Python-native services rather than importing or binding Go internals.

Config:

- Use existing `defenseclaw.config.load()` and save helpers.
- Never hand-edit config in panels if an existing CLI command is the mutation source of truth.
- Direct config editor edits may stage a Python object diff, but save must route through the existing CLI-compatible settings/config save path and emit audit activity.

Audit:

- Use existing Python `defenseclaw.db.Store`.
- Add missing list/query methods to the Python store only when necessary and cover them with tests.
- Do not query SQLite ad hoc in panel code.

Gateway:

- Use `defenseclaw.gateway.OrchestratorClient` where endpoints exist.
- Add typed methods for missing endpoints.
- Health polling targets `http://127.0.0.1:{api_port}/health`, matching current behavior.
- AI usage polling targets `/api/v1/ai-usage`, using resolved gateway token.
- Initial app boot must prime health-adjacent state by loading doctor cache, credential snapshot, logs, and AI usage without waiting for the first periodic tick.
- Periodic refresh cadence must preserve the current behavior unless changed deliberately:
  - fast refresh every 5 seconds for toasts, health, status, logs, and AI usage when AI Discovery is foregrounded
  - slow refresh every 30 seconds for AI usage when backgrounded and loaded list panels
  - spinner tick around 100ms for running-command feedback
- Poll failures should soft-fail where the Go TUI does: keep the prior AI usage snapshot on transient errors, show recoverable doctor/credential errors as toasts, and avoid crashing the TUI on missing first-run cache files.

CLI JSON:

- Prefer direct Python functions only when they are already cleanly separated from Click rendering and preserve audit semantics.
- Otherwise invoke `defenseclaw <command> --json` as a subprocess.
- All subprocess JSON parsing must have timeout, parse error, and empty result handling.

Files:

- `doctor_cache.json`: read through `doctor_cache.py`.
- `gateway.jsonl`: tail/parse through `log_tail.py`.
- registry indexes: read through `registry_cache.py`.
- `.env`: display only masked/resolved credential state unless using existing credentials commands.

## Panel Specifications

### Overview

Data sources:

- Gateway health endpoint.
- Audit counts from store.
- Doctor cache.
- Credential snapshot from `defenseclaw keys list --json`.
- AI usage snapshot.
- Config state.
- Silent bypass count from gateway/audit logs.

Parity requirements:

- Render service health, guardrail state, connector state, doctor status, credential state, discovered AI agents, recent activity, notices, and quick actions.
- Preserve doctor stale logic and reconciliation with live health.
- Preserve first-time setup notices.
- Preserve smart notices:
  - First-time setup hint when gateway is broken, guardrail is off, and `skill-scanner` is missing.
  - Gateway offline message only for broken gateway health states, not intentional standalone/disabled mode.
  - Standalone gateway hint sourced from `/health.gateway.details.hint` or `.summary`.
  - Guardrail-not-configured and `skill-scanner` missing warnings.
  - Doctor failure count after subtracting stale failures contradicted by live `/health`.
  - Missing required API key notice with at most two names plus `(+N more)`.
  - Connector drift warning when configured connector and live connector differ.
  - Zero-request guidance that uses hook wording for hook-only connectors and gateway-port wording for OpenClaw/proxy connectors.
- Preserve quick actions exactly: `s` Scan all, `d` Doctor, `i` Inventory, `g` Guardrail, `m` Mode, `p` Policy, `l` Logs, `R` Redaction, `N` Notify, `u` Upgrade, `X` Uninstall, `?` Help.
- Preserve service rows for Gateway, Agent, Watchdog, Guardrail, API, Sinks, Telemetry, AI Discovery, and Sandbox.
- Preserve configuration rows for Agent, Redaction, Policy posture, Enforcement, Human approval, Approval support, Environment, Policy dir, Data dir, LLM Provider/Model, and Cisco AI Defense when present.
- Preserve the Enforcement `Silent bypass` row when the count is non-zero.

Mouse/click:

- Quick actions are `Button`s.
- Service rows can open detail if current Go behavior supports detail.

Tests:

- No config first-run placeholder.
- Gateway disabled standalone does not render as hard failure.
- Doctor stale/fresh/failure/recovered cases.
- AI discovery snapshot sorting and empty/offline states.
- Quick-action click dispatches same command as keyboard.

### Alerts

Data sources:

- Audit store alert listing.
- Related scan findings where current detail view uses them.
- Gateway alert subscriptions where current code enriches alerts.

Parity requirements:

- Severity/status/action/target/timestamp table.
- Detail view with humanized finding details, scanner names, remediation, request/trace IDs.
- Filter support.
- Acknowledge/dismiss flows.
- Exact keys: `space` toggles selection and advances cursor; `a` selects all filtered rows; `A`/`X` clears selection; `x` acknowledges selected rows; `c` acknowledges filtered rows; `C` acknowledges all alerts; `d` dismisses the selected alert; `y` copies selected alert details; `1`-`5` select severity filters.
- Multi-select and acknowledge must skip gateway-sourced `gw:` synthetic alert IDs, matching the Go panel.
- `Enter` expands/collapses scan summary parent rows and toggles detail for normal audit/finding rows.
- Clipboard copy parity: `y` copies the selected alert summary/details with severity, action, target, and detail text.
- Critical count feeds status strip.

Mouse/click:

- Row click selects row.
- Double click or Enter opens detail.
- Action buttons/menu use widget events.

Tests:

- Row click selection.
- Detail open by click and Enter.
- Acknowledge/dismiss command argv.
- Filter text narrows table and keeps valid cursor.

### Skills

Data sources:

- `defenseclaw skill list --json`.
- Audit actions state.
- Registry attribution from config.

Parity requirements:

- Same status precedence as current Go and Python CLI.
- Connector-aware source banner.
- Registry source badge.
- Scan severity handling.
- Action menu: scan, allow, block, unblock, disable, enable, quarantine, restore, info, install where applicable.
- Direct keys: `s` scan selected skill, `b` block, `a` allow, `o` open action menu, `r` reload `defenseclaw skill list --json`, `Enter` detail, `Esc` close detail.
- `R` deep-links to Registries and focuses the selected registry-backed skill when possible.
- Action menu state rules:
  - Blocked: scan, info, unblock, allow.
  - Allowed: scan, info, block, disable.
  - Quarantined: scan, info, restore.
  - Disabled: scan, info, enable, block.
  - Default: scan, info, block, allow, disable, quarantine, install.

Mouse/click:

- Row click selects.
- Action button or context menu opens action menu.
- Action item click dispatches same command as keyboard.

Tests:

- Status precedence matches CLI.
- Action command argv parity.
- Empty list safe behavior.
- Registry attribution rendering.
- Click action dispatch.

### MCPs

Data sources:

- `defenseclaw mcp list --json`.
- Audit actions state.
- Config/registry attribution.

Parity requirements:

- Same list fields and status mapping.
- Same action menu as Go.
- `set` / `unset` form behavior preserved.
- Transport/command/url details preserved.
- `R` deep-links to Registries and focuses the selected registry-backed MCP when possible.
- Direct keys: `s` scan selected MCP, `b` block, `a` allow, `n` or `+` open the MCP set form, `o` open action menu, `r` reload `defenseclaw mcp list --json`, `Enter` detail, `Esc` close detail.
- MCP action menu must name the correct unset target by connector: Claude Code `~/.claude/settings.json`, Codex `./.mcp.json`, ZeptoClaw `~/.zeptoclaw/config.json`, Hermes `~/.hermes/config.yaml`, Cursor `./.cursor/mcp.json`, Windsurf `~/.codeium/windsurf/mcp_config.json`, Gemini CLI `~/.gemini/settings.json`, Copilot `./.github/mcp.json`, otherwise OpenClaw config. ZeptoClaw unset is rendered as read-only/manual-edit guidance.
- MCP set form exact fields and validation:
  - Name required.
  - At least one of Command or URL required.
  - Args passed as `--args` verbatim.
  - Transport passed as `--transport` when non-empty.
  - Env vars split on commas into repeated `--env KEY=VAL`, rejecting malformed pairs without `=`.
  - Skip scan accepts `y`, `yes`, `true`, or `1`.
  - `Tab`/Down advance, `Shift+Tab`/Up go back, `Enter` advances or submits on the last field, `Esc` cancels, Backspace removes one rune, and `Ctrl+U` clears the focused field.

Mouse/click:

- Row click selects.
- Set form fields and buttons are native widgets.

Tests:

- List parse.
- Set form validation.
- Set/unset argv.
- Click open/set/cancel.

### Plugins

Data sources:

- `defenseclaw plugin list --json`.
- Active connector.

Parity requirements:

- Hidden for non-OpenClaw connectors.
- OpenClaw-only notice preserved.
- Install/remove/quarantine/restore/allow/block/enable/disable/info actions preserved.
- Plugin scan status displayed.
- Direct keys: `s` scans selected plugin by ID, `o` opens action menu, `r` reloads, `Enter` detail, `Esc` close detail.
- Plugin action menu must be state-sensitive:
  - Scan and info are always shown.
  - Block/unblock are driven by verdict, not only runtime status.
  - Allow is shown when the plugin is not already allowed.
  - Enable/disable mirror runtime enabled state.
  - Quarantine is hidden on already-quarantined plugins; restore is shown only for quarantine status.
  - Remove is always last and destructive.

Mouse/click:

- Row and action menu widget handling.

Tests:

- Connector gating.
- Empty list no-op.
- Action argv.
- Click action dispatch.

### Inventory

Data sources:

- `defenseclaw aibom scan --json`.

Parity requirements:

- Category scope chips: skills, MCPs, agents, tools, models, memory, plugins.
- `o` toggles the fast-scan preset.
- There is no Go parity key for a chip selector. A Textual chip selector may be added as an enhancement, but it must be additive and tested separately from the parity keymap.
- Scope state survives panel switches.
- Same `--only <csv>` formatting as Go tests assert: default is `["aibom", "scan", "--json"]`; scoped scans append `["--only", "skills,plugins,mcp"]` with no spaces in the CSV.
- Valid categories are exactly `skills`, `plugins`, `mcp`, `agents`, `tools`, `models`, `memory`; unknown persisted values are dropped.
- Fast preset is exactly `skills`, `plugins`, `mcp`.
- Keyboard filters are local to Skills/Plugins sub-tabs: `1` all, `2` eligible/loaded, `3` warning/disabled, `4` blocked.
- Summary must render source connector, connector home/config paths, component counts, policy verdict counts, and scan coverage.
- Detail enrichment for Skills/Plugins/MCPs must include audit action state, recent history, latest scan info/findings where the current Go detail does.

Mouse/click:

- Chips are clickable toggles.
- Rows are selectable and expandable/details-capable where current behavior supports it.

Tests:

- Default scope.
- Fast preset.
- Individual chip toggles.
- CLI args exactly match expected `--only <csv>` values.
- Click toggles chips without layout drift.

### Policy

Data sources:

- Config/policy files.
- `defenseclaw policy ...`.
- `defenseclaw-gateway policy ...`.

Parity requirements:

- Preserve sub-tabs and drill-downs for Policies, Rule Packs, Judge Prompts, Suppressions, and OPA/Rego.
- Policies tab supports show YAML, activate, delete, validate, list, and create form.
- Rule Packs support active-pack switching, rule list drill-down, rule YAML overlay, and `$EDITOR` handoff for backing rule files.
- Suppressions support inner section cycling for Pre-Judge Strips, Finding Suppressions, and Tool Suppressions, delete, and `$EDITOR` handoff for `suppressions.yaml`.
- Preserve `T` running `policy test`.
- Preserve external editor launch behavior and reload policy/Rego data after editor exit.
- Preserve policy create form.
- Preserve syntax highlighting enough for usability, not necessarily exact colors.
- Preserve exact key routing:
  - `]`/`[` move outer sub-tabs everywhere.
  - `Tab`/right and `Shift+Tab`/left move outer sub-tabs except on Suppressions.
  - Policies: `r` local reload, `l` command `policy list`, `s`/`Enter` YAML detail, `a` activate, `d` delete, `v` validate, `n`/`+` create.
  - Rule Packs: `Enter` activates a different pack and runs `policy reload`, or opens the active pack's rule list; rule rows use `Enter` for YAML detail and `e` for `$EDITOR`.
  - Suppressions: `Tab`/`Shift+Tab` move inner sections, `d` deletes and saves, `Enter`/`e` edits `suppressions.yaml`.
  - OPA/Rego: `t` toggles tests, `v` validates, `r` reloads, `T` runs `policy test` in-panel, and `E` edits the selected Rego file.
- `policy test` is an in-panel runner with bounded timeout and captured stdout/stderr, not a normal Activity-panel command.
- `$EDITOR` fallback is `vi`; the terminal is released while editing and policy/Rego state is reloaded after editor exit.

Mouse/click:

- Sub-tabs are Textual tabs.
- Rows and action controls use widgets.

Tests:

- Form validation.
- Policy test command.
- Tab click changes active sub-view.
- Create/delete/activate argv.
- External editor launch contract.

### Logs

Data sources:

- Gateway/watchdog log files.
- Gateway JSONL activity and structured event logs where current Go parser supports them.

Parity requirements:

- Live tail.
- Pause/resume with Space.
- Filter with `/`.
- Event-type/severity/action chips.
- Filter presets: All, No Noise, Important, Errors, Warnings+, Scan, Drift, Guardrail.
- Structured Verdicts filters: action, event type, and severity, including `HIGH+`.
- Exact keys: `left`/`h` and `right`/`l` switch sources; `up`/`k`, `down`/`j`, `pgup`, and `pgdown` move cursor and pause; `g` jumps to start and pauses; `G` jumps to newest and resumes live tail; `f` cycles presets; `1`-`8` select presets directly; `e` toggles Errors; `w` toggles Warnings+.
- Verdicts-only chip keys: `a` cycles action, `t` cycles event type, and `s` cycles severity; while searching, those letters append to the search query instead.
- `Enter` opens structured detail for Verdicts/OTEL rows and raw-line detail for Gateway/Watchdog rows.
- `R` opens redaction toggle and `N` opens notifications toggle from Logs when search is inactive.
- Redaction indicator, including explicit `RAW` badge when redaction is disabled.
- Detail view for structured events.
- `J` on Verdicts opens the SQLite-backed judge response viewer for the last 20 responses, with correlation IDs, latency, inspected/judge model, parse errors, fail-closed state, prompt template, input hash, and redacted raw response where present.
- Scroll position semantics and "new lines since" status.

Mouse/click:

- Chips are clickable.
- Log rows/details selectable where supported.

Tests:

- Parser coverage for lifecycle, diagnostic, verdict, scan, finding, activity, egress, raw.
- Pause keeps scroll stable.
- Filter chip clicks.
- Redaction indicator.

### Audit

Data sources:

- Audit store.

Parity requirements:

- Append-only audit history listing.
- Filter support.
- Detail modal.
- Same keybindings for navigation and details.
- Exact keys: `j`/down and `k`/up navigate, `Enter` opens detail, `Esc` closes detail, `r` refreshes from SQLite, and `e` exports JSON to `defenseclaw-audit-export.json`.
- Audit export must add an Activity entry, finish it with success/failure, and show a toast.

Mouse/click:

- Row click selects.
- Double click opens detail.

Tests:

- Store rows render.
- Filter.
- Detail.
- Click open detail.

### Activity

Data sources:

- Command executor event stream.
- Gateway activity JSONL.

Parity requirements:

- Commands and Mutations sub-tabs.
- Command start/output/done entries.
- Terminal mode for latest command output.
- Scroll.
- Structured mutation diff open/close.
- Cancellation state.
- `!` reruns the most recent command when valid.
- Result metadata card mirrors Go: origin, category, risk, masked argv, elapsed/duration, config reload, restart completion, doctor cache refresh, and suggested next action.

Mouse/click:

- Sub-tabs clickable.
- Command/mutation rows selectable.
- Diff expand button clickable.

Tests:

- Output append.
- Finish metadata.
- Cancel.
- Mutation parse.
- Click diff expand.

### Tools

Data sources:

- `defenseclaw tool list` / status or audit/config-derived rules.

Parity requirements:

- Tool block/allow/unblock surface.
- Scoped/global state display.
- Action dispatch parity.
- Tools are audit-store action rows of type `tool`, not scanned inventory items.
- Scoped target names preserve the raw `tool@scope` string for CLI dispatch.
- Direct keys: `o` action menu, `r` refresh from audit store, `Enter` detail, `Esc` close detail.
- There is intentionally no scan action and no dedicated text filter in the Go Tools panel.
- Tool action menu state rules:
  - Blocked: info, unblock, allow.
  - Allowed: info, unblock, block.
  - Default/active: info, block, allow.

Mouse/click:

- Row selection and action buttons.

Tests:

- Empty tools.
- Scoped/global display.
- Action argv.
- Click action dispatch.

### AI Discovery

Data sources:

- `/api/v1/ai-usage`.
- `defenseclaw agent ...` commands.

Parity requirements:

- Same sub-views and filters as Go panel.
- Components/processes/models/signals confidence display.
- Refresh/scan command.
- Disabled/offline/empty states.
- Offline placeholder must mention that the AI discovery snapshot is not yet available, that the panel is waiting for `/api/v1/ai-usage`, and that persistent blank state may indicate gateway/token mismatch.
- Header must collapse zero churn counts, always keeping active and files scanned plus updated age when available.
- Confidence columns render band plus clamped percentage, e.g. `high (91%)`, and repeated confidence for the same visible component group is blanked after the first row.
- `r` performs an immediate AI usage poll. `Enter` opens/closes per-row detail. `Esc` closes detail first, then clears filter. `/` starts filter through the global filter path.
- Detail header omits empty component text and shows `<state> · <product> · <component (ecosystem)> x N signal(s)` shape.
- Detail rows expose signature/name/signal ID, detector/source, runtime PID/user/uptime/command, first/last seen, and last active when present.

Mouse/click:

- Tabs, filters, rows, refresh button clickable.

Tests:

- Snapshot parse.
- Confidence sorting.
- Filter behavior.
- Click refresh dispatches scan/poll.

### Registries

Data sources:

- Config registry sources.
- `~/.defenseclaw/registries/<id>/index.json`.
- `defenseclaw registry ...`.

Parity requirements:

- Sources / Entries / Approved sub-tabs.
- Sync one/source, sync all, approve, reject, remove source.
- Source kind labels.
- Registry attribution back to Skills/MCPs.
- Empty/error states.
- Keymap:
  - `1`, `2`, `3` switch Sources, Entries, Approved.
  - `r` refreshes config/index cache in memory.
  - `s` syncs the selected source; on Entries/Approved it syncs that row's source.
  - `S` syncs all enabled sources.
  - `a` approves the selected entry with `registry approve <source> <name> --type <type> --json`.
  - `x` rejects the selected entry with `registry reject <source> <name> --type <type> --json`.
  - `d` removes a source only from Sources tab with `registry remove <id> --non-interactive --json`.
- Empty states must match the current operator guidance:
  - Sources: no registry sources configured, run `defenseclaw registry add` or use Setup wizard.
  - Entries: sync a source to populate the view.
  - Approved: no entries approved yet, press `a` on Entries.
- Registry badges on Skills/MCPs truncate long IDs at the same visual budget and preserve the full value in detail.

Mouse/click:

- Sub-tabs clickable.
- Source/entry rows selectable.
- Action buttons.

Tests:

- Index parse.
- Source action argv.
- Approve/reject argv.
- Attribution propagation.
- Click sync/approve.

### Setup

Data sources:

- Config.
- Credential snapshot.
- Readiness checks.
- Health.
- Doctor cache.
- CLI setup commands.

Parity requirements:

- Wizards mode and Config mode.
- Wizard list and descriptions.
- Wizard forms for connector setup, credentials, LLM, local observability, token rotation, custom providers, skill scanner, MCP scanner, gateway, guardrail, Splunk, observability, webhooks, sandbox, registries.
- Config editor sections and field kinds.
- Complete config field catalog and `applyConfigField` behavior, including the high-risk fields enumerated in the Mandatory UI Parity Inventory.
- Required field validation.
- Secret masking/reveal behavior.
- Config diff preview.
- Save path routes through existing CLI-compatible/audited behavior.
- Restart readiness queue.
- Restart queue controls: `G` runs queued restart, `C` clears queued restart, and successful gateway restart detection clears the queue.
- Config editor controls: `S` review/save, `R` revert from disk, validation blocks save, and last-saved feedback is visible.
- Readiness matrix supports focused checks and one-key/click fix actions for failing checks.
- Redaction and notification modals.
- Uninstall/reset modal behavior.
- Audit Sinks and Webhooks editors resume back to the editor after running enable/disable/remove/test/show/migrate commands.

Mouse/click:

- Wizard rows clickable.
- Form controls are native widgets.
- Save/cancel/apply buttons are native widgets.
- Choice fields use `Select`, booleans use `Switch` or `Checkbox`.

Tests:

- Every wizard builds expected argv.
- Required field validation blocks submit.
- Choice/bool/string/password field behavior.
- Config diff.
- Save audit/activity.
- Credential row set/refresh clicks.
- Redaction/notification toggles.
- Uninstall/reset confirmation.

## Modal And Overlay Parity

Required modal/screen set:

- Help overlay.
- Detail modal.
- Command palette.
- Command preview.
- Action menu.
- MCP set form.
- Mode picker.
- Redaction toggle.
- Notifications toggle.
- Uninstall/reset confirmation.
- Config diff.
- First-run/Setup fallback.

Rules:

- Modal close behavior must be consistent: `Esc` closes, `Enter` confirms when a primary action is focused, `Tab` moves focus.
- Mouse click outside modal may close only if current Go behavior has an equivalent. Otherwise require explicit Cancel/Close.
- Destructive actions require confirmation or existing `--yes` semantics exactly as today.

## Styling And Layout

Use Textual CSS under `cli/defenseclaw/tui/app.tcss`.

Visual target:

- The TUI should feel like a polished, futuristic security operations console: dark, crisp, high-contrast, data-dense, and responsive.
- The look should be slick without becoming noisy. This is an operator tool, not a marketing page: prioritize scanability, fast recognition of state, and calm high-signal motion.
- Visual polish is a product requirement, not an optional pass after parity. A panel is not complete until it satisfies both feature parity and the visual/interaction quality gates below.

Color system:

| Token | Hex | Use |
|---|---:|---|
| `surface-base` | `#070A12` | App background |
| `surface-panel` | `#0D1220` | Primary panel background |
| `surface-raised` | `#121A2B` | Modals, command palette, active panels |
| `surface-hover` | `#18233A` | Hovered rows, clickable controls |
| `surface-selected` | `#203251` | Selected rows, focused list items |
| `border-muted` | `#27324A` | Low-emphasis borders and separators |
| `border-active` | `#38BDF8` | Active focus border |
| `text-primary` | `#E6F1FF` | Main text |
| `text-secondary` | `#9FB2CC` | Labels, metadata |
| `text-muted` | `#64748B` | Disabled/help text |
| `accent-cyan` | `#22D3EE` | Primary futuristic accent, active tabs, key focus |
| `accent-blue` | `#60A5FA` | Links, secondary active state |
| `accent-violet` | `#A78BFA` | AI discovery, command palette highlights |
| `accent-green` | `#34D399` | Success/pass/allow/clean |
| `accent-amber` | `#FBBF24` | Warning, stale, medium severity |
| `accent-orange` | `#FB923C` | Elevated warning / high latency |
| `accent-red` | `#F87171` | Failure/error/critical/block |
| `accent-pink` | `#F472B6` | Judge/PII/exfil high-signal tags only |

Color constraints:

- Keep the app predominantly dark neutral with cyan/blue/violet accents. Do not let the UI become a flat one-hue blue/purple theme.
- Red and green must be strong, consistent semantic signals:
  - green means success, pass, allow, clean, saved, completed
  - red means failure, error, critical, blocked, denied, destructive
- Red, amber, and green are reserved for state semantics and must not be used as decorative accents.
- Every foreground/background pair must meet a practical terminal contrast check in the default theme.
- Support degraded terminals:
  - 24-bit color: full palette.
  - 256-color: nearest palette fallback.
  - no color / `NO_COLOR`: semantic labels and symbols still carry meaning.
- Provide a high-contrast variant if the default palette fails in common terminals or accessibility QA.

Component style:

- Use rounded-first visual language. Primary panels, modals, command drawers, action menus, toasts, and detail panes should use Textual `border: round` where the terminal renders Unicode borders correctly.
- Avoid Textual's default boxy feel by overriding default borders, padding, focus colors, table cursor colors, and modal surfaces in `app.tcss`.
- Terminal rounded corners are still character-cell borders, not pixel-perfect GUI radii. If a terminal cannot render rounded borders cleanly, fall back to `solid` borders with the same spacing and colors.
- Cards/panels should use subtle rounded borders and title bars, not stacked decorative boxes.
- Active focus must be obvious: border color, row background, and key hint should agree.
- Use compact badges for state/severity/source: `RUNNING`, `WARN`, `BLOCK`, `ALLOW`, `STALE`, `OPENCLAW`, `registry:<id>`.
- Use segmented controls for tab-like filters and chips for scope/category filters.
- Use native Textual form widgets for editable controls:
  - `Switch` / `Checkbox` for booleans.
  - `Select` / `OptionList` for finite choices.
  - `Input` / `MaskedInput` for strings and secrets.
  - `TextArea` for YAML/Rego views or edits where multiline input is required.
  - `Button` for clear commands.
- Use `DataTable` row hover/cursor styling everywhere lists are actionable.
- Use `Sparkline` where it improves trend comprehension without stealing space: gateway health latency, recent event volume, AI discovery confidence trend, or command duration history.
- Use `ProgressBar` for long-running scans/setup commands when progress can be inferred. If true progress is unavailable, use a spinner plus elapsed time, not a fake percentage.
- Use `LoadingIndicator` or skeleton rows for async loads so panels do not feel blank or frozen.
- Use `RichLog` for command/log streams with subtle timestamp dimming and semantic highlights.

Motion and animation:

- Motion should communicate liveness, not decorate.
- Required animations:
  - Command running spinner with elapsed time.
  - Health polling pulse or subtle status refresh marker.
  - Loading indicator for async list loads.
  - Rounded loading panel state for panels waiting on gateway/audit/config data, using `LoadingIndicator` or skeleton rows.
  - Toast slide/fade equivalent where Textual supports it, or a timed appearance/disappearance if not.
  - Highlight flash on rows updated by a refresh or command completion.
  - Success/failure completion flash: green for successful command completion, red for failed command completion.
- Optional animations:
  - Progress animation for scan/setup operations.
  - Short shimmer/skeleton for tables while loading.
  - Soft pulse for stale/error badges, capped so it does not distract.
- Animation limits:
  - Respect `NO_COLOR`, reduced-motion config if added, and non-interactive environments.
  - Avoid global blinking. Critical alerts may pulse subtly, but text must remain readable at all times.
  - Animations must not reorder layout, resize widgets, or shift rows.

Polished UX requirements:

- Every panel must have a clear empty state with one primary next action.
- Every destructive action must have an explicit confirmation with a concise consequence statement.
- Every command preview must show masked argv, origin, and expected effect before execution when the command is destructive or config-mutating.
- Every async action must have a complete feedback loop: queued, running, succeeded, failed, or cancelled.
- Success and failure feedback must be visually distinct:
  - success: green badge/toast, duration, affected object count when known
  - failure: red badge/toast, error summary, exit code when applicable, suggested next action
- Toasts should be short, semantic, and actionable:
  - success: command completed, config saved, scan finished
  - warning: stale data, gateway offline, partial load
  - error: command failed, parse failed, auth denied
- Use consistent verbs across buttons and menus: Scan, Allow, Block, Unblock, Enable, Disable, Quarantine, Restore, Remove, Sync, Approve, Reject, Test, Save, Cancel.
- Prefer one-click primary actions only when they are non-destructive. Destructive or persistent mutations must pass through preview/confirm behavior already present in the Go TUI.
- Support both expert keyboard flow and mouse-first flow. Mouse polish must not remove any keyboard affordance.
- Show breadcrumbs or compact context labels in nested views, e.g. `Policy / Rule Packs / default / secrets.yaml`.
- Preserve scroll/cursor state when switching away from and back to a panel.
- After a command finishes, return focus to the most relevant panel control and visibly refresh affected data.
- Surface stale data explicitly with timestamps: `updated 12s ago`, `doctor stale`, `gateway offline`.
- For setup/config forms, group fields with compact section headings and inline hints. Avoid dumping huge forms without navigation.
- For secrets, default to masked values, support explicit reveal, and automatically re-mask when leaving the form/modal.

UX enhancement inventory:

- Global command palette with fuzzy filtering, category chips, keyboard hints, and mouse-selectable rows.
- Direct command input for raw `defenseclaw ...` commands with validation, completions, previews, and Activity streaming.
- Contextual hint engine that suggests panel-specific next actions without interrupting focused work.
- Persistent status strip with gateway state, active connector, running task count, latest alert severity, and stale-data indicator.
- Background task drawer in Activity showing running, completed, failed, and canceled tasks with elapsed time.
- Toast stack for short-lived feedback plus durable Activity entries for anything operationally important.
- Inline detail panes for tables where the Go TUI currently opens details, reducing modal churn while keeping modal fallback on narrow screens.
- Split-pane layouts for dense views: table on the left/top, structured detail on the right/bottom.
- Context breadcrumbs for nested setup, policy, registry, and detail screens.
- Filter chips with counts where counts are cheap to compute; no count should require an expensive scan on every render.
- Row-level action menus for Alerts, Skills, MCPs, Plugins, Tools, Registries, Audit, and Setup editors.
- Mini trend widgets using `Sparkline` only where the trend adds operational value.
- Validation messages beside edited fields, not only after Save.
- Diff preview before config writes, policy updates, registry approvals, and destructive changes.
- Empty, loading, partial-error, and offline states for every service-backed panel.
- Help overlay that reflects the active panel and hides irrelevant shortcuts.

Visual acceptance gates:

- All colors come from shared theme tokens in `app.tcss`; panel code must not hard-code decorative color literals.
- Rounded borders are the default for operator-facing surfaces. Any square/boxy surface must be intentional and documented in code.
- Every top-level panel has a visually distinct active/focused state, empty state, loading state, and error/partial-load state.
- The header, footer/status strip, command palette, modals, tables, badges, chips, forms, and toasts share one coherent visual language.
- The default theme must look intentionally designed at 80x24, 120x40, and 180x50, not merely functional.
- Animations must improve perceived responsiveness and must be disabled or reduced cleanly when configured.
- The TUI must remain readable in screenshots, terminal recordings, tmux, and remote SSH sessions.

Required style tokens:

- `state-success`
- `state-failure`
- `state-running`
- `state-warn`
- `state-error`
- `state-disabled`
- `state-muted`
- `selection`
- `badge`
- `badge-high`
- `badge-medium`
- `badge-low`
- `badge-info`
- `command-running`
- `command-success`
- `command-failure`
- `command-cancelled`
- `surface-base`
- `surface-panel`
- `surface-raised`
- `surface-hover`
- `surface-selected`
- `border-muted`
- `border-active`
- `text-primary`
- `text-secondary`
- `text-muted`
- `accent-cyan`
- `accent-blue`
- `accent-violet`
- `accent-green`
- `accent-amber`
- `accent-orange`
- `accent-red`
- `accent-pink`
- `focus-ring`
- `toast-success`
- `toast-warning`
- `toast-error`
- `toast-info`
- `chip-active`
- `chip-inactive`
- `row-updated`

Layout requirements:

- Minimum supported size: 80x24.
- Preferred/default QA size: 120x40.
- Wide QA size: 180x50.
- Header tabs collapse gracefully on narrow terminals, preserving numeric shortcuts.
- Tables must avoid changing column widths on every refresh unless necessary.
- Long targets/paths use middle or right truncation based on panel convention.
- Secrets are always masked unless an explicit reveal state is active.
- The visual design must be verified in all three QA sizes with screenshots or Textual SVG snapshots.
- No text may overlap, wrap into controls incoherently, or make buttons/filters change width during hover/focus.
- Interactive widgets must have hover, focus, disabled, active, loading, success, warning, and error states where applicable.
- Panels should avoid nested card-on-card composition. Use bands, tables, modals, and clear separators instead.

## Observability And Audit Behavior

The Python TUI must preserve TUI-launched command observability:

- Each command start and completion is visible in Activity.
- Mutating commands continue producing existing audit events through CLI/gateway logic.
- TUI-specific operator activity, such as config saves or command previews, must log through `defenseclaw audit log-activity` or a Python equivalent that writes the same event shape.
- Trace/request IDs displayed by Alerts and Logs must continue to come from the same audit/gateway fields.
- TUI refresh duration must continue to be recorded as `defenseclaw.slo.tui.refresh` when telemetry is enabled.
- Filter changes must continue to emit TUI filter traces/metrics for panels that emit them today: Alerts, Logs, Skills, and MCPs.
- Background/focus state should be consumed where Textual exposes it so theme/focus affordances do not regress from the Go app's background-color/focus handling.

## Test Plan

Add tests under `cli/tests/tui/` or `cli/defenseclaw/tui/tests/` depending on existing package test conventions. Prefer `cli/tests/tui/` if the test suite already discovers there cleanly.

Per-feature test gate rule:

- Every feature, panel, modal, command path, sub-tab, filter, and mouse target must carry its tests in the same implementation step that adds or ports the behavior.
- A feature is not parity-complete until the migration ledger names the Go oracle file/test, the Python implementation target, the test tier that covers it, and the exact command used to run that coverage.
- Each applicable feature must have unit/model coverage, Textual app integration coverage, mouse/click coverage, snapshot coverage for visible UI, agent-tty live coverage for PTY/child-process workflows, and negative/empty/error-state coverage.
- If a gate is not applicable, the ledger entry must say why. Missing tests, broad manual inspection, or "covered elsewhere" without naming the test are not acceptable completion evidence.
- Feature implementation order must be test-first or test-in-same-patch. A feature can be stubbed visually during a phase, but it cannot move from stub/partial to parity-complete without passing its gates.
- Regressions found by screenshots, agent-tty, or Go oracle comparison must become automated tests before the regression is considered fixed.
- Subagents can own individual panels or feature clusters only after the shared shell, service fakes, test fixtures, and ledger gate schema are in place. Each subagent handoff must include the Go source/test files, expected Python targets, and required test commands for its slice.
- The default launch path cannot switch from Go to Textual until every feature gate is either covered by a named passing test or explicitly marked not applicable with rationale.

Required coverage by feature type:

| Feature type | Required test gates |
| --- | --- |
| Pure parser/state/model logic | Unit/model tests, Go oracle mapping, negative/error fixtures |
| Visible panel or sub-tab | Unit/model tests, Textual app tests, snapshots at 80x24/120x40/180x50, empty/loading/error states |
| Clickable table, chip, button, tab, or modal control | Textual `Pilot.click()` tests, keyboard equivalent tests, focus/hover/disabled state snapshots where stable |
| Command, mutation, or setup action | Command preview/masking tests, fake subprocess runner tests, Activity/audit assertions, failure feedback tests |
| Interactive PTY or child-process workflow | agent-tty smoke or scenario test, teardown/interrupt behavior, command output assertions |
| Visual polish or animation/loading state | Snapshot coverage, reduced/no-color fallback checks, no-overlap resize checks |
| Go parity bug fix | Reproducing test named after the Go oracle or bug, plus the narrowest app/model test that would fail before the fix |

Test tiers:

1. Pure unit tests:
   - parsers
   - DTO conversions
   - registry matching
   - raw command-line parsing and rejection of shell operators
   - raw `defenseclaw ...` command completion fixtures
   - hint-engine ranking
   - shortcut precedence and `q` non-quit behavior
   - command masking
   - path resolution
   - filter logic
   - status precedence

2. Service tests:
   - fake audit store
   - fake gateway HTTP server
   - fake CLI subprocess runner
   - temp config/data dirs
   - doctor cache and registry cache file fixtures

3. Textual app tests:
   - `App.run_test()` plus `Pilot.press()` and `Pilot.click()`.
   - Keyboard and click parity for every panel.
   - Modal open/confirm/cancel flows.
   - Direct `:` command input accepts valid raw `defenseclaw ...` commands, rejects arbitrary host commands, and opens previews for mutating commands.
   - Hint bar updates when focus, selected row, gateway status, or panel state changes.
   - `Ctrl+C` quits globally, while `q` is local close/no-op and must not exit the app.
   - Activity `!` reruns the previous command.
   - Alerts `y` copies selected alert details through Textual/terminal clipboard support where available.
   - Alerts bulk action tests cover `space`, `a`, `A`, `X`, `x`, `c`, `C`, scan parent expansion, and synthetic `gw:` ID skipping.
   - Logs key tests cover source switching, pause-on-cursor-move, `g`/`G`, `f`, `e`, `w`, `1`-`8`, Verdicts `a`/`t`/`s`, raw-line detail, structured detail, `R`, `N`, and `J`.
   - Audit export test asserts `e` writes `defenseclaw-audit-export.json`, updates Activity, and emits success/failure toast state.
   - Policy key tests cover `]`/`[`, Suppressions inner Tab routing, Policies `l`/`s`/`a`/`d`/`v`/`n`, Rule Packs activation/reload/detail/editor, Suppressions delete/editor, and OPA/Rego `t`/`v`/`r`/`T`/`E`.
   - Resize tests at 80x24, 120x40, 180x50.

4. Snapshot tests:
   - Use Textual screenshot/SVG support or normalized text snapshots.
   - Snapshot only stable structural screens; avoid overfitting volatile timestamps/spinners.
   - Capture visual snapshots for every top-level panel at 80x24, 120x40, and 180x50.
   - Capture modal snapshots for command palette, command preview, action menu, config diff, setup wizard form, and detail modal.
   - Snapshot color-token usage in 24-bit and 256-color fallback modes where practical.
   - Snapshot rounded border treatment for panels, modals, toasts, command input, and action menus.

5. End-to-end smoke:
   - Launch `defenseclaw tui` in a PTY.
   - Assert startup screen appears.
   - Press `?`, `1`, `2`, `0`, `:`, `Esc`, `Ctrl+C`.
   - Run one harmless command through command palette, such as `version`.
   - Confirm pressing `q` on a normal panel does not terminate the app.

6. Visual/interaction polish tests:
   - Verify every interactive widget has focus and hover styling.
   - Verify rounded surfaces render cleanly or degrade to the documented solid-border fallback.
   - Verify row update highlight appears and then settles without changing row height.
   - Verify loading states appear for async list loads.
   - Verify command spinner/elapsed time appears during a fake long-running command.
   - Verify command success uses green feedback and command failure uses red feedback.
   - Verify hint suggestions match deterministic fixture expectations.
   - Verify RAW redaction badge appears when redaction is disabled.
   - Verify reduced/no-color mode still communicates state through text labels.
   - Verify destructive command previews mask secrets and highlight irreversible effects.
   - Verify first-run `Ctrl+R` builds the exact `init --non-interactive --yes --json-summary` argv for every connector/profile/scanner/bool combination.
   - Verify mode picker hotkeys select and confirm the correct connector setup alias, including `claudecode` -> `claude-code`.
   - Verify redaction, notifications, and uninstall modals render the correct consequence copy and dispatch the exact CLI argv.
   - Verify MCP set form field order, validation, UTF-8 backspace, `Ctrl+U`, env parsing, and skip-scan truthy values.
   - Verify Registries rejects unsafe source IDs before index reads.
   - Verify Setup section names, field keys, field kinds, choice options, hints, summaries, and `applyConfigField` write behavior against fixtures derived from the Go implementation.

7. Telemetry parity tests:
   - Refresh cycle records `defenseclaw.slo.tui.refresh` when telemetry is enabled.
   - Filter changes emit panel/filter old/new metadata where the Go TUI emits it today.

Parity mapping:

- For every Go test under `internal/tui/*_test.go`, record one of:
  - `ported`
  - `covered by broader Python test`
  - `obsolete because Textual widget handles it`
  - `deferred with issue`
- Obsolete must be used sparingly and must include rationale.

Mouse regression minimum:

- Header tab click changes panel.
- Command palette row click runs/previews command.
- Action menu row click dispatches command.
- Setup wizard row click opens form.
- Setup boolean/choice click changes value.
- Modal Run/Cancel clicks work.
- DataTable row click selects row in Alerts, Skills, MCPs, Plugins, Audit, Registries.

## Migration Phases

### Phase 0: Parity Harness

Deliverables:

- Add Textual dependency.
- Add package skeleton.
- Add Python `CmdEntry` registry for all current commands.
- Add registry parity tests against Click/gateway.
- Add fake subprocess runner and fake services.
- Add rounded app shell with header, status strip, hint bar, empty panels, keyboard routing, and shared theme tokens.
- Add direct command input for raw `defenseclaw ...` commands.
- Add hint-engine fixture tests.

Exit criteria:

- `defenseclaw tui --backend textual` launches.
- Keyboard panel navigation works.
- Command palette can run `version`.
- Direct command input can run `defenseclaw version`, reject `ls`, and reject shell operators.
- Rounded border snapshots pass at 80x24, 120x40, and 180x50.
- Hint bar shows deterministic panel-aware hints.
- Registry parity tests pass.

### Phase 1: Read-Only Core

Deliverables:

- Overview.
- Alerts.
- Audit.
- Logs.
- Activity command output for non-interactive commands.
- Health polling.
- Doctor cache.
- Status strip.

Exit criteria:

- Operator can monitor gateway/alerts/audit/logs.
- Mouse row selection works in Alerts and Audit.
- `doctor` refresh updates cache.
- Smoke PTY test passes.

### Phase 2: Asset Management

Deliverables:

- Skills.
- MCPs.
- Plugins.
- Tools.
- Shared action menu.
- MCP set form.
- Plugin connector gating.

Exit criteria:

- All asset list JSON parsing works.
- Scan/block/allow/unblock/enable/disable/quarantine/restore/info dispatch parity.
- Click action flows covered.
- Activity refreshes relevant panels after command completion.

### Phase 3: Inventory, AI Discovery, Registries

Deliverables:

- Inventory panel with category chips and fast-scan preset.
- AI Discovery panel.
- Registries panel.
- Registry attribution propagation to Skills/MCPs.

Exit criteria:

- AIBOM scan scope args match Go behavior.
- AI usage polling/refresh works.
- Registry sync/approve/reject/remove-source commands dispatch correctly.
- Click behavior is stable after resize.

### Phase 4: Policy

Deliverables:

- Policy panel.
- Sub-tabs.
- Create form.
- Policy test command.
- External editor launch integration.
- Gateway policy command dispatch.

Exit criteria:

- Policy CRUD/test/evaluate/reload flows match Go behavior.
- Form validation and command previews covered.

### Phase 5: Setup

Deliverables:

- Setup wizards.
- Config editor.
- Credential surface.
- Readiness checks.
- Observability sinks and webhook editors.
- Redaction/notifications modals.
- Config diff and save path.
- Uninstall/reset modals.

Exit criteria:

- Every setup wizard builds command argv matching Go tests.
- Config save emits the same activity/audit shape.
- Credential setting and refresh work.
- All setup click tests pass.

### Phase 6: Default Flip

Deliverables:

- `defenseclaw tui` defaults to Textual.
- No-args `defenseclaw` TTY handoff defaults to Textual.
- `defenseclaw-gateway tui` compatibility behavior.
- Docs update.
- Release notes.

Exit criteria:

- Full Python test suite passes.
- Relevant Go tests still pass.
- E2E smoke passes on macOS and Linux.
- Manual QA checklist signed off.

### Phase 7: Go TUI Retirement

Deliverables:

- Remove Go TUI default path.
- Remove Go TUI code after compatibility window.
- Remove Bubble Tea/Lip Gloss/Bubbles deps if unused.
- Delete Go-only TUI docs or replace with migration notes.

Exit criteria:

- No Go package imports `internal/tui`.
- Gateway runtime commands unaffected.
- Installer no longer depends on Go TUI assets.

## Manual QA Checklist

Run on macOS and Linux:

- Fresh install with no config.
- Existing config with gateway offline.
- Existing config with gateway running.
- OpenClaw connector.
- Non-OpenClaw connector.
- Narrow terminal 80x24.
- Normal terminal 120x40.
- Wide terminal 180x50.
- Terminal.app/iTerm2 or equivalent.
- tmux.
- SSH session.
- No mouse support or mouse reporting disabled.

Workflow checks:

- Launch/quit.
- Navigate all panels by keyboard.
- Navigate all panels by mouse.
- Open/close help.
- Run command palette command.
- Type and run `defenseclaw version` through the direct command input.
- Confirm direct command input rejects arbitrary host commands and shell operators.
- Cancel running command.
- Run `doctor`, see Overview update.
- Select alert and open detail.
- Scan one skill.
- Block/unblock one tool in a temp config.
- Toggle inventory scope chips.
- Tail logs and pause/resume.
- Open setup wizard, change a field, cancel.
- Preview config diff, cancel.
- Run registry sync against a temp file registry.

Visual/UX checks:

- Validate the default dark theme in a truecolor terminal.
- Validate 256-color fallback in a terminal with limited color support.
- Validate `NO_COLOR=1` mode.
- Confirm rounded borders render correctly, or the documented solid-border fallback activates cleanly.
- Confirm active focus is visible in every panel and modal.
- Confirm hover/click targets feel stable after terminal resize.
- Confirm animations communicate progress/liveness without distracting from text.
- Confirm loading indicators appear for async panels and command execution without leaving blank screens.
- Confirm successful commands use green feedback and failed commands use red feedback.
- Confirm contextual hints change correctly with selected rows, focused controls, offline gateway state, and empty panels.
- Confirm no widget changes size when hovered, focused, loading, or selected.
- Confirm all empty states have one clear primary next action.
- Confirm toasts appear, auto-dismiss, and never cover command input or destructive confirmations.

## Risks And Mitigations

Risk: Textual version drift.

- Mitigation: pin `textual>=8.2,<9.0`, run test suite before bumping, and use public widget APIs only.

Risk: Python TUI performance on large logs/tables.

- Mitigation: virtualized/efficient widgets, capped rows, incremental refresh, background workers, and parser benchmarks for large fixtures.

Risk: subprocess/PTY differences across terminals.

- Mitigation: keep non-interactive paths piped, use PTY only for known interactive commands, add PTY smoke tests on macOS/Linux, and preserve direct CLI fallback.

Risk: accidental business logic fork.

- Mitigation: all mutations route through CLI/gateway commands; services that call Python functions must be read-only or explicitly audited.

Risk: setup panel scope explodes.

- Mitigation: implement Setup last, after registry/executor/panel primitives are stable. Treat each wizard as a separately testable form.

Risk: mouse behavior still varies by terminal.

- Mitigation: rely on Textual widget events, keep keyboard parity complete, test in tmux/SSH/no-mouse modes, and do not make mouse the only path for any command.

## Completion Definition

The migration is complete when:

- `defenseclaw tui` and no-args `defenseclaw` launch the Python Textual TUI by default.
- All documented Go TUI panels and workflows have Python equivalents.
- All command registry entries are present and parity-tested.
- Every current Go TUI test is ported, covered, or explicitly retired with rationale.
- Mouse tests cover all major clickable workflows.
- The full visual system is implemented through shared tokens, with polished widget states and motion behavior passing snapshot/manual QA.
- Rounded app chrome, loading states, red/green success/failure feedback, contextual hints, and direct `defenseclaw ...` command entry all pass automated and manual QA.
- Manual QA passes on macOS and Linux.
- Docs no longer describe the Go TUI as the primary implementation.
- The Go TUI can be removed without losing runtime gateway functionality.
