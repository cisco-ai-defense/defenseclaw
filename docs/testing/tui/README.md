# DefenseClaw TUI Testing Plan

A complete, per-panel test plan for the Textual TUI under `cli/defenseclaw/tui/`,
designed to drive every user-input location through automated tests using the
[Textual testing guide](https://textual.textualize.io/guide/testing/) and
`pytest-textual-snapshot`.

---

## 0. How to use this plan

1. The **main agent** builds the framework foundation described in
   [`00-framework-foundation.md`](./00-framework-foundation.md). This is a
   prerequisite for every sub-agent task because they all share one `pytest`
   harness, one set of fixtures, one snapshot directory, and one set of helpers.
2. Once the foundation is green (i.e. `make cli-test` and `make cli-test-snap`
   both pass on `main` with zero new failures), the user spawns one sub-agent
   per plan file. Each sub-agent is invoked with the standard contract in
   [`99-sub-agent-contract.md`](./99-sub-agent-contract.md) and the file
   path of its assigned plan.
3. Sub-agents may NOT touch each other's files. Each plan declares exactly
   which test files it owns and which production files it is allowed to read.
   Production code changes are out-of-scope unless they are explicitly listed
   as a *known defect* in the plan; in that case the sub-agent files a
   follow-up issue and writes the test xfail-marked with a TODO so the
   refactor doesn't block the test sweep.

---

## 1. What's being tested

The TUI is a single-process Textual app rooted at
`cli.defenseclaw.tui.app.DefenseClawTUI` with the following user-input surface:

### 1.1 Panels (14)

| # | Panel | Route key | Owns file | Plan |
|---|---|---|---|---|
| 01 | Overview | `1` | `panels/overview.py` (re-exports `services/overview_state.py`) | [`panels/01-overview.md`](./panels/01-overview.md) |
| 02 | Alerts | `2` | `panels/alerts.py` | [`panels/02-alerts.md`](./panels/02-alerts.md) |
| 03 | Skills | `3` | `panels/skills.py` + `services/catalog_state.py` | [`panels/03-skills.md`](./panels/03-skills.md) |
| 04 | MCPs | `4` | `panels/mcps.py` + `services/catalog_state.py` | [`panels/04-mcps.md`](./panels/04-mcps.md) |
| 05 | Plugins | `5` | `panels/plugins.py` + `services/catalog_state.py` | [`panels/05-plugins.md`](./panels/05-plugins.md) |
| 06 | Inventory | `6` | `panels/inventory.py` + `services/inventory_state.py` | [`panels/06-inventory.md`](./panels/06-inventory.md) |
| 07 | Policy | `7` | `panels/policy.py` + `services/policy_state.py` (5 sub-tabs) | [`panels/07-policy.md`](./panels/07-policy.md) |
| 08 | Logs | `8` | `panels/logs.py` + `services/gateway_log_views.py` | [`panels/08-logs.md`](./panels/08-logs.md) |
| 09 | Audit | `9` | `panels/audit.py` | [`panels/09-audit.md`](./panels/09-audit.md) |
| 10 | Activity | `a` | `panels/activity.py` + `executor.py` | [`panels/10-activity.md`](./panels/10-activity.md) |
| 11 | Tools | `T` | `panels/tools.py` | [`panels/11-tools.md`](./panels/11-tools.md) |
| 12 | AI Discovery | `V` | `panels/ai_discovery.py` + `services/ai_discovery_state.py` | [`panels/12-ai-discovery.md`](./panels/12-ai-discovery.md) |
| 13 | Registries | `R` | `panels/registries.py` + `services/registry_cache.py` | [`panels/13-registries.md`](./panels/13-registries.md) |
| 14 | Setup | `0` | `panels/setup.py` + `services/setup_state.py` (18 wizards) | [`panels/14-setup.md`](./panels/14-setup.md) |
| 15 | First Run | n/a (boot-only) | `panels/first_run.py` | [`panels/15-first-run.md`](./panels/15-first-run.md) |

### 1.2 Modal screens (13)

| # | Screen | Trigger | File | Plan |
|---|---|---|---|---|
| 16 | Command Palette | `Ctrl+K` / `:` | `screens/command_palette.py` | [`screens/16-command-palette.md`](./screens/16-command-palette.md) |
| 17 | Panel Jumper | `Ctrl+P` | `screens/panel_jumper.py` | [`screens/17-panel-jumper.md`](./screens/17-panel-jumper.md) |
| 18 | Mode Picker | Overview `m` | `screens/mode_picker.py` | [`screens/18-mode-picker.md`](./screens/18-mode-picker.md) |
| 19 | Quick Start Wizard | Policy `n` | `screens/quick_start.py` + `creator/wizard.py` | [`screens/19-quick-start.md`](./screens/19-quick-start.md) |
| 20 | Playground | Policy `p` | `screens/playground.py` + `creator/playground_model.py` | [`screens/20-playground.md`](./screens/20-playground.md) |
| 21 | Command Preview | Setup wizard run | `screens/command_preview.py` | [`screens/21-command-preview.md`](./screens/21-command-preview.md) |
| 22 | Consequence (+ Redaction / Notifications / Uninstall) | toggle gates | `screens/consequence.py`, `screens/redaction.py`, `screens/notifications.py`, `screens/uninstall.py` | [`screens/22-consequence-family.md`](./screens/22-consequence-family.md) |
| 23 | MCP Set Form | MCPs `s` | `screens/mcp_set_form.py` | [`screens/23-mcp-set-form.md`](./screens/23-mcp-set-form.md) |
| 24 | Setup Resource Editor | Setup audit/webhook rows | `screens/setup_resource_editor.py` | [`screens/24-setup-resource-editor.md`](./screens/24-setup-resource-editor.md) |
| 25 | Config Diff | Setup save | `screens/config_diff.py` | [`screens/25-config-diff.md`](./screens/25-config-diff.md) |
| 26 | Detail / Judge History | row-level `Enter` | `screens/detail.py`, `screens/judge_history.py` | [`screens/26-detail-judge-history.md`](./screens/26-detail-judge-history.md) |
| 27 | Creator Command Palette | Playground `Ctrl+K` | `creator/command_palette.py` (logic) + Playground modal | [`screens/27-creator-command-palette.md`](./screens/27-creator-command-palette.md) |

### 1.3 Widgets / global concerns (5)

| # | Surface | File | Plan |
|---|---|---|---|
| 28 | Hint Bar | `widgets/hint_bar.py` | [`widgets/28-hint-bar.md`](./widgets/28-hint-bar.md) |
| 29 | Action Menu (widget + screen) | `widgets/action_menu.py` | [`widgets/29-action-menu.md`](./widgets/29-action-menu.md) |
| 30 | Toasts | `widgets/toasts.py` | [`widgets/30-toasts.md`](./widgets/30-toasts.md) |
| 31 | Native Metrics + Status Strip | `widgets/native_metrics.py`, `widgets/status_strip.py` | [`widgets/31-native-metrics-status-strip.md`](./widgets/31-native-metrics-status-strip.md) |
| 32 | App-shell global bindings & command line | `app.py` `BINDINGS`, `command_line.py`, `executor.py` | [`widgets/32-app-shell-bindings.md`](./widgets/32-app-shell-bindings.md) |

Total: **32 plans + 1 framework foundation + 1 sub-agent contract = 34 files**.

---

## 2. Test taxonomy used by every plan

Every plan follows the same five-layer pyramid so a sub-agent never has to
re-invent the test classes:

| Layer | What it asserts | Where the test runs | When to write it |
|---|---|---|---|
| **L1 - Pure model tests** | Pure data transitions on the panel model (no `App`, no `Pilot`). Cheap, run first. | A plain sync `def test_*()` calling the model directly. | Every state transition in `handle_key`, `cycle_*`, `set_*`, `apply_filter`, `*_intent()` factories, and parsers (`_coerce_*`, `parse_*`). |
| **L2 - App-shell integration** | The panel mounts inside the real `DefenseClawTUI`, accepts keys via `pilot.press`, refreshes the body/detail static, and produces the right `Hint Bar` text. | Async `def test_*()` using `app.run_test(size=...)`. | Every key binding listed in `app.py` `BINDINGS` and every panel-specific binding routed through `_panel_keys()`. |
| **L3 - Modal screen flow** | Pressing the trigger key opens the modal, the modal accepts its inputs, and dismissing with a value mutates the parent model correctly. | Async `pilot` test that asserts `isinstance(app.screen, FooScreen)`, drives keys, then asserts the panel reacted after `pilot.pause()`. | Every modal listed in §1.2. |
| **L4 - Snapshot scenes** | The rendered SVG matches a saved golden at 80x24, 120x40, and 180x50. Catches visual regressions a Pilot test can miss (color, spacing, overflow). | `def test_*(snap_compare)`. | Every panel's "empty", "populated", "filter-active", and "detail-open" states; every modal's "default", "with-input", and "error" states. |
| **L5 - Property / regression** | Hypothesis-style invariants ("cursor never escapes row bounds", "filter never crashes on UTF-8 noise", "any key sequence ends in a deterministic state") plus targeted regressions for shipped bugs. | Plain pytest with `hypothesis` strategies when needed; otherwise hand-written. | At least one invariant per panel; one regression per fixed bug. |

**Skipping L4 is forbidden** — Textual's runtime layout depends on terminal
geometry and even small CSS regressions are invisible without snapshots.

---

## 3. Naming and file layout

```
cli/tests/tui/
  conftest.py                       # framework foundation (built by main agent)
  helpers/
    __init__.py
    pilot.py                        # press_keys, dump_body, screen_class
    fakes.py                        # FakeConnector, FakeStore, FakeExecutor
    builders.py                     # tiny builders for AlertEvent, MCPRow, ...
  __snapshots__/                    # SVG goldens
  test_<surface>_model.py           # L1 only
  test_<surface>_app.py             # L2 + L3
  test_<surface>_snapshot.py        # L4 only
  test_<surface>_invariants.py      # L5 only
```

**Rule:** every sub-agent **must** put L1 and L5 in their own file so they can
run under `unittest discover` if anyone re-points the makefile. L2/L3/L4 share
files because they share the `app.run_test` boilerplate.

---

## 4. Quality gates each plan must hit before being marked done

A sub-agent's PR is mergeable only if **all** of the following are true:

1. `make lint` passes (`ruff` clean).
2. `make cli-test` passes (the synchronous suite still loads — async tests
   must not break unittest discovery).
3. `uv run pytest cli/tests/tui/ -v` passes locally.
4. `uv run pytest cli/tests/tui/ --snapshot-update` produces zero new diffs
   on the second run (i.e. snapshots are stable).
5. Coverage for the assigned model file is ≥ **90 %** statement coverage
   measured by `pytest --cov=defenseclaw.tui.<surface> --cov-report=term-missing`.
   Uncovered lines must be explicitly justified in the PR description
   (typically: defensive `except` blocks for unreachable cases, or
   platform-specific branches like Windows clipboard fallbacks).
6. At minimum, one snapshot exists at each of the three QA terminal sizes
   `(80, 24)`, `(120, 40)`, `(180, 50)`. Sub-agents may add more if a
   particular surface only manifests its bug at a particular size.
7. Every key listed in the plan's "Input surface" inventory has at least one
   L1 *or* L2 test that exercises it. Cross-reference is required in the
   plan's "Coverage matrix" section.
8. Hint bar text after each L2 interaction is asserted (not just present).
9. No real subprocess, network, or filesystem write outside `tmp_path`.
   Every `defenseclaw <cmd>` invocation must go through `FakeExecutor`.

---

## 5. Master "input surface" inventory (executive summary)

The full surface is enumerated per-panel in each file, but here is the global
list a reviewer can scan in one pass:

* **Global keys** (`app.py` `BINDINGS`): `Ctrl+C`, `q`, `?`, `:`, `Ctrl+K`,
  `Ctrl+P`, `Y`, `Ctrl+S`, `D`, `Tab`, `Shift+Tab`.
* **Panel switch keys**: `1` 2` `3` `4` `5` `6` `7` `8` `9` `a` `T` `V` `R`
  `0` (see `PANELS` in `app.py`).
* **Per-panel keys**: routed via each panel's `handle_key()` and via
  `app._panel_keys(...)` in `app.py` (which composes filter input, cursor
  moves, tab cycling, action chips, and detail open/close per panel).
* **Mouse clicks**: every panel has clickable action chips in
  `.panel-controls`, plus DataTable row clicks; every modal has buttons.
* **Filter inputs**: `Input` widgets in catalog panels (Skills/MCPs/Plugins/
  Tools/Audit/Alerts/Logs/Inventory), in the command line, in modal forms.
* **Forms**: Setup wizard `WizardFormField`, Quick Start wizard, Playground,
  MCP set form, Setup resource editor, First Run form.
* **Async surfaces**: command executor events (`CommandEvent`), AI usage
  fetch (`_fetch_ai_usage`), policy reloads, registry refresh, doctor cache,
  gateway log tail, stdin pipe to subprocess.

Every sub-agent file enumerates *its* slice of this list under
"Input surface inventory" and asserts coverage.

---

## 6. Index

* [`00-framework-foundation.md`](./00-framework-foundation.md) - **build this first**
* [`99-sub-agent-contract.md`](./99-sub-agent-contract.md) - sub-agent invocation template

* Panels: [`panels/`](./panels/)
* Screens: [`screens/`](./screens/)
* Widgets / global: [`widgets/`](./widgets/)
