# TUI architecture

Grep anchors are function or class names. `app.py` is about 14k lines, so line
numbers go stale within a day. Use `grep -n "def _body_text" cli/defenseclaw/tui/app.py`.

## File map (`cli/defenseclaw/tui/`)

| Path | What lives there |
|---|---|
| `app.py` | `DefenseClawTUI(SandboxPanelMixin, App)`: compose, key routing, every per-panel if-chain, intent pipeline, pollers. `PANELS`, `PANEL_SHORTCUTS`, `_panel_key`, `_communicate_captured` are module-level. |
| `sandbox_panel.py` | `SandboxPanelMixin`: all Sandboxes I/O (REST, event stream, workers). This is the template for a panel mixin. |
| `panels/<x>.py` | Panel models (`AlertsPanelModel`, `SetupPanelModel`, ...). Newer panels just re-export from `services/<x>_state.py` (see `panels/sandboxes.py`). |
| `panels/setup.py` | Setup model: wizards (`SetupWizard`, `WIZARD_COMMANDS`), field builders, config editor sections, `apply_config_field`. |
| `panels/first_run.py` | First-run launcher model (`DefenseClawTUI(first_run=True)`). |
| `services/*_state.py` | Pure models (no I/O). See the list below. |
| `screens/*.py` | `ModalScreen[T]` pickers and dialogs: `command_preview`, `consequence`, `config_diff`, `mode_picker`, `model_picker`, `panel_jumper`, `theme_picker`, `detail`, `sandbox_*`, `trusted_paths_editor`, `setup_resource_editor`, `mcp_set_form`, `uninstall`, `notifications`, `judge_history`, and `field_editor` (all Setup text entry). |
| `widgets/hint_bar.py` | `HintEngine.hint_for(HintState, StatusModel)`, with one branch per panel. |
| `widgets/status_strip.py`, `toasts.py`, `action_menu.py`, `native_metrics.py` | Status pills, toasts, `ActionMenu`/`MenuAction` (picker list), Overview metric tiles. |
| `executor.py` | `CommandExecutor.run(binary, args, *, stdin_input, env_overrides)` yields `CommandEvent` values (`start`/`output`/`done`). `resolve_subprocess_argv` maps `defenseclaw` to `sys.executable -m defenseclaw.main`. |
| `windows_process.py` | Job Object process tree used by the executor on Windows. |
| `command_line.py` | `ParsedCommand` (binary, args, display_name, category, risk, needs_preview, stdin_input, env_overrides), plus palette text parsing that rejects shell operators. |
| `registry.py`, `registry_data.py` | Command palette. `GO_PARITY_REGISTRY` rows are `(tui_name, binary, argv, description, category, needs_arg, arg_hint)`. |
| `models.py` | `HintState`, `StatusModel`, shared small dataclasses. |
| `theme.py` | `ThemeTokens` / `DEFAULT_TOKENS`, `SEVERITY_STYLES`, `STATE_STYLES`. |

Tests live in `cli/tests/tui/`. `fixtures.py` provides `snapshot_app(tmp, setup_config=None)`,
`snapshot_config` and `screen_text` (the fake-data app shared by smoke tests and the scripts).

## Shared-surface render pipeline

`_render_chrome()` is the single re-render path. It updates the tab strip and
badges (`_update_tab_labels`), then:

1. `_body_text()` switches on `self.active_panel`. It sets
   `self._table_columns`/`self._table_rows` from the model and returns
   the body markup string. It must stay pure and cheap, because
   `set_interval(2.0, self._periodic_refresh)` re-runs it.
2. `_safe_body_renderable(text)` parses the markup and falls back to plain text
   on `MarkupError`/`MissingStyle` (a safety net, not a licence to skip escaping).
3. `_render_panel_table()` fills the shared `DataTable#panel-table` (deltas via
   `_update_panel_table_delta`). `_active_table_cursor()` restores the cursor.
4. `_render_detail_panel()` shows `_detail_text()` in `#detail-panel`.
5. `_render_panel_control_visibility()` shows only `#<active>-controls`.
   `_render_panel_controls()` calls `_sync_<panel>_controls()` for per-view buttons.
6. `_refresh_hint()` builds a `HintState` (including `panel_view`) and
   `HintBar.refresh_hint`. `_status_text()` fills `#status`.

Heavy panels (Overview, Alerts, Logs, Audit) build a render snapshot off the UI
thread (`_run_deferred_panel_render`, `_build_panel_render_snapshot`) and apply
it with generation checks. Any direct `_render_chrome` bumps
`_panel_render_generation`, so stale snapshots are dropped.

Widget ids: `#header #tabs #body-scroll #body #panel-table #detail-panel
#<panel>-controls #command-input #command-palette #command-progress #hint #status #toasts`.

## Key routing (`DefenseClawTUI.on_key`)

1. A modal is open (`len(self.screen_stack) > 1`): the app does nothing and the
   modal owns keys.
2. The command palette is open or focused: `_handle_command_palette_key`.
3. The panel table has focus and the key is `up`/`down`: DataTable handles it
   (unless an overlay blocks it).
4. `_handle_active_panel_key(event)` normalizes with `_panel_key(event)` (it
   lowercases capitals except `A C E G J M N R S T V X`, and names
   enter/escape/space/tab/backspace/ctrl+x), then goes to the active
   panel's `model.handle_key` → `_apply_<panel>_action`. If it returns True,
   the key is stopped and default-prevented.
5. `tab`/`shift+tab` go to the next or previous panel.
6. `PANEL_SHORTCUTS[event.key.lower()]` switches panel (hidden panels are
   swallowed silently).

App `BINDINGS` (`:` palette, `?` help, `ctrl+p` jumper, `q` local close,
`ctrl+c` quit, ...) run through Textual's binding machinery. Check them before
claiming a key.

## Intent → preview → executor → refresh

```
model.handle_key(key) -> Action(kind, intent)
  -> _apply_<panel>_action -> run_worker(self._confirm_and_run_intent(intent), exclusive=False, thread=False)
_confirm_and_run_intent(intent)
  risk == "destructive" -> _confirm_and_run_destructive_intent -> ConsequenceModalScreen(danger)
  terminal              -> _confirm_and_run_terminal_intent (sandbox connect / launch)
  else                  -> ParsedCommand(..., stdin_input=intent.secret_stdin, env_overrides=...)
                           -> _confirm_and_run_parsed -> push_screen_wait(CommandPreviewScreen)
  -> run_worker(_run_command(binary, args, display_name, stdin_input, env_overrides))
       -> executor.run(...) events -> Activity log + command strip
       -> exit 0: _handle_successful_command(binary, args)   (per-command refresh)
  -> intent.follow_up: each runs only after the previous one finished with exit 0
```

`_handle_successful_command` switches on `args[0]` (`init`, `setup`, `keys`,
`sandbox`, `registry`, `doctor`, catalog mutations via
`_catalog_panel_invalidated_by_command`, and `policy`/`guardrail` for the
Policies panel). New mutating commands need a branch here, or the panel shows
stale data.

For quiet loads (no preview, no Activity entry), use
`await _communicate_captured(binary, args)` → `(returncode, stdout, stderr)`
with a `--json` command, then `model.apply_json(stdout)`. See
`_load_setup_credentials`, `_load_inventory_model` and `_load_catalog_model`.

The Setup config editor is the only direct write:
`apply_config_field` → `ConfigDiffScreen` → `config.save()` (`_save_setup_config`).

## Workers idiom

- For UI flows that await a modal, use
  `self.run_worker(self._open_x(), exclusive=False, thread=False)` and, inside it,
  `result = await self.push_screen_wait(XScreen(...))`.
- For blocking I/O, use `await asyncio.to_thread(fn, ...)` inside an async
  worker (see `_poll_config_once` and `_run_deferred_panel_render`). Never block the event loop.
- Background threads (the sandbox stream) hand results back with
  `call_from_thread` (see `SandboxPanelMixin._deliver_from_thread`).
- Guard re-entry with a flag (`_sandbox_action_running`) and refuse in one line.

## State services (`services/`)

`overview_state` (Overview model, `QUICK_ACTIONS`), `catalog_state` (skills,
mcps, plugins, tools lists and intents), `inventory_state`, `ai_discovery_state`,
`runtime_state`, `sandbox_state` (the latest pure-model template), `setup_state`
(Setup helpers), `policy_state` (Policies panel), `connector_filter` (shared
connector scope), `cli_choices` (wizard choice lists and pack presets),
`config_watch` (config generation polling), `read_repository` (single-thread
SQLite reads), `event_models`/`gateway_log_views`/`v8_event_history` (event
history read models), `registry_cache`, `judge_history`, and `tui_state`
(persisted session state: palette MRU, last panel).

## Theme tokens

`theme.py` `ThemeTokens`: `surface_*`, `border_muted`, `border_active`,
`text_primary/secondary/muted`, `accent_cyan` (#22D3EE, headings), `accent_blue`,
`accent_violet` (#A78BFA, detail titles), `accent_green` (ok), `accent_amber`
(#FBBF24, warn/cancelled), `accent_orange`, `accent_red` (#F87171, danger borders),
and `accent_pink`. The app uses `TOKENS = DEFAULT_TOKENS`. Use tokens in new code
rather than hex literals, and use `SEVERITY_STYLES`/`STATE_STYLES` for
severity and state colouring.
