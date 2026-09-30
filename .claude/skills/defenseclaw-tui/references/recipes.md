# Recipes

Run `scripts/touchpoints.py <panel>` before and after every panel change. Run
`scripts/gap_audit.py --prefix "<command>"` before building on a CLI command,
to see whether it has `--json` and whether it's already in the palette.

## Add a panel (the Sandboxes/Policies mixin recipe)

1. **Model**: create `services/<x>_state.py`. It's pure, with no Textual and no I/O:
   - A `<X>PanelModel` with `cursor`, `view` (if the panel has sub-views),
     `detail_open`, `set_config(cfg)`, `apply_json(stdout)` / `set_snapshot(...)`,
     and `set_error(message)`.
   - `data_table_columns(compact)` / `data_table_rows(compact)` (compact under 100 columns).
   - `handle_key(key) -> <X>PanelAction(kind, intent|None, hint)`, where `kind`
     is one of `none`, `move`, `view`, `detail`, `refresh`, `intent`, and so on.
   - `empty_state()` (says what to do next), `total_count()` for the badge,
     and `<x>_keys_hint(view)` for the hint bar.
   - Optional: re-export it from `panels/<x>.py` like `panels/sandboxes.py`.
2. **Mixin**: create `<x>_panel.py` with a `<X>PanelMixin`. It holds `_<x>_init`,
   `_<x>_mount`, `_schedule_<x>_load` (`run_worker` + `_communicate_captured` +
   `apply_json`), `_<x>_body_text`, `_sync_<x>_controls`,
   `_handle_<x>_control(button_id)` and `_apply_<x>_action(action)`. Add it to
   `class DefenseClawTUI(<X>PanelMixin, SandboxPanelMixin, App[None])`.
3. **app.py touchpoints** (this is exactly what `touchpoints.py` checks):
   - `PANELS`: add `("<x>", "<Key>", "<Label>")`. Don't reorder existing rows
     (Policies = `("policies", "P", "Policies")`, before Setup). The key must not
     collide with the reserved keys (`ux-rules.md`).
   - `__init__`: accept an optional `<x>_model` (so `fixtures.snapshot_app` can
     inject one) and call `self._<x>_init(...)`.
   - `compose`: add `Horizontal(id="<x>-controls", classes="panel-controls hidden")`
     with `Button`s `id="<x>-<verb>"`, sentence-case labels, and tooltips that end with the key `(k)`.
   - `_body_text`: set `self._table_columns`/`_table_rows` and return `_<x>_body_text()`.
   - `_handle_active_panel_key`: `return self._apply_<x>_action(self.<x>_model.handle_key(key))`.
     If a capital must stay distinct, read `event.character` (see the `U` special case for Sandboxes).
   - `_on_table_row_highlighted` / `_on_table_row_selected`: sync `model.cursor`.
     Sandboxes skips "selected" because Enter comes through the key path.
   - `_active_table_cursor`: return `self.<x>_model.cursor`.
   - `_render_panel_control_visibility`: `set_class(self.active_panel != "<x>" or self.help_open, "hidden")`.
   - `_render_panel_controls`: call `_sync_<x>_controls()` (per-view buttons: hide, don't disable).
   - `_on_panel_control_pressed`: `if button_id.startswith("<x>-"): self._handle_<x>_control(button_id)`.
   - `_detail_text`: only if the panel uses `#detail-panel` (Sandboxes uses a detail screen instead).
   - `action_switch_panel`: load or poll on first open (`self._schedule_<x>_load()`).
   - `_panel_total_count`: the badge count.
   - `_apply_config_snapshot`: `self.<x>_model.set_config(new_cfg)`.
   - `_handle_successful_command`: re-load after the CLI commands that change this panel's data.
   - `_help_sections`: a `"<x>"` key sheet that lists exactly the keys `handle_key` handles.
   - `_refresh_hint`: pass `panel_view` if the hint depends on the sub-view.
   - `widgets/hint_bar.py` `HintEngine.hint_for`: add a `panel == "<x>"` branch.
4. **Tests**: unit tests for the model (keys → actions, rows, empty state,
   `apply_json` with malformed input). Add at most 1-2 Pilot tests: the panel
   renders at 80x24 with fixture data, and one journey to a captured argv.
5. **Verify**: `render.py --panel <x> --size 80x24 --size 120x40 --expect "<first row>"`,
   then `demo.py --panel <x>` in tmux.

## Add a picker modal

- Copy `screens/mode_picker.py` (an `ActionMenu` of `MenuAction` rows with
  hotkeys plus a live preview line) or `screens/model_picker.py` (a filter
  `Input` above a list). `_open_connector_filter_picker` shows an inline
  `ActionMenu` picker. Never use `OptionList`.
- `class XPickerScreen(ModalScreen[T | None])`. Escape dismisses `None`, Enter
  dismisses the choice, and the current value is marked `← current`.
- Keep the choice list and preview text in pure functions in the screen module
  (or the state service) so they can be unit-tested without Pilot.
- Open it from the app with:
  ```python
  async def _open_x_picker(self) -> None:
      choice = await self.push_screen_wait(XPickerScreen(current=...))
      if choice is None:
          return
      await self._confirm_and_run_intent(self.<x>_model.intent_for(choice))
  # from a key/button handler:
  self.run_worker(self._open_x_picker(), exclusive=False, thread=False)
  ```
- Tests: pure tests for choices and preview, plus ≤ 2 Pilot tests using a tiny
  harness `App` whose `on_mount` pushes the screen with a result callback.

## Add a mutating action (preview, or danger for destructive)

1. The model builds the intent: `binary="defenseclaw"`, `args=(...)` (a tuple of
   strings, no shell), `label` (verb first, plain words), `category`, and
   `risk` (`"read-only"`, `"mutation"` or `"destructive"`).
2. `handle_key` returns an action carrying the intent. `_apply_<x>_action` calls
   `self.run_worker(self._confirm_and_run_intent(intent), exclusive=False, thread=False)`.
3. For destructive actions (delete or remove files or state that can't be
   undone), set `risk="destructive"`. `_confirm_and_run_intent` then uses
   `ConsequenceModalScreen` with a red border and a danger re-press. Say
   concretely what is lost. For panel-local confirmations that aren't CLI
   intents, build a `ConsequenceModalModel` with `ConsequenceAction(danger=True)`.
4. Add a `_handle_successful_command` branch so the panel refreshes after exit 0.
5. Journey test: press the key, confirm the preview, and assert the captured
   argv from the fake executor.

## Add a secret-bearing action

- The CLI side must accept `--value-stdin` (read one line, strip the newline,
  never echo, and exit 1 when empty). `click.prompt(hide_input=True)` and
  getpass do not read piped stdin.
- The intent's args include `--value-stdin`. The secret goes in
  `intent.secret_stdin` (or `intent.env_overrides` for env-shaped secrets).
  `_confirm_and_run_intent` copies it to `ParsedCommand.stdin_input`, and the
  executor uses a pipe (not a PTY) so nothing echoes.
- Collect the value with `FieldEditorScreen(..., password=True)`. Never put it
  in argv, the preview, the Activity log, toasts or the state file.
- Test: assert the captured `stdin_input` equals the value and that the value
  appears in no argv element or preview text.

## Add a Setup wizard or config field

- Wizard: add a `SetupWizard` member (never change existing enum values), its
  argv in `WIZARD_COMMANDS`, its fields in the `panels/setup.py` field builders,
  and its group and plain name in `panels/setup_catalog.py`. Keys come from
  `panels/setup_keys.py` for the `form` view. Credential args go through the
  secret recipe above. Follow-ups use `intent.follow_up` (these run only after
  exit 0).
- Config field: first confirm the key is modeled by the Python `Config`
  dataclass (`cli/defenseclaw/config.py`) and survives `Config.save()`.
  Unmodeled keys become read-only rows with a hint. Unset bool, int or choice
  means inherit (valid). Save blocks only on errors in fields that were changed.
- Text entry: a printable key on a text row opens `FieldEditorScreen` seeded
  with that character. Never append characters through `_panel_key`.
- Verify: `render.py --keys 0 enter` (form) and `--keys 0 c` (config editor) at
  80x24. The first field must be visible.

## Add a command-palette row

- Add a tuple to `GO_PARITY_REGISTRY` in `registry_data.py`:
  `(tui_name, "defenseclaw", (argv...), description, category, needs_arg, arg_hint)`.
  Use a `tui_name` that reads like the CLI (`policy list`), a sentence-case
  description that starts with a verb, and `needs_arg=True` with an `arg_hint`
  when the argv needs a trailing value.
- Palette commands go through `_confirm_and_run_parsed`, and non-read-only
  ones get the preview.
- Check: `gap_audit.py --prefix "<cmd>"` shows `palette yes`, and
  `render.py --keys : "text:<cmd>" enter` shows the preview.
