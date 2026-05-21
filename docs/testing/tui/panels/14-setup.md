# 14 — Setup panel test plan (SECOND-LARGEST)

The Setup panel is two-mode (wizards / config-editor) and exposes **18
wizards** plus a credential manager, a uninstall modal, restart queue, and
save-restart hints. After Policy it is the densest plan.

---

## 1. Files under test

* `cli/defenseclaw/tui/panels/setup.py` (~3400 lines)
* `cli/defenseclaw/tui/services/setup_state.py` (~740 lines)

---

## 2. File layout

```
cli/tests/tui/
  test_setup_state_helpers.py             # L1 - pure helpers in setup_state.py
  test_setup_model_sections.py            # L1 - build_setup_sections + field math
  test_setup_model_wizards_part1.py       # L1 - wizards 0-8
  test_setup_model_wizards_part2.py       # L1 - wizards 9-17
  test_setup_model_credentials_restart.py # L1 - credentials, restart queue
  test_setup_model_uninstall_toggles.py   # L1 - uninstall + redaction + notifications
  test_setup_app.py                       # L2 + L3
  test_setup_snapshot.py                  # L4
  test_setup_invariants.py                # L5
```

Splitting L1 across six files keeps each below ~400 lines and lets the
sub-agent commit incrementally.

---

## 3. Modes

* M01 — `wizards` (default landing)
* M02 — `config` (raw config editor)

`select_section`, `move_section`, `current_section`, and `current_field`
only apply in M02.

---

## 4. Wizards

Eighteen wizards from `SetupWizard` enum (see `panels/setup.py`):

| Idx | Name |
|---|---|
| 0 | Connector Setup |
| 1 | Credentials |
| 2 | LLM |
| 3 | Local OTel |
| 4 | Token Rotation |
| 5 | Custom Providers |
| 6 | Skill Scanner |
| 7 | MCP Scanner |
| 8 | Gateway |
| 9 | Guardrail |
| 10 | Splunk |
| 11 | Observability |
| 12 | Webhooks |
| 13 | Sandbox |
| 14 | Registries |
| 15 | Notifications Routing |
| 16 | AI Discovery |
| 17 | Splunk Dashboards |

---

## 5. Input-surface inventory

### 5.1 Mode and section keys

| ID | Key | Effect |
|---|---|---|
| K01 | `Tab/Shift+Tab` | switch between wizards / config modes |
| K02 | `1/2` (mode-level) | jump mode |
| K03 | `↑/↓` `j/k` | M02: move active line within section / M01: cursor wizard list |
| K04 | `Tab` (within M02 sections) | next section |
| K05 | `Shift+Tab` (within M02 sections) | previous section |
| K06 | `[/]` or section-tab chips | switch section in M02 |
| K07 | `g/G` `Home/End` | jump |

### 5.2 Per-field keys (M02 config editor)

| ID | Key | Effect |
|---|---|---|
| Kf01 | `Enter` | enter "edit" mode on string/int/password fields |
| Kf02 | `Space` | toggle bool fields |
| Kf03 | `→/←` | cycle choice fields |
| Kf04 | `Esc` | cancel edit |
| Kf05 | typed chars | append to value being edited |
| Kf06 | `Backspace` | drop char |
| Kf07 | `Enter` (in edit mode) | commit value |

### 5.3 Per-wizard keys (M01)

| ID | Key | Effect |
|---|---|---|
| Kw01 | `Enter` on wizard row | open `WizardForm` |
| Kw02 | `Esc` in form | close form |
| Kw03 | `Tab/Shift+Tab` in form | move field cursor |
| Kw04 | `Space`/`Enter` on form field | toggle / cycle / edit |
| Kw05 | `Ctrl+R` (commonly) | run wizard via executor |
| Kw06 | `Ctrl+T` | toggle reveal of password fields |
| Kw07 | typed chars | append to focused field |

### 5.4 Other keys

| ID | Key | Effect |
|---|---|---|
| Ko01 | `s` | save config changes (M02) — pushes Config Diff modal (plan 25) |
| Ko02 | `c` | open credentials view |
| Ko03 | `u` | open Uninstall modal |
| Ko04 | `t` | trigger restart-now (if pending) |
| Ko05 | `r` | toggle Redaction (pushes Redaction consequence modal) |
| Ko06 | `n` | toggle Notifications (pushes Notifications consequence modal) |
| Ko07 | `e` | edit a row resource (audit sink / webhook — opens Setup Resource Editor) |
| Ko08 | `?` | show wizard `WIZARD_HOW_TO` overlay |

### 5.5 Clicks

* C01 — Mode chips (Wizards / Config).
* C02 — Wizard list row click.
* C03 — Wizard "Run" button.
* C04 — Section tab chips (M02).
* C05 — Field row click → set active line.
* C06 — Bool toggle click.
* C07 — Choice cycle click.
* C08 — Reveal-password button.
* C09 — Save chip.
* C10 — Credentials chip.
* C11 — Uninstall chip.
* C12 — Restart-now chip.

### 5.6 Async surfaces

* A01 — Each wizard's executor invocation; argv asserted against `build_wizard_args`.
* A02 — Follow-up intents queued (`SetupCommandIntent.follow_up`): registry,
  splunk; assert ordering and that next step only runs if prior succeeds.
* A03 — Credential snapshot loading from JSON.
* A04 — Save sequence: pushes Config Diff modal, on confirm pushes restart
  prompt or queues restart.
* A05 — Restart queue side effects: assert reasons accumulate.

### 5.7 Forms data

* `WizardFormField(label, kind, value, options, hint, required)`.
* Kinds: `bool`, `string`, `choice`, `int`, `password`, `section`, `preset`, `whtype`, `regid`.
* `missing_required_fields` reports which labels are blank.

---

## 6. L1 — Pure model tests (across six files)

### 6.1 `test_setup_state_helpers.py`

Test every helper in `services/setup_state.py`:

* `apply_config_field` for each kind.
* `get_config_value` with dotted keys.
* `set_config_value` writes back via attr or dict.
* `looks_like_secret_value` heuristic table.
* `mask_secret` truncates correctly.
* `split_csv` strips whitespace.
* `parse_credential_rows` for each shape (dict, list of dicts, JSON string).
* `validate_config_field` for each kind (bool false-strings, int range,
  choice membership, password rules, string regex if any).
* `validation_errors` aggregates.
* `build_readiness_checks` for healthy / degraded / failing configs.
* `config_diff` between two `cfg` objects.

### 6.2 `test_setup_model_sections.py`

* `build_setup_sections` order matches the existing snapshot test
  (`test_setup_panel.py:test_setup_config_sections_match_go_catalog_order`).
* Per section, assert field set membership (Notifications, Guardrail,
  Scanners, AI Discovery, Audit Sinks, Webhooks, OTel, Asset Policy, etc.).
* `action_matrix_fields(prefix, cfg)` shape.
* `_field`, `_header`, `_value`, `_fmt_config_version` helpers.

### 6.3 `test_setup_model_wizards_part1.py` (wizards 0-8)

For each of the 9 wizards in this range:

* `wizard_form_defs(wizard, cfg)` returns the expected `WizardFormField` set.
* `build_wizard_args(wizard, fields)` returns argv that matches the CLI
  contract.
* `missing_required_fields(wizard, fields)` finds blanks for required
  fields only.
* `render_wizard_value(field, reveal=False)` masks passwords; `reveal=True`
  shows raw.
* For wizards that have a `_build_<wizard>_args` helper, assert the helper
  directly.

### 6.4 `test_setup_model_wizards_part2.py` (wizards 9-17)

Same coverage as part1 for wizards 9-17. Special cases:

* `splunk_wizard_follow_up_intents` — assert follow-up chain ordering.
* `registry_wizard_follow_up_intents` — same.
* `observability_wizard_fields(preset_id)` — parametrize over preset IDs.
* `webhook_wizard_fields(channel_type)` — parametrize over channel types
  (`slack`, `pagerduty`, `email`, ...).
* `splunk_dashboards_wizard_fields` and `_build_splunk_dashboards_args`.
* `notifications_routing_wizard_fields` and `notifications_routing_intents`
  (multi-channel routing).

### 6.5 `test_setup_model_credentials_restart.py`

* `set_credential_snapshot` replaces rows and bumps loaded_at.
* `selected_credential` indexes into rows.
* `credential_action("set"|"unset"|"refresh")` returns the right
  `SetupCommandIntent`.
* `credential_empty_state` text variations.
* `RestartQueue.with_reason` accumulates reasons without duplication.
* `queue_restart` / `clear_restart_queue` / `restart_now_intent` lifecycle.
* `mark_restart_started` toggles correctly.
* `save_restart_hints` reflects pending restart reasons.

### 6.6 `test_setup_model_uninstall_toggles.py`

* `redaction_desired_action` per current state.
* `redaction_toggle_intent` argv.
* `redaction_consequence_copy` content for on/off.
* `notifications_desired_action` per current state.
* `notifications_toggle_intent` argv.
* `notifications_consequence_copy` content.
* `uninstall_args_for_option` for each option (`dry-run`, `keep-data`,
  `wipe-data`).
* `uninstall_intent` for each option.
* `UninstallModalState`: show / hide, cursor up/down, select-by-hotkey.

---

## 7. L2 + L3 — App-shell integration (`test_setup_app.py`)

Route via key `0`. Cover each K / Kf / Kw / Ko / C / A ID.

### 7.1 Mode switch

```python
async def test_setup_starts_in_wizards_mode(piloted_app):
    async with piloted_app() as (app, pilot):
        await pilot.press("0")
        assert app.setup_model.mode == "wizards"

async def test_setup_tab_switches_to_config_mode(piloted_app):
    async with piloted_app() as (app, pilot):
        await pilot.press("0", "tab")
        await pilot.pause()
        assert app.setup_model.mode == "config"
```

### 7.2 Wizard form open / submit

```python
async def test_setup_credentials_wizard_emits_correct_argv(piloted_app, fake_executor):
    async with piloted_app() as (app, pilot):
        await pilot.press("0")
        # Cursor to "Credentials" wizard:
        for _ in range(SetupWizard.CREDENTIALS):
            await pilot.press("down")
        await pilot.press("enter")
        await pilot.pause()
        # Now in the form. Fill it...
        # ...press Ctrl+R to run...
        await pilot.press("ctrl+r")
        await pilot.pause()
        assert fake_executor.calls[-1][0][:3] == ("defenseclaw", "setup", "credentials")
```

Repeat for at least one wizard per "build args" helper (12 distinct argv
shapes total).

### 7.3 Save flow

* M02 → edit a field → press `s` → assert Config Diff modal pushed.
* Confirm modal → assert restart prompt (Consequence modal) pushed if
  setup_model.queue is non-empty.

### 7.4 Toggles

* `r` → assert RedactionToggleScreen pushed.
* `n` → assert Notifications consequence pushed.
* `u` → assert Uninstall modal pushed.

### 7.5 Setup resource editor (`e`)

* Cursor on an audit-sink row → `e` → assert SetupResourceEditorScreen pushed.

---

## 8. L4 — Snapshot scenes

* `setup_wizards_mode_initial`
* `setup_wizards_running_executor` (one wizard mid-run)
* `setup_wizards_form_open_with_password_hidden`
* `setup_wizards_form_open_with_password_revealed`
* `setup_wizards_form_missing_required_field_indicator`
* `setup_config_mode_section_general`
* `setup_config_mode_section_notifications`
* `setup_config_mode_section_audit_sinks`
* `setup_config_mode_field_edit_in_progress`
* `setup_config_mode_diff_overlay`
* `setup_credentials_view_populated`
* `setup_uninstall_modal_open`
* `setup_restart_queue_pending`

× 3 sizes = **39 SVGs**.

---

## 9. L5

* `test_wizard_argv_round_trips_through_build_wizard_args` (Hypothesis on
  field values).
* `test_missing_required_fields_matches_field_required_flag` (Hypothesis).
* `test_restart_queue_reason_accumulation_dedupes` (Hypothesis).
* `test_uninstall_modal_cursor_in_bounds` (Hypothesis on key sequences).

---

## 10. Known defects to file

* If `set_current_field_value` writes a value that fails `validate_config_field`
  silently → file P1.
* If the restart queue retains a reason after `clear_restart_queue` is called
  during a save flow → P1.
* If `e` (edit resource) opens the editor on a non-resource row without
  surfacing an error toast → P2.

---

## 11. Coverage matrix

Per K / Kf / Kw / Ko / C / A / wizard ID.

---

## 12. Deliverables

* [ ] Nine test files (six L1 + L2 + L4 + L5).
* [ ] 39 SVGs.
* [ ] Coverage `panels/setup.py` ≥ 90 %.
* [ ] Coverage `services/setup_state.py` ≥ 95 %.
* [ ] Matrix complete.
* [ ] All 18 wizards have at least one passing argv assertion.
