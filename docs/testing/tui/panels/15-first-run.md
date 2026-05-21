# 15 — First Run panel test plan

The First Run panel is the embedded fallback wizard shown if no `config.yaml`
exists. It collects the basics (connector, profile, scanner mode, judge,
fail mode, HITL, ...) and dispatches `defenseclaw init`.

---

## 1. Files under test

* `cli/defenseclaw/tui/panels/first_run.py`

---

## 2. File layout

```
cli/tests/tui/
  test_first_run_model.py
  test_first_run_app.py
  test_first_run_snapshot.py
  test_first_run_invariants.py
```

(Existing `test_first_run_launcher.py` and `test_first_run_panel.py` should
be CONSULTED but NOT modified. New tests live in the four files above.)

---

## 3. Input-surface inventory

### 3.1 Keys (`FirstRunPanelModel.handle_key`)

| ID | Key | Effect |
|---|---|---|
| K01 | `↑/k` | cursor up |
| K02 | `↓/j` | cursor down |
| K03 | `←/h` | cycle field value backward |
| K04 | `→/l` / `Enter` / `Space` | cycle field value forward |
| K05 | `Ctrl+R` | submit (returns intent) |

### 3.2 Fields (`default_first_run_fields`)

* F01 Connector (`choice`, 9 options)
* F02 Profile (`choice`, 2)
* F03 Scanner Mode (`choice`, 3)
* F04 LLM Judge (`bool`)
* F05 Hook Fail Mode (`choice`, 2)
* F06 HITL (`bool`)
* F07 HITL Min Severity (`choice`, 4)
* F08 Start Gateway (`bool`)
* F09 Verify (`bool`)

### 3.3 Clicks

* C01 — Click on a field row → set cursor.
* C02 — Click on field value → cycle (or toggle for bool).

### 3.4 Async surfaces

* A01 — Submit via Ctrl+R → returns `SetupCommandIntent` carrying the argv.
* A02 — `decide_first_run_prompt(answer, ...)` — pure decision used by app
  bootstrap before mounting the panel.

---

## 4. L1 — Pure model tests

### 4.1 Cursor

* `test_cursor_up_clamps_at_zero`.
* `test_cursor_down_clamps_at_last_field`.

### 4.2 Cycle

* `test_cycle_bool_toggles` per bool field.
* `test_cycle_choice_advances_through_options_and_wraps`.
* `test_cycle_choice_backwards_wraps`.
* `test_cycle_no_op_on_invalid_cursor`.

### 4.3 Args / intent

* `test_args_contains_init_non_interactive_yes_json_summary`.
* `test_args_carries_connector_profile_scanner_mode`.
* `test_args_with_judge_when_judge_true`.
* `test_args_no_judge_when_judge_false`.
* `test_args_with_fail_mode_open` and `closed`.
* `test_args_in_observe_profile_skips_hitl_flags`.
* `test_args_in_action_profile_with_hitl_includes_severity`.
* `test_args_in_action_profile_no_hitl_omits_severity`.
* `test_args_with_start_gateway_true` / `false`.
* `test_args_with_verify_true` / `false`.
* `test_intent_label_and_category`.

### 4.4 `decide_first_run_prompt`

Parametrize:

```python
@pytest.mark.parametrize("answer,skip,tty_ok,spawn_error,expected_outcome,expected_spawn", [
    (None, True,  True,  None, "unavailable", False),  # explicit skip
    (None, False, False, None, "unavailable", False),  # no TTY
    ("y", False, True, None, "handed", True),
    ("yes", False, True, None, "handed", True),
    ("",  False, True, None, "handed", True),         # blank == yes
    ("n", False, True, None, "declined", False),
    ("no", False, True, None, "declined", False),
    ("maybe", False, True, None, "unavailable", False),
    ("y", False, True, RuntimeError("boom"), "unavailable", True),
])
def test_decide_first_run_prompt(answer, skip, tty_ok, spawn_error,
                                 expected_outcome, expected_spawn): ...
```

### 4.5 Prompt text

* `test_first_run_prompt_text_includes_config_path`.

### 4.6 Empty state

* `test_empty_state_text_mentions_ctrl_r`.

---

## 5. L2 + L3

The panel is shown ONLY when `first_run_model.active=True`. Construct the
app with `first_run=True` and assert:

* `test_first_run_panel_shows_when_first_run_true`.
* `test_first_run_panel_does_not_show_when_first_run_false`.
* `test_first_run_panel_replaces_setup_panel_layout`.

For each K and C ID, assert state mutation via `app.first_run_model`.

Ctrl+R submit:

```python
async def test_first_run_ctrl_r_invokes_executor_with_init_argv(piloted_app, fake_executor):
    async with piloted_app(first_run=True) as (app, pilot):
        await pilot.press("ctrl+r")
        await pilot.pause()
        assert fake_executor.calls[-1][0][:2] == ("defenseclaw", "init")
```

---

## 6. L4 — Snapshot scenes

* `first_run_initial`
* `first_run_cursor_on_profile`
* `first_run_action_profile_hitl_visible`
* `first_run_observe_profile_hitl_hidden`
* `first_run_judge_enabled`
* `first_run_submission_running`

× 3 sizes = **18 SVGs**.

---

## 7. L5

* `test_cycle_round_trip_for_each_field_returns_to_initial` (Hypothesis on
  cycle counts).
* `test_handle_key_keeps_cursor_in_bounds` (Hypothesis on key sequences).
* `test_args_never_contains_duplicate_flags` (Hypothesis on field values).

---

## 8. Known defects to file

* If HITL min severity remains in argv after switching profile observe→action
  →observe → P1.
* If Ctrl+R is pressed during the bootstrap probe and the app then double-
  submits → P0.

---

## 9. Coverage matrix

Per K, C, A, F ID.

---

## 10. Deliverables

* [ ] Four files.
* [ ] 18 SVGs.
* [ ] Coverage `panels/first_run.py` ≥ 95 %.
* [ ] Matrix complete.
