# 10 — Activity panel test plan

Activity is special: it's the **live terminal output** of `defenseclaw`
subprocess invocations, plus history + mutations sub-tabs. It owns the
stdin pipe widget. Coverage of `executor.py` lives here.

---

## 1. Files under test

* `cli/defenseclaw/tui/panels/activity.py`
* `cli/defenseclaw/tui/executor.py` (specifically the `CommandEvent` flow
  and the threading-safe append; subprocess launch itself stays mocked)

---

## 2. File layout

```
cli/tests/tui/
  test_activity_model.py
  test_activity_app.py
  test_activity_snapshot.py
  test_activity_invariants.py
```

> `cli/tests/tui/test_executor.py` already exists. The sub-agent should
> read it but write new executor tests into `test_activity_app.py` so
> existing tests don't churn.

---

## 3. Sub-tabs

`ActivityTab`:
* T01 Terminal (live)
* T02 History (past invocations)
* T03 Mutations (gateway/config mutations the agent logged)

---

## 4. Input-surface inventory

### 4.1 Keys

| ID | Key | Effect |
|---|---|---|
| K01 | `1/2/3` | jump to tab |
| K02 | `Tab/Shift+Tab` | cycle tab |
| K03 | `↑/↓` `j/k` | scroll terminal / list |
| K04 | `PgUp/PgDn` | page scroll |
| K05 | `g/G` `Home/End` | jump |
| K06 | `Enter` (history row) | replay (re-run the same argv) |
| K07 | `x` | cancel current running command |
| K08 | `c` | clear history |
| K09 | `y` | copy current terminal output (or current history row) |
| K10 | `Ctrl+S` | save current output to file |
| K11 | any text key | passed to stdin via the stdin pipe widget |

### 4.2 Clicks

* C01 — Tab chips (3).
* C02 — Stdin pipe input.
* C03 — Cancel chip.
* C04 — Clear history chip.
* C05 — History row click.
* C06 — Replay chip.

### 4.3 Async surfaces

* A01 — `CommandEvent(kind="start")` → `add_entry`.
* A02 — `CommandEvent(kind="stdout"/"stderr")` → `append_output`.
* A03 — `CommandEvent(kind="exit", code=N)` → `finish_entry`.
* A04 — Stdin pipe text submitted via `Input` → forwarded to process.
* A05 — `clear_history(_)` removes finished entries only (running entry
  stays).

### 4.4 Data

* `ActivityEntry(label, argv, started_at, finished_at, exit_code, output_lines, status)`.
* Status labels: `running`, `success`, `failure`, `cancelled`.

---

## 5. L1 — Pure model tests

### 5.1 Lifecycle

* `test_add_entry_marks_running`.
* `test_append_output_pushes_lines_in_order`.
* `test_finish_entry_with_exit_zero_marks_success`.
* `test_finish_entry_with_exit_nonzero_marks_failure`.
* `test_finish_entry_with_cancel_marks_cancelled`.
* `test_status_label_per_status`.
* `test_meta_footer_includes_started_and_duration`.

### 5.2 Tab switching

* `test_set_tab_changes_visible_render` (terminal vs history vs mutations).
* `test_set_tab_does_not_reset_terminal_scroll`.

### 5.3 History

* `test_clear_history_removes_finished_entries_only`.
* `test_clear_history_returns_removed_count`.
* `test_select_entry_clamps`.
* `test_count_returns_entries_total`.
* `test_is_running_true_only_if_last_entry_is_running`.

### 5.4 Scroll

* `test_scroll_by_terminal_clamps_to_zero`.
* `test_scroll_by_history_clamps_to_max`.

### 5.5 Mutations

* `test_load_mutations_reads_from_disk_returns_count`.
* `test_render_mutations_shows_empty_state_when_zero`.

### 5.6 Key dispatch

* `test_handle_key_terminal_keys_route_to_terminal_handler`.
* `test_handle_key_mutation_keys_route_to_mutation_handler`.
* `test_handle_key_history_keys_route_to_history_handler`.

---

## 6. L2 + L3 — App-shell integration

Route via key `a`. Cover every K and C ID.

* K06 (replay): assert executor called again with the same argv.
* K07 (cancel): assert `executor.run` returned `.cancel()` is invoked.
* K10 (Ctrl+S): assert file written under `tmp_data_dir` with the
  expected content.
* K11 (stdin): drive `Input` widget; assert the executor's `stdin.write`
  was invoked with the line.

### 6.1 Stdin pipe visibility

```python
async def test_activity_stdin_visible_only_when_command_running(piloted_app, fake_executor):
    async with piloted_app() as (app, pilot):
        await pilot.press("a")
        stdin = app.query_one("#activity-stdin")
        assert stdin.has_class("open") is False
        # Simulate a running command:
        app._strip_running("defenseclaw doctor")
        await pilot.pause()
        assert stdin.has_class("open") is True
        # Finish:
        app._strip_finished(exit_code=0, duration=0.1)
        await pilot.pause()
        assert stdin.has_class("open") is False
```

---

## 7. L4 — Snapshot scenes

* `activity_terminal_idle`
* `activity_terminal_running_with_stdin`
* `activity_terminal_success`
* `activity_terminal_failure`
* `activity_terminal_cancelled`
* `activity_history_empty`
* `activity_history_three_entries`
* `activity_mutations_empty`
* `activity_mutations_with_entries`

× 3 sizes = **27 SVGs**.

---

## 8. L5

* `test_cancel_then_start_returns_clean_state` (idempotent).
* `test_history_order_preserved_under_random_event_interleaving` (Hypothesis).
* `test_terminal_scroll_in_bounds`.

---

## 9. Known defects to file

* If stdin pipe stays "open" after the command was cancelled but not
  cleanly finished → file P1.
* If `clear_history` removes the currently-running entry (per the comment
  in the code, it must NOT) → file P0.

---

## 10. Coverage matrix

Per K, C, A, T ID.

---

## 11. Deliverables

* [ ] Four files.
* [ ] 27 SVGs.
* [ ] Coverage `panels/activity.py` ≥ 92 %.
* [ ] Coverage `executor.py` ≥ 90 %.
* [ ] Matrix complete.
