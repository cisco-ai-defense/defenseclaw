# 08 — Logs panel test plan

The Logs panel tails three sources (gateway, otel, raw text) with chip
filters per source (verdict, action, event type, severity). Pause/resume
behavior matters because tests will assert no flicker when paused.

---

## 1. Files under test

* `cli/defenseclaw/tui/panels/logs.py`
* `cli/defenseclaw/tui/services/gateway_log_views.py` (consumed types only)

---

## 2. File layout

```
cli/tests/tui/
  test_logs_model.py
  test_logs_app.py
  test_logs_snapshot.py
  test_logs_invariants.py
```

---

## 3. Sources & chip groups

Three sources (`LogSource` enum):
* S01 gateway (verdicts)
* S02 otel
* S03 raw

Per source, chip groups:
* G01 filter chips (preset filters like "errors only").
* G02 verdict action chips (`allow / observe / block / ask`).
* G03 verdict event type chips (`request / response / tool / agent`).
* G04 verdict severity chips (`critical / high / medium / low / info`).

---

## 4. Input-surface inventory

### 4.1 Keys

| ID | Key | Effect |
|---|---|---|
| K01 | `Tab/Shift+Tab` | cycle source (within panel scope only) |
| K02 | `1/2/3` | jump to source S01/S02/S03 |
| K03 | `p` | toggle paused |
| K04 | `c` | clear filters |
| K05 | `↑/↓` `j/k` | cursor |
| K06 | `g/G` `Home/End` | jump |
| K07 | `Enter` | open detail |
| K08 | `r` | refresh from disk |
| K09 | `f` | cycle filter preset (G01) |
| K10 | `a` | cycle verdict action (G02) |
| K11 | `e` | cycle verdict event type (G03) |
| K12 | `s` | cycle verdict severity (G04) |
| K13 | `/` text | filter text input |
| K14 | `y` | copy current line/row |

### 4.2 Clicks

* C01 — source tab chips (3).
* C02 — chip groups G01-G04 (each chip click sets that group's value).
* C03 — Pause chip.
* C04 — Filter input.
* C05 — DataTable row click / double-click.

### 4.3 Async surfaces

* A01 — tail file growth (new lines appear).
* A02 — pause flips: new lines must be **counted** in `new_lines_since_pause`
  but not added to the visible buffer; resume flushes.
* A03 — source switch: confirm cursor and filter state are independent per
  source.

### 4.4 Data inputs

* Raw text lines (any UTF-8).
* `GatewayLogRow` records for gateway verdicts and OTel.
* Filter preset strings (defined in `gateway_log_views`).

---

## 5. L1 — Pure model tests

### 5.1 Source switching

* `test_set_source_changes_visible_buffer`.
* `test_next_source_wraps`.
* `test_previous_source_wraps`.
* `test_filter_state_is_independent_per_source`.

### 5.2 Pause / resume

* `test_paused_setter_freezes_visible_buffer`.
* `test_new_lines_since_pause_counts_growth`.
* `test_resume_appends_new_lines_in_order`.
* `test_pause_resume_round_trip_idempotent_on_empty_growth`.

### 5.3 Filter chips (G01-G04)

For each chip group:

* `test_set_X_chip_resets_cursor_to_zero`.
* `test_set_X_chip_filters_visible_rows`.
* `test_cycle_X_chip_period_matches_chip_count`.
* `test_X_chip_states_match_chip_group_state`.

### 5.4 Cursor / scroll

* `test_move_cursor_scrolls_when_height_exceeded`.
* `test_move_cursor_clamps_at_buffer_ends`.
* `test_scroll_offset_recomputes_after_filter_change`.

### 5.5 Detail

* `test_selected_detail_title_per_source`.
* `test_selected_detail_pairs_for_gateway_verdict`.
* `test_selected_detail_pairs_for_otel_row`.
* `test_selected_raw_line_for_raw_source`.

### 5.6 Line styling

* `test_line_style_key_for_error_severity_returns_error_class`.
* `test_line_style_key_default_returns_neutral_class`.

### 5.7 Visible row views

* `test_visible_row_views_returns_at_most_height_rows`.
* `test_visible_row_views_anchors_to_cursor`.
* `test_data_table_columns_per_source`.
* `test_data_table_rows_match_visible_views`.

---

## 6. L2 + L3 — App-shell integration

Route via key `8`. Cover every K and C ID. Pause / resume special case:

```python
async def test_logs_pause_freezes_view_and_counts_new_lines(piloted_app, tmp_data_dir):
    log_path = tmp_data_dir / "gateway.log"
    log_path.write_text("first\nsecond\n")
    async with piloted_app() as (app, pilot):
        await pilot.press("8", "p")             # switch + pause
        await pilot.pause()
        # Append while paused
        log_path.write_text("first\nsecond\nthird\nfourth\n")
        app.logs_model.refresh()
        await pilot.pause()
        assert app.logs_model.new_lines_since_pause == 2
        # Resume
        await pilot.press("p")
        await pilot.pause()
        assert app.logs_model.new_lines_since_pause == 0
        assert "fourth" in app.body_text
```

### 6.1 Hint bar

Assert text mentions: "paused" when paused, "filter" when filter empty,
"clear" when filter active.

---

## 7. L4 — Snapshot scenes

Per source × {empty, populated, filter-applied, paused-with-new-lines,
detail-open}:

* `logs_gateway_*` (5)
* `logs_otel_*` (5)
* `logs_raw_*` (5)

= 15 scenes × 3 sizes = **45 SVGs**.

---

## 8. L5

* `test_pause_growth_never_loses_lines_for_any_growth_sequence` (Hypothesis).
* `test_cycle_period_per_chip_group_matches_chip_count`.
* `test_filter_text_never_crashes` (Hypothesis).
* `test_cursor_in_bounds` (Hypothesis).

---

## 9. Known defects to file

* If a paused-then-resumed view shows lines in the wrong order when concurrent
  appenders are writing → file P0.
* If switching source while paused leaks the pause flag to the new source →
  file P1.

---

## 10. Coverage matrix

Per K, C, A, S, G ID.

---

## 11. Deliverables

* [ ] Four files.
* [ ] 45 SVGs.
* [ ] Coverage `panels/logs.py` ≥ 92 %.
* [ ] Matrix complete.
