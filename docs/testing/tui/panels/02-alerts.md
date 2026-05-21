# 02 — Alerts panel test plan

The Alerts panel is the operator's primary triage surface: filter, expand,
view detail, copy. It has the richest filter UI (severity chips + text input
+ exact-severity hot keys) and the most data-shaped detail block.

---

## 1. Files under test

* `cli/defenseclaw/tui/panels/alerts.py`
* `cli/defenseclaw/tui/services/policy_state.py` (only what `alerts.py` imports
  indirectly — read but don't test here)

---

## 2. File layout

```
cli/tests/tui/
  test_alerts_model.py
  test_alerts_app.py
  test_alerts_snapshot.py
  test_alerts_invariants.py
```

---

## 3. Input-surface inventory

### 3.1 Keys (`AlertsPanelModel.handle_key`)

| ID | Key | Effect |
|---|---|---|
| K01 | `/` | enter filter input mode |
| K02 | `Esc` (in filter) | exit filter mode preserving text |
| K03 | `Esc` (idle, detail open) | close detail |
| K04 | `Esc` (idle, no detail, filter empty) | clear filter (no-op if empty) |
| K05 | `↑/k` | cursor up one row |
| K06 | `↓/j` | cursor down one row |
| K07 | `Home/g` | jump to first row |
| K08 | `End/G` | jump to last row |
| K09 | `PageUp` | scroll up by page |
| K10 | `PageDown` | scroll down by page |
| K11 | `Enter` | toggle expand inline OR open detail (depends on row.expandable) |
| K12 | `Space` | toggle multi-select on current row |
| K13 | `a` | select all in current view |
| K14 | `A` (Shift+A) | deselect all |
| K15 | `c` | clear filter |
| K16 | `f` | toggle through severity filters (cycle: all → critical → high → medium → low → all) |
| K17 | `C` | exact severity filter "critical" |
| K18 | `H` | exact severity filter "high" |
| K19 | `M` | exact severity filter "medium" |
| K20 | `L` | exact severity filter "low" |
| K21 | `0` | reset severity filter to "all" |
| K22 | `y` | copy detail text to clipboard |
| K23 | `r` | refresh from store |
| K24 | `?` | (global help — confirm panel doesn't swallow) |
| K25 | any text key while in filter input | append to filter |
| K26 | `Backspace` while in filter | drop last char |
| K27 | `Enter` while in filter | commit filter and exit input mode |

### 3.2 Clicks

* C01 — severity chip in `.panel-controls`.
* C02 — filter input → focuses, enters filter mode.
* C03 — DataTable row click → set cursor.
* C04 — DataTable row double-click → expand/open detail.
* C05 — "Clear filter" chip when filter active.
* C06 — "Refresh" chip.

### 3.3 Async surfaces

* A01 — `refresh()` reads from `store.list_events()`.
* A02 — `refresh_gateway_scans()` merges synthetic scan & finding events.
* A03 — egress event tail injection through `synthetic_egress_event`.

### 3.4 Data inputs

* `AlertEvent` from JSON, gateway store, hook events.
* `_coerce_alert_event` accepts dict, namespace, or `AlertEvent`.
* `_parse_timestamp` accepts ISO strings, epoch ints, `datetime`.

---

## 4. L1 — Pure model tests

### 4.1 Filter logic

For each filter type, build a small `FakeAuditStore` with 10 known events
and assert `flat_rows()` returns the expected subset.

* `test_set_filter_substring_matches_target_field`.
* `test_set_filter_is_case_insensitive`.
* `test_set_filter_matches_run_id_and_details`.
* `test_clear_filter_restores_full_list`.
* `test_severity_filter_critical_excludes_high`.
* `test_severity_filter_high_excludes_medium`.
* Parametrize K17-K21 to exact-severity setters.
* `test_set_severity_filter_cycle_wraps_after_low`.

### 4.2 Cursor / selection

* `test_cursor_up_clamps_at_zero`.
* `test_cursor_down_clamps_at_last_row`.
* `test_toggle_expand_or_detail_inline_for_expandable_row`.
* `test_toggle_expand_or_detail_opens_detail_for_non_expandable`.
* `test_toggle_select_marks_row` / `_unmark_row`.
* `test_select_all_marks_filtered_rows_only` (selecting all while a filter
  is active must not mark hidden rows).
* `test_deselect_all_clears_selection_across_filter_changes`.
* `test_filtered_ids_matches_visible_rows`.

### 4.3 Severity counts

* `test_severity_counts_zero_for_empty_store`.
* `test_critical_count_matches_subset`.
* `test_format_severity_counts_orders_critical_first`.

### 4.4 Detail

* `test_detail_text_for_expandable_row_returns_expanded_block`.
* `test_detail_pairs_excludes_blank_values`.
* `test_copy_detail_text_returns_human_readable_form`.
* `test_humanize_alert_details_strips_known_noise_prefixes`.

### 4.5 Synthetic events

* `test_synthetic_scan_event_carries_run_id`.
* `test_synthetic_finding_event_index_matches`.
* `test_synthetic_egress_event_target_label_from_egress`.

### 4.6 Coercion helpers

* `test_coerce_alert_event_accepts_dict`.
* `test_coerce_alert_event_accepts_namespace`.
* `test_parse_timestamp_accepts_iso_offset_aware`.
* `test_parse_timestamp_accepts_epoch_int`.
* `test_parse_timestamp_falls_back_to_now_for_garbage`.

### 4.7 Filter input mode state machine

* `test_filter_key_appends_char_only_in_filter_mode`.
* `test_filter_key_backspace_drops_last_char`.
* `test_filter_key_enter_commits_and_exits_filter_mode`.

### 4.8 Empty state and summary text

* `test_empty_state_for_no_events`.
* `test_empty_state_for_filter_with_no_match`.
* `test_summary_text_contains_visible_total_and_severity_breakdown`.

---

## 5. L2 + L3 — App-shell integration

### 5.1 Mount

* `test_alerts_panel_routes_via_2_key`.
* `test_alerts_panel_renders_filter_chips_in_panel_controls`.
* `test_alerts_panel_renders_data_table_with_columns_severity_target_time`.

### 5.2 Keys (K01-K27)

One test per ID. Pattern:

```python
async def test_alerts_K05_arrow_down_moves_cursor(piloted_app):
    app = build_app_with_5_events(piloted_app)
    async with app as (app_, pilot):
        await pilot.press("2")          # switch to Alerts
        await press_keys(pilot, "down")
        assert app_.alerts_model.cursor == 1
```

Special cases:

* K11: assert both behaviors (expand vs open detail) by seeding two row types.
* K12-K14: assert selection set against `model.selected_ids`.
* K15-K21: assert chip visual updates AND hint bar mentions the new filter.
* K22 (`y`): assert `fake_clipboard[-1]` equals `model.copy_detail_text()`.
* K23 (`r`): assert `store.list_events` was called.
* K25/K26/K27: drive `await pilot.press("/")`, then individual chars, then
  `enter` — assert `model.filter == "<typed text>"` and table now filtered.

### 5.3 Clicks (C01-C06)

* C01: click each severity chip; assert `model.severity_filter` matches.
* C02: click filter input; assert focus is on input AND filter mode = True.
* C03: click row 3; assert cursor == 3.
* C04: double-click row 3; assert detail block open or row expanded.
* C05: click "Clear filter" chip when filter active; assert filter cleared.
* C06: click "Refresh" chip; assert `store.list_events` called.

### 5.4 Async surfaces

* A01: append events to fake store mid-test, call `model.refresh()`, assert
  table grows.
* A02: seed gateway scans; call `refresh_gateway_scans`; assert synthetic
  scan + finding rows appear.
* A03: feed egress event; assert row appears with correct target label.

### 5.5 Hint bar

* `test_alerts_hint_bar_mentions_filter_when_filter_empty`.
* `test_alerts_hint_bar_mentions_clear_when_filter_active`.
* `test_alerts_hint_bar_mentions_paste_in_filter_mode`.

---

## 6. L4 — Snapshot scenes

| Scene | Setup |
|---|---|
| `alerts_empty` | No events |
| `alerts_populated_no_filter` | 10 mixed-severity events |
| `alerts_filter_active_no_match` | Filter "zzzz" |
| `alerts_filter_active_with_match` | Filter matches 2 of 10 |
| `alerts_severity_critical` | All sev filter set to "critical" |
| `alerts_detail_open` | Cursor on row 3, detail expanded |
| `alerts_multiselect_3_rows` | Three rows selected via space |
| `alerts_synthetic_scan_block` | Gateway scan with 4 findings present |
| `alerts_egress_event` | One egress event injected |

× 3 sizes = **27 SVGs**.

---

## 7. L5 — Invariants

* `test_filter_text_never_crashes_on_unicode` (Hypothesis on `text()`).
* `test_cursor_stays_in_bounds_for_any_key_sequence` (Hypothesis on lists of keys).
* `test_select_all_then_deselect_all_returns_to_empty_selection`.
* `test_severity_cycle_period_is_5` (cycling 5 times returns to initial filter).
* `test_handle_key_is_idempotent_for_no_op_keys` (random non-bound keys leave
  state unchanged).

---

## 8. Known defects to file

* If filtering on emoji crashes (`UnicodeError` in `_alert_filter_change`) →
  file and xfail with TODO.
* If `Y` global binding conflicts with `y` while filter input is focused
  (typing "y" should append, not trigger global yank) → file as P0.

---

## 9. Coverage matrix

Build a checklist with one row per K**, C**, A** ID. The PR isn't
mergeable until every ID has a matching test name filled in.

## 10. Deliverables

* [ ] All four files, all four layers green.
* [ ] 27 SVGs.
* [ ] Coverage `panels/alerts.py` ≥ 92 %.
* [ ] Coverage matrix complete.
