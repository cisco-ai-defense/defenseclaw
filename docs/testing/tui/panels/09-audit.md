# 09 — Audit panel test plan

Audit reads from the audit `Event` store, filters by common presets +
substring + same-target / same-run-id, and supports JSON export.

---

## 1. Files under test

* `cli/defenseclaw/tui/panels/audit.py`

Store interface contract is the `FakeAuditStore` from the foundation.

---

## 2. File layout

```
cli/tests/tui/
  test_audit_model.py
  test_audit_app.py
  test_audit_snapshot.py
  test_audit_invariants.py
```

---

## 3. Input-surface inventory

### 3.1 Keys

| ID | Key | Effect |
|---|---|---|
| K01 | `/` | enter filter input |
| K02 | `Esc` | precedence per `handle_key` |
| K03 | `↑/↓` `j/k` | cursor |
| K04 | `g/G` `Home/End` | jump |
| K05 | `PgUp/PgDn` | scroll |
| K06 | `Enter` | toggle detail |
| K07 | `c` | clear filter |
| K08 | `f` | cycle common filter preset (`AuditCommonFilter`) |
| K09 | `t` | filter to same target as current row |
| K10 | `R` | filter to same run id as current row |
| K11 | `e` | export JSON to file (via executor) |
| K12 | `r` | refresh from store |
| K13 | `y` | copy current row to clipboard as JSON |
| K14 | filter text keys | append/backspace/enter |

### 3.2 Clicks

* C01 — common filter chips.
* C02 — filter input.
* C03 — DataTable rows.
* C04 — Export chip.
* C05 — "Same target" / "Same run" chips.

### 3.3 Async

* A01 — store.list_events called on refresh.
* A02 — JSON export argv assertion.

### 3.4 Data

* `Event` records (existing dataclass — read from `defenseclaw.models`).
* Common filter presets enumerated by `AuditCommonFilter`.

---

## 4. L1 — Pure model tests

### 4.1 Loading & filtering

* `test_set_events_replaces_full_list`.
* `test_apply_filter_substring_matches_action_or_target`.
* `test_clear_filter_restores_full_list`.
* `test_set_common_filter_each_preset_filters_correctly` (parametrize).
* `test_filter_same_target_only_active_when_row_selected`.
* `test_filter_same_run_only_active_when_run_id_present`.
* `test_active_filter_label_lists_active_filters`.

### 4.2 Cursor / scroll math

* `test_cursor_up_clamps_at_zero`.
* `test_cursor_down_clamps_at_last_row`.
* `test_set_cursor_clamps`.
* `test_scroll_by_with_negative_delta`.
* `test_scroll_offset_recomputes_after_filter_change`.
* `test_list_height_minus_filter_bar_minus_detail`.

### 4.3 Toolbar state

* `test_toolbar_state_reflects_active_filter`.
* `test_toolbar_state_shows_export_action_disabled_when_empty`.

### 4.4 Detail

* `test_toggle_detail_opens_then_closes`.
* `test_detail_pairs_for_event_with_findings`.
* `test_detail_rows_grouped_by_section`.
* `test_get_detail_info_returns_none_when_no_selection`.

### 4.5 Export

* `test_export_rows_match_data_table_rows_order`.
* `test_export_payload_returns_serializable_dicts`.
* `test_export_payload_redacts_known_pii_fields` (if redaction is on).

### 4.6 Render text

* `test_render_text_height_matches_request`.

---

## 5. L2 + L3 — App-shell integration

Route via key `9`. Cover each K and C ID.

* K11 (export): assert executor invoked with `audit export --json` and the
  target path is under `tmp_data_dir`.
* K13 (yank): assert clipboard contains the JSON of the current row.
* K09/K10: assert active filter label updates AND `summary_text` reflects.

### 5.1 Hint bar

Assert hint mentions "filter", "clear", "export", "same target/run"
depending on context.

---

## 6. L4 — Snapshot scenes

* `audit_empty`
* `audit_populated`
* `audit_filter_substring_active`
* `audit_common_filter_blocked_only`
* `audit_same_target_active`
* `audit_same_run_active`
* `audit_detail_open`
* `audit_export_running`

× 3 sizes = **24 SVGs**.

---

## 7. L5

* `test_cursor_in_bounds` (Hypothesis).
* `test_filter_substring_never_crashes_on_unicode` (Hypothesis).
* `test_common_filter_cycle_period`.
* `test_toggle_detail_idempotent_with_two_toggles`.

---

## 8. Known defects to file

* If "same run" filter persists after the original row is filtered out, file P1.
* If export overwrites an existing file without prompt → file P1 (UX).

---

## 9. Coverage matrix

Per K, C, A ID.

---

## 10. Deliverables

* [ ] Four files.
* [ ] 24 SVGs.
* [ ] Coverage `panels/audit.py` ≥ 92 %.
* [ ] Matrix complete.
