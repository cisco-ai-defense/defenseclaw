# 06 — Inventory panel test plan

The Inventory panel surfaces the discovered inventory of skills / MCPs /
plugins / agents / model providers / memories across scopes. Distinguished
from the catalog panels by **sub-tabs** and **scope chips** and a "summary"
row at the top.

---

## 1. Files under test

* `cli/defenseclaw/tui/panels/inventory.py`
* `cli/defenseclaw/tui/services/inventory_state.py`

---

## 2. File layout

```
cli/tests/tui/
  test_inventory_model.py
  test_inventory_app.py
  test_inventory_snapshot.py
  test_inventory_invariants.py
```

---

## 3. Input-surface inventory

### 3.1 Sub-tabs (`INVENTORY_SUBTABS`)

Six sub-tabs, one per category:

* T01 Skills
* T02 MCPs
* T03 Plugins
* T04 Agents
* T05 Model Providers
* T06 Memories

### 3.2 Keys

| ID | Key | Effect |
|---|---|---|
| K01 | `1..6` | switch sub-tab (T01-T06) |
| K02 | `Tab/Shift+Tab` (within panel — confirm doesn't conflict with global) | move scope chip selection |
| K03 | `/` | enter filter |
| K04 | `Esc` | precedence per `handle_key` |
| K05 | `↑/↓` `j/k` | cursor |
| K06 | `g/G` `Home/End` | jump |
| K07 | `Enter` | open detail |
| K08 | `r` | refresh / re-discover (subprocess: `inventory scan`) |
| K09 | `f` | toggle fast-scan mode |
| K10 | `s` | trigger scope cycle (Local / All / Stale) |
| K11 | filter keys | append/backspace/enter |

### 3.3 Clicks

* C01 — sub-tab chips (one per category).
* C02 — scope chips (Local / All / Stale).
* C03 — filter input.
* C04 — DataTable rows.
* C05 — Refresh / fast-scan chips.

### 3.4 Async surfaces

* A01 — `inventory scan` stream with intermediate updates.
* A02 — snapshot replacement (full re-render on every snapshot — confirm no
  flicker for unchanged rows).

### 3.5 Data inputs

* `InventorySnapshot` with all six categories.
* `InventoryFilter(category, scope, text, fast)` — pure dataclass.
* `InventorySummary` row.

---

## 4. L1 — Pure model tests

### 4.1 Snapshot ingestion

* `test_set_snapshot_replaces_full_state`.
* `test_set_snapshot_with_empty_categories_renders_empty_state`.
* `test_set_snapshot_garbage_row_shapes_are_ignored_with_warn`.

### 4.2 Sub-tab switching

* `test_set_tab_clamps_to_valid_subtab`.
* `test_set_tab_does_not_change_filter_text` (filter persists across tabs).
* `test_set_tab_resets_cursor_to_zero_per_tab`.

### 4.3 Scope cycling

* `test_set_scope_local_filters_to_local_only`.
* `test_set_scope_all_includes_all`.
* `test_set_scope_stale_includes_only_stale_entries` (definition of "stale"
  comes from `inventory_state.STALENESS_DEFINITION`).

### 4.4 Fast scan

* `test_toggle_fast_scan_emits_intent_with_fast_categories`.
* `test_fast_scan_categories_match_FAST_SCAN_CATEGORIES`.

### 4.5 Filtering

* Substring matches name and vendor.
* Filter intersects with scope chip and sub-tab.

### 4.6 Detail

* Each sub-tab's detail shape: assert `selected_detail_info` returns the
  right keys for the row type (`InventorySkill`, `InventoryMCP`, etc.).

### 4.7 Action intents (K08-K10)

* `test_inventory_refresh_intent_argv`.
* `test_inventory_fast_scan_intent_argv`.

---

## 5. L2 + L3

Route via key `6`. Test every K (K01-K11) and C (C01-C05). Switching
sub-tabs and asserting:

* Hint bar mentions the active sub-tab name.
* DataTable column headers change to match the active category.
* Cursor resets on sub-tab change.
* Snapshot scene updates atomically (no half-rendered intermediate row).

### 5.1 Scan stream

Same shape as Skills/MCPs scan; verify per-sub-tab refresh.

---

## 6. L4 — Snapshot scenes

For each of the 6 sub-tabs:

* `inventory_<subtab>_empty`
* `inventory_<subtab>_populated`
* `inventory_<subtab>_filter_active`

Plus:

* `inventory_summary_row_visible`
* `inventory_scope_stale_with_one_row`
* `inventory_fast_scan_running`

≈ 21 scenes × 3 sizes = **63 SVGs** (yes, this is the biggest snapshot set —
sub-agent should parametrize aggressively).

---

## 7. L5

* `test_subtab_switch_is_idempotent_after_full_cycle`.
* `test_filter_text_never_crashes_on_random_unicode` (Hypothesis).
* `test_scope_cycle_period_is_3`.
* `test_handle_key_keeps_cursor_in_bounds` (Hypothesis on key sequences).

---

## 8. Known defects to file

* If sub-tab switch leaves the previous sub-tab's `selected` highlighted on
  the new tab (off-by-one) → file P1.
* If fast scan re-runs on every keystroke when filter is being typed
  (debouncing missing) → file P1.

---

## 9. Coverage matrix

Per K, C, A, T ID.

---

## 10. Deliverables

* [ ] Four files.
* [ ] 63 SVGs.
* [ ] Coverage `panels/inventory.py` and `services/inventory_state.py` ≥ 92 %.
* [ ] Matrix complete.
