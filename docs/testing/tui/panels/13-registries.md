# 13 — Registries panel test plan

The Registries panel lists configured registry sources and their pulled
entries. Two-tab layout (Sources / Entries), with sync / approve / reject
actions.

---

## 1. Files under test

* `cli/defenseclaw/tui/panels/registries.py`
* `cli/defenseclaw/tui/services/registry_cache.py` (read-only here)

---

## 2. File layout

```
cli/tests/tui/
  test_registries_model.py
  test_registries_app.py
  test_registries_snapshot.py
  test_registries_invariants.py
```

---

## 3. Sub-tabs

`RegistriesTab`:
* T01 Sources
* T02 Entries

---

## 4. Input-surface inventory

### 4.1 Keys

| ID | Key | Effect |
|---|---|---|
| K01 | `1/2` | jump to tab |
| K02 | `Tab/Shift+Tab` | cycle tab |
| K03 | `↑/↓` `j/k` | cursor |
| K04 | `g/G` `Home/End` | jump |
| K05 | `Enter` | open detail |
| K06 | `s` | sync source (T01) |
| K07 | `S` (Shift+S) | sync ALL sources |
| K08 | `x` | remove source (T01) — only after confirm prompt |
| K09 | `a` | approve entry (T02) |
| K10 | `r` | reject entry (T02) |
| K11 | `f` | focus a specific entry (used after sync completes) |
| K12 | `c` | clear filter / focus |

### 4.2 Clicks

* C01 — Tab chips (2).
* C02 — Action chips (Sync / Sync All / Remove / Approve / Reject).
* C03 — DataTable rows.

### 4.3 Async

* A01 — `registry sync` stream — assert refresh after exit 0.
* A02 — `registry sync --all` stream.

### 4.4 Data

* `RegistrySourceRow(source_id, kind, url, enabled, last_synced_at, entry_count, status)`.
* `RegistryEntryRow(entry_type, name, version, status)`.
* `SourceIndex` cache state.

---

## 5. L1 — Pure model tests

* `test_set_tab_clamps`.
* `test_cursor_per_tab_independent`.
* `test_sync_source_intent_argv` for K06.
* `test_sync_all_intent_argv` for K07.
* `test_remove_source_intent_argv` for K08.
* `test_approve_entry_intent_argv` for K09.
* `test_reject_entry_intent_argv` for K10.
* `test_focus_entry_returns_true_when_found`.
* `test_focus_entry_returns_false_when_missing`.
* `test_selected_source_returns_none_when_empty`.
* `test_selected_entry_returns_none_when_empty`.
* `test_data_table_columns_per_tab`.
* `test_data_table_rows_match_sources_or_entries`.
* `test_empty_state_per_tab`.
* `test_selected_detail_info_for_source_includes_url_and_kind`.
* `test_selected_detail_info_for_entry_includes_metadata`.
* `test_visible_entries_filters_by_source_when_apply_focus_filter_is_true`.
* `test_attach_index_overlays_index_data_onto_source_row`.

---

## 6. L2 + L3

Route via key `R`. Cover each K and C ID.

* K07 (Shift+S sync all): assert executor invoked with `registry sync --all`.
* K08 (remove): assert confirm/consequence modal pushed BEFORE the
  executor call.

---

## 7. L4 — Snapshot scenes

* `registries_t01_sources_empty`
* `registries_t01_sources_populated`
* `registries_t01_source_detail_open`
* `registries_t01_sync_running`
* `registries_t02_entries_empty`
* `registries_t02_entries_populated`
* `registries_t02_entry_detail_open`
* `registries_t02_pending_approval_row`

× 3 sizes = **24 SVGs**.

---

## 8. L5

* `test_tab_cycle_period_is_2`.
* `test_cursor_in_bounds_per_tab`.
* `test_focus_entry_idempotent_when_called_twice_with_same_args`.

---

## 9. Known defects to file

* If sync-all runs syncs in parallel without serializing → file P1 (the
  registry cache lock contract assumes serial).
* If remove-source prompts twice (once via consequence modal, once via the
  command line) → file P2.

---

## 10. Coverage matrix

Per K, C, A ID.

---

## 11. Deliverables

* [ ] Four files.
* [ ] 24 SVGs.
* [ ] Coverage `panels/registries.py` ≥ 92 %.
* [ ] Matrix complete.
