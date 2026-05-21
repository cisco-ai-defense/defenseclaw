# 11 — Tools panel test plan

Tools is the simplest catalog twin: it lists `tool` records aggregated from
the audit store (most-recent tools used by agents). No install / scan;
just filter and inspect.

---

## 1. Files under test

* `cli/defenseclaw/tui/panels/tools.py`

---

## 2. File layout

```
cli/tests/tui/
  test_tools_model.py
  test_tools_app.py
  test_tools_snapshot.py
  test_tools_invariants.py
```

---

## 3. Input-surface inventory

### 3.1 Keys

| ID | Key | Effect |
|---|---|---|
| K01 | `/` | enter filter |
| K02 | `Esc` | precedence |
| K03 | `↑/↓` `j/k` | cursor |
| K04 | `g/G` `Home/End` | jump |
| K05 | `Enter` | open detail |
| K06 | `r` | refresh from store |
| K07 | `c` | clear filter |
| K08 | `s` | cycle "scope" filter (recent / all-time / by-agent) |
| K09 | filter input keys | text input |

### 3.2 Clicks

* C01 — filter input.
* C02 — Scope chips.
* C03 — DataTable rows.
* C04 — Refresh chip.

### 3.3 Async

* A01 — store refresh; assert tool aggregation.

### 3.4 Data

* `ToolRow(name, server, last_used_at, count, last_outcome)`.
* Aggregation across N events from store.

---

## 4. L1 — Pure model tests

* Aggregation: 5 events with 3 distinct tools → 3 rows, counts correct.
* Last-used-at is the max timestamp across the 5 events.
* Filter substring on name and server.
* Cursor clamping.
* Scope cycling.
* Detail pairs include all rows aggregated for that tool.
* Empty state.

---

## 5. L2 + L3

Route via key `T`. Each K and C ID async test.

* Hint bar: "filter" / "clear" / scope-name.

---

## 6. L4 — Snapshot scenes

* `tools_empty`
* `tools_populated`
* `tools_filter_active`
* `tools_scope_recent`
* `tools_scope_by_agent`
* `tools_detail_open`

× 3 sizes = **18 SVGs**.

---

## 7. L5

* `test_aggregation_count_equals_event_count_per_name_server` (Hypothesis on
  random event mixes).
* `test_filter_text_never_crashes`.
* `test_cursor_in_bounds`.

---

## 8. Known defects to file

* If aggregation key uses `name` only (not `name + server`), two tools with
  the same name but different servers collide → P1.

---

## 9. Coverage matrix

Per K, C, A ID.

---

## 10. Deliverables

* [ ] Four files.
* [ ] 18 SVGs.
* [ ] Coverage `panels/tools.py` ≥ 92 %.
* [ ] Matrix complete.
