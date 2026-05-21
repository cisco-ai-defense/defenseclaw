# 12 — AI Discovery panel test plan

The AI Discovery panel surfaces the network signals (`AIUsageSignal`) that
detect AI vendor usage on the host. Source data comes from an async fetch
(`_fetch_ai_usage`).

---

## 1. Files under test

* `cli/defenseclaw/tui/panels/ai_discovery.py`
* `cli/defenseclaw/tui/services/ai_discovery_state.py`

---

## 2. File layout

```
cli/tests/tui/
  test_ai_discovery_model.py
  test_ai_discovery_app.py
  test_ai_discovery_snapshot.py
  test_ai_discovery_invariants.py
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
| K05 | `Enter` | open detail (signal breakdown) |
| K06 | `r` | refresh (re-run `_fetch_ai_usage`) |
| K07 | `c` | clear filter |
| K08 | `s` | cycle state filter (`active / decayed / inactive`) |
| K09 | `v` | cycle vendor filter (`OpenAI / Anthropic / Google / All`) |
| K10 | filter input keys | text input |

### 3.2 Clicks

* C01 — filter input.
* C02 — state filter chips.
* C03 — vendor filter chips.
* C04 — DataTable rows.

### 3.3 Async

* A01 — `_fetch_ai_usage` returning `AIUsageSnapshot` with signals.
* A02 — refresh on `r` triggers an async fetch.

### 3.4 Data

* `AIUsageSignal(name, vendor, state, last_seen, request_count, percent)`.
* `AIUsageSnapshot(signals, summary, fetched_at)`.

---

## 4. L1 — Pure model tests

* Snapshot ingestion: empty / 1 / 100 signals.
* Filtering by state, vendor, substring.
* `sort_ai_discovery_signals_for_overview` ordering rules.
* `display_ai_discovery_name` and `display_ai_discovery_vendor` fallbacks.
* `ai_discovery_state_badge` for each state.
* Cursor clamping.
* Detail pairs.
* Stale snapshot: `fetched_at` > X minutes ago → render "stale" badge.

---

## 5. L2 + L3

Route via key `V`. Cover each K and C ID.

```python
async def test_ai_discovery_r_triggers_async_fetch(piloted_app, monkeypatch):
    fetch_calls = []
    async def fake_fetch(): fetch_calls.append(1); return None
    monkeypatch.setattr("defenseclaw.tui.app._fetch_ai_usage", fake_fetch)
    async with piloted_app() as (app, pilot):
        await pilot.press("V", "r")
        await pilot.pause()
        assert len(fetch_calls) >= 1
```

---

## 6. L4 — Snapshot scenes

* `ai_discovery_empty`
* `ai_discovery_populated_active`
* `ai_discovery_populated_mixed_states`
* `ai_discovery_filter_active`
* `ai_discovery_vendor_filter_openai`
* `ai_discovery_state_filter_decayed`
* `ai_discovery_detail_open`
* `ai_discovery_stale_snapshot`

× 3 sizes = **24 SVGs**.

---

## 7. L5

* `test_signal_ordering_total_order` (Hypothesis: sort is deterministic and
  transitive).
* `test_filter_substring_never_crashes`.
* `test_cursor_in_bounds`.

---

## 8. Known defects to file

* If state filter "decayed" includes "inactive" rows by mistake (string
  matching instead of enum compare) → P1.

---

## 9. Coverage matrix

Per K, C, A ID.

---

## 10. Deliverables

* [ ] Four files.
* [ ] 24 SVGs.
* [ ] Coverage `panels/ai_discovery.py` and `services/ai_discovery_state.py` ≥ 92 %.
* [ ] Matrix complete.
