# 03 — Skills panel test plan

The Skills panel is one of four "catalog" panels (Skills / MCPs / Plugins /
Tools) that share `services/catalog_state.py`. The plan focuses on the parts
unique to Skills; cross-cutting catalog behavior is duplicated in plans 04,
05, 11 with identical structure so each sub-agent stays self-contained.

---

## 1. Files under test

* `cli/defenseclaw/tui/panels/skills.py`
* `cli/defenseclaw/tui/services/catalog_state.py` (only the slice consumed
  by `SkillsPanelModel`)

---

## 2. File layout

```
cli/tests/tui/
  test_skills_model.py
  test_skills_app.py
  test_skills_snapshot.py
  test_skills_invariants.py
```

---

## 3. Input-surface inventory

### 3.1 Keys

| ID | Key | Effect |
|---|---|---|
| K01 | `/` | enter filter |
| K02 | `Esc` | exit filter / close detail / clear filter (precedence per `handle_key`) |
| K03 | `↑/↓` `j/k` | cursor move |
| K04 | `g/G` `Home/End` | jump |
| K05 | `Enter` | open detail (or toggle expand) |
| K06 | `r` | run `defenseclaw skill scan` via executor |
| K07 | `i` | run `defenseclaw skill install <name>` for current row |
| K08 | `u` | run `defenseclaw skill uninstall <name>` |
| K09 | `e` | run `defenseclaw skill enable <name>` |
| K10 | `d` | run `defenseclaw skill disable <name>` |
| K11 | `c` | clear filter |
| K12 | filter text keys | append/backspace/enter in filter mode |

### 3.2 Clicks

* C01 — Filter input.
* C02 — Action chips (Refresh/Install/Uninstall/Enable/Disable).
* C03 — Source filter chips (bundled/local/registry).
* C04 — DataTable row click → set cursor.
* C05 — DataTable row double-click → open detail.

### 3.3 Async surfaces

* A01 — executor stream from `skill scan` flushed into model; assert table
  refresh after exit code 0.
* A02 — `FakeConnector.list_skills` returns dict-shaped rows from registry
  cache (test the projector tolerates each shape).

### 3.4 Data inputs

* `SkillRow(name, source, source_id, version, installed, enabled, capabilities)`.
* Source labels: `bundled`, `local`, `registry`.
* Capability flags rendered as comma-separated badges.

---

## 4. L1 — Pure model tests

### 4.1 Loading & projection

* `test_skills_load_from_connector_normalizes_rows`.
* `test_skills_load_dedupes_by_name_source_id`.
* `test_skills_load_handles_empty_connector_response`.
* `test_skills_load_handles_garbage_row_shape` (`None`, missing keys, wrong types).

### 4.2 Filtering

* `test_filter_substring_matches_name`.
* `test_filter_substring_matches_capability`.
* `test_filter_excludes_disabled_when_source_filter_is_set_to_installed`.
* Parametrize over the source-filter chips (`bundled`, `local`, `registry`,
  `all`, `installed`, `enabled`).

### 4.3 Cursor / detail

* `test_cursor_clamping`.
* `test_open_detail_returns_detail_info_with_capabilities_pretty_printed`.
* `test_detail_pairs_excludes_empty_fields`.

### 4.4 Action intents

For each of K06-K10, assert the intent's argv matches the exact CLI
contract. Use a parametrize:

```python
@pytest.mark.parametrize("key,verb", [
    ("r", "scan"), ("i", "install"), ("u", "uninstall"),
    ("e", "enable"), ("d", "disable"),
])
def test_skill_action_intent_argv(key, verb): ...
```

### 4.5 Empty state and summary text

* `test_empty_state_when_connector_returns_zero`.
* `test_empty_state_when_filter_excludes_all`.
* `test_summary_text_shows_counts`.

---

## 5. L2 + L3 — App-shell integration

* Route via key `3`.
* Every K01-K12 mirrored in async tests.
* Every C01-C05 mirrored.
* `executor.calls` asserted for each action key.
* Hint bar text asserted for: idle, filter mode, after scan completes,
  after install command queued.

### 5.1 Streaming `skill scan` flow

```python
async def test_skills_scan_streams_into_activity(piloted_app, fake_executor):
    fake_executor.scripted_events = [
        CommandEvent(kind="stdout", line="scanning..."),
        CommandEvent(kind="stdout", line="scan complete"),
        CommandEvent(kind="exit", code=0),
    ]
    async with piloted_app() as (app, pilot):
        await pilot.press("3", "r")
        await fake_executor.flush(pilot)
        assert "scan complete" in app.activity_model.last_terminal_output
        # Skills model auto-refreshes after exit 0:
        assert fake_executor.scripted_events == []   # consumed
```

---

## 6. L4 — Snapshot scenes

* `skills_empty`
* `skills_populated_bundled_only`
* `skills_populated_mixed_sources`
* `skills_filter_active`
* `skills_detail_open`
* `skills_scan_running` (chip in "running" state)

× 3 sizes = **18 SVGs**.

---

## 7. L5 — Invariants

* `test_skills_filter_never_crashes_on_random_text` (Hypothesis).
* `test_skills_cursor_stays_in_bounds`.
* `test_install_uninstall_round_trip_is_idempotent_on_model`.

---

## 8. Known defects to file

* If the source-filter chip "registry" applies before the connector has loaded
  registry rows and renders the wrong empty state, file as P1.

---

## 9. Coverage matrix

One row per K**, C**, A** ID.

---

## 10. Deliverables

* [ ] Four files.
* [ ] 18 SVGs.
* [ ] Coverage `panels/skills.py` ≥ 92 %.
* [ ] Coverage `services/catalog_state.py` Skills-relevant code paths ≥ 90 %.
* [ ] Matrix complete.
