# 04 — MCPs panel test plan

The MCPs panel is the catalog twin of Skills but adds the `s` key that
launches the **MCP Set Form** modal (plan 23) and supports per-row
`approve / reject` from the registry view.

---

## 1. Files under test

* `cli/defenseclaw/tui/panels/mcps.py`
* `cli/defenseclaw/tui/services/catalog_state.py` (MCPs slice)

---

## 2. File layout

```
cli/tests/tui/
  test_mcps_model.py
  test_mcps_app.py
  test_mcps_snapshot.py
  test_mcps_invariants.py
```

---

## 3. Input-surface inventory

### 3.1 Keys

| ID | Key | Effect |
|---|---|---|
| K01 | `/` | enter filter |
| K02 | `Esc` | per panel's `handle_key` precedence |
| K03 | `↑/↓` `j/k` | cursor move |
| K04 | `g/G` `Home/End` | jump |
| K05 | `Enter` | open detail |
| K06 | `r` | run `mcp scan` |
| K07 | `i` | run `mcp install <name>` |
| K08 | `u` | run `mcp uninstall <name>` |
| K09 | `e` | run `mcp enable <name>` |
| K10 | `d` | run `mcp disable <name>` |
| K11 | `s` | push **MCP Set Form** modal (plan 23) |
| K12 | `a` | run `mcp approve <name>` (registry view) |
| K13 | `x` | run `mcp reject <name>` (registry view) |
| K14 | `c` | clear filter |
| K15 | filter input keys | append/backspace/enter |

### 3.2 Clicks

* C01 — filter input.
* C02 — action chips (Refresh / Install / Uninstall / Enable / Disable / Set / Approve / Reject).
* C03 — DataTable row click.
* C04 — DataTable row double-click.
* C05 — Transport chips (`stdio`, `http`, `sse`).

### 3.3 Async surfaces

* A01 — `mcp scan` stream.
* A02 — `MCP Set Form` returns an `MCPSetResult`; assert the model invokes
  the executor with the right argv.

### 3.4 Data inputs

* `MCPRow(name, transport, enabled, registry_source, version, env_count)`.
* Transport label: `stdio` / `http` / `sse`.

---

## 4. L1 — Pure model tests

### 4.1 Loading & projection

Same shape as Skills (§4.1) but add:

* `test_mcp_load_preserves_transport_field`.
* `test_mcp_load_with_unknown_transport_falls_back_to_stdio` (or
  whatever the panel's contract is).

### 4.2 Filtering

* `test_mcp_filter_by_name`.
* `test_mcp_filter_by_transport_chip`.
* Combine: `test_mcp_filter_substring_and_transport_chip_intersection`.

### 4.3 Action intents (K06-K13)

Parametrize same as Skills. For K11 (`s`) the model does NOT call the
executor — it returns a `MCPSetRequest` action. Assert that.

### 4.4 Set-form payload flow

* `test_mcp_apply_set_result_invokes_executor_with_args`.
* `test_mcp_set_result_with_invalid_env_pairs_is_rejected_at_model_layer`.

### 4.5 Approve / reject restricted to registry view

* `test_mcp_approve_returns_none_when_row_is_bundled` (no-op for bundled).
* `test_mcp_approve_returns_intent_when_row_is_from_registry`.

---

## 5. L2 + L3 — App-shell integration

* Route via key `4`.
* Mirror every K, C, A ID.
* K11 special:

  ```python
  async def test_mcps_s_opens_set_form_screen(piloted_app):
      app = make_app_with_mcp_rows()
      async with piloted_app() as (app, pilot):
          await pilot.press("4", "s")
          await pilot.pause()
          assert_screen_is(app, MCPSetFormScreen)
  ```

* K11 follow-through: dismiss with a valid result; assert the executor was
  called with the resulting args; assert the form's `name` field defaulted to
  the highlighted row.

* K12/K13 only valid on a "registry" view chip; if pressed elsewhere, assert
  toast or hint says "no row to approve".

### 5.1 Streaming `mcp scan`

Identical scenario to Skills' streaming test but checking `mcps_model` for
the refresh after exit 0.

---

## 6. L4 — Snapshot scenes

* `mcps_empty`
* `mcps_populated_mixed_transports`
* `mcps_filter_active`
* `mcps_transport_filter_http`
* `mcps_detail_open`
* `mcps_set_form_open` (already covered by plan 23, but produce a snapshot of
  the parent panel BEHIND the modal to assert overlay doesn't break layout)
* `mcps_registry_view_with_pending_approval`

× 3 sizes = **21 SVGs**.

---

## 7. L5 — Invariants

* `test_mcp_filter_never_crashes_on_random_text`.
* `test_mcp_cursor_stays_in_bounds`.
* `test_mcp_set_form_round_trip_does_not_corrupt_model` (open form, cancel,
  state equal to pre-open).

---

## 8. Known defects to file

* If pressing `s` on an empty MCPs list pushes a modal with an empty name
  default and the form silently writes "—" → file P1.
* If `mcp approve` argv accidentally double-quotes the registry source slug
  in argv → P0 (CLI rejects it).

---

## 9. Coverage matrix

Per K, C, A ID.

---

## 10. Deliverables

* [ ] Four files.
* [ ] 21 SVGs.
* [ ] Coverage `panels/mcps.py` ≥ 92 %.
* [ ] Matrix complete.
