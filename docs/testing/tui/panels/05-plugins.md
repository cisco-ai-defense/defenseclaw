# 05 — Plugins panel test plan

The Plugins panel is the third catalog twin. Same shape as Skills/MCPs but
limited to install/uninstall/enable/disable (no `scan`, no `set`,
no `approve/reject`).

---

## 1. Files under test

* `cli/defenseclaw/tui/panels/plugins.py`
* `cli/defenseclaw/tui/services/catalog_state.py` (Plugins slice)

---

## 2. File layout

```
cli/tests/tui/
  test_plugins_model.py
  test_plugins_app.py
  test_plugins_snapshot.py
  test_plugins_invariants.py
```

---

## 3. Input-surface inventory

### 3.1 Keys

| ID | Key | Effect |
|---|---|---|
| K01 | `/` | enter filter |
| K02 | `Esc` | precedence per `handle_key` |
| K03 | `↑/↓` `j/k` | cursor |
| K04 | `g/G` `Home/End` | jump |
| K05 | `Enter` | open detail |
| K06 | `i` | install |
| K07 | `u` | uninstall |
| K08 | `e` | enable |
| K09 | `d` | disable |
| K10 | `r` | refresh (no `scan`; just re-read connector) |
| K11 | `c` | clear filter |
| K12 | filter input keys | append/backspace/enter |

### 3.2 Clicks

* C01 — filter input.
* C02 — action chips.
* C03 — DataTable row click / double-click.
* C04 — Connector chip (some plugins only apply to certain connectors —
  click filters by connector).

### 3.3 Async surfaces

* A01 — `FakeConnector.list_plugins` shape variations.

### 3.4 Data inputs

* `PluginRow(name, version, enabled, installed, connector_scope, capabilities)`.
* `PluginScanSummary` for header metrics.

---

## 4. L1 — Pure model tests

* Loading & projection (mirror Skills).
* Filtering by name, capability, connector scope.
* Cursor clamping.
* Action intents K06-K10 with argv assertions.
* Empty state strings (connector returns zero, filter excludes all).
* Detail pairs format.

---

## 5. L2 + L3

Route via key `5`. One async test per K and C ID. Hint bar asserted.

---

## 6. L4 — Snapshot scenes

* `plugins_empty`
* `plugins_populated_with_codeguard`
* `plugins_filter_active`
* `plugins_connector_filter_openclaw`
* `plugins_detail_open`

× 3 sizes = **15 SVGs**.

---

## 7. L5

* Hypothesis filter stability.
* Cursor invariants.
* Install/uninstall round-trip idempotence.

---

## 8. Known defects to file

* If `i` is pressed on an already-installed plugin and the model still emits
  an `install` intent (no-op + log spam): file P2.

---

## 9. Coverage matrix

Per K, C, A ID.

---

## 10. Deliverables

* [ ] Four files.
* [ ] 15 SVGs.
* [ ] Coverage `panels/plugins.py` ≥ 92 %.
* [ ] Matrix complete.
