# 07 — Policy panel test plan (LARGEST)

The Policy panel is the most complex non-modal panel. It has **five sub-tabs**,
each with its own state machine, plus deep coupling with two modals
(Quick Start, Playground) and a YAML viewer with scroll math. This plan is
≈ 3-4× the size of any other panel plan; budget accordingly.

---

## 1. Files under test

* `cli/defenseclaw/tui/panels/policy.py` (re-exports only)
* `cli/defenseclaw/tui/services/policy_state.py` (~2300 lines; majority of work here)

> Quick Start screen and Playground screen are tested in plans 19 and 20.
> This plan only covers the **dispatch** from the Policy panel into those
> modals (`open_quick_start` and `open_playground` flags on `PolicyPanelAction`).

---

## 2. File layout

```
cli/tests/tui/
  test_policy_model.py             # L1 — split into sections for readability
  test_policy_model_policies.py    # L1 — Policies sub-tab only
  test_policy_model_rule_packs.py  # L1 — Rule Packs sub-tab
  test_policy_model_judge.py       # L1 — Judge sub-tab
  test_policy_model_suppressions.py# L1 — Suppressions sub-tab
  test_policy_model_opa.py         # L1 — OPA/Rego sub-tab
  test_policy_app.py               # L2 + L3
  test_policy_snapshot.py          # L4
  test_policy_invariants.py        # L5
```

Splitting L1 lets the sub-agent work on each sub-tab in series without merge
conflicts; tests in different files can run in parallel under `pytest-xdist`.

---

## 3. Sub-tabs

`POLICY_TAB_NAMES = ("Policies", "Rule Packs", "Judge Prompts", "Suppressions", "OPA / Rego")`

| T | Index | Name |
|---|---|---|
| T01 | 0 | Policies |
| T02 | 1 | Rule Packs |
| T03 | 2 | Judge Prompts |
| T04 | 3 | Suppressions |
| T05 | 4 | OPA / Rego |

Cycle keys:
* `Tab` (when not on filter) → next sub-tab.
* `Shift+Tab` → previous sub-tab.
* `1..5` (when key is panel-local) → set sub-tab directly.

---

## 4. Input-surface inventory (per sub-tab)

### 4.1 Common (all sub-tabs)

| ID | Key | Effect |
|---|---|---|
| Kc01 | `Tab` / `Shift+Tab` | cycle sub-tab |
| Kc02 | `1..5` | jump to sub-tab |
| Kc03 | `Esc` | close detail / clear filter (precedence per `handle_key`) |
| Kc04 | `/` | enter filter |
| Kc05 | `↑/↓` `j/k` | cursor / YAML scroll (T01, T05) |
| Kc06 | `PgUp/PgDn` | page scroll (T05 mostly) |
| Kc07 | `Home/End` `g/G` | jump |
| Kc08 | `r` | reload policies / rule pack |

### 4.2 T01 Policies (`handle_policies_key`)

| ID | Key | Effect |
|---|---|---|
| Kp01 | `Enter` | open policy detail |
| Kp02 | `n` | open Quick Start (returns `open_quick_start=True`) |
| Kp03 | `p` | open Playground (`open_playground=True`, carries policy name) |
| Kp04 | `e` | open YAML in editor (returns editor intent) |
| Kp05 | `v` | run `policy validate` |
| Kp06 | `t` | run `policy test` |
| Kp07 | `m` | run `policy materialize` |
| Kp08 | `R` (uppercase) | run `policy reload` |
| Kp09 | `/` text | filter policy list |

### 4.3 T02 Rule Packs (`handle_rule_pack_key`)

| ID | Key | Effect |
|---|---|---|
| Kr01 | `Enter` | open rule file detail |
| Kr02 | `e` | open rule file in editor |
| Kr03 | `↑/↓` | cursor through rule files |
| Kr04 | `r` | reload rule pack from disk |
| Kr05 | `p` | toggle through discovered packs (`discover_packs`) |

### 4.4 T03 Judge Prompts (`handle_judge_key`)

| ID | Key | Effect |
|---|---|---|
| Kj01 | `↑/↓` | cycle through ordered judges |
| Kj02 | `Enter` | open judge prompt detail |
| Kj03 | `e` | edit judge prompt file |

### 4.5 T04 Suppressions (`handle_suppressions_key`)

| ID | Key | Effect |
|---|---|---|
| Ks01 | `↑/↓` | move cursor within section |
| Ks02 | `Tab` (within sub-tab — confirm Tab still cycles sub-tabs at top level) | move between Pre-Judge / Finding / Tool sections |
| Ks03 | `Enter` | toggle suppression entry |
| Ks04 | `e` | edit suppressions.yaml |
| Ks05 | `s` | save suppressions.yaml |

### 4.6 T05 OPA / Rego (`handle_opa_key`)

| ID | Key | Effect |
|---|---|---|
| Ko01 | `↑/↓` | scroll YAML/Rego body |
| Ko02 | `PgUp/PgDn` | page scroll |
| Ko03 | `Home/End` | jump to top/bottom of file |
| Ko04 | `e` | edit Rego file |
| Ko05 | `l` | run `policy lint` (`rego_lint` module) |
| Ko06 | `t` | run `policy test --rego` |

### 4.7 Clicks (all sub-tabs)

* C01 — Sub-tab strip (5 chips).
* C02 — Action chips per sub-tab.
* C03 — DataTable / list row click → cursor.
* C04 — DataTable / list row double-click → detail.
* C05 — `handle_click(x, y)` — generic mouse hit-test path.

### 4.8 Async surfaces

* A01 — `policy validate` stream → status updates.
* A02 — `policy reload` stream → success/fail mid-modal.
* A03 — Quick Start modal save callback → `policy_to_gateway_yaml` → disk write.
* A04 — Playground save callback → re-emit YAML → reload.

---

## 5. L1 — Pure model tests (sub-divided)

### 5.1 `test_policy_model_policies.py`

* Loading from disk (bundled + user) and merge order.
* Filter substring matches policy name, description, severity table action.
* Cursor navigation through policies list.
* `active_policy_name` resolution (which file is currently "active").
* `policy_profile_summary` against a known YAML fixture.
* `severity_action_summary` row construction for each severity.
* Intents:
  * `policy_command_intent(args, hint)`.
  * `policy_validate_intent`, `policy_reload_intent`, `policy_test_intent`,
    `policy_materialize_intent`, `policy_edit_intent`, `editor_intent`,
    `aibom_scan_intent`.
* `handle_policies_key` for every Kp* ID.
* `open_quick_start` / `open_playground` flags returned correctly.

### 5.2 `test_policy_model_rule_packs.py`

* `discover_packs(dir)` finds bundled + custom packs.
* `load_rule_pack(directory)` returns `RulePackLoadResult` with files +
  errors.
* `load_rule_pack_yaml` parses well-formed and malformed YAML.
* `default_rule_pack_candidates` returns the right candidate list per rel
  path.
* `load_rule_files` skips broken files into the errors list.
* `parse_policy_rule` accepts dict and namespace.
* `handle_rule_pack_key` for every Kr* ID.

### 5.3 `test_policy_model_judge.py`

* `ordered_judge_names` with `PREFERRED_JUDGE_ORDER` first, then alphabetic.
* `parse_judge_prompt` accepts mapping and includes `source_path`.
* `parse_judge_category` for nested dict, list of strings, single string.
* `handle_judge_key` for every Kj* ID.

### 5.4 `test_policy_model_suppressions.py`

* `parse_suppressions` round-trips through `SuppressionsConfig.to_yaml_dict`.
* `parse_pre_judge_strip` / `parse_finding_suppression` / `parse_tool_suppression`.
* `save_suppressions_yaml` writes to `tmp_path` and re-parses to equal dict.
* `handle_suppressions_key` for every Ks* ID.
* `PolicySuppressionSelection` round-trip.

### 5.5 `test_policy_model_opa.py`

* `clamp_yaml_body(yaml_text, width, body_rows, scroll)` boundary cases:
  scroll past EOF, negative scroll, body smaller than viewport, body larger.
* `YAMLBodyWindow.lines` length matches `body_rows`.
* `_highlight_rego_line` syntax highlight smoke test (non-empty Rich tokens).
* `handle_opa_key` for every Ko* ID.

### 5.6 Cross-sub-tab

* `set_sub_tab(idx)` clamps idx to 0..4.
* `set_sub_tab` resets cursor when switching tabs.
* `reset_scrolls` resets all scroll offsets to 0.
* `handle_key` dispatch table: confirm `handle_key` routes to the right
  sub-tab handler based on `_sub_tab`.

---

## 6. L2 + L3 — App-shell integration (`test_policy_app.py`)

Route via key `7`. Cover each Kc / Kp / Kr / Kj / Ks / Ko / C ID with an
async test.

### 6.1 Sub-tab nav

```python
async def test_policy_tab_cycles_through_five_subtabs(piloted_app):
    async with piloted_app() as (app, pilot):
        await pilot.press("7")
        for expected in range(5):
            assert app.policy_model.sub_tab == expected
            await pilot.press("tab")
            await pilot.pause()
        assert app.policy_model.sub_tab == 0  # wraps
```

### 6.2 Modal dispatch

* Press `n` on T01; assert `assert_screen_is(app, QuickStartScreen)`.
* Press `p` on T01; assert `assert_screen_is(app, PlaygroundScreen)`.
* Dismiss Quick Start with a sample `Answers`; assert YAML written to
  `policy_dir`; assert policy list refreshed.
* Dismiss Playground with a mutated `Policy`; assert YAML re-emitted.

### 6.3 Editor intent

Press `e` on T01 / T02 / T03 / T05; in each case assert the model returned
an `editor` kind intent and the app shell did NOT shell out (since the
editor is "owned" by the app — confirm the dispatch path: see how `app.py`
handles editor intents).

### 6.4 Streaming `policy validate` and `policy reload`

Use `fake_executor.scripted_events` to push success and failure outputs;
assert the readiness summary row updates correctly.

---

## 7. L4 — Snapshot scenes

Per sub-tab × {empty, populated, detail-open, filter-active}:

* `policy_t01_empty`, `policy_t01_populated`, `policy_t01_detail_open`, `policy_t01_filter_active`
* `policy_t02_*`, `policy_t03_*`, `policy_t04_*`, `policy_t05_*`

Plus modal overlays:

* `policy_quick_start_overlay`
* `policy_playground_overlay`
* `policy_validate_running`
* `policy_reload_failed_with_error_block`

≈ (5 × 4) + 4 = 24 scenes × 3 sizes = **72 SVGs**.

---

## 8. L5 — Invariants

* `test_clamp_yaml_body_window_size_never_exceeds_body_rows` (Hypothesis).
* `test_clamp_yaml_body_scroll_is_always_non_negative` (Hypothesis).
* `test_handle_key_keeps_sub_tab_in_range_for_any_key_sequence` (Hypothesis).
* `test_policy_filter_text_never_crashes_for_random_unicode` (Hypothesis).
* `test_sub_tab_cycle_period_is_5`.
* `test_suppressions_yaml_roundtrip_is_idempotent_after_parse_save_load`.

---

## 9. Known defects to file

* If `clamp_yaml_body` returns a window with `< body_rows` lines for very
  small files instead of padding → file (cosmetic but breaks snapshot
  determinism).
* If `handle_key` swallows uppercase action letters (`R`) inside filter
  input mode → P1.
* If `policy_dir` writes accidentally overwrite bundled assets when filenames
  collide → P0.

---

## 10. Coverage matrix

One row per Kc / Kp / Kr / Kj / Ks / Ko / C / A ID.

---

## 11. Deliverables

* [ ] Nine test files (six L1 modules + L2 + L4 + L5).
* [ ] 72 SVGs.
* [ ] Coverage `services/policy_state.py` ≥ 90 %.
* [ ] Coverage `panels/policy.py` ≥ 100 % (re-export file).
* [ ] Matrix complete.
* [ ] Modal dispatch tests confirm Quick Start and Playground are pushed
      and dismiss behavior is correctly wired into the panel model.
