# 01 — Overview panel test plan

> **Status:** sub-agent ready. Dispatch only after the foundation canary is green.

The Overview panel is the landing screen. It composes the `OverviewMetrics`
widget, the connector "mode picker" trigger, the doctor cache, the AI usage
panel, and four quick-action chips. Half the panel is a `Static`-rendered Rich
Group; the other half is a real Textual widget tree (`OverviewMetrics`).

---

## 1. Files under test

* `cli/defenseclaw/tui/panels/overview.py` (re-exports only)
* `cli/defenseclaw/tui/services/overview_state.py` (pure model — most assertions live here)
* `cli/defenseclaw/tui/widgets/native_metrics.py` (composed widget — see plan 31 for the widget's own coverage, here only its mount/visibility)
* `cli/defenseclaw/tui/app.py` (only the `_render_overview_*`, `action_intent`-dispatch, mode-picker push, and `_periodic_refresh` overview branches)

> The sub-agent must not modify any of these files. If a real bug shows up,
> file the issue and `xfail(reason=..., strict=False)` the test.

---

## 2. File layout (the sub-agent writes exactly these files)

```
cli/tests/tui/
  test_overview_model.py        # L1
  test_overview_app.py          # L2 + L3
  test_overview_snapshot.py     # L4
  test_overview_invariants.py   # L5
```

---

## 3. Input-surface inventory

Every entry here MUST have a test that exercises it. The "Coverage matrix" in
§9 cross-references these IDs.

### 3.1 Keys (panel-local)

| ID | Key | Effect | Notes |
|---|---|---|---|
| K01 | `d` | Run `defenseclaw doctor` and stream into the doctor box | Goes through `action_intent("doctor")` |
| K02 | `D` (Shift+D) | Lightweight diagnose (toast summary) | Global binding, but only valid on Overview |
| K03 | `r` | Refresh health, doctor cache, AI usage | `action_refresh_overview` |
| K04 | `m` | Open `ModePickerScreen` | Pushes modal (plan 18) |
| K05 | `o` | Cycle connector to `openclaw` | Quick action, see `QUICK_ACTIONS` |
| K06 | `z` | Cycle connector to `zeptoclaw` | |
| K07 | `c` | Cycle connector to `claudecode` | |
| K08 | `↑/↓` | (no-op on Overview — confirm hint bar stays "press d/r/m") | |
| K09 | `Enter` | (no-op) | |

### 3.2 Clicks

* C01 — `#overview-metrics MetricTile` click → no-op (verify no crash).
* C02 — Quick-action chips in `.panel-controls` (Doctor / Refresh / Mode) →
  same effect as K01 / K03 / K04.
* C03 — AI Discovery row click → navigates to AI Discovery panel.

### 3.3 Async surfaces

* A01 — `executor.run("defenseclaw doctor")` callback feeds `set_doctor_cache`.
* A02 — `_fetch_ai_usage()` (already patched to `None` in the foundation) —
  test simulates a non-None return.
* A03 — `_periodic_refresh` ticks every 2 s — assert no flicker (body
  signature unchanged when state unchanged).

### 3.4 Reactive data the panel reads

* Health snapshot (`HealthSnapshot`) — gateway, agent, watchdog, guardrail,
  AI discovery subsystems each with `state` and `details`.
* Doctor cache (`DoctorCache`) — staleness window 60 s; `is_stale` flips
  between two adjacent ticks.
* Enforcement counts (`EnforcementCounts`) — sparkline data source.
* Silent bypass count — visual element only when > 0.
* Connector mode — derived from `cfg.claw.mode`.
* Version string — passed to `OverviewPanelModel.__init__`.

---

## 4. L1 — Pure model tests (`test_overview_model.py`)

Write one `def test_*` per row below. No `App`, no `Pilot`.

### 4.1 Constructor & setters

* `test_panel_starts_with_no_health_and_no_cache`.
* `test_set_health_replaces_snapshot`.
* `test_set_doctor_cache_replaces_and_recomputes_staleness`.
* `test_set_enforcement_counts_updates_sparkline_source`.
* `test_set_silent_bypass_count_zero_hides_row`.
* `test_set_silent_bypass_count_positive_shows_row`.
* `test_set_skill_scanner_available_toggles_quick_action_visibility`.

### 4.2 `build_notices`

`build_notices` returns a tuple of `OverviewNotice`. Cover:

* `test_notice_zero_connector_requests_appears_after_uptime_window`.
* `test_notice_zero_connector_requests_suppressed_before_window`.
* `test_notice_missing_required_credentials_lists_envs`.
* `test_notice_doctor_cache_stale_flag` (boundary at `now == cached_at + STALENESS_WINDOW`).
* `test_notice_no_health_renders_warning`.
* Snapshot-test the **ordering** of notices (gateway-down beats credentials-missing).

### 4.3 `subsystem_state` / `subsystem_health` / `*_detail`

* `test_subsystem_state_unknown_for_missing_key`.
* `test_subsystem_state_returns_health_state_when_present`.
* `test_gateway_health_is_broken_for_each_state` — parametrize over
  `("running","degraded","stopped","error","unknown")`.
* `test_live_health_contradicts_when_check_says_fail_but_runtime_says_running`.
* `test_partition_doctor_checks_separates_pass_warn_fail` — parametrize.

### 4.4 `action_intent`

Parametrize:

```python
@pytest.mark.parametrize("key,expected_args", [
    ("doctor", ("doctor",)),
    ("refresh", None),                # refresh has no argv; intent is None or has special label
    ("mode-picker", None),
    ("scan-skills", ("skill", "scan")),
    # ... walk through every entry in QUICK_ACTIONS
])
def test_action_intent_for_every_quick_action(key, expected_args): ...
```

### 4.5 Helper functions

* `gateway_health_is_broken` — already covered above.
* `format_age` — boundary at 0 s, 59 s, 60 s, 3599 s, 3600 s, 86399 s, 86400 s.
* `format_duration` — same boundaries.
* `format_scan_age` — None input returns "no scans".
* `friendly_connector_name` — table covering all wires (`openclaw → OpenClaw`, etc.).
* `connector_source_label` — every `(connector, category)` pair from `_active_connector`.
* `ai_discovery_state_badge` — every `state` value.
* `display_ai_discovery_name` and `display_ai_discovery_vendor` — fallbacks.
* `clamp_percent` — `< 0`, `0`, `50.4`, `99.6`, `100`, `> 100`.
* `keys_overflow_suffix` — `total==shown`, `total>shown`, `total==0`.
* `zero_connector_requests_notice` — different connectors and uptimes.
* `sort_ai_discovery_signals_for_overview` — sort stability with equal scores.

### 4.6 Top failures / missing credentials

* `test_doctor_cache_top_failures_returns_up_to_limit_ordered_by_severity`.
* `test_doctor_cache_missing_required_credentials_dedupes_and_sorts`.

---

## 5. L2 + L3 — App-shell integration (`test_overview_app.py`)

All async. Use `piloted_app` factory from the foundation.

### 5.1 Mount and initial render

```python
async def test_overview_mounts_with_native_metrics(piloted_app):
    async with piloted_app(size=(120, 40)) as (app, pilot):
        assert app.active_panel == "overview"
        metrics = app.query_one("#overview-metrics", OverviewMetrics)
        assert metrics.has_class("hidden") is False
        assert len(metrics.query(MetricTile)) == 4
        assert "SERVICES" in app.body_text
```

Add variants:

* `test_overview_metrics_hidden_after_switching_to_alerts` (already partially
  covered by `test_app_shell.py`; promote it here and parametrize the target panel).
* `test_overview_silent_bypass_row_renders_when_count_positive`.
* `test_overview_renders_doctor_summary_after_cache_set`.

### 5.2 Key bindings (each ID K01-K09)

* K01 (`d`):
  ```python
  async def test_overview_d_runs_doctor_through_executor(piloted_app, fake_executor):
      async with piloted_app() as (app, pilot):
          await pilot.press("d")
          await pilot.pause()
          assert any(call[0][:2] == ("defenseclaw", "doctor") for call in fake_executor.calls)
  ```
* K02 (`D`): assert toast contains "diagnose".
* K03 (`r`): assert `_fetch_ai_usage` was invoked and metrics tile values changed.
* K04 (`m`): `assert_screen_is(app, ModePickerScreen)`.
* K05/K06/K07 (`o`/`z`/`c`): assert executor invoked with `defenseclaw setup mode <wire>`.
* K08 (`↑/↓`): assert state unchanged AND hint bar still encourages `d/r/m`.
* K09 (`Enter`): assert state unchanged.

### 5.3 Mouse clicks (each ID C01-C03)

* C01: click each MetricTile; assert no exception, app remains on overview.
* C02: click the "Doctor" chip; same effect as K01 (mock `fake_executor`).
* C03: synthesize an AI usage signal in the model; click the AI discovery row;
  assert `app.active_panel == "ai"`.

### 5.4 Async surfaces (A01-A03)

* A01: scripted `CommandEvent`s flushed through `fake_executor.flush(pilot)`;
  assert `OverviewPanelModel.doctor_cache` updated.
* A02: monkey-patch `_fetch_ai_usage` to return a real `AIUsageSnapshot`,
  trigger refresh, assert AI box rendered.
* A03: call `app._periodic_refresh()` twice with no data change; assert
  `app._last_body_signature` did not change between ticks (the flicker-fix
  guard).

### 5.5 Hint bar (already covered by plan 28 but assert explicitly here)

* `test_overview_hint_text_mentions_d_r_m_when_idle`.
* `test_overview_hint_text_mentions_missing_credentials_when_present`.
* `test_overview_hint_text_changes_after_doctor_starts`.

### 5.6 Periodic refresh determinism (A03 invariant)

* `test_overview_refresh_does_not_repaint_when_state_unchanged`.
* `test_overview_refresh_repaints_when_doctor_cache_changes`.

---

## 6. L4 — Snapshot scenes (`test_overview_snapshot.py`)

For each scene below, take three snapshots at sizes `(80, 24)`, `(120, 40)`,
`(180, 50)`.

| Scene | Setup |
|---|---|
| `overview_empty` | Default app (no health, no cache, no signals) |
| `overview_healthy` | All subsystems `state="running"`, doctor cache fresh with all checks pass |
| `overview_degraded_gateway` | `gateway.state="degraded"`, others running |
| `overview_failing_doctor` | Doctor cache with 3 failing checks |
| `overview_with_silent_bypass` | `silent_bypass_count=5` |
| `overview_missing_credentials` | `KeysStatus` with `OPENAI_API_KEY` and `OPENCLAW_API_KEY` missing |
| `overview_ai_discovery_active` | 3 `AIUsageSignal`s of different vendors |
| `overview_d_running` | After K01 pressed, doctor command streaming |

Use a parametrize decorator so the cross-product is automatic:

```python
@pytest.mark.parametrize("scene", SCENES.keys())
@pytest.mark.parametrize("size", SIZE_NAMES.keys())
def test_overview_snapshot(snap_compare, scene, size): ...
```

---

## 7. L5 — Invariants (`test_overview_invariants.py`)

Use Hypothesis where natural; otherwise table-driven.

* `test_clamp_percent_always_in_0_100` (Hypothesis on floats).
* `test_format_age_monotonic_with_delta` (Hypothesis on `timedelta`).
* `test_subsystem_state_never_raises_for_arbitrary_key` (Hypothesis on
  `text()`).
* `test_handle_key_terminates_for_any_random_string` (Hypothesis on `text()`,
  property: after `model.action_intent(key)`, internal cursor and counts stay
  in declared ranges).
* `test_doctor_cache_is_stale_is_monotonic_in_age` — moving `now` forward
  cannot un-stale a cache that was stale.

---

## 8. Known defects to file (not block landing)

If during test authoring you find:

1. `_periodic_refresh` repaints despite identical signatures (the body
   signature tuple includes a `Group` instance whose `__eq__` is identity →
   bug). File before fixing; xfail strict=False with `TODO(panel-overview-flicker)`.
2. `format_age(timedelta(seconds=-1))` returns "in 0s" instead of "now". File.
3. Any race where AI usage tile shows "—" indefinitely if
   `_fetch_ai_usage` is patched to async with a `pilot.pause(delay=0.1)`. File.

---

## 9. Coverage matrix (sub-agent fills in test names before merging)

| Surface ID | Test name (model) | Test name (app) | Test name (snapshot) | Notes |
|---|---|---|---|---|
| K01 `d` | n/a | `test_overview_d_runs_doctor_through_executor` | `overview_d_running` | |
| K02 `D` | n/a | `test_overview_shift_d_toasts_diagnose_summary` | — | |
| K03 `r` | n/a | `test_overview_r_refreshes_health_and_ai_usage` | — | |
| K04 `m` | n/a | `test_overview_m_pushes_mode_picker_screen` | — | |
| K05 `o` | n/a | `test_overview_o_cycles_to_openclaw` | — | |
| K06 `z` | n/a | `test_overview_z_cycles_to_zeptoclaw` | — | |
| K07 `c` | n/a | `test_overview_c_cycles_to_claudecode` | — | |
| K08 `↑/↓` | n/a | `test_overview_arrow_keys_are_noop` | — | |
| K09 `Enter` | n/a | `test_overview_enter_is_noop` | — | |
| C01 metric click | n/a | `test_overview_metric_tile_click_is_noop` | — | |
| C02 chip click | n/a | `test_overview_doctor_chip_runs_doctor` | — | |
| C03 ai row click | n/a | `test_overview_ai_row_click_jumps_to_ai_panel` | — | |
| A01 doctor stream | `test_set_doctor_cache_replaces_and_recomputes_staleness` | `test_overview_streaming_doctor_appends_lines` | — | |
| A02 ai fetch | n/a | `test_overview_ai_usage_renders_after_async_fetch` | `overview_ai_discovery_active` | |
| A03 periodic refresh | n/a | `test_overview_refresh_does_not_repaint_when_state_unchanged` | — | |

(Sub-agent expands the matrix to cover §4.5 helpers and §5 mount cases.)

---

## 10. Deliverables (paste into PR description)

* [ ] All four files exist and pass.
* [ ] Snapshots checked in at three sizes × eight scenes = **24 SVGs**.
* [ ] Coverage of `services/overview_state.py` ≥ 95 %.
* [ ] Coverage of `panels/overview.py` ≥ 100 % (it's a re-export file).
* [ ] Hint bar asserted after every interaction.
* [ ] Coverage matrix in §9 fully ticked.
* [ ] Known defects filed if any of the §8 cases reproduces.
