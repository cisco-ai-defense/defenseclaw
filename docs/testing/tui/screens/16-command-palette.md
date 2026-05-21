# 16 — Command palette screen test plan

The global Ctrl+K / `:` command palette is the operator's keyboard fast-path
into any subcommand. It's a `ModalScreen[Command|None]` that filters a static
catalog and dismisses with the selected `Command`.

---

## 1. Files under test

* `cli/defenseclaw/tui/screens/command_palette.py`
* `cli/defenseclaw/tui/registry.py` (where `build_registry`, `match_command`,
  `match_cli_args` live; the palette uses these for fuzzy filtering)
* `cli/defenseclaw/tui/command_line.py` (the floating input below the
  palette — depends on app layout; verify side-by-side wiring here)

> Note: there is a *second* command palette inside the Playground modal
> at `creator/command_palette.py`. That one is covered by plan 27.

---

## 2. File layout

```
cli/tests/tui/
  test_command_palette_model.py     # L1 — registry, match, filter
  test_command_palette_screen.py    # L2 + L3
  test_command_palette_snapshot.py  # L4
  test_command_palette_invariants.py# L5
```

---

## 3. Input-surface inventory

### 3.1 Keys

| ID | Key | Effect |
|---|---|---|
| K01 | `Esc` | dismiss with `None` |
| K02 | `Enter` | dismiss with current match (or `None` if no matches) |
| K03 | `↑` | move cursor up |
| K04 | `↓` | move cursor down |
| K05 | any char | typed into `#cp-input`; triggers filter |
| K06 | `Backspace` | drop char |
| K07 | `Ctrl+A` (typical Textual Input bind) | select all in input |

### 3.2 Clicks

* C01 — Click on input → focus.
* C02 — Click on a row in the filtered list → set cursor (Textual Static
  doesn't accept row clicks natively, so this may be a no-op — verify and
  document).

### 3.3 Triggers (from app shell)

* G01 — `Ctrl+K` from any panel pushes the palette.
* G02 — `:` from any panel pushes the palette.
* G03 — Help button click pushes the palette (verify per app.py).

---

## 4. L1 — Pure model tests (registry & filter)

### 4.1 `build_registry`

* `test_build_registry_returns_non_empty_tuple`.
* `test_build_registry_entries_have_unique_labels`.
* `test_build_registry_entries_have_unique_argv_tails`.

### 4.2 `match_command`

For each registered command, write a test that pasting the full label or a
substring returns the expected entry and the remainder string.

* `test_match_command_exact_label_returns_entry`.
* `test_match_command_prefix_returns_entry_with_remainder`.
* `test_match_command_substring_returns_entry`.
* `test_match_command_no_match_returns_none`.

### 4.3 `match_cli_args`

* For each argv tail, assert returned entry.
* Negative: unknown argv tail returns `(None, ...)`.

### 4.4 `filter_commands` (from `creator/command_palette` — confirm import)

* `test_filter_commands_empty_query_returns_all`.
* `test_filter_commands_query_filters_by_label_and_hint`.
* `test_filter_commands_is_case_insensitive`.
* `test_filter_commands_unicode_friendly`.
* `test_filter_commands_returns_deterministic_order`.

---

## 5. L2 + L3 — Screen integration

### 5.1 Push and dismiss

```python
async def test_command_palette_opens_with_ctrl_k(piloted_app):
    async with piloted_app() as (app, pilot):
        await pilot.press("ctrl+k")
        await pilot.pause()
        assert_screen_is(app, CommandPaletteScreen)


async def test_command_palette_opens_with_colon(piloted_app):
    async with piloted_app() as (app, pilot):
        await pilot.press(":")
        await pilot.pause()
        assert_screen_is(app, CommandPaletteScreen)


async def test_command_palette_dismiss_with_esc_returns_none(piloted_app):
    async with piloted_app() as (app, pilot):
        await pilot.press("ctrl+k", "escape")
        await pilot.pause()
        assert type(app.screen).__name__ == "Screen"


async def test_command_palette_enter_dispatches_selected_command(piloted_app, fake_executor):
    async with piloted_app() as (app, pilot):
        await pilot.press("ctrl+k")
        await pilot.pause()
        # Type a query that selects "defenseclaw doctor"
        await press_keys(pilot, "d", "o", "c", "t", "o", "r")
        await pilot.press("enter")
        await pilot.pause()
        assert any(call[0][:2] == ("defenseclaw", "doctor") for call in fake_executor.calls)
```

### 5.2 Cursor

* K03 / K04 — assert `_cursor` field updates and the list re-renders with
  the new highlight.
* Cursor must not go below 0 or above `len(matches) - 1`.

### 5.3 Empty matches

* `test_palette_with_no_matches_dismisses_with_none_on_enter`.

### 5.4 Long match list (>14)

* Type to filter to ≥14 results.
* Assert the "+N more" footer appears.
* Assert moving cursor below row 14 still works.

---

## 6. L4 — Snapshot scenes

* `command_palette_empty_query`
* `command_palette_query_partial_match`
* `command_palette_query_no_match`
* `command_palette_long_list_with_overflow`

× 3 sizes = **12 SVGs**.

---

## 7. L5

* `test_filter_commands_terminates_for_any_unicode_query` (Hypothesis).
* `test_cursor_in_bounds_for_any_key_sequence` (Hypothesis).
* `test_filter_then_clear_returns_initial_match_list`.

---

## 8. Known defects to file

* If `Ctrl+K` is pressed twice and stacks two modal screens → file P0.
* If `:` is typed while a filter input on a panel is focused → the panel
  filter should absorb it, not push the palette → confirm and assert.

---

## 9. Coverage matrix

Per K, C, G ID.

---

## 10. Deliverables

* [ ] Four files.
* [ ] 12 SVGs.
* [ ] Coverage `screens/command_palette.py` ≥ 95 %.
* [ ] Coverage `registry.py` ≥ 95 %.
* [ ] Matrix complete.
