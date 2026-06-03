"""Click-first action bars for the catalog panels (Skills / MCPs /
Plugins / Tools).

These tests cover the new control bars that mirror the keyboard flow:
each catalog panel exposes a ``<panel>-controls`` ``Horizontal`` with a
``<panel>-filter`` ``Input`` plus a row of action buttons whose ids
follow ``<panel>-<suffix>``. The buttons route through the shared
``_handle_catalog_control`` dispatcher, which translates the click into
a ``CatalogListModel.handle_key`` call so the click and keystroke
paths produce the same intent (preview gating, Activity streaming,
audit records etc. are all shared with the keyboard flow).

These tests intentionally live outside ``test_app_shell.py`` — that
file is the highest-churn test surface in the TUI suite, so isolating
new coverage here avoids merge collisions with other agents touching
the broader shell tests.
"""

from __future__ import annotations

import pytest
from defenseclaw.tui.app import DefenseClawTUI
from textual.containers import Horizontal
from textual.widgets import Button, Input

CATALOG_PANELS: tuple[str, ...] = ("skills", "mcps", "plugins", "tools")


@pytest.mark.asyncio
@pytest.mark.parametrize("panel", CATALOG_PANELS)
async def test_catalog_control_bar_visible_on_panel(panel: str) -> None:
    """The catalog ``<panel>-controls`` bar shows only when its panel is
    the active one and is hidden otherwise. Without this guarantee the
    bars from every catalog panel would stack on top of each other
    (or, worse, the wrong panel's actions would silently fire).
    """

    app = DefenseClawTUI()
    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause()
        app.action_switch_panel(panel)
        await pilot.pause()
        # Cancel background _load_catalog_model workers spawned by
        # action_switch_panel — in CI they can outlive the test context
        # and crash _render_chrome during teardown.
        app.workers.cancel_all()
        await pilot.pause()
        bar = app.query_one(f"#{panel}-controls", Horizontal)
        assert bar.has_class("hidden") is False, (
            f"{panel}-controls should be visible while the {panel} panel is active"
        )
        # Switching to another catalog panel hides the previous bar.
        other = next(other for other in CATALOG_PANELS if other != panel)
        # Plugins is hidden when the active connector doesn't expose
        # plugins (Codex / Claude). Skip that visibility-comparison
        # case to avoid asserting a false negative on Codex test envs.
        if other == "plugins" and not app.plugins_model.is_visible_for_connector():
            return
        app.action_switch_panel(other)
        await pilot.pause()
        app.workers.cancel_all()
        await pilot.pause()
        assert bar.has_class("hidden") is True, (
            f"{panel}-controls must be hidden after switching to {other}"
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("panel", CATALOG_PANELS)
async def test_catalog_filter_input_mounted_and_constrained(panel: str) -> None:
    """Each catalog bar has a ``<panel>-filter`` ``Input`` constrained
    to a narrow width by the ``.panel-controls Input`` CSS rule so the
    bar fits on realistic terminal widths (~120 cells). A regression
    that drops the width constraint would push every action button
    off the right edge and break click-first parity for narrow
    terminals.
    """

    app = DefenseClawTUI()
    async with app.run_test(size=(120, 40)) as pilot:
        await pilot.pause()
        app.action_switch_panel(panel)
        await pilot.pause()
        inp = app.query_one(f"#{panel}-filter", Input)
        # 24 is the CSS-set width; min-width 16 is the floor. Anything
        # above 32 means the constraint was dropped.
        assert inp.region.width <= 32, (
            f"{panel}-filter width={inp.region.width} — Input should be CSS-constrained"
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("panel", CATALOG_PANELS)
async def test_catalog_filter_input_live_filters_model(panel: str) -> None:
    """Typing into the filter ``Input`` live-filters the catalog model
    on every keystroke — no Enter required. Without this contract the
    bar's mouse flow would silently lag the keystroke flow (where
    ``/ filter`` echoes into the body as you type).
    """

    app = DefenseClawTUI()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        app.action_switch_panel(panel)
        await pilot.pause()
        model = app.catalog_models[panel]
        inp = app.query_one(f"#{panel}-filter", Input)
        # Setting Input.value fires Input.Changed which routes through
        # ``_on_<panel>_filter_changed`` → ``set_filter``.
        inp.value = "totally-not-a-real-row"
        await pilot.pause()
        assert model.filter_text == "totally-not-a-real-row"


@pytest.mark.asyncio
@pytest.mark.parametrize("panel", CATALOG_PANELS)
async def test_catalog_filter_clear_button_resets_model_and_input(panel: str) -> None:
    """The Clear button clears BOTH the model's ``filter_text`` AND the
    ``Input`` widget's value. The two used to be able to drift
    (programmatic clear left the box stale, typed text left the model
    stale on bar redraw) — this test pins the contract.
    """

    app = DefenseClawTUI()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        app.action_switch_panel(panel)
        await pilot.pause()
        model = app.catalog_models[panel]
        inp = app.query_one(f"#{panel}-filter", Input)
        inp.value = "needle"
        await pilot.pause()
        assert model.filter_text == "needle"
        # Direct handler call dodges click-coordinate flakiness on
        # narrow viewports without weakening the contract under test.
        app._handle_catalog_control(panel, f"{panel}-filter-clear")  # noqa: SLF001
        await pilot.pause()
        assert model.filter_text == ""
        assert inp.value == ""


@pytest.mark.asyncio
@pytest.mark.parametrize("panel", CATALOG_PANELS)
async def test_catalog_clear_filter_button_disabled_when_no_filter(panel: str) -> None:
    """The ``Clear`` button is greyed when there's no filter to clear so
    the bar honestly advertises "nothing to clear" instead of swallowing
    a click as a silent no-op.
    """

    app = DefenseClawTUI()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        app.action_switch_panel(panel)
        await pilot.pause()
        # Make sure the panel starts with no filter applied.
        app.catalog_models[panel].clear_filter()
        app._sync_catalog_controls(panel)  # noqa: SLF001
        await pilot.pause()
        clear = app.query_one(f"#{panel}-filter-clear", Button)
        assert clear.disabled is True


@pytest.mark.asyncio
@pytest.mark.parametrize("panel", ("skills", "mcps", "plugins"))
async def test_catalog_refresh_button_routes_to_reload_intent(panel: str, monkeypatch) -> None:
    """Clicking ``Refresh`` on Skills / MCPs / Plugins runs the model's
    ``load_intent`` via the shared ``_load_catalog_model`` pipeline —
    i.e. the same code path the ``r`` keystroke takes. Mock the loader
    so the test never spawns a real ``defenseclaw skill list --json``
    subprocess.

    The Tools panel has a different refresh contract (audit-store
    re-read, no subprocess) — covered by
    ``test_tools_refresh_button_refreshes_audit_store`` below.
    """

    app = DefenseClawTUI()

    loaded: list[str] = []

    async def _fake_load(name: str) -> None:
        loaded.append(name)

    monkeypatch.setattr(app, "_load_catalog_model", _fake_load)
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        app.action_switch_panel(panel)
        await pilot.pause()
        # Switching panels may schedule an auto-load — drain that
        # before asserting our click adds a second call.
        loaded.clear()
        app._handle_catalog_control(panel, f"{panel}-refresh")  # noqa: SLF001
        await pilot.pause()
        assert loaded == [panel], (
            f"Refresh on {panel} bar should re-run _load_catalog_model({panel!r})"
        )


@pytest.mark.asyncio
async def test_tools_refresh_button_refreshes_audit_store() -> None:
    """The Tools panel refreshes in-place from the audit store rather
    than re-spawning a CLI subprocess, so a Refresh click should hit
    ``ToolsPanelModel.refresh()`` directly. Without this distinct test
    a Tools-only regression that drops the in-place refresh would
    sail through the parametrized ``_load_catalog_model`` coverage.
    """

    app = DefenseClawTUI()
    calls: list[bool] = []

    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        app.action_switch_panel("tools")
        await pilot.pause()
        # Wrap (not replace) so the underlying refresh still runs and
        # ``handle_key`` still sees a healthy model.
        original = app.tools_model.refresh

        def _spy() -> None:
            calls.append(True)
            original()

        app.tools_model.refresh = _spy  # type: ignore[method-assign]
        app._handle_catalog_control("tools", "tools-refresh")  # noqa: SLF001
        await pilot.pause()
        assert calls == [True]


@pytest.mark.asyncio
@pytest.mark.parametrize("panel", CATALOG_PANELS)
async def test_catalog_row_only_buttons_disabled_when_no_row(panel: str) -> None:
    """``Detail`` / ``Menu`` / ``Scan`` etc. all require a highlighted
    row — they're disabled when the table is empty so clicks can't fall
    into a silent "(no skill selected)" branch.
    """

    app = DefenseClawTUI()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        app.action_switch_panel(panel)
        await pilot.pause()
        # ``action_switch_panel`` schedules a background
        # ``_load_catalog_model`` worker the first time a catalog
        # panel is visited, which repopulates ``model.items`` from
        # disk. On slower runners (Linux CI) that worker can land
        # AFTER we zero the model below and BEFORE the assertion,
        # re-enabling the row-only buttons via the rerendered
        # ``_sync_catalog_controls``. Drain workers first so the
        # empty-state mutation is the last thing the model sees.
        app.workers.cancel_all()
        await pilot.pause()
        model = app.catalog_models[panel]
        # Force the model into an empty state so ``selected()`` is None.
        model.items = ()
        model.filtered = ()
        model.cursor = 0
        app._sync_catalog_controls(panel)  # noqa: SLF001
        # Every catalog bar has at least these row-only suffixes.
        for suffix in ("detail", "menu"):
            btn = app.query_one(f"#{panel}-{suffix}", Button)
            assert btn.disabled is True, (
                f"{panel}-{suffix} should be disabled while the table is empty"
            )


@pytest.mark.asyncio
async def test_skills_reveal_button_focuses_registries_panel(monkeypatch) -> None:
    """The ``Registry`` button on the Skills bar jumps to the Registries
    panel with the row's registry entry focused — same behaviour as the
    ``R`` keystroke. Use the Skills model because Plugins/Tools don't
    expose a Reveal-in-registry action.
    """

    app = DefenseClawTUI()
    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause()
        app.action_switch_panel("skills")
        await pilot.pause()
        # Skip the test if the user has no skills loaded — the click
        # only does anything when there's a selected row, and we'd
        # rather skip than fake catalog-loading machinery here.
        if app.skills_model.selected() is None:
            pytest.skip("no skills loaded in the test environment")
        app._handle_catalog_control("skills", "skills-reveal")  # noqa: SLF001
        await pilot.pause()
        assert app.active_panel == "registries"


@pytest.mark.asyncio
async def test_mcps_add_button_opens_set_form(monkeypatch) -> None:
    """The ``Add`` button on the MCPs bar opens the ``mcp set`` form
    via the same ``open_mcp_set_form`` intent the ``n`` keystroke uses.
    Mock the opener so the test doesn't push a modal.
    """

    app = DefenseClawTUI()
    opened: list[bool] = []

    async def _fake_open() -> None:
        opened.append(True)

    monkeypatch.setattr(app, "_open_mcp_set_form", _fake_open)
    async with app.run_test(size=(160, 40)) as pilot:
        await pilot.pause()
        app.action_switch_panel("mcps")
        await pilot.pause()
        app._handle_catalog_control("mcps", "mcps-add")  # noqa: SLF001
        await pilot.pause()
        assert opened == [True], "mcps-add click should open the mcp set form"


@pytest.mark.asyncio
async def test_catalog_button_dispatch_ignores_unknown_suffix() -> None:
    """An unknown button id under a catalog prefix is a no-op rather
    than crashing — the dispatcher must be defensive so a future bar
    addition that hasn't wired its handler doesn't take down the TUI
    on the first click.
    """

    app = DefenseClawTUI()
    async with app.run_test(size=(140, 40)) as pilot:
        await pilot.pause()
        app.action_switch_panel("skills")
        await pilot.pause()
        # Should NOT raise — silent ignore is the contract.
        app._handle_catalog_control("skills", "skills-this-suffix-does-not-exist")  # noqa: SLF001
        await pilot.pause()
