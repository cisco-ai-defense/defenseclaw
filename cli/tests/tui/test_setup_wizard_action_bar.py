"""Regressions for the Setup wizard-form action bar (Phase 1c click-first plan).

Lives in its own module so it stays out of the way of the broader
``test_app_shell.py`` churn — the wizard sub-bar is a contained
surface and these tests are read more easily next to each other.

Each test follows the same arc: open the Setup panel (key ``0``),
open a wizard form (key ``enter`` on the wizard list), then poke the
``#setup-wizard-*`` buttons through ``_handle_setup_control`` so we
exercise the full Button.Pressed → dispatcher → ``_handle_setup_key``
pipeline that real mouse clicks traverse.
"""

from __future__ import annotations

from dataclasses import replace

import pytest
from textual.widgets import Button

from cli.defenseclaw.tui.app import DefenseClawTUI


@pytest.mark.asyncio
async def test_setup_wizard_bar_hidden_until_form_opens() -> None:
    """The wizard action bar appears only after `form_active` flips True.

    The bar would be confusing on the wizard list (Run what?) and the
    config editor (no form to submit), so visibility is gated on
    ``setup_model.form_active`` in ``_render_panel_controls``.
    """

    app = DefenseClawTUI()
    async with app.run_test(size=(180, 50)) as pilot:
        await pilot.press("0")  # Setup panel key.
        await pilot.pause()
        assert app.active_panel == "setup"
        bar = app.query_one("#setup-wizard-controls")
        assert bar.has_class("hidden") is True

        # Open first wizard form via the same keystroke the user uses.
        await pilot.press("enter")
        await pilot.pause()
        assert app.setup_model.form_active is True
        assert bar.has_class("hidden") is False

        # Closing the form should hide the bar again.
        await pilot.press("escape")
        await pilot.pause()
        assert app.setup_model.form_active is False
        assert bar.has_class("hidden") is True


@pytest.mark.asyncio
async def test_setup_wizard_bar_run_disabled_when_required_fields_missing() -> None:
    """Run button greys out when `missing_required_fields()` is non-empty.

    Force-empties the wizard's required fields (substituted via
    ``dataclasses.replace`` because ``WizardFormField`` is frozen) so
    the assertion holds regardless of which wizard happens to be first
    today. If a wizard genuinely has no required fields, the contract
    is "disabled IFF missing", so the alternate branch passes too.
    """

    app = DefenseClawTUI()
    async with app.run_test(size=(180, 50)) as pilot:
        await pilot.press("0")
        await pilot.press("enter")
        await pilot.pause()
        app.setup_model.form_fields = [
            replace(field, value="") if field.required else field
            for field in app.setup_model.form_fields
        ]
        app._render_chrome()  # noqa: SLF001 - explicit re-sync after mutation.
        await pilot.pause()
        run_button = app.query_one("#setup-wizard-run", Button)
        if app.setup_model.missing_required_fields():
            assert run_button.disabled is True
        else:
            assert run_button.disabled is False


@pytest.mark.asyncio
async def test_setup_wizard_cancel_button_closes_form() -> None:
    """Cancel button routes to the same `close_wizard_form()` Esc fires."""

    app = DefenseClawTUI()
    async with app.run_test(size=(180, 50)) as pilot:
        await pilot.press("0")
        await pilot.press("enter")
        await pilot.pause()
        assert app.setup_model.form_active is True
        app._handle_setup_control("setup-wizard-cancel")  # noqa: SLF001
        await pilot.pause()
        assert app.setup_model.form_active is False


@pytest.mark.asyncio
async def test_setup_wizard_next_prev_buttons_move_cursor() -> None:
    """Prev / Next buttons advance and retreat `form_cursor`."""

    app = DefenseClawTUI()
    async with app.run_test(size=(180, 50)) as pilot:
        await pilot.press("0")
        await pilot.press("enter")
        await pilot.pause()
        navigable = [f for f in app.setup_model.form_fields if f.kind != "section"]
        if len(navigable) < 2:
            return  # Single-field wizards can't move; nothing to assert.
        start = app.setup_model.form_cursor
        app._handle_setup_control("setup-wizard-next")  # noqa: SLF001
        await pilot.pause()
        assert app.setup_model.form_cursor != start
        moved = app.setup_model.form_cursor
        app._handle_setup_control("setup-wizard-prev")  # noqa: SLF001
        await pilot.pause()
        assert app.setup_model.form_cursor != moved


@pytest.mark.asyncio
async def test_setup_wizard_clear_button_wipes_focused_value() -> None:
    """Clear field button blanks the focused field's value (Ctrl+U parity)."""

    app = DefenseClawTUI()
    async with app.run_test(size=(180, 50)) as pilot:
        await pilot.press("0")
        await pilot.press("enter")
        await pilot.pause()
        target_idx = None
        for idx, field in enumerate(app.setup_model.form_fields):
            if field.kind in {"string", "password", "int"}:
                target_idx = idx
                break
        if target_idx is None:
            return  # No clearable fields in this wizard.
        app.setup_model.form_cursor = target_idx
        app.setup_model.form_fields[target_idx] = replace(
            app.setup_model.form_fields[target_idx], value="junk"
        )
        await pilot.pause()
        app._handle_setup_control("setup-wizard-clear")  # noqa: SLF001
        await pilot.pause()
        assert app.setup_model.form_fields[target_idx].value == ""


@pytest.mark.asyncio
async def test_setup_wizard_reveal_button_only_enabled_for_secret_fields() -> None:
    """Toggle reveal is enabled iff focused field kind is ``password``."""

    app = DefenseClawTUI()
    async with app.run_test(size=(180, 50)) as pilot:
        await pilot.press("0")
        await pilot.press("enter")
        await pilot.pause()
        password_idx = None
        non_password_idx = None
        for idx, field in enumerate(app.setup_model.form_fields):
            if field.kind == "password" and password_idx is None:
                password_idx = idx
            elif field.kind not in {"password", "section"} and non_password_idx is None:
                non_password_idx = idx
        reveal = app.query_one("#setup-wizard-reveal", Button)
        if non_password_idx is not None:
            app.setup_model.form_cursor = non_password_idx
            app._render_chrome()  # noqa: SLF001
            await pilot.pause()
            assert reveal.disabled is True
        if password_idx is not None:
            app.setup_model.form_cursor = password_idx
            app._render_chrome()  # noqa: SLF001
            await pilot.pause()
            assert reveal.disabled is False
