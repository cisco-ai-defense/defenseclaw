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
from defenseclaw.tui.app import DefenseClawTUI
from textual.widgets import Button


async def _open_first_wizard_form(pilot) -> None:
    """Open the Setup panel and the first wizard's form.

    ``enter`` on the wizard list now opens the goal menu (the
    "what do you want to do?" step); a second ``enter`` selects the
    first goal which opens the filtered form. Tests that only care
    about the form sub-bar drive straight through to the form here.
    """

    await pilot.press("0")  # Setup panel key.
    await pilot.pause()
    await pilot.press("enter")  # wizard list -> goal menu.
    await pilot.pause()
    await pilot.press("enter")  # goal menu -> filtered form.
    await pilot.pause()


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

        # Enter opens the goal menu; the bar stays hidden there too.
        await pilot.press("enter")
        await pilot.pause()
        assert app.setup_model.goal_active is True
        assert bar.has_class("hidden") is True

        # Selecting a goal opens the filtered form.
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
        await _open_first_wizard_form(pilot)
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
        await _open_first_wizard_form(pilot)
        assert app.setup_model.form_active is True
        app._handle_setup_control("setup-wizard-cancel")  # noqa: SLF001
        await pilot.pause()
        assert app.setup_model.form_active is False


@pytest.mark.asyncio
async def test_setup_wizard_next_prev_buttons_move_cursor() -> None:
    """Prev / Next buttons advance and retreat `form_cursor`."""

    app = DefenseClawTUI()
    async with app.run_test(size=(180, 50)) as pilot:
        await _open_first_wizard_form(pilot)
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
        await _open_first_wizard_form(pilot)
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
        await _open_first_wizard_form(pilot)
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


@pytest.mark.asyncio
async def test_setup_wizard_run_button_submits_form_when_ready(monkeypatch) -> None:
    """Run button fires ``submit_wizard_form`` + flows the intent forward.

    Positive sibling to ``test_setup_wizard_bar_run_disabled_when_...``.
    Without this test a regression that pointed Run at the wrong key
    (e.g. ``enter`` instead of ``ctrl+r``) would only show up in
    manual QA — the submit path is the entire reason the wizard
    sub-bar exists.
    """

    from defenseclaw.tui.panels.setup import SetupCommandIntent, SetupPanelAction

    app = DefenseClawTUI()
    async with app.run_test(size=(180, 50)) as pilot:
        await _open_first_wizard_form(pilot)
        assert app.setup_model.form_active is True

        # Pre-load a fake submit result so the handler thinks the
        # form is valid and a real intent should flow to the
        # preview-and-run pipeline. We don't want the real argv
        # builder to actually shell out during the test.
        fake_intent = SetupCommandIntent(
            label="defenseclaw test wizard",
            args=("test", "wizard"),
        )

        def fake_submit() -> SetupPanelAction:
            return SetupPanelAction(handled=True, intent=fake_intent)

        monkeypatch.setattr(app.setup_model, "submit_wizard_form", fake_submit)

        captured: list[SetupCommandIntent] = []

        # ``_confirm_and_run_intent`` is consumed via ``run_worker``
        # which insists on a coroutine, so the patch must return one
        # — a sync lambda raises ``WorkerError: Unsupported attempt to
        # run an async worker``.
        async def fake_confirm(intent: SetupCommandIntent) -> None:
            captured.append(intent)

        monkeypatch.setattr(app, "_confirm_and_run_intent", fake_confirm)

        app._handle_setup_control("setup-wizard-run")  # noqa: SLF001
        await pilot.pause()
        assert captured == [fake_intent], (
            "Run button must route the SetupCommandIntent through "
            "_confirm_and_run_intent, mirroring the Ctrl+R flow."
        )


@pytest.mark.asyncio
async def test_setup_wizard_buttons_set_status_when_form_inactive() -> None:
    """Wizard buttons defend against being fired while no form is open.

    The sub-bar is hidden when ``form_active`` is False, so these
    clicks shouldn't normally be possible — but a mouse-down race or
    a stale Textual focus path could still deliver one. The handler
    must surface a status instead of falling through to a key handler
    that would misinterpret Ctrl+R on the wizard list.
    """

    app = DefenseClawTUI()
    async with app.run_test(size=(180, 50)) as pilot:
        await pilot.press("0")  # Setup panel, but wizard list (no form).
        await pilot.pause()
        assert app.setup_model.form_active is False
        for wizard_button in (
            "setup-wizard-run",
            "setup-wizard-cancel",
            "setup-wizard-prev",
            "setup-wizard-next",
            "setup-wizard-reveal",
            "setup-wizard-clear",
        ):
            app._handle_setup_control(wizard_button)  # noqa: SLF001
            await pilot.pause()
            assert "Open a wizard first" in app.status_text, (
                f"{wizard_button} should set status when form inactive, "
                f"got {app.status_text!r}"
            )
            # form_active must remain False — handler must not
            # accidentally open the form via the key dispatcher.
            assert app.setup_model.form_active is False
