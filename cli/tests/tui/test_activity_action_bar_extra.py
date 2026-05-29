"""Extra regressions for the Activity action bar (Phase 1a code-review gaps).

The core tests live in ``test_app_shell.py`` next to their siblings,
but ``test_app_shell.py`` is the highest-churn test file in the TUI
suite — placing these in their own module keeps them out of merge /
overwrite collisions when other agents land changes touching the
broader shell tests.

Covers gaps the initial Phase 1a test set missed:

* Cancel button visible (and enabled) when a command is actually
  running — the inverse of ``test_activity_panel_exposes_clickable_action_bar``
  which only proves it's hidden when idle.
* View in Drawer button routes to ``action_open_command`` — without
  this test the button could silently fail to fire the palette.
* Stdin submission gracefully handles broken-pipe / executor errors —
  the TUI must never crash because a subprocess just exited mid-write.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from textual.widgets import Button, Input

from defenseclaw.tui.app import DefenseClawTUI


@pytest.mark.asyncio
async def test_activity_cancel_button_visible_when_command_running() -> None:
    """Cancel joins the bar while a command is live (positive path).

    The hidden-on-idle assertion lives in
    ``test_activity_panel_exposes_clickable_action_bar``; this is the
    inverse — without it a regression that always-hides Cancel would
    pass the idle test but leave operators with no way to abort a
    runaway subprocess except Ctrl+C.
    """

    app = DefenseClawTUI()
    async with app.run_test(size=(180, 50)) as pilot:
        await pilot.press("A")
        await pilot.pause()
        # Flip the running flag and let the periodic-sync helper run.
        app.command_running = True
        app._render_chrome()  # noqa: SLF001
        await pilot.pause()
        cancel = app.query_one("#activity-cancel", Button)
        assert cancel.has_class("hidden") is False
        assert cancel.disabled is False


@pytest.mark.asyncio
async def test_activity_view_in_drawer_routes_to_open_command(monkeypatch) -> None:
    """View in Drawer button fires ``action_open_command`` (same as ``:``).

    The button exists so operators in a mouse-only terminal can pop
    the command palette without remembering ``:`` — but the contract
    is "same as the keystroke". Without this test a refactor that
    points the button at a half-built drawer wouldn't be noticed.
    """

    app = DefenseClawTUI()
    opened: list[bool] = []
    async with app.run_test(size=(180, 50)) as pilot:
        await pilot.press("A")
        await pilot.pause()
        monkeypatch.setattr(app, "action_open_command", lambda: opened.append(True))
        app._handle_activity_control("activity-open-drawer")  # noqa: SLF001
        await pilot.pause()
        assert opened == [True]


@pytest.mark.asyncio
async def test_activity_stdin_submission_handles_executor_error() -> None:
    """If ``executor.write_stdin`` raises, surface a status, don't crash.

    The TUI must never let a single bad write into a subprocess pipe
    take down the whole interface — broken pipes are a routine failure
    mode when a subprocess just exited. The handler catches broadly
    on purpose; this test locks in the contract so a future refactor
    that propagates the exception is caught immediately.
    """

    app = DefenseClawTUI()
    async with app.run_test(size=(180, 50)) as pilot:
        await pilot.press("A")
        await pilot.pause()
        app.command_running = True

        def boom(_text: str) -> None:
            raise OSError("[Errno 32] Broken pipe")

        app.executor.write_stdin = boom  # type: ignore[assignment]
        app._render_chrome()  # noqa: SLF001
        await pilot.pause()
        stdin = app.query_one("#activity-stdin", Input)
        app._on_activity_stdin_submitted(  # noqa: SLF001
            SimpleNamespace(input=stdin, value="3", validation_result=None)
        )
        # Status should describe the failure (so the operator knows
        # the input didn't make it through). The TUI must still be
        # responsive — proven by being able to query the input.
        assert "Send failed" in app.status_text
        assert "Broken pipe" in app.status_text
