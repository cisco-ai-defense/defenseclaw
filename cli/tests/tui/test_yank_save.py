# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for Step 10: Y copies output, Ctrl+S writes last-run.log.

Focus on the pure helpers (``_clipboard_copy``, ``_last_run_output_payload``,
``action_save_last_run_log``) so the test suite stays hermetic. The
async Textual end-to-end tests in ``test_app_shell`` still cover the
real keystroke pipeline.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from unittest.mock import patch

import pytest

from defenseclaw.tui.app import DefenseClawTUI


@dataclass
class _Guardrail:
    mode: str = "ask"
    enabled: bool = True
    connector: str = "openclaw"
    paths: object | None = None


@dataclass
class _Claw:
    mode: str = "openclaw"


@dataclass
class _Config:
    guardrail: _Guardrail = field(default_factory=_Guardrail)
    claw: _Claw = field(default_factory=_Claw)


def _make_app(tmp_path: Path) -> DefenseClawTUI:
    return DefenseClawTUI(config=_Config(), data_dir=tmp_path)


def _seed_entry(app: DefenseClawTUI, output: tuple[str, ...] = ("line one", "line two")) -> None:
    """Push a fake completed entry into the activity model.

    The real ``add_entry`` / ``append_output`` / ``finish_entry`` flow
    is what production uses; we mirror it here so the helpers see an
    entry that looks just like a finished CLI run.
    """

    app.activity_model.add_entry("doctor", masked_argv=("defenseclaw", "doctor"))
    for line in output:
        app.activity_model.append_output(line)
    app.activity_model.finish_entry(0)


# ---------------------------------------------------------------------------
# _last_run_output_payload
# ---------------------------------------------------------------------------


def test_payload_returns_none_with_no_entries(tmp_path: Path) -> None:
    """Fresh TUI → no Activity entries → helper must say so cleanly."""

    app = _make_app(tmp_path)
    assert app._last_run_output_payload() is None


def test_payload_includes_header_and_body(tmp_path: Path) -> None:
    """Payload header carries command + status + timestamps; body
    is the joined output stream so callers can split responsibility."""

    app = _make_app(tmp_path)
    _seed_entry(app, ("hello", "world"))

    payload = app._last_run_output_payload()
    assert payload is not None
    header, body = payload
    assert "doctor" in header
    assert "started " in header
    assert "saved   " in header
    assert body == "hello\nworld"


# ---------------------------------------------------------------------------
# _clipboard_copy
# ---------------------------------------------------------------------------


def test_clipboard_copy_falls_back_to_file_when_no_tool(tmp_path: Path) -> None:
    """No pbcopy / wl-copy / xclip / xsel on PATH must NOT silently
    fail — we always end up writing a file fallback so operators on
    bare containers still have a way to recover the bytes."""

    app = _make_app(tmp_path)
    with patch("defenseclaw.tui.app.shutil.which", return_value=None):
        ok, transport = app._clipboard_copy("hello world")
    assert ok is True
    assert transport.startswith("file:")
    fallback_path = Path(transport.removeprefix("file:"))
    assert fallback_path.exists()
    assert fallback_path.read_text(encoding="utf-8") == "hello world"
    # Mode is 0600 on POSIX (Windows ignores chmod; test still passes
    # because we mode-mask before comparing).
    if os.name == "posix":
        assert fallback_path.stat().st_mode & 0o777 == 0o600


def test_clipboard_copy_uses_pbcopy_when_present(tmp_path: Path) -> None:
    """When ``pbcopy`` is on PATH and exits 0, the helper reports it
    as the transport (not the file fallback)."""

    app = _make_app(tmp_path)

    class _FakeProc:
        returncode = 0

    with (
        patch("defenseclaw.tui.app.shutil.which", side_effect=lambda name: "/usr/bin/" + name if name == "pbcopy" else None),
        patch("defenseclaw.tui.app.subprocess.run", return_value=_FakeProc()) as mock_run,
    ):
        ok, transport = app._clipboard_copy("hello")
    assert ok is True
    assert transport == "pbcopy"
    # Confirm the argv we built actually pipes stdin to pbcopy.
    call = mock_run.call_args
    assert call is not None
    assert call.args[0] == ("pbcopy",)
    assert call.kwargs["input"] == b"hello"


def test_clipboard_copy_skips_failing_tool_and_keeps_trying(tmp_path: Path) -> None:
    """A pbcopy that exits non-zero shouldn't abort the chain — the
    helper must keep walking the transports until one succeeds."""

    app = _make_app(tmp_path)
    calls: list[str] = []

    class _Fail:
        returncode = 1

    class _Ok:
        returncode = 0

    def _which(name: str) -> str | None:
        return "/usr/bin/" + name

    def _run(argv, **_: object):
        calls.append(argv[0])
        # pbcopy is the first transport tried — make it fail so we
        # exercise the "keep looking" path. wl-copy is second; let
        # that one succeed.
        return _Ok() if argv[0] == "wl-copy" else _Fail()

    with (
        patch("defenseclaw.tui.app.shutil.which", side_effect=_which),
        patch("defenseclaw.tui.app.subprocess.run", side_effect=_run),
    ):
        ok, transport = app._clipboard_copy("payload")
    assert ok is True
    assert transport == "wl-copy"
    assert calls[:2] == ["pbcopy", "wl-copy"]


def test_clipboard_copy_empty_text_returns_false(tmp_path: Path) -> None:
    """Empty payload shouldn't pollute the clipboard or write zero-
    byte fallback files. The handler interprets this as "nothing to
    copy"."""

    app = _make_app(tmp_path)
    ok, transport = app._clipboard_copy("")
    assert ok is False
    assert transport == ""


# ---------------------------------------------------------------------------
# action_save_last_run_log
# ---------------------------------------------------------------------------


def test_action_save_last_run_log_writes_to_data_dir(tmp_path: Path) -> None:
    """``Ctrl+S`` writes ``<data_dir>/last-run.log`` so external
    tail-ers can rely on a stable path."""

    app = _make_app(tmp_path)
    _seed_entry(app, ("alpha", "beta", "gamma"))

    captured: list[tuple[str, str]] = []
    app.notify_toast = lambda level, msg: captured.append((level, msg))  # type: ignore[assignment]

    app.action_save_last_run_log()

    log_path = tmp_path / "last-run.log"
    assert log_path.exists()
    contents = log_path.read_text(encoding="utf-8")
    assert "alpha\nbeta\ngamma" in contents
    assert "# doctor" in contents
    # Mode 0600 on POSIX (Windows ignores; skip cleanly).
    if os.name == "posix":
        assert log_path.stat().st_mode & 0o777 == 0o600
    assert captured, "Ctrl+S must emit a toast confirming the save"
    level, msg = captured[-1]
    assert level == "success"
    assert "last-run.log" in msg


def test_action_save_last_run_log_warns_when_no_entries(tmp_path: Path) -> None:
    """Pressing Ctrl+S before any command has run shouldn't crash —
    it must surface a 'no output yet' warn toast."""

    app = _make_app(tmp_path)

    captured: list[tuple[str, str]] = []
    app.notify_toast = lambda level, msg: captured.append((level, msg))  # type: ignore[assignment]

    app.action_save_last_run_log()

    assert (tmp_path / "last-run.log").exists() is False
    assert captured == [("warn", "No command output to save yet.")]


# ---------------------------------------------------------------------------
# action_yank_output
# ---------------------------------------------------------------------------


def test_action_yank_output_warns_when_no_entries(tmp_path: Path) -> None:
    """Same UX as save: fresh TUI → Y toasts a friendly warn, not a
    silent no-op."""

    app = _make_app(tmp_path)

    captured: list[tuple[str, str]] = []
    app.notify_toast = lambda level, msg: captured.append((level, msg))  # type: ignore[assignment]

    app.action_yank_output()

    assert captured == [("warn", "No command output to copy yet.")]


def test_action_yank_output_warns_on_empty_body(tmp_path: Path) -> None:
    """An Activity entry with header but no streamed lines should
    still warn rather than copy a blank string to the clipboard."""

    app = _make_app(tmp_path)
    _seed_entry(app, output=())

    captured: list[tuple[str, str]] = []
    app.notify_toast = lambda level, msg: captured.append((level, msg))  # type: ignore[assignment]

    app.action_yank_output()
    assert captured and captured[-1] == ("warn", "Last command produced no output.")


def test_action_yank_output_success_path(tmp_path: Path) -> None:
    """Happy path: with output + a working clipboard tool, Y toasts
    a green ``success`` with the transport name."""

    app = _make_app(tmp_path)
    _seed_entry(app, ("the-result",))

    class _Ok:
        returncode = 0

    captured: list[tuple[str, str]] = []
    app.notify_toast = lambda level, msg: captured.append((level, msg))  # type: ignore[assignment]

    with (
        patch("defenseclaw.tui.app.shutil.which", side_effect=lambda name: "/usr/bin/" + name if name == "pbcopy" else None),
        patch("defenseclaw.tui.app.subprocess.run", return_value=_Ok()),
    ):
        app.action_yank_output()

    assert captured and captured[-1][0] == "success"
    assert "pbcopy" in captured[-1][1]
