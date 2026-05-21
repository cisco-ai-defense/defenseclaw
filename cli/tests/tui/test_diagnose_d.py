# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for Step 11: ``D`` runs defenseclaw doctor in the background.

Covers:
    * The pure ``_diagnose_summary_line`` helper used to pick the
      toast text.
    * The async ``_run_diagnose_background`` worker — pyatest-asyncio
      gives us a real event loop so the worker can ``await`` an
      ``asyncio.create_subprocess_exec`` we monkeypatch to a fake.
    * The synchronous ``action_run_diagnose`` guard rail that refuses
      to launch when another command is already running.

End-to-end keystroke routing is covered by the async ``test_app_shell``
suite via the regular ``run_test`` pilot harness.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pytest

from defenseclaw.tui.app import DefenseClawTUI, _diagnose_summary_line


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


def _capture_toasts(app: DefenseClawTUI) -> list[tuple[str, str]]:
    """Replace notify_toast with a list-collector so tests can
    assert on emitted toast levels/messages without spinning up
    Textual."""

    captured: list[tuple[str, str]] = []
    app.notify_toast = lambda level, msg: captured.append((level, msg))  # type: ignore[assignment]
    return captured


# ---------------------------------------------------------------------------
# _diagnose_summary_line
# ---------------------------------------------------------------------------


def test_summary_picks_summary_line_first() -> None:
    """A line containing the word "summary" wins outright — matches
    the Go TUI's preference."""

    out = _diagnose_summary_line(
        [
            "scanning skills…",
            "scanning mcps…",
            "Summary: All checks passed",
        ]
    )
    assert out == "Summary: All checks passed"


def test_summary_falls_back_to_verdict_keyword() -> None:
    """No 'summary' line → next-best is a verdict (checks passed,
    issues detected, etc.)."""

    out = _diagnose_summary_line(["doing stuff", "All checks passed"])
    assert out == "All checks passed"


def test_summary_returns_first_line_when_no_verdict() -> None:
    """Junk output with no recognizable verdict → first non-empty
    line so the toast still says *something* useful."""

    out = _diagnose_summary_line(["hello world", "and another line"])
    assert out == "hello world"


def test_summary_handles_empty_list() -> None:
    """Empty doctor output (CLI printed nothing) → empty string so
    caller can render "Doctor OK" without a trailing separator."""

    assert _diagnose_summary_line([]) == ""


def test_summary_strips_punctuation() -> None:
    """The leading/trailing colons + dashes that doctor uses as
    section dividers shouldn't leak into the toast."""

    out = _diagnose_summary_line(["= Summary ="])
    assert out == "Summary"


# ---------------------------------------------------------------------------
# action_run_diagnose guard rail
# ---------------------------------------------------------------------------


def test_action_run_diagnose_refuses_when_command_running(tmp_path: Path) -> None:
    """Don't launch a second subprocess while one is already streaming
    through the executor — toast a warn instead."""

    app = _make_app(tmp_path)
    app.command_running = True
    captured = _capture_toasts(app)

    app.action_run_diagnose()
    assert captured, "expected a warn toast"
    assert captured[0][0] == "warn"
    assert "another command is running" in captured[0][1].lower()


# ---------------------------------------------------------------------------
# _run_diagnose_background subprocess wiring
# ---------------------------------------------------------------------------


class _FakeProc:
    """Mimic the subset of ``asyncio.subprocess.Process`` we use."""

    def __init__(self, *, returncode: int, stdout: bytes) -> None:
        self.returncode = returncode
        self._stdout = stdout

    async def communicate(self) -> tuple[bytes, bytes]:
        return self._stdout, b""

    def kill(self) -> None:  # pragma: no cover - kill only fires on timeout
        pass


@pytest.mark.asyncio
async def test_run_diagnose_background_success_toast(tmp_path: Path) -> None:
    """Zero-exit + good summary → green ``success`` toast with the
    summary line appended."""

    app = _make_app(tmp_path)
    captured = _capture_toasts(app)

    async def _fake_exec(*_args: object, **_kwargs: object) -> _FakeProc:
        return _FakeProc(
            returncode=0,
            stdout=b"scanning skills\nSummary: All checks passed\n",
        )

    import defenseclaw.tui.app as app_mod

    monkey_target = "asyncio.create_subprocess_exec"
    with pytest.MonkeyPatch().context() as mp:
        mp.setattr(app_mod.asyncio, "create_subprocess_exec", _fake_exec)
        await app._run_diagnose_background()

    assert captured, "expected a toast"
    level, msg = captured[-1]
    assert level == "success"
    assert "All checks passed" in msg


@pytest.mark.asyncio
async def test_run_diagnose_background_failure_toast(tmp_path: Path) -> None:
    """Non-zero exit → ``warn`` toast carrying the last meaningful
    output line so the operator knows what went wrong."""

    app = _make_app(tmp_path)
    captured = _capture_toasts(app)

    async def _fake_exec(*_args: object, **_kwargs: object) -> _FakeProc:
        return _FakeProc(
            returncode=2,
            stdout=b"scan A\nscan B\nFAILED: gateway unreachable\n",
        )

    import defenseclaw.tui.app as app_mod

    with pytest.MonkeyPatch().context() as mp:
        mp.setattr(app_mod.asyncio, "create_subprocess_exec", _fake_exec)
        await app._run_diagnose_background()

    assert captured, "expected a toast"
    level, msg = captured[-1]
    assert level == "warn"
    assert "exit 2" in msg
    assert "gateway unreachable" in msg


@pytest.mark.asyncio
async def test_run_diagnose_background_handles_missing_binary(tmp_path: Path) -> None:
    """If ``defenseclaw`` isn't on PATH the launcher raises and we
    must toast a clear error — not blow up with a traceback."""

    app = _make_app(tmp_path)
    captured = _capture_toasts(app)

    async def _raise(*_args: object, **_kwargs: object) -> _FakeProc:
        raise FileNotFoundError("defenseclaw")

    import defenseclaw.tui.app as app_mod

    with pytest.MonkeyPatch().context() as mp:
        mp.setattr(app_mod.asyncio, "create_subprocess_exec", _raise)
        await app._run_diagnose_background()

    assert captured, "expected an error toast"
    level, msg = captured[-1]
    assert level == "error"
    assert "failed to launch" in msg.lower()


@pytest.mark.asyncio
async def test_run_diagnose_background_strips_ansi_codes(tmp_path: Path) -> None:
    """``defenseclaw doctor`` colours its output with ANSI escape
    sequences; the toast must not display raw ``\\x1b[…m`` runs."""

    app = _make_app(tmp_path)
    captured = _capture_toasts(app)

    async def _fake_exec(*_args: object, **_kwargs: object) -> _FakeProc:
        return _FakeProc(
            returncode=0,
            stdout=b"\x1b[32mSummary: All checks passed\x1b[0m\n",
        )

    import defenseclaw.tui.app as app_mod

    with pytest.MonkeyPatch().context() as mp:
        mp.setattr(app_mod.asyncio, "create_subprocess_exec", _fake_exec)
        await app._run_diagnose_background()

    assert captured, "expected a toast"
    _, msg = captured[-1]
    assert "\x1b" not in msg
    assert "All checks passed" in msg
