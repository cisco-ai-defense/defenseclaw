# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Console capability, ASCII fallback, and Textual launch contracts."""

from __future__ import annotations

import io
import json
import os
import sys
from contextlib import contextmanager, redirect_stdout
from pathlib import Path
from unittest import mock

import defenseclaw.main as main_mod
from click.testing import CliRunner
from defenseclaw import ux
from defenseclaw.commands import cmd_doctor, cmd_status
from defenseclaw.commands.cmd_tui import tui
from defenseclaw.config import default_config
from defenseclaw.context import AppContext

_BOX_PRONE = "✓✗⚠─━═│║└↪—…●○"


class _Stream(io.StringIO):
    def __init__(self, *, tty: bool, encoding: str = "utf-8") -> None:
        super().__init__()
        self._tty = tty
        self._encoding = encoding

    @property
    def encoding(self) -> str:
        return self._encoding

    def isatty(self) -> bool:
        return self._tty


@contextmanager
def _render_mode(enabled: bool):
    with (
        mock.patch.object(ux, "_configured_unicode_output", enabled),
        mock.patch.dict(os.environ, {"TERM": "xterm-256color"}, clear=False),
    ):
        yield


def _app() -> AppContext:
    app = AppContext()
    app.cfg = default_config()
    app.cfg.environment = "Málaga 東京"
    app.store = None
    app.logger = None
    return app


def _invoke_status(*args: str, unicode_output: bool):
    app = _app()
    client = mock.Mock()
    client.is_running.return_value = False
    with (
        _render_mode(unicode_output),
        mock.patch.object(cmd_status.shutil, "which", return_value=None),
        mock.patch.object(cmd_status, "resolve_scanner_binary", return_value=None),
        mock.patch.object(
            cmd_status,
            "config_path",
            return_value=Path("C:/Profiles/Málaga/東京/config.yaml"),
        ),
        mock.patch("defenseclaw.gateway.OrchestratorClient", return_value=client),
    ):
        return CliRunner().invoke(
            cmd_status.status,
            list(args),
            obj=app,
            catch_exceptions=False,
        )


def test_console_capability_detects_utf8_legacy_and_redirected_streams() -> None:
    with (
        mock.patch.object(ux, "_configured_unicode_output", None),
        mock.patch.dict(os.environ, {"TERM": "xterm-256color"}, clear=False),
    ):
        assert ux.configure_console_output(_Stream(tty=True, encoding="utf-8")) is True
        assert ux.configure_console_output(_Stream(tty=True, encoding="cp1252")) is False
        assert ux.configure_console_output(_Stream(tty=False, encoding="utf-8")) is False


def test_term_dumb_forces_ascii_even_on_utf8_tty() -> None:
    with (
        mock.patch.object(ux, "_configured_unicode_output", None),
        mock.patch.dict(os.environ, {"TERM": "dumb"}, clear=False),
    ):
        assert ux.configure_console_output(_Stream(tty=True, encoding="utf-8")) is False


def test_ascii_presentation_preserves_ordinary_unicode_text() -> None:
    source = "✓ └─ ready — C:/Profiles/Málaga/東京"
    with _render_mode(False):
        rendered = ux.console_text(source)
    assert rendered == "OK \\- ready - C:/Profiles/Málaga/東京"


def test_modern_console_retains_rich_unicode_presentation() -> None:
    source = "✓ └─ ready — C:/Profiles/Málaga/東京"
    with _render_mode(True):
        assert ux.console_text(source) == source


def test_ascii_mode_suppresses_inherited_force_color() -> None:
    with (
        _render_mode(False),
        mock.patch.dict(os.environ, {"FORCE_COLOR": "1"}, clear=False),
    ):
        assert ux._color_enabled() is False
        assert "\x1b" not in ux._style("✓ ready", fg="green")


def test_status_human_output_is_ascii_safe_on_legacy_console() -> None:
    result = _invoke_status(unicode_output=False)
    assert result.exit_code == 0
    assert "Málaga 東京" in result.output
    assert str(Path("C:/Profiles/Málaga/東京/config.yaml")) in result.output
    assert not any(glyph in result.output for glyph in _BOX_PRONE)
    assert "==================" in result.output


def test_status_human_output_retains_unicode_on_modern_console() -> None:
    result = _invoke_status(unicode_output=True)
    assert result.exit_code == 0
    assert "══════════════════" in result.output
    assert "─" in result.output
    assert "—" in result.output


def test_status_json_preserves_unicode_semantics_in_ascii_mode() -> None:
    result = _invoke_status("--json", unicode_output=False)
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["environment"] == "Málaga 東京"
    assert payload["config"] == str(Path("C:/Profiles/Málaga/東京/config.yaml"))


def test_doctor_human_rows_are_ascii_safe_but_keep_user_text() -> None:
    output = io.StringIO()
    result = cmd_doctor._DoctorResult()
    with (
        _render_mode(False),
        mock.patch.object(cmd_doctor, "_json_mode", False),
        redirect_stdout(output),
    ):
        cmd_doctor._doctor_subsection("Services")
        cmd_doctor._emit(
            "pass",
            "  └─ gateway",
            "ready — C:/Profiles/Málaga/東京",
            r=result,
        )
        cmd_doctor._emit_hint("open Windows Terminal → retry")

    rendered = output.getvalue()
    assert "Málaga/東京" in rendered
    assert not any(glyph in rendered for glyph in _BOX_PRONE)
    assert "\\- gateway" in rendered
    assert "-> open Windows Terminal -> retry" in rendered
    assert result.checks[0]["label"] == "  └─ gateway"
    assert result.checks[0]["detail"] == "ready — C:/Profiles/Málaga/東京"


def test_doctor_human_rows_retain_unicode_on_modern_console() -> None:
    output = io.StringIO()
    with (
        _render_mode(True),
        mock.patch.object(cmd_doctor, "_json_mode", False),
        mock.patch.object(cmd_doctor.ux, "_color_enabled", return_value=True),
        redirect_stdout(output),
    ):
        cmd_doctor._doctor_subsection("Services")
        cmd_doctor._emit("pass", "  └─ gateway", "ready — modern")
        cmd_doctor._emit_hint("retry → now")

    rendered = output.getvalue()
    assert "✓" in rendered
    assert "── Services ──" in rendered
    assert "└─ gateway" in rendered
    assert "ready — modern" in rendered
    assert "↪ retry → now" in rendered


def test_main_snapshots_capability_before_utf8_reconfigure() -> None:
    events: list[str] = []
    with (
        mock.patch.object(
            main_mod.ux,
            "configure_console_output",
            side_effect=lambda: events.append("configure"),
        ),
        mock.patch.object(
            main_mod,
            "_force_utf8_io",
            side_effect=lambda: events.append("reconfigure"),
        ),
        mock.patch.object(main_mod, "_try_launch_tui", return_value=True),
    ):
        main_mod.main()
    assert events == ["configure", "reconfigure"]


def test_implicit_tui_refuses_legacy_terminal_with_actionable_message() -> None:
    stdin = _Stream(tty=True)
    stdout = _Stream(tty=True)
    stderr = _Stream(tty=True)
    with (
        _render_mode(False),
        mock.patch.object(sys, "stdin", stdin),
        mock.patch.object(sys, "stdout", stdout),
        mock.patch.object(sys, "stderr", stderr),
        mock.patch.object(sys, "argv", ["defenseclaw"]),
        mock.patch("defenseclaw.tui.run_textual_tui") as run_tui,
    ):
        assert main_mod._try_launch_tui() is True

    run_tui.assert_not_called()
    assert "Windows Terminal or PowerShell 7" in stderr.getvalue()
    assert "defenseclaw status" in stderr.getvalue()


def test_implicit_tui_launches_on_capable_terminal() -> None:
    stdin = _Stream(tty=True)
    stdout = _Stream(tty=True)
    with (
        _render_mode(True),
        mock.patch.object(sys, "stdin", stdin),
        mock.patch.object(sys, "stdout", stdout),
        mock.patch.object(sys, "argv", ["defenseclaw"]),
        mock.patch("defenseclaw.tui.run_textual_tui") as run_tui,
    ):
        assert main_mod._try_launch_tui() is True

    run_tui.assert_called_once_with()


def test_explicit_tui_uses_the_same_capability_guard() -> None:
    runner = CliRunner()
    with mock.patch.object(ux, "terminal_supports_tui", return_value=False):
        rejected = runner.invoke(tui, catch_exceptions=False)
    assert rejected.exit_code != 0
    assert "Windows Terminal or PowerShell 7" in rejected.output

    with (
        mock.patch.object(ux, "terminal_supports_tui", return_value=True),
        mock.patch("defenseclaw.tui.run_textual_tui") as run_tui,
    ):
        accepted = runner.invoke(tui, catch_exceptions=False)
    assert accepted.exit_code == 0
    run_tui.assert_called_once_with()
