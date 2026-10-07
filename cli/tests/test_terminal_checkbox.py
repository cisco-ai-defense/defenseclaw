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

"""Regression tests for key-driven terminal checkbox prompts."""

from __future__ import annotations

import re
from unittest.mock import patch

import pytest
from defenseclaw import terminal_checkbox

termios = pytest.importorskip("termios", reason="POSIX terminal-mode regression")


def test_picker_restores_terminal_mode_before_following_line_prompt() -> None:
    """A raw-key reader must not leave Enter echoing as literal ``^M``."""

    original_mode: list[object] = ["canonical-with-icrnl"]
    current_mode = list(original_mode)

    def fake_tcgetattr(fd: int) -> list[object]:
        assert fd == 42
        return list(current_mode)

    def fake_tcsetattr(fd: int, when: int, attributes: list[object]) -> None:
        assert fd == 42
        assert when == termios.TCSANOW
        current_mode[:] = attributes

    def raw_getchar() -> str:
        # Model a pseudoterminal/Click transition that leaves ICRNL disabled.
        current_mode[:] = ["canonical-without-icrnl"]
        return "\r"

    class FakeStdin:
        @staticmethod
        def fileno() -> int:
            return 42

    with (
        patch.object(terminal_checkbox.click, "get_text_stream", return_value=FakeStdin()),
        patch.object(terminal_checkbox.os, "isatty", return_value=True),
        patch.object(termios, "tcgetattr", side_effect=fake_tcgetattr),
        patch.object(termios, "tcsetattr", side_effect=fake_tcsetattr),
    ):
        selected = terminal_checkbox.prompt_checkbox_selection(
            ["codex", "claudecode"],
            default_selected=["codex"],
            title="Select connectors",
            empty_ok=False,
            redraw=False,
            getchar=raw_getchar,
        )

    assert selected == ["codex"]
    assert current_mode == original_mode


def test_picker_forces_echo_when_snapshot_was_already_raw() -> None:
    """A leaked raw snapshot must not hide the next click.prompt."""

    raw_mode = [0, 0, 0, 0, 0, 0, []]
    current_mode = list(raw_mode)

    def fake_tcgetattr(fd: int) -> list[object]:
        assert fd == 42
        return list(current_mode)

    def fake_tcsetattr(fd: int, when: int, attributes: list[object]) -> None:
        assert fd == 42
        assert when == termios.TCSANOW
        current_mode[:] = attributes

    def raw_getchar() -> str:
        current_mode[:] = [0, 0, 0, 0, 0, 0, []]
        return "\r"

    class FakeStdin:
        @staticmethod
        def fileno() -> int:
            return 42

    with (
        patch.object(terminal_checkbox.click, "get_text_stream", return_value=FakeStdin()),
        patch.object(terminal_checkbox.os, "isatty", return_value=True),
        patch.object(termios, "tcgetattr", side_effect=fake_tcgetattr),
        patch.object(termios, "tcsetattr", side_effect=fake_tcsetattr),
    ):
        selected = terminal_checkbox.prompt_checkbox_selection(
            ["codex"],
            default_selected=["codex"],
            title="Select connectors",
            empty_ok=False,
            redraw=False,
            getchar=raw_getchar,
        )

    assert selected == ["codex"]
    assert current_mode[0] & termios.ICRNL
    assert current_mode[3] & termios.ECHO
    assert current_mode[3] & termios.ICANON
    assert current_mode[3] & termios.ISIG
    assert current_mode[3] & termios.IEXTEN


def test_restore_line_prompt_mode_fixes_inherited_raw_tty() -> None:
    """A later wizard in the same TTY must recover echo without a picker."""

    current_mode = [0, 0, 0, 0, 0, 0, []]

    def fake_tcgetattr(fd: int) -> list[object]:
        assert fd == 42
        return list(current_mode)

    def fake_tcsetattr(fd: int, when: int, attributes: list[object]) -> None:
        assert fd == 42
        current_mode[:] = attributes

    class FakeStdin:
        @staticmethod
        def fileno() -> int:
            return 42

    with (
        patch.object(terminal_checkbox.click, "get_text_stream", return_value=FakeStdin()),
        patch.object(terminal_checkbox.os, "isatty", return_value=True),
        patch.object(termios, "tcgetattr", side_effect=fake_tcgetattr),
        patch.object(termios, "tcsetattr", side_effect=fake_tcsetattr),
    ):
        terminal_checkbox.restore_line_prompt_mode()

    assert current_mode[0] & termios.ICRNL
    assert current_mode[1] & termios.OPOST and current_mode[1] & termios.ONLCR  # GAP-0057 staircase
    assert current_mode[3] & termios.ECHO
    assert current_mode[3] & termios.ICANON


def test_picker_restores_terminal_mode_when_interrupted() -> None:
    original_mode: list[object] = ["canonical-with-icrnl"]
    current_mode = list(original_mode)

    def fake_tcgetattr(fd: int) -> list[object]:
        assert fd == 42
        return list(current_mode)

    def fake_tcsetattr(fd: int, when: int, attributes: list[object]) -> None:
        assert fd == 42
        assert when == termios.TCSANOW
        current_mode[:] = attributes

    def interrupted_getchar() -> str:
        current_mode[:] = ["raw-without-icrnl"]
        raise KeyboardInterrupt

    class FakeStdin:
        @staticmethod
        def fileno() -> int:
            return 42

    with (
        patch.object(terminal_checkbox.click, "get_text_stream", return_value=FakeStdin()),
        patch.object(terminal_checkbox.os, "isatty", return_value=True),
        patch.object(termios, "tcgetattr", side_effect=fake_tcgetattr),
        patch.object(termios, "tcsetattr", side_effect=fake_tcsetattr),
        pytest.raises(KeyboardInterrupt),
    ):
        terminal_checkbox.prompt_checkbox_selection(
            ["codex"],
            default_selected=["codex"],
            title="Select connectors",
            empty_ok=False,
            redraw=False,
            getchar=interrupted_getchar,
        )

    assert current_mode == original_mode


def _replay_screen(output: str) -> list[str]:
    """Replay the carriage returns, newlines, cursor-up and erase-line controls a terminal would."""

    rows = [""]
    row = col = 0
    for token in re.split(r"(\x1b\[\d*[A-Za-z]|\r|\n)", output):
        if not token:
            continue
        if token == "\r":
            col = 0
        elif token == "\n":
            row += 1
            col = 0
            if row == len(rows):
                rows.append("")
        elif token.startswith("\x1b["):
            if token.endswith("A"):
                row = max(0, row - int(token[2:-1] or "1"))
            elif token == "\x1b[2K":
                rows[row] = ""
        else:
            line = rows[row].ljust(col)
            rows[row] = line[:col] + token + line[col + len(token):]
            col += len(token)
    while rows and not rows[-1]:
        rows.pop()
    return rows


def test_redraw_shows_the_empty_choice_warning_below_one_menu(capsys) -> None:
    """Enter on an empty choice must leave the warning on screen, not a copy of the first row."""

    keys = iter(["n", "\r", "\r"])

    def getchar() -> str:
        try:
            return next(keys)
        except StopIteration:
            raise KeyboardInterrupt from None

    with pytest.raises(KeyboardInterrupt):
        terminal_checkbox.prompt_checkbox_selection(
            ["hermes", "codex"],
            default_selected=["hermes"],
            title="Select connectors",
            empty_ok=False,
            redraw=True,
            getchar=getchar,
        )

    screen = _replay_screen(capsys.readouterr().out)
    assert screen[-3:-1] == ["  > [ ] hermes", "    [ ] codex"]
    assert screen[-1].endswith("Select at least one connector.")
    assert sum("hermes" in line for line in screen) == 1


def test_redraw_clears_the_empty_choice_warning_on_the_next_key(capsys) -> None:
    keys = iter(["n", "\r", "j", " ", "\r"])
    selected = terminal_checkbox.prompt_checkbox_selection(
        ["hermes", "codex"],
        default_selected=["hermes", "codex"],
        title="Select connectors",
        empty_ok=False,
        redraw=True,
        getchar=lambda: next(keys),
    )

    assert selected == ["codex"]
    screen = _replay_screen(capsys.readouterr().out)
    assert screen[-2:] == ["    [ ] hermes", "  > [x] codex"]
    assert sum("hermes" in line for line in screen) == 1
    assert not any("Select at least one connector." in line for line in screen)


def test_redraw_shows_a_toggle_read_together_with_enter(capsys) -> None:
    """GAP-1263: Space and Enter in one read are redrawn before returning."""

    keys = iter(["j", " \r"])
    selected = terminal_checkbox.prompt_checkbox_selection(
        ["hermes", "codex"],
        default_selected=[],
        title="Select connectors",
        empty_ok=False,
        redraw=True,
        getchar=lambda: next(keys),
    )

    assert selected == ["codex"]
    screen = _replay_screen(capsys.readouterr().out)
    assert screen[-2:] == ["    [ ] hermes", "  > [x] codex"]
