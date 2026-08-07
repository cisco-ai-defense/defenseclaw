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
