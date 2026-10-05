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

"""GAP-2181: a Ctrl+C pressed while the Windows TUI exits never reaches cmd.exe."""

from __future__ import annotations

from types import SimpleNamespace

from defenseclaw.tui import _hold_windows_ctrl_c_until_exit

_PROCESSED = 0x0001
_ORIGINAL = 0x01F7  # cooked console mode with processed input on


def test_processed_input_stays_off_until_exit_then_is_restored() -> None:
    console = {"mode": _ORIGINAL, "flushed": 0}
    flushes = SimpleNamespace(FlushConsoleInputBuffer=lambda _h: console.__setitem__("flushed", console["flushed"] + 1))

    def enable_application_mode():
        console["mode"] = 0x0200  # Textual's VT input mode
        return lambda: console.__setitem__("mode", _ORIGINAL)

    win32 = SimpleNamespace(
        enable_application_mode=enable_application_mode,
        get_console_mode=lambda _f: console["mode"],
        set_console_mode=lambda _f, mode: console.__setitem__("mode", mode),
        ENABLE_PROCESSED_INPUT=_PROCESSED,
        GetStdHandle=lambda _n: 7,
        STD_INPUT_HANDLE=-10,
        KERNEL32=flushes,
    )
    at_exit: list = []
    _hold_windows_ctrl_c_until_exit(win32, at_exit.append)

    restore = win32.enable_application_mode()
    restore()  # Textual's driver.close()
    assert console["mode"] == _ORIGINAL & ~_PROCESSED  # a late Ctrl+C is a key, not a console event
    assert len(at_exit) == 1

    at_exit[0]()  # interpreter exit
    assert console == {"mode": _ORIGINAL, "flushed": 1}
