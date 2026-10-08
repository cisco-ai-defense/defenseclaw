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

"""GAP-0264: a deleted working directory is one line, not a traceback."""

from __future__ import annotations

import errno
from unittest.mock import MagicMock

import pytest
from defenseclaw import main


def test_a_deleted_working_directory_is_one_line(monkeypatch, capsys) -> None:
    # main() snapshots console state into module globals and the environment.
    for name in ("_keep_console_width_when_piped", "_force_utf8_io"):
        monkeypatch.setattr(main, name, lambda: None)
    monkeypatch.setattr(main.ux, "configure_console_output", lambda *_a: None)
    monkeypatch.setattr(main, "_try_launch_tui", lambda: False)
    monkeypatch.setattr(main, "cli", MagicMock(side_effect=FileNotFoundError(errno.ENOENT, "No such file or directory")))

    def gone() -> str:
        raise FileNotFoundError(errno.ENOENT, "No such file or directory")

    monkeypatch.setattr(main.os, "getcwd", gone)
    with pytest.raises(SystemExit) as exited:
        main.main()
    assert exited.value.code == 1
    err = capsys.readouterr().err
    assert "the current directory no longer exists. cd to an existing directory" in err
    assert "Traceback" not in err

    # Another missing file is still the error it was.
    monkeypatch.setattr(main.os, "getcwd", lambda: "/")
    with pytest.raises(FileNotFoundError):
        main.main()
