# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""GAP-1313: a reader that closes the pipe early ends the CLI quietly."""

from __future__ import annotations

import errno
import sys
from unittest.mock import patch

import pytest
from defenseclaw import main as main_mod


class _ClosedStdout:
    def flush(self) -> None:
        raise OSError(errno.EINVAL, "Invalid argument")


def test_windows_einval_on_a_closed_stdout_counts_as_a_closed_pipe(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(sys, "stdout", _ClosedStdout())
    assert main_mod._output_pipe_closed(OSError(errno.EINVAL, "Invalid argument"))


def test_other_einval_errors_are_not_hidden(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    assert not main_mod._output_pipe_closed(OSError(errno.EINVAL, "Invalid argument"))
    monkeypatch.setattr(sys, "platform", "linux")
    assert not main_mod._output_pipe_closed(OSError(errno.EINVAL, "Invalid argument"))
    assert main_mod._output_pipe_closed(BrokenPipeError(errno.EPIPE, "Broken pipe"))


def test_main_exits_without_a_traceback_when_the_pipe_closes(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(sys, "stdout", _ClosedStdout())
    closed = OSError(errno.EINVAL, "Invalid argument")
    with (
        patch.object(main_mod.ux, "configure_console_output"),
        patch.object(main_mod, "_force_utf8_io"),
        patch.object(main_mod, "_try_launch_tui", side_effect=closed),
        patch.object(main_mod, "_silence_closed_stdout") as silence,
        pytest.raises(SystemExit) as exited,
    ):
        main_mod.main()
    assert exited.value.code == 1
    silence.assert_called_once()
