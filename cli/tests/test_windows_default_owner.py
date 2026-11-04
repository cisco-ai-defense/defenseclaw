# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""GAP-0050: an elevated Windows CLI creates files its user owns."""

from __future__ import annotations

import os
import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from defenseclaw import entry, windows_owner


def test_not_windows_changes_nothing() -> None:
    with patch.object(windows_owner, "os", SimpleNamespace(name="posix")), \
            patch.object(windows_owner, "_swap_default_owner") as swap:
        assert windows_owner.use_current_user_as_default_owner(["init"]) is False
    swap.assert_not_called()


@pytest.mark.parametrize(
    ("argv", "managed", "called"),
    [
        (["init", "--yes"], False, True),
        ([], False, True),
        (["enterprise", "windows", "status"], False, False),
        (["init"], True, False),
    ],
)
def test_windows_swaps_the_owner_except_for_managed_machines(argv, managed, called) -> None:
    with patch.object(windows_owner, "os", SimpleNamespace(name="nt")), \
            patch.object(windows_owner, "_managed_marker_present", return_value=managed), \
            patch.object(windows_owner, "_swap_default_owner", return_value=True) as swap:
        assert windows_owner.use_current_user_as_default_owner(argv) is called
    assert swap.called is called


def test_a_token_error_never_stops_the_cli() -> None:
    with patch.object(windows_owner, "os", SimpleNamespace(name="nt")), \
            patch.object(windows_owner, "_managed_marker_present", return_value=False), \
            patch.object(windows_owner, "_swap_default_owner", side_effect=OSError("access denied")):
        assert windows_owner.use_current_user_as_default_owner(["init"]) is False


def test_entry_sets_the_owner_first_on_windows(monkeypatch) -> None:
    calls = []
    monkeypatch.setattr(entry, "os", SimpleNamespace(name="nt", environ=os.environ))
    monkeypatch.setattr(windows_owner, "use_current_user_as_default_owner", lambda argv: calls.append(list(argv)))
    monkeypatch.setattr(sys, "argv", ["defenseclaw", "--version"])
    with pytest.raises(SystemExit):
        entry.main()
    assert calls == [["--version"]]
