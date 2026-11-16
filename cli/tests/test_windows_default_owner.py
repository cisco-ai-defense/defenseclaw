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
            patch.object(windows_owner, "_managed_deployment_present", return_value=managed), \
            patch.object(windows_owner, "_swap_default_owner", return_value=True) as swap:
        assert windows_owner.use_current_user_as_default_owner(argv) is called
    assert swap.called is called


def test_a_managed_pin_keeps_the_owner(monkeypatch) -> None:
    # GAP-0063 review: the children of Setup and of the managed service carry the pin.
    monkeypatch.setenv("DEFENSECLAW_DEPLOYMENT_MODE", "managed_enterprise")
    with patch.object(windows_owner, "os", SimpleNamespace(name="nt", environ=os.environ)), \
            patch.object(windows_owner, "_managed_marker_present") as marker, \
            patch.object(windows_owner, "_swap_default_owner") as swap:
        assert windows_owner.use_current_user_as_default_owner(["policy", "reload"]) is False
    marker.assert_not_called()
    swap.assert_not_called()


@pytest.mark.parametrize(
    ("layout", "program_files_readable", "present"),
    [
        ((), True, False),
        ((("Cisco", "Cisco Secure Client", "DefenseClaw"),), True, True),
        ((("Cisco", "DefenseClaw"),), True, True),
        ((), False, True),
    ],
)
def test_an_enterprise_install_root_keeps_the_owner(tmp_path, monkeypatch, layout, program_files_readable, present) -> None:
    # Only the standalone profile writes the marker: Secure Client, and a first
    # standalone install before its marker, have only their install root.
    monkeypatch.delenv("DEFENSECLAW_DEPLOYMENT_MODE", raising=False)
    for parts in layout:
        tmp_path.joinpath(*parts).mkdir(parents=True)
    with patch.object(windows_owner, "_managed_marker_present", return_value=False), \
            patch.object(windows_owner, "_program_files_dir", return_value=str(tmp_path) if program_files_readable else ""):
        assert windows_owner._managed_deployment_present() is present  # noqa: SLF001


def test_a_token_error_never_stops_the_cli() -> None:
    with patch.object(windows_owner, "os", SimpleNamespace(name="nt")), \
            patch.object(windows_owner, "_managed_deployment_present", return_value=False), \
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


@pytest.mark.parametrize(
    "value, kind, expected",
    [
        ("C:\\Program Files", "REG_SZ", "C:\\Program Files"),
        ("D:\\O\u2019Brien Apps", "REG_SZ", "D:\\O\u2019Brien Apps"),
        ("%SystemDrive%\\Program Files", "REG_EXPAND_SZ", ""),
        ("%SystemDrive%\\Program Files", "REG_SZ", ""),
        ("C:\\Program Files", "REG_EXPAND_SZ", ""),
        (" C:\\Program Files", "REG_SZ", ""),
        ("C:/Program Files", "REG_SZ", ""),
        ("\\\\server\\share", "REG_SZ", ""),
        ("Program Files", "REG_SZ", ""),
        ("C:\\Program Files\\..\\Users", "REG_SZ", ""),
        ("C:\\Program\tFiles", "REG_SZ", ""),
        (7, "REG_DWORD", ""),
    ],
)
def test_program_files_reads_only_a_canonical_reg_sz(monkeypatch, value, kind, expected) -> None:
    """g072 review 3 N4: the Python reader takes what the Go resolver takes."""

    class _Key:
        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

    fake = SimpleNamespace(
        HKEY_LOCAL_MACHINE=1,
        KEY_READ=1,
        KEY_WOW64_64KEY=2,
        REG_SZ="REG_SZ",
        OpenKey=lambda *_args: _Key(),
        QueryValueEx=lambda _key, _name: (value, kind),
    )
    monkeypatch.setitem(sys.modules, "winreg", fake)
    assert windows_owner._program_files_dir() == expected
