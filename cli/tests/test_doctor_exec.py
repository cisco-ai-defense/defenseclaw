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

"""Check-to-exec replacement-race coverage for Doctor lifecycle spawn."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from defenseclaw.commands.cmd_doctor import _windows_system_powershell
from defenseclaw.doctor_exec import (
    ExecBindError,
    bind_trusted_executable,
    revalidate_bound_executable,
    run_bound_executable,
)


def _write_exec(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)


def test_bind_trusted_executable_rejects_relative_and_missing(tmp_path: Path) -> None:
    with pytest.raises(ExecBindError, match="not absolute"):
        bind_trusted_executable("defenseclaw-gateway")
    with pytest.raises(ExecBindError):
        bind_trusted_executable(str(tmp_path / "missing-gateway"))


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux fexec via /proc/self/fd")
def test_posix_spawn_executes_held_inode_after_path_replacement(tmp_path: Path) -> None:
    tool = tmp_path / "defenseclaw-gateway"
    _write_exec(tool, "#!/bin/sh\necho ORIGINAL-GENERATION\n")
    bound = bind_trusted_executable(str(tool), verify_custody=False)
    try:
        tool.unlink()
        _write_exec(tool, "#!/bin/sh\necho REPLACED-GENERATION\n")
        result = run_bound_executable(
            bound,
            ["status"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        assert result.returncode == 0
        assert "ORIGINAL-GENERATION" in result.stdout
        assert "REPLACED-GENERATION" not in result.stdout
    finally:
        bound.close()


@pytest.mark.skipif(os.name == "nt", reason="POSIX bind")
def test_run_bound_keeps_explicit_argv_and_disables_shell(tmp_path: Path) -> None:
    tool = tmp_path / "defenseclaw-gateway"
    _write_exec(tool, "#!/bin/sh\necho ok\n")
    runner = MagicMock(return_value=subprocess.CompletedProcess(["x"], 0, "", ""))
    bound = bind_trusted_executable(str(tool), verify_custody=False)
    try:
        run_bound_executable(bound, ["restart"], runner=runner, timeout=1)
        argv, kwargs = runner.call_args
        assert argv[0][0] == bound.path
        assert argv[0][1:] == ["restart"]
        assert kwargs["shell"] is False
        if sys.platform.startswith("linux"):
            assert kwargs["executable"] == f"/proc/self/fd/{bound.fd}"
            assert bound.fd in kwargs["pass_fds"]
        else:
            assert kwargs["executable"] == bound.path
            assert "pass_fds" not in kwargs
    finally:
        bound.close()


@pytest.mark.skipif(os.name == "nt" or sys.platform.startswith("linux"), reason="Darwin path-identity fail-closed")
def test_darwin_spawn_fails_closed_after_path_replacement(tmp_path: Path) -> None:
    tool = tmp_path / "defenseclaw-gateway"
    _write_exec(tool, "#!/bin/sh\necho ORIGINAL-GENERATION\n")
    bound = bind_trusted_executable(str(tool), verify_custody=False)
    try:
        tool.unlink()
        _write_exec(tool, "#!/bin/sh\necho REPLACED-GENERATION\n")
        with pytest.raises(ExecBindError, match="replaced"):
            run_bound_executable(bound, ["status"], timeout=5)
    finally:
        bound.close()


def test_windows_path_identity_change_fails_closed(monkeypatch) -> None:
    from defenseclaw.doctor_exec import BoundExecutable, ExecutableIdentity, _assert_windows_path_still_bound

    bound = BoundExecutable(
        r"C:\Program Files\DefenseClaw\defenseclaw-gateway.exe",
        fd=3,
        identity=ExecutableIdentity(
            device=1,
            inode=2,
            size=3,
            windows_volume=10,
            windows_index=20,
        ),
    )
    monkeypatch.setattr("defenseclaw.doctor_exec._windows_path_file_id", lambda _path: (11, 21))
    with pytest.raises(ExecBindError, match="replaced"):
        _assert_windows_path_still_bound(bound)


def test_bind_uses_python_interpreter_as_real_executable() -> None:
    bound = bind_trusted_executable(os.path.realpath(sys.executable), verify_custody=False)
    try:
        assert bound.fd >= 0
        assert bound.identity.size > 0
        revalidate_bound_executable(bound)
    finally:
        bound.close()


def test_windows_pathname_custody_uses_executable_acl_not_private_file_owner(monkeypatch) -> None:
    from defenseclaw import doctor_exec

    powershell = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    parent = r"C:\Windows\System32\WindowsPowerShell\v1.0"

    monkeypatch.setattr(doctor_exec.os, "name", "nt")
    monkeypatch.setattr(doctor_exec.os.path, "abspath", lambda value: value)
    monkeypatch.setattr(doctor_exec.os.path, "dirname", lambda value: parent if value == powershell else value)
    monkeypatch.setattr(doctor_exec.os.path, "isfile", lambda _value: True)
    monkeypatch.setattr(
        "defenseclaw.gateway.packaged_windows_gateway_path",
        lambda: None,
    )
    seen: list[tuple[str, bool]] = []

    def custody(path: str, *, allow_current_user: bool = False, **_kwargs):
        seen.append((path, allow_current_user))
        return None

    monkeypatch.setattr(doctor_exec, "windows_acl_custody_write_error", custody)

    assert doctor_exec._verify_pathname_custody(powershell) == powershell
    assert seen == [(powershell, True), (parent, True)]


def test_windows_pathname_custody_refuses_untrusted_writers(monkeypatch) -> None:
    from defenseclaw import doctor_exec
    from defenseclaw.doctor_exec import ExecBindError

    tool = r"C:\Users\runneradmin\cursor-hook.exe"
    monkeypatch.setattr(doctor_exec.os, "name", "nt")
    monkeypatch.setattr(doctor_exec.os.path, "abspath", lambda value: value)
    monkeypatch.setattr(doctor_exec.os.path, "dirname", lambda value: r"C:\Users\runneradmin")
    monkeypatch.setattr(doctor_exec.os.path, "isfile", lambda _value: True)
    monkeypatch.setattr(
        "defenseclaw.gateway.packaged_windows_gateway_path",
        lambda: None,
    )
    monkeypatch.setattr(
        doctor_exec,
        "windows_acl_custody_write_error",
        lambda _path, **_kwargs: "ACL grants write access to untrusted SID S-1-5-32-545",
    )
    with pytest.raises(ExecBindError, match="custody"):
        doctor_exec._verify_pathname_custody(tool)


@pytest.mark.skipif(os.name != "nt", reason="native Windows PowerShell bind")
def test_bind_system_powershell_with_executable_custody() -> None:
    powershell, windows_directory = _windows_system_powershell()
    assert powershell
    assert windows_directory
    bound = bind_trusted_executable(powershell)
    try:
        assert bound.fd >= 0
        assert bound.path == powershell
        revalidate_bound_executable(bound)
    finally:
        bound.close()
