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

"""Portability regressions for Doctor's gateway repair evidence."""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from defenseclaw import doctor_gateway, file_permissions
from defenseclaw.commands import cmd_doctor
from defenseclaw.gateway import gateway_api_client_host


def test_paths_same_uses_filesystem_identity_for_hard_link_aliases(tmp_path):
    original = tmp_path / "gateway"
    alias = tmp_path / "gateway-alias"
    original.write_bytes(b"same object")
    try:
        os.link(original, alias)
    except OSError as exc:
        pytest.skip(f"hard links are unavailable: {exc}")

    assert os.path.samefile(original, alias)
    assert doctor_gateway.paths_same(os.fspath(original), os.fspath(alias))
    assert cmd_doctor._gateway_executable_matches(
        doctor_gateway.PIDRecord("ok", executable=os.fspath(original)),
        doctor_gateway.ProcessEvidence("ok", executable=os.fspath(alias)),
        platform_name="linux",
    )


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin case-folding regression")
def test_paths_same_uses_darwin_filesystem_case_identity(tmp_path):
    data_dir = tmp_path / "DoctorCaseHome"
    data_dir.mkdir()
    alternate_spelling = os.fspath(data_dir).swapcase()
    if not os.path.exists(alternate_spelling) or not os.path.samefile(data_dir, alternate_spelling):
        pytest.skip("test volume is case-sensitive")

    assert doctor_gateway.paths_same(os.fspath(data_dir), alternate_spelling)
    home_bound, foreign_home = cmd_doctor._gateway_process_home_binding(
        SimpleNamespace(data_dir=os.fspath(data_dir)),
        doctor_gateway.PIDRecord("ok", pid=4242, data_dir=alternate_spelling),
        doctor_gateway.ProcessEvidence("ok", pid=4242),
        platform_name="darwin",
    )
    assert home_bound
    assert not foreign_home


@pytest.mark.parametrize("bind", ["::", "[::]"])
def test_gateway_api_client_host_uses_ipv6_loopback_for_ipv6_wildcard(bind):
    cfg = SimpleNamespace(gateway=SimpleNamespace(api_bind=bind))

    assert gateway_api_client_host(cfg) == "::1"


@pytest.mark.skipif(os.name == "nt", reason="/proc socket fixture uses POSIX symlinks")
def test_linux_listener_evidence_accepts_ipv6_wildcard_for_ipv6_client_host(tmp_path):
    proc_root = tmp_path / "proc"
    net = proc_root / "net"
    descriptors = proc_root / "4242" / "fd"
    net.mkdir(parents=True)
    descriptors.mkdir(parents=True)
    port = 18_970
    header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
    row = f" 0: {'0' * 32}:{port:04X} {'0' * 32}:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 12345 1\n"
    (net / "tcp").write_text(header, encoding="ascii")
    (net / "tcp6").write_text(header + row, encoding="ascii")
    os.symlink("socket:[12345]", descriptors / "3")
    cfg = SimpleNamespace(gateway=SimpleNamespace(api_bind="[::]"))

    evidence = cmd_doctor._linux_gateway_listener_evidence(
        port,
        host=gateway_api_client_host(cfg),
        proc_root=os.fspath(proc_root),
    )

    assert evidence.status == "ok"
    assert evidence.pid == 4242


@pytest.mark.parametrize(
    ("mode_field", "acl_text", "expected"),
    [
        (
            "-rw-------+",
            " 0: group:everyone allow read\n",
            "extended ACL grants additional read access",
        ),
        (
            "-rw-------@",
            " 0: group:everyone allow read\n",
            "extended ACL grants additional read access",
        ),
        ("-rw-------@", "", None),
        ("-rw-------", "", None),
    ],
)
def test_darwin_acl_inspection_uses_mode_acl_marker(monkeypatch, tmp_path, mode_field, acl_text, expected):
    target = tmp_path / ".env"
    target.write_text("SECRET=synthetic\n", encoding="utf-8")
    observed: list[tuple[list[str], dict[str, object]]] = []

    def run(command, **kwargs):
        observed.append((command, kwargs))
        return subprocess.CompletedProcess(
            command,
            0,
            stdout=f"{mode_field} 1 owner group 17 Jul 30 12:00 {target.name}\n{acl_text}",
            stderr="",
        )

    monkeypatch.setattr(file_permissions.sys, "platform", "darwin")
    monkeypatch.setattr(file_permissions.subprocess, "run", run)

    assert file_permissions.darwin_acl_confidentiality_error(target) == expected
    assert observed[0][0] == ["/bin/ls", "-lde", os.path.abspath(target)]
    assert observed[0][1]["shell"] is False
    assert observed[0][1]["stdin"] is subprocess.DEVNULL
    assert observed[0][1]["timeout"] == 2.0


@pytest.mark.parametrize("permission", ["add_file", "add_subdirectory", "delete_child"])
def test_darwin_acl_write_inspection_rejects_directory_mutation_right(monkeypatch, permission):
    monkeypatch.setattr(file_permissions.sys, "platform", "darwin")
    monkeypatch.setattr(
        file_permissions,
        "_darwin_acl_output",
        lambda _path: (
            "drwx------@",
            f" 0: group:everyone allow {permission}\n",
        ),
    )

    assert file_permissions.darwin_acl_write_error("/private/synthetic") == (
        "extended ACL grants additional write access"
    )


@pytest.mark.skipif(sys.platform != "darwin", reason="native Darwin ACL regression")
def test_darwin_acl_native_detects_acl_rows_with_xattr_marker_and_directory_rights(tmp_path):
    target = tmp_path / ".env"
    target.write_text("SECRET=synthetic\n", encoding="utf-8")
    os.chmod(target, 0o600)
    directory = tmp_path / "managed"
    directory.mkdir(mode=0o700)
    try:
        subprocess.run(
            ["/usr/bin/xattr", "-w", "com.defenseclaw.test", "present", os.fspath(target)],
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            ["/bin/chmod", "+a", "everyone allow read", os.fspath(target)],
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            [
                "/bin/chmod",
                "+a",
                "everyone allow add_file,add_subdirectory,delete_child",
                os.fspath(directory),
            ],
            check=True,
            capture_output=True,
            text=True,
        )

        mode_field, acl_text = file_permissions._darwin_acl_output(target)
        assert "@" in mode_field
        assert "allow read" in acl_text
        assert file_permissions.darwin_acl_confidentiality_error(target) == (
            "extended ACL grants additional read access"
        )
        assert file_permissions.darwin_acl_write_error(directory) == (
            "extended ACL grants additional write access"
        )
    finally:
        subprocess.run(["/bin/chmod", "-N", os.fspath(target)], check=False)
        subprocess.run(["/bin/chmod", "-N", os.fspath(directory)], check=False)
        subprocess.run(
            ["/usr/bin/xattr", "-d", "com.defenseclaw.test", os.fspath(target)],
            check=False,
        )


@pytest.mark.skipif(os.name == "nt", reason="Darwin repair uses the POSIX file-mode branch")
def test_protect_private_file_invokes_darwin_acl_clear_seam(monkeypatch, tmp_path):
    target = tmp_path / ".env"
    target.write_text("SECRET=synthetic\n", encoding="utf-8")
    os.chmod(target, 0o600)
    clear_acl = Mock()

    monkeypatch.setattr(file_permissions.sys, "platform", "darwin")
    monkeypatch.setattr(file_permissions, "_clear_darwin_extended_acl", clear_acl)

    file_permissions.protect_private_file(target)

    clear_acl.assert_called_once()
    fd, path = clear_acl.call_args.args
    assert os.fspath(path) == os.path.abspath(target)
    assert fd >= 0


@pytest.mark.skipif(os.name == "nt", reason="Darwin repair uses POSIX file-mode semantics")
def test_fix_dotenv_permissions_repairs_darwin_acl_at_mode_0600(monkeypatch, tmp_path):
    target = tmp_path / ".env"
    target.write_text("SECRET=synthetic\n", encoding="utf-8")
    os.chmod(target, 0o600)
    cfg = SimpleNamespace(data_dir=os.fspath(tmp_path))
    inspect_acl = Mock(
        side_effect=[
            "extended ACL grants additional access",
            None,
        ]
    )
    protect = Mock()

    monkeypatch.setattr(cmd_doctor, "darwin_acl_confidentiality_error", inspect_acl)
    monkeypatch.setattr(cmd_doctor, "darwin_acl_write_error", lambda _path: None)
    monkeypatch.setattr(file_permissions, "protect_private_file", protect)

    tag, detail = cmd_doctor._fix_dotenv_perms(
        cfg,
        assume_yes=True,
        platform_name="darwin",
    )

    assert tag == "warn", detail
    assert "atomically replace" in detail
    assert cfg._doctor_gateway_token_rotation_required is True
    protect.assert_not_called()
    inspect_acl.assert_called_once_with(os.fspath(target))


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode regression")
def test_fix_dotenv_permissions_verifies_mode_after_repair(monkeypatch, tmp_path):
    target = tmp_path / ".env"
    target.write_text("SECRET=synthetic\n", encoding="utf-8")
    os.chmod(target, 0o400)
    cfg = SimpleNamespace(data_dir=os.fspath(tmp_path))
    monkeypatch.setattr(file_permissions, "protect_private_file", Mock())

    tag, detail = cmd_doctor._fix_dotenv_perms(
        cfg,
        assume_yes=True,
        platform_name="linux",
    )

    assert tag == "fail"
    assert "still not 0600 after repair" in detail


def test_windows_confidentiality_rejects_empty_effective_dacl(monkeypatch):
    current_sid = "S-1-5-21-current"
    fake_os = SimpleNamespace(name="nt", fspath=os.fspath)
    monkeypatch.setattr(file_permissions, "os", fake_os)
    monkeypatch.setattr(
        file_permissions,
        "_windows_acl_snapshot",
        lambda _path: (current_sid, False, []),
    )
    monkeypatch.setattr(file_permissions, "_windows_acl_has_required_access", lambda _path: False)
    monkeypatch.setattr(file_permissions, "_windows_current_user_sid", lambda: current_sid)

    problem = file_permissions.windows_acl_confidentiality_error("synthetic.env")

    assert problem == "owner/SYSTEM effective access is missing"


def test_windows_system_powershell_checks_every_system_directory_ancestor(
    monkeypatch,
    tmp_path,
):
    system_directory = tmp_path / "Windows" / "System32"
    executable = system_directory / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    executable.parent.mkdir(parents=True)
    executable.write_bytes(b"synthetic")

    class StubGetSystemDirectory:
        argtypes = None
        restype = None

        def __call__(self, buffer, _size):
            buffer.value = os.fspath(system_directory)
            return len(buffer.value)

    kernel32 = SimpleNamespace(GetSystemDirectoryW=StubGetSystemDirectory())
    inspected: list[str] = []
    monkeypatch.setattr(cmd_doctor.os, "name", "nt")
    monkeypatch.setattr(ctypes, "WinDLL", lambda *_args, **_kwargs: kernel32, raising=False)
    monkeypatch.setattr(file_permissions, "reject_reparse_path", lambda _path: None)
    monkeypatch.setattr(
        file_permissions,
        "windows_acl_custody_write_error",
        lambda path, *, allow_current_user, require_current_user_owner=False: inspected.append(
            f"{os.fspath(path)}:{allow_current_user}:{require_current_user_owner}"
        ),
    )

    resolved, windows_directory = cmd_doctor._windows_system_powershell()

    assert resolved == os.fspath(executable)
    assert windows_directory == os.fspath(system_directory.parent)
    assert inspected == [
        f"{os.fspath(executable)}:False:False",
        f"{os.fspath(executable.parent)}:False:False",
        f"{os.fspath(executable.parent.parent)}:False:False",
        f"{os.fspath(system_directory)}:False:False",
    ]


def test_windows_pid_integrity_checks_every_replaceable_ancestor(
    monkeypatch,
    tmp_path,
):
    pid_file = tmp_path / "profile" / ".defenseclaw" / "gateway.pid"
    pid_file.parent.mkdir(parents=True)
    pid_file.write_text("4242", encoding="ascii")
    info = pid_file.stat()
    monkeypatch.setattr(cmd_doctor.os, "name", "nt")
    inspected: list[str] = []
    monkeypatch.setattr(
        file_permissions,
        "windows_acl_custody_write_error",
        lambda path, *, allow_current_user, require_current_user_owner=False: inspected.append(
            f"{os.path.normpath(os.fspath(path))}:{allow_current_user}:{require_current_user_owner}"
        ),
    )

    problem = doctor_gateway._pid_record_integrity_error(
        os.fspath(pid_file),
        info,
    )

    assert problem == ""
    expected = [f"{os.path.normpath(os.fspath(pid_file))}:True:True"]
    ancestor = pid_file.parent
    while ancestor.parent != ancestor:
        expected.append(f"{os.path.normpath(os.fspath(ancestor))}:True:False")
        ancestor = ancestor.parent
    assert inspected == expected


def test_windows_gateway_data_dir_requires_current_user_owned_custody(
    monkeypatch,
    tmp_path,
):
    inspected: list[str] = []
    monkeypatch.setattr(cmd_doctor.os, "name", "nt")
    monkeypatch.setattr(
        file_permissions,
        "windows_acl_custody_write_error",
        lambda path, *, allow_current_user, require_current_user_owner=False: inspected.append(
            f"{os.path.normpath(os.fspath(path))}:{allow_current_user}:{require_current_user_owner}"
        ),
    )

    problem = cmd_doctor._gateway_data_dir_integrity_problem(
        SimpleNamespace(data_dir=os.fspath(tmp_path)),
    )

    assert problem == ""
    assert inspected == [f"{os.path.normpath(os.fspath(tmp_path))}:True:True"]


@pytest.mark.skipif(os.name != "nt", reason="native Windows custody smoke test")
def test_windows_default_pid_and_powershell_custody(tmp_path):
    pid_file = tmp_path / "gateway.pid"
    pid_file.write_text("4242", encoding="ascii")

    record = doctor_gateway.read_pid_record(os.fspath(pid_file))
    powershell, windows_directory = cmd_doctor._windows_system_powershell()

    assert record.status == "ok", record.reason
    assert record.pid == 4242
    assert os.path.isabs(powershell)
    assert os.path.basename(powershell).casefold() == "powershell.exe"
    assert os.path.isdir(windows_directory)


def test_fix_dotenv_permissions_refuses_foreign_windows_owner(monkeypatch, tmp_path):
    target = tmp_path / ".env"
    target.write_text("SECRET=synthetic\n", encoding="utf-8")
    cfg = SimpleNamespace(data_dir=os.fspath(tmp_path))
    protect = Mock()
    owner_problem = "owner SID S-1-5-21-foreign is not the current user"

    monkeypatch.setattr(
        file_permissions,
        "windows_acl_confidentiality_error",
        lambda _path: owner_problem,
    )
    monkeypatch.setattr(file_permissions, "windows_acl_write_error", lambda _path: owner_problem)
    monkeypatch.setattr(file_permissions, "protect_private_file", protect)

    tag, detail = cmd_doctor._fix_dotenv_perms(
        cfg,
        assume_yes=True,
        platform_name="nt",
    )

    assert tag == "fail"
    assert "owner" in detail.lower()
    protect.assert_not_called()


def test_windows_process_evidence_treats_unknown_open_error_as_unavailable(monkeypatch):
    class StubFunction:
        def __init__(self, result):
            self.result = result
            self.argtypes = None
            self.restype = None

        def __call__(self, *_args):
            return self.result

    kernel32 = SimpleNamespace(
        OpenProcess=StubFunction(0),
        CloseHandle=StubFunction(1),
    )
    monkeypatch.setattr(
        doctor_gateway.ctypes,
        "WinDLL",
        lambda *_args, **_kwargs: kernel32,
        raising=False,
    )
    monkeypatch.setattr(
        doctor_gateway.ctypes,
        "get_last_error",
        lambda: 8,  # ERROR_NOT_ENOUGH_MEMORY is not evidence that the PID is absent.
        raising=False,
    )

    evidence = doctor_gateway._windows_process_evidence(4242)

    assert evidence.status == "unavailable"
    assert "could not" in evidence.reason
