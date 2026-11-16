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
import json
import os
import shlex
import stat
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import click
import pytest
from defenseclaw import doctor_gateway, file_permissions
from defenseclaw import gateway as gateway_module
from defenseclaw.commands import cmd_doctor, cmd_setup, cmd_setup_cowork
from defenseclaw.gateway import gateway_api_client_host

from tests.os_view import os_view


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
def test_gateway_api_client_host_uses_ipv6_loopback_for_ipv6_wildcard(bind, monkeypatch):
    # Pinned rather than inherited from the runner: the resolver now consults a
    # real IPv6 probe, and this case is specifically "IPv6 is usable".
    monkeypatch.setattr(gateway_module, "_ipv6_loopback_available", lambda: True)
    cfg = SimpleNamespace(gateway=SimpleNamespace(api_bind=bind))

    assert gateway_api_client_host(cfg) == "::1"


@pytest.mark.parametrize("bind", ["::", "[::]"])
def test_gateway_api_client_host_falls_back_when_ipv6_is_unavailable(bind, monkeypatch):
    """A ``::`` listener is reached over IPv4 when the host has no usable IPv6.

    Hardened base images and some container runtimes disable IPv6 while still
    running the gateway. Returning ``::1`` there hands callers an address they
    can never connect to, so the resolver falls back to the loopback that
    worked before ``::`` was split out from the wildcard set.
    """
    monkeypatch.setattr(gateway_module, "_ipv6_loopback_available", lambda: False)
    cfg = SimpleNamespace(gateway=SimpleNamespace(api_bind=bind))

    assert gateway_api_client_host(cfg) == "127.0.0.1"


def test_ipv6_loopback_probe_is_local_and_cached():
    """The probe must not depend on network egress and must be memoized."""
    gateway_module._ipv6_loopback_available.cache_clear()
    first = gateway_module._ipv6_loopback_available()
    assert isinstance(first, bool)
    assert gateway_module._ipv6_loopback_available() is first
    assert gateway_module._ipv6_loopback_available.cache_info().hits >= 1


@pytest.mark.skipif(os.name == "nt", reason="/proc socket fixture uses POSIX symlinks")
def test_linux_listener_evidence_accepts_ipv6_wildcard_for_ipv6_client_host(tmp_path):
    proc_root = tmp_path / "proc"
    net = proc_root / "self" / "net"
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


@pytest.mark.parametrize(
    ("sid", "trusted"),
    [
        ("S-1-5-32-544", True),  # BUILTIN\Administrators, as a profile folder inherits it
        ("S-1-5-32-545", False),  # BUILTIN\Users
        # A group that is only named Administrators: trust follows the SID, never the name.
        ("S-1-5-21-1111111111-2222222222-3333333333-1001", False),
    ],
)
def test_windows_gateway_custody_trusts_the_builtin_administrators_sid_only(monkeypatch, tmp_path, sid, trusted):
    """The per-user gateway and its folder may inherit full control for BUILTIN\\Administrators."""
    current_sid = "S-1-5-21-current"
    gateway = tmp_path / "bin" / "defenseclaw-gateway.exe"
    gateway.parent.mkdir()
    gateway.write_bytes(b"synthetic")
    inherited_full_control = 0x10 | 0x03  # INHERITED, OBJECT_INHERIT | CONTAINER_INHERIT
    entries = [
        (0x001F01FF, 1, inherited_full_control, current_sid),
        (0x001F01FF, 1, inherited_full_control, "S-1-5-18"),
        (0x001F01FF, 1, inherited_full_control, sid),
    ]
    monkeypatch.setattr(file_permissions, "os", SimpleNamespace(name="nt", fspath=os.fspath))
    monkeypatch.setattr(file_permissions, "_windows_acl_snapshot", lambda _path: (current_sid, False, entries))
    monkeypatch.setattr(file_permissions, "_windows_current_user_sid", lambda: current_sid)
    monkeypatch.setattr(cmd_setup, "os", SimpleNamespace(name="nt", path=os.path))
    monkeypatch.setattr(gateway_module, "packaged_windows_gateway_path", lambda: "")

    resolved = cmd_setup._trusted_gateway_lifecycle_executable(os.fspath(gateway))

    assert resolved == (str(gateway.resolve()) if trusted else None)
    # Private files keep trusting only the user, OWNER RIGHTS and SYSTEM.
    assert file_permissions.windows_acl_write_error(os.fspath(gateway)) == f"ACL grants write access to untrusted SID {sid}"


@pytest.mark.parametrize(
    "owner_sid",
    [
        "S-1-5-32-544",  # Elevated Administrators owner.
        "S-1-5-18",  # LocalSystem owner.
        "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",  # TrustedInstaller owner.
    ],
)
def test_windows_gateway_lifecycle_accepts_trusted_system_owners(monkeypatch, tmp_path, owner_sid):
    current_sid = "S-1-5-21-current"
    gateway = tmp_path / "bin" / "defenseclaw-gateway.exe"
    gateway.parent.mkdir()
    gateway.write_bytes(b"synthetic")
    entries = [
        (0x001F01FF, 1, 0, current_sid),
        (0x001F01FF, 1, 0, "S-1-5-18"),
        (0x001F01FF, 1, 0, "S-1-5-32-544"),
        (0x001F01FF, 1, 0, owner_sid),
    ]
    monkeypatch.setattr(file_permissions, "os", SimpleNamespace(name="nt", fspath=os.fspath))
    monkeypatch.setattr(file_permissions, "_windows_acl_snapshot", lambda _path: (owner_sid, False, entries))
    monkeypatch.setattr(file_permissions, "_windows_current_user_sid", lambda: current_sid)
    monkeypatch.setattr(cmd_setup, "os", os_view("nt"))
    monkeypatch.setattr(cmd_setup.shutil, "which", lambda *_args, **_kwargs: os.fspath(gateway))
    monkeypatch.setattr(gateway_module, "packaged_windows_install_root", lambda: "")
    monkeypatch.setattr(gateway_module, "packaged_windows_gateway_path", lambda: "")

    assert cmd_setup._trusted_gateway_lifecycle_executable(os.fspath(gateway)) == str(gateway.resolve())
    assert cmd_setup._gateway_lifecycle_executable(native=True, search_path=os.fspath(gateway.parent)) == str(
        gateway.resolve()
    )
    # Private-file validation retains its current-user ownership requirement.
    assert file_permissions.windows_acl_write_error(gateway) == f"owner SID {owner_sid} is not the current user"


@pytest.mark.parametrize("writer_sid", ["S-1-5-32-545", "S-1-1-0"])
def test_windows_gateway_lifecycle_names_other_writers(monkeypatch, tmp_path, writer_sid):
    current_sid = "S-1-5-21-current"
    gateway = tmp_path / "bin" / "defenseclaw-gateway.exe"
    gateway.parent.mkdir()
    gateway.write_bytes(b"synthetic")
    entries = [
        (0x001F01FF, 1, 0, current_sid),
        (0x001F01FF, 1, 0, "S-1-5-32-544"),
        (0x001F01FF, 1, 0, writer_sid),
    ]
    monkeypatch.setattr(file_permissions, "os", SimpleNamespace(name="nt", fspath=os.fspath))
    monkeypatch.setattr(file_permissions, "_windows_acl_snapshot", lambda _path: (current_sid, False, entries))
    monkeypatch.setattr(file_permissions, "_windows_current_user_sid", lambda: current_sid)
    monkeypatch.setattr(cmd_setup, "os", os_view("nt"))
    monkeypatch.setattr(cmd_setup.shutil, "which", lambda *_args, **_kwargs: os.fspath(gateway))
    monkeypatch.setattr(gateway_module, "packaged_windows_install_root", lambda: "")
    monkeypatch.setattr(gateway_module, "packaged_windows_gateway_path", lambda: "")

    assert cmd_setup._trusted_gateway_lifecycle_executable(os.fspath(gateway)) is None
    reason = cmd_setup._refused_gateway_lifecycle_candidate(search_path=os.fspath(gateway.parent))
    assert f"untrusted SID {writer_sid}" in reason
    assert "Restore" in reason


def test_windows_gateway_lifecycle_accepts_read_only_users_ace(monkeypatch, tmp_path):
    current_sid = "S-1-5-21-current"
    gateway = tmp_path / "bin" / "defenseclaw-gateway.exe"
    gateway.parent.mkdir()
    gateway.write_bytes(b"synthetic")
    entries = [
        (0x001F01FF, 1, 0, current_sid),
        (0x001F01FF, 1, 0, "S-1-5-32-544"),
        (0x80000000, 1, 0, "S-1-5-32-545"),
    ]
    monkeypatch.setattr(file_permissions, "os", SimpleNamespace(name="nt", fspath=os.fspath))
    monkeypatch.setattr(file_permissions, "_windows_acl_snapshot", lambda _path: (current_sid, False, entries))
    monkeypatch.setattr(file_permissions, "_windows_current_user_sid", lambda: current_sid)
    monkeypatch.setattr(cmd_setup, "os", SimpleNamespace(name="nt", path=os.path))
    monkeypatch.setattr(gateway_module, "packaged_windows_gateway_path", lambda: "")

    assert cmd_setup._trusted_gateway_lifecycle_executable(os.fspath(gateway)) == str(gateway.resolve())


@pytest.mark.parametrize("writer_sid", ["", "S-1-5-32-545", "S-1-1-0"])
def test_windows_packaged_gateway_uses_the_same_custody_check(monkeypatch, tmp_path, writer_sid):
    current_sid = "S-1-5-21-current"
    gateway = tmp_path / "bin" / "defenseclaw-gateway.exe"
    gateway.parent.mkdir()
    gateway.write_bytes(b"synthetic")
    entries = [
        (0x001F01FF, 1, 0, current_sid),
        (0x001F01FF, 1, 0, "S-1-5-32-544"),
    ]
    if writer_sid:
        entries.append((0x001F01FF, 1, 0, writer_sid))
    monkeypatch.setattr(file_permissions, "os", SimpleNamespace(name="nt", fspath=os.fspath))
    monkeypatch.setattr(file_permissions, "_windows_acl_snapshot", lambda _path: ("S-1-5-32-544", False, entries))
    monkeypatch.setattr(file_permissions, "_windows_current_user_sid", lambda: current_sid)
    monkeypatch.setattr(cmd_setup, "os", SimpleNamespace(name="nt", path=os.path))
    monkeypatch.setattr(gateway_module, "packaged_windows_install_root", lambda: os.fspath(tmp_path))
    monkeypatch.setattr(gateway_module, "packaged_windows_gateway_path", lambda: os.fspath(gateway))

    result = cmd_setup._gateway_lifecycle_executable()
    selected, refusal = cmd_setup._gateway_lifecycle_resolution()
    assert selected == result
    if writer_sid:
        assert result is None
        assert f"untrusted SID {writer_sid}" in refusal
        assert f"untrusted SID {writer_sid}" in cmd_setup._refused_gateway_lifecycle_candidate()
    else:
        assert result == str(gateway.resolve())
        assert refusal == ""


@pytest.mark.parametrize("path_form", ["quoted", "relative_shadow"])
@pytest.mark.parametrize("writer_sid", ["S-1-5-32-544", "S-1-5-32-545"])
def test_windows_gateway_refusal_uses_the_selected_path_candidate(monkeypatch, tmp_path, path_form, writer_sid):
    current_sid = "S-1-5-21-current"
    gateway = tmp_path / "bin" / "defenseclaw-gateway.exe"
    gateway.parent.mkdir()
    gateway.write_bytes(b"synthetic")
    gateway.chmod(0o755)
    entries = [(0x001F01FF, 1, 0x13, writer_sid)]
    monkeypatch.setattr(file_permissions, "os", SimpleNamespace(name="nt", fspath=os.fspath))
    monkeypatch.setattr(file_permissions, "_windows_acl_snapshot", lambda _path: (current_sid, False, entries))
    monkeypatch.setattr(file_permissions, "_windows_current_user_sid", lambda: current_sid)
    monkeypatch.setattr(cmd_setup, "os", os_view("nt"))
    monkeypatch.setattr(gateway_module, "packaged_windows_install_root", lambda: None)
    monkeypatch.setattr(gateway_module, "GATEWAY_BIN_NAME", gateway.name)
    monkeypatch.setattr(gateway_module, "canonical_install_path", lambda: str(tmp_path / "absent.exe"))
    if path_form == "quoted":
        search_path = f'"{gateway.parent}"'
    else:
        shadow = tmp_path / "shadow"
        shadow.mkdir()
        (shadow / gateway.name).write_bytes(b"shadow")
        (shadow / gateway.name).chmod(0o755)
        monkeypatch.chdir(tmp_path)
        search_path = f"shadow{os.pathsep}{gateway.parent}"

    selected = cmd_setup._gateway_lifecycle_executable(native=True, search_path=search_path)
    refusal = cmd_setup._refused_gateway_lifecycle_candidate(search_path=search_path)
    if writer_sid == "S-1-5-32-544":
        assert selected == str(gateway.resolve())
        assert refusal == ""
    else:
        assert selected is None
        assert str(gateway.resolve()) in refusal
        assert writer_sid in refusal
        monkeypatch.setenv("PATH", search_path)
        with pytest.raises(click.ClickException, match=writer_sid) as exc:
            cmd_setup_cowork._render_hooks(SimpleNamespace(data_dir=str(tmp_path)))
        assert "was not found" not in str(exc.value)


@pytest.mark.parametrize("writer_sid", ["S-1-5-32-544", "S-1-5-32-545"])
def test_windows_gateway_refusal_uses_canonical_candidate(monkeypatch, tmp_path, writer_sid):
    current_sid = "S-1-5-21-current"
    gateway = tmp_path / "bin" / "defenseclaw-gateway.exe"
    gateway.parent.mkdir()
    gateway.write_bytes(b"synthetic")
    gateway.chmod(0o755)
    entries = [(0x001F01FF, 1, 0x13, writer_sid)]
    monkeypatch.setattr(file_permissions, "os", SimpleNamespace(name="nt", fspath=os.fspath))
    monkeypatch.setattr(file_permissions, "_windows_acl_snapshot", lambda _path: (current_sid, False, entries))
    monkeypatch.setattr(file_permissions, "_windows_current_user_sid", lambda: current_sid)
    monkeypatch.setattr(cmd_setup, "os", os_view("nt"))
    monkeypatch.setattr(cmd_setup.shutil, "which", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(gateway_module, "packaged_windows_install_root", lambda: None)
    monkeypatch.setattr(gateway_module, "canonical_install_path", lambda: str(gateway))

    selected = cmd_setup._gateway_lifecycle_executable(search_path=str(tmp_path / "absent"))
    refusal = cmd_setup._refused_gateway_lifecycle_candidate(search_path=str(tmp_path / "absent"))
    if writer_sid == "S-1-5-32-544":
        assert selected == str(gateway.resolve())
        assert refusal == ""
    else:
        assert selected is None
        assert str(gateway.resolve()) in refusal
        assert writer_sid in refusal


def test_windows_owner_assignment_leaves_a_path_the_user_already_owns(monkeypatch):
    """Setting an unchanged owner needs WRITE_OWNER, which a Modify-only TEMP folder does not grant.

    Doctor's observability snapshot in a per-session TEMP folder ended in
    "PermissionError: [WinError 5] Access is denied." that way.
    """
    current_sid = "S-1-5-21-current"
    monkeypatch.setattr(file_permissions, "_windows_acl_snapshot", lambda _path: (current_sid, False, []))
    monkeypatch.setattr(file_permissions, "_windows_current_user_sid", lambda: current_sid)
    monkeypatch.setattr(ctypes, "WinDLL", Mock(side_effect=AssertionError("owner rewritten")), raising=False)

    file_permissions._set_windows_current_user_owner("snapshot.yaml")


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
    monkeypatch.setattr(cmd_doctor, "os", os_view("nt"))
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
    monkeypatch.setattr(doctor_gateway, "os", os_view("nt"))
    inspected: list[str] = []
    monkeypatch.setattr(
        file_permissions,
        "windows_acl_custody_write_error",
        lambda path, *, allow_current_user, require_current_user_owner=False, ancestor_replace_only=False: (
            inspected.append(
                f"{os.path.normpath(os.fspath(path))}:{allow_current_user}:"
                f"{require_current_user_owner}:{ancestor_replace_only}"
            )
        ),
    )

    status, problem = doctor_gateway._pid_record_integrity_error(
        os.fspath(pid_file),
        info,
    )

    assert (status, problem) == ("ok", "")
    expected = [f"{os.path.normpath(os.fspath(pid_file))}:True:True:False"]
    ancestor = pid_file.parent
    while ancestor.parent != ancestor:
        expected.append(f"{os.path.normpath(os.fspath(ancestor))}:True:False:True")
        ancestor = ancestor.parent
    assert inspected == expected


@pytest.mark.parametrize(
    ("permissions", "expected_status"),
    [
        (0x00000004 | 0x00000002, "ok"),  # inherited Users (CI)(AD)/(WD): create-child only.
        (0x00000040, "denied"),  # FILE_DELETE_CHILD can replace the record's folder.
    ],
)
def test_windows_pid_integrity_ignores_create_child_on_second_volume_ancestor(
    monkeypatch,
    tmp_path,
    permissions,
    expected_status,
):
    """GAP-2615: DEFENSECLAW_HOME below Q:\\dch-root, which keeps the volume root's Users grants."""
    pid_file = tmp_path / "dch-root" / "dch" / "gateway.pid"
    pid_file.parent.mkdir(parents=True)
    pid_file.write_text("4242", encoding="ascii")
    info = pid_file.stat()
    current_sid = "S-1-5-21-current"
    shared_parent = os.path.normpath(os.fspath(pid_file.parent.parent))

    def snapshot(path):
        entries = [(0x001F01FF, 1, 0, current_sid)]
        if os.path.normpath(os.fspath(path)) == shared_parent:
            entries.append((permissions, 1, 0x02, "S-1-5-32-545"))
        return current_sid, False, entries

    monkeypatch.setattr(doctor_gateway, "os", os_view("nt"))
    monkeypatch.setattr(file_permissions, "os", os_view("nt"))
    monkeypatch.setattr(file_permissions, "_windows_acl_snapshot", snapshot)
    monkeypatch.setattr(file_permissions, "_windows_current_user_sid", lambda: current_sid)

    status, problem = doctor_gateway._pid_record_integrity_error(os.fspath(pid_file), info)

    assert status == expected_status
    if expected_status == "denied":
        assert "S-1-5-32-545" in problem


def test_windows_gateway_data_dir_requires_current_user_owned_custody(
    monkeypatch,
    tmp_path,
):
    inspected: list[str] = []
    monkeypatch.setattr(cmd_doctor, "os", os_view("nt"))
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


@pytest.mark.skipif(os.name == "nt", reason="POSIX UID ownership semantics")
def test_trusted_runtime_owner_accepts_root_and_self_only(monkeypatch) -> None:
    monkeypatch.delenv("SUDO_UID", raising=False)
    monkeypatch.delenv("SUDO_GID", raising=False)
    monkeypatch.delenv("SUDO_USER", raising=False)
    monkeypatch.setattr(file_permissions.os, "getuid", lambda: 0)
    assert file_permissions.trusted_runtime_owner(501, current_uid=0) is False
    assert file_permissions.trusted_runtime_owner(0, current_uid=501) is True
    assert file_permissions.trusted_runtime_owner(501, current_uid=501) is True
    assert file_permissions.trusted_runtime_owner(502, current_uid=501) is False


@pytest.mark.skipif(os.name == "nt", reason="POSIX sudo leftover naming")
def test_root_owned_private_regular_file_rejects_group_or_other_access(
    monkeypatch,
    tmp_path,
) -> None:
    path = tmp_path / "gateway.pid"
    path.write_text("{}\n", encoding="utf-8")
    real_lstat = os.lstat

    def lstat_root(candidate, *args, **kwargs):
        info = real_lstat(candidate, *args, **kwargs)
        fields = list(info)
        fields[stat.ST_UID] = 0
        return os.stat_result(fields)

    monkeypatch.setattr(file_permissions.os, "lstat", lstat_root)
    monkeypatch.setattr(file_permissions.os, "geteuid", lambda: 501)

    os.chmod(path, 0o600)
    assert file_permissions.root_owned_private_regular_file(path) is True
    os.chmod(path, 0o640)
    assert file_permissions.root_owned_private_regular_file(path) is False


@pytest.mark.skipif(os.name == "nt", reason="POSIX sudo leftover naming")
def test_sudo_runtime_leftover_relpaths_names_root_owned_runtime_files(
    monkeypatch,
    tmp_path,
) -> None:
    lock = tmp_path / "hook_contract_lock.json"
    lock.write_text("{}\n", encoding="utf-8")
    os.chmod(lock, 0o600)
    (tmp_path / "hooks").mkdir()
    token = tmp_path / "hooks" / ".hook-codex.token"
    token.write_text("token\n", encoding="utf-8")
    os.chmod(token, 0o600)
    real_lstat = os.lstat

    def lstat_root(path, *args, **kwargs):
        info = real_lstat(path, *args, **kwargs)
        resolved = os.path.abspath(os.fspath(path))
        if resolved in {os.path.abspath(lock), os.path.abspath(token)}:
            fields = list(info)
            fields[stat.ST_UID] = 0
            return os.stat_result(fields)
        return info

    monkeypatch.setattr(file_permissions.os, "lstat", lstat_root)
    monkeypatch.setattr(file_permissions.os, "geteuid", lambda: 501)

    leftovers = file_permissions.sudo_runtime_leftover_relpaths(tmp_path)

    assert leftovers == ["hook_contract_lock.json", "hooks/.hook-codex.token"]


@pytest.mark.skipif(os.name == "nt", reason="POSIX sudo leftover naming")
def test_doctor_names_sudo_runtime_leftovers(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(
        cmd_doctor,
        "sudo_runtime_leftover_relpaths",
        lambda _data_dir: ["hook_contract_lock.json", "gateway.pid"],
    )
    result = cmd_doctor._DoctorResult(quiet=True)

    cmd_doctor._check_sudo_runtime_leftovers(
        SimpleNamespace(data_dir=os.fspath(tmp_path)),
        result,
    )

    check = result.checks[-1]
    assert check["status"] == "fail"
    assert check["label"] == "Sudo leftovers"
    assert "hook_contract_lock.json" in check["detail"]
    assert "give them back to this account" in check["detail"]
    assert "descriptor-bound" not in check["remediation"]
    assert "rerun the gateway once with sudo" not in check["remediation"]
    assert 'sudo chown -R "$(id -un)" ' in check["remediation"]
    assert check["reason_code"] == "sudo-runtime-leftovers"


def _moved_store_config(monkeypatch, tmp_path, **extra):
    home = tmp_path / "install home"
    store = tmp_path / "moved store's data"
    home.mkdir()
    store.mkdir()
    (home / "config.yaml").write_text(f"data_dir: {json.dumps(os.fspath(store))}\n")
    monkeypatch.setenv("DEFENSECLAW_HOME", os.fspath(home))
    monkeypatch.delenv("DEFENSECLAW_CONFIG", raising=False)
    monkeypatch.setattr(gateway_module, "resolve_gateway_binary", lambda: "")
    return home, store, SimpleNamespace(data_dir=os.fspath(store), deployment_mode="", **extra)


def _chowned_dirs(remediation: str) -> list[str]:
    """The directories the printed chown returns, as the shell would read them."""
    tail = remediation.split('sudo chown -R "$(id -un)" ', 1)[1]
    returned, restore = tail.split(" && chmod -R u+rwX ", 1)
    assert shlex.split(restore.split(" && defenseclaw-gateway start", 1)[0]) == shlex.split(returned)
    return shlex.split(returned)


@pytest.mark.skipif(os.name == "nt", reason="POSIX sudo leftover naming")
def test_doctor_leftovers_remedy_returns_install_home_and_moved_store(monkeypatch, tmp_path) -> None:
    """GAP-0711, GAP-0713: one remedy for the leftovers covers both directories."""
    home, store, cfg = _moved_store_config(monkeypatch, tmp_path)
    monkeypatch.setattr(cmd_doctor, "sudo_runtime_leftover_relpaths", lambda _d: ["active_connector.json"])
    result = cmd_doctor._DoctorResult(quiet=True)

    cmd_doctor._check_sudo_runtime_leftovers(cfg, result)

    remediation = result.checks[-1]["remediation"]
    assert _chowned_dirs(remediation) == [os.fspath(home), os.fspath(store)]
    # One chain, in the order it must run: stop (succeeds when the gateway is
    # already stopped), return the files, start. A live root gateway makes the
    # start before the stop fail, so the stop comes first.
    steps = remediation.split(": sudo env ", 1)[1].split(" && ")
    assert len(steps) == 4, remediation
    assert steps[0].endswith(" stop") and steps[0].startswith("DEFENSECLAW_HOME=")
    assert steps[1].startswith('sudo chown -R "$(id -un)" ')
    assert steps[2].startswith("chmod -R u+rwX ")
    assert steps[3] == "defenseclaw-gateway start"
    assert "rerun the gateway once with sudo" not in remediation
    assert "stopped first" not in remediation


@pytest.mark.skipif(os.name == "nt", reason="POSIX sudo leftover naming")
@pytest.mark.parametrize("kind", ["managed", "secure_client"])
def test_doctor_leftovers_guidance_unchanged_for_managed_and_secure_client(monkeypatch, tmp_path, kind) -> None:
    """Managed installs and Secure Client hosts keep their own guidance."""
    _home, _store, cfg = _moved_store_config(monkeypatch, tmp_path)
    if kind == "managed":
        cfg.deployment_mode = "managed_enterprise"
    else:
        from defenseclaw.enforce import asset_lists

        monkeypatch.setattr(asset_lists, "is_secure_client", lambda _cfg: True)
    monkeypatch.setattr(cmd_doctor, "sudo_runtime_leftover_relpaths", lambda _d: ["active_connector.json"])
    result = cmd_doctor._DoctorResult(quiet=True)

    cmd_doctor._check_sudo_runtime_leftovers(cfg, result)

    check = result.checks[-1]
    assert "descriptor-bound" in check["remediation"]
    assert "chown" not in check["remediation"]


def _recovery_chain(remediation: str) -> str:
    """The copy-and-paste command that ends a root-gateway remedy."""
    for marker in ("Without the app, run: ", "start it as yourself with: "):
        if marker in remediation:
            return remediation.split(marker, 1)[1]
    raise AssertionError(f"no recovery command in {remediation!r}")


@pytest.mark.skipif(os.name == "nt", reason="POSIX per-user gateway account")
@pytest.mark.parametrize("platform_name", ["linux", "darwin", "win32"])
def test_root_gateway_remedy_is_written_for_the_running_os(monkeypatch, tmp_path, platform_name) -> None:
    """GAP-0706: macOS advice is for macOS only, and no remedy ends in a doubled period."""
    monkeypatch.setattr(cmd_doctor, "sys", SimpleNamespace(platform=platform_name))
    monkeypatch.setattr(gateway_module, "resolve_gateway_binary", lambda: "")
    remedy = cmd_doctor._root_gateway_remedy(SimpleNamespace(data_dir=os.fspath(tmp_path), deployment_mode=""))

    assert ("DefenseClawMac" in remedy) == (platform_name == "darwin")
    assert ("Start Gateway" in remedy) == (platform_name == "darwin")
    assert "macOS" not in remedy
    assert ("sudo env DEFENSECLAW_HOME=" in remedy) == (platform_name != "win32")
    assert ("sudo chown -R" in remedy) == (platform_name != "win32")
    assert not remedy.endswith(".") and ".." not in remedy
    assert (cmd_doctor.ROOT_GATEWAY_REASON + " " + remedy + ".").count("..") == 0
    if platform_name == "win32":
        # GAP-0747: rendered like managed.WindowsCommandLine, never a bare command.
        assert remedy == (
            "Stop it from an elevated PowerShell prompt (& 'defenseclaw-gateway.exe' stop), "
            "then start it as yourself from a normal PowerShell prompt (& 'defenseclaw-gateway.exe' start)"
        )
        assert "(defenseclaw-gateway " not in remedy
        # The call operator runs only in PowerShell (not cmd.exe): both steps name it.
        assert "from an elevated PowerShell prompt (" in remedy and "from a normal PowerShell prompt (" in remedy
        assert "administrator prompt" not in remedy


def test_windows_root_gateway_remedy_quotes_the_resolved_gateway_path(monkeypatch, tmp_path) -> None:
    """GAP-0747: a gateway path with a space or an apostrophe is one inert literal."""
    path = os.fspath(tmp_path / "O'Brien Jr" / "defenseclaw-gateway.exe")
    monkeypatch.setattr(gateway_module, "resolve_gateway_binary", lambda: path)
    remedy = cmd_doctor._root_gateway_remedy_for("win32", SimpleNamespace(data_dir=os.fspath(tmp_path), deployment_mode=""))
    quoted = path.replace("'", "''")
    assert f"(& '{quoted}' stop)" in remedy
    assert f"(& '{quoted}' start)" in remedy
    assert "sudo" not in remedy


def _gateway_account_fixture(monkeypatch, tmp_path, *, process_uid, deployment_mode=""):
    code = "root_gateway" if process_uid == 0 and deployment_mode != "managed_enterprise" else "trusted"
    monkeypatch.setattr(
        cmd_doctor,
        "_trusted_gateway_listener",
        lambda _cfg: cmd_doctor._GatewayTrust(code, "fixture", pid=4242),
    )
    result = cmd_doctor._DoctorResult(quiet=True)
    cmd_doctor._check_gateway_account(
        SimpleNamespace(data_dir=os.fspath(tmp_path), deployment_mode=deployment_mode),
        result,
    )
    return result


@pytest.mark.skipif(os.name == "nt" or os.geteuid() == 0, reason="POSIX per-user gateway account")
def test_doctor_warns_when_per_user_gateway_runs_as_root(monkeypatch, tmp_path) -> None:
    result = _gateway_account_fixture(monkeypatch, tmp_path, process_uid=0)

    check = result.checks[-1]
    assert check["status"] == "warn"
    assert check["label"] == "Gateway account"
    assert "running as root" in check["detail"]
    assert check["reason_code"] == "per-user-gateway-runs-as-root"
    assert ("DefenseClawMac" in check["remediation"]) == (sys.platform == "darwin")
    assert "sudo env DEFENSECLAW_HOME=" in check["remediation"]
    assert not check["remediation"].endswith(".")
    assert ".." not in check["remediation"]


@pytest.mark.skipif(os.name == "nt" or os.geteuid() == 0, reason="POSIX per-user gateway account")
def test_doctor_gateway_account_hint_quotes_the_home(monkeypatch, tmp_path) -> None:
    home = tmp_path / "my home; touch pwned"
    home.mkdir()
    binary = tmp_path / "bin with spaces" / "defenseclaw-gateway"
    binary.parent.mkdir()
    binary.write_text("#!/bin/sh\nexit 0\n")
    binary.chmod(0o700)
    monkeypatch.setattr(gateway_module, "resolve_gateway_binary", lambda: os.fspath(binary))
    # The gateway home is the one DEFENSECLAW_HOME names; the remedy reads it
    # from there, not from the data_dir doctor loaded (GAP-0711, GAP-0713).
    monkeypatch.setenv("DEFENSECLAW_HOME", os.fspath(home))
    monkeypatch.delenv("DEFENSECLAW_CONFIG", raising=False)
    result = _gateway_account_fixture(monkeypatch, home, process_uid=0)

    remediation = result.checks[-1]["remediation"]
    assert shlex.quote(os.fspath(home)) in remediation
    tokens = shlex.split(_recovery_chain(remediation))
    assert tokens[:5] == ["sudo", "env", f"DEFENSECLAW_HOME={home}", os.fspath(binary), "stop"]
    assert tokens[10] == os.fspath(home)


@pytest.mark.skipif(os.name == "nt" or os.geteuid() == 0, reason="POSIX per-user gateway account")
@pytest.mark.parametrize("platform_name", ["linux", "darwin"])
@pytest.mark.parametrize(
    "config_location",
    [
        "default",
        "default_with_store_config",
        "explicit_home",
        "explicit_external",
        "explicit_home_with_store_config",
    ],
)
def test_doctor_custom_store_root_gateway_uses_pid_record_home(
    monkeypatch, tmp_path, platform_name, config_location
) -> None:
    """The active config binds a moved store to the gateway PID-record home."""
    from defenseclaw.doctor_gateway import PIDRecord, ProcessEvidence

    home = tmp_path / "install home"
    store = tmp_path / "store"
    home.mkdir()
    store.mkdir()
    home_config = home / "config.yaml"
    home_config.write_text(f"data_dir: {store}\n")
    monkeypatch.setenv("DEFENSECLAW_HOME", os.fspath(home))
    monkeypatch.delenv("DEFENSECLAW_CONFIG", raising=False)
    if config_location == "explicit_external":
        external = tmp_path / "config location"
        external.mkdir()
        explicit_config = external / "config.yaml"
        explicit_config.write_text(f"data_dir: {store}\n")
        monkeypatch.setenv("DEFENSECLAW_CONFIG", os.fspath(explicit_config))
    elif config_location.startswith("explicit_home"):
        monkeypatch.setenv("DEFENSECLAW_CONFIG", os.fspath(home_config))
    if config_location.endswith("with_store_config"):
        (store / "config.yaml").write_text("data_dir: /unrelated/store\n")
    monkeypatch.setattr(cmd_doctor, "sys", SimpleNamespace(platform=platform_name))
    binary = tmp_path / "local bin" / "defenseclaw-gateway"
    binary.parent.mkdir()
    binary.write_text("#!/bin/sh\nexit 0\n")
    binary.chmod(0o700)
    monkeypatch.setattr(gateway_module, "resolve_gateway_binary", lambda: os.fspath(binary))
    record = PIDRecord(
        "ok", pid=4242, executable=os.fspath(binary),
        data_dir=os.fspath(home), start_identity="kernel-generation",
    )
    process = ProcessEvidence(
        "ok", pid=4242, executable=os.fspath(binary),
        start_identity=record.start_identity, uid=0,
    )
    cfg = SimpleNamespace(data_dir=os.fspath(store), deployment_mode="")
    from defenseclaw.config import gateway_pid_path

    assert gateway_pid_path(store) == os.fspath(home / "gateway.pid")
    monkeypatch.setattr(cmd_doctor, "pid_alive", lambda _pid: True)
    for listener_code in ("missing_listener", "unavailable", "ambiguous_listener", "root_gateway"):
        trust = cmd_doctor._GatewayTrust(
            listener_code, "fixture", pid=4242, home_bound=True,
            record=record, process=process,
        )
        monkeypatch.setattr(cmd_doctor, "_trusted_gateway_listener", lambda _cfg: trust)
        result = cmd_doctor._DoctorResult(quiet=True)
        cmd_doctor._check_gateway_account(cfg, result)
        assert [(check["label"], check["status"]) for check in result.checks] == [
            ("Gateway account", "warn")
        ]
        remediation = result.checks[0]["remediation"]
        tokens = shlex.split(_recovery_chain(remediation))
        assert ["sudo", "env", f"DEFENSECLAW_HOME={home}", os.fspath(binary), "stop"] == tokens[:5]
        # The root run left files in the install home and in the moved store.
        assert tokens[9:12] == ["$(id -un)", os.fspath(home), os.fspath(store)]
        assert tokens[-3:] == ["&&", "defenseclaw-gateway", "start"]
        assert f"DEFENSECLAW_HOME={store}" not in remediation

    foreign = PIDRecord(
        "ok", pid=4242, executable=os.fspath(binary),
        data_dir=os.fspath(tmp_path / "other"), start_identity="kernel-generation",
    )
    trust = cmd_doctor._GatewayTrust(
        "missing_listener", "fixture", pid=4242, home_bound=True,
        record=foreign, process=process,
    )
    monkeypatch.setattr(cmd_doctor, "_trusted_gateway_listener", lambda _cfg: trust)
    result = cmd_doctor._DoctorResult(quiet=True)
    cmd_doctor._check_gateway_account(cfg, result)
    assert result.checks == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX process evidence")
def test_linux_root_listener_diagnosis_accepts_custom_store_install_home(monkeypatch, tmp_path) -> None:
    from defenseclaw.doctor_gateway import PIDRecord
    from defenseclaw.enforce import asset_lists

    home = tmp_path / "install"
    store = tmp_path / "store"
    home.mkdir()
    store.mkdir()
    (home / "config.yaml").write_text(f"data_dir: {store}\n")
    monkeypatch.setenv("DEFENSECLAW_HOME", os.fspath(home))
    monkeypatch.setattr(cmd_doctor, "_process_uid", lambda _pid: 0)
    monkeypatch.setattr(cmd_doctor, "pid_alive", lambda _pid: True)
    monkeypatch.setattr(cmd_doctor, "_linux_root_process_identity_matches", lambda _record: True)
    monkeypatch.setattr(cmd_doctor, "_linux_root_listener_at", lambda _host, _port: True)
    monkeypatch.setattr(asset_lists, "is_secure_client", lambda _cfg: False)
    cfg = SimpleNamespace(data_dir=os.fspath(store), deployment_mode="")
    record = PIDRecord(
        "ok", pid=4242, executable="/usr/local/bin/defenseclaw-gateway",
        data_dir=os.fspath(home), start_identity="kernel-generation",
    )
    process_trust = cmd_doctor._GatewayTrust("unavailable", "fixture", pid=4242, record=record)
    result = cmd_doctor._linux_root_gateway_diagnosis(
        cfg, process_trust, "127.0.0.1", 18970, "linux"
    )
    assert result is not None and result.code == "root_gateway"
    assert result.home_bound

    foreign = PIDRecord(
        "ok", pid=4242, executable=record.executable,
        data_dir=os.fspath(tmp_path / "other"), start_identity=record.start_identity,
    )
    process_trust = cmd_doctor._GatewayTrust("unavailable", "fixture", pid=4242, record=foreign)
    assert cmd_doctor._linux_root_gateway_diagnosis(
        cfg, process_trust, "127.0.0.1", 18970, "linux"
    ) is None


@pytest.mark.skipif(os.name == "nt" or os.geteuid() == 0, reason="POSIX per-user gateway account")
@pytest.mark.parametrize("listener_code", ["missing_listener", "unavailable", "ambiguous_listener"])
def test_doctor_warns_for_live_root_gateway_before_listener_is_inspectable(
    monkeypatch, tmp_path, listener_code
) -> None:
    from defenseclaw.doctor_gateway import PIDRecord

    home = os.fspath(tmp_path)
    record = PIDRecord(
        "ok", pid=4242, executable="/usr/local/bin/defenseclaw-gateway",
        data_dir=home, start_identity="kernel-generation",
    )
    trust = cmd_doctor._GatewayTrust(listener_code, "listener pending", pid=4242, home_bound=True, record=record)
    monkeypatch.setattr(cmd_doctor, "_trusted_gateway_listener", lambda _cfg: trust)
    monkeypatch.setattr(cmd_doctor, "pid_alive", lambda _pid: True)
    monkeypatch.setattr(cmd_doctor, "_process_uid", lambda _pid: 0)
    result = cmd_doctor._DoctorResult(quiet=True)
    cmd_doctor._check_gateway_account(SimpleNamespace(data_dir=home, deployment_mode=""), result)
    assert [(check["label"], check["status"]) for check in result.checks] == [("Gateway account", "warn")]

    process = doctor_gateway.ProcessEvidence(
        "ok", pid=4242, executable=record.executable,
        start_identity=record.start_identity, uid=0,
    )
    monkeypatch.setattr(cmd_doctor, "_trusted_gateway_listener", lambda _cfg: cmd_doctor._GatewayTrust(
        listener_code, "listener pending", pid=4242, home_bound=True, record=record, process=process,
    ))
    monkeypatch.setattr(cmd_doctor, "_process_uid", lambda _pid: None)
    result = cmd_doctor._DoctorResult(quiet=True)
    cmd_doctor._check_gateway_account(SimpleNamespace(data_dir=home, deployment_mode=""), result)
    assert [(check["label"], check["status"]) for check in result.checks] == [("Gateway account", "warn")]

    changed_generation = doctor_gateway.ProcessEvidence(
        "ok", pid=4242, executable=record.executable, start_identity="different", uid=0,
    )
    monkeypatch.setattr(cmd_doctor, "_trusted_gateway_listener", lambda _cfg: cmd_doctor._GatewayTrust(
        listener_code, "listener pending", pid=4242, home_bound=True, record=record, process=changed_generation,
    ))
    result = cmd_doctor._DoctorResult(quiet=True)
    cmd_doctor._check_gateway_account(SimpleNamespace(data_dir=home, deployment_mode=""), result)
    assert result.checks == []

    monkeypatch.setattr(cmd_doctor, "_trusted_gateway_listener", lambda _cfg: trust)
    monkeypatch.setattr(cmd_doctor, "_process_uid", lambda _pid: 1000)
    result = cmd_doctor._DoctorResult(quiet=True)
    cmd_doctor._check_gateway_account(SimpleNamespace(data_dir=home, deployment_mode=""), result)
    assert result.checks == []


@pytest.mark.skipif(os.name == "nt" or os.geteuid() == 0, reason="POSIX per-user gateway account")
def test_doctor_gateway_account_quiet_for_own_or_managed_gateway(monkeypatch, tmp_path) -> None:
    assert _gateway_account_fixture(monkeypatch, tmp_path, process_uid=os.geteuid()).checks == []
    assert _gateway_account_fixture(monkeypatch, tmp_path, process_uid=None).checks == []
    managed = _gateway_account_fixture(monkeypatch, tmp_path, process_uid=0, deployment_mode="managed_enterprise")
    assert managed.checks == []


@pytest.mark.skipif(not sys.platform.startswith(("linux", "darwin")), reason="kernel process owner")
def test_process_uid_reads_this_process_owner() -> None:
    assert cmd_doctor._process_uid(os.getpid()) == os.getuid()
    assert cmd_doctor._process_uid(0) is None


@pytest.mark.skipif(os.name == "nt", reason="POSIX sudo leftover naming")
def test_data_dir_integrity_names_root_owned_sudo_leftover(monkeypatch, tmp_path) -> None:
    info = tmp_path.stat()
    fields = list(info)
    fields[stat.ST_UID] = 0
    monkeypatch.setattr(cmd_doctor.os, "lstat", lambda _path: os.stat_result(fields))
    monkeypatch.setattr(cmd_doctor.os, "geteuid", lambda: 501)

    problem = cmd_doctor._gateway_data_dir_integrity_problem(
        SimpleNamespace(data_dir=os.fspath(tmp_path)),
    )

    assert problem == "gateway data directory is root-owned from a sudo-started gateway"


@pytest.mark.skipif(os.name == "nt", reason="POSIX sudo leftover naming")
def test_dotenv_safety_names_root_owned_sudo_leftover_without_reading(
    monkeypatch,
    tmp_path,
) -> None:
    dotenv = tmp_path / ".env"
    dotenv.write_text("DEFENSECLAW_GATEWAY_TOKEN=synthetic\n", encoding="utf-8")
    os.chmod(dotenv, 0o600)
    info = dotenv.lstat()
    fields = list(info)
    fields[stat.ST_UID] = 0
    monkeypatch.setattr(cmd_doctor.os, "lstat", lambda _path: os.stat_result(fields))
    monkeypatch.setattr(cmd_doctor.os, "geteuid", lambda: 501)
    monkeypatch.setattr(cmd_doctor, "_gateway_data_dir_integrity_problem", lambda _cfg: "")
    read = Mock(side_effect=AssertionError("must not consume a root-owned dotenv"))
    monkeypatch.setattr(cmd_doctor, "read_regular_file_no_follow", read)

    problem = cmd_doctor._gateway_dotenv_safety_problem(
        SimpleNamespace(data_dir=os.fspath(tmp_path)),
    )

    assert problem == "dotenv is root-owned from a sudo-started gateway"
    read.assert_not_called()
