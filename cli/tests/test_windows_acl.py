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

from __future__ import annotations

import ctypes
import ntpath
import os
import struct
import sys
import threading
import time
from types import SimpleNamespace
from unittest.mock import Mock

import defenseclaw.windows_acl as windows_acl
import pytest
from defenseclaw.windows_acl import WindowsAclError, WindowsFileSecurity


def _sid(*subauthorities: int, authority: int = 5) -> bytes:
    return (
        bytes((1, len(subauthorities)))
        + authority.to_bytes(6, "big")
        + b"".join(struct.pack("<I", value) for value in subauthorities)
    )


def _dacl(*aces: tuple[int, int, int, bytes]) -> bytes:
    encoded = []
    for ace_type, ace_flags, access_mask, sid in aces:
        size = 8 + len(sid)
        encoded.append(struct.pack("<BBHI", ace_type, ace_flags, size, access_mask) + sid)
    payload = b"".join(encoded)
    return struct.pack("<BBHHH", 2, 0, 8 + len(payload), len(encoded), 0) + payload


OWNER = _sid(21, 101, 202, 303, 1001)
SYSTEM = _sid(18)
ADMINISTRATORS = _sid(32, 544)
USERS = _sid(32, 545)
PRIVATE = WindowsFileSecurity(
    OWNER,
    _dacl(
        (0, 0, 0x001F01FF, OWNER),
        (0, 0, 0x001F01FF, SYSTEM),
        (0, 0, 0x001F01FF, ADMINISTRATORS),
    ),
    True,
)
HIGH_MANDATORY_LABEL = _dacl(
    (0x11, 0, 0x00000003, _sid(0x3000, authority=16)),
)


class _FakeApi:
    def __init__(self) -> None:
        self.security: dict[int, WindowsFileSecurity] = {}
        self.paths: dict[str, int] = {}
        self.events: list[tuple[str, object]] = []
        self.next_handle = 10
        self.change_after_write = False
        self.private_flags: list[int] = []

    def open_path(self, path: str, *, access: int, directory: bool = False) -> int:
        self.events.append(("open", (path, access, directory)))
        return self.paths[path]

    def open_directory_no_delete(self, path: str, *, protect_name: bool = True) -> int:
        handle = self.next_handle
        self.next_handle += 1
        self.events.append(("lease-open", (path, protect_name)))
        return handle

    def assert_real_directory(self, handle: int) -> None:
        self.events.append(("lease-validate", handle))

    def close_handle(self, handle: int) -> None:
        self.events.append(("close", handle))

    def get_security(self, handle: int) -> WindowsFileSecurity:
        self.events.append(("get", handle))
        return self.security[handle]

    def set_security(self, handle: int, security: WindowsFileSecurity) -> None:
        self.events.append(("set", security))
        self.security[handle] = security

    def create_file(self, path: str, security: WindowsFileSecurity) -> int:
        handle = self.next_handle
        self.next_handle += 1
        self.paths[path] = handle
        self.security[handle] = security
        self.events.append(("create", security))
        return handle

    def write_all(self, handle: int, payload: bytes) -> None:
        self.events.append(("write", payload))
        if self.change_after_write:
            current = self.security[handle]
            self.security[handle] = WindowsFileSecurity(current.owner, current.dacl + b"drift", True)

    def flush(self, handle: int) -> None:
        self.events.append(("flush", handle))

    def replace_file(self, target: str, replacement: str, backup: str) -> None:
        self.events.append(("replace", (target, replacement, backup)))

    def move_file_no_replace(self, source: str, target: str) -> None:
        self.events.append(("move", (source, target)))

    def replace_regular_file_by_handle(self, source: str, target: str) -> None:
        self.events.append(("handle-replace", (source, target)))

    def delete_regular_file_by_handle(self, path: str) -> None:
        self.events.append(("handle-delete", path))

    def private_security(self, owner: bytes, *, ace_flags: int = 0) -> WindowsFileSecurity:
        assert owner == OWNER
        self.private_flags.append(ace_flags)
        return PRIVATE

    def trusted_owner_sids(self) -> frozenset[str]:
        return frozenset({"S-1-5-21-101-202-303-1001"})


def test_write_new_file_protects_exact_acl_before_first_payload_byte(monkeypatch: pytest.MonkeyPatch) -> None:
    api = _FakeApi()
    monkeypatch.setattr(windows_acl, "_api", api)
    requested = WindowsFileSecurity(PRIVATE.owner, PRIVATE.dacl, False)

    windows_acl.write_new_file("candidate.tmp", b"secret-payload", requested)

    create_index = api.events.index(("create", requested.staging_copy()))
    write_index = api.events.index(("write", b"secret-payload"))
    assert create_index < write_index
    assert api.events[create_index][1].dacl_protected is True
    assert api.security[api.paths["candidate.tmp"]] == requested.staging_copy()


def test_staging_copy_converts_only_inherited_ace_markers_to_explicit() -> None:
    inherited = WindowsFileSecurity(
        OWNER,
        _dacl(
            (0, 0x13, 0x001F01FF, OWNER),
            (0, 0x10, 0x00020089, SYSTEM),
        ),
        False,
    )

    staged = inherited.staging_copy()

    assert staged.dacl_protected is True
    assert staged.dacl == _dacl(
        (0, 0x03, 0x001F01FF, OWNER),
        (0, 0x00, 0x00020089, SYSTEM),
    )
    assert inherited.dacl != staged.dacl


def test_unprotected_set_security_input_omits_inherited_aces() -> None:
    original = _dacl(
        (0, 0x03, 0x001F01FF, OWNER),
        (0, 0x10, 0x00020089, SYSTEM),
        (0, 0x13, 0x001F01FF, ADMINISTRATORS),
    )

    assert windows_acl._explicit_dacl_copy(original) == _dacl(
        (0, 0x03, 0x001F01FF, OWNER),
    )


def test_unprotected_update_omits_inherited_aces_when_target_already_inherits() -> None:
    requested = WindowsFileSecurity(
        OWNER,
        _dacl(
            (0, 0x03, 0x001F01FF, OWNER),
            (0, 0x10, 0x00020089, SYSTEM),
        ),
        False,
    )
    current = WindowsFileSecurity(OWNER, requested.dacl, False)

    assert windows_acl._dacl_for_set_security(current, requested) == _dacl(
        (0, 0x03, 0x001F01FF, OWNER),
    )


def test_unprotect_transition_supplies_complete_dacl_with_inherited_markers() -> None:
    requested = WindowsFileSecurity(
        OWNER,
        _dacl(
            (0, 0x03, 0x001F01FF, OWNER),
            (0, 0x10, 0x00020089, SYSTEM),
        ),
        False,
    )
    current = requested.staging_copy()

    assert current.dacl_protected is True
    assert windows_acl._dacl_for_set_security(current, requested) == requested.dacl


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows ACL inheritance")
def test_native_staged_file_round_trips_unprotected_security(tmp_path) -> None:
    parent = tmp_path / "inherited"
    parent.mkdir()
    original = parent / "original.yaml"
    original.write_bytes(b"original\n")
    requested = windows_acl.capture_path(str(original))
    assert requested.dacl_protected is False

    staged = parent / "staged.yaml"
    windows_acl.write_new_file(str(staged), b"restored\n", requested)
    protected = windows_acl.capture_path(str(staged))
    assert protected.dacl_protected is True

    windows_acl.apply_path(str(staged), requested)

    assert windows_acl.capture_path(str(staged)) == requested


def test_write_new_file_fails_closed_when_acl_changes_during_write(monkeypatch: pytest.MonkeyPatch) -> None:
    api = _FakeApi()
    api.change_after_write = True
    monkeypatch.setattr(windows_acl, "_api", api)

    with pytest.raises(WindowsAclError, match="changed while writing"):
        windows_acl.write_new_file("candidate.tmp", b"secret-payload", PRIVATE)


def test_write_new_file_preserves_mandatory_label_before_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _FakeApi()
    monkeypatch.setattr(windows_acl, "_api", api)
    requested = WindowsFileSecurity(
        PRIVATE.owner,
        PRIVATE.dacl,
        False,
        HIGH_MANDATORY_LABEL,
        True,
    )

    windows_acl.write_new_file("labeled.tmp", b"secret-payload", requested)

    staged = requested.staging_copy()
    assert ("create", staged) in api.events
    assert staged.mandatory_label == HIGH_MANDATORY_LABEL
    assert staged.sacl_protected is True
    assert api.security[api.paths["labeled.tmp"]] == staged


def test_mandatory_label_normalization_rejects_unrepresentable_sacl_data() -> None:
    assert windows_acl._normalize_mandatory_label_acl(HIGH_MANDATORY_LABEL) == HIGH_MANDATORY_LABEL
    assert windows_acl._normalize_mandatory_label_acl(struct.pack("<BBHHH", 2, 0, 8, 0, 0)) is None

    audit_acl = _dacl((2, 0, 0x00000001, OWNER))
    with pytest.raises(WindowsAclError, match="unsupported SACL data"):
        windows_acl._normalize_mandatory_label_acl(audit_acl)


def test_native_security_descriptor_includes_mandatory_label_and_protection() -> None:
    api = object.__new__(windows_acl._CtypesWindowsApi)
    api._initialize_security_descriptor = Mock(return_value=1)
    api._set_security_descriptor_owner = Mock(return_value=1)
    api._set_security_descriptor_dacl = Mock(return_value=1)
    api._set_security_descriptor_sacl = Mock(return_value=1)
    api._set_security_descriptor_control = Mock(return_value=1)
    labeled = WindowsFileSecurity(
        PRIVATE.owner,
        PRIVATE.dacl,
        True,
        HIGH_MANDATORY_LABEL,
        True,
    )

    _descriptor, _owner, _dacl_buffer, label_buffer = api._absolute_descriptor(labeled)

    assert label_buffer is not None
    api._set_security_descriptor_sacl.assert_called_once()
    _descriptor_pointer, control_mask, control_bits = api._set_security_descriptor_control.call_args.args
    assert control_mask == windows_acl._SE_DACL_PROTECTED | windows_acl._SE_SACL_PROTECTED
    assert control_bits == control_mask


def test_apply_path_verifies_owner_dacl_and_protection(monkeypatch: pytest.MonkeyPatch) -> None:
    api = _FakeApi()
    api.paths["config.yaml"] = 7
    api.security[7] = WindowsFileSecurity(OWNER, PRIVATE.dacl, False)
    monkeypatch.setattr(windows_acl, "_api", api)

    windows_acl.apply_path("config.yaml", PRIVATE)

    assert api.security[7] == PRIVATE
    assert ("set", PRIVATE) in api.events


def test_private_directory_acl_requests_object_and_container_inheritance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _FakeApi()
    api.paths["backups"] = 8
    api.security[8] = PRIVATE
    monkeypatch.setattr(windows_acl, "_api", api)

    assert windows_acl.private_security_for_directory("backups", inherit_children=True) == PRIVATE
    assert api.private_flags == [0x03]


def test_windows_directory_chain_stays_held_across_handle_mutations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _FakeApi()
    monkeypatch.setattr(windows_acl, "_api", api)
    monkeypatch.setattr(windows_acl.os, "name", "nt")

    with windows_acl.hold_directory_chain(r"C:\Users\operator\.defenseclaw"):
        outer_handles = [value for event, value in api.events if event == "lease-validate"]
        windows_acl.replace_regular_file_by_handle(
            r"C:\Users\operator\.defenseclaw\candidate.tmp",
            r"C:\Users\operator\.defenseclaw\config.yaml",
        )
        windows_acl.delete_regular_file_by_handle(
            r"C:\Users\operator\.defenseclaw\retired.yaml",
        )
        assert not any(event == "close" and value in outer_handles for event, value in api.events)

    opened = [value for event, value in api.events if event == "lease-open"]
    assert opened[:4] == [
        ("C:\\", False),
        (r"C:\Users", False),
        (r"C:\Users\operator", False),
        (r"C:\Users\operator\.defenseclaw", True),
    ]
    for nested_ancestors in (opened[4:7], opened[7:10]):
        assert tuple(ntpath.normcase(path) for path, _protect_name in nested_ancestors) == tuple(
            ntpath.normcase(path) for path, _protect_name in opened[:3]
        )
        assert all(not protect_name for _path, protect_name in nested_ancestors)
    replace_index = next(index for index, event in enumerate(api.events) if event[0] == "handle-replace")
    delete_index = next(index for index, event in enumerate(api.events) if event[0] == "handle-delete")
    outer_close_indexes = [
        index for index, event in enumerate(api.events) if event[0] == "close" and event[1] in outer_handles
    ]
    assert replace_index < outer_close_indexes[0]
    assert delete_index < outer_close_indexes[0]
    assert [api.events[index][1] for index in outer_close_indexes] == list(
        reversed(outer_handles),
    )


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        (
            r"C:\Users\operator\.defenseclaw",
            ("C:\\", r"C:\Users", r"C:\Users\operator", r"C:\Users\operator\.defenseclaw"),
        ),
        (
            r"\\server\share\state\bundle",
            (
                "\\\\server\\share\\",
                r"\\server\share\state",
                r"\\server\share\state\bundle",
            ),
        ),
        (
            r"\\?\UNC\server\share\state",
            ("\\\\?\\UNC\\server\\share\\", r"\\?\UNC\server\share\state"),
        ),
    ],
)
def test_windows_directory_prefixes_cover_drive_unc_and_extended_unc(
    path: str,
    expected: tuple[str, ...],
) -> None:
    assert windows_acl._windows_directory_prefixes(path) == expected


@pytest.mark.parametrize("path", [r"relative\state", r"C:relative\state", r"\rooted"])
def test_windows_directory_prefixes_reject_non_absolute_paths(path: str) -> None:
    with pytest.raises(WindowsAclError, match="absolute path"):
        windows_acl._windows_directory_prefixes(path)


def test_windows_rename_and_disposition_layouts_match_x86_and_x64_abi() -> None:
    pointer_size = ctypes.sizeof(ctypes.c_void_p)
    expected_root_offset = 8 if pointer_size == 8 else 4
    assert windows_acl._FileRenameInformation.root_directory.offset == expected_root_offset
    assert windows_acl._FileRenameInformation.file_name_length.offset == (expected_root_offset + pointer_size)
    assert windows_acl._FileRenameInformation.file_name.offset == (
        expected_root_offset + pointer_size + ctypes.sizeof(ctypes.c_uint32)
    )
    assert ctypes.sizeof(windows_acl._FileRenameInformation) > (windows_acl._FileRenameInformation.file_name.offset)
    assert ctypes.sizeof(ctypes.c_ubyte) == 1


def test_native_claim_reader_requests_delete_sharing() -> None:
    api = object.__new__(windows_acl._CtypesWindowsApi)
    create_file = Mock(return_value=73)
    api._create_file = create_file
    api._file_information = Mock(return_value=SimpleNamespace(file_attributes=windows_acl._FILE_ATTRIBUTE_NORMAL))
    api.close_handle = Mock()

    assert api._open_regular_reader_shared_delete(r"C:\state\created.claim") == 73

    create_file.assert_called_once_with(
        r"C:\state\created.claim",
        windows_acl._GENERIC_READ,
        (windows_acl._FILE_SHARE_READ | windows_acl._FILE_SHARE_WRITE | windows_acl._FILE_SHARE_DELETE),
        None,
        windows_acl._OPEN_EXISTING,
        windows_acl._FILE_FLAG_OPEN_REPARSE_POINT,
        None,
    )
    api.close_handle.assert_not_called()


def test_native_exclusive_mutator_denies_write_and_delete_sharing() -> None:
    api = object.__new__(windows_acl._CtypesWindowsApi)
    create_file = Mock(return_value=83)
    api._create_file = create_file
    api._file_information = Mock(return_value=SimpleNamespace(file_attributes=windows_acl._FILE_ATTRIBUTE_NORMAL))
    api.close_handle = Mock()

    assert api._open_regular_mutator_exclusive(r"C:\state\current.env") == 83

    create_file.assert_called_once_with(
        r"C:\state\current.env",
        windows_acl._GENERIC_READ | windows_acl._READ_CONTROL | windows_acl._DELETE,
        windows_acl._FILE_SHARE_READ,
        None,
        windows_acl._OPEN_EXISTING,
        windows_acl._FILE_FLAG_OPEN_REPARSE_POINT | windows_acl._FILE_FLAG_WRITE_THROUGH,
        None,
    )
    api.close_handle.assert_not_called()


def test_native_exclusive_security_mutator_has_exact_repair_and_flush_rights() -> None:
    api = object.__new__(windows_acl._CtypesWindowsApi)
    create_file = Mock(return_value=84)
    api._create_file = create_file
    api._file_information = Mock(return_value=SimpleNamespace(file_attributes=windows_acl._FILE_ATTRIBUTE_NORMAL))
    api.close_handle = Mock()

    assert api._open_regular_security_mutator_exclusive(r"C:\state\current.env") == 84

    create_file.assert_called_once_with(
        r"C:\state\current.env",
        (
            windows_acl._GENERIC_READ
            | windows_acl._GENERIC_WRITE
            | windows_acl._READ_CONTROL
            | windows_acl._WRITE_DAC
            | windows_acl._WRITE_OWNER
            | windows_acl._DELETE
        ),
        windows_acl._FILE_SHARE_READ,
        None,
        windows_acl._OPEN_EXISTING,
        windows_acl._FILE_FLAG_OPEN_REPARSE_POINT | windows_acl._FILE_FLAG_WRITE_THROUGH,
        None,
    )
    api.close_handle.assert_not_called()


@pytest.mark.parametrize(
    "attributes",
    [windows_acl._FILE_ATTRIBUTE_DIRECTORY, windows_acl._FILE_ATTRIBUTE_REPARSE_POINT],
)
def test_native_exclusive_file_rejects_non_regular_targets(attributes: int) -> None:
    api = object.__new__(windows_acl._CtypesWindowsApi)
    api._create_file = Mock(return_value=85)
    api._file_information = Mock(return_value=SimpleNamespace(file_attributes=attributes))
    api.close_handle = Mock()

    with pytest.raises(WindowsAclError, match="not a real regular file"):
        api.open_exclusive_file(r"C:\state\rollback-member")

    api.close_handle.assert_called_once_with(85)


def test_native_directory_name_lease_requests_delete_without_delete_sharing() -> None:
    api = object.__new__(windows_acl._CtypesWindowsApi)
    create_file = Mock(return_value=87)
    api._create_file = create_file

    assert api.open_directory_no_delete(r"C:\state", protect_name=True) == 87

    create_file.assert_called_once_with(
        r"C:\state",
        windows_acl._FILE_READ_ATTRIBUTES | windows_acl._DELETE,
        windows_acl._FILE_SHARE_READ | windows_acl._FILE_SHARE_WRITE,
        None,
        windows_acl._OPEN_EXISTING,
        windows_acl._FILE_FLAG_OPEN_REPARSE_POINT | windows_acl._FILE_FLAG_BACKUP_SEMANTICS,
        None,
    )


def test_native_directory_ancestor_lease_avoids_delete_access() -> None:
    api = object.__new__(windows_acl._CtypesWindowsApi)
    create_file = Mock(return_value=89)
    api._create_file = create_file

    assert api.open_directory_no_delete("C:\\", protect_name=False) == 89

    create_file.assert_called_once_with(
        "C:\\",
        windows_acl._FILE_READ_ATTRIBUTES,
        windows_acl._FILE_SHARE_READ | windows_acl._FILE_SHARE_WRITE,
        None,
        windows_acl._OPEN_EXISTING,
        windows_acl._FILE_FLAG_OPEN_REPARSE_POINT | windows_acl._FILE_FLAG_BACKUP_SEMANTICS,
        None,
    )


def test_native_handle_move_never_replaces_a_later_target() -> None:
    api = object.__new__(windows_acl._CtypesWindowsApi)
    set_information = Mock(return_value=1)
    api._set_file_information = set_information

    api.move_open_regular_file_no_replace(91, r"C:\state\restored.env")

    handle, info_class, buffer, size = set_information.call_args.args
    information = ctypes.cast(
        buffer,
        ctypes.POINTER(windows_acl._FileRenameInformation),
    ).contents
    assert handle == 91
    assert info_class == windows_acl._FILE_RENAME_INFO_CLASS
    assert size == len(buffer)
    assert information.replace_if_exists == 0


def test_native_handle_delete_marks_only_the_claimed_file() -> None:
    api = object.__new__(windows_acl._CtypesWindowsApi)
    set_information = Mock(return_value=1)
    api._set_file_information = set_information

    api.delete_open_regular_file(97)

    handle, info_class, pointer, size = set_information.call_args.args
    assert handle == 97
    assert info_class == windows_acl._FILE_DISPOSITION_INFO_CLASS
    assert ctypes.cast(pointer, ctypes.POINTER(ctypes.c_ubyte)).contents.value == 1
    assert size == ctypes.sizeof(ctypes.c_ubyte)


def test_native_move_no_replace_requests_write_through() -> None:
    api = object.__new__(windows_acl._CtypesWindowsApi)
    move_file_ex = Mock(return_value=1)
    api._move_file_ex = move_file_ex

    api.move_file_no_replace(r"C:\state\staged.env", r"C:\state\.env")

    move_file_ex.assert_called_once_with(
        r"C:\state\staged.env",
        r"C:\state\.env",
        windows_acl._MOVEFILE_WRITE_THROUGH,
    )


def test_flush_path_propagates_native_file_flush(monkeypatch: pytest.MonkeyPatch) -> None:
    api = _FakeApi()
    api.paths["published.env"] = 101
    monkeypatch.setattr(windows_acl, "_api", api)

    windows_acl.flush_path("published.env")

    assert api.events == [
        ("open", ("published.env", windows_acl._GENERIC_WRITE, False)),
        ("flush", 101),
        ("close", 101),
    ]


def test_shared_delete_claim_reader_closes_native_handle_when_crt_conversion_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _FakeApi()
    api._open_regular_reader_shared_delete = Mock(return_value=79)
    fake_msvcrt = SimpleNamespace(
        open_osfhandle=Mock(side_effect=OSError("conversion failed")),
    )
    monkeypatch.setattr(windows_acl, "_api", api)
    monkeypatch.setattr(windows_acl.os, "name", "nt")
    monkeypatch.setitem(sys.modules, "msvcrt", fake_msvcrt)

    with pytest.raises(OSError, match="conversion failed"):
        windows_acl.open_regular_read_fd_shared_delete(r"C:\state\created.claim")

    api._open_regular_reader_shared_delete.assert_called_once_with(r"C:\state\created.claim")
    assert ("close", 79) in api.events


def test_flush_descriptor_closes_native_handle_when_crt_conversion_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _FakeApi()
    api.open_exclusive_file = Mock(return_value=81)
    fake_msvcrt = SimpleNamespace(
        open_osfhandle=Mock(side_effect=OSError("conversion failed")),
    )
    monkeypatch.setattr(windows_acl, "_api", api)
    monkeypatch.setattr(windows_acl.os, "name", "nt")
    monkeypatch.setitem(sys.modules, "msvcrt", fake_msvcrt)

    with pytest.raises(OSError, match="conversion failed"):
        windows_acl.open_regular_flush_fd(r"C:\state\backup.yaml")

    api.open_exclusive_file.assert_called_once_with(r"C:\state\backup.yaml")
    assert ("close", 81) in api.events


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows flush semantics")
def test_native_flush_descriptor_preserves_raw_bytes(tmp_path) -> None:
    backup = tmp_path / "backup.yaml"
    payload = b"first: line\r\nsecond: line\r\n"
    backup.write_bytes(payload)

    descriptor = windows_acl.open_regular_flush_fd(str(backup))
    try:
        os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        assert os.read(descriptor, len(payload) + 1) == payload
    finally:
        os.close(descriptor)

    assert backup.read_bytes() == payload


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows share modes")
def test_native_shared_delete_claim_allows_exact_hardlink_disposition(tmp_path) -> None:
    claim = tmp_path / "created.claim"
    destination = tmp_path / "created.yaml"
    claim.write_bytes(b"target-created state\n")
    os.link(claim, destination)

    descriptor = windows_acl.open_regular_read_fd_shared_delete(str(claim))
    try:
        assert os.path.samestat(os.fstat(descriptor), destination.stat())
        windows_acl.delete_regular_file_by_handle(str(destination))
    finally:
        os.close(descriptor)

    assert not destination.exists()
    assert claim.read_bytes() == b"target-created state\n"


def test_handle_publication_refuses_cross_directory_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = _FakeApi()
    monkeypatch.setattr(windows_acl, "_api", api)

    with pytest.raises(WindowsAclError, match="one held directory"):
        windows_acl.replace_regular_file_by_handle(
            r"C:\state\.rollback-candidate",
            r"C:\outside\active.yaml",
        )
    assert not any(event == "handle-replace" for event, _value in api.events)


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows share modes")
def test_native_windows_directory_lease_and_handle_mutators(tmp_path) -> None:
    parent = tmp_path / "held"
    moved = tmp_path / "moved"
    parent.mkdir()
    source = parent / "candidate.tmp"
    target = parent / "active.yaml"
    retired = parent / "retired.yaml"
    source.write_bytes(b"restored\n")
    target.write_bytes(b"target\n")
    retired.write_bytes(b"retired\n")

    with windows_acl.hold_directory_chain(str(parent)):
        with pytest.raises(OSError):
            parent.rename(moved)
        windows_acl.replace_regular_file_by_handle(str(source), str(target))
        windows_acl.delete_regular_file_by_handle(str(retired))

    assert target.read_bytes() == b"restored\n"
    assert not source.exists()
    assert not retired.exists()
    parent.rename(moved)


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows share modes")
def test_native_windows_directory_name_lease_blocks_empty_directory_deletion(tmp_path) -> None:
    held = tmp_path / "empty-held"
    held.mkdir()

    with windows_acl.hold_directory_chain(str(held)):
        with pytest.raises(OSError):
            held.rmdir()

    held.rmdir()


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows share modes")
def test_native_windows_descendant_name_lease_blocks_ancestor_rename(tmp_path) -> None:
    ancestor = tmp_path / "ancestor"
    held = ancestor / "held"
    moved = tmp_path / "moved-ancestor"
    held.mkdir(parents=True)

    with windows_acl.hold_directory_chain(str(held)):
        with pytest.raises(OSError):
            ancestor.rename(moved)

    ancestor.rename(moved)


@pytest.mark.parametrize(
    "sid",
    [
        _sid(0, authority=1),
        _sid(11),
        USERS,
        _sid(32, 546),
    ],
)
def test_broad_write_grants_are_rejected(sid: bytes) -> None:
    security = WindowsFileSecurity(OWNER, _dacl((0, 0, 0x00000002, sid)), True)

    with pytest.raises(WindowsAclError, match="broad write"):
        windows_acl.assert_not_broadly_writable(security)


def test_broad_read_grant_is_rejected_for_secret_environment() -> None:
    security = WindowsFileSecurity(OWNER, _dacl((0, 0, 0x00000001, USERS)), True)

    with pytest.raises(WindowsAclError, match="broad read"):
        windows_acl.assert_not_broadly_readable(security)


def test_inherit_only_broad_ace_does_not_grant_access_to_current_file() -> None:
    security = WindowsFileSecurity(OWNER, _dacl((0, 0x08, 0x001F01FF, USERS)), True)

    windows_acl.assert_not_broadly_writable(security)
    windows_acl.assert_not_broadly_readable(security)


def test_unrepresentable_callback_ace_fails_closed() -> None:
    security = WindowsFileSecurity(OWNER, _dacl((9, 0, 0x00000001, OWNER)), True)

    with pytest.raises(WindowsAclError, match="unsupported ACE"):
        windows_acl.assert_not_broadly_readable(security)


def test_arbitrary_service_sid_is_not_implicitly_trusted(monkeypatch: pytest.MonkeyPatch) -> None:
    api = _FakeApi()
    monkeypatch.setattr(windows_acl, "_api", api)
    service_owned = WindowsFileSecurity(
        _sid(80, 111, 222, 333, 444, 555),
        PRIVATE.dacl,
        True,
    )

    with pytest.raises(WindowsAclError, match="owner is not a trusted"):
        windows_acl.assert_trusted_owner(service_owned)


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows handle inheritance")
def test_phase_two_mutator_lease_wraps_and_captures_real_child(tmp_path) -> None:
    lease = tmp_path / "phase-two-mutator.lease"
    windows_acl.ensure_phase_two_mutator_lease(str(lease))

    completed = windows_acl.run_phase_two_mutator(
        [sys.executable, "-c", "print('lease-child-ok')"],
        lease_path=str(lease),
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
        env=dict(os.environ),
    )

    assert completed.args[0] == sys.executable
    assert completed.stdout.strip() == "lease-child-ok"
    assert lease.stat().st_size == 0


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows share modes")
def test_phase_two_mutator_waits_for_existing_exclusive_lease(tmp_path) -> None:
    lease = tmp_path / "phase-two-mutator.lease"
    marker = tmp_path / "child-ran"
    windows_acl.ensure_phase_two_mutator_lease(str(lease))
    errors: list[BaseException] = []

    def run_child() -> None:
        try:
            windows_acl.run_phase_two_mutator(
                [sys.executable, "-c", f"from pathlib import Path; Path({str(marker)!r}).touch()"],
                lease_path=str(lease),
                check=True,
                timeout=30,
            )
        except BaseException as exc:  # pragma: no cover - relayed to the test thread
            errors.append(exc)

    with windows_acl.hold_phase_two_mutator_lease(str(lease)):
        worker = threading.Thread(target=run_child, daemon=True)
        worker.start()
        time.sleep(0.3)
        assert not marker.exists()
    worker.join(timeout=30)

    assert not worker.is_alive()
    assert errors == []
    assert marker.is_file()


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows handle inheritance")
def test_phase_two_mutator_reuses_recovery_held_lease_without_deadlock(tmp_path) -> None:
    lease = tmp_path / "phase-two-mutator.lease"
    windows_acl.ensure_phase_two_mutator_lease(str(lease))

    with windows_acl.hold_phase_two_mutator_lease(str(lease)) as held:
        completed = windows_acl.run_phase_two_mutator(
            [sys.executable, "-c", "raise SystemExit(0)"],
            lease_path=str(lease),
            held_lease=held,
            check=True,
            timeout=30,
        )

    assert completed.returncode == 0
