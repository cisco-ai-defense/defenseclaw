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

import os
import struct
import sys
import threading
import time

import defenseclaw.windows_acl as windows_acl
import pytest
from defenseclaw.windows_acl import WindowsAclError, WindowsFileSecurity


def _sid(*subauthorities: int, authority: int = 5) -> bytes:
    return bytes((1, len(subauthorities))) + authority.to_bytes(6, "big") + b"".join(
        struct.pack("<I", value) for value in subauthorities
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


def test_write_new_file_fails_closed_when_acl_changes_during_write(monkeypatch: pytest.MonkeyPatch) -> None:
    api = _FakeApi()
    api.change_after_write = True
    monkeypatch.setattr(windows_acl, "_api", api)

    with pytest.raises(WindowsAclError, match="changed while writing"):
        windows_acl.write_new_file("candidate.tmp", b"secret-payload", PRIVATE)


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
