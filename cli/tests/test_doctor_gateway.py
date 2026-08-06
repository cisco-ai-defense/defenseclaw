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

"""Cross-platform tests for Doctor's native gateway evidence collectors."""

from __future__ import annotations

import json
import os
import stat
from types import SimpleNamespace

import pytest
from defenseclaw import doctor_gateway, file_permissions


def test_gateway_executable_name_uses_target_platform_separators() -> None:
    assert (
        doctor_gateway.gateway_executable_name(
            r"C:\Program Files\DefenseClaw\defenseclaw-gateway.exe",
            platform_name="win32",
        )
        == "defenseclaw-gateway.exe"
    )
    assert (
        doctor_gateway.gateway_executable_name(
            r"/tmp/attacker\defenseclaw-gateway",
            platform_name="linux",
        )
        == r"attacker\defenseclaw-gateway"
    )


def test_read_pid_record_accepts_current_json_envelope(tmp_path):
    path = tmp_path / "gateway.pid"
    path.write_text(
        json.dumps(
            {
                "pid": 4242,
                "executable": "/opt/defenseclaw-gateway",
                "start_identity": "start-1",
                "start_time": 123,
                "data_dir": "/var/lib/defenseclaw",
            }
        ),
        encoding="utf-8",
    )

    record = doctor_gateway.read_pid_record(os.fspath(path))

    assert record.status == "ok"
    assert record.pid == 4242
    assert record.executable == "/opt/defenseclaw-gateway"
    assert record.start_identity == "start-1"
    assert record.start_time == "123"
    assert record.data_dir == "/var/lib/defenseclaw"


def test_read_pid_record_rejects_symlink_before_open(monkeypatch, tmp_path):
    path = tmp_path / "gateway.pid"
    path.write_text("4242", encoding="utf-8")
    monkeypatch.setattr(doctor_gateway, "is_symlink", lambda _path: True)
    monkeypatch.setattr(
        doctor_gateway.os,
        "open",
        lambda *_args, **_kwargs: pytest.fail("symlink PID record must not be opened"),
    )

    record = doctor_gateway.read_pid_record(os.fspath(path))

    assert record.status == "malformed"
    assert "symbolic link or reparse point" in record.reason


def test_read_pid_record_rejects_nonregular_path(tmp_path):
    path = tmp_path / "gateway.pid"
    path.mkdir()

    record = doctor_gateway.read_pid_record(os.fspath(path))

    assert record.status == "malformed"
    assert record.reason == "PID file is not a regular file"


@pytest.mark.parametrize(
    ("payload", "reason"),
    [
        (b"\xff\xfe", "PID file is not valid UTF-8"),
        (b"4" * 16_385, "PID file exceeds the inspection limit"),
    ],
)
def test_read_pid_record_rejects_unsafe_bytes(tmp_path, payload, reason):
    path = tmp_path / "gateway.pid"
    path.write_bytes(payload)

    record = doctor_gateway.read_pid_record(os.fspath(path))

    assert record.status == "malformed"
    assert record.reason == reason


@pytest.mark.parametrize("field", ["executable", "data_dir"])
def test_read_pid_record_rejects_nul_path_fields(tmp_path, field):
    path = tmp_path / "gateway.pid"
    path.write_text(
        json.dumps({"pid": 4242, field: "trusted\u0000suffix"}),
        encoding="utf-8",
    )

    record = doctor_gateway.read_pid_record(os.fspath(path))

    assert record.status == "malformed"
    assert record.reason == "PID file contains an invalid path field"


@pytest.mark.parametrize(
    "pid",
    [
        True,
        42.5,
        doctor_gateway.MAX_PLATFORM_PID + 1,
    ],
)
def test_read_pid_record_rejects_noncanonical_json_pid(tmp_path, pid):
    path = tmp_path / "gateway.pid"
    path.write_text(json.dumps({"pid": pid}), encoding="utf-8")

    record = doctor_gateway.read_pid_record(os.fspath(path))

    assert record.status == "malformed"
    assert "PID file" in record.reason


def test_pid_file_fingerprint_changes_with_content(tmp_path):
    path = tmp_path / "gateway.pid"
    path.write_bytes(b"4242")
    before = doctor_gateway.pid_file_fingerprint(os.fspath(path))

    path.write_bytes(b"4343")
    after = doctor_gateway.pid_file_fingerprint(os.fspath(path))

    assert before is not None
    assert before[-1] == b"4242"
    assert after is not None
    assert after[-1] == b"4343"
    assert after != before


def test_pid_file_fingerprint_from_fd_rejects_windows_reparse_points(monkeypatch):
    info = SimpleNamespace(
        st_mode=stat.S_IFREG | 0o600,
        st_size=4,
        st_file_attributes=0x400,
    )
    monkeypatch.setattr(doctor_gateway.os, "fstat", lambda _fd: info)

    assert doctor_gateway.pid_file_fingerprint_from_fd(123) is None


def test_pid_file_fingerprint_from_fd_rejects_premature_eof(monkeypatch, tmp_path):
    path = tmp_path / "gateway.pid"
    path.write_bytes(b"4242")
    fd = os.open(path, os.O_RDONLY)
    real_read = os.read
    reads = 0

    def short_read(read_fd, count):
        nonlocal reads
        reads += 1
        if reads > 1:
            return b""
        return real_read(read_fd, min(count, 1))

    monkeypatch.setattr(doctor_gateway.os, "read", short_read)
    try:
        assert doctor_gateway.pid_file_fingerprint_from_fd(fd) is None
    finally:
        os.close(fd)


@pytest.mark.parametrize("unsafe_kind", ["symlink", "nonregular", "oversized"])
def test_pid_file_fingerprint_rejects_unsafe_sources(monkeypatch, tmp_path, unsafe_kind):
    path = tmp_path / "gateway.pid"
    if unsafe_kind == "nonregular":
        path.mkdir()
    elif unsafe_kind == "oversized":
        path.write_bytes(b"x" * 16_385)
    else:
        path.write_text("4242", encoding="utf-8")
        monkeypatch.setattr(doctor_gateway, "is_symlink", lambda _path: True)

    assert doctor_gateway.pid_file_fingerprint(os.fspath(path)) is None


def test_pid_file_fingerprint_rejects_path_replacement(monkeypatch, tmp_path):
    path = tmp_path / "gateway.pid"
    replacement = tmp_path / "replacement.pid"
    path.write_bytes(b"4242")
    replacement.write_bytes(b"4343")
    real_open = os.open

    def replace_before_open(open_path, flags, *args, **kwargs):
        os.replace(replacement, path)
        return real_open(open_path, flags, *args, **kwargs)

    monkeypatch.setattr(doctor_gateway.os, "open", replace_before_open)

    assert doctor_gateway.pid_file_fingerprint(os.fspath(path)) is None


def test_read_pid_record_rejects_a_b_a_path_replacement(monkeypatch, tmp_path):
    path = tmp_path / "gateway.pid"
    original = tmp_path / "original.pid"
    replacement = tmp_path / "replacement.pid"
    path.write_bytes(b"4242")
    replacement.write_bytes(b"4343")
    real_read = doctor_gateway.read_regular_file_no_follow

    def swap_around_read(read_path, *, max_bytes, expected_stat=None):
        os.replace(path, original)
        os.replace(replacement, path)
        try:
            return real_read(
                read_path,
                max_bytes=max_bytes,
                expected_stat=expected_stat,
            )
        finally:
            os.replace(path, replacement)
            os.replace(original, path)

    monkeypatch.setattr(
        doctor_gateway,
        "read_regular_file_no_follow",
        swap_around_read,
    )

    record = doctor_gateway.read_pid_record(os.fspath(path))

    assert record.status == "unavailable"
    assert record.pid == 0
    assert path.read_bytes() == b"4242"


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory-mode regression")
def test_pid_readers_reject_writable_parent_directory(tmp_path):
    parent = tmp_path / "unsafe"
    parent.mkdir()
    path = parent / "gateway.pid"
    path.write_text("4242", encoding="utf-8")
    os.chmod(path, 0o600)
    os.chmod(parent, 0o777)
    try:
        record = doctor_gateway.read_pid_record(os.fspath(path))

        # A group/world-writable ancestor is positively-observed untrusted
        # custody, so the record is refused as "denied". It is explicitly not
        # "malformed": the bytes on disk parse fine, and telling an operator
        # their PID file is corrupt would send them to the wrong repair.
        assert record.status == "denied"
        assert "ancestor directory is writable" in record.reason
        assert doctor_gateway.pid_file_fingerprint(os.fspath(path)) is None
    finally:
        os.chmod(parent, 0o700)


@pytest.mark.skipif(os.name == "nt", reason="/proc fixture uses POSIX symlinks")
def test_linux_process_evidence_reads_executable_and_start_identity(tmp_path):
    pid = 4242
    process_root = tmp_path / str(pid)
    process_root.mkdir()
    (process_root / "exe").symlink_to("/opt/defenseclaw-gateway")
    fields = ["S", *[str(index) for index in range(4, 23)]]
    fields[19] = "987654"
    (process_root / "stat").write_text(
        f"{pid} (gateway worker) {' '.join(fields)}\n",
        encoding="utf-8",
    )

    evidence = doctor_gateway._linux_process_evidence(
        pid,
        proc_root=os.fspath(tmp_path),
    )

    assert evidence.status == "ok"
    assert evidence.pid == pid
    assert evidence.executable == "/opt/defenseclaw-gateway"
    assert evidence.start_identity == "987654"


def test_darwin_process_evidence_uses_native_full_path_and_microsecond_identity(monkeypatch):
    pid = 4242
    monkeypatch.setattr(
        doctor_gateway,
        "_darwin_native_process_identity",
        lambda inspected_pid: (
            (
                "/opt/DefenseClaw/defenseclaw-gateway",
                "1785373323.123456",
            )
            if inspected_pid == pid
            else (_ for _ in ()).throw(ProcessLookupError(inspected_pid))
        ),
    )

    evidence = doctor_gateway._darwin_process_evidence(pid)

    assert evidence.status == "ok"
    assert evidence.executable == "/opt/DefenseClaw/defenseclaw-gateway"
    assert evidence.start_identity == "1785373323.123456"


@pytest.mark.parametrize(
    ("local_address", "target_host", "expected"),
    [
        ("127.0.0.1", "127.0.0.1", True),
        ("0.0.0.0", "127.0.0.1", True),
        ("::", "127.0.0.1", False),
        ("::1", "::1", True),
        ("::", "::1", True),
        ("0.0.0.0", "::1", False),
        ("127.0.0.1", "localhost", True),
        ("::1", "localhost", True),
        ("0.0.0.0", "localhost", True),
        ("::", "localhost", True),
        ("192.0.2.10", "localhost", False),
        ("not-an-address", "127.0.0.1", False),
        ("127.0.0.1", "not-an-address", False),
        ("not-an-address", "", True),
    ],
)
def test_listener_address_matching_is_address_family_aware(
    local_address,
    target_host,
    expected,
):
    assert doctor_gateway._listener_address_matches(local_address, target_host) is expected


def test_pid_record_maps_reader_codes_not_message_text(monkeypatch, tmp_path) -> None:
    """Doctor must classify reader refusals by stable code, not by prose.

    These statuses gate which lifecycle repairs are allowed to run, so the
    mapping is pinned against a deliberately misleading message: an error whose
    text says "exceeds" while its code says the object changed must be reported
    as ``unavailable``, not as a malformed size violation.
    """
    path = tmp_path / "gateway.pid"
    path.write_text("4242", encoding="utf-8")
    os.chmod(path, 0o600)

    cases = [
        (file_permissions.UNSAFE_PATH_EXCEEDS_LIMIT, "malformed", "exceeds the inspection limit"),
        (file_permissions.UNSAFE_PATH_NOT_REGULAR_FILE, "malformed", "not a regular file"),
        (file_permissions.UNSAFE_PATH_SYMLINK_OR_REPARSE, "malformed", "symbolic link or reparse point"),
        (file_permissions.UNSAFE_PATH_CHANGED, "unavailable", "changed while it was being inspected"),
        (file_permissions.UNSAFE_PATH_UNTRUSTED_CUSTODY, "denied", "custody is not trusted"),
        (file_permissions.UNSAFE_PATH_INSPECTION_FAILED, "unavailable", "could not be inspected"),
    ]
    for code, expected_status, expected_reason in cases:
        def refuse(*_args, _code=code, **_kwargs):
            # The message intentionally contradicts the code.
            raise file_permissions.UnsafePathError(
                "sensitive file exceeds a symlink non-file limit",
                code=_code,
            )

        monkeypatch.setattr(doctor_gateway, "read_regular_file_no_follow", refuse)
        record = doctor_gateway.read_pid_record(os.fspath(path))
        assert record.status == expected_status, code
        assert expected_reason in record.reason, code
        assert record.pid == 0


def test_pid_record_unknown_reader_code_fails_closed_as_unavailable(monkeypatch, tmp_path) -> None:
    """An unrecognized refusal must not be reported as a content verdict."""
    path = tmp_path / "gateway.pid"
    path.write_text("4242", encoding="utf-8")
    os.chmod(path, 0o600)

    def refuse(*_args, **_kwargs):
        raise file_permissions.UnsafePathError("brand new refusal", code="unsafe-path-future")

    monkeypatch.setattr(doctor_gateway, "read_regular_file_no_follow", refuse)
    record = doctor_gateway.read_pid_record(os.fspath(path))

    assert record.status == "unavailable"
    assert "could not be safely inspected" in record.reason


@pytest.mark.skipif(os.name == "nt", reason="POSIX ancestor-custody classification")
def test_pid_record_unverifiable_ancestor_is_unavailable_not_malformed(monkeypatch, tmp_path) -> None:
    """A UID-mapped or unstattable ancestor is unproven custody, not corruption.

    Network homes and bind-mounted containers routinely present an ancestor
    owned by neither root nor the current user. Reporting that as ``malformed``
    told operators their PID file was corrupt and sent them to the wrong fix.
    """
    path = tmp_path / "gateway.pid"
    path.write_text("4242", encoding="utf-8")
    os.chmod(path, 0o600)

    real_lstat = os.lstat
    foreign_dir = os.fspath(tmp_path)

    def lstat_with_foreign_ancestor(target, *args, **kwargs):
        info = real_lstat(target, *args, **kwargs)
        if os.fspath(target) == foreign_dir:
            fields = list(info)
            fields[stat.ST_UID] = info.st_uid + 4242
            return os.stat_result(fields)
        return info

    monkeypatch.setattr(doctor_gateway.os, "lstat", lstat_with_foreign_ancestor)
    record = doctor_gateway.read_pid_record(os.fspath(path))

    assert record.status == "unavailable"
    assert "not owned by a trusted principal" in record.reason
    assert record.pid == 0
