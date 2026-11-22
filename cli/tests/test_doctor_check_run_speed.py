# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""A doctor check run does no step twice and walks the audit store early (rel-1-0-10:GAP-0938).

doctor p50 was 4.35 s on a host with a 590 MiB audit store: the store walk ran
inline (1.8 s) and the repair preflight ran the Go validator a second time on
the config.yaml the configuration check had just validated (0.34 s).
"""

from __future__ import annotations

import errno
import json
import os
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest
from click.testing import CliRunner
from defenseclaw import doctor_recovery as recovery
from defenseclaw.commands import cmd_doctor
from defenseclaw.context import AppContext
from defenseclaw.doctor_recovery import AuditDBHealth, AuditDBHealthStatus

_KEPT = {"_check_config", "_check_audit_db", "_check_audit_db_store"}


def _valid_health() -> AuditDBHealth:
    return AuditDBHealth(AuditDBHealthStatus.VALID, "audit-db-valid", integrity_scanned=True, file_bytes=4096)


def _cfg(tmp_path: Path):
    (tmp_path / "config.yaml").write_text("config_version: 8\n", encoding="utf-8")
    cfg = mock.MagicMock()
    cfg.data_dir = str(tmp_path)
    cfg.audit_db = str(tmp_path / "audit.db")
    return cfg


def _run_doctor(cfg, args, *, stubs=None, inspect=None, validate=None):
    """Drive the doctor command with every check but config and audit store stubbed."""
    patched = {
        name: mock.MagicMock(return_value=None)
        for name in dir(cmd_doctor)
        if name.startswith("_check_") and name not in _KEPT and callable(getattr(cmd_doctor, name))
    }
    patched["_check_windows_gateway_diagnostics"] = mock.MagicMock(return_value=True)
    patched.update(stubs or {})
    app = AppContext()
    app.cfg = cfg
    recorder = mock.MagicMock()
    patches = [mock.patch.object(cmd_doctor, name, stub) for name, stub in patched.items()]
    patches += [
        mock.patch.object(cmd_doctor, "_doctor_config_present", return_value=True),
        mock.patch("defenseclaw.config_writer.managed_leftover_config", return_value=None),
        mock.patch.object(cmd_doctor, "_prefetch_sandbox_report", return_value=(None, None)),
        mock.patch.object(cmd_doctor, "_write_doctor_cache", return_value=None),
        mock.patch.object(cmd_doctor, "_run_fixers_with_lock", return_value=None),
        # doctor --json sets this module global; later tests read it.
        mock.patch.object(cmd_doctor, "_json_mode", cmd_doctor._json_mode),
        mock.patch("defenseclaw.logger.Logger", recorder),
        mock.patch("defenseclaw.doctor_recovery.inspect_audit_db", inspect or (lambda *_a, **_k: _valid_health())),
        mock.patch("defenseclaw.config_inspect.inspect_v8_config", validate),
    ]
    for patcher in patches:
        patcher.start()
    try:
        result = CliRunner().invoke(cmd_doctor.doctor, args, obj=app)
    finally:
        for patcher in reversed(patches):
            patcher.stop()
    start = result.output.find("{")
    assert start >= 0, (result.output, result.exception)
    return json.loads(result.output[start:]), recorder


class _Validator:
    def __init__(self, valid=True):
        self.calls = 0
        self.valid = valid

    def __call__(self, operation, *, config_path, **_kwargs):
        assert operation == "validate"
        self.calls += 1
        return SimpleNamespace(valid=self.valid, warnings=[])


def test_a_check_run_validates_config_yaml_once(tmp_path):
    # The canonical action fact needs the repair preflight; it reuses the
    # positive decision of the configuration check for the same bytes.
    validator = _Validator()
    payload, recorder = _run_doctor(_cfg(tmp_path), ["--json"], validate=validator)

    rows = [c for c in payload["checks"] if c["label"] == "Config file"]
    assert [row["status"] for row in rows] == ["pass"], payload["checks"]
    assert recorder.call_count == 1, "the action fact was not recorded: the preflight did not plan a noop"
    assert validator.calls == 1


def test_the_reused_decision_ends_with_the_run(tmp_path):
    validator = _Validator()
    cfg = _cfg(tmp_path)
    _run_doctor(cfg, ["--json"], validate=validator)
    with mock.patch("defenseclaw.config_inspect.inspect_v8_config", validator):
        assert cmd_doctor._plan_canonical_config_preflight(cfg).state == "noop"
    assert validator.calls == 2


def test_a_changed_or_rejected_config_is_validated_again(tmp_path):
    cfg = _cfg(tmp_path)
    validator = _Validator()
    with mock.patch("defenseclaw.config_inspect.inspect_v8_config", validator):
        cmd_doctor._begin_config_validation_run()
        try:
            cmd_doctor._check_config(cfg, cmd_doctor._DoctorResult())
            assert cmd_doctor._plan_canonical_config_preflight(cfg).state == "noop"
            assert validator.calls == 1
            # Same size, other bytes, mtime kept: the digest still differs.
            path = tmp_path / "config.yaml"
            stamp = path.stat()
            path.write_text("config_version: 9\n", encoding="utf-8")
            os.utime(path, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
            validator.valid = False
            assert cmd_doctor._plan_canonical_config_preflight(cfg).state == "blocked"
            assert validator.calls == 2
        finally:
            cmd_doctor._end_config_validation_run()

    rejected = _Validator(valid=False)
    with mock.patch("defenseclaw.config_inspect.inspect_v8_config", rejected):
        cmd_doctor._begin_config_validation_run()
        try:
            cmd_doctor._check_config(cfg, cmd_doctor._DoctorResult())
            cmd_doctor._plan_canonical_config_preflight(cfg)
        finally:
            cmd_doctor._end_config_validation_run()
    assert rejected.calls == 2


def test_a_repair_run_validates_again_after_its_repairs(tmp_path):
    validator = _Validator()
    _payload, recorder = _run_doctor(_cfg(tmp_path), ["--fix", "--yes", "--json"], validate=validator)
    assert recorder.call_count == 1
    assert validator.calls == 2


def _audit_spy():
    started = threading.Event()
    seen: list[bool] = []

    def inspect(*_args, **_kwargs):
        seen.append(threading.current_thread() is threading.main_thread())
        started.set()
        return _valid_health()

    return started, seen, inspect


def test_a_check_run_walks_the_audit_store_while_the_config_check_runs(tmp_path):
    started, on_main, inspect = _audit_spy()
    during: list[bool] = []

    def check_config(_cfg, _r):
        during.append(started.wait(5))

    payload, _ = _run_doctor(
        _cfg(tmp_path), ["--json"], stubs={"_check_config": check_config}, inspect=inspect, validate=_Validator()
    )

    assert during == [True], "the audit store walk did not start before the config check returned"
    assert on_main == [False]
    rows = [c for c in payload["checks"] if c["label"] == "Audit database"]
    assert [row["status"] for row in rows] == ["pass"], payload["checks"]


def test_a_repair_run_walks_the_audit_store_inline_after_the_config_check(tmp_path):
    started, on_main, inspect = _audit_spy()
    during: list[bool] = []

    def check_config(_cfg, _r):
        during.append(started.is_set())

    payload, _ = _run_doctor(
        _cfg(tmp_path),
        ["--fix", "--yes", "--json"],
        stubs={"_check_config": check_config},
        inspect=inspect,
        validate=_Validator(),
    )

    assert during == [False]
    assert on_main == [True]
    rows = [c for c in payload["checks"] if c["label"] == "Audit database"]
    assert [row["status"] for row in rows] == ["pass"], payload["checks"]


def test_an_error_in_the_audit_walk_is_raised_at_the_audit_row(tmp_path):
    def inspect(*_args, **_kwargs):
        raise RuntimeError("boom")

    pool, probe = None, None
    with mock.patch("defenseclaw.doctor_recovery.inspect_audit_db", inspect):
        cfg = _cfg(tmp_path)
        pool, probe = cmd_doctor._prefetch_audit_db_health(cfg)
        try:
            with pytest.raises(RuntimeError, match="boom"):
                cmd_doctor._check_audit_db_store(cfg, cmd_doctor._DoctorResult(), prefetched=probe)
        finally:
            pool.shutdown(wait=True)


linux_only = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="sendfile prefetch is Linux only")


def _file(tmp_path: Path, size: int) -> Path:
    path = tmp_path / "audit.db"
    path.write_bytes(os.urandom(size))
    return path


@linux_only
def test_the_prefetch_reads_through_sendfile_on_linux(tmp_path, monkeypatch):
    path = _file(tmp_path, 3 * recovery._AUDIT_PREFETCH_CHUNK_BYTES + 5)
    real = os.sendfile
    sent: list[int] = []

    def spy(out, fd, offset, count):
        n = real(out, fd, offset, count)
        sent.append(n)
        return n

    monkeypatch.setattr(os, "sendfile", spy)
    assert recovery._prefetch_audit_db(path, time.monotonic() + 60) is True
    assert sum(sent) == path.stat().st_size
    assert sent[-1] == 0


@linux_only
def test_the_sendfile_prefetch_stops_at_the_deadline(tmp_path, monkeypatch):
    path = _file(tmp_path, 3 * recovery._AUDIT_PREFETCH_CHUNK_BYTES)
    calls: list[int] = []
    real = os.sendfile

    def spy(out, fd, offset, count):
        calls.append(offset)
        return real(out, fd, offset, count)

    monkeypatch.setattr(os, "sendfile", spy)
    assert recovery._prefetch_audit_db(path, time.monotonic() - 1) is False
    assert calls == [0]


@linux_only
def test_a_sendfile_read_error_lets_the_walk_report_it(tmp_path, monkeypatch):
    path = _file(tmp_path, 1024)

    def broken(*_args):
        raise OSError(errno.EIO, "Input/output error")

    monkeypatch.setattr(os, "sendfile", broken)
    assert recovery._prefetch_audit_db(path, time.monotonic() + 60) is True


@linux_only
def test_a_file_system_without_sendfile_falls_back_to_a_buffered_read(tmp_path, monkeypatch):
    path = _file(tmp_path, 2 * recovery._AUDIT_PREFETCH_CHUNK_BYTES)
    real = os.sendfile
    offsets: list[int] = []

    def half(out, fd, offset, count):
        offsets.append(offset)
        if offset:
            raise OSError(errno.EINVAL, "Invalid argument")
        return real(out, fd, offset, count)

    monkeypatch.setattr(os, "sendfile", half)
    assert recovery._prefetch_audit_db(path, time.monotonic() + 60) is True
    assert offsets == [0, recovery._AUDIT_PREFETCH_CHUNK_BYTES]
    # The buffered read resumes at the offset and still honours the deadline.
    offsets.clear()
    assert recovery._prefetch_audit_db(path, time.monotonic() - 1) is False
    assert offsets == [0]


def test_other_platforms_use_the_buffered_read(tmp_path, monkeypatch):
    path = _file(tmp_path, 1024)
    monkeypatch.setattr(recovery.sys, "platform", "darwin")
    monkeypatch.setattr(os, "sendfile", mock.Mock(side_effect=AssertionError("no sendfile here")), raising=False)
    assert recovery._prefetch_audit_db(path, time.monotonic() + 60) is True
    assert recovery._prefetch_audit_db(path, time.monotonic() - 1) is False
