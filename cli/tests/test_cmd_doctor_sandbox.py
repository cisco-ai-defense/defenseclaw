# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""``defenseclaw doctor``'s Sandbox section (``defenseclaw-gateway sandbox doctor --json``)."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest
from defenseclaw.commands import cmd_doctor
from defenseclaw.commands.cmd_doctor import _check_sandbox, _DoctorResult

pytestmark = pytest.mark.skipif(os.name == "nt", reason="the fake gateway is a POSIX shell script")

REPORT = {
    "ok": False,
    "checks": [
        {"id": "platform", "title": "Platform", "status": "pass", "detail": "linux/arm64"},
        {
            "id": "openshell-cli",
            "title": "OpenShell CLI",
            "status": "fail",
            "detail": "openshell is not installed",
            "fix": {
                "summary": "install OpenShell",
                "command": "defenseclaw sandbox setup --install-openshell",
                "sudo": True,
                "automatic": False,
            },
        },
        {
            "id": "overlay-images",
            "title": "Harness images",
            "status": "warn",
            "detail": "not built yet: codex",
            "fix": {
                "summary": "build the images now",
                "command": "defenseclaw sandbox image build codex",
                "automatic": True,
            },
        },
        {"id": "shell-wrappers", "title": "Shell wrappers", "status": "skip", "detail": "no home"},
        {"id": "odd", "title": "Odd", "status": "bogus", "detail": "unknown status"},
    ],
}


def _gateway(tmp_path: Path, stdout: str, *, stderr: str = "", code: int = 0) -> str:
    out = tmp_path / "out.json"
    out.write_text(stdout, encoding="utf-8")
    err = tmp_path / "err.txt"
    err.write_text(stderr, encoding="utf-8")
    argv_log = tmp_path / "argv.txt"
    script = tmp_path / "defenseclaw-gateway"
    script.write_text(
        f'#!/bin/sh\nprintf "%s\\n" "$@" > "{argv_log}"\ncat "{out}"\ncat "{err}" >&2\nexit {code}\n',
        encoding="utf-8",
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return str(script)


def _cfg(enabled: bool) -> SimpleNamespace:
    return SimpleNamespace(openshell=SimpleNamespace(enabled=enabled))


@pytest.fixture(autouse=True)
def _linux(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr("defenseclaw.platform_support.host_os", lambda: "linux")
    monkeypatch.setattr(cmd_doctor, "_json_mode", False)


def _rows(result: _DoctorResult) -> list[tuple[str, str, str]]:
    return [(row["status"], row["label"], row["check_id"]) for row in result.checks]


def test_disabled_sandboxes_are_one_skip_row_without_running_the_gateway(monkeypatch) -> None:
    monkeypatch.setattr("defenseclaw.gateway.resolve_gateway_binary", lambda: pytest.fail("gateway resolved"))
    result = _DoctorResult()
    result.set_section("sandbox")
    _check_sandbox(_cfg(False), result)
    assert _rows(result) == [("skip", "Sandboxes", "doctor.sandbox.enabled")]
    assert "defenseclaw sandbox setup" in result.checks[0]["detail"]


def test_a_stand_in_config_never_reads_as_enabled(monkeypatch) -> None:
    from unittest.mock import MagicMock

    monkeypatch.setattr("defenseclaw.gateway.resolve_gateway_binary", lambda: pytest.fail("gateway resolved"))
    result = _DoctorResult()
    _check_sandbox(MagicMock(), result)
    assert result.checks[0]["status"] == "skip"


def test_windows_reports_the_platform_limit(monkeypatch) -> None:
    monkeypatch.setattr("defenseclaw.platform_support.host_os", lambda: "windows")
    result = _DoctorResult()
    _check_sandbox(_cfg(True), result)
    assert _rows(result) == [("warn", "Sandboxes", "doctor.sandbox.platform")]
    assert "Linux and macOS only" in result.checks[0]["detail"]


def test_a_missing_gateway_fails_with_the_upgrade_hint(monkeypatch) -> None:
    monkeypatch.setattr("defenseclaw.gateway.resolve_gateway_binary", lambda: None)
    result = _DoctorResult()
    _check_sandbox(_cfg(True), result)
    assert result.failed == 1
    assert "defenseclaw upgrade" in result.checks[0]["remediation"]


def test_each_go_check_becomes_one_row(tmp_path: Path, monkeypatch, capsys) -> None:
    binary = _gateway(tmp_path, json.dumps(REPORT))
    monkeypatch.setattr("defenseclaw.gateway.resolve_gateway_binary", lambda: binary)
    result = _DoctorResult()
    result.set_section("sandbox")
    _check_sandbox(_cfg(True), result)

    assert (tmp_path / "argv.txt").read_text().split() == ["sandbox", "doctor", "--json"]
    assert _rows(result) == [
        ("pass", "Platform", "doctor.sandbox.platform"),
        ("fail", "OpenShell CLI", "doctor.sandbox.openshell-cli"),
        ("warn", "Harness images", "doctor.sandbox.overlay-images"),
        ("skip", "Shell wrappers", "doctor.sandbox.shell-wrappers"),
        ("warn", "Odd", "doctor.sandbox.odd"),
    ]
    assert (result.passed, result.failed, result.warned, result.skipped) == (1, 1, 2, 1)
    cli_row = result.checks[1]
    assert cli_row["section"] == "sandbox"
    assert cli_row["remediation"] == "install OpenShell: defenseclaw sandbox setup --install-openshell"
    assert result.checks[2]["remediation"].endswith("(or 'defenseclaw sandbox doctor --fix')")
    assert result.checks[0]["remediation"] == ""
    printed = capsys.readouterr().out
    assert "OpenShell CLI" in printed and "install OpenShell" in printed


def test_json_mode_prints_nothing(tmp_path: Path, monkeypatch, capsys) -> None:
    binary = _gateway(tmp_path, json.dumps(REPORT))
    monkeypatch.setattr("defenseclaw.gateway.resolve_gateway_binary", lambda: binary)
    monkeypatch.setattr(cmd_doctor, "_json_mode", True)
    result = _DoctorResult()
    _check_sandbox(_cfg(True), result)
    assert len(result.checks) == 5
    assert capsys.readouterr().out == ""


def test_a_gateway_without_a_report_is_a_warning_with_its_error(tmp_path: Path, monkeypatch) -> None:
    binary = _gateway(tmp_path, "", stderr="✗ failed to load config: permission denied\nmore\n", code=1)
    monkeypatch.setattr("defenseclaw.gateway.resolve_gateway_binary", lambda: binary)
    result = _DoctorResult()
    _check_sandbox(_cfg(True), result)
    assert _rows(result) == [("warn", "Sandbox doctor", "doctor.sandbox.report")]
    assert result.checks[0]["detail"] == "failed to load config: permission denied"


def test_an_old_gateway_is_named_as_such(tmp_path: Path, monkeypatch) -> None:
    binary = _gateway(tmp_path, "not json", code=2)
    monkeypatch.setattr("defenseclaw.gateway.resolve_gateway_binary", lambda: binary)
    result = _DoctorResult()
    _check_sandbox(_cfg(True), result)
    assert "predate OpenShell 0.1" in result.checks[0]["detail"]


def test_a_hung_gateway_times_out(tmp_path: Path, monkeypatch) -> None:
    import subprocess

    def slow(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(cmd="defenseclaw-gateway", timeout=1)

    monkeypatch.setattr("defenseclaw.gateway.resolve_gateway_binary", lambda: "/bin/true")
    monkeypatch.setattr(cmd_doctor.subprocess, "run", slow)
    result = _DoctorResult()
    _check_sandbox(_cfg(True), result)
    assert "did not finish" in result.checks[0]["detail"]



def test_unused_sandbox_keeps_gateway_install_and_registration_failures() -> None:
    for detail in (
        "OpenShell 0.1.0 is older than 0.1.1; upgrade it in place",
        "the gateway refused DefenseClaw's TLS credentials: certificate mismatch",
    ):
        rows = cmd_doctor._sandbox_checks_by_root_cause([
            {"id": "gateway-version", "status": "fail", "detail": detail},
            {"id": "overlay-images", "status": "warn", "detail": "not built yet: codex"},
            {"id": "sandbox-hooks", "status": "pass", "detail": "no sandbox is running"},
        ])
        assert rows[0]["status"] == "fail"
        assert rows[0]["detail"] == detail

def test_a_stopped_gateway_is_one_root_cause_and_unused_sandboxes_only_warn(tmp_path: Path, monkeypatch) -> None:
    down = "the gateway is not answering"
    report = {
        "checks": [
            {"id": "docker", "title": "Docker", "status": "fail", "detail": "the Docker daemon is not reachable"},
            {"id": "gateway-service", "title": "Gateway service", "status": "fail", "detail": "not installed"},
            {"id": "gateway-version", "title": "Gateway", "status": "fail", "detail": f"{down}: refused"},
            {"id": "gateway-driver", "title": "Gateway compute driver", "status": "skip", "detail": down},
            {
                "id": "defenseclaw-daemon",
                "title": "DefenseClaw daemon",
                "status": "fail",
                "detail": "running, but sandboxes are unavailable: the OpenShell gateway is not available",
            },
            {"id": "overlay-images", "title": "Harness images", "status": "warn", "detail": "not built yet: codex"},
        ]
    }
    binary = _gateway(tmp_path, json.dumps(report))
    monkeypatch.setattr("defenseclaw.gateway.resolve_gateway_binary", lambda: binary)
    result = _DoctorResult()
    _check_sandbox(_cfg(True), result)
    status = {row["label"]: row["status"] for row in result.checks}
    assert status == {
        "Docker": "warn",
        "Gateway service": "skip",
        "Gateway": "warn",
        "Gateway compute driver": "skip",
        "DefenseClaw daemon": "skip",
        "Harness images": "warn",
    }
    assert result.checks[4]["detail"].startswith("depends on: OpenShell gateway")
    assert result.failed == 0


def test_local_policy_digest_refuses_untrusted_gateway(monkeypatch: pytest.MonkeyPatch) -> None:
    from defenseclaw import gateway

    monkeypatch.setattr(gateway, "resolve_gateway_binary", lambda: "/tmp/untrusted-gateway")
    monkeypatch.setattr(gateway, "resolve_trusted_gateway_binary", lambda: None)
    monkeypatch.setattr(
        gateway.subprocess, "run", lambda *_args, **_kwargs: pytest.fail("untrusted gateway executed")
    )
    assert gateway.local_policy_digest(SimpleNamespace(data_dir="")) is None
