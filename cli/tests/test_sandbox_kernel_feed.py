# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""The sandbox kernel feed in the per-user install's lifecycle.

The feed is a root service (``sudo defenseclaw-gateway sandbox kernel-feed
install``) with its own copy of ``defenseclaw-sensor-helper``. The per-user
install ships the helper beside the gateway (Linux), ``defenseclaw
uninstall`` removes that copy and names the command that removes the root
service, and ``install.sh`` says when an upgrade left the feed on an older
release.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from defenseclaw.commands import cmd_doctor, cmd_uninstall

REPO_ROOT = Path(__file__).resolve().parents[2]


def _plan(**fields: object) -> cmd_uninstall.UninstallPlan:
    return cmd_uninstall.UninstallPlan(**fields)


def test_uninstall_names_the_feed_removal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    unit = tmp_path / "defenseclaw-sandbox-feed.service"
    monkeypatch.setattr(cmd_uninstall.sys, "platform", "linux")
    assert cmd_uninstall._sandbox_kernel_feed_hint(_plan(), str(unit)) == ""
    unit.write_text("[Unit]\n", encoding="utf-8")
    gateway = "/home/dev/.local/bin/defenseclaw-gateway"
    kept = cmd_uninstall._sandbox_kernel_feed_hint(_plan(gateway_path=gateway), str(unit))
    assert kept == f"remove it with `sudo {gateway} sandbox kernel-feed uninstall`"
    # Once the gateway goes, the feed's own root copy removes it.
    gone = cmd_uninstall._sandbox_kernel_feed_hint(_plan(gateway_path=gateway, remove_binaries=True), str(unit))
    assert gone == f"remove it with `sudo {cmd_uninstall._SANDBOX_FEED_HELPER} --sandbox-feed --uninstall`"
    monkeypatch.setattr(cmd_uninstall.sys, "platform", "darwin")
    assert cmd_uninstall._sandbox_kernel_feed_hint(_plan(gateway_path=gateway), str(unit)) == ""


def test_the_feed_paths_match_the_go_lifecycle() -> None:
    lifecycle = (REPO_ROOT / "internal/sensor/sandboxfeed/lifecycle.go").read_text(encoding="utf-8")
    assert 'UnitPath        = "/etc/systemd/system/" + UnitName' in lifecycle
    assert 'UnitName        = "defenseclaw-sandbox-feed.service"' in lifecycle
    assert 'InstallDir      = "/usr/local/libexec/defenseclaw"' in lifecycle
    assert cmd_uninstall._SANDBOX_FEED_UNIT == "/etc/systemd/system/defenseclaw-sandbox-feed.service"
    assert cmd_uninstall._SANDBOX_FEED_HELPER == "/usr/local/libexec/defenseclaw/defenseclaw-sensor-helper"
    installer = (REPO_ROOT / "scripts/install.sh").read_text(encoding="utf-8")
    assert f'SANDBOX_FEED_UNIT="{cmd_uninstall._SANDBOX_FEED_UNIT}"' in installer
    assert f'SANDBOX_FEED_HELPER="{cmd_uninstall._SANDBOX_FEED_HELPER}"' in installer


def test_the_helper_ships_and_is_removed_with_the_per_user_install() -> None:
    release = yaml.safe_load((REPO_ROOT / ".goreleaser.yaml").read_text(encoding="utf-8"))
    default = next(archive for archive in release["archives"] if archive["id"] == "default")
    assert "defenseclaw-sensor-helper-posix" in default["ids"]
    installer = (REPO_ROOT / "scripts/install.sh").read_text(encoding="utf-8")
    managed = re.search(r'^readonly MANAGED_BINARIES="([^"]*)"', installer, re.MULTILINE)
    assert managed and "defenseclaw-sensor-helper" in managed.group(1).split()
    # A Mac install does not keep it: the feed is Linux only.
    assert '[[ "${OS}" == linux ]] || rm -f "${STAGING}/bin/defenseclaw-sensor-helper"' in installer
    _root, targets = cmd_uninstall._owned_binary_targets("linux")
    assert any(target.endswith("/defenseclaw-sensor-helper") for target in targets)


# ---------------------------------------------------------------------------
# defenseclaw doctor: the "Sandbox kernel feed" row (spec 11.3)
# ---------------------------------------------------------------------------

_SANDBOXES_ON = SimpleNamespace(openshell=SimpleNamespace(enabled=True))
_GATEWAY = "/home/u/.local/bin/defenseclaw-gateway"
_INSTALL = f"sudo {_GATEWAY} sandbox kernel-feed install"


def _feed_rows(tmp_path: Path, report: object, *, installed: bool = True, cfg=_SANDBOXES_ON, os_name: str = "linux"):
    unit = tmp_path / "defenseclaw-sandbox-feed.service"
    if installed:
        unit.write_text("[Unit]\n", encoding="utf-8")
    calls: list[list[str]] = []

    def run(argv, **_kwargs):
        calls.append(argv)
        stdout = report if isinstance(report, str) else json.dumps(report)
        return subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr="")

    result = cmd_doctor._DoctorResult()
    cmd_doctor._check_sandbox_kernel_feed(cfg, result, unit_path=str(unit), os_name=os_name, binary=_GATEWAY, run=run)
    for check in result.checks:
        assert check["label"] == "Sandbox kernel feed"
        assert check["check_id"] == "doctor.sandbox.kernel-feed"
    return result.checks, calls


def test_feed_row_only_when_the_feed_is_installed_on_linux(tmp_path: Path) -> None:
    sandboxes_off = SimpleNamespace(openshell=SimpleNamespace(enabled=False))
    for index, kwargs in enumerate(({"installed": False}, {"os_name": "darwin"}, {"cfg": sandboxes_off})):
        workdir = tmp_path / str(index)
        workdir.mkdir()
        checks, calls = _feed_rows(workdir, {"reachable": True}, **kwargs)
        assert checks == [] and calls == [], kwargs


def test_feed_row_names_the_update_command(tmp_path: Path) -> None:
    report = {
        "installed": True,
        "update_needed": True,
        "build": "1.1.0",
        "protocol": 1,
        "gateway_version": "1.2.0",
        "gateway_protocol": 2,
        "install_command": _INSTALL,
    }
    checks, calls = _feed_rows(tmp_path, report)
    assert calls == [[_GATEWAY, "sandbox", "kernel-feed", "status", "--json"]]
    (row,) = checks
    assert row["status"] == "warn" and row["reason_code"] == "kernel-feed-update"
    assert _INSTALL in row["remediation"] and "1.1.0" in row["detail"] and "1.2.0" in row["detail"]


def test_feed_row_pass_skip_and_unavailable(tmp_path: Path) -> None:
    reachable = {"installed": True, "reachable": True, "build": "1.2.0", "protocol": 2, "tetragon": "connected"}
    (row,), _ = _feed_rows(tmp_path, reachable)
    assert row["status"] == "pass" and "connected" in row["detail"] and "1.2.0" in row["detail"]
    (row,), _ = _feed_rows(tmp_path, {"installed": True, "reason": "kernel_feed_not_permitted"})
    assert row["status"] == "skip" and "docker group" in row["detail"]
    (row,), _ = _feed_rows(tmp_path, {"installed": True, "active": "failed", "reason": "kernel_feed_unavailable"})
    assert row["status"] == "warn" and row["reason_code"] == "kernel-feed-unavailable"
    # GAP-0091: a stopped feed gets the command that starts it; a running one
    # that does not answer, the status command.
    assert "sudo systemctl restart defenseclaw-sandbox-feed.service" in row["remediation"]
    (row,), _ = _feed_rows(tmp_path, {"installed": True, "active": "active", "reason": "kernel_feed_unavailable"})
    assert "sudo systemctl status defenseclaw-sandbox-feed.service" in row["remediation"]
    (row,), _ = _feed_rows(tmp_path, "not json")
    assert row["status"] == "warn" and row["reason_code"] == "kernel-feed-status-unavailable"


def test_feed_row_warns_while_its_tetragon_is_not_connected(tmp_path: Path) -> None:
    # GAP-0086: Tetragon stopped, the feed still answers; sandbox ps warns and
    # uses the sample, so doctor warns with the next step instead of passing.
    report = {
        "installed": True,
        "reachable": True,
        "build": "1.2.0",
        "protocol": 1,
        "tetragon": "unavailable",
        "tetragon_reason": "tetragon_unavailable",
    }
    (row,), _ = _feed_rows(tmp_path, report)
    assert row["status"] == "warn" and row["reason_code"] == "kernel-feed-tetragon-unavailable"
    assert "unavailable (tetragon_unavailable)" in row["detail"] and "1.2.0" in row["detail"]
    assert "sudo systemctl status tetragon" in row["remediation"] and "5-second sample" in row["remediation"]
    report = {"installed": True, "reachable": True, "build": "1.2.0", "protocol": 1}
    (row,), _ = _feed_rows(tmp_path, report)
    assert row["status"] == "warn" and "unknown" in row["detail"]
