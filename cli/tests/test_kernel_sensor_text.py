# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""The shared kernel sensor wording, and every doctor remediation runs as printed.

The Python twin of the Go TestTetragonHintsAreRunnable: the managed Linux
binaries are not on PATH and sudo resets PATH, so a printed command must carry
sudo and /opt/defenseclaw/bin, a Tetragon change the exact tetragon.conf.d write
and the restart that says what it drops, and a config change the YAML path.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from defenseclaw.commands.cmd_doctor import _check_kernel_sensor, _DoctorResult
from defenseclaw.kernel_sensor import (
    TETRAGON_RESTART,
    admin_command,
    fallback_text,
    helper_command,
    kernel_controls_line,
    kernel_sensor_summary,
    paused_suffix,
    tetragon_setting,
    your_policies_summary,
)

_PLANE_C = SimpleNamespace(enabled=True, enable_host_plane=True, planes=[])
_NO_PLANE_C = SimpleNamespace(enabled=True, enable_host_plane=False, planes=[])
_UNIX = {"server_address": "unix:///var/run/tetragon/tetragon.sock", "pid": 4242}
_TETRAGON = {"kind": "tetragon", "version": "1.7.1", "mode": "enforce", "events_lost": 0, "loss_known": True}

_BACKTICKED = re.compile(r"`([^`]+)`")
_RUNNABLE_PREFIXES = (
    "sudo /opt/defenseclaw/bin/",
    "sudo systemctl ",
    "sudo journalctl ",
    "systemctl status ",
)
_TETRAGON_FLAG = re.compile(r"^echo \S+ \| sudo tee /etc/tetragon/tetragon\.conf\.d/[a-z-]+$")
_YAML_SETTING = re.compile(r"^[a-z_]+(\.[a-z_<>]+)+: \S.*$")


def _runnable(span: str) -> bool:
    return span.startswith(_RUNNABLE_PREFIXES) or bool(_TETRAGON_FLAG.match(span) or _YAML_SETTING.match(span))


def _health(backend: dict | None, kernel: dict | None = None, components: dict | None = None) -> dict:
    plane_c: dict[str, Any] = {"available": True, "running": True}
    if backend is not None:
        plane_c["backend"] = backend
    policy: dict[str, Any] = {"kernel": kernel or {}, "components": components or {}}
    return {"ai_runtime": {"details": {"planes": {"c": plane_c}}}, "policy": policy}


def _rows(tmp_path: Path) -> list[dict]:
    """Every row the kernel sensor check can emit, one scenario each."""

    info_path = tmp_path / "tetragon-info.json"
    scenarios: list[tuple[dict | None, Any, dict | None, str | None]] = [
        ({"server_address": "localhost:54321"}, _PLANE_C, _health(_TETRAGON), None),
        (_UNIX, _PLANE_C, _health(_TETRAGON, kernel={"orphaned": ["defenseclaw-controls-0a1b2c3d"]}), None),
        (_UNIX, _NO_PLANE_C, _health(_TETRAGON), None),
        (_UNIX, _PLANE_C, _health(_TETRAGON), "off"),
        (None, _PLANE_C, _health(_TETRAGON), "observe"),
        (_UNIX, _PLANE_C, None, None),
        (_UNIX, _PLANE_C, _health({"kind": "native", "fallback_reason": "tetragon_unsupported_version: 1.5.0"}), None),
        (
            _UNIX,
            _PLANE_C,
            _health(
                _TETRAGON,
                kernel={"kernel_policy": "sha256:" + "1" * 64},
                components={"kernel_policy": "sha256:" + "2" * 64},
            ),
            None,
        ),
        (_UNIX, _PLANE_C, _health(_TETRAGON, kernel={"paused_until": "2026-10-07T14:05:00Z"}), None),
        (_UNIX, _PLANE_C, _health(_TETRAGON), None),
    ]
    rows: list[dict] = []
    for info, runtime, health, mode in scenarios:
        info_path.unlink(missing_ok=True)
        if info is not None:
            info_path.write_text(json.dumps(info), encoding="utf-8")
        cfg = SimpleNamespace(
            deployment_mode="managed_enterprise", data_dir="", ai_discovery=SimpleNamespace(runtime=runtime)
        )
        document = {"enterprise": {"tetragon": {"mode": mode}}} if mode else {}
        result = _DoctorResult()
        _check_kernel_sensor(
            cfg, result, live_health=health, info_path=str(info_path), os_name="linux", document=document
        )
        rows.extend(result.checks)
    return rows


def test_every_doctor_remediation_runs_as_printed(tmp_path: Path) -> None:
    rows = _rows(tmp_path)
    codes = {row.get("reason_code") for row in rows}
    for code in (
        "tetragon-tcp-api",
        "kernel-policy-orphaned",
        "tetragon-plane-c-off",
        "tetragon-mode-off",
        "tetragon-unavailable",
        "tetragon-fallback",
        "kernel-policy-not-applied",
        "kernel-enforce-paused",
    ):
        assert code in codes, (code, codes)
    for row in rows:
        text = f"{row.get('detail', '')} {row.get('remediation', '')}"
        for span in _BACKTICKED.findall(text):
            assert _runnable(span), (row.get("reason_code"), span)
        # No bare `defenseclaw-gateway`: it is not on PATH under sudo.
        assert "`sudo defenseclaw-gateway" not in text and "`defenseclaw-gateway" not in text, row
        if row.get("remediation"):
            assert _BACKTICKED.search(row["remediation"]), (row.get("reason_code"), row["remediation"])


def test_admin_commands_carry_sudo_and_the_package_path() -> None:
    assert admin_command("enterprise", "linux", "tetragon", "verify") == (
        "sudo /opt/defenseclaw/bin/defenseclaw-gateway enterprise linux tetragon verify"
    )
    assert (
        helper_command("--tetragon-cleanup") == "sudo /opt/defenseclaw/bin/defenseclaw-sensor-helper --tetragon-cleanup"
    )
    assert tetragon_setting("keep-sensors-on-exit", "false") == (
        "echo false | sudo tee /etc/tetragon/tetragon.conf.d/keep-sensors-on-exit"
    )
    assert "drops policies added with tetra" in TETRAGON_RESTART and _runnable(_BACKTICKED.findall(TETRAGON_RESTART)[0])


def test_shared_words_for_the_kernel_sensor_and_controls() -> None:
    assert kernel_sensor_summary(_TETRAGON) == "Tetragon v1.7.1, enforce, 0 events lost"
    assert kernel_sensor_summary({"kind": "native", "fallback_reason": "tetragon_tcp_api: localhost:54321"}) == (
        "cn_proc and fanotify (Tetragon not used: its API listens on TCP instead of a local socket)"
    )
    assert kernel_sensor_summary({}) == "" and kernel_sensor_summary(None) == ""
    assert fallback_text("something_new: the stream ended") == "the stream ended"
    assert kernel_controls_line({"mode": "observe", "enrolled_users": 3}) == "monitoring 3 users, not enforcing"
    assert kernel_controls_line({"mode": "enforce", "enrolled_users": 2, "approval": "missing"}) == (
        "monitoring 2 users; enforce is not approved yet"
    )
    floor = {"mode": "enforce", "enforced_users": 2, "enrolled_users": 3, "burn_in_users": 1, "next_ready_hours": 216}
    assert kernel_controls_line(floor) == "enforcing 2 of 3 users; 1 in burn-in, next ready ~9 days"
    assert paused_suffix({"paused_until": "2026-10-07T14:05:00Z"}) == "; paused until 2026-10-07T14:05:00Z"
    assert paused_suffix({}) == "" and paused_suffix(None) == ""


def test_your_policies_summary_counts_without_naming_events() -> None:
    backend = {
        "customer_policies": [
            {"name": "10-file-sensitive", "mode": "enforce"},
            {"name": "20-net-connect", "mode": "monitor"},
        ],
        "customer_events": {"seen": 40, "forwarded": 1, "dropped": 3},
    }
    assert your_policies_summary(backend) == "2 loaded (1 enforcing); 1 agent event forwarded, 3 over the budget"
    assert your_policies_summary({"customer_policies": []}) == ""
    assert your_policies_summary({"kind": "tetragon"}) == "" and your_policies_summary(None) == ""
