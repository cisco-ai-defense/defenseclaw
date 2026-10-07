# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Runtime panel model: the kernel sensor (Tetragon) behind Plane C on managed Linux."""

from __future__ import annotations

import copy
from typing import Any

from defenseclaw.tui.services.runtime_state import (
    PlaneRow,
    RuntimePanelModel,
    decode_runtime_snapshot,
)
from fixtures import screen_text, snapshot_app

_FINDING = {
    "finding_id": "run-1",
    "pid": 20,
    "process": "claude",
    "user": "dev",
    "agent_name": "claude",
    "score": 95,
    "severity": "critical",
    "signals": [{"id": "agent_credential_access", "detail": "dccert-block-marker", "weight": 30}],
    "correlation": {"verdict": "accounted", "reason": "discovery observed the same subject"},
}

_BACKEND: dict[str, Any] = {
    "kind": "tetragon",
    "version": "1.7.1",
    "mode": "observe",
    "socket": "/var/run/tetragon/tetragon.sock",
    "events_lost": 0,
    "loss_known": True,
    "policies": [
        {"name": "defenseclaw-observe-0a1b2c3d", "mode": "monitor", "state": "enabled"},
        {"name": "defenseclaw-connect-0a1b2c3d", "mode": "monitor", "state": "enabled"},
        {"name": "defenseclaw-controls-0a1b2c3d", "mode": "monitor", "state": "enabled"},
    ],
    "kernel_floor": {"mode": "monitor", "enrolled_users": 3},
}


def _snapshot(backend: Any = _BACKEND) -> dict[str, Any]:
    plane_c: dict[str, Any] = {
        "plane": "c",
        "name": "agent actions",
        "available": True,
        "running": True,
        "mechanism": "Tetragon 1.7.1 (gRPC) + fanotify",
    }
    if backend is not None:
        plane_c["backend"] = copy.deepcopy(backend)
    return {
        "enabled": True,
        "scanned_at": "2026-10-07T12:00:00Z",
        "planes": [
            {"plane": "a", "name": "inference heartbeat", "available": True, "running": True, "mechanism": "ps(1)"},
            plane_c,
        ],
        "findings": [_FINDING],
    }


def _plane_c(backend: Any = _BACKEND) -> PlaneRow:
    return decode_runtime_snapshot(_snapshot(backend)).planes[1]


def test_no_backend_leaves_the_plane_exactly_as_it_was() -> None:
    plane = _plane_c(None)
    assert not plane.is_tetragon
    assert plane.detail_lines() == ()
    assert plane.strip_label == "agent actions: up"
    assert plane.summary == "agent actions: up via Tetragon 1.7.1 (gRPC) + fanotify"
    # An older gateway or a non-Linux host: nothing new, and junk is ignored.
    for junk in ("tetragon", ["x"], 7, {}):
        assert _plane_c(junk).detail_lines() == ()


def test_tetragon_backend_reads_like_the_cli() -> None:
    plane = _plane_c()
    assert plane.backend_label == "Tetragon 1.7.1, observe"
    assert plane.detail_lines() == (
        "kernel sensor: Tetragon 1.7.1, observe, 0 events lost",
        "policies: observe monitor, connect monitor, controls monitor",
        "kernel floor: monitor for 3 users",
    )
    assert plane.strip_label == "agent actions: up (Tetragon)"
    # The mechanism already names Tetragon: the summary adds only the mode.
    assert plane.summary.endswith("+ fanotify (observe mode)")
    other = PlaneRow("c", "agent actions", True, True, mechanism="cn_proc", backend_kind="tetragon",
                     backend_version="1.7.1", backend_mode="consume")
    assert other.summary == "agent actions: up via cn_proc (Tetragon 1.7.1, consume)"


def test_loss_is_unknown_unless_the_helper_can_measure_it() -> None:
    for change in ({"loss_known": False}, {"loss_known": False, "events_lost": 4}):
        backend = {**_BACKEND, **change}
        assert "events lost unknown" in _plane_c(backend).detail_lines()[0]
    assert "events_lost" not in (missing := {k: v for k, v in _BACKEND.items() if k != "events_lost"})
    assert "events lost unknown" in _plane_c(missing).detail_lines()[0]
    assert "3 events lost" in _plane_c({**_BACKEND, "events_lost": 3}).detail_lines()[0]


def test_fallback_says_why_tetragon_is_not_used() -> None:
    backend = {"kind": "native", "fallback_reason": "tetragon_tcp_api: server-address is tcp://127.0.0.1:54321"}
    plane = _plane_c(backend)
    assert not plane.is_tetragon
    assert plane.strip_label == "agent actions: up"
    assert plane.detail_lines()[0].startswith("kernel sensor: cn_proc and fanotify (Tetragon not used: tetragon_tcp_api")


def test_enforce_floor_shows_burn_in_and_the_pause_with_its_way_out() -> None:
    floor = {"mode": "enforce", "enforced_users": 2, "enrolled_users": 3, "burn_in_users": 1,
             "paused_until": "2026-10-07T14:05:00Z"}
    plane = _plane_c({**_BACKEND, "mode": "enforce", "kernel_floor": floor})
    lines = plane.detail_lines()
    assert "kernel floor: enforce for 2 of 3 users (1 in burn-in); paused until 2026-10-07T14:05:00Z" in lines
    assert plane.kernel_paused_until == "2026-10-07T14:05:00Z"
    assert lines[-1].endswith("enterprise linux tetragon resume") and len(lines[-1]) < 64  # fits 80 columns
    assert plane.strip_label == "agent actions: up (Tetragon, paused)"


def test_failed_policies_are_counted_and_capped_and_text_is_clipped() -> None:
    policies = [{"name": "defenseclaw-observe-0a1b2c3d", "mode": "monitor", "state": "enabled"}] + [
        {"name": f"defenseclaw-controls-0a1b2c3{i}", "mode": "enforce", "state": "load_error",
         "error": "bpf: " + "x" * 200}
        for i in range(4)
    ]
    lines = _plane_c({**_BACKEND, "policies": policies}).detail_lines()
    assert lines[1] == "policies: observe monitor, 4 not loaded"
    failing = [line for line in lines if line.startswith("  controls:")]
    assert len(failing) == 2
    assert all(len(line) < 100 and line.endswith("...") for line in failing)


def test_linux_host_plane_hint_names_the_capability_cn_proc_needs() -> None:
    plane = PlaneRow("c", "agent actions", True, False, reason="not selected in ai_discovery.runtime.planes")
    hint = RuntimePanelModel(platform="linux").plane_fix(plane)
    assert "CAP_NET_ADMIN" in hint and "CAP_SYS_ADMIN" in hint and "no grant" not in hint


async def test_runtime_panel_shows_the_kernel_sensor_at_80x24(tmp_path) -> None:
    app = snapshot_app(tmp_path)
    async with app.run_test(size=(80, 24)) as pilot:
        app.runtime_model.set_snapshot(_snapshot())
        app.action_switch_panel("runtime")
        await pilot.pause()
        screen = screen_text(app)
    assert "Tetragon" in screen
    assert "critical" in screen  # the findings table stays above the fold
