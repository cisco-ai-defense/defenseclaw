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

_FLOOR: dict[str, Any] = {
    "mode": "enforce", "enrolled_users": 3, "enforced_users": 2, "burn_in_users": 1,
    "next_ready_hours": 216, "approval": "approved", "blocked_1h": 2, "would_block_1h": 5,
}

# What a managed host with a customer policy reports (SPEC-TETRAGON-UX 5.4).
_ENFORCE: dict[str, Any] = {
    **_BACKEND,
    "mode": "enforce",
    "kernel_floor": _FLOOR,
    "customer_events": {"seen": 40, "forwarded": 12, "dropped": 0, "container": 1},
    "customer_policies": [{"name": "file-sensitive", "mode": "monitor", "state": "enabled"}],
}


def _snapshot(backend: Any = _BACKEND, **extra: Any) -> dict[str, Any]:
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
        **extra,
    }


def _plane_c(backend: Any = _BACKEND) -> PlaneRow:
    return decode_runtime_snapshot(_snapshot(backend)).planes[1]


def _lines(**floor: Any) -> tuple[str, ...]:
    return _plane_c({**_ENFORCE, "kernel_floor": {**_FLOOR, **floor}}).detail_lines()


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
        "kernel sensor: Tetragon v1.7.1, observe, 0 events lost",
        "kernel controls: monitoring 3 users, not enforcing",
        "policies: observe monitor, connect monitor, controls monitor",
    )
    # The strip names the mode, so a glance tells observe from enforce.
    assert plane.strip_label == "agent actions: up (Tetragon, observe)"
    # The mechanism already names Tetragon: the summary adds only the mode.
    assert plane.summary.endswith("+ fanotify (observe mode)")
    other = PlaneRow("c", "agent actions", True, True, mechanism="cn_proc", backend_kind="tetragon",
                     backend_version="1.7.1", backend_mode="consume")
    assert other.summary == "agent actions: up via cn_proc (Tetragon 1.7.1, consume)"
    assert other.strip_label == "agent actions: up (Tetragon, consume)"


def test_loss_is_unknown_unless_the_helper_can_measure_it() -> None:
    for change in ({"loss_known": False}, {"loss_known": False, "events_lost": 4}):
        backend = {**_BACKEND, **change}
        assert "events lost unknown" in _plane_c(backend).detail_lines()[0]
    assert "events_lost" not in (missing := {k: v for k, v in _BACKEND.items() if k != "events_lost"})
    assert "events lost unknown" in _plane_c(missing).detail_lines()[0]
    assert "3 events lost" in _plane_c({**_BACKEND, "events_lost": 3}).detail_lines()[0]


def test_fallback_says_why_tetragon_is_not_used_without_the_reason_code() -> None:
    backend = {"kind": "native", "fallback_reason": "tetragon_tcp_api: server-address is tcp://127.0.0.1:54321"}
    plane = _plane_c(backend)
    assert not plane.is_tetragon
    assert plane.strip_label == "agent actions: up"
    (line,) = plane.detail_lines()
    assert line == "kernel sensor: cn_proc and fanotify (Tetragon not used: its API listens on TCP instead of a local socket)"
    assert "tetragon_tcp_api" not in line


def test_expanded_plane_c_shows_controls_blocks_and_your_policies_within_the_width() -> None:
    plane = _plane_c(_ENFORCE)
    assert plane.detail_lines() == (
        "kernel sensor: Tetragon v1.7.1, enforce, 0 events lost",
        "kernel controls: enforcing 2 of 3 users; 1 in burn-in, next ready ~9 days",
        "blocks (1h): 2 denied, 5 would-block; your policies: 12 agent events",
        "policies: observe monitor, connect monitor, controls monitor",
    )
    assert plane.strip_label == "agent actions: up (Tetragon, enforce)"
    assert all(len(line) <= 77 for line in plane.detail_lines())  # one column in, inside the 80-column body


def test_kernel_controls_say_when_enforce_is_not_approved_and_when_the_eta_is_known() -> None:
    assert "next ready ~9 days" in _lines()[1]
    assert "next ready ~20 hours" in _lines(next_ready_hours=20)[1]
    assert _lines(next_ready_hours=0)[1].endswith("1 in burn-in")  # no estimate yet ("measuring")
    assert _lines(burn_in_users=0)[1] == "kernel controls: enforcing 2 of 3 users"
    assert _lines(enforced_users=1, enrolled_users=1, burn_in_users=0)[1] == "kernel controls: enforcing 1 of 1 users"
    assert _lines(approval="missing")[1] == "kernel controls: monitoring 3 users; enforce is not approved yet"
    assert _lines(approval="stale")[1] == "kernel controls: monitoring 3 users; the approval is for another build"


def test_blocks_and_your_policies_appear_only_when_the_gateway_reports_them() -> None:
    plain = _plane_c({**_BACKEND, "kernel_floor": {k: v for k, v in _FLOOR.items() if not k.endswith("_1h")}})
    assert not any(line.startswith("blocks") or "your policies" in line for line in plain.detail_lines())
    quiet = {**_ENFORCE, "customer_events": {"seen": 0, "forwarded": 0, "dropped": 0, "container": 0}}
    assert "your policies: no agent events" in _plane_c(quiet).detail_lines()[2]
    one = {**_ENFORCE, "customer_events": {"forwarded": 1}}
    assert _plane_c(one).detail_lines()[2].endswith("your policies: 1 agent event")
    # Counts without the block fields still print the customer half.
    no_blocks = {**_ENFORCE, "kernel_floor": {k: v for k, v in _FLOOR.items() if not k.endswith("_1h")}}
    assert _plane_c(no_blocks).detail_lines()[2] == "your policies: 12 agent events"


def test_pause_names_who_and_when_and_prints_a_command_that_runs() -> None:
    floor = {**_FLOOR, "paused_until": "2026-10-07T14:05:00Z", "paused_by": "alice"}
    plane = _plane_c({**_ENFORCE, "kernel_floor": floor})
    lines = plane.detail_lines()
    assert lines[-2] == "paused until 14:05Z by alice; root can resume it with"
    assert lines[-1] == "sudo /opt/defenseclaw/bin/defenseclaw-gateway enterprise linux tetragon resume"
    assert plane.kernel_paused_until == "2026-10-07T14:05:00Z"
    assert plane.strip_label == "agent actions: up (Tetragon, paused)"
    # Another day names the date; a reboot pause and an ended pause read right.
    other_day = _plane_c({**_ENFORCE, "kernel_floor": {**_FLOOR, "paused_until": "2026-10-08T01:30:00Z"}})
    assert other_day.detail_lines()[-2] == "paused until 2026-10-08 01:30Z; root can resume it with"
    reboot = _plane_c({**_ENFORCE, "kernel_floor": {**_FLOOR, "paused_until": "reboot", "paused_by": "bob"}})
    assert reboot.detail_lines()[-2].startswith("paused until the next reboot by bob;")
    ended = _plane_c({**_ENFORCE, "kernel_floor": {**_FLOOR, "paused_until": "resumed"}})
    assert ended.kernel_paused_until == "" and ended.strip_label == "agent actions: up (Tetragon, enforce)"
    # The binaries are not on PATH and sudo resets it: no bare command is ever printed.
    for text in lines:
        if "defenseclaw-gateway" in text:
            assert text.startswith("sudo /opt/defenseclaw/bin/defenseclaw-gateway ")


def test_failed_policies_are_counted_and_capped_and_text_is_clipped() -> None:
    policies = [{"name": "defenseclaw-observe-0a1b2c3d", "mode": "monitor", "state": "enabled"}] + [
        {"name": f"defenseclaw-controls-0a1b2c3{i}", "mode": "enforce", "state": "load_error",
         "error": "bpf: " + "x" * 200}
        for i in range(4)
    ]
    lines = _plane_c({**_BACKEND, "policies": policies}).detail_lines()
    assert "policies: observe monitor, 4 not loaded" in lines
    failing = [line for line in lines if line.startswith("  controls:")]
    assert len(failing) == 2
    assert all(len(line) < 100 and line.endswith("...") for line in failing)


def test_finding_detail_says_what_the_kernel_did_and_what_your_policy_saw() -> None:
    finding = {
        **_FINDING,
        "activities": [
            {"tactic": "credential_access", "kernel_outcome": "blocked",
             "kernel_control": "kernel.ssh_private_key_read", "hook_join": "exact"},
            {"tactic": "persistence", "kernel_outcome": "would_block",
             "kernel_control": "kernel.persistence_write", "hook_seen": False},
            {"tactic": "discovery", "kernel_outcome": "observed"},
        ],
    }
    events = [
        {"policy_name": "file-sensitive", "function": "security_file_open", "outcome": "observed",
         "process": "cat", "pid": 20, "target": "dccert-target-marker"},
        {"policy_name": "file-sensitive", "function": "security_file_open", "outcome": "observed",
         "process": "cat", "pid": 20, "count": 2},
        {"policy_name": "elsewhere", "function": "tcp_connect", "outcome": "blocked", "process": "curl", "pid": 99},
    ]
    model = RuntimePanelModel(platform="linux")
    model.set_snapshot({**_snapshot(_ENFORCE), "findings": [finding], "customer_kernel_events": events})
    text = model.detail_text()
    notes = [line for line in text.splitlines() if line.startswith(("kernel:", "your policy"))]
    assert notes == [
        "kernel: blocked kernel.ssh_private_key_read (hook: exact)",
        "kernel: would have blocked kernel.persistence_write (no hook decision)",
        "your policy file-sensitive: observed security_file_open by cat (x3)",
    ]
    assert "elsewhere" not in text  # another process's event
    assert "dccert-target-marker" not in text  # an event target never reaches the screen


def test_finding_detail_is_unchanged_without_kernel_data_and_ignores_junk() -> None:
    model = RuntimePanelModel(platform="linux")
    model.set_snapshot({**_snapshot(), "customer_kernel_events": ["x", {"policy_name": ""}, 7]})
    assert "kernel:" not in model.detail_text() and "your policy" not in model.detail_text()
    model.set_snapshot({**_snapshot(), "customer_kernel_events": "nope", "findings": [{**_FINDING, "activities": "x"}]})
    assert model.detail_text().startswith("CRITICAL  score 95")


def test_overview_strip_carries_the_mode() -> None:
    model = RuntimePanelModel(platform="linux")
    model.set_snapshot(_snapshot(_ENFORCE))
    assert "agent actions: up (Tetragon, enforce)" in model.overview().plane_summary
    model.short_screen = True  # 80x24 starts on the one-line strip
    assert "agent actions: up (Tetragon, enforce)" in model.plane_strip()


def test_linux_host_plane_hint_names_the_capability_cn_proc_needs() -> None:
    plane = PlaneRow("c", "agent actions", True, False, reason="not selected in ai_discovery.runtime.planes")
    hint = RuntimePanelModel(platform="linux").plane_fix(plane)
    assert "CAP_NET_ADMIN" in hint and "CAP_SYS_ADMIN" in hint and "no grant" not in hint


async def test_runtime_panel_shows_the_kernel_sensor_at_80x24(tmp_path) -> None:
    app = snapshot_app(tmp_path)
    async with app.run_test(size=(80, 24)) as pilot:
        app.runtime_model.set_snapshot(_snapshot(_ENFORCE))
        app.action_switch_panel("runtime")
        await pilot.pause()
        screen = screen_text(app)
        assert "agent actions: up (Tetragon, enforce)" in screen
        assert "critical" in screen  # the findings table stays above the fold
        await pilot.press("p")
        await pilot.pause()
        expanded = screen_text(app)
    for line in ("kernel sensor: Tetragon v1.7.1, enforce, 0 events lost",
                 "kernel controls: enforcing 2 of 3 users; 1 in burn-in, next ready ~9 days",
                 "blocks (1h): 2 denied, 5 would-block; your policies: 12 agent events"):
        assert line in expanded  # each on one row: nothing wraps at 80 columns
    assert "critical" in expanded
