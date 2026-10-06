# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""The Sandboxes panel (key 7): model, keys, actions, terminal handover."""

from __future__ import annotations

import contextlib
import io
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from defenseclaw.tui import sandbox_panel
from defenseclaw.tui.app import PANEL_SHORTCUTS, PANELS, DefenseClawTUI
from defenseclaw.tui.panels.sandboxes import (
    ADMIN_MESSAGE,
    AdminPolicy,
    SandboxesPanelModel,
    SandboxPanelAction,
    admin_policy_from_config,
    decode_sandbox,
    review_pairs,
    undo_preview_text,
)
from defenseclaw.tui.screens.sandbox_launch import (
    SandboxLaunch,
    SandboxLaunchError,
    SandboxLaunchValues,
    harness_choices,
)
from defenseclaw.tui.services.sandbox_state import TOAST_DEDUPE_SECONDS, host_port, verdict_reason

STATUS = {
    "enabled": True,
    "available": True,
    "gateway": {"name": "openshell", "version": "0.1.1", "healthy": True},
    "ingress_addr": "127.0.0.1:18971",
    "egress_addr": "127.0.0.1:18972",
    "pack": "open",
    "profile": "open",
    "admin": {"configured": False, "authority": "advisory"},
    "sandboxes": 3,
    "running": 2,
    "pending_approvals": 1,
}

RUNNING = {
    "name": "myapp-claude-7f3a",
    "harness": "claudecode",
    "harness_name": "Claude Code",
    "phase": "ready",
    "pack": "open",
    "profile": "open",
    "workdir_mode": "mount",
    "project": "/home/dev/code/myapp",
    "workdir": "/work/myapp",
    "yolo": True,
    "uptime_seconds": 3725,
    "egress": {"destinations": 23, "blocked": 1},
    "hooks": {"tool_calls": 57, "tool_blocked": 1, "last_blocked": "rm -rf ~ (DC-TOOL-1)", "tampered": 2},
    "snapshot": {"kind": "git", "ref": "refs/defenseclaw/pre"},
    "nested_repos": [{"kind": "repository", "path": "vendor/x/.git", "quarantined": "vendor/x/.git.dc-quarantine"}],
    "pending_approvals": 1,
}
COPY = {
    "name": "fix-tests",
    "harness": "codex",
    "harness_name": "Codex",
    "phase": "ready",
    "pack": "balanced",
    "profile": "balanced",
    "workdir_mode": "copy",
    "uptime_seconds": 30,
    "hooks": {"silent": True},
}
STOPPED = {
    "name": "docs",
    "harness": "claudecode",
    "phase": "stopped",
    "pack": "open",
    "profile": "strict",
    "workdir_mode": "mount",
    "snapshot": {"kind": "git", "undone_at": "2026-09-27T10:00:00Z"},
}
ASK = {
    "id": "ask-1",
    "sandbox": "myapp-claude-7f3a",
    "kind": "host_port",
    "host": "host.openshell.internal",
    "port": 5432,
    "binary": "/usr/bin/psql",
    "risky": True,
    "reason": "a port on this machine",
    "status": "pending",
    "created_at": "2026-09-27T12:00:00Z",
}


# A public host off the balanced allowlist: the one kind of ask "always" may save.
PUBLIC_ASK = {
    "id": "ask-2",
    "sandbox": "myapp-claude-7f3a",
    "kind": "network_rule",
    "host": "www.example.com",
    "port": 443,
    "binary": "/usr/bin/curl",
    "reason": "www.example.com is not on the allowlist",
    "status": "pending",
    "created_at": "2026-09-27T12:01:00Z",
}
# triage.judgeEndpoint's private-network ask.
PRIVATE_ASK = {
    "id": "ask-3",
    "sandbox": "myapp-claude-7f3a",
    "kind": "network_rule",
    "host": "10.0.1.3",
    "port": 38591,
    "binary": "/usr/bin/curl",
    "risky": True,
    "reason": "the sandbox asks to reach 10.0.1.3 on your private network",
    "status": "pending",
    "created_at": "2026-09-27T12:02:00Z",
}


def _events(*items: dict[str, Any]) -> list[dict[str, Any]]:
    return list(items)


BLOCKED = {
    "seq": 5,
    "kind": "egress.blocked",
    "sandbox": "myapp-claude-7f3a",
    "host": "webhook.site",
    "category": "exfil destination",
    "unblockable": True,
    "message": "✗ webhook.site (exfil destination)",
}
PRIVATE = {
    "seq": 6,
    "kind": "egress.blocked",
    "sandbox": "fix-tests",
    "host": "10.0.0.5",
    "port": 22,
    "reason": "private network",
    "unblockable": False,
}
ALLOWED = {
    "seq": 4,
    "kind": "egress.allowed",
    "sandbox": "myapp-claude-7f3a",
    "host": "registry.npmjs.org",
    "message": "✓ registry.npmjs.org",
}


def _model(**kwargs: Any) -> SandboxesPanelModel:
    model = SandboxesPanelModel(**kwargs)
    model.set_snapshot(STATUS, [STOPPED, COPY, RUNNING], [ASK, {**ASK, "id": "done", "status": "approved"}])
    return model


# --- decoding and snapshot ---------------------------------------------------


def test_panel_is_registered_on_seven() -> None:
    assert ("sandboxes", "7", "Sandboxes") in PANELS
    assert PANEL_SHORTCUTS["7"] == "sandboxes"


def test_sandbox_rows_carry_what_the_panel_shows() -> None:
    row = decode_sandbox(RUNNING)
    assert row is not None
    assert row.running and row.uptime_text == "1h02m"
    assert row.policy_label == "open"
    assert row.undo_available is True
    assert row.alert_badge == "tamper, nested repo"
    assert any("2 tool call(s) ran without a DefenseClaw verdict" in alert for alert in row.alerts)
    assert any("quarantined as vendor/x/.git.dc-quarantine" in alert for alert in row.alerts)
    stopped = decode_sandbox(STOPPED)
    assert stopped is not None and stopped.uptime_text == "-" and stopped.policy_label == "open/strict"
    assert stopped.undo_available is False  # the snapshot was already undone
    assert decode_sandbox({"phase": "ready"}) is None


def test_the_detail_says_kept_changes_get_a_new_undo_point() -> None:
    """The daemon's accept (the user kept the last session's changes) is on the
    snapshot: the next start takes a new undo point, whoever starts it."""
    model = SandboxesPanelModel()
    kept = {**STOPPED, "snapshot": {"kind": "git", "accepted_at": "2026-09-30T10:00:00Z"}}
    model.set_snapshot(STATUS, [kept], [])
    row = model.selected_sandbox()
    assert row is not None and row.undo_available and row.undo_accepted
    assert dict(model.detail_pairs()[1])["Undo"] == (
        "available (U); the last session's changes were kept, so the next start takes a new undo point"
    )
    assert decode_sandbox(RUNNING).undo_accepted is False


def test_snapshot_sorts_running_first_and_keeps_only_pending_asks() -> None:
    model = _model()
    assert [row.name for row in model.rows] == ["fix-tests", "myapp-claude-7f3a", "docs"]
    assert [ask.id for ask in model.asks] == ["ask-1"]
    assert model.state() == "ready"
    assert "2 running" in model.headline() and "1 ask(s) waiting" in model.headline()
    assert "OpenShell 0.1.1 gateway openshell" in model.headline()


@pytest.mark.parametrize(
    ("gateway", "text", "note"),
    [
        ({"driver": "vm"}, "OpenShell 0.1.1 gateway openshell (MicroVM)", "MicroVM sandboxes work on a copy"),
        ({"driver": "vm", "healthy": False}, "gateway openshell (MicroVM, unhealthy)", "MicroVM sandboxes"),
        ({"driver": "docker"}, "OpenShell 0.1.1 gateway openshell (docker)", ""),
        # A daemon older than gateway.driver drove docker only.
        ({}, "OpenShell 0.1.1 gateway openshell", ""),
    ],
)
def test_the_status_names_the_gateways_compute_driver(gateway: dict[str, Any], text: str, note: str) -> None:
    model = SandboxesPanelModel()
    model.set_snapshot({**STATUS, "gateway": {**STATUS["gateway"], **gateway}}, [], [])
    assert model.status.gateway.endswith(text) and text in model.headline()
    assert model.status.driver == gateway.get("driver", "")
    if note:
        assert model.status.copy_only_note.startswith(note) and "pull (P)" in model.status.copy_only_note
        # At 80 columns the gateway's name gives way, but not that it runs MicroVMs.
        assert model.headline(max_width=52) == "2 running · 3 total · MicroVM gateway"
    else:
        assert model.status.copy_only_note == ""
        assert model.headline(max_width=52) == "2 running · 3 total"


def test_a_run_image_is_in_the_details() -> None:
    image = "defenseclaw.invalid/sandbox-run:claudecode-0123456789ab-ba9876543210-u501"
    row = decode_sandbox({**COPY, "run_image": image})
    assert row is not None and row.run_image == image and row.copy_mode
    model = SandboxesPanelModel()
    model.set_snapshot(STATUS, [{**COPY, "run_image": image}], [])
    pairs = dict(model.detail_pairs()[1])
    assert pairs["Run image"] == image
    assert pairs["Undo"] == "reverts the last pull --apply (U)" and pairs["Pull"].startswith("P brings the work back")
    assert "Run image" not in dict(_model().detail_pairs()[1])


def test_hook_events_are_in_the_details() -> None:
    hooks = {
        "tool_calls": 12,
        "events": {"Stop": 2, "PostToolUse": 11, "SessionStart": 2, "PreToolUse": 12, "bad": "x", "": 4},
        "other_events": 1,
    }
    row = decode_sandbox({**RUNNING, "hooks": hooks})
    assert row is not None
    assert row.hook_events == (("PreToolUse", 12), ("PostToolUse", 11), ("SessionStart", 2), ("Stop", 2))
    model = SandboxesPanelModel()
    model.set_snapshot(STATUS, [{**RUNNING, "hooks": hooks}], [])
    pairs = dict(model.detail_pairs()[1])
    assert pairs["Hook events"] == "PreToolUse 12 · PostToolUse 11 · SessionStart 2 · Stop 2 · other events 1"
    assert "Hook events" not in dict(_model().detail_pairs()[1])


DESTINATIONS = {
    "name": "myapp-claude-7f3a",
    "destinations": [
        {"host": "api.openai.com", "kind": "other_ai_api", "provider": "Codex", "tunnels": 3, "binaries": ["/usr/bin/curl"]},
        {"host": "api.anthropic.com", "kind": "model_provider", "provider": "Claude Code", "connections": 5},
        {"host": "pastebin.com", "kind": "blocked", "category": "paste_site", "blocked": 4},
    ],
    "models": [{"provider": "anthropic", "model": "claude-haiku", "calls": 2, "failed": 1}],
}


def test_the_detail_lists_the_destinations() -> None:
    model = SandboxesPanelModel()
    model.set_snapshot(STATUS, [{**RUNNING, "egress": {"destinations": 23, "blocked": 1, "model_apis": 1, "shadow_ai": 1}}], [])
    title, pairs = model.detail_pairs(DESTINATIONS)
    assert dict(pairs)["Sites"] == "23 contacted, 1 blocked · AI: 1 model API, 1 shadow AI"
    rows = [value for label, value in pairs if label == "Destination"]
    assert rows == [
        "api.openai.com — shadow AI (Codex) · 3 requests · /usr/bin/curl",
        "api.anthropic.com — model provider (Claude Code) · 5 requests",
        "pastebin.com — blocked (paste site) · 0 requests, 4 refused",
    ]
    assert dict(pairs)["Model calls"] == "anthropic claude-haiku: 2 (1 failed)"
    assert dict(model.detail_pairs("unavailable: the daemon is down")[1])["Destinations"] == "unavailable: the daemon is down"
    assert "Destinations" not in dict(model.detail_pairs()[1]) and "Destination" not in dict(model.detail_pairs()[1])
    many = {"destinations": [{"host": f"h{i}.example", "kind": "other"} for i in range(15)]}
    assert dict(model.detail_pairs(many)[1])["Destinations"] == "+3 more: defenseclaw sandbox destinations myapp-claude-7f3a"
    assert dict(model.detail_pairs({})[1])["Destinations"] == "none reached yet"


@pytest.mark.asyncio
async def test_the_sandbox_detail_shows_its_destinations_at_80x24(fetch, monkeypatch) -> None:
    app = DefenseClawTUI(config=_config())
    shown: list[Any] = []

    async def push_screen_wait(screen: Any) -> Any:
        shown.append(screen)
        return None

    monkeypatch.setattr(app, "push_screen_wait", push_screen_wait)
    async with app.run_test(size=(80, 24)):
        await app._refresh_sandbox_snapshot(render=False)  # noqa: SLF001
        app.sandbox_model.view = "sandboxes"
        app.sandbox_model.cursor = 0
        app.sandbox_model.detail_open = True
        await app._open_sandbox_detail()  # noqa: SLF001
    pairs = shown[0].model.pairs
    assert ("Destination", "api.openai.com — shadow AI (Codex) · 3 requests · /usr/bin/curl") in pairs


def test_a_failed_refresh_keeps_the_last_good_snapshot() -> None:
    model = _model()
    model.fetched_at = datetime.now(timezone.utc) - timedelta(seconds=90)
    model.set_error("the DefenseClaw daemon is not reachable")
    assert len(model.rows) == 3
    assert model.state() == "ready"
    assert "last good snapshot (last update 1m ago)" in model.stale_note()


@pytest.mark.parametrize(
    ("status", "error", "state", "text"),
    [
        (None, "", "waiting", "Loading sandboxes"),
        (None, "the DefenseClaw daemon is not reachable", "unreachable", "not answering"),
        ({"enabled": False}, "", "off", "defenseclaw sandbox setup"),
        (
            {"enabled": True, "available": False, "reason": "OpenShell gateway is down"},
            "",
            "unavailable",
            "OpenShell gateway is down",
        ),
    ],
)
def test_headline_explains_each_state(status, error, state, text) -> None:
    model = SandboxesPanelModel()
    if status is not None:
        model.set_snapshot(status, [], [])
    if error:
        model.set_error(error)
    assert model.state() == state
    assert text in model.headline()


def test_admin_status_line() -> None:
    model = SandboxesPanelModel()
    model.set_snapshot(
        {
            **STATUS,
            "admin": {"configured": True, "authority": "authoritative", "detail": "openshell.admin is authoritative"},
        },
        [],
        [],
    )
    assert model.admin_line() == "Organization policy: openshell.admin is authoritative"


# --- the live feed -------------------------------------------------------------


def test_a_block_toast_names_the_host_without_the_first_requests_port() -> None:
    # An unblockable block holds the host on every port, and the toast is
    # once per host: ":80" of a plain-HTTP request that came first said the
    # block stopped there (PR 1022 review of fix 4).
    model = _model()
    notices = model.add_events([{**BLOCKED, "port": 80}], now=100.0)
    assert [n.message for n in notices] == [
        "✗ webhook.site blocked in myapp-claude-7f3a (exfil destination). Sandboxes panel (7): u to unblock"
    ]


def test_events_are_deduplicated_by_sequence_and_toast_once() -> None:
    model = _model()
    notices = model.add_events([ALLOWED, BLOCKED, PRIVATE], now=100.0)
    assert [n.message for n in notices] == [
        "✗ webhook.site blocked in myapp-claude-7f3a (exfil destination). Sandboxes panel (7): u to unblock"
    ]
    assert model.last_seq == 6
    # A replay of the same events adds nothing.
    assert model.add_events([BLOCKED, PRIVATE], now=101.0) == []
    assert len(model.feed) == 3
    # The same destination blocked again soon does not toast again.
    again = {**BLOCKED, "seq": 7}
    assert model.add_events([again], now=100.0 + TOAST_DEDUPE_SECONDS - 1) == []
    later = {**BLOCKED, "seq": 8}
    assert len(model.add_events([later], now=100.0 + TOAST_DEDUPE_SECONDS + 1)) == 1


def test_a_restarted_daemon_resets_the_resume_point() -> None:
    model = _model()
    model.add_events([{**ALLOWED, "seq": 500}], toast=False)
    assert model.last_seq == 500
    # The daemon restarted: its counter starts over on the new live stream.
    notices = model.add_events([{**BLOCKED, "seq": 1}], live=True, now=1.0)
    assert model.last_seq == 1 and len(notices) == 1
    # A buffered read still skips what it has seen.
    assert model.add_events([{**BLOCKED, "seq": 1}]) == []


def test_a_feed_that_started_over_is_read_from_its_start() -> None:
    model = _model()
    last = {**ALLOWED, "seq": 40, "time": "2026-09-27T12:00:00Z"}
    model.add_events([last], toast=False)
    # The daemon still holds the resume point, or only newer events pushed it out.
    assert model.resume_point_lost([last, {**BLOCKED, "seq": 41}]) is False
    assert model.resume_point_lost([{**BLOCKED, "seq": 45}]) is False
    # A restarted daemon numbers from one again: nothing at or after 40, or
    # another event under that number.
    assert model.resume_point_lost([]) is True
    assert model.resume_point_lost([{**BLOCKED, "seq": 40, "time": "2026-09-27T13:00:00Z"}]) is True
    model.reset_resume_point()
    assert model.last_seq == 0 and model.resume_point_lost([]) is False


def test_backlog_replay_never_toasts() -> None:
    model = _model()
    assert model.add_events([BLOCKED], toast=False) == []
    assert model.last_seq == 5


def test_a_dropped_marker_does_not_swallow_the_event_after_it() -> None:
    model = SandboxesPanelModel()
    model.add_events([{"seq": 10, "kind": "dropped", "message": "12 events were skipped"}, {**ALLOWED, "seq": 10}])
    assert [row.kind for row in model.feed] == ["dropped", "egress.allowed"]
    assert model.last_seq == 10


def test_asks_toast_and_leave_when_resolved() -> None:
    model = _model()
    notices = model.add_events(
        [
            {
                "seq": 20,
                "kind": "approval.requested",
                "sandbox": "myapp-claude-7f3a",
                "approval_id": "ask-1",
                "host": "host.openshell.internal",
                "port": 5432,
                # triage.go's sentence, as the daemon sends it.
                "message": "the sandbox asks to reach port 5432 on your machine",
            }
        ]
    )
    assert [n.message for n in notices] == [
        "? myapp-claude-7f3a: the sandbox asks to reach port 5432 on your machine. "
        "Sandboxes panel (7): press a to review"
    ]
    model.add_events([{"seq": 21, "kind": "approval.resolved", "approval_id": "ask-1"}])
    assert model.asks == ()


def test_ask_rows_show_the_daemons_sentence_once() -> None:
    model = SandboxesPanelModel()
    model.add_events(
        [
            {"seq": 1, "kind": "approval.requested", "sandbox": "x", "message": "the sandbox asks to reach 10.0.0.5"},
            {"seq": 2, "kind": "approval.requested", "sandbox": "x", "host": "10.0.0.5", "port": 22},
        ]
    )
    summaries = [row.summary for row in model.feed]
    assert summaries == ["the sandbox asks to reach 10.0.0.5", "asks to reach 10.0.0.5:22"]
    assert all(summary.count("asks to reach") == 1 for summary in summaries)


def test_a_planted_repository_raises_a_toast() -> None:
    model = _model()
    notices = model.add_events(
        [
            {
                "seq": 30,
                "kind": "finding",
                "sandbox": "myapp-claude-7f3a",
                "reason": "nested_repo",
                "message": "⚠ quarantined a new git repository at vendor/x",
            }
        ]
    )
    assert notices[0].level == "warn" and "quarantined a new git repository" in notices[0].message


def test_activity_rows_render_plain_lines() -> None:
    model = _model()
    model.add_events(
        [
            ALLOWED,
            BLOCKED,
            PRIVATE,
            {
                "seq": 9,
                "kind": "tool.blocked",
                "sandbox": "x",
                "tool": "Bash",
                "reason": "DC-TOOL-1: deletes your home folder",
            },
        ]
    )
    model.view = "activity"
    rows = model.data_table_rows()
    # A tool block has its own glyph: u lifts only blocked destinations (✗).
    assert rows[0][2:] == ("⊘", "Bash blocked: DC-TOOL-1: deletes your home folder")
    assert rows[1][2:] == ("✗", "10.0.0.5:22 (private network)")
    assert rows[2][2:] == ("✗", "webhook.site (exfil destination)  (u unblocks)")
    assert rows[3][2:] == ("✓", "registry.npmjs.org")
    assert model.data_table_columns() == ("Time", "Sandbox", "", "Event")


# What the daemon sends (manager/egress.go, watch.go, hooks.go).
PROXY_BLOCK = {
    "seq": 50,
    "kind": "egress.blocked",
    "sandbox": "myapp-claude-7f3a",
    "host": "webhook.site",
    "category": "webhook_catcher",
    "reason": "Webhook catchers record every request sent to them for whoever holds the URL, "
    "a common exfiltration sink.",
    "unblockable": True,
    "message": "✗ webhook.site (webhook_catcher)",
}
OPENSHELL_BLOCK = {
    "seq": 51,
    "kind": "egress.blocked",
    "sandbox": "myapp-claude-7f3a",
    "host": "www.iana.org",
    "reason": "transparent_tcp_policy_denied",
    "message": "✗ www.iana.org (direct connection denied by OpenShell)",
}
TOOL_BLOCK = {
    "seq": 52,
    "kind": "tool.blocked",
    "sandbox": "myapp-claude-7f3a",
    "tool": "Bash",
    "reason": "DefenseClaw policy blocked this action (rule E2E-SANDBOX-MARKER: E2E sandbox marker command). "
    "Do not retry it in another form.",
    "message": "✗ Bash blocked by DefenseClaw: E2E-SANDBOX-MARKER (E2E sandbox marker command)",
}


def test_a_blocked_large_upload_names_its_threshold() -> None:
    model = _model()
    model.add_events(
        [
            {
                "seq": 60,
                "kind": "egress.blocked",
                "sandbox": "myapp-claude-7f3a",
                "host": "files.example.net",
                "category": "large_upload",
                "reason": "This sandbox tried to send more than 10 MiB to a destination it had not contacted before.",
                "unblockable": True,
                "severity": "HIGH",
            }
        ]
    )
    model.view = "activity"
    assert [row[3] for row in model.data_table_rows()] == [
        "files.example.net (large upload blocked: this sandbox tried to send more than 10 MiB to a destination "
        "it had not contacted before)  (u unblocks)"
    ]
    model.cursor = 0
    pairs = dict(model.detail_pairs()[1])
    assert pairs["Category"] == "large upload" and pairs["Reason"].startswith("This sandbox tried to send more than 10 MiB")


def test_an_https_and_an_http_refusal_of_one_host_read_apart() -> None:
    # PR 1022 live retest N3: after a cut, the two refusals read as one line
    # twice. The port shows unless it is 443.
    refusal = "This destination is blocked since this sandbox tried to send more than 1 MiB to it."
    model = _model()
    model.add_events(
        [
            {
                "seq": 61,
                "kind": "egress.blocked",
                "sandbox": "s",
                "host": "httpbin.org",
                "port": 443,
                "category": "large_upload",
                "reason": refusal,
            },
            {
                "seq": 62,
                "kind": "egress.blocked",
                "sandbox": "s",
                "host": "httpbin.org",
                "port": 80,
                "category": "large_upload",
                "reason": refusal,
            },
        ]
    )
    model.view = "activity"
    why = "(large upload blocked: this destination is blocked since this sandbox tried to send more than 1 MiB to it)"
    assert sorted(row[3] for row in model.data_table_rows()) == [f"httpbin.org {why}", f"httpbin.org:80 {why}"]


def test_host_port_brackets_an_ipv6_literal_with_its_port() -> None:
    # PR 1022 review of N3: "fd00:ec2::254:80" is another address.
    assert host_port("fd00:ec2::254", 80) == "[fd00:ec2::254]:80"
    assert host_port("fd00:ec2::254", 443) == "fd00:ec2::254"
    assert host_port("[::1]", 8080) == "[::1]:8080"
    assert host_port("example.com", 80) == "example.com:80"


def test_feed_rows_use_plain_labels_and_no_advice_for_the_agent() -> None:
    model = _model()
    model.add_events([PROXY_BLOCK, OPENSHELL_BLOCK, TOOL_BLOCK])
    model.view = "activity"
    events = [row[3] for row in model.data_table_rows()]
    assert events == [
        "Bash blocked by DefenseClaw rule E2E-SANDBOX-MARKER: E2E sandbox marker command",
        "www.iana.org (no OpenShell rule allows it)",
        "webhook.site (webhook catcher)  (u unblocks)",
    ]
    assert all("_" not in event and "ask the user" not in event for event in events)
    model.cursor = 0
    pairs = dict(model.detail_pairs()[1])
    assert pairs["Reason"] == (
        "DefenseClaw policy blocked this action (rule E2E-SANDBOX-MARKER: E2E sandbox marker command)"
    )
    model.cursor = 2
    pairs = dict(model.detail_pairs()[1])
    assert pairs["Category"] == "webhook catcher" and pairs["Reason"].startswith("Webhook catchers record")
    # The unblock dialog says why the destination was blocked.
    assert model.block_explanation("myapp-claude-7f3a", "webhook.site").startswith("Webhook catchers record")
    assert model.block_explanation("myapp-claude-7f3a", "www.iana.org") == "no OpenShell rule allows it"
    # The sandbox's last tool block reads the same.
    model.set_snapshot(
        STATUS, [{**RUNNING, "hooks": {"tool_calls": 3, "tool_blocked": 1, "last_blocked": TOOL_BLOCK["reason"]}}], []
    )
    model.view = "sandboxes"
    model.cursor = 0
    assert dict(model.detail_pairs()[1])["Last tool block"] == (
        "DefenseClaw policy blocked this action (rule E2E-SANDBOX-MARKER: E2E sandbox marker command)"
    )
    # A gateway from before GAP-1885 still reads without its advice.
    old = "Blocked by DefenseClaw rule E2E-SANDBOX-MARKER: E2E sandbox marker command. Try another approach."
    assert verdict_reason(old) == "Blocked by DefenseClaw rule E2E-SANDBOX-MARKER: E2E sandbox marker command"


@pytest.mark.asyncio
async def test_the_unblock_dialog_says_why_it_was_blocked(fetch, monkeypatch) -> None:
    app = DefenseClawTUI(config=_config())
    screens: list[Any] = []

    async def push_screen_wait(screen: Any) -> Any:
        screens.append(screen)
        return None

    monkeypatch.setattr(app, "push_screen_wait", push_screen_wait)
    async with app.run_test(size=(160, 44)):
        await app._refresh_sandbox_snapshot(render=False)  # noqa: SLF001
        app.sandbox_model.add_events([PROXY_BLOCK])
        await app._sandbox_unblock("myapp-claude-7f3a", "webhook.site")  # noqa: SLF001
    assert screens[0].subtitle == (
        "DefenseClaw blocked this destination: Webhook catchers record every request sent to them "
        "for whoever holds the URL, a common exfiltration sink."
    )


def test_tool_blocks_do_not_offer_unblock() -> None:
    model = _model()
    model.add_events([PROXY_BLOCK, TOOL_BLOCK])
    model.view = "activity"
    model.cursor = 0  # the tool block
    assert model.unblock_offered() is False
    assert "u unblock" not in model.keys_line()
    action = model.handle_key("u")
    assert action.kind == "hint" and "guardrail rules decide tool calls" in action.hint
    assert "defenseclaw policy" in dict(model.detail_pairs()[1])["Decided by"]
    model.cursor = 1  # the blocked destination
    assert model.unblock_offered() is True
    assert "u unblock" in model.keys_line()


def test_a_defenseclaw_ask_is_on_the_feed() -> None:
    """A tool call DefenseClaw asked the user to confirm reads as an ask, and counts."""
    model = _model()
    model.add_events(
        [
            {
                "seq": 53,
                "kind": "tool.asked",
                "sandbox": "myapp-claude-7f3a",
                "tool": "Bash",
                "reason": "DefenseClaw rule C2-WEBHOOK-SITE asks you to confirm this.",
                "message": "? DefenseClaw asked you to confirm Bash: DefenseClaw rule C2-WEBHOOK-SITE asks you to confirm this.",
            }
        ]
    )
    model.view = "activity"
    model.cursor = 0
    event = model.selected_event()
    assert event is not None and event.glyph == "?"
    assert event.summary.startswith("Bash asked for your confirmation: DefenseClaw rule C2-WEBHOOK-SITE")
    assert model.unblock_offered() is False
    assert "defenseclaw policy" in dict(model.detail_pairs()[1])["Decided by"]
    model.set_snapshot(STATUS, [{**RUNNING, "hooks": {"tool_calls": 3, "tool_blocked": 1, "tool_asked": 1}}], [])
    model.view = "sandboxes"
    model.cursor = 0
    assert dict(model.detail_pairs()[1])["Tool calls"] == "3 (1 blocked, 1 asked)"


@pytest.mark.asyncio
async def test_the_tool_block_detail_offers_no_unblock_key(fetch, monkeypatch) -> None:
    app = DefenseClawTUI(config=_config())
    shown: list[Any] = []

    async def push_screen_wait(screen: Any) -> Any:
        shown.append(screen)
        return None

    monkeypatch.setattr(app, "push_screen_wait", push_screen_wait)
    async with app.run_test(size=(160, 44)):
        await app._refresh_sandbox_snapshot(render=False)  # noqa: SLF001
        app.sandbox_model.add_events([PROXY_BLOCK, TOOL_BLOCK])
        app.sandbox_model.view = "activity"
        app.sandbox_model.cursor = 0
        app.sandbox_model.detail_open = True
        await app._open_sandbox_detail()  # noqa: SLF001
        app.sandbox_model.cursor = 1
        app.sandbox_model.detail_open = True
        await app._open_sandbox_detail()  # noqa: SLF001
    assert (shown[0].keys, shown[0].keys_hint) == (frozenset(), "Keys: Esc close")
    assert shown[1].keys == frozenset({"u"}) and "u unblock" in shown[1].keys_hint


# --- keys --------------------------------------------------------------------


def test_t_cycles_the_views() -> None:
    model = _model()
    assert [model.handle_key("t").kind for _ in range(3)] == ["view"] * 3
    assert model.view == "sandboxes"


def test_u_unblocks_the_latest_block_from_the_sandboxes_view() -> None:
    model = _model()
    model.add_events([ALLOWED, BLOCKED, PRIVATE])
    model.cursor = 1  # myapp-claude-7f3a
    action = model.handle_key("u")
    assert action == SandboxPanelAction("unblock", sandbox="myapp-claude-7f3a", host="webhook.site")


def test_u_on_a_selected_feed_row_and_on_a_closed_destination() -> None:
    model = _model()
    model.add_events([ALLOWED, BLOCKED, PRIVATE])
    model.view = "activity"
    model.cursor = 0  # newest first: the private destination
    action = model.handle_key("u")
    assert action.kind == "hint" and "private networks" in action.hint
    model.cursor = 1
    assert model.handle_key("u").host == "webhook.site"


def test_u_respects_the_organization_policy() -> None:
    model = _model(admin=AdminPolicy(allow_unblock=False))
    model.add_events([BLOCKED])
    action = model.handle_key("u")
    assert action.kind == "hint" and ADMIN_MESSAGE in action.hint


def test_u_without_blocks() -> None:
    assert _model().handle_key("u").hint == "No blocked destination in fix-tests to unblock."
    empty = SandboxesPanelModel()
    empty.set_snapshot(STATUS, [], [])
    assert empty.handle_key("u").hint == "No blocked destination to unblock."


def test_ask_keys() -> None:
    model = _model()
    first = model.handle_key("a")
    assert first.kind == "view" and model.view == "asks" and "a to approve" in first.hint
    assert model.handle_key("a") == SandboxPanelAction("approve", sandbox="myapp-claude-7f3a", approval_id="ask-1")
    assert model.handle_key("x") == SandboxPanelAction("reject", sandbox="myapp-claude-7f3a", approval_id="ask-1")
    model.set_snapshot(STATUS, [RUNNING], [PUBLIC_ASK])
    # The selected ask went away with the refresh: the first key says so,
    # the next acts on the ask now selected.
    assert "no longer waiting" in model.handle_key("A").hint
    assert model.handle_key("A").always is True
    # r refreshes in every view, as in every other panel; it never rejects.
    assert model.handle_key("r").kind == "refresh"
    model.view = "sandboxes"
    assert model.handle_key("r").kind == "refresh"
    assert model.handle_key("x").kind == "none"


def test_always_approve_respects_the_organization_policy() -> None:
    model = _model(admin=AdminPolicy(allow_unblock=False))
    model.view = "asks"
    assert ADMIN_MESSAGE in model.handle_key("A").hint
    assert model.handle_key("a").kind == "approve"


def test_no_asks() -> None:
    model = SandboxesPanelModel()
    model.set_snapshot(STATUS, [RUNNING], [])
    assert model.handle_key("a").hint == "No asks are waiting."


def test_no_asks_text_holds_for_every_pack() -> None:
    # Doors into the machine ask in every pack; balanced also asks for hosts
    # off its allowlist and strict for every destination (packs approvals mode).
    model = SandboxesPanelModel()
    model.set_snapshot(STATUS, [RUNNING], [])
    model.view = "asks"
    text = model.empty_state()
    assert text.startswith("No asks are waiting.") and "Only" not in text
    assert "private-network address" in text and "balanced" in text and "strict" in text
    # A port on this machine drafts no proposal (OpenShell denies the mapping
    # itself), so the text must not promise that one asks (R2-47).
    assert "localhost ports" not in text and "Ports on this machine never ask" in text
    assert "--host-port" in text


@pytest.mark.parametrize(
    ("cursor", "key", "kind", "hint"),
    [
        (1, "U", "undo", ""),
        (1, "R", "review", ""),
        (1, "s", "stop", ""),
        (1, "d", "delete", ""),
        (1, "c", "connect", ""),
        (1, "P", "hint", "works on your folder directly; R reviews its changes and U undoes them"),
        # A copy: P pulls its work back, and U reverts the last pull --apply
        # (it needs no snapshot).
        (0, "P", "pull", ""),
        (0, "U", "undo", ""),
        (0, "R", "hint", "P brings its work back after showing it (defenseclaw sandbox pull fix-tests)"),
        (2, "U", "hint", "no snapshot to undo"),
        (2, "s", "hint", "is not running"),
        (2, "c", "connect", ""),
    ],
)
def test_sandbox_keys(cursor: int, key: str, kind: str, hint: str) -> None:
    model = _model()
    model.cursor = cursor
    action = model.handle_key(key)
    assert action.kind == kind
    assert hint in action.hint
    if kind not in {"hint"}:
        assert action.sandbox == model.rows[cursor].name


def test_sandbox_keys_from_the_asks_view_use_the_asks_sandbox() -> None:
    model = _model()
    model.view = "asks"
    assert model.handle_key("R") == SandboxPanelAction("review", sandbox="myapp-claude-7f3a")


def test_a_copy_row_offers_pull_instead_of_review() -> None:
    model = _model()
    model.cursor = 0  # fix-tests works on a copy
    line = model.keys_line()
    assert "P pull" in line and "R review" not in line and "U undo" in line and len(line) <= 78
    model.cursor = 1  # myapp mounts its folder
    assert "R review" in model.keys_line() and "P pull" not in model.keys_line()
    # Lowercase p is not the panel's: it still opens Policies.
    assert model.handle_key("p").handled is False


def test_new_run_wrappers_and_detail() -> None:
    model = _model()
    assert model.handle_key("n").kind == "new_run"
    assert model.handle_key("w").kind == "wrappers"
    assert model.handle_key("enter").kind == "detail" and model.detail_open
    assert model.handle_key("x").kind == "none"
    assert model.handle_key("escape").kind == "detail" and not model.detail_open


def test_unknown_keys_fall_through_so_panel_hotkeys_work() -> None:
    model = _model()
    for key in ("1", "8", "0", "q", "tab"):
        assert model.handle_key(key).handled is False


def test_empty_panel_has_no_selection_hint() -> None:
    model = SandboxesPanelModel()
    model.set_snapshot(STATUS, [], [])
    assert "Select a sandbox first" in model.handle_key("s").hint
    assert "No sandboxes yet" in model.empty_state()


# --- rendering helpers -------------------------------------------------------


def test_sandbox_table_rows() -> None:
    model = _model()
    assert model.data_table_columns()[:6] == ("Name", "Phase", "Harness", "Pack/Profile", "Mode", "Up")
    # "Tool calls" says what the numbers are (a bare "1/57" under "Tools" did not).
    assert model.data_table_columns()[8] == "Tool calls"
    assert model.data_table_columns(compact=True)[5] == "Tool calls"
    row = model.data_table_rows()[1]
    assert row == (
        "myapp-claude-7f3a",
        "ready",
        "Claude Code",
        "open",
        "mount",
        "1h02m",
        "23",
        "1",
        "57 (1 blocked)",
        "tamper, nested repo",
    )
    assert model.data_table_rows(compact=True)[1][5] == "57 (1 blocked)"
    assert model.data_table_rows()[0][8] == "0"  # fix-tests made no tool call
    model.view = "asks"
    assert model.data_table_rows() == (
        (
            "myapp-claude-7f3a",
            "port on this machine",
            "host.openshell.internal:5432",
            "/usr/bin/psql",
            "risky",
            "a port on this machine",
        ),
    )


def test_detail_pairs_for_each_view() -> None:
    model = _model()
    model.cursor = 1
    title, pairs = model.detail_pairs()
    labels = dict(pairs)
    assert title == "Sandbox myapp-claude-7f3a"
    assert labels["Project"] == "/home/dev/code/myapp → /work/myapp (mount)"
    assert labels["Last tool block"] == "rm -rf ~ (DC-TOOL-1)"
    model.view = "asks"
    title, pairs = model.detail_pairs()
    assert title == "Ask" and dict(pairs)["Decide"].startswith("a approve")
    assert "x reject" in dict(pairs)["Decide"] and "r reject" not in dict(pairs)["Decide"]
    model.add_events([BLOCKED])
    model.view = "activity"
    assert dict(model.detail_pairs()[1])["Unblock"] == "press u"


def test_review_and_undo_text() -> None:
    review = {
        "summary": "8 files changed (+212 −37)",
        "risk_line": "package.json#scripts.postinstall, .envrc",
        "report": {
            "files_changed": 8,
            "insertions": 212,
            "deletions": 37,
            "flags": [
                {"label": "package.json#scripts.postinstall", "severity": "high", "detail": "runs on npm install"}
            ],
            "changes": [{"status": "M", "path": "src/app.ts"}],
        },
    }
    pairs = dict(review_pairs(review))
    assert pairs["Summary"] == "8 files changed (+212 −37)"
    assert pairs["⚠ HIGH"] == "package.json#scripts.postinstall: runs on npm install"
    assert pairs["  M"] == "src/app.ts"
    assert review_pairs({}) == (("Summary", "No changes since the session started."),)
    preview = {"result": {"changes": [{"path": f"f{i}"} for i in range(7)], "nested_repos": ["vendor/x"]}}
    text = undo_preview_text(preview)
    assert "7 file(s) go back to the snapshot: f0, f1, f2, f3, f4 and 2 more." in text
    assert "1 planted git repository removed." in text
    assert "nothing to do" in undo_preview_text({"result": {}})


def test_admin_policy_from_config() -> None:
    cfg = SimpleNamespace(
        deployment_mode="managed_enterprise",
        openshell=SimpleNamespace(admin=SimpleNamespace(allow_unblock=False, allowed_harnesses=["codex"])),
    )
    policy = admin_policy_from_config(cfg)
    assert policy.unblock_refused and policy.authoritative and policy.allowed_harnesses == ("codex",)
    assert admin_policy_from_config(None) == AdminPolicy()


# --- the launch dialog -------------------------------------------------------


def test_launch_values_build_the_run_argv(tmp_path: Path) -> None:
    project = tmp_path / "myapp"
    project.mkdir()
    launch = SandboxLaunchValues(
        harness="codex", folder=str(project), name="fix-tests", copy=True, safe=True, profile="strict"
    ).build()
    assert launch == SandboxLaunch(
        ("sandbox", "run", "codex", "--name", "fix-tests", "--copy", "--safe", "--profile", "strict"),
        str(project),
        f"sandbox run codex in {project}",
    )
    # The run names the command the user types (sandboxcli.ResolveHarness takes it).
    plain = SandboxLaunchValues(harness="claudecode", folder=str(project), profile="(pack default)").build()
    assert plain.argv == ("sandbox", "run", "claude")
    assert plain.display == f"sandbox run claude in {project}"


def test_launch_values_refuse_bad_folders(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path / "home"
    (home / "code").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    with pytest.raises(SandboxLaunchError, match="not a folder"):
        SandboxLaunchValues(folder=str(home / "missing")).build()
    # Go's words (workspace.ValidateSource), one reason each.
    for folder, reason in (
        (home, "it is your home directory"),
        (tmp_path, "it contains your home directory"),
        (Path("/"), "it is a top-level system directory"),
    ):
        with pytest.raises(SandboxLaunchError, match=reason):
            SandboxLaunchValues(folder=str(folder)).build()
    with pytest.raises(SandboxLaunchError, match="choose a project folder"):
        SandboxLaunchValues(folder="").build()
    with pytest.raises(SandboxLaunchError, match="unknown profile"):
        SandboxLaunchValues(folder=str(home / "code"), profile="loose").build()
    assert SandboxLaunchValues(folder=str(home / "code")).build().cwd == str(home / "code")


def test_harness_choices_follow_config_and_organization() -> None:
    # Every harness the Go tree runs (harness.Names()), the defaults first.
    everything = harness_choices(())
    assert everything[:2] == (("Claude Code", "claudecode"), ("Codex", "codex"))
    assert {name for _label, name in everything} == {
        "amp", "antigravity", "claudecode", "codex", "copilot", "cursor",
        "devin", "hermes", "kiro", "omnigent", "opencode", "openhands",
    }  # fmt: skip
    assert harness_choices(("codex",))[:2] == (("Codex", "codex"), ("Claude Code", "claudecode"))
    assert harness_choices((), ("codex",)) == (("Codex", "codex"),)
    assert harness_choices(("opencode",), ("opencode", "codex"))[0] == ("OpenCode", "opencode")


# --- the app -----------------------------------------------------------------


def _config() -> SimpleNamespace:
    return SimpleNamespace(
        gateway=SimpleNamespace(api_port=18970, host="127.0.0.1", token="token"),
        openshell=SimpleNamespace(enabled=True, harnesses=["claudecode"], wrappers=[], admin=None),
    )


@pytest.fixture
def fetch(monkeypatch: pytest.MonkeyPatch):
    payload = sandbox_panel.SandboxFetch(status=STATUS, sandboxes=[RUNNING, STOPPED], approvals=[ASK])
    monkeypatch.setattr(sandbox_panel, "fetch_sandbox_snapshot", lambda _config: payload)
    # Never open a real activity stream from tests, nor ask a daemon for
    # a detail's destinations.
    monkeypatch.setattr(DefenseClawTUI, "_ensure_sandbox_stream", lambda self: None)

    async def destinations(self, name: str) -> Any:
        return DESTINATIONS

    monkeypatch.setattr(DefenseClawTUI, "_fetch_sandbox_destinations", destinations)
    monkeypatch.setattr(sandbox_panel, "openshell_sandboxes_supported", lambda os_name=None: True)
    return payload


@pytest.mark.asyncio
async def test_the_panel_loads_and_renders_the_snapshot(fetch) -> None:
    app = DefenseClawTUI(config=_config())
    async with app.run_test(size=(160, 44)) as pilot:
        await pilot.press("7")
        await app._refresh_sandbox_snapshot(render=True)  # noqa: SLF001 - app-level polling contract
        await pilot.pause()
        assert app.active_panel == "sandboxes"
        body = app._sandbox_body_text()  # noqa: SLF001
        assert "READY" in body and "2 running" in body
        assert app._table_rows[0][0] == "myapp-claude-7f3a"  # noqa: SLF001
        await pilot.press("t")
        await pilot.pause()
        assert app.sandbox_model.view == "activity"


@pytest.mark.asyncio
async def test_a_failed_poll_keeps_rows_and_says_so(fetch, monkeypatch) -> None:
    app = DefenseClawTUI(config=_config())
    async with app.run_test(size=(160, 44)) as pilot:
        await app._refresh_sandbox_snapshot(render=False)  # noqa: SLF001
        monkeypatch.setattr(
            sandbox_panel,
            "fetch_sandbox_snapshot",
            lambda _config: sandbox_panel.SandboxFetch(error="the DefenseClaw daemon is not reachable"),
        )
        await app._refresh_sandbox_snapshot(render=False)  # noqa: SLF001
        await pilot.pause()
        assert len(app.sandbox_model.rows) == 2
        assert "not reachable" in app._sandbox_body_text()  # noqa: SLF001


@pytest.mark.asyncio
async def test_shift_u_reaches_undo_and_u_reaches_unblock(fetch, monkeypatch) -> None:
    app = DefenseClawTUI(config=_config())
    seen: list[str] = []
    monkeypatch.setattr(app, "_apply_sandbox_action", lambda action: seen.append(action.kind) or True)
    async with app.run_test(size=(160, 44)) as pilot:
        await pilot.press("7")
        await app._refresh_sandbox_snapshot(render=True)  # noqa: SLF001
        app.sandbox_model.add_events([BLOCKED])
        await pilot.pause()
        app.query_one("#command-input").blur()
        await pilot.press("U")
        await pilot.press("u")
        await pilot.pause()
    assert seen[-2:] == ["undo", "unblock"]


class _Calls:
    def __init__(self, result: Any = None) -> None:
        self.calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []
        self.result = result if result is not None else {}

    async def __call__(self, method: str, *args: Any, **kwargs: Any) -> Any:
        self.calls.append((method, args, kwargs))
        return self.result


def _screen_answers(*answers: Any):
    queue = list(answers)

    async def push_screen_wait(_screen: Any) -> Any:
        return queue.pop(0)

    return push_screen_wait


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("choice", "expected"),
    [
        ("sandbox", ("unblock_sandbox_egress", ("webhook.site",), {"sandbox": "myapp-claude-7f3a", "always": False})),
        ("always", ("unblock_sandbox_egress", ("webhook.site",), {"sandbox": "", "always": True})),
        (None, None),
    ],
)
async def test_unblock_asks_for_the_scope(fetch, monkeypatch, choice, expected) -> None:
    app = DefenseClawTUI(config=_config())
    calls = _Calls({"message": "webhook.site unblocked for myapp-claude-7f3a"})
    monkeypatch.setattr(app, "_sandbox_call", calls)
    # "always" then confirms, as approve-always does.
    monkeypatch.setattr(app, "push_screen_wait", _screen_answers(choice, "always"))
    async with app.run_test(size=(160, 44)):
        await app._sandbox_unblock("myapp-claude-7f3a", "webhook.site")  # noqa: SLF001
    assert calls.calls == ([expected] if expected else [])


@pytest.mark.asyncio
async def test_always_approve_confirms_first(fetch, monkeypatch) -> None:
    fetch.approvals = [PUBLIC_ASK]
    app = DefenseClawTUI(config=_config())
    calls = _Calls({"message": "approved; OpenShell applies it once the sandbox's hooks are quiet", "persisted": True})
    toasts: list[tuple[str, str]] = []
    monkeypatch.setattr(app, "_sandbox_call", calls)
    monkeypatch.setattr(app, "push_screen_wait", _screen_answers("cancel", "always"))
    monkeypatch.setattr(app, "notify_toast", lambda level, message: toasts.append((level, message)))
    action = SandboxPanelAction("approve", sandbox="myapp-claude-7f3a", approval_id="ask-2", always=True)
    async with app.run_test(size=(160, 44)):
        await app._refresh_sandbox_snapshot(render=False)  # noqa: SLF001
        await app._sandbox_decide(action, approve=True)  # noqa: SLF001
        assert calls.calls == []
        await app._sandbox_decide(action, approve=True)  # noqa: SLF001
    assert calls.calls == [("decide_sandbox_approval", ("ask-2",), {"approve": True, "always": True})]
    # Its own confirmation, not the one-time approve's words (R2-56).
    assert toasts[-1] == (
        "success",
        "always allowed www.example.com (saved to openshell.egress.unblocked); "
        "approved; OpenShell applies it once the sandbox's hooks are quiet",
    )


@pytest.mark.parametrize("raw", [ASK, PRIVATE_ASK, {**PUBLIC_ASK, "allowed_ips": ["10.0.0.0/8"]}])
def test_always_is_not_offered_for_asks_that_open_one_sandbox_only(raw) -> None:
    model = SandboxesPanelModel()
    model.set_snapshot(STATUS, [RUNNING], [raw])
    model.view = "asks"
    ask = model.selected_ask()
    assert ask is not None and ask.always_refusal
    assert model.always_offered() is False
    action = model.handle_key("A")
    assert action.kind == "hint" and "press a to approve once" in action.hint
    assert "A always" not in model.keys_line()
    decide = dict(model.detail_pairs()[1])["Decide"]
    assert decide.startswith("a approve once") and "A always" not in decide
    assert model.handle_key("a").kind == "approve"


def test_always_is_offered_for_a_public_host() -> None:
    model = SandboxesPanelModel()
    model.set_snapshot(STATUS, [RUNNING], [PUBLIC_ASK])
    model.view = "asks"
    assert model.always_offered() is True
    assert "A always" in model.keys_line()
    assert dict(model.detail_pairs()[1])["Decide"] == "a approve · A always approve · x reject"


@pytest.mark.asyncio
async def test_a_private_ask_never_asks_to_confirm_always(fetch, monkeypatch) -> None:
    fetch.approvals = [PRIVATE_ASK]
    app = DefenseClawTUI(config=_config())
    calls = _Calls()
    toasts: list[tuple[str, str]] = []
    monkeypatch.setattr(app, "_sandbox_call", calls)
    monkeypatch.setattr(app, "push_screen_wait", lambda _screen: pytest.fail("a confirmation was shown"))
    monkeypatch.setattr(app, "notify_toast", lambda level, message: toasts.append((level, message)))
    action = SandboxPanelAction("approve", sandbox="myapp-claude-7f3a", approval_id="ask-3", always=True)
    async with app.run_test(size=(160, 44)):
        await app._refresh_sandbox_snapshot(render=False)  # noqa: SLF001
        await app._sandbox_decide(action, approve=True)  # noqa: SLF001
        app.sandbox_model.view = "asks"
        app._sync_sandbox_controls()  # noqa: SLF001
        assert app.query_one("#sandboxes-always").has_class("hidden")
        assert not app.query_one("#sandboxes-approve").has_class("hidden")
    assert calls.calls == []
    assert toasts[-1][0] == "warn" and "press a to approve once" in toasts[-1][1]


@pytest.mark.asyncio
async def test_undo_of_a_stopped_sandbox_previews_then_restores(fetch, monkeypatch) -> None:
    app = DefenseClawTUI(config=_config())
    calls = _Calls({"result": {"changes": [{"path": "a.txt"}]}})
    monkeypatch.setattr(app, "_sandbox_call", calls)
    monkeypatch.setattr(app, "push_screen_wait", _screen_answers("undo"))
    async with app.run_test(size=(160, 44)):
        await app._refresh_sandbox_snapshot(render=False)  # noqa: SLF001
        await app._sandbox_undo("docs")  # noqa: SLF001
    # Never stop=True: a sandbox that started meanwhile is refused, not
    # stopped past the command line's detached-run check.
    assert [(method, kwargs) for method, _args, kwargs in calls.calls] == [
        ("undo_sandbox", {"preview": True, "stop": False}),
        ("undo_sandbox", {"stop": False}),
    ]


@pytest.mark.asyncio
async def test_undo_of_a_running_sandbox_runs_the_command_line(fetch, monkeypatch) -> None:
    """Undo stops the sandbox first; the command line says what the stop ends
    (a detached run too) and asks, and the daemon's stop keeps the run's log."""
    app = DefenseClawTUI(config=_config())
    calls = _Calls()
    ran = _fake_terminal(monkeypatch, app)
    monkeypatch.setattr(app, "_sandbox_call", calls)
    monkeypatch.setattr(app, "push_screen_wait", lambda _screen: pytest.fail("the TUI asked instead of the CLI"))
    async with app.run_test(size=(160, 44)):
        await app._refresh_sandbox_snapshot(render=False)  # noqa: SLF001
        await app._sandbox_undo("myapp-claude-7f3a")  # noqa: SLF001
    assert calls.calls == []
    assert ran == [(["/opt/dc/defenseclaw-gateway", "sandbox", "undo", "myapp-claude-7f3a"], os.getcwd())]


@pytest.mark.asyncio
async def test_undo_of_a_copy_runs_the_command_line(fetch, monkeypatch) -> None:
    """A copy's undo reverts its last `pull --apply` with git on this machine;
    the command line previews it and asks (or says there is none)."""
    fetch.sandboxes = [RUNNING, STOPPED, {**COPY, "phase": "stopped"}]
    app = DefenseClawTUI(config=_config())
    calls = _Calls()
    ran = _fake_terminal(monkeypatch, app)
    monkeypatch.setattr(app, "_sandbox_call", calls)
    monkeypatch.setattr(app, "push_screen_wait", lambda _screen: pytest.fail("the TUI asked instead of the CLI"))
    async with app.run_test(size=(160, 44)):
        await app._refresh_sandbox_snapshot(render=False)  # noqa: SLF001
        await app._sandbox_undo("fix-tests")  # noqa: SLF001
    assert calls.calls == []
    assert ran == [(["/opt/dc/defenseclaw-gateway", "sandbox", "undo", "fix-tests"], os.getcwd())]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("choice", "flags"),
    [("review", []), ("apply", ["--apply"]), ("branch", ["--branch"]), ("cancel", None), (None, None)],
)
async def test_pull_shows_applies_or_branches_through_the_command_line(fetch, monkeypatch, choice, flags) -> None:
    fetch.sandboxes = [RUNNING, {**COPY, "project": "/home/dev/code/tests"}]
    app = DefenseClawTUI(config=_config())
    calls = _Calls()
    ran = _fake_terminal(monkeypatch, app)
    menus: list[Any] = []

    async def push_screen_wait(screen: Any) -> Any:
        menus.append(screen)
        return choice

    monkeypatch.setattr(app, "_sandbox_call", calls)
    monkeypatch.setattr(app, "push_screen_wait", push_screen_wait)
    async with app.run_test(size=(160, 44)):
        await app._refresh_sandbox_snapshot(render=False)  # noqa: SLF001
        await app._sandbox_pull("fix-tests")  # noqa: SLF001
    assert calls.calls == []
    assert [action.action_id for action in menus[0].actions] == ["review", "apply", "branch", "cancel"]
    assert "a copy of /home/dev/code/tests" in menus[0].subtitle
    argv = ["/opt/dc/defenseclaw-gateway", "sandbox", "pull", "fix-tests", *(flags or [])]
    assert ran == ([] if flags is None else [(argv, os.getcwd())])


@pytest.mark.asyncio
async def test_shift_p_pulls_a_copy_and_p_still_opens_policies(fetch, monkeypatch) -> None:
    fetch.sandboxes = [RUNNING, COPY]
    app = DefenseClawTUI(config=_config())
    seen: list[SandboxPanelAction] = []
    async with app.run_test(size=(160, 44)) as pilot:
        await pilot.press("7")
        await app._refresh_sandbox_snapshot(render=True)  # noqa: SLF001
        await pilot.pause()
        app.query_one("#command-input").blur()
        app.sandbox_model.cursor = 0  # fix-tests
        app._sync_sandbox_controls()  # noqa: SLF001
        # A copy: Pull and Undo, no Review.
        assert not app.query_one("#sandboxes-pull").has_class("hidden")
        assert not app.query_one("#sandboxes-undo").has_class("hidden")
        assert app.query_one("#sandboxes-review").has_class("hidden")
        assert app._sandbox_detail_keys()[0] == ("c", "s", "d", "U", "P", "u")  # noqa: SLF001
        apply = app._apply_sandbox_action  # noqa: SLF001

        def record(action: SandboxPanelAction) -> bool:
            if action.kind == "pull":
                seen.append(action)
                return True
            return apply(action)

        monkeypatch.setattr(app, "_apply_sandbox_action", record)
        await pilot.press("P")
        await pilot.pause()
        assert seen == [SandboxPanelAction("pull", sandbox="fix-tests")]
        await pilot.press("p")
        await pilot.pause()
        assert app.active_panel == "policies"


@pytest.mark.asyncio
async def test_a_new_run_on_a_microvm_gateway_locks_the_copy_box(fetch, monkeypatch) -> None:
    fetch.status = {**STATUS, "gateway": {**STATUS["gateway"], "driver": "vm"}}
    app = DefenseClawTUI(config=_config())
    screens: list[Any] = []

    async def push_screen_wait(screen: Any) -> Any:
        screens.append(screen)
        return None

    monkeypatch.setattr(app, "push_screen_wait", push_screen_wait)
    async with app.run_test(size=(160, 44)):
        await app._refresh_sandbox_snapshot(render=False)  # noqa: SLF001
        await app._sandbox_new_run()  # noqa: SLF001
        fetch.status = STATUS
        await app._refresh_sandbox_snapshot(render=False)  # noqa: SLF001
        await app._sandbox_new_run()  # noqa: SLF001
    assert screens[0].copy_only == "MicroVM sandboxes work on a copy; pull (P) brings the changes back."
    assert screens[1].copy_only == ""


@pytest.mark.asyncio
async def test_undo_with_nothing_to_undo_asks_nothing(fetch, monkeypatch) -> None:
    app = DefenseClawTUI(config=_config())
    calls = _Calls({"result": {"kind": "git", "head_before": "a", "head_after": "a"}})
    monkeypatch.setattr(app, "_sandbox_call", calls)
    monkeypatch.setattr(app, "push_screen_wait", lambda _screen: pytest.fail("confirmation shown"))
    async with app.run_test(size=(160, 44)):
        await app._sandbox_undo("docs")  # noqa: SLF001
    assert [method for method, _args, _kwargs in calls.calls] == ["undo_sandbox"]


def test_undo_is_empty_mirrors_go() -> None:
    from defenseclaw.tui.panels.sandboxes import undo_is_empty

    assert undo_is_empty({}) is True
    assert undo_is_empty({"result": {"head_before": "a", "head_after": "a"}}) is True
    assert undo_is_empty({"result": {"head_before": "a", "head_after": "b"}}) is False
    assert undo_is_empty({"result": {"nested_repos": ["vendor/x"]}}) is False
    assert undo_is_empty({"result": {"changes": [{"path": "a"}]}}) is False
    # UndoResult.Empty: what undo cannot restore does not count, the
    # bytecode caches it deletes do.
    assert undo_is_empty({"result": {"ignored": [NODE_MODULES]}}) is True
    assert undo_is_empty({"result": {"ignored": [PYCACHE]}}) is False
    # A directory the undo point keeps a copy of is restored (#944).
    assert undo_is_empty({"result": {"ignored": [{**NODE_MODULES, "restored": True}]}}) is False


# UndoResult.Ignored entries: a dependency folder with a host executable,
# which undo leaves as the session did, and a bytecode cache it deletes.
NODE_MODULES = {
    "path": "node_modules/",
    "added": 2,
    "modified": 1,
    "executables": ["node_modules/.bin/tool"],
    "executable_count": 3,
    "dependencies": True,
    "remedy": "delete it and reinstall the packages (for example `npm ci`)",
}
PYCACHE = {"path": "calc/__pycache__/", "added": 2, "removed": True}


def test_undo_preview_says_what_undo_cannot_restore() -> None:
    from defenseclaw.tui.services.sandbox_state import undo_done_text, undo_unrestored_lines

    preview = {"result": {"changes": [{"path": "a.txt"}], "ignored": [NODE_MODULES, PYCACHE]}}
    expected = (
        "undo cannot restore node_modules/ (3 files added or changed during the session, including .bin/tool "
        "and 2 more that run on this machine): delete it and reinstall the packages (for example `npm ci`)"
    )
    assert undo_unrestored_lines(preview) == (expected,)
    text = undo_preview_text(preview)
    assert "1 file(s) go back to the snapshot: a.txt." in text
    assert "Removes 2 files the session wrote to calc/__pycache__/ (a Python bytecode cache)." in text
    assert expected in text
    many = {"result": {"ignored": [{**NODE_MODULES, "path": f"d{i}/"} for i in range(10)]}}
    lines = undo_unrestored_lines(many)
    assert len(lines) == 9
    assert lines[-1] == "… and 2 more places undo cannot restore (`defenseclaw sandbox review` lists them)"
    assert undo_done_text({"summary": "restored 1 file", **preview}, "docs") == (
        "restored 1 file, except node_modules/ (undo cannot restore them)"
    )
    assert undo_done_text({}, "docs") == "docs: the project folder is back to its pre-session snapshot"


def test_undo_preview_names_the_kept_directories_it_restores() -> None:
    # openshell.workdir.undo_ignored: the undo point keeps a copy (#944).
    from defenseclaw.tui.services.sandbox_state import undo_done_text, undo_unrestored_lines

    kept = {**NODE_MODULES, "restored": True}
    over = {**NODE_MODULES, "path": "web/node_modules/", "over_cap": True}
    preview = {"result": {"ignored": [kept, over]}}
    lines = undo_unrestored_lines(preview)
    assert len(lines) == 1 and lines[0].startswith("undo cannot restore web/node_modules/")
    assert lines[0].endswith("(its copy would pass openshell.workdir.undo_ignored.max_mb)")
    assert "Restores node_modules/ from the copy the undo point keeps." in undo_preview_text(preview)
    assert undo_done_text({"summary": "restored 1 file", "result": {"ignored": [kept]}}, "docs") == (
        "restored 1 file (node_modules/ too, from the copy the undo point keeps)"
    )


@pytest.mark.asyncio
async def test_undo_with_only_changes_it_cannot_restore_lists_them(fetch, monkeypatch) -> None:
    """Not "nothing to undo": the session changed host executables undo leaves in place."""
    from defenseclaw.tui.screens.sandbox_detail import SandboxDetailScreen

    app = DefenseClawTUI(config=_config())
    calls = _Calls({"result": {"kind": "git", "ignored": [NODE_MODULES]}})
    toasts: list[tuple[str, str]] = []
    shown: list[Any] = []

    async def push_screen_wait(screen: Any) -> Any:
        shown.append(screen)
        return None

    monkeypatch.setattr(app, "_sandbox_call", calls)
    monkeypatch.setattr(app, "notify_toast", lambda level, message: toasts.append((level, message)))
    monkeypatch.setattr(app, "push_screen_wait", push_screen_wait)
    async with app.run_test(size=(160, 44)):
        await app._sandbox_undo("docs")  # noqa: SLF001
    assert [method for method, _args, _kwargs in calls.calls] == ["undo_sandbox"]
    assert toasts[-1][0] == "warn" and "cannot restore 1 place(s)" in toasts[-1][1]
    assert len(shown) == 1 and isinstance(shown[0], SandboxDetailScreen)
    values = [value for _label, value in shown[0].model.pairs]
    assert any("node_modules/" in value and ".bin/tool" in value and "npm ci" in value for value in values)


@pytest.mark.asyncio
async def test_undo_confirmation_and_result_name_what_it_cannot_restore(fetch, monkeypatch) -> None:
    from defenseclaw.tui.widgets.action_menu import ActionMenuScreen

    app = DefenseClawTUI(config=_config())
    calls = _Calls({"summary": "restored 1 file", "result": {"changes": [{"path": "a.txt"}], "ignored": [NODE_MODULES]}})
    toasts: list[tuple[str, str]] = []
    shown: list[Any] = []

    async def push_screen_wait(screen: Any) -> Any:
        shown.append(screen)
        return "undo"

    monkeypatch.setattr(app, "_sandbox_call", calls)
    monkeypatch.setattr(app, "notify_toast", lambda level, message: toasts.append((level, message)))
    monkeypatch.setattr(app, "push_screen_wait", push_screen_wait)
    async with app.run_test(size=(160, 44)):
        await app._sandbox_undo("docs")  # noqa: SLF001
    assert isinstance(shown[0], ActionMenuScreen)
    assert "undo cannot restore node_modules/" in shown[0].subtitle
    assert toasts[-1] == ("warn", "restored 1 file, except node_modules/ (undo cannot restore them)")


@pytest.mark.asyncio
async def test_delete_runs_the_command_line_which_asks(fetch, monkeypatch) -> None:
    """The command line looks for copy-mode work that never came back and
    forgets its own state for the sandbox; the daemon does neither."""
    app = DefenseClawTUI(config=_config())
    calls = _Calls({"deleted": True})
    ran = _fake_terminal(monkeypatch, app)
    monkeypatch.setattr(app, "_sandbox_call", calls)
    monkeypatch.setattr(app, "push_screen_wait", lambda _screen: pytest.fail("the TUI asked instead of the CLI"))
    async with app.run_test(size=(160, 44)):
        await app._sandbox_delete("fix-tests")  # noqa: SLF001
    assert calls.calls == []
    assert ran == [(["/opt/dc/defenseclaw-gateway", "sandbox", "delete", "fix-tests"], os.getcwd())]


@pytest.mark.asyncio
async def test_api_refusals_become_plain_toasts(fetch, monkeypatch) -> None:
    from defenseclaw.gateway import SandboxAPIError

    app = DefenseClawTUI(config=_config())
    toasts: list[tuple[str, str]] = []

    async def refuse(*_args: Any, **_kwargs: Any) -> Any:
        raise SandboxAPIError("admin_violation", f"{ADMIN_MESSAGE}: unblocking is not allowed", status=403)

    monkeypatch.setattr(app, "_sandbox_call", refuse)
    monkeypatch.setattr(app, "notify_toast", lambda level, message: toasts.append((level, message)))
    reject = SandboxPanelAction("reject", sandbox="docs", approval_id="ask-1")
    async with app.run_test(size=(160, 44)):
        await app._guarded_sandbox_action(app._sandbox_decide(reject, approve=False))  # noqa: SLF001
    assert toasts[-1] == ("warn", f"{ADMIN_MESSAGE}: unblocking is not allowed")
    assert app._sandbox_action_running is False  # noqa: SLF001


def _fake_terminal(monkeypatch, app, returncode: int = 0):
    ran: list[tuple[list[str], str]] = []

    @contextlib.contextmanager
    def suspend():
        # App.suspend points stdout and stderr at the terminal it hands over
        # (UTF-8 once main() has run); a buffer stands in for it. Without one,
        # headless Textual forwards the handover banner to the test process's
        # own stdout, a cp1252 pipe on Windows runners.
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            yield

    def run(argv, cwd=None, check=False):
        ran.append((argv, cwd))
        return SimpleNamespace(returncode=returncode)

    monkeypatch.setattr(app, "suspend", suspend)
    monkeypatch.setattr(sandbox_panel.subprocess, "run", run)
    monkeypatch.setattr("defenseclaw.gateway.resolve_gateway_binary", lambda: "/opt/dc/defenseclaw-gateway")
    monkeypatch.setattr("builtins.input", lambda _prompt="": "")
    return ran


@pytest.mark.asyncio
async def test_connect_hands_the_terminal_to_the_harness(fetch, monkeypatch) -> None:
    app = DefenseClawTUI(config=_config())
    ran = _fake_terminal(monkeypatch, app)
    async with app.run_test(size=(160, 44)):
        await app._sandbox_connect("myapp-claude-7f3a")  # noqa: SLF001
    assert ran == [(["/opt/dc/defenseclaw-gateway", "sandbox", "connect", "myapp-claude-7f3a"], os.getcwd())]


@pytest.mark.asyncio
async def test_new_run_uses_the_dialog_and_the_project_folder(fetch, monkeypatch, tmp_path: Path) -> None:
    app = DefenseClawTUI(config=_config())
    ran = _fake_terminal(monkeypatch, app, returncode=3)
    launch = SandboxLaunch(("sandbox", "run", "codex", "--copy"), str(tmp_path), "sandbox run codex")
    monkeypatch.setattr(app, "push_screen_wait", _screen_answers(launch))
    async with app.run_test(size=(160, 44)):
        await app._refresh_sandbox_snapshot(render=False)  # noqa: SLF001
        await app._sandbox_new_run()  # noqa: SLF001
    assert ran == [(["/opt/dc/defenseclaw-gateway", "sandbox", "run", "codex", "--copy"], str(tmp_path))]


@pytest.mark.asyncio
async def test_a_terminal_that_cannot_be_handed_over_says_what_to_run(fetch, monkeypatch) -> None:
    from textual.app import SuspendNotSupported

    app = DefenseClawTUI(config=_config())
    toasts: list[tuple[str, str]] = []

    @contextlib.contextmanager
    def suspend():
        raise SuspendNotSupported("headless")
        yield  # pragma: no cover

    monkeypatch.setattr(app, "suspend", suspend)
    monkeypatch.setattr(app, "notify_toast", lambda level, message: toasts.append((level, message)))
    monkeypatch.setattr("defenseclaw.gateway.resolve_gateway_binary", lambda: "/opt/dc/defenseclaw-gateway")
    async with app.run_test(size=(160, 44)):
        code = app._run_sandbox_terminal(SandboxLaunch(("sandbox", "connect", "x"), "/p", "x"))  # noqa: SLF001
    assert code is None
    assert toasts[-1] == (
        "warn",
        "This terminal cannot be handed over; run it in a shell: cd /p && defenseclaw sandbox connect x",
    )


@pytest.mark.asyncio
async def test_the_setup_wizard_runs_in_the_terminal(fetch, monkeypatch) -> None:
    from defenseclaw.tui.panels.setup import SetupWizard
    from defenseclaw.tui.services.setup_state import SetupCommandIntent

    app = DefenseClawTUI(config=_config())
    ran = _fake_terminal(monkeypatch, app)
    monkeypatch.setattr(app, "push_screen_wait", _screen_answers(True))
    args = ("sandbox", "setup", "--non-interactive", "--harness", "claudecode", "--no-wrappers")
    intent = SetupCommandIntent(label="setup Sandbox", args=args, origin="setup-wizard", risk="setup", terminal=True)
    async with app.run_test(size=(160, 44)):
        app.setup_model.wizard_status[SetupWizard.SANDBOX] = "running..."
        await app._confirm_and_run_intent(intent)  # noqa: SLF001
    assert ran == [(["/opt/dc/defenseclaw-gateway", *args], os.getcwd())]
    assert app.setup_model.wizard_status[SetupWizard.SANDBOX] == "done"


@pytest.mark.asyncio
async def test_the_wrapper_toggle_runs_enable_or_disable(fetch, monkeypatch) -> None:
    app = DefenseClawTUI(config=_config())
    commands: list[tuple[str, tuple[str, ...]]] = []

    async def run_command(binary: str, args: tuple[str, ...], *, display_name: str | None = None) -> None:
        commands.append((binary, args))

    monkeypatch.setattr(app, "_run_command", run_command)
    monkeypatch.setattr(app, "push_screen_wait", _screen_answers("claudecode", "claudecode"))
    async with app.run_test(size=(160, 44)):
        await app._sandbox_wrappers_menu()  # noqa: SLF001
        app.sandbox_model.wrappers = ("claudecode",)
        await app._sandbox_wrappers_menu()  # noqa: SLF001
    assert commands == [
        ("defenseclaw", ("sandbox", "enable", "claude")),
        ("defenseclaw", ("sandbox", "disable", "claude")),
    ]


@pytest.mark.asyncio
async def test_the_wrapper_toggle_does_not_enable_while_sandboxes_are_off(fetch, monkeypatch) -> None:
    """GAP-1219: a wrapper while sandboxes are off breaks the plain command."""
    app = DefenseClawTUI(config=_config())
    commands: list[tuple[str, ...]] = []
    menus: list[tuple[str, ...]] = []
    toasts: list[str] = []

    async def run_command(binary: str, args: tuple[str, ...], *, display_name: str | None = None) -> None:
        commands.append(args)

    async def answer(screen):
        menus.append(tuple(action.description for action in screen.actions))
        return "claudecode"

    monkeypatch.setattr(app, "_run_command", run_command)
    monkeypatch.setattr(app, "push_screen_wait", answer)
    monkeypatch.setattr(app, "notify_toast", lambda level, message: toasts.append(message))
    async with app.run_test(size=(160, 44)):
        monkeypatch.setattr(app.sandbox_model, "state", lambda: "off")
        await app._sandbox_wrappers_menu()  # noqa: SLF001
        app.sandbox_model.wrappers = ("claudecode",)
        await app._sandbox_wrappers_menu()  # noqa: SLF001
    assert "Sandboxes are off; run the Sandbox wizard (0 Setup) first" in menus[0]
    assert toasts == ["Sandboxes are off; run the Sandbox wizard (0 Setup) first."]
    assert commands == [("sandbox", "disable", "claude")]


@pytest.mark.asyncio
async def test_stream_events_raise_toasts_on_any_panel(fetch, monkeypatch) -> None:
    app = DefenseClawTUI(config=_config())
    toasts: list[tuple[str, str]] = []
    monkeypatch.setattr(app, "notify_toast", lambda level, message: toasts.append((level, message)))
    async with app.run_test(size=(160, 44)):
        assert app.active_panel == "overview"
        app._on_sandbox_events([BLOCKED], True)  # noqa: SLF001
    assert toasts and "webhook.site blocked" in toasts[0][1]


def test_the_stream_loop_resumes_after_the_last_sequence(monkeypatch) -> None:
    """One pass of the background loop: backlog without toasts, then follow."""

    app = DefenseClawTUI(config=_config())
    delivered: list[tuple[list[dict[str, Any]], bool]] = []

    class Stream:
        closed = False

        def __iter__(self):
            yield {"seq": 9, "kind": "egress.blocked", "host": "h", "unblockable": True}
            app._sandbox_stream_stop.set()  # noqa: SLF001

        def close(self) -> None:
            self.closed = True

    opened: list[int] = []

    class Client:
        def sandbox_activity(self, **_kwargs):
            return [{"seq": 8, "kind": "egress.allowed", "host": "a"}]

        def open_sandbox_activity_stream(self, since: int = 0, **_kwargs):
            opened.append(since)
            return Stream()

        def close(self) -> None:
            pass

    monkeypatch.setattr(sandbox_panel, "sandbox_client", lambda _config, timeout=5: Client())

    def deliver(callback, *args):
        if callback == app._on_sandbox_events:  # noqa: SLF001
            events, toast = args
            delivered.append((events, toast))
            app.sandbox_model.add_events(events, toast=toast)
        return True

    monkeypatch.setattr(app, "_deliver_from_thread", deliver)
    app._sandbox_stream_loop()  # noqa: SLF001
    assert opened == [8]
    assert [(events[0]["seq"], toast) for events, toast in delivered] == [(8, False), (9, True)]


def test_the_stream_loop_reads_a_restarted_daemons_feed_from_its_start(monkeypatch) -> None:
    app = DefenseClawTUI(config=_config())
    app.sandbox_model.add_events([{**ALLOWED, "seq": 40}], toast=False)
    reads: list[int] = []
    opened: list[int] = []

    class Stream:
        def __iter__(self):
            app._sandbox_stream_stop.set()  # noqa: SLF001
            return iter(())

        def close(self) -> None:
            pass

    class Client:
        def sandbox_activity(self, since: int = 0, **_kwargs):
            reads.append(since)
            # The restarted daemon has published two events since it started.
            return [event for event in ({**ALLOWED, "seq": 1}, {**BLOCKED, "seq": 2}) if event["seq"] > since]

        def open_sandbox_activity_stream(self, since: int = 0, **_kwargs):
            opened.append(since)
            return Stream()

        def close(self) -> None:
            pass

    monkeypatch.setattr(sandbox_panel, "sandbox_client", lambda _config, timeout=5: Client())

    def deliver(callback, *args):
        if callback == app._on_sandbox_events:  # noqa: SLF001
            events, toast = args
            app.sandbox_model.add_events(events, toast=toast)
        elif callback == app._on_sandbox_resume:  # noqa: SLF001
            callback(*args)
        return True

    monkeypatch.setattr(app, "_deliver_from_thread", deliver)
    app._sandbox_stream_loop()  # noqa: SLF001
    assert reads == [39, 0]
    assert opened == [2]
    assert any(row.host == "webhook.site" for row in app.sandbox_model.feed)


@pytest.mark.asyncio
async def test_the_launch_dialog_returns_a_run_and_refuses_a_bad_folder(tmp_path: Path) -> None:
    from defenseclaw.tui.screens.sandbox_launch import SandboxLaunchScreen
    from textual.app import App
    from textual.widgets import Checkbox, Input, Static

    project = tmp_path / "proj"
    project.mkdir()
    results: list[Any] = []

    class Host(App[None]):
        def on_mount(self) -> None:
            self.push_screen(
                SandboxLaunchScreen((("Codex", "codex"), ("Claude Code", "claudecode")), folder=str(tmp_path / "gone")),
                results.append,
            )

    app = Host()
    async with app.run_test(size=(100, 24)) as pilot:
        await pilot.pause()
        screen = app.screen
        await pilot.press("ctrl+s")
        await pilot.pause()
        assert app.screen is screen, "a missing folder keeps the dialog open"
        assert "is not a folder" in str(screen.query_one("#sandbox-launch-status", Static).render())
        screen.query_one("#sandbox-launch-folder", Input).value = str(project)
        screen.query_one("#sandbox-launch-copy", Checkbox).value = True
        await pilot.press("ctrl+s")
        await pilot.pause()
    assert results == [
        SandboxLaunch(("sandbox", "run", "codex", "--copy"), str(project), f"sandbox run codex in {project}")
    ]


def test_unreachable_hooks_are_an_alert_and_a_toast() -> None:
    row = decode_sandbox(
        {
            **RUNNING,
            "hooks": {"unreachable": True, "unreachable_reason": "no hook arrived in 90s", "ingress_refused": 3},
        }
    )
    assert row is not None
    assert "hooks unreachable" in row.alert_badge
    assert any(
        "DefenseClaw hooks are not reaching the daemon; every tool call is being blocked (no hook arrived in 90s)"
        in alert
        and "defenseclaw sandbox doctor" in alert
        for alert in row.alerts
    )
    refused = decode_sandbox({**RUNNING, "hooks": {"ingress_refused": 2}})
    assert refused is not None and any("refused 2 hook request(s)" in alert for alert in refused.alerts)

    model = _model()
    unreachable = (
        "⚠ DefenseClaw hooks are not reaching the daemon; every tool call is being blocked (why). "
        "Run: defenseclaw sandbox doctor"
    )
    notices = model.add_events(
        [
            {"seq": 40, "kind": "finding", "sandbox": "x", "reason": "hooks_unreachable", "message": unreachable},
            {
                "seq": 41,
                "kind": "finding",
                "sandbox": "x",
                "reason": "hooks_restored",
                "message": "DefenseClaw hooks reach the daemon again",
            },
        ]
    )
    assert [n.level for n in notices] == ["error", "success"]
    assert notices[0].message.startswith("x: DefenseClaw hooks are not reaching the daemon")


def test_failed_hook_calls_are_an_alert() -> None:
    from defenseclaw.tui.panels.sandboxes import decode_activity

    row = decode_sandbox({**RUNNING, "hooks": {"hook_failed": 3, "last_hook_failure": "HTTP 429 Too Many Requests"}})
    assert (
        "3 hook calls failed, so the harness's actions were blocked (hooks fail closed); "
        "DefenseClaw last answered HTTP 429 Too Many Requests"
    ) in row.alerts
    assert "hook errors" in row.alert_badge
    one = decode_sandbox({**RUNNING, "hooks": {"hook_failed": 1}})
    assert "1 hook call failed, so the harness's action was blocked (hooks fail closed)" in one.alerts
    assert decode_sandbox(RUNNING).hook_failed == 0
    event = decode_activity({"seq": 1, "kind": "hook.failed", "message": "✗ a hook call failed (HTTP 429)"})
    assert event.glyph == "✗" and event.summary == "a hook call failed (HTTP 429)"


# --- review fixes: unblock state, scope and policy ------------------------------


UNBLOCKED_MYAPP = {
    "seq": 30,
    "kind": "egress.unblocked",
    "sandbox": "myapp-claude-7f3a",
    "host": "webhook.site",
    "reason": "sandbox",
    "message": "unblocked webhook.site for sandbox myapp-claude-7f3a",
}


def test_an_unblock_event_lifts_the_block_it_covers() -> None:
    model = _model()
    elsewhere = {**BLOCKED, "seq": 7, "sandbox": "fix-tests"}
    model.add_events([BLOCKED, elsewhere])
    assert model.total_count() == 1 + 2  # the ask plus two blocked destinations
    model.add_events([{**UNBLOCKED_MYAPP, "host": "WEBHOOK.site."}])
    assert [(row.sandbox, row.host) for row in model.current_blocks()] == [("fix-tests", "webhook.site")]
    model.cursor = 1  # myapp-claude-7f3a
    action = model.handle_key("u")
    assert action.kind == "hint" and "No blocked destination in myapp-claude-7f3a" in action.hint
    assert model.total_count() == 1 + 1
    model.view = "activity"
    rows = model.data_table_rows()
    assert any(row[3] == "webhook.site (exfil destination)  (unblocked)" for row in rows)
    model.cursor = len(rows) - 1  # the oldest: myapp's lifted block
    assert "already unblocked for myapp-claude-7f3a" in model.handle_key("u").hint
    # "always" lifts it everywhere; a later block is offered again.
    model.add_events([{**UNBLOCKED_MYAPP, "seq": 31, "sandbox": "", "reason": "always"}])
    assert model.current_blocks() == ()
    model.add_events([{**BLOCKED, "seq": 32}])
    assert [row.seq for row in model.current_blocks()] == [32]


def test_blocks_of_deleted_sandboxes_are_history() -> None:
    model = _model()
    model.add_events([{**BLOCKED, "sandbox": "gone"}])
    assert model.current_blocks() == () and model.total_count() == 1
    assert model.block_notice() == ("", "", "")


def test_u_never_reaches_into_another_sandbox() -> None:
    model = _model()
    model.add_events([BLOCKED])  # blocked in myapp-claude-7f3a
    model.cursor = 0  # fix-tests is selected
    assert model.unblock_target() is None
    action = model.handle_key("u")
    assert action.kind == "hint"
    assert action.hint == (
        "No blocked destination in fix-tests. webhook.site was blocked in myapp-claude-7f3a: "
        "select that sandbox, or press t for Activity."
    )
    assert model.block_notice() == (
        "✗ webhook.site (exfil destination)",
        " in myapp-claude-7f3a",
        "select it, then u",
    )
    model.cursor = 1
    assert model.block_notice()[2] == "u unblocks"
    # Asks use the ask's sandbox.
    model.view = "asks"
    assert model.handle_key("u") == SandboxPanelAction("unblock", sandbox="myapp-claude-7f3a", host="webhook.site")


def test_u_names_the_organization_policy_when_unblocking_is_refused() -> None:
    # allow_unblock: false makes the daemon report every block as not unblockable.
    model = _model(admin=AdminPolicy(allow_unblock=False))
    model.add_events([{**BLOCKED, "unblockable": False}])
    # The refusal says what to do next, as the always-approve one does.
    refusal = (
        f"Unblocking is {ADMIN_MESSAGE}; ask your DefenseClaw administrator (openshell.admin.allow_unblock is off)."
    )
    model.cursor = 1
    assert model.handle_key("u").hint == refusal
    model.cursor = 0
    assert model.handle_key("u").hint == refusal
    model.view = "activity"
    assert model.handle_key("u").hint == refusal
    assert dict(model.detail_pairs()[1])["Unblock"].startswith(ADMIN_MESSAGE + "; ask your DefenseClaw administrator")
    assert ADMIN_MESSAGE in model.block_notice()[2]


def test_a_saved_unblock_the_organization_turned_off_says_so() -> None:
    cfg = SimpleNamespace(
        openshell=SimpleNamespace(
            admin=SimpleNamespace(allow_unblock=False, allowed_harnesses=[]),
            egress=SimpleNamespace(unblocked=["*.webhook.site", "pastebin.com"]),
        )
    )
    model = _model()
    model.set_config(cfg)
    model.add_events([{**BLOCKED, "host": "pastebin.com", "unblockable": False}])
    model.view = "activity"
    assert model.data_table_rows()[0][3].endswith("(your saved unblock is off: openshell.admin.allow_unblock)")
    assert model.block_notice()[2].startswith("your saved unblock is off")
    assert dict(model.detail_pairs()[1])["Unblock"].startswith("your saved unblock is off")


def test_hint_bar_keys_fit_one_line_at_80_columns() -> None:
    from defenseclaw.tui.models import HintState
    from defenseclaw.tui.widgets.hint_bar import HintEngine

    engine = HintEngine()
    for view, must in (("sandboxes", "U undo"), ("activity", "u unblock"), ("asks", "x reject")):
        line = engine.hint_for(HintState(active_panel="sandboxes", panel_view=view))
        assert must in line and len(line) <= 78, (view, len(line))
        assert "r reject" not in line


@pytest.mark.asyncio
@pytest.mark.parametrize(("size", "view"), [((80, 24), "sandboxes"), ((80, 24), "asks"), ((100, 30), "sandboxes")])
async def test_the_list_and_the_asks_stay_on_screen(fetch, size, view) -> None:
    fetch.sandboxes = [RUNNING, STOPPED, COPY]
    app = DefenseClawTUI(config=_config())
    async with app.run_test(size=size) as pilot:
        await pilot.press("7")
        await app._refresh_sandbox_snapshot(render=True)  # noqa: SLF001
        # Blocks in two sandboxes and alerts on two of them.
        app.sandbox_model.add_events([BLOCKED, {**BLOCKED, "seq": 7, "host": "paste.example"}, PRIVATE])
        app.sandbox_model.view = view
        app._render_chrome()  # noqa: SLF001
        await pilot.pause()
        table = app.query_one("#panel-table")
        body = app._sandbox_body_text()  # noqa: SLF001
        assert body.count("\n") + 1 <= 5, body
        rows = len(app.sandbox_model.data_table_rows(compact=size[0] < 100))
        # The header row plus every row fits between the controls and the bottom chrome.
        assert table.region.y + 1 + rows <= size[1] - 4, (table.region, rows)
        assert table.region.height >= 1 + rows
        if size[0] < 100 and view == "sandboxes":
            assert "Pack/Profile" not in app.sandbox_model.data_table_columns(compact=True)


# --- review fixes: detail keys, review scrolling, confirmations -----------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("view", "key", "expected"),
    [
        ("asks", "a", SandboxPanelAction("approve", sandbox="myapp-claude-7f3a", approval_id="ask-1")),
        ("asks", "x", SandboxPanelAction("reject", sandbox="myapp-claude-7f3a", approval_id="ask-1")),
        ("activity", "u", SandboxPanelAction("unblock", sandbox="myapp-claude-7f3a", host="webhook.site")),
        ("sandboxes", "U", SandboxPanelAction("undo", sandbox="myapp-claude-7f3a")),
    ],
)
async def test_detail_keys_close_the_window_and_act_on_its_row(fetch, monkeypatch, view, key, expected) -> None:
    app = DefenseClawTUI(config=_config())
    seen: list[SandboxPanelAction] = []
    async with app.run_test(size=(160, 44)):
        await app._refresh_sandbox_snapshot(render=False)  # noqa: SLF001
        app.sandbox_model.add_events([BLOCKED])
        app.sandbox_model.view = view
        app.sandbox_model.cursor = 0
        app.sandbox_model.detail_open = True
        monkeypatch.setattr(app, "push_screen_wait", _screen_answers(key))
        monkeypatch.setattr(app, "_apply_sandbox_action", lambda action: seen.append(action) or True)
        await app._open_sandbox_detail()  # noqa: SLF001
    assert seen == [expected]
    assert app.sandbox_model.detail_open is False


@pytest.mark.asyncio
async def test_the_detail_window_returns_its_keys_and_scrolls() -> None:
    from defenseclaw.tui.screens.sandbox_detail import SandboxDetailScreen
    from textual.app import App
    from textual.containers import VerticalScroll

    results: list[Any] = []
    pairs = [("Warning", "the secret scan skipped 2 large files")] + [("  M", f"src/f{i}.ts") for i in range(40)]

    class Host(App[None]):
        def on_mount(self) -> None:
            self.push_screen(SandboxDetailScreen("Review x", pairs, keys=("a", "U")), results.append)

    app = Host()
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        scroll = app.screen.query_one("#sandbox-detail-scroll", VerticalScroll)
        close = app.screen.query_one("#sandbox-detail-close")
        assert scroll.max_scroll_y > 0
        assert close.region.bottom <= 24, "the Close button stays on screen"
        await pilot.press("pagedown")
        await pilot.pause()
        assert scroll.scroll_y > 0
        await pilot.press("U")
        await pilot.pause()
    assert results == ["U"]


def test_review_puts_warnings_and_findings_before_the_files() -> None:
    review = {
        "summary": "30 files changed",
        "report": {
            "files_changed": 30,
            "flags": [{"label": ".envrc", "severity": "high"}],
            "findings": [{"title": "AWS key", "path": "config.js"}],
            "changes": [{"status": "M", "path": f"src/f{i}.ts"} for i in range(30)],
            "warnings": ["the secret scan skipped 2 large files"],
        },
    }
    labels = [label for label, _value in review_pairs(review)]
    first_file = labels.index("  M")
    assert labels.index("Warning") < first_file
    assert labels.index("⚠ HIGH") < first_file and labels.index("Finding") < first_file
    assert review_pairs(review)[-1] == ("", "… and 5 more (defenseclaw sandbox review --diff)")


@pytest.mark.asyncio
async def test_stop_asks_first_then_runs_the_command_line(fetch, monkeypatch) -> None:
    """The command line asks while a detached run the stop would end is going;
    the daemon's stop marks it interrupted and keeps its log for `sandbox logs`."""
    app = DefenseClawTUI(config=_config())
    calls = _Calls()
    ran = _fake_terminal(monkeypatch, app)
    monkeypatch.setattr(app, "_sandbox_call", calls)
    monkeypatch.setattr(app, "push_screen_wait", _screen_answers("cancel", "stop"))
    async with app.run_test(size=(160, 44)):
        await app._sandbox_stop("myapp-claude-7f3a")  # noqa: SLF001
        assert ran == []
        await app._sandbox_stop("myapp-claude-7f3a")  # noqa: SLF001
    assert calls.calls == []
    assert ran == [(["/opt/dc/defenseclaw-gateway", "sandbox", "stop", "myapp-claude-7f3a"], os.getcwd())]


@pytest.mark.asyncio
async def test_always_unblock_confirms_and_a_done_unblock_is_no_longer_offered(fetch, monkeypatch) -> None:
    app = DefenseClawTUI(config=_config())
    calls = _Calls({"message": "unblocked webhook.site for every sandbox"})
    monkeypatch.setattr(app, "_sandbox_call", calls)
    monkeypatch.setattr(app, "push_screen_wait", _screen_answers("always", "cancel", "sandbox"))
    async with app.run_test(size=(160, 44)):
        await app._refresh_sandbox_snapshot(render=False)  # noqa: SLF001
        app.sandbox_model.add_events([BLOCKED])
        await app._sandbox_unblock("myapp-claude-7f3a", "webhook.site")  # noqa: SLF001
        assert calls.calls == [], "cancelling the confirmation unblocks nothing"
        await app._sandbox_unblock("myapp-claude-7f3a", "webhook.site")  # noqa: SLF001
        assert app.sandbox_model.current_blocks() == ()
    assert calls.calls == [
        ("unblock_sandbox_egress", ("webhook.site",), {"sandbox": "myapp-claude-7f3a", "always": False})
    ]


@pytest.mark.asyncio
async def test_the_unblock_menu_shows_what_each_scope_does() -> None:
    from defenseclaw.tui.widgets.action_menu import ActionMenuScreen, MenuAction
    from textual.app import App
    from textual.widgets import Button

    actions = (
        MenuAction("sandbox", "Only in x", "Lifts the block for this sandbox until it is deleted."),
        MenuAction("always", "In every sandbox (always)…", "Adds the host to openshell.egress.unblocked (asks first)."),
    )

    class Host(App[None]):
        def on_mount(self) -> None:
            self.push_screen(ActionMenuScreen("Unblock h", actions, show_descriptions=True))

    app = Host()
    async with app.run_test(size=(80, 30)) as pilot:
        await pilot.pause()
        rows = list(app.screen.query(Button))
        assert all(row.region.height >= 4 for row in rows), [row.region for row in rows]


# --- review fixes: the launch dialog ----------------------------------------------


@pytest.mark.asyncio
async def test_the_launch_dialog_fits_80_columns_and_shows_why_it_refuses(tmp_path: Path) -> None:
    from defenseclaw.tui.screens.sandbox_launch import SandboxLaunchScreen
    from textual.app import App
    from textual.widgets import Select, Static

    class Host(App[None]):
        def on_mount(self) -> None:
            self.push_screen(SandboxLaunchScreen((("Codex", "codex"),), folder=""))

    app = Host()
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        screen = app.screen
        dialog = screen.query_one("#sandbox-launch-dialog")
        assert dialog.region.right <= 80
        assert isinstance(app.focused, Select), app.focused
        await pilot.press("ctrl+s")
        await pilot.pause()
        status = screen.query_one("#sandbox-launch-status", Static)
        assert str(status.render()) == "Choose a project folder."
        assert status.region.height >= 1 and status.region.bottom <= 24


@pytest.mark.asyncio
async def test_on_a_microvm_gateway_the_copy_box_is_ticked_and_locked(tmp_path: Path) -> None:
    from defenseclaw.tui.screens.sandbox_launch import SandboxLaunchScreen
    from textual.app import App
    from textual.containers import VerticalScroll
    from textual.widgets import Checkbox, Input, Static

    project = tmp_path / "proj"
    project.mkdir()
    note = "MicroVM sandboxes work on a copy; pull (P) brings the changes back."
    results: list[Any] = []

    class Host(App[None]):
        def on_mount(self) -> None:
            self.push_screen(SandboxLaunchScreen((("Codex", "codex"),), folder="", copy_only=note), results.append)

    app = Host()
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        screen = app.screen
        box = screen.query_one("#sandbox-launch-copy", Checkbox)
        assert box.value is True and box.disabled is True
        shown = screen.query_one("#sandbox-launch-copy-note", Static)
        assert str(shown.render()) == note
        screen.query_one("#sandbox-launch-dialog", VerticalScroll).scroll_to_widget(shown, animate=False)
        # The scroll lands after a screen refresh, which a slow runner may not reach in one pause.
        for _ in range(20):
            await pilot.pause()
            if shown.region.bottom <= 24:
                break
        assert shown.region.right <= 80 and 0 < shown.region.bottom <= 24
        screen.query_one("#sandbox-launch-folder", Input).value = str(project)
        box.value = False  # the box is locked: a run there always works on a copy
        await pilot.press("ctrl+s")
        await pilot.pause()
    assert results == [
        SandboxLaunch(("sandbox", "run", "codex", "--copy"), str(project), f"sandbox run codex in {project}")
    ]


def test_the_launch_dialog_starts_in_a_sandbox_project(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "myapp"
    project.mkdir()
    app = DefenseClawTUI(config=_config())
    app.sandbox_model.set_snapshot(STATUS, [{**RUNNING, "project": str(project)}, STOPPED], [])
    app.sandbox_model.cursor = 1  # docs: no project, so the newest with one
    assert app._sandbox_default_folder() == str(project)  # noqa: SLF001
    app.sandbox_model.set_snapshot(STATUS, [], [])
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(home)
    assert app._sandbox_default_folder() == ""  # noqa: SLF001 - never the home folder


# --- manual round 2 -------------------------------------------------------------


@pytest.mark.skipif(os.name != "posix", reason="POSIX SIGINT regression; os.kill(SIGINT) ends the process on Windows")
@pytest.mark.asyncio
async def test_ctrl_c_during_the_handover_never_reaches_the_tui(fetch, monkeypatch) -> None:
    """R2-46: Ctrl-C at the child's prompt reaches the TUI too (same foreground group).

    asyncio's handler cancels the app's main task on the first one, so the
    TUI quit once the child ended. While the terminal is handed over the
    TUI ignores it; at "Press Enter" it returns to the TUI.
    """
    import signal
    import time

    app = DefenseClawTUI(config=_config())
    ran = _fake_terminal(monkeypatch, app)
    reached_the_tui: list[int] = []
    after_prompt_ctrl_c: list[bool] = []

    def child(argv, cwd=None, check=False):
        ran.append((argv, cwd))
        os.kill(os.getpid(), signal.SIGINT)
        time.sleep(0.05)  # the handler runs here
        return SimpleNamespace(returncode=0)

    def prompt(_text: str = "") -> str:
        os.kill(os.getpid(), signal.SIGINT)
        time.sleep(0.05)
        after_prompt_ctrl_c.append(True)
        return ""

    monkeypatch.setattr(sandbox_panel.subprocess, "run", child)
    monkeypatch.setattr("builtins.input", prompt)
    async with app.run_test(size=(160, 44)):

        def tui_handler(signum: int, _frame: Any) -> None:
            reached_the_tui.append(signum)

        previous = signal.signal(signal.SIGINT, tui_handler)
        try:
            code = app._run_sandbox_terminal(SandboxLaunch(("sandbox", "connect", "x"), "/p", "x"))  # noqa: SLF001
            assert signal.getsignal(signal.SIGINT) is tui_handler, "the TUI's handler is back"
        finally:
            signal.signal(signal.SIGINT, previous)
    assert code == 0 and len(ran) == 1
    assert reached_the_tui == [], "Ctrl-C reached the TUI's own handler"
    assert after_prompt_ctrl_c == [], "Ctrl-C at the prompt returns to the TUI"


@pytest.mark.asyncio
async def test_irreversible_confirmations_focus_cancel(fetch, monkeypatch) -> None:
    """R2-55: pressing the key and Enter must not delete, undo or unblock everywhere."""
    fetch.approvals = [PUBLIC_ASK]
    app = DefenseClawTUI(config=_config())
    screens: list[Any] = []

    async def push_screen_wait(screen: Any) -> Any:
        screens.append(screen)
        # The unblock scope menu picks "always"; every confirmation is cancelled.
        return "always" if len(screens) == 1 else "cancel"

    monkeypatch.setattr(app, "push_screen_wait", push_screen_wait)
    monkeypatch.setattr(app, "_sandbox_call", _Calls({"result": {"changes": [{"path": "a.txt"}]}}))
    ran = _fake_terminal(monkeypatch, app, returncode=1)
    async with app.run_test(size=(160, 44)):
        await app._refresh_sandbox_snapshot(render=False)  # noqa: SLF001
        await app._sandbox_unblock("myapp-claude-7f3a", "webhook.site")  # noqa: SLF001
        await app._sandbox_delete("docs")  # noqa: SLF001
        await app._sandbox_undo("myapp-claude-7f3a")  # noqa: SLF001
        await app._sandbox_decide(  # noqa: SLF001
            SandboxPanelAction("approve", sandbox="myapp-claude-7f3a", approval_id="ask-2", always=True), approve=True
        )
        await app._sandbox_stop("myapp-claude-7f3a")  # noqa: SLF001
    confirmations = {screen.title: screen for screen in screens[1:]}
    # Delete, and the undo of a running sandbox, ask on the command line,
    # whose questions default to no.
    assert [tuple(argv[1:3]) for argv, _cwd in ran] == [("sandbox", "delete"), ("sandbox", "undo")]
    for title in (
        "Unblock webhook.site in every sandbox?",
        "Always allow www.example.com?",
    ):
        screen = confirmations[title]
        assert screen.selected_index is not None, title
        assert screen.actions[screen.selected_index].action_id == "cancel", title
    # Stop keeps the sandbox for connect: it keeps its default.
    assert confirmations["Stop myapp-claude-7f3a?"].selected_index is None


@pytest.mark.asyncio
async def test_a_cancel_first_menu_answers_enter_with_cancel() -> None:
    from defenseclaw.tui.widgets.action_menu import ActionMenuScreen, MenuAction
    from textual.app import App

    results: list[Any] = []

    class Host(App[None]):
        def on_mount(self) -> None:
            self.push_screen(
                ActionMenuScreen(
                    "Delete x?",
                    (MenuAction("delete", "Delete", variant="error"), MenuAction("cancel", "Cancel")),
                    selected_index=1,
                ),
                results.append,
            )

    app = Host()
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
    assert results == ["cancel"]


def test_the_block_banner_clears_once_the_block_is_resolved_or_old() -> None:
    """R2-58: an approved ask for the host resolves its blocks; old blocks leave the banner."""
    model = _model()
    model.cursor = 1  # myapp-claude-7f3a
    model.add_events([{**OPENSHELL_BLOCK, "time": "2026-09-28T10:00:00Z"}])
    now = datetime(2026, 9, 28, 10, 1, tzinfo=timezone.utc)
    assert model.block_notice(now=now)[:2] == ("✗ www.iana.org (no OpenShell rule allows it)", " in myapp-claude-7f3a")
    assert model.block_notice(now=now + timedelta(minutes=16)) == ("", "", "")
    rejected = {
        "seq": 60,
        "kind": "approval.resolved",
        "sandbox": "myapp-claude-7f3a",
        "approval_id": "ask-9",
        "host": "www.iana.org",
        "port": 443,
        "reason": "rejected",
        "message": "rejected www.iana.org",
    }
    model.add_events([rejected])
    assert model.block_notice(now=now)[0], "a rejection resolves nothing"
    model.add_events([{**rejected, "seq": 61, "reason": "operator", "message": "approved www.iana.org"}])
    assert model.block_notice(now=now) == ("", "", "")
    model.view = "activity"
    assert "www.iana.org (no OpenShell rule allows it)  (approved)" in [row[3] for row in model.data_table_rows()]


def _holder_fetch(fetch, project: Path) -> None:
    fetch.sandboxes = [RUNNING, {**STOPPED, "project": str(project), "harness_name": "Claude Code"}]


# --- the selection follows its item through refreshes -------------------------


def _ask(ask_id: str, minute: int) -> dict[str, Any]:
    return {**ASK, "id": ask_id, "created_at": f"2026-09-27T12:{minute:02d}:00Z"}


def test_the_selection_follows_its_ask_through_a_refresh() -> None:
    model = SandboxesPanelModel()
    model.set_snapshot(STATUS, [RUNNING], [_ask("ask-1", 1), _ask("ask-2", 2)])
    model.view = "asks"
    model.cursor = 1
    # An older ask arrives: every index moves, the selection does not.
    model.set_snapshot(STATUS, [RUNNING], [_ask("ask-0", 0), _ask("ask-1", 1), _ask("ask-2", 2)])
    assert model.handle_key("a") == SandboxPanelAction("approve", sandbox="myapp-claude-7f3a", approval_id="ask-2")


def test_a_key_is_refused_once_when_its_ask_went_away() -> None:
    model = SandboxesPanelModel()
    model.set_snapshot(STATUS, [RUNNING], [_ask("ask-1", 1), _ask("ask-2", 2), _ask("ask-3", 3)])
    model.view = "asks"
    model.cursor = 1
    # ask-2 was decided elsewhere; the cursor now sits on ask-3, which the
    # operator never picked.
    model.add_events([{"seq": 3, "kind": "approval.resolved", "approval_id": "ask-2"}])
    refused = model.handle_key("a")
    assert refused.kind == "hint" and "no longer waiting" in refused.hint
    assert model.handle_key("a") == SandboxPanelAction("approve", sandbox="myapp-claude-7f3a", approval_id="ask-3")
    # The operator's own decision is not a surprise.
    model.cursor = 0
    model.remove_ask("ask-1")
    assert model.handle_key("x") == SandboxPanelAction("reject", sandbox="myapp-claude-7f3a", approval_id="ask-3")


def test_the_activity_selection_follows_its_event() -> None:
    model = _model()
    model.add_events([BLOCKED])
    model.view = "activity"
    model.cursor = 0
    # The feed shows the newest first: a new block moves every row down.
    model.add_events([{**BLOCKED, "seq": 7, "host": "paste.example"}])
    assert model.handle_key("u") == SandboxPanelAction("unblock", sandbox="myapp-claude-7f3a", host="webhook.site")


def test_the_sandbox_selection_follows_its_row() -> None:
    model = SandboxesPanelModel()
    model.set_snapshot(STATUS, [RUNNING, STOPPED], [])
    model.cursor = 1  # docs
    # fix-tests starts and sorts before both.
    model.set_snapshot(STATUS, [RUNNING, STOPPED, COPY], [])
    assert model.handle_key("d") == SandboxPanelAction("delete", sandbox="docs")
    model.set_snapshot(STATUS, [RUNNING, COPY], [])
    refused = model.handle_key("d")
    assert refused.kind == "hint" and "is gone" in refused.hint


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("answer", "expected"),
    [
        ("copy", [("sandbox", "run", "claude", "--name", "two", "--copy")]),
        ("connect", [("sandbox", "connect", "docs")]),
        ("cancel", []),
    ],
)
async def test_new_run_offers_copy_connect_or_delete_when_the_folder_is_held(
    fetch, monkeypatch, tmp_path: Path, answer, expected
) -> None:
    """R2-57: another sandbox mounting the folder live becomes a choice, not a refusal."""
    project = tmp_path / "app"
    project.mkdir()
    _holder_fetch(fetch, project)
    app = DefenseClawTUI(config=_config())
    ran = _fake_terminal(monkeypatch, app, returncode=3)
    launch = SandboxLaunchValues(harness="claudecode", folder=str(project), name="two").build()
    screens: list[Any] = []
    answers = [launch, answer]

    async def push_screen_wait(screen: Any) -> Any:
        screens.append(screen)
        return answers.pop(0)

    monkeypatch.setattr(app, "push_screen_wait", push_screen_wait)
    async with app.run_test(size=(160, 44)):
        await app._refresh_sandbox_snapshot(render=False)  # noqa: SLF001
        await app._sandbox_new_run()  # noqa: SLF001
    menu = screens[1]
    assert menu.title == "docs already mounts this folder live"
    assert [action.action_id for action in menu.actions] == ["copy", "connect", "delete", "cancel"]
    assert "defenseclaw sandbox connect docs" in menu.actions[1].description
    assert "defenseclaw sandbox delete docs" in menu.actions[2].description
    assert [tuple(argv[1:]) for argv, _cwd in ran] == expected
    if answer == "copy":
        # The TUI names the run by the command a user would type.
        assert app.status_text == "defenseclaw sandbox run claude --name two --copy exited 3"


@pytest.mark.asyncio
async def test_new_run_can_delete_the_sandbox_holding_the_folder(fetch, monkeypatch, tmp_path: Path) -> None:
    project = tmp_path / "app"
    project.mkdir()
    _holder_fetch(fetch, project)
    app = DefenseClawTUI(config=_config())
    ran = _fake_terminal(monkeypatch, app)
    fake_run = sandbox_panel.subprocess.run

    def run(argv, cwd=None, check=False):
        result = fake_run(argv, cwd=cwd, check=check)
        if argv[1:3] == ["sandbox", "delete"]:  # the command line asked and deleted it
            fetch.sandboxes = [RUNNING]
        return result

    monkeypatch.setattr(sandbox_panel.subprocess, "run", run)
    calls = _Calls({"deleted": True})
    monkeypatch.setattr(app, "_sandbox_call", calls)
    launch = SandboxLaunchValues(harness="claudecode", folder=str(project)).build()
    monkeypatch.setattr(app, "push_screen_wait", _screen_answers(launch, "delete"))
    async with app.run_test(size=(160, 44)):
        await app._refresh_sandbox_snapshot(render=False)  # noqa: SLF001
        await app._sandbox_new_run()  # noqa: SLF001
    # The delete runs through the command line, which asks and looks for
    # copy-mode work first; the daemon is not called directly.
    assert calls.calls == []
    assert [tuple(argv[1:]) for argv, _cwd in ran] == [("sandbox", "delete", "docs"), ("sandbox", "run", "claude")]


def test_only_a_live_mount_of_the_same_or_a_nested_folder_holds_it(tmp_path: Path) -> None:
    project = tmp_path / "app"
    (project / "sub").mkdir(parents=True)
    other = tmp_path / "other"
    other.mkdir()
    model = SandboxesPanelModel()
    model.set_snapshot(
        STATUS, [{**STOPPED, "project": str(project)}, {**COPY, "project": str(other), "workdir_mode": "copy"}], []
    )
    assert model.live_mount_holder(str(project)).name == "docs"
    assert model.live_mount_holder(str(project / "sub")).name == "docs"
    assert model.live_mount_holder(str(tmp_path)).name == "docs"  # around it
    assert model.live_mount_holder(str(other)) is None  # a copy holds nothing
    assert model.live_mount_holder(str(tmp_path / "app2")) is None


@pytest.mark.asyncio
@pytest.mark.parametrize(("size", "hidden"), [((80, 24), True), ((99, 30), True), ((120, 30), False)])
async def test_narrow_terminals_drop_the_button_bar(fetch, size, hidden) -> None:
    """R2-61: under 100 columns the KEYS line carries the keys and the rows get the room."""
    app = DefenseClawTUI(config=_config())
    async with app.run_test(size=size) as pilot:
        await pilot.press("7")
        await app._refresh_sandbox_snapshot(render=True)  # noqa: SLF001
        await pilot.pause()
        assert app.query_one("#sandboxes-controls").has_class("hidden") is hidden
        assert "KEYS" in app.hint_text


@pytest.mark.asyncio
async def test_resizing_the_terminal_collapses_and_restores_the_button_bar(fetch) -> None:
    app = DefenseClawTUI(config=_config())
    async with app.run_test(size=(120, 30)) as pilot:
        await pilot.press("7")
        await app._refresh_sandbox_snapshot(render=True)  # noqa: SLF001
        await pilot.pause()
        bar = app.query_one("#sandboxes-controls")
        assert not bar.has_class("hidden")
        await pilot.resize_terminal(80, 24)
        await pilot.pause()
        await pilot.pause()
        assert bar.has_class("hidden")
        assert "Pack/Profile" not in app._table_columns  # noqa: SLF001
        await pilot.resize_terminal(120, 30)
        await pilot.pause()
        await pilot.pause()
        assert not bar.has_class("hidden")


def test_narrow_asks_keep_what_the_reason_adds() -> None:
    model = SandboxesPanelModel()
    model.set_snapshot(STATUS, [RUNNING], [PRIVATE_ASK, PUBLIC_ASK])
    model.view = "asks"
    assert model.data_table_columns(compact=True) == ("Sandbox", "Destination", "Binary", "Risk", "Reason")
    assert model.data_table_rows(compact=True) == (
        ("myapp-claude-7f3a", "www.example.com", "curl", "-", "not on the allowlist"),
        ("myapp-claude-7f3a", "10.0.1.3:38591", "curl", "risky", "private network"),
    )


def test_hook_tamper_raises_a_toast_and_marks_the_sandbox() -> None:
    model = _model()
    notices = model.add_events(
        [
            {
                "seq": 70,
                "kind": "finding",
                "sandbox": "myapp-claude-7f3a",
                "reason": "hook_tamper",
                "severity": "HIGH",
                "message": "⚠ hook tamper: Bash ran without a DefenseClaw verdict; "
                "the sandbox keeps running (hooks.on_tamper: alert)",
            }
        ]
    )
    assert [n.level for n in notices] == ["error"]
    assert notices[0].message.startswith("⚠ myapp-claude-7f3a: hook tamper: Bash ran without a DefenseClaw verdict")
    row = next(row for row in model.rows if row.name == "myapp-claude-7f3a")
    assert row.alert_badge.startswith("tamper")
    assert model.alert_notice()[0].startswith("⚠ myapp-claude-7f3a: hook tamper: 2 tool call(s)")


def test_an_ask_row_names_what_is_asked() -> None:
    model = SandboxesPanelModel()
    model.add_events(
        [
            {
                "seq": 1,
                "kind": "approval.requested",
                "sandbox": "x",
                "host": "www.example.com",
                "port": 443,
                "approval_id": "ap_1",
                "message": "approvals are manual for the strict profile",
            }
        ]
    )
    assert model.feed[0].summary == "asks to reach www.example.com (approvals are manual for the strict profile)"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("asks_during_detail", "expected"),
    [
        # An older ask arrives while the detail is open: the key still acts
        # on the ask the detail showed.
        (
            [_ask("ask-0", 0), _ask("ask-1", 1)],
            SandboxPanelAction("approve", sandbox="myapp-claude-7f3a", approval_id="ask-1"),
        ),
        # The ask the detail showed is gone: nothing is approved.
        ([_ask("ask-0", 0)], None),
    ],
)
async def test_a_detail_key_acts_on_the_item_the_detail_showed(fetch, monkeypatch, asks_during_detail, expected) -> None:
    app = DefenseClawTUI(config=_config())
    seen: list[SandboxPanelAction] = []
    async with app.run_test(size=(160, 44)) as pilot:
        await app._refresh_sandbox_snapshot(render=False)  # noqa: SLF001 - settle the mount's poll
        await pilot.pause()
        model = app.sandbox_model
        model.set_snapshot(STATUS, [RUNNING], [_ask("ask-1", 1)])
        model.view = "asks"
        model.cursor = 0
        assert model.handle_key("enter").kind == "detail"

        async def push_screen_wait(_screen: Any) -> Any:
            model.set_snapshot(STATUS, [RUNNING], asks_during_detail)  # the 5 s poll
            return "a"

        monkeypatch.setattr(app, "push_screen_wait", push_screen_wait)
        monkeypatch.setattr(app, "_apply_sandbox_action", lambda action: seen.append(action) or True)
        await app._open_sandbox_detail()  # noqa: SLF001
    if expected is None:
        assert len(seen) == 1 and seen[0].kind == "hint" and "no longer waiting" in seen[0].hint
    else:
        assert seen == [expected]
