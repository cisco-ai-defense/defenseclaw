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
from defenseclaw.tui.services.sandbox_state import TOAST_DEDUPE_SECONDS

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


def test_snapshot_sorts_running_first_and_keeps_only_pending_asks() -> None:
    model = _model()
    assert [row.name for row in model.rows] == ["fix-tests", "myapp-claude-7f3a", "docs"]
    assert [ask.id for ask in model.asks] == ["ask-1"]
    assert model.state() == "ready"
    assert "2 running" in model.headline() and "1 ask(s) waiting" in model.headline()
    assert "OpenShell 0.1.1 gateway openshell" in model.headline()


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
                "message": "host.openshell.internal:5432",
            }
        ]
    )
    assert notices and "myapp-claude-7f3a asks to reach host.openshell.internal:5432" in notices[0].message
    model.add_events([{"seq": 21, "kind": "approval.resolved", "approval_id": "ask-1"}])
    assert model.asks == ()


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
    assert rows[0][2:] == ("✗", "Bash blocked: DC-TOOL-1: deletes your home folder")
    assert rows[1][2:] == ("✗", "10.0.0.5:22 (private network)")
    assert rows[2][2:] == ("✗", "webhook.site (exfil destination)  (u unblocks)")
    assert rows[3][2:] == ("✓", "registry.npmjs.org")
    assert model.data_table_columns() == ("Time", "Sandbox", "", "Event")


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
    assert _model().handle_key("u").hint == "No blocked destination to unblock."


def test_ask_keys() -> None:
    model = _model()
    first = model.handle_key("a")
    assert first.kind == "view" and model.view == "asks" and "a to approve" in first.hint
    assert model.handle_key("a") == SandboxPanelAction("approve", sandbox="myapp-claude-7f3a", approval_id="ask-1")
    assert model.handle_key("A").always is True
    assert model.handle_key("r") == SandboxPanelAction("reject", sandbox="myapp-claude-7f3a", approval_id="ask-1")
    model.view = "sandboxes"
    assert model.handle_key("r").kind == "refresh"


def test_always_approve_respects_the_organization_policy() -> None:
    model = _model(admin=AdminPolicy(allow_unblock=False))
    model.view = "asks"
    assert ADMIN_MESSAGE in model.handle_key("A").hint
    assert model.handle_key("a").kind == "approve"


def test_no_asks() -> None:
    model = SandboxesPanelModel()
    model.set_snapshot(STATUS, [RUNNING], [])
    assert model.handle_key("a").hint == "No asks are waiting."


@pytest.mark.parametrize(
    ("cursor", "key", "kind", "hint"),
    [
        (1, "U", "undo", ""),
        (1, "R", "review", ""),
        (1, "s", "stop", ""),
        (1, "d", "delete", ""),
        (1, "c", "connect", ""),
        (0, "U", "hint", "defenseclaw sandbox pull fix-tests"),
        (0, "R", "hint", "defenseclaw sandbox pull fix-tests"),
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
        "1/57",
        "tamper, nested repo",
    )
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
    plain = SandboxLaunchValues(harness="claudecode", folder=str(project), profile="(pack default)").build()
    assert plain.argv == ("sandbox", "run", "claudecode")


def test_launch_values_refuse_bad_folders(tmp_path: Path, monkeypatch) -> None:
    home = tmp_path / "home"
    (home / "code").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    with pytest.raises(SandboxLaunchError, match="not a folder"):
        SandboxLaunchValues(folder=str(home / "missing")).build()
    for folder in (home, tmp_path, Path("/")):
        with pytest.raises(SandboxLaunchError, match="home folder"):
            SandboxLaunchValues(folder=str(folder)).build()
    with pytest.raises(SandboxLaunchError, match="unknown profile"):
        SandboxLaunchValues(folder=str(home / "code"), profile="loose").build()
    assert SandboxLaunchValues(folder=str(home / "code")).build().cwd == str(home / "code")


def test_harness_choices_follow_config_and_organization() -> None:
    assert harness_choices(()) == (("Claude Code", "claudecode"), ("Codex", "codex"))
    assert harness_choices(("codex",)) == (("Codex", "codex"), ("Claude Code", "claudecode"))
    assert harness_choices((), ("codex",)) == (("Codex", "codex"),)


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
    # Never open a real activity stream from tests.
    monkeypatch.setattr(DefenseClawTUI, "_ensure_sandbox_stream", lambda self: None)
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
    monkeypatch.setattr(app, "push_screen_wait", _screen_answers(choice))
    async with app.run_test(size=(160, 44)):
        await app._sandbox_unblock("myapp-claude-7f3a", "webhook.site")  # noqa: SLF001
    assert calls.calls == ([expected] if expected else [])


@pytest.mark.asyncio
async def test_always_approve_confirms_first(fetch, monkeypatch) -> None:
    app = DefenseClawTUI(config=_config())
    calls = _Calls({"message": "queued: applies when the agent is idle"})
    monkeypatch.setattr(app, "_sandbox_call", calls)
    monkeypatch.setattr(app, "push_screen_wait", _screen_answers("cancel", "always"))
    action = SandboxPanelAction("approve", sandbox="myapp-claude-7f3a", approval_id="ask-1", always=True)
    async with app.run_test(size=(160, 44)):
        await app._sandbox_decide(action, approve=True)  # noqa: SLF001
        assert calls.calls == []
        await app._sandbox_decide(action, approve=True)  # noqa: SLF001
    assert calls.calls == [("decide_sandbox_approval", ("ask-1",), {"approve": True, "always": True})]


@pytest.mark.asyncio
async def test_undo_previews_then_stops_and_restores(fetch, monkeypatch) -> None:
    app = DefenseClawTUI(config=_config())
    calls = _Calls({"result": {"changes": [{"path": "a.txt"}]}, "stopped": True})
    monkeypatch.setattr(app, "_sandbox_call", calls)
    monkeypatch.setattr(app, "push_screen_wait", _screen_answers("undo"))
    async with app.run_test(size=(160, 44)):
        await app._sandbox_undo("myapp-claude-7f3a")  # noqa: SLF001
    assert [(method, kwargs) for method, _args, kwargs in calls.calls] == [
        ("undo_sandbox", {"preview": True, "stop": False}),
        ("undo_sandbox", {"stop": True}),
    ]


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


@pytest.mark.asyncio
async def test_delete_needs_confirmation(fetch, monkeypatch) -> None:
    app = DefenseClawTUI(config=_config())
    calls = _Calls({"deleted": True})
    monkeypatch.setattr(app, "_sandbox_call", calls)
    monkeypatch.setattr(app, "push_screen_wait", _screen_answers("cancel", "delete"))
    async with app.run_test(size=(160, 44)):
        await app._sandbox_delete("docs")  # noqa: SLF001
        await app._sandbox_delete("docs")  # noqa: SLF001
    assert calls.calls == [("delete_sandbox", ("docs",), {})]


@pytest.mark.asyncio
async def test_api_refusals_become_plain_toasts(fetch, monkeypatch) -> None:
    from defenseclaw.gateway import SandboxAPIError

    app = DefenseClawTUI(config=_config())
    toasts: list[tuple[str, str]] = []

    async def refuse(*_args: Any, **_kwargs: Any) -> Any:
        raise SandboxAPIError("admin_violation", f"{ADMIN_MESSAGE}: unblocking is not allowed", status=403)

    monkeypatch.setattr(app, "_sandbox_call", refuse)
    monkeypatch.setattr(app, "notify_toast", lambda level, message: toasts.append((level, message)))
    async with app.run_test(size=(160, 44)):
        await app._guarded_sandbox_action(app._sandbox_stop("docs"))  # noqa: SLF001
    assert toasts[-1] == ("warn", f"{ADMIN_MESSAGE}: unblocking is not allowed")
    assert app._sandbox_action_running is False  # noqa: SLF001


def _fake_terminal(monkeypatch, app, returncode: int = 0):
    ran: list[tuple[list[str], str]] = []

    @contextlib.contextmanager
    def suspend():
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
