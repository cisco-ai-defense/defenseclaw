# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""The Sandboxes panel on a managed computer: the user's own policy (plan 7.1).

The policy comes from the daemon (``Status.managed``, ``policy/explain``);
nothing is read from config.yaml, which a user on a managed computer cannot
read, and nothing names another account.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any

import pytest
from defenseclaw.tui import sandbox_panel
from defenseclaw.tui.app import DefenseClawTUI
from defenseclaw.tui.panels.sandboxes import (
    AdminPolicy,
    SandboxesPanelModel,
    SandboxPanelAction,
    admin_policy_from_config,
)
from defenseclaw.tui.services import sandbox_state
from defenseclaw.tui.services.sandbox_state import (
    POLICY_CHIP_SECONDS,
    admin_policy_from_explain,
    decode_status,
    managed_policy_pairs,
    sandbox_keys_hint,
)

NOW = datetime(2026, 9, 27, 12, 0, tzinfo=timezone.utc)
DIGEST = "sha256:7f3a" + "0" * 60

MANAGED = {
    "profile": "contractors",
    "description": "Contractors. Coding agents only in a sandbox.",
    "effective_digest": DIGEST,
    "updated_at": "2026-09-27T11:58:00Z",
    "request_access": "it-security@example.com",
    "install_mode": "setup",
    "driver": "docker",
    "openshell_version": "0.1.3",
}
STATUS = {
    "enabled": True,
    "available": True,
    "gateway": {"name": "openshell", "version": "0.1.3", "healthy": True, "driver": "docker"},
    "sandboxes": 0,
    "running": 0,
    "managed": MANAGED,
}
EXPLAIN = {
    "profile": "contractors",
    "description": "Contractors. Coding agents only in a sandbox.",
    "match": "group",
    "matched_group": "CORP\\Contractors",
    "allowed": True,
    "required_for": ["claudecode", "codex"],
    "egress_allow_only": ["api.example.net", "*.corp.example", "pypi.org"],
    "egress_block": ["evil.example", "bad.example"],
    "user_approvals": "session",
    "allow_unblock": False,
    "mcp_included": ["docs", "tickets"],
    "mcp_blocked": [{"name": "files", "reason": "organization_block"}],
    "workdir_mode": "copy",
    "allow_mount": False,
    "allow_host_ports": False,
    "allow_yolo": False,
    "on_silence": "alert",
    "max_silence_after": "10m",
    "policy_digest": DIGEST,
    "updated_at": "2026-09-27T11:58:00Z",
    "request_access": "it-security@example.com",
}


def _model(status: dict[str, Any] = STATUS) -> SandboxesPanelModel:
    model = SandboxesPanelModel()
    model.set_snapshot(status, [], [], now=NOW)
    return model


def test_status_carries_the_callers_own_managed_policy() -> None:
    managed = decode_status(STATUS).managed
    assert managed is not None
    assert (managed.profile, managed.driver, managed.openshell_version, managed.install_mode) == ("contractors", "docker", "0.1.3", "setup")
    assert managed.updated_at == datetime(2026, 9, 27, 11, 58, tzinfo=timezone.utc)
    assert decode_status({**STATUS, "managed": None}).managed is None
    assert decode_status({k: v for k, v in STATUS.items() if k != "managed"}).managed is None


def test_the_policy_line_replaces_the_local_organization_line() -> None:
    model = _model()
    # The daemon's answer, not the local file: even with an admin status the
    # line is the user's own policy.
    status = {**STATUS, "admin": {"configured": True, "authority": "authoritative", "detail": "openshell.admin is authoritative"}}
    model.set_snapshot(status, [], [], now=NOW)
    assert model.admin_line() == "Your policy: contractors · updated" + model.admin_line().split("updated", 1)[1]
    assert "e explains" in model.admin_line()
    provisional = _model({**STATUS, "managed": {**MANAGED, "profile": "offline-floor", "provisional": True}})
    assert "offline-floor (provisional: your directory couldn't be reached)" in provisional.policy_line(NOW)
    assert SandboxesPanelModel().policy_line() == ""


def test_provisional_default_match_names_the_directory_outage() -> None:
    profile = dict(managed_policy_pairs({"profile": "offline-floor", "match": "default_lookup_failed"}, NOW))["Profile"]
    assert profile == (
        "offline-floor   matched: the default (your directory couldn't be reached; "
        "no assignment needs the missing facts)"
    )


def test_policy_pairs_follow_the_plan() -> None:
    pairs = dict(managed_policy_pairs(EXPLAIN, NOW))
    assert pairs["Profile"] == "contractors   matched: your group CORP\\Contractors"
    assert pairs["Required"] == "claude and codex run only in a sandbox on this computer"
    assert pairs["Egress"] == (
        "only 3 hosts are reachable (api.example.net, *.corp.example, pypi.org); "
        "2 hosts are always blocked (evil.example, bad.example)"
    )
    assert pairs["Approvals"] == "you may approve asks for this session only; you can't unblock destinations"
    assert pairs["MCP"] == "2 of your servers included; 1 blocked by your organization"
    assert pairs["Workspace"] == "copy mode; no mounts; no host ports; skip-permissions off"
    assert pairs["Hooks"] == "claude and codex: an alert after 10m of agent work without hooks"
    assert pairs["Policy id"] == "sha256:7f3a00000000… (yours), updated 2 min ago; access: it-security@example.com"
    assert managed_policy_pairs({}, NOW) == ()
    refused = dict(managed_policy_pairs({"match": "none", "allowed": False, "policy_digest": "sha256:ab"}, NOW))
    assert refused["Sandboxes"] == "your organization doesn't allow sandboxes for you"
    assert refused["Policy id"].endswith("access: contact your IT help desk")


def test_exempt_policy_pairs_use_the_gateway_host_run_gate() -> None:
    exempt = dict(managed_policy_pairs({**EXPLAIN, "host_run_gate": "exempt", "enrollment_exempt": True}, NOW))
    assert exempt["Required"] == (
        "your account is exempt from enrollment (enterprise.enrollment.exempt_users), so required_for doesn't apply to you: "
        "claude and codex may also run on this computer outside a sandbox, where their calls are still inspected and logged"
    )
    refused = dict(managed_policy_pairs({**EXPLAIN, "host_run_gate": "refused"}, NOW))
    assert refused["Required"] == "claude and codex run only in a sandbox on this computer"
    empty = dict(managed_policy_pairs({**EXPLAIN, "host_run_gate": "", "required_for": []}, NOW))
    assert empty["Required"] == "no agent has to run in a sandbox"


def test_the_explain_sets_the_switches_instead_of_the_local_file() -> None:
    # The local admin read is gone on a managed computer.
    cfg = SimpleNamespace(
        deployment_mode="managed_enterprise",
        openshell=SimpleNamespace(admin=SimpleNamespace(allow_unblock=True, allowed_harnesses=["amp"])),
    )
    assert admin_policy_from_config(cfg) == AdminPolicy()
    # An unmanaged computer keeps its advisory read.
    own = SimpleNamespace(deployment_mode="", openshell=cfg.openshell)
    assert admin_policy_from_config(own).allowed_harnesses == ("amp",)

    model = _model()
    model.set_config(cfg)
    assert model.managed_explain_stale()
    model.set_managed_explain({"managed": EXPLAIN})
    assert not model.managed_explain_stale()
    assert model.admin.unblock_refused and model.admin.allowed_harnesses == ()
    assert admin_policy_from_explain(EXPLAIN).unblock_refused
    # A later config reload does not bring the local file back.
    model.set_config(own)
    assert model.admin.unblock_refused


def test_a_live_policy_change_shows_a_chip_for_a_while() -> None:
    model = _model()
    assert model.policy_chip(NOW) == ""
    changed = {**MANAGED, "profile": "staff", "effective_digest": "sha256:" + "1" * 64}
    model.set_snapshot({**STATUS, "managed": changed}, [], [], now=NOW)
    assert model.policy_chip(NOW) == "policy changed: contractors → staff"
    assert "● policy changed: contractors → staff" in model.policy_line(NOW)
    assert model.policy_chip(NOW + timedelta(seconds=POLICY_CHIP_SECONDS + 1)) == ""
    # A same-profile update says so; the same digest is no change.
    model.set_snapshot({**STATUS, "managed": {**changed, "effective_digest": "sha256:" + "2" * 64}}, [], [], now=NOW)
    assert model.policy_chip(NOW) == "policy changed: updated"
    quiet = _model()
    quiet.set_snapshot(STATUS, [], [], now=NOW)
    assert quiet.policy_chip(NOW) == ""


def test_e_explains_on_a_managed_computer_and_hints_elsewhere() -> None:
    assert _model().handle_key("e") == SandboxPanelAction("explain")
    plain = SandboxesPanelModel()
    plain.set_snapshot({k: v for k, v in STATUS.items() if k != "managed"}, [], [], now=NOW)
    action = plain.handle_key("e")
    assert action.kind == "hint" and "defenseclaw sandbox policy explain" in action.hint


def test_the_keys_line_offers_e_within_80_columns() -> None:
    model = _model()
    assert "e policy" in model.keys_line() and len(model.keys_line()) <= 78
    for copy in (False, True):
        line = sandbox_keys_hint("sandboxes", copy=copy, policy=True)
        assert "e policy" in line and "u unblock" not in line and len(line) <= 78
    assert "e policy" in sandbox_keys_hint("sandboxes", has_rows=False, policy=True)
    assert "e policy" not in sandbox_keys_hint("sandboxes")


def test_off_and_busy_states_are_neutral_on_a_managed_computer() -> None:
    busy = _model(
        {**STATUS, "enabled": False, "gateway_elsewhere": "held by PID 4242 of another account (uid 1999, alice)"}
    )
    text = busy.headline()
    assert text.startswith("Sandboxes aren't available for your account right now: another account is using them.")
    assert "it-security@example.com" in text
    for leak in ("alice", "4242", "1999", "setup", "hand"):
        assert leak not in text
    assert busy.off_hint() == text
    off = _model({**STATUS, "enabled": False}).headline()
    assert "your organization manages this setting" in off and "Setup" not in off
    gone = _model({**STATUS, "available": False, "managed": {**MANAGED, "unavailable": "OpenShell is not installed"}}).headline()
    assert gone.startswith("Sandboxes aren't available on this computer: OpenShell is not installed.")
    # GAP-0187: the temporary setup-change notice says to retry, with no contact-IT line.
    changing = _model(
        {**STATUS, "available": False, "managed": {**MANAGED, "unavailable": sandbox_state.SETUP_CHANGING_NOTICE}}
    ).headline()
    assert changing == f"Sandboxes aren't available on this computer: {sandbox_state.SETUP_CHANGING_NOTICE}."
    assert "exception" not in changing and "it-security@example.com" not in changing
    # Unmanaged computers keep their own advice.
    plain = SandboxesPanelModel()
    plain.set_snapshot({"enabled": False}, [], [], now=NOW)
    assert "Set them up in Setup" in plain.headline()


def test_the_sandbox_detail_names_the_users_policy() -> None:
    model = SandboxesPanelModel()
    model.set_snapshot(
        STATUS,
        [{"name": "box", "harness": "claudecode", "harness_name": "Claude Code", "phase": "ready", "profile": "open", "pack": "open"}],
        [],
        now=NOW,
    )
    _title, pairs = model.detail_pairs()
    assert dict(pairs)["Your policy"].startswith("contractors")


# --- the screen at 80x24 ------------------------------------------------------


def test_texts_a_person_wrote_are_safe_and_bounded_like_the_cli() -> None:
    evil = "ops\x1b[31m‮\nline"
    status = decode_status({**STATUS, "managed": {**MANAGED, "profile": evil, "request_access": "a@b.example" + "x" * 600,
                                                  "unavailable": "gone\x07", "description": "d\r\ne"}})
    assert status.managed is not None
    assert status.managed.profile == "ops�[31m� line"
    assert status.managed.description == "d  e"
    assert status.managed.unavailable == "gone�"
    assert len(status.managed.request_access.encode()) <= 512
    pairs = dict(managed_policy_pairs({**EXPLAIN, "profile": evil, "description": "x\x1b[2Jy",
                                       "request_access": "it\x1b[0m@example.com" + "é" * 400,
                                       "egress_block": ["bad\x1b.example"]}, NOW))
    assert "\x1b" not in "".join(pairs.values()) and "‮" not in "".join(pairs.values())
    assert pairs["Profile"].startswith("ops�[31m� line")
    assert len(pairs["Policy id"].split("access: ", 1)[1].encode()) <= 512


def test_only_an_answer_with_the_managed_object_is_the_users_policy() -> None:
    model = _model()
    # An older daemon's plain explain (OpenShell settings) is not shown as policy.
    assert model.set_managed_explain({"pack": "balanced", "profile": "standard", "network_mode": "restricted"}) is False
    assert model.managed_explain == {} and model.policy_pairs() == ()
    assert model.set_managed_explain({"managed": EXPLAIN}) is True
    assert dict(model.policy_pairs(NOW))["Required"].startswith("claude and codex")


def test_an_exempt_account_can_run_on_the_host_when_sandboxes_are_disallowed() -> None:
    pairs = dict(managed_policy_pairs({**EXPLAIN, "allowed": False, "host_run_gate": "exempt"}, NOW))
    assert "doesn't allow sandboxes" in pairs["Sandboxes"]
    assert "required_for doesn't apply" in pairs["Required"]
    assert "outside a sandbox" in pairs["Required"]


def test_a_failed_policy_read_backs_off_before_the_next_try() -> None:
    model = _model()
    assert model.managed_explain_due(100.0)
    model.note_managed_explain_failed(100.0)
    assert not model.managed_explain_due(100.0 + 5)
    assert model.managed_explain_due(100.0 + sandbox_state.MANAGED_EXPLAIN_RETRY_SECONDS)
    # A plain answer counts as a failed read too.
    model.set_managed_explain({"pack": "balanced"})
    assert not model.managed_explain_due(time.monotonic() + 1)
    model.set_managed_explain({"managed": EXPLAIN})
    assert not model.managed_explain_due() and model.managed_explain_failed_at is None


@pytest.fixture
def managed_daemon(
monkeypatch: pytest.MonkeyPatch):
    payload = sandbox_panel.SandboxFetch(status=STATUS, sandboxes=[], approvals=[])
    monkeypatch.setattr(sandbox_panel, "fetch_sandbox_snapshot", lambda _config: payload)
    monkeypatch.setattr(sandbox_panel, "fetch_managed_explain", lambda _config: {"managed": EXPLAIN})
    monkeypatch.setattr(DefenseClawTUI, "_ensure_sandbox_stream", lambda self: None)
    monkeypatch.setattr(sandbox_panel, "openshell_sandboxes_supported", lambda os_name=None: True)

    async def explain(self: Any, method: str, *args: Any, **kwargs: Any) -> Any:
        assert method == "sandbox_policy_explain"
        return {"managed": EXPLAIN}

    monkeypatch.setattr(DefenseClawTUI, "_sandbox_call", explain)
    return payload


@pytest.mark.asyncio
async def test_the_policy_section_fits_80x24_and_e_opens_it(managed_daemon) -> None:
    config = SimpleNamespace(
        gateway=SimpleNamespace(api_port=18970, host="127.0.0.1", token="token"),
        openshell=SimpleNamespace(enabled=True, harnesses=["claudecode"], wrappers=[], admin=None),
    )
    app = DefenseClawTUI(config=config)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.press("7")
        await app._refresh_sandbox_snapshot(render=True)  # noqa: SLF001
        await pilot.pause()
        body = app._sandbox_body_text()  # noqa: SLF001
        assert "Your policy: contractors" in body
        assert body.count("\n") + 1 <= 5, body
        # The refresh read the user's policy once; the switches come from it.
        assert not app.sandbox_model.managed_explain_stale()
        assert app.sandbox_model.admin.unblock_refused
        await pilot.press("e")
        await pilot.pause()
        await pilot.pause()
        screen = app.screen
        assert screen.__class__.__name__ == "SandboxDetailScreen"
        assert screen.model.title == "Your sandbox policy on this computer"
        assert dict(screen.model.pairs)["Required"] == "claude and codex run only in a sandbox on this computer"
        assert screen.query_one("#sandbox-detail-close").region.bottom <= 24
        await pilot.press("escape")
        await pilot.pause()


def test_the_approvals_row_matches_what_approve_always_does() -> None:
    # GAP-0169 (#1200): under allow_unblock: false the managed gateway refuses
    # approve --always, so an approval lasts this session only, as `sandbox
    # policy explain` says.
    def row(approvals: str, unblock: bool) -> str:
        return dict(managed_policy_pairs({**EXPLAIN, "user_approvals": approvals, "allow_unblock": unblock}, NOW))["Approvals"]

    assert row("", True) == "you may approve asks for a session or for good"
    assert row("", False) == "you may approve asks for this session only; you can't unblock destinations"
    assert row("session", True) == "you may approve asks for this session only"
    assert row("session", False) == "you may approve asks for this session only; you can't unblock destinations"
    assert row("none", True) == "you can't approve asks; they are refused"
    assert row("none", False) == "you can't approve asks; they are refused; you can't unblock destinations"
