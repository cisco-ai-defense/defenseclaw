# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""``guardrail profile explain`` and the profile validation messages."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest
from click.testing import CliRunner
from defenseclaw.commands import cmd_guardrail
from defenseclaw.config import (
    GuardrailProfile,
    GuardrailProfileAssignment,
    GuardrailProfileMatch,
    default_config,
    validate_guardrail_profiles,
)
from defenseclaw.context import AppContext


def test_explain_asks_the_gateway_and_reports_the_match(monkeypatch):
    from defenseclaw.gateway import OrchestratorClient

    asked = {}

    def resolve(self, *, user="", connector="", agent=""):
        asked.update(user=user, connector=connector, agent=agent)
        return {
            "profiles_configured": True,
            "profile": "strict",
            "match": "group",
            "matched_group": "CORP\\Contractors",
            "digest": "sha256:" + "0" * 64,
            "connector": "codex",
            "effective": {"mode": "action", "block_at": "LOW", "alert_at": "", "rule_pack_dir": "", "hilt": {}},
        }

    monkeypatch.setattr(OrchestratorClient, "guardrail_profile_resolve", resolve)
    app = AppContext()
    app.cfg = default_config()
    app.logger = MagicMock()
    runner = CliRunner()

    result = runner.invoke(
        cmd_guardrail.guardrail,
        ["profile", "explain", "--user", "alice", "--connector", "codex"],
        obj=app,
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    assert asked == {"user": "alice", "connector": "codex", "agent": ""}
    assert "profile: strict" in result.output
    assert "group (CORP\\Contractors)" in result.output
    assert "mode=action" in result.output

    as_json = runner.invoke(
        cmd_guardrail.guardrail,
        ["profile", "explain", "--user", "alice", "--json"],
        obj=app,
        catch_exceptions=False,
    )
    assert json.loads(as_json.output)["profile"] == "strict"

    # Without --user, explain (also with --connector, GAP-0085) and guardrail
    # status ask about the account running the command, and status names its
    # profile (GAP-0056).
    monkeypatch.setattr("getpass.getuser", lambda: "alice")
    app.cfg.guardrail.profiles = {"strict": GuardrailProfile(mode="action")}
    mine = runner.invoke(
        cmd_guardrail.guardrail, ["profile", "explain", "--connector", "codex"], obj=app, catch_exceptions=False
    )
    assert mine.exit_code == 0, mine.output
    assert asked == {"user": "alice", "connector": "codex", "agent": ""}
    status = runner.invoke(cmd_guardrail.guardrail, ["status"], obj=app, catch_exceptions=False)
    assert "strict for alice (by group CORP\\Contractors): mode action" in status.output

    # An agent assignment that wins for alice's Codex agent is named on the
    # same line instead of implying strict decides there too (GAP-0075).
    agent_id = "agt-" + "1" * 16
    app.cfg.guardrail.profiles["pin"] = GuardrailProfile(mode="observe")
    app.cfg.guardrail.profile_assignments = [
        GuardrailProfileAssignment(profile="pin", match=GuardrailProfileMatch(agents=[agent_id, "agt-" + "2" * 16]))
    ]
    monkeypatch.setattr(
        OrchestratorClient,
        "agent_identities",
        lambda self, *, user=None, connector=None: {"identities": [{"agent_id": agent_id, "connector": "codex"}]},
    )

    def resolve_scoped(self, *, user="", connector="", agent=""):
        asked.setdefault("probes", []).append((connector, agent))
        return {"profile": "pin", "match": "agent"} if agent == agent_id else resolve(self, user=user)

    monkeypatch.setattr(OrchestratorClient, "guardrail_profile_resolve", resolve_scoped)
    status = runner.invoke(cmd_guardrail.guardrail, ["status"], obj=app, catch_exceptions=False)
    assert asked["probes"] == [("", ""), ("codex", agent_id)]
    assert f"; except pin for Codex agent {agent_id} (by agent)" in status.output


def _explain(monkeypatch, result, *args):
    """Run ``guardrail profile explain`` against a gateway that answers *result*."""
    from defenseclaw.gateway import OrchestratorClient

    def resolve(self, *, user="", connector="", agent=""):
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(OrchestratorClient, "guardrail_profile_resolve", resolve)
    app = AppContext()
    app.cfg = default_config()
    app.logger = MagicMock()
    return CliRunner().invoke(
        cmd_guardrail.guardrail, ["profile", "explain", "--user", "alice", *args], obj=app, catch_exceptions=False
    )


def test_explain_names_a_failed_lookup_instead_of_a_group_count(monkeypatch):
    """GAP-0124: no group count for an account whose directory lookup failed."""
    result = _explain(
        monkeypatch,
        {
            "profiles_configured": True,
            "profile": "watch",
            "match": "default_lookup_failed",
            "subject": {"user_name": "alice@corp.example.com", "group_count": 0},
            "lookup_error": "in 3000 groups, more than the 2048 DefenseClaw names",
        },
    )
    assert "(groups unknown)" in result.output
    assert "user lookup failed: in 3000 groups" in result.output
    assert "0 group(s)" not in result.output


def test_explain_blames_a_slow_directory_not_a_stopped_gateway(monkeypatch):
    """GAP-0140: a read timeout is a running gateway still resolving the user."""
    import requests

    slow = _explain(monkeypatch, requests.exceptions.ReadTimeout("Read timed out. (read timeout=35)"))
    assert slow.exit_code == 1
    assert "did not answer within 35 s" in slow.output
    assert "directory lookup for alice may be slow" in slow.output
    assert "Start it with" not in slow.output

    stopped = _explain(monkeypatch, requests.exceptions.ConnectionError("Connection refused"))
    assert stopped.exit_code == 1
    assert "Could not ask the gateway" in stopped.output
    assert "Start it with: defenseclaw-gateway start" in stopped.output

    # guardrail status and doctor say the same for their shorter wait.
    cfg = default_config()
    cfg.guardrail.profiles = {"strict": GuardrailProfile(mode="action")}
    text = cmd_guardrail.profile_status_text(cfg, {"user": "alice", "error": "timed out", "timed_out": True})
    assert "running but did not answer in time" in text


def test_warnings_from_the_gateway_reach_explain_status_and_doctor(monkeypatch):
    """GAP-0182: what the decision alone does not show is a warning in each view."""
    from defenseclaw import gateway
    from defenseclaw.commands import cmd_doctor

    note = 'assignment 1 selects this account by the short name "alice", so it selects a local account of that name too'
    answer = {
        "profiles_configured": True,
        "profile": "strict",
        "match": "user",
        "subject": {"user_name": "alice", "group_count": 1},
        "warnings": [note],
        # GAP-0145: a directory that does not answer.
        "directory": {"failing": 2, "message": "directory lookups are failing for 2 account(s) since 21:04:08Z"},
    }
    explained = _explain(monkeypatch, answer).output
    assert note in explained
    assert "directory lookups are failing for 2 account(s)" in explained

    app = AppContext()
    app.cfg = default_config()
    app.cfg.guardrail.profiles = {"strict": GuardrailProfile(mode="action")}
    app.logger = MagicMock()
    monkeypatch.setattr(gateway, "current_user_guardrail_profile", lambda cfg: {**answer, "user": "alice", "overrides": []})
    status = CliRunner().invoke(cmd_guardrail.guardrail, ["status"], obj=app, catch_exceptions=False)
    assert note in status.output
    assert "directory lookups are failing for 2 account(s)" in status.output

    # `profile list` reads the config file and adds what the running gateway
    # warns about, such as a group the host no longer knows (GAP-0135).
    app.cfg.guardrail.profile_assignments = [
        GuardrailProfileAssignment(profile="strict", match=GuardrailProfileMatch(groups=["dc-rename-me@dclab.test"]))
    ]
    monkeypatch.setattr(
        gateway.OrchestratorClient, "guardrail_profile_resolve", lambda self, **kwargs: {"warnings": ["assignment 1: group is gone"]}
    )
    listed = CliRunner().invoke(cmd_guardrail.guardrail, ["profile", "list"], obj=app, catch_exceptions=False)
    assert "assignment 1: group is gone" in listed.output
    as_json = CliRunner().invoke(cmd_guardrail.guardrail, ["profile", "list", "--json"], obj=app, catch_exceptions=False)
    assert json.loads(as_json.output)["warnings"] == ["assignment 1: group is gone"]

    result = cmd_doctor._DoctorResult(quiet=True)
    cmd_doctor._check_guardrail_profile(app.cfg, result)
    assert [(c["status"], c["label"]) for c in result.checks] == [
        ("pass", "Guardrail profile"),
        ("warn", "Directory lookups"),
        ("warn", "Guardrail assignments"),
    ]


def test_explain_shows_how_old_the_facts_of_live_requests_are(monkeypatch):
    """GAP-0134: explain resolves fresh groups, requests keep cached facts for 15 minutes."""
    result = _explain(
        monkeypatch,
        {
            "profiles_configured": True,
            "profile": "ml",
            "match": "group",
            "subject": {"user_name": "alice", "group_count": 2},
            "cache": {"age_seconds": 420, "refresh_after_seconds": 480, "profile": "watch", "match": "default", "differs": True},
            "warnings": ["requests of this account still use the directory facts the gateway fetched 7m0s ago"],
        },
    )
    assert "cache:   requests use directory facts 7m old (profile watch, match default)" in result.output
    assert "refreshes them after 15m" in result.output
    assert "still use the directory facts" in result.output


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda gc: gc.profile_assignments.append(GuardrailProfileAssignment(profile="ml-team", match=GuardrailProfileMatch(users=["a"]))), "unknown profile 'ml-team'"),
        (lambda gc: gc.profile_assignments.append(GuardrailProfileAssignment(profile="contractors")), "match needs at least one of groups"),
        (lambda gc: setattr(gc.profiles["contractors"], "hook_fail_mode", "open"), "hook_fail_mode is not allowed in a guardrail profile"),
        (lambda gc: setattr(gc, "default_profile", "nobody"), "guardrail.default_profile: unknown profile"),
    ],
)
def test_profile_validation_mirrors_the_gateway(mutate, message):
    gc = default_config().guardrail
    gc.profiles = {"contractors": GuardrailProfile(mode="action")}
    validate_guardrail_profiles(gc)
    mutate(gc)
    with pytest.raises(ValueError, match=message):
        validate_guardrail_profiles(gc)
