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
