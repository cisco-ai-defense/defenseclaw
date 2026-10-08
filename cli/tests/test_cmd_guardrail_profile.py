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
import os
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
    # The explicit account is stable across Unix UID and Windows SID lookups.
    monkeypatch.setattr("defenseclaw.gateway.current_profile_account", lambda **kwargs: ("alice", "alice"))
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


def test_unix_current_profile_ignores_environment_account(monkeypatch):
    if os.name == "nt":
        pytest.skip("Unix account lookup only")
    import pwd

    from defenseclaw.gateway import current_profile_account

    monkeypatch.setenv("LOGNAME", "other-account")
    monkeypatch.setenv("USER", "other-account")
    account = pwd.getpwuid(os.geteuid()).pw_name
    assert current_profile_account() == (account, account)
    assert current_profile_account(secure_client=True) == ("other-account", "other-account")


def test_explain_on_windows_asks_for_the_token_sid(monkeypatch):
    # An Entra ID login name (EntraAlice) is no account name Windows can look
    # up, so explain and doctor reported default_lookup_failed for every Entra
    # user; they now ask for the token SID and still show the login name.
    from defenseclaw.gateway import OrchestratorClient, current_user_guardrail_profile

    asked = []

    def resolve(self, *, user="", connector="", agent=""):
        asked.append(user)
        return {"profiles_configured": True, "profile": "entra", "match": "user", "subject": {"upn": "alice@contoso.onmicrosoft.com"}}

    monkeypatch.setattr(OrchestratorClient, "guardrail_profile_resolve", resolve)
    monkeypatch.setattr("defenseclaw.file_permissions._windows_current_user_sid", lambda: "S-1-12-1-1-2-3-4")
    monkeypatch.setattr("getpass.getuser", lambda: "EntraAlice")
    app = AppContext()
    app.cfg = default_config()
    app.logger = MagicMock()
    app.cfg.guardrail.profiles = {"entra": GuardrailProfile(mode="action")}
    monkeypatch.setattr("defenseclaw.gateway.os.name", "nt")

    explained = CliRunner().invoke(cmd_guardrail.guardrail, ["profile", "explain"], obj=app, catch_exceptions=False)
    mine = current_user_guardrail_profile(app.cfg)

    assert explained.exit_code == 0, explained.output
    assert "alice@contoso.onmicrosoft.com" in explained.output
    assert asked == ["S-1-12-1-1-2-3-4", "S-1-12-1-1-2-3-4"]
    assert mine["user"] == "EntraAlice"



def test_profile_timeout_displays_account_name_instead_of_windows_sid(monkeypatch):
    from defenseclaw import gateway
    from requests.exceptions import ReadTimeout

    app = AppContext()
    app.cfg = default_config()
    app.cfg.guardrail.profiles = {"strict": GuardrailProfile(mode="action")}
    monkeypatch.setattr(gateway, "current_profile_account", lambda **kwargs: ("S-1-12-1-1-2-3-4", "EntraAlice"))

    def timeout(self, *, user=""):
        assert user == "S-1-12-1-1-2-3-4"
        raise ReadTimeout("profile lookup")

    monkeypatch.setattr(gateway.OrchestratorClient, "guardrail_profile_resolve", timeout)
    result = gateway.current_user_guardrail_profile(app.cfg)

    assert result["user"] == "EntraAlice"
    assert "unknown for EntraAlice" in cmd_guardrail.profile_status_text(app.cfg, result)

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


def test_explain_match_line_names_default_lookup_failed(monkeypatch):
    """GAP-0275: "match: default" while requests get default_lookup_failed."""
    result = _explain(
        monkeypatch,
        {
            "profiles_configured": True,
            "profile": "",
            "match": "default",
            "subject": {"user_name": "alice@corp.example.com", "group_count": 1},
            "cache": {"match": "default_lookup_failed", "profile": "", "age_seconds": 0, "refresh_after_seconds": 0},
        },
    )
    match_line = next(line for line in result.output.splitlines() if line.strip().startswith("match:"))
    assert "default_lookup_failed" in match_line


def test_explain_failed_gateway_lookup_has_no_cached_facts(monkeypatch):
    result = _explain(
        monkeypatch,
        {
            "profiles_configured": True,
            "profile": "ml",
            "match": "group",
            "subject": {"user_name": "alice", "group_count": 1},
            "cache": {
                "failing_since": "2026-10-08T12:00:00Z",
                "last_error": "directory unavailable",
                "profile": "watch",
                "match": "default_lookup_failed",
                "differs": True,
            },
        },
    )
    assert "cache:   requests have no cached directory facts" in result.output
    assert "default_lookup_failed" in result.output
    assert "facts 0s old" not in result.output
    assert "refreshes them after 0s" not in result.output


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


def test_reload_notice_says_when_the_running_gateway_has_not_applied_the_file(monkeypatch):
    """GAP-0352, GAP-0363: validate, status and explain describe config.yaml;
    the notice says when the gateway rejected its last reload or holds keys
    for a restart, and is silent once the gateway applied the file."""
    from defenseclaw import gateway

    cfg = default_config()
    health: dict = {}
    monkeypatch.setattr(gateway, "foreign_loopback_listener", lambda host, port: "")
    monkeypatch.setattr(gateway.OrchestratorClient, "health", lambda self: health)

    health["policy"] = {"generation": 4, "last_reload_error": "guardrail profile strict rule pack: directory_not_found"}
    notice = gateway.gateway_reload_notice(cfg)
    assert "has NOT applied" in notice and "directory_not_found" in notice and "generation 4" in notice
    health["policy"] = {"generation": 5, "pending_restart": ["gateway"]}
    assert "except gateway" in gateway.gateway_reload_notice(cfg)
    health["policy"] = {"generation": 6}
    assert gateway.gateway_reload_notice(cfg) == ""


def test_profile_summary_includes_every_scoped_assignment(monkeypatch):
    from defenseclaw import gateway

    app = AppContext()
    app.cfg = default_config()
    app.cfg.guardrail.profiles = {
        "base": GuardrailProfile(mode="observe"),
        "pin": GuardrailProfile(mode="action"),
    }
    agents = [f"agt-{n:016d}" for n in range(17)]
    app.cfg.guardrail.profile_assignments = [
        GuardrailProfileAssignment(profile="pin", match=GuardrailProfileMatch(agents=[agent]))
        for agent in agents
    ]
    monkeypatch.setattr(gateway, "current_profile_account", lambda **kwargs: ("alice", "alice"))
    monkeypatch.setattr(
        gateway.OrchestratorClient,
        "agent_identities_all",
        lambda self, *, user: {"identities": [{"agent_id": agent, "connector": "codex"} for agent in agents]},
    )
    monkeypatch.setattr(
        gateway.OrchestratorClient,
        "guardrail_profile_resolve",
        lambda self, *, user="", connector="", agent="": {
            "profile": "pin" if agent else "base",
            "match": "agent" if agent else "default",
        },
    )

    result = gateway.current_user_guardrail_profile(app.cfg)
    assert len(result["overrides"]) == len(agents)
    assert agents[-1] in cmd_guardrail.profile_status_text(app.cfg, result)


def test_profile_status_does_not_present_unknown_connector_as_active(monkeypatch):
    from defenseclaw import gateway

    cfg = default_config()
    cfg.guardrail.profiles = {"base": GuardrailProfile(mode="observe"), "pin": GuardrailProfile(mode="action")}
    cfg.guardrail.profile_assignments = [
        GuardrailProfileAssignment(profile="pin", match=GuardrailProfileMatch(connectors=["claudcode"]))
    ]
    monkeypatch.setattr(gateway, "current_profile_account", lambda **kwargs: ("alice", "alice"))
    probes = []

    def resolve(self, *, user="", connector="", agent=""):
        probes.append(connector)
        return {"profile": "pin" if connector else "base", "match": "connector" if connector else "default"}

    monkeypatch.setattr(gateway.OrchestratorClient, "guardrail_profile_resolve", resolve)
    answer = gateway.current_user_guardrail_profile(cfg)
    assert answer["overrides"] == []
    assert probes == [""]


def test_cursor_status_names_missing_prompt_hook(monkeypatch):
    from defenseclaw import gateway

    app = AppContext()
    app.cfg = default_config()
    monkeypatch.setattr(app.cfg, "active_connectors", lambda: ["cursor"])
    monkeypatch.setattr(app.cfg, "has_connector_configured", lambda: True)
    monkeypatch.setattr(gateway, "current_user_guardrail_profile", lambda cfg: None)
    result = CliRunner().invoke(cmd_guardrail.guardrail, ["status", "--json"], obj=app, catch_exceptions=False)
    assert result.exit_code == 0
    assert "beforeSubmitPrompt" in json.loads(result.output)["warnings"][-1]
