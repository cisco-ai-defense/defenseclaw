# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""#1441: status and doctor say what each kind of hook failure does.

A single fail-mode=open read as if a hung gateway let every call run. The
hooks tell three kinds apart: no gateway took the call (follows the outage
mode), a verified gateway gave no answer in time (runs only an ordinary
Claude Code or Codex call in a per-user open mode, GAP-0518), and an answer
or local hook error (blocks in every tier).
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from defenseclaw import config as dcconfig
from defenseclaw import fail_mode
from defenseclaw.commands import cmd_status


def _cfg(*, saved: str = "", managed: bool = False, secure_client: bool = False) -> SimpleNamespace:
    guardrail = dcconfig.GuardrailConfig(hook_fail_mode=saved)
    guardrail.secure_client_hook_fail_modes = lambda: secure_client
    return SimpleNamespace(
        guardrail=guardrail,
        deployment_mode="managed_enterprise" if managed or secure_client else "",
        managed_outside_secure_client=lambda: managed,
    )


@pytest.mark.parametrize("connector", ["claudecode", "codex"])
def test_per_user_open_runs_only_an_ordinary_call_a_hung_gateway_did_not_answer(connector: str) -> None:
    assert fail_mode.failure_outcomes(_cfg(), connector, "open") == {
        "gateway_down": "allow",
        "no_answer": "allow-ordinary",
        "hook_error": "block",
    }


@pytest.mark.parametrize("connector", ["cursor", "copilot", "devin", "kiro", "opencode", "amp", "hermes"])
def test_per_user_open_blocks_a_no_answer_of_the_other_connectors(connector: str) -> None:
    assert fail_mode.failure_outcomes(_cfg(), connector, "open") == {
        "gateway_down": "allow",
        "no_answer": "block",
        "hook_error": "block",
    }


@pytest.mark.parametrize("connector", ["claudecode", "cursor"])
def test_closed_mode_blocks_every_failure(connector: str) -> None:
    want = {"gateway_down": "block", "no_answer": "block", "hook_error": "block"}
    assert fail_mode.failure_outcomes(_cfg(saved="closed"), connector, "closed") == want
    assert fail_mode.failure_outcomes(_cfg(managed=True), connector, "closed") == want


def test_managed_open_allows_only_a_proven_stopped_service() -> None:
    assert fail_mode.failure_outcomes(_cfg(saved="open", managed=True), "claudecode", "open") == {
        "gateway_down": "allow-if-service-stopped",
        "no_answer": "block",
        "hook_error": "block",
    }


def test_no_breakdown_for_secure_client_proxy_connectors_or_an_unknown_mode() -> None:
    assert fail_mode.failure_outcomes(_cfg(secure_client=True), "claudecode", "open") is None
    assert fail_mode.failure_outcomes(_cfg(), "openclaw", "open") is None
    assert fail_mode.failure_outcomes(_cfg(), "claudecode", "unknown") is None


def test_summary_names_every_failure_kind_in_order() -> None:
    summary = fail_mode.failure_outcomes_summary(fail_mode.failure_outcomes(_cfg(), "claudecode", "open"))
    assert summary == (
        "gateway down: allow with a warning; "
        "no answer: allow with a warning unless the call may reach a protected file; "
        "hook or answer error: block"
    )
    assert fail_mode.failure_outcomes_summary(None) == ""


def test_report_carries_the_outcomes_of_its_effective_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    def base(cfg, connector, *, inspect_effective_policy=True):
        return {"effective": "open", "provenance": "hook-script", "note": ""}

    monkeypatch.setattr(fail_mode, "_connector_fail_mode_report", base)
    report = fail_mode.connector_fail_mode_report(_cfg(), "claudecode", inspect_effective_policy=False)
    assert report["on_failure"]["no_answer"] == "allow-ordinary"


def test_status_prints_the_outcomes_after_the_fail_mode() -> None:
    report = {"effective": "open", "on_failure": fail_mode.failure_outcomes(_cfg(), "cursor", "open")}
    assert cmd_status._status_failure_outcomes_suffix(report) == (
        " on-failure=(gateway down: allow with a warning; no answer: block; hook or answer error: block)"
    )
    assert cmd_status._status_failure_outcomes_suffix({"effective": "unknown"}) == ""
