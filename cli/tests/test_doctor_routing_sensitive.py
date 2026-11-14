# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""doctor routing.sensitive row (rel-1-0-10 GAP-0003)."""

from types import SimpleNamespace

from defenseclaw.commands.cmd_doctor import routing_sensitive_row


def _cfg(sensitive, *, enabled=True, dm=False):
    return SimpleNamespace(
        routing=SimpleNamespace(enabled=enabled, sensitive=sensitive),
        decision_model=SimpleNamespace(enabled=dm, base_url="https://dm.example/v1" if dm else ""),
    )


def test_no_row_without_routing_sensitive():
    assert routing_sensitive_row(_cfg({}, enabled=True)) is None
    assert routing_sensitive_row(_cfg({"aliases": ["local"], "signals": ["s"]}, enabled=False)) is None


def test_check_off_says_how_to_turn_it_on():
    status, detail, fix = routing_sensitive_row(_cfg({"aliases": ["local"], "severity_at_least": "high"}))
    assert status == "info" and "HIGH" in detail and "check off" in detail
    assert "routing.sensitive.check auto" in fix and "0.4 s" in fix


def test_decision_model_check_without_a_decision_model_warns():
    status, detail, _fix = routing_sensitive_row(_cfg({"aliases": ["local"], "signals": ["s"], "check": "decision_model"}))
    assert status == "warn" and "regex-only" in detail


def test_check_on_passes():
    status, detail, _fix = routing_sensitive_row(_cfg({"aliases": ["local"], "check": "auto"}, dm=True))
    assert status == "pass" and "check auto" in detail and "unavailable -> local" in detail
