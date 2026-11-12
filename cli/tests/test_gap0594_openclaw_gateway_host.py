# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""GAP-0594 review N5: the OpenClaw plugin sends nothing to a non-loopback
gateway.host, so doctor fails that host instead of leaving only a console
warning inside OpenClaw."""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from defenseclaw.commands import cmd_doctor
from defenseclaw.commands.cmd_doctor import _DoctorResult, _openclaw_plugin_host_is_loopback
from defenseclaw.config import Config, GatewayConfig, GuardrailConfig, OpenShellConfig


@pytest.mark.parametrize(
    ("host", "loopback"),
    [
        ("127.0.0.1", True),
        ("127.1.2.3", True),
        ("localhost", True),
        ("::1", True),
        ("[::1]", True),
        ("0.0.0.0", False),
        ("10.0.0.5", False),
        ("gateway.example.com", False),
        ("127.0.0.256", False),
    ],
)
def test_loopback_rule_matches_the_plugin(host, loopback) -> None:
    assert _openclaw_plugin_host_is_loopback(host) is loopback


def _cfg(host: str) -> Config:
    cfg = Config(
        data_dir="/tmp/defenseclaw",
        audit_db="/tmp/defenseclaw/audit.db",
        quarantine_dir="/tmp/defenseclaw/quarantine",
        plugin_dir="/tmp/defenseclaw/plugins",
        policy_dir="/tmp/defenseclaw/policies",
        guardrail=GuardrailConfig(enabled=True, connector="openclaw"),
        gateway=GatewayConfig(host=host),
        openshell=OpenShellConfig(),
    )
    cfg.claw.mode = "openclaw"
    return cfg


def test_doctor_fails_a_non_loopback_gateway_host(monkeypatch) -> None:
    monkeypatch.setattr(cmd_doctor, "_doctor_active_connectors", lambda cfg: ["openclaw"])
    r = _DoctorResult()
    cmd_doctor._check_openclaw_gateway_host(_cfg("10.0.0.5"), r)
    assert [c["status"] for c in r.checks] == ["fail"]
    assert "not a loopback address" in r.checks[0]["detail"]
    assert "gateway.host 127.0.0.1" in r.checks[0]["remediation"]


def test_doctor_is_quiet_for_loopback(monkeypatch) -> None:
    monkeypatch.setattr(cmd_doctor, "_doctor_active_connectors", lambda cfg: ["openclaw"])
    r = _DoctorResult()
    cmd_doctor._check_openclaw_gateway_host(_cfg("localhost"), r)
    assert r.checks == []
