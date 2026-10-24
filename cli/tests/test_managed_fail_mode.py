# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Per-user hooks close; managed administrators may choose outage-open.

Mirrors internal/config/hook_fail_mode_matrix_test.go: for every connector,
per-user, managed standalone and Secure Client, in observe and action mode,
an administrator's explicit open or closed wins on a managed computer, and
an unset fail mode is closed except under Secure Client, where it is open
(#1163). On the
standalone profile no connector is lowered to an upstream fail-open: its
managed hooks block through the native deny.
"""

from __future__ import annotations

import pytest
from defenseclaw import config_writer
from defenseclaw.config import Config, GuardrailConfig, PerConnectorGuardrailConfig
from defenseclaw.fail_mode import upstream_fail_open

CONNECTORS = (
    "amp",
    "antigravity",
    "claudecode",
    "codex",
    "copilot",
    "cursor",
    "devin",
    "hermes",
    "kiro",
    "opencode",
)
DEPLOYMENTS = {
    "per-user": ("", "", "closed"),
    "standalone": ("managed_enterprise", "standalone", "closed"),
    "secure-client": ("managed_enterprise", "secure_client", "open"),
}


@pytest.fixture(autouse=True)
def _no_host_markers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DEFENSECLAW_DEPLOYMENT_MODE", raising=False)
    monkeypatch.delenv("DEFENSECLAW_ENTERPRISE_PROFILE", raising=False)
    monkeypatch.setattr(config_writer, "machine_managed_standalone", lambda: False)


def _config(deployment: str, mode: str, global_mode: str, connector: str, connector_mode: str) -> Config:
    deployment_mode, profile, _ = DEPLOYMENTS[deployment]
    guardrail = GuardrailConfig(mode=mode, hook_fail_mode=global_mode)
    if connector_mode:
        guardrail.connectors = {connector: PerConnectorGuardrailConfig(hook_fail_mode=connector_mode)}
    cfg = Config(deployment_mode=deployment_mode, enterprise_profile=profile, guardrail=guardrail)
    if deployment == "secure-client":
        # load() marks a Secure Client guardrail (_apply_secure_client_hook_fail_default).
        object.__setattr__(cfg.guardrail, "_secure_client", True)
    return cfg


@pytest.mark.parametrize("connector", CONNECTORS)
@pytest.mark.parametrize("deployment", list(DEPLOYMENTS))
@pytest.mark.parametrize("mode", ["observe", "action"])
@pytest.mark.parametrize(
    ("global_mode", "connector_mode", "want"),
    [
        ("", "", None),
        ("  ", "", None),
        ("open", "", "open"),
        ("", " Open ", "open"),
        ("closed", "", "closed"),
        ("", "closed", "closed"),
        ("open", "closed", "closed"),
        ("closed", "open", "open"),
        ("opne", "", "closed"),
    ],
)
def test_hook_fail_mode_matrix(connector, deployment, mode, global_mode, connector_mode, want):
    cfg = _config(deployment, mode, global_mode, connector, connector_mode)
    if want is None:
        want = DEPLOYMENTS[deployment][2]
    if deployment == "per-user":
        want = "closed"
    assert cfg.guardrail.effective_hook_fail_mode(connector) == want
    assert cfg.managed_outside_secure_client() is (deployment == "standalone")


@pytest.mark.parametrize("connector", ["antigravity", "copilot", "hermes"])
def test_standalone_never_lowers_to_upstream_fail_open(connector):
    assert not upstream_fail_open(_config("standalone", "observe", "", connector, ""), connector)
    assert not upstream_fail_open(_config("standalone", "observe", "open", connector, ""), connector)
    # Secure Client keeps the upstream fail-open; a per-user hook blocks its
    # own failures with the agent's native deny on every OS.
    assert upstream_fail_open(_config("secure-client", "observe", "", connector, ""), connector)
    assert not upstream_fail_open(_config("per-user", "observe", "", connector, ""), connector)


def test_machine_marker_makes_any_managed_config_standalone(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config_writer, "machine_managed_standalone", lambda: True)
    cfg = Config(
        deployment_mode="managed_enterprise",
        enterprise_profile="secure_client",
        guardrail=GuardrailConfig(mode="observe"),
    )
    assert cfg.managed_outside_secure_client()
    assert cfg.guardrail.effective_hook_fail_mode("kiro") == "closed"
    cfg.guardrail.hook_fail_mode = "open"
    assert cfg.guardrail.effective_hook_fail_mode("kiro") == "open"
