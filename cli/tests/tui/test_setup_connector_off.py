# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Setup does not list a connector the config turns off as active (GAP-0854)."""

from __future__ import annotations

import pytest
from defenseclaw.tui.panels import setup_catalog
from defenseclaw.tui.panels.setup import SetupWizard, wizard_state_summary


def _config(*, hermes_enabled: bool | None, others: tuple[str, ...] = ("claudecode", "codex", "copilot", "opencode")):
    from defenseclaw.config import PerConnectorGuardrailConfig, default_config

    cfg = default_config()
    cfg.guardrail.connectors = {name: PerConnectorGuardrailConfig(mode="action") for name in others}
    cfg.guardrail.connectors["hermes"] = PerConnectorGuardrailConfig(mode="action", enabled=hermes_enabled)
    return cfg


def test_setup_names_the_turned_off_connector_as_off_not_active() -> None:
    cfg = _config(hermes_enabled=False)

    summary = wizard_state_summary(SetupWizard.CONNECTOR_SETUP, cfg)
    assert summary == "Active connectors: claudecode, codex, copilot, opencode  ·  Off: hermes"
    status = setup_catalog.task_status(SetupWizard.CONNECTOR_SETUP, cfg)
    assert (status.state, status.text) == ("ok", "4 agents, 1 off")


@pytest.mark.parametrize("enabled", [True, None])
def test_setup_keeps_an_enabled_connector_active(enabled: bool | None) -> None:
    cfg = _config(hermes_enabled=enabled)

    summary = wizard_state_summary(SetupWizard.CONNECTOR_SETUP, cfg)
    assert summary == "Active connectors: claudecode, codex, copilot, hermes, opencode"
    status = setup_catalog.task_status(SetupWizard.CONNECTOR_SETUP, cfg)
    assert (status.state, status.text) == ("ok", "5 agents")


def test_setup_with_every_connector_off_needs_attention() -> None:
    cfg = _config(hermes_enabled=False, others=())
    cfg.guardrail.connectors["codex"] = cfg.guardrail.connectors["hermes"].__class__(mode="action", enabled=False)

    assert wizard_state_summary(SetupWizard.CONNECTOR_SETUP, cfg) == "Active connectors: none  ·  Off: codex, hermes"
    status = setup_catalog.task_status(SetupWizard.CONNECTOR_SETUP, cfg)
    assert (status.state, status.text) == ("attention", "2 agents off")


def test_setup_reads_the_off_flag_from_a_plain_mapping() -> None:
    cfg = {"guardrail": {"connectors": {"codex": {}, "hermes": {"enabled": False}}}}

    assert wizard_state_summary(SetupWizard.CONNECTOR_SETUP, cfg) == "Active connectors: codex  ·  Off: hermes"
    status = setup_catalog.task_status(SetupWizard.CONNECTOR_SETUP, cfg)
    assert (status.state, status.text) == ("ok", "codex, 1 off")
