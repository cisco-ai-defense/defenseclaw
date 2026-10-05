# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""``guardrail.block_at`` / ``alert_at`` in the Python config (mirrors internal/config)."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml
from defenseclaw.config import (
    ApplicationProtectionConfig,
    Config,
    GuardrailConfig,
    PerConnectorGuardrailConfig,
    _merge_guardrail,
    load,
)


def test_levels_load_in_any_case_and_resolve_connector_then_global() -> None:
    gc = _merge_guardrail(
        {"block_at": "high", "alert_at": " Low ", "connectors": {"codex": {"block_at": "critical"}, "hermes": {}}},
        "/tmp",
    )
    assert (gc.block_at, gc.alert_at, gc.connectors["codex"].block_at) == ("HIGH", "LOW", "CRITICAL")
    assert (gc.effective_block_at("codex"), gc.effective_alert_at("codex")) == ("CRITICAL", "LOW")
    assert (gc.effective_block_at("hermes"), gc.effective_block_at("")) == ("HIGH", "HIGH")
    assert GuardrailConfig().effective_block_at("codex") == ""  # the rule pack decides


@pytest.mark.parametrize(
    ("guardrail", "message"),
    [
        (GuardrailConfig(block_at="SEVERE"), "guardrail.block_at: must be one of CRITICAL, HIGH, MEDIUM, LOW"),
        (GuardrailConfig(alert_at="3"), "guardrail.alert_at: must be one of CRITICAL, HIGH, MEDIUM, LOW"),
        (
            GuardrailConfig(connectors={"codex": PerConnectorGuardrailConfig(alert_at="hihg")}),
            "guardrail.connectors['codex']: alert_at: must be one of CRITICAL, HIGH, MEDIUM, LOW",
        ),
    ],
)
def test_validate_rejects_unknown_levels(guardrail: GuardrailConfig, message: str) -> None:
    with pytest.raises(ValueError, match=message.replace("[", r"\[").replace("]", r"\]")):
        guardrail.validate()
    GuardrailConfig(block_at="low", connectors={"codex": PerConnectorGuardrailConfig(alert_at="")}).validate()


def test_application_protection_overlays_refuse_levels() -> None:
    overlay = ApplicationProtectionConfig(guardrail=PerConnectorGuardrailConfig(mode="observe", block_at="HIGH"))
    with pytest.raises(ValueError, match="application_protection.guardrail: block_at is not supported"):
        overlay.validate()


def _config(tmp_path: Path, guardrail: GuardrailConfig) -> Config:
    return Config(
        data_dir=str(tmp_path),
        audit_db=os.path.join(tmp_path, "audit.db"),
        quarantine_dir=os.path.join(tmp_path, "quarantine"),
        plugin_dir=os.path.join(tmp_path, "plugins"),
        policy_dir=os.path.join(tmp_path, "policies"),
        environment="macos",
        guardrail=guardrail,
    )


def _disk(tmp_path: Path) -> dict:
    return yaml.safe_load((tmp_path / "config.yaml").read_text(encoding="utf-8"))["guardrail"]


def _reload(tmp_path: Path) -> Config:
    with patch("defenseclaw.config.default_data_path", return_value=tmp_path):
        return load()


def test_levels_round_trip_and_inherit_leaves_no_key(tmp_path: Path) -> None:
    connectors = {"codex": PerConnectorGuardrailConfig(), "hermes": PerConnectorGuardrailConfig()}
    _config(tmp_path, GuardrailConfig(enabled=True, connectors=connectors)).save()
    disk = _disk(tmp_path)
    # Unset levels are omitted (Go omitempty), so untouched configs stay as they were.
    assert "block_at" not in disk and "alert_at" not in disk["connectors"]["codex"]

    cfg = _reload(tmp_path)
    cfg.guardrail.block_at = "HIGH"
    cfg.guardrail.connectors["codex"].alert_at = "LOW"
    cfg.save()
    assert _disk(tmp_path)["block_at"] == "HIGH"
    assert _disk(tmp_path)["connectors"]["codex"]["alert_at"] == "LOW"
    cfg = _reload(tmp_path)
    assert (cfg.guardrail.effective_block_at("codex"), cfg.guardrail.effective_alert_at("codex")) == ("HIGH", "LOW")

    cfg.guardrail.block_at = ""
    cfg.guardrail.connectors["codex"].alert_at = ""
    cfg.save()
    disk = _disk(tmp_path)
    assert "block_at" not in disk and "alert_at" not in disk["connectors"]["codex"]
    assert _reload(tmp_path).guardrail.effective_block_at("codex") == ""
