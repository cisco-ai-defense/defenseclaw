# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""OpenClaw setup advisories.

GAP-1958: OpenClaw shows a DefenseClaw approval only in its Control UI and on
chat channels that forward /approve; openclaw tui and local chat do not, so
the call is denied when the request times out. Setup with human approval, the
interactive HILT note and doctor's Human approval row now say where to answer.

GAP-1959: from OpenClaw 2026.5.12 Amazon Bedrock is the external plugin
@openclaw/amazon-bedrock-provider. A Bedrock model without it fails with "No
API provider registered for api: bedrock-converse-stream"; setup now warns and
names the install command. Both only warn: setup still succeeds.
"""

from __future__ import annotations

import copy
import json
from types import SimpleNamespace

import pytest
from defenseclaw.commands import cmd_setup
from defenseclaw.connector_contracts import openclaw_bedrock_plugin_missing

MID = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
LEGACY_BEDROCK = {
    "models": {
        "providers": {"amazon-bedrock": {"api": "bedrock-converse-stream", "auth": "aws-sdk", "models": [{"id": MID}]}}
    },
    "agents": {"defaults": {"model": {"primary": "amazon-bedrock/" + MID}}},
    "plugins": {"allow": ["defenseclaw"], "entries": {"defenseclaw": {"enabled": True}}},
}


def _with_plugin(allow=("amazon-bedrock", "defenseclaw"), enabled=True, deny=None):
    cfg = copy.deepcopy(LEGACY_BEDROCK)
    cfg["plugins"]["allow"] = list(allow)
    cfg["plugins"]["entries"]["amazon-bedrock"] = {"enabled": enabled}
    if deny is not None:
        cfg["plugins"]["deny"] = list(deny)
    return cfg


def _discovery(version: str) -> SimpleNamespace:
    signal = SimpleNamespace(
        installed=True,
        version=version,
        error="",
        binary_path="/home/u/.local/bin/openclaw",
        config_path="",
        config_paths=(),
        forms=(),
    )
    return SimpleNamespace(agents={"openclaw": signal})


@pytest.mark.parametrize(
    ("version", "cfg", "missing"),
    [
        ("OpenClaw 2026.6.8 (844f405)", LEGACY_BEDROCK, True),
        ("OpenClaw 2026.5.12", LEGACY_BEDROCK, True),
        ("OpenClaw 2026.5.7", LEGACY_BEDROCK, False),
        ("OpenClaw 2026.3.24 (cff6dc9)", LEGACY_BEDROCK, False),
        ("", LEGACY_BEDROCK, False),
        ("OpenClaw 2026.6.8", _with_plugin(), False),
        ("OpenClaw 2026.6.8", _with_plugin(allow=("defenseclaw",)), True),
        ("OpenClaw 2026.6.8", _with_plugin(enabled=False), True),
        ("OpenClaw 2026.6.8", _with_plugin(deny=("amazon-bedrock",)), True),
        ("OpenClaw 2026.6.8", {"agents": {"defaults": {"model": {"primary": "openai/gpt-5"}}}}, False),
        ("OpenClaw 2026.6.8", "not a dict", False),
    ],
)
def test_bedrock_needs_the_external_provider_plugin(version, cfg, missing) -> None:
    assert openclaw_bedrock_plugin_missing(version, cfg) is missing


def _setup(tmp_path, capsys, *, cfg, human_approval, version="OpenClaw 2026.6.8 (844f405)") -> str:
    path = tmp_path / "openclaw.json"
    path.write_text(json.dumps(cfg))
    got = cmd_setup._check_connector_version_supported_for_setup(
        "openclaw",
        mode="action",
        emit=True,
        data_dir=str(tmp_path),
        _allow_prompt=False,
        _discovery=_discovery(version),
        human_approval=human_approval,
        openclaw_config_file=str(path),
    )
    assert got is True
    return capsys.readouterr().out


def test_setup_warns_about_the_missing_bedrock_plugin_and_names_the_install(tmp_path, capsys) -> None:
    out = _setup(tmp_path, capsys, cfg=LEGACY_BEDROCK, human_approval=False)
    assert "@openclaw/amazon-bedrock-provider" in out
    assert "No API provider registered for api: bedrock-converse-stream" in out
    assert "openclaw plugins install @openclaw/amazon-bedrock-provider" in out


def test_setup_is_quiet_when_the_bedrock_plugin_is_installed(tmp_path, capsys) -> None:
    out = _setup(tmp_path, capsys, cfg=_with_plugin(), human_approval=False)
    assert "amazon-bedrock-provider" not in out
    assert "Control UI" not in out


def test_setup_with_human_approval_names_where_openclaw_shows_approvals(tmp_path, capsys) -> None:
    out = _setup(tmp_path, capsys, cfg=_with_plugin(), human_approval=True)
    assert "Control UI" in out
    assert "openclaw tui" in out
    assert "/approve" in out


def test_the_interactive_hilt_note_names_the_approval_surfaces() -> None:
    note = cmd_setup._hilt_support_note("openclaw")
    assert "Control UI" in note and "openclaw tui" in note
