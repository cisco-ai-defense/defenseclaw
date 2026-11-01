# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""GAP-1956: human approval on an OpenClaw without plugin approvals.

OpenClaw before 2026.3.28 (the install.sh pin is 2026.3.24) has no plugin
approval hook and rejects approvals.plugin in openclaw.json, so its gateway
stopped starting after `setup openclaw --human-approval`. Setup's version
gate now refuses that combination before it writes anything.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from defenseclaw.commands import cmd_setup


def _discovery(version: str) -> SimpleNamespace:
    signal = SimpleNamespace(
        installed=True, version=version, error="", binary_path="/home/u/.local/bin/openclaw",
        config_path="", config_paths=(), forms=(),
    )
    return SimpleNamespace(agents={"openclaw": signal})


@pytest.mark.parametrize(
    ("version", "human_approval", "admitted"),
    [
        ("OpenClaw 2026.3.24 (cff6dc9)", True, False),
        ("OpenClaw 2026.3.24 (cff6dc9)", False, True),
        ("OpenClaw 2026.3.28 (abc1234)", True, True),
        ("OpenClaw 2026.6.8", True, True),
    ],
)
def test_openclaw_human_approval_needs_plugin_approvals(tmp_path, version, human_approval, admitted) -> None:
    got = cmd_setup._check_connector_version_supported_for_setup(
        "openclaw", mode="action", emit=False, data_dir=str(tmp_path), _allow_prompt=False,
        _discovery=_discovery(version), human_approval=human_approval,
    )
    assert got is admitted


def test_guardrail_setup_reads_the_effective_human_approval() -> None:
    on = SimpleNamespace(enabled=True)
    off = SimpleNamespace(enabled=False)
    gc = SimpleNamespace(hilt=off, effective_hilt=lambda c: on if c == "openclaw" else off)
    assert cmd_setup._guardrail_hilt_enabled_for(gc, "openclaw") is True
    assert cmd_setup._guardrail_hilt_enabled_for(gc, "codex") is False
    assert cmd_setup._guardrail_hilt_enabled_for(SimpleNamespace(hilt=on), "openclaw") is True
