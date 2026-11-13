# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""``config set`` refuses an invalid sandbox floor value before it writes,
also where the Go validator is missing (the Python-only fallback, which
every test here runs under; lane F3, found live on dev)."""

from __future__ import annotations

import pytest
from click.testing import CliRunner
from defenseclaw.commands import cmd_config

_BASE = "config_version: 9\nguardrail:\n  profiles:\n    eng:\n      mode: action\n"


@pytest.mark.parametrize(
    ("key", "value", "message"),
    [
        ("guardrail.profiles.eng.sandbox.max_silence_after", "30s", 'sandbox.max_silence_after "30s" must be at least 1m'),
        ("guardrail.profiles.eng.sandbox.ask_timeout", "36h", 'sandbox.ask_timeout "36h" must be at most 24h0m0s'),
        ("guardrail.profiles.eng.sandbox.idle_suspend_after", "10s", 'sandbox.idle_suspend_after "10s" must be at least 1m'),
        ("openshell.admin.sandbox_class", "microvm", "admin.sandbox_class is an Agent Substrate key"),
    ],
)
def test_config_set_refuses_an_invalid_floor_before_writing(tmp_path, monkeypatch, key, value, message):
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    path = tmp_path / "config.yaml"
    path.write_text(_BASE + f"data_dir: {tmp_path}\n", encoding="utf-8")
    before = path.read_bytes()
    result = CliRunner().invoke(cmd_config.config_cmd, ["set", key, value])
    assert result.exit_code != 0, result.output
    assert "config.yaml was not changed" in result.output
    assert message in result.output
    assert "Traceback" not in result.output
    assert path.read_bytes() == before


def test_config_set_writes_a_valid_runtime_key(tmp_path, monkeypatch):
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    path = tmp_path / "config.yaml"
    path.write_text(_BASE + f"data_dir: {tmp_path}\n", encoding="utf-8")
    result = CliRunner().invoke(cmd_config.config_cmd, ["set", "guardrail.profiles.eng.sandbox.unattended_asks", "queue"])
    assert result.exit_code == 0, result.output
    assert "unattended_asks: queue" in path.read_text(encoding="utf-8")
