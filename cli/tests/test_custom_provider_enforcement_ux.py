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
"""The honest custom-provider enforcement UX (WS2).

These guard the wording that closes the "I bound a custom provider to a
hook connector so my agent runs on it" misconception: proxy connectors
say *enforced*, hook connectors say *judge/aux only*.
"""

from __future__ import annotations

from types import SimpleNamespace

from defenseclaw.commands.cmd_setup import _echo_custom_provider_enforcement
from defenseclaw.commands.cmd_setup_provider import _echo_provider_enforcement_legend


def _cfg(connector: str) -> SimpleNamespace:
    return SimpleNamespace(guardrail=SimpleNamespace(connector=connector))


def test_setup_llm_enforcement_note_proxy(capsys) -> None:
    _echo_custom_provider_enforcement(_cfg("openclaw"))
    out = capsys.readouterr().out
    assert "Enforced" in out
    assert "openclaw" in out


def test_setup_llm_enforcement_note_hook(capsys) -> None:
    _echo_custom_provider_enforcement(_cfg("hermes"))
    out = capsys.readouterr().out
    assert "Judge/aux only" in out
    assert "NOT routed through or" in out


def test_setup_llm_enforcement_note_opencode_is_hook(capsys) -> None:
    _echo_custom_provider_enforcement(_cfg("opencode"))
    out = capsys.readouterr().out
    assert "Judge/aux only" in out


def test_provider_list_legend_proxy(capsys) -> None:
    app = SimpleNamespace(cfg=SimpleNamespace(guardrail=SimpleNamespace(connector="zeptoclaw")))
    _echo_provider_enforcement_legend(app)
    out = capsys.readouterr().out
    assert "proxy connector" in out
    assert "enforced on the agent" in out


def test_provider_list_legend_hook(capsys) -> None:
    app = SimpleNamespace(cfg=SimpleNamespace(guardrail=SimpleNamespace(connector="cursor")))
    _echo_provider_enforcement_legend(app)
    out = capsys.readouterr().out
    assert "hook connector" in out
    assert "judge/aux model only" in out
