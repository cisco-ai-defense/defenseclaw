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

"""Hooks must deny every verdict other than ALLOW and WARN."""
from __future__ import annotations

import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

import langchain_hook  # noqa: E402
import picoclaw_hook  # noqa: E402
from generic_hook import ACTION_ALLOW, ACTION_ESCALATE, ACTION_WARN, Verdict  # noqa: E402


# -----------------------------------------------------------------------
# PicoClaw before_tool
# -----------------------------------------------------------------------
def _pico_engine(action: int) -> MagicMock:
    engine = MagicMock()
    engine.evaluate.return_value = Verdict.from_raw(action, 0x06)
    return engine


@pytest.mark.parametrize("action", [ACTION_ESCALATE, 5, -1])
def test_picoclaw_denies_non_permitting_actions(monkeypatch, action):
    monkeypatch.setattr(picoclaw_hook, "get_engine", lambda: _pico_engine(action))
    result = picoclaw_hook.handle_before_tool({"tool": "drive", "arguments": {"x": 1}})
    assert result["action"] == "deny_tool"


@pytest.mark.parametrize("action", [ACTION_ALLOW, ACTION_WARN])
def test_picoclaw_continues_on_allow_and_warn(monkeypatch, action):
    monkeypatch.setattr(picoclaw_hook, "get_engine", lambda: _pico_engine(action))
    result = picoclaw_hook.handle_before_tool({"tool": "get_sensors", "arguments": {}})
    assert result == {"action": "continue"}


# -----------------------------------------------------------------------
# LangGraph node without langchain_core.messages
# -----------------------------------------------------------------------
@pytest.fixture
def langchain_without_toolmessage(monkeypatch):
    """Provide langchain_core.tools but make ToolMessage unimportable."""
    core = types.ModuleType("langchain_core")
    tools = types.ModuleType("langchain_core.tools")

    class BaseTool:  # minimal stand-in
        pass

    tools.BaseTool = BaseTool
    tools.ToolException = type("ToolException", (Exception,), {})
    monkeypatch.setitem(sys.modules, "langchain_core", core)
    monkeypatch.setitem(sys.modules, "langchain_core.tools", tools)
    # None in sys.modules makes "import langchain_core.messages" raise ImportError.
    monkeypatch.setitem(sys.modules, "langchain_core.messages", None)
    for name in ("_BaseTool", "_ToolMessage", "_ToolException"):
        monkeypatch.setattr(langchain_hook, name, None)
    yield


def test_langgraph_node_drops_blocked_calls_without_toolmessage(
        langchain_without_toolmessage, monkeypatch):
    ec = MagicMock()
    ec.evaluate.side_effect = lambda tool_name, arguments: (
        Verdict.error("POLICY_TABLE") if tool_name == "exec_shell" else Verdict.allow())
    monkeypatch.setattr(langchain_hook, "_connector", ec)

    class AIMessage:
        def __init__(self, tool_calls):
            self.tool_calls = tool_calls

    calls = [
        {"name": "exec_shell", "args": {"cmd": "id"}, "id": "1"},
        {"name": "read_file", "args": {"path": "/tmp/x"}, "id": "2"},
    ]
    original = AIMessage(list(calls))
    out = langchain_hook.edge_connector_node({"messages": [original]})

    assert langchain_hook._ToolMessage is None
    remaining = out["messages"][-1].tool_calls
    assert [c["name"] for c in remaining] == ["read_file"]
    # The caller's message is not mutated.
    assert original.tool_calls == calls
