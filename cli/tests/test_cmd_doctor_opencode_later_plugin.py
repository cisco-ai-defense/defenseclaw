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

"""GAP-0469 (follow-up of GAP-0465): doctor names another OpenCode plugin
beside defenseclaw.js in action mode, where the bridge refuses every tool
call while a later plugin is loaded and OpenCode shows only that the command
was blocked."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from defenseclaw.commands import cmd_doctor


def _cfg(mode: str) -> SimpleNamespace:
    return SimpleNamespace(guardrail=SimpleNamespace(mode="observe", effective_mode=lambda _connector: mode))


def _plugins(tmp_path: Path, *others: str) -> Path:
    plugins = tmp_path / ".config" / "opencode" / "plugins"
    plugins.mkdir(parents=True)
    own = plugins / "defenseclaw.js"
    own.write_text("// defenseclaw bridge\n", encoding="utf-8")
    for name in others:
        target = tmp_path / ".config" / "opencode" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("export const Mine = async () => ({})\n", encoding="utf-8")
    return own


def _hook_rows(monkeypatch: pytest.MonkeyPatch, own: Path, mode: str) -> list[dict]:
    monkeypatch.setattr(cmd_doctor, "_hook_health_paths_from_lock", lambda _cfg, _name: [str(own)])
    monkeypatch.setattr(cmd_doctor, "_edited_hook_problem", lambda *_args: None)
    monkeypatch.setattr(cmd_doctor, "_managed_plugin_drift", lambda *_args: "")
    monkeypatch.setattr(cmd_doctor, "_opencode_load_heartbeat_status", lambda _cfg: ("pass", "loaded"))
    result = cmd_doctor._DoctorResult(passive=True, quiet=True)
    cmd_doctor._check_hook_health(_cfg(mode), "opencode", result)
    return result.checks


def test_action_mode_warns_and_names_the_plugin_beside_defenseclaw(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    own = _plugins(tmp_path, "plugins/mine.js", "plugin/other.ts", "plugins/notes.txt")

    rows = _hook_rows(monkeypatch, own, "action")

    assert [row["label"] for row in rows] == ["OpenCode hooks", "OpenCode plugin order"]
    order = rows[1]
    assert order["status"] == "warn"
    assert "mine.js" in order["detail"] and "other.ts" in order["detail"]
    assert "notes.txt" not in order["detail"]
    assert "later plugin argument mutations are not observable" in order["detail"]
    assert str(own.parent / "mine.js") in order["remediation"]
    assert "defenseclaw guardrail mode observe --connector opencode" in order["remediation"]


def test_observe_mode_and_a_lone_plugin_add_no_row(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    own = _plugins(tmp_path, "plugins/mine.js")
    assert [row["label"] for row in _hook_rows(monkeypatch, own, "observe")] == ["OpenCode hooks"]

    lone = _plugins(tmp_path / "lone")
    assert [row["label"] for row in _hook_rows(monkeypatch, lone, "action")] == ["OpenCode hooks"]
