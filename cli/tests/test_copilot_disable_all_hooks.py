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

"""An agent setting that turns its hooks off fails every guarded-or-not check (rel-1-0-4 GAP-0580).

With ``disableAllHooks: true`` in the per-user Copilot settings, Copilot runs
none of its hooks, so no tool call reaches DefenseClaw. The doctor Copilot row
failed, but ``status``, the first-run "Connector runtime" read-back (also used
after guardrail changes) and the ``guardrail status`` posture rows read
:func:`hook_integrity.agent_hook_switch_problems`, which had no Copilot branch,
and showed the connector as guarded. The Claude Code and Codex switches were
reported there only as a warning.

Each case starts from the files Setup writes
(internal/gateway/connector/testdata/hook_registration_every_connector.json).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest
from defenseclaw import bootstrap, hook_integrity
from defenseclaw.commands import cmd_doctor, cmd_status

from tests.test_hook_registration_every_connector import _CASES, _case_id, _install

_COPILOT = [case for case in _CASES if case["connector"] == "copilot"]
_COPILOT_PARAMS = [
    pytest.param(
        case,
        id=_case_id(case),
        marks=pytest.mark.skipif(sys.platform == "win32" and case["os"] == "posix", reason="POSIX hook layouts"),
    )
    for case in _COPILOT
]

# Every layer of the Copilot settings cascade (connector_paths.copilot_settings_paths).
_USER_LAYERS = ["{home}/.copilot/config.json", "{home}/.copilot/settings.json"]
_REPOSITORY_LAYERS = [
    "{home}/ws/.claude/settings.json",
    "{home}/ws/.github/copilot/settings.json",
    "{home}/ws/.claude/settings.local.json",
    "{home}/ws/.github/copilot/settings.local.json",
]


def _layers(case: dict[str, Any]) -> list[str]:
    return _USER_LAYERS + (_REPOSITORY_LAYERS if case["scope"] == "workspace" else [])


_SWITCH_CASES = [
    pytest.param(
        case,
        layer,
        platform,
        id=f"{_case_id(case)}-{Path(layer).parent.name}-{Path(layer).name}-{platform}",
        marks=pytest.mark.skipif(sys.platform == "win32" and case["os"] == "posix", reason="POSIX hook layouts"),
    )
    for case in _COPILOT
    for layer in _layers(case)
    for platform in ("posix", "windows")
]


def _copilot(tmp_path: Path, monkeypatch, case: dict[str, Any], platform: str = "posix"):
    monkeypatch.delenv("COPILOT_HOME", raising=False)
    if platform == "windows":
        monkeypatch.setattr(hook_integrity, "_is_windows", lambda: True)
        monkeypatch.setattr(hook_integrity, "hook_launcher_problems", lambda cfg, connector: [])
    return _install(tmp_path, monkeypatch, case)


def _write(tmp_path: Path, layer: str, content: str) -> Path:
    path = Path(layer.replace("{home}", str(tmp_path / "home")))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _readiness(cfg, connector: str):
    return bootstrap._connector_runtime_readiness(cfg, connector)


def _doctor_rows(cfg, monkeypatch) -> list[dict[str, Any]]:
    monkeypatch.setattr(cmd_doctor, "_opencode_managed_plugin_drift", lambda *_a, **_k: "")
    r = cmd_doctor._DoctorResult(passive=True, quiet=True)
    cmd_doctor._check_connector_hooks(cfg, "copilot", r)
    return [row for row in r.checks if row["label"] == "Copilot hooks"]


@pytest.mark.parametrize("case", _COPILOT_PARAMS)
def test_the_files_setup_writes_are_guarded(tmp_path, monkeypatch, case):
    cfg, _paths = _copilot(tmp_path, monkeypatch, case)
    _write(tmp_path, "{home}/.copilot/settings.json", json.dumps({"disableAllHooks": False}))
    assert hook_integrity.agent_hook_switch_problems(cfg, "copilot") == []
    assert hook_integrity.unrunnable_hook_problem(cfg, "copilot") == ""
    assert cmd_status._hook_runtime_degraded_suffix(cfg, "copilot") == ""
    assert _readiness(cfg, "copilot") is None


@pytest.mark.parametrize("case, layer, platform", _SWITCH_CASES)
def test_disable_all_hooks_is_reported_by_every_check(tmp_path, monkeypatch, case, layer, platform):
    cfg, _paths = _copilot(tmp_path, monkeypatch, case, platform)
    settings = _write(tmp_path, layer, json.dumps({"disableAllHooks": True}))

    problems = hook_integrity.agent_hook_switch_problems(cfg, "copilot")
    assert len(problems) == 1 and str(settings) in problems[0], problems
    assert "not guarding its tool calls" in problems[0]
    assert f"remove disableAllHooks from {settings}" in hook_integrity.repair_command("copilot", problems[0])
    # status, guardrail status and the setup read-back.
    assert hook_integrity.unrunnable_hook_problem(cfg, "copilot") == problems[0]
    assert problems[0] in cmd_status._hook_runtime_degraded_suffix(cfg, "copilot")
    step = _readiness(cfg, "copilot")
    assert step is not None and step.status == "fail" and problems[0] in step.detail, step
    if platform == "posix":
        rows = _doctor_rows(cfg, monkeypatch)
        assert rows and all(row["status"] == "fail" for row in rows), rows


@pytest.mark.parametrize("case", _COPILOT_PARAMS)
def test_a_later_settings_layer_turns_the_hooks_back_on(tmp_path, monkeypatch, case):
    cfg, _paths = _copilot(tmp_path, monkeypatch, case)
    layers = _layers(case)
    _write(tmp_path, layers[0], json.dumps({"disableAllHooks": True}))
    _write(tmp_path, layers[-1], json.dumps({"disableAllHooks": False}))
    assert hook_integrity.agent_hook_switch_problems(cfg, "copilot") == []


@pytest.mark.parametrize("content", ['{"disableAllHooks": "yes"}', "{not json", "[]"])
@pytest.mark.skipif(sys.platform == "win32", reason="POSIX hook layouts")
def test_unreadable_copilot_settings_fail_closed(tmp_path, monkeypatch, content):
    case = next(c for c in _COPILOT if c["scope"] == "user")
    cfg, _paths = _copilot(tmp_path, monkeypatch, case)
    settings = _write(tmp_path, "{home}/.copilot/settings.json", content)
    problems = hook_integrity.agent_hook_switch_problems(cfg, "copilot")
    assert len(problems) == 1 and str(settings) in problems[0], problems
    assert "cannot tell whether Copilot runs its hooks" in problems[0]
    assert hook_integrity.unrunnable_hook_problem(cfg, "copilot") == problems[0]
    step = _readiness(cfg, "copilot")
    assert step is not None and step.status == "fail", step


@pytest.mark.parametrize(
    "connector, path, content",
    [
        ("claudecode", "{home}/.claude/settings.json", None),
        ("codex", "{home}/.codex/config.toml", "\n[features]\nhooks = false\n"),
    ],
)
@pytest.mark.skipif(sys.platform == "win32", reason="POSIX hook layouts")
def test_every_agent_hook_switch_fails_the_setup_read_back(tmp_path, monkeypatch, connector, path, content):
    case = next(c for c in _CASES if c["connector"] == connector and c["os"] == "posix" and c["scope"] == "user")
    cfg, paths = _install(tmp_path, monkeypatch, case)
    target = Path(path.replace("{home}", str(tmp_path / "home")))
    assert str(target) in paths
    if content is None:
        document = json.loads(target.read_text(encoding="utf-8"))
        document["disableAllHooks"] = True
        target.write_text(json.dumps(document), encoding="utf-8")
    else:
        target.write_text(target.read_text(encoding="utf-8") + content, encoding="utf-8")
    assert hook_integrity.agent_hook_switch_problems(cfg, connector)
    step = _readiness(cfg, connector)
    assert step is not None and step.status == "fail", step


@pytest.mark.parametrize("value", [True, "yes"], ids=["true", "not-boolean"])
@pytest.mark.parametrize("platform", ["posix", "windows"])
@pytest.mark.parametrize("recorded", [True, False], ids=["recorded", "lock-without-paths"])
@pytest.mark.parametrize("case", _COPILOT_PARAMS)
def test_disable_all_hooks_in_the_hook_registration_file(tmp_path, monkeypatch, case, recorded, platform, value):
    """Copilot also reads disableAllHooks from the DefenseClaw hook file itself, as setup and the Windows doctor do."""

    cfg, paths = _copilot(tmp_path, monkeypatch, case, platform)
    registration = Path(paths[0])
    document = json.loads(registration.read_text(encoding="utf-8"))
    registration.write_text(json.dumps({"disableAllHooks": value, **document}), encoding="utf-8")
    if not recorded:
        # A lock from before the hook files were recorded (an upgrade).
        lock = Path(cfg.data_dir, "hook_contract_lock.json")
        lock.write_text(json.dumps({"version": 2, "connectors": {"copilot": {"locations": {}}}}), encoding="utf-8")

    problems = hook_integrity.agent_hook_switch_problems(cfg, "copilot")
    assert len(problems) == 1 and str(registration) in problems[0], problems
    assert f"remove disableAllHooks from {registration}" in hook_integrity.repair_command("copilot", problems[0])
    assert hook_integrity.unrunnable_hook_problem(cfg, "copilot") == problems[0]
    assert problems[0] in cmd_status._hook_runtime_degraded_suffix(cfg, "copilot")
    if recorded:
        step = _readiness(cfg, "copilot")
        assert step is not None and step.status == "fail" and problems[0] in step.detail, step
    if platform == "posix":
        rows = _doctor_rows(cfg, monkeypatch)
        assert rows and all(row["status"] == "fail" for row in rows), rows
        assert any(str(registration) in row["detail"] for row in rows), rows


@pytest.mark.parametrize("case", _COPILOT_PARAMS)
def test_disable_all_hooks_false_in_the_hook_registration_file_is_guarded(tmp_path, monkeypatch, case):
    cfg, paths = _copilot(tmp_path, monkeypatch, case)
    registration = Path(paths[0])
    document = json.loads(registration.read_text(encoding="utf-8"))
    registration.write_text(json.dumps({"disableAllHooks": False, **document}), encoding="utf-8")
    assert hook_integrity.agent_hook_switch_problems(cfg, "copilot") == []
    assert _readiness(cfg, "copilot") is None


@pytest.mark.parametrize(
    "field, value, why",
    [("timeout", 1, "timeout is 1"), ("matcher", "NoSuchTool", "")],
    ids=["timeout", "matcher"],
)
@pytest.mark.skipif(sys.platform == "win32", reason="POSIX hook layouts")
def test_a_hook_entry_that_lets_tool_calls_run_unchecked_fails_the_setup_read_back(
    tmp_path, monkeypatch, field, value, why
):
    case = next(c for c in _CASES if c["connector"] == "claudecode" and c["os"] == "posix" and c["scope"] == "user")
    cfg, paths = _install(tmp_path, monkeypatch, case)
    settings = Path(tmp_path / "home" / ".claude" / "settings.json")
    assert str(settings) in paths
    document = json.loads(settings.read_text(encoding="utf-8"))
    for entry in document["hooks"]["PreToolUse"]:
        if field == "matcher":
            entry["matcher"] = value
        else:
            for handler in entry["hooks"]:
                handler[field] = value
    settings.write_text(json.dumps(document), encoding="utf-8")

    problems = hook_integrity.unguarded_tool_call_hooks(cfg, "claudecode")
    assert problems and "tool calls can run unchecked" in problems[0] and why in problems[0], problems
    step = _readiness(cfg, "claudecode")
    assert step is not None and step.status == "fail" and problems[0] in step.detail, step
