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

"""Every hook edit that lets a tool call run unchecked fails doctor, status and fail-mode (rel-1-0-4 GAP-0538).

On Linux the Antigravity doctor row stayed PASS with ``enabled: false`` or
matcher ``run_command`` on the DefenseClaw PreToolUse registration, and the
Copilot row with preToolUse ``type: prompt`` or ``timeoutSec: 1``;
``guardrail fail-mode`` showed no drift, and ``guardrail fail-mode closed
--yes`` said there was nothing to do. Doctor only looked for the hook script
name in the file; the field checks ran on Windows only.

Each case starts from a file Setup writes
(internal/gateway/connector/testdata/hook_registration_every_connector.json)
and edits one field of one tool-guard event in the shared table
(hook_guard_matrix.TOOL_GUARD_HOOKS).
"""

from __future__ import annotations

import copy
import json
import re
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner
from defenseclaw import codex_toml, doctor_hooks, fail_mode, hook_integrity
from defenseclaw.commands import cmd_doctor, cmd_guardrail, cmd_setup
from defenseclaw.context import AppContext
from defenseclaw.hook_guard_matrix import ANTIGRAVITY, KIRO, TOOL_GUARD_HOOKS, _entries, antigravity_hook_key

from tests.test_hook_registration_every_connector import _CASES, _case_id, _install

_GUARDED = [case for case in _CASES if case["connector"] in TOOL_GUARD_HOOKS]


def _edits(connector: str) -> list[str]:
    spec = TOOL_GUARD_HOOKS[connector]
    edits = ["event-removed", "timeout-short"]
    if spec.typed:
        edits.append("type-prompt")
    if spec.matchers:
        edits.append("matcher-narrowed")
    if spec.layout in (ANTIGRAVITY, KIRO):
        edits.append("disabled")
    if connector == "claudecode":
        edits += ["async", "if-condition"]
    return edits


_EDIT_CASES = [
    pytest.param(
        case,
        event,
        edit,
        id=f"{_case_id(case)}-{event}-{edit}",
        marks=pytest.mark.skipif(sys.platform == "win32" and case["os"] == "posix", reason="POSIX hook layouts"),
    )
    for case in _GUARDED
    for event in TOOL_GUARD_HOOKS[case["connector"]].events
    for edit in _edits(case["connector"])
]


def _load(path: str, content: str) -> Any:
    if path.endswith(".toml"):
        return codex_toml.loads(content.encode("utf-8"))
    if path.endswith((".yaml", ".yml")):
        import yaml

        return yaml.safe_load(content)
    return json.loads(content)


def _dump(path: str, document: Any) -> str:
    if path.endswith((".yaml", ".yml")):
        import yaml

        return yaml.safe_dump(document, sort_keys=False)
    return json.dumps(document, indent=2)


def _edit(connector: str, document: dict[str, Any], event: str, edit: str) -> None:
    """Apply *edit* to the DefenseClaw *event* entry of *document*, in place."""

    spec = TOOL_GUARD_HOOKS[connector]
    if edit == "event-removed":
        if spec.layout == ANTIGRAVITY:
            del document[antigravity_hook_key(event)]
        elif spec.layout == KIRO:
            document["hooks"] = [item for item in document["hooks"] if item.get("trigger") != event]
        else:
            hooks = document["hooks"] if isinstance(document.get("hooks"), dict) else document
            del hooks[event]
        return
    entries = list(_entries(spec, document, event))
    assert entries, f"{connector} {event} has no entry to edit"
    for entry in entries:
        matcher_holder = entry.containers[-1] if entry.containers else entry.handler
        timeout_holder = entry.containers[0] if spec.layout == KIRO else entry.handler
        if edit == "timeout-short":
            timeout_holder[spec.timeout_key] = 1
        elif edit == "type-prompt":
            entry.handler["type"] = "prompt"
        elif edit == "matcher-narrowed":
            matcher_holder["matcher"] = "run_command"
        elif edit == "disabled":
            entry.containers[0]["enabled"] = False
        elif edit == "async":
            entry.handler["async"] = True
        elif edit == "if-condition":
            entry.handler["if"] = "Bash(git *)"


_TOML_EDITS = {
    "timeout-short": ("timeout = 30", "timeout = 1"),
    "type-prompt": ("type = 'command'", "type = 'prompt'"),
    "matcher-narrowed": ("matcher = '*'", "matcher = 'run_command'"),
}


def _edit_toml(content: str, event: str, edit: str) -> str:
    """Edit the Codex config.toml text Setup wrote (there is no TOML writer here)."""

    blocks = re.split(r"(?m)^(?=\[)", content)
    owned = (f"[[hooks.{event}]]", f"[[hooks.{event}.hooks]]")
    if edit == "event-removed":
        return "".join(block for block in blocks if not block.startswith(owned))
    old, new = _TOML_EDITS[edit]
    edited = [block.replace(old, new) if block.startswith(owned) else block for block in blocks]
    assert edited != blocks, f"no {old!r} in the Codex {event} entry"
    return "".join(edited)


def _edited_case(case: dict[str, Any], event: str, edit: str) -> dict[str, Any]:
    edited = copy.deepcopy(case)
    file = edited["files"][0]
    if file["path"].endswith(".toml"):
        file["content"] = _edit_toml(file["content"], event, edit)
        return edited
    document = _load(file["path"], file["content"])
    _edit(case["connector"], document, event, edit)
    file["content"] = _dump(file["path"], document)
    return edited


def _windows(monkeypatch, case: dict[str, Any]) -> None:
    if case["os"] == "windows":
        monkeypatch.setattr(hook_integrity, "_is_windows", lambda: True)
        monkeypatch.setattr(hook_integrity, "hook_launcher_problems", lambda cfg, connector: [])


def _doctor_rows(cfg, connector: str, monkeypatch) -> list[dict[str, Any]]:
    monkeypatch.setattr(cmd_doctor, "_opencode_managed_plugin_drift", lambda *_a, **_k: "")
    r = cmd_doctor._DoctorResult(passive=True, quiet=True)
    cmd_doctor._check_connector_hooks(cfg, connector, r)
    return list(r.checks)


def _fail_mode_drift(cfg, connector: str) -> list[str]:
    return list(fail_mode.connector_fail_mode_report(cfg, connector)["drift"])


def test_the_table_covers_every_hook_connector_setup_writes():
    # A new hook connector needs its tool-guard row; a renamed event or a
    # changed timeout in Setup fails the pristine cases below.
    hook_connectors = {case["connector"] for case in _CASES} - {"amp", "opencode"}
    assert hook_connectors == set(TOOL_GUARD_HOOKS)


@pytest.mark.parametrize(
    "case",
    [
        pytest.param(
            case,
            id=_case_id(case),
            marks=pytest.mark.skipif(sys.platform == "win32" and case["os"] == "posix", reason="POSIX hook layouts"),
        )
        for case in _GUARDED
    ],
)
def test_the_files_setup_writes_keep_tool_calls_guarded(tmp_path, monkeypatch, case):
    _windows(monkeypatch, case)
    cfg, paths = _install(tmp_path, monkeypatch, case)
    connector = case["connector"]
    assert hook_integrity.unguarded_tool_call_hooks(cfg, connector) == []
    assert fail_mode.REGISTRATION_UNGUARDED not in _fail_mode_drift(cfg, connector)
    document = _load(paths[0], Path(paths[0]).read_text(encoding="utf-8"))
    spec = TOOL_GUARD_HOOKS[connector]
    for event in spec.events:
        entries = list(_entries(spec, document, event))
        assert entries, f"Setup registers no {connector} {event} entry"
        for entry in entries:
            assert entry.timeout == spec.timeout


@pytest.mark.parametrize("case, event, edit", _EDIT_CASES)
def test_status_quickstart_and_fail_mode_report_an_unguarded_hook_edit(tmp_path, monkeypatch, case, event, edit):
    _windows(monkeypatch, case)
    connector = case["connector"]
    cfg, paths = _install(tmp_path, monkeypatch, _edited_case(case, event, edit))
    problems = hook_integrity.hook_registration_problems(cfg, connector)
    assert problems and event in problems[0] and paths[0] in problems[0], problems
    assert "not inspected" in problems[0] or "can run unchecked" in problems[0]
    assert hook_integrity.repair_command(connector, problems[0]).startswith(
        f"run `{hook_integrity.setup_command(connector)} --yes`"
    )
    # guardrail status says the connector is not guarded, and the
    # fail-mode views show drift, so `fail-mode closed --yes` repairs it.
    assert hook_integrity.unrunnable_hook_problem(cfg, connector) == problems[0]
    assert fail_mode.REGISTRATION_UNGUARDED in _fail_mode_drift(cfg, connector)
    assert fail_mode.registration_unguarded(cfg, connector)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX hook layouts")
@pytest.mark.parametrize("case, event, edit", [p for p in _EDIT_CASES if p.values[0]["os"] == "posix"])
def test_doctor_fails_an_unguarded_hook_edit(tmp_path, monkeypatch, case, event, edit):
    connector = case["connector"]
    label = cmd_doctor._SETUP_READINESS_PRIMARY_LABELS[connector]
    cfg, _paths = _install(tmp_path, monkeypatch, case)
    pristine = [row for row in _doctor_rows(cfg, connector, monkeypatch) if row["label"] == label]
    assert not any(
        "can run unchecked" in str(row.get("detail")) or "not inspected" in str(row.get("detail")) for row in pristine
    ), pristine

    cfg, paths = _install(tmp_path / "edited", monkeypatch, _edited_case(case, event, edit))
    rows = [row for row in _doctor_rows(cfg, connector, monkeypatch) if row["label"] == label]
    failed = [row for row in rows if row["status"] == "fail" and event in str(row.get("detail"))]
    assert failed, rows
    assert not any(row["status"] == "pass" for row in rows), rows
    assert f"{hook_integrity.setup_command(connector)} --yes" in str(failed[0].get("remediation"))


# A managed install keeps the field checks: Antigravity, Devin, Hermes and
# Kiro keep user-writable per-user files there, and the enterprise policy
# guard checks no enabled flag or matcher. Only a machine-policy connector's
# timeout is the enterprise policy's to check.
_MANAGED_EDIT_CASES = [
    p
    for p in _EDIT_CASES
    if p.values[0]["os"] == "posix"
    and p.values[2] != "event-removed"
    and not (p.values[2] == "timeout-short" and TOOL_GUARD_HOOKS[p.values[0]["connector"]].machine_policy)
]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX hook layouts")
@pytest.mark.parametrize("case, event, edit", _MANAGED_EDIT_CASES)
def test_a_managed_install_fails_an_unguarded_hook_edit(tmp_path, monkeypatch, case, event, edit):
    connector = case["connector"]
    label = cmd_doctor._SETUP_READINESS_PRIMARY_LABELS[connector]
    cfg, _paths = _install(tmp_path, monkeypatch, _edited_case(case, event, edit))
    cfg.deployment_mode = "managed_enterprise"
    rows = [row for row in _doctor_rows(cfg, connector, monkeypatch) if row["label"] == label]
    assert any(row["status"] == "fail" and event in str(row.get("detail")) for row in rows), rows
    assert not any(row["status"] == "pass" for row in rows), rows
    assert fail_mode.REGISTRATION_UNGUARDED in _fail_mode_drift(cfg, connector)


@pytest.mark.parametrize("connector", sorted(c for c, spec in TOOL_GUARD_HOOKS.items() if spec.machine_policy))
def test_a_managed_install_leaves_the_machine_policy_timeout_to_the_enterprise_policy(tmp_path, monkeypatch, connector):
    case = next(c for c in _GUARDED if c["connector"] == connector and c["os"] == "posix")
    event = TOOL_GUARD_HOOKS[connector].events[0]
    cfg, _paths = _install(tmp_path, monkeypatch, _edited_case(case, event, "timeout-short"))
    cfg.deployment_mode = "managed_enterprise"
    assert hook_integrity.unguarded_tool_call_hooks(cfg, connector) == []


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX hook layouts")
def test_doctor_fix_restarts_the_gateway_for_an_unguarded_hook_edit(tmp_path, monkeypatch):
    case = next(c for c in _GUARDED if c["connector"] == "antigravity" and c["os"] == "posix")
    cfg, _paths = _install(tmp_path, monkeypatch, _edited_case(case, "PreToolUse", "disabled"))
    monkeypatch.setattr(cmd_doctor, "_doctor_active_connectors", lambda _cfg: ["antigravity"])
    assert cmd_doctor._drifted_hook_connectors(cfg) == ["antigravity"]


def _single_connector_fail_mode(cfg) -> str:
    app = AppContext()
    app.cfg = cfg
    app.logger = MagicMock()
    with (
        patch.object(cmd_guardrail, "_gateway_running", return_value=False),
        patch.object(cmd_guardrail, "reconcile_connector_registration"),
        patch.object(cmd_setup, "_restart_services"),
        patch.object(type(cfg), "save", lambda self: None),
    ):
        result = CliRunner().invoke(cmd_guardrail.fail_mode_cmd, ["closed", "--yes"], obj=app)
    assert result.exit_code == 0, result.output
    return " ".join(result.output.split())


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX hook layouts")
@pytest.mark.parametrize("connector", ["antigravity", "copilot"])
def test_fail_mode_closed_does_not_skip_an_unguarded_registration(tmp_path, monkeypatch, connector):
    case = next(c for c in _GUARDED if c["connector"] == connector and c["os"] == "posix" and c["scope"] == "user")
    event = TOOL_GUARD_HOOKS[connector].events[0]
    cfg, _paths = _install(tmp_path, monkeypatch, case)
    cfg.guardrail.connector = connector
    cfg.guardrail.connectors = {}
    cfg.guardrail.hook_fail_mode = "closed"
    cfg.guardrail.enabled = True
    assert "nothing to do" in _single_connector_fail_mode(cfg)

    cfg, _paths = _install(tmp_path / "edited", monkeypatch, _edited_case(case, event, "timeout-short"))
    cfg.guardrail.connector = connector
    cfg.guardrail.connectors = {}
    cfg.guardrail.hook_fail_mode = "closed"
    cfg.guardrail.enabled = True
    assert "nothing to do" not in _single_connector_fail_mode(cfg)

    app = AppContext()
    app.cfg = cfg
    app.logger = MagicMock()
    view = CliRunner().invoke(cmd_guardrail.fail_mode_cmd, [], obj=app)
    assert view.exit_code == 0, view.output
    assert f"drift: {fail_mode.REGISTRATION_UNGUARDED}" in view.output


# The Windows registration validators enforce the same fields on Windows.
_WINDOWS_ANTIGRAVITY = next(c for c in _CASES if c["connector"] == "antigravity" and c["os"] == "windows")


@pytest.mark.parametrize("edit", _edits("antigravity"))
def test_the_windows_antigravity_validator_refuses_each_unguarded_edit(edit):
    document = json.loads(_WINDOWS_ANTIGRAVITY["files"][0]["content"])
    _edit("antigravity", document, "PreToolUse", edit)
    with pytest.raises(doctor_hooks._InspectionError):
        doctor_hooks._validate_antigravity_hook_matrix(document)


def test_the_windows_validators_agree_with_the_shared_table():
    # Copilot, Antigravity, Devin and Hermes read their timeout (and the
    # Antigravity matcher) from the table; the Claude Code and Codex event
    # tables cover more events, so their tool-guard rows must match it.
    claude = TOOL_GUARD_HOOKS["claudecode"]
    matcher, timeout = doctor_hooks._CLAUDE_REQUIRED_HOOKS["PreToolUse"]
    assert matcher in claude.matchers and timeout == claude.timeout
    codex = TOOL_GUARD_HOOKS["codex"]
    _key, matcher, timeout = doctor_hooks._CODEX_HOOK_SPECS["PreToolUse"]
    assert matcher in codex.matchers and timeout == codex.timeout
    assert doctor_hooks._HERMES_REQUIRED_HOOKS["pre_tool_call"] in TOOL_GUARD_HOOKS["hermes"].matchers
    assert doctor_hooks._ANTIGRAVITY_REQUIRED_HOOKS["PreToolUse"] is True
