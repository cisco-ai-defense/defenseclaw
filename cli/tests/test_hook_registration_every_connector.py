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

"""status, quickstart and doctor agree on every connector's registered hooks (GAP-0489).

internal/gateway/connector/testdata/hook_registration_every_connector.json
holds the agent hook files per-user Setup writes for every built-in hook
connector (the Go test TestEveryHookConnectorSetupMatchesTheSharedGolden
keeps it equal to Setup). Status and quickstart said "no DefenseClaw hooks
are registered" for the Antigravity hooks.json (one
``defenseclaw-antigravity-<event>`` key per event) and the Devin workspace
hooks.v1.json (events at the root) right after a clean Setup, while doctor
passed them: status read only a top-level ``hooks`` key.

Each case checks the three readers on the file Setup wrote, and on the same
JSON file with the DefenseClaw entries taken out, where all three must say
the hooks are gone.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any

import pytest
from defenseclaw import bootstrap, hook_integrity
from defenseclaw.commands import cmd_doctor, cmd_status
from defenseclaw.config import default_config

_GOLDEN = json.loads(
    (
        Path(__file__).resolve().parents[2]
        / "internal"
        / "gateway"
        / "connector"
        / "testdata"
        / "hook_registration_every_connector.json"
    ).read_text(encoding="utf-8")
)
_CASES = _GOLDEN["cases"]
_POSIX = [case for case in _CASES if case["os"] == "posix"]
_JSON_POSIX = [case for case in _POSIX if all(f["path"].endswith(".json") for f in case["files"])]

# The doctor rows that say a hook file does not register DefenseClaw.
_DOCTOR_UNREGISTERED = re.compile(
    r"does not reference DefenseClaw|no hooks registered|no DefenseClaw hook|hook file not found|not found at"
    r"|registration .*missing|is missing$|contains no DefenseClaw",
    re.IGNORECASE,
)


def _case_id(case: dict[str, Any]) -> str:
    return f"{case['connector']}-{case['scope']}-{case['os']}"


def _without_defenseclaw(value: Any) -> Any:
    """*value* with every DefenseClaw hook entry taken out, other settings kept."""

    if isinstance(value, dict):
        return {
            key: _without_defenseclaw(item) for key, item in value.items() if not key.startswith("defenseclaw-")
        }
    if isinstance(value, list):
        return [
            _without_defenseclaw(item)
            for item in value
            if not re.search(r"defenseclaw|\{data_dir\}", json.dumps(item), re.IGNORECASE)
        ]
    return value


def _install(tmp_path: Path, monkeypatch, case: dict[str, Any], *, removed: bool = False):
    home = tmp_path / "home"
    data_dir = home / ".defenseclaw"
    (data_dir / "hooks").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.chdir(tmp_path)
    # The hook scripts the gateway renders at start (doctor checks they exist;
    # their digests are another check, hook_runtime_problems).
    for script in hook_integrity.HOOK_SCRIPT_NAMES.values():
        stub = data_dir / "hooks" / script
        stub.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        stub.chmod(0o700)
    paths = []
    for file in case["files"]:
        content = file["content"]
        if removed:
            content = json.dumps(_without_defenseclaw(json.loads(content)), indent=2)
        path = Path(file["path"].replace("{data_dir}", str(data_dir)).replace("{home}", str(home)))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content.replace("{data_dir}", str(data_dir)).replace("{home}", str(home)), encoding="utf-8")
        paths.append(str(path))
    lock = {"version": 2, "connectors": {case["connector"]: {"locations": {"hook_config_paths": paths}}}}
    (data_dir / "hook_contract_lock.json").write_text(json.dumps(lock), encoding="utf-8")
    cfg = default_config()
    cfg.data_dir = str(data_dir)
    cfg.claw.workspace_dir = str(home / "ws") if case["scope"] == "workspace" else ""
    return cfg, paths


def _status_problem(cfg, connector: str) -> str:
    return cmd_status._hook_runtime_degraded_suffix(cfg, connector)


def _quickstart_problem(cfg, connector: str) -> str:
    step = bootstrap._connector_runtime_readiness(cfg, connector)
    return "" if step is None else step.detail


def _doctor_rows(cfg, connector: str, monkeypatch) -> list[dict[str, Any]]:
    # The OpenCode row also checks the custody receipt Setup leaves in the data
    # directory, which this fixture does not have; that is not registration.
    monkeypatch.setattr(cmd_doctor, "_opencode_managed_plugin_drift", lambda *_a, **_k: "")
    r = cmd_doctor._DoctorResult(passive=True)
    cmd_doctor._check_connector_hooks(cfg, connector, r)
    rows = list(r.checks)
    assert rows, f"doctor wrote no hook row for {connector}"
    return rows


def _doctor_unregistered(rows: list[dict[str, Any]]) -> list[str]:
    return [
        f"{row['label']}: {row['detail']}"
        for row in rows
        if row.get("status") == "fail" and _DOCTOR_UNREGISTERED.search(str(row.get("detail") or ""))
    ]


def test_the_golden_covers_every_supported_hook_connector():
    connectors = {case["connector"] for case in _CASES}
    assert set(hook_integrity.HOOK_SCRIPT_NAMES) <= connectors
    assert {"amp", "opencode"} <= connectors
    assert {("antigravity", "windows"), ("devin", "posix")} <= {(c["connector"], c["os"]) for c in _CASES}
    assert any(c["connector"] == "devin" and c["scope"] == "workspace" for c in _CASES)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX hook layouts")
@pytest.mark.parametrize("case", _POSIX, ids=_case_id)
def test_status_quickstart_and_doctor_call_the_setup_file_registered(tmp_path, monkeypatch, case):
    connector = case["connector"]
    cfg, paths = _install(tmp_path, monkeypatch, case)
    assert hook_integrity.hook_registration_problems(cfg, connector) == []
    assert _status_problem(cfg, connector) == ""
    assert _quickstart_problem(cfg, connector) == ""
    # Doctor also checks what the hook scripts hold (the fixture's are stubs);
    # only a row that calls the file unregistered disagrees with status.
    assert _doctor_unregistered(_doctor_rows(cfg, connector, monkeypatch)) == []


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX hook layouts")
@pytest.mark.parametrize("case", _JSON_POSIX, ids=_case_id)
def test_status_quickstart_and_doctor_all_see_removed_hooks(tmp_path, monkeypatch, case):
    connector = case["connector"]
    cfg, paths = _install(tmp_path, monkeypatch, case, removed=True)
    expected = f"no DefenseClaw hooks are registered in {paths[0]}"
    assert hook_integrity.hook_registration_problems(cfg, connector) == [expected]
    assert "DEGRADED" in _status_problem(cfg, connector)
    assert expected in _quickstart_problem(cfg, connector)
    assert _doctor_unregistered(_doctor_rows(cfg, connector, monkeypatch))


@pytest.mark.parametrize("case", [c for c in _CASES if c["os"] == "windows"], ids=_case_id)
def test_the_windows_render_is_registered_until_its_entries_are_removed(tmp_path, monkeypatch, case):
    # Per-user Windows names the launcher only inside each PowerShell
    # -EncodedCommand; status and quickstart decode it.
    monkeypatch.setattr(hook_integrity, "_is_windows", lambda: True)
    connector = case["connector"]
    cfg, paths = _install(tmp_path, monkeypatch, case)
    assert "defenseclaw-hook.exe" not in Path(paths[0]).read_text(encoding="utf-8")
    assert hook_integrity.hook_registration_problems(cfg, connector) == []
    assert _quickstart_problem(cfg, connector) == ""
    cfg, paths = _install(tmp_path / "removed", monkeypatch, case, removed=True)
    assert hook_integrity.hook_registration_problems(cfg, connector) == [
        f"no DefenseClaw hooks are registered in {paths[0]}"
    ]
    assert os.path.getsize(paths[0]) < 16
