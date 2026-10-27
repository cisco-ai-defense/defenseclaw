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

"""Status and quickstart read Antigravity and Devin hook files the way Setup writes them (GAP-0489).

internal/gateway/connector/testdata/antigravity_devin_hooks.json holds the
files Go Setup writes on Linux and Windows: Antigravity's
~/.gemini/config/hooks.json, with DefenseClaw's hooks under top-level
defenseclaw-antigravity-<event> keys, and Devin's project .devin/hooks.v1.json,
with the event map at its root. Each sits beside a user's own hook set and is
also there after teardown removed DefenseClaw's entries. The Go tests
TestAntigravityAndDevinHookFilesMatchTheSharedGolden and
TestAntigravityAndDevinSetupWritesTheGoldenFiles check it against Setup.
Status read only a top-level ``hooks`` key and called both files unregistered
right after a clean Setup.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from defenseclaw import hook_integrity
from defenseclaw.hook_integrity import hook_registration_problems

_GOLDEN = json.loads(
    (
        Path(__file__).resolve().parents[2]
        / "internal"
        / "gateway"
        / "connector"
        / "testdata"
        / "antigravity_devin_hooks.json"
    ).read_text(encoding="utf-8")
)
_POSIX = ["antigravity_linux", "devin_workspace_linux"]

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX hook layouts")
_WINDOWS = ["antigravity_windows", "devin_workspace_windows"]


def _json_text(value: str) -> str:
    return json.dumps(value)[1:-1]


def _install(tmp_path: Path, name: str, form: str):
    """Write the golden file *name* (``healthy`` or ``removed``) and the lock Setup records."""

    golden = _GOLDEN["files"][name]
    home = tmp_path / "home"
    data_dir = home / ".defenseclaw"
    (data_dir / "hooks").mkdir(parents=True, exist_ok=True)
    launcher = tmp_path / "bin" / "defenseclaw-hook.exe"
    launcher.parent.mkdir(parents=True, exist_ok=True)
    launcher.write_bytes(b"MZ")
    text = json.dumps(golden[form])
    text = text.replace(_json_text(_GOLDEN["data_dir"]), _json_text(str(data_dir)))
    # Devin names the launcher in its command; point it at one that exists.
    windows_launcher = _GOLDEN["hook_binary_windows"].replace("\\", "/")
    text = text.replace(_json_text(windows_launcher), _json_text(launcher.as_posix()))
    config = home / golden["path"]
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(text, encoding="utf-8")
    lock = {"version": 2, "connectors": {golden["connector"]: {"locations": {"hook_config_paths": [str(config)]}}}}
    (data_dir / "hook_contract_lock.json").write_text(json.dumps(lock), encoding="utf-8")
    return SimpleNamespace(data_dir=str(data_dir), deployment_mode=""), config, golden["connector"]


def _status_and_quickstart(cfg, connector: str) -> tuple[str, object]:
    from defenseclaw.bootstrap import _connector_runtime_readiness
    from defenseclaw.commands.cmd_status import _hook_runtime_degraded_suffix

    return _hook_runtime_degraded_suffix(cfg, connector), _connector_runtime_readiness(cfg, connector)


def _unregistered(config: Path) -> list[str]:
    return [f"no DefenseClaw hooks are registered in {config}"]


@posix_only
@pytest.mark.parametrize("name", _POSIX)
def test_the_posix_file_setup_writes_is_registered(tmp_path, monkeypatch, name):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(hook_integrity, "_is_windows", lambda: False)
    cfg, _, connector = _install(tmp_path, name, "healthy")
    assert hook_registration_problems(cfg, connector) == []
    assert _status_and_quickstart(cfg, connector) == ("", None)


@pytest.mark.parametrize("name", _WINDOWS)
def test_the_windows_file_setup_writes_is_registered(tmp_path, monkeypatch, name):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(hook_integrity, "_is_windows", lambda: True)
    cfg, _, connector = _install(tmp_path, name, "healthy")
    assert hook_registration_problems(cfg, connector) == []
    assert _status_and_quickstart(cfg, connector) == ("", None)


@pytest.mark.parametrize("name", [*_POSIX, *_WINDOWS])
def test_teardown_leaves_only_the_users_hooks_and_status_says_unregistered(tmp_path, monkeypatch, name):
    # The user's own hook set stays; it does not run DefenseClaw.
    monkeypatch.chdir(tmp_path)
    windows = name in _WINDOWS
    if not windows and sys.platform == "win32":
        pytest.skip("POSIX hook layouts")
    monkeypatch.setattr(hook_integrity, "_is_windows", lambda: windows)
    cfg, config, connector = _install(tmp_path, name, "removed")
    assert hook_registration_problems(cfg, connector) == _unregistered(config)
    suffix, step = _status_and_quickstart(cfg, connector)
    assert "DEGRADED" in suffix
    assert step is not None and step.status == "warn" and "is not guarded" in step.detail


@pytest.mark.parametrize("name", [*_POSIX, *_WINDOWS])
def test_defenseclaw_entries_emptied_by_hand_are_unregistered(tmp_path, monkeypatch, name):
    # Keys left behind with no handler (Antigravity) or no DefenseClaw group
    # (Devin) register nothing.
    monkeypatch.chdir(tmp_path)
    windows = name in _WINDOWS
    if not windows and sys.platform == "win32":
        pytest.skip("POSIX hook layouts")
    monkeypatch.setattr(hook_integrity, "_is_windows", lambda: windows)
    cfg, config, connector = _install(tmp_path, name, "healthy")
    document = json.loads(config.read_text(encoding="utf-8"))
    if connector == "antigravity":
        for key, hook_set in document.items():
            if key.startswith("defenseclaw-antigravity-"):
                document[key] = {event: [] for event in hook_set}
    else:
        document = {event: groups[:-1] for event, groups in document.items()}
    config.write_text(json.dumps(document), encoding="utf-8")
    assert hook_registration_problems(cfg, connector) == _unregistered(config)


@pytest.mark.parametrize("name", ["devin_workspace_linux", "devin_workspace_windows"])
def test_a_devin_project_file_with_a_foreign_hooks_key_is_guarded(tmp_path, monkeypatch, name):
    # GAP-1720: a project hooks.v1.json that already held a foreign hook set
    # under a "hooks" key made the tool-guard check read that key as the event
    # map, so the readiness wait failed "PreToolUse hook is not registered"
    # and setup rolled back. Setup writes the events at the root beside it.
    monkeypatch.chdir(tmp_path)
    windows = name.endswith("windows")
    if not windows and sys.platform == "win32":
        pytest.skip("POSIX hook layouts")
    monkeypatch.setattr(hook_integrity, "_is_windows", lambda: windows)
    cfg, config, connector = _install(tmp_path, name, "healthy")
    document = json.loads(config.read_text(encoding="utf-8"))
    document["hooks"] = {"PostToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "/bin/true"}]}]}
    config.write_text(json.dumps(document), encoding="utf-8")
    assert hook_integrity.unguarded_tool_call_hooks(cfg, connector) == []
    assert hook_registration_problems(cfg, connector) == []


@posix_only
def test_a_devin_user_config_still_reads_its_hooks_key(tmp_path, monkeypatch):
    # Only the project hooks.v1.json is a bare event map; config.json keeps
    # its hooks key, and other top-level settings there are not hooks.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(hook_integrity, "_is_windows", lambda: False)
    cfg, config, _ = _install(tmp_path, "devin_workspace_linux", "healthy")
    events = json.loads(config.read_text(encoding="utf-8"))
    user_config = config.parent.parent / "config.json"
    lock = {"version": 2, "connectors": {"devin": {"locations": {"hook_config_paths": [str(user_config)]}}}}
    Path(cfg.data_dir, "hook_contract_lock.json").write_text(json.dumps(lock), encoding="utf-8")
    user_config.write_text(json.dumps({"hooks": events}), encoding="utf-8")
    assert hook_registration_problems(cfg, "devin") == []
    user_config.write_text(json.dumps({**events, "hooks": {}}), encoding="utf-8")
    assert hook_registration_problems(cfg, "devin") == _unregistered(user_config)
