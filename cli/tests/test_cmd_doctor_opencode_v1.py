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

"""An OpenCode downgraded to V1 after setup fails the doctor hooks row (rel-1-0-6 GAP-0069)."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from defenseclaw import migrations
from defenseclaw.commands import cmd_doctor


def _rows(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, installed: tuple[str, str] | None) -> list[dict]:
    plugins = tmp_path / ".config" / "opencode" / "plugins"
    plugins.mkdir(parents=True)
    own = plugins / "defenseclaw.js"
    own.write_text("// defenseclaw bridge\n", encoding="utf-8")
    monkeypatch.setattr(cmd_doctor, "_hook_health_paths_from_lock", lambda _cfg, _name: [str(own)])
    monkeypatch.setattr(cmd_doctor, "_edited_hook_problem", lambda *_args: None)
    monkeypatch.setattr(cmd_doctor, "_managed_plugin_drift", lambda *_args: "")
    # OpenCode has not started since the gateway did: the row used to SKIP.
    monkeypatch.setattr(
        cmd_doctor, "_opencode_load_heartbeat_status", lambda _cfg: ("warn", "no authenticated load heartbeat"),
    )
    monkeypatch.setattr(migrations, "_installed_opencode", lambda _data_dir: installed)
    result = cmd_doctor._DoctorResult(passive=True, quiet=True)
    cfg = SimpleNamespace(
        data_dir=str(tmp_path), guardrail=SimpleNamespace(mode="observe", effective_mode=lambda _c: "observe"),
    )
    cmd_doctor._check_hook_health(cfg, "opencode", result)
    return result.checks


def test_v1_after_setup_fails_with_the_v2_remedy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    rows = _rows(tmp_path, monkeypatch, ("1.18.34", "/opt/dc-agents/bin/opencode"))

    assert [row["status"] for row in rows] == ["fail"]
    detail = rows[0]["detail"]
    assert "OpenCode 1.18.34" in detail and "OpenCode V1" in detail and "NOT protected" in detail
    remedy = rows[0].get("remediation") or ""
    assert "@opencode/cli@2" in remedy and "opencode service restart" in remedy


@pytest.mark.parametrize("installed", [("2.2.4", "/opt/dc-agents/bin/opencode"), None])
def test_v2_or_unknown_version_keeps_the_closed_opencode_skip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, installed: tuple[str, str] | None,
) -> None:
    rows = _rows(tmp_path, monkeypatch, installed)

    assert [row["status"] for row in rows] == ["skip"]
