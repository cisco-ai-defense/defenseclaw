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

"""GAP-1141 / GAP-1138: doctor and status catch a drifted hook script or token."""

from __future__ import annotations

import hashlib
import json
import os
import sys
from types import SimpleNamespace

import pytest
from defenseclaw.commands.cmd_doctor import _check_hook_runtime_integrity, _DoctorResult
from defenseclaw.hook_integrity import hook_registration_problems, hook_runtime_problems

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="Unix hook scripts only")


def _install(tmp_path):
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    script = hooks / "codex-hook.sh"
    script.write_text('#!/bin/bash\n[ -f "${HOOK_DIR}/.hook-codex.token" ] || exit 2\n')
    (hooks / ".hook-codex.token").write_text("t\n")
    digest = "sha256:" + hashlib.sha256(script.read_bytes()).hexdigest()
    lock = {
        "version": 2,
        "connectors": {
            "codex": {
                "locations": {"hook_script_paths": [str(script)]},
                "hook_script_digests": {"codex-hook.sh": digest},
            }
        },
    }
    (tmp_path / "hook_contract_lock.json").write_text(json.dumps(lock))
    return SimpleNamespace(data_dir=str(tmp_path)), script


def test_clean_install_has_no_problems(tmp_path, monkeypatch):
    monkeypatch.delenv("DEFENSECLAW_GATEWAY_TOKEN", raising=False)
    cfg, _ = _install(tmp_path)
    assert hook_runtime_problems(cfg, "codex") == []


def test_edited_script_and_missing_token_fail_doctor(tmp_path, monkeypatch):
    monkeypatch.delenv("DEFENSECLAW_GATEWAY_TOKEN", raising=False)
    cfg, script = _install(tmp_path)
    text = script.read_text().splitlines(keepends=True)
    script.write_text(text[0] + "exit 0\n" + "".join(text[1:]))
    os.remove(tmp_path / "hooks" / ".hook-codex.token")

    problems = hook_runtime_problems(cfg, "codex")
    assert len(problems) == 2
    assert "changed since setup" in problems[0]
    assert ".hook-codex.token is missing" in problems[1]

    r = _DoctorResult(passive=True, quiet=True)
    _check_hook_runtime_integrity(cfg, "codex", r)
    row = next(row for row in r.checks if row.get("label") == "Hook runtime files")
    assert row["status"] == "fail"
    assert "defenseclaw setup codex" in row["detail"]


def test_missing_scoped_token_is_reported_even_with_gateway_token_env(tmp_path, monkeypatch):
    # GAP-1138: doctor loads DEFENSECLAW_GATEWAY_TOKEN from .env, but the
    # connector-scoped hook clears it, so the missing file still breaks hooks.
    monkeypatch.setenv("DEFENSECLAW_GATEWAY_TOKEN", "from-dotenv")
    cfg, _ = _install(tmp_path)
    os.remove(tmp_path / "hooks" / ".hook-codex.token")
    problems = hook_runtime_problems(cfg, "codex")
    assert len(problems) == 1 and ".hook-codex.token is missing" in problems[0]


def test_removed_hook_registration_is_reported(tmp_path):
    # GAP-1230: the hooks key deleted from the agent's settings file.
    settings = tmp_path / "settings.json"
    hook = {"command": "/x/defenseclaw/claude-code-hook.sh"}
    settings.write_text(json.dumps({"hooks": {"PreToolUse": [{"hooks": [hook]}]}}))
    lock = {"version": 2, "connectors": {"claudecode": {"locations": {"hook_config_paths": [str(settings)]}}}}
    (tmp_path / "hook_contract_lock.json").write_text(json.dumps(lock))
    cfg = SimpleNamespace(data_dir=str(tmp_path))
    assert hook_registration_problems(cfg, "claudecode") == []

    settings.write_text(json.dumps({"model": "x"}))
    problems = hook_registration_problems(cfg, "claudecode")
    assert problems and str(settings) in problems[0]
    assert hook_registration_problems(cfg, "codex") == []


def test_older_build_render_is_not_reported_fresh(tmp_path, monkeypatch):
    # GAP-1316: an older build's script still holds the freshness sentinels,
    # but it does not match the digest setup sealed.
    from unittest import mock

    from defenseclaw.commands import cmd_doctor

    cfg, script = _install(tmp_path)
    script.write_text(script.read_text() + "# rendered by an older build\n")
    r = _DoctorResult(passive=True, quiet=True)
    with mock.patch.object(cmd_doctor, "_stale_generated_hook_reasons", return_value=[]):
        cmd_doctor._check_generated_hook_freshness(cfg, "codex", "Codex hooks", r)
    row = r.checks[-1]
    assert row["status"] == "warn" and "defenseclaw-gateway restart" in row["remediation"]
