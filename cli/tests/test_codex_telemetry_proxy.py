# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""GAP-1550: doctor says when Codex telemetry to the gateway would use a proxy."""

from __future__ import annotations

import os
from unittest.mock import patch

from defenseclaw.commands.cmd_doctor import _CODEX_DOTENV_PROXY_MARKER, codex_telemetry_proxy_status


def _status(tmp_path, env, dotenv=None, os_name="posix"):
    if dotenv is not None:
        (tmp_path / ".env").write_text(dotenv)
    with patch.dict(os.environ, {"CODEX_HOME": str(tmp_path)}, clear=False):
        return codex_telemetry_proxy_status(env, os_name=os_name)


def test_no_proxy_variable_reports_nothing(tmp_path):
    assert _status(tmp_path, {"NO_PROXY": "corp.example"}) is None


def test_proxy_without_loopback_warns_with_one_line_fix(tmp_path):
    tag, detail, fix = _status(tmp_path, {"HTTPS_PROXY": "http://proxy.test:3128", "no_proxy": "corp.example"})
    assert tag == "warn"
    assert "HTTPS_PROXY" in detail and "OTLP credential" in detail
    assert fix.startswith("in the shell that starts Codex run: export NO_PROXY=")
    tag, _, fix = _status(tmp_path, {"http_proxy": "http://proxy.test:3128"}, os_name="nt")
    assert tag == "warn" and "setx NO_PROXY 127.0.0.1,localhost,::1" in fix


def test_managed_dotenv_or_shell_loopback_passes(tmp_path):
    env = {"HTTPS_PROXY": "http://proxy.test:3128"}
    block = f"A=1\n{_CODEX_DOTENV_PROXY_MARKER} >>>\nNO_PROXY=\"${{NO_PROXY}},127.0.0.1,169.254.169.254\"\n"
    assert _status(tmp_path, env, dotenv=block)[0] == "pass"
    os.remove(tmp_path / ".env")
    assert _status(tmp_path, {**env, "NO_PROXY": "corp.example, 127.0.0.1"})[0] == "pass"


def test_managed_dotenv_without_metadata_entry_warns(tmp_path):
    # GAP-2620: an older block without the instance-metadata addresses.
    old = f"{_CODEX_DOTENV_PROXY_MARKER} >>>\nNO_PROXY=\"${{NO_PROXY}},127.0.0.1,localhost,::1\"\n"
    tag, detail, fix = _status(tmp_path, {"HTTPS_PROXY": "http://proxy.test:3128"}, dotenv=old)
    assert tag == "warn" and "instance-metadata" in detail
    assert "defenseclaw-gateway restart" in fix
