# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""``defenseclaw keys set NAME --value-stdin``."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner
from defenseclaw.commands.cmd_keys import keys_cmd
from defenseclaw.safety import SafetyError

from tests.test_cmd_keys import _make_app_context

SECRET = "stdin-secret-test-only-9f3a"


def _dotenv(tmp_path: Path) -> str:
    path = tmp_path / ".env"
    return path.read_text(encoding="utf-8") if path.exists() else ""


def test_reads_first_line_strips_newline_and_never_echoes(tmp_path):
    app = _make_app_context(str(tmp_path))
    result = CliRunner().invoke(
        keys_cmd,
        ["set", "DEFENSECLAW_TEST_KEY", "--value-stdin"],
        obj=app,
        input=f"{SECRET}\r\nsecond-line\n",
    )
    assert result.exit_code == 0, result.output
    assert SECRET not in result.output
    body = _dotenv(tmp_path)
    assert f"DEFENSECLAW_TEST_KEY={SECRET}" in body.replace('"', "").replace("'", "")
    assert "second-line" not in body


def test_empty_stdin_exits_1_and_saves_nothing(tmp_path):
    app = _make_app_context(str(tmp_path))
    for payload in ("", "\n"):
        result = CliRunner().invoke(keys_cmd, ["set", "DEFENSECLAW_TEST_KEY", "--value-stdin"], obj=app, input=payload)
        assert result.exit_code == 1
    assert "DEFENSECLAW_TEST_KEY" not in _dotenv(tmp_path)


def test_value_and_value_stdin_are_mutually_exclusive(tmp_path):
    app = _make_app_context(str(tmp_path))
    result = CliRunner().invoke(
        keys_cmd,
        ["set", "DEFENSECLAW_TEST_KEY", "--value", "x", "--value-stdin"],
        obj=app,
        input="y\n",
    )
    assert result.exit_code == 2
    assert "DEFENSECLAW_TEST_KEY" not in _dotenv(tmp_path)


def test_keys_set_refuses_ignored_fail_mode_without_saving_or_restart_advice(tmp_path):
    app = _make_app_context(str(tmp_path))
    for mode in ("open", "closed"):
        with patch("defenseclaw.enforce.asset_lists.is_managed_standalone", return_value=False):
            result = CliRunner().invoke(
                keys_cmd, ["set", "DEFENSECLAW_FAIL_MODE", "--value-stdin"], obj=app, input=f"{mode}\n",
            )
        assert result.exit_code != 0, result.output
        assert "ignored" in result.output.lower()
        assert "defenseclaw guardrail fail-mode" in result.output
        assert "restart" not in result.output.lower()
        assert "Saved" not in result.output
        assert "DEFENSECLAW_FAIL_MODE" not in _dotenv(tmp_path)


def test_keys_set_managed_fail_mode_names_the_policy_bundle_route(tmp_path):
    app = _make_app_context(str(tmp_path))
    with patch("defenseclaw.enforce.asset_lists.is_managed_standalone", return_value=True):
        result = CliRunner().invoke(
            keys_cmd, ["set", "DEFENSECLAW_FAIL_MODE", "--value", "open"], obj=app,
        )
    assert result.exit_code != 0, result.output
    assert "ignored" in result.output.lower()
    assert "defenseclaw-gateway enterprise bundle apply" in result.output
    assert "enterprise secret" not in result.output
    assert "restart" not in result.output.lower()
    assert "DEFENSECLAW_FAIL_MODE" not in _dotenv(tmp_path)


def test_keys_set_refuses_other_ignored_process_control_keys(tmp_path):
    app = _make_app_context(str(tmp_path))
    for name in ("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT", "DEFENSECLAW_CONFIG", "PATH"):
        result = CliRunner().invoke(keys_cmd, ["set", name, "--value", "1"], obj=app)
        assert result.exit_code != 0, result.output
        assert "ignored" in result.output.lower()
        assert name not in _dotenv(tmp_path)


def test_saves_and_exits_0_when_the_gateway_cannot_record_the_audit_event(tmp_path):
    from defenseclaw.logger import CanonicalObservabilityUnavailableError

    class _OfflineLogger:
        def log_activity(self, **_kwargs):
            raise CanonicalObservabilityUnavailableError("gateway authentication is unavailable")

    app = _make_app_context(str(tmp_path))
    app.logger = _OfflineLogger()
    result = CliRunner().invoke(keys_cmd, ["set", "DEFENSECLAW_TEST_KEY", "--value-stdin"], obj=app, input=f"{SECRET}\n")

    assert result.exit_code == 0, result.output
    assert SECRET not in result.output
    assert "DEFENSECLAW_TEST_KEY" in _dotenv(tmp_path)


@pytest.mark.parametrize("action", ("set", "remove"))
def test_keys_refuse_linked_dotenv_with_bounded_remedy_and_unchanged_target(tmp_path, action):
    target = tmp_path / "held.env"
    original = "DEFENSECLAW_TEST_KEY=held-secret\n"
    target.write_text(original, encoding="utf-8")
    try:
        (tmp_path / ".env").symlink_to(target)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    app = _make_app_context(str(tmp_path))
    args = ["set", "DEFENSECLAW_TEST_KEY", "--value", SECRET] if action == "set" else [
        "remove", "DEFENSECLAW_TEST_KEY", "--yes"
    ]
    with patch("defenseclaw.enforce.asset_lists.is_managed_standalone", return_value=False):
        result = CliRunner().invoke(keys_cmd, args, obj=app)

    assert result.exit_code != 0
    assert not isinstance(result.exception, SafetyError)
    assert "symlink" in result.output.lower()
    assert "restore" in result.output.lower()
    assert "Traceback" not in result.output
    assert SECRET not in result.output
    assert target.read_text(encoding="utf-8") == original
