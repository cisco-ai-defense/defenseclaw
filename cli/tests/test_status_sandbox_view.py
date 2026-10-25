# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Status inside an agent's sandbox does not call a valid config invalid (GAP-1395).

Codex runs its tools in an unprivileged user namespace that shows every
unmapped host owner, root included, as the overflow UID. ``/home`` then looks
owned by account 65534, and status called a valid config invalid and advised
``chmod go-w /home``.
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner
from defenseclaw import file_permissions
from defenseclaw.commands import cmd_config, cmd_status
from defenseclaw.commands.cmd_status import status as status_cmd
from defenseclaw.config_inspect import ConfigInspectError

from tests.helpers import cleanup_app, make_app_context

posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX executable custody")


def _sandboxed_gateway(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[str, Path]:
    hidden = tmp_path / "home"
    binary = hidden / "bin" / "defenseclaw-gateway"
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b"#!/bin/sh\n")
    binary.chmod(0o755)
    real_owner = file_permissions.tracked_host_owner_uid

    def owner(path, info):
        # The folder's owner is unmapped in the sandbox: the host lookup has
        # no evidence, as tracked_host_owner_uid reports outside the scanner.
        return -1 if Path(path) == hidden else real_owner(path, info)

    monkeypatch.setattr(file_permissions, "tracked_host_owner_uid", owner)
    monkeypatch.setattr(
        file_permissions, "namespace_hides_owner", lambda info: info.st_ino == os.lstat(hidden).st_ino
    )
    return str(binary), hidden


@posix_only
def test_sandbox_hidden_folder_owner_is_not_called_another_account(tmp_path, monkeypatch):
    binary, hidden = _sandboxed_gateway(tmp_path, monkeypatch)
    with pytest.raises(file_permissions.UnsafePathError) as raised:
        file_permissions.trusted_posix_executable_path(binary)
    message = file_permissions.unsafe_gateway_remedy(raised.value)
    assert raised.value.code == file_permissions.UNSAFE_PATH_NAMESPACE_VIEW
    assert str(hidden) in message and "sandbox" in message
    assert "chmod" not in message and "another account" not in message


@posix_only
def test_a_folder_of_another_account_is_still_refused(tmp_path, monkeypatch):
    binary, _hidden = _sandboxed_gateway(tmp_path, monkeypatch)
    monkeypatch.setattr(file_permissions, "namespace_hides_owner", lambda info: False)
    with pytest.raises(file_permissions.UnsafePathError) as raised:
        file_permissions.trusted_posix_executable_path(binary)
    assert raised.value.code == file_permissions.UNSAFE_PATH_UNTRUSTED_CUSTODY
    assert "chmod go-w" in str(raised.value)


def test_namespace_hides_owner_is_false_outside_linux(monkeypatch):
    monkeypatch.setattr(sys, "platform", "darwin")
    assert not file_permissions.namespace_hides_owner(os.stat_result((0,) * 10))


def test_validate_config_reports_not_checked_instead_of_invalid(tmp_path, monkeypatch):
    path = tmp_path / "config.yaml"
    path.write_text("config_version: 9\n", encoding="utf-8")
    monkeypatch.setattr(cmd_config.config_module, "config_path", lambda: path)
    monkeypatch.setattr(cmd_config, "_looks_like_v8_config", lambda _path: True)
    hidden = file_permissions.UnsafePathError(
        "the owner of folder /home cannot be checked here",
        code=file_permissions.UNSAFE_PATH_NAMESPACE_VIEW,
    )

    def inspect(*_args, **_kwargs):
        raise ConfigInspectError(file_permissions.unsafe_gateway_remedy(hidden)) from hidden

    monkeypatch.setattr(cmd_config, "inspect_v8_config", inspect)
    result = cmd_config.validate_config()
    assert result.ok and not result.errors
    assert result.not_checked == "the owner of folder /home cannot be checked here"


class StatusInSandboxTests(unittest.TestCase):
    def setUp(self):
        self.app, self.tmp_dir, self.db_path = make_app_context()

    def tearDown(self):
        cleanup_app(self.app, self.db_path, self.tmp_dir)

    def _invoke(self, args=()):
        with patch.object(cmd_status, "_fetch_runtime_bound_health", return_value=None):
            return CliRunner().invoke(status_cmd, list(args), obj=self.app, catch_exceptions=False)

    def test_status_says_the_check_did_not_run_and_exits_zero(self):
        self.app.config_not_checked = "the owner of folder /home cannot be checked here"
        result = self._invoke()
        self.assertEqual(result.exit_code, 0, msg=result.output)
        self.assertIn("Config check", result.output)
        self.assertIn("not run: the owner of folder /home cannot be checked here", result.output)
        self.assertNotIn("invalid", result.output)
        self.assertNotIn("chmod", result.output)
        as_json = self._invoke(["--json"])
        self.assertEqual(as_json.exit_code, 0, msg=as_json.output)
        payload = json.loads(as_json.output)
        self.assertNotIn("config_errors", payload)
        self.assertEqual(payload["config_not_checked"], "the owner of folder /home cannot be checked here")


@posix_only
def test_managed_config_owner_hidden_by_the_sandbox_is_named_unknown(tmp_path, monkeypatch):
    from defenseclaw import config as dcconfig

    managed = tmp_path / "etc" / "config.yaml"
    managed.parent.mkdir()
    managed.write_text("config_version: 9\n", encoding="utf-8")
    managed.chmod(0o644)
    monkeypatch.setattr(dcconfig, "tracked_host_owner_uid", lambda path, info: -1)
    monkeypatch.setattr(dcconfig, "namespace_hides_owner", lambda info: True)
    monkeypatch.setattr(dcconfig, "_macos_write_acl_problem", lambda path: None)
    problem = dcconfig._managed_config_trust_problem(str(managed))
    assert problem and "cannot be checked inside this sandbox" in problem
    assert "not trusted" not in problem


# A check that did not run is never reported as passing (GAP-1395 refix).
_HIDDEN = "the owner of folder /home cannot be checked here"


def _not_checked_result() -> cmd_config.ValidationResult:
    result = cmd_config.ValidationResult()
    result.path = "/isolated/.defenseclaw/config.yaml"
    result.exists = True
    result.not_checked = _HIDDEN
    return result


def _run_cli(args, *, load_error=None):
    from types import SimpleNamespace

    from defenseclaw.main import cli

    cfg = SimpleNamespace(audit_db="/isolated/audit.db", _source_config_version=8)
    load = {"side_effect": load_error} if load_error else {"return_value": cfg}
    with (
        patch("defenseclaw.config.require_v8_config"),
        patch("defenseclaw.config.load", **load),
        patch("defenseclaw.commands.cmd_config.validate_config", side_effect=_not_checked_result),
        patch("defenseclaw.db.Store"),
        patch("defenseclaw.logger.Logger.from_config"),
        patch.object(cmd_config.config_module, "config_path", return_value=Path("/isolated/.defenseclaw/config.yaml")),
        patch("defenseclaw.gateway.current_gateway_reload_notice", return_value=""),
    ):
        return CliRunner().invoke(cli, list(args))


@pytest.mark.parametrize("args", (["config", "validate"], ["config", "validate", "--quiet"]))
def test_config_validate_in_the_sandbox_view_does_not_say_valid(args):
    result = _run_cli(args)
    assert result.exit_code == 1, result.output
    assert "valid" not in result.output and "syntax OK" not in result.output
    if "--quiet" not in args:
        assert f"not checked: {_HIDDEN}" in result.output


def test_other_commands_say_the_config_check_did_not_run():
    from defenseclaw.main import cli

    callback = unittest.mock.Mock(return_value=None)
    with patch.object(cli.commands["alerts"], "callback", callback):
        result = _run_cli(["alerts"])
    assert result.exit_code == 0, result.output
    assert f"Config check: not run: {_HIDDEN}" in result.output
    callback.assert_called_once()


def test_doctor_does_not_say_config_validate_passes_when_it_did_not_run():
    from defenseclaw.commands import cmd_doctor

    with patch.object(cmd_doctor, "_json_mode", False):
        result = _run_cli(["doctor", "--json-output"], load_error=TypeError("gateway must be a mapping"))
    assert result.exit_code == 1, result.output
    checks = json.loads(result.output)["checks"]
    assert {"status": "warn", "label": "Config validation"}.items() <= next(
        item for item in checks if item["label"] == "Config validation"
    ).items()
    assert any(f"not run: {_HIDDEN}" in item["detail"] for item in checks)
    assert not any("config validate passes" in item["detail"] for item in checks)
