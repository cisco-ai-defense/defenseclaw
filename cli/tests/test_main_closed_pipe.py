# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""GAP-1313: a reader that closes the pipe early ends the CLI quietly."""

from __future__ import annotations

import errno
import sys
from unittest.mock import patch

import pytest
from click.testing import CliRunner
from defenseclaw import main as main_mod


def test_managed_skill_block_without_user_config_names_asset_policy(monkeypatch):
    from defenseclaw import config
    from defenseclaw.enforce import asset_lists

    def missing_config(*_args, **_kwargs):
        raise config.ManagedNotInitializedError("defenseclaw init does not apply")

    monkeypatch.setattr(config, "require_v8_config", missing_config)
    monkeypatch.setattr(asset_lists, "audit_first_run_refusal", lambda *_args: None)
    result = CliRunner().invoke(main_mod.cli, ["skill", "block", "dc-x"])
    assert result.exit_code == 3
    assert "asset_policy block and allow lists" in result.output
    assert "defenseclaw init" not in result.output


class _ClosedStdout:
    def flush(self) -> None:
        raise OSError(errno.EINVAL, "Invalid argument")


def test_windows_einval_on_a_closed_stdout_counts_as_a_closed_pipe(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(sys, "stdout", _ClosedStdout())
    assert main_mod._output_pipe_closed(OSError(errno.EINVAL, "Invalid argument"))


def test_the_cli_never_creates_an_audit_db_in_the_managed_config_folder(monkeypatch, tmp_path):
    # GAP-0062: DEFENSECLAW_HOME pointed at the managed folder made the CLI
    # create audit.db there (and narrow the folder's mode).
    from types import SimpleNamespace

    from defenseclaw import upgrade_shim

    managed = tmp_path / "etc" / "defenseclaw"
    managed.mkdir(parents=True)
    descriptor = managed / "managed-runtime.json"
    descriptor.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(upgrade_shim, "managed_descriptor", lambda: str(descriptor))
    assert main_mod._cli_audit_db(SimpleNamespace(audit_db=str(managed / "audit.db"))) == ":memory:"
    (tmp_path / "home").mkdir()
    own = str(tmp_path / "home" / "audit.db")
    assert main_mod._cli_audit_db(SimpleNamespace(audit_db=own)) == own
    # An administrator's shell has no data folder of its own (GAP-0168).
    assert main_mod._cli_audit_db(SimpleNamespace(audit_db=str(tmp_path / "root" / "audit.db"))) == ":memory:"
    monkeypatch.setattr(upgrade_shim, "managed_descriptor", lambda: None)
    assert main_mod._cli_audit_db(SimpleNamespace(audit_db=str(managed / "audit.db"))) == str(managed / "audit.db")


def test_other_einval_errors_are_not_hidden(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    assert not main_mod._output_pipe_closed(OSError(errno.EINVAL, "Invalid argument"))
    monkeypatch.setattr(sys, "platform", "linux")
    assert not main_mod._output_pipe_closed(OSError(errno.EINVAL, "Invalid argument"))
    assert main_mod._output_pipe_closed(BrokenPipeError(errno.EPIPE, "Broken pipe"))


def test_main_exits_without_a_traceback_when_the_pipe_closes(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(sys, "stdout", _ClosedStdout())
    closed = OSError(errno.EINVAL, "Invalid argument")
    with (
        patch.object(main_mod.ux, "configure_console_output"),
        patch.object(main_mod, "_force_utf8_io"),
        patch.object(main_mod, "_try_launch_tui", side_effect=closed),
        patch.object(main_mod, "_silence_closed_stdout") as silence,
        pytest.raises(SystemExit) as exited,
    ):
        main_mod.main()
    assert exited.value.code == 1
    silence.assert_called_once()


def test_main_turns_an_unreachable_gateway_audit_into_one_line(capsys):
    # GAP-1689: skill scan after init --no-start-gateway printed a traceback.
    from defenseclaw.logger import CanonicalObservabilityUnavailableError

    unavailable = CanonicalObservabilityUnavailableError("gateway authentication is unavailable")
    with (
        patch.object(main_mod.ux, "configure_console_output"),
        patch.object(main_mod, "_force_utf8_io"),
        patch.object(main_mod, "_try_launch_tui", side_effect=unavailable),
        pytest.raises(SystemExit) as exited,
    ):
        main_mod.main()
    assert exited.value.code == 1
    err = capsys.readouterr().err
    assert "Traceback" not in err
    assert err.count("\n") == 1
    assert "gateway authentication is unavailable" in err
    assert "defenseclaw-gateway start" in err


def test_ctrl_c_ends_the_cli_with_one_line_and_exit_130(capsys):
    # GAP-0408: Ctrl+C during the upgrade's "Migrating config and data" step
    # printed a KeyboardInterrupt traceback before the rollback message.
    with (
        patch.object(main_mod.ux, "configure_console_output"),
        patch.object(main_mod, "_force_utf8_io"),
        patch.object(main_mod, "_try_launch_tui", side_effect=KeyboardInterrupt),
        pytest.raises(SystemExit) as exited,
    ):
        main_mod.main()
    assert exited.value.code == 130
    err = capsys.readouterr().err
    assert "Traceback" not in err and err.strip() == "Interrupted."


def test_main_turns_a_refused_config_change_into_one_line_and_exit_1(capsys):
    # GAP-0055: a value the schema rejects at write time used to end in a Python traceback.
    from defenseclaw.observability.v8_config import V8ConfigError

    rejected = V8ConfigError("config.yaml", "$.scanners.mcp_scanner.analyzers", "oneOf", "use exactly one supported source shape")
    with (
        patch.object(main_mod.ux, "configure_console_output"),
        patch.object(main_mod, "_force_utf8_io"),
        patch.object(main_mod, "_try_launch_tui", side_effect=rejected),
        pytest.raises(SystemExit) as exited,
    ):
        main_mod.main()
    assert exited.value.code == 1
    err = capsys.readouterr().err
    assert "Traceback" not in err and err.count("\n") == 1
    assert err.startswith("Error: config.yaml was not changed: scanners.mcp_scanner.analyzers")


def test_main_turns_a_managed_config_refusal_into_one_line_and_exit_3(capsys):
    from defenseclaw.config_writer import MANAGED_REFUSAL, ManagedConfigWriteError

    with (
        patch.object(main_mod.ux, "configure_console_output"),
        patch.object(main_mod, "_force_utf8_io"),
        patch.object(main_mod, "_try_launch_tui", side_effect=ManagedConfigWriteError(MANAGED_REFUSAL)),
        pytest.raises(SystemExit) as exited,
    ):
        main_mod.main()
    assert exited.value.code == 3
    err = capsys.readouterr().err
    assert "Traceback" not in err
    assert err == f"error: {MANAGED_REFUSAL}\n"
