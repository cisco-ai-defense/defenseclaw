# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""CLI status and config error wording (final-cert UX batch 6)."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner
from defenseclaw import config as dcconfig
from defenseclaw import config_inspect, ux
from defenseclaw.commands import cmd_guardrail
from defenseclaw.commands.cmd_migrate import migrate_cmd
from defenseclaw.context import AppContext
from defenseclaw.migrations import MigrationError, _pending_migration_steps, migrate

from tests.test_fail_mode_runtime import _runtime_cfg


@pytest.fixture()
def data_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.delenv("DEFENSECLAW_CONFIG", raising=False)
    root = tmp_path / "data"
    root.mkdir()
    return root


@pytest.mark.parametrize("content", ["", "\n  \n", "# only a comment\n"])
def test_empty_config_is_named_not_migrated(data_dir: Path, content: str) -> None:
    # GAP-1633: an empty file is not a 0.x install to import.
    path = data_dir / "config.yaml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(MigrationError, match="is empty") as raised:
        migrate(str(data_dir))
    assert "defenseclaw init" in str(raised.value)
    with pytest.raises(dcconfig.ConfigVersionError, match="nothing was changed"):
        dcconfig.require_v8_config(path=str(path))
    assert path.read_text(encoding="utf-8") == content


def test_empty_config_hint_dates_the_kept_copy(data_dir: Path) -> None:
    # GAP-1786: previous/ only changes on a version upgrade, so say how old it is.
    path = data_dir / "config.yaml"
    path.write_text("", encoding="utf-8")
    assert "previous" not in dcconfig.empty_config_message(str(path))
    kept = data_dir / "previous" / "data" / "config.yaml"
    kept.parent.mkdir(parents=True)
    kept.write_text("config_version: 8\n", encoding="utf-8")
    (data_dir / "previous" / "VERSION").write_text("1.0.1\n", encoding="utf-8")
    os.utime(kept, (1790916000, 1790916000))

    message = dcconfig.empty_config_message(str(path))

    assert f"kept the DefenseClaw 1.0.1 config from 2026-10-02 04:40 UTC in {kept}" in message
    assert "lacks every change made since then" in message


def test_unversioned_config_still_asks_for_migrate(data_dir: Path) -> None:
    path = data_dir / "config.yaml"
    path.write_text("gateway: {}\n", encoding="utf-8")
    with pytest.raises(dcconfig.ConfigVersionError, match="defenseclaw migrate"):
        dcconfig.require_v8_config(path=str(path))


def test_from_version_newer_than_this_release_warns_only_where_it_is_read(
    data_dir: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # GAP-0348: on a downgrade the installer passes the newer release it
    # replaces; a 1.x config never reads it, so the run prints no warning.
    path = data_dir / "config.yaml"
    path.write_text(f"config_version: {dcconfig.CURRENT_CONFIG_VERSION}\n", encoding="utf-8")
    downgrade = CliRunner().invoke(migrate_cmd, ["--data-dir", str(data_dir), "--from-version", "999.0.0"])
    assert downgrade.exit_code == 0, downgrade.output
    assert "--from-version" not in downgrade.stderr + downgrade.output
    # GAP-1610: a 0.x config without a cursor skips the steps up to it, so warn there.
    _pending_migration_steps(7, "999.0.0", str(data_dir), str(path), dcconfig.CURRENT_CONFIG_VERSION)
    assert "--from-version 999.0.0 is newer than this DefenseClaw" in capsys.readouterr().err
    _pending_migration_steps(7, "0.8.4", str(data_dir), str(path), dcconfig.CURRENT_CONFIG_VERSION)
    assert "--from-version" not in capsys.readouterr().err


def test_helper_timeout_is_not_reported_as_invalid(monkeypatch: pytest.MonkeyPatch) -> None:
    # GAP-1621
    def slow(*_args, **_kwargs):
        raise subprocess.TimeoutExpired(cmd="defenseclaw-gateway", timeout=1)

    monkeypatch.setattr(config_inspect, "run_pinned_executable", slow)
    with pytest.raises(config_inspect.ConfigInspectTimeoutError, match="did not finish within 60 s"):
        config_inspect._run(["defenseclaw-gateway", "config-v8", "validate"])


def test_doctor_reports_helper_timeout_as_warn(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # GAP-1621: a helper timeout is a busy host; both doctor rows warn.
    from types import SimpleNamespace

    from defenseclaw.commands import cmd_doctor
    from defenseclaw.observability import v8_status

    (tmp_path / "config.yaml").write_text("config_version: 8\nobservability: {}\n", encoding="utf-8")

    def slow(*_args, **_kwargs):
        raise config_inspect.ConfigInspectTimeoutError("the configuration check did not finish within 60 s")

    monkeypatch.setattr(config_inspect, "inspect_v8_config", slow)
    monkeypatch.setattr(v8_status, "inspect_v8_config", slow)
    with pytest.raises(config_inspect.ConfigInspectTimeoutError):
        v8_status.inspect_v8_operator_status(tmp_path / "config.yaml")
    result = cmd_doctor._DoctorResult()
    cfg = SimpleNamespace(data_dir=str(tmp_path))
    cmd_doctor._check_config(cfg, result)
    cmd_doctor._check_observability(cfg, result)
    assert (result.failed, result.warned) == (0, 2)


def test_version_detail_arrow_has_ascii_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    # GAP-1601: '↳' came out as mojibake when piped in PowerShell.
    monkeypatch.setattr(ux, "_configured_unicode_output", False)
    assert ux.console_text("↳ (commit=abc)") == "-> (commit=abc)"


def test_guardrail_status_disabled_has_no_drift_or_proxy_port(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # GAP-1648 and GAP-1649: hooks removed on purpose are not drift, and a
    # hook-only install has no proxy port.
    cfg, home = _runtime_cfg(monkeypatch, tmp_path, {"claudecode": "open"})
    app = AppContext()
    app.cfg = cfg
    app.logger = MagicMock()
    with (
        patch("defenseclaw.fail_mode._is_windows", return_value=True),
        patch("defenseclaw.fail_mode.Path.home", return_value=home),
    ):
        enabled = CliRunner().invoke(cmd_guardrail.status_cmd, [], obj=app)
        cfg.guardrail.enabled = False
        disabled = CliRunner().invoke(cmd_guardrail.status_cmd, [], obj=app)
    assert enabled.exit_code == 0, enabled.output
    assert "runtime fail-mode drift" in enabled.output
    assert disabled.exit_code == 0, disabled.output
    assert "disabled (guardrail off)" in disabled.output
    assert "runtime fail-mode drift" not in disabled.output
    assert "port:" not in enabled.output and "port:" not in disabled.output


def test_empty_config_hint_names_the_newest_backup(data_dir: Path) -> None:
    # GAP-2206: a newer full backup beats the day-old copy the upgrade kept.
    path = data_dir / "config.yaml"
    path.write_text("", encoding="utf-8")
    kept = data_dir / "previous" / "data" / "config.yaml"
    kept.parent.mkdir(parents=True)
    kept.write_text("config_version: 7\n", encoding="utf-8")
    os.utime(kept, (1790916000, 1790916000))  # 2026-10-02 04:40 UTC
    backups = data_dir / "backups"
    backups.mkdir()
    (backups / "config.yaml.empty").write_text("", encoding="utf-8")
    os.utime(backups / "config.yaml.empty", (1790990000, 1790990000))
    older = backups / "config.yaml.before-redaction-1"
    older.write_text("config_version: 8\n", encoding="utf-8")
    os.utime(older, (1790920000, 1790920000))
    newest = backups / "config.yaml.before-redaction-2"
    newest.write_text("config_version: 8\n", encoding="utf-8")
    os.utime(newest, (1790931480, 1790931480))  # 2026-10-02 08:58 UTC

    message = dcconfig.empty_config_message(str(path))

    assert f"(the newest backup is {newest}, from 2026-10-02 08:58 UTC; " in message
    assert f"the last version upgrade kept an older copy from 2026-10-02 04:40 UTC in {kept})" in message
    assert "config.yaml.empty" not in message

    os.utime(kept, (1790999000, 1790999000))  # the upgrade copy is now the newest
    assert "the newest backup" not in dcconfig.empty_config_message(str(path))
