# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""An administrator's `acp verify --runtime-data-dir` reads the user's enrollment as that user (GAP-2111).

Enterprise setup runs as the enrolled user and writes the editor entry, the
contract lock and the owned-entries record in that user's home. Root checking
it must read that user's editor file and accept that user's own record, not
look in root's home or ask the record to be root's.
"""

from __future__ import annotations

import json
import os
import shlex
from pathlib import Path

import pytest
from click.testing import CliRunner
from defenseclaw import winquote
from defenseclaw.commands import cmd_acp
from defenseclaw.commands.cmd_acp import acp_cmd, setup_repair_command
from defenseclaw.winquote import powershell_command_line, powershell_literal_value, split_windows_words

from tests.helpers import cleanup_app
from tests.test_acp_verify_guard_parity_r105 import _setup

pytestmark = pytest.mark.skipif(os.name == "nt", reason="root and account homes are POSIX")
pwd = pytest.importorskip("pwd")


def _as_root_checking(monkeypatch, tmp_path: Path, user_home: Path) -> None:
    admin = tmp_path / "admin-home"
    admin.mkdir()
    monkeypatch.setenv("HOME", str(admin))
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    owner = os.getuid()
    real = pwd.getpwuid

    def getpwuid(uid: int):
        entry = real(uid)
        if uid != owner:
            return entry
        return pwd.struct_passwd((*entry[:5], str(user_home), entry[6]))

    monkeypatch.setattr(pwd, "getpwuid", getpwuid)
    monkeypatch.setattr(os, "geteuid", lambda: 0)


def test_root_verify_reads_the_enrolled_users_entry_and_record(tmp_path, monkeypatch):
    app, data_dir, db_path, settings, _guard, _agent, _lock = _setup(tmp_path, monkeypatch)
    try:
        assert (Path(data_dir) / "acp" / "owned-entries.json").is_file()
        _as_root_checking(monkeypatch, tmp_path, tmp_path)

        def verify():
            return CliRunner().invoke(
                acp_cmd, ["verify", "--client", "zed", "--agent", "kiro", "--runtime-data-dir", data_dir], obj=app
            )

        result = verify()
        assert result.exit_code == 0, result.output
        assert "Verified zed/kiro" in result.output

        document = json.loads(settings.read_text())
        document["theme"] = "One Dark"
        settings.write_text(json.dumps(document, indent=2))
        result = verify()
        assert result.exit_code == 0, result.output

        document["agent_servers"]["DefenseClaw · Kiro"]["env"] = {"LD_PRELOAD": "/tmp/x.so"}
        settings.write_text(json.dumps(document))
        result = verify()
        assert result.exit_code != 0, result.output
        assert "entry changed after setup" in result.output, result.output

        status = CliRunner().invoke(acp_cmd, ["status", "--runtime-data-dir", data_dir, "--json"], obj=app)
        assert status.exit_code == 0, status.output
        assert json.loads(status.output)["clients"]["zed"] == str(settings)
    finally:
        cleanup_app(app, db_path, data_dir)


def test_managed_standalone_repair_names_the_enterprise_setup_the_user_can_run(tmp_path, monkeypatch):
    """A managed standalone host has no per-user `acp setup`; verify names the gateway's enterprise setup."""
    app, data_dir, db_path, _settings, guard, _agent, _lock = _setup(tmp_path, monkeypatch)
    try:
        app.cfg.deployment_mode = "managed_enterprise"
        app.cfg.gateway.api_port = 18970
        command = setup_repair_command(app.cfg, "zed", "kiro", data_dir)
        gateway = str(Path(guard).with_name("defenseclaw-gateway"))
        assert command == shlex.join([
            gateway, "enterprise", "acp", "setup", "--client", "zed", "--agent", "kiro",
            "--profile", app.cfg.acp.profile_for_pair("zed", "kiro"), "--data-dir", data_dir,
            "--api-port", "18970", "--guard-binary", guard,
        ]), command
        assert "--managed" not in command
    finally:
        cleanup_app(app, db_path, data_dir)


class _WindowsOs:
    """cmd_acp's view of os on Windows: os.name is "nt", the rest is this host's."""

    name = "nt"

    def __getattr__(self, attribute: str):
        return getattr(os, attribute)


@pytest.mark.parametrize("quote", ["'", "\u2018", "\u2019", "\u201a", "\u201b"])
def test_managed_standalone_repair_on_windows_is_one_powershell_line(tmp_path, monkeypatch, quote):
    """g072 review 3 M2: the managed Windows ACP setup command parses under a profile like O\u2019Brien.

    It was built by hand: only the apostrophe was doubled, so the
    ``--data-dir`` literal ended at the typographic quote, and verify said
    "run & '...'" without naming PowerShell.
    """
    base = tmp_path / f"O{quote}Brien"
    base.mkdir()
    app, data_dir, db_path, settings, guard, _agent, _lock = _setup(base, monkeypatch)
    try:
        app.cfg.deployment_mode = "managed_enterprise"
        app.cfg.gateway.api_port = 18970
        monkeypatch.setattr(cmd_acp, "os", _WindowsOs())
        monkeypatch.setattr(winquote, "os", _WindowsOs())
        command = setup_repair_command(app.cfg, "zed", "kiro", data_dir)
        gateway = str(Path(guard).with_name("defenseclaw-gateway"))
        args = [
            "enterprise", "acp", "setup", "--client", "zed", "--agent", "kiro",
            "--profile", app.cfg.acp.profile_for_pair("zed", "kiro"), "--data-dir", data_dir,
            "--api-port", "18970", "--guard-binary", guard,
        ]
        assert command == powershell_command_line(gateway, *args), command
        assert quote * 2 in command
        words = split_windows_words(command)
        assert words[0] == "&"
        assert [powershell_literal_value(word[1:-1]) if word[:1] == "'" else word for word in words[1:]] == [
            gateway,
            *args,
        ]

        document = json.loads(settings.read_text())
        document["agent_servers"]["DefenseClaw \u00b7 Kiro"]["env"] = {"LD_PRELOAD": "/tmp/x.so"}
        settings.write_text(json.dumps(document))
        result = CliRunner().invoke(
            acp_cmd, ["verify", "--client", "zed", "--agent", "kiro", "--runtime-data-dir", data_dir], obj=app
        )
        assert result.exit_code != 0, result.output
        assert f"in PowerShell, run {command}" in " ".join(result.output.split()), result.output
    finally:
        cleanup_app(app, db_path, data_dir)
