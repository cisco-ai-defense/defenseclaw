"""GAP-1508: a failed gateway restart ends setup without a 'protected' summary."""

from __future__ import annotations

from unittest.mock import patch

import click
import pytest
from defenseclaw.commands import cmd_setup


def test_failed_restart_prints_no_protection_summary(tmp_path, capsys) -> None:
    with patch.object(cmd_setup, "_restart_defense_gateway", return_value=False):
        with pytest.raises(click.ClickException) as raised:
            cmd_setup._restart_services(
                str(tmp_path),
                connector="claudecode",
                connectors=["claudecode", "codex", "hermes", "opencode"],
            )
    out = capsys.readouterr().out
    assert "registrations are current" not in out
    assert "enforcement via native lifecycle surfaces" not in out
    assert "may not be protected" in raised.value.message
    assert "defenseclaw-gateway start" in raised.value.message


def test_failed_restart_of_one_hook_connector_prints_no_enforcement_line(tmp_path, capsys) -> None:
    with patch.object(cmd_setup, "_restart_defense_gateway", return_value=False):
        with pytest.raises(click.ClickException):
            cmd_setup._restart_services(str(tmp_path), connector="claudecode")
    assert "enforcement via hook bus" not in capsys.readouterr().out
