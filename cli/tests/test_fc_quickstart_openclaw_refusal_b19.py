"""GAP-2466: quickstart's refusal on a guarded OpenClaw install."""

from __future__ import annotations

from unittest.mock import patch

from click.testing import CliRunner
from defenseclaw.commands import cmd_quickstart


def _run(args, configured, detected):
    with (
        patch.object(cmd_quickstart, "_configured_quickstart_connectors", return_value=configured),
        patch("defenseclaw.commands.cmd_setup._detect_installed_connectors", return_value=detected),
        patch("defenseclaw.commands.cmd_setup._read_picked_connector", return_value=""),
        patch("defenseclaw.bootstrap.run_first_run", side_effect=AssertionError("quickstart ran")),
    ):
        result = CliRunner().invoke(cmd_quickstart.quickstart_cmd, args)
    return result.exit_code, " ".join(result.output.split())


def test_bare_quickstart_on_guarded_openclaw_offers_only_working_commands():
    rc, out = _run(["--skip-gateway"], ["openclaw"], ["codex", "claudecode", "openclaw"])
    assert rc == 2, out
    assert "Claude Code, Codex, OpenClaw" in out
    assert "This install guards OpenClaw, which is proxy-backed" in out
    assert "Reconfigure OpenClaw: defenseclaw setup openclaw" in out
    assert "defenseclaw setup <connector> --replace" in out
    assert "keep the rest" not in out and "defenseclaw init" not in out


def test_connector_over_guarded_openclaw_uses_display_names():
    rc, out = _run(["--connector", "claudecode", "--mode", "action", "--skip-gateway"], ["openclaw"], [])
    assert rc == 2, out
    assert "already guards: OpenClaw. OpenClaw is proxy-backed" in out
    assert "Switch this install to Claude Code: defenseclaw setup claude-code --replace --mode action" in out


def test_zeptoclaw_over_guarded_openclaw_offers_only_working_commands():
    # GAP-2468: proxy-to-proxy refusal, singular wording and no init advice.
    rc, out = _run(["--connector", "zeptoclaw", "--skip-gateway"], ["openclaw"], [])
    assert rc == 2, out
    assert "ZeptoClaw is proxy-backed and cannot run next to OpenClaw" in out
    assert "Switch to it and remove OpenClaw: defenseclaw setup zeptoclaw --replace" in out
    assert "Keep guarding OpenClaw: defenseclaw setup openclaw" in out
    assert "defenseclaw init" not in out and "these connectors" not in out


def test_zeptoclaw_over_hook_roster_keeps_plural_wording():
    rc, out = _run(["--connector", "zeptoclaw", "--skip-gateway"], ["claudecode", "codex"], [])
    assert rc == 2, out
    assert "cannot run next to these connectors" in out and "remove them" in out
    assert "defenseclaw init" in out
