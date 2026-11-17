"""The CLI suite starts every test in an empty user home (rel-1-0-10:GAP-0457)."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

CLI_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = CLI_ROOT.parent
GUARDRAIL_TESTS = "cli/tests/test_guardrail.py::TestSetupGuardrailCommand::"

pytestmark = pytest.mark.skipif(
    os.name == "nt", reason="the Windows profile variables are isolated by _isolated_windows_identity"
)


def test_a_test_starts_in_an_empty_home() -> None:
    home = Path.home()
    assert not (home / ".defenseclaw").exists()
    assert home.is_dir()
    assert list(home.iterdir()) == []
    for name in ("DEFENSECLAW_HOME", "DEFENSECLAW_CONFIG", "CODEX_HOME", "CLAUDE_CONFIG_DIR", "HERMES_HOME"):
        assert name not in os.environ


def test_setup_guardrail_tests_pass_on_a_machine_with_another_connector_set_up(tmp_path: Path) -> None:
    """A machine whose own home has OpenClaw set up ran the setup-guardrail tests red.

    The guard that refuses a connector that is not on the roster read the real
    ~/.defenseclaw/config.yaml of the box ("Claude Code is not set up here
    (set up: openclaw)"); a clean CI home never showed it. The same tests run
    here as a child with such a home, and the suite's own isolation must keep
    them green.
    """
    real_home = tmp_path / "home"
    data = real_home / ".defenseclaw"
    data.mkdir(parents=True)
    (data / "config.yaml").write_text(
        "config_version: 9\nguardrail:\n  connector: openclaw\n  enabled: true\n", encoding="utf-8"
    )
    env = dict(os.environ, HOME=str(real_home))
    for name in ("DEFENSECLAW_HOME", "DEFENSECLAW_CONFIG", "CODEX_HOME", "CLAUDE_CONFIG_DIR", "HERMES_HOME"):
        env.pop(name, None)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-p",
            "no:cacheprovider",
            "-q",
            f"{GUARDRAIL_TESTS}test_agent_alias_still_works",
            f"{GUARDRAIL_TESTS}test_non_interactive_missing_action_connector_refuses_without_saving",
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
    )
    assert result.returncode == 0, result.stdout[-3000:] + result.stderr[-1000:]
    assert "2 passed" in result.stdout
    assert "failed" not in result.stdout
