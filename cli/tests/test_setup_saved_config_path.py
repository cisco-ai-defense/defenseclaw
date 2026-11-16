"""rel-1-0-6:GAP-0445: setup commands name the config file they wrote."""

from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from defenseclaw.commands import cmd_setup


def _gateway() -> SimpleNamespace:
    return SimpleNamespace(
        host="127.0.0.1", port=18789, api_port=19994, token_env="OPENCLAW_GATEWAY_TOKEN", resolved_token=lambda: ""
    )


@pytest.mark.parametrize("pass_data_dir", [True, False])
def test_setup_gateway_names_the_custom_home_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], pass_data_dir: bool
) -> None:
    # On per-user macOS with DEFENSECLAW_HOME=~/dchome, setup gateway wrote
    # ~/dchome/config.yaml and printed "Saved to ~/.defenseclaw/config.yaml".
    home = tmp_path / "dchome"
    home.mkdir()
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    monkeypatch.delenv("DEFENSECLAW_CONFIG", raising=False)
    cmd_setup._print_gateway_summary(_gateway(), openclaw=False, data_dir=str(home) if pass_data_dir else None)
    out = capsys.readouterr().out
    assert f"Saved to {home / 'config.yaml'}" in out, out
    assert "~/.defenseclaw/config.yaml" not in out, out


def test_other_setup_summaries_name_the_written_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    home = tmp_path / "custom"
    home.mkdir()
    monkeypatch.setenv("DEFENSECLAW_HOME", str(home))
    monkeypatch.delenv("DEFENSECLAW_CONFIG", raising=False)
    want = str(home / "config.yaml")
    from defenseclaw.config import CiscoAIDefenseConfig, LLMConfig, SkillScannerConfig

    cmd_setup._print_summary(SkillScannerConfig(), LLMConfig(), CiscoAIDefenseConfig(), str(home))
    assert f"Saved to {want}" in capsys.readouterr().out
    cmd_setup._echo_batch_setup_summary(
        ["claudecode"], {"modes": {"claudecode": "observe"}}, restart=True, data_dir=str(home)
    )
    out = capsys.readouterr().out
    assert f"Config saved to {want}" in out and "~/.defenseclaw/config.yaml" not in out, out


def test_no_setup_message_hard_codes_the_default_config_path() -> None:
    # Every user-facing "saved" line names the config file through
    # config_path_for_data_dir, so DEFENSECLAW_HOME and a custom data_dir
    # are shown as they are (setup gateway, guardrail, llm, scanners, mcp,
    # splunk, connector batches and the trusted-prefix prompt).
    source = Path(cmd_setup.__file__).read_text(encoding="utf-8")
    calls = re.findall(r'(?:echo|ok|subhead|secho)\(\s*f?"[^"\n]*~/\.defenseclaw/config\.yaml[^"\n]*"', source)
    assert calls == [], calls
