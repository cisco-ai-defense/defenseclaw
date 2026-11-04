"""GAP-0565: OpenAI-compatible judge request settings in config.yaml."""

import json
from types import SimpleNamespace

from click.testing import CliRunner
import yaml

from defenseclaw import config as config_module
from defenseclaw.commands import cmd_config
from defenseclaw.context import AppContext
from tests.environment import isolated_home_env


def test_judge_extra_body_config_set_get_validate_and_clear(tmp_path, monkeypatch):
    for key, value in isolated_home_env(tmp_path / "home").items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("DEFENSECLAW_DEPLOYMENT_MODE", raising=False)
    install = tmp_path / "install"
    install.mkdir()
    path = install / "config.yaml"
    path.write_text(f"config_version: 9\ndata_dir: {install}\nobservability: {{}}\n")
    monkeypatch.setenv("DEFENSECLAW_HOME", str(install))
    monkeypatch.setenv("DEFENSECLAW_CONFIG", str(path))
    monkeypatch.setattr(cmd_config.config_module, "config_path", lambda: path)
    monkeypatch.setattr("defenseclaw.gateway.local_policy_digest", lambda *args, **kwargs: None)
    runner = CliRunner()
    value = {"chat_template_kwargs": {"enable_thinking": False, "labels": ["a", "b"]}}

    result = runner.invoke(
        cmd_config.config_cmd,
        ["set", "guardrail.judge.extra_body", "--json", json.dumps(value)],
        obj=AppContext(),
    )
    assert result.exit_code == 0, result.output
    assert config_module.load().guardrail.judge.extra_body == value
    result = runner.invoke(cmd_config.config_cmd, ["get", "guardrail.judge.extra_body", "--format", "json"], obj=AppContext())
    assert result.exit_code == 0 and json.loads(result.output) == value, result.output
    monkeypatch.setattr(cmd_config, "inspect_v8_config", lambda *args, **kwargs: SimpleNamespace(valid=True, warnings=[]))
    result = runner.invoke(cmd_config.config_cmd, ["validate", "--quiet"], obj=AppContext())
    assert result.exit_code == 0, result.output

    before = path.read_bytes()
    result = runner.invoke(
        cmd_config.config_cmd,
        ["set", "guardrail.judge.extra_body", "--json", '{"max_tokens":1}'],
        obj=AppContext(),
    )
    assert result.exit_code != 0 and "max_tokens" in result.output, result.output
    assert path.read_bytes() == before

    result = runner.invoke(cmd_config.config_cmd, ["unset", "guardrail.judge.extra_body"], obj=AppContext())
    assert result.exit_code == 0, result.output
    assert config_module.load().guardrail.judge.extra_body == {}
    assert "extra_body" not in (yaml.safe_load(path.read_text()).get("guardrail") or {}).get("judge", {})
