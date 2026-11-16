# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0
"""Issue #1404: openclaw.json gateway.auth.token as a SecretRef object.

Recent OpenClaw releases store the gateway token as a SecretRef such as
``{"source": "store", "provider": "default", "id": "OPENCLAW_GATEWAY_TOKEN"}``.
Every DefenseClaw reader of that setting must resolve a ``source: env``
reference from the environment, never use any other object as a token, and
never abort ``init``.
"""

from __future__ import annotations

import json
import os
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from defenseclaw.connector_paths import openclaw_gateway_token

ENV_NAME = "DC_TEST_GH1404_TOKEN"
ENV_VALUE = "env-token-gh1404-value"
LITERAL = "literal-token-gh1404-value"

STORE_REF = {"source": "store", "provider": "default", "id": "OPENCLAW_GATEWAY_TOKEN"}
ENV_REF = {"source": "env", "provider": "default", "id": ENV_NAME}

# name -> (token setting, env value or None, expected token, notice expected)
CASES = {
    "string": (LITERAL, None, LITERAL, False),
    "env-set": (ENV_REF, ENV_VALUE, ENV_VALUE, False),
    "env-unset": (ENV_REF, None, "", True),
    "store": (STORE_REF, None, "", True),
    "file": ({"source": "file", "provider": "vault", "id": "/gateway/token"}, None, "", True),
    "malformed-no-id": ({"source": "env"}, None, "", True),
    "malformed-bad-id": ({"source": "env", "id": "not a name"}, None, "", True),
    "malformed-no-source": ({"id": "OPENCLAW_GATEWAY_TOKEN"}, None, "", True),
    "list": (["a", "b"], None, "", True),
    "string-secretref-text": ("{'source': 'store', 'id': 'X'}", None, "", True),
    "number": (42, None, "", True),
}


def _openclaw_json(token) -> dict:
    return {"gateway": {"mode": "local", "port": 19404, "auth": {"mode": "token", "token": token}}}


def _write_openclaw_json(tmp_path, token) -> str:
    path = tmp_path / "openclaw" / "openclaw.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(_openclaw_json(token)), encoding="utf-8")
    return str(path)


@pytest.fixture
def token_env(monkeypatch):
    # setenv first so monkeypatch records the original state and restores it:
    # the real dotenv writer sets os.environ, which must not leak into later tests.
    for name in (ENV_NAME, "OPENCLAW_GATEWAY_TOKEN", "DEFENSECLAW_GATEWAY_TOKEN"):
        monkeypatch.setenv(name, "unset")
        monkeypatch.delenv(name)

    def apply(value):
        if value is not None:
            monkeypatch.setenv(ENV_NAME, value)

    return apply


def _assert_plain_notice(notice: str) -> None:
    assert "gateway.auth.token" in notice
    assert "OPENCLAW_GATEWAY_TOKEN" in notice and "DEFENSECLAW_GATEWAY_TOKEN" in notice
    assert ENV_VALUE not in notice and LITERAL not in notice
    assert "{" not in notice, "the SecretRef object is never echoed"


@pytest.mark.parametrize("name", sorted(CASES))
def test_shared_reader_handles_every_shape(name, token_env):
    setting, env_value, expected, has_notice = CASES[name]
    token_env(env_value)
    token = openclaw_gateway_token(_openclaw_json(setting))
    assert token.value == expected
    assert isinstance(token.value, str)
    assert bool(token.notice) is has_notice
    if has_notice:
        _assert_plain_notice(token.notice)


def test_shared_reader_without_a_token_is_silent():
    for document in (None, {}, {"gateway": "x"}, {"gateway": {"auth": "x"}}, {"gateway": {"auth": {}}}):
        assert openclaw_gateway_token(document) == openclaw_gateway_token({})
        assert openclaw_gateway_token(document).value == ""
        assert openclaw_gateway_token(document).notice == ""


def test_store_notice_names_the_source_and_env_notice_names_the_variable(token_env):
    token_env(None)
    assert '"store" secret source' in openclaw_gateway_token(_openclaw_json(STORE_REF)).notice
    assert ENV_NAME in openclaw_gateway_token(_openclaw_json(ENV_REF)).notice


@pytest.mark.parametrize("name", sorted(CASES))
def test_init_resolve_openclaw_gateway(name, tmp_path, token_env):
    from defenseclaw.commands.cmd_init import _resolve_openclaw_gateway

    setting, env_value, expected, has_notice = CASES[name]
    token_env(env_value)
    result = _resolve_openclaw_gateway(_write_openclaw_json(tmp_path, setting))
    assert result["token"] == expected
    assert result["port"] == 19404
    assert bool(result["token_notice"]) is has_notice


@pytest.mark.parametrize("name", sorted(CASES))
def test_setup_detect_openclaw_gateway_token(name, tmp_path, token_env, capsys):
    from defenseclaw.commands import cmd_setup

    setting, env_value, expected, has_notice = CASES[name]
    token_env(env_value)
    cmd_setup._OPENCLAW_TOKEN_NOTICES_SHOWN.clear()
    path = _write_openclaw_json(tmp_path, setting)
    assert cmd_setup._detect_openclaw_gateway_token(path) == expected
    assert cmd_setup._detect_openclaw_gateway_token(path) == expected
    out = capsys.readouterr()
    text = out.out + out.err
    assert ENV_VALUE not in text and LITERAL not in text
    if has_notice:
        assert text.count("gateway.auth.token") == 1, "one plain message per run"
    else:
        assert "gateway.auth.token" not in text


def test_setup_detect_missing_or_invalid_file(tmp_path):
    from defenseclaw.commands.cmd_setup import _detect_openclaw_gateway_token

    assert _detect_openclaw_gateway_token(str(tmp_path / "missing.json")) == ""
    bad = tmp_path / "bad.json"
    bad.write_bytes(b"\xff\xfe not json")
    assert _detect_openclaw_gateway_token(str(bad)) == ""


def _openclaw_cfg(tmp_path, setting):
    from defenseclaw.config import Config, GatewayConfig, GuardrailConfig, OpenShellConfig
    from defenseclaw.file_permissions import make_private_directory

    data_dir = os.path.realpath(str(tmp_path / "dchome"))
    cfg = Config(
        data_dir=data_dir,
        audit_db=os.path.join(data_dir, "audit.db"),
        quarantine_dir=os.path.join(data_dir, "quarantine"),
        plugin_dir=os.path.join(data_dir, "plugins"),
        policy_dir=os.path.join(data_dir, "policies"),
        guardrail=GuardrailConfig(),
        gateway=GatewayConfig(),
        openshell=OpenShellConfig(),
    )
    make_private_directory(cfg.data_dir)
    cfg.claw.mode = "openclaw"
    cfg.guardrail.connector = "openclaw"
    cfg.claw.config_file = _write_openclaw_json(tmp_path, setting)
    return cfg


def _dotenv(cfg) -> str:
    path = os.path.join(cfg.data_dir, ".env")
    if not os.path.exists(path):
        return ""
    with open(path, encoding="utf-8") as fh:
        return fh.read()


@pytest.mark.parametrize("name", sorted(CASES))
def test_bootstrap_apply_gateway_defaults(name, tmp_path, token_env, monkeypatch):
    from defenseclaw.bootstrap import BootstrapReport, _apply_gateway_defaults

    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / "dchome"))
    setting, env_value, expected, has_notice = CASES[name]
    token_env(env_value)
    cfg = _openclaw_cfg(tmp_path, setting)
    report = BootstrapReport()

    detected = _apply_gateway_defaults(cfg, True, None, report)

    assert bool(report.openclaw_token_notice) is has_notice
    dotenv = _dotenv(cfg)
    assert "source" not in dotenv and "{" not in dotenv
    if expected:
        assert detected is True
        assert cfg.gateway.token_env == "OPENCLAW_GATEWAY_TOKEN"
        assert f"OPENCLAW_GATEWAY_TOKEN={expected}" in dotenv
    else:
        assert cfg.gateway.token_env == "DEFENSECLAW_GATEWAY_TOKEN"
        assert "OPENCLAW_GATEWAY_TOKEN=" not in dotenv


def test_init_setup_gateway_defaults_warns_and_continues(tmp_path, token_env, monkeypatch, capsys):
    from defenseclaw.commands.cmd_init import _setup_gateway_defaults

    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / "dchome"))
    token_env(None)
    cfg = _openclaw_cfg(tmp_path, STORE_REF)
    with patch.object(type(cfg), "active_connectors", return_value=["openclaw"]):
        _setup_gateway_defaults(cfg, MagicMock(), is_new_config=True)
    out = capsys.readouterr().out
    assert out.count("gateway.auth.token") == 1
    assert "auto-generated on first boot" in out
    assert cfg.gateway.token_env == "DEFENSECLAW_GATEWAY_TOKEN"


def test_setup_guardrail_adopt_token_skips_a_store_ref(tmp_path, token_env, monkeypatch):
    from defenseclaw.commands import cmd_setup

    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / "dchome"))
    token_env(None)
    cmd_setup._OPENCLAW_TOKEN_NOTICES_SHOWN.clear()
    cfg = _openclaw_cfg(tmp_path, STORE_REF)
    with patch.object(cmd_setup, "_save_secret_to_dotenv") as save:
        cmd_setup._adopt_openclaw_gateway_token(SimpleNamespace(cfg=cfg, logger=None))
    save.assert_not_called()


def test_setup_guardrail_adopt_token_uses_an_env_ref(tmp_path, token_env, monkeypatch):
    from defenseclaw.commands import cmd_setup

    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / "dchome"))
    token_env(ENV_VALUE)
    cfg = _openclaw_cfg(tmp_path, ENV_REF)
    with (
        patch.object(cmd_setup, "_save_adopted_gateway_token") as save,
        patch.object(cmd_setup, "keep_running_gateway_token"),
    ):
        cmd_setup._adopt_openclaw_gateway_token(SimpleNamespace(cfg=cfg, logger=None))
    assert {call.args[1] for call in save.call_args_list} == {ENV_VALUE}


def test_doctor_fix_gateway_token_ignores_a_store_ref(tmp_path, token_env, monkeypatch):
    from defenseclaw.commands import cmd_doctor

    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / "dchome"))
    token_env(None)
    cfg = _openclaw_cfg(tmp_path, STORE_REF)
    with (
        patch.object(cmd_doctor, "_doctor_config_present", return_value=True),
        patch.object(cmd_doctor, "_active_connector", return_value="openclaw"),
        patch("defenseclaw.commands.cmd_setup._save_secret_to_dotenv") as save,
    ):
        status, _detail = cmd_doctor._fix_gateway_token(cfg, assume_yes=True, plan_only=True)
    assert all(call.args[0] != "OPENCLAW_GATEWAY_TOKEN" for call in save.call_args_list)
    assert "OpenClaw configuration" not in _detail, (status, _detail)


@pytest.mark.parametrize("setting", [STORE_REF, ENV_REF], ids=["store", "env-unset"])
def test_init_first_run_with_a_secretref_completes(setting, tmp_path, token_env, monkeypatch):
    """The reported failure: init --connector openclaw rolled back the whole first run."""
    from defenseclaw.bootstrap import FirstRunOptions, StepResult, run_first_run
    from defenseclaw.config import load

    from tests.helpers import record_test_setup_agent_selections

    home = tmp_path / "home"
    (home / ".openclaw").mkdir(parents=True)
    (home / ".openclaw" / "openclaw.json").write_text(json.dumps(_openclaw_json(setting)), encoding="utf-8")
    data_dir = os.path.realpath(str(tmp_path / "dchome"))
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("DEFENSECLAW_HOME", data_dir)
    token_env(None)
    with (
        patch(
            "defenseclaw.agent_selection.record_setup_agent_selections", side_effect=record_test_setup_agent_selections
        ),
        patch("defenseclaw.bootstrap._quiet_guardrail_setup", return_value=StepResult("Guardrail", "pass", "test")),
    ):
        report = run_first_run(
            FirstRunOptions(
                connector="openclaw", profile="observe", skip_install=True, start_gateway=False, verify=False
            )
        )
        cfg = load()

    failed = [(s.name, s.detail) for s in report.setup if s.status == "fail"]
    assert failed == [], failed
    assert report.status != "needs_attention"
    notices = [s for s in report.setup if s.name == "OpenClaw token"]
    assert len(notices) == 1 and notices[0].status == "warn"
    _assert_plain_notice(notices[0].detail)
    assert "openclaw" in cfg.active_connectors()


# The line DefenseClaw 1.0.5 and 1.0.6 left in ~/.defenseclaw/.env before init failed.
STALE_LINE = "OPENCLAW_GATEWAY_TOKEN={'source': 'store', 'provider': 'default', 'id': 'OPENCLAW_GATEWAY_TOKEN'}"
STALE_VALUE = STALE_LINE.partition("=")[2]


@pytest.mark.parametrize(
    "name",
    [
        "DEFENSECLAW_LLM_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "VIRUSTOTAL_API_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "SPLUNK_ACCESS_TOKEN",
        "DEFENSECLAW_DECISION_MODEL_KEY",
        "openai_api_key",
    ],
)
def test_env_ref_naming_a_defenseclaw_credential_is_refused(name, monkeypatch):
    monkeypatch.setenv(name, "credential-value-gh1404")
    token = openclaw_gateway_token(_openclaw_json({"source": "env", "provider": "default", "id": name}))
    assert token.value == ""
    _assert_plain_notice(token.notice)
    assert name in token.notice and "credential-value-gh1404" not in token.notice


@pytest.mark.parametrize("name", ["OPENCLAW_GATEWAY_TOKEN", "DEFENSECLAW_GATEWAY_TOKEN", "MY_OPENCLAW_TOKEN"])
def test_env_ref_naming_a_gateway_token_variable_resolves(name, monkeypatch):
    monkeypatch.setenv(name, ENV_VALUE)
    token = openclaw_gateway_token(_openclaw_json({"source": "env", "provider": "default", "id": name}))
    assert (token.value, token.notice) == (ENV_VALUE, "")


def test_resolved_token_ignores_secretref_text(token_env, monkeypatch):
    from defenseclaw.config import GatewayConfig

    for name in ("OPENCLAW_GATEWAY_TOKEN", "DEFENSECLAW_GATEWAY_TOKEN"):
        monkeypatch.setenv(name, STALE_VALUE)
    assert GatewayConfig(token_env="OPENCLAW_GATEWAY_TOKEN").resolved_token() == ""
    assert GatewayConfig(token=STALE_VALUE).resolved_token() == ""
    monkeypatch.setenv("DEFENSECLAW_GATEWAY_TOKEN", "real-token-gh1404")
    assert GatewayConfig(token_env="OPENCLAW_GATEWAY_TOKEN").resolved_token() == "real-token-gh1404"


def test_doctor_does_not_count_secretref_text_as_a_token():
    from defenseclaw.commands.cmd_doctor import _normalized_gateway_token

    assert _normalized_gateway_token(STALE_VALUE) == ""
    assert _normalized_gateway_token("real-token-gh1404") == "real-token-gh1404"


def _seed_stale_dotenv(data_dir: str, extra: str = "") -> str:
    os.makedirs(data_dir, mode=0o700, exist_ok=True)
    path = os.path.join(data_dir, ".env")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("DEFENSECLAW_LLM_KEY=keep-me\n" + STALE_LINE + "\n" + extra)
    os.chmod(path, 0o600)
    return path


@pytest.mark.parametrize("setting", [STORE_REF, LITERAL], ids=["store", "string"])
def test_upgrade_retry_from_the_base_dotenv_line(setting, tmp_path, token_env, monkeypatch):
    """Init on the fix after a failed base init: the SecretRef text never becomes the token."""
    from defenseclaw.bootstrap import FirstRunOptions, StepResult, run_first_run
    from defenseclaw.config import load

    from tests.helpers import record_test_setup_agent_selections

    home = tmp_path / "home"
    (home / ".openclaw").mkdir(parents=True)
    (home / ".openclaw" / "openclaw.json").write_text(json.dumps(_openclaw_json(setting)), encoding="utf-8")
    data_dir = os.path.realpath(str(tmp_path / "dchome"))
    dotenv = _seed_stale_dotenv(data_dir)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("DEFENSECLAW_HOME", data_dir)
    token_env(None)
    # The CLI loads ~/.defenseclaw/.env into the process environment at start.
    monkeypatch.setenv("OPENCLAW_GATEWAY_TOKEN", STALE_VALUE)
    with (
        patch(
            "defenseclaw.agent_selection.record_setup_agent_selections", side_effect=record_test_setup_agent_selections
        ),
        patch("defenseclaw.bootstrap._quiet_guardrail_setup", return_value=StepResult("Guardrail", "pass", "test")),
    ):
        report = run_first_run(
            FirstRunOptions(
                connector="openclaw", profile="observe", skip_install=True, start_gateway=False, verify=False
            )
        )
        cfg = load()

    assert [s for s in report.setup if s.status == "fail"] == []
    body = open(dotenv, encoding="utf-8").read()
    assert "source" not in body and "DEFENSECLAW_LLM_KEY=keep-me" in body
    cleanup = [s for s in report.setup if s.name == "Gateway token"]
    assert len(cleanup) == 1 and cleanup[0].status == "pass" and cleanup[0].next_command == ""
    assert "Removed a gateway token line" in cleanup[0].detail and STALE_VALUE not in cleanup[0].detail
    warns = [s for s in report.setup if s.name == "OpenClaw token"]
    if setting == LITERAL:
        # The OpenClaw token resolves, so the cleanup is the only note: no token warning.
        assert warns == []
        assert cfg.gateway.resolved_token() == LITERAL
        assert f"OPENCLAW_GATEWAY_TOKEN={LITERAL}" in body
    else:
        assert cfg.gateway.resolved_token() == ""
        assert "OPENCLAW_GATEWAY_TOKEN" not in body


def test_doctor_fix_removes_the_base_dotenv_line(tmp_path, token_env, monkeypatch):
    from defenseclaw.commands import cmd_doctor

    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / "dchome"))
    token_env(None)
    cfg = _openclaw_cfg(tmp_path, STORE_REF)
    dotenv = _seed_stale_dotenv(cfg.data_dir)
    monkeypatch.setenv("OPENCLAW_GATEWAY_TOKEN", STALE_VALUE)
    with (
        patch.object(cmd_doctor, "_doctor_config_present", return_value=True),
        patch.object(cmd_doctor, "_active_connector", return_value="openclaw"),
    ):
        status, detail = cmd_doctor._fix_gateway_token(cfg, assume_yes=True)
    assert "already set" not in detail, (status, detail)
    assert status == "pass" and "removed a stale OpenClaw secret reference line" in detail
    assert STALE_VALUE not in detail
    body = open(dotenv, encoding="utf-8").read()
    assert "source" not in body and "DEFENSECLAW_LLM_KEY=keep-me" in body
    assert os.environ.get("OPENCLAW_GATEWAY_TOKEN", "") != STALE_VALUE


@pytest.mark.parametrize(
    "value",
    ["{opensource}", "{xYresourceZ}", "  {source", "{source: store}", "source", "{not-a-ref}", "0123abcd" * 8],
)
def test_secret_ref_text_must_not_match(value):
    from defenseclaw.connector_paths import is_secret_ref_text

    assert is_secret_ref_text(value) is False


@pytest.mark.parametrize(
    "value",
    [STALE_VALUE, "  " + STALE_VALUE + "  ", '{"source":"env","id":"X"}', '{"id": "X", "source": "store"}'],
)
def test_secret_ref_text_matches_the_repr_and_json(value):
    from defenseclaw.connector_paths import is_secret_ref_text

    assert is_secret_ref_text(value) is True


def test_init_cleanup_alone_is_one_info_line(tmp_path, token_env, monkeypatch, capsys):
    from defenseclaw.commands.cmd_init import _setup_gateway_defaults

    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path / "dchome"))
    token_env(None)
    cfg = _openclaw_cfg(tmp_path, LITERAL)
    _seed_stale_dotenv(cfg.data_dir)
    with patch.object(type(cfg), "active_connectors", return_value=["openclaw"]):
        _setup_gateway_defaults(cfg, MagicMock(), is_new_config=True)
    out = capsys.readouterr().out
    assert out.count("Removed a gateway token line") == 1
    assert "\u26a0" not in out and "gateway.auth.token" not in out


def test_agent_fallback_ignores_secret_ref_text(monkeypatch):
    from defenseclaw.commands import cmd_agent

    monkeypatch.setenv("DEFENSECLAW_GATEWAY_TOKEN", STALE_VALUE)
    monkeypatch.setenv("OPENCLAW_GATEWAY_TOKEN", "real-token-gh1404")
    with patch("defenseclaw.config.load", side_effect=RuntimeError("no config")):
        _host, _port, token = cmd_agent._resolve_gateway_target(
            SimpleNamespace(cfg=None), gateway_host=None, gateway_port=None, gateway_token_env=None
        )
    assert token == "real-token-gh1404"


def _cfg_with_keys(tmp_path, dotenv_body: str, llm_env: str = ""):
    from defenseclaw.config import Config, GatewayConfig, GuardrailConfig, OpenShellConfig

    data_dir = tmp_path / "dc"
    data_dir.mkdir()
    (data_dir / ".env").write_text(dotenv_body, encoding="utf-8")
    cfg = Config(
        data_dir=str(data_dir),
        audit_db=str(data_dir / "audit.db"),
        quarantine_dir=str(data_dir / "q"),
        plugin_dir=str(data_dir / "p"),
        policy_dir=str(data_dir / "pol"),
        guardrail=GuardrailConfig(),
        gateway=GatewayConfig(),
        openshell=OpenShellConfig(),
    )
    if llm_env:
        cfg.llm.api_key_env = llm_env
    return cfg


def test_credential_names_are_exact(tmp_path):
    from defenseclaw.connector_paths import defenseclaw_credential_names

    cfg = _cfg_with_keys(
        tmp_path,
        "OPENAI_KEY=x\nexport SPLUNK_HEC_TOKEN=y\nOPENCLAW_GATEWAY_TOKEN=z\nDEFENSECLAW_GATEWAY_TOKEN=w\n# COMMENTED=1\n",
        llm_env="MY_CUSTOM_LLM_VAR",
    )
    names = defenseclaw_credential_names(cfg)
    for name in (
        "OPENAI_KEY",
        "SPLUNK_HEC_TOKEN",
        "MY_CUSTOM_LLM_VAR",
        "AWS_BEARER_TOKEN_BEDROCK",
        "DEFENSECLAW_LLM_KEY",
    ):
        assert name in names, name
    for name in ("OPENCLAW_GATEWAY_TOKEN", "DEFENSECLAW_GATEWAY_TOKEN", "COMMENTED", "# COMMENTED"):
        assert name not in names, name


@pytest.mark.parametrize(
    "name", ["OPENAI_KEY", "SPLUNK_HEC_TOKEN", "MY_CUSTOM_LLM_VAR", "AWS_BEARER_TOKEN_BEDROCK", "GITHUB_TOKEN"]
)
def test_env_ref_naming_a_stored_or_configured_credential_is_refused(name, tmp_path, monkeypatch):
    from defenseclaw.connector_paths import defenseclaw_credential_names

    cfg = _cfg_with_keys(tmp_path, "OPENAI_KEY=x\nSPLUNK_HEC_TOKEN=y\nGITHUB_TOKEN=g\n", llm_env="MY_CUSTOM_LLM_VAR")
    monkeypatch.setenv(name, "credential-value-gh1404")
    token = openclaw_gateway_token(
        _openclaw_json({"source": "env", "provider": "default", "id": name}),
        credential_names=defenseclaw_credential_names(cfg),
    )
    assert token.value == ""
    _assert_plain_notice(token.notice)
    assert "credential-value-gh1404" not in token.notice


def test_env_ref_naming_an_unrelated_variable_still_resolves(tmp_path, monkeypatch):
    from defenseclaw.connector_paths import defenseclaw_credential_names

    cfg = _cfg_with_keys(tmp_path, "OPENAI_KEY=x\n")
    monkeypatch.setenv("MY_OPENCLAW_TOKEN", ENV_VALUE)
    token = openclaw_gateway_token(
        _openclaw_json({"source": "env", "id": "MY_OPENCLAW_TOKEN"}), credential_names=defenseclaw_credential_names(cfg)
    )
    assert (token.value, token.notice) == (ENV_VALUE, "")
