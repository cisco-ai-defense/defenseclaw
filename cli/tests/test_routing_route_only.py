# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Route-only enable/disable/status helpers (S1 slice 5b)."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml
from defenseclaw import routing_route_only as ro
from defenseclaw.config import load


def _config(tmp_path: Path, routing: dict) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump({"config_version": 9, "data_dir": str(tmp_path), "observability": {}, "routing": routing}), encoding="utf-8")
    return path


_ROUTING = {
    "enabled": True,
    "classifier": "rules",
    "models": [{"name": "haiku", "provider": "anthropic", "model": "claude-haiku-4-5"}],
}


@pytest.fixture
def homes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    claude = tmp_path / "claude"
    codex = tmp_path / "codex"
    claude.mkdir()
    codex.mkdir()
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(claude))
    monkeypatch.setenv("CODEX_HOME", str(codex))
    for k in list(os.environ):
        if k.startswith(("ANTHROPIC_", "CLAUDE_CODE_", "AWS_")):
            monkeypatch.delenv(k, raising=False)
    return tmp_path


def test_enable_records_claude_upstream_and_disable_clears(homes: Path, tmp_path: Path) -> None:
    (homes / "claude" / "settings.json").write_text(json.dumps({"env": {"ANTHROPIC_BASE_URL": "https://llm.corp.example/"}}), encoding="utf-8")
    path = _config(tmp_path, dict(_ROUTING))
    with patch.dict(os.environ, {"DEFENSECLAW_CONFIG": str(path)}):
        cfg = load(data_dir=tmp_path)
        out = ro.enable(cfg, "claudecode")
        assert out["upstream"] == {"base_url": "https://llm.corp.example", "api": "messages"}
        saved = yaml.safe_load(path.read_text(encoding="utf-8"))["routing"]["route_only"]
        assert saved == {"connectors": ["claudecode"], "upstreams": {"claudecode": {"base_url": "https://llm.corp.example", "api": "messages"}}}
        assert [s for s in ro.status(cfg) if s["connector"] == "claudecode"][0]["enabled"] is True
        ro.disable(load(data_dir=tmp_path), "claudecode")
    assert "route_only" not in yaml.safe_load(path.read_text(encoding="utf-8"))["routing"]


_AWS_CONFIG = "[default]\nregion = us-west-2\n[profile bedrock-dev]\nregion = us-west-2\n"


def _aws_files(homes: Path, monkeypatch: pytest.MonkeyPatch, config: str = _AWS_CONFIG, creds: str = "") -> None:
    (homes / "aws-config").write_text(config, encoding="utf-8")
    (homes / "aws-credentials").write_text(creds, encoding="utf-8")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(homes / "aws-config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(homes / "aws-credentials"))


def _settings(homes: Path, doc: dict) -> None:
    (homes / "claude" / "settings.json").write_text(json.dumps(doc), encoding="utf-8")


def test_bedrock_iam_uses_gateway_signing_and_bearer_passes_through(homes: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _aws_files(homes, monkeypatch)
    monkeypatch.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
    monkeypatch.setenv("AWS_REGION", "us-west-2")
    # IAM credentials (no Bedrock API key): the gateway signs with the profile.
    up = ro.detect_upstream("claudecode")
    assert up is not None and up.base_url == "https://bedrock-runtime.us-west-2.amazonaws.com" and up.api == "invoke"
    assert up.to_config()["bedrock"] == {"auth": "profile", "profile": "default", "region": "us-west-2"}
    (homes / "claude" / "settings.json").write_text(json.dumps({"env": {"AWS_PROFILE": "bedrock-dev"}}), encoding="utf-8")
    up = ro.detect_upstream("claudecode")
    assert up is not None and up.to_config()["bedrock"] == {"auth": "profile", "profile": "bedrock-dev", "region": "us-west-2"}
    monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", "x")
    up = ro.detect_upstream("claudecode")
    assert up is not None and up.to_config() == {
        "base_url": "https://bedrock-runtime.us-west-2.amazonaws.com",
        "api": "invoke",
        "bedrock": {"auth": "passthrough", "region": "us-west-2"},
    }


def test_codex_upstreams(homes: Path) -> None:
    cfgfile = homes / "codex" / "config.toml"
    cfgfile.write_text("model_provider = \"bedrock\"\n[model_providers.bedrock]\nbase_url = \"https://mantle.example/v1/\"\nwire_api = \"responses\"\n", encoding="utf-8")
    up = ro.detect_upstream("codex")
    assert up is not None and up.base_url == "https://mantle.example/v1" and up.api == "responses"
    cfgfile.write_text("model = \"gpt-5\"\n", encoding="utf-8")
    assert ro.detect_upstream("codex").base_url == "https://api.openai.com/v1"
    (homes / "codex" / "auth.json").write_text(json.dumps({"tokens": {"id_token": "x"}}), encoding="utf-8")
    assert ro.detect_upstream("codex").base_url == "https://chatgpt.com/backend-api/codex"
    cfgfile.write_text("profile = \"w\"\n[profiles.w]\nmodel_provider = \"azure\"\n", encoding="utf-8")
    with pytest.raises(ro.RouteOnlyError, match="profile"):
        ro.detect_upstream("codex")


def test_refusals(homes: Path, tmp_path: Path) -> None:
    path = _config(tmp_path, {"enabled": False})
    with patch.dict(os.environ, {"DEFENSECLAW_CONFIG": str(path)}):
        cfg = load(data_dir=tmp_path)
        with pytest.raises(ro.RouteOnlyError, match="semantic routing"):
            ro.enable(cfg, "claudecode")
        with pytest.raises(ro.RouteOnlyError, match="no route-only support"):
            ro.enable(cfg, "cursor")


# REVIEW-code-slice7 P2-2: Bedrock detection picks the identity the agent
# really uses, or refuses with the two options.
def test_bedrock_existing_skip_is_passthrough(homes: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
    gw = "https://llm-gw.corp.example/bedrock"
    env = {"CLAUDE_CODE_SKIP_BEDROCK_AUTH": "1", "ANTHROPIC_BEDROCK_BASE_URL": gw, "AWS_REGION": "eu-west-1"}
    _settings(homes, {"env": env})
    up = ro.detect_upstream("claudecode")
    want = {"base_url": gw, "api": "invoke", "bedrock": {"auth": "passthrough", "region": "eu-west-1"}}
    assert up is not None and up.to_config() == want


def test_bedrock_static_keys_without_profile_refused(homes: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _aws_files(homes, monkeypatch)
    monkeypatch.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
    _settings(homes, {"env": {"AWS_ACCESS_KEY_ID": "AKIDAGENT", "AWS_SECRET_ACCESS_KEY": "x"}})
    with pytest.raises(ro.RouteOnlyError, match="AWS_ACCESS_KEY_ID") as exc:
        ro.detect_upstream("claudecode")
    assert "AKIDAGENT" not in str(exc.value) and "AWS_BEARER_TOKEN_BEDROCK" in str(exc.value)
    # With a profile named, the profile wins in the agent SDK too.
    _settings(homes, {"env": {"AWS_ACCESS_KEY_ID": "AKIDAGENT", "AWS_PROFILE": "bedrock-dev"}})
    assert ro.detect_upstream("claudecode").to_config()["bedrock"]["profile"] == "bedrock-dev"


@pytest.mark.parametrize("key", ["awsCredentialExport", "awsAuthRefresh"])
def test_bedrock_credential_helpers_refused(homes: Path, monkeypatch: pytest.MonkeyPatch, key: str) -> None:
    _aws_files(homes, monkeypatch)
    monkeypatch.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
    _settings(homes, {key: "aws sso login --profile x", "env": {"AWS_PROFILE": "bedrock-dev"}})
    with pytest.raises(ro.RouteOnlyError, match=key):
        ro.detect_upstream("claudecode")


def test_bedrock_profile_must_exist(homes: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _aws_files(homes, monkeypatch, config="[profile other]\n", creds="[from-creds]\naws_access_key_id = A\n")
    monkeypatch.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
    with pytest.raises(ro.RouteOnlyError, match="profile .default. is not in the AWS"):
        ro.detect_upstream("claudecode")
    _settings(homes, {"env": {"AWS_PROFILE": "missing"}})
    with pytest.raises(ro.RouteOnlyError, match="profile .missing."):
        ro.detect_upstream("claudecode")
    _settings(homes, {"env": {"AWS_PROFILE": "from-creds"}})
    assert ro.detect_upstream("claudecode").to_config()["bedrock"]["profile"] == "from-creds"


def test_bedrock_custom_aws_config_file(homes: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _aws_files(homes, monkeypatch, config="[profile shell-only]\n")
    monkeypatch.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
    # A shell AWS_CONFIG_FILE is honored for the profile check.
    _settings(homes, {"env": {"AWS_PROFILE": "shell-only"}})
    assert ro.detect_upstream("claudecode").to_config()["bedrock"]["profile"] == "shell-only"
    # One set only in settings.json env is not visible to the gateway.
    other = homes / "agent-only-config"
    other.write_text("[profile agent-only]\n", encoding="utf-8")
    _settings(homes, {"env": {"AWS_PROFILE": "agent-only", "AWS_CONFIG_FILE": str(other)}})
    with pytest.raises(ro.RouteOnlyError, match="AWS_CONFIG_FILE"):
        ro.detect_upstream("claudecode")


def test_bedrock_signing_refuses_a_non_aws_host(homes: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _aws_files(homes, monkeypatch)
    monkeypatch.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
    _settings(homes, {"env": {"ANTHROPIC_BEDROCK_BASE_URL": "https://llm-gw.corp.example"}})
    with pytest.raises(ro.RouteOnlyError, match="bedrock-runtime"):
        ro.detect_upstream("claudecode")


def test_enable_refuses_a_missing_profile(homes: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _aws_files(homes, monkeypatch, config="")
    monkeypatch.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
    path = _config(tmp_path, dict(_ROUTING))
    with patch.dict(os.environ, {"DEFENSECLAW_CONFIG": str(path)}):
        cfg = load(data_dir=tmp_path)
        with pytest.raises(ro.RouteOnlyError, match="AWS profile"):
            ro.enable(cfg, "claudecode")
    assert "route_only" not in (yaml.safe_load(path.read_text(encoding="utf-8"))["routing"])
