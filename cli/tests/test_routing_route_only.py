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
        if k.startswith(("ANTHROPIC_", "CLAUDE_CODE_", "AWS_BEARER")):
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


def test_bedrock_iam_uses_gateway_signing_and_bearer_passes_through(homes: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for k in ("AWS_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION"):
        monkeypatch.delenv(k, raising=False)
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
