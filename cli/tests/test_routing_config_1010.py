# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""1.0.10 semantic-routing keys survive a load/save round trip (S1 slice 1)."""

from __future__ import annotations

import copy
import os
from pathlib import Path
from unittest.mock import patch

import yaml
from defenseclaw.config import load

_MODELS = [
    {"name": "fast", "provider": "openai", "model": "gpt-4.1-mini", "api_key_env": "OPENAI_ROUTER_KEY", "apis": ["chat", "responses"]},
    {"name": "claude", "provider": "anthropic", "model": "claude-haiku-4-5", "credential": "anthropic-org"},
    {"name": "local", "provider": "ollama", "model": "llama3.1", "base_url": "http://127.0.0.1:11434"},
]

_NEW_KEYS = {
    "classifier": "rules",
    "min_confidence": 0.6,
    "on_classifier_error": "rules",
    "default_alias": "fast",
    "categories": {"code": "claude", "chat": "fast"},
    "allow_user_override": True,
    "sensitive": {"severity_at_least": "HIGH", "aliases": ["local"]},
    "systemone": {"use_decision_model": False, "base_url": "http://127.0.0.1:8791/v1/systemone", "model": "s1", "timeout_ms": 300},
    "route_only": {
        "connectors": ["claudecode"],
        "upstreams": {"claudecode": {"base_url": "https://api.anthropic.com", "api": "messages"}},
    },
    "admin": {"allowed_aliases": ["fast", "claude", "local"], "denied_providers": ["azure"], "locked": ["default_alias"]},
}


def _write(path: Path, data_dir: Path, routing: dict, profiles: dict | None = None) -> None:
    doc = {"config_version": 9, "data_dir": str(data_dir), "observability": {}, "routing": routing}
    if profiles is not None:
        doc["guardrail"] = {"profiles": profiles}
    path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


def _round_trip(tmp_path: Path, routing: dict, profiles: dict | None = None) -> dict:
    config_path = tmp_path / "config.yaml"
    _write(config_path, tmp_path, routing, profiles)
    with patch.dict(os.environ, {"DEFENSECLAW_CONFIG": str(config_path)}, clear=False):
        cfg = load(data_dir=tmp_path)
        cfg.save()
    return yaml.safe_load(config_path.read_text(encoding="utf-8"))


def test_every_1010_routing_key_round_trips(tmp_path: Path) -> None:
    routing = {"enabled": False, "models": copy.deepcopy(_MODELS), **copy.deepcopy(_NEW_KEYS)}
    persisted = _round_trip(tmp_path, routing)
    assert persisted["routing"] == routing


def test_only_new_keys_keep_the_routing_block(tmp_path: Path) -> None:
    # Before 1.0.10 the serializer dropped the block unless enabled, version,
    # port, algorithm or a 1.0.9 nested key was set.
    routing = {"enabled": False, "classifier": "rules"}
    persisted = _round_trip(tmp_path, routing)
    assert persisted["routing"] == routing


def test_profile_routing_overlay_round_trips(tmp_path: Path) -> None:
    routing = {"enabled": False, "models": copy.deepcopy(_MODELS)}
    profiles = {"eng": {"mode": "action", "routing": {"allowed_aliases": ["fast", "claude"], "default_alias": "claude", "allow_user_override": False}}}
    persisted = _round_trip(tmp_path, routing, profiles)
    assert persisted["guardrail"]["profiles"]["eng"]["routing"] == profiles["eng"]["routing"]


def test_1_0_9_routing_block_is_unchanged(tmp_path: Path) -> None:
    routing = {
        "enabled": True,
        "version": "0.3.0",
        "port": 8801,
        "models": copy.deepcopy(_MODELS[:1]),
        "decisions": [{"name": "default", "model_refs": ["fast"]}],
    }
    routing["models"][0].pop("apis")
    persisted = _round_trip(tmp_path, routing)
    assert persisted["routing"] == routing
    assert "classifier" not in persisted["routing"]
