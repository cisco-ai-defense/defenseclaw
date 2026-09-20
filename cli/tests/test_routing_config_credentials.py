# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""Semantic-routing config persistence and credential-registry regressions."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import yaml
from click.testing import CliRunner
from defenseclaw import credentials
from defenseclaw.commands.cmd_keys import keys_cmd
from defenseclaw.config import Config, RoutingConfig, load
from defenseclaw.context import AppContext


def _full_routing_config(*, enabled: bool) -> dict:
    return {
        "enabled": enabled,
        "version": "0.3.0",
        "port": 8799,
        "algorithm": "priority",
        "remote": {
            "endpoint": "http://127.0.0.1:8799",
            "timeout_ms": 1200,
        },
        "models": [
            {
                "name": "fast",
                "provider": "openai",
                "model": "gpt-4.1-mini",
                "base_url": "https://api.openai.com/v1",
                "api_key_env": "OPENAI_ROUTER_KEY",
                "capabilities": ["chat", "tools"],
            },
            {
                "name": "local",
                "provider": "vllm",
                "model": "qwen-local",
            },
        ],
        "signals": {
            "keywords": [
                {
                    "name": "coding",
                    "keywords": ["python", "golang"],
                    "operator": "or",
                }
            ],
        },
        "decisions": [
            {
                "name": "coding-to-fast",
                "priority": 10,
                "conditions": [{"type": "keyword", "name": "coding"}],
                "operator": "and",
                "model_refs": ["fast"],
                "algorithm": "priority",
            }
        ],
    }


def test_disabled_routing_graph_survives_enable_and_save(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    routing = _full_routing_config(enabled=False)
    config_path.write_text(
        yaml.safe_dump(
            {
                "config_version": 8,
                "data_dir": str(tmp_path),
                "observability": {},
                "routing": routing,
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    with patch.dict(os.environ, {"DEFENSECLAW_CONFIG": str(config_path)}, clear=False):
        cfg = load(data_dir=tmp_path)
        assert cfg.routing.remote == routing["remote"]
        assert cfg.routing.models == routing["models"]
        assert cfg.routing.signals == routing["signals"]
        assert cfg.routing.decisions == routing["decisions"]

        cfg.routing.enabled = True
        cfg.save()

    persisted = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    expected = dict(routing, enabled=True)
    assert persisted["routing"] == expected


def test_disabled_nested_only_routing_graph_is_not_replaced_on_enable(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    routing = _full_routing_config(enabled=False)
    for lifecycle_field in ("version", "port", "algorithm"):
        routing.pop(lifecycle_field)
    config_path.write_text(
        yaml.safe_dump(
            {
                "config_version": 8,
                "data_dir": str(tmp_path),
                "observability": {},
                "routing": routing,
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    with patch.dict(os.environ, {"DEFENSECLAW_CONFIG": str(config_path)}, clear=False):
        cfg = load(data_dir=tmp_path)
        cfg.routing.enabled = True
        cfg.save()

    persisted = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert persisted["routing"] == dict(routing, enabled=True)


def _routing_cfg(tmp_path: Path, *, enabled: bool, models: list[dict]) -> Config:
    return Config(
        data_dir=str(tmp_path),
        routing=RoutingConfig(enabled=enabled, models=models),
    )


def test_routing_credentials_are_unique_required_and_skip_keyless_models(tmp_path: Path) -> None:
    cfg = _routing_cfg(
        tmp_path,
        enabled=True,
        models=[
            {
                "name": "fast",
                "base_url": "https://api.openai.com/v1",
                "api_key_env": "ROUTER_PROVIDER_KEY",
            },
            {
                "name": "smart",
                "base_url": "https://api.openai.com/v1",
                "api_key_env": " ROUTER_PROVIDER_KEY ",
            },
            {"name": "local", "base_url": "http://127.0.0.1:8000/v1"},
        ],
    )

    matching = [status for status in credentials.classify(cfg) if status.resolution.env_name == "ROUTER_PROVIDER_KEY"]
    assert len(matching) == 1
    assert matching[0].requirement is credentials.Requirement.REQUIRED
    assert matching[0].spec.feature == "routing.models"
    assert matching[0].spec.resolve_bound_endpoint(cfg) == "https://api.openai.com/v1"
    assert "fast, smart" in matching[0].spec.description
    assert all("local" not in status.spec.description for status in credentials.classify(cfg))


def test_disabled_routing_key_is_reported_not_used(tmp_path: Path) -> None:
    cfg = _routing_cfg(
        tmp_path,
        enabled=False,
        models=[{"name": "smart", "api_key_env": "DISABLED_ROUTER_KEY"}],
    )

    status = next(status for status in credentials.classify(cfg) if status.resolution.env_name == "DISABLED_ROUTER_KEY")
    assert status.requirement is credentials.Requirement.NOT_USED


def test_static_credential_precedes_and_absorbs_routing_requirement(tmp_path: Path) -> None:
    cfg = _routing_cfg(
        tmp_path,
        enabled=True,
        models=[{"name": "shared", "api_key_env": "DEFENSECLAW_LLM_KEY"}],
    )

    matching = [status for status in credentials.classify(cfg) if status.resolution.env_name == "DEFENSECLAW_LLM_KEY"]
    assert len(matching) == 1
    assert matching[0].spec is credentials.lookup("DEFENSECLAW_LLM_KEY")
    assert matching[0].requirement is credentials.Requirement.REQUIRED


def test_lookup_recognizes_config_discovered_routing_key(tmp_path: Path) -> None:
    cfg = _routing_cfg(
        tmp_path,
        enabled=True,
        models=[{"name": "smart", "api_key_env": "ROUTER_LOOKUP_KEY"}],
    )

    assert credentials.lookup("ROUTER_LOOKUP_KEY") is None
    spec = credentials.lookup("ROUTER_LOOKUP_KEY", cfg)
    assert spec is not None
    assert spec.feature == "routing.models"


def test_keys_set_recognizes_config_discovered_routing_key(tmp_path: Path) -> None:
    cfg = _routing_cfg(
        tmp_path,
        enabled=True,
        models=[
            {
                "name": "smart",
                "base_url": "https://router.example.test/v1",
                "api_key_env": "ROUTER_SET_KEY",
            }
        ],
    )
    app = AppContext()
    app.cfg = cfg

    result = CliRunner().invoke(
        keys_cmd,
        ["set", "ROUTER_SET_KEY", "--value", "router-secret"],
        obj=app,
    )

    assert result.exit_code == 0, result.output
    assert "is not in the DefenseClaw registry" not in result.output
    assert "routing.models:" in result.output
    assert "bound to https://router.example.test/v1" in result.output
