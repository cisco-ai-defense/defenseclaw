# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""routing.admin rules, budgets and visibility: Python passthrough and schema (1.0.10, S11)."""

from __future__ import annotations

import copy
import os
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml
from defenseclaw.config import load
from defenseclaw.observability.v8_config import V8ConfigError, validate_v8_source

ADMIN = {
    "rules": [
        {"id": "secrets-stay-local", "match": {"severity_at_least": "HIGH"}, "allow": ["local"], "default": "local"},
        {
            "id": "contractors-no-cloud",
            "match": {"groups": ["DCLAB\\contractors"]},
            "action": "deny",
            "message": "Contractors may not use cloud models. Contact IT.",
        },
        {"id": "code", "match": {"categories": ["code"], "connectors": ["codex"]}, "allow": ["fast", "local"]},
    ],
    "budgets": [
        {"id": "per-user-daily", "scope": "user", "subject": "*", "period": "day", "limit_usd": 20, "on_exceed": "downgrade:local"},
        {"id": "eng", "scope": "group", "subject": "DCLAB\\eng", "period": "month", "limit_usd": 500.5, "on_exceed": "deny"},
    ],
    "visibility": {"users_see": "own"},
}

MODELS = [
    {"name": "fast", "provider": "openai", "model": "gpt-4.1-mini"},
    {"name": "local", "provider": "vllm", "model": "qwen-local"},
]


def _document(tmp_path: Path, admin: dict, *, enabled: bool = False) -> dict:
    return {
        "config_version": 8,
        "data_dir": str(tmp_path),
        "observability": {},
        "routing": {"enabled": enabled, "models": copy.deepcopy(MODELS), "admin": copy.deepcopy(admin)},
    }


def test_admin_rules_and_budgets_survive_a_python_save(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(_document(tmp_path, ADMIN), sort_keys=False), encoding="utf-8")
    with patch.dict(os.environ, {"DEFENSECLAW_CONFIG": str(config_path)}, clear=False):
        cfg = load(data_dir=tmp_path)
        assert cfg.routing.admin == ADMIN
        cfg.routing.enabled = True
        cfg.save()
    persisted = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert persisted["routing"]["admin"] == ADMIN
    assert persisted["routing"]["enabled"] is True


def test_admin_only_routing_block_is_kept(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    document = _document(tmp_path, {"visibility": {"users_see": "none"}})
    del document["routing"]["models"]
    config_path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    with patch.dict(os.environ, {"DEFENSECLAW_CONFIG": str(config_path)}, clear=False):
        load(data_dir=tmp_path).save()
    persisted = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert persisted["routing"]["admin"] == {"visibility": {"users_see": "none"}}


def test_config_without_admin_saves_without_it(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    document = _document(tmp_path, {})
    del document["routing"]["admin"]
    config_path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    with patch.dict(os.environ, {"DEFENSECLAW_CONFIG": str(config_path)}, clear=False):
        load(data_dir=tmp_path).save()
    assert "admin" not in yaml.safe_load(config_path.read_text(encoding="utf-8"))["routing"]


def test_schema_accepts_the_admin_example(tmp_path: Path) -> None:
    validate_v8_source(_document(tmp_path, ADMIN))


@pytest.mark.parametrize(
    "edit",
    [
        lambda a: a["rules"][1].update(allow=["fast"]),  # deny with allow
        lambda a: a["rules"][0].update(message="x"),  # message on a constrain rule
        lambda a: a["rules"][0].pop("allow") and a["rules"][0].pop("default"),  # constrain that changes nothing
        lambda a: a["rules"][0].update(match={}),  # empty match
        lambda a: a["rules"][0]["match"].update(severity_at_least="NONE"),
        lambda a: a["rules"][0].update(action="allow"),
        lambda a: a["rules"][0].update(id="Bad Id"),
        lambda a: a["budgets"][0].update(scope="team"),
        lambda a: a["budgets"][0].update(period="year"),
        lambda a: a["budgets"][0].update(limit_usd=0),
        lambda a: a["budgets"][0].update(on_exceed="block"),
        lambda a: a["budgets"][1].update(subject="*"),  # pooled group budget for everyone
        lambda a: a["budgets"][0].pop("period"),
        lambda a: a.update(visibility={"users_see": "all"}),
        lambda a: a.update(extra=True),
    ],
)
def test_schema_refuses_bad_admin_entries(tmp_path: Path, edit) -> None:
    admin = copy.deepcopy(ADMIN)
    edit(admin)
    with pytest.raises(V8ConfigError):
        validate_v8_source(_document(tmp_path, admin))
