# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import yaml
from click.testing import CliRunner
from defenseclaw.commands.cmd_setup_tokenomics import status_of, tokenomics
from defenseclaw.context import AppContext
from defenseclaw.observability.v8_config import load_validate_v8
from defenseclaw.tokenomics_seed import load_default_pricing, pricing_changes

BASE = "config_version: 9\nobservability: {}\n"
MINE = (
    "config_version: 9\nobservability:\n  pricing:\n    version: mine-1\n    models:\n"
    "      - {provider: x, model: y, input_per_mtok: 1, output_per_mtok: 2}\n"
)


def _app(tmp_path: Path, text: str = BASE) -> AppContext:
    (tmp_path / "config.yaml").write_text(text)
    app = AppContext()
    app.cfg = SimpleNamespace(data_dir=str(tmp_path))
    return app


def test_seed_is_a_valid_closed_schema_table() -> None:
    seed = load_default_pricing()
    assert seed["version"] and seed["models"]
    assert not [k for k in seed if k.startswith("_")]
    load_validate_v8(yaml.safe_dump({"config_version": 9, "observability": {"pricing": seed}}))


def test_seed_never_replaces_an_operator_table() -> None:
    assert pricing_changes({"observability": {"pricing": {"version": "mine", "models": []}}}) == []
    assert len(pricing_changes({"observability": {}})) == 1
    assert len(pricing_changes({})) == 1


def test_status_defaults_are_off() -> None:
    expected = {"enabled": False, "local_store": False, "retention_days": 30, "pricing_version": "", "priced_models": 0}
    assert status_of({}) == expected


def test_enable_writes_blocks_and_seeds_pricing_then_disable_keeps_the_table(tmp_path: Path) -> None:
    app = _app(tmp_path)
    result = CliRunner().invoke(tokenomics, ["--enable", "--json"], obj=app, catch_exceptions=False)
    assert result.exit_code == 0, result.output
    state = json.loads(result.output)
    assert state["enabled"] and state["local_store"] and state["priced_models"] > 0
    written = yaml.safe_load((tmp_path / "config.yaml").read_text())
    load_validate_v8(yaml.safe_dump(written))  # what we wrote is valid
    result = CliRunner().invoke(tokenomics, ["--disable", "--json"], obj=app, catch_exceptions=False)
    state = json.loads(result.output)
    assert state["enabled"] is False and state["priced_models"] > 0


def test_enable_keeps_an_existing_price_table(tmp_path: Path) -> None:
    app = _app(tmp_path, MINE)
    result = CliRunner().invoke(tokenomics, ["--enable", "--json"], obj=app, catch_exceptions=False)
    state = json.loads(result.output)
    assert state["pricing_version"] == "mine-1" and state["priced_models"] == 1


def test_flags_conflict_and_default_is_status(tmp_path: Path) -> None:
    app = _app(tmp_path)
    assert CliRunner().invoke(tokenomics, ["--enable", "--disable"], obj=app).exit_code != 0
    result = CliRunner().invoke(tokenomics, [], obj=app, catch_exceptions=False)
    assert "Tokenomics:     off" in result.output and "Price table:    none" in result.output
