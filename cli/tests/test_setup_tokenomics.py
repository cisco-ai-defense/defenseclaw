# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from click.testing import CliRunner
from defenseclaw import price_lookup
from defenseclaw.commands.cmd_setup_tokenomics import status_of, tokenomics
from defenseclaw.context import AppContext
from defenseclaw.observability.v8_config import load_validate_v8
from defenseclaw.tokenomics_seed import _SOURCE_TREE, load_default_pricing, pricing_changes

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


def test_seed_leaves_any_operator_pricing_setting_alone() -> None:
    fallback_only = {"observability": {"pricing": {"unknown_model": "fallback", "fallback": {"input_per_mtok": 2, "output_per_mtok": 8}}}}
    assert pricing_changes(fallback_only) == []
    assert pricing_changes({"observability": {"pricing": {}}}) != []


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


def test_disable_turns_the_local_store_off_and_says_what_stays(tmp_path: Path) -> None:
    # rel-1-0-10 GAP-1166: --disable left local_store.enabled on, so status read
    # "Local store: on" after tokenomics was turned off.
    app = _app(tmp_path)
    assert CliRunner().invoke(tokenomics, ["--enable"], obj=app, catch_exceptions=False).exit_code == 0
    (tmp_path / "model_usage").mkdir()
    result = CliRunner().invoke(tokenomics, ["--disable"], obj=app, catch_exceptions=False)
    assert result.exit_code == 0, result.output
    tok = yaml.safe_load((tmp_path / "config.yaml").read_text())["observability"]["tokenomics"]
    assert tok["enabled"] is False and tok["local_store"]["enabled"] is False
    assert "Local store:    off" in result.output
    assert f"usage already recorded stays in {tmp_path / 'model_usage'}" in result.output
    state = json.loads(CliRunner().invoke(tokenomics, ["--status", "--json"], obj=app, catch_exceptions=False).output)
    assert state["enabled"] is False and state["local_store"] is False


def test_status_says_a_store_left_on_is_idle_while_tokenomics_is_off(tmp_path: Path) -> None:
    app = _app(tmp_path, BASE.replace("observability: {}", "observability:\n  tokenomics:\n    local_store: {enabled: true}"))
    result = CliRunner().invoke(tokenomics, ["--status"], obj=app, catch_exceptions=False)
    assert "Local store:    on, idle while tokenomics is off (keeps 30 days)" in result.output


# rel-1-0-10:GAP-0041: the seed prices each model at its vendor's list price
# (checked 2026-11-21, _sources). gpt-5-2* was meant for gpt-5.2 but, with
# its hyphen, matched only dated gpt-5 snapshots (gpt-5-2025-08-07), so
# gpt-5.2 had no cost. Dated gpt-5 snapshots keep the gpt-5 price, and
# gpt-5.2-pro, which costs 12 times gpt-5.2, gets no row rather than the
# gpt-5.2 price.
@pytest.mark.parametrize(
    ("model", "entry", "rates"),
    [
        ("gpt-5", "openai/gpt-5", (1.25, 10.0, 0.125)),
        ("gpt-5-2025-08-07", "openai/gpt-5-20*", (1.25, 10.0, 0.125)),
        ("gpt-5.2", "openai/gpt-5.2", (1.75, 14.0, 0.175)),
        ("gpt-5.2-2025-12-11", "openai/gpt-5.2-20*", (1.75, 14.0, 0.175)),
        ("gpt-5.2-pro", None, None),
        ("gpt-5-pro", None, None),
        ("gpt-5-mini-2025-08-07", None, None),
    ],
)
def test_seed_prices_openai_ids_at_their_list_price(model: str, entry: str | None, rates: tuple | None) -> None:
    seed = load_default_pricing()
    assert price_lookup.price_entry(seed, "openai", model) == entry
    if rates is None:
        return
    row = next(r for r in seed["models"] if f"{r['provider']}/{r['model']}" == entry)
    assert (row["input_per_mtok"], row["output_per_mtok"], row["cache_read_per_mtok"]) == rates


def test_every_seed_row_names_its_source_and_check_date() -> None:
    raw = json.loads(_SOURCE_TREE.read_text(encoding="utf-8"))
    sources = {s["row"]: s for s in raw["_sources"]}
    rows = [f"{r['provider']}/{r['model']}" for r in raw["models"]]
    assert sorted(sources) == sorted(rows)
    for row in rows:
        assert sources[row]["source"].startswith("https://"), row
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", sources[row]["checked"]), row
