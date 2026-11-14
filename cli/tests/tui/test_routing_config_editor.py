# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Config editor: routing keys are editable, tokenomics is read-only (GAP-0630)."""

from __future__ import annotations

from dataclasses import replace

from defenseclaw.config import Config
from defenseclaw.tui.panels.setup import build_setup_sections
from defenseclaw.tui.services.setup_state import apply_config_field, validate_config_field


def section(cfg, name):
    return next(s for s in build_setup_sections(cfg, "linux") if s.name == name)


def test_routing_and_tokenomics_sections_exist() -> None:
    names = [s.name for s in build_setup_sections(Config(), "linux")]
    assert "Routing" in names and "Tokenomics" in names


def test_only_safe_routing_fields_are_editable() -> None:
    cfg = Config()
    cfg.routing.models = [{"name": "fast", "provider": "openai", "model": "m"}, {"name": "deep", "provider": "anthropic", "model": "m"}]
    cfg.routing.admin = {"rules": [{"id": "r"}], "budgets": []}
    fields = {f.key: f for f in section(cfg, "Routing").fields if f.key}
    # Turning routing on and the classifier need a model and an endpoint: read-only.
    assert fields["routing.enabled"].kind == "header" and fields["routing.classifier"].kind == "header"
    for key in ("routing.min_confidence", "routing.on_classifier_error", "routing.allow_user_override"):
        assert fields[key].kind != "header", key
    # The default alias can only name an alias that exists.
    alias = fields["routing.default_alias"]
    assert alias.kind == "choice" and alias.options == ("", "fast", "deep")
    assert validate_config_field(replace(alias, value="ghost")).severity == "error"
    assert validate_config_field(replace(alias, value="deep")).severity == "ok"
    assert fields["routing.on_classifier_error"].options == ("original", "rules")
    assert fields["routing.summary"].kind == "header" and fields["routing.summary"].value == "2 model(s), 1 rule(s), 0 budget(s)"


def test_default_alias_is_read_only_without_models() -> None:
    fields = {f.key: f for f in section(Config(), "Routing").fields if f.key}
    assert fields["routing.default_alias"].kind == "header"


def test_tokenomics_rows_are_read_only_and_name_the_command() -> None:
    cfg = Config()
    cfg.observability.tokenomics.enabled = True
    cfg.observability.pricing.version = "2026-11-12.1"
    cfg.observability.pricing.models = [object(), object()]
    rows = [f for f in section(cfg, "Tokenomics").fields if f.key]
    assert rows and all(f.kind == "header" for f in rows)
    by_key = {f.key: f for f in rows}
    assert by_key["observability.tokenomics.enabled"].value == "true"
    assert by_key["observability.pricing.version"].value == "2026-11-12.1, 2 model(s)"
    assert all("defenseclaw" in f.hint for f in rows)


def test_routing_values_are_validated() -> None:
    cfg = Config()
    fields = {f.key: f for f in section(cfg, "Routing").fields if f.key}

    def check(key, value):
        return validate_config_field(replace(fields[key], value=value))

    assert check("routing.min_confidence", "0.6").severity == "ok"
    assert check("routing.min_confidence", "1.5").severity == "error"
    assert check("routing.min_confidence", "high").severity == "error"
    assert check("routing.on_classifier_error", "nope").severity == "error"


def test_applying_routing_values_reaches_the_config_that_saves() -> None:
    cfg = Config()
    apply_config_field(cfg, "routing.min_confidence", "0.7")
    apply_config_field(cfg, "routing.on_classifier_error", "rules")
    apply_config_field(cfg, "routing.allow_user_override", "true")
    assert cfg.routing.min_confidence == 0.7 and cfg.routing.on_classifier_error == "rules"
    assert cfg.routing.allow_user_override is True
    saved = cfg.routing.to_dict()
    assert saved["min_confidence"] == 0.7 and saved["on_classifier_error"] == "rules" and saved["allow_user_override"] is True
