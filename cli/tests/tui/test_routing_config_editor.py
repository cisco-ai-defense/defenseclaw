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


def test_routing_fields_are_editable_and_the_lists_are_read_only() -> None:
    cfg = Config()
    cfg.routing.models = [{"name": "fast", "provider": "openai", "model": "m"}]
    cfg.routing.admin = {"rules": [{"id": "r"}], "budgets": []}
    fields = {f.key: f for f in section(cfg, "Routing").fields if f.key}
    for key in ("routing.enabled", "routing.classifier", "routing.default_alias", "routing.min_confidence",
                "routing.on_classifier_error", "routing.allow_user_override"):
        assert fields[key].kind != "header", key
    assert fields["routing.classifier"].options == ("rules", "systemone", "vllm_sr")
    assert fields["routing.on_classifier_error"].options == ("original", "rules")
    assert fields["routing.summary"].kind == "header" and fields["routing.summary"].value == "1 model(s), 1 rule(s), 0 budget(s)"


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
    assert check("routing.classifier", "rules").severity == "ok"
    assert check("routing.classifier", "poetry").severity == "error"
    assert check("routing.on_classifier_error", "nope").severity == "error"
    assert check("routing.enabled", "maybe").severity == "error"


def test_applying_routing_values_reaches_the_config_that_saves() -> None:
    cfg = Config()
    apply_config_field(cfg, "routing.classifier", "rules")
    apply_config_field(cfg, "routing.min_confidence", "0.7")
    apply_config_field(cfg, "routing.enabled", "true")
    apply_config_field(cfg, "routing.allow_user_override", "true")
    assert cfg.routing.classifier == "rules" and cfg.routing.min_confidence == 0.7
    assert cfg.routing.enabled is True and cfg.routing.allow_user_override is True
    saved = cfg.routing.to_dict()
    assert saved["classifier"] == "rules" and saved["min_confidence"] == 0.7 and saved["allow_user_override"] is True
