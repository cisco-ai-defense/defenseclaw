# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Setup config editor save gate and persistence (pure model tests)."""

from __future__ import annotations

import os

import yaml
from defenseclaw.config import default_config, load, prepare_fresh_v8_config
from defenseclaw.tui.panels.setup import (
    SetupPanelModel,
    SetupWizard,
    build_setup_sections,
    build_wizard_args,
    guardrail_wizard_fields,
    wizard_field_value,
)
from defenseclaw.tui.services.setup_state import (
    ConfigField,
    ConfigSection,
    apply_config_field,
    blocking_validation_errors,
    is_python_modeled,
    validate_config_field,
    validation_errors,
)


def _focus(model: SetupPanelModel, key: str) -> None:
    for section_index, section in enumerate(model.sections):
        for line, field in enumerate(section.fields):
            if field.key == key:
                model.mode = "config"
                model.active_section = section_index
                model.active_line = line
                return
    raise AssertionError(f"{key} is not in the config editor")


def _field(model: SetupPanelModel, key: str) -> ConfigField:
    for section in model.sections:
        for field in section.fields:
            if field.key == key:
                return field
    raise AssertionError(f"{key} is not in the config editor")


def test_default_config_has_no_blocking_errors() -> None:
    sections = build_setup_sections(default_config())
    assert blocking_validation_errors(sections) == ()
    model = SetupPanelModel(default_config())
    hints = model.save_restart_hints()
    assert hints.blocking == 0
    assert hints.blocking_errors == ()


def test_untouched_invalid_field_does_not_block_a_save() -> None:
    cfg = default_config()
    cfg.gateway.port = 99999  # invalid, but already on disk
    model = SetupPanelModel(cfg)
    assert any(error.startswith("gateway.port:") for error in model.validation_errors())

    _focus(model, "gateway.host")
    assert model.set_current_field_value("127.0.0.2")

    action = model.review_save_action()
    assert action.open_diff is True
    hints = model.save_restart_hints()
    assert hints.issues >= 1
    assert hints.blocking == 0


def test_changed_invalid_field_blocks_the_save() -> None:
    model = SetupPanelModel(default_config())
    _focus(model, "gateway.port")
    assert model.set_current_field_value("not-a-port")

    action = model.review_save_action()
    assert action.open_diff is False
    assert model.blocking_validation_errors() == ("gateway.port: expected an integer",)
    assert model.save_restart_hints().blocking == 1


def test_unset_typed_field_inherits_and_is_valid() -> None:
    for kind, options in (("bool", ()), ("int", ()), ("choice", ("open", "closed"))):
        unset = ConfigField("X", "some.key", kind, "", "", options)
        assert validate_config_field(unset).severity == "ok", kind
        cleared = ConfigField("X", "some.key", kind, "", "5", options)
        assert validate_config_field(cleared).severity == "error", kind
    sections = (ConfigSection("S", (ConfigField("X", "some.key", "int", "", ""),), ""),)
    assert validation_errors(sections) == ()


def test_every_editable_field_is_saved_by_the_python_config() -> None:
    cfg = default_config()
    unmodeled = [
        field.key
        for section in build_setup_sections(cfg)
        for field in section.fields
        if field.kind != "header" and field.key and not is_python_modeled(cfg, field.key)
    ]
    assert unmodeled == []


def test_keys_the_config_cannot_save_are_read_only_rows() -> None:
    model = SetupPanelModel(default_config())
    for key in ("agent.id", "gateway.tls", "guardrail.stream_buffer_bytes", "scanners.plugin_scanner"):
        assert is_python_modeled(None, key) is False, key
        row = _field(model, key)
        assert row.interactive is False, key
        assert row.hint
    hooks = next(section for section in model.sections if section.name == "Connector Hooks")
    assert hooks.fields
    assert all(not field.interactive for field in hooks.fields)
    assert all(field.hint.startswith("Set by defenseclaw setup") for field in hooks.fields)


def test_modeled_paths_through_dict_and_renamed_fields() -> None:
    assert is_python_modeled(None, "gateway.port")
    assert is_python_modeled(None, "guardrail.connectors.codex.mode")
    assert is_python_modeled(None, "openshell.mcp.import")
    assert not is_python_modeled(None, "gateway.nope")
    assert not is_python_modeled(None, "gateway.port.deeper")


def test_edited_port_round_trips_through_a_v8_config(tmp_path, monkeypatch) -> None:
    data_dir = str(tmp_path)
    monkeypatch.setenv("HOME", data_dir)
    monkeypatch.setenv("DEFENSECLAW_HOME", data_dir)
    cfg = prepare_fresh_v8_config(default_config())
    cfg.data_dir = data_dir
    cfg.audit_db = os.path.join(data_dir, "audit.db")
    cfg.policy_dir = os.path.join(data_dir, "policies")
    cfg.save()

    model = SetupPanelModel(load(data_dir=data_dir))
    _focus(model, "gateway.port")
    assert model.set_current_field_value("19999")
    _focus(model, "guardrail.block_at")
    assert model.set_current_field_value("HIGH")
    assert model.review_save_action().open_diff is True
    model.apply_changes_to_config()
    model.config.save()

    with open(os.path.join(data_dir, "config.yaml"), encoding="utf-8") as stream:
        saved = yaml.safe_load(stream)
    assert saved["gateway"]["port"] == 19999 and saved["guardrail"]["block_at"] == "HIGH"
    assert load(data_dir=data_dir).gateway.port == 19999
    assert model.has_changes() is False


def test_unmodeled_key_edit_is_dropped_by_save_which_is_why_it_is_read_only(tmp_path, monkeypatch) -> None:
    data_dir = str(tmp_path)
    monkeypatch.setenv("HOME", data_dir)
    monkeypatch.setenv("DEFENSECLAW_HOME", data_dir)
    cfg = prepare_fresh_v8_config(default_config())
    cfg.data_dir = data_dir
    cfg.audit_db = os.path.join(data_dir, "audit.db")
    cfg.policy_dir = os.path.join(data_dir, "policies")
    apply_config_field(cfg, "agent.id", "my-agent")
    cfg.save()
    with open(os.path.join(data_dir, "config.yaml"), encoding="utf-8") as stream:
        assert "agent" not in (yaml.safe_load(stream) or {})


def test_guardrail_rule_pack_keeps_a_custom_pack_untouched() -> None:
    cfg = {"guardrail": {"enabled": True, "rule_pack_dir": "/packs/MyPack"}}
    fields = list(guardrail_wizard_fields(cfg))
    assert wizard_field_value(fields, "Rule Pack") == "custom (MyPack)"
    args = build_wizard_args(SetupWizard.GUARDRAIL, fields, cfg)
    assert "--rule-pack" not in args

    index = next(i for i, field in enumerate(fields) if field.label == "Rule Pack")
    fields[index] = fields[index].with_value("default")
    args = build_wizard_args(SetupWizard.GUARDRAIL, fields, cfg)
    assert ("--rule-pack", "default") in tuple(zip(args, args[1:], strict=False))


def test_guardrail_rule_pack_preset_is_shown_as_is() -> None:
    cfg = {"guardrail": {"enabled": True, "rule_pack_dir": "/packs/strict"}}
    fields = guardrail_wizard_fields(cfg)
    assert wizard_field_value(fields, "Rule Pack") == "strict"


def test_reloading_the_config_keeps_the_cursor_on_the_same_field() -> None:
    cfg = default_config()
    model = SetupPanelModel(cfg)
    _focus(model, "guardrail.block_message")

    model.set_config(cfg)

    field = model.current_field()
    assert field is not None and field.key == "guardrail.block_message"
