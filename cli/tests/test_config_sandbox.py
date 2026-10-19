# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Common sandbox source validation shares its cases with the Go loader."""

from pathlib import Path

import pytest
import yaml
from defenseclaw.config import Config, SandboxConfig, _config_to_dict, _merge_openshell, _merge_sandbox, load
from defenseclaw.observability.v8_config import load_validate_v8

_CASES = yaml.safe_load(
    (Path(__file__).resolve().parents[2] / "testdata/sandbox/common_config_cases.yaml").read_text(encoding="utf-8")
)["cases"]


@pytest.mark.parametrize("case", _CASES, ids=lambda case: case["name"])
def test_common_source_corpus(case):
    version = 8 if case["name"] == "secure_client_namespace_is_frozen" else 9
    document = {"config_version": version, **yaml.safe_load(case["source"])}
    if case["valid"]:
        load_validate_v8(document)
    else:
        expected = case["path"].replace(".", r"\.") if case.get("path") else None
        with pytest.raises(ValueError, match=expected):
            load_validate_v8(document)


def test_absence_preserves_legacy_and_lane_defaults_are_off():
    cfg = Config()
    assert cfg.sandbox is None
    assert "sandbox" not in _config_to_dict(cfg)
    assert _merge_sandbox(None) is None
    sandbox = _merge_sandbox({"enabled": True, "runtime": "axis"}, "/state")
    assert sandbox.enabled and sandbox.runtime == "axis"
    assert not sandbox.runtimes.axis.enabled and not sandbox.runtimes.openshell.enabled
    common = _merge_sandbox({}, "/state")
    legacy = _merge_openshell({}, "/state")
    assert common.runtime == "auto" and common.yolo is None
    for field in ("llm", "pack_dir", "workdir", "approvals", "mcp", "admin"):
        assert getattr(common, field) == getattr(legacy, field)


@pytest.mark.parametrize("raw", ["axis", [], 42, False])
def test_non_mapping_common_config_is_an_actionable_value_error(tmp_path, monkeypatch, raw):
    import defenseclaw.config as config_module

    message = "sandbox: expected a configuration mapping"
    with pytest.raises(ValueError, match=f"^{message}$"):
        _merge_sandbox(raw)

    source = {"config_version": 9, "data_dir": str(tmp_path), "sandbox": raw}
    (tmp_path / "config.yaml").write_text(yaml.safe_dump(source), encoding="utf-8")
    monkeypatch.setattr(config_module, "default_data_path", lambda: tmp_path)
    with pytest.raises(ValueError, match=f"^{message}$"):
        load()


def test_common_round_trip_retains_false_and_vendor_settings():
    cfg = Config(sandbox=SandboxConfig(enabled=True, runtime="axis", yolo=False))
    cfg.sandbox.runtimes.axis.enabled = True
    cfg.sandbox.mcp.import_ = False
    cfg.openshell.binary = "/trusted/openshell"
    saved = _config_to_dict(cfg)
    assert saved["openshell"]["binary"] == "/trusted/openshell"
    assert saved["sandbox"]["mcp"]["import"] is False
    assert "import_" not in saved["sandbox"]["mcp"]
    assert saved["sandbox"]["yolo"] is False
    assert _merge_sandbox(saved["sandbox"]) == cfg.sandbox


def test_runtime_selection_and_partial_nested_settings_keep_legacy_policy():
    legacy = {"egress": {"block": ["blocked.example"], "allow": ["allowed.example"]},
              "workdir": {"masks": [".secret"], "git_depth": 17}, "harnesses": ["claudecode"], "profile": "strict"}
    common = _merge_sandbox({"enabled": True, "runtime": "axis", "egress": {"ports": [443]},
                             "workdir": {"git_depth": 0}}, "/state", legacy)
    assert common.egress.block == ["blocked.example"] and common.egress.allow == ["allowed.example"]
    assert common.egress.ports == [443]
    assert common.workdir.masks == [".secret"] and common.workdir.git_depth == 0
    assert common.harnesses == ["claudecode"] and common.profile == "strict"


@pytest.mark.parametrize("active", [False, True])
def test_loaded_common_policy_reaches_existing_consumers(tmp_path, monkeypatch, active):
    import defenseclaw.config as config_module

    common = {"enabled": active, "runtime": "openshell", "runtimes": {"openshell": {"enabled": active}},
              "llm": "none", "harnesses": ["claudecode"]}
    source = {"config_version": 9, "data_dir": str(tmp_path), "openshell": {"enabled": True, "pack_dir": "",
              "egress": {"block": ["blocked.example"]}, "workdir": {"masks": [".secret"]}}, "sandbox": common}
    (tmp_path / "config.yaml").write_text(yaml.safe_dump(source), encoding="utf-8")
    monkeypatch.setattr(config_module, "default_data_path", lambda: tmp_path)
    cfg = load()
    assert cfg.openshell.enabled is active
    assert cfg.openshell.pack_dir == "" and cfg.sandbox.pack_dir == ""
    assert cfg.openshell.egress.block == ["blocked.example"] and cfg.openshell.workdir.masks == [".secret"]
    assert cfg.openshell.llm == "none" and "claudecode" in cfg.policy_connectors()
