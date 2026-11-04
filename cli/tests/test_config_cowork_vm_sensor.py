# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Cowork host-delivery config stays closed and survives CLI round trips."""

import re
from copy import deepcopy
from pathlib import Path

import pytest
import yaml
from defenseclaw import config as cfgmod
from defenseclaw import config_writer
from defenseclaw.observability.v8_config import load_validate_v8


@pytest.fixture(autouse=True)
def isolated_config(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    monkeypatch.delenv("DEFENSECLAW_CONFIG", raising=False)
    monkeypatch.delenv(cfgmod.DEPLOYMENT_MODE_ENV, raising=False)
    monkeypatch.delenv("DEFENSECLAW_ENTERPRISE_PROFILE", raising=False)
    monkeypatch.setattr(config_writer, "machine_managed_standalone", lambda: False)
    monkeypatch.setattr(config_writer, "_use_go_validator", lambda: False)


def source(block=None):
    document = {
        "config_version": 9,
        "deployment_mode": "managed_enterprise",
        "enterprise": {"profile": "standalone"},
        "observability": {},
    }
    if block is not None:
        document["enterprise"]["cowork_vm_sensor"] = block
    return document


def enabled_block():
    return {
        "mode": "on",
        "tenant": "tenant_1",
        "device": "mac-42",
        "collector": "edr.example.com:443",
        "vendor": "cisco",
        "source_dir": "/opt/cisco/defenseclaw/share/cowork",
        "package_sha256": "a" * 64,
        "signature_sha256": "b" * 64,
    }


def test_absent_and_off_need_no_delivery_inputs(tmp_path):
    for block in (None, {}, {"mode": "off"}):
        cfg = cfgmod.load(data_dir=tmp_path, parsed_source=source(block))
        assert cfg.enterprise_cowork_vm_sensor.mode == "off"
        assert cfg.enterprise_cowork_vm_sensor.package_sha256 == ""
        assert "enterprise_cowork_vm_sensor" not in cfgmod._config_to_dict(cfg)


@pytest.mark.parametrize(
    "mode,profile", [("", ""), ("unmanaged_byod", "standalone"), ("managed_enterprise", "secure_client")]
)
@pytest.mark.parametrize("block", [{}, {"mode": "off"}, enabled_block()])
def test_cowork_refused_outside_standalone(tmp_path, mode, profile, block):
    document = source(block)
    document["deployment_mode"] = mode
    document["enterprise"]["profile"] = profile
    if profile == "secure_client":
        document["config_version"] = 8
    with pytest.raises(
        ValueError, match="requires deployment_mode managed_enterprise and enterprise.profile standalone"
    ):
        cfgmod.load(data_dir=tmp_path, parsed_source=document)
    with pytest.raises(ValueError):
        load_validate_v8(yaml.safe_dump(document).encode(), source_name="config.yaml")


@pytest.mark.parametrize(
    "field,value",
    [
        ("mode", True),
        ("mode", "enabled"),
        ("tenant", "x,device=other"),
        ("tenant", 123),
        ("device", ["id"]),
        ("device", "\ufeffid"),
        ("device", "id\n"),
        ("device", "d" * 129),
        ("collector", "https://edr.example.com"),
        ("collector", "edr.example.com:0"),
        ("collector", "edr.example.com:65536"),
        ("vendor", "Cisco"),
        ("package_sha256", "A" * 64),
        ("signature_sha256", "no"),
        ("source_dir", "C:cowork"),
        ("source_dir", r"\\server\cowork"),
        ("source_dir", "/cowork\x00"),
        ("source_dir", "/symlink/../cowork"),
        ("source_dir", "/cowork/./source"),
        ("source_dir", "/cowork//source"),
        ("source_dir", "/cowork/"),
        ("source_dir", r"C:\symlink\..\cowork"),
        ("source_dir", r"C:\cowork\.\source"),
        ("source_dir", r"C:\cowork.\source"),
        ("source_dir", "C:\\cowork\\"),
        ("unknown_key", "value"),
    ],
)
def test_bad_values_fail_python_load(tmp_path, field, value):
    block = enabled_block()
    block[field] = value
    with pytest.raises(ValueError, match="enterprise.cowork_vm_sensor"):
        cfgmod.load(data_dir=tmp_path, parsed_source=source(block))


def test_missing_package_pin_and_argument_limit(tmp_path):
    block = enabled_block()
    del block["package_sha256"]
    with pytest.raises(ValueError, match="package_sha256"):
        cfgmod.load(data_dir=tmp_path, parsed_source=source(block))
    block = enabled_block()
    block["tenant"] = "t" * 128
    base = f"tenant={block['tenant']},device=,collector={block['collector']}"
    block["device"] = "d" * (256 - len(base))
    cfgmod.load(data_dir=tmp_path, parsed_source=source(block))
    block["device"] += "d"
    with pytest.raises(ValueError, match="256-byte"):
        cfgmod.load(data_dir=tmp_path, parsed_source=source(block))


def test_windows_source_and_unsigned_staging_candidate(tmp_path):
    block = enabled_block()
    block["source_dir"] = r"C:\Program Files\Cisco\DefenseClaw\cowork-source"
    del block["signature_sha256"]
    cfg = cfgmod.load(data_dir=tmp_path, parsed_source=source(block))
    assert cfg.enterprise_cowork_vm_sensor.source_dir == block["source_dir"]
    assert cfg.enterprise_cowork_vm_sensor.signature_sha256 == ""
    load_validate_v8(yaml.safe_dump(source(block)).encode(), source_name="config.yaml")


def test_lifecycle_roundtrip_preserves_block_and_ignores_mirror_edits(tmp_path):
    block = enabled_block()
    path = tmp_path / "config.yaml"
    document = source(deepcopy(block))
    document["data_dir"] = str(tmp_path)
    path.write_bytes(b"\xef\xbb\xbf" + yaml.safe_dump(document).replace("\n", "\r\n").encode())
    cfg = cfgmod.load()
    assert cfg.enterprise_cowork_vm_sensor.package_sha256 == "a" * 64
    # This mirror is load only: the lifecycle's config remains authoritative.
    cfg.enterprise_cowork_vm_sensor.tenant = "ignored-mirror-edit"
    cfg.environment = "macos"
    cfg.save(actor=config_writer.ACTOR_LIFECYCLE)
    saved = yaml.safe_load(path.read_text(encoding="utf-8-sig"))
    assert saved["enterprise"]["cowork_vm_sensor"] == block
    assert "enterprise_cowork_vm_sensor" not in saved
    before = path.read_bytes()
    cfg.save(actor=config_writer.ACTOR_LIFECYCLE)
    assert path.read_bytes() == before


def test_cowork_restart_keys_match_go_writer():
    root = Path(__file__).resolve().parents[2]
    go = (root / "internal/config/configwrite/configwrite.go").read_text()
    match = re.search(r"\nvar restartKeys = \[\]string\{(.*?)\n\}", go, re.S)
    assert match is not None
    assert list(config_writer.RESTART_KEYS) == re.findall(r'"([^"]+)"', match[1])
    changed = ["enterprise.cowork_vm_sensor.mode", "enterprise.cowork_vm_sensor.package_sha256"]
    assert config_writer.restart_required(changed) == changed


def test_fleet_config_without_device_is_valid(tmp_path):
    # Each host derives its own device ID; validation reserves the longest.
    block = enabled_block()
    del block["device"]
    cfg = cfgmod.load(data_dir=tmp_path, parsed_source=source(block))
    assert cfg.enterprise_cowork_vm_sensor.device == ""
    load_validate_v8(yaml.safe_dump(source(block)).encode(), source_name="config.yaml")
    base = f"tenant={block['tenant']},device=,collector=:443"
    block["collector"] = "c" * (256 - len(base) - 64) + ":443"
    cfgmod.load(data_dir=tmp_path, parsed_source=source(block))
    block["collector"] = "c" + block["collector"]
    with pytest.raises(ValueError, match="256-byte"):
        cfgmod.load(data_dir=tmp_path, parsed_source=source(block))


def test_cowork_derived_device_limit_matches_go():
    root = Path(__file__).resolve().parents[2]
    go = (root / "internal/config/cowork_vm_sensor.go").read_text()
    match = re.search(r"const CoworkDerivedDeviceMaxLen = (\d+)", go)
    assert match is not None
    assert int(match[1]) == cfgmod._COWORK_DERIVED_DEVICE_MAX_LEN
