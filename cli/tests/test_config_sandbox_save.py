# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Common sandbox authority must survive modeled Python config saves."""

import copy
from pathlib import Path

import pytest
import yaml
from defenseclaw import config as config_module
from defenseclaw import config_writer


@pytest.fixture
def saved_config(tmp_path, monkeypatch):
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    monkeypatch.delenv("DEFENSECLAW_CONFIG", raising=False)
    path = tmp_path / "config.yaml"

    def create(*, common=True, legacy=None):
        document = {
            "config_version": 9,
            "data_dir": str(tmp_path),
            "observability": {},
            "openshell": legacy or {"binary": "openshell"},
        }
        if common:
            document["sandbox"] = {
                "enabled": True,
                "runtime": "openshell",
                "runtimes": {"openshell": {"enabled": True}},
            }
        config_module.write_config_yaml_secure(str(path), document)
        return config_module.load(data_dir=tmp_path), path

    return create


def file_state(path):
    return path.read_bytes(), Path(config_writer.generation_path(str(path))).read_bytes()


@pytest.mark.parametrize("verified", [False, True])
def test_legacy_teardown_refuses_before_write_or_verification(saved_config, verified):
    cfg, path = saved_config()
    assert cfg.openshell.enabled
    before = file_state(path)
    snapshot = copy.deepcopy(cfg._loaded_v8_modeled_snapshot)
    cfg.openshell.enabled = False
    verified_paths = []
    with pytest.raises(config_writer.ConfigConflictError, match=r"sandbox\.enabled"):
        if verified:
            cfg.save_verified(verified_paths.append)
        else:
            cfg.save()
    assert not verified_paths
    assert file_state(path) == before
    assert cfg._loaded_v8_modeled_snapshot == snapshot
    assert config_module.load(data_dir=path.parent).sandbox.enabled


@pytest.mark.parametrize(
    ("suffix", "change"),
    [
        ("harnesses", lambda cfg: cfg.openshell.harnesses.append("codex")),
        ("wrappers", lambda cfg: cfg.openshell.wrappers.append("codex")),
        ("egress.unblocked", lambda cfg: cfg.openshell.egress.unblocked.append("allowed.example")),
        ("workdir.mode", lambda cfg: setattr(cfg.openshell.workdir, "mode", "copy")),
        ("mcp.import", lambda cfg: setattr(cfg.openshell.mcp, "import_", False)),
        ("admin.allow_yolo", lambda cfg: setattr(cfg.openshell.admin, "allow_yolo", False)),
        ("resources.cpu", lambda cfg: setattr(cfg.openshell.resources, "cpu", "1")),
        ("yolo", lambda cfg: setattr(cfg.openshell, "yolo", False)),
    ],
)
def test_legacy_shared_policy_names_canonical_field(saved_config, suffix, change):
    cfg, path = saved_config()
    before = file_state(path)
    change(cfg)
    with pytest.raises(config_writer.ConfigConflictError) as failure:
        cfg.save()
    assert f"sandbox.{suffix}" in str(failure.value)
    assert "reload" in str(failure.value).lower()
    assert file_state(path) == before


def test_common_config_allows_vendor_only_openshell_changes(saved_config):
    cfg, path = saved_config()
    cfg.openshell.binary = "reviewed-openshell"
    cfg.openshell.gateway.name = "team"
    cfg.save()
    loaded = config_module.load(data_dir=path.parent)
    assert loaded.sandbox.enabled
    assert loaded.openshell.binary == "reviewed-openshell"
    assert loaded.openshell.gateway.name == "team"


def test_absent_common_config_retains_legacy_writes(saved_config):
    cfg, path = saved_config(common=False, legacy={"enabled": True})
    cfg.openshell.enabled = False
    cfg.openshell.egress.block.append("blocked.example")
    cfg.save()
    loaded = config_module.load(data_dir=path.parent)
    assert loaded.sandbox is None
    assert not loaded.openshell.enabled
    assert loaded.openshell.egress.block == ["blocked.example"]


def test_direct_canonical_mutation_disables_master_and_saves_policy(saved_config):
    cfg, path = saved_config()
    previous_generation = config_writer.read_generation_state(str(path)).generation
    cfg.sandbox.enabled = False
    cfg.sandbox.egress.block.append("blocked.example")
    result = cfg.save()
    assert result.generation == previous_generation + 1
    loaded = config_module.load(data_dir=path.parent)
    assert not loaded.sandbox.enabled and not loaded.openshell.enabled
    assert loaded.sandbox.egress.block == loaded.openshell.egress.block == ["blocked.example"]
    assert cfg.save().generation == result.generation


def test_canonical_mutation_keeps_explicit_overlap_validation(saved_config):
    cfg, path = saved_config(legacy={"profile": "strict"})
    # The common model inherits the explicit legacy policy, but the file still
    # owns that legacy pin. A canonical edit must retain the conflict refusal.
    before = file_state(path)
    cfg.sandbox.profile = "balanced"
    with pytest.raises(ValueError, match=r"sandbox\.profile"):
        cfg.save()
    assert file_state(path) == before


def test_concurrently_added_common_authority_refuses_legacy_write(saved_config):
    stale, path = saved_config(common=False, legacy={"enabled": True})
    saved_config(legacy={"enabled": True})
    before = file_state(path)
    stale.openshell.enabled = False
    with pytest.raises(config_writer.ConfigConflictError, match=r"sandbox\.enabled"):
        stale.save()
    assert file_state(path) == before


@pytest.mark.parametrize("initial_common", [False, True])
def test_canonical_mutation_refuses_changed_authority_presence(saved_config, initial_common):
    stale, path = saved_config(common=initial_common)
    saved_config(common=not initial_common)
    before = file_state(path)
    if stale.sandbox is None:
        stale.sandbox = config_module.SandboxConfig()
    else:
        stale.sandbox.enabled = False
    with pytest.raises(config_writer.ConfigConflictError, match="sandbox.*reload"):
        stale.save()
    assert file_state(path) == before


@pytest.mark.parametrize("initial_common", [False, True])
def test_vendor_only_save_preserves_concurrent_authority_change(saved_config, initial_common):
    stale, path = saved_config(common=initial_common)
    saved_config(common=not initial_common)
    stale.openshell.binary = "reviewed-openshell"
    stale.save()
    document = yaml.safe_load(path.read_bytes())
    assert ("sandbox" in document) is not initial_common
    assert document["openshell"]["binary"] == "reviewed-openshell"


@pytest.mark.parametrize(
    ("name", "first", "second"),
    [
        (
            "egress.block",
            lambda cfg: cfg.sandbox.egress.block.append("first.example"),
            lambda cfg: cfg.sandbox.egress.block.append("second.example"),
        ),
        (
            "admin.allow_yolo",
            lambda cfg: setattr(cfg.sandbox.admin, "allow_yolo", False),
            lambda cfg: setattr(cfg.sandbox.admin, "allow_yolo", True),
        ),
        (
            "profile",
            lambda cfg: setattr(cfg.sandbox, "profile", "strict"),
            lambda cfg: setattr(cfg.sandbox, "profile", "balanced"),
        ),
    ],
)
def test_stale_common_policy_edit_refuses_without_changing_state(saved_config, name, first, second):
    stale, path = saved_config()
    concurrent = config_module.load(data_dir=path.parent)
    first(concurrent)
    concurrent.save()
    before = file_state(path)
    snapshot = copy.deepcopy(stale._loaded_v8_modeled_snapshot)
    second(stale)
    with pytest.raises(config_writer.ConfigConflictError, match=r"sandbox\." + name.replace(".", r"\.")):
        stale.save()
    assert file_state(path) == before
    assert stale._loaded_v8_modeled_snapshot == snapshot


def test_independent_common_policy_edits_merge(saved_config):
    stale, path = saved_config()
    concurrent = config_module.load(data_dir=path.parent)
    concurrent.sandbox.egress.block.append("first.example")
    concurrent.save()
    stale.sandbox.profile = "strict"
    stale.save()
    saved = yaml.safe_load(path.read_bytes())["sandbox"]
    assert saved["egress"]["block"] == ["first.example"]
    assert saved["profile"] == "strict"


def test_same_concurrent_common_policy_value_is_idempotent(saved_config):
    stale, path = saved_config()
    concurrent = config_module.load(data_dir=path.parent)
    concurrent.sandbox.profile = "strict"
    concurrent.save()
    before = file_state(path)
    stale.sandbox.profile = "strict"
    stale.save()
    assert file_state(path) == before


def test_inherited_legacy_policy_change_refuses_stale_common_edit(saved_config):
    stale, path = saved_config(legacy={"egress": {"block": ["old.example"]}})
    config_writer.apply(
        [config_writer.Change("openshell.egress.block", ["old.example", "concurrent.example"])],
        "cli:test", "synthetic concurrent legacy edit", path=path,
    )
    before = file_state(path)
    snapshot = copy.deepcopy(stale._loaded_v8_modeled_snapshot)
    stale.sandbox.egress.block.append("stale.example")
    with pytest.raises(config_writer.ConfigConflictError, match=r"sandbox\.egress\.block"):
        stale.save()
    assert file_state(path) == before
    assert stale._loaded_v8_modeled_snapshot == snapshot
