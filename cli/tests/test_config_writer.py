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

"""The single config writer (config_writer) and Config.save on top of it."""

from __future__ import annotations

import os
import stat

import pytest
from defenseclaw import config_writer
from defenseclaw.config_writer import Change


def _config(tmp_path, body: str = "") -> str:
    path = tmp_path / "config.yaml"
    path.write_text(f"config_version: 9\ndata_dir: {tmp_path}\n# operator note\n{body}observability: {{}}\n")
    return str(path)


def test_apply_keeps_comments_validates_and_advances_generation(tmp_path, monkeypatch):
    monkeypatch.delenv("DEFENSECLAW_DEPLOYMENT_MODE", raising=False)
    path = _config(tmp_path, "guardrail:\n  mode: observe # keep\n")

    first = config_writer.apply([Change("guardrail.mode", "action")], "cli:test", "test", path=path)
    text = open(path, encoding="utf-8").read()
    assert first.generation == 1 and first.changed == ["guardrail.mode"]
    assert "# operator note" in text and "mode: action # keep" in text
    assert config_writer.read_generation_state(path).config_sha256 == first.sha256

    with pytest.raises(config_writer.ConfigConflictError):
        config_writer.apply([Change("guardrail.mode", "observe")], "cli:test", "t", "0" * 64, path=path)
    with pytest.raises(Exception):
        config_writer.apply([Change("guardrail.mode", "bogus")], "cli:test", "t", path=path)
    assert open(path, encoding="utf-8").read() == text

    second = config_writer.apply(
        [Change("gateway.api_port", 18971), Change("guardrail.mode", unset=True)],
        "cli:test",
        "t",
        first.sha256,
        path=path,
    )
    assert second.generation == 2 and second.restart_required == ["gateway.api_port"]
    # A truncated state file keeps its counter: the next write resumes past it.
    with open(config_writer.generation_path(path), "w", encoding="utf-8") as handle:
        handle.write('{"generation": 41, "config_sha')
    third = config_writer.apply([Change("guardrail.mode", "action")], "cli:test", "t", path=path)
    assert third.generation == 42 and config_writer.read_generation_state(path).generation_reset
    # The writer names every key the running gateway applies only on restart.
    assert config_writer.restart_required(
        [
            "guardrail.hook_fail_mode",
            "guardrail.connectors.codex.enabled",
            "guardrail.block_at",
            "gateway.watcher.enabled",
            "application_protection.connectors.codex.guardrail.block_at",
            "cisco_ai_defense.endpoint",
        ]
    ) == ["guardrail.hook_fail_mode", "guardrail.connectors.codex.enabled"]


def test_unset_removes_a_dependent_pair_in_one_write(tmp_path, monkeypatch):
    # GAP-0084: the digest pins the pack, so each key alone is refused.
    from unittest.mock import patch

    from click.testing import CliRunner
    from defenseclaw.commands import cmd_config

    monkeypatch.delenv("DEFENSECLAW_DEPLOYMENT_MODE", raising=False)
    path = _config(
        tmp_path,
        "openshell:\n  admin:\n    required_pack: balanced\n    required_pack_digest: sha256:" + "ab" * 32 + "\n",
    )
    pack, digest = "openshell.admin.required_pack", "openshell.admin.required_pack_digest"
    with (
        patch.object(cmd_config.config_module, "config_path", return_value=tmp_path / "config.yaml"),
        patch("defenseclaw.gateway.local_policy_digest", return_value=None),
    ):
        alone = CliRunner().invoke(cmd_config.config_cmd, ["unset", pack])
        both = CliRunner().invoke(cmd_config.config_cmd, ["unset", pack, digest])
    assert alone.exit_code != 0 and f"config unset {pack} {digest}" in alone.output
    assert both.exit_code == 0, both.output
    text = open(path, encoding="utf-8").read()
    assert "required_pack" not in text


def test_every_write_re_renders_custom_providers_from_llm_providers(tmp_path, monkeypatch):
    import json

    monkeypatch.delenv("DEFENSECLAW_DEPLOYMENT_MODE", raising=False)
    path = _config(tmp_path)
    entry = {"name": "custom-gateway", "domains": ["llm.example.internal"], "env_keys": ["LLM_GATEWAY"]}
    config_writer.apply([Change("llm_providers.custom", [entry])], "cli:test", "t", path=path)
    overlay = json.loads((tmp_path / "custom-providers.json").read_text(encoding="utf-8"))
    assert overlay["_derived_from"] and [p["name"] for p in overlay["providers"]] == ["custom-gateway"]


def test_writer_refuses_local_actors_on_a_standalone_managed_device(tmp_path, monkeypatch):
    path = _config(tmp_path)
    (tmp_path / config_writer.MANAGED_RUNTIME_DESCRIPTOR).write_text("{}")
    tmp_path.chmod(0o755)
    monkeypatch.setenv("DEFENSECLAW_DEPLOYMENT_MODE", "managed_enterprise")
    monkeypatch.setenv("DEFENSECLAW_ENTERPRISE_PROFILE", "standalone")
    with pytest.raises(config_writer.ManagedConfigWriteError):
        config_writer.apply([Change("guardrail.mode", "action")], "cli:test", "t", path=path)
    with pytest.raises(FileNotFoundError):
        config_writer.read_generation_state(path)
    # A refusal leaves the lifecycle's folder as it was: every user's hook reads it.
    if os.name != "nt":
        assert stat.S_IMODE(tmp_path.stat().st_mode) == 0o755


def test_machine_marker_makes_a_standard_users_writers_managed(tmp_path, monkeypatch):
    # A standard user's per-user config says nothing about the host: the
    # machine marker the enterprise lifecycle publishes decides.
    from defenseclaw import upgrade_shim
    from defenseclaw.config import default_config
    from defenseclaw.enforce import asset_lists

    path = _config(tmp_path)
    monkeypatch.delenv("DEFENSECLAW_DEPLOYMENT_MODE", raising=False)
    monkeypatch.setattr(upgrade_shim, "managed_deployment", lambda: "standalone")
    with pytest.raises(config_writer.ManagedConfigWriteError):
        config_writer.apply([Change("guardrail.mode", "action")], "cli:test", "t", path=path)
    with pytest.raises(asset_lists.ManagedDeviceError):
        asset_lists.refuse_if_managed(default_config(), target_type="skill", op=asset_lists.OP_BLOCK, name="x")
    config_writer.apply([Change("guardrail.mode", "action")], config_writer.ACTOR_LIFECYCLE, "t", path=path)


def test_a_refusal_is_audited_when_the_command_has_no_logger(monkeypatch):
    # `config` skips the startup load, so the refusal opens its own logger.
    from unittest.mock import MagicMock

    import click
    from defenseclaw import config as config_module
    from defenseclaw import logger as logger_module
    from defenseclaw.context import AppContext
    from defenseclaw.enforce import asset_lists

    audit = MagicMock()
    monkeypatch.setattr(config_module, "load", lambda: object())
    monkeypatch.setattr(logger_module.Logger, "from_config", staticmethod(lambda _cfg: audit))
    with click.Context(click.Command("set"), obj=AppContext()):
        asset_lists.audit_managed_refusal("config-update", "guardrail.mode", "verb=set")
    audit.log_action.assert_called_once_with(
        "config-update", "guardrail.mode", "outcome=refused reason=managed_device verb=set"
    )


def test_config_save_goes_through_the_writer(tmp_path, monkeypatch):
    from defenseclaw import config as config_module

    monkeypatch.delenv("DEFENSECLAW_DEPLOYMENT_MODE", raising=False)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    path = _config(tmp_path, "guardrail:\n  mode: observe # keep\n")
    cfg = config_module.load(data_dir=str(tmp_path))
    cfg.guardrail.mode = "action"

    result = cfg.save()

    assert result.generation == 1 and result.changed == ["guardrail.mode"]
    assert "mode: action # keep" in open(path, encoding="utf-8").read()


def test_operator_block_from_a_stale_config_keeps_a_concurrent_block(tmp_path, monkeypatch):
    # Two processes load the same config, then each blocks a different skill:
    # the second write is made against the file on disk, so both stay blocked.
    from defenseclaw import config as config_module
    from defenseclaw.enforce import asset_lists

    monkeypatch.delenv("DEFENSECLAW_DEPLOYMENT_MODE", raising=False)
    monkeypatch.setenv("DEFENSECLAW_HOME", str(tmp_path))
    _config(tmp_path)
    first = config_module.load(data_dir=str(tmp_path))
    second = config_module.load(data_dir=str(tmp_path))

    for cfg, name in ((first, "evil-a"), (second, "evil-b")):
        asset_lists.write_operator_decision(cfg, op=asset_lists.OP_BLOCK, target_type="skill", name=name)

    on_disk = config_module.load(data_dir=str(tmp_path)).asset_policy.skill.denied
    assert [rule.name for rule in on_disk] == ["evil-a", "evil-b"]


def test_only_the_writer_writes_config_yaml():
    """Spec section 3 guard: config.yaml is written through config_writer
    (which takes config.yaml.lock, validates and records the generation).
    The modules listed here are that writer, its callers' shared helpers and
    the 0.x import steps, which lock and record the generation themselves."""
    import pathlib
    import re

    package = pathlib.Path(config_writer.__file__).resolve().parent
    allowed = {
        "config.py",
        "config_writer.py",
        "migrations.py",
        "observability/v8_writer.py",
        "commands/cmd_setup.py",  # setup rollback: replace_document, or a recorded exact restore
    }
    names = r"(?:config_path|cfg_path|config_file|CONFIG_PATH)"
    direct = re.compile(
        rf"open\([^)\n]*\b{names}\b[^)\n]*,\s*[\"'][wax]"
        rf"|os\.replace\([^)\n]*,\s*{names}\s*\)"
        rf"|\b\w*atomic_write\w*\(\s*{names}\b"
        rf"|\b{names}\.write_(?:text|bytes)\("
    )
    offenders = []
    for path in package.rglob("*.py"):
        rel = path.relative_to(package).as_posix()
        if rel in allowed:
            continue
        match = direct.search(path.read_text(encoding="utf-8"))
        if match:
            offenders.append(f"{rel}: {match.group(0)}")
    assert not offenders, "config.yaml written outside config_writer: " + "; ".join(offenders)
