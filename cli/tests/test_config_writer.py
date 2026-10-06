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
    # The writer names every key the running gateway applies only on restart.
    assert config_writer.restart_required(
        ["guardrail.hook_fail_mode", "guardrail.connectors.codex.enabled", "guardrail.block_at", "gateway.watcher.enabled"]
    ) == ["guardrail.hook_fail_mode", "guardrail.connectors.codex.enabled"]


def test_writer_refuses_local_actors_on_a_standalone_managed_device(tmp_path, monkeypatch):
    path = _config(tmp_path)
    monkeypatch.setenv("DEFENSECLAW_DEPLOYMENT_MODE", "managed_enterprise")
    monkeypatch.setenv("DEFENSECLAW_ENTERPRISE_PROFILE", "standalone")
    with pytest.raises(config_writer.ManagedConfigWriteError):
        config_writer.apply([Change("guardrail.mode", "action")], "cli:test", "t", path=path)
    with pytest.raises(FileNotFoundError):
        config_writer.read_generation_state(path)


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
