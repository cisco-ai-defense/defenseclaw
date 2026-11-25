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

"""Upgrades and init keep the shipped Rego modules current (GAP-0776)."""

from __future__ import annotations

from pathlib import Path

import pytest
from defenseclaw import rego_policies
from defenseclaw.config import CURRENT_CONFIG_VERSION
from defenseclaw.migrations import migrate


def test_upgrade_and_init_bring_the_shipped_rego_modules(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DEFENSECLAW_CONFIG", raising=False)
    monkeypatch.delenv("DEFENSECLAW_DEPLOYMENT_MODE", raising=False)
    shipped = {name: path.read_bytes() for name, path in rego_policies.shipped_modules().items()}
    # A release that changes a module must list its digest (print them with
    # `python -m defenseclaw.rego_policies`), or init keeps the old copy.
    for name, data in shipped.items():
        assert rego_policies.module_digest(data) in rego_policies.STOCK_REGO_DIGESTS[name], name

    data_dir = tmp_path / "data"
    rego = data_dir / "policies" / "rego"
    rego.mkdir(parents=True)
    older = shipped["admission.rego"] + b"\n# older release\n"
    edited = shipped["guardrail.rego"] + b"\n# operator edit\n"
    retired = b"package defenseclaw.sandbox\n"
    (rego / "admission.rego").write_bytes(older)
    (rego / "guardrail.rego").write_bytes(edited)
    (rego / "sandbox.rego").write_bytes(retired)
    (rego / "custom-team.rego").write_bytes(b"package defenseclaw.admission\n")
    stock = dict(rego_policies.STOCK_REGO_DIGESTS)
    stock["admission.rego"] |= {rego_policies.module_digest(older)}
    stock["sandbox.rego"] |= {rego_policies.module_digest(retired)}
    monkeypatch.setattr(rego_policies, "STOCK_REGO_DIGESTS", stock)
    (data_dir / "config.yaml").write_text(f"config_version: {CURRENT_CONFIG_VERSION}\n")

    migrate(str(data_dir))

    for name, data in shipped.items():
        assert (rego / name).read_bytes() == data, name
    (backup,) = (data_dir / "backups").glob("rego-*")
    assert (backup / "admission.rego").read_bytes() == older
    assert (backup / "guardrail.rego").read_bytes() == edited
    assert (backup / "sandbox.rego").read_bytes() == retired
    assert not (rego / "sandbox.rego").exists()
    assert (rego / "custom-team.rego").read_bytes() == b"package defenseclaw.admission\n"

    # init writes a missing module and keeps one edited for this release.
    mine = shipped["admission.rego"] + b"\n# edited for this release\n"
    (rego / "admission.rego").write_bytes(mine)
    (rego / "guardrail.rego").unlink()
    result = rego_policies.seed_rego(str(data_dir / "policies"), str(data_dir / "backups"))
    assert (result.seeded, result.kept) == (["guardrail.rego"], ["admission.rego"])
    assert (rego / "admission.rego").read_bytes() == mine
    assert (rego / "guardrail.rego").read_bytes() == shipped["guardrail.rego"]


def test_upgrade_keeps_rego_beside_external_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DEFENSECLAW_DEPLOYMENT_MODE", raising=False)
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    external = tmp_path / "team"
    rego = external / "policies" / "rego"
    rego.mkdir(parents=True)
    edited = rego_policies.shipped_modules()["admission.rego"].read_bytes() + b"\n# operator edit\n"
    module = rego / "admission.rego"
    module.write_bytes(edited)
    config_path = external / "config.yaml"
    config_path.write_text(f"config_version: {CURRENT_CONFIG_VERSION}\npolicy_dir: {external / 'policies'}\n")
    monkeypatch.setenv("DEFENSECLAW_CONFIG", str(config_path))

    migrate(str(data_dir), from_version="0.8.10")

    assert module.read_bytes() == edited
    assert not list((data_dir / "backups").glob("rego-*"))


def test_a_downgrade_needs_no_rego_step_the_older_release_replaces_every_shipped_module(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # GAP-1080: unlike the rule packs (GAP-1077), the older release's migrate
    # does not keep a Rego module it does not know. rego_policies.py is the same
    # file in 1.0.10 and 1.0.11, and its refresh_rego replaces every shipped module,
    # edited ones too, with a copy in backups/rego-*. So a downgrade ends on the
    # target's modules whatever this release seeded, and the user's edit is backed up.
    target = tmp_path / "target-1.0.10"
    target.mkdir()
    (target / "admission.rego").write_bytes(b"package defenseclaw.admission\n# 1.0.10\n")
    (target / "guardrail.rego").write_bytes(b"package defenseclaw.guardrail\n# 1.0.10\n")
    monkeypatch.setattr(rego_policies, "shipped_modules", lambda: {p.name: p for p in sorted(target.iterdir())})
    policy_dir = tmp_path / "policies"
    rego = policy_dir / "rego"
    rego.mkdir(parents=True)
    unedited = b"package defenseclaw.admission\n# 1.0.11\n"
    edited = b"package defenseclaw.guardrail\n# 1.0.11\n# mine\n"
    (rego / "admission.rego").write_bytes(unedited)
    (rego / "guardrail.rego").write_bytes(edited)
    (rego / "custom-team.rego").write_bytes(b"package team\n")
    stock = dict(rego_policies.STOCK_REGO_DIGESTS)
    stock["admission.rego"] = stock["admission.rego"] | {rego_policies.module_digest(unedited)}
    monkeypatch.setattr(rego_policies, "STOCK_REGO_DIGESTS", stock)

    result = rego_policies.refresh_rego(str(policy_dir), str(tmp_path / "backups"))

    assert (result.refreshed, result.replaced_edited) == (["admission.rego"], ["guardrail.rego"])
    assert (rego / "admission.rego").read_bytes() == (target / "admission.rego").read_bytes()
    assert (rego / "guardrail.rego").read_bytes() == (target / "guardrail.rego").read_bytes()
    assert (Path(result.backup_dir) / "guardrail.rego").read_bytes() == edited
    assert (rego / "custom-team.rego").read_bytes() == b"package team\n"
