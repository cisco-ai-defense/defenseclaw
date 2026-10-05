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

"""Upgrades refresh unedited seeded guardrail profiles (GAP-0027)."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from defenseclaw import guardrail_profiles
from defenseclaw.config import CURRENT_CONFIG_VERSION
from defenseclaw.migrations import migrate
from defenseclaw.paths import bundled_guardrail_profiles_dir


def test_bundled_profiles_are_listed_as_stock() -> None:
    # A release that changes a profile must list its digest, or the next
    # upgrade keeps the old pack. Print them with
    # `python -m defenseclaw.guardrail_profiles`.
    bundled = bundled_guardrail_profiles_dir()
    assert bundled is not None
    for name in ("default", "strict", "permissive"):
        digest = guardrail_profiles.profile_digest(bundled / name)
        assert digest in guardrail_profiles.STOCK_PROFILE_DIGESTS[name], name


@pytest.fixture()
def seeded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A data dir whose default profile is an older stock copy."""

    monkeypatch.delenv("DEFENSECLAW_CONFIG", raising=False)
    data_dir = tmp_path / "data"
    guardrail = data_dir / "policies" / "guardrail"
    guardrail.mkdir(parents=True)
    old = guardrail / "default"
    shutil.copytree(bundled_guardrail_profiles_dir() / "default", old)
    rules = old / "rules" / "c2.yaml"
    rules.write_text(rules.read_text() + "\n# older release\n")
    stock = dict(guardrail_profiles.STOCK_PROFILE_DIGESTS)
    stock["default"] = stock["default"] | {guardrail_profiles.profile_digest(old)}
    monkeypatch.setattr(guardrail_profiles, "STOCK_PROFILE_DIGESTS", stock)
    (data_dir / "config.yaml").write_text(f"config_version: {CURRENT_CONFIG_VERSION}\n")
    return data_dir


def test_migrate_refreshes_an_unedited_older_profile(seeded: Path) -> None:
    old_digest = guardrail_profiles.profile_digest(seeded / "policies/guardrail/default")

    migrate(str(seeded))

    bundled = bundled_guardrail_profiles_dir() / "default"
    assert guardrail_profiles.profile_digest(
        seeded / "policies/guardrail/default"
    ) == guardrail_profiles.profile_digest(bundled)
    (backup,) = (seeded / "backups").glob("guardrail-profiles-*/default")
    assert guardrail_profiles.profile_digest(backup) == old_digest


def test_migrate_keeps_an_edited_profile(seeded: Path) -> None:
    rules = seeded / "policies/guardrail/default/rules/c2.yaml"
    rules.write_text(rules.read_text() + "# operator edit\n")
    edited = rules.read_bytes()

    migrate(str(seeded))

    assert rules.read_bytes() == edited
    assert not (seeded / "backups").exists()
