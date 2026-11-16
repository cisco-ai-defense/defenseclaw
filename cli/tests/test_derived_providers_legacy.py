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

"""GAP-0163: the derived custom-providers.json never replaces a legacy
overlay that holds what llm_providers in config.yaml does not."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from defenseclaw import derived_providers
from defenseclaw.config import Config, _merge_llm_providers

_CONFIG_ACME = {
    "name": "acme-gw",
    "domains": ["b11-acme.example.test"],
    "env_keys": ["B11_ACME_DUMMY_KEY"],
    "base_url": "https://b11-acme.example.test/v1",
    "request_path_overrides": {"chat": "/acme/chat"},
    "extra_headers": {"X-B11-Config": "dummy-config"},
}


def _cfg(tmp_path: Path) -> Config:
    cfg = Config()
    cfg.data_dir = str(tmp_path)
    cfg.llm_providers = _merge_llm_providers({"custom": [_CONFIG_ACME], "ollama_ports": [11434]})
    return cfg


@pytest.mark.parametrize(
    "legacy",
    [
        {"providers": [{"name": "acme-gw", "domains": ["b11-acme-alt.example.test"]}]},
        {"providers": [{"name": "acme-gw", "base_url": "https://b11-acme-legacy.example.test/v1"}]},
        {"providers": [{"name": "acme-gw", "extra_headers": {"X-B11-Config": "dummy-legacy-wins"}}]},
        {"providers": [{"name": "acme-gw", "request_path_overrides": {"legacy": "/legacy/only"}}]},
        {"providers": [{"name": "other-gw", "domains": ["other.example.test"]}]},
        {"providers": [], "ollama_ports": [11500]},
    ],
)
def test_write_keeps_a_legacy_overlay_config_does_not_hold(tmp_path: Path, legacy: dict) -> None:
    cfg = _cfg(tmp_path)
    path = tmp_path / "custom-providers.json"
    path.write_text(json.dumps(legacy), encoding="utf-8")
    before = path.read_bytes()

    derived_providers.write(cfg, str(path))

    assert path.read_bytes() == before
    assert derived_providers.overlay_state(cfg, str(path))[0] == derived_providers.STATE_LEGACY


@pytest.mark.parametrize("absorbed", [True, False])
def test_write_replaces_a_legacy_overlay_config_already_holds(tmp_path: Path, absorbed: bool) -> None:
    cfg = _cfg(tmp_path)
    path = tmp_path / "custom-providers.json"
    legacy = {
        "providers": [
            {"name": "ACME-GW", "domains": ["b11-acme.example.test"], "extra_headers": {"X-B11-Config": "dummy-config"}}
        ],
        "ollama_ports": [11434],
    }
    if absorbed:
        # Seeded into llm_providers by an edit command: the save replaces it.
        legacy["providers"].append({"name": "removed-gw", "domains": ["removed.example.test"]})
    path.write_text(json.dumps(legacy), encoding="utf-8")

    derived_providers.write(cfg, str(path), absorbed=absorbed)

    assert derived_providers.overlay_state(cfg, str(path))[0] == derived_providers.STATE_FRESH
