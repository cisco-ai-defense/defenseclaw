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

from __future__ import annotations

import json
from pathlib import Path

from defenseclaw.inventory.plugin_directories import discover_plugin_directories


def _seed_cached_plugin(
    cache: Path,
    registry: str,
    name: str,
    version: str,
) -> Path:
    root = cache / registry / name / version
    manifest = root / ".codex-plugin" / "plugin.json"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(
        json.dumps({
            "name": name,
            "version": version,
            "description": f"{name} plugin",
        }),
        encoding="utf-8",
    )
    return root


def test_codex_cache_discovers_manifests_uses_activation_and_deduplicates(
    tmp_path: Path,
) -> None:
    codex_home = tmp_path / ".codex"
    cache = codex_home / "plugins" / "cache"
    browser = _seed_cached_plugin(cache, "openai-bundled", "browser", "2.0.0")
    sites_active = _seed_cached_plugin(cache, "openai-bundled", "sites", "1.2.0")
    _seed_cached_plugin(cache, "openai-curated-remote", "sites", "9.0.0")
    github_old = _seed_cached_plugin(
        cache, "openai-curated-remote", "github", "0.1.0"
    )
    github_new = _seed_cached_plugin(
        cache, "openai-curated-remote", "github", "0.2.0"
    )
    (codex_home / "config.toml").write_text(
        "[plugins.'browser@openai-bundled']\n"
        "enabled = true\n"
        "[plugins.'sites@openai-bundled']\n"
        "enabled = true\n",
        encoding="utf-8",
    )

    entries = discover_plugin_directories(str(cache), connector="codex")
    by_id = {entry.id: entry for entry in entries}

    assert set(by_id) == {"browser", "github", "sites"}
    assert by_id["browser"].path == str(browser)
    assert by_id["browser"].enabled is True
    assert by_id["sites"].path == str(sites_active)
    assert by_id["sites"].enabled is True
    assert by_id["github"].path == str(github_new)
    assert by_id["github"].path != str(github_old)
    assert by_id["github"].enabled is False
    assert all(entry.manifest == ".codex-plugin/plugin.json" for entry in entries)
    assert "openai-bundled" not in by_id
    assert "openai-curated-remote" not in by_id


def test_regular_plugin_root_still_returns_immediate_plugins(tmp_path: Path) -> None:
    root = tmp_path / "plugins"
    (root / "real-plugin").mkdir(parents=True)
    (root / "cache").mkdir()
    (root / ".staging").mkdir()

    entries = discover_plugin_directories(str(root), connector="codex")

    assert [(entry.id, entry.path) for entry in entries] == [
        ("real-plugin", str(root / "real-plugin"))
    ]
