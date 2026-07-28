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

"""Direct coverage for shared plugin-directory filtering."""

from __future__ import annotations

import builtins
import importlib.util
import os
import sys
from pathlib import Path
from unittest.mock import patch

import defenseclaw.inventory.plugin_directories as plugin_directories_module
from defenseclaw.inventory.plugin_directories import (
    discover_plugin_directories,
    plugin_directory_entries,
)

from tests.helpers import seed_cached_plugin

try:
    import tomllib as fallback_toml_parser
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as fallback_toml_parser


def test_plugin_directory_module_falls_back_to_tomli_without_stdlib_parser(
    tmp_path: Path,
) -> None:
    module_name = "defenseclaw.inventory._plugin_directories_tomli_contract"
    spec = importlib.util.spec_from_file_location(
        module_name,
        plugin_directories_module.__file__,
    )
    assert spec is not None
    assert spec.loader is not None
    compat_module = importlib.util.module_from_spec(spec)
    original_import = builtins.__import__

    def import_without_tomllib(name, *args, **kwargs):
        if name == "tomllib":
            raise ModuleNotFoundError("stdlib TOML parser unavailable", name=name)
        return original_import(name, *args, **kwargs)

    with (
        patch.dict(
            sys.modules,
            {"tomli": fallback_toml_parser, module_name: compat_module},
        ),
        patch.object(builtins, "__import__", side_effect=import_without_tomllib),
    ):
        spec.loader.exec_module(compat_module)

    codex_home = tmp_path / ".codex"
    cache = codex_home / "plugins" / "cache"
    cache.mkdir(parents=True)
    (codex_home / "config.toml").write_text(
        "[plugins.'example@registry']\nenabled = true\n",
        encoding="utf-8",
    )

    assert compat_module.tomllib is fallback_toml_parser
    assert compat_module._codex_active_plugins(str(cache)) == {
        "example@registry": True
    }


def test_codex_cache_discovers_manifests_uses_activation_and_deduplicates(
    tmp_path: Path,
) -> None:
    codex_home = tmp_path / ".codex"
    cache = codex_home / "plugins" / "cache"
    browser = seed_cached_plugin(cache, "openai-bundled", "browser", "2.0.0")
    sites_active = seed_cached_plugin(cache, "openai-bundled", "sites", "1.2.0")
    seed_cached_plugin(cache, "openai-curated-remote", "sites", "9.0.0")
    github_old = seed_cached_plugin(
        cache, "openai-curated-remote", "github", "0.1.0"
    )
    github_new = seed_cached_plugin(
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
    assert len(entries) == 3
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


def test_plugin_directory_entries_missing_root(tmp_path: Path) -> None:
    assert plugin_directory_entries(os.fspath(tmp_path / "missing")) == []


def test_plugin_directory_entries_handles_list_error(tmp_path: Path) -> None:
    with patch(
        "defenseclaw.inventory.plugin_directories.os.listdir",
        side_effect=OSError("unreadable"),
    ):
        assert plugin_directory_entries(os.fspath(tmp_path)) == []


def test_plugin_directory_entries_filters_and_sorts(tmp_path: Path) -> None:
    for name in ("zeta", "alpha", "cache", ".hidden", "..plugin-appserver.staging-1"):
        (tmp_path / name).mkdir()
    (tmp_path / "ordinary-file").write_text(
        "not a plugin directory", encoding="utf-8"
    )

    assert plugin_directory_entries(os.fspath(tmp_path)) == [
        ("alpha", os.fspath(tmp_path / "alpha")),
        ("zeta", os.fspath(tmp_path / "zeta")),
    ]
