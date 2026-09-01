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
import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

import defenseclaw.inventory.plugin_directories as plugin_directories_module
import pytest
from defenseclaw.inventory.plugin_directories import (
    PluginRegistryState,
    discover_plugin_directories,
    plugin_directory_entries,
    probe_claude_plugin_registry,
    read_amp_plugin_source,
)
from defenseclaw.inventory.plugin_identity import AmbiguousPluginIdentityError

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


def test_claude_v2_registry_discovers_exact_cached_plugin_roots(
    tmp_path: Path,
) -> None:
    root = tmp_path / ".claude" / "plugins"
    plugin = root / "cache" / "compound-market" / "compound-engineering" / "1.2.3"
    manifest = plugin / ".claude-plugin" / "plugin.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        json.dumps(
            {
                "name": "compound-engineering",
                "displayName": "Compound Engineering",
                "version": "1.2.3",
                "description": "Engineering workflows",
            }
        ),
        encoding="utf-8",
    )
    (root / "marketplaces" / "compound-market").mkdir(parents=True)
    (root / "flat-plugin").mkdir()
    (root / "installed_plugins.json").write_text(
        json.dumps(
            {
                "version": 2,
                "plugins": {
                    "@compound/engineering@compound-market": [
                        {
                            "scope": "user",
                            "installPath": str(plugin),
                            "version": "registry-fallback",
                        }
                    ]
                },
            }
        ),
        encoding="utf-8",
    )

    entries = discover_plugin_directories(str(root), connector="claudecode")

    assert [entry.id for entry in entries] == ["compound-engineering", "flat-plugin"]
    cached = entries[0]
    assert cached.path == str(plugin)
    assert cached.name == "Compound Engineering"
    assert cached.version == "1.2.3"
    assert cached.description == "Engineering workflows"
    assert cached.origin == "user:compound-market"
    assert cached.manifest == ".claude-plugin/plugin.json"
    assert cached.registry == "compound-market"
    assert cached.cached is True
    assert cached.enabled is True


def test_claude_registry_probe_reports_missing_malformed_unsupported_and_empty(
    tmp_path: Path,
) -> None:
    root = tmp_path / ".claude" / "plugins"
    root.mkdir(parents=True)
    registry = root / "installed_plugins.json"

    missing = probe_claude_plugin_registry(str(root))
    assert missing is not None
    assert missing.source_path == str(registry)
    assert missing.state is PluginRegistryState.MISSING
    assert missing.entries == 0
    assert missing.failed is False

    registry.write_text("{not-json", encoding="utf-8")
    malformed = probe_claude_plugin_registry(str(root))
    assert malformed is not None
    assert malformed.state is PluginRegistryState.MALFORMED
    assert malformed.failed is True

    registry.write_text(json.dumps({"version": 3, "plugins": {}}), encoding="utf-8")
    unsupported = probe_claude_plugin_registry(str(root))
    assert unsupported is not None
    assert unsupported.state is PluginRegistryState.UNSUPPORTED
    assert unsupported.failed is True

    registry.write_text(json.dumps({"version": 2, "plugins": {}}), encoding="utf-8")
    valid_empty = probe_claude_plugin_registry(str(root))
    assert valid_empty is not None
    assert valid_empty.state is PluginRegistryState.VALID
    assert valid_empty.entries == 0
    assert valid_empty.failed is False


def test_claude_registry_probe_reports_linked_and_unreadable_sources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    linked_root = tmp_path / "linked" / "plugins"
    linked_root.mkdir(parents=True)
    physical = tmp_path / "physical.json"
    physical.write_text(json.dumps({"version": 2, "plugins": {}}), encoding="utf-8")
    registry = linked_root / "installed_plugins.json"
    try:
        registry.symlink_to(physical)
    except OSError:
        pytest.skip("file symlinks are unavailable on this host")

    linked = probe_claude_plugin_registry(str(linked_root))
    assert linked is not None
    assert linked.source_path == str(registry)
    assert linked.state is PluginRegistryState.UNSAFE_OR_UNREADABLE
    assert linked.failed is True

    unreadable_root = tmp_path / "unreadable" / "plugins"
    unreadable_root.mkdir(parents=True)
    unreadable_registry = unreadable_root / "installed_plugins.json"
    unreadable_registry.write_text(
        json.dumps({"version": 2, "plugins": {}}),
        encoding="utf-8",
    )
    real_open = plugin_directories_module.os.open

    def deny_registry(path: str, flags: int) -> int:
        if path == str(unreadable_registry):
            raise PermissionError("denied for test")
        return real_open(path, flags)

    monkeypatch.setattr(plugin_directories_module.os, "open", deny_registry)
    unreadable = probe_claude_plugin_registry(str(unreadable_root))
    assert unreadable is not None
    assert unreadable.source_path == str(unreadable_registry)
    assert unreadable.state is PluginRegistryState.UNSAFE_OR_UNREADABLE
    assert unreadable.failed is True


def test_claude_registry_probe_reports_successful_v2_entry_count(
    tmp_path: Path,
) -> None:
    root = tmp_path / ".claude" / "plugins"
    plugin = root / "cache" / "market" / "visible-plugin" / "1.0.0"
    plugin.mkdir(parents=True)
    registry = root / "installed_plugins.json"
    registry.write_text(
        json.dumps(
            {
                "version": 2,
                "plugins": {
                    "visible-plugin@market": [
                        {"scope": "user", "installPath": str(plugin)}
                    ]
                },
            }
        ),
        encoding="utf-8",
    )

    probe = probe_claude_plugin_registry(str(root))

    assert probe is not None
    assert probe.source_path == str(registry)
    assert probe.state is PluginRegistryState.VALID
    assert probe.entries == 1
    assert probe.failed is False


def test_claude_v2_registry_uses_registry_identity_without_manifest(
    tmp_path: Path,
) -> None:
    root = tmp_path / ".claude" / "plugins"
    plugin = root / "cache" / "ponytail-market" / "ponytail" / "2026.8.1"
    plugin.mkdir(parents=True)
    (root / "installed_plugins.json").write_text(
        json.dumps(
            {
                "version": 2,
                "plugins": {
                    "ponytail@ponytail-market": [
                        {
                            "scope": "user",
                            "installPath": str(plugin),
                            "version": "2026.8.1",
                        }
                    ]
                },
            }
        ),
        encoding="utf-8",
    )

    entries = discover_plugin_directories(str(root), connector="claudecode")

    assert len(entries) == 1
    assert entries[0].id == "ponytail"
    assert entries[0].path == str(plugin)
    assert entries[0].version == "2026.8.1"
    assert entries[0].manifest == ""
    assert entries[0].cached is True


def test_claude_registry_malformed_manifest_cannot_hide_installed_plugin(
    tmp_path: Path,
) -> None:
    root = tmp_path / ".claude" / "plugins"
    plugin = root / "cache" / "market" / "visible-plugin" / "1.0.0"
    manifest = plugin / ".claude-plugin" / "plugin.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text("{not-json", encoding="utf-8")
    (root / "installed_plugins.json").write_text(
        json.dumps(
            {
                "version": 2,
                "plugins": {
                    "visible-plugin@market": [
                        {"scope": "user", "installPath": str(plugin)}
                    ]
                },
            }
        ),
        encoding="utf-8",
    )

    entries = discover_plugin_directories(str(root), connector="claudecode")

    assert [(entry.id, entry.path) for entry in entries] == [
        ("visible-plugin", str(plugin))
    ]
    assert entries[0].manifest == ""


def test_claude_registry_ignores_malformed_unsupported_and_escaping_records(
    tmp_path: Path,
) -> None:
    root = tmp_path / ".claude" / "plugins"
    outside = tmp_path / "outside-plugin"
    outside.mkdir()
    (root / "flat-plugin").mkdir(parents=True)
    cache = root / "cache"
    cache.mkdir()
    registry = root / "installed_plugins.json"

    registry.write_text("{not-json", encoding="utf-8")
    assert [
        entry.id
        for entry in discover_plugin_directories(str(root), connector="claudecode")
    ] == ["flat-plugin"]

    registry.write_text(
        json.dumps(
            {
                "version": 1,
                "plugins": {
                    "outside@market": [
                        {"scope": "user", "installPath": str(outside)}
                    ],
                    "cache-container@market": [
                        {"scope": "user", "installPath": str(cache)}
                    ],
                },
            }
        ),
        encoding="utf-8",
    )
    assert [
        entry.id
        for entry in discover_plugin_directories(str(root), connector="claudecode")
    ] == ["flat-plugin"]

    registry.write_text(
        json.dumps(
            {
                "version": 2,
                "plugins": {
                    "outside@market": [
                        {"scope": "user", "installPath": str(outside)}
                    ],
                    "cache-container@market": [
                        {"scope": "user", "installPath": str(cache)}
                    ],
                },
            }
        ),
        encoding="utf-8",
    )
    assert [
        entry.id
        for entry in discover_plugin_directories(str(root), connector="claudecode")
    ] == ["flat-plugin"]


def test_claude_registry_rejects_linked_cache_components(tmp_path: Path) -> None:
    root = tmp_path / ".claude" / "plugins"
    physical = tmp_path / "physical-cache"
    plugin = physical / "market" / "linked-plugin" / "1.0.0"
    plugin.mkdir(parents=True)
    cache = root / "cache"
    root.mkdir(parents=True)
    try:
        cache.symlink_to(physical, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable on this host")
    (root / "installed_plugins.json").write_text(
        json.dumps(
            {
                "version": 2,
                "plugins": {
                    "linked-plugin@market": [
                        {
                            "scope": "user",
                            "installPath": str(
                                cache / "market" / "linked-plugin" / "1.0.0"
                            ),
                        }
                    ]
                },
            }
        ),
        encoding="utf-8",
    )

    assert discover_plugin_directories(str(root), connector="claudecode") == []


def test_claude_registry_preserves_user_and_project_install_instances(
    tmp_path: Path,
) -> None:
    root = tmp_path / ".claude" / "plugins"
    user = root / "cache" / "market" / "duplicate" / "1.0.0"
    project_a = root / "cache" / "market" / "duplicate" / "2.0.0"
    project_b = root / "cache" / "market" / "duplicate" / "3.0.0"
    for plugin in (user, project_a, project_b):
        plugin.mkdir(parents=True)
    (root / "installed_plugins.json").write_text(
        json.dumps(
            {
                "version": 2,
                "plugins": {
                    "duplicate@market": [
                        {"scope": "user", "installPath": str(user)},
                        {
                            "scope": "project",
                            "projectPath": "/workspace/alpha",
                            "installPath": str(project_a),
                        },
                        {
                            "scope": "project",
                            "projectPath": "/workspace/beta",
                            "installPath": str(project_b),
                        },
                    ]
                },
            }
        ),
        encoding="utf-8",
    )

    entries = discover_plugin_directories(str(root), connector="claudecode")

    assert [(entry.scope, entry.project_path, entry.path) for entry in entries] == [
        ("project", "/workspace/alpha", str(project_a)),
        ("project", "/workspace/beta", str(project_b)),
        ("user", "", str(user)),
    ]
    assert all(entry.registry_source == str(root / "installed_plugins.json") for entry in entries)
    assert probe_claude_plugin_registry(str(root)).entries == 3  # type: ignore[union-attr]


def test_claude_registry_same_scope_project_identity_fails_closed(
    tmp_path: Path,
) -> None:
    root = tmp_path / ".claude" / "plugins"
    first = root / "cache" / "market" / "duplicate" / "1.0.0"
    second = root / "cache" / "market" / "duplicate" / "2.0.0"
    first.mkdir(parents=True)
    second.mkdir(parents=True)
    (root / "installed_plugins.json").write_text(
        json.dumps(
            {
                "version": 2,
                "plugins": {
                    "duplicate@market": [
                        {
                            "scope": "project",
                            "projectPath": "/workspace/alpha",
                            "installPath": str(first),
                        },
                        {
                            "scope": "project",
                            "projectPath": "/workspace/alpha/.",
                            "installPath": str(second),
                        },
                    ]
                },
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        AmbiguousPluginIdentityError,
        match="ambiguous Claude plugin identity",
    ):
        discover_plugin_directories(str(root), connector="claudecode")


def test_amp_discovers_bounded_direct_typescript_plugins_without_links(
    tmp_path: Path,
) -> None:
    root = tmp_path / "plugins"
    root.mkdir()
    defenseclaw = root / "defenseclaw.ts"
    architect = root / "architect-mode.ts"
    defenseclaw.write_text("// DefenseClaw Amp policy bridge\n", encoding="utf-8")
    architect.write_text("// @amp-agent-mode {\"key\":\"architect\",\"label\":\"architect\"}\n", encoding="utf-8")
    (root / "directory-plugin").mkdir()
    (root / "ordinary.js").write_text("export default () => {}\n", encoding="utf-8")
    oversized = root / "oversized.ts"
    oversized.write_bytes(b"x" * (plugin_directories_module._MAX_AMP_PLUGIN_BYTES + 1))
    linked = root / "linked.ts"
    try:
        linked.symlink_to(defenseclaw)
    except OSError:
        linked = None

    entries = discover_plugin_directories(str(root), connector="amp")

    assert [entry.id for entry in entries] == [
        "architect-mode",
        "defenseclaw",
        "directory-plugin",
    ]
    by_id = {entry.id: entry for entry in entries}
    assert by_id["defenseclaw"].path == str(defenseclaw)
    assert by_id["defenseclaw"].manifest == "defenseclaw.ts"
    assert read_amp_plugin_source(str(architect)).startswith("// @amp-agent-mode")
    if linked is not None:
        assert read_amp_plugin_source(str(linked)) == ""
    assert discover_plugin_directories(str(root), connector="codex") == [
        by_id["directory-plugin"],
    ]


def test_amp_file_and_directory_plugin_identity_collision_fails_closed(
    tmp_path: Path,
) -> None:
    root = tmp_path / "plugins"
    root.mkdir()
    (root / "reviewer").mkdir()
    (root / "reviewer.ts").write_text("export default () => {}\n", encoding="utf-8")

    with pytest.raises(AmbiguousPluginIdentityError):
        discover_plugin_directories(str(root), connector="amp")


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
