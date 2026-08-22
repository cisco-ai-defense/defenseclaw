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
from types import SimpleNamespace
from unittest.mock import patch

import defenseclaw.inventory.plugin_directories as plugin_directories_module
import pytest
from defenseclaw.inventory.plugin_directories import (
    discover_exact_plugin_directory,
    discover_plugin_directories,
    plugin_directory_entries,
    read_amp_plugin_source,
)
from defenseclaw.inventory.plugin_identity import AmbiguousPluginIdentityError

from tests.environment import requires_symlink_privilege
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


def test_codex_stable_reader_rejects_named_replacement(
    tmp_path: Path,
    monkeypatch,
) -> None:
    original = tmp_path / "plugin.json"
    replacement = tmp_path / "replacement.json"
    original.write_text('{"name":"original"}', encoding="utf-8")
    replacement.write_text('{"name":"replacement"}', encoding="utf-8")
    original_stat = os.stat

    def swapped_named_stat(path, *args, **kwargs):
        if (
            os.path.abspath(os.fspath(path)) == os.path.abspath(os.fspath(original))
            and kwargs.get("follow_symlinks") is False
        ):
            return original_stat(replacement, follow_symlinks=False)
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(
        plugin_directories_module,
        "open_regular_file_no_follow",
        lambda path: os.open(
            path,
            os.O_RDONLY | getattr(os, "O_BINARY", 0),
        ),
    )
    monkeypatch.setattr(
        plugin_directories_module,
        "reject_reparse_path",
        lambda _path: None,
    )
    monkeypatch.setattr(plugin_directories_module.os, "stat", swapped_named_stat)

    with pytest.raises(OSError, match="replaced"):
        plugin_directories_module._read_bounded_stable_file(
            str(original),
            max_bytes=1024,
        )


def test_codex_stable_directory_rejects_content_mutation(
    tmp_path: Path,
    monkeypatch,
) -> None:
    directory = tmp_path / "cache"
    directory.mkdir()
    original_stat = os.stat
    before = original_stat(directory, follow_symlinks=False)
    after = SimpleNamespace(
        st_mode=before.st_mode,
        st_dev=before.st_dev,
        st_ino=before.st_ino,
        st_size=before.st_size,
        st_mtime_ns=before.st_mtime_ns + 1,
        st_ctime_ns=before.st_ctime_ns,
        st_file_attributes=getattr(before, "st_file_attributes", 0),
    )
    observations = iter((before, after))

    monkeypatch.setattr(
        plugin_directories_module,
        "reject_reparse_path",
        lambda _path: None,
    )
    monkeypatch.setattr(
        plugin_directories_module.os,
        "stat",
        lambda *_args, **_kwargs: next(observations),
    )

    with pytest.raises(OSError, match="changed"):
        plugin_directories_module._stable_directory_info(str(directory))


def test_codex_stable_directory_accepts_nonportable_size(
    tmp_path: Path,
    monkeypatch,
) -> None:
    directory = tmp_path / "cache"
    directory.mkdir()
    original_stat = os.stat
    before = original_stat(directory, follow_symlinks=False)
    after = SimpleNamespace(
        st_mode=before.st_mode,
        st_dev=before.st_dev,
        st_ino=before.st_ino,
        st_size=before.st_size + 4096,
        st_mtime_ns=before.st_mtime_ns,
        st_ctime_ns=before.st_ctime_ns,
        st_file_attributes=getattr(before, "st_file_attributes", 0),
    )
    observations = iter((before, after))

    monkeypatch.setattr(
        plugin_directories_module,
        "reject_reparse_path",
        lambda _path: None,
    )
    monkeypatch.setattr(
        plugin_directories_module.os,
        "stat",
        lambda *_args, **_kwargs: next(observations),
    )

    assert plugin_directories_module._stable_directory_info(str(directory)) is after


def test_codex_cache_accepts_missing_windows_direntry_identity(
    tmp_path: Path,
    monkeypatch,
) -> None:
    codex_home = tmp_path / ".codex"
    cache = codex_home / "plugins" / "cache"
    plugin = seed_cached_plugin(
        cache,
        "openai-bundled",
        "browser",
        "1.0.0",
    )
    (codex_home / "config.toml").write_text(
        "[plugins.'browser@openai-bundled']\nenabled = true\n",
        encoding="utf-8",
    )
    real_scandir = os.scandir

    class ZeroIdentityEntry:
        def __init__(self, entry):
            self._entry = entry
            self.name = entry.name
            self.path = entry.path

        def is_symlink(self):
            return self._entry.is_symlink()

        def stat(self, *, follow_symlinks=True):
            info = os.stat(
                self.path,
                follow_symlinks=follow_symlinks,
            )
            return SimpleNamespace(
                st_mode=info.st_mode,
                st_dev=0,
                st_ino=0,
                # Windows DirEntry.stat() can report zero for directory size
                # even when a named os.stat() exposes its allocation size.
                st_size=0,
                st_mtime_ns=info.st_mtime_ns,
                st_ctime_ns=info.st_ctime_ns,
                st_file_attributes=getattr(info, "st_file_attributes", 0),
            )

    class ZeroIdentityScandir:
        def __init__(self, path):
            with real_scandir(path) as iterator:
                self._entries = [
                    ZeroIdentityEntry(entry)
                    for entry in iterator
                ]

        def __enter__(self):
            return iter(self._entries)

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(
        plugin_directories_module.os,
        "scandir",
        ZeroIdentityScandir,
    )

    entries = discover_plugin_directories(str(cache), connector="codex")

    assert [(entry.id, entry.path, entry.enabled) for entry in entries] == [
        ("browser", str(plugin), True),
    ]


def test_codex_cache_uses_named_snapshot_when_entry_identity_is_unavailable(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "registry"
    directory.mkdir()
    named = os.stat(directory, follow_symlinks=False)
    enumerated = SimpleNamespace(
        st_mode=named.st_mode,
        st_dev=0,
        st_ino=0,
        st_size=named.st_size,
        st_mtime_ns=named.st_mtime_ns + 1,
        st_ctime_ns=named.st_ctime_ns,
        st_file_attributes=getattr(named, "st_file_attributes", 0),
    )

    assert plugin_directories_module._directory_entry_matches(
        enumerated,
        named,
    )


def test_codex_cache_rejects_identified_entry_with_mutated_metadata(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "registry"
    directory.mkdir()
    observed = os.stat(directory, follow_symlinks=False)
    named = SimpleNamespace(
        st_mode=observed.st_mode,
        st_dev=observed.st_dev or 1,
        st_ino=observed.st_ino or 1,
        st_size=observed.st_size,
        st_mtime_ns=observed.st_mtime_ns,
        st_ctime_ns=observed.st_ctime_ns,
        st_file_attributes=getattr(observed, "st_file_attributes", 0),
    )
    enumerated = SimpleNamespace(
        st_mode=named.st_mode,
        st_dev=named.st_dev,
        st_ino=named.st_ino,
        st_size=named.st_size,
        st_mtime_ns=named.st_mtime_ns + 1,
        st_ctime_ns=named.st_ctime_ns,
        st_file_attributes=getattr(named, "st_file_attributes", 0),
    )

    assert not plugin_directories_module._directory_entry_matches(
        enumerated,
        named,
    )


def test_codex_cache_accepts_nonportable_directory_size_with_identity(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "registry"
    directory.mkdir()
    named = os.stat(directory, follow_symlinks=False)
    enumerated = SimpleNamespace(
        st_mode=named.st_mode,
        st_dev=named.st_dev,
        st_ino=named.st_ino,
        st_size=named.st_size + 4096,
        st_mtime_ns=named.st_mtime_ns,
        st_ctime_ns=named.st_ctime_ns,
        st_file_attributes=getattr(named, "st_file_attributes", 0),
    )

    assert plugin_directories_module._directory_entry_matches(
        enumerated,
        named,
    )


@requires_symlink_privilege
def test_codex_cache_rejects_reparse_ancestor(tmp_path: Path) -> None:
    actual_home = tmp_path / "actual-codex-home"
    cache = actual_home / "plugins" / "cache"
    seed_cached_plugin(cache, "openai-bundled", "browser", "1.0.0")
    linked_home = tmp_path / ".codex"
    linked_home.symlink_to(actual_home, target_is_directory=True)

    assert discover_plugin_directories(
        str(linked_home / "plugins" / "cache"),
        connector="codex",
    ) == []


@requires_symlink_privilege
def test_codex_cache_rejects_reparse_manifest_ancestor(tmp_path: Path) -> None:
    cache = tmp_path / ".codex" / "plugins" / "cache"
    plugin = cache / "openai-bundled" / "browser" / "1.0.0"
    plugin.mkdir(parents=True)
    outside_manifest = tmp_path / "outside-manifest"
    outside_manifest.mkdir()
    (outside_manifest / "plugin.json").write_text(
        '{"name":"redirected","version":"9.9.9"}',
        encoding="utf-8",
    )
    (plugin / ".codex-plugin").symlink_to(
        outside_manifest,
        target_is_directory=True,
    )

    assert discover_plugin_directories(str(cache), connector="codex") == []


@requires_symlink_privilege
def test_codex_exact_marketplace_plugin_rejects_reparse_ancestor(
    tmp_path: Path,
) -> None:
    actual_root = tmp_path / "actual-marketplace"
    plugin = actual_root / "browser"
    manifest = plugin / ".codex-plugin" / "plugin.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text('{"name":"browser","version":"1.0.0"}', encoding="utf-8")
    linked_root = tmp_path / "linked-marketplace"
    linked_root.symlink_to(actual_root, target_is_directory=True)

    assert discover_exact_plugin_directory(
        str(linked_root / "browser"),
        origin="codex marketplace",
    ) == []


def test_regular_plugin_root_still_returns_immediate_plugins(tmp_path: Path) -> None:
    root = tmp_path / "plugins"
    (root / "real-plugin").mkdir(parents=True)
    (root / "cache").mkdir()
    (root / ".staging").mkdir()

    entries = discover_plugin_directories(str(root), connector="codex")

    assert [(entry.id, entry.path) for entry in entries] == [
        ("real-plugin", str(root / "real-plugin"))
    ]


def test_claude_cache_discovers_versions_and_resolves_scoped_enablement(
    tmp_path: Path,
    monkeypatch,
) -> None:
    claude_home = tmp_path / ".claude"
    cache = claude_home / "plugins" / "cache"
    old = cache / "team-tools" / "formatter" / "1.0.0"
    current = cache / "team-tools" / "formatter" / "2.0.0"
    disabled = cache / "team-tools" / "analyzer" / "1.0.0"
    for path, name, version, default_enabled in (
        (old, "formatter", "1.0.0", True),
        (current, "formatter", "2.0.0", True),
        (disabled, "analyzer", "1.0.0", True),
    ):
        manifest = path / ".claude-plugin" / "plugin.json"
        manifest.parent.mkdir(parents=True)
        manifest.write_text(
            json.dumps(
                {
                    "name": name,
                    "version": version,
                    "defaultEnabled": default_enabled,
                }
            ),
            encoding="utf-8",
        )
    workspace = tmp_path / "workspace"
    (workspace / ".claude").mkdir(parents=True)
    claude_home.mkdir(exist_ok=True)
    (claude_home / "settings.json").write_text(
        json.dumps(
            {
                "enabledPlugins": {
                    "formatter@team-tools": False,
                    "analyzer@team-tools": True,
                }
            }
        ),
        encoding="utf-8",
    )
    (workspace / ".claude" / "settings.json").write_text(
        json.dumps(
            {
                "enabledPlugins": {
                    "formatter@team-tools": True,
                }
            }
        ),
        encoding="utf-8",
    )
    (workspace / ".claude" / "settings.local.json").write_text(
        json.dumps(
            {
                "enabledPlugins": {
                    "analyzer@team-tools": False,
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(claude_home))

    entries = discover_plugin_directories(
        str(cache),
        connector="claudecode",
        workspace_dir=str(workspace),
        claude_managed_settings_paths=(),
    )
    by_id = {entry.id: entry for entry in entries}
    assert set(by_id) == {
        "analyzer@team-tools",
        "formatter@team-tools#1.0.0",
        "formatter@team-tools#2.0.0",
    }
    assert by_id["formatter@team-tools#1.0.0"].path == str(old)
    assert by_id["formatter@team-tools#2.0.0"].path == str(current)
    # Two cache versions are ambiguous because Claude retains orphaned copies
    # after update/uninstall. Filesystem-only discovery must not call either
    # copy active.
    assert all(
        not entry.enabled
        and not entry.activation_verified
        and entry.logical_id == "formatter@team-tools"
        for entry in entries
        if entry.id.startswith("formatter@team-tools#")
    )
    assert by_id["analyzer@team-tools"].enabled is False
    assert by_id["analyzer@team-tools"].activation_verified is True
    assert all(entry.manifest == ".claude-plugin/plugin.json" for entry in entries)


def test_claude_cache_accepts_optional_manifest_but_requires_explicit_enablement(
    tmp_path: Path,
    monkeypatch,
) -> None:
    claude_home = tmp_path / ".claude"
    cache = claude_home / "plugins" / "cache"
    plugin = cache / "official" / "manifestless" / "sha-123"
    plugin.mkdir(parents=True)
    (plugin / "skills").mkdir()
    claude_home.mkdir(exist_ok=True)
    (claude_home / "settings.json").write_text(
        json.dumps({"enabledPlugins": {"manifestless@official": True}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(claude_home))

    entries = discover_plugin_directories(
        str(cache),
        connector="claudecode",
        claude_managed_settings_paths=(),
    )

    assert len(entries) == 1
    assert entries[0].id == "manifestless@official"
    assert entries[0].path == str(plugin)
    assert entries[0].manifest == ""
    assert entries[0].enabled is True
    assert entries[0].activation_verified is True


def test_claude_skills_root_classifies_only_manifest_plugins(
    tmp_path: Path,
    monkeypatch,
) -> None:
    claude_home = tmp_path / ".claude"
    skills = claude_home / "skills"
    plain = skills / "plain-skill"
    plain.mkdir(parents=True)
    (plain / "SKILL.md").write_text("# Plain\n", encoding="utf-8")
    plugin = skills / "release-tools"
    manifest = plugin / ".claude-plugin" / "plugin.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        json.dumps(
            {
                "name": "release-tools",
                "version": "3.2.1",
                "defaultEnabled": False,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(claude_home))

    entries = discover_plugin_directories(
        str(skills),
        connector="claudecode",
        claude_managed_settings_paths=(),
    )
    assert len(entries) == 1
    assert entries[0].id == "release-tools@skills-dir"
    assert entries[0].path == str(plugin)
    assert entries[0].enabled is False
    assert entries[0].registry == "skills-dir"


def test_claude_managed_plugin_state_overrides_local_and_policy_helper_is_unverified(
    tmp_path: Path,
    monkeypatch,
) -> None:
    claude_home = tmp_path / ".claude"
    cache = claude_home / "plugins" / "cache"
    plugin = cache / "official" / "guard" / "1.0.0"
    plugin.mkdir(parents=True)
    claude_home.mkdir(exist_ok=True)
    (claude_home / "settings.json").write_text(
        json.dumps({"enabledPlugins": {"guard@official": True}}),
        encoding="utf-8",
    )
    managed = tmp_path / "managed-settings.json"
    managed.write_text(
        json.dumps({"enabledPlugins": {"guard@official": False}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(claude_home))

    entries = discover_plugin_directories(
        str(cache),
        connector="claudecode",
        claude_managed_settings_paths=(str(managed),),
    )
    assert len(entries) == 1
    assert entries[0].enabled is False
    assert entries[0].activation_verified is True

    managed.write_text(
        json.dumps(
            {
                "policyHelper": {"path": r"C:\Program Files\Corp\policy.exe"},
                "enabledPlugins": {"guard@official": True},
            }
        ),
        encoding="utf-8",
    )
    entries = discover_plugin_directories(
        str(cache),
        connector="claudecode",
        claude_managed_settings_paths=(str(managed),),
    )
    assert len(entries) == 1
    assert entries[0].enabled is False
    assert entries[0].activation_verified is False


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
