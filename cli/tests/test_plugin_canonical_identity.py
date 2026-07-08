"""Regression coverage for WIN-AUD-022 canonical plugin identity."""

from __future__ import annotations

import json
import os
import stat
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from click.testing import CliRunner
from defenseclaw.commands.cmd_plugin import _PluginInstallTransaction, plugin
from defenseclaw.enforce import PolicyEngine
from defenseclaw.inventory.plugin_identity import (
    AmbiguousPluginIdentityError,
    PluginIdentityError,
    canonical_plugin_id,
    filesystem_identity_key,
    is_link_or_reparse,
    resolve_plugin_identity,
    validate_plugin_id,
)
from defenseclaw.models import Finding, ScanResult

from tests.helpers import cleanup_app, make_app_context


def _plugin(path: str, plugin_id: str, content: str = "new") -> str:
    os.makedirs(path, exist_ok=True)
    with open(os.path.join(path, "plugin.json"), "w", encoding="utf-8") as handle:
        json.dump({"id": plugin_id}, handle)
    with open(os.path.join(path, "payload.txt"), "w", encoding="utf-8") as handle:
        handle.write(content)
    return path


def _clean_result() -> ScanResult:
    return ScanResult(
        scanner="plugin-scanner",
        target="scan-target",
        timestamp=datetime.now(timezone.utc),
        findings=[],
        duration=timedelta(milliseconds=1),
    )


def _critical_result() -> ScanResult:
    return ScanResult(
        scanner="plugin-scanner",
        target="scan-target",
        timestamp=datetime.now(timezone.utc),
        findings=[
            Finding(
                id="critical-test",
                severity="CRITICAL",
                title="critical test finding",
                description="test",
                scanner="plugin-scanner",
            )
        ],
        duration=timedelta(milliseconds=1),
    )


@pytest.fixture
def app_context():
    app, tmp, database = make_app_context()
    app.cfg.plugin_dir = os.path.join(tmp, "legacy")
    root = os.path.join(tmp, "connector-plugins")
    os.makedirs(root)
    app.cfg.plugin_dirs = lambda connector=None: [root]  # type: ignore[method-assign]
    app.cfg.active_connectors = lambda: ["openclaw"]  # type: ignore[method-assign]
    try:
        yield app, tmp, root
    finally:
        cleanup_app(app, database, tmp)


def test_exact_duplicate_reproduction_is_non_mutating_without_force(app_context):
    app, tmp, root = app_context
    existing = _plugin(os.path.join(root, "clean-plugin"), "clean-plugin", "old")
    source = _plugin(os.path.join(tmp, "clean plugin"), "clean-plugin", "new")

    result = CliRunner().invoke(plugin, ["install", source], obj=app)

    assert result.exit_code != 0
    assert "already exists" in result.output
    assert open(os.path.join(existing, "payload.txt"), encoding="utf-8").read() == "old"
    assert os.path.isdir(source)
    assert sorted(os.listdir(root)) == ["clean-plugin"]


def test_install_rejects_source_without_supported_manifest(app_context):
    app, tmp, root = app_context
    source = os.path.join(tmp, "manifestless source")
    os.makedirs(source)
    with open(os.path.join(source, "plugin.py"), "w", encoding="utf-8") as handle:
        handle.write("# no manifest\n")

    result = CliRunner().invoke(plugin, ["install", source], obj=app)

    assert result.exit_code != 0
    assert "does not contain a supported manifest" in result.output
    assert os.listdir(root) == []


@patch("defenseclaw.scanner.plugin.PluginScannerWrapper.scan", return_value=_clean_result())
def test_space_containing_local_source_installs_by_manifest_id(_scan, app_context):
    app, tmp, root = app_context
    source = _plugin(os.path.join(tmp, "source folder with spaces"), "space-safe-id")

    result = CliRunner().invoke(plugin, ["install", source], obj=app)

    assert result.exit_code == 0, result.output
    assert os.path.isdir(os.path.join(root, "space-safe-id"))
    assert os.path.isdir(source)


@patch("defenseclaw.scanner.plugin.PluginScannerWrapper.scan", return_value=_clean_result())
def test_force_converges_alias_to_one_canonical_directory(_scan, app_context):
    app, tmp, root = app_context
    _plugin(os.path.join(root, "old alias"), "clean-plugin", "old")
    source = _plugin(os.path.join(tmp, "clean plugin"), "clean-plugin", "new")
    _scan.return_value.target = os.path.join(root, "clean-plugin")

    result = CliRunner().invoke(plugin, ["install", "--force", source], obj=app)

    assert result.exit_code == 0, result.output
    assert sorted(os.listdir(root)) == ["clean-plugin"]
    assert open(os.path.join(root, "clean-plugin", "payload.txt"), encoding="utf-8").read() == "new"
    assert os.path.isdir(source)
    entry = app.store.get_action("plugin", "clean-plugin", "openclaw")
    assert entry is not None
    assert entry.source_path == os.path.join(root, "clean-plugin")
    scans = app.store.latest_scans_by_scanner("plugin-scanner")
    assert scans[0]["target"] == os.path.join(root, "clean-plugin")


@patch("defenseclaw.scanner.plugin.PluginScannerWrapper.scan", return_value=_clean_result())
@patch("defenseclaw.registry.fetch_npm_package")
def test_fetched_source_identity_is_read_after_materialization(fetch, _scan, app_context):
    app, tmp, root = app_context
    fetch.return_value = _plugin(os.path.join(tmp, "package-cache-name"), "manifest-name")

    result = CliRunner().invoke(plugin, ["install", "untrusted-package-hint"], obj=app)

    assert result.exit_code == 0, result.output
    assert os.path.isdir(os.path.join(root, "manifest-name"))
    assert not os.path.exists(os.path.join(root, "untrusted-package-hint"))


def test_transaction_preflights_all_connectors_and_rolls_back_exact_layout(tmp_path):
    source = _plugin(str(tmp_path / "source"), "shared", "new")
    first = tmp_path / "first"
    second = tmp_path / "second"
    _plugin(str(first / "alias-one"), "shared", "first-old")
    _plugin(str(second / "alias-two"), "shared", "second-old")

    tx = _PluginInstallTransaction.prepare(source, [("one", str(first)), ("two", str(second))], "shared", force=True)
    installed = tx.commit()
    assert set(installed) == {"one", "two"}
    tx.rollback()

    assert (first / "alias-one" / "payload.txt").read_text() == "first-old"
    assert (second / "alias-two" / "payload.txt").read_text() == "second-old"
    assert not (first / "shared").exists()
    assert not (second / "shared").exists()


def test_multi_connector_collision_preflight_has_no_partial_mutation(tmp_path):
    source = _plugin(str(tmp_path / "source"), "shared")
    untouched_root = tmp_path / "not-created"
    colliding_root = tmp_path / "collision"
    _plugin(str(colliding_root / "alias"), "shared", "old")

    with pytest.raises(PluginIdentityError, match="already exists"):
        _PluginInstallTransaction.prepare(
            source,
            [("first", str(untouched_root)), ("second", str(colliding_root))],
            "shared",
            force=False,
        )

    assert not untouched_root.exists()
    assert (colliding_root / "alias" / "payload.txt").read_text() == "old"


@patch("defenseclaw.scanner.plugin.PluginScannerWrapper.scan")
def test_multi_connector_scan_failure_restores_all_replacements(scan, app_context):
    app, tmp, first = app_context
    second = os.path.join(tmp, "second-root")
    os.makedirs(second)
    app.cfg.active_connectors = lambda: ["one", "two"]  # type: ignore[method-assign]
    app.cfg.plugin_dirs = lambda connector=None: [first if connector == "one" else second]  # type: ignore[method-assign]
    _plugin(os.path.join(first, "old-one"), "shared", "first-old")
    _plugin(os.path.join(second, "old-two"), "shared", "second-old")
    source = _plugin(os.path.join(tmp, "new source"), "shared", "new")
    scan.side_effect = [_clean_result(), RuntimeError("second scan failed")]

    result = CliRunner().invoke(plugin, ["install", "--force", source], obj=app)

    assert result.exit_code != 0
    assert "second scan failed" in result.output
    assert open(os.path.join(first, "old-one", "payload.txt"), encoding="utf-8").read() == "first-old"
    assert open(os.path.join(second, "old-two", "payload.txt"), encoding="utf-8").read() == "second-old"
    assert sorted(os.listdir(first)) == ["old-one"]
    assert sorted(os.listdir(second)) == ["old-two"]
    assert app.store.latest_scans_by_scanner("plugin-scanner") == []


@patch("defenseclaw.scanner.plugin.PluginScannerWrapper.scan")
def test_multi_connector_action_uses_canonical_identity_everywhere(scan, app_context):
    app, tmp, first = app_context
    second = os.path.join(tmp, "second-root")
    os.makedirs(second)
    app.cfg.active_connectors = lambda: ["one", "two"]  # type: ignore[method-assign]
    app.cfg.plugin_dirs = lambda connector=None: [first if connector == "one" else second]  # type: ignore[method-assign]
    _plugin(os.path.join(first, "old-one"), "shared", "first-old")
    _plugin(os.path.join(second, "old-two"), "shared", "second-old")
    source = _plugin(os.path.join(tmp, "new source"), "shared", "new")
    scan.side_effect = [_critical_result(), _critical_result()]

    result = CliRunner().invoke(plugin, ["install", "--force", "--action", source], obj=app)

    assert result.exit_code != 0
    assert os.path.isdir(source)
    for connector, root in (("one", first), ("two", second)):
        assert os.listdir(root) == []
        quarantine_path = os.path.join(app.cfg.quarantine_dir, "plugins", connector, "shared")
        assert os.path.isfile(os.path.join(quarantine_path, "payload.txt"))
        entry = app.store.get_action("plugin", "shared", connector)
        assert entry is not None
        assert entry.actions.file == "quarantine"
        assert entry.source_path == os.path.join(root, "shared")


@pytest.mark.parametrize(
    "value",
    [
        "",
        ".",
        "..",
        "../escape",
        "a/b",
        "a\\b",
        "C:\\escape",
        "NUL",
        "name.",
        "unsafe?name",
        "unsafe*name",
        "unsafe|name",
        "bad\x00id",
        "bad\x1fid",
    ],
)
def test_manifest_id_rejects_traversal_control_and_reserved_forms(value):
    with pytest.raises(PluginIdentityError):
        validate_plugin_id(value)


@pytest.mark.parametrize("value", ["clean-plugin", "vendor.plugin", "plugin_name", "Plugin-2"])
def test_manifest_id_preserves_supported_ids(value):
    assert validate_plugin_id(value) == value


def test_ambiguous_aliases_fail_closed(tmp_path):
    root = tmp_path / "plugins"
    _plugin(str(root / "first"), "same-id")
    _plugin(str(root / "second"), "same-id")
    with pytest.raises(AmbiguousPluginIdentityError, match="remove or rename"):
        resolve_plugin_identity(str(root), "same-id")


@pytest.mark.parametrize(
    "arguments",
    [
        ["list", "--connector", "codex"],
        ["info", "same-id", "--connector", "codex"],
        ["scan", "same-id", "--connector", "codex"],
        ["quarantine", "same-id", "--connector", "codex"],
        ["remove", "same-id", "--connector", "codex"],
        ["disable", "same-id", "--connector", "codex"],
        ["enable", "same-id", "--connector", "codex"],
        ["block", "same-id", "--connector", "codex"],
        ["allow", "same-id", "--connector", "codex"],
    ],
)
@patch("defenseclaw.commands.cmd_plugin._list_openclaw_plugins", return_value=[])
def test_lifecycle_commands_fail_closed_on_ambiguous_identity(_openclaw, arguments, app_context):
    app, _tmp, root = app_context
    app.cfg.active_connectors = lambda: ["codex"]  # type: ignore[method-assign]
    _plugin(os.path.join(root, "first-alias"), "same-id", "first")
    _plugin(os.path.join(root, "second-alias"), "same-id", "second")

    result = CliRunner().invoke(plugin, arguments, obj=app)

    assert result.exit_code != 0
    assert "ambiguous plugin identity" in result.output
    assert "remove or rename duplicate directories" in result.output
    assert os.path.isdir(os.path.join(root, "first-alias"))
    assert os.path.isdir(os.path.join(root, "second-alias"))


def test_restore_fails_closed_when_active_identity_is_ambiguous(app_context):
    app, _tmp, root = app_context
    app.cfg.active_connectors = lambda: ["codex"]  # type: ignore[method-assign]
    _plugin(os.path.join(root, "first-alias"), "same-id", "first")
    _plugin(os.path.join(root, "second-alias"), "same-id", "second")
    quarantine_copy = os.path.join(app.cfg.quarantine_dir, "plugins", "codex", "same-id")
    _plugin(quarantine_copy, "same-id", "quarantined")
    pe = PolicyEngine(app.store)
    pe.quarantine_for_connector("plugin", "same-id", "codex", "test")
    pe.set_source_path("plugin", "same-id", os.path.join(root, "first-alias"), "codex")

    result = CliRunner().invoke(plugin, ["restore", "same-id", "--connector", "codex"], obj=app)

    assert result.exit_code != 0
    assert "ambiguous plugin identity" in result.output
    assert os.path.isdir(quarantine_copy)


def test_case_collision_matches_host_filesystem_semantics(tmp_path):
    probe = tmp_path / "CaseProbe"
    probe.mkdir()
    filesystem_is_insensitive = (tmp_path / "caseprobe").exists()
    upper = filesystem_identity_key("Plugin", str(tmp_path))
    lower = filesystem_identity_key("plugin", str(tmp_path))
    assert (upper == lower) is filesystem_is_insensitive


def test_install_case_collision_follows_target_filesystem_semantics(tmp_path):
    root = tmp_path / "plugins"
    _plugin(str(root / "existing"), "Plugin", "old")
    source = _plugin(str(tmp_path / "source"), "plugin", "new")
    if filesystem_identity_key("Plugin", str(root)) == filesystem_identity_key("plugin", str(root)):
        with pytest.raises(PluginIdentityError, match="already exists"):
            _PluginInstallTransaction.prepare(source, [("test", str(root))], "plugin", force=False)
    else:
        tx = _PluginInstallTransaction.prepare(source, [("test", str(root))], "plugin", force=False)
        tx.commit()
        tx.finalize()
        assert sorted(path.name for path in root.iterdir()) == ["existing", "plugin"]


def test_source_tree_link_is_rejected_without_target_mutation(tmp_path):
    source = _plugin(str(tmp_path / "source"), "linked")
    outside = tmp_path / "outside.txt"
    outside.write_text("outside")
    try:
        os.symlink(outside, os.path.join(source, "linked.txt"))
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation unavailable")
    root = tmp_path / "plugins"

    with pytest.raises(PluginIdentityError, match="linked entry"):
        _PluginInstallTransaction.prepare(source, [("openclaw", str(root))], "linked", force=False)

    assert outside.read_text() == "outside"
    assert not root.exists()


def test_transaction_revalidates_staged_tree_after_copy(tmp_path):
    source = _plugin(str(tmp_path / "source"), "linked")
    root = tmp_path / "plugins"

    with (
        patch(
            "defenseclaw.commands.cmd_plugin._reject_linked_tree",
            side_effect=[None, PluginIdentityError("plugin source contains a linked entry: staged")],
        ) as reject_links,
        pytest.raises(PluginIdentityError, match="linked entry"),
    ):
        _PluginInstallTransaction.prepare(
            source,
            [("openclaw", str(root))],
            "linked",
            force=False,
        )

    assert reject_links.call_count == 2
    assert root.exists()
    assert list(root.iterdir()) == []


@patch("defenseclaw.inventory.plugin_identity.os.lstat")
def test_windows_reparse_attribute_is_treated_as_link(lstat):
    lstat.return_value = SimpleNamespace(
        st_mode=stat.S_IFDIR,
        st_file_attributes=getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400),
    )
    assert is_link_or_reparse("reparse-entry") is True


def test_canonical_id_uses_manifest_not_space_containing_basename(tmp_path):
    source = _plugin(str(tmp_path / "source folder with spaces"), "canonical-id")
    assert canonical_plugin_id(source) == ("canonical-id", "plugin.json")
