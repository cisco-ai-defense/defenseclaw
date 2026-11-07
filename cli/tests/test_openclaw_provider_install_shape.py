# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""The OpenClaw provider is identified by its own files, however it was installed."""

from __future__ import annotations

import json
import shutil

from defenseclaw.scanner.plugin_scanner import vendor_identity
from defenseclaw.scanner.plugin_scanner.scanner import scan_plugin
from defenseclaw.scanner.plugin_scanner.types import PluginScanOptions

from tests.environment import requires_symlink_privilege
from tests.test_openclaw_vendor_provider import _high_rules, _openclaw_peer

PROVIDER = "@openclaw/amazon-bedrock-provider"
VERSION = "2026.10.9"


def _write(path, text) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _published_provider(root) -> None:
    """A package as npm publishes it: its own files plus bundled dependencies."""

    _write(root / "package.json", json.dumps({
        "name": PROVIDER, "version": VERSION,
        "dependencies": {"dep": "1.0.0"},
        "peerDependencies": {"openclaw": ">=2026.10.9"},
        "bundledDependencies": ["dep"],
    }))
    _write(root / "openclaw.plugin.json", json.dumps({"id": "amazon-bedrock"}))
    _write(root / "dist" / "index.js", "const match = /region/.exec(value);\n")
    _write(root / "node_modules" / "dep" / "package.json", json.dumps({"name": "dep"}))
    _write(root / "node_modules" / "dep" / "index.js", "module.exports = 1;\n")


def _installed_by_openclaw(published, installed, peer) -> None:
    """The tree OpenClaw leaves: manifest rewritten, dependencies hoisted by npm."""

    shutil.copytree(published, installed, ignore=shutil.ignore_patterns("node_modules"))
    manifest = json.loads((installed / "package.json").read_text(encoding="utf-8"))
    manifest.pop("bundledDependencies")
    manifest["devDependencies"] = {"@openclaw/plugin-sdk": "workspace:*"}
    _write(installed / "package.json", json.dumps(manifest, indent=2))
    modules = installed / "node_modules"
    _write(modules / "@scope" / "hoisted" / "index.js", "module.exports = 2;\n")
    _write(modules / "dep" / "package.json", json.dumps({"name": "dep", "version": "1.0.1"}))
    _write(modules / "dep" / "index.js", "module.exports = 3;\n")
    _write(modules / ".package-lock.json", json.dumps({"packages": {}}))
    (modules / "openclaw").symlink_to(peer, target_is_directory=True)


def test_r109_g610_pinned_provider_releases() -> None:
    for version in ("2026.10.9", "2026.10.10", "2026.11.1"):
        assert len(vendor_identity.VENDOR_DIGESTS[(PROVIDER, version)]) == 64
    assert {name for name, _ in vendor_identity.VENDOR_DIGESTS} == {PROVIDER}


@requires_symlink_privilege
def test_r109_g610_provider_installed_by_openclaw_is_admitted(tmp_path, monkeypatch) -> None:
    published = tmp_path / "published"
    _published_provider(published)
    digest = vendor_identity._package_digest(str(published))
    assert digest
    monkeypatch.setitem(vendor_identity.VENDOR_DIGESTS, (PROVIDER, VERSION), digest)
    installed = tmp_path / "installed"
    _installed_by_openclaw(published, installed, _openclaw_peer(tmp_path))

    # The installer changed the manifest and the dependency tree; the package
    # own files are what was published.
    assert vendor_identity._package_digest(
        str(installed), tolerated_links=frozenset({"node_modules/openclaw"}),
    ) == digest
    assert vendor_identity.inspect_official_provider_tree(str(installed)) == (
        vendor_identity.ProviderIdentity(PROVIDER, True)
    )
    assert vendor_identity.inspect_official_provider_tree(str(published)) == (
        vendor_identity.ProviderIdentity(PROVIDER, False)
    )
    assert _high_rules(installed) == set()
    assert not {f.rule_id for f in scan_plugin(
        str(installed), PluginScanOptions(policy="permissive"),
    ).findings if f.severity == "HIGH"}
    # Strict keeps the ordinary scan, which flags the regex call.
    assert "SRC-EXEC" in {f.rule_id for f in scan_plugin(
        str(installed), PluginScanOptions(profile="strict"),
    ).findings if f.severity == "HIGH"}


@requires_symlink_privilege
def test_r109_g610_modified_installed_provider_is_scanned(tmp_path, monkeypatch) -> None:
    published = tmp_path / "published"
    _published_provider(published)
    monkeypatch.setitem(
        vendor_identity.VENDOR_DIGESTS, (PROVIDER, VERSION),
        vendor_identity._package_digest(str(published)),
    )
    peer = _openclaw_peer(tmp_path)
    base = tmp_path / "installed"
    _installed_by_openclaw(published, base, peer)
    assert vendor_identity.inspect_official_provider_tree(str(base)) is not None

    def edit_manifest(root, change) -> None:
        manifest = json.loads((root / "package.json").read_text(encoding="utf-8"))
        change(manifest)
        _write(root / "package.json", json.dumps(manifest))

    cases = {
        "one-byte-change": lambda root: _write(
            root / "dist" / "index.js", "const match = /Region/.exec(value);\n"),
        "added-call": lambda root: _write(
            root / "dist" / "index.js", "const match = /region/.exec(value); exec(command);\n"),
        "extra-own-file": lambda root: _write(root / "dist" / "extra.js", "module.exports = 4;\n"),
        "extra-root-file": lambda root: _write(root / "postinstall.js", "module.exports = 5;\n"),
        "nested-modules-own-file": lambda root: _write(
            root / "dist" / "node_modules" / "x.js", "module.exports = 6;\n"),
        "missing-own-file": lambda root: (root / "openclaw.plugin.json").unlink(),
        "install-script": lambda root: edit_manifest(
            root, lambda m: m.update(scripts={"postinstall": "node postinstall.js"})),
        "other-source": lambda root: edit_manifest(
            root, lambda m: m["dependencies"].update(dep="https://example.invalid/dep.tgz")),
        "dependency-link": lambda root: (root / "node_modules" / "dep2").symlink_to(
            peer, target_is_directory=True),
        "own-link": lambda root: (root / "dist" / "link").symlink_to(
            peer, target_is_directory=True),
        "unpinned-version": lambda root: edit_manifest(
            root, lambda m: m.update(version="2026.99.1")),
    }
    for name, edit in cases.items():
        root = tmp_path / name
        shutil.copytree(base, root, symlinks=True)
        edit(root)
        assert vendor_identity.inspect_official_provider_tree(str(root)) is None, name
    for name in ("added-call", "one-byte-change", "unpinned-version"):
        assert "SRC-EXEC" in _high_rules(tmp_path / name), name


@requires_symlink_privilege
def test_r109_g610_dependency_layout_is_not_identity(tmp_path, monkeypatch) -> None:
    """npm resolves dependencies at install time; their layout varies per install."""

    published = tmp_path / "published"
    _published_provider(published)
    monkeypatch.setitem(
        vendor_identity.VENDOR_DIGESTS, (PROVIDER, VERSION),
        vendor_identity._package_digest(str(published)),
    )
    installed = tmp_path / "installed"
    _installed_by_openclaw(published, installed, _openclaw_peer(tmp_path))
    _write(installed / "node_modules" / "extra" / "index.js", "module.exports = 8;\n")
    assert vendor_identity.inspect_official_provider_tree(str(installed)) is not None
    assert _high_rules(installed) == set()
    # A native binary among the dependencies is still reported.
    _write(installed / "node_modules" / "extra" / "addon.node", "native fixture")
    assert vendor_identity.inspect_official_provider_tree(str(installed)) is not None
    assert "STRUCT-NATIVE-IN-SKIPDIR" in _high_rules(installed)
