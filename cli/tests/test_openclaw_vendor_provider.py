# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Published-provider identity keeps the scanner's ordinary decisions."""

from __future__ import annotations

import json
import shutil
from types import SimpleNamespace

from defenseclaw.commands.cmd_plugin import _build_scan_options
from defenseclaw.enforce import asset_lists
from defenseclaw.scanner.plugin_scanner import vendor_identity
from defenseclaw.scanner.plugin_scanner.scanner import scan_plugin
from defenseclaw.scanner.plugin_scanner.types import PluginScanOptions

from tests.environment import requires_symlink_privilege


def _package(root, name: str, source: str) -> None:
    root.mkdir()
    (root / "package.json").write_text(
        json.dumps({"name": name, "version": "2026.10.9"}), encoding="utf-8",
    )
    (root / "index.js").write_text(source, encoding="utf-8")


def _high_rules(root) -> set[str]:
    return {f.rule_id for f in scan_plugin(str(root)).findings if f.severity == "HIGH"}


def test_r108_g501_exact_provider_tree_and_scanned_twins(tmp_path, monkeypatch) -> None:
    source = 'const region = /region/.exec(value);\n'
    official = tmp_path / "official"
    _package(official, "@openclaw/amazon-bedrock-provider", source)
    digest = vendor_identity._tree_sha256(str(official))
    assert digest
    monkeypatch.setitem(
        vendor_identity.VENDOR_DIGESTS,
        ("@openclaw/amazon-bedrock-provider", "2026.10.9"), digest,
    )

    assert _high_rules(official) == set()
    assert "SRC-EXEC" in {
        f.rule_id for f in scan_plugin(
            str(official), PluginScanOptions(include_self=True),
        ).findings
    }

    (official / "index.js").write_text(source + 'exec("echo ok");\n', encoding="utf-8")
    assert "SRC-EXEC" in _high_rules(official)

    unrelated = tmp_path / "unrelated"
    _package(unrelated, "other-provider", source)
    assert "SRC-EXEC" in _high_rules(unrelated)

    benign = tmp_path / "benign"
    _package(benign, "other-provider", 'const match = /region/.test(value);\n')
    assert "SRC-EXEC" not in _high_rules(benign)


@requires_symlink_privilege
def test_r109_g501_identity_matrix(tmp_path, monkeypatch) -> None:
    source = tmp_path / "published"
    source.mkdir()
    (source / "package.json").write_text(json.dumps({
        "name": "@openclaw/amazon-bedrock-provider",
        "version": "2026.10.9",
        "peerDependencies": {"openclaw": ">=2026.10.9"},
    }), encoding="utf-8")
    (source / "index.js").write_text("const match = /region/.exec(value);\n", encoding="utf-8")
    (source / "node_modules").mkdir()
    dependency = source / "node_modules" / "dependency"
    dependency.mkdir()
    (dependency / "index.d.ts").write_text("export const value: string;\n", encoding="utf-8")
    digest = vendor_identity._tree_sha256(str(source))
    assert digest
    monkeypatch.setitem(
        vendor_identity.VENDOR_DIGESTS,
        ("@openclaw/amazon-bedrock-provider", "2026.10.9"), digest,
    )
    peer = tmp_path / "host-peer"
    peer.mkdir()
    (peer / "package.json").write_text('{"name":"openclaw"}', encoding="utf-8")

    installed = tmp_path / "installed"
    shutil.copytree(source, installed)
    (installed / "node_modules" / "openclaw").symlink_to(peer, target_is_directory=True)
    assert vendor_identity._tree_sha256(str(installed)) is None
    assert vendor_identity._tree_sha256(
        str(installed), tolerated_links=frozenset({"node_modules/openclaw"}),
    ) == digest
    assert vendor_identity.inspect_official_provider_tree(str(source)) == "@openclaw/amazon-bedrock-provider"
    assert vendor_identity.inspect_official_provider_tree(str(installed)) == "@openclaw/amazon-bedrock-provider"
    assert "SRC-EXEC" not in _high_rules(installed)
    assert "SRC-EXEC" in {
        f.rule_id for f in scan_plugin(
            str(installed), PluginScanOptions(disable_vendor_identity=True),
        ).findings if f.severity == "HIGH"
    }
    assert not {f.rule_id for f in scan_plugin(
        str(installed), PluginScanOptions(policy="permissive"),
    ).findings if f.severity == "HIGH"}
    strict = scan_plugin(str(installed), PluginScanOptions(profile="strict"))
    assert "SRC-EXEC" in {f.rule_id for f in strict.findings if f.severity == "HIGH"}
    strict_with_profile_override = scan_plugin(
        str(installed), PluginScanOptions(policy="strict", profile="default"),
    )
    assert "SRC-EXEC" in {
        f.rule_id for f in strict_with_profile_override.findings if f.severity == "HIGH"
    }
    assert "SRC-EXEC" in {f.rule_id for f in scan_plugin(
        str(installed), PluginScanOptions(include_self=True),
    ).findings if f.severity == "HIGH"}

    def change(name, edit, *, expect_high=True):
        root = tmp_path / name
        shutil.copytree(installed, root, symlinks=True)
        edit(root)
        assert vendor_identity.inspect_official_provider_tree(str(root)) is None, name
        if expect_high:
            assert "SRC-EXEC" in _high_rules(root), name

    change("source-change", lambda root: (root / "index.js").write_text(
        'const match = /region/.exec(value); exec("echo ok");\n', encoding="utf-8",
    ))
    change("single-byte-change", lambda root: (root / "index.js").write_text(
        "const match = /Region/.exec(value);\n", encoding="utf-8",
    ))
    change("extra-readme", lambda root: (root / "node_modules" / "README").write_text(
        "Package usage notes.\n", encoding="utf-8",
    ))
    change("extra-types", lambda root: (root / "node_modules" / "index.d.ts").write_text(
        "export const value: string;\n", encoding="utf-8",
    ))
    change("changed-types", lambda root: (root / "node_modules" / "dependency" / "index.d.ts").write_text(
        "export const value: number;\n", encoding="utf-8",
    ))
    change("extra-text", lambda root: (root / "node_modules" / "payload.txt").write_text(
        "Local note.\n", encoding="utf-8",
    ))
    change("missing-file", lambda root: (root / "index.js").unlink(), expect_high=False)
    change("unexpected-link", lambda root: (root / "node_modules" / "other").symlink_to(
        peer, target_is_directory=True,
    ))
    change("wrong-version", lambda root: (root / "package.json").write_text(json.dumps({
        "name": "@openclaw/amazon-bedrock-provider", "version": "2026.10.8",
    }), encoding="utf-8"))
    change("lookalike-name", lambda root: (root / "package.json").write_text(json.dumps({
        "name": "@openclaw/amazon-bedrock-provider-copy", "version": "2026.10.9",
    }), encoding="utf-8"))
    wrong = tmp_path / "wrong-peer"
    wrong.mkdir()
    (wrong / "package.json").write_text('{"name":"other"}', encoding="utf-8")
    def replace_peer(root):
        (root / "node_modules" / "openclaw").unlink()
        (root / "node_modules" / "openclaw").symlink_to(wrong, target_is_directory=True)

    change("wrong-peer-name", replace_peer)

    def point_inside(root):
        (root / "node_modules" / "openclaw").unlink()
        inside_root = root / "host-peer"
        inside_root.mkdir()
        (inside_root / "package.json").write_text('{"name":"openclaw"}', encoding="utf-8")
        (root / "node_modules" / "openclaw").symlink_to(inside_root, target_is_directory=True)

    change("inside-peer", point_inside)

    benign = tmp_path / "benign"
    _package(benign, "other-provider", "const match = /region/.test(value);\n")
    assert "SRC-EXEC" not in _high_rules(benign)

    (dependency / "addon.node").write_bytes(b"native fixture")
    native_digest = vendor_identity._tree_sha256(str(source))
    assert native_digest
    monkeypatch.setitem(
        vendor_identity.VENDOR_DIGESTS,
        ("@openclaw/amazon-bedrock-provider", "2026.10.9"), native_digest,
    )
    assert vendor_identity.inspect_official_provider_tree(str(source)) is not None
    assert "STRUCT-NATIVE-IN-SKIPDIR" in _high_rules(source)


@requires_symlink_privilege
def test_r109_g501_peer_link_revalidated_after_hash(tmp_path, monkeypatch) -> None:
    published = tmp_path / "published"
    published.mkdir()
    (published / "package.json").write_text(json.dumps({
        "name": "@openclaw/amazon-bedrock-provider",
        "version": "2026.10.9",
        "peerDependencies": {"openclaw": ">=2026.10.9"},
    }), encoding="utf-8")
    (published / "index.js").write_text(
        "const match = /region/.exec(value);\n", encoding="utf-8",
    )
    (published / "node_modules").mkdir()
    digest = vendor_identity._tree_sha256(str(published))
    assert digest
    monkeypatch.setitem(
        vendor_identity.VENDOR_DIGESTS,
        ("@openclaw/amazon-bedrock-provider", "2026.10.9"), digest,
    )
    installed = tmp_path / "installed"
    shutil.copytree(published, installed)
    peer = installed / "node_modules" / "openclaw"
    wrong = tmp_path / "wrong-peer"
    wrong.mkdir()
    (wrong / "package.json").write_text('{"name":"other"}', encoding="utf-8")
    original = vendor_identity._tree_sha256

    def create_link_during_hash(path, **kwargs):
        if path == str(installed):
            peer.symlink_to(wrong, target_is_directory=True)
        return original(path, **kwargs)

    monkeypatch.setattr(vendor_identity, "_tree_sha256", create_link_during_hash)
    assert "SRC-EXEC" in _high_rules(installed)


@requires_symlink_privilege
def test_r109_g501_peer_ancestor_revalidated_after_hash(tmp_path, monkeypatch) -> None:
    published = tmp_path / "published"
    (published / "node_modules").mkdir(parents=True)
    (published / "package.json").write_text(json.dumps({
        "name": "@openclaw/amazon-bedrock-provider",
        "version": "2026.10.9",
        "peerDependencies": {"openclaw": ">=2026.10.9"},
    }), encoding="utf-8")
    (published / "index.js").write_text("const match = /region/.exec(value);\n", encoding="utf-8")
    digest = vendor_identity._tree_sha256(str(published))
    assert digest
    monkeypatch.setitem(
        vendor_identity.VENDOR_DIGESTS,
        ("@openclaw/amazon-bedrock-provider", "2026.10.9"), digest,
    )
    installed = tmp_path / "installed"
    shutil.copytree(published, installed)
    peer_target = tmp_path / "peer-target"
    peer_target.mkdir()
    (peer_target / "package.json").write_text('{"name":"openclaw"}', encoding="utf-8")
    (installed / "node_modules" / "openclaw").symlink_to(peer_target, target_is_directory=True)
    assert not _high_rules(installed)  # Ordinary installed provider remains allowed.

    original = vendor_identity._tree_sha256

    def swap_ancestor_after_hash(path, **kwargs):
        result = original(path, **kwargs)
        if path == str(installed):
            (installed / "node_modules").rename(tmp_path / "saved-node_modules")
            (installed / "node_modules").symlink_to(tmp_path / "saved-node_modules", target_is_directory=True)
        return result

    monkeypatch.setattr(vendor_identity, "_tree_sha256", swap_ancestor_after_hash)
    assert "SRC-EXEC" in _high_rules(installed)


@requires_symlink_privilege
def test_r109_g501_whole_tree_revalidated_after_hash(tmp_path, monkeypatch) -> None:
    published = tmp_path / "published"
    (published / "runtime" / "child").mkdir(parents=True)
    (published / "node_modules").mkdir()
    (published / "package.json").write_text(json.dumps({
        "name": "@openclaw/amazon-bedrock-provider",
        "version": "2026.10.9",
        "peerDependencies": {"openclaw": ">=2026.10.9"},
    }), encoding="utf-8")
    (published / "index.js").write_text("const match = /region/.exec(value);\n", encoding="utf-8")
    (published / "runtime" / "child" / "entry.js").write_text(
        "export const value = 1;\n", encoding="utf-8",
    )
    digest = vendor_identity._tree_sha256(str(published))
    assert digest
    monkeypatch.setitem(
        vendor_identity.VENDOR_DIGESTS,
        ("@openclaw/amazon-bedrock-provider", "2026.10.9"), digest,
    )
    peer = tmp_path / "peer"
    peer.mkdir()
    (peer / "package.json").write_text('{"name":"openclaw"}', encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "entry.js").write_text("exec('changed command');\n", encoding="utf-8")
    original = vendor_identity._tree_sha256

    for profile in ("default", "permissive"):
        installed = tmp_path / profile
        shutil.copytree(published, installed)
        (installed / "node_modules" / "openclaw").symlink_to(
            peer, target_is_directory=True,
        )
        assert not {f.rule_id for f in scan_plugin(
            str(installed), PluginScanOptions(policy=profile),
        ).findings if f.severity == "HIGH"}

        changed = False

        def change_unrelated_entry(path, **kwargs):
            nonlocal changed
            result = original(path, **kwargs)
            if path == str(installed) and not changed:
                (installed / "runtime" / "child").rename(tmp_path / f"saved-{profile}")
                (installed / "runtime" / "child").symlink_to(
                    outside, target_is_directory=True,
                )
                changed = True
            return result

        with monkeypatch.context() as patch:
            patch.setattr(vendor_identity, "_tree_sha256", change_unrelated_entry)
            assert "SRC-EXEC" in {f.rule_id for f in scan_plugin(
                str(installed), PluginScanOptions(policy=profile),
            ).findings if f.severity == "HIGH"}
        assert changed


def test_r109_g501_secure_client_scan_options(monkeypatch) -> None:
    from defenseclaw.commands.cmd_plugin import _scan_options_for_connector

    monkeypatch.setattr(asset_lists, "is_secure_client", lambda cfg: True)
    app = SimpleNamespace(cfg=SimpleNamespace(
        claw=SimpleNamespace(home_dir=""),
        guardrail=SimpleNamespace(hook_policy_tier=lambda connector: "strict"),
    ))
    options = _build_scan_options(
        app, "", None, None, "", "", 0, True, False, False, True,
    )
    assert options["disable_vendor_identity"] is True
    assert _scan_options_for_connector(app, "openclaw", {}) == {
        "disable_vendor_identity": True,
    }

    monkeypatch.setattr(asset_lists, "is_secure_client", lambda cfg: False)
    assert _scan_options_for_connector(app, "openclaw", {}) == {
        "policy": "strict", "profile": "strict",
    }
