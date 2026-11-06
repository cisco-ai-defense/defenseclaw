# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Published-provider identity keeps the scanner's ordinary decisions."""

from __future__ import annotations

import json
import os
import shutil
from types import SimpleNamespace

import pytest
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


def _openclaw_peer(tmp_path, label="host-peer"):
    peer = tmp_path / label / "node_modules" / "openclaw"
    (peer / "bin").mkdir(parents=True)
    (peer / "package.json").write_text('{"name":"openclaw"}', encoding="utf-8")
    executable = peer / "bin" / "openclaw"
    executable.write_text("openclaw entry\n", encoding="utf-8")
    executable.chmod(0o755)
    return peer


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
    peer = _openclaw_peer(tmp_path)

    installed = tmp_path / "installed"
    shutil.copytree(source, installed)
    (installed / "node_modules" / "openclaw").symlink_to(peer, target_is_directory=True)
    assert vendor_identity._tree_sha256(str(installed)) is None
    assert vendor_identity._tree_sha256(
        str(installed), tolerated_links=frozenset({"node_modules/openclaw"}),
    ) == digest
    source_identity = vendor_identity.inspect_official_provider_tree(str(source))
    installed_identity = vendor_identity.inspect_official_provider_tree(str(installed))
    assert source_identity == vendor_identity.ProviderIdentity(
        "@openclaw/amazon-bedrock-provider", False,
    )
    assert installed_identity == vendor_identity.ProviderIdentity(
        "@openclaw/amazon-bedrock-provider", True,
    )
    assert not scan_plugin(str(source)).findings
    assert "VENDOR-PEER-POSSIBLE" in {
        f.rule_id for f in scan_plugin(str(installed)).findings if f.severity == "INFO"
    }
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
    peer_target = _openclaw_peer(tmp_path, "peer-target")
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
    peer = _openclaw_peer(tmp_path, "peer")
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


def _linked_provider(tmp_path, monkeypatch, target):
    published = tmp_path / "published"
    (published / "node_modules").mkdir(parents=True)
    (published / "package.json").write_text(json.dumps({
        "name": "@openclaw/amazon-bedrock-provider", "version": "2026.10.9",
        "peerDependencies": {"openclaw": ">=2026.10.9"},
    }), encoding="utf-8")
    (published / "index.js").write_text(
        "const match = /region/.exec(value);\n", encoding="utf-8",
    )
    digest = vendor_identity._tree_sha256(str(published))
    assert digest
    monkeypatch.setitem(
        vendor_identity.VENDOR_DIGESTS,
        ("@openclaw/amazon-bedrock-provider", "2026.10.9"), digest,
    )
    installed = tmp_path / "installed"
    shutil.copytree(published, installed)
    (installed / "node_modules" / "openclaw").symlink_to(
        target, target_is_directory=True,
    )
    return installed


@requires_symlink_privilege
def test_r109_g610_peer_package_provenance_matrix(tmp_path, monkeypatch) -> None:
    from defenseclaw.scanner.plugin import PluginScannerWrapper

    ordinary = _openclaw_peer(tmp_path, "ordinary")
    unrelated = _openclaw_peer(tmp_path, "unrelated")
    data_dir = tmp_path / "state"
    state_peer = data_dir / "node_modules" / "openclaw"
    state_peer.mkdir(parents=True)
    (state_peer / "package.json").write_text('{"name":"openclaw"}', encoding="utf-8")
    private_peer = tmp_path / ".ssh" / "node_modules" / "openclaw"
    private_peer.mkdir(parents=True)
    (private_peer / "package.json").write_text('{"name":"openclaw"}', encoding="utf-8")
    alias = tmp_path / "alias"
    alias.symlink_to(private_peer.parent.parent, target_is_directory=True)
    state_alias = tmp_path / "state-alias"
    state_alias.symlink_to(data_dir, target_is_directory=True)
    other = tmp_path / "other-package"
    other.mkdir()
    (other / "package.json").write_text('{"name":"other"}', encoding="utf-8")

    cases = (
        ("ordinary", ordinary, True),
        ("unrelated-openclaw", unrelated, True),
        ("private", private_peer, False),
        ("private-alias", alias / "node_modules/openclaw", False),
        ("state", state_peer, False),
        ("state-alias", state_alias / "node_modules/openclaw", False),
        ("other-package", other, False),
    )
    for label, target, possible in cases:
        tree = _linked_provider(tmp_path / f"provider-{label}", monkeypatch, target)
        identity = vendor_identity.inspect_official_provider_tree(
            str(tree), data_dir=str(data_dir),
        )
        assert (identity is not None) is possible, label
        for profile in ("default", "permissive", "strict"):
            result = scan_plugin(
                str(tree), PluginScanOptions(policy=profile, data_dir=str(data_dir)),
            )
            high = {f.rule_id for f in result.findings if f.severity == "HIGH"}
            assert ("SRC-EXEC" in high) is (profile == "strict" or not possible), (label, profile)
            visible = {f.rule_id for f in result.findings if f.severity == "INFO"}
            assert ("VENDOR-PEER-POSSIBLE" in visible) is (possible and profile != "strict")
            if possible and profile != "strict":
                assert result.assessment.verdict == "benign"
        if label in ("ordinary", "private-alias", "state"):
            wrapped = PluginScannerWrapper(data_dir=str(data_dir)).scan(str(tree))
            assert ("SRC-EXEC" in {
                f.rule_id for f in wrapped.findings if f.severity == "HIGH"
            }) is not possible

    benign = tmp_path / "benign"
    _package(benign, "ordinary-plugin", "export const value = 1;\n")
    assert not _high_rules(benign)


@requires_symlink_privilege
@pytest.mark.parametrize("wrapper_form", (
    "exec", "set-e", "inline-comment", "shebang-option", "package-local",
))
def test_r109_g610_shell_wrappers_do_not_change_peer_classification(
    tmp_path, monkeypatch, wrapper_form,
) -> None:
    import subprocess

    active = _openclaw_peer(tmp_path, "active")
    old = _openclaw_peer(tmp_path, "old")
    active_entry = active / "bin/openclaw"
    active_entry.write_text("#!/bin/sh\nprintf 'active\\n'\n", encoding="utf-8")
    wrapper = old / "bin/openclaw" if wrapper_form == "package-local" else tmp_path / "bin/openclaw"
    wrapper.parent.mkdir(parents=True, exist_ok=True)
    forms = {
        "exec": f'#!/bin/sh\nexec "{active_entry}" "$@"\n',
        "set-e": f'#!/bin/sh\nset -e\nexec "{active_entry}" "$@"\n',
        "inline-comment": f'#!/bin/sh\nexec "{active_entry}" "$@" # provider\n',
        "shebang-option": f'#!/bin/sh -e\nexec "{active_entry}" "$@"\n',
        "package-local": f'#!/bin/sh\nexec "{active_entry}" "$@"\n',
    }
    wrapper.write_text(forms[wrapper_form], encoding="utf-8")
    wrapper.chmod(0o755)
    assert subprocess.check_output([str(wrapper)], text=True).strip() == "active"
    monkeypatch.setattr(shutil, "which", lambda name: str(wrapper))

    for label, target in (("active", active), ("old", old)):
        tree = _linked_provider(tmp_path / label, monkeypatch, target)
        for profile in ("default", "permissive", "strict"):
            result = scan_plugin(str(tree), PluginScanOptions(policy=profile))
            high = {f.rule_id for f in result.findings if f.severity == "HIGH"}
            assert ("SRC-EXEC" in high) is (profile == "strict"), (wrapper_form, label, profile)
            possible = {f.rule_id for f in result.findings if f.severity == "INFO"}
            assert ("VENDOR-PEER-POSSIBLE" in possible) is (profile != "strict")


@requires_symlink_privilege
def test_r109_g610_unresolved_executable_does_not_change_peer_classification(
    tmp_path, monkeypatch,
) -> None:
    package = _openclaw_peer(tmp_path)
    tree = _linked_provider(tmp_path / "provider", monkeypatch, package)
    launcher = tmp_path / "bin/openclaw"
    launcher.parent.mkdir()
    launcher.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    launcher.chmod(0o755)
    monkeypatch.setattr(shutil, "which", lambda name: str(launcher))
    for profile in ("default", "permissive", "strict"):
        result = scan_plugin(str(tree), PluginScanOptions(policy=profile))
        high = {f.rule_id for f in result.findings if f.severity == "HIGH"}
        assert ("SRC-EXEC" in high) is (profile == "strict")
        assert ("VENDOR-PEER-POSSIBLE" in {f.rule_id for f in result.findings}) is (
            profile != "strict"
        )


def test_r109_g501_contents_rehashed_after_metadata_stable_edit(tmp_path, monkeypatch) -> None:
    published = tmp_path / "published"
    published.mkdir()
    (published / "package.json").write_text(json.dumps({
        "name": "@openclaw/amazon-bedrock-provider", "version": "2026.10.9",
    }), encoding="utf-8")
    changed_source = 'require("child_process").exec("true");\n'
    safe_source = "export const value = 1;".ljust(len(changed_source) - 1) + "\n"
    assert len(safe_source) == len(changed_source)
    (published / "index.js").write_text(safe_source, encoding="utf-8")
    digest = vendor_identity._tree_sha256(str(published))
    assert digest
    monkeypatch.setitem(
        vendor_identity.VENDOR_DIGESTS,
        ("@openclaw/amazon-bedrock-provider", "2026.10.9"), digest,
    )
    installed = tmp_path / "installed"
    shutil.copytree(published, installed)
    assert not _high_rules(installed)

    original_digest = vendor_identity._tree_sha256
    original_identity = vendor_identity._filesystem_identity
    monkeypatch.setattr(
        vendor_identity, "_filesystem_identity",
        lambda info: (*original_identity(info)[:-1], 0),
    )
    changed = False

    def edit_after_first_digest(path, **kwargs):
        nonlocal changed
        result = original_digest(path, **kwargs)
        if path == str(installed) and not changed:
            entry = installed / "index.js"
            before = entry.stat()
            entry.write_text(changed_source, encoding="utf-8")
            os.utime(entry, ns=(before.st_atime_ns, before.st_mtime_ns))
            changed = True
        return result

    monkeypatch.setattr(vendor_identity, "_tree_sha256", edit_after_first_digest)
    assert "SRC-EXEC" in _high_rules(installed)
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
