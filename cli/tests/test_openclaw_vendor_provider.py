# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Published-provider identity keeps the scanner's ordinary decisions."""

from __future__ import annotations

import json
import os
import shutil
import stat
from types import SimpleNamespace

import pytest
from defenseclaw import hermes_skills
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
def test_r109_g610_cross_volume_peer_is_outside_provider(tmp_path, monkeypatch) -> None:
    """A peer on another drive or share is outside the provider, not invalid."""
    import ntpath

    sep = ntpath.sep
    for other_volume in ("D:" + sep + "openclaw", sep * 2 + sep.join(("server", "share", "openclaw"))):
        with pytest.raises(ValueError):
            ntpath.commonpath(("C:" + sep + "provider", other_volume))

    provider_volume = tmp_path / "volume-c"
    peer_volume = tmp_path / "volume-d"
    provider_volume.mkdir()
    peer_volume.mkdir()
    ordinary = _openclaw_peer(peer_volume, "ordinary")
    data_dir = peer_volume / "state"
    state_peer = data_dir / "node_modules" / "openclaw"
    state_peer.mkdir(parents=True)
    (state_peer / "package.json").write_text('{"name":"openclaw"}', encoding="utf-8")
    private_peer = peer_volume / ".ssh" / "node_modules" / "openclaw"
    private_peer.mkdir(parents=True)
    (private_peer / "package.json").write_text('{"name":"openclaw"}', encoding="utf-8")
    state_alias = provider_volume / "state-alias"
    state_alias.symlink_to(data_dir, target_is_directory=True)
    other = peer_volume / "other-package"
    other.mkdir()
    (other / "package.json").write_text('{"name":"other"}', encoding="utf-8")

    real_commonpath = os.path.commonpath
    volumes = tuple(os.path.realpath(v) for v in (provider_volume, peer_volume))

    def volume(path):
        for index, root in enumerate(volumes):
            try:
                if os.path.normcase(real_commonpath((root, path))) == os.path.normcase(root):
                    return index
            except ValueError:
                continue
        return -1

    def cross_volume_commonpath(paths):
        paths = [os.fspath(path) for path in paths]
        if len({volume(path) for path in paths}) > 1:
            raise ValueError("Paths don't have the same drive")
        return real_commonpath(paths)

    cases = (
        ("ordinary", ordinary, True),
        ("private", private_peer, False),
        ("state", state_peer, False),
        ("state-alias", state_alias / "node_modules/openclaw", False),
        ("other-package", other, False),
    )
    trees = {
        label: _linked_provider(provider_volume / f"provider-{label}", monkeypatch, target)
        for label, target, _ in cases
    }
    monkeypatch.setattr(os.path, "commonpath", cross_volume_commonpath)
    for label, _, possible in cases:
        tree = trees[label]
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


class _JunctionStat:
    """``lstat`` of a Windows directory junction: a mount-point directory."""

    def __init__(self, info) -> None:
        self._info = info
        self.st_mode = (info.st_mode & ~stat.S_IFMT(info.st_mode)) | stat.S_IFDIR
        self.st_file_attributes = (
            stat.FILE_ATTRIBUTE_DIRECTORY | stat.FILE_ATTRIBUTE_REPARSE_POINT
        )
        self.st_reparse_tag = getattr(stat, "IO_REPARSE_TAG_MOUNT_POINT", 0xA0000003)

    def __getattr__(self, name):
        return getattr(self._info, name)


def _model_junctions(monkeypatch, *aliases) -> None:
    """Show the given symlinks to the identity code as Windows junctions.

    As on Windows, ``lstat`` reports a directory with a mount-point reparse
    tag and ``os.path.islink`` is false, while ``os.readlink`` and
    ``os.path.realpath`` still follow the alias.
    """
    junctions = {os.path.abspath(alias) for alias in aliases}

    def is_junction(path) -> bool:
        return isinstance(path, (str, os.PathLike)) and os.path.abspath(path) in junctions

    def lstat(path, *args, **kwargs):
        info = os.lstat(path, *args, **kwargs)
        return _JunctionStat(info) if is_junction(path) else info

    def stat_(path, *args, follow_symlinks=True, **kwargs):
        info = os.stat(path, *args, follow_symlinks=follow_symlinks, **kwargs)
        return _JunctionStat(info) if not follow_symlinks and is_junction(path) else info

    path_module = SimpleNamespace(**{
        name: getattr(os.path, name) for name in dir(os.path) if not name.startswith("__")
    })
    path_module.islink = lambda path: not is_junction(path) and os.path.islink(path)
    windows_os = SimpleNamespace(**{
        name: getattr(os, name) for name in dir(os) if not name.startswith("__")
    })
    windows_os.lstat, windows_os.stat, windows_os.path = lstat, stat_, path_module
    monkeypatch.setattr(vendor_identity, "os", windows_os)
    monkeypatch.setattr(hermes_skills, "os", windows_os)


@requires_symlink_privilege
def test_r109_g610_windows_junction_peers_match_link_peers(tmp_path, monkeypatch) -> None:
    """A junction peer or alias is judged like the same symlink peer or alias."""
    ordinary = _openclaw_peer(tmp_path, "ordinary")
    data_dir = tmp_path / "state"
    state_peer = data_dir / "node_modules" / "openclaw"
    state_peer.mkdir(parents=True)
    (state_peer / "package.json").write_text('{"name":"openclaw"}', encoding="utf-8")
    private_peer = tmp_path / ".ssh" / "node_modules" / "openclaw"
    private_peer.mkdir(parents=True)
    (private_peer / "package.json").write_text('{"name":"openclaw"}', encoding="utf-8")
    aliases = {}
    for label, target in (
        ("ordinary-alias", ordinary.parent.parent),
        ("private-alias", private_peer.parent.parent),
        ("state-alias", data_dir),
        ("named-private-alias", tmp_path / ".ssh" / ".." / "ordinary"),
    ):
        aliases[label] = tmp_path / label
        aliases[label].symlink_to(target, target_is_directory=True)

    # (label, peer target, peer entry is a junction, admitted with a possible peer)
    cases = (
        ("junction-peer", ordinary, True, True),
        ("link-through-junction", aliases["ordinary-alias"] / "node_modules/openclaw", False, True),
        ("junction-through-junction", aliases["ordinary-alias"] / "node_modules/openclaw", True, True),
        ("junction-peer-private", private_peer, True, False),
        ("junction-peer-state", state_peer, True, False),
        ("link-through-private-junction", aliases["private-alias"] / "node_modules/openclaw", False, False),
        ("junction-through-private-junction", aliases["private-alias"] / "node_modules/openclaw", True, False),
        ("link-through-state-junction", aliases["state-alias"] / "node_modules/openclaw", False, False),
        ("link-through-named-private-junction", aliases["named-private-alias"] / "node_modules/openclaw", False, False),
        ("extra-junction", ordinary, True, False),
    )
    trees = {}
    for label, target, _, _ in cases:
        trees[label] = _linked_provider(tmp_path / f"provider-{label}", monkeypatch, target)
    extra = trees["extra-junction"] / "lib-alias"
    extra.symlink_to(ordinary, target_is_directory=True)
    _model_junctions(monkeypatch, *aliases.values(), extra, *(
        trees[label] / "node_modules" / "openclaw" for label, _, junction, _ in cases if junction
    ))

    for label, _, _, possible in cases:
        tree = trees[label]
        identity = vendor_identity.inspect_official_provider_tree(
            str(tree), data_dir=str(data_dir),
        )
        assert (identity is not None) is possible, label
        if possible:
            assert identity.possible_peer, label
        for profile in ("default", "permissive", "strict"):
            result = scan_plugin(
                str(tree), PluginScanOptions(policy=profile, data_dir=str(data_dir)),
            )
            high = {f.rule_id for f in result.findings if f.severity == "HIGH"}
            assert ("SRC-EXEC" in high) is (profile == "strict" or not possible), (label, profile)
            visible = {f.rule_id for f in result.findings if f.severity == "INFO"}
            assert ("VENDOR-PEER-POSSIBLE" in visible) is (possible and profile != "strict"), (
                label, profile,
            )


@pytest.mark.skipif(os.name == "nt", reason="Unix shell wrappers")
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
