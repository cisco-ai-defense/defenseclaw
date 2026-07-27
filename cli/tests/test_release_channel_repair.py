# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path

import pytest
import yaml

from scripts import release_candidate

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "verify-release-channel-target.py"
SPEC = importlib.util.spec_from_file_location("verify_release_channel_target", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

RepairTargetError = MODULE.RepairTargetError

VERSION = "0.8.8"
COMMIT = "a" * 40
SOURCE_TREE = "b" * 40


def _canonical_json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _identity_payloads(
    version: str = VERSION,
    bridge_version: str = "0.8.4",
) -> tuple[bytes, bytes, bytes]:
    identity = {
        "runtime_config_version": 8,
        "schema_version": 1,
        "source_install_compatibility_epoch": 2,
        "source_release": version,
    }
    bridge = {
        "checksums_sha256": "c" * 64,
        "commit": "d" * 40,
        "tree": "e" * 40,
        "version": bridge_version,
    }
    source_map = {
        "bridge": bridge,
        "policy_commit": COMMIT,
        "policy_mode": "same_as_release_source",
        "policy_tree": SOURCE_TREE,
        "release_version": version,
        "schema_version": 1,
        "source_commit": COMMIT,
        "source_install_identity": identity,
        "source_tree": SOURCE_TREE,
    }
    source_map_payload = _canonical_json(source_map)
    provenance = {
        "bridge": bridge,
        "policy_commit": COMMIT,
        "policy_tree": SOURCE_TREE,
        "release_source_map_sha256": _sha256(source_map_payload),
        "release_version": version,
        "schema_version": 1,
        "source_commit": COMMIT,
        "source_install_identity": identity,
        "source_tree": SOURCE_TREE,
    }
    upgrade_manifest = {
        "minimum_source_version": bridge_version,
        "release_version": version,
        "required_bridge_version": bridge_version,
        "schema_version": 2,
        "tested_source_versions": [
            "0.8.7" if tuple(map(int, version.split("."))) > (0, 8, 7) else "0.8.6",
            bridge_version,
        ],
    }
    return _canonical_json(provenance), source_map_payload, _canonical_json(upgrade_manifest)


def _custody(
    tmp_path: Path,
    *,
    version: str = VERSION,
    bridge_version: str = "0.8.4",
) -> tuple[Path, Path, dict[str, object]]:
    downloads = tmp_path / "custody"
    downloads.mkdir()
    provenance, source_map, upgrade_manifest = _identity_payloads(version, bridge_version)
    payloads = {
        "defenseclaw-upgrade.sh": b"upgrade sh\n",
        "defenseclaw-upgrade.ps1": b"upgrade ps1\n",
        "defenseclaw-rescue.sh": b"rescue sh\n",
        "defenseclaw-rescue.ps1": b"rescue ps1\n",
        "install.sh": b"install sh\n",
        "install.ps1": b"install ps1\n",
        "release-provenance.json": provenance,
        "release-source-map.json": source_map,
        "upgrade-manifest.json": upgrade_manifest,
        f"defenseclaw_{version}_linux_amd64.tar.gz": b"runtime\n",
    }
    checksums = "".join(f"{_sha256(payload)}  {name}\n" for name, payload in sorted(payloads.items())).encode()
    downloads_payloads = {
        "checksums.txt": checksums,
        "checksums.txt.bundle": b'{"bundle":"fixture"}\n',
        "checksums.txt.pem": b"certificate\n",
        "checksums.txt.sig": b"signature\n",
        "release-provenance.json": provenance,
        "release-source-map.json": source_map,
        "upgrade-manifest.json": upgrade_manifest,
    }
    for name, payload in downloads_payloads.items():
        (downloads / name).write_bytes(payload)
    remote_payloads = {
        **payloads,
        **{name: payload for name, payload in downloads_payloads.items() if name in MODULE.PROOF_ASSET_NAMES},
    }
    release: dict[str, object] = {
        "tag_name": version,
        "draft": False,
        "prerelease": False,
        "immutable": True,
        "assets": [
            {"name": name, "digest": f"sha256:{_sha256(payload)}"} for name, payload in sorted(remote_payloads.items())
        ],
    }
    release_json = tmp_path / "release.json"
    release_json.write_text(json.dumps(release), encoding="utf-8")
    return release_json, downloads, release


def _verify(release_json: Path, downloads: Path, *, version: str = VERSION) -> None:
    MODULE.verify_target(
        release_json=release_json,
        download_dir=downloads,
        version=version,
        commit=COMMIT,
        source_tree=SOURCE_TREE,
    )


def test_repair_authenticates_closed_immutable_release_custody(tmp_path: Path) -> None:
    release_json, downloads, _release = _custody(tmp_path)
    _verify(release_json, downloads)


def test_repair_rejects_unsorted_checksum_inventory() -> None:
    first = f"{'a' * 64}  z-last\n"
    second = f"{'b' * 64}  a-first\n"

    with pytest.raises(RepairTargetError, match="asset names must be strictly sorted"):
        MODULE._parse_checksums((first + second).encode())


def test_repair_derives_bridge_identity_from_authenticated_manifest(tmp_path: Path) -> None:
    release_json, downloads, _release = _custody(tmp_path, bridge_version="0.8.3")

    _verify(release_json, downloads)

    assert '"0.8.4"' not in SCRIPT.read_text(encoding="utf-8")


def test_repair_rejects_targets_before_the_release_channel_asset_floor(
    tmp_path: Path,
) -> None:
    release_json, downloads, _release = _custody(tmp_path, version="0.8.7")

    with pytest.raises(
        RepairTargetError,
        match=r"starts with release 0\.8\.8",
    ):
        MODULE.verify_target(
            release_json=release_json,
            download_dir=downloads,
            version="0.8.7",
            commit=COMMIT,
            source_tree=SOURCE_TREE,
        )


@pytest.mark.parametrize("macos_status", ["notarized", "unverified"])
def test_repair_requirements_are_in_the_production_publish_set(macos_status: str) -> None:
    payload = set(release_candidate.payload_asset_names(VERSION, macos_status))
    published = set(release_candidate.published_asset_names(VERSION, macos_status))

    assert MODULE.REQUIRED_PAYLOAD_NAMES <= payload <= published
    assert MODULE.PROOF_ASSET_NAMES <= published


@pytest.mark.parametrize("field", ["draft", "prerelease"])
def test_repair_rejects_unpublished_release_state(tmp_path: Path, field: str) -> None:
    release_json, downloads, release = _custody(tmp_path)
    release[field] = True
    release_json.write_text(json.dumps(release), encoding="utf-8")
    with pytest.raises(RepairTargetError, match="published non-prerelease"):
        _verify(release_json, downloads)


def test_repair_rejects_mutable_release(tmp_path: Path) -> None:
    release_json, downloads, release = _custody(tmp_path)
    release["immutable"] = False
    release_json.write_text(json.dumps(release), encoding="utf-8")
    with pytest.raises(RepairTargetError, match="Immutable Releases"):
        _verify(release_json, downloads)


def test_repair_rejects_remote_digest_not_bound_by_signed_checksums(tmp_path: Path) -> None:
    release_json, downloads, release = _custody(tmp_path)
    rows = copy.deepcopy(release["assets"])
    assert isinstance(rows, list)
    row = next(item for item in rows if item["name"] == "install.sh")
    row["digest"] = f"sha256:{'f' * 64}"
    release["assets"] = rows
    release_json.write_text(json.dumps(release), encoding="utf-8")
    with pytest.raises(RepairTargetError, match="signed checksum for install.sh"):
        _verify(release_json, downloads)


def test_repair_rejects_extra_remote_asset(tmp_path: Path) -> None:
    release_json, downloads, release = _custody(tmp_path)
    rows = copy.deepcopy(release["assets"])
    assert isinstance(rows, list)
    rows.append({"name": "unexpected.bin", "digest": f"sha256:{'f' * 64}"})
    release["assets"] = rows
    release_json.write_text(json.dumps(release), encoding="utf-8")
    with pytest.raises(RepairTargetError, match="namespace differs"):
        _verify(release_json, downloads)


def test_repair_rejects_provenance_from_another_commit(tmp_path: Path) -> None:
    release_json, downloads, _release = _custody(tmp_path)
    with pytest.raises(RepairTargetError, match="commit mismatch"):
        MODULE.verify_target(
            release_json=release_json,
            download_dir=downloads,
            version=VERSION,
            commit="f" * 40,
            source_tree=SOURCE_TREE,
        )


def test_repair_rejects_unexpected_local_proof(tmp_path: Path) -> None:
    release_json, downloads, _release = _custody(tmp_path)
    (downloads / "extra").write_text("extra", encoding="utf-8")
    with pytest.raises(RepairTargetError, match="exact bounded proof set"):
        _verify(release_json, downloads)


@pytest.mark.skipif(os.name == "nt", reason="proof symlink rejection requires POSIX symlinks")
def test_repair_rejects_linked_local_proof(tmp_path: Path) -> None:
    release_json, downloads, _release = _custody(tmp_path)
    proof = downloads / "checksums.txt.sig"
    link_target = tmp_path / "linked-signature"
    link_target.write_bytes(proof.read_bytes())
    proof.unlink()
    proof.symlink_to(link_target)

    with pytest.raises(RepairTargetError, match="exact bounded proof set"):
        _verify(release_json, downloads)


@pytest.mark.skipif(os.name == "nt", reason="atomic replacement of an open file is POSIX-specific")
def test_read_regular_remains_bound_to_open_descriptor_during_path_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proof = tmp_path / "proof"
    replacement = tmp_path / "replacement"
    original_payload = b"authenticated proof\n"
    replacement_payload = b"swapped pathname\n"
    proof.write_bytes(original_payload)
    replacement.write_bytes(replacement_payload)
    real_read = MODULE.os.read
    swapped = False

    def swap_then_read(descriptor: int, size: int) -> bytes:
        nonlocal swapped
        if not swapped:
            replacement.replace(proof)
            swapped = True
        return real_read(descriptor, size)

    monkeypatch.setattr(MODULE.os, "read", swap_then_read)

    with pytest.raises(RepairTargetError, match="changed while it was read"):
        MODULE._read_regular(proof, label="proof", maximum=1024)
    assert swapped
    assert proof.read_bytes() == replacement_payload


@pytest.mark.skipif(os.name == "nt", reason="proof symlink rejection requires POSIX symlinks")
def test_read_regular_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_bytes(b"proof\n")
    proof = tmp_path / "proof"
    proof.symlink_to(target)

    with pytest.raises(RepairTargetError, match="regular nonsymlink"):
        MODULE._read_regular(proof, label="proof", maximum=1024)


def test_read_regular_rejects_oversize_before_reading(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proof = tmp_path / "proof"
    proof.write_bytes(b"x" * 17)

    def unexpected_read(_descriptor: int, _size: int) -> bytes:
        raise AssertionError("oversized proof must not be read")

    monkeypatch.setattr(MODULE.os, "read", unexpected_read)

    with pytest.raises(RepairTargetError, match="invalid size: 17"):
        MODULE._read_regular(proof, label="proof", maximum=16)


@pytest.mark.skipif(os.name == "nt", reason="atomic replacement of an open file is POSIX-specific")
def test_repair_rejects_proof_swapped_after_directory_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release_json, downloads, _release = _custody(tmp_path)
    proof = downloads / "checksums.txt.sig"
    replacement = tmp_path / "replacement"
    replacement.write_bytes(proof.read_bytes())
    real_snapshot = MODULE._download_snapshot

    def snapshot_then_swap(path: Path):
        snapshot = real_snapshot(path)
        replacement.replace(proof)
        return snapshot

    monkeypatch.setattr(MODULE, "_download_snapshot", snapshot_then_swap)

    with pytest.raises(RepairTargetError, match="changed before it was read"):
        _verify(release_json, downloads)


def test_repair_rejects_directory_mutation_after_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release_json, downloads, _release = _custody(tmp_path)
    real_read_regular = MODULE._read_regular
    mutated = False

    def read_then_mutate(path: Path, **kwargs):
        nonlocal mutated
        payload = real_read_regular(path, **kwargs)
        if path.parent == downloads and not mutated:
            (downloads / "late-extra").write_bytes(b"extra\n")
            mutated = True
        return payload

    monkeypatch.setattr(MODULE, "_read_regular", read_then_mutate)

    with pytest.raises(RepairTargetError, match="directory changed during verification"):
        _verify(release_json, downloads)
    assert mutated


def test_repair_takes_one_directory_enumeration_when_views_would_change(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    release_json, downloads, _release = _custody(tmp_path)
    original_iterdir = Path.iterdir
    first_view = tuple(original_iterdir(downloads))
    calls = 0

    def changing_iterdir(path: Path):
        nonlocal calls
        if path != downloads:
            return original_iterdir(path)
        calls += 1
        if calls == 1:
            return iter(first_view)
        extra = downloads / "late-extra"
        extra.write_bytes(b"extra\n")
        return iter((*first_view, extra))

    monkeypatch.setattr(Path, "iterdir", changing_iterdir)

    _verify(release_json, downloads)

    assert calls == 1


def test_workflow_repair_is_expiry_independent_and_nonpublishing() -> None:
    workflow = yaml.load(
        (ROOT / ".github/workflows/release.yaml").read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )
    assert workflow["concurrency"] == {
        "group": "release-${{ github.repository }}",
        "cancel-in-progress": "false",
    }
    assert "repair-channel" in workflow["on"]["workflow_dispatch"]["inputs"]["operation"]["options"]
    confirmation = workflow["on"]["workflow_dispatch"]["inputs"]["immutable_releases_confirmed"]
    assert confirmation["required"] == "false"
    assert confirmation["default"] == "false"
    repair = workflow["jobs"]["repair-stable-channel"]
    assert "concurrency" not in repair
    assert "needs" not in repair
    assert repair["if"] == "inputs.operation == 'repair-channel'"
    assert repair["permissions"] == {"contents": "write", "id-token": "write"}
    rendered = json.dumps(repair, sort_keys=True)
    assert "immutable_releases_confirmed" not in rendered
    assert "actions/download-artifact@" not in rendered
    assert "scripts/download_release_custody.py" in rendered
    assert "scripts/verify-release-channel-target.py" in rendered
    assert "scripts/publish-release-channel.sh" in rendered
    custody_helper = (ROOT / "scripts/download_release_custody.py").read_text(encoding="utf-8")
    assert '"upgrade-manifest.json"' in custody_helper
    assert '"RELEASE_CHANNEL_REPAIR": "1"' in rendered
    assert "gh release create" not in rendered
    assert "gh release upload" not in rendered
    authenticate = next(
        step["run"] for step in repair["steps"] if step.get("name") == "Authenticate immutable release custody"
    )
    assert authenticate.index("scripts/verify-sigstore-blob.py") < authenticate.index(
        "scripts/verify-release-channel-target.py"
    )
