# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import io
import json
import shutil
import tarfile
import zipfile
from pathlib import Path

import pytest
from defenseclaw.extension_fingerprint import (
    REFERENCE_PACKAGE_PATH,
    ExtensionFingerprintError,
    canonical_reference_bytes,
    fingerprint_repository_runtime,
)

from scripts import extension_runtime_fingerprint
from scripts.extension_runtime_fingerprint import stage, verify_archive, verify_contract

ROOT = Path(__file__).resolve().parents[2]


def _write_source_runtime(root: Path, *, index: str = "export default function register() {}\n") -> None:
    (root / "dist" / "policy").mkdir(parents=True)
    (root / "node_modules" / "js-yaml").mkdir(parents=True)
    (root / "node_modules" / "argparse").mkdir(parents=True)
    (root / "src").mkdir()
    (root / "package.json").write_text(
        json.dumps({"name": "defenseclaw", "version": "9.8.7", "main": "dist/index.js"}),
        encoding="utf-8",
    )
    (root / "openclaw.plugin.json").write_text(
        json.dumps({"id": "defenseclaw", "name": "DefenseClaw Security"}),
        encoding="utf-8",
    )
    (root / "dist" / "index.js").write_text(index, encoding="utf-8")
    (root / "dist" / "policy" / "default.json").write_text("{}\n", encoding="utf-8")
    (root / "node_modules" / "js-yaml" / "index.js").write_text("export {};\n", encoding="utf-8")
    (root / "node_modules" / "argparse" / "index.js").write_text("export {};\n", encoding="utf-8")
    (root / "src" / "not-published.ts").write_text("// source only\n", encoding="utf-8")
    (root / "package-lock.json").write_text("{}\n", encoding="utf-8")


def _write_runtime_archive(source: Path, archive: Path) -> None:
    with tarfile.open(archive, mode="w:gz") as output:
        for relative in (
            "package.json",
            "openclaw.plugin.json",
            "dist",
            "node_modules/js-yaml",
            "node_modules/argparse",
        ):
            output.add(source / relative, arcname=relative)


def _write_wheel(reference: Path, wheel: Path) -> None:
    with zipfile.ZipFile(wheel, mode="w") as output:
        output.writestr(f"defenseclaw/{REFERENCE_PACKAGE_PATH}", reference.read_bytes())


def _write_tar_members(archive: Path, members: list[tuple[str, bytes]]) -> None:
    with tarfile.open(archive, mode="w:gz") as output:
        for name, payload in members:
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            output.addfile(info, io.BytesIO(payload))


def test_release_contract_binds_wheel_reference_to_exact_plugin_archive(tmp_path: Path) -> None:
    source = tmp_path / "source"
    _write_source_runtime(source)
    reference = tmp_path / "extension-runtime-fingerprint.json"
    archive = tmp_path / "defenseclaw-plugin-9.8.7.tar.gz"
    wheel = tmp_path / "defenseclaw-9.8.7-py3-none-any.whl"

    expected = fingerprint_repository_runtime(source)
    staged = stage(source, reference)
    _write_runtime_archive(source, archive)
    _write_wheel(reference, wheel)

    assert staged == expected
    assert reference.read_bytes() == canonical_reference_bytes(expected)
    assert len(reference.read_bytes()) < 256
    verify_archive(source, reference, archive)
    verify_contract(source, reference, archive, wheel)


def test_atomic_write_does_not_unlink_reused_temporary_name_after_publish(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "extension-runtime-fingerprint.json"
    temporary = output.with_name(f".{output.name}.{extension_runtime_fingerprint.os.getpid()}.tmp")
    real_replace = extension_runtime_fingerprint.os.replace

    def replace_and_reuse(source: Path, destination: Path) -> None:
        real_replace(source, destination)
        temporary.write_bytes(b"unrelated")

    monkeypatch.setattr(extension_runtime_fingerprint.os, "replace", replace_and_reuse)

    extension_runtime_fingerprint._write_atomic(output, b"published")

    assert output.read_bytes() == b"published"
    assert temporary.read_bytes() == b"unrelated"


def test_atomic_write_does_not_unlink_preexisting_temporary_name(tmp_path: Path) -> None:
    output = tmp_path / "extension-runtime-fingerprint.json"
    temporary = output.with_name(f".{output.name}.{extension_runtime_fingerprint.os.getpid()}.tmp")
    temporary.write_bytes(b"preexisting")

    with pytest.raises(FileExistsError):
        extension_runtime_fingerprint._write_atomic(output, b"published")

    assert not output.exists()
    assert temporary.read_bytes() == b"preexisting"


def test_release_contract_rejects_plugin_bytes_changed_after_wheel_staging(tmp_path: Path) -> None:
    source = tmp_path / "source"
    _write_source_runtime(source)
    reference = tmp_path / "extension-runtime-fingerprint.json"
    wheel = tmp_path / "defenseclaw-9.8.7-py3-none-any.whl"
    stage(source, reference)
    _write_wheel(reference, wheel)

    tampered = tmp_path / "tampered"
    shutil.copytree(source, tampered)
    (tampered / "dist" / "index.js").write_text("eval(untrustedInput)\n", encoding="utf-8")
    archive = tmp_path / "defenseclaw-plugin-9.8.7.tar.gz"
    _write_runtime_archive(tampered, archive)

    with pytest.raises(ExtensionFingerprintError, match="plugin archive"):
        verify_contract(source, reference, archive, wheel)


def test_release_contract_rejects_wheel_reference_for_different_runtime(tmp_path: Path) -> None:
    source = tmp_path / "source"
    _write_source_runtime(source)
    reference = tmp_path / "extension-runtime-fingerprint.json"
    archive = tmp_path / "defenseclaw-plugin-9.8.7.tar.gz"
    stage(source, reference)
    _write_runtime_archive(source, archive)

    other = tmp_path / "other"
    _write_source_runtime(other, index="export default function changed() {}\n")
    other_reference = tmp_path / "other-reference.json"
    stage(other, other_reference)
    wheel = tmp_path / "defenseclaw-9.8.7-py3-none-any.whl"
    _write_wheel(other_reference, wheel)

    with pytest.raises(ExtensionFingerprintError, match="wheel extension fingerprint"):
        verify_contract(source, reference, archive, wheel)


def test_repository_fingerprint_normalizes_disappearing_walk_entries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source"
    _write_source_runtime(source)
    disappearing = source / "dist" / "index.js"
    real_lstat = Path.lstat

    def disappear_during_walk(path: Path):
        if path == disappearing:
            raise FileNotFoundError("removed during inventory")
        return real_lstat(path)

    monkeypatch.setattr(Path, "lstat", disappear_during_walk)

    with pytest.raises(ExtensionFingerprintError, match="inventory is not fully readable"):
        fingerprint_repository_runtime(source)


def test_plugin_archive_rejects_entry_count_before_materializing_all_members(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive = tmp_path / "too-many.tar.gz"
    _write_tar_members(archive, [(f"dist/{index}.js", b"") for index in range(3)])
    monkeypatch.setattr(extension_runtime_fingerprint, "_MAX_PLUGIN_ARCHIVE_ENTRIES", 2)

    with pytest.raises(ExtensionFingerprintError, match="entry count"):
        extension_runtime_fingerprint._fingerprint_archive(archive)


def test_plugin_archive_rejects_per_member_and_cumulative_expansion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    oversized = tmp_path / "oversized-member.tar.gz"
    _write_tar_members(oversized, [("dist/bomb.js", b"x" * 33)])
    monkeypatch.setattr(extension_runtime_fingerprint, "_MAX_PLUGIN_ARCHIVE_MEMBER_BYTES", 32)
    with pytest.raises(ExtensionFingerprintError, match="member exceeds"):
        extension_runtime_fingerprint._fingerprint_archive(oversized)

    cumulative = tmp_path / "cumulative-expansion.tar.gz"
    _write_tar_members(cumulative, [("dist/one.js", b"x" * 20), ("dist/two.js", b"x" * 20)])
    monkeypatch.setattr(extension_runtime_fingerprint, "_MAX_PLUGIN_ARCHIVE_MEMBER_BYTES", 32)
    monkeypatch.setattr(extension_runtime_fingerprint, "_MAX_PLUGIN_ARCHIVE_EXPANDED_BYTES", 32)
    with pytest.raises(ExtensionFingerprintError, match="archive exceeds the expanded"):
        extension_runtime_fingerprint._fingerprint_archive(cumulative)


def test_plugin_archive_rejects_compressed_stream_before_opening(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archive = tmp_path / "compressed-limit.tar.gz"
    _write_tar_members(archive, [("dist/index.js", b"x" * 32)])
    monkeypatch.setattr(
        extension_runtime_fingerprint,
        "_MAX_PLUGIN_ARCHIVE_COMPRESSED_BYTES",
        archive.stat().st_size - 1,
    )

    with pytest.raises(ExtensionFingerprintError, match="compressed size"):
        extension_runtime_fingerprint._fingerprint_archive(archive)


def test_wheel_rejects_entry_and_member_bounds_before_reading_reference(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wheel = tmp_path / "bounded.whl"
    with zipfile.ZipFile(wheel, mode="w", compression=zipfile.ZIP_STORED) as output:
        output.writestr("first", b"")
        output.writestr("second", b"x" * 33)

    monkeypatch.setattr(extension_runtime_fingerprint, "_MAX_WHEEL_ENTRIES", 1)
    with monkeypatch.context() as zip_guard:
        zip_guard.setattr(
            zipfile,
            "ZipFile",
            lambda *_args, **_kwargs: pytest.fail("ZipFile materialized entries before the preflight count bound"),
        )
        with pytest.raises(ExtensionFingerprintError, match="entry count"):
            extension_runtime_fingerprint._wheel_reference(wheel)

    monkeypatch.setattr(extension_runtime_fingerprint, "_MAX_WHEEL_ENTRIES", 2)
    monkeypatch.setattr(extension_runtime_fingerprint, "_MAX_WHEEL_MEMBER_BYTES", 32)
    with pytest.raises(ExtensionFingerprintError, match="member exceeds"):
        extension_runtime_fingerprint._wheel_reference(wheel)


def test_wheel_rejects_cumulative_compressed_and_expanded_bounds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wheel = tmp_path / "cumulative.whl"
    with zipfile.ZipFile(wheel, mode="w", compression=zipfile.ZIP_DEFLATED) as output:
        output.writestr("first", b"a" * 20)
        output.writestr("second", b"b" * 20)

    with zipfile.ZipFile(wheel) as archive:
        members = archive.infolist()
    compressed_total = sum(info.compress_size for info in members)
    monkeypatch.setattr(extension_runtime_fingerprint, "_MAX_WHEEL_COMPRESSED_BYTES", compressed_total - 1)
    with pytest.raises(ExtensionFingerprintError, match="compressed size"):
        extension_runtime_fingerprint._wheel_reference(wheel)

    monkeypatch.setattr(extension_runtime_fingerprint, "_MAX_WHEEL_COMPRESSED_BYTES", compressed_total)
    monkeypatch.setattr(extension_runtime_fingerprint, "_MAX_WHEEL_EXPANDED_BYTES", 39)
    with pytest.raises(ExtensionFingerprintError, match="expanded size"):
        extension_runtime_fingerprint._wheel_reference(wheel)


def test_make_and_release_workflow_enforce_extension_artifact_contract() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    workflow = (ROOT / ".github/workflows/release.yaml").read_text(encoding="utf-8")
    windows_workflow = (ROOT / ".github/workflows/windows-native.yml").read_text(encoding="utf-8")
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8")
    tsconfig = json.loads((ROOT / "extensions/defenseclaw/tsconfig.json").read_text(encoding="utf-8"))

    assert "_stage-extension-fingerprint: plugin" in makefile
    assert "dist-cli: _bundle-data _stage-extension-fingerprint" in makefile
    assert "dist-plugin: _stage-extension-fingerprint" in makefile
    assert "scripts/extension_runtime_fingerprint.py verify-archive" in makefile
    assert "scripts/extension_runtime_fingerprint.py verify-contract" in makefile
    assert "make dist-cli dist-plugin dist-extension-contract" in workflow
    windows_package_job = windows_workflow[windows_workflow.index("  package-artifact:") :]
    assert "actions/setup-node@" in windows_package_job
    assert 'node-version: "24"' in windows_package_job
    assert tsconfig["compilerOptions"]["newLine"] == "lf"
    for path in (
        "extensions/defenseclaw/package.json",
        "extensions/defenseclaw/openclaw.plugin.json",
        "internal/configs/providers.json",
    ):
        assert f"{path} text eol=lf" in attributes
    assert '"_data/plugin/*.json"' in pyproject
