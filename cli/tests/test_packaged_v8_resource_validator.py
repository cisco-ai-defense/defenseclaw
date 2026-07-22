# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR_PATH = ROOT / "scripts" / "validate_packaged_v8_resources.py"
SPEC = importlib.util.spec_from_file_location("validate_packaged_v8_resources", VALIDATOR_PATH)
assert SPEC and SPEC.loader
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


def _write_exact_inventory(package_root: Path) -> None:
    for relative, names in validator.EXPECTED_V8_RESOURCES.items():
        directory = package_root / relative
        directory.mkdir(parents=True)
        for name in names:
            (directory / name).write_bytes(b"fixture\n")


def test_exact_packaged_v8_inventory_is_accepted(tmp_path: Path) -> None:
    package_root = tmp_path / "site-packages" / "defenseclaw"
    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir()
    _write_exact_inventory(package_root)

    validator._validate_inventory(package_root, runtime_root, label="staged")


def test_nested_entry_cannot_impersonate_a_packaged_v8_file(tmp_path: Path) -> None:
    package_root = tmp_path / "site-packages" / "defenseclaw"
    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir()
    _write_exact_inventory(package_root)
    nested = package_root / "_data/config/v8/observability.md"
    nested.unlink()
    nested.mkdir()
    (nested / "payload").write_bytes(b"not a regular resource\n")

    with pytest.raises(validator.PackagedV8ResourceError, match=r"non_files=.*observability\.md"):
        validator._validate_inventory(package_root, runtime_root, label="staged")


def test_runtime_fallback_tree_is_rejected(tmp_path: Path) -> None:
    package_root = tmp_path / "site-packages" / "defenseclaw"
    runtime_root = tmp_path / "runtime"
    _write_exact_inventory(package_root)
    (runtime_root / "Lib/schemas").mkdir(parents=True)

    with pytest.raises(validator.PackagedV8ResourceError, match="Lib/schemas fallback"):
        validator._validate_inventory(package_root, runtime_root, label="packaged")


def test_public_validator_rejects_nested_import_shadow_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    site_packages = tmp_path / "site-packages"
    canonical_root = site_packages / "defenseclaw"
    shadow_root = site_packages / "vendor" / "defenseclaw"
    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir()
    _write_exact_inventory(canonical_root)
    _write_exact_inventory(shadow_root)
    monkeypatch.setattr(validator.resources, "files", lambda package: shadow_root)

    with pytest.raises(
        validator.PackagedV8ResourceError,
        match="did not resolve to the canonical staged package root",
    ):
        validator.validate_packaged_v8_resources(
            site_packages,
            runtime_root,
            label="staged",
        )


def test_public_validator_rejects_canonical_package_symlink_indirection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    site_packages = tmp_path / "site-packages"
    canonical_root = site_packages / "defenseclaw"
    runtime_root = tmp_path / "runtime"
    runtime_root.mkdir()
    _write_exact_inventory(canonical_root)
    monkeypatch.setattr(validator.resources, "files", lambda package: canonical_root)
    real_is_symlink = Path.is_symlink
    monkeypatch.setattr(
        Path,
        "is_symlink",
        lambda path: path == canonical_root or real_is_symlink(path),
    )

    with pytest.raises(
        validator.PackagedV8ResourceError,
        match="package root uses symlink or junction indirection",
    ):
        validator.validate_packaged_v8_resources(
            site_packages,
            runtime_root,
            label="packaged",
        )
