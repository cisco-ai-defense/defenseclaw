# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib.util
import os
import stat
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / "scripts" / "generate_telemetry_registry.py"


def _load_generator() -> ModuleType:
    name = "telemetry_output_writer_test_generator"
    spec = importlib.util.spec_from_file_location(name, GENERATOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def generator() -> ModuleType:
    return _load_generator()


def _outputs(generator: ModuleType) -> dict[Path, bytes]:
    logical = {
        Path(path): (f'{{"logical":{path!r}}}\n').encode()
        for path in generator.runtime_assets.LOGICAL_TO_ENCODED
    }
    logical.update(
        {
            Path(path): (f"// generated {path}\n").encode()
            for path in generator.GO_CANDIDATE_OUTPUT_PATHS
        }
    )
    return logical


def _repository(tmp_path: Path) -> Path:
    root = tmp_path / "repository"
    root.mkdir()
    return root


def test_physical_inventory_is_exact_and_deterministic(generator: ModuleType) -> None:
    outputs = _outputs(generator)
    first = generator._physical_outputs(outputs)
    second = generator._physical_outputs(outputs)

    assert first == second
    assert set(first) == generator.REPOSITORY_PHYSICAL_OUTPUT_PATHS
    for logical, encoded in generator.runtime_assets.LOGICAL_TO_ENCODED.items():
        assert generator.runtime_assets.decode_canonical_gzip(first[encoded]) == outputs[Path(logical)]
    for path in generator.GO_CANDIDATE_OUTPUT_PATHS:
        assert first[path] == outputs[Path(path)]


def test_writer_publishes_exact_files_and_removes_only_retired_outputs(
    generator: ModuleType,
    tmp_path: Path,
) -> None:
    root = _repository(tmp_path)
    outputs = _outputs(generator)
    unrelated = root / "schemas/telemetry/generated/manual-note.txt"
    unrelated.parent.mkdir(parents=True)
    unrelated.write_text("preserve me", encoding="utf-8")
    for relative in generator.RETIRED_REPOSITORY_OUTPUT_PATHS:
        retired = root / relative
        retired.parent.mkdir(parents=True, exist_ok=True)
        retired.write_text("retired", encoding="utf-8")

    with pytest.raises(generator.RegistryError, match="extra=.*output-manifest.json"):
        generator.check_outputs(root, outputs)
    generator.write_outputs(root, outputs)
    generator.check_outputs(root, outputs)

    assert unrelated.read_text(encoding="utf-8") == "preserve me"
    assert all(not (root / relative).exists() for relative in generator.RETIRED_REPOSITORY_OUTPUT_PATHS)
    for relative, payload in generator._physical_outputs(outputs).items():
        target = root / relative
        assert target.read_bytes() == payload
        assert stat.S_IMODE(target.stat().st_mode) == 0o644


@pytest.mark.parametrize("drift", ["missing", "stale", "mode"])
def test_checker_reports_file_drift(
    generator: ModuleType,
    tmp_path: Path,
    drift: str,
) -> None:
    root = _repository(tmp_path)
    outputs = _outputs(generator)
    generator.write_outputs(root, outputs)
    relative = sorted(generator.REPOSITORY_PHYSICAL_OUTPUT_PATHS)[0]
    target = root / relative
    if drift == "missing":
        target.unlink()
    elif drift == "stale":
        target.write_bytes(b"stale\n")
    else:
        target.chmod(0o600)

    with pytest.raises(generator.RegistryError, match=rf"{drift}={relative}"):
        generator.check_outputs(root, outputs)


@pytest.mark.parametrize(
    "relative",
    [
        "internal/observability/zz_generated_telemetry_unowned.go",
        "schemas/telemetry/runtime/compatibility/unowned.json.gz",
    ],
)
def test_checker_and_writer_reject_unowned_generated_outputs(
    generator: ModuleType,
    tmp_path: Path,
    relative: str,
) -> None:
    root = _repository(tmp_path)
    outputs = _outputs(generator)
    generator.write_outputs(root, outputs)
    extra = root / relative
    extra.parent.mkdir(parents=True, exist_ok=True)
    extra.write_bytes(b"unowned")

    with pytest.raises(generator.RegistryError, match=rf"extra={relative}"):
        generator.check_outputs(root, outputs)
    with pytest.raises(generator.RegistryError, match="generated output drift: extra="):
        generator.write_outputs(root, outputs)
    assert extra.read_bytes() == b"unowned"


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unavailable")
def test_writer_rejects_symlinked_output_parent(
    generator: ModuleType,
    tmp_path: Path,
) -> None:
    root = _repository(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    runtime_parent = root / "schemas/telemetry"
    runtime_parent.mkdir(parents=True)
    (runtime_parent / "runtime").symlink_to(outside, target_is_directory=True)

    with pytest.raises(generator.RegistryError, match="not a real directory"):
        generator.write_outputs(root, _outputs(generator))
    assert list(outside.iterdir()) == []


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks unavailable")
def test_writer_refuses_symlinked_retired_file(
    generator: ModuleType,
    tmp_path: Path,
) -> None:
    root = _repository(tmp_path)
    outside = tmp_path / "outside.json"
    outside.write_text("do not remove", encoding="utf-8")
    retired = root / sorted(generator.RETIRED_REPOSITORY_OUTPUT_PATHS)[0]
    retired.parent.mkdir(parents=True)
    retired.symlink_to(outside)

    with pytest.raises(generator.RegistryError, match="not a regular file"):
        generator.write_outputs(root, _outputs(generator))
    assert outside.read_text(encoding="utf-8") == "do not remove"


def test_failed_replace_cleans_its_temporary_file(
    generator: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = _repository(tmp_path)

    def fail_replace(_source: Path, _target: Path) -> None:
        raise OSError("simulated replace failure")

    monkeypatch.setattr(generator.os, "replace", fail_replace)
    with pytest.raises(OSError, match="simulated replace failure"):
        generator.write_outputs(root, _outputs(generator))
    assert list(root.rglob("*.tmp")) == []


def test_writer_requires_the_exact_logical_inventory(
    generator: ModuleType,
) -> None:
    outputs = _outputs(generator)
    outputs.pop(next(iter(outputs)))
    with pytest.raises(generator.RegistryError, match="inventory is partial or substituted"):
        generator._physical_outputs(outputs)
