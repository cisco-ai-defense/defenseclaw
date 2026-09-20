"""Adversarial tests for the pure generated telemetry Go preflight."""

from __future__ import annotations

import dataclasses
import importlib.util
import sys
from collections.abc import Sequence
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
COORDINATOR = ROOT / "scripts/telemetry_go_output_coordinator.py"
MATERIALIZED_DIGEST = "1" * 64
CANDIDATE_DIGEST = "2" * 64
SYMBOL_DIGEST = "3" * 64
DECLARATION_COUNT = 32
DECLARATION_PARTITION = (8, 4, 4, 4, 4, 8, 0)


class _ExplodingSequence(Sequence[Any]):
    def __init__(self, length: int):
        self.length = length

    def __len__(self) -> int:
        return self.length

    def __getitem__(self, index: int) -> Any:
        raise AssertionError(f"oversized sequence was accessed at {index}")


def _load_module() -> ModuleType:
    module_name = "telemetry_go_output_coordinator_test"
    spec = importlib.util.spec_from_file_location(module_name, COORDINATOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def module() -> ModuleType:
    return _load_module()


@pytest.fixture(scope="module")
def candidate(module: ModuleType) -> dict[str, Any]:
    keys = tuple(
        module.GoDeclarationKey(
            "fixture",
            f"owner#{index:04d}" if index < 5 else f"declaration.{index:04d}",
        )
        for index in range(DECLARATION_COUNT)
    )
    inventories = []
    offset = 0
    for path, count in zip(module.EXACT_GO_OUTPUT_PATHS, DECLARATION_PARTITION, strict=True):
        inventories.append(module.GoFileDeclarationInventory(path, keys[offset : offset + count]))
        offset += count
    header = module.canonical_go_header(MATERIALIZED_DIGEST, CANDIDATE_DIGEST, SYMBOL_DIGEST)
    outputs = tuple(
        module.RenderedGoOutput(
            path,
            header + f"package observability\n\n// {index}\n".encode("ascii"),
            module.OWNERSHIP_MARKER,
        )
        for index, path in enumerate(module.EXACT_GO_OUTPUT_PATHS)
    )
    return {"keys": keys, "inventories": tuple(inventories), "outputs": outputs}


def _preflight(module: ModuleType, candidate: dict[str, Any], **overrides: Any) -> Any:
    values = {
        "outputs": candidate["outputs"],
        "declaration_inventory": candidate["inventories"],
        "expected_declaration_keys": candidate["keys"],
        "materialized_view_sha256": MATERIALIZED_DIGEST,
        "candidate_render_index_sha256": CANDIDATE_DIGEST,
        "go_symbol_table_sha256": SYMBOL_DIGEST,
    }
    values.update(overrides)
    return module.preflight_go_outputs(**values)


def test_complete_candidate_is_immutable_and_deterministic(
    module: ModuleType,
    candidate: dict[str, Any],
) -> None:
    first = _preflight(module, candidate)
    second = _preflight(
        module,
        candidate,
        outputs=tuple(reversed(candidate["outputs"])),
        declaration_inventory=tuple(reversed(candidate["inventories"])),
    )

    assert first == second
    assert dataclasses.is_dataclass(first)
    assert first.outputs == tuple(sorted(first.outputs, key=lambda item: module.EXACT_GO_OUTPUT_PATHS.index(item.path)))
    assert tuple(output.path for output in first.outputs) == module.EXACT_GO_OUTPUT_PATHS
    assert tuple(len(output.declaration_keys) for output in first.outputs) == DECLARATION_PARTITION
    assert sum("#" in key.source_id for key in candidate["keys"]) == 5
    assert first.metadata.format_version == 1
    assert first.metadata.materialized_view_sha256 == MATERIALIZED_DIGEST
    assert len(first.metadata.manifest_sha256) == 64
    with pytest.raises(dataclasses.FrozenInstanceError):
        first.metadata.format_version = 2


def test_explicit_empty_candidate_is_valid_but_cannot_carry_file_inventory(
    module: ModuleType,
    candidate: dict[str, Any],
) -> None:
    result = _preflight(module, candidate, outputs=(), declaration_inventory=())

    assert result.outputs == ()
    assert len(result.metadata.manifest_sha256) == 64
    with pytest.raises(module.GoOutputPreflightError, match="empty Go candidate"):
        _preflight(module, candidate, outputs=(), declaration_inventory=candidate["inventories"])


@pytest.mark.parametrize("kept", [1, 6])
def test_strict_output_subset_is_rejected(
    module: ModuleType,
    candidate: dict[str, Any],
    kept: int,
) -> None:
    with pytest.raises(module.GoOutputPreflightError, match="all seven exact paths or none"):
        _preflight(module, candidate, outputs=candidate["outputs"][:kept])


def test_extra_internal_output_path_is_rejected(module: ModuleType, candidate: dict[str, Any]) -> None:
    extra = module.RenderedGoOutput(
        "internal/observability/zz_generated_telemetry_extra.go",
        candidate["outputs"][0].payload,
        module.OWNERSHIP_MARKER,
    )
    outputs = (*candidate["outputs"][:-1], extra)

    with pytest.raises(module.GoOutputPreflightError, match="extra internal path"):
        _preflight(module, candidate, outputs=outputs)


def test_duplicate_output_path_is_rejected(module: ModuleType, candidate: dict[str, Any]) -> None:
    outputs = (*candidate["outputs"][:-1], candidate["outputs"][0])

    with pytest.raises(module.GoOutputPreflightError, match="duplicate path"):
        _preflight(module, candidate, outputs=outputs)


@pytest.mark.parametrize(
    ("mutation", "expected"),
    [
        (lambda output: dataclasses.replace(output, mode=0o755), "mode is not 0644"),
        (lambda output: dataclasses.replace(output, marker=b"// handwritten"), "marker is not canonical"),
        (lambda output: dataclasses.replace(output, payload=bytearray(output.payload)), "not immutable bytes"),
    ],
)
def test_payload_mode_and_ownership_are_strict(
    module: ModuleType,
    candidate: dict[str, Any],
    mutation: Any,
    expected: str,
) -> None:
    outputs = list(candidate["outputs"])
    outputs[0] = mutation(outputs[0])

    with pytest.raises(module.GoOutputPreflightError, match=expected):
        _preflight(module, candidate, outputs=tuple(outputs))


def test_malformed_digest_header_is_rejected(module: ModuleType, candidate: dict[str, Any]) -> None:
    outputs = list(candidate["outputs"])
    outputs[0] = dataclasses.replace(
        outputs[0],
        payload=outputs[0].payload.replace(MATERIALIZED_DIGEST.encode("ascii"), b"z" * 64, 1),
    )

    with pytest.raises(module.GoOutputPreflightError, match="canonical SHA-256"):
        _preflight(module, candidate, outputs=tuple(outputs))


def test_mixed_digest_headers_are_rejected(module: ModuleType, candidate: dict[str, Any]) -> None:
    outputs = list(candidate["outputs"])
    mixed_header = module.canonical_go_header("4" * 64, CANDIDATE_DIGEST, SYMBOL_DIGEST)
    old_header = module.canonical_go_header(MATERIALIZED_DIGEST, CANDIDATE_DIGEST, SYMBOL_DIGEST)
    outputs[0] = dataclasses.replace(outputs[0], payload=outputs[0].payload.replace(old_header, mixed_header, 1))

    with pytest.raises(module.GoOutputPreflightError, match="mixed digest headers"):
        _preflight(module, candidate, outputs=tuple(outputs))


def test_uniform_but_stale_digest_headers_are_rejected(module: ModuleType, candidate: dict[str, Any]) -> None:
    stale_header = module.canonical_go_header("4" * 64, CANDIDATE_DIGEST, SYMBOL_DIGEST)
    current_header = module.canonical_go_header(MATERIALIZED_DIGEST, CANDIDATE_DIGEST, SYMBOL_DIGEST)
    outputs = tuple(
        dataclasses.replace(output, payload=output.payload.replace(current_header, stale_header, 1))
        for output in candidate["outputs"]
    )

    with pytest.raises(module.GoOutputPreflightError, match="headers are stale"):
        _preflight(module, candidate, outputs=outputs)


def test_oversized_header_is_rejected(module: ModuleType, candidate: dict[str, Any]) -> None:
    outputs = list(candidate["outputs"])
    oversized = module.OWNERSHIP_MARKER + b"\n" + b"x" * module.MAX_HEADER_BYTES + b"\n\npackage observability\n"
    outputs[0] = dataclasses.replace(outputs[0], payload=oversized)

    with pytest.raises(module.GoOutputPreflightError, match="missing or oversized"):
        _preflight(module, candidate, outputs=tuple(outputs))


@pytest.mark.parametrize("body", [b"", b"package other\n"])
def test_header_must_be_followed_by_exact_observability_package(
    module: ModuleType,
    candidate: dict[str, Any],
    body: bytes,
) -> None:
    outputs = list(candidate["outputs"])
    header = module.canonical_go_header(MATERIALIZED_DIGEST, CANDIDATE_DIGEST, SYMBOL_DIGEST)
    outputs[0] = dataclasses.replace(outputs[0], payload=header + body)

    with pytest.raises(module.GoOutputPreflightError, match="package observability"):
        _preflight(module, candidate, outputs=tuple(outputs))


def test_missing_declaration_file_inventory_is_rejected(module: ModuleType, candidate: dict[str, Any]) -> None:
    with pytest.raises(module.GoOutputPreflightError, match="cover all seven exact paths"):
        _preflight(module, candidate, declaration_inventory=candidate["inventories"][:-1])


def test_duplicate_declaration_file_inventory_is_rejected(module: ModuleType, candidate: dict[str, Any]) -> None:
    inventories = (*candidate["inventories"][:-1], candidate["inventories"][0])

    with pytest.raises(module.GoOutputPreflightError, match="duplicate path"):
        _preflight(module, candidate, declaration_inventory=inventories)


def test_declaration_partition_is_derived_from_the_callers_complete_plan(
    module: ModuleType, candidate: dict[str, Any]
) -> None:
    inventories = list(candidate["inventories"])
    ids = inventories[0]
    catalog = inventories[1]
    moved = ids.declaration_keys[-1]
    inventories[0] = dataclasses.replace(ids, declaration_keys=ids.declaration_keys[:-1])
    inventories[1] = dataclasses.replace(catalog, declaration_keys=(*catalog.declaration_keys, moved))

    result = _preflight(module, candidate, declaration_inventory=tuple(inventories))
    assert result.outputs[0].declaration_keys == ids.declaration_keys[:-1]
    assert result.outputs[1].declaration_keys == (*catalog.declaration_keys, moved)


def test_duplicate_declaration_key_is_rejected(module: ModuleType, candidate: dict[str, Any]) -> None:
    inventories = list(candidate["inventories"])
    ids = inventories[0]
    duplicated = (*ids.declaration_keys[:-1], ids.declaration_keys[0])
    inventories[0] = dataclasses.replace(ids, declaration_keys=duplicated)

    with pytest.raises(module.GoOutputPreflightError, match="missing or duplicate"):
        _preflight(module, candidate, declaration_inventory=tuple(inventories))


def test_missing_expected_declaration_key_is_rejected(module: ModuleType, candidate: dict[str, Any]) -> None:
    inventories = list(candidate["inventories"])
    ids = inventories[0]
    replacement = module.GoDeclarationKey("fixture", "declaration.foreign")
    inventories[0] = dataclasses.replace(ids, declaration_keys=(*ids.declaration_keys[:-1], replacement))

    with pytest.raises(module.GoOutputPreflightError, match="caller-expected exact keys"):
        _preflight(module, candidate, declaration_inventory=tuple(inventories))


def test_duplicate_expected_declaration_key_is_rejected(module: ModuleType, candidate: dict[str, Any]) -> None:
    keys = (*candidate["keys"][:-1], candidate["keys"][0])

    with pytest.raises(module.GoOutputPreflightError, match="contains duplicates"):
        _preflight(module, candidate, expected_declaration_keys=keys)


@pytest.mark.parametrize(
    ("override", "expected"),
    [
        ({"outputs": _ExplodingSequence(8)}, "all seven exact paths or none"),
        ({"declaration_inventory": _ExplodingSequence(8)}, "cover all seven exact paths"),
        ({"expected_declaration_keys": _ExplodingSequence(100_001)}, "safety bound"),
    ],
)
def test_oversized_sequences_fail_before_iteration(
    module: ModuleType,
    candidate: dict[str, Any],
    override: dict[str, Any],
    expected: str,
) -> None:
    with pytest.raises(module.GoOutputPreflightError, match=expected):
        _preflight(module, candidate, **override)
