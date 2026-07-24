# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from scripts import telemetry_runtime_assets as assets

ROOT = Path(__file__).resolve().parents[2]


def test_runtime_asset_inventory_is_exact_and_stable() -> None:
    assert assets.LOGICAL_TO_ENCODED == {
        "schemas/telemetry/generated/telemetry.schema.json": (
            "schemas/telemetry/runtime/telemetry.schema.json.gz"
        ),
        "schemas/telemetry/generated/catalog.json": (
            "schemas/telemetry/runtime/catalog.json.gz"
        ),
        "schemas/telemetry/generated/compatibility/galileo-rich-v2.json": (
            "schemas/telemetry/runtime/compatibility/galileo-rich-v2.json.gz"
        ),
        "schemas/telemetry/generated/compatibility/local-observability-v1.json": (
            "schemas/telemetry/runtime/compatibility/local-observability-v1.json.gz"
        ),
        "schemas/telemetry/generated/compatibility/openinference-v1.json": (
            "schemas/telemetry/runtime/compatibility/openinference-v1.json.gz"
        ),
        "schemas/telemetry/generated/compatibility/v7-exporter-selection.json": (
            "schemas/telemetry/runtime/compatibility/v7-exporter-selection.json.gz"
        ),
    }


def test_canonical_gzip_is_deterministic_bounded_and_round_trips() -> None:
    payload = b'{"schema_version":1,"value":"person@example.test"}\n'
    first = assets.canonical_gzip(payload)
    second = assets.canonical_gzip(payload)
    assert first == second
    assert first[:10] == b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff"
    assert assets.decode_canonical_gzip(first) == payload
    with pytest.raises(assets.RuntimeAssetError, match="size limit"):
        assets.decode_canonical_gzip(first, maximum=len(payload) - 1)


@pytest.mark.parametrize("logical_path", assets.LOGICAL_TO_ENCODED)
def test_repository_runtime_assets_decode_portably(logical_path: str) -> None:
    payload = assets.read_logical_asset(ROOT, logical_path)
    assert isinstance(json.loads(payload), dict)
    assert payload.endswith(b"\n")


@pytest.mark.parametrize(
    "encoded",
    [
        b"not-gzip",
        assets.canonical_gzip(b"{}") + b"trailing",
        gzip.compress(b"{}", compresslevel=1, mtime=1),
    ],
)
def test_decoder_rejects_malformed_trailing_and_noncanonical_members(encoded: bytes) -> None:
    with pytest.raises(assets.RuntimeAssetError):
        assets.decode_canonical_gzip(encoded)


def test_decoder_rejects_corrupt_crc_and_size_trailer() -> None:
    encoded = assets.canonical_gzip(b'{"value":"exact"}\n')
    for offset in (-8, -4):
        corrupted = bytearray(encoded)
        corrupted[offset] ^= 1
        with pytest.raises(assets.RuntimeAssetError, match="malformed"):
            assets.decode_canonical_gzip(bytes(corrupted))


def test_stage_expands_exact_logical_json_names(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    destination = tmp_path / "wheel"
    expected: dict[str, bytes] = {}
    for index, (logical, encoded) in enumerate(assets.LOGICAL_TO_ENCODED.items()):
        payload = (json.dumps({"artifact": logical, "index": index}, sort_keys=True) + "\n").encode()
        physical = repository / encoded
        physical.parent.mkdir(parents=True, exist_ok=True)
        physical.write_bytes(assets.canonical_gzip(payload))
        expected[Path(logical).name] = payload
    destination.mkdir(parents=True)
    (destination / "stale.json").write_text("{}", encoding="utf-8")

    assets.stage_wheel_assets(repository, destination)

    assert {path.name: path.read_bytes() for path in destination.glob("*.json")} == expected


def test_unknown_logical_asset_is_value_safe() -> None:
    with pytest.raises(assets.RuntimeAssetError, match="unknown telemetry runtime artifact"):
        assets.encoded_path("private-value")
